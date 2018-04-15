//! The `binary` module provides functionality for encoding and decoding binary
//! DNS data.

use error::EEndOfInput;
use std::fmt::{Display, Formatter};
use std::ops::{Deref, DerefMut};
use {std, BoxedError, Name};

/// The `prelude` module provides definitions for implementing binary-encoding
/// and binary-decoding for a custom type.
pub mod prelude {
    pub use super::{BinaryDecodeError, BinaryDecoder, BinaryEncodeError,
                    BinaryEncoder, DecodeBinary, EncodeBinary};
}

/// `DecodeBinary` is a trait for reading an object from its binary DNS form.
pub trait DecodeBinary<'a>: Sized {
    /// Constructs the object by reading it from a binary decoder.
    fn decode_binary(
        d: &mut BinaryDecoder<'a>,
    ) -> Result<Self, BinaryDecodeError>;
}

/// `BinaryDecoder` reads binary DNS data from a buffer.
///
/// `BinaryDecoder` provides low-level access for reading binary DNS data.
/// Typically, an application would use the
/// [`DecodeBinary`](trait.DecodeBinary.html) trait instead of calling
/// `BinaryDecoder` methods directly.
///
#[derive(Clone, Debug)]
pub struct BinaryDecoder<'a> {
    buffer: &'a [u8],
    cursor: usize,
}

impl<'a> BinaryDecoder<'a> {
    /// Constructs a binary decoder that reads from a buffer.
    pub fn new(buffer: &'a [u8]) -> Self {
        BinaryDecoder {
            buffer,
            cursor: 0,
        }
    }

    /// Returns the source buffer.
    pub fn buffer(&self) -> &'a [u8] {
        self.buffer
    }

    /// Returns the source buffer sliced at the cursor.
    pub fn peek(&self) -> &'a [u8] {
        unsafe { self.buffer.get_unchecked(self.cursor..) }
    }

    /// Returns the cursor offset.
    pub fn position(&self) -> usize {
        self.cursor
    }

    /// Moves the cursor to an absolute offset.
    pub fn set_position(&mut self, n: usize) {
        assert!(n <= self.buffer.len());
        self.cursor = n;
    }

    /// Moves the cursor forward by a specific number of bytes after
    /// bounds-checking the new cursor position.
    ///
    /// # Panics
    ///
    /// This method panics if it would cause the cursor to be moved out of range
    /// of the source buffer (including one-past-the-end) or if overflow would
    /// occur when calculating the new cursor position. To avoid performing
    /// these checks (for performance reasons), use the
    /// [`advance_cursor_unchecked`](#method.advance_cursor_unchecked) method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let mut d = dnslite::binary::BinaryDecoder::new(b"hello world");
    /// assert_eq!(d.peek(), b"hello world");
    ///
    /// d.advance_cursor(6);
    /// assert_eq!(d.peek(), b"world");
    ///
    /// d.advance_cursor(5); // move to one-past-the-end
    /// assert_eq!(d.peek(), b"");
    /// ```
    ///
    /// Moving the cursor by an invalid value causes a panic.
    ///
    /// ```rust,should_panic
    /// let mut d = dnslite::binary::BinaryDecoder::new(b"hello world");
    /// d.advance_cursor(12); // PANIC!
    /// ```
    ///
    pub fn advance_cursor(&mut self, len: usize) {
        let sum = self.cursor.checked_add(len).unwrap();
        assert!(sum <= self.buffer.len());
        self.cursor = sum;
    }

    /// Moves the cursor forward by a specific number of bytes without
    /// bounds-checking.
    ///
    /// # Safety
    ///
    /// This method is unsafe because it does not check that new cursor offset
    /// is within range of the source buffer. If this constraint is violated
    /// then behavior is undefined.
    ///
    /// ```rust
    /// let mut d = dnslite::binary::BinaryDecoder::new(b"hello world");
    /// assert_eq!(d.peek(), b"hello world");
    ///
    /// unsafe { d.advance_cursor_unchecked(6); }
    /// assert_eq!(d.peek(), b"world");
    ///
    /// unsafe { d.advance_cursor_unchecked(5); } // move to one-past-the-end
    /// assert_eq!(d.peek(), b"");
    /// ```
    ///
    pub unsafe fn advance_cursor_unchecked(&mut self, len: usize) {
        debug_assert!(
            self.cursor
                .checked_add(len,)
                .map_or(false, |x| x <= self.buffer.len(),)
        );
        self.cursor += len;
    }
}

/// `BinaryDecodeError` describes an error that resulted from reading binary DNS
/// data.
///
/// A `BinaryDecodeError` instance is returned by methods that read binary DNS
/// data via [`BinaryDecoder`](struct.BinaryDecoder.html).
///
/// `BinaryDecodeError` contains the following three properties.
///
/// * An **expectation** describing what was being decoded (e.g., `"u8"` or
///   `"domain name"`),
/// * A **position** describing where in the binary data the error occurred,
///   and,
/// * An underlying **cause** describing why the error occurred.
///
#[derive(Debug)]
pub struct BinaryDecodeError {
    expectation: &'static str,
    position: usize,
    cause: BoxedError,
}

impl Display for BinaryDecodeError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{} (expectation: {}, offset: {}): {}",
            std::error::Error::description(self),
            self.expectation,
            self.position,
            self.cause
        )
    }
}

impl std::error::Error for BinaryDecodeError {
    fn description(&self) -> &str {
        "Failed to decode binary DNS data"
    }
}

impl BinaryDecodeError {
    pub fn new<E>(expectation: &'static str, position: usize, cause: E) -> Self
    where
        E: Into<BoxedError>,
    {
        BinaryDecodeError {
            expectation,
            position,
            cause: cause.into(),
        }
    }

    pub fn expectation(&self) -> &str {
        self.expectation
    }

    pub fn set_expectation(&mut self, expectation: &'static str) {
        self.expectation = expectation
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn cause(&self) -> &BoxedError {
        &self.cause
    }
}

/// `EncodeBinary` is a trait for writing an object to its binary DNS form.
pub trait EncodeBinary {
    /// Writes the object to a binary encoder.
    fn encode_binary(
        &self,
        encoder: &mut BinaryEncoder,
    ) -> Result<(), BinaryEncodeError>;
}

/// `BinaryEncoder` writes binary DNS data to a buffer.
///
/// `BinaryEncoder` provides low-level access for writing binary DNS data.
/// Typically, an application would use the
/// [`EncodeBinary`](trait.EncodeBinary.html) trait instead of calling
/// `BinaryEncoder` methods directly.
///
/// `BinaryEncoder` maintains a **compression table**, which is a table of
/// offsets to domain names that can be used as compression targets. By default,
/// the compression table is disabled, and callers opt in to using compression
/// by calling the [`enable_compression`](#method.enable_compression) method.
///
#[derive(Debug)]
pub struct BinaryEncoder {
    buffer: Vec<u8>,
    len_limit: usize,
    compression_table: Vec<usize>,
}

impl Default for BinaryEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryEncoder {
    /// Constructs a binary encoder with a length limit of 65,535 bytes.
    pub fn new() -> Self {
        BinaryEncoder {
            buffer: Vec::new(),
            len_limit: 0xffff,
            compression_table: Vec::new(),
        }
    }

    /// Sets the length limit.
    ///
    /// # Panics
    ///
    /// This method panics if the new length limit is smaller than the size of
    /// the target buffer. This constraint ensures all compression table offsets
    /// remain valid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dnslite::binary::BinaryEncoder;
    ///
    /// let mut e = BinaryEncoder::new();
    /// assert!(e.append(b"hello world").is_ok());
    ///
    /// let mut e = BinaryEncoder::new().with_length_limit(10);
    /// assert!(e.append(b"hello world").is_err()); // ERROR: out of space
    /// ```
    ///
    ///
    pub fn with_length_limit(mut self, len_limit: usize) -> Self {
        assert!(self.buffer.len() <= len_limit);
        self.len_limit = len_limit;
        self
    }

    /// Converts the binary encoder into the target buffer.
    pub fn into_buffer(self) -> Vec<u8> {
        self.buffer
    }

    /// Writes the bytes to the end of the target buffer.
    pub fn append(&mut self, b: &[u8]) -> Result<(), BinaryEncodeError> {
        if self.len_limit < self.buffer.len() + b.len() {
            return Err(BinaryEncodeError::new());
        }
        self.buffer.extend_from_slice(b);
        Ok(())
    }

    /// Returns the target buffer.
    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    /// Returns mutable access to the target buffer.
    ///
    /// # Safety
    ///
    /// The caller must ensure it does not modify the target buffer such that it
    /// invalidates any compression table entries. If this constraint is
    /// violated then behavior is undefined.
    ///
    pub unsafe fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    /// Enable domain-name compression.
    ///
    /// This method returns an object that exposes methods for using the binary
    /// encoder's compression table, which contains positions of domain names in
    /// the target buffer that are suitable for domain-name compression.
    ///
    /// Domain-name compression is strictly opt-in. The reason for this design
    /// is to help prevent mistaken compression of domain names in unknown
    /// resource record types, which would violate [RFC 3597, section
    /// 4](https://tools.ietf.org/html/rfc3597#section-4).
    ///
    pub fn enable_compression(&mut self) -> TextEncoderCompressionGuard {
        TextEncoderCompressionGuard { encoder: self }
    }

    /// Returns `None`, always.
    ///
    /// To find an entry in the compression table, the caller must use the
    /// [`TextEncoderCompressionGuard`](struct.TextEncoderCompressionGuard.html)
    /// type, which is instantiated by calling the
    /// [`enable_compression`](#method.enable_compression) method.
    ///
    pub fn find_compression_entry(&self, _name: &Name) -> Option<usize> {
        None
    }
}

/// `TextEncoderCompressionGuard` wraps a
/// [`BinaryEncoder`](struct.BinaryEncoder.html) instance with domain-name
/// compression semantics.
#[derive(Debug)]
pub struct TextEncoderCompressionGuard<'a> {
    encoder: &'a mut BinaryEncoder,
}

impl<'a> Deref for TextEncoderCompressionGuard<'a> {
    type Target = BinaryEncoder;
    fn deref(&self) -> &Self::Target {
        self.encoder
    }
}

impl<'a> DerefMut for TextEncoderCompressionGuard<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.encoder
    }
}

impl<'a> TextEncoderCompressionGuard<'a> {
    /// Adds an entry to the binary encoder's compression table.
    ///
    /// This method has no mutable effect if the `position` value is out of
    /// range—i.e., greater than `0x3fff`. However, the position must always
    /// refer to a valid domain name.
    ///
    /// The caller must avoid inserting a duplicate value into the compression
    /// table.
    ///
    /// # Safety
    ///
    /// The `position` argument must be an offset of a valid domain name in the
    /// target buffer. If this constraint is violated then the compression table
    /// is corrupt and behavior is undefined.
    ///
    /// The reason this function is unsafe is for performance reasons. A
    /// validity check on the `position` argument would require this method to
    /// scan the entire domain name in the target buffer to ensure its validity.
    ///
    pub unsafe fn insert_compression_entry(&mut self, position: usize) {

        // The position must always refer to a valid domain name.
        debug_assert!(
            Name::from_binary(&self.encoder.buffer, position).is_ok()
        );

        if position < 0x4000 {

            // Duplicate entries are not allowed.
            debug_assert!(
                self.encoder
                    .compression_table
                    .iter()
                    .all(|&n| n != position,)
            );

            self.encoder.compression_table.push(position);
        }
    }

    /// Searches for a domain name in the target buffer and returns its offset.
    ///
    /// If the domain name exists in the target buffer, this method returns
    /// `Some(n)`, where `n` is the position of the domain name in the target
    /// buffer. Otherwise, if the domain name does not exist in the target
    /// buffer, this method returns `None`.
    ///
    /// Note that the search is for an _exact_ match, meaning `key` must match
    /// the ASCII case of the domain name in the target buffer. The reason for
    /// this constraint is to preserve case, as required by [RFC
    /// 1035](https://tools.ietf.org/html/rfc1035).
    ///
    pub fn find_compression_entry(&self, key: &Name) -> Option<usize> {
        self.encoder
            .compression_table
            .iter()
            .cloned()
            .find(|&position| {
                let name = unsafe {
                    Name::from_binary_unchecked(&self.encoder.buffer, position)
                };
                key.eq_case_sensitive(name)
            })
    }
}

/// `BinaryEncodeError` describes an error that resulted from writing binary DNS
/// data.
///
/// A `BinaryEncodeError` instance is returned by methods that write binary DNS
/// data via [`BinaryEncode`](struct.BinaryEncoder.html).
///
/// A `BinaryEncodeError` instance always denotes an “out of space” condition,
/// which could be the first step leading to the truncation of a DNS message.
///
#[derive(Debug, PartialEq)]
pub struct BinaryEncodeError {}

impl Display for BinaryEncodeError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        f.write_str(std::error::Error::description(self))
    }
}

impl std::error::Error for BinaryEncodeError {
    fn description(&self) -> &str {
        "Failed to encode binary DNS data: insufficient space"
    }
}

impl BinaryEncodeError {
    #[doc(hidden)]
    pub fn new() -> Self {
        BinaryEncodeError {}
    }
}

impl<'a> DecodeBinary<'a> for u8 {
    fn decode_binary(
        d: &mut BinaryDecoder<'a>,
    ) -> Result<Self, BinaryDecodeError> {
        let buffer = d.peek();
        if buffer.len() < 1 {
            return Err(BinaryDecodeError::new(
                "u8",
                d.position(),
                EEndOfInput,
            ));
        }
        unsafe {
            d.advance_cursor_unchecked(1);
        }
        Ok(buffer[0])
    }
}

impl EncodeBinary for u8 {
    fn encode_binary(
        &self,
        e: &mut BinaryEncoder,
    ) -> Result<(), BinaryEncodeError> {
        let buffer = [*self];
        e.append(&buffer)
    }
}

impl<'a> DecodeBinary<'a> for u16 {
    fn decode_binary(
        d: &mut BinaryDecoder<'a>,
    ) -> Result<Self, BinaryDecodeError> {
        use byteorder::{BigEndian, ByteOrder};
        let buffer = d.peek();
        if buffer.len() < 2 {
            return Err(BinaryDecodeError::new(
                "u16",
                d.position(),
                EEndOfInput,
            ));
        }
        let n = BigEndian::read_u16(&buffer[..2]);
        unsafe {
            d.advance_cursor_unchecked(2);
        }
        Ok(n)
    }
}

impl EncodeBinary for u16 {
    fn encode_binary(
        &self,
        e: &mut BinaryEncoder,
    ) -> Result<(), BinaryEncodeError> {
        use byteorder::{BigEndian, ByteOrder};
        let buffer: &mut [u8] = &mut [0; 2];
        BigEndian::write_u16(buffer, *self);
        e.append(buffer)
    }
}

impl<'a> DecodeBinary<'a> for u32 {
    fn decode_binary(
        d: &mut BinaryDecoder<'a>,
    ) -> Result<Self, BinaryDecodeError> {
        use byteorder::{BigEndian, ByteOrder};
        let buffer = d.peek();
        if buffer.len() < 4 {
            return Err(BinaryDecodeError::new(
                "u32",
                d.position(),
                EEndOfInput,
            ));
        }
        let n = BigEndian::read_u32(&buffer[..4]);
        unsafe {
            d.advance_cursor_unchecked(4);
        }
        Ok(n)
    }
}

impl EncodeBinary for u32 {
    fn encode_binary(
        &self,
        e: &mut BinaryEncoder,
    ) -> Result<(), BinaryEncodeError> {
        use byteorder::{BigEndian, ByteOrder};
        let buffer: &mut [u8] = &mut [0; 4];
        BigEndian::write_u32(buffer, *self);
        e.append(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn binary_decoder_bounds_checks_cursor_advancement() {
        let mut d = BinaryDecoder::new(b"alpha bravo");
        d.advance_cursor(12);
    }

    #[test]
    fn binary_encoder_enables_and_disables_compression() {

        let source = b"\x05alpha\x05bravo\x07charlie\x00";
        let n1 = Name::from_binary(source, 0).unwrap();
        let n2 = n1.pop_front().unwrap();
        let n3 = n2.pop_front().unwrap();

        let mut e = BinaryEncoder::new();

        assert_eq!(e.find_compression_entry(n1), None);
        assert_eq!(e.find_compression_entry(n2), None);
        assert_eq!(e.find_compression_entry(n3), None);

        {
            let mut c = e.enable_compression();
            assert_matches!(c.append(source), Ok(()));
            unsafe {
                c.insert_compression_entry(0);
                c.insert_compression_entry(6);
                c.insert_compression_entry(12);
            }
            assert_eq!(c.find_compression_entry(n1), Some(0));
            assert_eq!(c.find_compression_entry(n2), Some(6));
            assert_eq!(c.find_compression_entry(n3), Some(12));
        }

        assert_eq!(e.find_compression_entry(n1), None);
        assert_eq!(e.find_compression_entry(n2), None);
        assert_eq!(e.find_compression_entry(n3), None);

        {
            let c = e.enable_compression();
            assert_eq!(c.find_compression_entry(n1), Some(0));
            assert_eq!(c.find_compression_entry(n2), Some(6));
            assert_eq!(c.find_compression_entry(n3), Some(12));
        }
    }

    #[test]
    fn binary_encoder_does_not_insert_compression_entry_above_3fff() {

        let source = b"\x05alpha\x05bravo\x07charlie\x00";
        let n1 = Name::from_binary(source, 0).unwrap();
        let n2 = n1.pop_front().unwrap();
        let n3 = n2.pop_front().unwrap();

        let mut e = BinaryEncoder::new();
        assert_matches!(e.append(&vec![0x00; 0x3fff]), Ok(()));

        {
            let mut c = e.enable_compression();
            assert_matches!(c.append(source), Ok(()));
            unsafe {
                c.insert_compression_entry(0x3fff);
                c.insert_compression_entry(0x3fff + 6);
                c.insert_compression_entry(0x3fff + 12);
            }
            assert_eq!(c.find_compression_entry(n1), Some(0x3fff));
            assert_eq!(c.find_compression_entry(n2), None);
            assert_eq!(c.find_compression_entry(n3), None);
        }

        // Do it again, but ensure the cutoff is exactly 0x4000.

        let mut e = BinaryEncoder::new();
        assert_matches!(e.append(&vec![0x00; 0x4000]), Ok(()));

        {
            let mut c = e.enable_compression();
            assert_matches!(c.append(source), Ok(()));
            unsafe {
                c.insert_compression_entry(0x4000);
            }
            assert_eq!(c.find_compression_entry(n1), None);
        }
    }

    #[test]
    fn binary_encoder_matches_exact_name_when_searching_for_compression_entry()
    {

        let source = b"\x05bravo\x00";
        let n1 = Name::from_binary(source, 0).unwrap();

        let n2 = Name::from_binary(b"\x05alpha\x05bravo\x00", 0).unwrap();
        let n3 = Name::from_binary(b"\x05bravo\x07charlie\x00", 0).unwrap();

        let mut e = BinaryEncoder::new();

        {
            let mut c = e.enable_compression();
            assert_matches!(c.append(source), Ok(()));
            unsafe {
                c.insert_compression_entry(0);
            }
            assert_eq!(c.find_compression_entry(n1), Some(0));
            assert_eq!(c.find_compression_entry(n2), None);
            assert_eq!(c.find_compression_entry(n3), None);
        }
    }

    #[test]
    fn binary_encoder_preserves_case_when_searching_for_compression_entry() {

        let source1 = b"\x05alpha\x05bravo\x07charlie\x00";
        let n1 = Name::from_binary(source1, 0).unwrap();

        let source2 = b"\x05alpha\x05bravo\x07charliE\x00";
        let n2 = Name::from_binary(source2, 0).unwrap();

        let mut e = BinaryEncoder::new();

        {
            let mut c = e.enable_compression();
            assert_matches!(c.append(source1), Ok(()));
            unsafe {
                c.insert_compression_entry(0);
            }
            assert_eq!(c.find_compression_entry(n1), Some(0));
            assert_eq!(c.find_compression_entry(n2), None);
        }
    }

    #[test]
    fn u8_implements_decode_binary() {
        let mut d = BinaryDecoder::new(b"\x00\x80\xff");
        assert_matches!(u8::decode_binary(&mut d), Ok(0));
        assert_matches!(u8::decode_binary(&mut d), Ok(0x80));
        assert_matches!(u8::decode_binary(&mut d), Ok(0xff));
        assert_matches!(
            u8::decode_binary(&mut d),
            Err(ref e) if e.expectation() == "u8"
                && e.position() == 3
                && e.cause().downcast_ref::<EEndOfInput>() == Some(&EEndOfInput)
        );
    }

    #[test]
    fn u8_implements_encode_binary() {
        let mut e = BinaryEncoder::new().with_length_limit(3);
        assert_matches!(0x12u8.encode_binary(&mut e), Ok(()));
        assert_matches!(0x80u8.encode_binary(&mut e), Ok(()));
        assert_matches!(0xffu8.encode_binary(&mut e), Ok(()));
        assert_matches!(
            0x34u8.encode_binary(&mut e),
            Err(ref e) if *e == BinaryEncodeError::new()
        );
        assert_eq!(e.into_buffer(), b"\x12\x80\xff");
    }

    #[test]
    fn u16_implements_decode_binary() {
        let mut d = BinaryDecoder::new(b"\x12\x34\x90\xab\xff");
        assert_matches!(u16::decode_binary(&mut d), Ok(0x1234));
        assert_matches!(u16::decode_binary(&mut d), Ok(0x90ab));
        assert_matches!(
            u16::decode_binary(&mut d),
            Err(ref e) if e.expectation() == "u16"
                && e.position() == 4
                && e.cause().downcast_ref::<EEndOfInput>() == Some(&EEndOfInput)
        );
    }

    #[test]
    fn u16_implements_encode_binary() {
        let mut e = BinaryEncoder::new().with_length_limit(5);
        assert_matches!(0x1234u16.encode_binary(&mut e), Ok(()));
        assert_matches!(0x90abu16.encode_binary(&mut e), Ok(()));
        assert_matches!(
            0xffffu16.encode_binary(&mut e),
            Err(ref e) if *e == BinaryEncodeError::new()
        );
        assert_eq!(e.into_buffer(), b"\x12\x34\x90\xab");
    }

    #[test]
    fn u32_implements_decode_binary() {
        let mut d =
            BinaryDecoder::new(b"\x12\x34\x56\x78\x90\xab\xcd\xef\x01\x02\x03");
        assert_matches!(u32::decode_binary(&mut d), Ok(0x12345678));
        assert_matches!(u32::decode_binary(&mut d), Ok(0x90abcdef));
        assert_matches!(
            u32::decode_binary(&mut d),
            Err(ref e) if e.expectation() == "u32"
                && e.position() == 8
                && e.cause().downcast_ref::<EEndOfInput>() == Some(&EEndOfInput)
        );
    }

    #[test]
    fn u32_implements_encode_binary() {
        let mut e = BinaryEncoder::new().with_length_limit(11);
        assert_matches!(0x12345678u32.encode_binary(&mut e), Ok(()));
        assert_matches!(0x90abcdefu32.encode_binary(&mut e), Ok(()));
        assert_matches!(
            0x01020304u32.encode_binary(&mut e),
            Err(ref e) if *e == BinaryEncodeError::new()
        );
        assert_eq!(
            e.into_buffer(),
            b"\x12\x34\x56\x78\x90\xab\xcd\xef"
        );
    }
}
