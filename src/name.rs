use ascii::AsciiCaseBytes;
use binary::prelude::*;
use std::borrow::{Borrow, Cow};
use std::cmp::Ordering;
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use text::prelude::*;
use {std, text, BoxedError};

// These limits are defined in RFC 1035.
pub const MAX_LABEL_LENGTH: usize = 63;
pub const MAX_NAME_LENGTH: usize = 255;

const EXPECTATION_NAME: &str = "domain name";

declare_static_error_type!(
    EBadCompression,
    "Domain name compression is invalid"
);
declare_static_error_type!(
    EEmptyLabel,
    "Domain name label is empty but not root"
);
declare_static_error_type!(ELabelTooLong, "Domain name label is too long");
declare_static_error_type!(
    ENameIsRelative,
    "Domain name is relative and no origin is specified"
);
declare_static_error_type!(ENameTooLong, "Domain name is too long");
declare_static_error_type!(
    ENameOverrun,
    "Domain name would extend past end of input"
);
declare_static_error_type!(
    EUnsupportedFlags,
    "Domain name label flags are unsupported"
);

#[derive(Debug)]
struct EBadNameText(BoxedError);

impl Display for EBadNameText {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{}: {}",
            std::error::Error::description(self),
            self.0
        )
    }
}

impl std::error::Error for EBadNameText {
    fn description(&self) -> &str {
        "The domain name is invalid"
    }
}

/// `&Label` borrows a domain name label.
///
/// A **domain name label** is a single component of a domain name. For example,
/// `"example"`, `"com"`, and `""` are the three components making up the domain
/// name `"example.com."`.
///
/// A `&Label` instance borrows a single label, which is a slice of bytes with
/// the following caveats.
///
/// * `&Label` compares and hashes as ASCII-case-insensitive.
/// * `&Label` allows only a maximum of 63 bytes, ([RFC 1035, section
///   2.3.4](https://tools.ietf.org/html/rfc1035)).
///
/// A `&Label` instance is otherwise unconstrained. This is because although
/// _host names_ are limited to a subset of ASCII characters, DNS domain names
/// are not.
///
/// `&Label` is similar to `&str` in that it's constructible only as a reference
/// type.
///
#[derive(Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Label {
    inner: AsciiCaseBytes, // DST (dynamic-sized type)
}

impl AsRef<Label> for Label {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl AsRef<[u8]> for Label {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl Deref for Label {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl DerefMut for Label {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_bytes_mut()
    }
}

impl Debug for Label {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        use std::fmt::Write;
        f.write_char('"')?;
        text::format_string(f, self.as_bytes(), true, Some(b'.'))?;
        f.write_char('"')?;
        Ok(())
    }
}

impl Display for Label {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        text::format_string(f, self.as_bytes(), false, Some(b'.'))?;
        Ok(())
    }
}

impl Label {
    /// Borrows the root label.
    pub fn root() -> &'static Self {
        const BUFFER: &[u8] = &[];
        unsafe { Self::from_binary_unchecked(BUFFER) }
    }

    /// Borrows a label from a slice of bytes.
    ///
    /// # Errors
    ///
    /// Label construction will fail if the byte slice is 64 bytes or longer.
    /// This limit is imposed by the DNS protocol (defined in [RFC 1035, section
    /// 2.3.4](https://tools.ietf.org/html/rfc1035)).
    ///
    pub fn from_binary(bytes: &[u8]) -> Result<&Self, BoxedError> {

        if MAX_LABEL_LENGTH < bytes.len() {
            return Err(ELabelTooLong)?;
        }

        Ok(unsafe { std::mem::transmute(bytes) })
    }

    unsafe fn from_binary_unchecked(bytes: &[u8]) -> &Self {
        debug_assert!(bytes.len() <= MAX_LABEL_LENGTH);
        std::mem::transmute(bytes)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    /// Returns true if and only if the label is empty.
    ///
    /// An empty label is the **root label**, which is represented as the
    /// trailing dot at the end of an absolute domain name when represented in
    /// text form. The root label can exist only at the end of a domain
    /// name–never at the beginning or in the middle.
    ///
    pub fn is_root(&self) -> bool {
        self.is_empty()
    }
}

// NameRepr is the underlying representation of a &Name reference. Because &Name
// is a fat pointer, NameRepr must be two machine words.
//
// At a minimum, NameRepr must store a pointer to the first byte of the buffer
// and an offset to the first byte of the domain name. Keep in mind that the
// domain name may be compressed, in which case one or more labels will point
// backwards in the buffer. This is why we need a pointer to the entire buffer
// and not just the first byte of the domain name.
//
// We may be tempted to store other data in the NampRepr, such as the domain
// name's length, but doing so would require us to scan the domain name during
// construction--O(n) complexity instead of O(1)--and this is a problem because
// construction should be cheap. For example, suppose we have a reference to a
// record--i.e., &Record. If the domain name is compressed, then the offset to
// the RDATA wouldn't tell us the domain length and we would instead need to
// scan the domain name.
//
// One extra thing we do as an invariant, however, is we keep every &Name in
// *normalized* form. This means that the NameRepr points at a label prefix and
// not a compression pointer. This rationale for this is that it make some
// operations cheaper, such as name.first(), because we don't need to follow any
// compression jumps.
//
#[repr(C)]
#[derive(Clone, Debug)]
struct NameRepr {
    buffer: *const u8,
    offset: usize,
}

impl NameRepr {
    unsafe fn into_name<'a>(self) -> &'a Name {
        std::mem::transmute(self)
    }

    unsafe fn into_normalized_name<'a>(self) -> &'a Name {
        Self::into_name(self).normalize()
    }

    fn from_name(name: &Name) -> Self {
        unsafe { std::mem::transmute(name) }
    }
}

/// `&Name` borrows a domain name.
///
/// A `&Name` instance borrows a slice of bytes making up a **DNS domain name**
/// represented in binary form—i.e., as the domain name exists in a DNS message
/// on the wire.
///
/// By way of analogy, `&Name` is to [`NameBuf`](struct.NameBuf.html) as `&str`
/// is to `String`.
///
/// `&Name` constrains its domain name to a maximum of 255 bytes. This limit is
/// defined in [RFC 1035, section 2.3.4](https://tools.ietf.org/html/rfc1035).
///
/// As a matter of convenience, `&Name` compares and hashes as
/// ASCII-case-insensitive but is case-preserving.
///
pub struct Name {
    _dummy: [detail::NotConstructible],
}

impl AsRef<Name> for Name {
    fn as_ref(&self) -> &Name {
        self
    }
}

impl ToOwned for Name {
    type Owned = NameBuf;
    fn to_owned(&self) -> Self::Owned {
        NameBuf::from(self)
    }
}

impl Debug for Name {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        use std::fmt::Write;
        f.write_char('"')?;
        self.format(f, true)?;
        f.write_char('"')?;
        Ok(())
    }
}

impl Display for Name {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        self.format(f, false)
    }
}

impl Eq for Name {}

impl PartialEq for Name {
    fn eq(&self, other: &Name) -> bool {
        self.labels().eq(other.labels())
    }
}

impl PartialOrd for Name {
    fn partial_cmp(&self, other: &Name) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Name {
    fn cmp(&self, other: &Name) -> Ordering {
        self.labels().cmp(other.labels())
    }
}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for label in self.labels() {
            label.hash(state);
        }
    }
}

impl EncodeText for Name {
    fn encode_text<W: std::io::Write, M: TextEncodeMode>(
        &self,
        encoder: &mut TextEncoder<W, M>,
    ) -> Result<(), TextEncodeError> {
        encoder.encode_multi_string(b'.', self.labels().map(|x| x.as_bytes()))
    }
}

impl<'a> DecodeBinary<'a> for &'a Name {
    fn decode_binary(
        decoder: &mut BinaryDecoder<'a>,
    ) -> Result<Self, BinaryDecodeError> {

        let (name, extent) = Name::from_binary_unchecked_with_extent(
            decoder.buffer(),
            decoder.position(),
        ).map_err(|e| {
            BinaryDecodeError::new(EXPECTATION_NAME, decoder.position(), e)
        })?;

        decoder.set_position(extent);

        Ok(name)
    }
}

impl EncodeBinary for Name {
    fn encode_binary(
        &self,
        encoder: &mut BinaryEncoder,
    ) -> Result<(), BinaryEncodeError> {

        // TODO: Implement name compression.

        for label in self.labels() {
            (label.len() as u8).encode_binary(encoder)?;
            encoder.append(label.as_bytes())?;
        }

        Ok(())
    }
}

impl Name {
    /// Borrows the root domain name–i.e., `"."` as it's represented in text
    /// form.
    pub fn root() -> &'static Self {
        static BUFFER: &[u8] = &[0];
        let repr = NameRepr {
            buffer: BUFFER.as_ptr(),
            offset: 0,
        };
        unsafe { repr.into_name() }
    }

    /// Borrows a domain name from a slice of bytes.
    pub fn from_binary(
        buffer: &[u8],
        offset: usize,
    ) -> Result<&Self, BoxedError> {
        Self::check(buffer, offset)?;
        Ok(unsafe { Self::from_binary_unchecked(buffer, offset) })
    }

    /// Borrows a domain name from a slice of bytes without checking the
    /// validity of the name.
    ///
    /// # Safety
    ///
    /// This method is unsafe because it does not check that the domain name is
    /// valid. If this constraint is violated then behavior is undefined.
    ///
    pub unsafe fn from_binary_unchecked(buffer: &[u8], offset: usize) -> &Self {
        debug_assert!(Self::check(buffer, offset).is_ok());
        let repr = NameRepr {
            buffer: buffer.as_ptr(),
            offset,
        };
        repr.into_normalized_name()
    }

    /// Borrows a domain name in binary form while also returning the domain
    /// name's extent.
    ///
    /// The domain name's extent is the offset of the first byte following the
    /// uncompressed portion of the domain name. If the domain name is embedded
    /// in a resource record (stored in binary form), then the extent specifies
    /// the offset of the TYPE field. If the domain name is embedded in an
    /// RDATA, then the extent specifies the offset of the next field—or the end
    /// of the RDATA, if the domain name is the last field.
    ///
    /// The extent is calculated as part of the validity check when constructing
    /// a `&Name` from untrusted arguments.
    ///
    #[doc(hidden)]
    pub fn from_binary_unchecked_with_extent(
        buffer: &[u8],
        offset: usize,
    ) -> Result<(&Self, usize), BoxedError> {
        let extent = Self::check(buffer, offset)?;
        let name = unsafe { Self::from_binary_unchecked(buffer, offset) };
        Ok((name, extent))
    }

    fn check(buffer: &[u8], offset: usize) -> Result<usize, BoxedError> {

        // Unlike in methods that start with a (valid) &Name as a parameter,
        // here we don't trust anything about the buffer other than its length.
        // Note we don't even trust the offset.

        // We use min_offset to ensure that compression pointers always jump
        // backwards. This ensures there are no infinite cycles.

        let mut compressed = false;
        let mut len = 0;
        let mut cur_offset = offset;
        let mut min_offset = offset;
        let mut extent = offset;

        loop {
            let prefix = match buffer.get(cur_offset) {
                None => return Err(ENameOverrun)?,
                Some(&b) => b,
            };

            if prefix & 0b1100_0000 == 0b1100_0000 {
                let hi = prefix ^ 0b1100_0000;
                cur_offset += 1;
                let lo = *buffer
                    .get(cur_offset)
                    .ok_or_else(|| ENameOverrun)?;
                let next_offset = ((hi as usize) << 8) + (lo as usize);
                if min_offset <= next_offset {
                    return Err(EBadCompression)?;
                }
                // Invariant: Compression jumps backwards.
                debug_assert!(next_offset < buffer.len());
                cur_offset = next_offset;
                min_offset = cur_offset;
                if !compressed {
                    extent += 2;
                    compressed = true;
                }
                continue;
            }

            if prefix & 0b1100_0000 != 0 {
                return Err(EUnsupportedFlags)?;
            }

            if MAX_NAME_LENGTH < len + 1 + prefix as usize {
                return Err(ENameTooLong)?;
            }

            len += 1 + prefix as usize;

            cur_offset += 1 + prefix as usize;
            if !compressed {
                extent = cur_offset;
            }

            if prefix == 0 {
                return Ok(extent);
            }
        }
    }

    /// Returns an iterator that yields each label in the domain name.
    pub fn labels(&self) -> NameLabelIter {
        NameLabelIter::new(self)
    }

    /// Returns the size of the domain name, in bytes, as represented in binary
    /// form.
    ///
    /// A length of a domain name in binary form is, for most cases, one greater
    /// than the length of that domain name when represented in text form. For
    /// example, the domain name `"example.com."` has a length of 13.
    ///
    /// For details about binary form, see [RFC
    /// 1035](https://tools.ietf.org/html/rfc1035).
    ///
    /// Compression has no effect on the length of a domain name. The length is
    /// *as if* the domain name were uncompressed.
    ///
    /// # Example
    ///
    /// ```rust
    /// use dnslite::{Name, NameBuf};
    ///
    /// let n = NameBuf::from_text("example.com.").unwrap();
    /// assert_eq!(n.len(), 13);
    ///
    /// let n = NameBuf::from_text(".").unwrap();
    /// assert_eq!(n.len(), 1);
    ///
    /// // This name is in compressed form.
    /// let n = Name::from_binary(b"\x03com\x00\x07example\xc0\x00", 5)
    ///             .unwrap();
    /// assert_eq!(n.len(), 13);
    /// ```
    ///
    pub fn len(&self) -> usize {
        self.labels()
            .fold(0, |length, label| length + 1 + label.len())
    }

    /// Returns true if and only if the domain name is the root domain
    /// name—i.e., if it's length is zero.
    pub fn is_empty(&self) -> bool {
        let repr = NameRepr::from_name(self);
        unsafe { *repr.buffer.offset(repr.offset as isize) == 0 }
    }

    /// Returns true if and only if the domain name is *exactly* equal to
    /// another domain name.
    ///
    /// `&Name` normally compares as ASCII-case-insensitive. This method
    /// provides case-sensitive comparison.
    ///
    pub fn eq_case_sensitive(&self, other: &Name) -> bool {
        let mut a = self.labels();
        let mut b = other.labels();
        loop {
            match (a.next(), b.next()) {
                (None, None) => return true,
                (Some(a), Some(b)) if a.as_bytes() == b.as_bytes() => continue,
                _ => return false,
            }
        }
    }

    /// Returns the first label in the domain name.
    pub fn first(&self) -> &Label {
        debug_assert!(self.is_normalized());
        let repr = NameRepr::from_name(self);
        let prefix = unsafe { *repr.buffer.offset(repr.offset as isize) };
        unsafe {
            let bytes = std::slice::from_raw_parts(
                repr.buffer.offset(repr.offset as isize + 1),
                prefix as usize,
            );
            Label::from_binary_unchecked(bytes)
        }
    }

    /// Returns a tuple pairing the domain name's first label with the name
    /// starting with the second label, if available.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dnslite::{Label, Name};
    ///
    /// let n1 = Name::from_binary(b"\x07example\x03com\x00", 0).unwrap();
    /// let n2 = Name::from_binary(b"\x03com\x00", 0).unwrap();
    /// let n3 = Name::from_binary(b"\x00", 0).unwrap();
    ///
    /// assert_eq!(
    ///     n1.split_first(),
    ///     (Label::from_binary(b"example").unwrap(), Some(n2))
    /// );
    ///
    /// assert_eq!(
    ///     n2.split_first(),
    ///     (Label::from_binary(b"com").unwrap(), Some(n3))
    /// );
    ///
    /// assert_eq!(n3.split_first(), (Label::root(), None));
    /// ```
    ///
    pub fn split_first(&self) -> (&Label, Option<&Name>) {
        (self.first(), self.pop_front())
    }

    /// Returns the domain name starting with its second label, if the name has
    /// two or more labels.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dnslite::Name;
    ///
    /// let n1 = Name::from_binary(b"\x07example\x03com\x00", 0).unwrap();
    /// let n2 = Name::from_binary(b"\x03com\x00", 0).unwrap();
    /// let n3 = Name::from_binary(b"\x00", 0).unwrap();
    ///
    /// assert_eq!(n1.pop_front(), Some(n2));
    /// assert_eq!(n2.pop_front(), Some(n3));
    /// assert_eq!(n3.pop_front(), None);
    /// ```
    ///
    pub fn pop_front(&self) -> Option<&Name> {
        debug_assert!(self.is_normalized());
        let mut repr = NameRepr::from_name(self);
        let prefix = unsafe { *repr.buffer.offset(repr.offset as isize) };
        if prefix == 0 {
            return None;
        }
        repr.offset += 1 + prefix as usize;
        Some(unsafe { repr.into_normalized_name() })
    }

    fn format(
        &self,
        f: &mut Formatter,
        as_quoted: bool,
    ) -> Result<(), std::fmt::Error> {

        use std::fmt::Write;

        let mut first = true;
        for label in self.labels() {
            if !first || label.is_root() {
                f.write_char('.')?;
            }
            first = false;
            text::format_string(f, label.as_bytes(), as_quoted, Some(b'.'))?;
        }

        Ok(())
    }

    // Follows any compression pointers until the name's offset points directly
    // at its first label.
    fn normalize(&self) -> &Name {
        let mut repr = NameRepr::from_name(self);
        loop {
            let prefix = unsafe { *repr.buffer.offset(repr.offset as isize) };
            if prefix & 0b1100_0000 == 0b1100_0000 {
                let hi = prefix ^ 0b1100_0000;
                repr.offset += 1;
                let lo = unsafe { *repr.buffer.offset(repr.offset as isize) };
                repr.offset = ((hi as usize) << 8) + (lo as usize);
                continue;
            }
            break;
        }
        unsafe { repr.into_name() }
    }

    #[cfg(debug_assertions)]
    fn is_normalized(&self) -> bool {
        let repr = NameRepr::from_name(self);
        let prefix = unsafe { *repr.buffer.offset(repr.offset as isize) };
        prefix & 0b1100_0000 != 0b1100_0000
    }
}

/// `NameBuf` owns a domain name.
///
/// A `NameBuf` instance owns a heap-allocated sequence of bytes making up a
/// **DNS domain name** represented in binary form—i.e., as the domain name
///  exists in a DNS message on the wire.
///
/// By way of analogy, `NameBuf` is to [`&Name`](struct.Name.html) as `String`
/// is to `&str`.
///
#[derive(Clone)]
pub struct NameBuf {
    buffer: Vec<u8>,
}

impl<'a> From<&'a Name> for NameBuf {
    fn from(source: &'a Name) -> Self {
        unsafe { NameBuf::from_labels_unchecked(source.labels()) }
    }
}

impl<'a> From<Cow<'a, Name>> for NameBuf {
    fn from(source: Cow<'a, Name>) -> Self {
        match source {
            Cow::Borrowed(x) => NameBuf::from(x),
            Cow::Owned(x) => x.clone(),
        }
    }
}

impl FromStr for NameBuf {
    type Err = BoxedError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_text(s)
    }
}

impl AsRef<Name> for NameBuf {
    fn as_ref(&self) -> &Name {
        self.as_name()
    }
}

impl Borrow<Name> for NameBuf {
    fn borrow(&self) -> &Name {
        self.as_name()
    }
}

impl Deref for NameBuf {
    type Target = Name;
    fn deref(&self) -> &Self::Target {
        self.as_name()
    }
}

impl Debug for NameBuf {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        Debug::fmt(self.deref(), f)
    }
}

impl Display for NameBuf {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        Display::fmt(self.deref(), f)
    }
}

impl Eq for NameBuf {}

impl PartialEq for NameBuf {
    fn eq(&self, other: &NameBuf) -> bool {
        PartialEq::eq(self.as_name(), other)
    }
}

impl PartialOrd for NameBuf {
    fn partial_cmp(&self, other: &NameBuf) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NameBuf {
    fn cmp(&self, other: &NameBuf) -> Ordering {
        Ord::cmp(self.as_name(), other)
    }
}

impl Hash for NameBuf {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash(self.as_name(), state)
    }
}

impl<'a, M: 'a + TextDecodeMode> DecodeText<'a, M> for NameBuf {
    fn decode_text(
        decoder: &mut TextDecoder<'a, M>,
    ) -> Result<Self, TextDecodeError> {

        let mut buffer = Vec::new();
        let mut n_empty = 0;
        let mut n_label = 0;
        let mut length = 0;
        let saved_position = decoder.position();

        for label_result in decoder.decode_multi_string(b'.') {

            let label = label_result.map_err(|mut e| {
                e.set_expectation(EXPECTATION_NAME);
                e
            })?;

            if 1 == n_empty && 1 == n_label && label.is_empty() {
                n_empty = 2;
                n_label = 2;
                continue; // special handling for "."
            }

            if 1 <= n_empty {
                return Err(TextDecodeError::new(
                    EXPECTATION_NAME,
                    saved_position,
                    EEmptyLabel,
                ));
            }

            if label.is_empty() {
                debug_assert_eq!(n_empty, 0);
                n_empty = 1;
            }

            if MAX_LABEL_LENGTH < label.as_ref().len() {
                return Err(TextDecodeError::new(
                    EXPECTATION_NAME,
                    saved_position,
                    ELabelTooLong,
                ));
            }

            length += 1 + label.len();
            n_label += 1;

            if MAX_NAME_LENGTH < length {
                return Err(TextDecodeError::new(
                    EXPECTATION_NAME,
                    saved_position,
                    ENameTooLong,
                ));
            }

            buffer.reserve(1 + label.len());
            debug_assert!(label.len() <= 255);
            buffer.push(label.len() as u8);
            buffer.extend_from_slice(label.as_ref());
        }

        debug_assert!(n_empty <= 1 || (n_empty == 2 && n_label == 2));

        if 0 == n_empty {
            match decoder.origin() {
                None => {
                    return Err(TextDecodeError::new(
                        EXPECTATION_NAME,
                        saved_position,
                        ENameIsRelative,
                    ));
                }
                Some(origin) => {

                    if MAX_NAME_LENGTH < buffer.len() + origin.len() {
                        return Err(TextDecodeError::new(
                            EXPECTATION_NAME,
                            saved_position,
                            ENameTooLong,
                        ));
                    }

                    buffer.reserve(origin.len());

                    for label in origin.labels() {
                        debug_assert!(label.len() < 256);
                        buffer.push(label.len() as u8);
                        buffer.extend_from_slice(label);
                    }
                }
            }
        }

        Ok(NameBuf { buffer: buffer })
    }
}

impl NameBuf {
    /// Constructs the root domain name—i.e., `"."` in text form.
    pub fn root() -> Self {
        NameBuf {
            buffer: vec![0],
        }
    }

    /// Constructs a domain name by converting it from text form.
    ///
    /// This method will fail if the domain name is invalid or if the domain
    /// name is not fully qualified–i.e., ends with a `'.'`.
    ///
    pub fn from_text<B: AsRef<[u8]>>(text: B) -> Result<Self, BoxedError> {
        Ok(Self::from_text_impl(text.as_ref(), None)
            .map_err(|e| EBadNameText(e))?)
    }

    /// Constructs a domain name by converting it from text form.
    ///
    /// This method will fail if the domain name is invalid or if no origin is
    /// specified and the domain is not fully qualified.
    ///
    pub fn from_text_with_origin<B: AsRef<[u8]>>(
        text: B,
        origin: Option<&Name>,
    ) -> Result<Self, BoxedError> {
        Ok(Self::from_text_impl(text.as_ref(), origin)
            .map_err(|e| EBadNameText(e))?)
    }

    fn from_text_impl(
        text: &[u8],
        origin: Option<&Name>,
    ) -> Result<Self, BoxedError> {

        let mut decoder = TextDecoder::new(text);
        decoder.set_origin(origin.map(|x| x.to_owned()));

        let name = Self::decode_text(&mut decoder).map_err(|e| e.into_cause())?;

        if !decoder.peek().is_empty() {
            return Err(text::EBadChar(decoder.peek()[0]))?;
        }

        Ok(name)
    }

    unsafe fn from_binary_unchecked(buffer: Vec<u8>) -> Self {
        debug_assert!(Name::from_binary(&buffer, 0).is_ok());
        NameBuf { buffer: buffer }
    }

    fn as_name(&self) -> &Name {
        unsafe { Name::from_binary_unchecked(&self.buffer, 0) }
    }

    unsafe fn from_labels_unchecked<I, L>(labels: I) -> Self
    where
        I: IntoIterator<Item = L>,
        L: AsRef<Label>,
    {
        let labels = labels.into_iter();

        let buffer = labels.fold(Vec::new(), |mut buffer, label| {
            let label = label.as_ref();
            buffer.reserve(1 + label.len());
            debug_assert!(label.len() <= MAX_LABEL_LENGTH);
            buffer.push(label.len() as u8);
            buffer.extend_from_slice(label.as_bytes());
            buffer
        });

        NameBuf::from_binary_unchecked(buffer)
    }

    /// Returns the size of the domain name, in bytes, as represented in binary
    /// form.
    ///
    /// This method specializes the same-named method in
    /// [`&Name`](struct.Name.html) and calculates length more efficiently.
    ///
    pub fn len(&self) -> usize {
        self.buffer.len()
    }
}

impl PartialEq<NameBuf> for Name {
    fn eq(&self, other: &NameBuf) -> bool {
        PartialEq::eq(self, other.deref())
    }
}

impl PartialOrd<NameBuf> for Name {
    fn partial_cmp(&self, other: &NameBuf) -> Option<Ordering> {
        PartialOrd::partial_cmp(self, other.deref())
    }
}

impl<'a> PartialEq<NameBuf> for &'a Name {
    fn eq(&self, other: &NameBuf) -> bool {
        PartialEq::eq(*self, other.deref())
    }
}

impl<'a> PartialOrd<NameBuf> for &'a Name {
    fn partial_cmp(&self, other: &NameBuf) -> Option<Ordering> {
        PartialOrd::partial_cmp(*self, other.deref())
    }
}

impl<'a> PartialEq<Cow<'a, Name>> for Name {
    fn eq(&self, other: &Cow<'a, Name>) -> bool {
        PartialEq::eq(self, other.deref())
    }
}

impl<'a> PartialOrd<Cow<'a, Name>> for Name {
    fn partial_cmp(&self, other: &Cow<'a, Name>) -> Option<Ordering> {
        PartialOrd::partial_cmp(self, other.deref())
    }
}

impl<'a, 'b> PartialEq<Cow<'a, Name>> for &'b Name {
    fn eq(&self, other: &Cow<'a, Name>) -> bool {
        PartialEq::eq(*self, other.deref())
    }
}

impl<'a, 'b> PartialOrd<Cow<'a, Name>> for &'b Name {
    fn partial_cmp(&self, other: &Cow<'a, Name>) -> Option<Ordering> {
        PartialOrd::partial_cmp(*self, other.deref())
    }
}

impl PartialEq<Name> for NameBuf {
    fn eq(&self, other: &Name) -> bool {
        PartialEq::eq(self.deref(), other)
    }
}

impl PartialOrd<Name> for NameBuf {
    fn partial_cmp(&self, other: &Name) -> Option<Ordering> {
        PartialOrd::partial_cmp(self.deref(), other)
    }
}

impl<'a> PartialEq<&'a Name> for NameBuf {
    fn eq(&self, other: &&'a Name) -> bool {
        PartialEq::eq(self.deref(), *other)
    }
}

impl<'a> PartialOrd<&'a Name> for NameBuf {
    fn partial_cmp(&self, other: &&'a Name) -> Option<Ordering> {
        PartialOrd::partial_cmp(self.deref(), *other)
    }
}

impl<'a> PartialEq<Cow<'a, Name>> for NameBuf {
    fn eq(&self, other: &Cow<'a, Name>) -> bool {
        PartialEq::eq(self.deref(), other.deref())
    }
}

impl<'a> PartialOrd<Cow<'a, Name>> for NameBuf {
    fn partial_cmp(&self, other: &Cow<'a, Name>) -> Option<Ordering> {
        PartialOrd::partial_cmp(self.deref(), other.deref())
    }
}

impl<'a> PartialEq<Name> for Cow<'a, Name> {
    fn eq(&self, other: &Name) -> bool {
        PartialEq::eq(self.deref(), other)
    }
}

impl<'a> PartialOrd<Name> for Cow<'a, Name> {
    fn partial_cmp(&self, other: &Name) -> Option<Ordering> {
        PartialOrd::partial_cmp(self.deref(), other)
    }
}

impl<'a, 'b> PartialEq<&'b Name> for Cow<'a, Name> {
    fn eq(&self, other: &&'b Name) -> bool {
        PartialEq::eq(self.deref(), *other)
    }
}

impl<'a, 'b> PartialOrd<&'b Name> for Cow<'a, Name> {
    fn partial_cmp(&self, other: &&'b Name) -> Option<Ordering> {
        PartialOrd::partial_cmp(self.deref(), *other)
    }
}

impl<'a> PartialEq<NameBuf> for Cow<'a, Name> {
    fn eq(&self, other: &NameBuf) -> bool {
        PartialEq::eq(self.deref(), other.deref())
    }
}

impl<'a> PartialOrd<NameBuf> for Cow<'a, Name> {
    fn partial_cmp(&self, other: &NameBuf) -> Option<Ordering> {
        PartialOrd::partial_cmp(self.deref(), other.deref())
    }
}

/// `NameLabelIter` is an iterator that yields each label in a domain name.
#[derive(Clone, Debug)]
pub struct NameLabelIter<'a> {
    name: Option<&'a Name>,
}

impl<'a> Iterator for NameLabelIter<'a> {
    type Item = &'a Label;
    fn next(&mut self) -> Option<Self::Item> {

        if self.name.is_none() {
            return None;
        }

        let (label, remainder) = self.name.unwrap().split_first();
        self.name = remainder;
        Some(label)
    }
}

impl<'a> NameLabelIter<'a> {
    fn new(name: &'a Name) -> Self {
        debug_assert!(name.is_normalized());
        NameLabelIter {
            name: Some(name),
        }
    }
}

mod detail {
    #[derive(Debug)]
    pub struct NotConstructible {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_enforces_length_limit() {

        let ok =
            b"this-is-the-longest-allowed-label-which-is-63-bytes-xxxx-xxxx-x";
        let nok =
            b"this-is-slice-is-one-byte-too-long-to-be-a-valid-label-xxxx-xxxx";

        assert_matches!(Label::from_binary(ok), Ok(_));
        assert_matches!(Label::from_binary(nok), Err(_));
    }

    #[test]
    fn label_is_ascii_case_insensitive() {

        use testing::HashRecorder;

        fn make(s: &[u8]) -> (&Label, HashRecorder) {
            let l = Label::from_binary(s).unwrap();
            let mut h = HashRecorder::new();
            l.hash(&mut h);
            (l, h)
        }

        macro_rules! ok {
            ($lhs:expr,eq, $rhs:expr) => {
                let (lhs, lhash) = make($lhs.as_ref());
                let (rhs, rhash) = make($rhs.as_ref());
                assert_eq!(lhs, rhs);
                assert_eq!(rhs, lhs);
                assert_eq!(lhs.cmp(&rhs), Ordering::Equal);
                assert_eq!(rhs.cmp(&lhs), Ordering::Equal);
                assert_eq!(lhash, rhash);
            };
            ($lhs:expr,lt, $rhs:expr) => {
                let (lhs, lhash) = make($lhs.as_ref());
                let (rhs, rhash) = make($rhs.as_ref());
                assert_ne!(lhs, rhs);
                assert_ne!(rhs, lhs);
                assert_eq!(lhs.cmp(&rhs), Ordering::Less);
                assert_eq!(rhs.cmp(&lhs), Ordering::Greater);
                assert_ne!(lhash, rhash);
            };
        }

        ok!("", eq, "");
        ok!("", lt, "alpha");
        ok!("alpha", eq, "alpha");
        ok!("alpha", lt, "alpha-bravo");
        ok!("alpha", lt, "bravo");
        ok!("alpha", eq, "ALPHA");
        ok!("alpha", lt, "BRAVO");
        ok!("ALPHA", lt, "bravo");

        // Test for transitivity for the case that three labels differ by ASCII
        // case and a character that falls between uppercase and lowercase.
        //
        // (lower == upper) ->
        //  ((lower < between) && (upper < between))
        //  OR
        //  ((between < lower) && (between < upper)).
        //
        // We want to *not* have:
        //
        // upper < between < lower
        // OR
        // lower < between < upper.

        let lower = make(b"alpha").0;
        let upper = make(b"Alpha").0;
        let between = make(b"_lpha").0;

        assert_eq!(lower.cmp(&upper), Ordering::Equal);
        assert_eq!(upper.cmp(&lower), Ordering::Equal);
        assert_eq!(upper.cmp(&between), lower.cmp(&between));
    }

    #[test]
    fn label_formats_to_string() {

        macro_rules! ok {
            (debug, $source:expr) => {{
                let label = Label::from_binary($source).unwrap();
                let result = format!("{:?}", label);
                let mut decoder = text::TextDecoder::new(result.as_bytes());
                let s = decoder.decode_string().unwrap();
                assert_eq!(s.as_ref(), $source);
            }};
            (display, $source:expr) => {{
                let label = Label::from_binary($source).unwrap();
                let result = format!("{}", label);
                let mut decoder = text::TextDecoder::new(result.as_bytes());
                let s = decoder.decode_string().unwrap();
                assert_eq!(s.as_ref(), $source);
            }};
        }

        ok!(debug, b"alpha");
        ok!(debug, b"alpha\0bravo");
        ok!(debug, b"alpha\tbravo");
        ok!(debug, b"alpha\nbravo");
        ok!(debug, b"alpha\rbravo");
        ok!(debug, b"alpha  bravo");
        ok!(debug, b"alpha\"bravo");
        ok!(debug, b"alpha(bravo");
        ok!(debug, b"alpha)bravo");
        ok!(debug, b"alpha;bravo");
        ok!(debug, b"alpha\\bravo");
        ok!(debug, b"alpha.bravo");
        ok!(debug, b"alpha\x7fbravo");
        ok!(debug, b"alpha\xffbravo");

        ok!(display, b"alpha");
        ok!(display, b"alpha\0bravo");
        ok!(display, b"alpha\tbravo");
        ok!(display, b"alpha\nbravo");
        ok!(display, b"alpha\rbravo");
        ok!(display, b"alpha  bravo");
        ok!(display, b"alpha\"bravo");
        ok!(display, b"alpha(bravo");
        ok!(display, b"alpha)bravo");
        ok!(display, b"alpha;bravo");
        ok!(display, b"alpha\\bravo");
        ok!(display, b"alpha.bravo");
        ok!(display, b"alpha\x7fbravo");
        ok!(display, b"alpha\xffbravo");
    }

    #[test]
    fn name_construction_checks_for_errors_and_returns_end_offset() {

        macro_rules! ok {
            ($source:expr, $offset:expr, $extent:expr) => {
                assert_matches!(
                    Name::from_binary_unchecked_with_extent($source, $offset),
                    Ok((_, x)) if x == $extent
                );
            };
        }

        macro_rules! nok {
            ($source:expr, $offset:expr) => {
                assert_matches!(Name::from_binary($source, $offset), Err(_));
            };
        }

        ok!(b"\x00", 0, 1);
        ok!(b"\xff\x00", 1, 2);
        ok!(b"\xff\x05alpha\x05bravo\x07charlie\x00", 1, 22);
        ok!(
            b"\x07charlie\x00\x05bravo\xc0\x00\x05alpha\xc0\x09",
            0,
            9
        );
        ok!(
            b"\x07charlie\x00\x05bravo\xc0\x00\x05alpha\xc0\x09",
            9,
            17
        );
        ok!(
            b"\x07charlie\x00\x05bravo\xc0\x00\x05alpha\xc0\x09",
            17,
            25
        );
        ok!(b"\x05alpha\x00\xc0\x00\xc0\x07\xc0\x09", 11, 13);

        nok!(b"\x00", 1);
        nok!(b"\x05alpha", 0);
        nok!(b"\xc0", 0);
        nok!(b"\xc0\x00", 0);
        nok!(b"\xc0\x01", 0);
        nok!(b"\x05alpha\xc0", 0);
        nok!(b"\x05alpha\xc0\x00", 0);
        nok!(b"\x05alpha\xc0\x01", 0);
        nok!(b"\x05alpha\xc0\x05", 0);
        nok!(b"\x80alpha\x00", 0);
        nok!(b"\x40alpha\x00", 0);

        // Compression offset uses high byte.

        {
            let mut buffer = vec![0xff; 258];
            buffer.extend_from_slice(b"\x05alpha\x00\xc1\x02");
            ok!(&buffer, 258 + 0, 258 + 7);
            ok!(&buffer, 258 + 7, 258 + 9);
        }

        // Domain name too long:

        ok!(
            b"\x090xxx-xxxx\x0910xx-xxxx\x0920xx-xxxx\x0930xx-xxxx\
              \x0940xx-xxxx\x0950xx-xxxx\x0960xx-xxxx\x0970xx-xxxx\
              \x0980xx-xxxx\x0990xx-xxxx\x09100x-xxxx\x09110x-xxxx\
              \x09120x-xxxx\x09130x-xxxx\x09140x-xxxx\x09150x-xxxx\
              \x09160x-xxxx\x09170x-xxxx\x09180x-xxxx\x09190x-xxxx\
              \x09200x-xxxx\x09210x-xxxx\x09220x-xxxx\x09230x-xxxx\
              \x09240x-xxxx\x03250\x00",
            0,
            255
        );

        nok!(
            b"\x090xxx-xxxx\x0910xx-xxxx\x0920xx-xxxx\x0930xx-xxxx\
              \x0940xx-xxxx\x0950xx-xxxx\x0960xx-xxxx\x0970xx-xxxx\
              \x0980xx-xxxx\x0990xx-xxxx\x09100x-xxxx\x09110x-xxxx\
              \x09120x-xxxx\x09130x-xxxx\x09140x-xxxx\x09150x-xxxx\
              \x09160x-xxxx\x09170x-xxxx\x09180x-xxxx\x09190x-xxxx\
              \x09200x-xxxx\x09210x-xxxx\x09220x-xxxx\x09230x-xxxx\
              \x09240x-xxxx\x04250x\x00",
            0
        );
    }

    #[test]
    fn name_label_iteration_follows_compression() {

        let n = Name::from_binary(
            b"\x07charlie\x00\x05bravo\xc0\x00\x05alpha\xc0\x09",
            17,
        ).unwrap();
        let actual = n.labels().collect::<Vec<_>>();
        let expectation: Vec<_> = [
            Label::from_binary(b"alpha").unwrap(),
            Label::from_binary(b"bravo").unwrap(),
            Label::from_binary(b"charlie").unwrap(),
            Label::root(),
        ].iter()
            .map(|x| *x)
            .collect();
        assert_eq!(actual, expectation);
    }

    #[test]
    fn name_provides_case_sensitive_comparison() {

        let n1 =
            Name::from_binary(b"\x05alpha\x05bravo\x07charlie\x00", 0).unwrap();
        let n2 =
            Name::from_binary(b"\x05alpha\x05bravo\x07charlie\x00", 0).unwrap();
        assert!(n1.eq_case_sensitive(&n2));

        let n1 =
            Name::from_binary(b"\x05alpha\x05bravo\x07charlie\x00", 0).unwrap();
        let n2 =
            Name::from_binary(b"\x05AlPhA\x05bRaVo\x07ChArLiE\x00", 0).unwrap();
        assert!(!n1.eq_case_sensitive(&n2));

        let n1 =
            Name::from_binary(b"\x05alpha\x05bravo\x07charlie\x00", 0).unwrap();
        let n2 =
            Name::from_binary(b"\x05alpha\x05bravo\x05delta\x00", 0).unwrap();
        assert!(!n1.eq_case_sensitive(&n2))
    }

    #[test]
    fn name_splits_after_first_label() {

        static SOURCE: &[u8] = b"\x05alpha\x05bravo\x07charlie\x00";

        let n1 = Name::from_binary(SOURCE, 0).unwrap();
        let n2 = Name::from_binary(SOURCE, 6).unwrap();
        let n3 = Name::from_binary(SOURCE, 12).unwrap();
        let n4 = Name::from_binary(SOURCE, 20).unwrap();

        assert_eq!(
            n1.split_first(),
            (Label::from_binary(b"alpha").unwrap(), Some(n2))
        );
        assert_eq!(
            n2.split_first(),
            (Label::from_binary(b"bravo").unwrap(), Some(n3))
        );
        assert_eq!(
            n3.split_first(),
            (
                Label::from_binary(b"charlie").unwrap(),
                Some(n4)
            )
        );
        assert_eq!(n4.split_first(), (Label::root(), None));
    }

    #[test]
    fn name_provides_length() {

        macro_rules! ok {
            ($source:expr, $offset:expr, $length:expr) => {
                let result = Name::from_binary($source, $offset);
                assert_matches!(result, Ok(_));
                assert_eq!(result.unwrap().len(), $length);
            };
        }

        ok!(b"\x00", 0, 1);
        ok!(b"\x05alpha\x00", 0, 7);
        ok!(b"\x05alpha\x05bravo\x07charlie\x00", 0, 21);
        ok!(
            b"\x07charlie\x00\x05bravo\xc0\x00\x05alpha\xc0\x09",
            17,
            21
        );
        ok!(b"\x05alpha\x00\xc0\x00\xc0\x07\xc0\x09", 11, 7);
    }

    #[test]
    fn name_is_empty() {
        assert!(
            Name::from_binary(b"\x00", 0)
                .unwrap()
                .is_empty()
        );
        assert!(
            Name::from_binary(b"alpha\x00", 5)
                .unwrap()
                .is_empty()
        );
        assert!(!Name::from_binary(b"\x05alpha\x00", 0)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn name_pops_front_label() {

        let n =
            Name::from_binary(b"\x05alpha\x05bravo\x07charlie\x00", 0).unwrap();

        let mut popped = n;
        assert_eq!(
            popped,
            Name::from_binary(b"\x05alpha\x05bravo\x07charlie\x00", 0).unwrap()
        );

        popped = popped.pop_front().unwrap();
        assert_eq!(
            popped,
            Name::from_binary(b"\x05bravo\x07charlie\x00", 0).unwrap()
        );

        popped = popped.pop_front().unwrap();
        assert_eq!(
            popped,
            Name::from_binary(b"\x07charlie\x00", 0).unwrap()
        );

        popped = popped.pop_front().unwrap();
        assert_eq!(popped, Name::from_binary(b"\x00", 0).unwrap());

        assert!(popped.pop_front().is_none());
    }

    #[test]
    fn name_buf_decodes_text() {

        macro_rules! ok {
            ($text:expr, $origin:expr, $binary:expr, $remainder:expr) => {
                let mut d = TextDecoder::new($text);
                d.set_origin(
                    $origin.map(|x| {
                        Name::from_binary(x, 0).unwrap().to_owned()
                    }));
                assert_matches!(
                    NameBuf::decode_text(&mut d),
                    Ok(ref x) if x == Name::from_binary($binary, 0).unwrap()
                );
                assert_eq!(d.peek(), $remainder);
            };
        }

        macro_rules! nok {
            ($text:expr, $origin:expr) => {{
                let mut d = TextDecoder::new($text);
                d.set_origin(
                    $origin.map(|x| Name::from_binary(x, 0).unwrap().to_owned()),
                );
                assert_matches!(
                                    NameBuf::decode_text(&mut d),
                                    Err(ref e) if
                                        e.expectation() == EXPECTATION_NAME &&
                                        e.position() == TextPosition::zero()
                                );
            }};
        }

        // Verify: The text input may contain a fully qualified domain name.

        ok!(b".", None, b"\x00", b"");
        ok!(b"alpha.", None, b"\x05alpha\x00", b"");
        ok!(
            b"alpha.bravo.",
            None,
            b"\x05alpha\x05bravo\x00",
            b""
        );

        // Verify: The text input may contain a partially qualified domain name
        // if the origin is set.

        ok!(b"alpha", Some(b"\x00"), b"\x05alpha\x00", b"");
        ok!(
            b"alpha",
            Some(b"\x05bravo\x00"),
            b"\x05alpha\x05bravo\x00",
            b""
        );

        // Verify: The text input may be quoted.

        ok!(
            b"\"alpha bravo.\"",
            None,
            b"\x0balpha bravo\x00",
            b""
        );

        // Verify: The text input may be escaped.

        ok!(
            b"alpha\\ bravo.",
            None,
            b"\x0balpha bravo\x00",
            b""
        );
        ok!(
            b"alpha\\.bravo.",
            None,
            b"\x0balpha.bravo\x00",
            b""
        );

        // Verify: The text input must not be empty, regardless whether the
        // origin is set.

        nok!(b"", None);
        nok!(b"", Some(b"\x05bravo\x00"));

        // Verify: The text input must not contain a partially qualified domain
        // name if the origin is not set.

        nok!(b"alpha", None);

        // Verify: If the text input is fully qualified, then the origin is
        // ignored.

        ok!(b".", Some(b"\x05bravo\x00"), b"\x00", b"");
        ok!(
            b"alpha.",
            Some(b"\x05bravo\x00"),
            b"\x05alpha\x00",
            b""
        );

        // Verify: Any empty label must be last.

        nok!(b"alpha..bravo.", None);
        nok!(b"..alpha.bravo.", None);
        nok!(b".alpha.bravo..", None);
        nok!(b"..", None);

        // Verify: Spaces must be escaped.

        nok!(b"alpha bravo.", None);

        // Verify: Labels must not exceed the maximum length.

        ok!(
            b"0xxx-xxxx-10xx-xxxx-20xx-xxxx-30xx-xxxx-40xx-xxxx-50xx-xxxx-60x.",
            None,
            b"\x3f0xxx-xxxx-10xx-xxxx-20xx-xxxx-30xx-xxxx-40xx-xxxx-50xx-xxxx-60x\x00",
            b""
        );

        nok!(
            b"0xxx-xxxx-10xx-xxxx-20xx-xxxx-30xx-xxxx-40xx-xxxx-50xx-xxxx-60xx.",
            None
        );

        // Verify: The domain name must not exceed the maximum length, including
        // the origin if the origin is set.

        ok!(
            b"0xxx-xxxx.10xx-xxxx.20xx-xxxx.30xx-xxxx.\
              40xx-xxxx.50xx-xxxx.60xx-xxxx.70xx-xxxx.\
              80xx-xxxx.90xx-xxxx.100x-xxxx.110x-xxxx.\
              120x-xxxx.130x-xxxx.140x-xxxx.150x-xxxx.\
              160x-xxxx.170x-xxxx.180x-xxxx.190x-xxxx.\
              200x-xxxx.210x-xxxx.220x-xxxx.230x-xxxx.\
              240x-xxxx.250.",
            None,
            b"\x090xxx-xxxx\x0910xx-xxxx\x0920xx-xxxx\x0930xx-xxxx\
              \x0940xx-xxxx\x0950xx-xxxx\x0960xx-xxxx\x0970xx-xxxx\
              \x0980xx-xxxx\x0990xx-xxxx\x09100x-xxxx\x09110x-xxxx\
              \x09120x-xxxx\x09130x-xxxx\x09140x-xxxx\x09150x-xxxx\
              \x09160x-xxxx\x09170x-xxxx\x09180x-xxxx\x09190x-xxxx\
              \x09200x-xxxx\x09210x-xxxx\x09220x-xxxx\x09230x-xxxx\
              \x09240x-xxxx\x03250\x00",
            b""
        );

        nok!(
            b"0xxx-xxxx.10xx-xxxx.20xx-xxxx.30xx-xxxx.\
              40xx-xxxx.50xx-xxxx.60xx-xxxx.70xx-xxxx.\
              80xx-xxxx.90xx-xxxx.100x-xxxx.110x-xxxx.\
              120x-xxxx.130x-xxxx.140x-xxxx.150x-xxxx.\
              160x-xxxx.170x-xxxx.180x-xxxx.190x-xxxx.\
              200x-xxxx.210x-xxxx.220x-xxxx.230x-xxxx.\
              240x-xxxx.250x.",
            None
        );

        ok!(
            b"0xxx-xxxx.10xx-xxxx.20xx-xxxx.30xx-xxxx.\
              40xx-xxxx.50xx-xxxx.60xx-xxxx.70xx-xxxx.\
              80xx-xxxx.90xx-xxxx.100x-xxxx.110x-xxxx.\
              120x-xxxx.130x-xxxx.140x-xxxx.150x-xxxx.\
              160x-xxxx.170x-xxxx.180x-xxxx.190x-xxxx.\
              200x-xxxx.210x-xxxx.220x-xxxx.230x-xxxx.\
              240x-xxxx",
            Some(b"\x03xxx\x00"),
            b"\x090xxx-xxxx\x0910xx-xxxx\x0920xx-xxxx\x0930xx-xxxx\
              \x0940xx-xxxx\x0950xx-xxxx\x0960xx-xxxx\x0970xx-xxxx\
              \x0980xx-xxxx\x0990xx-xxxx\x09100x-xxxx\x09110x-xxxx\
              \x09120x-xxxx\x09130x-xxxx\x09140x-xxxx\x09150x-xxxx\
              \x09160x-xxxx\x09170x-xxxx\x09180x-xxxx\x09190x-xxxx\
              \x09200x-xxxx\x09210x-xxxx\x09220x-xxxx\x09230x-xxxx\
              \x09240x-xxxx\x03xxx\x00",
            b""
        );

        nok!(
            b"0xxx-xxxx.10xx-xxxx.20xx-xxxx.30xx-xxxx.\
              40xx-xxxx.50xx-xxxx.60xx-xxxx.70xx-xxxx.\
              80xx-xxxx.90xx-xxxx.100x-xxxx.110x-xxxx.\
              120x-xxxx.130x-xxxx.140x-xxxx.150x-xxxx.\
              160x-xxxx.170x-xxxx.180x-xxxx.190x-xxxx.\
              200x-xxxx.210x-xxxx.220x-xxxx.230x-xxxx.\
              240x-xxxx",
            Some(b"\x04xxxx\x00")
        );
    }

    #[test]
    fn name_buf_fails_to_from_text_with_extra_data_after_name() {
        assert_matches!(NameBuf::from_text(b"alpha. bravo"), Err(_));
    }

    #[test]
    fn name_buf_constructs_from_labels_unchecked() {
        assert_eq!(
            unsafe {
                NameBuf::from_labels_unchecked(
                    vec![
                        Label::from_binary(b"alpha").unwrap(),
                        Label::from_binary(b"bravo").unwrap(),
                        Label::root(),
                    ].iter(),
                )
            },
            Name::from_binary(b"\x05alpha\x05bravo\x00", 0).unwrap()
        );
    }

    #[test]
    fn root_name_buf_eq_root_name() {
        assert_eq!(NameBuf::root(), Name::root());
        assert_eq!(Name::root(), &NameBuf::root());
    }

    #[test]
    fn name_compares_with_name_buf() {

        let b1 = Name::from_binary(b"\x05alpha\x00", 0).unwrap();
        let b2 = Name::from_binary(b"\x05bravo\x00", 0).unwrap();

        let o1 = b1.to_owned();
        let o2 = b2.to_owned();

        let c1 = Cow::Borrowed(b1);
        let c2 = Cow::Borrowed(b2);

        // lhs: Name

        assert_eq!(b1, o1);
        assert_ne!(b1, o2);
        assert!(!(b1 < o1));
        assert!(b1 < o2);

        assert_eq!(b1, &o1);
        assert_ne!(b1, &o2);
        assert!(!(b1 < &o1));
        assert!(b1 < &o2);

        assert_eq!(b1, c1);
        assert_ne!(b1, c2);
        assert!(!(b1 < c1));
        assert!(b1 < c2);

        assert_eq!(b1, &c1);
        assert_ne!(b1, &c2);
        assert!(!(b1 < &c1));
        assert!(b1 < &c2);

        // lhs: NameBuf

        assert_eq!(o1, b1);
        assert_ne!(o1, b2);
        assert!(!(o1 < b1));
        assert!(o1 < b2);

        assert_eq!(&o1, b1);
        assert_ne!(&o1, b2);
        assert!(!(&o1 < b1));
        assert!(&o1 < b2);

        assert_eq!(o1, c1);
        assert_ne!(o1, c2);
        assert!(!(o1 < c1));
        assert!(o1 < c2);

        // lhs: Cow<Name>

        assert_eq!(c1, b1);
        assert_ne!(c1, b2);
        assert!(!(c1 < b1));
        assert!(c1 < b2);

        assert_eq!(&c1, b1);
        assert_ne!(&c1, b2);
        assert!(!(&c1 < b1));
        assert!(&c1 < b2);

        assert_eq!(c1, o1);
        assert_ne!(c1, o2);
        assert!(!(c1 < o1));
        assert!(c1 < o2);
    }

    #[test]
    fn name_formats_to_string() {

        macro_rules! ok {
            ($source:expr) => {{
                let source = Name::from_binary($source, 0).unwrap();
                let text = format!("{}", source);
                match NameBuf::from_text(text.as_bytes()) {
                    Ok(ref x) if *x == source => {}
                    x => panic!("Got unexpected display result {:?}", x),
                }

                let text = format!("{:?}", source);
                match NameBuf::from_text(text.as_bytes()) {
                    Ok(ref x) if *x == source => {}
                    x => panic!("Got unexpected debug result {:?}", x),
                }
            }};
        }

        ok!(b"\x00");
        ok!(b"\x05alpha\x00");
        ok!(b"\x05alpha\x05bravo\x00");
        ok!(b"\x0balpha\0bravo\x00");
        ok!(b"\x0balpha\tbravo\x00");
        ok!(b"\x0balpha\nbravo\x00");
        ok!(b"\x0balpha\rbravo\x00");
        ok!(b"\x0balpha bravo\x00");
        ok!(b"\x0balpha\"bravo\x00");
        ok!(b"\x0balpha(bravo\x00");
        ok!(b"\x0balpha)bravo\x00");
        ok!(b"\x0balpha.bravo\x00");
        ok!(b"\x0balpha;bravo\x00");
        ok!(b"\x0balpha\\bravo\x00");
        ok!(b"\x0balpha\x7fbravo\x00");
        ok!(b"\x0balpha\xffbravo\x00");
    }

    #[test]
    fn name_encodes_and_name_buf_decodes_as_text() {

        let source =
            Name::from_binary(b"\x0balpha bravo\x07charlie\x00", 0).unwrap();

        let mut encoder = TextEncoder::new(Vec::new());
        source.encode_text(&mut encoder).unwrap();
        let text = encoder.into_writer();

        let mut decoder = TextDecoder::new(&text);
        assert_matches!(
            NameBuf::decode_text(&mut decoder),
            Ok(ref x) if *x == source
        );
    }

    #[test]
    fn name_encodes_and_decodes_as_binary() {

        let source =
            Name::from_binary(b"\x0balpha bravo\x07charlie\x00", 0).unwrap();

        let mut encoder = BinaryEncoder::new();
        source.encode_binary(&mut encoder).unwrap();
        let binary = encoder.into_buffer();

        let mut decoder = BinaryDecoder::new(&binary);
        assert_matches!(
            <&Name>::decode_binary(&mut decoder),
            Ok(ref x) if *x == source
        );
    }

    #[test]
    fn name_buf_impls_from_name() {
        let source = Name::from_binary(b"\x05alpha\x00", 0).unwrap();
        let actual = NameBuf::from(source);
        assert_eq!(actual, source);
    }

    #[test]
    fn name_buf_impls_from_cow_name() {
        let source = Name::from_binary(b"\x05alpha\x00", 0).unwrap();
        let actual = NameBuf::from(Cow::Borrowed(source));
        assert_eq!(actual, source);

        let actual = NameBuf::from(Cow::Owned(source.to_owned()));
        assert_eq!(actual, source);
    }

    #[test]
    fn name_formats_as_text_form() {

        macro_rules! ok {
            ($source:expr) => {
                let source = Name::from_binary($source, 0).unwrap();
                let text = format!("{:?}", source);
                assert_matches!(
                                    NameBuf::from_text(text.as_bytes()),
                                    Ok(ref n) if n == source
                                );
                let text = format!("{}", source);
                assert_matches!(
                                    NameBuf::from_text(text.as_bytes()),
                                    Ok(ref n) if n == source
                                );
            };
        }

        ok!(b"\x00");
        ok!(b"\x05alpha\x05bravo\x07charlie\x00");
        ok!(b"\0balpha.bravo\x0dcharlie.delta\x00");
        ok!(b"\0balpha bravo\x0dcharlie delta\x00");
    }
}
