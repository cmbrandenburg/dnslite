//! The `text` module provides functionality for encoding and decoding text
//! data in zone-file format.

use {BoxedError, Name, NameBuf, ascii, std};
use error::EEndOfInput;
use std::borrow::Cow;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;

/// The `prelude` module provides definitions for implementing text-encoding and
/// text-decoding for a custom type.
pub mod prelude {
    pub use super::{DecodeText, EncodeText, TextDecodeError, TextDecodeMode,
                    TextDecoder, TextEncodeError, TextEncodeMode, TextEncoder,
                    TextPosition};
}

declare_static_error_type!(EBadEscape, "Escape sequence is ill-formed");
declare_static_error_type!(EParenNotClosed, "Parenthesis '(' is not closed");
declare_static_error_type!(EParenNotMatched, "Parenthesis ')' is not matched");
declare_static_error_type!(EParensTooDeep, "Parentheses are nested too deeply");
declare_static_error_type!(EQuoteNotClosed, "Quote is not closed");

#[doc(hidden)]
#[derive(Debug, PartialEq)]
pub struct EBadChar(pub u8);

impl Display for EBadChar {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "Got unexpected character {:?} (0x{:x})",
            self.0 as char,
            self.0
        )
    }
}

impl std::error::Error for EBadChar {
    fn description(&self) -> &str {
        "Got unexpected character"
    }
}

/// `DecodeText` is a trait for reading an object from its text form.
pub trait DecodeText<'a, M: TextDecodeMode>: Sized {
    /// Constructs the object using a text decoder.
    fn decode_text(d: &mut TextDecoder<'a, M>)
        -> Result<Self, TextDecodeError>;
}

/// `TextDecoder` reads text data from a buffer.
///
/// `TextDecoder` provides low-level access for reading text data. Typically, an
/// application would use the [`DecodeText`](trait.DecodeText.html) trait
/// instead of calling `TextDecoder`
/// methods directly.
///
/// A `TextDecoder` instance is always in one of the following two modes.
///
/// * In **normal mode**, the text decoder reads text outside of an RDATA part.
/// * In **RDATA mode**, the text decoder reads text inside an RDATA part.
///
/// The reason for having two different modes is that RDATA mode specially
/// handles parentheses and line breaks between fields.
///
/// `TextDecoder` can decode tokens and strings in either mode, but other
/// operations are limited by mode.
///
#[derive(Clone, Debug)]
pub struct TextDecoder<'a, M: TextDecodeMode> {
    cursor: &'a [u8],
    position: TextPosition,
    string_continuation: StringContinuation,
    rdata_paren_depth: u32,
    origin: Option<NameBuf>,
    _mode: PhantomData<M>,
}

#[derive(Clone, Debug, PartialEq)]
enum StringContinuation {
    None,
    Unquoted,
    Quoted,
}

#[doc(hidden)]
pub trait TextDecodeMode: Sized {
    fn decode_leader(
        decoder: &mut TextDecoder<Self>,
        expectation: &'static str,
    ) -> Result<(), TextDecodeError>;
}

#[doc(hidden)]
#[derive(Debug)]
pub struct NormalMode {}

#[doc(hidden)]
#[derive(Debug)]
pub struct RDataMode {}

impl TextDecodeMode for NormalMode {
    fn decode_leader(
        decoder: &mut TextDecoder<Self>,
        _expectation: &'static str,
    ) -> Result<(), TextDecodeError> {
        decoder.decode_whitespace();
        Ok(())
    }
}

impl TextEncodeMode for NormalMode {}

impl TextDecodeMode for RDataMode {
    fn decode_leader(
        decoder: &mut TextDecoder<Self>,
        expectation: &'static str,
    ) -> Result<(), TextDecodeError> {
        loop {
            decoder.decode_whitespace();

            if decoder.cursor.is_empty() {
                return Ok(());
            }

            if decoder.cursor.starts_with(b")") {
                if 0 == decoder.rdata_paren_depth {
                    return Err(TextDecodeError::new(
                        expectation,
                        decoder.position,
                        EParenNotMatched,
                    ));
                }
                decoder.rdata_paren_depth -= 1;
                decoder.advance_cursor(1, false);
                continue;
            }

            if decoder.cursor.starts_with(b"(") {
                match decoder.rdata_paren_depth.checked_add(1) {
                    None => {
                        return Err(TextDecodeError::new(
                            expectation,
                            decoder.position,
                            EParensTooDeep,
                        ));
                    }
                    Some(x) => {
                        decoder.rdata_paren_depth = x;
                        decoder.advance_cursor(1, false);
                    }
                };
                continue;
            }

            if 1 <= decoder.rdata_paren_depth &&
                decoder.cursor.starts_with(b"\r\n")
            {
                decoder.advance_cursor(2, true);
                continue;
            }

            if 1 <= decoder.rdata_paren_depth &&
                decoder.cursor.starts_with(b"\n")
            {
                decoder.advance_cursor(1, true);
                continue;
            }

            if decoder.cursor.starts_with(b";") {
                decoder.decode_line();
                continue;
            }

            return Ok(());
        }
    }
}

impl TextEncodeMode for RDataMode {}

impl<'a> TextDecoder<'a, NormalMode> {
    /// Constructs a text decoder that reads from a buffer.
    ///
    /// The newly constructed text decoder has its cursor pointing to the first
    /// byte of the source buffer.
    ///
    pub fn new(text: &'a [u8]) -> Self {
        TextDecoder {
            cursor: text,
            position: TextPosition::zero(),
            string_continuation: StringContinuation::None,
            rdata_paren_depth: 0,
            origin: None,
            _mode: PhantomData,
        }
    }

    /// Reads the end of the buffer.
    ///
    /// This method consumes all contiguous space and tab characters starting at
    /// the cursor. The call succeeds if it reaches the end of the buffer.
    /// Otherwise, it fails and leaves the text decoder in a valid but
    /// unspecified state.
    ///
    pub fn decode_end_of_file(&mut self) -> Result<(), TextDecodeError> {

        const EXPECTATION: &str = "end of input";

        NormalMode::decode_leader(self, EXPECTATION)?;

        if !self.cursor.is_empty() {
            return Err(TextDecodeError::new(
                EXPECTATION,
                self.position,
                EBadChar(self.cursor[0]),
            ));
        }
        Ok(())
    }

    /// Reads a line break.
    ///
    /// This method consumes all contiguous space and tab characters starting at
    /// the cursor. Then it consumes the first line break, if available, in
    /// which case the call succeeds. Otherwise, if the buffer at the cursor
    /// contains something other than a line break (or the end of input), then
    /// the call fails and leaves the text decoder in a valid but unspecified
    /// state.
    ///
    pub fn decode_end_of_line(&mut self) -> Result<(), TextDecodeError> {
        const EXPECTATION: &str = "end of line";
        NormalMode::decode_leader(self, EXPECTATION)?;
        self.decode_end_of_line_impl(EXPECTATION)
    }

    /// Transforms the text decoder into RDATA mode.
    pub fn begin_rdata(mut self) -> TextDecoder<'a, RDataMode> {

        self.rdata_paren_depth = 0;

        TextDecoder {
            cursor: self.cursor,
            position: self.position,
            string_continuation: self.string_continuation,
            rdata_paren_depth: self.rdata_paren_depth,
            origin: self.origin,
            _mode: PhantomData,
        }
    }
}

impl<'a> TextDecoder<'a, RDataMode> {
    /// Transforms the text decoder into normal mode.
    ///
    /// This method consumes any remaining legal whitespace, parentheses, and
    /// line breaks in the RDATA part, including the final, RDATA-terminating
    /// line break.
    ///
    pub fn end_rdata(
        mut self,
    ) -> Result<TextDecoder<'a, NormalMode>, TextDecodeError> {

        const EXPECTATION: &str = "end of RDATA";

        RDataMode::decode_leader(&mut self, EXPECTATION)?;

        if 1 <= self.rdata_paren_depth {
            return Err(TextDecodeError::new(
                EXPECTATION,
                self.position,
                EParenNotClosed,
            ));
        }

        self.decode_end_of_line_impl(EXPECTATION)?;

        Ok(TextDecoder {
            cursor: self.cursor,
            position: self.position,
            string_continuation: self.string_continuation,
            rdata_paren_depth: self.rdata_paren_depth,
            origin: self.origin,
            _mode: PhantomData,
        })
    }
}

impl<'a, M: TextDecodeMode> TextDecoder<'a, M> {
    /// Returns the source buffer sliced at the cursor.
    pub fn peek(&self) -> &'a [u8] {
        self.cursor
    }

    /// Returns the cursor offset.
    pub fn position(&self) -> TextPosition {
        self.position
    }

    fn decode_end_of_line_impl(
        &mut self,
        expectation: &'static str,
    ) -> Result<(), TextDecodeError> {

        if self.cursor.is_empty() {
            // Nothing to do.
        } else if self.cursor.starts_with(b"\r\n") {
            self.advance_cursor(2, true);
        } else if self.cursor.starts_with(b"\n") {
            self.advance_cursor(1, true);
        } else {
            return Err(TextDecodeError::new(
                expectation,
                self.position,
                EBadChar(self.cursor[0]),
            ));
        }

        Ok(())
    }

    /// Sets the domain name origin.
    ///
    /// If the origin is set, then any decoded domain name that isn't fully
    /// qualified will have the origin appended to it.
    ///
    pub fn set_origin(&mut self, origin: Option<NameBuf>) {
        self.origin = origin;
    }

    /// Gets the domain name origin, if available.
    pub fn origin(&self) -> Option<&Name> {
        self.origin.as_ref().map(|x| x.as_ref())
    }

    /// Reads the next field as a token.
    ///
    /// This method consumes all contiguous space and tab characters starting at
    /// the cursor, as well as relevant parentheses and line breaks if the
    /// decoder is in RDATA mode. Then it consumes the token at the cursor,
    /// which is a contiguous and nonempty sequence of bytes delimited by
    /// whitespace, parentheses, quote, or a comment. If no valid token exists,
    /// then the call fails and leaves the text decoder in a valid but
    /// unspecified state.
    ///
    pub fn decode_token(&mut self) -> Result<&'a [u8], TextDecodeError> {

        const DELIMS: &[u8] = b" \t\r\n\"();";
        const EXPECTATION: &str = "token";

        M::decode_leader(self, EXPECTATION)?;

        if self.cursor.is_empty() {
            return Err(TextDecodeError::new(
                EXPECTATION,
                self.position,
                EEndOfInput,
            ));
        }

        let orig_buffer = self.cursor;

        loop {
            let n = self.cursor
                .iter()
                .position(|&b| DELIMS.iter().any(|&delim| delim == b))
                .unwrap_or_else(|| self.cursor.len());

            self.advance_cursor(n, false);

            if self.cursor.starts_with(b"\r") &&
                !self.cursor.starts_with(b"\r\n")
            {
                self.advance_cursor(1, false);
                continue;
            }

            break;
        }

        let token_len = orig_buffer.len() - self.cursor.len();

        if token_len == 0 {
            debug_assert!(!self.cursor.is_empty());
            return Err(TextDecodeError::new(
                EXPECTATION,
                self.position,
                EBadChar(self.cursor[0]),
            ));
        }

        Ok(&orig_buffer[..token_len])
    }

    /// Reads the next field as a character string.
    ///
    /// This method consumes all contiguous space and tab characters starting at
    /// the cursor, as well as relevant parentheses and line breaks if the
    /// decoder is in RDATA mode. Then it consumes the character string at the
    /// cursor, whose format is specified in [RFC 1035, section
    /// 5.1](https://tools.ietf.org/html/rfc1035). If no valid character string
    /// exists, then the call fails and leaves the text decoder in a valid but
    /// unspecified state.
    ///
    pub fn decode_string(&mut self) -> Result<Cow<'a, [u8]>, TextDecodeError> {
        self.decode_string_impl(None).map(|(s, _)| s)
    }

    /// Reads the next field as a multi-part character string.
    ///
    /// This method consumes all contiguous space and tab characters starting at
    /// the cursor, as well as relevant parentheses and line breaks if the
    /// decoder is in RDATA mode. Then it returns an iterator that consumes the
    /// character string at the cursor, part by part. The character string
    /// format is specified in [RFC 1035, section
    /// 5.1](https://tools.ietf.org/html/rfc1035).
    ///
    /// The difference between this method and the
    /// [`decode_string`](#method.decode_string) method is that the caller can
    /// use this method to distinguish between escaped separators and
    /// non-escaped separators, whereas single-part strings make no such
    /// distinction. Practically speaking, this method is used for parsing
    /// domain names, where the separator is the `'.'` character, whereas other
    /// DNS character-string types are parsed as single-part strings.
    ///
    /// The returned iterator must be drained or else the text decoder will be
    /// left in a valid but unspecified state. The reason the iterator does not
    /// self-drain (via the `Drop` trait) is that it cannot correctly handle
    /// errors.
    ///
    pub fn decode_multi_string<'b>(
        &'b mut self,
        separator: u8,
    ) -> TextDecoderMultiStringIter<'a, 'b, M> {
        TextDecoderMultiStringIter {
            decoder: self,
            separator,
            done: false,
        }
    }

    fn decode_string_impl(
        &mut self,
        separator: Option<u8>,
    ) -> Result<(Cow<'a, [u8]>, bool), TextDecodeError> {

        const EXPECTATION: &str = "character string";

        fn is_u8_unquoted_delim(b: u8) -> bool {
            const DELIMS: &[u8] = b" \t\r\n\"()\\;";
            DELIMS.contains(&b)
        }

        fn is_u8_quoted_delim(b: u8) -> bool {
            const DELIMS: &[u8] = b"\r\n\"\\";
            DELIMS.contains(&b)
        }

        if self.string_continuation == StringContinuation::None {

            M::decode_leader(self, EXPECTATION)?;
        }

        let quoted = match self.string_continuation {
            StringContinuation::Quoted => true,
            StringContinuation::Unquoted => false,
            StringContinuation::None => {
                match self.cursor.first().cloned() {
                    None => return Err(TextDecodeError::new(
                        EXPECTATION,
                        self.position,
                        EEndOfInput,
                    )),
                    Some(b'"') => {
                        self.advance_cursor(1, false);
                        true
                    }
                    Some(b) if is_u8_unquoted_delim(b) => {
                        return Err(TextDecodeError::new(
                            EXPECTATION,
                            self.position,
                            EBadChar(b),
                        ));
                    }
                    _ => false,
                }
            }
        };

        self.string_continuation = StringContinuation::None;

        let mut capture = Capture::Borrowed {
            buffer: self.cursor,
            length: 0,
        };

        loop {

            // Find the next byte that we may interpret in a special way.

            let n = self.cursor
                .iter()
                .position(|&b| if quoted {
                    is_u8_quoted_delim(b)
                } else {
                    is_u8_unquoted_delim(b)
                } ||
                    separator.as_ref().map_or(false, |&delim| delim == b))
                .unwrap_or_else(|| self.cursor.len());

            capture.extend(&self.cursor[..n]);
            self.advance_cursor(n, false);

            match (quoted, self.cursor.first()) {
                (_, Some(&b'\\')) if self.cursor.len() == 1 => {
                    return Err(TextDecodeError::new(
                        EXPECTATION,
                        self.position,
                        EBadEscape,
                    ));
                }
                (_, Some(&b'\\'))
                    if ascii::is_u8_ascii_digit(self.cursor[1]) => {
                    let n_digits = self.cursor[1..]
                        .iter()
                        .take(3)
                        .filter(|&&b| ascii::is_u8_ascii_digit(b))
                        .count();
                    if n_digits != 3 {
                        return Err(TextDecodeError::new(
                            EXPECTATION,
                            self.position,
                            EBadEscape,
                        ));
                    }
                    let m = 100 * u16::from(self.cursor[1] - b'0') +
                        10 * u16::from(self.cursor[2] - b'0') +
                        u16::from(self.cursor[3] - b'0');
                    if 256 <= m {
                        return Err(TextDecodeError::new(
                            EXPECTATION,
                            self.position,
                            EBadEscape,
                        ));
                    }
                    capture.take_ownership_if_borrowed();
                    capture.push(m as u8);
                    self.advance_cursor(4, false);
                }
                (_, Some(&b'\\'))
                    if self.cursor[1] == b'\n' || self.cursor[1] == b'\r' => {
                    return Err(TextDecodeError::new(
                        EXPECTATION,
                        self.position,
                        EBadEscape,
                    ));
                }
                (_, Some(&b'\\')) => {
                    capture.take_ownership_if_borrowed();
                    capture.push(self.cursor[1]);
                    self.advance_cursor(2, false);
                }
                (_, Some(&b'\r')) if !self.cursor.starts_with(b"\r\n") => {
                    capture.push(self.cursor[0]);
                    self.advance_cursor(1, false);
                }
                (false, None) => return Ok((capture.into_cow(), false)),
                (false, Some(&b)) if is_u8_unquoted_delim(b) => {
                    return Ok((capture.into_cow(), false));
                }
                (true, None) |
                (true, Some(&b'\r')) |
                (true, Some(&b'\n')) => {
                    return Err(TextDecodeError::new(
                        EXPECTATION,
                        self.position,
                        EQuoteNotClosed,
                    ));
                }
                (true, Some(&b'"')) => {
                    self.advance_cursor(1, false); // consume quote
                    return Ok((capture.into_cow(), false));
                }
                (_, Some(&b)) => {
                    debug_assert_eq!(b, separator.unwrap());
                    self.advance_cursor(1, false); // consume separator
                    self.string_continuation = if quoted {
                        StringContinuation::Quoted
                    } else {
                        StringContinuation::Unquoted
                    };
                    return Ok((capture.into_cow(), true));
                }
            }
        }
    }

    fn decode_line(&mut self) -> &'a [u8] {
        let n = self.cursor
            .iter()
            .position(|&b| b == b'\n')
            .unwrap_or_else(|| self.cursor.len());
        let mut line = &self.cursor[..n];
        if line.ends_with(b"\r") {
            line = &line[..line.len() - 1];
        }
        self.advance_cursor(n, false);
        line
    }

    fn decode_whitespace(&mut self) -> bool {
        let n = self.cursor
            .iter()
            .position(|&b| !is_u8_space(b))
            .unwrap_or_else(|| self.cursor.len());
        self.advance_cursor(n, false);
        0 < n
    }

    fn advance_cursor(&mut self, n: usize, eol: bool) {
        debug_assert!(
            n == 0 || self.cursor[..n - 1].iter().all(|b| b != &b'\n')
        );
        debug_assert_eq!(eol, 0 < n && self.cursor[n - 1] == b'\n');
        self.cursor = &self.cursor[n..];
        self.position.byte += n as u64;
        if eol {
            self.position.line += 1;
            self.position.column = 0;
        } else {
            self.position.column += n as u64;
        }
    }
}

/// `TextDecoderMultiStringIter` iterates through the parts of a multi-part text
/// string.
#[derive(Debug)]
pub struct TextDecoderMultiStringIter<'a: 'b, 'b, M: 'a + TextDecodeMode> {
    decoder: &'b mut TextDecoder<'a, M>,
    separator: u8,
    done: bool,
}

impl<'a, 'b, M: TextDecodeMode> Iterator
    for TextDecoderMultiStringIter<'a, 'b, M> {
    type Item = Result<Cow<'a, [u8]>, TextDecodeError>;
    fn next(&mut self) -> Option<Self::Item> {

        if self.done {
            return None;
        }

        match self.decoder.decode_string_impl(Some(self.separator)) {
            Err(e) => Some(Err(e)),
            Ok((part, more)) => {
                debug_assert!(!self.done);
                self.done = !more;
                Some(Ok(part))
            }
        }
    }
}

/// `TextDecodeError` describes an error that resulted from reading text data.
///
/// A `TextDecodeError` instance is returned by methods that parse text data via
/// [`TextDecoder`](struct.TextDecoder.html).
///
/// `TextDecodeError` contains the following three properties.
///
/// * An **expectation** describing what was being decoded (e.g., `"character
///   string"` or `"domain name"`),
/// * A **position** describing where in the text data the error occurred, and,
/// * An underlying **cause** describing what why the error occurred.
///
#[derive(Debug)]
pub struct TextDecodeError {
    expectation: &'static str,
    position: TextPosition,
    cause: BoxedError,
}

impl Display for TextDecodeError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{} (expectation: {}, line: {}, column: {}, byte: {}): {}",
            std::error::Error::description(self),
            self.expectation,
            self.position.line,
            self.position.column,
            self.position.byte,
            self.cause
        )
    }
}

impl std::error::Error for TextDecodeError {
    fn description(&self) -> &str {
        "Failed to decode text data"
    }
}

impl TextDecodeError {
    pub fn new<E: Into<BoxedError>>(
        expectation: &'static str,
        position: TextPosition,
        cause: E,
    ) -> Self {
        TextDecodeError {
            expectation,
            position,
            cause: cause.into(),
        }
    }

    pub fn expectation(&self) -> &'static str {
        self.expectation
    }

    pub fn set_expectation(&mut self, expectation: &'static str) {
        self.expectation = expectation
    }

    pub fn position(&self) -> TextPosition {
        self.position
    }

    pub fn cause(&self) -> &BoxedError {
        &self.cause
    }

    pub fn into_cause(self) -> BoxedError {
        self.cause
    }
}

/// `TextPosition` specifies a location within a text stream.
///
/// A `TextPosition` instance is a triple specifying a **line number**, **column
/// number**, and **byte offset**. By convention, all three values are
/// zero-based—i.e., the first line is 0, the first column of a line is 0, etc.
///
/// The purpose of `TextPosition` is as a property of
/// [`TextDecodeError`](struct.TextDecodeError.html) specifying where in the
/// text stream the error occurred.
///
/// # Examples
///
/// ```rust
/// use dnslite::text::TextPosition;
///
/// let p = TextPosition::zero();
/// assert_eq!(p, TextPosition::new(0, 0, 0));
///
/// assert_eq!(p.line(), 0);
/// assert_eq!(p.column(), 0);
/// assert_eq!(p.byte(), 0);
/// ```
///
///
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TextPosition {
    line: u64,
    column: u64,
    byte: u64,
}

impl TextPosition {
    /// Constructs a zero-value text position.
    pub fn zero() -> Self {
        Self::default()
    }

    pub fn new(line: u64, column: u64, byte: u64) -> Self {
        TextPosition { line, column, byte }
    }

    pub fn line(&self) -> u64 {
        self.line
    }

    pub fn column(&self) -> u64 {
        self.column
    }

    pub fn byte(&self) -> u64 {
        self.byte
    }
}

/// `EncodeText` is a trait for writing an object to its text form.
pub trait EncodeText {
    /// Writes the object to a text encoder.
    fn encode_text<W: std::io::Write, M: TextEncodeMode>(
        &self,
        encoder: &mut TextEncoder<W, M>,
    ) -> Result<(), TextEncodeError>;
}

/// `TextEncoder` writes text data.
///
/// `TextEncoder` provides low-level access for writing text data. Typically, an
/// application would use the [`EncodeText`](trait.EncodeText.html) trait
/// instead of calling `TextEncoder` methods directly.
///
/// A `TextEncoder` instance is always in one of the two following modes.
///
/// * In **normal mode**, the text encoder writes text outside of an RDATA part.
/// * In **RDATA mode**, the text encoder writes text inside of an RDATA part.
///
/// `TextEncoder`  can encode tokens and strings in either mode, but other
/// operations are limited by mode.
///
/// `TextEncoder` doesn't support special RDATA field separators, such as
/// parentheses and line breaks, but this may change in the future.
///
#[derive(Debug)]
pub struct TextEncoder<W: std::io::Write, M: TextEncodeMode> {
    writer: W,
    state: EncoderState,
    _mode: PhantomData<M>,
}

#[derive(Debug)]
struct EncoderState {
    column: usize,
    next_field_needs_space: bool,
}

#[doc(hidden)]
pub trait TextEncodeMode: Sized {}

impl<W: std::io::Write> TextEncoder<W, NormalMode> {
    /// Constructs a text encoder that writes to a target.
    pub fn new(writer: W) -> Self {
        TextEncoder {
            writer,
            state: EncoderState {
                column: 0,
                next_field_needs_space: false,
            },
            _mode: PhantomData,
        }
    }

    /// Converts the text encoder into the write target.
    pub fn into_writer(self) -> W {
        self.writer
    }

    /// Writes a line break.
    pub fn encode_end_of_line(&mut self) -> Result<(), TextEncodeError> {
        self.encode_end_of_line_impl()?;
        Ok(())
    }

    /// Writes whitespace characters until the current line fills to a specified
    /// column.
    pub fn encode_space_until_column(
        &mut self,
        column: usize,
    ) -> Result<(), TextEncodeError> {

        let n_spaces = if self.state.column < column {
            column - self.state.column
        } else {
            0
        } as usize;

        let buffer = vec![b' '; n_spaces];
        self.writer.write_all(&buffer)?;

        if 1 <= n_spaces {
            self.state.column = column;
            self.state.next_field_needs_space = false;
        }

        Ok(())
    }

    /// Transforms the text encoder into RDATA mode.
    pub fn begin_rdata(
        self,
    ) -> Result<TextEncoder<W, RDataMode>, TextEncodeError> {
        Ok(TextEncoder {
            writer: self.writer,
            state: self.state,
            _mode: PhantomData,
        })
    }
}

impl<W: std::io::Write> TextEncoder<W, RDataMode> {
    /// Transforms the text encoder into normal mode.
    pub fn end_rdata(
        mut self,
    ) -> Result<TextEncoder<W, NormalMode>, TextEncodeError> {
        self.encode_end_of_line_impl()?;
        Ok(TextEncoder {
            writer: self.writer,
            state: self.state,
            _mode: PhantomData,
        })
    }
}

impl<W: std::io::Write, M: TextEncodeMode> TextEncoder<W, M> {
    /// Writes a token.
    ///
    /// This method writes leading whitespace, as needed, to separate the token
    /// from the previous field.
    ///
    pub fn encode_token(
        &mut self,
        token: &[u8],
    ) -> Result<(), TextEncodeError> {

        debug_assert!(!token.contains(&b' '));
        debug_assert!(!token.contains(&b'\t'));
        debug_assert!(!token.windows(2).any(|s| s == b"\r\n"));
        debug_assert!(!token.contains(&b'\n'));
        debug_assert!(!token.contains(&b'\"'));
        debug_assert!(!token.contains(&b'('));
        debug_assert!(!token.contains(&b')'));
        debug_assert!(!token.contains(&b';'));

        self.encode_leader()?;
        self.writer.write_all(token)?;
        self.state.column += token.len();
        Ok(())
    }

    /// Writes a character string.
    ///
    /// This method writes leading whitespace, as needed, to separate the string
    /// from the previous field.
    ///
    pub fn encode_string(
        &mut self,
        string: &[u8],
    ) -> Result<(), TextEncodeError> {

        self.encode_leader()?;

        let mut buffer = FormattableBytes(Vec::new());
        let quoted = string.contains(&b' ');

        if quoted {
            buffer.0.push(b'"');
        }

        format_string(&mut buffer, string, quoted, None)?;

        if quoted {
            buffer.0.push(b'"');
        }

        self.writer.write_all(&buffer.0)?;
        self.state.column += buffer.0.len();

        Ok(())
    }

    /// Writes a multi-part character string.
    ///
    /// This method first writes leading whitespace, as needed, to separate the
    /// string from the previous field. Then it writes each part of the string,
    /// separated by the specified separator character. Any instance of the
    /// separator character within a string part is escaped.
    ///
    pub fn encode_multi_string<'a, I>(
        &mut self,
        separator: u8,
        parts: I,
    ) -> Result<(), TextEncodeError>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        self.encode_leader()?;

        let mut buffer = FormattableBytes(Vec::new());
        let mut first = true;
        for part in parts {
            if !first {
                buffer.0.push(separator);
            }
            first = false;
            format_string(&mut buffer, part, false, Some(separator))?;
        }

        self.writer.write_all(&buffer.0)?;
        self.state.column += buffer.0.len();

        Ok(())
    }

    fn encode_end_of_line_impl(&mut self) -> Result<(), TextEncodeError> {
        self.writer.write_all(b"\n")?;
        self.state.column = 0;
        self.state.next_field_needs_space = false;
        Ok(())
    }

    fn encode_leader(&mut self) -> Result<(), TextEncodeError> {

        if self.state.next_field_needs_space {
            self.writer.write_all(b" ")?;
            self.state.column += 1;
        }

        self.state.next_field_needs_space = true;

        Ok(())
    }
}

/// `TextEncodeError` describes an error resulting from reading text data.
#[derive(Debug)]
pub struct TextEncodeError {
    cause: BoxedError,
}

impl Display for TextEncodeError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}: {}", std::error::Error::description(self), self.cause)
    }
}

impl std::error::Error for TextEncodeError {
    fn description(&self) -> &str {
        "Failed to encode text data"
    }
}

impl From<std::fmt::Error> for TextEncodeError {
    fn from(e: std::fmt::Error) -> Self {
        TextEncodeError::new(e)
    }
}

impl From<std::io::Error> for TextEncodeError {
    fn from(e: std::io::Error) -> Self {
        TextEncodeError::new(e)
    }
}

impl TextEncodeError {
    #[doc(hidden)]
    pub fn new<E: Into<BoxedError>>(cause: E) -> Self {
        TextEncodeError { cause: cause.into() }
    }
}

// Capture is like a Cow but is used for dynamically growing a slice of
// immutable input. If the slice can't be continuous (because it must be
// mutated) then the slice is converted into a Vec.
//
// The goal is to eliminate unnecessary allocations. We allocate if and only if
// the input contains at least one escape sequence, in which case we must
// mutate, e.g., "\\032" or "\\ " to " ".
//
#[derive(Debug)]
enum Capture<'a> {
    Borrowed { buffer: &'a [u8], length: usize },
    Owned { buffer: Vec<u8> },
}

impl<'a> Capture<'a> {
    fn extend(&mut self, bytes: &'a [u8]) {
        match *self {
            Capture::Borrowed { ref mut length, .. } => {
                *length += bytes.len();
            }
            Capture::Owned { ref mut buffer } => {
                buffer.extend_from_slice(bytes);
            }
        }
    }

    fn push(&mut self, b: u8) {
        match *self {
            Capture::Borrowed { ref mut length, .. } => {
                *length += 1;
            }
            Capture::Owned { ref mut buffer } => {
                buffer.push(b);
            }
        }
    }

    fn take_ownership_if_borrowed(&mut self) {
        let (buffer, length) = match *self {
            Capture::Borrowed { buffer, length } => (buffer, length),
            _ => return,
        };
        *self = Capture::Owned { buffer: Vec::from(&buffer[..length]) };
    }

    fn into_cow(self) -> Cow<'a, [u8]> {
        match self {
            Capture::Borrowed { buffer, length } => Cow::Borrowed(
                &buffer[..length],
            ),
            Capture::Owned { buffer } => Cow::Owned(buffer),
        }
    }
}

// FormattableBytes is a workaround for Vec<u8> not implementing the
// std::fmt::Write trait.
#[derive(Debug)]
struct FormattableBytes(Vec<u8>);

impl std::fmt::Write for FormattableBytes {
    fn write_str(&mut self, s: &str) -> Result<(), std::fmt::Error> {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

#[doc(hidden)]
pub fn format_string<W: std::fmt::Write>(
    writer: &mut W,
    text: &[u8],
    as_quoted: bool,
    special_escape: Option<u8>,
) -> Result<(), std::fmt::Error> {

    fn is_u8_quoted_special(b: u8) -> bool {
        b <= 32 || 128 <= b || b == b'"' || b == b'\\'
    }

    fn is_u8_unquoted_special(b: u8) -> bool {
        b <= 32 || 128 <= b || b == b'"' || b == b'(' || b == b')' ||
            b == b'\\' || b == b';'
    }

    let mut cursor = text;
    while !cursor.is_empty() {
        let n = cursor
            .iter()
            .position(|&b| if as_quoted {
                is_u8_quoted_special(b)
            } else {
                is_u8_unquoted_special(b)
            } ||
                special_escape.as_ref().map_or(
                    false,
                    |&special| b == special,
                ))
            .unwrap_or_else(|| cursor.len());

        debug_assert!(std::str::from_utf8(&cursor[..n]).is_ok());
        let s = unsafe { std::str::from_utf8_unchecked(&cursor[..n]) };
        writer.write_str(s)?;

        cursor = &cursor[n..];

        match cursor.first().cloned() {
            None => break,
            Some(b' ') => writer.write_str("\\ ")?,
            Some(b'\\') => writer.write_str("\\\\")?,
            Some(b'\"') => writer.write_str("\\\"")?,
            Some(b'(') if !as_quoted => writer.write_str("\\(")?,
            Some(b')') if !as_quoted => writer.write_str("\\)")?,
            Some(b';') if !as_quoted => writer.write_str("\\;")?,
            Some(b) => {
                writer.write_char('\\')?;
                writer.write_char((b'0' + (b / 100 % 10)) as char)?;
                writer.write_char((b'0' + (b / 10 % 10)) as char)?;
                writer.write_char((b'0' + (b % 10)) as char)?;
            }
        }

        cursor = &cursor[1..];
    }

    Ok(())
}

fn is_u8_space(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_decoder_constructs_into_normal_mode() {
        let _d: TextDecoder<NormalMode> = TextDecoder::new(b"");
    }

    #[test]
    fn text_decoder_decodes_end_of_file() {

        macro_rules! ok {
            ($source:expr) => {
                let mut d = TextDecoder::new($source);
                assert_matches!(d.decode_end_of_file(), Ok(()));
                assert_eq!(d.peek(), b"");
            };
        }

        macro_rules! nok {
            ($source:expr, $position:tt, $cause_type:ty, $cause_value:expr) => {
                let mut d = TextDecoder::new($source);
                assert_matches!(
                    d.decode_end_of_file(),
                    Err(ref e) if
                        e.expectation() == "end of input" &&
                        e.position() == TextPosition::new $position &&
                        e.cause().downcast_ref::<$cause_type>() ==
                            Some(&$cause_value)
                );
            };
        }

        ok!(b"");
        ok!(b" \t \t \t");

        nok!(b"\r\n", (0, 0, 0), EBadChar, EBadChar(b'\r'));
        nok!(b"\n", (0, 0, 0), EBadChar, EBadChar(b'\n'));
        nok!(b" \t \t \t\r\n", (0, 6, 6), EBadChar, EBadChar(b'\r'));
        nok!(b" \t \t \t\n", (0, 6, 6), EBadChar, EBadChar(b'\n'));
        nok!(b"alpha", (0, 0, 0), EBadChar, EBadChar(b'a'));
        nok!(b" \t \t \talpha", (0, 6, 6), EBadChar, EBadChar(b'a'));
    }

    #[test]
    fn text_decoder_decodes_end_of_line() {

        macro_rules! ok {
            ($source:expr) => {
                let mut d = TextDecoder::new($source);
                assert_matches!(d.decode_end_of_line(), Ok(()));
                assert_eq!(d.peek(), b"");
            };
        }

        macro_rules! nok {
            ($source:expr,
             $position:tt,
             $cause_type:ty,
             $cause_value:expr) =>
            {
                let mut d = TextDecoder::new($source);
                assert_matches!(
                    d.decode_end_of_line(),
                    Err(ref e) if
                        e.expectation() == "end of line" &&
                        e.position() == TextPosition::new $position &&
                        e.cause().downcast_ref::<$cause_type>() ==
                            Some(&$cause_value)
                );
            };
        }

        ok!(b"");
        ok!(b"\r\n");
        ok!(b"\n");
        ok!(b" \t \t \t");
        ok!(b" \t \t \t\r\n");
        ok!(b" \t \t \t\n");

        nok!(b"\r", (0, 0, 0), EBadChar, EBadChar(b'\r'));
        nok!(b"\r\r\n", (0, 0, 0), EBadChar, EBadChar(b'\r'));
        nok!(b"\r \n", (0, 0, 0), EBadChar, EBadChar(b'\r'));
        nok!(b"alpha", (0, 0, 0), EBadChar, EBadChar(b'a'));
        nok!(b"   alpha", (0, 3, 3), EBadChar, EBadChar(b'a'));
    }

    #[test]
    fn text_decoder_begins_and_ends_rdata() {

        macro_rules! ok {
            ($source:expr, $remainder:expr) => {
                let d = TextDecoder::new($source).begin_rdata();
                let d = match d.end_rdata() {
                    Ok(x) => x,
                    x => panic!("Got unexpectation result {:?}", x),
                };
                assert_eq!(d.peek(), $remainder);
            };
        }

        macro_rules! nok {
            ($source:expr, $position:tt, $cause_type:ty, $cause_value:expr) => {
                let d = TextDecoder::new($source).begin_rdata();
                assert_matches!(
                    d.end_rdata(),
                    Err(ref e) if
                        e.expectation() == "end of RDATA" &&
                        e.position() == TextPosition::new $position &&
                        e.cause().downcast_ref::<$cause_type>() ==
                            Some(&$cause_value)
                );
            };
        }

        ok!(b"", b"");
        ok!(b"\r\n", b"");
        ok!(b"\n", b"");
        ok!(b" \t \t \t\r\n", b"");
        ok!(b" \t \t \t\n", b"");
        ok!(b"((()))", b"");
        ok!(b"( ( \t\r\n \t)\r\n )\r\nalpha", b"alpha");
        ok!(b"( ( \t\n \t)\n )\nalpha", b"alpha");
        ok!(b" ; alpha", b"");
        ok!(b" ; alpha\r\n", b"");
        ok!(b" ; alpha\n", b"");
        ok!(b"( ; alpha\r\n  ; bravo\r\n)", b"");

        nok!(b"(", (0, 1, 1), EParenNotClosed, EParenNotClosed);
        nok!(b"((())", (0, 5, 5), EParenNotClosed, EParenNotClosed);
        nok!(b"(\r\n", (1, 0, 3), EParenNotClosed, EParenNotClosed);

        nok!(b")", (0, 0, 0), EParenNotMatched, EParenNotMatched);
        nok!(b"((())))", (0, 6, 6), EParenNotMatched, EParenNotMatched);
        nok!(b"(\r\n))", (1, 1, 4), EParenNotMatched, EParenNotMatched);

        nok!(b"alpha", (0, 0, 0), EBadChar, EBadChar(b'a'));
        nok!(b"\r", (0, 0, 0), EBadChar, EBadChar(b'\r'));
        nok!(b"(; comment\r\n)alpha", (1, 1, 13), EBadChar, EBadChar(b'a'));
    }

    #[test]
    fn text_decoder_decodes_token_in_normal_mode() {

        macro_rules! ok {
            ($source:expr, $token:expr, $remainder:expr) => {
                let mut d = TextDecoder::new($source);
                assert_matches!(d.decode_token(), Ok(x) if x == $token);
                assert_eq!(d.peek(), $remainder);
            };
        }

        macro_rules! nok {
            ($source:expr, $position:tt, $cause_type:ty, $cause_value:expr) => {
                let mut d = TextDecoder::new($source);
                assert_matches!(
                    d.decode_token(),
                    Err(ref e) if
                        e.expectation() == "token" &&
                        e.position() == TextPosition::new $position &&
                        e.cause().downcast_ref::<$cause_type>() ==
                            Some(&$cause_value)
                );
            };
        }

        ok!(b"alpha", b"alpha", b"");
        ok!(b" \t \t \talpha ", b"alpha", b" ");
        ok!(b"alpha ", b"alpha", b" ");
        ok!(b"alpha\t", b"alpha", b"\t");
        ok!(b"alpha\r\n", b"alpha", b"\r\n");
        ok!(b"alpha\n", b"alpha", b"\n");
        ok!(b"alpha\r", b"alpha\r", b"");
        ok!(b"alpha\rbravo", b"alpha\rbravo", b"");
        ok!(b"alpha\"", b"alpha", b"\"");
        ok!(b"alpha(", b"alpha", b"(");
        ok!(b"alpha)", b"alpha", b")");
        ok!(b"alpha;", b"alpha", b";");

        nok!(b"", (0, 0, 0), EEndOfInput, EEndOfInput);
        nok!(b" ", (0, 1, 1), EEndOfInput, EEndOfInput);
        nok!(b"\t", (0, 1, 1), EEndOfInput, EEndOfInput);
        nok!(b"\r\n", (0, 0, 0), EBadChar, EBadChar(b'\r'));
        nok!(b"\n", (0, 0, 0), EBadChar, EBadChar(b'\n'));
        nok!(b"(", (0, 0, 0), EBadChar, EBadChar(b'('));
        nok!(b")", (0, 0, 0), EBadChar, EBadChar(b')'));
        nok!(b";", (0, 0, 0), EBadChar, EBadChar(b';'));
    }

    #[test]
    fn text_decoder_decodes_token_in_rdata_mode() {

        macro_rules! ok {
            ($source:expr, $token:expr, $remainder:expr) => {
                let mut d = TextDecoder::new($source).begin_rdata();
                assert_matches!(d.decode_token(), Ok(x) if x == $token);
                assert_eq!(d.peek(), $remainder);
            };
        }

        macro_rules! nok {
            ($source:expr, $position:tt, $cause_type:ty, $cause_value:expr) => {
                let mut d = TextDecoder::new($source).begin_rdata();
                assert_matches!(
                    d.decode_token(),
                    Err(ref e) if
                        e.expectation() == "token" &&
                        e.position() == TextPosition::new $position &&
                        e.cause().downcast_ref::<$cause_type>() ==
                            Some(&$cause_value)
                );
            };
        }

        ok!(b"alpha", b"alpha", b"");
        ok!(b" \t \t \talpha", b"alpha", b"");
        ok!(b"alpha ", b"alpha", b" ");
        ok!(b"alpha\t", b"alpha", b"\t");
        ok!(b"alpha\r\n", b"alpha", b"\r\n");
        ok!(b"alpha\n", b"alpha", b"\n");
        ok!(b"alpha\r", b"alpha\r", b"");
        ok!(b"alpha\rbravo", b"alpha\rbravo", b"");
        ok!(b"alpha\"", b"alpha", b"\"");
        ok!(b"alpha(", b"alpha", b"(");
        ok!(b"alpha)", b"alpha", b")");
        ok!(b"alpha;", b"alpha", b";");

        ok!(b"(\r\n \t \t \talpha", b"alpha", b"");
        ok!(b"(\n \t \t \talpha", b"alpha", b"");
        ok!(b"(;comment\r\nalpha", b"alpha", b"");
        ok!(b"(;comment\nalpha", b"alpha", b"");
        ok!(b"(alpha)", b"alpha", b")");

        nok!(b"", (0, 0, 0), EEndOfInput, EEndOfInput);
        nok!(b" ", (0, 1, 1), EEndOfInput, EEndOfInput);
        nok!(b"\t", (0, 1, 1), EEndOfInput, EEndOfInput);
        nok!(b"\r\n", (0, 0, 0), EBadChar, EBadChar(b'\r'));
        nok!(b"\n", (0, 0, 0), EBadChar, EBadChar(b'\n'));
        nok!(b")", (0, 0, 0), EParenNotMatched, EParenNotMatched);
        nok!(b";", (0, 1, 1), EEndOfInput, EEndOfInput);
    }

    #[test]
    fn text_decoder_decodes_string_in_normal_mode() {

        macro_rules! ok {
            ($source:expr, $string:expr, $remainder:expr) => {
                let mut d = TextDecoder::new($source);
                assert_matches!(
                    d.decode_string(),
                    Ok(ref x) if x.as_ref() == $string
                );
                assert_eq!(d.peek(), $remainder);
            };
        }

        macro_rules! nok {
            ($source:expr, $position:tt, $cause_type:ty, $cause_value:expr) => {
                let mut d = TextDecoder::new($source);
                assert_matches!(
                    d.decode_string(),
                    Err(ref e) if
                        e.expectation() == "character string" &&
                        e.position() == TextPosition::new $position &&
                        e.cause().downcast_ref::<$cause_type>() ==
                            Some(&$cause_value)
                );
            };
        }

        ok!(b"alpha", b"alpha", b"");
        ok!(b" \t \t \talpha ", b"alpha", b" ");
        ok!(b"alpha ", b"alpha", b" ");
        ok!(b"alpha\t", b"alpha", b"\t");
        ok!(b"alpha\r\n", b"alpha", b"\r\n");
        ok!(b"alpha\n", b"alpha", b"\n");
        ok!(b"alpha\r", b"alpha\r", b"");
        ok!(b"alpha\rbravo", b"alpha\rbravo", b"");
        ok!(b"alpha\"", b"alpha", b"\"");
        ok!(b"alpha(", b"alpha", b"(");
        ok!(b"alpha)", b"alpha", b")");
        ok!(b"alpha;", b"alpha", b";");

        ok!(b"\"\"", b"", b"");
        ok!(b"\"alpha bravo\"", b"alpha bravo", b"");
        ok!(b"\"alpha\tbravo\"", b"alpha\tbravo", b"");
        ok!(b"\"alpha\rbravo\"", b"alpha\rbravo", b"");
        ok!(b"\"alpha(bravo\"", b"alpha(bravo", b"");
        ok!(b"\"alpha)bravo\"", b"alpha)bravo", b"");
        ok!(b"\"alpha;bravo\"", b"alpha;bravo", b"");

        ok!(b"alpha\\032bravo", b"alpha bravo", b"");
        ok!(b"alpha\\ bravo", b"alpha bravo", b"");
        ok!(b"alpha\\\\bravo", b"alpha\\bravo", b"");
        ok!(b"alpha\\\tbravo", b"alpha\tbravo", b"");
        ok!(b"alpha\\(bravo", b"alpha(bravo", b"");
        ok!(b"alpha\\)bravo", b"alpha)bravo", b"");
        ok!(b"alpha\\;bravo", b"alpha;bravo", b"");
        ok!(b"alpha\\\"bravo", b"alpha\"bravo", b"");
        ok!(b"alpha\\bravo", b"alphabravo", b"");

        ok!(b"\"alpha\\032bravo\"", b"alpha bravo", b"");
        ok!(b"\"alpha\\ bravo\"", b"alpha bravo", b"");
        ok!(b"\"alpha\\\\bravo\"", b"alpha\\bravo", b"");
        ok!(b"\"alpha\\\tbravo\"", b"alpha\tbravo", b"");
        ok!(b"\"alpha\\(bravo\"", b"alpha(bravo", b"");
        ok!(b"\"alpha\\)bravo\"", b"alpha)bravo", b"");
        ok!(b"\"alpha\\;bravo\"", b"alpha;bravo", b"");
        ok!(b"\"alpha\\\"bravo\"", b"alpha\"bravo", b"");
        ok!(b"\"alpha\\bravo\"", b"alphabravo", b"");

        nok!(b"", (0, 0, 0), EEndOfInput, EEndOfInput);
        nok!(b" ", (0, 1, 1), EEndOfInput, EEndOfInput);
        nok!(b"\t", (0, 1, 1), EEndOfInput, EEndOfInput);
        nok!(b"\r\n", (0, 0, 0), EBadChar, EBadChar(b'\r'));
        nok!(b"\n", (0, 0, 0), EBadChar, EBadChar(b'\n'));
        nok!(b"(alpha", (0, 0, 0), EBadChar, EBadChar(b'('));
        nok!(b")alpha", (0, 0, 0), EBadChar, EBadChar(b')'));
        nok!(b";alpha", (0, 0, 0), EBadChar, EBadChar(b';'));

        nok!(b"\"alpha", (0, 6, 6), EQuoteNotClosed, EQuoteNotClosed);
        nok!(
            b"\"alpha\r\nbravo\"",
            (0, 6, 6),
            EQuoteNotClosed,
            EQuoteNotClosed
        );

        nok!(b"alpha\\256bravo", (0, 5, 5), EBadEscape, EBadEscape);
        nok!(b"alpha\\25bravo", (0, 5, 5), EBadEscape, EBadEscape);
        nok!(b"alpha\\25", (0, 5, 5), EBadEscape, EBadEscape);
        nok!(b"alpha\\2bravo", (0, 5, 5), EBadEscape, EBadEscape);
        nok!(b"alpha\\2", (0, 5, 5), EBadEscape, EBadEscape);
        nok!(b"alpha\\\nbravo", (0, 5, 5), EBadEscape, EBadEscape);
    }

    #[test]
    fn text_decoder_decodes_string_in_rdata_mode() {

        macro_rules! ok {
            ($source:expr, $string:expr, $remainder:expr) => {
                let mut d = TextDecoder::new($source).begin_rdata();
                assert_matches!(
                    d.decode_string(),
                    Ok(ref x) if x.as_ref() == $string
                );
                assert_eq!(d.peek(), $remainder);
            };
        }

        macro_rules! nok {
            ($source:expr, $position:tt, $cause_type:ty, $cause_value:expr) => {
                let mut d = TextDecoder::new($source).begin_rdata();
                assert_matches!(
                    d.decode_string(),
                    Err(ref e) if
                        e.expectation() == "character string" &&
                        e.position() == TextPosition::new $position &&
                        e.cause().downcast_ref::<$cause_type>() ==
                            Some(&$cause_value)
                );
            };
        }

        ok!(b"alpha", b"alpha", b"");
        ok!(b" \t \t \talpha ", b"alpha", b" ");
        ok!(b"alpha ", b"alpha", b" ");
        ok!(b"alpha\t", b"alpha", b"\t");
        ok!(b"alpha\r\n", b"alpha", b"\r\n");
        ok!(b"alpha\n", b"alpha", b"\n");
        ok!(b"alpha\r", b"alpha\r", b"");
        ok!(b"alpha\rbravo", b"alpha\rbravo", b"");
        ok!(b"alpha\"", b"alpha", b"\"");
        ok!(b"alpha(", b"alpha", b"(");
        ok!(b"alpha)", b"alpha", b")");
        ok!(b"alpha;", b"alpha", b";");

        ok!(b"(\r\n \t \t \talpha", b"alpha", b"");
        ok!(b"(\n \t \t \talpha", b"alpha", b"");
        ok!(b"(;comment\r\nalpha", b"alpha", b"");
        ok!(b"(;comment\nalpha", b"alpha", b"");
        ok!(b"(alpha)", b"alpha", b")");

        ok!(b"\"\"", b"", b"");
        ok!(b"\"alpha bravo\"", b"alpha bravo", b"");
        ok!(b"\"alpha\tbravo\"", b"alpha\tbravo", b"");
        ok!(b"\"alpha\rbravo\"", b"alpha\rbravo", b"");
        ok!(b"\"alpha(bravo\"", b"alpha(bravo", b"");
        ok!(b"\"alpha)bravo\"", b"alpha)bravo", b"");
        ok!(b"\"alpha;bravo\"", b"alpha;bravo", b"");

        ok!(b"alpha\\032bravo", b"alpha bravo", b"");
        ok!(b"alpha\\ bravo", b"alpha bravo", b"");
        ok!(b"alpha\\\\bravo", b"alpha\\bravo", b"");
        ok!(b"alpha\\\tbravo", b"alpha\tbravo", b"");
        ok!(b"alpha\\(bravo", b"alpha(bravo", b"");
        ok!(b"alpha\\)bravo", b"alpha)bravo", b"");
        ok!(b"alpha\\;bravo", b"alpha;bravo", b"");
        ok!(b"alpha\\\"bravo", b"alpha\"bravo", b"");
        ok!(b"alpha\\bravo", b"alphabravo", b"");

        ok!(b"\"alpha\\032bravo\"", b"alpha bravo", b"");
        ok!(b"\"alpha\\ bravo\"", b"alpha bravo", b"");
        ok!(b"\"alpha\\\\bravo\"", b"alpha\\bravo", b"");
        ok!(b"\"alpha\\\tbravo\"", b"alpha\tbravo", b"");
        ok!(b"\"alpha\\(bravo\"", b"alpha(bravo", b"");
        ok!(b"\"alpha\\)bravo\"", b"alpha)bravo", b"");
        ok!(b"\"alpha\\;bravo\"", b"alpha;bravo", b"");
        ok!(b"\"alpha\\\"bravo\"", b"alpha\"bravo", b"");
        ok!(b"\"alpha\\bravo\"", b"alphabravo", b"");

        nok!(b"", (0, 0, 0), EEndOfInput, EEndOfInput);
        nok!(b" ", (0, 1, 1), EEndOfInput, EEndOfInput);
        nok!(b"\t", (0, 1, 1), EEndOfInput, EEndOfInput);
        nok!(b"\r\n", (0, 0, 0), EBadChar, EBadChar(b'\r'));
        nok!(b"\n", (0, 0, 0), EBadChar, EBadChar(b'\n'));
        nok!(b")", (0, 0, 0), EParenNotMatched, EParenNotMatched);
        nok!(b";", (0, 1, 1), EEndOfInput, EEndOfInput);

        nok!(b"\"alpha", (0, 6, 6), EQuoteNotClosed, EQuoteNotClosed);
        nok!(
            b"\"alpha\r\nbravo\"",
            (0, 6, 6),
            EQuoteNotClosed,
            EQuoteNotClosed
        );

        nok!(b"alpha\\256bravo", (0, 5, 5), EBadEscape, EBadEscape);
        nok!(b"alpha\\25bravo", (0, 5, 5), EBadEscape, EBadEscape);
        nok!(b"alpha\\25", (0, 5, 5), EBadEscape, EBadEscape);
        nok!(b"alpha\\2bravo", (0, 5, 5), EBadEscape, EBadEscape);
        nok!(b"alpha\\2", (0, 5, 5), EBadEscape, EBadEscape);
        nok!(b"alpha\\\nbravo", (0, 5, 5), EBadEscape, EBadEscape);
    }

    #[test]
    fn text_decoder_decodes_multi_string_in_normal_mode() {

        macro_rules! ok {
            ($sep:expr, $source:expr, $parts:expr, $remainder:expr) => {
                let mut d = TextDecoder::new($source);
                assert_matches!(
                    d.decode_multi_string($sep).collect::<Result<Vec<_>, _>>(),
                    Ok(ref x) if x == $parts
                );
                assert_eq!(d.peek(), $remainder);
            };
        }

        macro_rules! nok {
            ($sep:expr,
             $source:expr, 
             $position:tt,
             $cause_type:ty,
             $cause_value:expr) =>
            {
                let mut d = TextDecoder::new($source);
                assert_matches!(
                    d.decode_multi_string($sep).collect::<Result<Vec<_>, _>>(),
                    Err(ref e) if
                        e.expectation() == "character string" &&
                        e.position() == TextPosition::new $position &&
                        e.cause().downcast_ref::<$cause_type>() ==
                            Some(&$cause_value)
                );
            };
        }

        ok!(b'.', b".", &[&b""[..], &b""[..]], b"");
        ok!(b'.', b"alpha", &[&b"alpha"[..]], b"");
        ok!(b'.', b"alpha.", &[&b"alpha"[..], &b""[..]], b"");
        ok!(b'.', b"alpha.bravo", &[&b"alpha"[..], &b"bravo"[..]], b"");
        ok!(
            b'.',
            b"alpha.bravo.",
            &[&b"alpha"[..], &b"bravo"[..], &b""[..]],
            b""
        );
        ok!(
            b'.',
            b"alpha.bravo.charlie",
            &[&b"alpha"[..], &b"bravo"[..], &b"charlie"[..]],
            b""
        );

        ok!(b'.', b"\"\"", &[&b""[..]], b"");
        ok!(b'.', b"\".\"", &[&b""[..], &b""[..]], b"");
        ok!(b'.', b"\"alpha\"", &[&b"alpha"[..]], b"");
        ok!(b'.', b"\"alpha.\"", &[&b"alpha"[..], &b""[..]], b"");
        ok!(b'.', b"\"alpha.bravo\"", &[&b"alpha"[..], &b"bravo"[..]], b"");
        ok!(
            b'.',
            b"\"alpha.bravo.\"",
            &[&b"alpha"[..], &b"bravo"[..], &b""[..]],
            b""
        );
        ok!(
            b'.',
            b"\"alpha.bravo.charlie\"",
            &[&b"alpha"[..], &b"bravo"[..], &b"charlie"[..]],
            b""
        );

        ok!(b'.', b" \t \t \talpha.", &[&b"alpha"[..], &b""[..]], b"");

        // Leading whitespace is consumed only for the first part.

        ok!(
            b'.',
            b" \t \t \talpha.bravo",
            &[&b"alpha"[..], &b"bravo"[..]],
            b""
        );
        ok!(b'.', b"alpha. bravo", &[&b"alpha"[..], &b""[..]], b" bravo");

        // Consecutive separators are handled as expected.

        ok!(b'.', b"..", &[&b""[..], &b""[..], &b""[..]], b"");
        ok!(b'.', b"\"..\"", &[&b""[..], &b""[..], &b""[..]], b"");

        // The separator can be a null.

        ok!(b'\0', b"alpha\0bravo", &[&b"alpha"[..], &b"bravo"[..]], b"");

        // Errors are caught as expected.

        nok!(b'.', b"", (0, 0, 0), EEndOfInput, EEndOfInput);

        nok!(
            b'.',
            b"\"alpha.bravo",
            (0, 12, 12),
            EQuoteNotClosed,
            EQuoteNotClosed
        );
    }

    #[test]
    fn text_decoder_decodes_multi_string_in_rdata_mode() {

        macro_rules! ok {
            ($sep:expr, $source:expr, $parts:expr, $remainder:expr) => {
                let mut d = TextDecoder::new($source).begin_rdata();
                assert_matches!(
                    d.decode_multi_string($sep).collect::<Result<Vec<_>, _>>(),
                    Ok(ref x) if x == $parts
                );
                assert_eq!(d.peek(), $remainder);
            };
        }

        macro_rules! nok {
            ($sep:expr,
             $source:expr, 
             $position:tt,
             $cause_type:ty,
             $cause_value:expr) =>
            {
                let mut d = TextDecoder::new($source).begin_rdata();
                assert_matches!(
                    d.decode_multi_string($sep).collect::<Result<Vec<_>, _>>(),
                    Err(ref e) if
                        e.expectation() == "character string" &&
                        e.position() == TextPosition::new $position &&
                        e.cause().downcast_ref::<$cause_type>() ==
                            Some(&$cause_value)
                );
            };
        }

        ok!(b'.', b".", &[&b""[..], &b""[..]], b"");
        ok!(b'.', b"alpha", &[&b"alpha"[..]], b"");
        ok!(b'.', b"alpha.", &[&b"alpha"[..], &b""[..]], b"");
        ok!(b'.', b"alpha.bravo", &[&b"alpha"[..], &b"bravo"[..]], b"");
        ok!(
            b'.',
            b"alpha.bravo.",
            &[&b"alpha"[..], &b"bravo"[..], &b""[..]],
            b""
        );
        ok!(
            b'.',
            b"alpha.bravo.charlie",
            &[&b"alpha"[..], &b"bravo"[..], &b"charlie"[..]],
            b""
        );

        ok!(b'.', b"\"\"", &[&b""[..]], b"");
        ok!(b'.', b"\".\"", &[&b""[..], &b""[..]], b"");
        ok!(b'.', b"\"alpha\"", &[&b"alpha"[..]], b"");
        ok!(b'.', b"\"alpha.\"", &[&b"alpha"[..], &b""[..]], b"");
        ok!(b'.', b"\"alpha.bravo\"", &[&b"alpha"[..], &b"bravo"[..]], b"");
        ok!(
            b'.',
            b"\"alpha.bravo.\"",
            &[&b"alpha"[..], &b"bravo"[..], &b""[..]],
            b""
        );
        ok!(
            b'.',
            b"\"alpha.bravo.charlie\"",
            &[&b"alpha"[..], &b"bravo"[..], &b"charlie"[..]],
            b""
        );

        ok!(b'.', b" \t \t \talpha.", &[&b"alpha"[..], &b""[..]], b"");

        // Leading whitespace is consumed only for the first part.

        ok!(
            b'.',
            b" \t \t \talpha.bravo",
            &[&b"alpha"[..], &b"bravo"[..]],
            b""
        );
        ok!(
            b'.',
            b"(\r\n \t \t \talpha.bravo",
            &[&b"alpha"[..], &b"bravo"[..]],
            b""
        );
        ok!(
            b'.',
            b"(\n \t \t \talpha.bravo",
            &[&b"alpha"[..], &b"bravo"[..]],
            b""
        );
        ok!(
            b'.',
            b"(;comment\r\nalpha.bravo",
            &[&b"alpha"[..], &b"bravo"[..]],
            b""
        );
        ok!(
            b'.',
            b"(;comment\nalpha.bravo",
            &[&b"alpha"[..], &b"bravo"[..]],
            b""
        );
        ok!(b'.', b"alpha. bravo", &[&b"alpha"[..], &b""[..]], b" bravo");

        // Consecutive separators are handled as expected.

        ok!(b'.', b"..", &[&b""[..], &b""[..], &b""[..]], b"");
        ok!(b'.', b"\"..\"", &[&b""[..], &b""[..], &b""[..]], b"");

        // The separator can be a null.

        ok!(b'\0', b"alpha\0bravo", &[&b"alpha"[..], &b"bravo"[..]], b"");

        // Errors are caught as expected.

        nok!(b'.', b"", (0, 0, 0), EEndOfInput, EEndOfInput);

        nok!(
            b'.',
            b"\"alpha.bravo",
            (0, 12, 12),
            EQuoteNotClosed,
            EQuoteNotClosed
        );
    }

    #[test]
    fn text_encoder_encodes_end_of_line() {

        let mut enc = TextEncoder::new(Vec::new());
        assert_matches!(enc.encode_end_of_line(), Ok(()));

        let text = enc.into_writer();
        let mut dec = TextDecoder::new(&text);
        assert_matches!(dec.decode_end_of_line(), Ok(()));
        assert_eq!(dec.peek(), b"");
    }

    #[test]
    fn text_encoder_begins_and_ends_rdata() {

        let enc = TextEncoder::new(Vec::new());
        let enc = enc.begin_rdata().unwrap();
        let enc = enc.end_rdata().unwrap();

        let text = enc.into_writer();
        let dec = TextDecoder::new(&text).begin_rdata();
        let dec = dec.end_rdata().unwrap();
        assert_eq!(dec.peek(), b"");
    }

    #[test]
    fn text_encoder_encodes_token() {

        let mut enc = TextEncoder::new(Vec::new());
        assert_matches!(enc.encode_token(b"alpha"), Ok(()));
        assert_matches!(enc.encode_token(b"bravo\rcharlie"), Ok(()));
        assert_matches!(enc.encode_token(b"delta"), Ok(()));

        let text = enc.into_writer();
        let mut dec = TextDecoder::new(&text);
        assert_matches!(dec.decode_token(), Ok(b"alpha"));
        assert_matches!(dec.decode_token(), Ok(b"bravo\rcharlie"));
        assert_matches!(dec.decode_token(), Ok(b"delta"));
        assert_eq!(dec.peek(), b"");
    }

    #[test]
    fn text_encoder_encodes_string() {

        macro_rules! decode {
            ($dec:expr, $string:expr) => {
                assert_matches!(
                    $dec.decode_string(),
                    Ok(ref x) if x.as_ref() == $string
                );
            };
        }

        let mut enc = TextEncoder::new(Vec::new());
        assert_matches!(enc.encode_string(b"alpha bravo"), Ok(()));
        assert_matches!(enc.encode_string(b"alpha\tbravo"), Ok(()));
        assert_matches!(enc.encode_string(b"alpha\rbravo"), Ok(()));
        assert_matches!(enc.encode_string(b"alpha\"bravo"), Ok(()));
        assert_matches!(enc.encode_string(b"alpha(bravo"), Ok(()));
        assert_matches!(enc.encode_string(b"alpha)bravo"), Ok(()));
        assert_matches!(enc.encode_string(b"alpha;bravo"), Ok(()));
        assert_matches!(enc.encode_string(b"alpha\0bravo"), Ok(()));
        assert_matches!(enc.encode_string(b"alpha\xffbravo"), Ok(()));

        let text = enc.into_writer();
        let mut dec = TextDecoder::new(&text);
        decode!(dec, b"alpha bravo");
        decode!(dec, b"alpha\tbravo");
        decode!(dec, b"alpha\rbravo");
        decode!(dec, b"alpha\"bravo");
        decode!(dec, b"alpha(bravo");
        decode!(dec, b"alpha)bravo");
        decode!(dec, b"alpha;bravo");
        decode!(dec, b"alpha\0bravo");
        decode!(dec, b"alpha\xffbravo");
        assert_eq!(dec.peek(), b"");
    }

    #[test]
    fn text_encoder_encodes_multi_string() {

        macro_rules! encode {
            ($enc:expr, $parts:expr) => {
                assert_matches!(
                    $enc.encode_multi_string(b'.', $parts),
                    Ok(())
                );
            };
        }

        macro_rules! decode {
            ($dec:expr, $parts:expr) => {
                assert_matches!(
                    $dec.decode_multi_string(b'.')
                        .collect::<Result<Vec<_>, _>>(),
                    Ok(ref x) if x == $parts
                );
            };
        }

        let mut enc = TextEncoder::new(Vec::new());
        encode!(enc, vec![&b"alpha bravo"[..], &b"charlie"[..]]);
        encode!(enc, vec![&b"alpha\tbravo"[..], &b"charlie"[..]]);
        encode!(enc, vec![&b"alpha\rbravo"[..], &b"charlie"[..]]);
        encode!(enc, vec![&b"alpha\"bravo"[..], &b"charlie"[..]]);
        encode!(enc, vec![&b"alpha(bravo"[..], &b"charlie"[..]]);
        encode!(enc, vec![&b"alpha)bravo"[..], &b"charlie"[..]]);
        encode!(enc, vec![&b"alpha;bravo"[..], &b"charlie"[..]]);
        encode!(enc, vec![&b"alpha\0bravo"[..], &b"charlie"[..]]);
        encode!(enc, vec![&b"alpha\xffbravo"[..], &b"charlie"[..]]);
        encode!(enc, vec![&b"alpha.bravo"[..], &b"charlie"[..]]);

        let text = enc.into_writer();
        let mut dec = TextDecoder::new(&text);
        decode!(dec, &[&b"alpha bravo"[..], &b"charlie"[..]]);
        decode!(dec, &[&b"alpha\tbravo"[..], &b"charlie"[..]]);
        decode!(dec, &[&b"alpha\rbravo"[..], &b"charlie"[..]]);
        decode!(dec, &[&b"alpha\"bravo"[..], &b"charlie"[..]]);
        decode!(dec, &[&b"alpha(bravo"[..], &b"charlie"[..]]);
        decode!(dec, &[&b"alpha)bravo"[..], &b"charlie"[..]]);
        decode!(dec, &[&b"alpha;bravo"[..], &b"charlie"[..]]);
        decode!(dec, &[&b"alpha\0bravo"[..], &b"charlie"[..]]);
        decode!(dec, &[&b"alpha\xffbravo"[..], &b"charlie"[..]]);
        decode!(dec, &[&b"alpha.bravo"[..], &b"charlie"[..]]);
        assert_eq!(dec.peek(), b"");
    }

    #[test]
    fn text_encodes_encodes_space_until_column() {

        // These test cases are brittle.

        let mut enc = TextEncoder::new(Vec::new());
        assert_matches!(enc.encode_space_until_column(10), Ok(()));
        let text = enc.into_writer();
        assert_eq!(text, b"          ");

        let mut enc = TextEncoder::new(Vec::new());
        assert_matches!(enc.encode_space_until_column(10), Ok(()));
        assert_matches!(enc.encode_space_until_column(5), Ok(()));
        let text = enc.into_writer();
        assert_eq!(text, b"          ");

        // The encoder maintains the column count when encoding a token.

        let mut enc = TextEncoder::new(Vec::new());
        assert_matches!(enc.encode_token(b"alpha"), Ok(()));
        assert_matches!(enc.encode_space_until_column(10), Ok(()));
        let text = enc.into_writer();
        assert_eq!(text, b"alpha     ");

        // The encoder maintains the column count when encoding a string.

        let mut enc = TextEncoder::new(Vec::new());
        assert_matches!(enc.encode_string(b"alpha bravo"), Ok(()));
        assert_matches!(enc.encode_space_until_column(20), Ok(()));
        let text = enc.into_writer();
        assert_eq!(text.len(), 20);

        // The encoder maintains the column count when encoding a multi-part
        // string.

        let mut enc = TextEncoder::new(Vec::new());
        assert_matches!(
            enc.encode_multi_string(b'.', vec![&b"alpha"[..], &b"bravo"[..]]),
            Ok(())
        );
        assert_matches!(enc.encode_space_until_column(20), Ok(()));
        let text = enc.into_writer();
        assert_eq!(text.len(), 20);

        // The encoder resets the column count when encoding a line break.

        let mut enc = TextEncoder::new(Vec::new());
        assert_matches!(enc.encode_token(b"alpha"), Ok(()));
        assert_matches!(enc.encode_end_of_line(), Ok(()));
        assert_matches!(enc.encode_space_until_column(10), Ok(()));
        let text = enc.into_writer();
        assert!(text.ends_with(b"          "));
    }
}
