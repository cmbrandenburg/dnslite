use binary::prelude::*;
use std;
use std::fmt::{Display, Formatter};
use text::prelude::*;

const MAX: u32 = 0x_8000_0000;
const EXPECTATION: &str = "serial number";

declare_static_error_type!(EBadSerial, "Serial number is ill-formed");
declare_static_error_type!(EOutOfRange, "Serial number is out of range");

/// `Serial` is a zone serial number.
///
/// A `Serial` instance wraps an unsigned 32-bit number that denotes a zone's
/// configuration version.
///
/// `Serial` implements **sequence space arithmetic**, defined in [RFC
/// 1982][rfc_1982].
///
/// * For addition,`Serial` safely wraps on overflow.
/// * For comparison, `Serial` accounts for wrapping such that `s < s + n` for
///   any value `s` where `n < 0x8000_0000`.
///
/// # Examples
///
/// ```
/// use dnslite::Serial;
///
/// // Serial addition safely wraps on overflow.
/// assert_eq!(Serial(0) + 1, Serial(1));
/// assert_eq!(Serial(0xffff_ffff) + 1, Serial(0));
/// assert_eq!(Serial(0xffff_ffff) + 2, Serial(1));
///
/// // Serial comparison accounts for overflow.
/// assert!(Serial(0) < Serial(1));
/// assert!(Serial(0xffff_fffe) < Serial(0xffff_ffff));
/// assert!(Serial(0xffff_ffff) < Serial(0));
///
/// // One consequence is that antipodal values do not have a defined
/// // ordering.
/// assert!(  Serial(0) < Serial(0x7fff_ffff) );
/// assert!(!(Serial(0) < Serial(0x8000_0000)));
/// assert!(!(Serial(0x8000_0000) < Serial(0)));
/// assert!(  Serial(0x8000_0001) < Serial(0) );
///
/// // Nonetheless, Serial implements full equality--even for antipodal
/// // values.
/// assert_eq!(Serial(0), Serial(0));
/// assert_ne!(Serial(0), Serial(0x8000_0000));
/// ```
///
/// [rfc_1982]: https://tools.ietf.org/html/rfc1982
///
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Serial(pub u32);

impl Display for Serial {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        self.0.fmt(f)
    }
}

impl From<Serial> for u32 {
    fn from(x: Serial) -> Self {
        x.0
    }
}

impl PartialOrd for Serial {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {

        let i1 = self.0; // same name used in RFC 1982
        let i2 = other.0; // same name used in RFC 1982

        if i1 == i2 {
            Some(std::cmp::Ordering::Equal)
        } else if (i1 < i2 && i2 - i1 < MAX) || (i1 > i2 && i1 - i2 > MAX) {
            Some(std::cmp::Ordering::Less)
        } else if (i1 < i2 && i2 - i1 > MAX) || (i1 > i2 && i1 - i2 < MAX) {
            Some(std::cmp::Ordering::Greater)
        } else {
            debug_assert!(
                (i1 < i2 && i2 - i1 == 0x_8000_0000) ||
                    (i1 > i2 && i1 - i2 == 0x_8000_0000)
            );

            // According to RFC 1982, section 3.2, implementations are free to
            // define any result for this condition.
            //
            // > Thus the problem case is left undefined, implementations are
            // free to return either result, or to flag an error, and users must
            // take care not to depend on any particular outcome. <

            None
        }
    }
}

impl std::ops::Add<u32> for Serial {
    type Output = Self;
    fn add(self, other: u32) -> Self::Output {
        debug_assert!(other < MAX);
        Serial(self.0.wrapping_add(other))
    }
}

impl std::ops::AddAssign<u32> for Serial {
    fn add_assign(&mut self, other: u32) {
        debug_assert!(other < MAX);
        self.0 = self.0.wrapping_add(other);
    }
}

impl<'a> DecodeBinary<'a> for Serial {
    fn decode_binary(
        decoder: &mut BinaryDecoder<'a>,
    ) -> Result<Self, BinaryDecodeError> {
        u32::decode_binary(decoder).map(|x| Serial(x)).map_err(
            |mut e| {
                e.set_expectation(EXPECTATION);
                e
            },
        )
    }
}

impl EncodeBinary for Serial {
    fn encode_binary(
        &self,
        encoder: &mut BinaryEncoder,
    ) -> Result<(), BinaryEncodeError> {
        self.0.encode_binary(encoder)
    }
}

impl<'a, M: TextDecodeMode> DecodeText<'a, M> for Serial {
    fn decode_text(
        decoder: &mut TextDecoder<'a, M>,
    ) -> Result<Self, TextDecodeError> {

        let position = decoder.position();

        let token = decoder.decode_token().map_err(|mut e| {
            e.set_expectation(EXPECTATION);
            e
        })?;

        if token.iter().any(|&b| b < b'0' || b'9' < b) {
            return Err(TextDecodeError::new(EXPECTATION, position, EBadSerial));
        }

        let utf8 = std::str::from_utf8(token).map_err(|_| {
            TextDecodeError::new(EXPECTATION, position, EOutOfRange)
        })?;

        u32::from_str_radix(utf8, 10).map(|x| Serial(x)).map_err(|_| {
            TextDecodeError::new(EXPECTATION, position, EOutOfRange)
        })
    }
}

impl EncodeText for Serial {
    fn encode_text<W: std::io::Write, M: TextEncodeMode>(
        &self,
        encoder: &mut TextEncoder<W, M>,
    ) -> Result<(), TextEncodeError> {
        let text = format!("{}", self.0);
        encoder.encode_token(text.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIXME
    #[test]
    fn serial_displays_as_decimal_number() {
        let got = format!("{}", Serial(1234));
        let expected = format!("{}", 1234);
        assert_eq!(got, expected);
    }

    #[test]
    fn u32_from_serial_is_inner_value() {
        let x = Serial(1234);
        let got = u32::from(x);
        let expected = 1234;
        assert_eq!(got, expected);
    }

    #[test]
    fn serial_compares_using_sequence_space_arithmetic() {

        use std::cmp::Ordering;

        fn compare(lhs: u32, rhs: u32) -> Option<Ordering> {
            Serial(lhs).partial_cmp(&Serial(rhs))
        }

        assert_eq!(compare(0, 0), Some(Ordering::Equal));
        assert_eq!(compare(0x7fff_ffff, 0x7fff_ffff), Some(Ordering::Equal));
        assert_eq!(compare(0x8000_0000, 0x8000_0000), Some(Ordering::Equal));
        assert_eq!(compare(0xffff_ffff, 0xffff_ffff), Some(Ordering::Equal));

        assert_eq!(compare(0, 1), Some(Ordering::Less));
        assert_eq!(compare(1, 0), Some(Ordering::Greater));

        assert_eq!(compare(0, 0x4000_0000), Some(Ordering::Less));
        assert_eq!(compare(0x4000_0000, 0), Some(Ordering::Greater));

        assert_eq!(compare(0, 0x7fff_ffff), Some(Ordering::Less));
        assert_eq!(compare(0x7fff_ffff, 0), Some(Ordering::Greater));

        assert_eq!(compare(0, 0x8000_0000), None);
        assert_eq!(compare(0x8000_0000, 0), None);

        assert_eq!(compare(0, 0x8000_0001), Some(Ordering::Greater));
        assert_eq!(compare(0x8000_0001, 0), Some(Ordering::Less));

        assert_eq!(compare(0, 0xc000_0000), Some(Ordering::Greater));
        assert_eq!(compare(0xc000_0000, 0), Some(Ordering::Less));

        assert_eq!(compare(0, 0xffff_ffff), Some(Ordering::Greater));
        assert_eq!(compare(0xffff_ffff, 0), Some(Ordering::Less));

        assert_eq!(compare(1, 0xffff_ffff), Some(Ordering::Greater));
        assert_eq!(compare(0xffff_ffff, 1), Some(Ordering::Less));
    }

    #[test]
    fn serial_addition_wraps_on_overflow() {
        assert_eq!(Serial(17) + 42, Serial(59));
        assert_eq!(Serial(0xffff_ffff) + 1, Serial(0));
        assert_eq!(Serial(0xffff_ffff) + 0x7fff_ffff, Serial(0x7fff_fffe));
    }

    #[test]
    fn serial_implements_binary_encoding_and_decoding() {
        let mut e = BinaryEncoder::new();
        assert_matches!(Serial(0x12345678).encode_binary(&mut e), Ok(()));
        let binary = e.into_buffer();
        let mut d = BinaryDecoder::new(&binary);
        assert_matches!(Serial::decode_binary(&mut d), Ok(Serial(0x12345678)));
        assert_matches!(d.peek(), b"");
    }

    #[test]
    fn serial_sets_expectation_when_binary_decoding_fails() {
        let mut d = BinaryDecoder::new(b"\x12\x34\x56");
        assert_matches!(
            Serial::decode_binary(&mut d),
            Err(ref e) if
                e.expectation() == "serial number" &&
                e.position() == 0
        );
    }

    #[test]
    fn serial_implements_text_encoding_and_decoding() {
        let mut e = TextEncoder::new(Vec::new());
        assert_matches!(Serial(0x12345678).encode_text(&mut e), Ok(()));
        let text = e.into_writer();
        let mut d = TextDecoder::new(&text);
        assert_matches!(Serial::decode_text(&mut d), Ok(Serial(0x12345678)));
        assert_matches!(d.peek(), b"");
    }

    #[test]
    fn serial_sets_expectation_when_text_decoding_fails() {
        let mut d = TextDecoder::new(b"invalid");
        assert_matches!(
            Serial::decode_text(&mut d),
            Err(ref e) if
                e.expectation() == "serial number" &&
                e.position() == TextPosition::zero() &&
                e.cause().downcast_ref::<EBadSerial>() == Some(&EBadSerial)
        );
    }

    #[test]
    fn serial_has_special_text_decoding_error_for_out_of_range() {
        let mut d = TextDecoder::new(b"4294967296");
        assert_matches!(
            Serial::decode_text(&mut d),
            Err(ref e) if
                e.expectation() == "serial number" &&
                e.position() == TextPosition::zero() &&
                e.cause().downcast_ref::<EOutOfRange>() == Some(&EOutOfRange)
        );
    }
}
