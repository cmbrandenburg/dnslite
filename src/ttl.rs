use {BoxedError, ascii, std};
use binary::prelude::*;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use text::prelude::*;

// RFC 2181, section 8: "...[A] TTL value is an unsigned number, with a minimum
// value of 0, and a maximum value of 2147483647."
const MAX_TTL: u32 = 2147483647;

const EXPECTATION: &str = "TTL";

declare_static_error_type!(EBadTtl, "TTL is ill-formed");
declare_static_error_type!(EOutOfRange, "TTL is out of range");

/// `Ttl` specifies a time-to-live value.
///
/// A **time-to-live** is an unsigned 32-bit integer denoting a time duration
/// measured in seconds.
///
/// `Ttl` enforces a maximum value of 2,147,483,647 (2<sup>31</sup> - 1), as
/// defined in [RFC 2181, section
/// 8](https://tools.ietf.org/html/rfc2181#section-8). This enforcement is
/// strict, causing out-of-range text conversions to fail and converting
/// out-of-range binary values to zero automatically.
///
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ttl(u32);

impl Display for Ttl {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        self.0.fmt(f)
    }
}

impl From<Ttl> for u32 {
    fn from(x: Ttl) -> Self {
        x.0
    }
}

impl FromStr for Ttl {
    type Err = BoxedError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ttl::from_text_impl(s.as_bytes())
    }
}

impl<'a> DecodeBinary<'a> for Ttl {
    fn decode_binary(
        decoder: &mut BinaryDecoder<'a>,
    ) -> Result<Self, BinaryDecodeError> {

        u32::decode_binary(decoder)
            .map(|x| {

                // From RFC 2181, section 8: "Implementations should treat TTL
                // values received with the most significant bit set as if the
                // entire value received was zero."

                Ttl(if MAX_TTL < x { 0 } else { x })
            })
            .map_err(|mut e| {
                e.set_expectation(EXPECTATION);
                e
            })
    }
}

impl EncodeBinary for Ttl {
    fn encode_binary(
        &self,
        encoder: &mut BinaryEncoder,
    ) -> Result<(), BinaryEncodeError> {
        self.0.encode_binary(encoder)
    }
}

impl<'a, M: TextDecodeMode> DecodeText<'a, M> for Ttl {
    fn decode_text(
        decoder: &mut TextDecoder<'a, M>,
    ) -> Result<Self, TextDecodeError> {

        let position = decoder.position();

        let token = decoder.decode_token().map_err(|mut e| {
            e.set_expectation(EXPECTATION);
            e
        })?;

        Ttl::from_text_impl(token).map_err(|e| {
            TextDecodeError::new(EXPECTATION, position, e)
        })
    }
}

impl EncodeText for Ttl {
    fn encode_text<W: std::io::Write, M: TextEncodeMode>(
        &self,
        encoder: &mut TextEncoder<W, M>,
    ) -> Result<(), TextEncodeError> {
        let text = format!("{}", self.0);
        encoder.encode_token(text.as_bytes())
    }
}

impl Ttl {
    /// Constructs a zero-valued `Ttl`.
    pub fn zero() -> Ttl {
        Ttl(0)
    }

    /// Constructs a `Ttl` from a `u32` value.
    ///
    /// This method will fail if the value is out of range.
    ///
    pub fn from_u32(seconds: u32) -> Result<Ttl, BoxedError> {

        if MAX_TTL < seconds {
            return Err(EOutOfRange)?;
        }

        Ok(Ttl(seconds))
    }

    /// Constructs a `Ttl` from a `u32` value without checking that the value is
    /// valid.
    ///
    /// # Safety
    ///
    /// The DNS TTL value must be less than `0x8000_0000`. If this constraint is
    /// violated, then behavior is undefined.
    ///
    pub unsafe fn from_u32_unchecked(seconds: u32) -> Ttl {
        debug_assert!(seconds < MAX_TTL);
        Ttl(seconds)
    }

    fn from_text_impl(text: &[u8]) -> Result<Ttl, BoxedError> {

        if text.is_empty() {
            return Err(EBadTtl)?;
        }

        if text.iter().all(|&b| ascii::is_u8_ascii_digit(b)) {
            let s = unsafe { std::str::from_utf8_unchecked(text) };
            let n = u32::from_str_radix(s, 10).map_err(|_| EOutOfRange)?;
            if MAX_TTL < n {
                return Err(EOutOfRange)?;
            }
            return Ok(Ttl(n));
        }

        // Try to parse the string as a human-friendly TTL, e.g., "1h30m" ->
        // 5400 seconds.

        let mut remainder = text;
        let mut sum: u32 = 0;
        while !remainder.is_empty() {

            let n = remainder
                .iter()
                .position(|&b| !ascii::is_u8_ascii_digit(b))
                .unwrap_or_else(|| remainder.len());

            if n == 0 {
                return Err(EBadTtl)?;
            }

            let s = unsafe { std::str::from_utf8_unchecked(&remainder[..n]) };
            let value = u32::from_str_radix(s, 10).map_err(|_| EOutOfRange)?;
            remainder = &remainder[n..];

            let multiplier = match remainder.first() {
                Some(&b'w') | Some(&b'W') => 7 * 24 * 60 * 60,
                Some(&b'd') | Some(&b'D') => 24 * 60 * 60,
                Some(&b'h') | Some(&b'H') => 60 * 60,
                Some(&b'm') | Some(&b'M') => 60,
                Some(&b's') | Some(&b'S') => 1,
                None => 1,
                _ => return Err(EBadTtl)?,
            };

            if !remainder.is_empty() {
                remainder = &remainder[1..];
            }

            sum = value
                .checked_mul(multiplier)
                .and_then(|n| sum.checked_add(n))
                .ok_or(EOutOfRange)?;

            if MAX_TTL < sum {
                return Err(EOutOfRange)?;
            }
        }

        Ok(Ttl(sum))
    }

    /// Returns this TTL minus another TTL, returning `None` if underflow
    /// occurred.
    pub fn checked_sub(self, other: Ttl) -> Option<Ttl> {
        self.0.checked_sub(other.0).map(Ttl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_constructs_to_zero() {
        assert_eq!(Ttl::zero(), Ttl(0));
    }

    #[test]
    fn ttl_construction_from_u32_checks_range() {
        assert_matches!(Ttl::from_u32(0), Ok(x) if x == Ttl::zero());
        assert_matches!(
            Ttl::from_u32(0x7fff_ffff),
            Ok(x) if x == Ttl (0x7fff_ffff)
        );
        assert_matches!(
            Ttl::from_u32(0x8000_0000),
            Err(ref e) if
                e.downcast_ref::<EOutOfRange>() == Some(&EOutOfRange)
        );
        assert_matches!(
            Ttl::from_u32(0xffff_ffff),
            Err(ref e) if
                e.downcast_ref::<EOutOfRange>() == Some(&EOutOfRange)
        );
    }

    #[test]
    fn ttl_constructs_from_u32_unchecked() {
        assert_eq!(
            unsafe { Ttl::from_u32_unchecked(1234) },
            Ttl(1234)
        );
    }

    #[test]
    fn ttl_displays_in_text_form() {
        let text = format!("{}", Ttl(1234));
        let mut d = TextDecoder::new(text.as_bytes());
        assert_matches!(
            Ttl::decode_text(&mut d),
            Ok(x) if x == Ttl(1234)
        );
        assert_eq!(d.peek(), b"");
    }

    #[test]
    fn ttl_converts_into_u32() {
        assert_eq!(u32::from(Ttl(1234)), 1234);
    }

    #[test]
    fn ttl_implements_checked_subtraction() {
        let a = Ttl::from_u32(100).unwrap();
        assert_eq!(a.checked_sub(Ttl::from_u32(20).unwrap()), Some(Ttl(80)));
        assert_eq!(a.checked_sub(Ttl::from_u32(100).unwrap()), Some(Ttl(0)));
        assert_eq!(a.checked_sub(Ttl::from_u32(101).unwrap()), None);
    }

    #[test]
    fn ttl_decodes_from_binary() {

        use error::EEndOfInput;

        macro_rules! ok {
            ($source:expr, $value:expr) => {
                let mut d = BinaryDecoder::new($source);
                assert_matches!(
                    Ttl::decode_binary(&mut d),
                    Ok(x) if x == Ttl($value)
                );
            };
        }

        macro_rules! nok {
            ($source:expr, $cause_type:ty, $cause_value:expr) => {
                let mut d = BinaryDecoder::new($source);
                assert_matches!(
                    Ttl::decode_binary(&mut d),
                    Err(ref e) if
                        e.expectation() == EXPECTATION &&
                        e.position() == 0 &&
                        e.cause().downcast_ref::<$cause_type>() ==
                            Some(&$cause_value)
                );
            };
        }

        ok!(b"\x00\x00\x00\x00", 0);
        ok!(b"\x12\x34\x56\x78", 0x12345678);
        ok!(b"\x80\x00\x00\x00", 0);
        ok!(b"\xff\xff\xff\xff", 0);

        nok!(b"\x12\x34\x56", EEndOfInput, EEndOfInput);
    }

    #[test]
    fn ttl_encodes_to_binary() {
        let mut e = BinaryEncoder::new();
        assert_matches!(Ttl(0x12345678).encode_binary(&mut e), Ok(()));
        let binary = e.into_buffer();
        assert_eq!(binary, b"\x12\x34\x56\x78");
    }

    #[test]
    fn ttl_decodes_from_text() {

        // This tests both FromStr and DecodeText.

        macro_rules! ok {
            ($source:expr, $value:expr) => {
                assert_matches!(
                    Ttl::from_str($source),
                    Ok(x) if x == Ttl($value),
                    "FromStr"
                );
                let mut d = TextDecoder::new($source.as_bytes());
                assert_matches!(
                    Ttl::decode_text(&mut d),
                    Ok(x) if x == Ttl($value),
                    "DecodeText"
                );
            };
        }

        macro_rules! nok {
            ($source:expr, $cause_type:ty, $cause_value:expr) => {
                assert_matches!(
                    Ttl::from_str($source),
                    Err(ref e) if
                        e.downcast_ref::<$cause_type>() == Some(&$cause_value),
                    "FromStr"
                );
                let mut d = TextDecoder::new($source.as_bytes());
                assert_matches!(
                    Ttl::decode_text(&mut d),
                    Err(ref e) if
                        e.expectation() == EXPECTATION &&
                        e.position() == TextPosition::zero() &&
                        e.cause().downcast_ref::<$cause_type>() ==
                            Some(&$cause_value),
                        "DecodeText"
                );
            };
        }

        ok!("0", 0);
        ok!("1", 1);
        ok!("1234", 1234);

        ok!("1w1d1h1m1s", 694861);
        ok!("1W1D1H1M1S", 694861);
        ok!("1w1d1h1m1", 694861);
        ok!("2w3d4h5m6s", 1483506);
        ok!("2W3D4H5M6S", 1483506);
        ok!("2w3d4h5m6", 1483506);
        ok!("1w", 604800);
        ok!("1d", 86400);
        ok!("1h", 3600);
        ok!("1m", 60);
        ok!("1s", 1);

        nok!("invalid", EBadTtl, EBadTtl);
        nok!("1x2", EBadTtl, EBadTtl);

        ok!("2147483647", 2147483647);
        ok!("3550w5d3h14m7s", 2147483647);
        nok!("2147483648", EOutOfRange, EOutOfRange);
        nok!("4294967296", EOutOfRange, EOutOfRange);
        nok!("3550w5d3h14m8s", EOutOfRange, EOutOfRange);
        nok!("3551w", EOutOfRange, EOutOfRange);
        nok!("24856d", EOutOfRange, EOutOfRange);
        nok!("596524h", EOutOfRange, EOutOfRange);
        nok!("35791395m", EOutOfRange, EOutOfRange);
        nok!("35791395m", EOutOfRange, EOutOfRange);
        nok!("2147483648s", EOutOfRange, EOutOfRange);
        nok!("-0", EBadTtl, EBadTtl);
        nok!("-1234", EBadTtl, EBadTtl);

        // As a special case, the empty string yields a different error
        // depending on whether we're using FromStr or DecodeText.

        {
            use error::EEndOfInput;

            assert_matches!(
                Ttl::from_str(""),
                Err(ref e) if
                    e.downcast_ref::<EBadTtl>() == Some(&EBadTtl)
            );

            let mut d = TextDecoder::new(b"");
            assert_matches!(
                Ttl::decode_text(&mut d),
                Err(ref e) if
                    e.expectation() == EXPECTATION &&
                    e.position() == TextPosition::zero() &&
                    e.cause().downcast_ref::<EEndOfInput>() ==
                        Some(&EEndOfInput)
            );
        }
    }

    #[test]
    fn ttl_encodes_to_text() {

        macro_rules! ok {
            ($value:expr) => {
                let mut e = TextEncoder::new(Vec::new());
                let ttl = Ttl::from_u32($value).unwrap();
                assert_matches!(ttl.encode_text(&mut e), Ok(()));
                let text = e.into_writer();
                let mut d = TextDecoder::new(&text);
                assert_matches!(
                    Ttl::decode_text(&mut d),
                    Ok(x) if x == Ttl($value)
                );
            };
        }

        ok!(0);
        ok!(1234);
        ok!(0x7fff_ffff);
    }
}
