#[allow(unused)] // otherwise warns on nightly, as of 2017-11-18
use std::ascii::AsciiExt;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use std::ops::{Deref, DerefMut};

// AsciiCaseBytes wraps a byte slice with ASCII-case-insensitive semantics. It
// is guaranteed to be a DST (dynamically sized type).
//
// Note that AsciiCaseBytes ignores case only when comparing with another
// AsciiCaseBytes. Otherwise, such as when coercing to a &[u8] and comparing
// with another &[u8], it's case-sensitive.
//
#[derive(Debug, Eq)]
pub struct AsciiCaseBytes {
    inner: [u8],
}

impl Deref for AsciiCaseBytes {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for AsciiCaseBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl PartialEq for AsciiCaseBytes {
    fn eq(&self, other: &AsciiCaseBytes) -> bool {
        self.inner.eq_ignore_ascii_case(&other.inner)
    }
}

impl Hash for AsciiCaseBytes {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for &c in self.inner.iter() {
            state.write_u8(c.to_ascii_lowercase());
        }
    }
}

impl PartialOrd for AsciiCaseBytes {
    fn partial_cmp(&self, other: &AsciiCaseBytes) -> Option<Ordering> {
        Some(Ord::cmp(self, other))
    }
}

impl Ord for AsciiCaseBytes {
    fn cmp(&self, other: &AsciiCaseBytes) -> Ordering {

        let mut a = self.inner.iter();
        let mut b = other.inner.iter();

        loop {
            match (a.next(), b.next()) {
                (Some(a), Some(b)) => {
                    match a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase()) {
                        Ordering::Equal => continue,
                        x => return x,
                    }
                }
                (Some(_), None) => return Ordering::Greater,
                (None, Some(_)) => return Ordering::Less,
                (None, None) => return Ordering::Equal,
            }
        }
    }
}

impl AsciiCaseBytes {
    #[cfg(test)]
    pub fn new(s: &[u8]) -> &Self {
        use std;
        unsafe { std::mem::transmute(s) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_case_bytes_compares_and_hashes_ascii_case_insensitive() {

        use std::cmp::Ordering;

        fn make(s: &[u8]) -> (&AsciiCaseBytes, Vec<u8>) {
            use testing;
            let s = AsciiCaseBytes::new(s);
            let h = testing::hash_exact(&s);
            (s, h)
        }

        macro_rules! tc {
            ($lhs:expr, eq, $rhs:expr) => {
                let (lhs, lhash) = make($lhs.as_ref());
                let (rhs, rhash) = make($rhs.as_ref());
                assert_eq!(lhs, rhs);
                assert_eq!(rhs, lhs);
                assert_eq!(lhs.cmp(&rhs), Ordering::Equal);
                assert_eq!(rhs.cmp(&lhs), Ordering::Equal);
                assert_eq!(lhash, rhash);
            };
            ($lhs:expr, lt, $rhs:expr) => {
                let (lhs, lhash) = make($lhs.as_ref());
                let (rhs, rhash) = make($rhs.as_ref());
                assert_ne!(lhs, rhs);
                assert_ne!(rhs, lhs);
                assert_eq!(lhs.cmp(&rhs), Ordering::Less);
                assert_eq!(rhs.cmp(&lhs), Ordering::Greater);
                assert_ne!(lhash, rhash);
            };
        }

        tc!("", eq, "");
        tc!("", lt, "alpha");
        tc!("alpha", eq, "alpha");
        tc!("alpha", lt, "alpha-bravo");
        tc!("alpha", lt, "bravo");
        tc!("alpha", eq, "ALPHA");
        tc!("alpha", lt, "BRAVO");
        tc!("ALPHA", lt, "bravo");

        // Test for transitivity for the case that three strings differ by ASCII
        // case because of a character that falls between uppercase and
        // lowercase.
        //
        // (lower == upper) ->
        //  ((lower < between) && (upper < between))
        //  OR
        //  ((between < lower) && (between < upper)).

        let lower = make(b"alpha").0;
        let upper = make(b"Alpha").0;
        let between = make(b"_lpha").0;

        assert_eq!(lower.cmp(&upper), Ordering::Equal);
        assert_eq!(upper.cmp(&lower), Ordering::Equal);
        assert_eq!(upper.cmp(&between), lower.cmp(&between));
    }
}
