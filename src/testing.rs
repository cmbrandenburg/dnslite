#[cfg(test)]
pub use self::test_only::{HashRecorder, hash_exact};

#[cfg(test)]
mod test_only {
    use std::hash::{Hash, Hasher};

    #[derive(Debug, Eq, PartialEq)]
    pub struct HashRecorder(Vec<u8>);

    impl HashRecorder {
        pub fn new() -> Self {
            HashRecorder(Vec::new())
        }
    }

    impl Hasher for HashRecorder {
        fn finish(&self) -> u64 {
            panic!("HashRecorder does not produce hash values");
        }

        fn write(&mut self, bytes: &[u8]) {
            self.0.extend(bytes)
        }
    }

    pub fn hash_exact<T: Hash>(item: &T) -> Vec<u8> {
        let mut h = HashRecorder::new();
        item.hash(&mut h);
        h.0
    }
}
