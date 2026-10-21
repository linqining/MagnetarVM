//! SHA-256 Fiat–Shamir transcript.
//!
//! The transcript binds every absorbed message with a length-prefixed label
//! and a running counter. It is intentionally hash-agile at the API boundary:
//! callers never see the internal state except through `challenge`.

use sha2::{Digest, Sha256};

pub const TRANSCRIPT_DOMAIN: &[u8] = b"magnetar-transcript-v1";

#[derive(Clone, Debug)]
pub struct Sha256Transcript {
    state: [u8; 32],
    counter: u64,
}

impl Sha256Transcript {
    pub fn new(protocol: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(TRANSCRIPT_DOMAIN);
        absorb_bytes(&mut hasher, b"protocol", protocol.as_bytes());
        Self {
            state: hasher.finalize().into(),
            counter: 0,
        }
    }

    pub fn absorb(&mut self, label: &str, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.state);
        absorb_bytes(&mut hasher, label.as_bytes(), data);
        hasher.update(self.counter.to_le_bytes());
        self.state = hasher.finalize().into();
        self.counter = self.counter.wrapping_add(1);
    }

    pub fn challenge_bytes(&mut self, label: &str, len: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(len);
        let mut block = 0u64;
        while output.len() < len {
            let mut hasher = Sha256::new();
            hasher.update(self.state);
            absorb_bytes(&mut hasher, b"challenge", label.as_bytes());
            hasher.update(self.counter.to_le_bytes());
            hasher.update(block.to_le_bytes());
            let digest: [u8; 32] = hasher.finalize().into();
            output.extend_from_slice(&digest);
            block = block.wrapping_add(1);
        }
        output.truncate(len);
        self.state = Sha256::digest(&output).into();
        self.counter = self.counter.wrapping_add(1);
        output
    }

    pub fn challenge_u64(&mut self, label: &str) -> u64 {
        let bytes = self.challenge_bytes(label, 8);
        u64::from_le_bytes(bytes.try_into().expect("8 bytes"))
    }

    pub fn challenge_32(&mut self, label: &str) -> [u8; 32] {
        self.challenge_bytes(label, 32)
            .try_into()
            .expect("32 bytes")
    }

    pub fn state(&self) -> [u8; 32] {
        self.state
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn sha256_labeled(label: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    absorb_bytes(&mut hasher, label, data);
    hasher.finalize().into()
}

fn absorb_bytes(hasher: &mut Sha256, label: &[u8], data: &[u8]) {
    hasher.update((label.len() as u64).to_le_bytes());
    hasher.update(label);
    hasher.update((data.len() as u64).to_le_bytes());
    hasher.update(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_is_deterministic() {
        let mut a = Sha256Transcript::new("test");
        let mut b = Sha256Transcript::new("test");
        a.absorb("x", b"hello");
        b.absorb("x", b"hello");
        assert_eq!(a.challenge_32("r"), b.challenge_32("r"));
    }

    #[test]
    fn absorbing_changes_the_challenge() {
        let mut a = Sha256Transcript::new("test");
        let mut b = Sha256Transcript::new("test");
        a.absorb("x", b"hello");
        b.absorb("x", b"world");
        assert_ne!(a.challenge_32("r"), b.challenge_32("r"));
    }

    #[test]
    fn domains_are_separated() {
        let mut a = Sha256Transcript::new("protocol-a");
        let mut b = Sha256Transcript::new("protocol-b");
        assert_ne!(a.challenge_32("r"), b.challenge_32("r"));
    }

    #[test]
    fn labels_are_separated() {
        let mut a = Sha256Transcript::new("test");
        let mut b = Sha256Transcript::new("test");
        assert_ne!(a.challenge_32("left"), b.challenge_32("right"));
    }

    #[test]
    fn sha256_matches_known_vector() {
        let digest = sha256(b"abc");
        assert_eq!(
            digest,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
    }
}
