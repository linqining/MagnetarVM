//! SHA-256 Fiat–Shamir transcript.
//!
//! The transcript binds every absorbed message with a length-prefixed label
//! and a running counter. It is intentionally hash-agile at the API boundary:
//! callers never see the internal state except through `challenge`.

use sha2::{Digest, Sha256};
use sha3::Sha3_256;

pub const TRANSCRIPT_DOMAIN: &[u8] = b"magnetar-transcript-v1";

/// Common interface for SHA-256 and SHA3-256 Fiat–Shamir transcripts.
pub trait Transcript {
    fn absorb(&mut self, label: &str, data: &[u8]);
    fn challenge_bytes(&mut self, label: &str, len: usize) -> Vec<u8>;

    fn challenge_u64(&mut self, label: &str) -> u64 {
        let bytes = self.challenge_bytes(label, 8);
        u64::from_le_bytes(bytes.try_into().expect("8 bytes"))
    }

    fn challenge_32(&mut self, label: &str) -> [u8; 32] {
        self.challenge_bytes(label, 32)
            .try_into()
            .expect("32 bytes")
    }
}

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

/// SHA3-256 transcript with the same domain-separated message framing as
/// `Sha256Transcript`.
#[derive(Clone, Debug)]
pub struct Sha3Transcript {
    state: [u8; 32],
    counter: u64,
}

impl Sha3Transcript {
    pub fn new(protocol: &str) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(TRANSCRIPT_DOMAIN);
        absorb_bytes(&mut hasher, b"protocol", protocol.as_bytes());
        Self {
            state: hasher.finalize().into(),
            counter: 0,
        }
    }

    pub fn absorb(&mut self, label: &str, data: &[u8]) {
        let mut hasher = Sha3_256::new();
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
            let mut hasher = Sha3_256::new();
            hasher.update(self.state);
            absorb_bytes(&mut hasher, b"challenge", label.as_bytes());
            hasher.update(self.counter.to_le_bytes());
            hasher.update(block.to_le_bytes());
            let digest: [u8; 32] = hasher.finalize().into();
            output.extend_from_slice(&digest);
            block = block.wrapping_add(1);
        }
        output.truncate(len);
        self.state = Sha3_256::digest(&output).into();
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

impl Transcript for Sha256Transcript {
    fn absorb(&mut self, label: &str, data: &[u8]) {
        Sha256Transcript::absorb(self, label, data);
    }

    fn challenge_bytes(&mut self, label: &str, len: usize) -> Vec<u8> {
        Sha256Transcript::challenge_bytes(self, label, len)
    }
}

impl Transcript for Sha3Transcript {
    fn absorb(&mut self, label: &str, data: &[u8]) {
        Sha3Transcript::absorb(self, label, data);
    }

    fn challenge_bytes(&mut self, label: &str, len: usize) -> Vec<u8> {
        Sha3Transcript::challenge_bytes(self, label, len)
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

fn absorb_bytes<D: Digest>(hasher: &mut D, label: &[u8], data: &[u8]) {
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
    fn sha3_transcript_is_deterministic_and_domain_separated() {
        let mut a = Sha3Transcript::new("test");
        let mut b = Sha3Transcript::new("test");
        let mut c = Sha3Transcript::new("other");
        a.absorb("x", b"hello");
        b.absorb("x", b"hello");
        assert_eq!(a.challenge_32("r"), b.challenge_32("r"));
        assert_ne!(a.challenge_32("r"), c.challenge_32("r"));
    }

    #[test]
    fn sha3_matches_known_vector() {
        let digest: [u8; 32] = Sha3_256::digest(b"abc").into();
        assert_eq!(
            digest,
            [
                0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3,
                0x90, 0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45,
                0x11, 0x43, 0x15, 0x32
            ]
        );
    }

    #[test]
    fn challenge_lengths_and_counters_are_consistent() {
        let mut transcript = Sha256Transcript::new("test");
        assert_eq!(transcript.counter(), 0);
        assert!(transcript.challenge_bytes("r", 0).is_empty());
        assert_eq!(transcript.counter(), 1);
        assert_eq!(transcript.challenge_bytes("r", 1).len(), 1);
        assert_eq!(transcript.challenge_bytes("r", 31).len(), 31);
        assert_eq!(transcript.challenge_bytes("r", 65).len(), 65);
        assert_eq!(transcript.counter(), 4);
        assert_ne!(transcript.state(), [0u8; 32]);

        let mut sha3 = Sha3Transcript::new("test");
        assert_eq!(sha3.counter(), 0);
        assert_eq!(sha3.challenge_bytes("r", 33).len(), 33);
        assert_eq!(sha3.counter(), 1);
        assert_eq!(sha3.challenge_u64("r").to_le_bytes().len(), 8);
        assert_eq!(sha3.counter(), 2);
    }

    #[test]
    fn labeled_hashing_binds_the_label_and_data() {
        assert_eq!(
            sha256_labeled(b"label", b"data"),
            sha256_labeled(b"label", b"data")
        );
        assert_ne!(
            sha256_labeled(b"label", b"data"),
            sha256_labeled(b"other", b"data")
        );
        assert_ne!(
            sha256_labeled(b"label", b"data"),
            sha256_labeled(b"label", b"other")
        );
        assert_ne!(sha256_labeled(b"label", b"data"), sha256(b"data"));
    }

    #[test]
    fn trait_object_and_inherent_methods_agree() {
        let mut inherent = Sha256Transcript::new("test");
        let mut dynamic = Sha256Transcript::new("test");
        inherent.absorb("x", b"hello");
        let expected = inherent.challenge_u64("r");

        let transcript: &mut dyn Transcript = &mut dynamic;
        transcript.absorb("x", b"hello");
        assert_eq!(transcript.challenge_u64("r"), expected);
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
