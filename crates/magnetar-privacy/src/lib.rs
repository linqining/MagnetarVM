//! Privacy boundary.
//!
//! Magnetar is a transparent succinct argument; its witness is not hidden.
//! This crate keeps zero-knowledge as a separate, opt-in concern.

use magnetar_transcript::{sha256, sha256_labeled};
use rand::{rngs::OsRng, CryptoRng, RngCore};
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivacyMode {
    Transparent,
    ZeroKnowledge,
}

impl PrivacyMode {
    pub fn is_zero_knowledge(self) -> bool {
        self == PrivacyMode::ZeroKnowledge
    }
}

pub trait HidingCommitment {
    type Commitment;
    type Blinding;
    type Error;

    fn commit(&self, value: &[u8]) -> Result<(Self::Commitment, Self::Blinding), Self::Error>;

    fn verify(
        &self,
        commitment: &Self::Commitment,
        value: &[u8],
        blinding: &Self::Blinding,
    ) -> Result<bool, Self::Error>;
}

/// A deterministic hash commitment. It binds but does not hide: identical
/// values produce identical commitments. It exists to exercise the interface.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoPrivacy;

impl HidingCommitment for NoPrivacy {
    type Commitment = [u8; 32];
    type Blinding = [u8; 32];
    type Error = PrivacyError;

    fn commit(&self, value: &[u8]) -> Result<([u8; 32], [u8; 32]), Self::Error> {
        let blinding = sha256_labeled(b"no-privacy-blinding", value);
        let mut input = Vec::with_capacity(64 + value.len());
        input.extend_from_slice(&blinding);
        input.extend_from_slice(value);
        Ok((sha256_labeled(b"no-privacy-commit", &input), blinding))
    }

    fn verify(
        &self,
        commitment: &[u8; 32],
        value: &[u8],
        blinding: &[u8; 32],
    ) -> Result<bool, Self::Error> {
        let mut input = Vec::with_capacity(64 + value.len());
        input.extend_from_slice(blinding);
        input.extend_from_slice(value);
        Ok(sha256_labeled(b"no-privacy-commit", &input) == *commitment)
    }
}

/// Randomized hash commitment: computationally hiding under a random oracle,
/// with a fresh 32-byte blinding value per commitment.
#[derive(Clone, Copy, Debug, Default)]
pub struct HidingHashCommitment;

impl HidingHashCommitment {
    pub fn commit_with<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        value: &[u8],
    ) -> Result<([u8; 32], [u8; 32]), PrivacyError> {
        let mut blinding = [0u8; 32];
        rng.fill_bytes(&mut blinding);
        let mut input = Vec::with_capacity(32 + value.len());
        input.extend_from_slice(&blinding);
        input.extend_from_slice(value);
        Ok((sha256_labeled(b"hiding-commit", &input), blinding))
    }
}

impl HidingCommitment for HidingHashCommitment {
    type Commitment = [u8; 32];
    type Blinding = [u8; 32];
    type Error = PrivacyError;

    fn commit(&self, value: &[u8]) -> Result<([u8; 32], [u8; 32]), Self::Error> {
        let mut rng = OsRng;
        self.commit_with(&mut rng, value)
    }

    fn verify(
        &self,
        commitment: &[u8; 32],
        value: &[u8],
        blinding: &[u8; 32],
    ) -> Result<bool, Self::Error> {
        let mut input = Vec::with_capacity(32 + value.len());
        input.extend_from_slice(blinding);
        input.extend_from_slice(value);
        Ok(sha256_labeled(b"hiding-commit", &input) == *commitment)
    }
}

/// Placeholder for the blinded-commitment / ZK-sum-check layer.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnimplementedZeroKnowledge;

impl HidingCommitment for UnimplementedZeroKnowledge {
    type Commitment = [u8; 32];
    type Blinding = [u8; 32];
    type Error = PrivacyError;

    fn commit(&self, _value: &[u8]) -> Result<([u8; 32], [u8; 32]), Self::Error> {
        Err(PrivacyError::Unimplemented)
    }

    fn verify(
        &self,
        _commitment: &[u8; 32],
        _value: &[u8],
        _blinding: &[u8; 32],
    ) -> Result<bool, Self::Error> {
        Err(PrivacyError::Unimplemented)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PrivacyError {
    #[error("zero-knowledge layer is not implemented")]
    Unimplemented,
    #[error("commitment does not match")]
    Mismatch,
}

/// Convenience for callers that only need a binding digest.
pub fn binding_digest(value: &[u8]) -> [u8; 32] {
    sha256(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_privacy_binds_values() {
        let scheme = NoPrivacy;
        let (commitment, blinding) = scheme.commit(b"hello").unwrap();
        assert!(scheme.verify(&commitment, b"hello", &blinding).unwrap());
        assert!(!scheme.verify(&commitment, b"world", &blinding).unwrap());
    }

    #[test]
    fn hiding_commitment_uses_fresh_randomness() {
        let scheme = HidingHashCommitment;
        let (first, first_blinding) = scheme.commit(b"hello").unwrap();
        let (second, second_blinding) = scheme.commit(b"hello").unwrap();
        assert_ne!(first, second);
        assert!(scheme.verify(&first, b"hello", &first_blinding).unwrap());
        assert!(scheme.verify(&second, b"hello", &second_blinding).unwrap());
        assert!(!scheme.verify(&first, b"world", &first_blinding).unwrap());
    }

    #[test]
    fn zk_backend_is_explicitly_unimplemented() {
        assert_eq!(
            UnimplementedZeroKnowledge.commit(b"hello"),
            Err(PrivacyError::Unimplemented)
        );
        assert_eq!(
            UnimplementedZeroKnowledge.verify(&[0u8; 32], b"hello", &[0u8; 32]),
            Err(PrivacyError::Unimplemented)
        );
    }

    #[test]
    fn privacy_modes_and_binding_digests() {
        assert!(!PrivacyMode::Transparent.is_zero_knowledge());
        assert!(PrivacyMode::ZeroKnowledge.is_zero_knowledge());
        assert_eq!(binding_digest(b"value"), sha256(b"value"));
        assert_ne!(binding_digest(b"value"), binding_digest(b"other"));
    }

    #[test]
    fn hiding_commitment_rejects_wrong_blindings() {
        let scheme = HidingHashCommitment;
        let (commitment, blinding) = scheme.commit(b"hello").unwrap();
        let mut wrong = blinding;
        wrong[0] ^= 1;
        assert!(!scheme.verify(&commitment, b"hello", &wrong).unwrap());
        assert!(!scheme.verify(&commitment, b"other", &blinding).unwrap());
    }
}
