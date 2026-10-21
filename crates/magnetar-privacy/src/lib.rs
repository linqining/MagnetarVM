//! Privacy boundary.
//!
//! Magnetar is a transparent succinct argument; its witness is not hidden.
//! This crate keeps zero-knowledge as a separate, opt-in concern.

use magnetar_transcript::{sha256, sha256_labeled};
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
    fn zk_backend_is_explicitly_unimplemented() {
        assert_eq!(
            UnimplementedZeroKnowledge.commit(b"hello"),
            Err(PrivacyError::Unimplemented)
        );
    }
}
