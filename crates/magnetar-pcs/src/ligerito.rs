//! Ligerito index-opening PCS over the binary tower field.
//!
//! This wraps the vendored `ligerito` crate. Ligerito commits to a vector of
//! field elements and proves values at chosen indices; it is an index-opening
//! commitment, not a multilinear point-evaluation PCS. The intended use in
//! this workspace is memory/register tables, where openings are indexed by
//! address.

use std::marker::PhantomData;

use ligerito::eval_proof::EvalClaim;
use ligerito::{
    hardcoded_config_12, hardcoded_config_12_verifier, hardcoded_config_16,
    hardcoded_config_16_verifier, hardcoded_config_20, hardcoded_config_20_verifier,
    hardcoded_config_24, hardcoded_config_24_verifier, hardcoded_config_26,
    hardcoded_config_26_verifier, hardcoded_config_28, hardcoded_config_28_verifier,
    hardcoded_config_30, hardcoded_config_30_verifier, prove_with_evaluations,
    verify_with_evaluations, FiatShamir, FinalizedLigeritoProof, VerifierConfig,
};
use ligerito_binary_fields::BinaryElem128;
use magnetar_constraint::F2_128;

use crate::PcsError;

pub type LigeritoProof = FinalizedLigeritoProof<BinaryElem128, BinaryElem128>;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LigeritoCommitment {
    pub root: [u8; 32],
    pub log_size: usize,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LigeritoIndexOpening {
    pub indices: Vec<u64>,
    pub values: Vec<F2_128>,
    pub proof: LigeritoProof,
}

impl LigeritoIndexOpening {
    pub fn encoded_len(&self) -> Result<usize, PcsError> {
        bincode::serialize(self)
            .map(|bytes| bytes.len())
            .map_err(|error| PcsError::Encoding(error.to_string()))
    }
}

/// Ligerito PCS for power-of-two vector sizes 2^12 through 2^30.
#[derive(Clone, Copy, Debug)]
pub struct LigeritoPcs {
    pub log_size: usize,
}

impl LigeritoPcs {
    pub fn new(log_size: usize) -> Result<Self, PcsError> {
        match log_size {
            12 | 16 | 20 | 24 | 26 | 28 | 30 => Ok(Self { log_size }),
            other => Err(PcsError::UnsupportedLigeritoSize(other)),
        }
    }

    pub fn size(&self) -> usize {
        1usize << self.log_size
    }

    fn pad(&self, values: &[F2_128]) -> Result<Vec<BinaryElem128>, PcsError> {
        if values.is_empty() || values.len() > self.size() {
            return Err(PcsError::ShapeMismatch);
        }
        let mut poly: Vec<BinaryElem128> = values
            .iter()
            .map(|value| BinaryElem128::from(value.value()))
            .collect();
        poly.resize(self.size(), BinaryElem128::from(0u128));
        Ok(poly)
    }

    fn verifier_config(&self) -> VerifierConfig {
        match self.log_size {
            12 => hardcoded_config_12_verifier(),
            16 => hardcoded_config_16_verifier(),
            20 => hardcoded_config_20_verifier(),
            24 => hardcoded_config_24_verifier(),
            26 => hardcoded_config_26_verifier(),
            28 => hardcoded_config_28_verifier(),
            30 => hardcoded_config_30_verifier(),
            other => unreachable!("validated log size {other}"),
        }
    }

    fn config(&self) -> ligerito::ProverConfig<BinaryElem128, BinaryElem128> {
        let t = PhantomData::<BinaryElem128>;
        let u = PhantomData::<BinaryElem128>;
        match self.log_size {
            12 => hardcoded_config_12(t, u),
            16 => hardcoded_config_16(t, u),
            20 => hardcoded_config_20(t, u),
            24 => hardcoded_config_24(t, u),
            26 => hardcoded_config_26(t, u),
            28 => hardcoded_config_28(t, u),
            30 => hardcoded_config_30(t, u),
            other => unreachable!("validated log size {other}"),
        }
    }

    pub fn commit(&self, values: &[F2_128]) -> Result<LigeritoCommitment, PcsError> {
        let poly = self.pad(values)?;
        let claims = [EvalClaim {
            index: 0,
            value: poly[0],
        }];
        let proof =
            prove_with_evaluations(&self.config(), &poly, &claims, FiatShamir::new_sha256(0))
                .map_err(|error| PcsError::Ligerito(error.to_string()))?;
        let root = proof
            .initial_ligero_cm
            .root
            .root
            .ok_or_else(|| PcsError::Ligerito("missing commitment root".into()))?;
        Ok(LigeritoCommitment {
            root,
            log_size: self.log_size,
        })
    }

    pub fn open(
        &self,
        commitment: &LigeritoCommitment,
        values: &[F2_128],
        indices: &[u64],
    ) -> Result<LigeritoIndexOpening, PcsError> {
        if commitment.log_size != self.log_size {
            return Err(PcsError::ShapeMismatch);
        }
        if indices.is_empty() {
            return Err(PcsError::EmptyIndices);
        }
        let poly = self.pad(values)?;
        let mut seen = std::collections::HashSet::with_capacity(indices.len());
        let mut claims = Vec::with_capacity(indices.len());
        let mut opened = Vec::with_capacity(indices.len());
        for &index in indices {
            let index =
                usize::try_from(index).map_err(|_| PcsError::IndexOutOfRange(usize::MAX))?;
            if index >= self.size() {
                return Err(PcsError::IndexOutOfRange(index));
            }
            if !seen.insert(index) {
                return Err(PcsError::DuplicateIndex(index));
            }
            claims.push(EvalClaim {
                index,
                value: poly[index],
            });
            opened.push(values[index]);
        }
        let proof =
            prove_with_evaluations(&self.config(), &poly, &claims, FiatShamir::new_sha256(0))
                .map_err(|error| PcsError::Ligerito(error.to_string()))?;
        if proof.initial_ligero_cm.root.root != Some(commitment.root) {
            return Err(PcsError::EvaluationMismatch);
        }
        Ok(LigeritoIndexOpening {
            indices: indices.to_vec(),
            values: opened,
            proof,
        })
    }

    pub fn verify(
        &self,
        commitment: &LigeritoCommitment,
        opening: &LigeritoIndexOpening,
    ) -> Result<bool, PcsError> {
        if commitment.log_size != self.log_size
            || opening.indices.len() != opening.values.len()
            || opening.indices.is_empty()
            || opening.proof.initial_ligero_cm.root.root != Some(commitment.root)
        {
            return Ok(false);
        }
        let mut claims = Vec::with_capacity(opening.indices.len());
        let mut seen = std::collections::HashSet::with_capacity(opening.indices.len());
        for (&index, value) in opening.indices.iter().zip(&opening.values) {
            let index =
                usize::try_from(index).map_err(|_| PcsError::IndexOutOfRange(usize::MAX))?;
            if index >= self.size() || !seen.insert(index) {
                return Ok(false);
            }
            claims.push(EvalClaim {
                index,
                value: BinaryElem128::from(value.value()),
            });
        }
        verify_with_evaluations::<BinaryElem128, BinaryElem128>(
            &self.verifier_config(),
            &opening.proof,
            &claims,
            FiatShamir::new_sha256(0),
        )
        .map_err(|error| PcsError::Ligerito(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(size: usize) -> Vec<F2_128> {
        (0..size)
            .map(|index| F2_128::from((index as u64).wrapping_mul(17) + 3))
            .collect()
    }

    #[test]
    fn ligerito_index_openings_verify_and_reject_tampering() {
        let pcs = LigeritoPcs::new(12).unwrap();
        let values = values(pcs.size());
        let commitment = pcs.commit(&values).unwrap();
        let indices = [0, 7, 4095];
        let opening = pcs.open(&commitment, &values, &indices).unwrap();
        assert!(pcs.verify(&commitment, &opening).unwrap());

        let mut wrong_value = opening.clone();
        wrong_value.values[1] = wrong_value.values[1] + F2_128::from(1u64);
        assert!(!pcs.verify(&commitment, &wrong_value).unwrap());

        let mut wrong_index = opening.clone();
        wrong_index.indices[1] = 8;
        assert!(!pcs.verify(&commitment, &wrong_index).unwrap());

        let mut wrong_commitment = commitment.clone();
        wrong_commitment.root[0] ^= 1;
        assert!(!pcs.verify(&wrong_commitment, &opening).unwrap());

        let encoded = opening.encoded_len().unwrap();
        assert!(encoded > 0);
    }

    #[test]
    fn ligerito_rejects_bad_shapes_and_duplicate_indices() {
        let pcs = LigeritoPcs::new(12).unwrap();
        let values = values(pcs.size());
        let commitment = pcs.commit(&values).unwrap();
        assert!(matches!(
            pcs.open(&commitment, &values, &[]),
            Err(PcsError::EmptyIndices)
        ));
        assert!(matches!(
            pcs.open(&commitment, &values, &[1, 1]),
            Err(PcsError::DuplicateIndex(1))
        ));
        assert!(matches!(
            pcs.open(&commitment, &values, &[4096]),
            Err(PcsError::IndexOutOfRange(4096))
        ));
        assert!(matches!(
            LigeritoPcs::new(13),
            Err(PcsError::UnsupportedLigeritoSize(13))
        ));
    }
}
