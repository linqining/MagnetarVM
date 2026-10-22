//! Reference MosaicPCS packing and lift.
//!
//! Components are placed on disjoint aligned subcubes of one packed
//! polynomial `G`. A claim on component `i` at point `r` lifts to a claim on
//! `G` at `r || suffix_i` without an adapter sum-check. Batching and ring
//! switching are not yet implemented.

use crate::p3_pcs::{P3BinaryPcs, P3Commitment, P3Opening};
use magnetar_constraint::F2_128;
use magnetar_proof::{eq, prove, verify_rounds, Mle, Pcs, ProofError, SumcheckProof};
use magnetar_transcript::Sha256Transcript;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct MosaicComponent {
    pub size_bits: usize,
    pub offset: usize,
    pub suffix: Vec<F2_128>,
}

#[derive(Clone, Debug)]
pub struct PackedMosaic {
    pub total_bits: usize,
    pub components: Vec<MosaicComponent>,
    pub values: Vec<F2_128>,
}

#[derive(Debug, Error)]
pub enum MosaicError {
    #[error("mosaic needs at least one component")]
    Empty,
    #[error("component size must be a nonzero power of two, got {0}")]
    InvalidSize(usize),
    #[error("component sizes overflow the packed table")]
    Overflow,
    #[error("component index {0} is out of range")]
    Index(usize),
    #[error(transparent)]
    Proof(#[from] ProofError),
    #[error("batching needs at least one claim")]
    EmptyBatch,
    #[error("batching claim point has the wrong arity")]
    PointArity,
    #[error("batched sumcheck failed")]
    BatchSumcheck,
}

impl PackedMosaic {
    pub fn new(components: &[Vec<F2_128>]) -> Result<Self, MosaicError> {
        if components.is_empty() {
            return Err(MosaicError::Empty);
        }
        for component in components {
            if component.is_empty() || !component.len().is_power_of_two() {
                return Err(MosaicError::InvalidSize(component.len()));
            }
        }
        let total_size = components
            .iter()
            .try_fold(0usize, |sum, component| sum.checked_add(component.len()))
            .ok_or(MosaicError::Overflow)?;
        let total_bits = total_size.next_power_of_two().trailing_zeros() as usize;
        let mut values = vec![F2_128::from(0u64); 1usize << total_bits];
        let mut layout = Vec::with_capacity(components.len());
        let mut offset = 0usize;
        for component in components {
            let size_bits = component.len().trailing_zeros() as usize;
            let aligned = (offset + component.len() - 1) & !(component.len() - 1);
            if aligned + component.len() > values.len() {
                return Err(MosaicError::Overflow);
            }
            values[aligned..aligned + component.len()].copy_from_slice(component);
            let suffix_bits = total_bits - size_bits;
            let suffix_value = aligned >> size_bits;
            let suffix = (0..suffix_bits)
                .map(|bit| F2_128::from(((suffix_value >> bit) & 1) as u64))
                .collect();
            layout.push(MosaicComponent {
                size_bits,
                offset: aligned,
                suffix,
            });
            offset = aligned + component.len();
        }
        Ok(Self {
            total_bits,
            components: layout,
            values,
        })
    }

    /// Lift a component point to a point on the packed polynomial.
    pub fn lift(&self, index: usize, point: &[F2_128]) -> Result<Vec<F2_128>, MosaicError> {
        let component = self
            .components
            .get(index)
            .ok_or(MosaicError::Index(index))?;
        if point.len() != component.size_bits {
            return Err(MosaicError::Index(index));
        }
        let mut lifted = point.to_vec();
        lifted.extend_from_slice(&component.suffix);
        Ok(lifted)
    }

    pub fn eval_component(&self, index: usize, point: &[F2_128]) -> Result<F2_128, MosaicError> {
        let component = self
            .components
            .get(index)
            .ok_or(MosaicError::Index(index))?;
        let values =
            &self.values[component.offset..component.offset + (1usize << component.size_bits)];
        Ok(Mle::new(values.to_vec())?.eval(point)?)
    }

    pub fn eval_packed(&self, point: &[F2_128]) -> Result<F2_128, MosaicError> {
        Ok(Mle::new(self.values.clone())?.eval(point)?)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MosaicBatchingProof {
    pub sumcheck: SumcheckProof<F2_128>,
    pub point: Vec<F2_128>,
    pub value: F2_128,
}

fn challenge(transcript: &mut Sha256Transcript, label: &str) -> F2_128 {
    let bytes = transcript.challenge_32(label);
    let mut value = [0u8; 16];
    value.copy_from_slice(&bytes[..16]);
    F2_128::from_bits(u128::from_le_bytes(value))
}

fn absorb_claims(transcript: &mut Sha256Transcript, claims: &[(Vec<F2_128>, F2_128)]) {
    transcript.absorb("claims", &(claims.len() as u64).to_le_bytes());
    for (point, value) in claims {
        transcript.absorb("arity", &(point.len() as u64).to_le_bytes());
        for coordinate in point {
            transcript.absorb("point", &coordinate.value().to_le_bytes());
        }
        transcript.absorb("value", &value.value().to_le_bytes());
    }
}

/// Batch several claims `G(r_i) = v_i` into one claim `G(r) = v`.
///
/// Prover side. The verifier samples the batching coefficients and replays the
/// sum-check; the output is a single evaluation claim for the PCS.
pub fn batch_claims(
    values: &[F2_128],
    claims: &[(Vec<F2_128>, F2_128)],
    transcript: &mut Sha256Transcript,
) -> Result<MosaicBatchingProof, MosaicError> {
    if claims.is_empty() {
        return Err(MosaicError::EmptyBatch);
    }
    let total_bits = values.len().trailing_zeros() as usize;
    if values.len() != 1usize << total_bits {
        return Err(MosaicError::InvalidSize(values.len()));
    }
    absorb_claims(transcript, claims);
    let alphas = (0..claims.len())
        .map(|_| challenge(transcript, "batch"))
        .collect::<Vec<_>>();
    let mle = Mle::new(values.to_vec())?;
    let poly = |point: &[F2_128]| {
        let weight = claims
            .iter()
            .zip(&alphas)
            .fold(F2_128::from(0u64), |sum, ((claim_point, _), alpha)| {
                sum + *alpha * eq(claim_point, point)
            });
        weight * mle.eval(point).unwrap_or(F2_128::from(0u64))
    };
    let (sumcheck, point, _) = prove(poly, total_bits, 2, |round, values| {
        for coefficient in values {
            transcript.absorb("round", &coefficient.value().to_le_bytes());
        }
        transcript.absorb("round", &(round as u64).to_le_bytes());
        challenge(transcript, "sumcheck")
    })?;
    let value = mle.eval(&point)?;
    Ok(MosaicBatchingProof {
        sumcheck,
        point,
        value,
    })
}

pub fn verify_batching(
    proof: &MosaicBatchingProof,
    claims: &[(Vec<F2_128>, F2_128)],
    total_bits: usize,
    transcript: &mut Sha256Transcript,
) -> Result<(), MosaicError> {
    if claims.is_empty() {
        return Err(MosaicError::EmptyBatch);
    }
    absorb_claims(transcript, claims);
    let alphas = (0..claims.len())
        .map(|_| challenge(transcript, "batch"))
        .collect::<Vec<_>>();
    let expected = claims
        .iter()
        .zip(&alphas)
        .fold(F2_128::from(0u64), |sum, ((_, value), alpha)| {
            sum + *alpha * *value
        });
    if proof.sumcheck.claimed_sum != expected {
        return Err(MosaicError::BatchSumcheck);
    }
    let (point, current) = verify_rounds(&proof.sumcheck, total_bits, 2, |round, values| {
        for coefficient in values {
            transcript.absorb("round", &coefficient.value().to_le_bytes());
        }
        transcript.absorb("round", &(round as u64).to_le_bytes());
        challenge(transcript, "sumcheck")
    })?;
    if point != proof.point {
        return Err(MosaicError::BatchSumcheck);
    }
    let weight = claims
        .iter()
        .zip(&alphas)
        .fold(F2_128::from(0u64), |sum, ((claim_point, _), alpha)| {
            sum + *alpha * eq(claim_point, &point)
        });
    if current != weight * proof.value {
        return Err(MosaicError::BatchSumcheck);
    }
    Ok(())
}

impl PackedMosaic {
    /// Commit the packed polynomial as one field-element vector.
    ///
    /// This reference layer commits one field element per bit. It still gives
    /// the single-commitment/single-evaluation structure of MosaicPCS; the
    /// paper's 128-bits-per-element packing and ring switching are separate.
    pub fn commit(&self, pcs: &P3BinaryPcs) -> Result<P3Commitment, MosaicError> {
        Ok(pcs.commit(&self.values)?)
    }

    pub fn open(&self, pcs: &P3BinaryPcs, point: &[F2_128]) -> Result<P3Opening, MosaicError> {
        Ok(pcs.open(&self.values, point)?)
    }

    pub fn verify(
        &self,
        pcs: &P3BinaryPcs,
        commitment: &P3Commitment,
        point: &[F2_128],
        value: F2_128,
        opening: &P3Opening,
    ) -> Result<bool, MosaicError> {
        Ok(pcs.verify(commitment, point, value, opening)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(size: usize, seed: u64) -> Vec<F2_128> {
        (0..size)
            .map(|index| F2_128::from(index as u64 * 17 + seed))
            .collect()
    }

    #[test]
    fn packed_components_lift_without_adapter() {
        let components = vec![values(2, 1), values(4, 2), values(8, 3)];
        let mosaic = PackedMosaic::new(&components).unwrap();
        let points = [
            vec![F2_128::from(5u64)],
            vec![F2_128::from(7u64), F2_128::from(11u64)],
            vec![
                F2_128::from(13u64),
                F2_128::from(17u64),
                F2_128::from(19u64),
            ],
        ];
        for (index, point) in points.iter().enumerate() {
            let lifted = mosaic.lift(index, point).unwrap();
            assert_eq!(
                mosaic.eval_component(index, point).unwrap(),
                mosaic.eval_packed(&lifted).unwrap()
            );
        }
    }

    #[test]
    fn packing_rejects_invalid_shapes() {
        assert!(PackedMosaic::new(&[]).is_err());
        assert!(PackedMosaic::new(&[vec![F2_128::from(1u64); 3]]).is_err());
    }
    #[test]
    fn batching_reduces_claims_to_one_point() {
        let components = vec![values(2, 1), values(4, 2), values(8, 3)];
        let mosaic = PackedMosaic::new(&components).unwrap();
        let point0 = mosaic.lift(0, &[F2_128::from(5u64)]).unwrap();
        let point1 = mosaic
            .lift(1, &[F2_128::from(7u64), F2_128::from(11u64)])
            .unwrap();
        let claims = vec![
            (point0.clone(), mosaic.eval_packed(&point0).unwrap()),
            (point1.clone(), mosaic.eval_packed(&point1).unwrap()),
        ];
        let mut prover_transcript = Sha256Transcript::new("mosaic-batch-test");
        let proof = batch_claims(&mosaic.values, &claims, &mut prover_transcript).unwrap();
        let mut verifier_transcript = Sha256Transcript::new("mosaic-batch-test");
        verify_batching(&proof, &claims, mosaic.total_bits, &mut verifier_transcript).unwrap();
        assert_eq!(proof.value, mosaic.eval_packed(&proof.point).unwrap());
    }
    #[test]
    fn packed_mosaic_commits_and_opens_once() {
        let components = vec![values(2, 1), values(4, 2), values(8, 3)];
        let mosaic = PackedMosaic::new(&components).unwrap();
        let pcs = P3BinaryPcs::new(100);
        let commitment = mosaic.commit(&pcs).unwrap();
        let point = vec![
            F2_128::from(3u64),
            F2_128::from(5u64),
            F2_128::from(7u64),
            F2_128::from(11u64),
        ];
        let value = mosaic.eval_packed(&point).unwrap();
        let opening = mosaic.open(&pcs, &point).unwrap();
        assert!(mosaic
            .verify(&pcs, &commitment, &point, value, &opening)
            .unwrap());
        assert!(!mosaic
            .verify(
                &pcs,
                &commitment,
                &point,
                value + F2_128::from(1u64),
                &opening,
            )
            .unwrap());
    }
}
