//! B2 interface: prove a weighted linear combination of committed rows, ending
//! in one plain multilinear evaluation.
//!
//! This is the residual-opening layer needed by a univariate-skip round: the
//! skip challenge yields Lagrange weights over Boolean rows, and this protocol
//! reduces `sum_i lambda_i f(i) = v` to `f(r) = v_r` plus one PCS opening.

use magnetar_constraint::F2_128;
use magnetar_pcs::{P3BinaryPcs, P3Commitment, P3Opening};
use magnetar_proof::{prove_product2, verify_rounds, Mle, Pcs, ProofError, SumcheckProof};
use magnetar_transcript::Sha256Transcript;

use crate::univariate_skip::{SkipRound, SkipRoundProof};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BoundRowProof {
    pub commitment: P3Commitment,
    pub sumcheck: SumcheckProof<F2_128>,
    pub point: Vec<F2_128>,
    pub value: F2_128,
    pub opening: P3Opening,
}

fn challenge(transcript: &mut Sha256Transcript, label: &str) -> F2_128 {
    let bytes = transcript.challenge_32(label);
    let mut value = [0u8; 16];
    value.copy_from_slice(&bytes[..16]);
    F2_128::from_bits(u128::from_le_bytes(value))
}

fn absorb(pcs: &P3BinaryPcs, transcript: &mut Sha256Transcript, commitment: &P3Commitment) {
    transcript.absorb("bound-commitment", &pcs.commitment_bytes(commitment));
}

fn check_weights(weights: &[F2_128]) -> Result<usize, ProofError> {
    if weights.is_empty() || !weights.len().is_power_of_two() {
        return Err(ProofError::DimensionMismatch);
    }
    Ok(weights.len().trailing_zeros() as usize)
}

/// Prove `sum_i weights[i] * values[i]` and open `values` at the final point.
pub fn prove_bound_rows(
    weights: &[F2_128],
    values: &[F2_128],
    pcs: &P3BinaryPcs,
    transcript: &mut Sha256Transcript,
) -> Result<BoundRowProof, ProofError> {
    let num_vars = check_weights(weights)?;
    if values.len() != weights.len() {
        return Err(ProofError::DimensionMismatch);
    }
    let commitment = pcs.commit(values)?;
    absorb(pcs, transcript, &commitment);
    let (sumcheck, point, _) =
        prove_product2(weights.to_vec(), values.to_vec(), |_round, polynomial| {
            for value in polynomial {
                transcript.absorb("bound-round", &value.value().to_le_bytes());
            }
            challenge(transcript, "bound-sumcheck")
        })?;
    let value = Mle::new(values.to_vec())?.eval(&point)?;
    let opening = pcs.open(values, &point)?;
    let _ = num_vars;
    Ok(BoundRowProof {
        commitment,
        sumcheck,
        point,
        value,
        opening,
    })
}

/// Verify a bound-row proof against the expected weighted sum.
pub fn verify_bound_rows(
    weights: &[F2_128],
    expected_sum: F2_128,
    proof: &BoundRowProof,
    pcs: &P3BinaryPcs,
    transcript: &mut Sha256Transcript,
) -> Result<bool, ProofError> {
    let num_vars = check_weights(weights)?;
    if proof.point.len() != num_vars {
        return Ok(false);
    }
    absorb(pcs, transcript, &proof.commitment);
    if proof.sumcheck.claimed_sum != expected_sum {
        return Ok(false);
    }
    let (point, current) = verify_rounds(&proof.sumcheck, num_vars, 2, |_round, polynomial| {
        for value in polynomial {
            transcript.absorb("bound-round", &value.value().to_le_bytes());
        }
        challenge(transcript, "bound-sumcheck")
    })?;
    if point != proof.point {
        return Ok(false);
    }
    let weight_at = Mle::new(weights.to_vec())?.eval(&point)?;
    if current != weight_at * proof.value {
        return Ok(false);
    }
    pcs.verify(&proof.commitment, &point, proof.value, &proof.opening)
}

/// A skip challenge plus the bound-row proof that it is a weighted claim on
/// the committed rows.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SkipBoundProof {
    pub skip: SkipRoundProof,
    pub bound: BoundRowProof,
}

pub fn prove_skip_bound(
    round: &SkipRound,
    values: &[F2_128],
    pcs: &P3BinaryPcs,
    transcript: &mut Sha256Transcript,
) -> Result<SkipBoundProof, ProofError> {
    let skip = round
        .prove(values, transcript)
        .map_err(|error| ProofError::Pcs(format!("univariate skip failed: {error:?}")))?;
    let weights = round
        .row_weights(skip.point)
        .map_err(|error| ProofError::Pcs(format!("skip weights failed: {error:?}")))?;
    let bound = prove_bound_rows(&weights, values, pcs, transcript)?;
    Ok(SkipBoundProof { skip, bound })
}

pub fn verify_skip_bound(
    round: &SkipRound,
    proof: &SkipBoundProof,
    pcs: &P3BinaryPcs,
    transcript: &mut Sha256Transcript,
) -> Result<bool, ProofError> {
    if round.verify(&proof.skip, transcript).is_err() {
        return Ok(false);
    }
    let weights = round
        .row_weights(proof.skip.point)
        .map_err(|error| ProofError::Pcs(format!("skip weights failed: {error:?}")))?;
    verify_bound_rows(
        &weights,
        proof.skip.evaluation,
        &proof.bound,
        pcs,
        transcript,
    )
}

/// Toy zero-row argument: a skip challenge plus a bound-row proof that the
/// committed rows evaluate to zero on the Boolean domain.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ZeroRowsProof {
    pub skip: SkipRoundProof,
    pub bound: BoundRowProof,
}

pub fn prove_zero_rows(
    round: &SkipRound,
    values: &[F2_128],
    pcs: &P3BinaryPcs,
    transcript: &mut Sha256Transcript,
) -> Result<ZeroRowsProof, ProofError> {
    let skip = round
        .prove(values, transcript)
        .map_err(|error| ProofError::Pcs(format!("univariate skip failed: {error:?}")))?;
    let weights = round
        .row_weights(skip.point)
        .map_err(|error| ProofError::Pcs(format!("skip weights failed: {error:?}")))?;
    let bound = prove_bound_rows(&weights, values, pcs, transcript)?;
    Ok(ZeroRowsProof { skip, bound })
}

pub fn verify_zero_rows(
    round: &SkipRound,
    proof: &ZeroRowsProof,
    pcs: &P3BinaryPcs,
    transcript: &mut Sha256Transcript,
) -> Result<bool, ProofError> {
    if proof.skip.evaluation != F2_128::from(0u64) {
        return Ok(false);
    }
    if round.verify(&proof.skip, transcript).is_err() {
        return Ok(false);
    }
    let weights = round
        .row_weights(proof.skip.point)
        .map_err(|error| ProofError::Pcs(format!("skip weights failed: {error:?}")))?;
    verify_bound_rows(&weights, F2_128::from(0u64), &proof.bound, pcs, transcript)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(seed: u64, len: usize) -> Vec<F2_128> {
        (0..len)
            .map(|index| F2_128::from(index as u64 * 31 + seed))
            .collect()
    }

    #[test]
    fn bound_rows_round_trip_and_tamper() {
        let weights = values(7, 16);
        let values = values(11, 16);
        let expected = weights
            .iter()
            .zip(&values)
            .fold(F2_128::from(0u64), |sum, (weight, value)| {
                sum + *weight * *value
            });
        let pcs = P3BinaryPcs::new(100);
        let mut prover = Sha256Transcript::new("bound-test");
        let proof = prove_bound_rows(&weights, &values, &pcs, &mut prover).unwrap();
        let mut verifier = Sha256Transcript::new("bound-test");
        assert!(verify_bound_rows(&weights, expected, &proof, &pcs, &mut verifier).unwrap());

        let mut verifier = Sha256Transcript::new("bound-test");
        assert!(!verify_bound_rows(
            &weights,
            expected + F2_128::from(1u64),
            &proof,
            &pcs,
            &mut verifier
        )
        .unwrap());

        let mut tampered = proof.clone();
        tampered.value = tampered.value + F2_128::from(1u64);
        let mut verifier = Sha256Transcript::new("bound-test");
        assert!(!verify_bound_rows(&weights, expected, &tampered, &pcs, &mut verifier).unwrap());

        let mut tampered = proof;
        tampered.opening.commitment.num_variables += 1;
        let mut verifier = Sha256Transcript::new("bound-test");
        assert!(!verify_bound_rows(&weights, expected, &tampered, &pcs, &mut verifier).unwrap());
    }

    #[test]
    fn skip_bound_chain_round_trip_and_tamper() {
        let round = SkipRound::new(2).unwrap();
        let values = values(13, 4);
        let pcs = P3BinaryPcs::new(100);
        let mut prover = Sha256Transcript::new("skip-bound-test");
        let proof = prove_skip_bound(&round, &values, &pcs, &mut prover).unwrap();
        let mut verifier = Sha256Transcript::new("skip-bound-test");
        assert!(verify_skip_bound(&round, &proof, &pcs, &mut verifier).unwrap());

        let mut tampered = proof.clone();
        tampered.skip.evaluation = tampered.skip.evaluation + F2_128::from(1u64);
        let mut verifier = Sha256Transcript::new("skip-bound-test");
        assert!(!verify_skip_bound(&round, &tampered, &pcs, &mut verifier).unwrap());

        let mut tampered = proof;
        tampered.bound.value = tampered.bound.value + F2_128::from(1u64);
        let mut verifier = Sha256Transcript::new("skip-bound-test");
        assert!(!verify_skip_bound(&round, &tampered, &pcs, &mut verifier).unwrap());
    }
    #[test]
    fn zero_rows_proof_accepts_zero_and_rejects_nonzero() {
        let round = SkipRound::new(2).unwrap();
        let pcs = P3BinaryPcs::new(100);
        let zero = vec![F2_128::from(0u64); 4];
        let mut prover = Sha256Transcript::new("zero-rows-test");
        let proof = prove_zero_rows(&round, &zero, &pcs, &mut prover).unwrap();
        let mut verifier = Sha256Transcript::new("zero-rows-test");
        assert!(verify_zero_rows(&round, &proof, &pcs, &mut verifier).unwrap());

        let nonzero = values(19, 4);
        let mut prover = Sha256Transcript::new("zero-rows-test");
        let proof = prove_zero_rows(&round, &nonzero, &pcs, &mut prover).unwrap();
        let mut verifier = Sha256Transcript::new("zero-rows-test");
        assert!(!verify_zero_rows(&round, &proof, &pcs, &mut verifier).unwrap());
    }
}
