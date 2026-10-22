//! Native F2 sum-check and a non-succinct F2 commitment.
//!
//! This is a reference prototype for the binary relation side: challenges are
//! F2 elements, round polynomials are F2 vectors, and the opening checks the
//! multilinear evaluation over F2.

use std::cell::RefCell;

use magnetar_constraint::F2;
use magnetar_transcript::Sha256Transcript;

use crate::{Mle, ProofError};

#[derive(Clone, Debug, Default)]
pub struct F2Pcs;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct F2Commitment([u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct F2Opening(Vec<F2>);

impl F2Pcs {
    pub fn commit(&self, values: &[F2]) -> F2Commitment {
        F2Commitment(root(values))
    }

    pub fn open(&self, values: &[F2]) -> F2Opening {
        F2Opening(values.to_vec())
    }

    pub fn verify(
        &self,
        commitment: &F2Commitment,
        values: &[F2],
        point: &[F2],
        value: F2,
    ) -> Result<bool, ProofError> {
        if root(values) != commitment.0 {
            return Ok(false);
        }
        Ok(Mle::new(values.to_vec())?.eval(point)? == value)
    }
}

fn root(values: &[F2]) -> [u8; 32] {
    let bytes = values.iter().map(|value| value.value()).collect::<Vec<_>>();
    magnetar_transcript::sha256(&bytes)
}

fn f2_challenge(transcript: &RefCell<Sha256Transcript>) -> F2 {
    let mut transcript = transcript.borrow_mut();
    F2::new(transcript.challenge_u64("f2-bit") & 1 == 1)
}

#[derive(Clone, Debug)]
pub struct F2LinearProof {
    pub claimed: F2,
    pub rounds: Vec<[F2; 2]>,
    pub challenges: Vec<F2>,
}

fn fold(values: &[F2], challenge: F2) -> Vec<F2> {
    values
        .chunks_exact(2)
        .map(|pair| pair[0] + challenge * (pair[1] - pair[0]))
        .collect()
}

/// Native F2 multilinear sum-check (degree one per round).
///
/// A product sum-check over F2 needs extension-field challenges for
/// interpolation; this reference prototype keeps the linear case.
pub fn prove_f2_linear(values: &[F2]) -> Result<F2LinearProof, ProofError> {
    if values.is_empty() || !values.len().is_power_of_two() {
        return Err(ProofError::NotPowerOfTwo(values.len()));
    }
    let transcript = RefCell::new(Sha256Transcript::new("f2-linear-v1"));
    let claimed = values.iter().fold(F2::ZERO, |sum, value| sum + *value);
    let mut current = values.to_vec();
    let mut rounds = Vec::new();
    let mut challenges = Vec::new();
    while current.len() > 1 {
        let zero = current
            .iter()
            .step_by(2)
            .fold(F2::ZERO, |sum, value| sum + *value);
        let one = current
            .iter()
            .skip(1)
            .step_by(2)
            .fold(F2::ZERO, |sum, value| sum + *value);
        {
            let mut guard = transcript.borrow_mut();
            guard.absorb("round", &[zero.value(), one.value()]);
        }
        let challenge = f2_challenge(&transcript);
        rounds.push([zero, one]);
        challenges.push(challenge);
        current = fold(&current, challenge);
    }
    Ok(F2LinearProof {
        claimed,
        rounds,
        challenges,
    })
}

/// Verify the F2 linear sum-check and return its terminal claim.
pub fn verify_f2_linear(proof: &F2LinearProof) -> Result<F2, ProofError> {
    let transcript = RefCell::new(Sha256Transcript::new("f2-linear-v1"));
    let mut current = proof.claimed;
    let mut challenges = Vec::new();
    for (round, [zero, one]) in proof.rounds.iter().enumerate() {
        if *zero + *one != current {
            return Err(ProofError::RoundSum { round });
        }
        {
            let mut guard = transcript.borrow_mut();
            guard.absorb("round", &[zero.value(), one.value()]);
        }
        let challenge = f2_challenge(&transcript);
        challenges.push(challenge);
        current = *zero + challenge * (*one - *zero);
    }
    if challenges != proof.challenges {
        return Err(ProofError::RoundSum {
            round: proof.rounds.len(),
        });
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_constraint::Field;

    fn bits(values: &[u64]) -> Vec<F2> {
        values.iter().map(|value| F2::from_u64(*value)).collect()
    }

    #[test]
    fn native_f2_sumcheck_and_pcs_round_trip() {
        let values = bits(&[1, 0, 1, 1, 0, 1, 0, 1]);
        let proof = prove_f2_linear(&values).unwrap();
        let terminal = verify_f2_linear(&proof).unwrap();

        let pcs = F2Pcs;
        let commitment = pcs.commit(&values);
        let opening = pcs.open(&values);
        let value = Mle::new(values.clone())
            .unwrap()
            .eval(&proof.challenges)
            .unwrap();
        assert_eq!(terminal, value);
        assert!(pcs
            .verify(&commitment, &opening.0, &proof.challenges, value)
            .unwrap());
    }
}
