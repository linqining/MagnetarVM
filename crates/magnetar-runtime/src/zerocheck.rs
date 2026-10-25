//! B-c composition prototype: a zerocheck for the Boolean constraint
//! `C(f) = f + f^2` over a committed bit vector.
//!
//! The sum-check summand is `eq(rho, x) * C(f(x))` where `f(x)` is the
//! multilinear extension of the committed rows. The prover folds the row vector
//! and applies the composition at each partial point; the final claim is
//! `eq(rho, r) * C(f(r))`, so the verifier only needs one opening of `f` at `r`.

use magnetar_constraint::F2_128;
use magnetar_pcs::{P3BinaryPcs, P3Commitment, P3Opening};
use magnetar_proof::{verify_rounds, Mle, Pcs, ProofError, SumcheckProof};
use magnetar_transcript::Sha256Transcript;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BooleanityProof {
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

fn fold(values: &[F2_128], at: F2_128) -> Vec<F2_128> {
    values
        .chunks_exact(2)
        .map(|pair| pair[0] + at * (pair[0] + pair[1]))
        .collect()
}

fn folds_for_degree(values: &[F2_128], points: usize) -> Vec<Vec<F2_128>> {
    let even = fold(values, F2_128::from(0u64));
    let odd = fold(values, F2_128::from(1u64));
    (0..points)
        .map(|point| {
            let t = F2_128::from(point as u64);
            even.iter()
                .zip(&odd)
                .map(|(a, b)| *a + t * (*a + *b))
                .collect()
        })
        .collect()
}

fn eq_vector(rho: &[F2_128]) -> Vec<F2_128> {
    let mut values = vec![F2_128::from(1u64)];
    for coordinate in rho {
        let one_plus = F2_128::from(1u64) + *coordinate;
        let stride = values.len();
        let mut next = vec![F2_128::from(0u64); stride * 2];
        for (index, value) in values.iter().enumerate() {
            next[index] = *value * one_plus;
            next[stride + index] = *value * *coordinate;
        }
        values = next;
    }
    values
}

fn eq_at(rho: &[F2_128], point: &[F2_128]) -> F2_128 {
    rho.iter()
        .zip(point)
        .fold(F2_128::from(1u64), |product, (left, right)| {
            let one = F2_128::from(1u64);
            product * (*left * *right + (one + *left) * (one + *right))
        })
}

pub fn prove_booleanity(
    values: &[F2_128],
    pcs: &P3BinaryPcs,
    transcript: &mut Sha256Transcript,
) -> Result<BooleanityProof, ProofError> {
    if values.is_empty() || !values.len().is_power_of_two() {
        return Err(ProofError::DimensionMismatch);
    }
    let num_vars = values.len().trailing_zeros() as usize;
    let commitment = pcs.commit(values)?;
    transcript.absorb("booleanity-commitment", &pcs.commitment_bytes(&commitment));
    let rho = (0..num_vars)
        .map(|_| challenge(transcript, "booleanity-rho"))
        .collect::<Vec<_>>();
    let mut current = values.to_vec();
    let mut eq = eq_vector(&rho);
    let mut claimed_sum = F2_128::from(0u64);
    for (value, weight) in current.iter().zip(&eq) {
        claimed_sum = claimed_sum + *weight * (*value + *value * *value);
    }
    if claimed_sum != F2_128::from(0u64) {
        return Err(ProofError::Pcs(
            "booleanity zerocheck claim is not zero".into(),
        ));
    }

    let mut rounds = Vec::with_capacity(num_vars);
    let mut challenges = Vec::with_capacity(num_vars);
    for _ in 0..num_vars {
        let value_folds = folds_for_degree(&current, 4);
        let eq_folds = folds_for_degree(&eq, 4);
        let mut polynomial = [F2_128::from(0u64); 4];
        for (point, coefficient) in polynomial.iter_mut().enumerate() {
            let values_t = &value_folds[point];
            let eq_t = &eq_folds[point];
            *coefficient = (0..values_t.len()).fold(F2_128::from(0u64), |sum, index| {
                sum + eq_t[index] * (values_t[index] + values_t[index] * values_t[index])
            });
        }
        for value in &polynomial {
            transcript.absorb("booleanity-round", &value.value().to_le_bytes());
        }
        let r = challenge(transcript, "booleanity-sumcheck");
        current = fold(&current, r);
        eq = fold(&eq, r);
        rounds.push(polynomial.to_vec());
        challenges.push(r);
    }

    let value = Mle::new(values.to_vec())?.eval(&challenges)?;
    let opening = pcs.open(values, &challenges)?;
    Ok(BooleanityProof {
        commitment,
        sumcheck: SumcheckProof {
            claimed_sum,
            round_polys: rounds,
        },
        point: challenges,
        value,
        opening,
    })
}

pub fn verify_booleanity(
    proof: &BooleanityProof,
    pcs: &P3BinaryPcs,
    transcript: &mut Sha256Transcript,
) -> Result<bool, ProofError> {
    let num_vars = proof.point.len();
    transcript.absorb(
        "booleanity-commitment",
        &pcs.commitment_bytes(&proof.commitment),
    );
    let rho = (0..num_vars)
        .map(|_| challenge(transcript, "booleanity-rho"))
        .collect::<Vec<_>>();
    if proof.sumcheck.claimed_sum != F2_128::from(0u64) {
        return Ok(false);
    }
    let (point, current) = verify_rounds(&proof.sumcheck, num_vars, 3, |_round, values| {
        for value in values {
            transcript.absorb("booleanity-round", &value.value().to_le_bytes());
        }
        challenge(transcript, "booleanity-sumcheck")
    })?;
    if point != proof.point {
        return Ok(false);
    }
    let expected = eq_at(&rho, &point) * (proof.value + proof.value * proof.value);
    if current != expected {
        return Ok(false);
    }
    pcs.verify(&proof.commitment, &point, proof.value, &proof.opening)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bits(len: usize, seed: u64) -> Vec<F2_128> {
        (0..len)
            .map(|index| F2_128::from(((index as u64 * 17 + seed) >> 1) & 1))
            .collect()
    }

    #[test]
    fn booleanity_round_trip_and_tamper() {
        let values = bits(16, 3);
        let pcs = P3BinaryPcs::new(100);
        let mut prover = Sha256Transcript::new("booleanity-test");
        let proof = prove_booleanity(&values, &pcs, &mut prover).unwrap();
        let mut verifier = Sha256Transcript::new("booleanity-test");
        assert!(verify_booleanity(&proof, &pcs, &mut verifier).unwrap());

        let mut tampered = proof.clone();
        tampered.value = tampered.value + F2_128::from(1u64);
        let mut verifier = Sha256Transcript::new("booleanity-test");
        assert!(!verify_booleanity(&tampered, &pcs, &mut verifier).unwrap());

        let mut tampered = proof.clone();
        tampered.sumcheck.claimed_sum = F2_128::from(1u64);
        let mut verifier = Sha256Transcript::new("booleanity-test");
        assert!(!verify_booleanity(&tampered, &pcs, &mut verifier).unwrap());

        let mut tampered = proof;
        tampered.opening.commitment.num_variables += 1;
        let mut verifier = Sha256Transcript::new("booleanity-test");
        assert!(!verify_booleanity(&tampered, &pcs, &mut verifier).unwrap());
    }

    #[test]
    fn non_boolean_rows_are_rejected() {
        let mut values = bits(16, 5);
        values[3] = F2_128::from(2u64);
        let pcs = P3BinaryPcs::new(100);
        let mut prover = Sha256Transcript::new("booleanity-invalid");
        assert!(prove_booleanity(&values, &pcs, &mut prover).is_err());
    }
}
