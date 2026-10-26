//! Reference sum-check engine and multilinear extensions.
//!
//! This is a small, slow implementation intended to validate protocol wiring.
//! It is not the optimized BinarySpartan prover; it is the executable
//! specification that the optimized prover must match.

use magnetar_constraint::{Field, F2_128};
use thiserror::Error;

/// Commitment interface used by the reference Spartan reduction.
///
/// Implementations commit to a power-of-two evaluation vector. The reference
/// Merkle implementation is not succinct; Ligerito can implement this trait
/// without changing the reduction.
pub trait Pcs {
    type Commitment: Clone + std::fmt::Debug;
    type Opening: Clone + std::fmt::Debug;

    fn commit(&self, values: &[F2_128]) -> Result<Self::Commitment, ProofError>;
    fn open(&self, values: &[F2_128], point: &[F2_128]) -> Result<Self::Opening, ProofError>;
    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &[F2_128],
        value: F2_128,
        opening: &Self::Opening,
    ) -> Result<bool, ProofError>;
    fn commitment_bytes(&self, commitment: &Self::Commitment) -> Vec<u8>;
}

/// A multilinear polynomial given by its evaluations on the Boolean hypercube.
#[derive(Clone, Debug)]
pub struct Mle<F: Field> {
    evaluations: Vec<F>,
    num_vars: usize,
}

impl<F: Field> Mle<F> {
    pub fn new(evaluations: Vec<F>) -> Result<Self, ProofError> {
        if evaluations.is_empty() || !evaluations.len().is_power_of_two() {
            return Err(ProofError::NotPowerOfTwo(evaluations.len()));
        }
        let num_vars = evaluations.len().trailing_zeros() as usize;
        Ok(Self {
            evaluations,
            num_vars,
        })
    }

    pub fn from_fn(num_vars: usize, f: impl Fn(&[F]) -> F) -> Result<Self, ProofError> {
        let len = hypercube_size(num_vars)?;
        let mut evaluations = Vec::with_capacity(len);
        for index in 0..len {
            let point = point_from_index(index, num_vars);
            evaluations.push(f(&point));
        }
        Self::new(evaluations)
    }

    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    pub fn len(&self) -> usize {
        self.evaluations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.evaluations.is_empty()
    }

    pub fn evaluations(&self) -> &[F] {
        &self.evaluations
    }

    /// Evaluate the multilinear extension at an arbitrary point.
    pub fn eval(&self, point: &[F]) -> Result<F, ProofError> {
        if point.len() != self.num_vars {
            return Err(ProofError::PointLength {
                expected: self.num_vars,
                actual: point.len(),
            });
        }
        let mut values = self.evaluations.clone();
        for coordinate in point {
            let mut folded = Vec::with_capacity(values.len() / 2);
            for pair in values.chunks_exact(2) {
                folded.push(pair[0] + *coordinate * (pair[1] - pair[0]));
            }
            values = folded;
        }
        Ok(values[0])
    }
}

/// `eq(a, b) = Π_i (a_i b_i + (1-a_i)(1-b_i))`.
pub fn eq<F: Field>(a: &[F], b: &[F]) -> F {
    debug_assert_eq!(a.len(), b.len());
    let mut result = F::one();
    for (left, right) in a.iter().zip(b.iter()) {
        result = result * (*left * *right + (F::one() - *left) * (F::one() - *right));
    }
    result
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SumcheckProof<F: Field> {
    pub claimed_sum: F,
    pub round_polys: Vec<Vec<F>>,
}

/// Prove the sum of `poly` over the Boolean hypercube.
///
/// `challenge` is called after each round polynomial is fixed. In a
/// non-interactive deployment it should be backed by a Fiat–Shamir transcript
/// that absorbs the round polynomial first.
pub fn prove<F, P, C>(
    poly: P,
    num_vars: usize,
    degree: usize,
    mut challenge: C,
) -> Result<(SumcheckProof<F>, Vec<F>, F), ProofError>
where
    F: Field,
    P: Fn(&[F]) -> F,
    C: FnMut(usize, &[F]) -> F,
{
    let size = hypercube_size(num_vars)?;
    let mut claimed_sum = F::zero();
    for index in 0..size {
        claimed_sum = claimed_sum + poly(&point_from_index(index, num_vars));
    }

    let mut challenges = Vec::with_capacity(num_vars);
    let mut round_polys = Vec::with_capacity(num_vars);

    for round in 0..num_vars {
        let remaining = num_vars - round - 1;
        let mut values = Vec::with_capacity(degree + 1);
        for t in 0..=degree {
            let mut sum = F::zero();
            let remaining_size = hypercube_size(remaining)?;
            for index in 0..remaining_size {
                let mut point = Vec::with_capacity(num_vars);
                point.extend_from_slice(&challenges);
                point.push(F::from_u64(t as u64));
                point.extend(point_from_index::<F>(index, remaining));
                sum = sum + poly(&point);
            }
            values.push(sum);
        }
        let r = challenge(round, &values);
        challenges.push(r);
        round_polys.push(values);
    }

    let final_eval = poly(&challenges);
    Ok((
        SumcheckProof {
            claimed_sum,
            round_polys,
        },
        challenges,
        final_eval,
    ))
}

fn fold_vector<F: Field>(values: &[F], challenge: F) -> Vec<F> {
    let mut folded = values
        .chunks_exact(2)
        .map(|pair| pair[1] - pair[0])
        .collect::<Vec<_>>();
    F::mul_slice_assign(&mut folded, challenge);
    for (value, pair) in folded.iter_mut().zip(values.chunks_exact(2)) {
        *value = *value + pair[0];
    }
    folded
}

fn vector_sum<F: Field>(values: &[F]) -> F {
    values.iter().fold(F::zero(), |sum, value| sum + *value)
}

/// Sum-check for an MLE given by its evaluation vector.
///
/// Each round polynomial has degree one, so the prover only folds the vector.
pub fn prove_linear<F, C>(
    values: Vec<F>,
    mut challenge: C,
) -> Result<(SumcheckProof<F>, Vec<F>, F), ProofError>
where
    F: Field,
    C: FnMut(usize, &[F]) -> F,
{
    if values.is_empty() || !values.len().is_power_of_two() {
        return Err(ProofError::NotPowerOfTwo(values.len()));
    }
    let mut values = values;
    let claimed_sum = vector_sum(&values);
    let rounds = values.len().trailing_zeros() as usize;
    let mut challenges = Vec::with_capacity(rounds);
    let mut round_polys = Vec::with_capacity(rounds);

    for round in 0..rounds {
        let even = values
            .iter()
            .step_by(2)
            .fold(F::zero(), |sum, value| sum + *value);
        let odd = values
            .iter()
            .skip(1)
            .step_by(2)
            .fold(F::zero(), |sum, value| sum + *value);
        let polynomial = vec![even, odd];
        let r = challenge(round, &polynomial);
        challenges.push(r);
        values = fold_vector(&values, r);
        round_polys.push(polynomial);
    }

    Ok((
        SumcheckProof {
            claimed_sum,
            round_polys,
        },
        challenges,
        values[0],
    ))
}

/// Sum-check for a product of two MLEs, degree two per variable.
pub fn prove_product2<F, C>(
    left_values: Vec<F>,
    right_values: Vec<F>,
    mut challenge: C,
) -> Result<(SumcheckProof<F>, Vec<F>, F), ProofError>
where
    F: Field,
    C: FnMut(usize, &[F]) -> F,
{
    let len = left_values.len();
    if len == 0 || !len.is_power_of_two() || right_values.len() != len {
        return Err(ProofError::DimensionMismatch);
    }
    let mut left_values = left_values;
    let mut right_values = right_values;
    let claimed_sum = (0..len).fold(F::zero(), |sum, index| {
        sum + left_values[index] * right_values[index]
    });
    let rounds = len.trailing_zeros() as usize;
    let mut challenges = Vec::with_capacity(rounds);
    let mut round_polys = Vec::with_capacity(rounds);

    for round in 0..rounds {
        let mut polynomial = Vec::with_capacity(3);
        for t in 0..=2 {
            let t = F::from_u64(t as u64);
            let left_t = fold_vector(&left_values, t);
            let right_t = fold_vector(&right_values, t);
            polynomial.push(
                (0..left_t.len())
                    .fold(F::zero(), |sum, index| sum + left_t[index] * right_t[index]),
            );
        }
        let r = challenge(round, &polynomial);
        challenges.push(r);
        left_values = fold_vector(&left_values, r);
        right_values = fold_vector(&right_values, r);
        round_polys.push(polynomial);
    }

    let final_eval = left_values[0] * right_values[0];
    Ok((
        SumcheckProof {
            claimed_sum,
            round_polys,
        },
        challenges,
        final_eval,
    ))
}

/// Sum-check for `eq(x) * (a(x)b(x) - c(x))`, degree three per variable.
///
/// All four inputs are evaluation vectors over the same Boolean hypercube.
pub fn prove_product4<F, C>(
    eq_values: Vec<F>,
    a_values: Vec<F>,
    b_values: Vec<F>,
    c_values: Vec<F>,
    mut challenge: C,
) -> Result<(SumcheckProof<F>, Vec<F>, F), ProofError>
where
    F: Field + Send + Sync,
    C: FnMut(usize, &[F]) -> F,
{
    let len = eq_values.len();
    if len == 0
        || !len.is_power_of_two()
        || a_values.len() != len
        || b_values.len() != len
        || c_values.len() != len
    {
        return Err(ProofError::DimensionMismatch);
    }
    let mut eq_values = eq_values;
    let mut a_values = a_values;
    let mut b_values = b_values;
    let mut c_values = c_values;
    let claimed_sum = (0..len).fold(F::zero(), |sum, index| {
        sum + eq_values[index] * (a_values[index] * b_values[index] - c_values[index])
    });
    let rounds = len.trailing_zeros() as usize;
    let mut challenges = Vec::with_capacity(rounds);
    let mut round_polys = Vec::with_capacity(rounds);

    for round in 0..rounds {
        let mut polynomial = Vec::with_capacity(4);
        for t in 0..=3 {
            let t = F::from_u64(t as u64);
            let eq_t = fold_vector(&eq_values, t);
            let a_t = fold_vector(&a_values, t);
            let b_t = fold_vector(&b_values, t);
            let c_t = fold_vector(&c_values, t);
            polynomial.push((0..eq_t.len()).fold(F::zero(), |sum, index| {
                sum + eq_t[index] * (a_t[index] * b_t[index] - c_t[index])
            }));
        }
        let r = challenge(round, &polynomial);
        challenges.push(r);
        eq_values = fold_vector(&eq_values, r);
        a_values = fold_vector(&a_values, r);
        b_values = fold_vector(&b_values, r);
        c_values = fold_vector(&c_values, r);
        round_polys.push(polynomial);
    }

    let final_eval = eq_values[0] * (a_values[0] * b_values[0] - c_values[0]);
    Ok((
        SumcheckProof {
            claimed_sum,
            round_polys,
        },
        challenges,
        final_eval,
    ))
}

/// Verify the round polynomials and return the challenges and final claim.
///
/// This is the inner half of `verify`; callers such as Spartan need the
/// challenges before they can compute the oracle evaluation.
pub fn verify_rounds<F, C>(
    proof: &SumcheckProof<F>,
    num_vars: usize,
    degree: usize,
    mut challenge: C,
) -> Result<(Vec<F>, F), ProofError>
where
    F: Field,
    C: FnMut(usize, &[F]) -> F,
{
    if proof.round_polys.len() != num_vars {
        return Err(ProofError::RoundCount {
            expected: num_vars,
            actual: proof.round_polys.len(),
        });
    }
    let mut current = proof.claimed_sum;
    let mut challenges = Vec::with_capacity(num_vars);
    for (round, values) in proof.round_polys.iter().enumerate() {
        if values.len() != degree + 1 {
            return Err(ProofError::RoundDegree {
                round,
                expected: degree + 1,
                actual: values.len(),
            });
        }
        if values.len() < 2 {
            return Err(ProofError::RoundDegree {
                round,
                expected: 2,
                actual: values.len(),
            });
        }
        let boolean_sum = values[0] + values[1];
        if boolean_sum != current {
            return Err(ProofError::RoundSum { round });
        }
        let r = challenge(round, values);
        current = interpolate(values, r)?;
        challenges.push(r);
    }
    Ok((challenges, current))
}

/// Verify a sum-check proof against the oracle evaluation at the final point.
pub fn verify<F, C>(
    proof: &SumcheckProof<F>,
    num_vars: usize,
    degree: usize,
    oracle_eval: F,
    challenge: C,
) -> Result<Vec<F>, ProofError>
where
    F: Field,
    C: FnMut(usize, &[F]) -> F,
{
    let (challenges, current) = verify_rounds(proof, num_vars, degree, challenge)?;
    if current != oracle_eval {
        return Err(ProofError::FinalOracle);
    }
    Ok(challenges)
}

fn interpolate<F: Field>(values: &[F], x: F) -> Result<F, ProofError> {
    let mut result = F::zero();
    for (i, value) in values.iter().enumerate() {
        let mut term = *value;
        for (j, _) in values.iter().enumerate() {
            if i == j {
                continue;
            }
            let denominator = F::from_u64(i as u64) - F::from_u64(j as u64);
            let inverse = denominator.inv().ok_or(ProofError::Interpolation)?;
            term = term * (x - F::from_u64(j as u64)) * inverse;
        }
        result = result + term;
    }
    Ok(result)
}

fn hypercube_size(num_vars: usize) -> Result<usize, ProofError> {
    if num_vars >= usize::BITS as usize {
        return Err(ProofError::TooManyVariables(num_vars));
    }
    Ok(1usize << num_vars)
}

fn point_from_index<F: Field>(mut index: usize, num_vars: usize) -> Vec<F> {
    let mut point = Vec::with_capacity(num_vars);
    for _ in 0..num_vars {
        point.push(F::from_u64((index & 1) as u64));
        index >>= 1;
    }
    point
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProofError {
    #[error("evaluation vector length {0} is not a nonzero power of two")]
    NotPowerOfTwo(usize),
    #[error("point has {actual} coordinates, expected {expected}")]
    PointLength { expected: usize, actual: usize },
    #[error("too many variables: {0}")]
    TooManyVariables(usize),
    #[error("round polynomial count {actual}, expected {expected}")]
    RoundCount { expected: usize, actual: usize },
    #[error("round {round} polynomial has {actual} values, expected {expected}")]
    RoundDegree {
        round: usize,
        expected: usize,
        actual: usize,
    },
    #[error("round {round} sum-check identity failed")]
    RoundSum { round: usize },
    #[error("interpolation failed")]
    Interpolation,
    #[error("final oracle evaluation mismatch")]
    FinalOracle,
    #[error("PCS error: {0}")]
    Pcs(String),
    #[error("vector lengths do not match")]
    DimensionMismatch,
}

pub mod bit_pcs;
pub mod dual_field;
pub mod f2_protocol;
pub mod simd;
pub mod spartan;
pub mod virtual_spartan;
pub use bit_pcs::{
    BitPcs, DirectBitPcs, PackedBitPcs, PackedOpening, PackedTableOpening, RevealingPackedBitPcs,
    RingSwitchOpening, RingSwitchPackedBitPcs,
};
pub use simd::SharedBlockMatrix;
pub use spartan::{
    prove_lockstep, prove_lockstep_bits, prove_lockstep_bits_with_point, prove_lockstep_claims,
    prove_lockstep_with_matrices, prove_shared_simd_spartan, prove_spartan, prove_spartan_bits,
    prove_spartan_with_matrices, verify_lockstep, verify_lockstep_bits,
    verify_lockstep_bits_with_replacements, verify_lockstep_bits_with_replacements_point,
    verify_lockstep_claims, verify_lockstep_segments, verify_lockstep_with_matrices,
    verify_shared_simd_spartan, verify_shared_simd_spartan_with_witnesses, verify_spartan,
    verify_spartan_bits, verify_spartan_with_matrices, witness_vector, LockstepClaims,
    LockstepProof, SparseMatrix, SpartanError, SpartanMatrix, SpartanProof,
};

/// Sum-check for `eq(x) * (a0*b0 - c0 + alpha * (a1*b1 - c1))`, degree three.
#[allow(clippy::too_many_arguments)]
pub fn prove_product6<F, C>(
    eq_values: Vec<F>,
    a0_values: Vec<F>,
    b0_values: Vec<F>,
    c0_values: Vec<F>,
    a1_values: Vec<F>,
    b1_values: Vec<F>,
    c1_values: Vec<F>,
    alpha: F,
    mut challenge: C,
) -> Result<(SumcheckProof<F>, Vec<F>, F), ProofError>
where
    F: Field + Send + Sync,
    C: FnMut(usize, &[F]) -> F,
{
    let len = eq_values.len();
    let all = [
        a0_values.len(),
        b0_values.len(),
        c0_values.len(),
        a1_values.len(),
        b1_values.len(),
        c1_values.len(),
    ];
    if len == 0 || !len.is_power_of_two() || all.iter().any(|length| *length != len) {
        return Err(ProofError::DimensionMismatch);
    }
    let mut eq_values = eq_values;
    let mut a0_values = a0_values;
    let mut b0_values = b0_values;
    let mut c0_values = c0_values;
    let mut a1_values = a1_values;
    let mut b1_values = b1_values;
    let mut c1_values = c1_values;
    let claimed_sum = (0..len).fold(F::zero(), |sum, index| {
        sum + eq_values[index]
            * (a0_values[index] * b0_values[index] - c0_values[index]
                + alpha * (a1_values[index] * b1_values[index] - c1_values[index]))
    });
    let rounds = len.trailing_zeros() as usize;
    let mut challenges = Vec::with_capacity(rounds);
    let mut round_polys = Vec::with_capacity(rounds);

    for round in 0..rounds {
        let pairs = eq_values.len() / 2;
        let evaluate_pair = |index: usize| {
            let left = index * 2;
            let right = left + 1;
            let eq0 = eq_values[left];
            let eq1 = eq_values[right];
            let a00 = a0_values[left];
            let a01 = a0_values[right];
            let b00 = b0_values[left];
            let b01 = b0_values[right];
            let c00 = c0_values[left];
            let c01 = c0_values[right];
            let a10 = a1_values[left];
            let a11 = a1_values[right];
            let b10 = b1_values[left];
            let b11 = b1_values[right];
            let c10 = c1_values[left];
            let c11 = c1_values[right];
            let mut values = [F::zero(); 4];
            for (point, value) in values.iter_mut().enumerate() {
                let t = F::from_u64(point as u64);
                let one_plus = F::one() + t;
                let eq = eq0 * one_plus + eq1 * t;
                let a0 = a00 * one_plus + a01 * t;
                let b0 = b00 * one_plus + b01 * t;
                let c0 = c00 * one_plus + c01 * t;
                let a1 = a10 * one_plus + a11 * t;
                let b1 = b10 * one_plus + b11 * t;
                let c1 = c10 * one_plus + c11 * t;
                *value = eq * (a0 * b0 - c0 + alpha * (a1 * b1 - c1));
            }
            values
        };
        let workers = std::env::var("MAGNETAR_PRODUCT6_THREADS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(4)
            .max(1);
        let mut polynomial = [F::zero(); 4];
        if pairs >= 512 && workers > 1 {
            let task_size = 4096usize;
            let tasks = pairs.div_ceil(task_size);
            let next = std::sync::atomic::AtomicUsize::new(0);
            let partials = std::thread::scope(|scope| {
                let mut handles = Vec::with_capacity(workers.min(tasks));
                for _ in 0..workers.min(tasks) {
                    let evaluate_pair = &evaluate_pair;
                    let next = &next;
                    handles.push(scope.spawn(move || {
                        let mut partial = [F::zero(); 4];
                        loop {
                            let task = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if task >= tasks {
                                break;
                            }
                            let start = task * task_size;
                            let end = (start + task_size).min(pairs);
                            for index in start..end {
                                let values = evaluate_pair(index);
                                for point in 0..4 {
                                    partial[point] = partial[point] + values[point];
                                }
                            }
                        }
                        partial
                    }));
                }
                let mut partials = [F::zero(); 4];
                for handle in handles {
                    let partial = handle.join().expect("product6 worker");
                    for point in 0..4 {
                        partials[point] = partials[point] + partial[point];
                    }
                }
                partials
            });
            polynomial = partials;
        } else {
            for index in 0..pairs {
                let values = evaluate_pair(index);
                for point in 0..4 {
                    polynomial[point] = polynomial[point] + values[point];
                }
            }
        }
        let mut polynomial = polynomial.to_vec();
        let r = challenge(round, &polynomial);
        challenges.push(r);
        eq_values = fold_vector(&eq_values, r);
        a0_values = fold_vector(&a0_values, r);
        b0_values = fold_vector(&b0_values, r);
        c0_values = fold_vector(&c0_values, r);
        a1_values = fold_vector(&a1_values, r);
        b1_values = fold_vector(&b1_values, r);
        c1_values = fold_vector(&c1_values, r);
        round_polys.push(polynomial);
    }

    let final_eval = eq_values[0]
        * (a0_values[0] * b0_values[0] - c0_values[0]
            + alpha * (a1_values[0] * b1_values[0] - c1_values[0]));
    Ok((
        SumcheckProof {
            claimed_sum,
            round_polys,
        },
        challenges,
        final_eval,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_constraint::F61;

    #[test]
    fn mle_evaluates_on_hypercube() {
        let mle = Mle::new(vec![F61::from(1), F61::from(2), F61::from(3), F61::from(4)]).unwrap();
        assert_eq!(mle.num_vars(), 2);
        assert_eq!(
            mle.eval(&[F61::from(0), F61::from(0)]).unwrap(),
            F61::from(1)
        );
        assert_eq!(
            mle.eval(&[F61::from(1), F61::from(1)]).unwrap(),
            F61::from(4)
        );
    }

    #[test]
    fn sumcheck_accepts_an_honest_proof() {
        let poly = |point: &[F61]| point[0] * point[1] + point[0] + F61::from(1);
        let (proof, challenges, final_eval) =
            prove(poly, 2, 2, |round, _| F61::from(round as u64 + 2)).unwrap();
        assert_eq!(proof.claimed_sum, F61::from(7));
        let verified = verify(&proof, 2, 2, final_eval, |round, _| {
            F61::from(round as u64 + 2)
        })
        .unwrap();
        assert_eq!(challenges, verified);
    }

    #[test]
    fn linear_sumcheck_matches_mle() {
        let evaluations = vec![
            F61::from(1),
            F61::from(2),
            F61::from(3),
            F61::from(4),
            F61::from(5),
            F61::from(6),
            F61::from(7),
            F61::from(8),
        ];
        let (proof, challenges, final_eval) =
            prove_linear(evaluations.clone(), |round, _| F61::from(round as u64 + 2)).unwrap();
        let mle = Mle::new(evaluations).unwrap();
        assert_eq!(final_eval, mle.eval(&challenges).unwrap());
        let verified = verify(&proof, challenges.len(), 1, final_eval, |round, _| {
            F61::from(round as u64 + 2)
        })
        .unwrap();
        assert_eq!(challenges, verified);
    }

    #[test]
    fn sumcheck_rejects_a_tampered_round() {
        let poly = |point: &[F61]| point[0] * point[1] + F61::from(1);
        let (mut proof, _, final_eval) =
            prove(poly, 2, 2, |round, _| F61::from(round as u64 + 3)).unwrap();
        proof.round_polys[0][0] = proof.round_polys[0][0] + F61::from(1);
        assert!(verify(&proof, 2, 2, final_eval, |round, _| F61::from(
            round as u64 + 3
        ),)
        .is_err());
    }

    #[test]
    fn mle_from_fn_matches_the_hypercube_layout() {
        let mle = Mle::from_fn(2, |point: &[F61]| {
            F61::from(point[1].value() * 2 + point[0].value())
        })
        .unwrap();
        assert_eq!(
            mle.evaluations(),
            &[F61::from(0), F61::from(1), F61::from(2), F61::from(3)]
        );
        assert_eq!(mle.len(), 4);
        assert!(!mle.is_empty());
        assert_eq!(mle.num_vars(), 2);
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        assert!(matches!(
            Mle::new(Vec::<F61>::new()),
            Err(ProofError::NotPowerOfTwo(0))
        ));
        assert!(matches!(
            Mle::new(vec![F61::from(1); 3]),
            Err(ProofError::NotPowerOfTwo(3))
        ));
        let mle = Mle::new(vec![F61::from(1), F61::from(2)]).unwrap();
        assert!(matches!(
            mle.eval(&[]),
            Err(ProofError::PointLength {
                expected: 1,
                actual: 0
            })
        ));
        assert!(matches!(
            hypercube_size(usize::BITS as usize),
            Err(ProofError::TooManyVariables(_))
        ));

        let empty = SumcheckProof {
            claimed_sum: F61::from(0),
            round_polys: Vec::new(),
        };
        assert!(matches!(
            verify(&empty, 1, 1, F61::from(0), |_, _| F61::from(0)),
            Err(ProofError::RoundCount {
                expected: 1,
                actual: 0
            })
        ));
        let one_value = SumcheckProof {
            claimed_sum: F61::from(0),
            round_polys: vec![vec![F61::from(0)]],
        };
        assert!(matches!(
            verify(&one_value, 1, 1, F61::from(0), |_, _| F61::from(0)),
            Err(ProofError::RoundDegree { .. })
        ));
    }

    #[test]
    fn eq_is_the_hypercube_selector() {
        let vertex = [F61::from(0), F61::from(1)];
        assert_eq!(eq(&vertex, &vertex), F61::from(1));
        assert_eq!(eq(&vertex, &[F61::from(1), F61::from(1)]), F61::from(0));
        assert_eq!(eq::<F61>(&[], &[]), F61::from(1));
    }

    #[test]
    fn verify_rounds_and_product_proofs_are_consistent() {
        let poly = |point: &[F61]| point[0] * point[1] + F61::from(1);
        let challenge = |round: usize, _: &[F61]| F61::from(round as u64 + 2);
        let (proof, challenges, final_eval) = prove(poly, 2, 2, challenge).unwrap();
        let (rx, value) = verify_rounds(&proof, 2, 2, challenge).unwrap();
        assert_eq!(rx, challenges);
        assert_eq!(value, final_eval);

        let left = vec![F61::from(1), F61::from(2), F61::from(3), F61::from(4)];
        let right = vec![F61::from(5), F61::from(6), F61::from(7), F61::from(8)];
        let (product_proof, product_rx, product_eval) =
            prove_product2(left.clone(), right.clone(), challenge).unwrap();
        let expected = Mle::new(left).unwrap().eval(&product_rx).unwrap()
            * Mle::new(right).unwrap().eval(&product_rx).unwrap();
        assert_eq!(product_eval, expected);
        verify(&product_proof, 2, 2, product_eval, challenge).unwrap();
    }
}
