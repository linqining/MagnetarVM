//! Reference sum-check engine and multilinear extensions.
//!
//! This is a small, slow implementation intended to validate protocol wiring.
//! It is not the optimized BinarySpartan prover; it is the executable
//! specification that the optimized prover must match.

use magnetar_constraint::Field;
use thiserror::Error;

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

#[derive(Clone, Debug)]
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

/// Verify a sum-check proof against the oracle evaluation at the final point.
pub fn verify<F, C>(
    proof: &SumcheckProof<F>,
    num_vars: usize,
    degree: usize,
    oracle_eval: F,
    mut challenge: C,
) -> Result<Vec<F>, ProofError>
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
            let denominator = F::from_u64(j as u64) - F::from_u64(i as u64);
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
}
