//! Groundwork for the B6 univariate-skip reduction.
//!
//! A skip round reads the first `k` Boolean coordinates as points of an
//! additive subspace `D` of `F2_128`. This module provides the subspace and
//! the Lagrange interpolation needed to evaluate the resulting univariate
//! polynomial at an off-domain challenge. It deliberately does not change the
//! CPU proof format yet; the zerocheck/inner-product reduction is still a
//! separate protocol layer.

use magnetar_constraint::{Field, F2_128};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubspaceDomain {
    points: Vec<F2_128>,
}

impl SubspaceDomain {
    /// Additive subspace spanned by the first `log_size` basis elements.
    pub fn new(log_size: usize) -> Result<Self, UnivariateSkipError> {
        if log_size == 0 || log_size > 16 {
            return Err(UnivariateSkipError::UnsupportedSize(log_size));
        }
        let mut points = vec![F2_128::from(0u64)];
        for bit in 0..log_size {
            let basis = F2_128::from(1u128 << bit);
            let mut extended = Vec::with_capacity(points.len() * 2);
            for point in &points {
                extended.push(*point);
                extended.push(*point + basis);
            }
            points = extended;
        }
        if points.len() != 1usize << log_size {
            return Err(UnivariateSkipError::UnsupportedSize(log_size));
        }
        Ok(Self { points })
    }

    pub fn log_size(&self) -> usize {
        self.points.len().trailing_zeros() as usize
    }

    pub fn points(&self) -> &[F2_128] {
        &self.points
    }

    /// Lagrange weights for evaluating the interpolant at `at`.
    pub fn lagrange_weights(&self, at: F2_128) -> Result<Vec<F2_128>, UnivariateSkipError> {
        let mut weights = Vec::with_capacity(self.points.len());
        for (index, point) in self.points.iter().enumerate() {
            let mut numerator = F2_128::from(1u64);
            let mut denominator = F2_128::from(1u64);
            for (other_index, other) in self.points.iter().enumerate() {
                if index == other_index {
                    continue;
                }
                numerator = numerator * (at + *other);
                denominator = denominator * (*point + *other);
            }
            let inverse = denominator.inv().ok_or(UnivariateSkipError::Singular)?;
            weights.push(numerator * inverse);
        }
        Ok(weights)
    }

    /// Evaluate the degree `< |D|` interpolant through `values` at `at`.
    pub fn interpolate(
        &self,
        values: &[F2_128],
        at: F2_128,
    ) -> Result<F2_128, UnivariateSkipError> {
        if values.len() != self.points.len() {
            return Err(UnivariateSkipError::Length {
                expected: self.points.len(),
                actual: values.len(),
            });
        }
        Ok(self
            .lagrange_weights(at)?
            .iter()
            .zip(values)
            .fold(F2_128::from(0u64), |sum, (weight, value)| {
                sum + *weight * *value
            }))
    }

    /// Sum of the interpolant over the subspace, i.e. the Boolean sum it lifts.
    pub fn domain_sum(&self, values: &[F2_128]) -> Result<F2_128, UnivariateSkipError> {
        if values.len() != self.points.len() {
            return Err(UnivariateSkipError::Length {
                expected: self.points.len(),
                actual: values.len(),
            });
        }
        Ok(values
            .iter()
            .fold(F2_128::from(0u64), |sum, value| sum + *value))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnivariateSkipError {
    UnsupportedSize(usize),
    Singular,
    Challenge,
    Evaluation,
    Length { expected: usize, actual: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(value: u64) -> F2_128 {
        F2_128::from(value.wrapping_mul(17) + 3)
    }

    fn eval_polynomial(coefficients: &[F2_128], at: F2_128) -> F2_128 {
        coefficients
            .iter()
            .rev()
            .fold(F2_128::from(0u64), |acc, coefficient| {
                acc * at + *coefficient
            })
    }

    #[test]
    fn additive_domain_is_distinct() {
        let domain = SubspaceDomain::new(4).unwrap();
        assert_eq!(domain.points().len(), 16);
        let mut sorted = domain.points().to_vec();
        sorted.sort_by_key(|value| value.value());
        sorted.dedup();
        assert_eq!(sorted.len(), 16);
        let invalid = SubspaceDomain::new(0).unwrap_err();
        assert_eq!(invalid, UnivariateSkipError::UnsupportedSize(0));
    }

    #[test]
    fn interpolation_matches_values_and_low_degree_polynomial() {
        let domain = SubspaceDomain::new(3).unwrap();
        let values = (0..8).map(field).collect::<Vec<_>>();
        for (point, value) in domain.points().iter().zip(&values) {
            assert_eq!(domain.interpolate(&values, *point).unwrap(), *value);
        }

        let mut coefficients = (0..8).map(field).collect::<Vec<_>>();
        coefficients[7] = F2_128::from(0u64);
        let values = domain
            .points()
            .iter()
            .map(|point| eval_polynomial(&coefficients, *point))
            .collect::<Vec<_>>();
        let at = field(91);
        assert_eq!(
            domain.interpolate(&values, at).unwrap(),
            eval_polynomial(&coefficients, at)
        );
        assert_eq!(
            domain.domain_sum(&values).unwrap(),
            domain
                .points()
                .iter()
                .map(|point| eval_polynomial(&coefficients, *point))
                .fold(F2_128::from(0u64), |sum, value| sum + value)
        );
    }
    #[test]
    fn skip_round_vanishes_on_domain_and_matches_coset() {
        let round = SkipRound::new(3).unwrap();
        let values = (0..8).map(field).collect::<Vec<_>>();
        let message = round.message(&values).unwrap();
        for point in round.domain().points() {
            assert_eq!(
                round.evaluate(&message, *point).unwrap(),
                F2_128::from(0u64)
            );
        }
        for (point, expected) in round.coset().iter().zip(&message) {
            assert_eq!(round.evaluate(&message, *point).unwrap(), *expected);
        }
        let at = field(77);
        let mut combined_values = vec![F2_128::from(0u64); round.domain().points().len()];
        combined_values.extend_from_slice(&message);
        let expected = interpolate_points(&round.combined, &combined_values, at).unwrap();
        let actual = round.evaluate(&message, at).unwrap();
        assert_eq!(actual, expected);

        let zero = round.message(&[F2_128::from(0u64); 8]).unwrap();
        assert!(zero.iter().all(|value| *value == F2_128::from(0u64)));
        let mut tampered = message;
        tampered[0] = tampered[0] + F2_128::from(1u64);
        assert_ne!(
            round.evaluate(&tampered, at).unwrap(),
            expected,
            "tampering the coset message must change the reconstructed polynomial"
        );
    }

    #[test]
    fn skip_round_proof_binds_message_and_challenge() {
        let round = SkipRound::new(2).unwrap();
        let values = (0..4).map(field).collect::<Vec<_>>();
        let mut prover = magnetar_transcript::Sha256Transcript::new("skip-test");
        let proof = round.prove(&values, &mut prover).unwrap();
        let mut verifier = magnetar_transcript::Sha256Transcript::new("skip-test");
        round.verify(&proof, &mut verifier).unwrap();

        let mut tampered = proof.clone();
        tampered.message[0] = tampered.message[0] + F2_128::from(1u64);
        let mut verifier = magnetar_transcript::Sha256Transcript::new("skip-test");
        assert_eq!(
            round.verify(&tampered, &mut verifier).unwrap_err(),
            UnivariateSkipError::Challenge
        );

        let mut tampered = proof;
        tampered.evaluation = tampered.evaluation + F2_128::from(1u64);
        let mut verifier = magnetar_transcript::Sha256Transcript::new("skip-test");
        assert_eq!(
            round.verify(&tampered, &mut verifier).unwrap_err(),
            UnivariateSkipError::Evaluation
        );
    }
}

/// One univariate-skip round over an additive subspace and one coset.
///
/// The round polynomial `Q` vanishes on `domain` and is transmitted on
/// `coset = domain + shift`. The verifier reconstructs `Q` by interpolation
/// over `domain ∪ coset` with zero values on `domain`. This is the message
/// layer of a zerocheck skip round; the residual inner-product reduction is
/// intentionally a separate step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkipRound {
    domain: SubspaceDomain,
    coset: Vec<F2_128>,
    combined: Vec<F2_128>,
    barycentric: Vec<F2_128>,
}

impl SkipRound {
    pub fn new(log_size: usize) -> Result<Self, UnivariateSkipError> {
        let domain = SubspaceDomain::new(log_size)?;
        let shift = F2_128::from(1u128 << log_size);
        let coset = domain
            .points()
            .iter()
            .map(|point| *point + shift)
            .collect::<Vec<_>>();
        if coset.iter().any(|point| domain.points().contains(point)) {
            return Err(UnivariateSkipError::Singular);
        }
        let mut combined = domain.points().to_vec();
        combined.extend_from_slice(&coset);
        let barycentric = domain
            .points()
            .iter()
            .map(|point| {
                let denominator = domain
                    .points()
                    .iter()
                    .filter(|other| *other != point)
                    .fold(F2_128::from(1u64), |product, other| {
                        product * (*point + *other)
                    });
                denominator.inv().ok_or(UnivariateSkipError::Singular)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            domain,
            coset,
            combined,
            barycentric,
        })
    }

    pub fn log_size(&self) -> usize {
        self.domain.log_size()
    }

    pub fn domain(&self) -> &SubspaceDomain {
        &self.domain
    }

    pub fn coset(&self) -> &[F2_128] {
        &self.coset
    }

    /// The round message: the interpolant of `values` on the domain, evaluated
    /// on the coset. The verifier will force the reconstructed round polynomial
    /// to vanish on the domain.
    pub fn message(&self, values: &[F2_128]) -> Result<Vec<F2_128>, UnivariateSkipError> {
        if values.len() != self.domain.points().len() {
            return Err(UnivariateSkipError::Length {
                expected: self.domain.points().len(),
                actual: values.len(),
            });
        }
        self.coset
            .iter()
            .map(|at| {
                let numerator = self
                    .domain
                    .points()
                    .iter()
                    .fold(F2_128::from(1u64), |product, point| {
                        product * (*at + *point)
                    });
                let mut sum = F2_128::from(0u64);
                for ((point, weight), value) in self
                    .domain
                    .points()
                    .iter()
                    .zip(&self.barycentric)
                    .zip(values)
                {
                    let inverse = (*at + *point).inv().ok_or(UnivariateSkipError::Singular)?;
                    sum = sum + *value * *weight * inverse;
                }
                Ok(numerator * sum)
            })
            .collect()
    }

    /// Reconstruct the skip-round polynomial at `at` from the coset message.
    pub fn evaluate(&self, message: &[F2_128], at: F2_128) -> Result<F2_128, UnivariateSkipError> {
        if message.len() != self.coset.len() {
            return Err(UnivariateSkipError::Length {
                expected: self.coset.len(),
                actual: message.len(),
            });
        }
        let mut values = vec![F2_128::from(0u64); self.combined.len()];
        values[self.domain.points().len()..].copy_from_slice(message);
        interpolate_points(&self.combined, &values, at)
    }
}

fn interpolate_points(
    points: &[F2_128],
    values: &[F2_128],
    at: F2_128,
) -> Result<F2_128, UnivariateSkipError> {
    if points.len() != values.len() {
        return Err(UnivariateSkipError::Length {
            expected: points.len(),
            actual: values.len(),
        });
    }
    let mut result = F2_128::from(0u64);
    for (index, point) in points.iter().enumerate() {
        let mut numerator = F2_128::from(1u64);
        let mut denominator = F2_128::from(1u64);
        for (other_index, other) in points.iter().enumerate() {
            if index == other_index {
                continue;
            }
            numerator = numerator * (at + *other);
            denominator = denominator * (*point + *other);
        }
        let inverse = denominator.inv().ok_or(UnivariateSkipError::Singular)?;
        result = result + values[index] * numerator * inverse;
    }
    Ok(result)
}

/// Message and challenge evaluation of one skip round.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SkipRoundProof {
    pub message: Vec<F2_128>,
    pub point: F2_128,
    pub evaluation: F2_128,
}

fn challenge(transcript: &mut magnetar_transcript::Sha256Transcript, label: &str) -> F2_128 {
    let bytes = transcript.challenge_32(label);
    let mut value = [0u8; 16];
    value.copy_from_slice(&bytes[..16]);
    F2_128::from_bits(u128::from_le_bytes(value))
}

impl SkipRound {
    pub fn prove(
        &self,
        values: &[F2_128],
        transcript: &mut magnetar_transcript::Sha256Transcript,
    ) -> Result<SkipRoundProof, UnivariateSkipError> {
        let message = self.message(values)?;
        for value in &message {
            transcript.absorb("skip-message", &value.value().to_le_bytes());
        }
        let point = challenge(transcript, "skip-challenge");
        let evaluation = self.evaluate(&message, point)?;
        Ok(SkipRoundProof {
            message,
            point,
            evaluation,
        })
    }

    pub fn verify(
        &self,
        proof: &SkipRoundProof,
        transcript: &mut magnetar_transcript::Sha256Transcript,
    ) -> Result<(), UnivariateSkipError> {
        for value in &proof.message {
            transcript.absorb("skip-message", &value.value().to_le_bytes());
        }
        let point = challenge(transcript, "skip-challenge");
        if point != proof.point {
            return Err(UnivariateSkipError::Challenge);
        }
        let evaluation = self.evaluate(&proof.message, point)?;
        if evaluation != proof.evaluation {
            return Err(UnivariateSkipError::Evaluation);
        }
        Ok(())
    }
}
