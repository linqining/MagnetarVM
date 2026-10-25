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
}
