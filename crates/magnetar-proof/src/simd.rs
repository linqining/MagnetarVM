//! Shared-matrix representation for SIMD R1CS instances.
//!
//! A block-diagonal batch of q copies of the same row relation is represented
//! by one base sparse matrix plus an instance count. Products, row
//! combinations, and MLE evaluations are computed blockwise without
//! materializing q copies of the matrix.

use magnetar_constraint::{ConstraintSystem, F2_128};

use crate::spartan::{bits, MatrixPart, SparseMatrix};
use crate::{eq, SpartanError};

#[derive(Clone, Debug)]
pub struct SharedBlockMatrix {
    base: SparseMatrix,
    instances: usize,
}

impl SharedBlockMatrix {
    pub fn from_system(
        system: &ConstraintSystem,
        part: MatrixPart,
        instances: usize,
    ) -> Result<Self, SpartanError> {
        if instances == 0 || !instances.is_power_of_two() {
            return Err(SpartanError::Dimensions);
        }
        Ok(Self {
            base: SparseMatrix::from_system(system, part)?,
            instances,
        })
    }

    pub fn instances(&self) -> usize {
        self.instances
    }

    pub fn rows(&self) -> usize {
        self.base.rows.len() * self.instances
    }

    pub fn cols(&self) -> usize {
        self.base.cols * self.instances
    }

    pub fn mul_vec(&self, z: &[F2_128]) -> Result<Vec<F2_128>, SpartanError> {
        if z.len() != self.cols() {
            return Err(SpartanError::Dimensions);
        }
        let mut result = Vec::with_capacity(self.rows());
        for instance in 0..self.instances {
            let start = instance * self.base.cols;
            result.extend(self.base.mul_vec(&z[start..start + self.base.cols])?);
        }
        Ok(result)
    }

    pub fn row_combination(&self, row_point: &[F2_128]) -> Result<Vec<F2_128>, SpartanError> {
        let (local, instance_point) = split_point(row_point, self.base.rows.len(), self.instances)?;
        let local = self.base.row_combination(&local)?;
        let mut result = vec![F2_128::from(0u64); self.cols()];
        for instance in 0..self.instances {
            let weight = eq(
                &instance_point,
                &bits(instance, self.instances.trailing_zeros() as usize),
            );
            for (column, coefficient) in local.iter().enumerate() {
                result[instance * self.base.cols + column] = *coefficient * weight;
            }
        }
        Ok(result)
    }

    pub fn eval_mle(
        &self,
        row_point: &[F2_128],
        col_point: &[F2_128],
    ) -> Result<F2_128, SpartanError> {
        let (row_local, row_instance) =
            split_point(row_point, self.base.rows.len(), self.instances)?;
        let (col_local, col_instance) = split_point(col_point, self.base.cols, self.instances)?;
        let base = self.base.eval_mle(&row_local, &col_local)?;
        let mut sum = F2_128::from(0u64);
        for instance in 0..self.instances {
            let index = bits(instance, self.instances.trailing_zeros() as usize);
            sum = sum + base * eq(&row_instance, &index) * eq(&col_instance, &index);
        }
        Ok(sum)
    }
}

fn split_point(
    point: &[F2_128],
    local_size: usize,
    instances: usize,
) -> Result<(Vec<F2_128>, Vec<F2_128>), SpartanError> {
    let local_bits = local_size.trailing_zeros() as usize;
    let instance_bits = instances.trailing_zeros() as usize;
    if point.len() != local_bits + instance_bits {
        return Err(SpartanError::Dimensions);
    }
    Ok((point[..local_bits].to_vec(), point[local_bits..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_constraint::Expr;

    #[test]
    fn shared_block_matrix_matches_an_explicit_batch() {
        let mut base = ConstraintSystem::new(3);
        base.add_constraint(
            Expr::var(0).add(Expr::var(1)),
            Expr::constant(1u64),
            Expr::var(2),
        );
        let base_matrix = SparseMatrix::from_system(&base, MatrixPart::A).unwrap();
        let mut rows = base_matrix.rows.clone();
        let shifted = base_matrix
            .rows
            .iter()
            .map(|row| {
                row.iter()
                    .map(|(column, coefficient)| (column + base_matrix.cols, *coefficient))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        rows.extend(shifted);
        let explicit = SparseMatrix {
            rows,
            cols: base_matrix.cols * 2,
        };
        let values = vec![
            F2_128::from(1u64),
            F2_128::from(2u64),
            F2_128::from(3u64),
            F2_128::from(4u64),
            F2_128::from(5u64),
            F2_128::from(6u64),
            F2_128::from(7u64),
            F2_128::from(8u64),
        ];
        let shared = SharedBlockMatrix::from_system(&base, MatrixPart::A, 2).unwrap();
        assert_eq!(shared.rows(), explicit.rows.len());
        assert_eq!(shared.cols(), explicit.cols);
        assert_eq!(
            shared.mul_vec(&values).unwrap(),
            explicit.mul_vec(&values).unwrap()
        );

        let row_point = (0..shared.rows().trailing_zeros() as usize)
            .map(|index| F2_128::from(index as u64 + 1))
            .collect::<Vec<_>>();
        let col_point = (0..shared.cols().trailing_zeros() as usize)
            .map(|index| F2_128::from(index as u64 + 9))
            .collect::<Vec<_>>();
        assert_eq!(
            shared.row_combination(&row_point).unwrap(),
            explicit.row_combination(&row_point).unwrap()
        );
        assert_eq!(
            shared.eval_mle(&row_point, &col_point).unwrap(),
            explicit.eval_mle(&row_point, &col_point).unwrap()
        );
    }
}
