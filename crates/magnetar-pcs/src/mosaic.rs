//! Reference MosaicPCS packing and lift.
//!
//! Components are placed on disjoint aligned subcubes of one packed
//! polynomial `G`. A claim on component `i` at point `r` lifts to a claim on
//! `G` at `r || suffix_i` without an adapter sum-check. Batching and ring
//! switching are not yet implemented.

use magnetar_constraint::F2_128;
use magnetar_proof::Mle;
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
    Proof(#[from] magnetar_proof::ProofError),
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
}
