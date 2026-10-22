//! Dual SIMD R1CS boundary.
//!
//! Magnetar arithmetizes the CPU with two SIMD relations over one shared
//! bit-valued witness: one over `F2` for bit constraints and one over
//! `F2_128` for packed products. This module provides the reference relation
//! boundary; the CPU row systems are not yet converted to a single uniform
//! SIMD instance.

use crate::field::F2_128;
use crate::ir::{ConstraintError, ConstraintSystem, Witness};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SimdError {
    #[error("SIMD instance count must be a nonzero power of two, got {0}")]
    InvalidInstanceCount(usize),
    #[error("SIMD instance count mismatch: expected {expected}, got {actual}")]
    InstanceCount { expected: usize, actual: usize },
    #[error("binary and packed SIMD relations have different instance counts")]
    RelationCountMismatch,
    #[error("packed witness length mismatch: expected {expected}, got {actual}")]
    PackedLength { expected: usize, actual: usize },
    #[error("packed witness contains a non-boolean value")]
    NonBoolean,
    #[error(transparent)]
    Constraint(#[from] ConstraintError),
}

/// `q` copies of one constraint system, sharing a fixed matrix structure.
#[derive(Clone, Debug)]
pub struct SimdR1cs {
    pub system: ConstraintSystem,
    pub instances: usize,
}

impl SimdR1cs {
    pub fn new(system: ConstraintSystem, instances: usize) -> Result<Self, SimdError> {
        if instances == 0 || !instances.is_power_of_two() {
            return Err(SimdError::InvalidInstanceCount(instances));
        }
        Ok(Self { system, instances })
    }

    pub fn check(&self, witnesses: &[Witness]) -> Result<(), SimdError> {
        if witnesses.len() != self.instances {
            return Err(SimdError::InstanceCount {
                expected: self.instances,
                actual: witnesses.len(),
            });
        }
        for witness in witnesses {
            self.system.check(witness)?;
        }
        Ok(())
    }
}

/// Pack a bit-valued witness into `F2_128` elements, 128 bits per element.
///
/// The binary tower's canonical basis is the little-endian bit basis of the
/// 128-bit representation, so packing is the identity on the bit vector once
/// it is grouped into 128-bit chunks.
pub fn pack_binary(bits: &[F2_128]) -> Result<Vec<F2_128>, SimdError> {
    let mut packed = Vec::with_capacity(bits.len().div_ceil(128));
    for chunk in bits.chunks(128) {
        let mut value = 0u128;
        for (bit, element) in chunk.iter().enumerate() {
            if element.value() > 1 {
                return Err(SimdError::NonBoolean);
            }
            value |= element.value() << bit;
        }
        packed.push(F2_128::from_bits(value));
    }
    Ok(packed)
}

/// Unpack `packed` back into `len` bit-valued elements.
pub fn unpack_binary(packed: &[F2_128], len: usize) -> Result<Vec<F2_128>, SimdError> {
    if packed.len() != len.div_ceil(128) {
        return Err(SimdError::PackedLength {
            expected: len.div_ceil(128),
            actual: packed.len(),
        });
    }
    let mut bits = Vec::with_capacity(len);
    for element in packed {
        let value = element.value();
        for bit in 0..128 {
            if bits.len() == len {
                break;
            }
            bits.push(F2_128::from((value >> bit) & 1));
        }
    }
    Ok(bits)
}

/// Two SIMD relations over the same matrix of witnesses.
#[derive(Clone, Debug)]
pub struct DualSimdR1cs {
    pub binary: SimdR1cs,
    pub packed: SimdR1cs,
}

impl DualSimdR1cs {
    pub fn new(binary: SimdR1cs, packed: SimdR1cs) -> Result<Self, SimdError> {
        if binary.instances != packed.instances {
            return Err(SimdError::RelationCountMismatch);
        }
        Ok(Self { binary, packed })
    }

    pub fn instances(&self) -> usize {
        self.binary.instances
    }

    pub fn check(&self, witnesses: &[Witness]) -> Result<(), SimdError> {
        self.binary.check(witnesses)?;
        self.packed.check(witnesses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::F2_128;
    use crate::ir::Expr;

    fn systems() -> (SimdR1cs, SimdR1cs) {
        // Binary relation: x*x = x and y*y = y (bit-valued x, y).
        let mut binary = ConstraintSystem::new(5);
        binary.add_constraint(Expr::var(0).mul(Expr::var(0)), Expr::var(0), Expr::var(0));
        binary.add_constraint(Expr::var(1).mul(Expr::var(1)), Expr::var(1), Expr::var(1));
        // Packed relation: (x + y) * z = w.
        let mut packed = ConstraintSystem::new(5);
        packed.add_constraint(Expr::var(0).add(Expr::var(1)), Expr::var(2), Expr::var(3));
        (
            SimdR1cs::new(binary, 2).unwrap(),
            SimdR1cs::new(packed, 2).unwrap(),
        )
    }

    #[test]
    fn packed_binary_round_trips() {
        let bits = (0..200u64)
            .map(|index| F2_128::from((index * 17 + 3) & 1))
            .collect::<Vec<_>>();
        let packed = pack_binary(&bits).unwrap();
        assert_eq!(packed.len(), 2);
        let unpacked = unpack_binary(&packed, bits.len()).unwrap();
        assert_eq!(unpacked, bits);
        assert!(pack_binary(&[F2_128::from(2u64)]).is_err());
    }

    #[test]
    fn dual_simd_checks_shared_witnesses() {
        let (binary, packed) = systems();
        let dual = DualSimdR1cs::new(binary, packed).unwrap();
        let witnesses = vec![
            Witness::new(vec![
                F2_128::from(1u64),
                F2_128::from(0u64),
                F2_128::from(5u64),
                F2_128::from(5u64),
                F2_128::from(0u64),
            ]),
            Witness::new(vec![
                F2_128::from(0u64),
                F2_128::from(1u64),
                F2_128::from(7u64),
                F2_128::from(7u64),
                F2_128::from(0u64),
            ]),
        ];
        dual.check(&witnesses).unwrap();

        let mut tampered = witnesses;
        tampered[1] = Witness::new(vec![
            F2_128::from(0u64),
            F2_128::from(1u64),
            F2_128::from(7u64),
            F2_128::from(8u64),
            F2_128::from(0u64),
        ]);
        assert!(dual.check(&tampered).is_err());
    }
}
