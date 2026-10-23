//! Bit-witness commitment backend.
//!
//! `BitPcs` is the abstraction boundary between the CPU relations (which are
//! over a bit-valued witness) and the commitment/proof layer. `DirectBitPcs`
//! implements the current one-field-element-per-bit encoding. A future
//! `PackedBitPcs` can implement 128-bits-per-field commitment + ring switching
//! behind the same trait.

use magnetar_constraint::F2_128;

use crate::{Mle, Pcs, ProofError};

pub trait BitPcs {
    type Commitment: Clone + std::fmt::Debug;
    type Opening: Clone + std::fmt::Debug;

    fn commit(&self, bits: &[bool]) -> Result<Self::Commitment, ProofError>;
    fn open(&self, bits: &[bool], point: &[F2_128]) -> Result<(F2_128, Self::Opening), ProofError>;
    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &[F2_128],
        value: F2_128,
        opening: &Self::Opening,
    ) -> Result<bool, ProofError>;
    fn commitment_bytes(&self, commitment: &Self::Commitment) -> Vec<u8>;
}

/// Current encoding: one F2^128 field element per witness bit.
#[derive(Clone, Copy, Debug)]
pub struct DirectBitPcs<P: Pcs> {
    pub pcs: P,
}

impl<P: Pcs> DirectBitPcs<P> {
    pub fn new(pcs: P) -> Self {
        Self { pcs }
    }

    fn values(bits: &[bool]) -> Vec<F2_128> {
        bits.iter()
            .map(|bit| F2_128::from(u64::from(*bit)))
            .collect()
    }
}

impl<P: Pcs> BitPcs for DirectBitPcs<P> {
    type Commitment = P::Commitment;
    type Opening = P::Opening;

    fn commit(&self, bits: &[bool]) -> Result<Self::Commitment, ProofError> {
        self.pcs.commit(&Self::values(bits))
    }

    fn open(&self, bits: &[bool], point: &[F2_128]) -> Result<(F2_128, Self::Opening), ProofError> {
        let values = Self::values(bits);
        let value = Mle::new(values.clone())?.eval(point)?;
        let opening = self.pcs.open(&values, point)?;
        Ok((value, opening))
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &[F2_128],
        value: F2_128,
        opening: &Self::Opening,
    ) -> Result<bool, ProofError> {
        self.pcs.verify(commitment, point, value, opening)
    }

    fn commitment_bytes(&self, commitment: &Self::Commitment) -> Vec<u8> {
        self.pcs.commitment_bytes(commitment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Commitment(Vec<F2_128>);

    #[derive(Clone, Debug)]
    struct Opening;

    struct TestPcs;

    impl Pcs for TestPcs {
        type Commitment = Commitment;
        type Opening = Opening;

        fn commit(&self, values: &[F2_128]) -> Result<Self::Commitment, ProofError> {
            Ok(Commitment(values.to_vec()))
        }

        fn open(&self, values: &[F2_128], point: &[F2_128]) -> Result<Self::Opening, ProofError> {
            let _ = Mle::new(values.to_vec())?.eval(point)?;
            Ok(Opening)
        }

        fn verify(
            &self,
            _commitment: &Self::Commitment,
            _point: &[F2_128],
            _value: F2_128,
            _opening: &Self::Opening,
        ) -> Result<bool, ProofError> {
            Ok(true)
        }

        fn commitment_bytes(&self, commitment: &Self::Commitment) -> Vec<u8> {
            commitment
                .0
                .iter()
                .flat_map(|value| value.value().to_le_bytes())
                .collect()
        }
    }

    #[test]
    fn direct_bit_pcs_opens_bit_mle() {
        let backend = DirectBitPcs::new(TestPcs);
        let bits = [true, false, true, true];
        let commitment = backend.commit(&bits).unwrap();
        let point = [F2_128::from(1u64), F2_128::from(0u64)];
        let (value, opening) = backend.open(&bits, &point).unwrap();
        assert!(backend
            .verify(&commitment, &point, value, &opening)
            .unwrap());
    }
}
