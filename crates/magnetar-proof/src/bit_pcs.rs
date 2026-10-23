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
    fn packed_and_direct_agree_on_all_points_128() {
        let bits = (0..128).map(|index| index % 3 == 0).collect::<Vec<_>>();
        let direct = DirectBitPcs::new(TestPcs);
        let packed = PackedBitPcs::new(TestPcs);
        for mask in 0..128usize {
            let point = (0..7)
                .map(|bit| F2_128::from(((mask >> bit) & 1) as u64))
                .collect::<Vec<_>>();
            let (direct_value, _) = direct.open(&bits, &point).unwrap();
            let (packed_value, opening) = packed.open(&bits, &point).unwrap();
            assert_eq!(direct_value, packed_value, "mask {mask}");
            let commitment = packed.commit(&bits).unwrap();
            assert!(packed
                .verify(&commitment, &point, packed_value, &opening)
                .unwrap());
        }
    }

    #[test]
    fn packed_and_direct_agree_on_random_field_points() {
        let bits = (0..128).map(|index| index % 5 == 0).collect::<Vec<_>>();
        let direct = DirectBitPcs::new(TestPcs);
        let packed = PackedBitPcs::new(TestPcs);
        for seed in 0..32u128 {
            let point = (0..7)
                .map(|bit| F2_128::from(seed.wrapping_mul(bit as u128 + 1) & 0xff))
                .collect::<Vec<_>>();
            let (direct_value, _) = direct.open(&bits, &point).unwrap();
            let (packed_value, opening) = packed.open(&bits, &point).unwrap();
            assert_eq!(direct_value, packed_value, "seed {seed}");
            let commitment = packed.commit(&bits).unwrap();
            assert!(packed
                .verify(&commitment, &point, packed_value, &opening)
                .unwrap());
        }
    }

    #[test]
    fn packed_and_direct_compute_the_same_bit_value() {
        let bits = [true, false, true, true, false, true, false, false];
        let point = [F2_128::from(1u64), F2_128::from(0u64), F2_128::from(1u64)];
        let direct = DirectBitPcs::new(TestPcs);
        let packed = PackedBitPcs::new(TestPcs);
        let (direct_value, _) = direct.open(&bits, &point).unwrap();
        let (packed_value, opening) = packed.open(&bits, &point).unwrap();
        assert_eq!(direct_value, packed_value);
        let commitment = packed.commit(&bits).unwrap();
        assert!(packed
            .verify(&commitment, &point, packed_value, &opening)
            .unwrap());
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

/// Packed opening: the PCS opening is on the packed table, while the bit-MLE
/// value is recovered by the basis/bit linear functional.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PackedOpening<O> {
    pub packed_value: F2_128,
    pub opening: O,
}

/// 128-bits-per-field commitment backend.
///
/// The low `min(7, log2(len))` bits select the basis coefficient; the high
/// bits index the packed table. `open` commits/opens the packed table and
/// derives the bit-MLE value by the basis linear functional.
#[derive(Clone, Copy, Debug)]
pub struct PackedBitPcs<P: Pcs> {
    pub pcs: P,
}

impl<P: Pcs> PackedBitPcs<P> {
    pub fn new(pcs: P) -> Self {
        Self { pcs }
    }

    fn pack(bits: &[bool]) -> Result<Vec<F2_128>, ProofError> {
        if bits.is_empty() || !bits.len().is_power_of_two() {
            return Err(ProofError::NotPowerOfTwo(bits.len()));
        }
        let total_bits = bits.len().trailing_zeros() as usize;
        if total_bits > 7 {
            return Err(ProofError::Pcs(
                "PackedBitPcs currently supports at most 128 witness bits".into(),
            ));
        }
        let low_bits = total_bits.min(7);
        let low_len = 1usize << low_bits;
        let high_len = bits.len() / low_len;
        let mut packed = vec![F2_128::from(0u64); high_len];
        for high in 0..high_len {
            let mut value = F2_128::from(0u64);
            for low in 0..low_len {
                if bits[high * low_len + low] {
                    value = value + F2_128::from(1u128 << low);
                }
            }
            packed[high] = value;
        }
        if packed.len() == 1 {
            packed.push(F2_128::from(0u64));
        }
        Ok(packed)
    }

    fn bit_value(packed: F2_128, low_point: &[F2_128]) -> F2_128 {
        let low_len = 1usize << low_point.len();
        let mut value = F2_128::from(0u64);
        for low in 0..low_len {
            if (packed.value() >> low) & 1 == 1 {
                let low_bits = (0..low_point.len())
                    .map(|bit| F2_128::from(((low >> bit) & 1) as u64))
                    .collect::<Vec<_>>();
                value = value + crate::eq(low_point, &low_bits);
            }
        }
        value
    }

    fn high_point(point: &[F2_128]) -> (usize, Vec<F2_128>) {
        let low_bits = point.len().min(7);
        let high_bits = point.len() - low_bits;
        let mut high = if high_bits == 0 {
            Vec::new()
        } else {
            point[low_bits..].to_vec()
        };
        if high.is_empty() {
            high.push(F2_128::from(0u64));
        }
        (low_bits, high)
    }
}

impl<P: Pcs> BitPcs for PackedBitPcs<P> {
    type Commitment = P::Commitment;
    type Opening = PackedOpening<P::Opening>;

    fn commit(&self, bits: &[bool]) -> Result<Self::Commitment, ProofError> {
        let packed = Self::pack(bits)?;
        self.pcs.commit(&packed)
    }

    fn open(&self, bits: &[bool], point: &[F2_128]) -> Result<(F2_128, Self::Opening), ProofError> {
        let packed = Self::pack(bits)?;
        let low_bits = point.len().min(7);
        let (_, high) = Self::high_point(point);
        let packed_mle = Mle::new(packed.clone())?;
        let packed_value = packed_mle.eval(&high)?;
        let value = Self::bit_value(packed_value, &point[..low_bits]);
        let opening = self.pcs.open(&packed, &high)?;
        Ok((
            value,
            PackedOpening {
                packed_value,
                opening,
            },
        ))
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &[F2_128],
        value: F2_128,
        opening: &Self::Opening,
    ) -> Result<bool, ProofError> {
        let low_bits = point.len().min(7);
        let (_, high) = Self::high_point(point);
        if Self::bit_value(opening.packed_value, &point[..low_bits]) != value {
            return Ok(false);
        }
        self.pcs
            .verify(commitment, &high, opening.packed_value, &opening.opening)
    }

    fn commitment_bytes(&self, commitment: &Self::Commitment) -> Vec<u8> {
        self.pcs.commitment_bytes(commitment)
    }
}

/// Multi-field packed opening that reveals the packed table. This is a
/// correctness fallback for witness sizes above one field: the verifier
/// recomputes the deterministic commitment and evaluates the bit MLE from the
/// packed table. It is not succinct (proof size grows as len/128) and is not
/// the paper's ring-switching backend.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PackedTableOpening {
    pub packed: Vec<F2_128>,
}

#[derive(Clone, Copy, Debug)]
pub struct RevealingPackedBitPcs<P: Pcs> {
    pub pcs: P,
}

impl<P: Pcs> RevealingPackedBitPcs<P> {
    pub fn new(pcs: P) -> Self {
        Self { pcs }
    }

    #[allow(clippy::needless_range_loop)]
    fn pack(bits: &[bool]) -> Result<Vec<F2_128>, ProofError> {
        if bits.is_empty() || !bits.len().is_power_of_two() {
            return Err(ProofError::NotPowerOfTwo(bits.len()));
        }
        let total_bits = bits.len().trailing_zeros() as usize;
        let low_bits = total_bits.min(7);
        let low_len = 1usize << low_bits;
        let high_len = bits.len() / low_len;
        let mut packed = vec![F2_128::from(0u64); high_len];
        for high in 0..high_len {
            let mut value = F2_128::from(0u64);
            for low in 0..low_len {
                if bits[high * low_len + low] {
                    value = value + F2_128::from(1u128 << low);
                }
            }
            packed[high] = value;
        }
        if packed.len() == 1 {
            packed.push(F2_128::from(0u64));
        }
        Ok(packed)
    }

    #[allow(clippy::needless_range_loop)]
    fn eval(packed: &[F2_128], point: &[F2_128]) -> F2_128 {
        let low_bits = point.len().min(7);
        let low_len = 1usize << low_bits;
        let high_bits = point.len() - low_bits;
        let high_len = 1usize << high_bits;
        let low_point = &point[..low_bits];
        let high_point = &point[low_bits..];
        let mut value = F2_128::from(0u64);
        for high in 0..high_len {
            let high_bits_vec = (0..high_bits)
                .map(|bit| F2_128::from(((high >> bit) & 1) as u64))
                .collect::<Vec<_>>();
            let high_eq = crate::eq(high_point, &high_bits_vec);
            for low in 0..low_len {
                if (packed[high].value() >> low) & 1 == 1 {
                    let low_bits_vec = (0..low_bits)
                        .map(|bit| F2_128::from(((low >> bit) & 1) as u64))
                        .collect::<Vec<_>>();
                    value = value + high_eq * crate::eq(low_point, &low_bits_vec);
                }
            }
        }
        value
    }
}

impl<P: Pcs> BitPcs for RevealingPackedBitPcs<P> {
    type Commitment = P::Commitment;
    type Opening = PackedTableOpening;

    fn commit(&self, bits: &[bool]) -> Result<Self::Commitment, ProofError> {
        self.pcs.commit(&Self::pack(bits)?)
    }

    fn open(&self, bits: &[bool], point: &[F2_128]) -> Result<(F2_128, Self::Opening), ProofError> {
        let packed = Self::pack(bits)?;
        let value = Self::eval(&packed, point);
        Ok((value, PackedTableOpening { packed }))
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &[F2_128],
        value: F2_128,
        opening: &Self::Opening,
    ) -> Result<bool, ProofError> {
        let recomputed = self.pcs.commit(&opening.packed)?;
        if self.pcs.commitment_bytes(&recomputed) != self.pcs.commitment_bytes(commitment) {
            return Ok(false);
        }
        Ok(Self::eval(&opening.packed, point) == value)
    }

    fn commitment_bytes(&self, commitment: &Self::Commitment) -> Vec<u8> {
        self.pcs.commitment_bytes(commitment)
    }
}

#[cfg(test)]
mod reveal_tests {
    use super::*;

    #[derive(Clone, Debug)]
    struct TestPcs;

    impl Pcs for TestPcs {
        type Commitment = Vec<F2_128>;
        type Opening = ();

        fn commit(&self, values: &[F2_128]) -> Result<Self::Commitment, ProofError> {
            Ok(values.to_vec())
        }

        fn open(&self, _values: &[F2_128], _point: &[F2_128]) -> Result<(), ProofError> {
            Ok(())
        }

        fn verify(
            &self,
            _commitment: &Self::Commitment,
            _point: &[F2_128],
            _value: F2_128,
            _opening: &(),
        ) -> Result<bool, ProofError> {
            Ok(true)
        }

        fn commitment_bytes(&self, commitment: &Self::Commitment) -> Vec<u8> {
            commitment
                .iter()
                .flat_map(|value| value.value().to_le_bytes())
                .collect()
        }
    }

    #[test]
    fn revealing_backend_handles_multi_field_witness() {
        let bits = (0..256).map(|index| index % 7 == 0).collect::<Vec<_>>();
        let point = (0..8)
            .map(|bit| F2_128::from((bit * 3 + 1) as u64))
            .collect::<Vec<_>>();
        let direct = DirectBitPcs::new(TestPcs);
        let reveal = RevealingPackedBitPcs::new(TestPcs);
        let (direct_value, _) = direct.open(&bits, &point).unwrap();
        let (value, opening) = reveal.open(&bits, &point).unwrap();
        assert_eq!(direct_value, value);
        let commitment = reveal.commit(&bits).unwrap();
        assert!(reveal.verify(&commitment, &point, value, &opening).unwrap());
    }
}
