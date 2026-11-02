//! Bit-witness commitment backend.
//!
//! `BitPcs` is the abstraction boundary between the CPU relations (which are
//! over a bit-valued witness) and the commitment/proof layer. `DirectBitPcs`
//! implements the current one-field-element-per-bit encoding. A future
//! `PackedBitPcs` can implement 128-bits-per-field commitment + ring switching
//! behind the same trait.

use magnetar_constraint::F2_128;

use crate::{Mle, PackedBits, Pcs, ProofError};

pub trait BitPcs {
    type Commitment: Clone + std::fmt::Debug;
    type Opening: Clone + std::fmt::Debug;

    fn commit(&self, bits: &PackedBits) -> Result<Self::Commitment, ProofError>;
    fn open(&self, bits: &PackedBits, point: &[F2_128]) -> Result<(F2_128, Self::Opening), ProofError>;

    /// Open a witness whose commitment the caller already computed. Backends
    /// whose `open` needs the commitment internally can override this to skip
    /// a second commit; the default ignores it.
    fn open_with_commitment(
        &self,
        bits: &PackedBits,
        point: &[F2_128],
        _commitment: &Self::Commitment,
    ) -> Result<(F2_128, Self::Opening), ProofError> {
        self.open(bits, point)
    }
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

    fn values(bits: &PackedBits) -> Vec<F2_128> {
        (0..bits.len())
            .map(|index| F2_128::from(u64::from(bits.get(index))))
            .collect()
    }
}

impl<P: Pcs> BitPcs for DirectBitPcs<P> {
    type Commitment = P::Commitment;
    type Opening = P::Opening;

    fn commit(&self, bits: &PackedBits) -> Result<Self::Commitment, ProofError> {
        self.pcs.commit(&Self::values(bits))
    }

    fn open(&self, bits: &PackedBits, point: &[F2_128]) -> Result<(F2_128, Self::Opening), ProofError> {
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

    #[test]
    fn fast_transpose_matches_naive() {
        let values = (0..128u128)
            .map(|index| {
                let mut state = index.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0xdead_beef;
                state ^= state << 17;
                state ^= state >> 29;
                F2_128::from(state.wrapping_mul(index + 3))
            })
            .collect::<Vec<_>>();
        let fast = RingSwitchPackedBitPcs::<TestPcs>::transpose128(&values);
        let naive = RingSwitchPackedBitPcs::<TestPcs>::transpose128_naive(&values);
        assert_eq!(fast, naive);
    }

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
    fn ring_switch_packing_is_the_little_endian_word_view() {
        let bools = (0..1024usize)
            .map(|index| (index * index + 3 * index + 1) % 7 < 3)
            .collect::<Vec<_>>();
        let bits = PackedBits::from_bools(&bools);
        let packed = RingSwitchPackedBitPcs::<TestPcs>::pack(&bits).unwrap();
        let expected = (0..8)
            .map(|field| {
                let mut word = 0u128;
                for low in 0..128 {
                    if bools[field * 128 + low] {
                        word |= 1u128 << low;
                    }
                }
                F2_128::from(word)
            })
            .collect::<Vec<_>>();
        assert_eq!(packed, expected);
    }

    #[test]
    fn packed_and_direct_agree_on_all_points_128() {
        let bits = PackedBits::from_bools(
            &(0..128).map(|index| index % 3 == 0).collect::<Vec<_>>(),
        );
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
        let bits = PackedBits::from_bools(
            &(0..128).map(|index| index % 5 == 0).collect::<Vec<_>>(),
        );
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
        let bits = PackedBits::from_bools(&[true, false, true, true, false, true, false, false]);
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
    fn eq_vector_matches_pointwise_eq() {
        let point = (1..=5)
            .map(|index| F2_128::from((index * 7 + 3) as u64))
            .collect::<Vec<_>>();
        let table = RingSwitchPackedBitPcs::<TestPcs>::eq_vector(&point);
        assert_eq!(table.len(), 1 << point.len());
        for (index, value) in table.iter().enumerate() {
            let bits = (0..point.len())
                .map(|bit| F2_128::from(((index >> bit) & 1) as u64))
                .collect::<Vec<_>>();
            assert_eq!(*value, crate::eq(&point, &bits), "index {index}");
        }
    }

    #[test]
    fn eval_rs_eq_table_matches_pointwise() {
        let row_batch = RingSwitchPackedBitPcs::<TestPcs>::eq_vector(&[
            F2_128::from(3u64),
            F2_128::from(5u64),
            F2_128::from(7u64),
            F2_128::from(3u64),
            F2_128::from(5u64),
            F2_128::from(7u64),
            F2_128::from(3u64),
        ]);
        let z = vec![F2_128::from(6u64), F2_128::from(9u64), F2_128::from(11u64)];
        let table = RingSwitchPackedBitPcs::<TestPcs>::eval_rs_eq_table(&z, &row_batch);
        for (index, value) in table.iter().enumerate() {
            let query = (0..z.len())
                .map(|bit| F2_128::from(((index >> bit) & 1) as u64))
                .collect::<Vec<_>>();
            assert_eq!(
                *value,
                RingSwitchPackedBitPcs::<TestPcs>::eval_rs_eq(&z, &query, &row_batch),
                "index {index}"
            );
        }
    }

    #[test]
    fn ring_switch_matches_direct_for_multi_field() {
        let bits = PackedBits::from_bools(
            &(0..256)
                .map(|index| index % 11 == 0)
                .collect::<Vec<_>>(),
        );
        let point = (0..8)
            .map(|bit| F2_128::from((bit * 5 + 1) as u64))
            .collect::<Vec<_>>();
        let direct = DirectBitPcs::new(TestPcs);
        let ring = RingSwitchPackedBitPcs::new(TestPcs);
        let (direct_value, _) = direct.open(&bits, &point).unwrap();
        let packed = RingSwitchPackedBitPcs::<TestPcs>::pack(&bits).unwrap();
        let eq_suffix = RingSwitchPackedBitPcs::<TestPcs>::eq_vector(&point[7..]);
        let mut s_hat = vec![F2_128::from(0u64); 128];
        for (high, &w) in eq_suffix.iter().enumerate() {
            for (bit, slot) in s_hat.iter_mut().enumerate() {
                if (packed[high].value() >> bit) & 1 == 1 {
                    *slot = *slot + w;
                }
            }
        }
        let claim = RingSwitchPackedBitPcs::<TestPcs>::evaluate(&s_hat, &point[..7]);
        eprintln!("direct={direct_value:?} claim={claim:?} packed={packed:?}");
        let (value, opening) = ring.open(&bits, &point).unwrap();
        assert_eq!(direct_value, value);
        let commitment = ring.commit(&bits).unwrap();
        assert!(ring.verify(&commitment, &point, value, &opening).unwrap());
        let mut tampered = opening.clone();
        tampered.s_hat_v[0] = tampered.s_hat_v[0] + F2_128::from(1u64);
        assert!(!ring.verify(&commitment, &point, value, &tampered).unwrap());
    }

    #[test]
    fn direct_bit_pcs_opens_bit_mle() {
        let backend = DirectBitPcs::new(TestPcs);
        let bits = PackedBits::from_bools(&[true, false, true, true]);
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

    fn pack(bits: &PackedBits) -> Result<Vec<F2_128>, ProofError> {
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
        let mut packed = Vec::with_capacity(high_len);
        if low_bits == 7 {
            for high in 0..high_len {
                packed.push(F2_128::from(bits.field_128(high)));
            }
        } else {
            packed.push(F2_128::from(
                bits.words().first().copied().unwrap_or(0) as u128,
            ));
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

    fn commit(&self, bits: &PackedBits) -> Result<Self::Commitment, ProofError> {
        let packed = Self::pack(bits)?;
        self.pcs.commit(&packed)
    }

    fn open(&self, bits: &PackedBits, point: &[F2_128]) -> Result<(F2_128, Self::Opening), ProofError> {
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

    fn pack(bits: &PackedBits) -> Result<Vec<F2_128>, ProofError> {
        if bits.is_empty() || !bits.len().is_power_of_two() {
            return Err(ProofError::NotPowerOfTwo(bits.len()));
        }
        let low_bits = (bits.len().trailing_zeros() as usize).min(7);
        let low_len = 1usize << low_bits;
        let high_len = bits.len() / low_len;
        let mut packed = Vec::with_capacity(high_len);
        if low_bits == 7 {
            for high in 0..high_len {
                packed.push(F2_128::from(bits.field_128(high)));
            }
        } else {
            packed.push(F2_128::from(
                bits.words().first().copied().unwrap_or(0) as u128,
            ));
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

    fn commit(&self, bits: &PackedBits) -> Result<Self::Commitment, ProofError> {
        self.pcs.commit(&Self::pack(bits)?)
    }

    fn open(&self, bits: &PackedBits, point: &[F2_128]) -> Result<(F2_128, Self::Opening), ProofError> {
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
        let bits = crate::PackedBits::from_bools(&(0..256).map(|index| index % 7 == 0).collect::<Vec<_>>());
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

/// Ring-switching opening for multi-field packed witnesses.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RingSwitchOpening<O> {
    pub s_hat_v: Vec<F2_128>,
    pub sumcheck: crate::SumcheckProof<F2_128>,
    pub packed_value: F2_128,
    pub pcs_opening: O,
}

/// Hidden benchmark hook: pack bits with the hardware kernel or the scalar
/// reference. Used by the testkit to measure the SIMD packing path.
#[doc(hidden)]
pub fn pack_bits_bench<P: Pcs>(
    bits: &crate::PackedBits,
    _hardware: bool,
) -> Result<Vec<F2_128>, ProofError> {
    RingSwitchPackedBitPcs::<P>::pack(bits)
}

/// Multi-field packed backend implementing the DP24/Binius ring-switch
/// reduction. Witnesses are packed 128 bits per field element; the final
/// evaluation is reduced to a product sum-check against the packed table.
#[derive(Clone, Copy, Debug)]
pub struct RingSwitchPackedBitPcs<P: Pcs> {
    pub pcs: P,
}

impl<P: Pcs> RingSwitchPackedBitPcs<P> {
    pub fn new(pcs: P) -> Self {
        Self { pcs }
    }

    fn pack(bits: &PackedBits) -> Result<Vec<F2_128>, ProofError> {
        if bits.len() < 256 || !bits.len().is_power_of_two() {
            return Err(ProofError::Pcs(
                "ring-switch packing requires at least 256 bits".into(),
            ));
        }
        // 128 consecutive bits are one field element, so the packed table is
        // the witness words read as little-endian u128s: no shifting or SIMD
        // transpose is needed.
        Ok((0..bits.fields_128())
            .map(|field| F2_128::from(bits.field_128(field)))
            .collect())
    }

    fn transpose128(values: &[F2_128]) -> Vec<F2_128> {
        if values.len() != 128 {
            return Self::transpose128_naive(values);
        }
        let mut output = [0u128; 128];
        for (row, value) in values.iter().enumerate() {
            let mut bits = value.value();
            let row_bit = 1u128 << row;
            while bits != 0 {
                let column = bits.trailing_zeros() as usize;
                output[column] |= row_bit;
                bits &= bits - 1;
            }
        }
        output.into_iter().map(F2_128::from).collect()
    }

    fn transpose128_naive(values: &[F2_128]) -> Vec<F2_128> {
        let mut output = vec![F2_128::from(0u64); 128];
        for (row, value) in values.iter().enumerate() {
            let bits = value.value();
            for (column, out) in output.iter_mut().enumerate() {
                if (bits >> column) & 1 == 1 {
                    *out = *out + F2_128::from(1u128 << row);
                }
            }
        }
        output
    }

    fn scale_vertical(values: &[F2_128], scalar: F2_128) -> Vec<F2_128> {
        values.iter().map(|value| *value * scalar).collect()
    }

    fn scale_horizontal(values: &[F2_128], scalar: F2_128) -> Vec<F2_128> {
        let transposed = Self::transpose128(values);
        let scaled = Self::scale_vertical(&transposed, scalar);
        Self::transpose128(&scaled)
    }

    fn eval_rs_eq(z_vals: &[F2_128], query: &[F2_128], row_batch: &[F2_128]) -> F2_128 {
        let mut eval = vec![F2_128::from(0u64); 128];
        eval[0] = F2_128::from(1u64);
        for (vertical, horizontal) in z_vals.iter().zip(query) {
            let vertical_scaled = Self::scale_vertical(&eval, *vertical);
            let horizontal_scaled = Self::scale_horizontal(&eval, *horizontal);
            F2_128::add_assign_slice(&mut eval, &vertical_scaled);
            F2_128::add_assign_slice(&mut eval, &horizontal_scaled);
        }
        let transposed = Self::transpose128(&eval);
        transposed
            .iter()
            .zip(row_batch)
            .fold(F2_128::from(0u64), |sum, (value, coeff)| {
                sum + *value * *coeff
            })
    }

    fn eval_rs_eq_table(z_vals: &[F2_128], row_batch: &[F2_128]) -> Vec<F2_128> {
        let mut scalars = vec![F2_128::from(1u64); 1usize << z_vals.len()];
        for (bit, vertical) in z_vals.iter().enumerate() {
            let len = 1usize << bit;
            for index in 0..len {
                let value = scalars[index];
                scalars[index] = value * (F2_128::from(1u64) + *vertical);
                scalars[len + index] = value * *vertical;
            }
        }
        let mut byte_table = [[F2_128::from(0u64); 256]; 16];
        for (byte, table) in byte_table.iter_mut().enumerate() {
            for (mask, value) in table.iter_mut().enumerate() {
                let mut sum = F2_128::from(0u64);
                for bit in 0..8 {
                    if (mask >> bit) & 1 == 1 {
                        sum = sum + row_batch[byte * 8 + bit];
                    }
                }
                *value = sum;
            }
        }
        scalars
            .into_iter()
            .map(|scalar| {
                let bytes = scalar.value().to_le_bytes();
                bytes
                    .iter()
                    .enumerate()
                    .fold(F2_128::from(0u64), |sum, (byte, value)| {
                        sum + byte_table[byte][usize::from(*value)]
                    })
            })
            .collect()
    }

    fn eq_vector(point: &[F2_128]) -> Vec<F2_128> {
        // Doubling construction: `eq(point, index) = prod_b (index_b ? z_b : 1+z_b)`.
        // Building it level by level avoids the per-index vector the previous
        // implementation allocated (one heap allocation per table entry: 8.4 M
        // at RV64 `2^16`, the largest term of the ring-switch opening).
        let mut values = vec![F2_128::from(1u64); 1usize << point.len()];
        for (bit, vertical) in point.iter().enumerate() {
            let len = 1usize << bit;
            for index in 0..len {
                let value = values[index];
                values[index] = value * (F2_128::from(1u64) + *vertical);
                values[len + index] = value * *vertical;
            }
        }
        values
    }

    fn evaluate(values: &[F2_128], point: &[F2_128]) -> F2_128 {
        assert_eq!(values.len(), 1 << point.len());
        let mut current = values.to_vec();
        for challenge in point.iter().rev() {
            let half = current.len() / 2;
            for index in 0..half {
                current[index] = current[index] * (F2_128::from(1u64) + *challenge)
                    + current[index + half] * *challenge;
            }
            current.truncate(half);
        }
        current[0]
    }

    fn transpose_components(values: &[F2_128]) -> Vec<F2_128> {
        Self::transpose128(values)
    }

    fn challenge_field(
        transcript: &mut magnetar_transcript::Sha256Transcript,
        label: &str,
    ) -> F2_128 {
        let bytes = transcript.challenge_bytes(label, 16);
        F2_128::from_bits(u128::from_le_bytes(bytes.try_into().expect("16 bytes")))
    }

    fn sumcheck_challenge(
        transcript: &mut magnetar_transcript::Sha256Transcript,
        round: usize,
        values: &[F2_128],
    ) -> F2_128 {
        transcript.absorb("round", &(round as u64).to_le_bytes());
        for value in values {
            transcript.absorb("round-poly", &value.value().to_le_bytes());
        }
        Self::challenge_field(transcript, "sumcheck")
    }
}

impl<P: Pcs> BitPcs for RingSwitchPackedBitPcs<P> {
    type Commitment = P::Commitment;
    type Opening = RingSwitchOpening<P::Opening>;

    fn commit(&self, bits: &PackedBits) -> Result<Self::Commitment, ProofError> {
        self.pcs.commit(&Self::pack(bits)?)
    }

    fn open(&self, bits: &PackedBits, point: &[F2_128]) -> Result<(F2_128, Self::Opening), ProofError> {
        Self::open_inner(self, bits, point, None)
    }

    fn open_with_commitment(
        &self,
        bits: &PackedBits,
        point: &[F2_128],
        commitment: &Self::Commitment,
    ) -> Result<(F2_128, Self::Opening), ProofError> {
        Self::open_inner(self, bits, point, Some(commitment))
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &[F2_128],
        value: F2_128,
        opening: &Self::Opening,
    ) -> Result<bool, ProofError> {
        use magnetar_transcript::Sha256Transcript;

        let high_bits = point.len() - 7;
        if high_bits == 0 || opening.s_hat_v.len() != 128 || (1usize << high_bits) < 2 {
            return Ok(false);
        }
        let prefix = &point[..7];
        let suffix = &point[7..];
        if Self::evaluate(&opening.s_hat_v, prefix) != value {
            return Ok(false);
        }
        let mut transcript = Sha256Transcript::new("magnetar-ring-switch-v1");
        transcript.absorb("commitment", &self.pcs.commitment_bytes(commitment));
        for value in point {
            transcript.absorb("point", &value.value().to_le_bytes());
        }
        for value in &opening.s_hat_v {
            transcript.absorb("s-hat-v", &value.value().to_le_bytes());
        }
        let r_double = (0..7)
            .map(|_| Self::challenge_field(&mut transcript, "row-batch"))
            .collect::<Vec<_>>();
        let eq_double = Self::eq_vector(&r_double);
        let s_hat_u = Self::transpose_components(&opening.s_hat_v);
        let sumcheck_claim = s_hat_u
            .iter()
            .zip(&eq_double)
            .fold(F2_128::from(0u64), |sum, (a, b)| sum + *a * *b);
        if opening.sumcheck.claimed_sum != sumcheck_claim {
            return Ok(false);
        }
        let (ry, product) =
            crate::verify_rounds(&opening.sumcheck, high_bits, 2, |round, values| {
                Self::sumcheck_challenge(&mut transcript, round, values)
            })?;
        if !self
            .pcs
            .verify(commitment, &ry, opening.packed_value, &opening.pcs_opening)?
        {
            return Ok(false);
        }
        let a_at = Self::eval_rs_eq(suffix, &ry, &eq_double);
        Ok(product == opening.packed_value * a_at)
    }

    fn commitment_bytes(&self, commitment: &Self::Commitment) -> Vec<u8> {
        self.pcs.commitment_bytes(commitment)
    }
}

impl<P: Pcs> RingSwitchPackedBitPcs<P> {
    /// Opening implementation shared by `open` and `open_with_commitment`.
    /// `known` lets the caller pass the commitment of `bits` it already holds,
    /// which skips a full commit of the packed table.
    fn open_inner(
        &self,
        bits: &PackedBits,
        point: &[F2_128],
        known: Option<&P::Commitment>,
    ) -> Result<(F2_128, RingSwitchOpening<P::Opening>), ProofError> {
        use magnetar_transcript::Sha256Transcript;

        let profile = std::env::var_os("MAGNETAR_PROFILE_RING").is_some();
        let started = std::time::Instant::now();
        let packed = Self::pack(bits)?;
        if profile {
            eprintln!("ring pack: {:?}", started.elapsed());
        }
        let high_bits = point.len() - 7;
        if high_bits == 0 || packed.len() != 1 << high_bits {
            return Err(ProofError::Pcs("ring-switch point size mismatch".into()));
        }
        let prefix = &point[..7];
        let suffix = &point[7..];
        let eq_suffix = Self::eq_vector(suffix);
        // 128 packed columns x 2^high_bits rows: iterate the set bits of each
        // packed word instead of testing all 128, and split the rows across
        // workers (the per-slot sums are XOR, so the reduction is exact).
        let mut s_hat_v = vec![F2_128::from(0u64); 128];
        let workers = std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1)
            .clamp(1, eq_suffix.len().max(1));
        if workers > 1 && eq_suffix.len() >= 4096 {
            let chunk = eq_suffix.len().div_ceil(workers);
            let partials = std::thread::scope(|scope| {
                let mut handles = Vec::with_capacity(workers);
                for start in (0..eq_suffix.len()).step_by(chunk) {
                    let end = (start + chunk).min(eq_suffix.len());
                    let weights = &eq_suffix[start..end];
                    let words = &packed[start..end];
                    handles.push(scope.spawn(move || {
                        let mut local = [F2_128::from(0u64); 128];
                        for (weight, word) in weights.iter().zip(words) {
                            let mut set = word.value();
                            while set != 0 {
                                let bit = set.trailing_zeros() as usize;
                                local[bit] = local[bit] + *weight;
                                set &= set - 1;
                            }
                        }
                        local
                    }));
                }
                handles
                    .into_iter()
                    .map(|handle| handle.join().expect("ring-switch worker"))
                    .collect::<Vec<_>>()
            });
            for partial in partials {
                for (slot, value) in s_hat_v.iter_mut().zip(partial) {
                    *slot = *slot + value;
                }
            }
        } else {
            for (high, &weight) in eq_suffix.iter().enumerate() {
                let mut set = packed[high].value();
                while set != 0 {
                    let bit = set.trailing_zeros() as usize;
                    s_hat_v[bit] = s_hat_v[bit] + weight;
                    set &= set - 1;
                }
            }
        }
        let claim = Self::evaluate(&s_hat_v, prefix);

        let commitment = match known {
            Some(commitment) => commitment.clone(),
            None => self.pcs.commit(&packed)?,
        };
        let mut transcript = Sha256Transcript::new("magnetar-ring-switch-v1");
        transcript.absorb("commitment", &self.pcs.commitment_bytes(&commitment));
        for value in point {
            transcript.absorb("point", &value.value().to_le_bytes());
        }
        for value in &s_hat_v {
            transcript.absorb("s-hat-v", &value.value().to_le_bytes());
        }
        let r_double = (0..7)
            .map(|_| Self::challenge_field(&mut transcript, "row-batch"))
            .collect::<Vec<_>>();
        let eq_double = Self::eq_vector(&r_double);
        let s_hat_u = Self::transpose_components(&s_hat_v);
        let sumcheck_claim = s_hat_u
            .iter()
            .zip(&eq_double)
            .fold(F2_128::from(0u64), |sum, (a, b)| sum + *a * *b);
        let a_values = if (1usize << high_bits) >= 64 {
            Self::eval_rs_eq_table(suffix, &eq_double)
        } else {
            (0..1usize << high_bits)
                .map(|index| {
                    let query = (0..high_bits)
                        .map(|bit| F2_128::from(((index >> bit) & 1) as u64))
                        .collect::<Vec<_>>();
                    Self::eval_rs_eq(suffix, &query, &eq_double)
                })
                .collect::<Vec<_>>()
        };
        if profile {
            eprintln!("ring eval: {:?}", started.elapsed());
        }
        let product_started = std::time::Instant::now();
        let (sumcheck, ry, _) =
            crate::prove_product2(packed.clone(), a_values, |round, values| {
                Self::sumcheck_challenge(&mut transcript, round, values)
            })?;
        if sumcheck.claimed_sum != sumcheck_claim {
            return Err(ProofError::Pcs(
                "ring-switch sumcheck claim mismatch".into(),
            ));
        }
        if profile {
            eprintln!("ring product2: {:?}", product_started.elapsed());
        }
        let open_started = std::time::Instant::now();
        let packed_value = Self::evaluate(&packed, &ry);
        let pcs_opening = self.pcs.open(&packed, &ry)?;
        if profile {
            eprintln!("ring p3 open: {:?}", open_started.elapsed());
        }
        Ok((
            claim,
            RingSwitchOpening {
                s_hat_v,
                sumcheck,
                packed_value,
                pcs_opening,
            },
        ))
    
    }
}
