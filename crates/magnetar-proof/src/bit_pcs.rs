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
    fn avx2_and_scalar_packing_agree() {
        let bits = (0..1024usize)
            .map(|index| (index * index + 3 * index + 1) % 7 < 3)
            .collect::<Vec<_>>();
        let scalar = RingSwitchPackedBitPcs::<TestPcs>::pack_scalar(&bits);
        let packed = RingSwitchPackedBitPcs::<TestPcs>::pack(&bits).unwrap();
        assert_eq!(scalar, packed);
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
    fn ring_switch_matches_direct_for_multi_field() {
        let bits = (0..256).map(|index| index % 11 == 0).collect::<Vec<_>>();
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
pub fn pack_bits_bench<P: Pcs>(bits: &[bool], hardware: bool) -> Result<Vec<F2_128>, ProofError> {
    if hardware {
        RingSwitchPackedBitPcs::<P>::pack(bits)
    } else {
        Ok(RingSwitchPackedBitPcs::<P>::pack_scalar(bits))
    }
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

    fn pack(bits: &[bool]) -> Result<Vec<F2_128>, ProofError> {
        if bits.len() < 256 || !bits.len().is_power_of_two() {
            return Err(ProofError::Pcs(
                "ring-switch packing requires at least 256 bits".into(),
            ));
        }
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("avx2") {
                // SAFETY: the length is checked above and the slice is at least
                // 256 bytes, so four 32-byte loads per 128-bit chunk are in
                // bounds; `bool` has a one-byte 0/1 representation.
                return Ok(unsafe { Self::pack_avx2(bits) });
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: NEON is baseline on aarch64; each load reads 16 bytes
            // within a 128-byte chunk and `bool` is a 0/1 byte.
            return Ok(unsafe { Self::pack_neon(bits) });
        }
        #[allow(unreachable_code)]
        Ok(Self::pack_scalar(bits))
    }

    fn pack_scalar(bits: &[bool]) -> Vec<F2_128> {
        let low_bits = 7;
        let low_len = 1usize << low_bits;
        let high_len = bits.len() / low_len;
        let mut packed = vec![F2_128::from(0u64); high_len];
        for (high, slot) in packed.iter_mut().enumerate() {
            let mut word = 0u128;
            for low in 0..low_len {
                if bits[high * low_len + low] {
                    word |= 1u128 << low;
                }
            }
            *slot = F2_128::from(word);
        }
        packed
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn pack_avx2(bits: &[bool]) -> Vec<F2_128> {
        use std::arch::x86_64::{
            __m256i, _mm256_cmpeq_epi8, _mm256_loadu_si256, _mm256_movemask_epi8,
            _mm256_setzero_si256,
        };
        let low_len = 128usize;
        let high_len = bits.len() / low_len;
        let mut packed = vec![F2_128::from(0u64); high_len];
        let zero: __m256i = _mm256_setzero_si256();
        for (high, slot) in packed.iter_mut().enumerate() {
            let ptr = bits.as_ptr().add(high * low_len) as *const __m256i;
            let mut word = 0u128;
            for group in 0..4usize {
                let value = unsafe { _mm256_loadu_si256(ptr.add(group)) };
                let equal = _mm256_cmpeq_epi8(value, zero);
                let nonzero = !(_mm256_movemask_epi8(equal) as u32);
                word |= u128::from(nonzero) << (group * 32);
            }
            *slot = F2_128::from(word);
        }
        packed
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn pack_neon(bits: &[bool]) -> Vec<F2_128> {
        use std::arch::aarch64::{
            vaddvq_u16, vget_high_u8, vget_low_u8, vld1q_s16, vld1q_u8, vmovl_u8, vshlq_u16,
        };
        let shift_values = [0i16, 1, 2, 3, 4, 5, 6, 7];
        let shifts = unsafe { vld1q_s16(shift_values.as_ptr()) };
        unsafe fn pack_u16(ptr: *const u8, shifts: std::arch::aarch64::int16x8_t) -> u16 {
            let value = unsafe { vld1q_u8(ptr) };
            let low = unsafe { vaddvq_u16(vshlq_u16(vmovl_u8(vget_low_u8(value)), shifts)) };
            let high = unsafe { vaddvq_u16(vshlq_u16(vmovl_u8(vget_high_u8(value)), shifts)) };
            low | (high << 8)
        }
        let low_len = 128usize;
        let high_len = bits.len() / low_len;
        let mut packed = vec![F2_128::from(0u64); high_len];
        for (high, slot) in packed.iter_mut().enumerate() {
            let ptr = bits.as_ptr().add(high * low_len);
            let mut word = 0u128;
            for group in 0..8usize {
                let value = unsafe { pack_u16(ptr.add(group * 16) as *const u8, shifts) };
                word |= u128::from(value) << (group * 16);
            }
            *slot = F2_128::from(word);
        }
        packed
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
        let mut scaled = values.to_vec();
        F2_128::mul_slice_assign(&mut scaled, scalar);
        scaled
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

    fn eq_vector(point: &[F2_128]) -> Vec<F2_128> {
        (0..1usize << point.len())
            .map(|index| {
                let bits = (0..point.len())
                    .map(|bit| F2_128::from(((index >> bit) & 1) as u64))
                    .collect::<Vec<_>>();
                crate::eq(point, &bits)
            })
            .collect()
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

    fn commit(&self, bits: &[bool]) -> Result<Self::Commitment, ProofError> {
        self.pcs.commit(&Self::pack(bits)?)
    }

    fn open(&self, bits: &[bool], point: &[F2_128]) -> Result<(F2_128, Self::Opening), ProofError> {
        use magnetar_transcript::Sha256Transcript;

        let packed = Self::pack(bits)?;
        let high_bits = point.len() - 7;
        if high_bits == 0 || packed.len() != 1 << high_bits {
            return Err(ProofError::Pcs("ring-switch point size mismatch".into()));
        }
        let prefix = &point[..7];
        let suffix = &point[7..];
        let eq_suffix = Self::eq_vector(suffix);
        let mut s_hat_v = vec![F2_128::from(0u64); 128];
        for (high, &weight) in eq_suffix.iter().enumerate() {
            let packed_value = packed[high].value();
            for (bit, value) in s_hat_v.iter_mut().enumerate() {
                if (packed_value >> bit) & 1 == 1 {
                    *value = *value + weight;
                }
            }
        }
        let claim = Self::evaluate(&s_hat_v, prefix);

        let commitment = self.pcs.commit(&packed)?;
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
        let a_values = (0..1usize << high_bits)
            .map(|index| {
                let query = (0..high_bits)
                    .map(|bit| F2_128::from(((index >> bit) & 1) as u64))
                    .collect::<Vec<_>>();
                Self::eval_rs_eq(suffix, &query, &eq_double)
            })
            .collect::<Vec<_>>();
        let (sumcheck, ry, _) =
            crate::prove_product2(packed.clone(), a_values, |round, values| {
                Self::sumcheck_challenge(&mut transcript, round, values)
            })?;
        if sumcheck.claimed_sum != sumcheck_claim {
            return Err(ProofError::Pcs(
                "ring-switch sumcheck claim mismatch".into(),
            ));
        }
        let packed_value = Self::evaluate(&packed, &ry);
        let pcs_opening = self.pcs.open(&packed, &ry)?;
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
