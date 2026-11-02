//! Virtual Spartan per-segment claim consistency.
//!
//! The full witness claim `W(r) = v` is split into one claim per aligned
//! segment. For a segment at offset `s` with `b = s >> size_bits`, the local
//! point is the low part of `r`, and the full claim is reconstructed as
//! `Σ_i eq(r_high, b_i) · W_i(r_low)`.

use magnetar_constraint::{Segment, SegmentOwner, WitnessLayout, F2_128};
use thiserror::Error;

use crate::{eq, Mle, ProofError};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SegmentClaim {
    pub value: F2_128,
}

#[derive(Debug, Error)]
pub enum VirtualSpartanError {
    #[error("witness has {actual} values, expected {expected}")]
    WitnessLength { expected: usize, actual: usize },
    #[error("claim point has {actual} coordinates, expected {expected}")]
    PointLength { expected: usize, actual: usize },
    #[error("segment claim count/order mismatch")]
    ClaimShape,
    #[error("full witness claim does not match segment claims")]
    ClaimMismatch,
    #[error("routed segment claims do not match the layout owners")]
    RoutingShape,
    #[error(transparent)]
    Proof(#[from] ProofError),
}

fn suffix_bits(segment: &Segment, total_bits: usize) -> Vec<F2_128> {
    let size_bits = segment.len.trailing_zeros() as usize;
    let suffix = segment.offset >> size_bits;
    (0..total_bits - size_bits)
        .map(|bit| F2_128::from(((suffix >> bit) & 1) as u64))
        .collect()
}

fn local_point(point: &[F2_128], segment: &Segment) -> Vec<F2_128> {
    let size_bits = segment.len.trailing_zeros() as usize;
    point[..size_bits].to_vec()
}

/// A segment claim tagged with the component that owns the segment.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoutedSegmentClaim {
    pub name: String,
    pub owner: SegmentOwner,
    pub value: F2_128,
}

/// Attach each per-segment claim to the `SegmentOwner` recorded in the layout.
/// This is the routing hook for Virtual Spartan component claims.
pub fn route_segment_claims(
    layout: &WitnessLayout,
    claims: &[SegmentClaim],
) -> Result<Vec<RoutedSegmentClaim>, VirtualSpartanError> {
    if claims.len() != layout.segments.len() {
        return Err(VirtualSpartanError::ClaimShape);
    }
    Ok(layout
        .segments
        .iter()
        .zip(claims)
        .map(|(segment, claim)| RoutedSegmentClaim {
            name: segment.name.clone(),
            owner: segment.owner,
            value: claim.value,
        })
        .collect())
}

/// Group routed claims by their owning component.
pub fn route_segment_claims_by_owner(
    layout: &WitnessLayout,
    claims: &[SegmentClaim],
) -> Result<Vec<(SegmentOwner, Vec<RoutedSegmentClaim>)>, VirtualSpartanError> {
    let routed = route_segment_claims(layout, claims)?;
    let mut groups: Vec<(SegmentOwner, Vec<RoutedSegmentClaim>)> = Vec::new();
    for claim in routed {
        if let Some(group) = groups.iter_mut().find(|(owner, _)| *owner == claim.owner) {
            group.1.push(claim);
        } else {
            groups.push((claim.owner, vec![claim]));
        }
    }
    Ok(groups)
}

/// Expected owner -> segment-count table for a witness layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtualClaimRouter {
    pub expected: Vec<(SegmentOwner, usize)>,
}

impl VirtualClaimRouter {
    pub fn new(layout: &WitnessLayout) -> Self {
        let mut expected: Vec<(SegmentOwner, usize)> = Vec::new();
        for segment in &layout.segments {
            if let Some(group) = expected
                .iter_mut()
                .find(|(owner, _)| *owner == segment.owner)
            {
                group.1 += 1;
            } else {
                expected.push((segment.owner, 1));
            }
        }
        Self { expected }
    }

    /// Verify that every routed group is present exactly once with the expected
    /// segment count. This is the consumption check for Virtual Spartan claims.
    pub fn verify(
        &self,
        groups: &[(SegmentOwner, Vec<RoutedSegmentClaim>)],
    ) -> Result<(), VirtualSpartanError> {
        if groups.len() != self.expected.len() {
            return Err(VirtualSpartanError::RoutingShape);
        }
        for (owner, count) in &self.expected {
            let Some((_, claims)) = groups.iter().find(|(group, _)| group == owner) else {
                return Err(VirtualSpartanError::RoutingShape);
            };
            if claims.len() != *count {
                return Err(VirtualSpartanError::RoutingShape);
            }
        }
        Ok(())
    }
}

pub fn split_segment_claims(
    layout: &WitnessLayout,
    values: &[F2_128],
    point: &[F2_128],
) -> Result<Vec<SegmentClaim>, VirtualSpartanError> {
    let total_bits = layout.total_bits.trailing_zeros() as usize;
    let expected = layout.total_bits;
    if values.len() != expected {
        return Err(VirtualSpartanError::WitnessLength {
            expected,
            actual: values.len(),
        });
    }
    if point.len() != total_bits {
        return Err(VirtualSpartanError::PointLength {
            expected: total_bits,
            actual: point.len(),
        });
    }
    let mut claims = Vec::with_capacity(layout.segments.len());
    for segment in &layout.segments {
        let local = local_point(point, segment);
        let segment_values = values[segment.offset..segment.end()].to_vec();
        let value = Mle::new(segment_values)?.eval(&local)?;
        claims.push(SegmentClaim { value });
    }
    Ok(claims)
}

/// Evaluate the multilinear extension of a bit slice without materializing the
/// field-valued vector.
pub fn eval_bits_slice_mle(
    bits: &crate::PackedBits,
    offset: usize,
    point: &[F2_128],
) -> F2_128 {
    let len = if point.is_empty() {
        1
    } else {
        1usize << point.len()
    };
    if offset + len > bits.len() {
        return F2_128::from(0u64);
    }
    if point.is_empty() {
        return F2_128::from(u64::from(bits.get(offset)));
    }
    let low_bits = point.len().min(16);
    let low = crate::spartan::eq_vector_tensor(&point[..low_bits]);
    let high = if point.len() > low_bits {
        crate::spartan::eq_vector_tensor(&point[low_bits..])
    } else {
        vec![F2_128::from(1u64)]
    };
    let mut total = F2_128::from(0u64);
    for (block, weight) in high.iter().enumerate() {
        let start = offset + (block << low_bits);
        let mut sum = F2_128::from(0u64);
        for (bit, equality) in low.iter().enumerate() {
            if bits.get(start + bit) {
                sum = sum + *equality;
            }
        }
        total = total + sum * *weight;
    }
    total
}

/// The equality tensors one segment width needs.
///
/// `low` covers the segment's low `low_bits` coordinates (capped at 16, which
/// keeps the table within a megabyte); `high` covers the remaining coordinates.
/// Both depend only on the width and the point, never on the segment's offset,
/// so every segment of the same width shares them.
struct SegmentTensors {
    low_bits: usize,
    low: Vec<F2_128>,
    high: Vec<F2_128>,
}

impl SegmentTensors {
    fn build(size_bits: usize, point: &[F2_128]) -> Self {
        let low_bits = size_bits.min(16);
        let low = crate::spartan::eq_vector_tensor(&point[..low_bits]);
        let high = if size_bits > low_bits {
            crate::spartan::eq_vector_tensor(&point[low_bits..size_bits])
        } else {
            vec![F2_128::from(1u64)]
        };
        Self {
            low_bits,
            low,
            high,
        }
    }

    /// Multilinear evaluation of one bit slice with these tensors.
    ///
    /// Reads whole 64-bit words instead of calling `PackedBits::get` per bit,
    /// and adds the low equality weights in exactly the order the shipped
    /// per-bit loop did, so the claim is bit-identical.
    fn eval(&self, words: &[u64], offset: usize) -> F2_128 {
        if self.low_bits == 0 {
            let bit = (words[offset >> 6] >> (offset & 63)) & 1;
            return if bit == 1 {
                F2_128::from(1u64)
            } else {
                F2_128::from(0u64)
            };
        }
        let low_len = 1usize << self.low_bits;
        let mut total = F2_128::from(0u64);
        for (block, weight) in self.high.iter().enumerate() {
            let start = offset + (block << self.low_bits);
            let mut sum = F2_128::from(0u64);
            let mut done = 0usize;
            while done < low_len {
                let absolute = start + done;
                let word = words[absolute >> 6];
                let shift = absolute & 63;
                let take = (64 - shift).min(low_len - done);
                let chunk = if take == 64 {
                    word
                } else {
                    (word >> shift) & ((1u64 << take) - 1)
                };
                let mut set = chunk;
                while set != 0 {
                    let bit = set.trailing_zeros() as usize;
                    sum = sum + self.low[done + bit];
                    set &= set - 1;
                }
                done += take;
            }
            total = total + sum * *weight;
        }
        total
    }
}

/// Split the full witness claim into per-segment claims directly from the bit
/// witness, mirroring [`split_segment_claims`].
///
/// The segments are independent, and each one's evaluation depends only on the
/// point and its own bits, so this shares one equality-tensor pair per segment
/// width and runs the segments across the worker pool. The claims come back in
/// layout order and carry the same field elements as the sequential version.
pub fn split_segment_claims_bits(
    layout: &WitnessLayout,
    bits: &crate::PackedBits,
    point: &[F2_128],
) -> Result<Vec<SegmentClaim>, VirtualSpartanError> {
    let total_bits = layout.total_bits.trailing_zeros() as usize;
    if bits.len() != layout.total_bits {
        return Err(VirtualSpartanError::WitnessLength {
            expected: layout.total_bits,
            actual: bits.len(),
        });
    }
    if point.len() != total_bits {
        return Err(VirtualSpartanError::PointLength {
            expected: total_bits,
            actual: point.len(),
        });
    }
    // One tensor pair per distinct segment width (widths are powers of two, so
    // this is a handful of entries even for a wide CPU relation).
    let mut tensors: Vec<Option<SegmentTensors>> = (0..=total_bits).map(|_| None).collect();
    for segment in &layout.segments {
        let size_bits = segment.len.trailing_zeros() as usize;
        if tensors[size_bits].is_none() {
            tensors[size_bits] = Some(SegmentTensors::build(size_bits, point));
        }
    }
    let words = bits.words();
    let evaluate = |segment: &Segment| -> SegmentClaim {
        let size_bits = segment.len.trailing_zeros() as usize;
        let tensors = tensors[size_bits].as_ref().expect("width table");
        SegmentClaim {
            value: tensors.eval(words, segment.offset),
        }
    };
    let segments = &layout.segments;
    let workers = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .clamp(1, segments.len().max(1));
    let claims = if workers > 1 {
        let chunk = segments.len().div_ceil(workers);
        let mut ordered = Vec::with_capacity(segments.len());
        std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(workers);
            for (index, part) in segments.chunks(chunk).enumerate() {
                let evaluate = &evaluate;
                handles.push((index, scope.spawn(move || {
                    part.iter().map(evaluate).collect::<Vec<_>>()
                })));
            }
            handles.sort_by_key(|(index, _)| *index);
            for (_, handle) in handles {
                ordered.extend(handle.join().expect("segment claim worker"));
            }
        });
        ordered
    } else {
        segments.iter().map(&evaluate).collect()
    };
    Ok(claims)
}

pub fn reconstruct_segment_claim(
    layout: &WitnessLayout,
    claims: &[SegmentClaim],
    point: &[F2_128],
) -> Result<F2_128, VirtualSpartanError> {
    if claims.len() != layout.segments.len() {
        return Err(VirtualSpartanError::ClaimShape);
    }
    let total_bits = layout.total_bits.trailing_zeros() as usize;
    if point.len() != total_bits {
        return Err(VirtualSpartanError::PointLength {
            expected: total_bits,
            actual: point.len(),
        });
    }
    let mut reconstructed = F2_128::from(0u64);
    for (segment, claim) in layout.segments.iter().zip(claims) {
        let local = local_point(point, segment);
        let suffix = suffix_bits(segment, total_bits);
        reconstructed = reconstructed + eq(&suffix, &point[local.len()..]) * claim.value;
    }
    Ok(reconstructed)
}

pub fn verify_segment_claims(
    layout: &WitnessLayout,
    claims: &[SegmentClaim],
    point: &[F2_128],
    full_value: F2_128,
) -> Result<(), VirtualSpartanError> {
    let reconstructed = reconstruct_segment_claim(layout, claims, point)?;
    if reconstructed != full_value {
        return Err(VirtualSpartanError::ClaimMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_constraint::{SegmentKind, SegmentOwner};

    fn layout() -> WitnessLayout {
        WitnessLayout::new(vec![
            Segment::new("a", 0, 2, SegmentKind::Direct, SegmentOwner::Cpu),
            Segment::new("b", 4, 4, SegmentKind::Direct, SegmentOwner::Cpu),
            Segment::new("c", 8, 8, SegmentKind::Direct, SegmentOwner::Cpu),
        ])
        .unwrap()
    }

    #[test]
    fn virtual_claim_router_consumes_all_owner_groups() {
        let layout = layout();
        let values = (0..layout.total_bits)
            .map(|index| F2_128::from(index as u64 + 1))
            .collect::<Vec<_>>();
        let point = (0..layout.total_bits.trailing_zeros() as usize)
            .map(|bit| F2_128::from((bit + 1) as u64))
            .collect::<Vec<_>>();
        let claims = split_segment_claims(&layout, &values, &point).unwrap();
        let groups = route_segment_claims_by_owner(&layout, &claims).unwrap();
        VirtualClaimRouter::new(&layout).verify(&groups).unwrap();
        let mut bad = groups.clone();
        bad[0].1.pop();
        assert!(VirtualClaimRouter::new(&layout).verify(&bad).is_err());
    }

    #[test]
    fn segment_claims_are_routed_to_owners() {
        let layout = layout();
        let values = (0..layout.total_bits)
            .map(|index| F2_128::from(index as u64 + 1))
            .collect::<Vec<_>>();
        let point = (0..layout.total_bits.trailing_zeros() as usize)
            .map(|bit| F2_128::from((bit + 1) as u64))
            .collect::<Vec<_>>();
        let claims = split_segment_claims(&layout, &values, &point).unwrap();
        let routed = route_segment_claims(&layout, &claims).unwrap();
        assert_eq!(routed.len(), layout.segments.len());
        let grouped = route_segment_claims_by_owner(&layout, &claims).unwrap();
        assert_eq!(
            grouped
                .iter()
                .map(|(_, claims)| claims.len())
                .sum::<usize>(),
            claims.len()
        );
        for (routed, segment) in routed.iter().zip(&layout.segments) {
            assert_eq!(routed.name, segment.name);
            assert_eq!(routed.owner, segment.owner);
        }
    }

    /// The word-level, shared-tensor, multi-threaded split must return exactly
    /// the per-segment claims of the shipped per-bit evaluator, in layout order.
    #[test]
    fn split_bits_claims_match_the_reference_evaluator() {
        let layout = WitnessLayout::new(vec![
            Segment::new("a", 0, 2, SegmentKind::Direct, SegmentOwner::Cpu),
            Segment::new("b", 2, 2, SegmentKind::Direct, SegmentOwner::Cpu),
            Segment::new("c", 4, 4, SegmentKind::Direct, SegmentOwner::Cpu),
            Segment::new("d", 8, 8, SegmentKind::Direct, SegmentOwner::Cpu),
        ])
        .unwrap();
        let total_bits = layout.total_bits.trailing_zeros() as usize;
        let pattern = (0..layout.total_bits)
            .map(|index| (index.wrapping_mul(0x9e37).rotate_left(5) & 7) < 3)
            .collect::<Vec<_>>();
        let bits = crate::PackedBits::from_bools(&pattern);
        let point = (0..total_bits)
            .map(|bit| F2_128::from((bit as u64 * 11 + 5) & 0xff))
            .collect::<Vec<_>>();
        let expected = layout
            .segments
            .iter()
            .map(|segment| {
                let size_bits = segment.len.trailing_zeros() as usize;
                eval_bits_slice_mle(&bits, segment.offset, &point[..size_bits])
            })
            .collect::<Vec<_>>();
        let claims = split_segment_claims_bits(&layout, &bits, &point).unwrap();
        assert_eq!(
            claims.iter().map(|claim| claim.value).collect::<Vec<_>>(),
            expected
        );
    }

    #[test]
    fn segment_claims_reconstruct_full_witness() {
        let layout = layout();
        let mut values = vec![F2_128::from(0u64); layout.total_bits];
        for segment in &layout.segments {
            for (offset, value) in values[segment.offset..segment.end()].iter_mut().enumerate() {
                *value = F2_128::from((segment.offset + offset) as u64 * 7 + 1);
            }
        }
        let point = (0..layout.total_bits.trailing_zeros() as usize)
            .map(|bit| F2_128::from(bit as u64 * 7 + 3))
            .collect::<Vec<_>>();
        let full = Mle::new(values.clone()).unwrap().eval(&point).unwrap();
        let claims = split_segment_claims(&layout, &values, &point).unwrap();
        verify_segment_claims(&layout, &claims, &point, full).unwrap();

        let mut tampered = claims;
        tampered[1].value = tampered[1].value + F2_128::from(1u64);
        assert!(verify_segment_claims(&layout, &tampered, &point, full).is_err());
    }
    #[derive(Clone, Debug)]
    struct TestCommitment([u8; 32]);

    #[derive(Clone, Debug)]
    struct TestOpening(Vec<F2_128>);

    #[derive(Clone, Copy, Debug, Default)]
    struct TestPcs;

    fn root(values: &[F2_128]) -> [u8; 32] {
        let mut bytes = Vec::new();
        for value in values {
            bytes.extend_from_slice(&value.value().to_le_bytes());
        }
        magnetar_transcript::sha256(&bytes)
    }

    impl crate::Pcs for TestPcs {
        type Commitment = TestCommitment;
        type Opening = TestOpening;

        fn commit(&self, values: &[F2_128]) -> Result<Self::Commitment, ProofError> {
            Ok(TestCommitment(root(values)))
        }

        fn open(&self, values: &[F2_128], point: &[F2_128]) -> Result<Self::Opening, ProofError> {
            Mle::new(values.to_vec())?.eval(point)?;
            Ok(TestOpening(values.to_vec()))
        }

        fn verify(
            &self,
            commitment: &Self::Commitment,
            point: &[F2_128],
            value: F2_128,
            opening: &Self::Opening,
        ) -> Result<bool, ProofError> {
            Ok(root(&opening.0) == commitment.0
                && Mle::new(opening.0.clone())?.eval(point)? == value)
        }

        fn commitment_bytes(&self, commitment: &Self::Commitment) -> Vec<u8> {
            commitment.0.to_vec()
        }
    }

    #[test]
    fn routes_a_real_spartan_witness_claim() {
        use crate::spartan::prove_simd_spartan;
        use crate::witness_vector;
        use magnetar_constraint::{ConstraintSystem, Expr, SimdR1cs, Witness};

        let mut base = ConstraintSystem::new(3);
        base.add_constraint(
            Expr::var(0).add(Expr::var(1)),
            Expr::constant(1u64),
            Expr::var(2),
        );
        let witnesses = vec![
            Witness::new(vec![
                F2_128::from(1u64),
                F2_128::from(2u64),
                F2_128::from(3u64),
            ]),
            Witness::new(vec![
                F2_128::from(0u64),
                F2_128::from(0u64),
                F2_128::from(0u64),
            ]),
        ];
        let proof = prove_simd_spartan(&base, &witnesses, &TestPcs).unwrap();
        crate::spartan::verify_simd_spartan(&base, witnesses.len(), &proof, &TestPcs).unwrap();
        let simd = SimdR1cs::new(base, witnesses.len()).unwrap();
        let combined = simd.combined_system();
        let combined_witness = simd.combined_witness(&witnesses).unwrap();
        let z = witness_vector(&combined, &combined_witness).unwrap();
        let layout = WitnessLayout::new(vec![
            Segment::new("a", 0, 2, SegmentKind::Direct, SegmentOwner::Cpu),
            Segment::new("b", 2, 2, SegmentKind::Direct, SegmentOwner::Cpu),
            Segment::new("c", 4, 4, SegmentKind::Direct, SegmentOwner::Cpu),
        ])
        .unwrap();
        let point = (0..z.len().trailing_zeros() as usize)
            .map(|bit| F2_128::from(bit as u64 * 11 + 5))
            .collect::<Vec<_>>();
        let full = Mle::new(z.clone()).unwrap().eval(&point).unwrap();
        let claims = split_segment_claims(&layout, &z, &point).unwrap();
        verify_segment_claims(&layout, &claims, &point, full).unwrap();
        verify_segment_claims(&layout, &claims, &point, full + F2_128::from(1u64)).unwrap_err();
    }
}
