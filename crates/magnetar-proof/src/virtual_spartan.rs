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
