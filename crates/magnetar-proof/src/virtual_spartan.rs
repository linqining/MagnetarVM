//! Virtual Spartan per-segment claim consistency.
//!
//! The full witness claim `W(r) = v` is split into one claim per aligned
//! segment. For a segment at offset `s` with `b = s >> size_bits`, the local
//! point is the low part of `r`, and the full claim is reconstructed as
//! `Σ_i eq(r_high, b_i) · W_i(r_low)`.

use magnetar_constraint::{Segment, WitnessLayout, F2_128};
use thiserror::Error;

use crate::{eq, Mle, ProofError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentClaim {
    pub name: String,
    pub point: Vec<F2_128>,
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

pub fn split_segment_claims(
    layout: &WitnessLayout,
    values: &[F2_128],
    point: &[F2_128],
) -> Result<Vec<SegmentClaim>, VirtualSpartanError> {
    let expected = 1usize << layout.total_bits;
    if values.len() != expected {
        return Err(VirtualSpartanError::WitnessLength {
            expected,
            actual: values.len(),
        });
    }
    if point.len() != layout.total_bits {
        return Err(VirtualSpartanError::PointLength {
            expected: layout.total_bits,
            actual: point.len(),
        });
    }
    let mut claims = Vec::with_capacity(layout.segments.len());
    for segment in &layout.segments {
        let local = local_point(point, segment);
        let segment_values = values[segment.offset..segment.end()].to_vec();
        let value = Mle::new(segment_values)?.eval(&local)?;
        claims.push(SegmentClaim {
            name: segment.name.clone(),
            point: local,
            value,
        });
    }
    Ok(claims)
}

pub fn verify_segment_claims(
    layout: &WitnessLayout,
    claims: &[SegmentClaim],
    point: &[F2_128],
    full_value: F2_128,
) -> Result<(), VirtualSpartanError> {
    if claims.len() != layout.segments.len() {
        return Err(VirtualSpartanError::ClaimShape);
    }
    if point.len() != layout.total_bits {
        return Err(VirtualSpartanError::PointLength {
            expected: layout.total_bits,
            actual: point.len(),
        });
    }
    let mut reconstructed = F2_128::from(0u64);
    for (segment, claim) in layout.segments.iter().zip(claims) {
        if claim.name != segment.name || claim.point != local_point(point, segment) {
            return Err(VirtualSpartanError::ClaimShape);
        }
        let suffix = suffix_bits(segment, layout.total_bits);
        reconstructed = reconstructed + eq(&suffix, &point[claim.point.len()..]) * claim.value;
    }
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
    fn segment_claims_reconstruct_full_witness() {
        let layout = layout();
        let mut values = vec![F2_128::from(0u64); 1 << layout.total_bits];
        for segment in &layout.segments {
            for (offset, value) in values[segment.offset..segment.end()].iter_mut().enumerate() {
                *value = F2_128::from((segment.offset + offset) as u64 * 7 + 1);
            }
        }
        let point = (0..layout.total_bits)
            .map(|bit| F2_128::from(bit as u64 * 7 + 3))
            .collect::<Vec<_>>();
        let full = Mle::new(values.clone()).unwrap().eval(&point).unwrap();
        let claims = split_segment_claims(&layout, &values, &point).unwrap();
        verify_segment_claims(&layout, &claims, &point, full).unwrap();

        let mut tampered = claims;
        tampered[1].value = tampered[1].value + F2_128::from(1u64);
        assert!(verify_segment_claims(&layout, &tampered, &point, full).is_err());
    }
}
