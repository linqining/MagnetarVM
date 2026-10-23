//! Paper-style packed select relation.
//!
//! One bit-valued witness is shared by two relations:
//! - s1 over F2: `c * x_i = y_i` for every bit;
//! - s2 over F2^128: `c * (Σ β_i x_i) = Σ β_i y_i`, one packed constraint.
//!
//! `β_i` is the monomial basis of F2^128. This is the word-wide selection
//! example from Magnetar §5.1 with the same witness on both sides.

use magnetar_constraint::{
    ConstraintSystem, Expr, Segment, SegmentKind, SegmentOwner, Witness, WitnessLayout, F2_128,
};
use magnetar_pcs::{P3MosaicCommitment, P3MosaicOpening, P3SharedPcs};
use magnetar_proof::dual_field::{BitRelation, BitRow};
use magnetar_proof::{prove_lockstep, verify_lockstep, witness_vector, LockstepProof};

use crate::RuntimeError;

#[derive(Clone, Debug)]
pub struct PackedSelectLayout {
    pub width: usize,
    pub condition: usize,
    pub x: Vec<usize>,
    pub y: Vec<usize>,
    pub bit_relation: BitRelation,
    pub packed_system: ConstraintSystem,
}

fn packed_linear(values: &[usize]) -> Expr {
    values
        .iter()
        .enumerate()
        .fold(Expr::constant(0u64), |expr, (bit, var)| {
            expr.add(Expr::var(*var).scale(F2_128::from(1u128 << bit)))
        })
}

impl PackedSelectLayout {
    pub fn new(width: usize) -> Self {
        assert!((1..=128).contains(&width));
        let condition = 0;
        let x = (1..1 + width).collect::<Vec<_>>();
        let y = (1 + width..1 + 2 * width).collect::<Vec<_>>();
        let num_vars = 1 + 2 * width;

        let mut bit_relation = BitRelation::new(num_vars);
        for bit in 0..width {
            bit_relation.add(BitRow::new(vec![condition], vec![x[bit]], vec![y[bit]]));
        }

        let mut packed_system = ConstraintSystem::new(num_vars);
        packed_system.add_constraint(
            Expr::var(condition),
            Expr::var(condition),
            Expr::var(condition),
        );
        packed_system.add_constraint(Expr::var(condition), packed_linear(&x), packed_linear(&y));
        Self {
            width,
            condition,
            x,
            y,
            bit_relation,
            packed_system,
        }
    }

    /// The packed relation inside a lockstep proof, padded with zero rows so
    /// both matrices have the bit relation's row count.
    pub fn lockstep_packed_system(&self) -> ConstraintSystem {
        let mut system = self.packed_system.clone();
        for _ in system.constraints.len()..self.bit_relation.rows.len() {
            system.add_constraint(
                Expr::constant(0u64),
                Expr::constant(1u64),
                Expr::constant(0u64),
            );
        }
        system
    }

    pub fn witness(&self, condition: bool, value: u64) -> Witness {
        let mut bits = vec![false; self.bit_relation.num_vars];
        bits[self.condition] = condition;
        for bit in 0..self.width {
            let input = (value >> bit) & 1 == 1;
            bits[self.x[bit]] = input;
            bits[self.y[bit]] = condition && input;
        }
        self.bit_relation.to_witness(&bits)
    }

    pub fn witness_bits(&self, condition: bool, value: u64) -> Vec<bool> {
        let witness = self.witness(condition, value);
        witness
            .values()
            .iter()
            .map(|value| value.value() == 1)
            .collect()
    }
}

fn segment_layout(z_len: usize) -> Result<WitnessLayout, RuntimeError> {
    let total_bits = z_len.trailing_zeros() as usize;
    if total_bits == 0 {
        return Err(RuntimeError::Proof(
            "packed select witness is too small".into(),
        ));
    }
    let half = total_bits - 1;
    WitnessLayout::new(vec![
        Segment::new("lo", 0, 1 << half, SegmentKind::Direct, SegmentOwner::Cpu),
        Segment::new(
            "hi",
            1 << half,
            1 << half,
            SegmentKind::Direct,
            SegmentOwner::Cpu,
        ),
    ])
    .map_err(|error| RuntimeError::Proof(error.to_string()))
}

pub fn prove_packed_select(
    width: usize,
    condition: bool,
    value: u64,
) -> Result<
    (
        LockstepProof<P3MosaicCommitment, P3MosaicOpening>,
        WitnessLayout,
    ),
    RuntimeError,
> {
    let layout = PackedSelectLayout::new(width);
    let witness = layout.witness(condition, value);
    let s1 = layout.bit_relation.to_system();
    let z = witness_vector(&layout.lockstep_packed_system(), &witness)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let segments = segment_layout(z.len())?;
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    let proof = prove_lockstep(
        &s1,
        &layout.lockstep_packed_system(),
        &witness,
        &segments,
        &pcs,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((proof, segments))
}

pub fn verify_packed_select(
    width: usize,
    proof: &LockstepProof<P3MosaicCommitment, P3MosaicOpening>,
    segments: &WitnessLayout,
) -> Result<(), RuntimeError> {
    let layout = PackedSelectLayout::new(width);
    let s1 = layout.bit_relation.to_system();
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    verify_lockstep(&s1, &layout.lockstep_packed_system(), segments, proof, &pcs)
        .map_err(|error| RuntimeError::Proof(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_select_shares_one_witness_for_64_bits() {
        let layout = PackedSelectLayout::new(64);
        assert_eq!(layout.packed_system.constraints.len(), 2);
        let selected = layout.witness(true, 0xAAAA_AAAA_AAAA_AAAA);
        assert!(layout.packed_system.check(&selected).is_ok());
        let cleared = layout.witness(false, 0xAAAA_AAAA_AAAA_AAAA);
        assert!(layout.packed_system.check(&cleared).is_ok());
        let (proof, segments) = prove_packed_select(64, true, 0xAAAA_AAAA_AAAA_AAAA).unwrap();
        verify_packed_select(64, &proof, &segments).unwrap();
    }
}
