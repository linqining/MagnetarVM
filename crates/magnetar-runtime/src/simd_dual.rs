//! Dual-relation lockstep: an F2 bit XOR relation over the packed CPU row's
//! rs1/rs2/rd variables, plus the packed CPU ALU system, over one witness.

use magnetar_constraint::{Segment, SegmentKind, SegmentOwner, WitnessLayout};
use magnetar_cpu::simd::uniform_cpu_row_layout;
use magnetar_cpu::{CpuVarKind, StepOp};
use magnetar_pcs::{P3MosaicCommitment, P3MosaicOpening, P3SharedPcs};
use magnetar_proof::dual_field::{BitRelation, BitRow};
use magnetar_proof::{prove_lockstep, verify_lockstep, witness_vector, LockstepProof};

use crate::RuntimeError;

fn bit_relation(layout: &magnetar_cpu::simd::UniformCpuRowLayout, op: StepOp) -> BitRelation {
    let mut relation = BitRelation::new(layout.num_vars);
    match op {
        StepOp::Xor => {
            let groups = layout.var_groups();
            let rs1 = groups
                .iter()
                .find(|group| group.kind == CpuVarKind::Rs1)
                .expect("rs1 group");
            let rs2 = groups
                .iter()
                .find(|group| group.kind == CpuVarKind::Rs2)
                .expect("rs2 group");
            let rd = groups
                .iter()
                .find(|group| group.kind == CpuVarKind::Rd)
                .expect("rd group");
            let one = layout.step.alu.selectors[StepOp::Xor.index()];
            for bit in 0..layout.width {
                relation.add(BitRow::new(
                    vec![rs1.vars[bit], rs2.vars[bit]],
                    vec![one],
                    vec![rd.vars[bit]],
                ));
            }
        }
        StepOp::Sub => {
            let adder = &layout.step.alu.sub_adder;
            let one = layout.step.alu.selectors[StepOp::Sub.index()];
            for bit in 0..layout.width {
                relation.add(BitRow::new(
                    vec![adder.a[bit], adder.b[bit], adder.carry[bit]],
                    vec![one],
                    vec![adder.sum[bit]],
                ));
            }
        }
        StepOp::Add => {
            let adder = &layout.step.alu.adder;
            let one = layout.step.alu.selectors[StepOp::Add.index()];
            for bit in 0..layout.width {
                relation.add(BitRow::new(
                    vec![adder.a[bit], adder.b[bit], adder.carry[bit]],
                    vec![one],
                    vec![adder.sum[bit]],
                ));
            }
        }
        _ => panic!("unsupported dual CPU op"),
    }
    relation
}

fn segment_layout(z_len: usize) -> Result<WitnessLayout, RuntimeError> {
    let total_bits = z_len.trailing_zeros() as usize;
    if total_bits == 0 {
        return Err(RuntimeError::Proof("dual CPU witness is too small".into()));
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

pub fn prove_dual_cpu(
    width: usize,
    op: StepOp,
    left: u64,
    right: u64,
) -> Result<
    (
        LockstepProof<P3MosaicCommitment, P3MosaicOpening>,
        WitnessLayout,
    ),
    RuntimeError,
> {
    let (_system, layout) = uniform_cpu_row_layout(width);
    let row = layout.witness(op, 0, left, right, 0);
    let relation = bit_relation(&layout, op);
    let packed = layout.system.clone();
    let mut s1 = relation.to_system();
    for _ in s1.constraints.len()..packed.constraints.len() {
        s1.add_constraint(
            magnetar_constraint::Expr::constant(0u64),
            magnetar_constraint::Expr::constant(1u64),
            magnetar_constraint::Expr::constant(0u64),
        );
    }
    let z = witness_vector(&packed, &row.witness)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let layout_segments = segment_layout(z.len())?;
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    let proof = prove_lockstep(&s1, &packed, &row.witness, &layout_segments, &pcs)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((proof, layout_segments))
}

pub fn verify_dual_cpu(
    width: usize,
    op: StepOp,
    proof: &LockstepProof<P3MosaicCommitment, P3MosaicOpening>,
    layout: &WitnessLayout,
) -> Result<(), RuntimeError> {
    let (_system, row_layout) = uniform_cpu_row_layout(width);
    let relation = bit_relation(&row_layout, op);
    let mut s1 = relation.to_system();
    for _ in s1.constraints.len()..row_layout.system.constraints.len() {
        s1.add_constraint(
            magnetar_constraint::Expr::constant(0u64),
            magnetar_constraint::Expr::constant(1u64),
            magnetar_constraint::Expr::constant(0u64),
        );
    }
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    verify_lockstep(&s1, &row_layout.system, layout, proof, &pcs)
        .map_err(|error| RuntimeError::Proof(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f2_xor_and_packed_cpu_run_in_lockstep() {
        let (proof, layout) =
            prove_dual_cpu(8, StepOp::Xor, 0b1010_1010, 0b1100_1100).expect("prove");
        verify_dual_cpu(8, StepOp::Xor, &proof, &layout).expect("verify");
    }

    #[test]
    fn f2_add_parity_and_packed_cpu_run_in_lockstep() {
        let (proof, layout) =
            prove_dual_cpu(8, StepOp::Add, 0b1010_1010, 0b1100_1100).expect("prove");
        verify_dual_cpu(8, StepOp::Add, &proof, &layout).expect("verify");
    }

    #[test]
    fn f2_sub_parity_and_packed_cpu_run_in_lockstep() {
        let (proof, layout) =
            prove_dual_cpu(8, StepOp::Sub, 0b1010_1010, 0b0000_1100).expect("prove");
        verify_dual_cpu(8, StepOp::Sub, &proof, &layout).expect("verify");
    }
}
