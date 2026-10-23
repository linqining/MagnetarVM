//! Dual-relation lockstep: an F2 bit XOR relation over the packed CPU row's
//! rs1/rs2/rd variables, plus the packed CPU ALU system, over one witness.

use magnetar_constraint::{Segment, SegmentKind, SegmentOwner, WitnessLayout};
use magnetar_cpu::simd::uniform_cpu_row_layout;
use magnetar_cpu::{CpuVarKind, StepOp};
use magnetar_pcs::{P3MosaicCommitment, P3MosaicOpening, P3SharedPcs};
use magnetar_proof::dual_field::{BitRelation, BitRow};
use magnetar_proof::{prove_lockstep, verify_lockstep, witness_vector, LockstepProof};

use crate::simd_f2::{GatedCpuRow, GatedCpuRowInput};
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
        StepOp::Sll | StepOp::Srl | StepOp::Sra | StepOp::Slli | StepOp::Srli | StepOp::Srai => {
            let groups = layout.var_groups();
            let rs1 = groups
                .iter()
                .find(|group| group.kind == CpuVarKind::Rs1)
                .expect("rs1 group");
            let alu = &layout.step.alu;
            let shamt = alu.shift_shamt_vars();
            let (stages, products) = if matches!(op, StepOp::Sll | StepOp::Slli) {
                (alu.shift_left_stages(), alu.shift_left_products())
            } else {
                (alu.shift_right_stages(), alu.shift_right_products())
            };
            let mut previous = rs1.vars.clone();
            for stage in 0..stages.len() {
                let shift = 1usize << stage;
                for bit in 0..layout.width {
                    let source = if matches!(op, StepOp::Sll | StepOp::Slli) {
                        if bit >= shift {
                            previous[bit - shift]
                        } else {
                            continue;
                        }
                    } else if bit + shift < layout.width {
                        previous[bit + shift]
                    } else if matches!(op, StepOp::Sra | StepOp::Srai) {
                        rs1.vars[layout.width - 1]
                    } else {
                        continue;
                    };
                    relation.add(BitRow::new(
                        vec![source, previous[bit]],
                        vec![shamt[stage]],
                        vec![products[stage][bit]],
                    ));
                    relation.add(BitRow::new(
                        vec![previous[bit], products[stage][bit]],
                        vec![alu.selectors[op.index()]],
                        vec![stages[stage][bit]],
                    ));
                }
                previous = stages[stage].clone();
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

#[allow(clippy::type_complexity)]
fn dual_batch_matrices(
    layout: &magnetar_cpu::simd::UniformCpuRowLayout,
    op: StepOp,
    cycles: usize,
) -> Result<
    (
        magnetar_constraint::ConstraintSystem,
        magnetar_constraint::ConstraintSystem,
        [magnetar_proof::SharedBlockMatrix; 3],
        [magnetar_proof::SharedBlockMatrix; 3],
    ),
    RuntimeError,
> {
    use magnetar_proof::spartan::MatrixPart;
    use magnetar_proof::SharedBlockMatrix;

    if cycles == 0 || !cycles.is_power_of_two() {
        return Err(RuntimeError::Proof(
            "dual batch cycles must be a power of two".into(),
        ));
    }
    let relation = bit_relation(layout, op);
    let packed = layout.system.clone();
    let mut s1_system = relation.to_system();
    for _ in s1_system.constraints.len()..packed.constraints.len() {
        s1_system.add_constraint(
            magnetar_constraint::Expr::constant(0u64),
            magnetar_constraint::Expr::constant(1u64),
            magnetar_constraint::Expr::constant(0u64),
        );
    }
    let base_cols = (layout.num_vars + 1).next_power_of_two();
    let groups = layout.var_groups();
    let pc = groups
        .iter()
        .find(|group| group.kind == CpuVarKind::Pc)
        .ok_or_else(|| RuntimeError::Proof("dual row has no PC group".into()))?;
    let next_pc = groups
        .iter()
        .find(|group| group.kind == CpuVarKind::NextPc)
        .ok_or_else(|| RuntimeError::Proof("dual row has no NextPc group".into()))?;
    let chain_rows = cycles.saturating_sub(1) * pc.vars.len();
    let mut extra_a = Vec::new();
    let mut extra_b = Vec::new();
    let mut extra_c = Vec::new();
    for instance in 0..cycles.saturating_sub(1) {
        for bit in 0..pc.vars.len() {
            extra_a.push(vec![(
                instance * base_cols + next_pc.vars[bit],
                magnetar_constraint::F2_128::from(1u64),
            )]);
            extra_b.push(vec![(
                instance * base_cols + layout.num_vars,
                magnetar_constraint::F2_128::from(1u64),
            )]);
            extra_c.push(vec![(
                (instance + 1) * base_cols + pc.vars[bit],
                magnetar_constraint::F2_128::from(1u64),
            )]);
        }
    }
    let zero_rows = vec![Vec::new(); chain_rows];
    let a0 = SharedBlockMatrix::from_system(&s1_system, MatrixPart::A, cycles)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(zero_rows.clone());
    let b0 = SharedBlockMatrix::from_system(&s1_system, MatrixPart::B, cycles)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(zero_rows.clone());
    let c0 = SharedBlockMatrix::from_system(&s1_system, MatrixPart::C, cycles)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(zero_rows);
    let a1 = SharedBlockMatrix::from_system(&packed, MatrixPart::A, cycles)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_a);
    let b1 = SharedBlockMatrix::from_system(&packed, MatrixPart::B, cycles)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_b);
    let c1 = SharedBlockMatrix::from_system(&packed, MatrixPart::C, cycles)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_c);
    Ok((s1_system, packed, [a0, b0, c0], [a1, b1, c1]))
}

pub fn prove_dual_batch(
    width: usize,
    op: StepOp,
    cycles: usize,
) -> Result<
    (
        LockstepProof<P3MosaicCommitment, P3MosaicOpening>,
        WitnessLayout,
    ),
    RuntimeError,
> {
    use magnetar_proof::prove_lockstep_with_matrices;

    let (_system, layout) = uniform_cpu_row_layout(width);
    let (_s1, packed, s1, s2) = dual_batch_matrices(&layout, op, cycles)?;
    let mut z = Vec::new();
    for cycle in 0..cycles {
        let row = layout.witness(
            op,
            0x1000 + 4 * cycle as u64,
            0x12 + cycle as u64,
            0x34 + cycle as u64,
            0,
        );
        z.extend(
            witness_vector(&packed, &row.witness)
                .map_err(|error| RuntimeError::Proof(error.to_string()))?,
        );
    }
    let layout_segments = segment_layout(z.len())?;
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    let proof = prove_lockstep_with_matrices(
        &z,
        &s1[0],
        &s1[1],
        &s1[2],
        &s2[0],
        &s2[1],
        &s2[2],
        &layout_segments,
        &pcs,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((proof, layout_segments))
}

pub fn verify_dual_batch(
    width: usize,
    op: StepOp,
    cycles: usize,
    proof: &LockstepProof<P3MosaicCommitment, P3MosaicOpening>,
    layout: &WitnessLayout,
) -> Result<(), RuntimeError> {
    use magnetar_proof::verify_lockstep_with_matrices;

    let (_system, row_layout) = uniform_cpu_row_layout(width);
    let (_s1, _packed, s1, s2) = dual_batch_matrices(&row_layout, op, cycles)?;
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    verify_lockstep_with_matrices(
        &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], layout, proof, &pcs,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))
}

/// Gated dual batch: the selector-gated CPU row as s1 (bit relation) and its
/// packed F2^128 system as s2, with PC-chain extra rows on the packed side.
pub fn prove_gated_dual_batch(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
) -> Result<
    (
        LockstepProof<P3MosaicCommitment, P3MosaicOpening>,
        WitnessLayout,
    ),
    RuntimeError,
> {
    use magnetar_proof::spartan::MatrixPart;
    use magnetar_proof::{prove_lockstep_with_matrices, SharedBlockMatrix};

    if rows.is_empty() || !rows.len().is_power_of_two() {
        return Err(RuntimeError::Proof(
            "gated dual batch must be a nonzero power of two".into(),
        ));
    }
    let row = GatedCpuRow::new(width);
    let s1_system = row.relation.to_system();
    let mut s2_system = row.packed_companion_system();
    for _ in s2_system.constraints.len()..s1_system.constraints.len() {
        s2_system.add_constraint(
            magnetar_constraint::Expr::constant(0u64),
            magnetar_constraint::Expr::constant(1u64),
            magnetar_constraint::Expr::constant(0u64),
        );
    }
    let base_cols = (row.relation.num_vars + 1).next_power_of_two();
    let mut extra_a = Vec::new();
    let mut extra_b = Vec::new();
    let mut extra_c = Vec::new();
    for instance in 0..rows.len().saturating_sub(1) {
        for bit in 0..width {
            extra_a.push(vec![(
                instance * base_cols + row.next_pc[bit],
                magnetar_constraint::F2_128::from(1u64),
            )]);
            extra_b.push(vec![(
                instance * base_cols + row.alu.one,
                magnetar_constraint::F2_128::from(1u64),
            )]);
            extra_c.push(vec![(
                (instance + 1) * base_cols + row.pc[bit],
                magnetar_constraint::F2_128::from(1u64),
            )]);
        }
    }
    let zero_rows = vec![Vec::new(); rows.len().saturating_sub(1) * width];
    let a0 = SharedBlockMatrix::from_system(&s1_system, MatrixPart::A, rows.len())
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(zero_rows.clone());
    let b0 = SharedBlockMatrix::from_system(&s1_system, MatrixPart::B, rows.len())
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(zero_rows.clone());
    let c0 = SharedBlockMatrix::from_system(&s1_system, MatrixPart::C, rows.len())
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(zero_rows);
    let a1 = SharedBlockMatrix::from_system(&s2_system, MatrixPart::A, rows.len())
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_a);
    let b1 = SharedBlockMatrix::from_system(&s2_system, MatrixPart::B, rows.len())
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_b);
    let c1 = SharedBlockMatrix::from_system(&s2_system, MatrixPart::C, rows.len())
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_c);
    let mut z = Vec::new();
    for (pc, input) in rows {
        let bits = match input {
            GatedCpuRowInput::Alu { left, right, op } => {
                row.alu_witness_at(*pc, *left, *right, *op)
            }
            GatedCpuRowInput::Memory {
                rs1,
                imm,
                value,
                is_mem,
            } => row.memory_witness_at(*pc, *rs1, *imm, *value, *is_mem),
        };
        z.extend(
            witness_vector(&s2_system, &row.relation.to_witness(&bits))
                .map_err(|error| RuntimeError::Proof(error.to_string()))?,
        );
    }
    let layout_segments = segment_layout(z.len())?;
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    let proof =
        prove_lockstep_with_matrices(&z, &a0, &b0, &c0, &a1, &b1, &c1, &layout_segments, &pcs)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((proof, layout_segments))
}

pub fn verify_gated_dual_batch(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
    proof: &LockstepProof<P3MosaicCommitment, P3MosaicOpening>,
    layout: &WitnessLayout,
) -> Result<(), RuntimeError> {
    use magnetar_proof::spartan::MatrixPart;
    use magnetar_proof::{verify_lockstep_with_matrices, SharedBlockMatrix};

    let row = GatedCpuRow::new(width);
    let s1_system = row.relation.to_system();
    let mut s2_system = row.packed_companion_system();
    for _ in s2_system.constraints.len()..s1_system.constraints.len() {
        s2_system.add_constraint(
            magnetar_constraint::Expr::constant(0u64),
            magnetar_constraint::Expr::constant(1u64),
            magnetar_constraint::Expr::constant(0u64),
        );
    }
    let base_cols = (row.relation.num_vars + 1).next_power_of_two();
    let mut extra_a = Vec::new();
    let mut extra_b = Vec::new();
    let mut extra_c = Vec::new();
    for instance in 0..rows.len().saturating_sub(1) {
        for bit in 0..width {
            extra_a.push(vec![(
                instance * base_cols + row.next_pc[bit],
                magnetar_constraint::F2_128::from(1u64),
            )]);
            extra_b.push(vec![(
                instance * base_cols + row.alu.one,
                magnetar_constraint::F2_128::from(1u64),
            )]);
            extra_c.push(vec![(
                (instance + 1) * base_cols + row.pc[bit],
                magnetar_constraint::F2_128::from(1u64),
            )]);
        }
    }
    let zero_rows = vec![Vec::new(); rows.len().saturating_sub(1) * width];
    let a0 = SharedBlockMatrix::from_system(&s1_system, MatrixPart::A, rows.len())
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(zero_rows.clone());
    let b0 = SharedBlockMatrix::from_system(&s1_system, MatrixPart::B, rows.len())
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(zero_rows.clone());
    let c0 = SharedBlockMatrix::from_system(&s1_system, MatrixPart::C, rows.len())
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(zero_rows);
    let a1 = SharedBlockMatrix::from_system(&s2_system, MatrixPart::A, rows.len())
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_a);
    let b1 = SharedBlockMatrix::from_system(&s2_system, MatrixPart::B, rows.len())
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_b);
    let c1 = SharedBlockMatrix::from_system(&s2_system, MatrixPart::C, rows.len())
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_c);
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    verify_lockstep_with_matrices(&a0, &b0, &c0, &a1, &b1, &c1, layout, proof, &pcs)
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
    fn gated_dual_backends_share_the_same_test() {
        use magnetar_proof::spartan::MatrixPart;
        use magnetar_proof::{
            prove_lockstep_bits, verify_lockstep_bits, BitPcs, DirectBitPcs, PackedBitPcs,
            SparseMatrix,
        };

        let row = GatedCpuRow::new(3);
        let bits = row.alu_witness_at(0, 5, 3, crate::simd_f2::GatedAluOp::Add);
        let base_cols = (row.relation.num_vars + 1).next_power_of_two();
        let mut packed_bits = vec![false; base_cols];
        packed_bits[..bits.len()].copy_from_slice(&bits);
        let s1 = row.relation.to_system();
        let mut s2 = row.packed_companion_system();
        for _ in s2.constraints.len()..s1.constraints.len() {
            s2.add_constraint(
                magnetar_constraint::Expr::constant(0u64),
                magnetar_constraint::Expr::constant(1u64),
                magnetar_constraint::Expr::constant(0u64),
            );
        }
        let a0 = SparseMatrix::from_system(&s1, MatrixPart::A).unwrap();
        let b0 = SparseMatrix::from_system(&s1, MatrixPart::B).unwrap();
        let c0 = SparseMatrix::from_system(&s1, MatrixPart::C).unwrap();
        let a1 = SparseMatrix::from_system(&s2, MatrixPart::A).unwrap();
        let b1 = SparseMatrix::from_system(&s2, MatrixPart::B).unwrap();
        let c1 = SparseMatrix::from_system(&s2, MatrixPart::C).unwrap();
        let layout = segment_layout(base_cols).unwrap();
        let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
        let direct = DirectBitPcs::new(pcs.clone());
        let proof =
            prove_lockstep_bits(&packed_bits, &a0, &b0, &c0, &a1, &b1, &c1, &layout, &direct)
                .unwrap();
        verify_lockstep_bits(&a0, &b0, &c0, &a1, &b1, &c1, &layout, &proof, &direct).unwrap();

        let packed = PackedBitPcs::new(pcs);
        let p3_commitment = packed.commit(&packed_bits).unwrap();
        let p3_point = (0..8)
            .map(|bit| magnetar_constraint::F2_128::from((bit % 2) as u64))
            .collect::<Vec<_>>();
        let (p3_value, p3_opening) = packed.open(&packed_bits, &p3_point).unwrap();
        assert!(packed
            .verify(&p3_commitment, &p3_point, p3_value, &p3_opening)
            .unwrap());
        let commitment = packed.commit(&packed_bits).unwrap();
        let point = (0..6)
            .map(|bit| magnetar_constraint::F2_128::from((bit % 2) as u64))
            .collect::<Vec<_>>();
        let (value, opening) = packed.open(&packed_bits, &point).unwrap();
        assert!(packed.verify(&commitment, &point, value, &opening).unwrap());
        let proof =
            prove_lockstep_bits(&packed_bits, &a0, &b0, &c0, &a1, &b1, &c1, &layout, &packed)
                .unwrap();
        verify_lockstep_bits(&a0, &b0, &c0, &a1, &b1, &c1, &layout, &proof, &packed).unwrap();
    }

    #[test]
    fn gated_dual_batch_runs_in_lockstep() {
        let rows = [
            (
                0x1000,
                GatedCpuRowInput::Alu {
                    left: 5,
                    right: 3,
                    op: crate::simd_f2::GatedAluOp::Add,
                },
            ),
            (
                0x1004,
                GatedCpuRowInput::Memory {
                    rs1: 0x10,
                    imm: 2,
                    value: 0x34,
                    is_mem: true,
                },
            ),
        ];
        let (proof, layout) = prove_gated_dual_batch(8, &rows).expect("prove");
        verify_gated_dual_batch(8, &rows, &proof, &layout).expect("verify");
    }

    #[test]
    fn gated_dual_batch_scales_to_eight_cycles() {
        let rows = (0..8usize)
            .map(|index| {
                (
                    0x1000 + 4 * index as u64,
                    GatedCpuRowInput::Alu {
                        left: 0x12 + index as u64,
                        right: 0x34 + index as u64,
                        op: crate::simd_f2::GatedAluOp::Add,
                    },
                )
            })
            .collect::<Vec<_>>();
        let (proof, layout) = prove_gated_dual_batch(8, &rows).expect("prove");
        verify_gated_dual_batch(8, &rows, &proof, &layout).expect("verify");
    }

    #[test]
    fn dual_shared_batch_runs_in_lockstep() {
        for op in [
            StepOp::Xor,
            StepOp::Add,
            StepOp::Sub,
            StepOp::Sll,
            StepOp::Srl,
            StepOp::Sra,
        ] {
            let (proof, layout) = prove_dual_batch(8, op, 2).expect("prove");
            verify_dual_batch(8, op, 2, &proof, &layout).expect("verify");
        }
    }

    #[test]
    fn f2_sub_parity_and_packed_cpu_run_in_lockstep() {
        let (proof, layout) =
            prove_dual_cpu(8, StepOp::Sub, 0b1010_1010, 0b0000_1100).expect("prove");
        verify_dual_cpu(8, StepOp::Sub, &proof, &layout).expect("verify");
    }
}
