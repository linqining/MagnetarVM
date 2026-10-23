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
use magnetar_constraint::F2_128;

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
            GatedCpuRowInput::Shift { left, shamt, kind } => {
                row.shift_witness_at(*pc, *left, *shamt, *kind)
            }
            GatedCpuRowInput::Branch {
                left,
                right,
                imm,
                beq,
            } => row.branch_witness_at(*pc, *left, *right, *imm, *beq),
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

#[allow(clippy::type_complexity)]
fn gated_shared_matrices(
    row: &GatedCpuRow,
    cycles: usize,
    statement: Option<(u64, u64)>,
) -> Result<
    (
        usize,
        [magnetar_proof::SharedBlockMatrix; 3],
        [magnetar_proof::SharedBlockMatrix; 3],
    ),
    RuntimeError,
> {
    use magnetar_proof::spartan::MatrixPart;
    use magnetar_proof::SharedBlockMatrix;

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
    for instance in 0..cycles.saturating_sub(1) {
        for bit in 0..row.width {
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
    let mut statement_rows = 0usize;
    if let Some((initial_pc, final_pc)) = statement {
        statement_rows = 2 * row.width;
        for (instance, pc) in [(0usize, initial_pc), (cycles - 1, final_pc)] {
            for bit in 0..row.width {
                let value = (pc >> bit) & 1;
                let var = if instance == 0 {
                    row.pc[bit]
                } else {
                    row.next_pc[bit]
                };
                extra_a.push(vec![(
                    instance * base_cols + var,
                    magnetar_constraint::F2_128::from(1u64),
                )]);
                extra_b.push(vec![(
                    instance * base_cols + row.alu.one,
                    magnetar_constraint::F2_128::from(1u64),
                )]);
                if value == 1 {
                    extra_c.push(vec![(
                        instance * base_cols + row.alu.one,
                        magnetar_constraint::F2_128::from(1u64),
                    )]);
                } else {
                    extra_c.push(Vec::new());
                }
            }
        }
    }
    let zero_rows = vec![Vec::new(); cycles.saturating_sub(1) * row.width + statement_rows];
    let a0 = SharedBlockMatrix::from_system(&s1_system, MatrixPart::A, cycles)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(zero_rows.clone());
    let b0 = SharedBlockMatrix::from_system(&s1_system, MatrixPart::B, cycles)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(zero_rows.clone());
    let c0 = SharedBlockMatrix::from_system(&s1_system, MatrixPart::C, cycles)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(zero_rows);
    let a1 = SharedBlockMatrix::from_system(&s2_system, MatrixPart::A, cycles)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_a);
    let b1 = SharedBlockMatrix::from_system(&s2_system, MatrixPart::B, cycles)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_b);
    let c1 = SharedBlockMatrix::from_system(&s2_system, MatrixPart::C, cycles)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_c);
    Ok((base_cols, [a0, b0, c0], [a1, b1, c1]))
}

#[allow(dead_code)]
#[allow(clippy::type_complexity)]
pub(crate) fn gated_claim_inputs(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
) -> Result<
    (
        Vec<F2_128>,
        [magnetar_proof::SharedBlockMatrix; 3],
        [magnetar_proof::SharedBlockMatrix; 3],
        magnetar_constraint::WitnessLayout,
    ),
    RuntimeError,
> {
    let row = GatedCpuRow::new(width);
    let (base_cols, systems0, systems1) = gated_shared_matrices(&row, rows.len(), None)?;
    let bits = gated_batch_bits(&row, base_cols, rows);
    let layout = segment_layout(bits.len())?;
    let z = bits
        .iter()
        .map(|bit| F2_128::from(u64::from(*bit)))
        .collect::<Vec<_>>();
    Ok((z, systems0, systems1, layout))
}

fn gated_batch_bits(
    row: &GatedCpuRow,
    base_cols: usize,
    rows: &[(u64, GatedCpuRowInput)],
) -> Vec<bool> {
    let mut bits = Vec::with_capacity(rows.len() * base_cols);
    for (pc, input) in rows {
        let instance = match input {
            GatedCpuRowInput::Alu { left, right, op } => {
                row.alu_witness_at(*pc, *left, *right, *op)
            }
            GatedCpuRowInput::Memory {
                rs1,
                imm,
                value,
                is_mem,
            } => row.memory_witness_at(*pc, *rs1, *imm, *value, *is_mem),
            GatedCpuRowInput::Shift { left, shamt, kind } => {
                row.shift_witness_at(*pc, *left, *shamt, *kind)
            }
            GatedCpuRowInput::Branch {
                left,
                right,
                imm,
                beq,
            } => row.branch_witness_at(*pc, *left, *right, *imm, *beq),
        };
        bits.extend(instance);
        bits.resize(bits.len() + base_cols - row.relation.num_vars, false);
    }
    bits
}

#[allow(clippy::type_complexity)]
pub fn prove_gated_dual_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
    backend: &B,
) -> Result<(LockstepProof<B::Commitment, B::Opening>, WitnessLayout), RuntimeError> {
    use magnetar_proof::prove_lockstep_bits;

    if rows.is_empty() || !rows.len().is_power_of_two() {
        return Err(RuntimeError::Proof(
            "gated dual batch must be a nonzero power of two".into(),
        ));
    }
    let row = GatedCpuRow::new(width);
    let (base_cols, s1, s2) = gated_shared_matrices(&row, rows.len(), None)?;
    let bits = gated_batch_bits(&row, base_cols, rows);
    let layout = segment_layout(bits.len())?;
    let proof = prove_lockstep_bits(
        &bits, &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], &layout, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((proof, layout))
}

pub fn verify_gated_dual_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
    proof: &LockstepProof<B::Commitment, B::Opening>,
    layout: &WitnessLayout,
    backend: &B,
) -> Result<(), RuntimeError> {
    use magnetar_proof::verify_lockstep_bits;

    let row = GatedCpuRow::new(width);
    let (_base_cols, s1, s2) = gated_shared_matrices(&row, rows.len(), None)?;
    verify_lockstep_bits(
        &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], layout, proof, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))
}

#[allow(clippy::type_complexity)]
pub fn prove_gated_dual_batch_bits_with_pc<B: magnetar_proof::BitPcs>(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
    backend: &B,
    initial_pc: u64,
    final_pc: u64,
) -> Result<(LockstepProof<B::Commitment, B::Opening>, WitnessLayout), RuntimeError> {
    use magnetar_proof::prove_lockstep_bits;

    if rows.is_empty() || !rows.len().is_power_of_two() {
        return Err(RuntimeError::Proof(
            "gated dual batch must be a nonzero power of two".into(),
        ));
    }
    let row = GatedCpuRow::new(width);
    let (base_cols, s1, s2) =
        gated_shared_matrices(&row, rows.len(), Some((initial_pc, final_pc)))?;
    let bits = gated_batch_bits(&row, base_cols, rows);
    let layout = segment_layout(bits.len())?;
    let proof = prove_lockstep_bits(
        &bits, &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], &layout, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((proof, layout))
}

pub fn verify_gated_dual_batch_bits_with_pc<B: magnetar_proof::BitPcs>(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
    proof: &LockstepProof<B::Commitment, B::Opening>,
    layout: &WitnessLayout,
    backend: &B,
    initial_pc: u64,
    final_pc: u64,
) -> Result<(), RuntimeError> {
    use magnetar_proof::verify_lockstep_bits;

    let row = GatedCpuRow::new(width);
    let (_base_cols, s1, s2) =
        gated_shared_matrices(&row, rows.len(), Some((initial_pc, final_pc)))?;
    verify_lockstep_bits(
        &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], layout, proof, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))
}

#[cfg(test)]
mod shared_claim_tests {
    use super::*;
    use magnetar_pcs::{P3BinaryPcs, P3MosaicTable, P3SharedPcs};
    use magnetar_proof::spartan::{
        prove_lockstep_claims_bits, verify_lockstep_claims_with_matrices,
    };
    use magnetar_proof::DirectBitPcs;

    #[test]
    fn gated_claims_use_shared_commitment() {
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
                GatedCpuRowInput::Alu {
                    left: 7,
                    right: 2,
                    op: crate::simd_f2::GatedAluOp::Xor,
                },
            ),
        ];
        let (z, a0, a1, layout) = gated_claim_inputs(8, &rows).unwrap();
        let commitment = P3BinaryPcs::new(100)
            .commit_mosaic(&[P3MosaicTable {
                columns: vec![z.clone()],
            }])
            .unwrap();
        let backend = DirectBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let (claims, _ry) = prove_lockstep_claims_bits(
            &z,
            &a0[0],
            &a0[1],
            &a0[2],
            &a1[0],
            &a1[1],
            &a1[2],
            &layout,
            &backend,
            commitment.clone(),
        )
        .unwrap();
        assert_eq!(claims.commitment, commitment);
        assert!(!claims.segments.is_empty());
        let verifier = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
        let (_ry, segments, value) = verify_lockstep_claims_with_matrices(
            &a0[0], &a0[1], &a0[2], &a1[0], &a1[1], &a1[2], &layout, &claims, &verifier,
        )
        .unwrap();
        assert!(!segments.is_empty());
        let _ = value;
    }
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
            prove_lockstep_bits, verify_lockstep_bits, BitPcs, DirectBitPcs, RevealingPackedBitPcs,
            SparseMatrix,
        };

        let row = GatedCpuRow::new(4);
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

        let packed = RevealingPackedBitPcs::new(pcs);
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
    fn gated_dual_combines_ring_switch_and_mosaic() {
        use magnetar_pcs::mosaic::PackedSharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;

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
        let pcs = PackedSharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()).unwrap();
        let backend = RingSwitchPackedBitPcs::new(pcs);
        let (proof, layout) = prove_gated_dual_batch_bits(8, &rows, &backend).unwrap();
        verify_gated_dual_batch_bits(8, &rows, &proof, &layout, &backend).unwrap();
    }

    #[test]
    fn gated_dual_uses_mosaic_pcs_adapter() {
        use magnetar_pcs::mosaic::PackedSharedPcs;
        use magnetar_proof::DirectBitPcs;

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
        let pcs = PackedSharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()).unwrap();
        let backend = DirectBitPcs::new(pcs);
        let (proof, layout) = prove_gated_dual_batch_bits(8, &rows, &backend).unwrap();
        verify_gated_dual_batch_bits(8, &rows, &proof, &layout, &backend).unwrap();
    }

    #[test]
    fn gated_dual_binds_public_pc_statement() {
        use magnetar_proof::DirectBitPcs;

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
                GatedCpuRowInput::Alu {
                    left: 7,
                    right: 2,
                    op: crate::simd_f2::GatedAluOp::Xor,
                },
            ),
        ];
        let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
        let direct = DirectBitPcs::new(pcs);
        let (proof, layout) =
            prove_gated_dual_batch_bits_with_pc(8, &rows, &direct, 0x1000, 0x1008).unwrap();
        verify_gated_dual_batch_bits_with_pc(8, &rows, &proof, &layout, &direct, 0x1000, 0x1008)
            .unwrap();
        assert!(verify_gated_dual_batch_bits_with_pc(
            8, &rows, &proof, &layout, &direct, 0x1000, 0x100c,
        )
        .is_err());
    }

    #[test]
    fn gated_dual_batch_runs_with_both_backends_on_q8() {
        use magnetar_proof::{DirectBitPcs, RingSwitchPackedBitPcs};

        let rows = (0..8usize)
            .map(|index| {
                (
                    0x1000 + 4 * index as u64,
                    if index % 5 == 4 {
                        GatedCpuRowInput::Shift {
                            left: 0x12 + index as u64,
                            shamt: 2,
                            kind: crate::simd_f2::BitShiftKind::Sll,
                        }
                    } else {
                        GatedCpuRowInput::Alu {
                            left: 0x12 + index as u64,
                            right: 0x34 + index as u64,
                            op: match index % 4 {
                                0 => crate::simd_f2::GatedAluOp::Add,
                                1 => crate::simd_f2::GatedAluOp::Sub,
                                2 => crate::simd_f2::GatedAluOp::Sltu,
                                _ => crate::simd_f2::GatedAluOp::Slt,
                            },
                        }
                    },
                )
            })
            .collect::<Vec<_>>();
        let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
        let direct = DirectBitPcs::new(pcs.clone());
        let (proof, layout) = prove_gated_dual_batch_bits(8, &rows, &direct).unwrap();
        verify_gated_dual_batch_bits(8, &rows, &proof, &layout, &direct).unwrap();

        let ring = RingSwitchPackedBitPcs::new(pcs);
        let (proof, layout) = prove_gated_dual_batch_bits(8, &rows, &ring).unwrap();
        verify_gated_dual_batch_bits(8, &rows, &proof, &layout, &ring).unwrap();
    }

    #[test]
    fn gated_dual_ring_switch_handles_width8() {
        use magnetar_proof::spartan::MatrixPart;
        use magnetar_proof::{
            prove_lockstep_bits, verify_lockstep_bits, RingSwitchPackedBitPcs, SparseMatrix,
        };

        let row = GatedCpuRow::new(8);
        let bits = row.alu_witness_at(0x1004, 5, 3, crate::simd_f2::GatedAluOp::Add);
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
        let backend = RingSwitchPackedBitPcs::new(pcs);
        let proof = prove_lockstep_bits(
            &packed_bits,
            &a0,
            &b0,
            &c0,
            &a1,
            &b1,
            &c1,
            &layout,
            &backend,
        )
        .unwrap();
        verify_lockstep_bits(&a0, &b0, &c0, &a1, &b1, &c1, &layout, &proof, &backend).unwrap();
    }

    #[test]
    fn gated_dual_revealing_backend_handles_width8() {
        use magnetar_proof::spartan::MatrixPart;
        use magnetar_proof::{
            prove_lockstep_bits, verify_lockstep_bits, RevealingPackedBitPcs, SparseMatrix,
        };

        let row = GatedCpuRow::new(8);
        let bits = row.alu_witness_at(0x1004, 5, 3, crate::simd_f2::GatedAluOp::Add);
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
        let backend = RevealingPackedBitPcs::new(pcs);
        let proof = prove_lockstep_bits(
            &packed_bits,
            &a0,
            &b0,
            &c0,
            &a1,
            &b1,
            &c1,
            &layout,
            &backend,
        )
        .unwrap();
        verify_lockstep_bits(&a0, &b0, &c0, &a1, &b1, &c1, &layout, &proof, &backend).unwrap();
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
                        op: match index % 4 {
                            0 => crate::simd_f2::GatedAluOp::Add,
                            1 => crate::simd_f2::GatedAluOp::Sub,
                            2 => crate::simd_f2::GatedAluOp::Sltu,
                            _ => crate::simd_f2::GatedAluOp::Slt,
                        },
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
