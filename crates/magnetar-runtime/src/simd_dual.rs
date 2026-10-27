//! Dual-relation lockstep: an F2 bit XOR relation over the packed CPU row's
//! rs1/rs2/rd variables, plus the packed CPU ALU system, over one witness.

use magnetar_constraint::{
    MemoryKind, RoutingKind, Segment, SegmentKind, SegmentOwner, WitnessLayout,
};
use magnetar_cpu::simd::uniform_cpu_row_layout;
use magnetar_cpu::{CpuVarKind, StepOp};
use magnetar_pcs::{P3MosaicCommitment, P3MosaicOpening, P3SharedPcs};
use magnetar_proof::dual_field::{BitRelation, BitRow};
use magnetar_proof::{prove_lockstep, verify_lockstep, witness_vector, LockstepProof};

use crate::simd_f2::{GatedCpuRow, GatedCpuRowInput};
use crate::RuntimeError;
use magnetar_constraint::F2_128;
use serde::{Deserialize as _, Serialize as _};

type LockstepBatch<B> = (
    LockstepProof<
        <B as magnetar_proof::BitPcs>::Commitment,
        <B as magnetar_proof::BitPcs>::Opening,
    >,
    WitnessLayout,
);

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

pub(crate) fn gated_segment_layout(
    cycles: usize,
    base_cols: usize,
    owners: &[SegmentOwner],
) -> Result<WitnessLayout, RuntimeError> {
    let segments = (0..cycles)
        .map(|index| {
            Segment::new(
                format!("gated{index}"),
                index * base_cols,
                base_cols,
                SegmentKind::Direct,
                owners.get(index).copied().unwrap_or(SegmentOwner::Cpu),
            )
        })
        .collect();
    WitnessLayout::new(segments).map_err(|error| RuntimeError::Proof(error.to_string()))
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
    let s1_system = row.relation().to_system();
    let mut s2_system = row.packed_companion_system();
    for _ in s2_system.constraints.len()..s1_system.constraints.len() {
        s2_system.add_constraint(
            magnetar_constraint::Expr::constant(0u64),
            magnetar_constraint::Expr::constant(1u64),
            magnetar_constraint::Expr::constant(0u64),
        );
    }
    let base_cols = (row.relation().num_vars + 1).next_power_of_two();
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
                (instance + 1) * base_cols + row.pc()[bit],
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
                kind,
            } => row.branch_witness_at(*pc, *left, *right, *imm, *kind),
            GatedCpuRowInput::Mul {
                left,
                right,
                out,
                high,
                signed_a,
                signed_b,
            } => row.mul_witness_at(*pc, *left, *right, *out, *high, *signed_a, *signed_b),
            GatedCpuRowInput::Div {
                num,
                den,
                out,
                is_rem,
            } => row.div_witness_at(*pc, *num, *den, *out, *is_rem),
            GatedCpuRowInput::SDiv {
                num,
                den,
                out,
                is_rem,
            } => row.sdiv_witness_at(*pc, *num, *den, *out, *is_rem),
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
                (instance + 1) * base_cols + row.pc()[bit],
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
pub trait GatedRowLike {
    fn relation(&self) -> &magnetar_proof::dual_field::BitRelation;
    fn packed_companion_system(&self) -> magnetar_constraint::ConstraintSystem;
    fn width(&self) -> usize;
    fn pc(&self) -> &[magnetar_constraint::VarId];
    fn next_pc(&self) -> &[magnetar_constraint::VarId];
    fn one(&self) -> magnetar_constraint::VarId;
}

impl GatedRowLike for GatedCpuRow {
    fn relation(&self) -> &magnetar_proof::dual_field::BitRelation {
        &self.relation
    }
    fn packed_companion_system(&self) -> magnetar_constraint::ConstraintSystem {
        self.packed_companion_system()
    }
    fn width(&self) -> usize {
        self.width
    }
    fn pc(&self) -> &[magnetar_constraint::VarId] {
        &self.pc
    }
    fn next_pc(&self) -> &[magnetar_constraint::VarId] {
        &self.next_pc
    }
    fn one(&self) -> magnetar_constraint::VarId {
        self.alu.one
    }
}

impl GatedRowLike for crate::reservation_cpu_row::ReservationCpuRow {
    fn relation(&self) -> &magnetar_proof::dual_field::BitRelation {
        &self.relation
    }
    fn packed_companion_system(&self) -> magnetar_constraint::ConstraintSystem {
        self.cpu.packed_companion_system()
    }
    fn width(&self) -> usize {
        self.width
    }
    fn pc(&self) -> &[magnetar_constraint::VarId] {
        &self.cpu.pc
    }
    fn next_pc(&self) -> &[magnetar_constraint::VarId] {
        &self.cpu.next_pc
    }
    fn one(&self) -> magnetar_constraint::VarId {
        self.cpu.alu.one
    }
}

fn gated_shared_matrices<R: GatedRowLike>(
    row: &R,
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

    let s1_system = row.relation().to_system();
    let mut s2_system = row.packed_companion_system();
    for _ in s2_system.constraints.len()..s1_system.constraints.len() {
        s2_system.add_constraint(
            magnetar_constraint::Expr::constant(0u64),
            magnetar_constraint::Expr::constant(1u64),
            magnetar_constraint::Expr::constant(0u64),
        );
    }
    let base_cols = (row.relation().num_vars + 1).next_power_of_two();
    let mut extra_a = Vec::new();
    let mut extra_b = Vec::new();
    let mut extra_c = Vec::new();
    for instance in 0..cycles.saturating_sub(1) {
        for bit in 0..row.width() {
            extra_a.push(vec![(
                instance * base_cols + row.next_pc()[bit],
                magnetar_constraint::F2_128::from(1u64),
            )]);
            extra_b.push(vec![(
                instance * base_cols + row.one(),
                magnetar_constraint::F2_128::from(1u64),
            )]);
            extra_c.push(vec![(
                (instance + 1) * base_cols + row.pc()[bit],
                magnetar_constraint::F2_128::from(1u64),
            )]);
        }
    }
    let mut statement_rows = 0usize;
    if let Some((initial_pc, final_pc)) = statement {
        statement_rows = 2 * row.width();
        for (instance, pc) in [(0usize, initial_pc), (cycles - 1, final_pc)] {
            for bit in 0..row.width() {
                let value = (pc >> bit) & 1;
                let var = if instance == 0 {
                    row.pc()[bit]
                } else {
                    row.next_pc()[bit]
                };
                extra_a.push(vec![(
                    instance * base_cols + var,
                    magnetar_constraint::F2_128::from(1u64),
                )]);
                extra_b.push(vec![(
                    instance * base_cols + row.one(),
                    magnetar_constraint::F2_128::from(1u64),
                )]);
                if value == 1 {
                    extra_c.push(vec![(
                        instance * base_cols + row.one(),
                        magnetar_constraint::F2_128::from(1u64),
                    )]);
                } else {
                    extra_c.push(Vec::new());
                }
            }
        }
    }
    let zero_rows = vec![Vec::new(); cycles.saturating_sub(1) * row.width() + statement_rows];
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

#[allow(dead_code, clippy::type_complexity)]
/// C2 building block: one SIMD instance covering several consecutive cycles.
///
/// The base relation is replicated block-diagonally for `group` rows and
/// cross-step rows force `next_pc(row i) == pc(row i+1)` using the per-row
/// constant-one variable. This is the intra-instance part of the paper's
/// multi-cycle SIMD instance; boundary links between instances are still the
/// existing extra rows in `gated_shared_matrices`.
pub(crate) fn grouped_gated_system(
    width: usize,
    rows: &[(u64, crate::reservation_cpu_row::ReservationCpuInput)],
    group: usize,
) -> Result<
    (
        magnetar_constraint::ConstraintSystem,
        magnetar_constraint::ConstraintSystem,
        Vec<F2_128>,
        usize,
    ),
    RuntimeError,
> {
    use magnetar_constraint::{ConstraintSystem, Expr};
    if group == 0 || !group.is_power_of_two() || !rows.len().is_multiple_of(group) {
        return Err(RuntimeError::Proof(
            "SIMD group must divide the cycle count".into(),
        ));
    }
    let row = crate::reservation_cpu_row::ReservationCpuRow::new(width);
    let base = row.cpu.relation.to_system();
    let base_cols = base.num_vars;
    let mut base2 = row.cpu.packed_companion_system();
    while base2.constraints.len() < base.constraints.len() {
        base2.add_constraint(
            magnetar_constraint::Expr::constant(0u64),
            magnetar_constraint::Expr::constant(1u64),
            magnetar_constraint::Expr::constant(0u64),
        );
    }
    let mut combined = ConstraintSystem::new(0);
    let mut combined2 = ConstraintSystem::new(0);
    let mut offsets = Vec::with_capacity(group);
    for _ in 0..group {
        offsets.push(combined.merge(base.clone()));
        combined2.merge(base2.clone());
    }
    for index in 0..group - 1 {
        for bit in 0..width {
            combined2.add_constraint(
                Expr::var(offsets[index] + row.cpu.next_pc[bit]),
                Expr::var(offsets[index] + row.cpu.alu.one),
                Expr::var(offsets[index + 1] + row.cpu.pc[bit]),
            );
        }
    }
    let padded_cols = (combined.num_vars + 1).next_power_of_two();
    combined.num_vars = padded_cols - 1;
    combined2.num_vars = padded_cols - 1;
    let (z, _, _, _) = reservation_claim_inputs(width, rows)?;
    let row_stride = (row.cpu.relation.num_vars + 1).next_power_of_two();
    let mut witness = Vec::with_capacity(rows.len() / group * padded_cols);
    for group_start in (0..rows.len()).step_by(group) {
        for local in 0..group {
            let start = (group_start + local) * row_stride;
            witness.extend_from_slice(&z[start..start + base_cols]);
        }
        witness.resize(
            witness.len() + padded_cols - group * base_cols,
            F2_128::from(0u64),
        );
    }
    Ok((combined, combined2, witness, base_cols))
}

pub(crate) fn reservation_claim_matrices(
    width: usize,
    cycles: usize,
) -> Result<
    (
        [magnetar_proof::SharedBlockMatrix; 3],
        [magnetar_proof::SharedBlockMatrix; 3],
        magnetar_constraint::WitnessLayout,
    ),
    RuntimeError,
> {
    let row = crate::reservation_cpu_row::ReservationCpuRow::new(width);
    let (base_cols, systems0, systems1) = gated_shared_matrices(&row, cycles, None)?;
    let layout = gated_segment_layout(cycles, base_cols, &[])?;
    Ok((systems0, systems1, layout))
}

#[allow(dead_code, clippy::type_complexity)]
pub(crate) fn group_virtual_specs(
    specs: &[crate::VirtualSegmentSpec],
    cycles: usize,
    base_cols: usize,
    row_vars: usize,
    block_cols: usize,
    group: usize,
) -> Vec<crate::VirtualSegmentSpec> {
    let mut grouped = Vec::with_capacity(specs.len() + 1);
    for spec in specs {
        let mut sources = Vec::new();
        for (offset, len) in &spec.sources {
            for index in *offset..*offset + *len {
                let cycle = index / base_cols;
                if cycle >= cycles {
                    continue;
                }
                let column = index % base_cols;
                if column >= row_vars {
                    continue;
                }
                let mapped = (cycle / group) * block_cols + (cycle % group) * row_vars + column;
                sources.push((mapped, 1usize));
            }
        }
        if !sources.is_empty() {
            grouped.push(crate::VirtualSegmentSpec {
                name: spec.name.clone(),
                sources,
                owner: spec.owner,
                projection: spec.projection,
            });
        }
    }
    let padding = block_cols - group * row_vars;
    if padding > 0 {
        let sources = (0..cycles / group)
            .map(|instance| (instance * block_cols + group * row_vars, padding))
            .collect::<Vec<_>>();
        grouped.push(crate::VirtualSegmentSpec {
            name: "group_padding".into(),
            sources,
            owner: magnetar_constraint::SegmentOwner::Cpu,
            projection: magnetar_constraint::ProjectionKind::Identity,
        });
    }
    grouped
}

pub(crate) fn choose_group(cycles: usize) -> usize {
    if cycles >= 4 && cycles.is_multiple_of(2) {
        2
    } else {
        1
    }
}

#[allow(dead_code, clippy::type_complexity)]
fn grouped_virtual_layout(
    width: usize,
    cycles: usize,
    group: usize,
    block_cols: usize,
) -> Result<(magnetar_constraint::WitnessLayout, Vec<usize>, usize), RuntimeError> {
    let row = crate::reservation_cpu_row::ReservationCpuRow::new(width);
    let row_vars = row.cpu.relation.num_vars;
    let base_cols = (row_vars + 1).next_power_of_two();
    let specs = reservation_virtual_specs(width, cycles, base_cols);
    let grouped = group_virtual_specs(&specs, cycles, base_cols, row_vars, block_cols, group);
    let padded = crate::build_padded_virtual_layout(&grouped)?;
    let inner_cols = cycles / group * block_cols;
    let mut mapping = vec![0usize; inner_cols];
    for map in &padded.mapping {
        let mut cursor = map.padded_offset;
        for (original, len) in &map.sources {
            for offset in 0..*len {
                mapping[original + offset] = cursor + offset;
            }
            cursor += len;
        }
    }
    Ok((padded.layout, mapping, inner_cols))
}

#[allow(dead_code, clippy::type_complexity)]
pub(crate) fn reservation_grouped_virtual_inputs(
    width: usize,
    rows: &[(u64, crate::reservation_cpu_row::ReservationCpuInput)],
    group: usize,
) -> Result<
    (
        Vec<F2_128>,
        [magnetar_proof::SharedBlockMatrix; 3],
        [magnetar_proof::SharedBlockMatrix; 3],
        magnetar_constraint::WitnessLayout,
        Vec<usize>,
        usize,
    ),
    RuntimeError,
> {
    let cycles = rows.len();
    let (z_group, a0, a1, _) = reservation_grouped_lockstep(width, rows, group)?;
    let block_cols = a0[0].cols() / (cycles / group);
    let (layout, mapping, inner_cols) = grouped_virtual_layout(width, cycles, group, block_cols)?;
    let mut z_virtual = vec![F2_128::from(0u64); layout.total_bits];
    for (original, virtual_index) in mapping.iter().enumerate().take(inner_cols) {
        z_virtual[*virtual_index] = z_group[original];
    }
    Ok((z_virtual, a0, a1, layout, mapping, inner_cols))
}

#[allow(dead_code, clippy::type_complexity)]
pub(crate) fn reservation_grouped_virtual_view(
    width: usize,
    cycles: usize,
    group: usize,
) -> Result<
    (
        [magnetar_proof::SharedBlockMatrix; 3],
        [magnetar_proof::SharedBlockMatrix; 3],
        magnetar_constraint::WitnessLayout,
        Vec<usize>,
        usize,
    ),
    RuntimeError,
> {
    let dummy = vec![
        (
            0u64,
            crate::reservation_cpu_row::ReservationCpuInput {
                cpu: crate::simd_f2::GatedCpuRowInput::Alu {
                    left: 0,
                    right: 0,
                    op: crate::simd_f2::GatedAluOp::Inactive,
                },
                addr: 0,
                res_addr: 0,
                pre_valid: false,
                is_lr: false,
                is_sc: false,
                is_invalidate: false,
                next_pre_valid: false,
                next_pre_addr: 0,
                value: 0,
                has_value: false,
                next_pc: 4,
                step2: false,
            },
        );
        cycles
    ];
    let (_, a0, a1, layout, mapping, inner) =
        reservation_grouped_virtual_inputs(width, &dummy, group)?;
    Ok((a0, a1, layout, mapping, inner))
}

#[allow(dead_code, clippy::type_complexity)]
pub(crate) fn reservation_grouped_lockstep(
    width: usize,
    rows: &[(u64, crate::reservation_cpu_row::ReservationCpuInput)],
    group: usize,
) -> Result<
    (
        Vec<F2_128>,
        [magnetar_proof::SharedBlockMatrix; 3],
        [magnetar_proof::SharedBlockMatrix; 3],
        magnetar_constraint::WitnessLayout,
    ),
    RuntimeError,
> {
    use magnetar_constraint::{Segment, SegmentKind, SegmentOwner, WitnessLayout};
    use magnetar_proof::spartan::MatrixPart;
    use magnetar_proof::SharedBlockMatrix;
    let cycles = rows.len();
    let groups = cycles / group;
    let (system, system2, z, row_cols) = grouped_gated_system(width, rows, group)?;
    let block_cols = (system.num_vars + 1).next_power_of_two();
    let row = crate::reservation_cpu_row::ReservationCpuRow::new(width);
    let mut extra_a = Vec::new();
    let mut extra_b = Vec::new();
    let mut extra_c = Vec::new();
    for instance in 0..groups.saturating_sub(1) {
        for bit in 0..width {
            extra_a.push(vec![(
                instance * block_cols + (group - 1) * row_cols + row.cpu.next_pc[bit],
                F2_128::from(1u64),
            )]);
            extra_b.push(vec![(
                instance * block_cols + (group - 1) * row_cols + row.cpu.alu.one,
                F2_128::from(1u64),
            )]);
            extra_c.push(vec![(
                (instance + 1) * block_cols + row.cpu.pc[bit],
                F2_128::from(1u64),
            )]);
        }
    }
    let zero = vec![Vec::new(); extra_a.len()];
    let a0 = SharedBlockMatrix::from_system(&system, MatrixPart::A, groups)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(zero.clone());
    let b0 = SharedBlockMatrix::from_system(&system, MatrixPart::B, groups)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(zero.clone());
    let c0 = SharedBlockMatrix::from_system(&system, MatrixPart::C, groups)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(zero);
    let a1 = SharedBlockMatrix::from_system(&system2, MatrixPart::A, groups)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_a);
    let b1 = SharedBlockMatrix::from_system(&system2, MatrixPart::B, groups)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_b);
    let c1 = SharedBlockMatrix::from_system(&system2, MatrixPart::C, groups)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_c);
    let segments = (0..groups)
        .map(|instance| {
            Segment::new(
                format!("group{instance}"),
                instance * block_cols,
                block_cols,
                SegmentKind::Direct,
                SegmentOwner::Cpu,
            )
        })
        .collect::<Vec<_>>();
    let layout =
        WitnessLayout::new(segments).map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((z, [a0, b0, c0], [a1, b1, c1], layout))
}

pub(crate) fn reservation_virtual_specs(
    width: usize,
    cycles: usize,
    base_cols: usize,
) -> Vec<crate::VirtualSegmentSpec> {
    let row = crate::reservation_cpu_row::ReservationCpuRow::new(width);
    let gated = &row.cpu;
    let pc_start = gated.pc[0];
    let seq_start = pc_start + width;
    let reservation_start = row.reservation_offset;
    let gated_end = reservation_start;
    let mut parts: Vec<(&str, usize, usize, SegmentOwner)> = vec![
        ("alu", 0, gated.memory_offset, SegmentOwner::Cpu),
        (
            "memory_cpu_lo",
            gated.memory_offset,
            gated.memory_offset + gated.memory.adder.out[0],
            SegmentOwner::Cpu,
        ),
        (
            "memory_cpu_mid",
            gated.memory_offset + gated.memory.adder.out[0] + width,
            gated.memory_offset + gated.memory.data[0],
            SegmentOwner::Cpu,
        ),
        (
            "memory_cpu_hi",
            gated.memory_offset + gated.memory.data[0] + width,
            gated.shift_offset,
            SegmentOwner::Cpu,
        ),
        (
            "shift_sll_lo",
            gated.shift_offset,
            gated.shift_offset + gated.shift.sll.shamt[0],
            SegmentOwner::Routing(RoutingKind::Shifts),
        ),
        (
            "shift_sll_hi",
            gated.shift_offset + gated.shift.sll.shamt[0] + width.trailing_zeros() as usize,
            gated.shift_offset + gated.shift.srl_offset,
            SegmentOwner::Routing(RoutingKind::Shifts),
        ),
        (
            "shift_srl_lo",
            gated.shift_offset + gated.shift.srl_offset,
            gated.shift_offset + gated.shift.srl_offset + gated.shift.srl.shamt[0],
            SegmentOwner::Routing(RoutingKind::Shifts),
        ),
        (
            "shift_srl_hi",
            gated.shift_offset
                + gated.shift.srl_offset
                + gated.shift.srl.shamt[0]
                + width.trailing_zeros() as usize,
            gated.shift_offset + gated.shift.sra_offset,
            SegmentOwner::Routing(RoutingKind::Shifts),
        ),
        (
            "shift_sra_lo",
            gated.shift_offset + gated.shift.sra_offset,
            gated.shift_offset + gated.shift.sra_offset + gated.shift.sra.shamt[0],
            SegmentOwner::Routing(RoutingKind::Shifts),
        ),
        (
            "shift_sra_hi",
            gated.shift_offset
                + gated.shift.sra_offset
                + gated.shift.sra.shamt[0]
                + width.trailing_zeros() as usize,
            gated.shift_offset + gated.shift.is_sll,
            SegmentOwner::Routing(RoutingKind::Shifts),
        ),
        (
            "shift_sel_lo",
            gated.shift_offset + gated.shift.is_sll,
            gated.shift_offset + gated.shift.is_shift,
            SegmentOwner::Routing(RoutingKind::Shifts),
        ),
        (
            "shift_one",
            gated.shift_offset + gated.shift.is_shift + 1,
            gated.branch_offset,
            SegmentOwner::Routing(RoutingKind::Shifts),
        ),
        (
            "branch",
            gated.branch_offset,
            gated.mul_offset,
            SegmentOwner::Pcs,
        ),
        ("mul", gated.mul_offset, gated.div_offset, SegmentOwner::Cpu),
        (
            "div",
            gated.div_offset,
            gated.sdiv_offset,
            SegmentOwner::Cpu,
        ),
        ("sdiv", gated.sdiv_offset, pc_start, SegmentOwner::Cpu),
        ("tail", seq_start, gated_end, SegmentOwner::Cpu),
        (
            "reservation",
            reservation_start,
            row.relation.num_vars,
            SegmentOwner::Cpu,
        ),
        (
            "padding",
            row.relation.num_vars,
            base_cols,
            SegmentOwner::Cpu,
        ),
    ];
    parts.retain(|(_, start, end, _)| end > start);
    let mut specs = Vec::with_capacity(parts.len() * cycles);
    for cycle in 0..cycles {
        let base = cycle * base_cols;
        for (name, start, end, owner) in &parts {
            specs.push(crate::VirtualSegmentSpec {
                name: format!("{name}{cycle}"),
                sources: vec![(base + start, end - start)],
                owner: *owner,
                projection: owner.projection(),
            });
        }
    }
    let addr_sources = (0..cycles)
        .map(|cycle| {
            (
                cycle * base_cols + gated.memory_offset + gated.memory.adder.out[0],
                width,
            )
        })
        .collect::<Vec<_>>();
    let data_sources = (0..cycles)
        .map(|cycle| {
            (
                cycle * base_cols + gated.memory_offset + gated.memory.data[0],
                width,
            )
        })
        .collect::<Vec<_>>();
    let active_sources = (0..cycles)
        .map(|cycle| {
            (
                cycle * base_cols + gated.shift_offset + gated.shift.is_shift,
                1,
            )
        })
        .collect::<Vec<_>>();
    specs.push(crate::VirtualSegmentSpec {
        name: "shift_active".into(),
        sources: active_sources,
        owner: SegmentOwner::Routing(RoutingKind::Shifts),
        projection: SegmentOwner::Routing(RoutingKind::Shifts).projection(),
    });
    let shift_stages = width.trailing_zeros() as usize;
    for (name, shamt) in [
        ("shift_sll", gated.shift.sll.shamt[0]),
        (
            "shift_srl",
            gated.shift.srl_offset + gated.shift.srl.shamt[0],
        ),
        (
            "shift_sra",
            gated.shift.sra_offset + gated.shift.sra.shamt[0],
        ),
    ] {
        let sources = (0..cycles)
            .map(|cycle| (cycle * base_cols + gated.shift_offset + shamt, shift_stages))
            .collect::<Vec<_>>();
        specs.push(crate::VirtualSegmentSpec {
            name: name.into(),
            sources,
            owner: SegmentOwner::Routing(RoutingKind::Shifts),
            projection: SegmentOwner::Routing(RoutingKind::Shifts).projection(),
        });
    }
    let pc_sources = (0..cycles)
        .map(|cycle| (cycle * base_cols + pc_start, seq_start - pc_start))
        .collect::<Vec<_>>();
    specs.push(crate::VirtualSegmentSpec {
        name: "pc_bits".into(),
        sources: pc_sources,
        owner: SegmentOwner::Pcs,
        projection: SegmentOwner::Pcs.projection(),
    });
    specs.push(crate::VirtualSegmentSpec {
        name: "memory_addr".into(),
        sources: addr_sources,
        owner: SegmentOwner::Memory(MemoryKind::Ram),
        projection: SegmentOwner::Memory(MemoryKind::Ram).projection(),
    });
    specs.push(crate::VirtualSegmentSpec {
        name: "memory_data".into(),
        sources: data_sources,
        owner: SegmentOwner::Memory(MemoryKind::Ram),
        projection: SegmentOwner::Memory(MemoryKind::Ram).projection(),
    });
    specs
}

#[allow(clippy::type_complexity)]
pub(crate) fn reservation_claim_inputs(
    width: usize,
    rows: &[(u64, crate::reservation_cpu_row::ReservationCpuInput)],
) -> Result<
    (
        Vec<F2_128>,
        [magnetar_proof::SharedBlockMatrix; 3],
        [magnetar_proof::SharedBlockMatrix; 3],
        magnetar_constraint::WitnessLayout,
    ),
    RuntimeError,
> {
    let row = crate::reservation_cpu_row::ReservationCpuRow::new(width);
    let (base_cols, systems0, systems1) = gated_shared_matrices(&row, rows.len(), None)?;
    let mut bits = Vec::with_capacity(rows.len() * base_cols);
    for (pc, input) in rows {
        bits.extend(row.witness(*pc, *input));
        bits.resize(bits.len() + base_cols - row.relation.num_vars, false);
    }
    let owners = rows
        .iter()
        .map(|(_, input)| match input.cpu {
            crate::simd_f2::GatedCpuRowInput::Memory { .. } if input.is_invalidate => {
                SegmentOwner::Routing(RoutingKind::Stores)
            }
            crate::simd_f2::GatedCpuRowInput::Memory { .. } => {
                SegmentOwner::Memory(MemoryKind::Ram)
            }
            crate::simd_f2::GatedCpuRowInput::Shift { .. } => {
                SegmentOwner::Routing(RoutingKind::Shifts)
            }
            crate::simd_f2::GatedCpuRowInput::Branch { .. } => SegmentOwner::Pcs,
            _ => SegmentOwner::Cpu,
        })
        .collect::<Vec<_>>();
    let layout = gated_segment_layout(rows.len(), base_cols, &owners)?;
    let z = bits
        .iter()
        .map(|bit| F2_128::from(u64::from(*bit)))
        .collect::<Vec<_>>();
    Ok((z, systems0, systems1, layout))
}

#[allow(clippy::type_complexity)]
pub(crate) fn reservation_virtual_inputs(
    width: usize,
    rows: &[(u64, crate::reservation_cpu_row::ReservationCpuInput)],
) -> Result<
    (
        Vec<F2_128>,
        [magnetar_proof::SharedBlockMatrix; 3],
        [magnetar_proof::SharedBlockMatrix; 3],
        magnetar_constraint::WitnessLayout,
        Vec<usize>,
    ),
    RuntimeError,
> {
    let cycles = rows.len();
    let (z, a0, a1, _) = reservation_claim_inputs(width, rows)?;
    let base_cols = a0[0].cols() / cycles;
    let specs = reservation_virtual_specs(width, cycles, base_cols);
    let padded = crate::build_padded_virtual_layout(&specs)?;
    let mut mapping = vec![0usize; z.len()];
    for map in &padded.mapping {
        let mut cursor = map.padded_offset;
        for (original, len) in &map.sources {
            for offset in 0..*len {
                mapping[original + offset] = cursor + offset;
            }
            cursor += len;
        }
    }
    Ok((padded.pad_values(&z), a0, a1, padded.layout, mapping))
}

pub(crate) fn reservation_virtual_view(
    width: usize,
    cycles: usize,
    base_cols: usize,
) -> Result<(magnetar_constraint::WitnessLayout, Vec<usize>, usize), RuntimeError> {
    let specs = reservation_virtual_specs(width, cycles, base_cols);
    let padded = crate::build_padded_virtual_layout(&specs)?;
    let total = cycles * base_cols;
    let mut mapping = vec![0usize; total];
    for map in &padded.mapping {
        let mut cursor = map.padded_offset;
        for (original, len) in &map.sources {
            for offset in 0..*len {
                mapping[original + offset] = cursor + offset;
            }
            cursor += len;
        }
    }
    Ok((padded.layout, mapping, total))
}

pub(crate) fn gated_batch_bits(
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
                kind,
            } => row.branch_witness_at(*pc, *left, *right, *imm, *kind),
            GatedCpuRowInput::Mul {
                left,
                right,
                out,
                high,
                signed_a,
                signed_b,
            } => row.mul_witness_at(*pc, *left, *right, *out, *high, *signed_a, *signed_b),
            GatedCpuRowInput::Div {
                num,
                den,
                out,
                is_rem,
            } => row.div_witness_at(*pc, *num, *den, *out, *is_rem),
            GatedCpuRowInput::SDiv {
                num,
                den,
                out,
                is_rem,
            } => row.sdiv_witness_at(*pc, *num, *den, *out, *is_rem),
        };
        bits.extend(instance);
        bits.resize(bits.len() + base_cols - row.relation.num_vars, false);
    }
    bits
}

#[allow(clippy::type_complexity)]
/// Prototype op-specialized row: only the ALU relation is committed, instead
/// of the full combined gated CPU row. Used to measure the benefit of removing
/// unused mul/div/shift/memory subrelations.
pub fn prove_alu_only_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    backend: &B,
) -> Result<LockstepBatch<B>, RuntimeError> {
    use magnetar_proof::spartan::MatrixPart;
    use magnetar_proof::{prove_lockstep_bits, SharedBlockMatrix};

    if cycles == 0 || !cycles.is_power_of_two() {
        return Err(RuntimeError::Proof(
            "ALU-only batch must be a nonzero power of two".into(),
        ));
    }
    let row = crate::simd_f2::GatedAluRow::new(width);
    let relation = row.relation.clone();
    let mut system = relation.to_system();
    let base_cols = (system.num_vars + 1).next_power_of_two();
    while system.constraints.len() < system.constraints.len().next_power_of_two() {
        system.add_constraint(
            magnetar_constraint::Expr::constant(0u64),
            magnetar_constraint::Expr::constant(1u64),
            magnetar_constraint::Expr::constant(0u64),
        );
    }
    let matrices = |part| {
        SharedBlockMatrix::from_system(&system, part, cycles)
            .map_err(|error| RuntimeError::Proof(error.to_string()))
    };
    let a = matrices(MatrixPart::A)?;
    let b = matrices(MatrixPart::B)?;
    let c = matrices(MatrixPart::C)?;
    let mut bits = Vec::with_capacity(cycles * base_cols);
    for row_index in 0..cycles {
        let mut witness = row.witness(
            0x12 + row_index as u64,
            0x34 + row_index as u64,
            if row_index % 2 == 0 {
                crate::simd_f2::GatedAluOp::Add
            } else {
                crate::simd_f2::GatedAluOp::Xor
            },
        );
        witness.resize(base_cols, false);
        bits.extend(witness);
    }
    let layout = segment_layout(bits.len())?;
    let proof = prove_lockstep_bits(&bits, &a, &b, &c, &a, &b, &c, &layout, backend)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((proof, layout))
}

pub fn verify_alu_only_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    proof: &LockstepProof<B::Commitment, B::Opening>,
    layout: &WitnessLayout,
    backend: &B,
) -> Result<(), RuntimeError> {
    use magnetar_proof::spartan::MatrixPart;
    use magnetar_proof::{verify_lockstep_bits, SharedBlockMatrix};

    let row = crate::simd_f2::GatedAluRow::new(width);
    let relation = row.relation.clone();
    let mut system = relation.to_system();
    while system.constraints.len() < system.constraints.len().next_power_of_two() {
        system.add_constraint(
            magnetar_constraint::Expr::constant(0u64),
            magnetar_constraint::Expr::constant(1u64),
            magnetar_constraint::Expr::constant(0u64),
        );
    }
    let matrices = |part| {
        SharedBlockMatrix::from_system(&system, part, cycles)
            .map_err(|error| RuntimeError::Proof(error.to_string()))
    };
    let a = matrices(MatrixPart::A)?;
    let b = matrices(MatrixPart::B)?;
    let c = matrices(MatrixPart::C)?;
    verify_lockstep_bits(&a, &b, &c, &a, &b, &c, layout, proof, backend)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(())
}

struct AluPcRow {
    width: usize,
    instr: crate::simd_f2::GatedAluRow,
    pc_add: crate::simd_f2::GatedBitAdder,
    pc: Vec<magnetar_constraint::VarId>,
    next_pc: Vec<magnetar_constraint::VarId>,
    relation: BitRelation,
}

impl AluPcRow {
    fn new(width: usize) -> Self {
        use magnetar_constraint::VarId;
        let instr = crate::simd_f2::GatedAluRow::new(width);
        let pc_add = crate::simd_f2::GatedBitAdder::new(width);
        let mut relation = instr.relation.clone();
        let add_offset = relation.num_vars;
        relation.num_vars += pc_add.relation.num_vars;
        for row in &pc_add.relation.rows {
            let shift =
                |vars: &[VarId]| vars.iter().map(|var| *var + add_offset).collect::<Vec<_>>();
            relation.add(BitRow::new(shift(&row.a), shift(&row.b), shift(&row.c)));
        }
        let pc = (relation.num_vars..relation.num_vars + width)
            .map(|var| var as VarId)
            .collect::<Vec<_>>();
        relation.num_vars += width;
        let next_pc = (relation.num_vars..relation.num_vars + width)
            .map(|var| var as VarId)
            .collect::<Vec<_>>();
        relation.num_vars += width;
        let one = instr.one;
        for bit in 0..width {
            relation.add(BitRow::new(vec![pc[bit]], vec![pc[bit]], vec![pc[bit]]));
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![next_pc[bit]],
                vec![next_pc[bit]],
            ));
            relation.add(BitRow::new(
                vec![pc[bit]],
                vec![one],
                vec![add_offset as VarId + pc_add.a[bit]],
            ));
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![one],
                vec![add_offset as VarId + pc_add.out[bit]],
            ));
            let constant = add_offset as VarId + pc_add.b[bit];
            if bit == 2 {
                relation.add(BitRow::new(vec![constant], vec![one], vec![one]));
            } else {
                relation.add(BitRow::new(vec![constant], vec![one], Vec::new()));
            }
        }
        relation.add(BitRow::new(
            vec![add_offset as VarId + pc_add.gate],
            vec![one],
            vec![one],
        ));
        Self {
            width,
            instr,
            pc_add,
            pc,
            next_pc,
            relation,
        }
    }

    fn witness_at(
        &self,
        pc: u64,
        left: u64,
        right: u64,
        op: crate::simd_f2::GatedAluOp,
    ) -> Vec<bool> {
        let mut bits = self.instr.witness(left, right, op);
        let addition = self.pc_add.witness(pc, 4, true);
        bits.extend(addition);
        bits.resize(self.relation.num_vars, false);
        for bit in 0..self.width {
            bits[self.pc[bit]] = (pc >> bit) & 1 == 1;
            bits[self.next_pc[bit]] = ((pc + 4) >> bit) & 1 == 1;
        }
        bits
    }
}

impl GatedRowLike for AluPcRow {
    fn relation(&self) -> &BitRelation {
        &self.relation
    }
    fn packed_companion_system(&self) -> magnetar_constraint::ConstraintSystem {
        self.relation.to_system()
    }
    fn width(&self) -> usize {
        self.width
    }
    fn pc(&self) -> &[magnetar_constraint::VarId] {
        &self.pc
    }
    fn next_pc(&self) -> &[magnetar_constraint::VarId] {
        &self.next_pc
    }
    fn one(&self) -> magnetar_constraint::VarId {
        self.instr.one
    }
}

pub fn prove_alu_pc_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    backend: &B,
) -> Result<LockstepBatch<B>, RuntimeError> {
    use magnetar_proof::prove_lockstep_bits;

    if cycles == 0 || !cycles.is_power_of_two() {
        return Err(RuntimeError::Proof(
            "ALU+PC batch must be a nonzero power of two".into(),
        ));
    }
    let row = AluPcRow::new(width);
    let system = row.relation.to_system();
    let witness = row.relation.to_witness(&row.witness_at(
        0x1000,
        0x12,
        0x34,
        crate::simd_f2::GatedAluOp::Add,
    ));
    system
        .check(&witness)
        .map_err(|error| RuntimeError::Proof(format!("ALU+PC row witness: {error}")))?;
    let (base_cols, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    let mut bits = Vec::with_capacity(cycles * base_cols);
    for index in 0..cycles {
        let pc = initial_pc + 4 * index as u64;
        let mut witness = row.witness_at(
            pc,
            0x12 + index as u64,
            0x34 + index as u64,
            if index % 2 == 0 {
                crate::simd_f2::GatedAluOp::Add
            } else {
                crate::simd_f2::GatedAluOp::Xor
            },
        );
        witness.resize(base_cols, false);
        bits.extend(witness);
    }
    let layout = segment_layout(bits.len())?;
    let proof = prove_lockstep_bits(
        &bits, &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], &layout, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((proof, layout))
}

pub fn verify_alu_pc_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    proof: &LockstepProof<B::Commitment, B::Opening>,
    layout: &WitnessLayout,
    backend: &B,
) -> Result<(), RuntimeError> {
    use magnetar_proof::verify_lockstep_bits;

    let row = AluPcRow::new(width);
    let (_, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    verify_lockstep_bits(
        &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], layout, proof, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(())
}

struct ShiftPcRow {
    width: usize,
    instr: crate::simd_f2::GatedShiftRow,
    pc_add: crate::simd_f2::GatedBitAdder,
    pc: Vec<magnetar_constraint::VarId>,
    next_pc: Vec<magnetar_constraint::VarId>,
    relation: BitRelation,
}

impl ShiftPcRow {
    fn new(width: usize) -> Self {
        use magnetar_constraint::VarId;
        let instr = crate::simd_f2::GatedShiftRow::new(width);
        let pc_add = crate::simd_f2::GatedBitAdder::new(width);
        let mut relation = instr.relation.clone();
        let add_offset = relation.num_vars;
        relation.num_vars += pc_add.relation.num_vars;
        for row in &pc_add.relation.rows {
            let shift =
                |vars: &[VarId]| vars.iter().map(|var| *var + add_offset).collect::<Vec<_>>();
            relation.add(BitRow::new(shift(&row.a), shift(&row.b), shift(&row.c)));
        }
        let pc = (relation.num_vars..relation.num_vars + width)
            .map(|var| var as VarId)
            .collect::<Vec<_>>();
        relation.num_vars += width;
        let next_pc = (relation.num_vars..relation.num_vars + width)
            .map(|var| var as VarId)
            .collect::<Vec<_>>();
        relation.num_vars += width;
        let one = instr.one;
        for bit in 0..width {
            relation.add(BitRow::new(vec![pc[bit]], vec![pc[bit]], vec![pc[bit]]));
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![next_pc[bit]],
                vec![next_pc[bit]],
            ));
            relation.add(BitRow::new(
                vec![pc[bit]],
                vec![one],
                vec![add_offset as VarId + pc_add.a[bit]],
            ));
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![one],
                vec![add_offset as VarId + pc_add.out[bit]],
            ));
            let constant = add_offset as VarId + pc_add.b[bit];
            if bit == 2 {
                relation.add(BitRow::new(vec![constant], vec![one], vec![one]));
            } else {
                relation.add(BitRow::new(vec![constant], vec![one], Vec::new()));
            }
        }
        relation.add(BitRow::new(
            vec![add_offset as VarId + pc_add.gate],
            vec![one],
            vec![one],
        ));
        Self {
            width,
            instr,
            pc_add,
            pc,
            next_pc,
            relation,
        }
    }

    fn witness_at(
        &self,
        pc: u64,
        left: u64,
        shamt: u64,
        kind: crate::simd_f2::BitShiftKind,
    ) -> Vec<bool> {
        let mut bits = self.instr.witness(left, shamt, kind);
        let addition = self.pc_add.witness(pc, 4, true);
        bits.extend(addition);
        bits.resize(self.relation.num_vars, false);
        for bit in 0..self.width {
            bits[self.pc[bit]] = (pc >> bit) & 1 == 1;
            bits[self.next_pc[bit]] = ((pc + 4) >> bit) & 1 == 1;
        }
        bits
    }
}

impl GatedRowLike for ShiftPcRow {
    fn relation(&self) -> &BitRelation {
        &self.relation
    }
    fn packed_companion_system(&self) -> magnetar_constraint::ConstraintSystem {
        self.relation.to_system()
    }
    fn width(&self) -> usize {
        self.width
    }
    fn pc(&self) -> &[magnetar_constraint::VarId] {
        &self.pc
    }
    fn next_pc(&self) -> &[magnetar_constraint::VarId] {
        &self.next_pc
    }
    fn one(&self) -> magnetar_constraint::VarId {
        self.instr.one
    }
}

pub fn prove_shift_pc_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    backend: &B,
) -> Result<LockstepBatch<B>, RuntimeError> {
    use magnetar_proof::prove_lockstep_bits;

    let row = ShiftPcRow::new(width);
    let system = row.relation.to_system();
    let witness = row.relation.to_witness(&row.witness_at(
        initial_pc,
        0x12,
        2,
        crate::simd_f2::BitShiftKind::Sll,
    ));
    system
        .check(&witness)
        .map_err(|error| RuntimeError::Proof(format!("shift+PC row witness: {error}")))?;
    let (base_cols, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    let mut bits = Vec::with_capacity(cycles * base_cols);
    for index in 0..cycles {
        let pc = initial_pc + 4 * index as u64;
        let mut witness = row.witness_at(
            pc,
            0x12 + index as u64,
            (index % 4) as u64,
            crate::simd_f2::BitShiftKind::Sll,
        );
        witness.resize(base_cols, false);
        bits.extend(witness);
    }
    let layout = segment_layout(bits.len())?;
    let proof = prove_lockstep_bits(
        &bits, &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], &layout, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((proof, layout))
}

pub fn verify_shift_pc_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    proof: &LockstepProof<B::Commitment, B::Opening>,
    layout: &WitnessLayout,
    backend: &B,
) -> Result<(), RuntimeError> {
    use magnetar_proof::verify_lockstep_bits;

    let row = ShiftPcRow::new(width);
    let (_, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    verify_lockstep_bits(
        &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], layout, proof, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(())
}

struct MulPcRow {
    width: usize,
    instr: crate::mul_row::GatedMulRow,
    pc_add: crate::simd_f2::GatedBitAdder,
    pc: Vec<magnetar_constraint::VarId>,
    next_pc: Vec<magnetar_constraint::VarId>,
    relation: BitRelation,
}

impl MulPcRow {
    fn new(width: usize) -> Self {
        use magnetar_constraint::VarId;
        let instr = crate::mul_row::GatedMulRow::new(width);
        let pc_add = crate::simd_f2::GatedBitAdder::new(width);
        let mut relation = instr.relation.clone();
        let add_offset = relation.num_vars;
        relation.num_vars += pc_add.relation.num_vars;
        for row in &pc_add.relation.rows {
            let shift =
                |vars: &[VarId]| vars.iter().map(|var| *var + add_offset).collect::<Vec<_>>();
            relation.add(BitRow::new(shift(&row.a), shift(&row.b), shift(&row.c)));
        }
        let pc = (relation.num_vars..relation.num_vars + width)
            .map(|var| var as VarId)
            .collect::<Vec<_>>();
        relation.num_vars += width;
        let next_pc = (relation.num_vars..relation.num_vars + width)
            .map(|var| var as VarId)
            .collect::<Vec<_>>();
        relation.num_vars += width;
        let one = instr.one;
        for bit in 0..width {
            relation.add(BitRow::new(vec![pc[bit]], vec![pc[bit]], vec![pc[bit]]));
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![next_pc[bit]],
                vec![next_pc[bit]],
            ));
            relation.add(BitRow::new(
                vec![pc[bit]],
                vec![one],
                vec![add_offset as VarId + pc_add.a[bit]],
            ));
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![one],
                vec![add_offset as VarId + pc_add.out[bit]],
            ));
            let constant = add_offset as VarId + pc_add.b[bit];
            if bit == 2 {
                relation.add(BitRow::new(vec![constant], vec![one], vec![one]));
            } else {
                relation.add(BitRow::new(vec![constant], vec![one], Vec::new()));
            }
        }
        relation.add(BitRow::new(
            vec![add_offset as VarId + pc_add.gate],
            vec![one],
            vec![one],
        ));
        Self {
            width,
            instr,
            pc_add,
            pc,
            next_pc,
            relation,
        }
    }

    fn witness_at(&self, pc: u64, left: u64, right: u64) -> Vec<bool> {
        self.witness_with_flags(pc, left, right, false, false, false)
    }

    fn witness_with_flags(
        &self,
        pc: u64,
        left: u64,
        right: u64,
        high: bool,
        signed_a: bool,
        signed_b: bool,
    ) -> Vec<bool> {
        let _ = high;
        let mut bits = self
            .instr
            .witness_with_signs(left, right, signed_a, signed_b);
        let addition = self.pc_add.witness(pc, 4, true);
        bits.extend(addition);
        bits.resize(self.relation.num_vars, false);
        for bit in 0..self.width {
            bits[self.pc[bit]] = (pc >> bit) & 1 == 1;
            bits[self.next_pc[bit]] = ((pc + 4) >> bit) & 1 == 1;
        }
        bits
    }
}

impl GatedRowLike for MulPcRow {
    fn relation(&self) -> &BitRelation {
        &self.relation
    }
    fn packed_companion_system(&self) -> magnetar_constraint::ConstraintSystem {
        self.relation.to_system()
    }
    fn width(&self) -> usize {
        self.width
    }
    fn pc(&self) -> &[magnetar_constraint::VarId] {
        &self.pc
    }
    fn next_pc(&self) -> &[magnetar_constraint::VarId] {
        &self.next_pc
    }
    fn one(&self) -> magnetar_constraint::VarId {
        self.instr.one
    }
}

pub fn prove_mul_pc_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    backend: &B,
) -> Result<LockstepBatch<B>, RuntimeError> {
    use magnetar_proof::prove_lockstep_bits;

    let row = MulPcRow::new(width);
    let system = row.relation.to_system();
    let witness = row
        .relation
        .to_witness(&row.witness_at(initial_pc, 0x12, 0x34));
    system
        .check(&witness)
        .map_err(|error| RuntimeError::Proof(format!("mul+PC row witness: {error}")))?;
    let (base_cols, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    let mut bits = Vec::with_capacity(cycles * base_cols);
    for index in 0..cycles {
        let pc = initial_pc + 4 * index as u64;
        let mut witness = row.witness_at(pc, 0x12 + index as u64, 0x34 + index as u64);
        witness.resize(base_cols, false);
        bits.extend(witness);
    }
    let layout = segment_layout(bits.len())?;
    let proof = prove_lockstep_bits(
        &bits, &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], &layout, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((proof, layout))
}

pub fn verify_mul_pc_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    proof: &LockstepProof<B::Commitment, B::Opening>,
    layout: &WitnessLayout,
    backend: &B,
) -> Result<(), RuntimeError> {
    use magnetar_proof::verify_lockstep_bits;

    let row = MulPcRow::new(width);
    let (_, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    verify_lockstep_bits(
        &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], layout, proof, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(())
}

struct MemPcRow {
    width: usize,
    instr: crate::simd_f2::GatedMemoryRow,
    pc_add: crate::simd_f2::GatedBitAdder,
    pc: Vec<magnetar_constraint::VarId>,
    next_pc: Vec<magnetar_constraint::VarId>,
    relation: BitRelation,
}

impl MemPcRow {
    fn new(width: usize) -> Self {
        use magnetar_constraint::VarId;
        let instr = crate::simd_f2::GatedMemoryRow::new(width);
        let pc_add = crate::simd_f2::GatedBitAdder::new(width);
        let mut relation = instr.relation.clone();
        let add_offset = relation.num_vars;
        relation.num_vars += pc_add.relation.num_vars;
        for row in &pc_add.relation.rows {
            let shift =
                |vars: &[VarId]| vars.iter().map(|var| *var + add_offset).collect::<Vec<_>>();
            relation.add(BitRow::new(shift(&row.a), shift(&row.b), shift(&row.c)));
        }
        let pc = (relation.num_vars..relation.num_vars + width)
            .map(|var| var as VarId)
            .collect::<Vec<_>>();
        relation.num_vars += width;
        let next_pc = (relation.num_vars..relation.num_vars + width)
            .map(|var| var as VarId)
            .collect::<Vec<_>>();
        relation.num_vars += width;
        let one = instr.adder.gate;
        for bit in 0..width {
            relation.add(BitRow::new(vec![pc[bit]], vec![pc[bit]], vec![pc[bit]]));
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![next_pc[bit]],
                vec![next_pc[bit]],
            ));
            relation.add(BitRow::new(
                vec![pc[bit]],
                vec![one],
                vec![add_offset as VarId + pc_add.a[bit]],
            ));
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![one],
                vec![add_offset as VarId + pc_add.out[bit]],
            ));
            let constant = add_offset as VarId + pc_add.b[bit];
            if bit == 2 {
                relation.add(BitRow::new(vec![constant], vec![one], vec![one]));
            } else {
                relation.add(BitRow::new(vec![constant], vec![one], Vec::new()));
            }
        }
        relation.add(BitRow::new(
            vec![add_offset as VarId + pc_add.gate],
            vec![one],
            vec![one],
        ));
        Self {
            width,
            instr,
            pc_add,
            pc,
            next_pc,
            relation,
        }
    }

    fn witness_at(&self, pc: u64, rs1: u64, imm: u64, value: u64) -> Vec<bool> {
        let mut bits = self.instr.witness(rs1, imm, value, true);
        let addition = self.pc_add.witness(pc, 4, true);
        bits.extend(addition);
        bits.resize(self.relation.num_vars, false);
        for bit in 0..self.width {
            bits[self.pc[bit]] = (pc >> bit) & 1 == 1;
            bits[self.next_pc[bit]] = ((pc + 4) >> bit) & 1 == 1;
        }
        bits
    }
}

impl GatedRowLike for MemPcRow {
    fn relation(&self) -> &BitRelation {
        &self.relation
    }
    fn packed_companion_system(&self) -> magnetar_constraint::ConstraintSystem {
        self.relation.to_system()
    }
    fn width(&self) -> usize {
        self.width
    }
    fn pc(&self) -> &[magnetar_constraint::VarId] {
        &self.pc
    }
    fn next_pc(&self) -> &[magnetar_constraint::VarId] {
        &self.next_pc
    }
    fn one(&self) -> magnetar_constraint::VarId {
        self.instr.adder.gate
    }
}

pub fn prove_mem_pc_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    backend: &B,
) -> Result<LockstepBatch<B>, RuntimeError> {
    use magnetar_proof::prove_lockstep_bits;

    let row = MemPcRow::new(width);
    let system = row.relation.to_system();
    let witness = row
        .relation
        .to_witness(&row.witness_at(initial_pc, 0x10, 0, 0x40));
    system
        .check(&witness)
        .map_err(|error| RuntimeError::Proof(format!("mem+PC row witness: {error}")))?;
    let (base_cols, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    let mut bits = Vec::with_capacity(cycles * base_cols);
    for index in 0..cycles {
        let pc = initial_pc + 4 * index as u64;
        let mut witness = row.witness_at(pc, 0x10 + index as u64, 0, 0x40 + index as u64);
        witness.resize(base_cols, false);
        bits.extend(witness);
    }
    let layout = segment_layout(bits.len())?;
    let proof = prove_lockstep_bits(
        &bits, &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], &layout, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((proof, layout))
}

pub fn verify_mem_pc_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    proof: &LockstepProof<B::Commitment, B::Opening>,
    layout: &WitnessLayout,
    backend: &B,
) -> Result<(), RuntimeError> {
    use magnetar_proof::verify_lockstep_bits;

    let row = MemPcRow::new(width);
    let (_, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    verify_lockstep_bits(
        &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], layout, proof, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(())
}

struct DivPcRow {
    width: usize,
    instr: crate::div_row::GatedDivRow,
    pc_add: crate::simd_f2::GatedBitAdder,
    pc: Vec<magnetar_constraint::VarId>,
    next_pc: Vec<magnetar_constraint::VarId>,
    relation: BitRelation,
    one: magnetar_constraint::VarId,
}

impl DivPcRow {
    fn new(width: usize) -> Self {
        use magnetar_constraint::VarId;
        let instr = crate::div_row::GatedDivRow::new(width);
        let pc_add = crate::simd_f2::GatedBitAdder::new(width);
        let mut relation = instr.relation.clone();
        let add_offset = relation.num_vars;
        relation.num_vars += pc_add.relation.num_vars;
        for row in &pc_add.relation.rows {
            let shift =
                |vars: &[VarId]| vars.iter().map(|var| *var + add_offset).collect::<Vec<_>>();
            relation.add(BitRow::new(shift(&row.a), shift(&row.b), shift(&row.c)));
        }
        let pc = (relation.num_vars..relation.num_vars + width)
            .map(|var| var as VarId)
            .collect::<Vec<_>>();
        relation.num_vars += width;
        let next_pc = (relation.num_vars..relation.num_vars + width)
            .map(|var| var as VarId)
            .collect::<Vec<_>>();
        relation.num_vars += width;
        let one = (instr.add_offset + instr.add_alu.one) as VarId;
        for bit in 0..width {
            relation.add(BitRow::new(vec![pc[bit]], vec![pc[bit]], vec![pc[bit]]));
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![next_pc[bit]],
                vec![next_pc[bit]],
            ));
            relation.add(BitRow::new(
                vec![pc[bit]],
                vec![one],
                vec![add_offset as VarId + pc_add.a[bit]],
            ));
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![one],
                vec![add_offset as VarId + pc_add.out[bit]],
            ));
            let constant = add_offset as VarId + pc_add.b[bit];
            if bit == 2 {
                relation.add(BitRow::new(vec![constant], vec![one], vec![one]));
            } else {
                relation.add(BitRow::new(vec![constant], vec![one], Vec::new()));
            }
        }
        relation.add(BitRow::new(
            vec![add_offset as VarId + pc_add.gate],
            vec![one],
            vec![one],
        ));
        Self {
            width,
            instr,
            pc_add,
            pc,
            next_pc,
            relation,
            one,
        }
    }

    fn witness_at(&self, pc: u64, num: u64, den: u64) -> Vec<bool> {
        let mut bits = self.instr.witness(num, den);
        let addition = self.pc_add.witness(pc, 4, true);
        bits.extend(addition);
        bits.resize(self.relation.num_vars, false);
        for bit in 0..self.width {
            bits[self.pc[bit]] = (pc >> bit) & 1 == 1;
            bits[self.next_pc[bit]] = ((pc + 4) >> bit) & 1 == 1;
        }
        bits
    }
}

impl GatedRowLike for DivPcRow {
    fn relation(&self) -> &BitRelation {
        &self.relation
    }
    fn packed_companion_system(&self) -> magnetar_constraint::ConstraintSystem {
        self.relation.to_system()
    }
    fn width(&self) -> usize {
        self.width
    }
    fn pc(&self) -> &[magnetar_constraint::VarId] {
        &self.pc
    }
    fn next_pc(&self) -> &[magnetar_constraint::VarId] {
        &self.next_pc
    }
    fn one(&self) -> magnetar_constraint::VarId {
        self.one
    }
}

pub fn prove_div_pc_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    backend: &B,
) -> Result<LockstepBatch<B>, RuntimeError> {
    use magnetar_proof::prove_lockstep_bits;

    let row = DivPcRow::new(width);
    let system = row.relation.to_system();
    let witness = row
        .relation
        .to_witness(&row.witness_at(initial_pc, 0x60, 3));
    system
        .check(&witness)
        .map_err(|error| RuntimeError::Proof(format!("div+PC row witness: {error}")))?;
    let (base_cols, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    let mut bits = Vec::with_capacity(cycles * base_cols);
    for index in 0..cycles {
        let pc = initial_pc + 4 * index as u64;
        let mut witness = row.witness_at(pc, 0x60 + (index as u64 % 16), 3);
        witness.resize(base_cols, false);
        bits.extend(witness);
    }
    let layout = segment_layout(bits.len())?;
    let proof = prove_lockstep_bits(
        &bits, &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], &layout, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((proof, layout))
}

pub fn verify_div_pc_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    proof: &LockstepProof<B::Commitment, B::Opening>,
    layout: &WitnessLayout,
    backend: &B,
) -> Result<(), RuntimeError> {
    use magnetar_proof::verify_lockstep_bits;

    let row = DivPcRow::new(width);
    let (_, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    verify_lockstep_bits(
        &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], layout, proof, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(())
}

struct SDivPcRow {
    width: usize,
    instr: crate::signed_div_row::SignedDivRow,
    pc_add: crate::simd_f2::GatedBitAdder,
    pc: Vec<magnetar_constraint::VarId>,
    next_pc: Vec<magnetar_constraint::VarId>,
    relation: BitRelation,
    one: magnetar_constraint::VarId,
}

impl SDivPcRow {
    fn new(width: usize) -> Self {
        use magnetar_constraint::VarId;
        let instr = crate::signed_div_row::SignedDivRow::new(width);
        let pc_add = crate::simd_f2::GatedBitAdder::new(width);
        let mut relation = instr.relation.clone();
        let add_offset = relation.num_vars;
        relation.num_vars += pc_add.relation.num_vars;
        for row in &pc_add.relation.rows {
            let shift =
                |vars: &[VarId]| vars.iter().map(|var| *var + add_offset).collect::<Vec<_>>();
            relation.add(BitRow::new(shift(&row.a), shift(&row.b), shift(&row.c)));
        }
        let pc = (relation.num_vars..relation.num_vars + width)
            .map(|var| var as VarId)
            .collect::<Vec<_>>();
        relation.num_vars += width;
        let next_pc = (relation.num_vars..relation.num_vars + width)
            .map(|var| var as VarId)
            .collect::<Vec<_>>();
        relation.num_vars += width;
        let one = instr.one;
        for bit in 0..width {
            relation.add(BitRow::new(vec![pc[bit]], vec![pc[bit]], vec![pc[bit]]));
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![next_pc[bit]],
                vec![next_pc[bit]],
            ));
            relation.add(BitRow::new(
                vec![pc[bit]],
                vec![one],
                vec![add_offset as VarId + pc_add.a[bit]],
            ));
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![one],
                vec![add_offset as VarId + pc_add.out[bit]],
            ));
            let constant = add_offset as VarId + pc_add.b[bit];
            if bit == 2 {
                relation.add(BitRow::new(vec![constant], vec![one], vec![one]));
            } else {
                relation.add(BitRow::new(vec![constant], vec![one], Vec::new()));
            }
        }
        relation.add(BitRow::new(
            vec![add_offset as VarId + pc_add.gate],
            vec![one],
            vec![one],
        ));
        Self {
            width,
            instr,
            pc_add,
            pc,
            next_pc,
            relation,
            one,
        }
    }

    fn witness_at(&self, pc: u64, num: u64, den: u64) -> Vec<bool> {
        let mut bits = self.instr.witness(num, den);
        let addition = self.pc_add.witness(pc, 4, true);
        bits.extend(addition);
        bits.resize(self.relation.num_vars, false);
        for bit in 0..self.width {
            bits[self.pc[bit]] = (pc >> bit) & 1 == 1;
            bits[self.next_pc[bit]] = ((pc + 4) >> bit) & 1 == 1;
        }
        bits
    }
}

impl GatedRowLike for SDivPcRow {
    fn relation(&self) -> &BitRelation {
        &self.relation
    }
    fn packed_companion_system(&self) -> magnetar_constraint::ConstraintSystem {
        self.relation.to_system()
    }
    fn width(&self) -> usize {
        self.width
    }
    fn pc(&self) -> &[magnetar_constraint::VarId] {
        &self.pc
    }
    fn next_pc(&self) -> &[magnetar_constraint::VarId] {
        &self.next_pc
    }
    fn one(&self) -> magnetar_constraint::VarId {
        self.one
    }
}

pub fn prove_sdiv_pc_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    backend: &B,
) -> Result<LockstepBatch<B>, RuntimeError> {
    use magnetar_proof::prove_lockstep_bits;

    let row = SDivPcRow::new(width);
    let system = row.relation.to_system();
    let witness = row
        .relation
        .to_witness(&row.witness_at(initial_pc, 0x20, 3));
    system
        .check(&witness)
        .map_err(|error| RuntimeError::Proof(format!("sdiv+PC row witness: {error}")))?;
    let (base_cols, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    let mut bits = Vec::with_capacity(cycles * base_cols);
    for index in 0..cycles {
        let pc = initial_pc + 4 * index as u64;
        let mut witness = row.witness_at(pc, 0x20 + (index as u64 % 16), 3);
        witness.resize(base_cols, false);
        bits.extend(witness);
    }
    let layout = segment_layout(bits.len())?;
    let proof = prove_lockstep_bits(
        &bits, &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], &layout, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((proof, layout))
}

pub fn verify_sdiv_pc_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    proof: &LockstepProof<B::Commitment, B::Opening>,
    layout: &WitnessLayout,
    backend: &B,
) -> Result<(), RuntimeError> {
    use magnetar_proof::verify_lockstep_bits;

    let row = SDivPcRow::new(width);
    let (_, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    verify_lockstep_bits(
        &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], layout, proof, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(())
}

struct BranchPcRow {
    width: usize,
    instr: crate::branch_row::GatedBranchRow,
    pc: Vec<magnetar_constraint::VarId>,
    next_pc: Vec<magnetar_constraint::VarId>,
    relation: BitRelation,
}

impl BranchPcRow {
    fn new(width: usize) -> Self {
        use magnetar_constraint::VarId;
        let instr = crate::branch_row::GatedBranchRow::new(width);
        let mut relation = instr.relation.clone();
        let pc = (relation.num_vars..relation.num_vars + width)
            .map(|var| var as VarId)
            .collect::<Vec<_>>();
        relation.num_vars += width;
        let next_pc = (relation.num_vars..relation.num_vars + width)
            .map(|var| var as VarId)
            .collect::<Vec<_>>();
        relation.num_vars += width;
        let one = instr.one;
        for bit in 0..width {
            relation.add(BitRow::new(vec![pc[bit]], vec![pc[bit]], vec![pc[bit]]));
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![next_pc[bit]],
                vec![next_pc[bit]],
            ));
            relation.add(BitRow::new(
                vec![pc[bit]],
                vec![one],
                vec![(instr.target_offset + instr.target_alu.a[bit]) as VarId],
            ));
            relation.add(BitRow::new(
                vec![pc[bit]],
                vec![one],
                vec![(instr.seq_offset + instr.seq_alu.a[bit]) as VarId],
            ));
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![one],
                vec![instr.next[bit]],
            ));
        }
        Self {
            width,
            instr,
            pc,
            next_pc,
            relation,
        }
    }

    fn witness_at(
        &self,
        pc: u64,
        imm: u64,
        rs1: u64,
        rs2: u64,
        kind: crate::branch_row::BranchKind,
    ) -> Vec<bool> {
        let bits = self.instr.witness(pc, imm, rs1, rs2, kind);
        let mut out = bits.clone();
        out.resize(self.relation.num_vars, false);
        for bit in 0..self.width {
            out[self.pc[bit]] = (pc >> bit) & 1 == 1;
            out[self.next_pc[bit]] = bits[self.instr.next[bit]];
        }
        out
    }
}

impl GatedRowLike for BranchPcRow {
    fn relation(&self) -> &BitRelation {
        &self.relation
    }
    fn packed_companion_system(&self) -> magnetar_constraint::ConstraintSystem {
        self.relation.to_system()
    }
    fn width(&self) -> usize {
        self.width
    }
    fn pc(&self) -> &[magnetar_constraint::VarId] {
        &self.pc
    }
    fn next_pc(&self) -> &[magnetar_constraint::VarId] {
        &self.next_pc
    }
    fn one(&self) -> magnetar_constraint::VarId {
        self.instr.one
    }
}

pub fn prove_branch_pc_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    backend: &B,
) -> Result<LockstepBatch<B>, RuntimeError> {
    use magnetar_proof::prove_lockstep_bits;

    let row = BranchPcRow::new(width);
    let system = row.relation.to_system();
    let witness = row.relation.to_witness(&row.witness_at(
        initial_pc,
        8,
        0x12,
        0x12,
        crate::branch_row::BranchKind::Beq,
    ));
    system
        .check(&witness)
        .map_err(|error| RuntimeError::Proof(format!("branch+PC row witness: {error}")))?;
    let (base_cols, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    let mut bits = Vec::with_capacity(cycles * base_cols);
    for index in 0..cycles {
        let pc = initial_pc + 8 * index as u64;
        let mut witness = row.witness_at(
            pc,
            8,
            0x12 + index as u64,
            0x12 + index as u64,
            crate::branch_row::BranchKind::Beq,
        );
        witness.resize(base_cols, false);
        bits.extend(witness);
    }
    let layout = segment_layout(bits.len())?;
    let proof = prove_lockstep_bits(
        &bits, &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], &layout, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((proof, layout))
}

pub fn verify_branch_pc_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    proof: &LockstepProof<B::Commitment, B::Opening>,
    layout: &WitnessLayout,
    backend: &B,
) -> Result<(), RuntimeError> {
    use magnetar_proof::verify_lockstep_bits;

    let row = BranchPcRow::new(width);
    let (_, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    verify_lockstep_bits(
        &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], layout, proof, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(())
}

fn pc_row_virtual_specs(
    width: usize,
    cycles: usize,
    base_cols: usize,
    instr_len: usize,
    pc_start: usize,
) -> Vec<crate::VirtualSegmentSpec> {
    let mut specs = Vec::with_capacity(cycles * 4);
    for cycle in 0..cycles {
        let base = cycle * base_cols;
        let mut push = |name: String, start: usize, len: usize, owner: SegmentOwner| {
            if len > 0 {
                specs.push(crate::VirtualSegmentSpec {
                    name,
                    sources: vec![(base + start, len)],
                    owner,
                    projection: owner.projection(),
                });
            }
        };
        push(format!("instr{cycle}"), 0, instr_len, SegmentOwner::Cpu);
        push(
            format!("pc_add{cycle}"),
            instr_len,
            pc_start.saturating_sub(instr_len),
            SegmentOwner::Cpu,
        );
        push(format!("pc{cycle}"), pc_start, 2 * width, SegmentOwner::Pcs);
        let tail = pc_start + 2 * width;
        push(
            format!("padding{cycle}"),
            tail,
            base_cols.saturating_sub(tail),
            SegmentOwner::Cpu,
        );
    }
    specs
}

pub fn alu_pc_virtual_specs(
    width: usize,
    cycles: usize,
) -> Result<Vec<crate::VirtualSegmentSpec>, RuntimeError> {
    let row = AluPcRow::new(width);
    let (base_cols, _, _) = gated_shared_matrices(&row, cycles, None)?;
    Ok(pc_row_virtual_specs(
        width,
        cycles,
        base_cols,
        row.instr.relation.num_vars,
        row.pc[0],
    ))
}

pub fn shift_pc_virtual_specs(
    width: usize,
    cycles: usize,
) -> Result<Vec<crate::VirtualSegmentSpec>, RuntimeError> {
    let row = ShiftPcRow::new(width);
    let (base_cols, _, _) = gated_shared_matrices(&row, cycles, None)?;
    Ok(pc_row_virtual_specs(
        width,
        cycles,
        base_cols,
        row.instr.relation.num_vars,
        row.pc[0],
    ))
}

pub fn mem_pc_virtual_specs(
    width: usize,
    cycles: usize,
) -> Result<Vec<crate::VirtualSegmentSpec>, RuntimeError> {
    let row = MemPcRow::new(width);
    let (base_cols, _, _) = gated_shared_matrices(&row, cycles, None)?;
    Ok(pc_row_virtual_specs(
        width,
        cycles,
        base_cols,
        row.instr.relation.num_vars,
        row.pc[0],
    ))
}

pub fn mul_pc_virtual_specs(
    width: usize,
    cycles: usize,
) -> Result<Vec<crate::VirtualSegmentSpec>, RuntimeError> {
    let row = MulPcRow::new(width);
    let (base_cols, _, _) = gated_shared_matrices(&row, cycles, None)?;
    Ok(pc_row_virtual_specs(
        width,
        cycles,
        base_cols,
        row.instr.relation.num_vars,
        row.pc[0],
    ))
}

pub fn div_pc_virtual_specs(
    width: usize,
    cycles: usize,
) -> Result<Vec<crate::VirtualSegmentSpec>, RuntimeError> {
    let row = DivPcRow::new(width);
    let (base_cols, _, _) = gated_shared_matrices(&row, cycles, None)?;
    Ok(pc_row_virtual_specs(
        width,
        cycles,
        base_cols,
        row.instr.relation.num_vars,
        row.pc[0],
    ))
}

pub fn branch_pc_virtual_specs(
    width: usize,
    cycles: usize,
) -> Result<Vec<crate::VirtualSegmentSpec>, RuntimeError> {
    let row = BranchPcRow::new(width);
    let (base_cols, _, _) = gated_shared_matrices(&row, cycles, None)?;
    Ok(pc_row_virtual_specs(
        width,
        cycles,
        base_cols,
        row.instr.relation.num_vars,
        row.pc[0],
    ))
}

struct SegmentedPcRow {
    width: usize,
    relation: BitRelation,
    pc: Vec<magnetar_constraint::VarId>,
    next_pc: Vec<magnetar_constraint::VarId>,
    one: magnetar_constraint::VarId,
}

impl GatedRowLike for SegmentedPcRow {
    fn relation(&self) -> &BitRelation {
        &self.relation
    }
    fn packed_companion_system(&self) -> magnetar_constraint::ConstraintSystem {
        self.relation.to_system()
    }
    fn width(&self) -> usize {
        self.width
    }
    fn pc(&self) -> &[magnetar_constraint::VarId] {
        &self.pc
    }
    fn next_pc(&self) -> &[magnetar_constraint::VarId] {
        &self.next_pc
    }
    fn one(&self) -> magnetar_constraint::VarId {
        self.one
    }
}

fn segmented_pc_row<R: GatedRowLike>(
    original: &R,
    instr_len: usize,
    width: usize,
    cycles: usize,
) -> Result<
    (
        SegmentedPcRow,
        Vec<usize>,
        magnetar_constraint::WitnessLayout,
    ),
    RuntimeError,
> {
    use magnetar_constraint::{Segment, SegmentKind, SegmentOwner, WitnessLayout};

    let (original_cols, _, _) = gated_shared_matrices(original, cycles, None)?;
    let pc_start = original.pc()[0];
    let pc_len = 2 * width;
    let instr_size = instr_len.next_power_of_two();
    let add_len = pc_start - instr_len;
    let add_size = if add_len == 0 {
        0
    } else {
        add_len.next_power_of_two()
    };
    let pc_size = pc_len.next_power_of_two();
    let base_cols = (instr_size + add_size + pc_size)
        .next_power_of_two()
        .max(original_cols);
    let mut mapping = vec![usize::MAX; original.relation().num_vars];
    let mut blocks = Vec::new();
    let mut cursor = 0usize;
    for (index, target) in mapping.iter_mut().take(instr_len).enumerate() {
        *target = index;
    }
    blocks.push(("instr".to_string(), cursor, instr_size, SegmentOwner::Cpu));
    cursor += instr_size;
    if add_size > 0 {
        for index in 0..add_len {
            mapping[instr_len + index] = cursor + index;
        }
        blocks.push(("pc_add".to_string(), cursor, add_size, SegmentOwner::Cpu));
        cursor += add_size;
    }
    for index in 0..pc_len {
        mapping[pc_start + index] = cursor + index;
    }
    blocks.push(("pc".to_string(), cursor, pc_size, SegmentOwner::Pcs));
    cursor += pc_size;
    let mut padding_index = 0usize;
    while cursor < base_cols {
        let remaining = base_cols - cursor;
        let mut size = 1usize << (usize::BITS - 1 - remaining.leading_zeros());
        while size > 1 && !cursor.is_multiple_of(size) {
            size >>= 1;
        }
        blocks.push((
            format!("padding{padding_index}"),
            cursor,
            size,
            SegmentOwner::Cpu,
        ));
        padding_index += 1;
        cursor += size;
    }
    let mut relation = BitRelation::new(base_cols - 1);
    for row in &original.relation().rows {
        let map = |vars: &[magnetar_constraint::VarId]| {
            vars.iter().map(|var| mapping[*var]).collect::<Vec<_>>()
        };
        relation.add(BitRow::new(map(&row.a), map(&row.b), map(&row.c)));
    }
    let pc = original
        .pc()
        .iter()
        .map(|var| mapping[*var])
        .collect::<Vec<_>>();
    let next_pc = original
        .next_pc()
        .iter()
        .map(|var| mapping[*var])
        .collect::<Vec<_>>();
    let one = mapping[original.one()];
    let row = SegmentedPcRow {
        width,
        relation,
        pc,
        next_pc,
        one,
    };
    let mut segments = Vec::with_capacity(cycles * blocks.len());
    for cycle in 0..cycles {
        for (name, offset, size, owner) in &blocks {
            segments.push(Segment::new(
                format!("{name}{cycle}"),
                cycle * base_cols + offset,
                *size,
                SegmentKind::Direct,
                *owner,
            ));
        }
    }
    let layout =
        WitnessLayout::new(segments).map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((row, mapping, layout))
}

#[allow(clippy::too_many_arguments)]
fn prove_segmented_pc_batch<B, R, F>(
    original: &R,
    instr_len: usize,
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    pc_step: u64,
    witness: F,
    backend: &B,
) -> Result<LockstepBatch<B>, RuntimeError>
where
    B: magnetar_proof::BitPcs,
    R: GatedRowLike,
    F: Fn(u64) -> Vec<bool>,
{
    use magnetar_proof::prove_lockstep_bits;

    let (row, mapping, layout) = segmented_pc_row(original, instr_len, width, cycles)?;
    let (base_cols, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    if base_cols * cycles != layout.total_bits {
        return Err(RuntimeError::Proof(format!(
            "segmented layout mismatch: base={base_cols} cycles={cycles} total={}",
            layout.total_bits
        )));
    }
    let mut bits = Vec::with_capacity(cycles * base_cols);
    for index in 0..cycles {
        let pc = initial_pc + pc_step * index as u64;
        let instance = witness(pc);
        let mut block = vec![false; base_cols];
        for (source, target) in mapping.iter().enumerate() {
            if instance[source] {
                block[*target] = true;
            }
        }
        bits.extend(block);
    }
    let proof = prove_lockstep_bits(
        &bits, &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], &layout, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((proof, layout))
}

#[allow(clippy::too_many_arguments)]
fn verify_segmented_pc_batch<B, R>(
    original: &R,
    instr_len: usize,
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    proof: &LockstepProof<B::Commitment, B::Opening>,
    layout: &magnetar_constraint::WitnessLayout,
    backend: &B,
) -> Result<(), RuntimeError>
where
    B: magnetar_proof::BitPcs,
    R: GatedRowLike,
{
    use magnetar_proof::verify_lockstep_bits;

    let (row, _, expected) = segmented_pc_row(original, instr_len, width, cycles)?;
    if expected.total_bits != layout.total_bits || expected.segments.len() != layout.segments.len()
    {
        return Err(RuntimeError::Proof("segmented layout mismatch".into()));
    }
    let (_, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    verify_lockstep_bits(
        &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], layout, proof, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(())
}

pub fn prove_alu_pc_segmented_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    backend: &B,
) -> Result<LockstepBatch<B>, RuntimeError> {
    let row = AluPcRow::new(width);
    prove_segmented_pc_batch(
        &row,
        row.instr.relation.num_vars,
        width,
        cycles,
        initial_pc,
        final_pc,
        4,
        |pc| row.witness_at(pc, 0x12, 0x34, crate::simd_f2::GatedAluOp::Add),
        backend,
    )
}

pub fn verify_alu_pc_segmented_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    proof: &LockstepProof<B::Commitment, B::Opening>,
    layout: &magnetar_constraint::WitnessLayout,
    backend: &B,
) -> Result<(), RuntimeError> {
    let row = AluPcRow::new(width);
    verify_segmented_pc_batch(
        &row,
        row.instr.relation.num_vars,
        width,
        cycles,
        initial_pc,
        final_pc,
        proof,
        layout,
        backend,
    )
}

pub fn prove_shift_pc_segmented_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    backend: &B,
) -> Result<LockstepBatch<B>, RuntimeError> {
    let row = ShiftPcRow::new(width);
    prove_segmented_pc_batch(
        &row,
        row.instr.relation.num_vars,
        width,
        cycles,
        initial_pc,
        final_pc,
        4,
        |pc| row.witness_at(pc, 0x12, 2, crate::simd_f2::BitShiftKind::Sll),
        backend,
    )
}

pub fn verify_shift_pc_segmented_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    proof: &LockstepProof<B::Commitment, B::Opening>,
    layout: &magnetar_constraint::WitnessLayout,
    backend: &B,
) -> Result<(), RuntimeError> {
    let row = ShiftPcRow::new(width);
    verify_segmented_pc_batch(
        &row,
        row.instr.relation.num_vars,
        width,
        cycles,
        initial_pc,
        final_pc,
        proof,
        layout,
        backend,
    )
}

pub fn prove_mem_pc_segmented_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    backend: &B,
) -> Result<LockstepBatch<B>, RuntimeError> {
    let row = MemPcRow::new(width);
    prove_segmented_pc_batch(
        &row,
        row.instr.relation.num_vars,
        width,
        cycles,
        initial_pc,
        final_pc,
        4,
        |pc| row.witness_at(pc, 0x10, 0, 0x40),
        backend,
    )
}

pub fn verify_mem_pc_segmented_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    proof: &LockstepProof<B::Commitment, B::Opening>,
    layout: &magnetar_constraint::WitnessLayout,
    backend: &B,
) -> Result<(), RuntimeError> {
    let row = MemPcRow::new(width);
    verify_segmented_pc_batch(
        &row,
        row.instr.relation.num_vars,
        width,
        cycles,
        initial_pc,
        final_pc,
        proof,
        layout,
        backend,
    )
}

pub fn prove_mul_pc_segmented_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    backend: &B,
) -> Result<LockstepBatch<B>, RuntimeError> {
    let row = MulPcRow::new(width);
    prove_segmented_pc_batch(
        &row,
        row.instr.relation.num_vars,
        width,
        cycles,
        initial_pc,
        final_pc,
        4,
        |pc| row.witness_at(pc, 0x12, 0x34),
        backend,
    )
}

pub fn verify_mul_pc_segmented_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    proof: &LockstepProof<B::Commitment, B::Opening>,
    layout: &magnetar_constraint::WitnessLayout,
    backend: &B,
) -> Result<(), RuntimeError> {
    let row = MulPcRow::new(width);
    verify_segmented_pc_batch(
        &row,
        row.instr.relation.num_vars,
        width,
        cycles,
        initial_pc,
        final_pc,
        proof,
        layout,
        backend,
    )
}

pub fn prove_div_pc_segmented_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    backend: &B,
) -> Result<LockstepBatch<B>, RuntimeError> {
    let row = DivPcRow::new(width);
    prove_segmented_pc_batch(
        &row,
        row.instr.relation.num_vars,
        width,
        cycles,
        initial_pc,
        final_pc,
        4,
        |pc| row.witness_at(pc, 0x60, 3),
        backend,
    )
}

pub fn verify_div_pc_segmented_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    proof: &LockstepProof<B::Commitment, B::Opening>,
    layout: &magnetar_constraint::WitnessLayout,
    backend: &B,
) -> Result<(), RuntimeError> {
    let row = DivPcRow::new(width);
    verify_segmented_pc_batch(
        &row,
        row.instr.relation.num_vars,
        width,
        cycles,
        initial_pc,
        final_pc,
        proof,
        layout,
        backend,
    )
}

pub fn prove_branch_pc_segmented_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    backend: &B,
) -> Result<LockstepBatch<B>, RuntimeError> {
    let row = BranchPcRow::new(width);
    prove_segmented_pc_batch(
        &row,
        row.instr.relation.num_vars,
        width,
        cycles,
        initial_pc,
        final_pc,
        8,
        |pc| row.witness_at(pc, 8, 0x12, 0x12, crate::branch_row::BranchKind::Beq),
        backend,
    )
}

pub fn verify_branch_pc_segmented_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    proof: &LockstepProof<B::Commitment, B::Opening>,
    layout: &magnetar_constraint::WitnessLayout,
    backend: &B,
) -> Result<(), RuntimeError> {
    let row = BranchPcRow::new(width);
    verify_segmented_pc_batch(
        &row,
        row.instr.relation.num_vars,
        width,
        cycles,
        initial_pc,
        final_pc,
        proof,
        layout,
        backend,
    )
}

struct MixedAluBranchRow {
    width: usize,
    alu: AluPcRow,
    branch: BranchPcRow,
    mem: MemPcRow,
    shift: ShiftPcRow,
    mul: MulPcRow,
    div: DivPcRow,
    sdiv: SDivPcRow,
    branch_offset: usize,
    mem_offset: usize,
    shift_offset: usize,
    mul_offset: usize,
    div_offset: usize,
    sdiv_offset: usize,
    pc: Vec<magnetar_constraint::VarId>,
    next_pc: Vec<magnetar_constraint::VarId>,
    select_alu: magnetar_constraint::VarId,
    select_branch: magnetar_constraint::VarId,
    select_mem: magnetar_constraint::VarId,
    select_shift: magnetar_constraint::VarId,
    select_mul: magnetar_constraint::VarId,
    select_div: magnetar_constraint::VarId,
    select_sdiv: magnetar_constraint::VarId,
    and_alu: Vec<magnetar_constraint::VarId>,
    and_branch: Vec<magnetar_constraint::VarId>,
    and_mem: Vec<magnetar_constraint::VarId>,
    and_shift: Vec<magnetar_constraint::VarId>,
    and_mul: Vec<magnetar_constraint::VarId>,
    and_div: Vec<magnetar_constraint::VarId>,
    and_sdiv: Vec<magnetar_constraint::VarId>,
    one: magnetar_constraint::VarId,
    relation: BitRelation,
}

#[derive(Clone, Copy)]
pub enum MixedAluBranchInput {
    Alu {
        left: u64,
        right: u64,
        op: crate::simd_f2::GatedAluOp,
    },
    Fetch {
        left: u64,
        right: u64,
        imm: u64,
        kind: crate::branch_row::BranchKind,
    },
    Memory {
        rs1: u64,
        imm: u64,
        value: u64,
    },
    Shift {
        left: u64,
        shamt: u64,
        kind: crate::simd_f2::BitShiftKind,
    },
    Multiply {
        left: u64,
        right: u64,
        high: bool,
        signed_a: bool,
        signed_b: bool,
    },
    Divide {
        num: u64,
        den: u64,
    },
    SignedDivide {
        num: u64,
        den: u64,
    },
    Jump {
        target: u64,
    },
}

impl MixedAluBranchInput {
    fn kind(&self) -> u8 {
        match self {
            Self::Alu { .. } => MIXED_ALU,
            Self::Fetch { .. } => MIXED_BRANCH,
            Self::Memory { .. } => MIXED_MEMORY,
            Self::Shift { .. } => MIXED_SHIFT,
            Self::Multiply { .. } => MIXED_MULTIPLY,
            Self::Divide { .. } => MIXED_DIVIDE,
            Self::SignedDivide { .. } => MIXED_SDIV,
            Self::Jump { .. } => MIXED_JUMP,
        }
    }
}

impl MixedAluBranchRow {
    fn new(width: usize) -> Self {
        use magnetar_constraint::VarId;
        let alu = AluPcRow::new(width);
        let branch = BranchPcRow::new(width);
        let mem = MemPcRow::new(width);
        let shift = ShiftPcRow::new(width);
        let mul = MulPcRow::new(width);
        let div = DivPcRow::new(width);
        let sdiv = SDivPcRow::new(width);
        let branch_offset = alu.relation.num_vars;
        let mem_offset = branch_offset + branch.relation.num_vars;
        let shift_offset = mem_offset + mem.relation.num_vars;
        let mul_offset = shift_offset + shift.relation.num_vars;
        let div_offset = mul_offset + mul.relation.num_vars;
        let sdiv_offset = div_offset + div.relation.num_vars;
        let mut relation = alu.relation.clone();
        relation.num_vars += branch.relation.num_vars
            + mem.relation.num_vars
            + shift.relation.num_vars
            + mul.relation.num_vars
            + div.relation.num_vars
            + sdiv.relation.num_vars;
        for (source, offset) in [
            (&branch.relation, branch_offset),
            (&mem.relation, mem_offset),
            (&shift.relation, shift_offset),
            (&mul.relation, mul_offset),
            (&div.relation, div_offset),
            (&sdiv.relation, sdiv_offset),
        ] {
            for row in &source.rows {
                let shift =
                    |vars: &[VarId]| vars.iter().map(|var| *var + offset).collect::<Vec<_>>();
                relation.add(BitRow::new(shift(&row.a), shift(&row.b), shift(&row.c)));
            }
        }
        let take = |relation: &mut BitRelation, n: usize| {
            let start = relation.num_vars;
            relation.num_vars += n;
            (start..start + n).map(|v| v as VarId).collect::<Vec<_>>()
        };
        let pc = take(&mut relation, width);
        let next_pc = take(&mut relation, width);
        let select_alu = relation.num_vars as VarId;
        let select_branch = select_alu + 1;
        let select_mem = select_alu + 2;
        let select_shift = select_alu + 3;
        let select_mul = select_alu + 4;
        let select_div = select_alu + 5;
        let select_sdiv = select_alu + 6;
        relation.num_vars += 7;
        let and_alu = take(&mut relation, width);
        let and_branch = take(&mut relation, width);
        let and_mem = take(&mut relation, width);
        let and_shift = take(&mut relation, width);
        let and_mul = take(&mut relation, width);
        let and_div = take(&mut relation, width);
        let and_sdiv = take(&mut relation, width);
        let one = alu.instr.one;
        for bit in 0..width {
            relation.add(BitRow::new(vec![pc[bit]], vec![pc[bit]], vec![pc[bit]]));
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![next_pc[bit]],
                vec![next_pc[bit]],
            ));
            relation.add(BitRow::new(vec![alu.pc[bit]], vec![one], vec![pc[bit]]));
            relation.add(BitRow::new(
                vec![branch.pc[bit] + branch_offset],
                vec![one],
                vec![pc[bit]],
            ));
            relation.add(BitRow::new(
                vec![mem.pc[bit] + mem_offset],
                vec![one],
                vec![pc[bit]],
            ));
            relation.add(BitRow::new(
                vec![shift.pc[bit] + shift_offset],
                vec![one],
                vec![pc[bit]],
            ));
            relation.add(BitRow::new(
                vec![mul.pc[bit] + mul_offset],
                vec![one],
                vec![pc[bit]],
            ));
            relation.add(BitRow::new(
                vec![div.pc[bit] + div_offset],
                vec![one],
                vec![pc[bit]],
            ));
            relation.add(BitRow::new(
                vec![sdiv.pc[bit] + sdiv_offset],
                vec![one],
                vec![pc[bit]],
            ));
            relation.add(BitRow::new(
                vec![select_alu],
                vec![alu.next_pc[bit]],
                vec![and_alu[bit]],
            ));
            relation.add(BitRow::new(
                vec![select_branch],
                vec![branch.next_pc[bit] + branch_offset],
                vec![and_branch[bit]],
            ));
            relation.add(BitRow::new(
                vec![select_mem],
                vec![mem.next_pc[bit] + mem_offset],
                vec![and_mem[bit]],
            ));
            relation.add(BitRow::new(
                vec![select_shift],
                vec![shift.next_pc[bit] + shift_offset],
                vec![and_shift[bit]],
            ));
            relation.add(BitRow::new(
                vec![select_mul],
                vec![mul.next_pc[bit] + mul_offset],
                vec![and_mul[bit]],
            ));
            relation.add(BitRow::new(
                vec![select_div],
                vec![div.next_pc[bit] + div_offset],
                vec![and_div[bit]],
            ));
            relation.add(BitRow::new(
                vec![select_sdiv],
                vec![sdiv.next_pc[bit] + sdiv_offset],
                vec![and_sdiv[bit]],
            ));
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![one],
                vec![
                    and_alu[bit],
                    and_branch[bit],
                    and_mem[bit],
                    and_shift[bit],
                    and_mul[bit],
                    and_div[bit],
                    and_sdiv[bit],
                ],
            ));
        }
        for selector in [
            select_alu,
            select_branch,
            select_mem,
            select_shift,
            select_mul,
            select_div,
            select_sdiv,
        ] {
            relation.add(BitRow::new(vec![selector], vec![selector], vec![selector]));
        }
        relation.add(BitRow::new(
            vec![
                select_alu,
                select_branch,
                select_mem,
                select_shift,
                select_mul,
                select_div,
                select_sdiv,
            ],
            vec![one],
            vec![one],
        ));
        Self {
            width,
            alu,
            branch,
            mem,
            shift,
            mul,
            div,
            sdiv,
            branch_offset,
            mem_offset,
            shift_offset,
            mul_offset,
            div_offset,
            sdiv_offset,
            pc,
            next_pc,
            select_alu,
            select_branch,
            select_mem,
            select_shift,
            select_mul,
            select_div,
            select_sdiv,
            and_alu,
            and_branch,
            and_mem,
            and_shift,
            and_mul,
            and_div,
            and_sdiv,
            one,
            relation,
        }
    }

    fn witness_at(&self, pc: u64, input: &MixedAluBranchInput) -> Vec<bool> {
        let (left, right, op) = match input {
            MixedAluBranchInput::Alu { left, right, op } => (*left, *right, *op),
            _ => (0, 0, crate::simd_f2::GatedAluOp::Add),
        };
        let (bl, br, imm, kind) = match input {
            MixedAluBranchInput::Fetch {
                left,
                right,
                imm,
                kind,
            } => (*left, *right, *imm, *kind),
            _ => (0, 1, 0, crate::branch_row::BranchKind::Beq),
        };
        let (rs1, mem_imm, value) = match input {
            MixedAluBranchInput::Memory { rs1, imm, value } => (*rs1, *imm, *value),
            _ => (0x10, 0, 0x40),
        };
        let (shift_left, shamt, shift_kind) = match input {
            MixedAluBranchInput::Shift { left, shamt, kind } => (*left, *shamt, *kind),
            _ => (0x12, 2, crate::simd_f2::BitShiftKind::Sll),
        };
        let (mul_left, mul_right) = match input {
            MixedAluBranchInput::Multiply { left, right, .. } => (*left, *right),
            _ => (0x12, 0x34),
        };
        let (num, den) = match input {
            MixedAluBranchInput::Divide { num, den } => (*num, *den),
            _ => (0x60, 3),
        };
        let (snum, sden) = match input {
            MixedAluBranchInput::SignedDivide { num, den } => (*num, *den),
            _ => (0x20, 3),
        };
        let mut bits = self.alu.witness_at(pc, left, right, op);
        bits.extend(self.branch.witness_at(pc, imm, bl, br, kind));
        bits.extend(self.mem.witness_at(pc, rs1, mem_imm, value));
        bits.extend(self.shift.witness_at(pc, shift_left, shamt, shift_kind));
        bits.extend(self.mul.witness_at(pc, mul_left, mul_right));
        bits.extend(self.div.witness_at(pc, num, den));
        bits.extend(self.sdiv.witness_at(pc, snum, sden));
        bits.resize(self.relation.num_vars, false);
        let selected = match input {
            MixedAluBranchInput::Alu { .. } => 0usize,
            MixedAluBranchInput::Fetch { .. } => 1,
            MixedAluBranchInput::Memory { .. } => 2,
            MixedAluBranchInput::Shift { .. } => 3,
            MixedAluBranchInput::Multiply { .. } => 4,
            MixedAluBranchInput::Divide { .. } => 5,
            MixedAluBranchInput::SignedDivide { .. } => 6,
            MixedAluBranchInput::Jump { .. } => 0,
        };
        let next = match selected {
            0 => self.alu.next_pc.clone(),
            1 => self
                .branch
                .next_pc
                .iter()
                .map(|v| *v + self.branch_offset)
                .collect(),
            2 => self
                .mem
                .next_pc
                .iter()
                .map(|v| *v + self.mem_offset)
                .collect(),
            3 => self
                .shift
                .next_pc
                .iter()
                .map(|v| *v + self.shift_offset)
                .collect(),
            4 => self
                .mul
                .next_pc
                .iter()
                .map(|v| *v + self.mul_offset)
                .collect(),
            5 => self
                .div
                .next_pc
                .iter()
                .map(|v| *v + self.div_offset)
                .collect(),
            _ => self
                .sdiv
                .next_pc
                .iter()
                .map(|v| *v + self.sdiv_offset)
                .collect(),
        };
        for bit in 0..self.width {
            bits[self.pc[bit]] = (pc >> bit) & 1 == 1;
            bits[self.next_pc[bit]] = bits[next[bit]];
        }
        bits[self.select_alu] = selected == 0;
        bits[self.select_branch] = selected == 1;
        bits[self.select_mem] = selected == 2;
        bits[self.select_shift] = selected == 3;
        bits[self.select_mul] = selected == 4;
        bits[self.select_div] = selected == 5;
        bits[self.select_sdiv] = selected == 6;
        for bit in 0..self.width {
            bits[self.and_alu[bit]] = bits[self.select_alu] && bits[self.alu.next_pc[bit]];
            bits[self.and_branch[bit]] =
                bits[self.select_branch] && bits[self.branch.next_pc[bit] + self.branch_offset];
            bits[self.and_mem[bit]] =
                bits[self.select_mem] && bits[self.mem.next_pc[bit] + self.mem_offset];
            bits[self.and_shift[bit]] =
                bits[self.select_shift] && bits[self.shift.next_pc[bit] + self.shift_offset];
            bits[self.and_mul[bit]] =
                bits[self.select_mul] && bits[self.mul.next_pc[bit] + self.mul_offset];
            bits[self.and_div[bit]] =
                bits[self.select_div] && bits[self.div.next_pc[bit] + self.div_offset];
            bits[self.and_sdiv[bit]] =
                bits[self.select_sdiv] && bits[self.sdiv.next_pc[bit] + self.sdiv_offset];
        }
        bits
    }
}

impl GatedRowLike for MixedAluBranchRow {
    fn relation(&self) -> &BitRelation {
        &self.relation
    }
    fn packed_companion_system(&self) -> magnetar_constraint::ConstraintSystem {
        self.relation.to_system()
    }
    fn width(&self) -> usize {
        self.width
    }
    fn pc(&self) -> &[magnetar_constraint::VarId] {
        &self.pc
    }
    fn next_pc(&self) -> &[magnetar_constraint::VarId] {
        &self.next_pc
    }
    fn one(&self) -> magnetar_constraint::VarId {
        self.one
    }
}

pub fn prove_alu_branch_pc_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    backend: &B,
) -> Result<LockstepBatch<B>, RuntimeError> {
    use magnetar_proof::prove_lockstep_bits;

    let row = MixedAluBranchRow::new(width);
    let system = row.relation.to_system();
    let witness = row.relation.to_witness(&row.witness_at(
        initial_pc,
        &MixedAluBranchInput::Fetch {
            left: 0,
            right: 1,
            imm: 0,
            kind: crate::branch_row::BranchKind::Beq,
        },
    ));
    system
        .check(&witness)
        .map_err(|error| RuntimeError::Proof(format!("mixed row witness: {error}")))?;
    let (base_cols, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    let mut bits = Vec::with_capacity(cycles * base_cols);
    for index in 0..cycles {
        let pc = initial_pc + 4 * index as u64;
        let input = if index % 2 == 0 {
            MixedAluBranchInput::Fetch {
                left: index as u64,
                right: index as u64 + 1,
                imm: 0,
                kind: crate::branch_row::BranchKind::Beq,
            }
        } else {
            MixedAluBranchInput::Alu {
                left: index as u64,
                right: 3,
                op: crate::simd_f2::GatedAluOp::Add,
            }
        };
        let mut witness = row.witness_at(pc, &input);
        witness.resize(base_cols, false);
        bits.extend(witness);
    }
    let layout = segment_layout(bits.len())?;
    let proof = prove_lockstep_bits(
        &bits, &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], &layout, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((proof, layout))
}

pub fn verify_alu_branch_pc_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    proof: &LockstepProof<B::Commitment, B::Opening>,
    layout: &magnetar_constraint::WitnessLayout,
    backend: &B,
) -> Result<(), RuntimeError> {
    use magnetar_proof::verify_lockstep_bits;

    let row = MixedAluBranchRow::new(width);
    let (_, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    verify_lockstep_bits(
        &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], layout, proof, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(())
}

pub const MIXED_ALU: u8 = 1 << 0;
pub const MIXED_BRANCH: u8 = 1 << 1;
pub const MIXED_MEMORY: u8 = 1 << 2;
pub const MIXED_SHIFT: u8 = 1 << 3;
pub const MIXED_MULTIPLY: u8 = 1 << 4;
pub const MIXED_DIVIDE: u8 = 1 << 5;
pub const MIXED_SDIV: u8 = 1 << 6;
pub const MIXED_JUMP: u8 = 1 << 7;

pub fn mixed_rows_component_mask(rows: &[(u64, MixedAluBranchInput)]) -> u8 {
    rows.iter().fold(0u8, |mask, (_, input)| {
        mask | match input {
            MixedAluBranchInput::Alu { .. } => MIXED_ALU,
            MixedAluBranchInput::Fetch { .. } => MIXED_BRANCH,
            MixedAluBranchInput::Memory { .. } => MIXED_MEMORY,
            MixedAluBranchInput::Shift { .. } => MIXED_SHIFT,
            MixedAluBranchInput::Multiply { .. } => MIXED_MULTIPLY,
            MixedAluBranchInput::Divide { .. } => MIXED_DIVIDE,
            MixedAluBranchInput::SignedDivide { .. } => MIXED_SDIV,
            MixedAluBranchInput::Jump { .. } => MIXED_JUMP,
        }
    })
}

/// Number of witness variables in a dynamic mixed row for diagnostics.
pub fn mixed_row_relation_vars(mask: u8, width: usize) -> Result<usize, RuntimeError> {
    Ok(DynamicMixedRow::build(mask, width)?.relation.num_vars)
}

pub fn mixed_trace_component_mask(
    trace: &magnetar_spec::Trace,
    width: usize,
) -> Result<u8, RuntimeError> {
    Ok(mixed_rows_component_mask(
        &mixed_alu_branch_rows_from_trace(trace, width)?,
    ))
}

fn branch_taken(input: &MixedAluBranchInput) -> bool {
    let MixedAluBranchInput::Fetch {
        left,
        right,
        kind,
        ..
    } = input
    else {
        return false;
    };
    match kind {
        crate::branch_row::BranchKind::Beq => left == right,
        crate::branch_row::BranchKind::Bne => left != right,
        crate::branch_row::BranchKind::Blt => (*left as i64) < (*right as i64),
        crate::branch_row::BranchKind::Bge => (*left as i64) >= (*right as i64),
        crate::branch_row::BranchKind::Bltu => left < right,
        crate::branch_row::BranchKind::Bgeu => left >= right,
    }
}

pub(crate) fn row_pc_correction(
    row: Option<&magnetar_spec::TraceRow>,
    input: &MixedAluBranchInput,
) -> bool {
    let Some(row) = row else {
        return false;
    };
    if row.instruction_len != 2 {
        return false;
    }
    match input {
        MixedAluBranchInput::Jump { .. } => false,
        MixedAluBranchInput::Fetch { .. } => !branch_taken(input),
        _ => true,
    }
}

pub fn mixed_alu_branch_rows_from_trace(
    trace: &magnetar_spec::Trace,
    width: usize,
) -> Result<Vec<(u64, MixedAluBranchInput)>, RuntimeError> {
    mixed_alu_branch_rows_from_trace_mode(trace, width, false)
}

/// Dynamic-row mapping that encodes the halt/ecall row as a jump so the
/// smaller MIXED_JUMP component replaces the branch component.
pub fn mixed_alu_branch_rows_from_trace_dynamic(
    trace: &magnetar_spec::Trace,
    width: usize,
) -> Result<Vec<(u64, MixedAluBranchInput)>, RuntimeError> {
    mixed_alu_branch_rows_from_trace_mode(trace, width, true)
}

fn dynamic_padding_input(mask: u8, final_pc: u64) -> MixedAluBranchInput {
    if mask & MIXED_BRANCH != 0 {
        MixedAluBranchInput::Fetch {
            left: 0,
            right: 0,
            imm: 0,
            kind: crate::branch_row::BranchKind::Beq,
        }
    } else if mask & MIXED_JUMP != 0 {
        MixedAluBranchInput::Jump { target: final_pc }
    } else {
        MixedAluBranchInput::Alu {
            left: 0,
            right: 0,
            op: crate::simd_f2::GatedAluOp::Add,
        }
    }
}

fn mixed_alu_branch_rows_from_trace_mode(
    trace: &magnetar_spec::Trace,
    width: usize,
    halt_as_jump: bool,
) -> Result<Vec<(u64, MixedAluBranchInput)>, RuntimeError> {
    use crate::simd_f2::GatedCpuRowInput;

    let rows = crate::simd_full::gated_rows_from_trace_full(trace, width)?;
    rows.into_iter()
        .map(|(pc, input)| match input {
            GatedCpuRowInput::Alu {
                left,
                right,
                op: crate::simd_f2::GatedAluOp::Jal,
            }
            | GatedCpuRowInput::Alu {
                left,
                right,
                op: crate::simd_f2::GatedAluOp::Jalr,
            } => Ok((
                pc,
                MixedAluBranchInput::Jump {
                    target: left.wrapping_add(right) & !1,
                },
            )),
            GatedCpuRowInput::Alu { left, right, op } => {
                Ok((pc, MixedAluBranchInput::Alu { left, right, op }))
            }
            GatedCpuRowInput::Branch {
                left,
                right,
                imm,
                kind,
            } => {
                // The halt/ecall row is represented as a zero-condition branch
                // with a zero offset: its next PC is the current PC. Encode it
                // as a jump so the smaller MIXED_JUMP component is used instead
                // of the full branch component for the whole trace.
                if halt_as_jump
                    && left == 0
                    && right == 0
                    && imm == 0
                    && kind == crate::branch_row::BranchKind::Beq
                {
                    Ok((pc, MixedAluBranchInput::Jump { target: pc }))
                } else {
                    Ok((
                        pc,
                        MixedAluBranchInput::Fetch {
                            left,
                            right,
                            imm,
                            kind,
                        },
                    ))
                }
            }
            GatedCpuRowInput::Memory {
                rs1,
                imm,
                value,
                is_mem: true,
            } => Ok((pc, MixedAluBranchInput::Memory { rs1, imm, value })),
            GatedCpuRowInput::Shift { left, shamt, kind } => {
                Ok((pc, MixedAluBranchInput::Shift { left, shamt, kind }))
            }
            GatedCpuRowInput::Mul {
                left,
                right,
                high,
                signed_a,
                signed_b,
                ..
            } => Ok((
                pc,
                MixedAluBranchInput::Multiply {
                    left,
                    right,
                    high,
                    signed_a,
                    signed_b,
                },
            )),
            GatedCpuRowInput::Div { num, den, .. } => {
                Ok((pc, MixedAluBranchInput::Divide { num, den }))
            }
            GatedCpuRowInput::SDiv { num, den, .. } => {
                Ok((pc, MixedAluBranchInput::SignedDivide { num, den }))
            }
            other => Err(RuntimeError::Proof(format!(
                "mixed ALU+branch+memory row does not support {other:?}"
            ))),
        })
        .collect()
}

fn mixed_trace_bits(
    width: usize,
    rows: &[(u64, MixedAluBranchInput)],
    final_pc: u64,
) -> Result<(Vec<bool>, usize, usize, u64, u64), RuntimeError> {
    if rows.is_empty() {
        return Err(RuntimeError::Proof("empty mixed trace".into()));
    }
    let row = MixedAluBranchRow::new(width);
    let cycles = rows.len().next_power_of_two().max(2);
    let initial_pc = rows[0].0;
    let (base_cols, _, _) = gated_shared_matrices(&row, cycles, None)?;
    let mut bits = Vec::with_capacity(cycles * base_cols);
    for index in 0..cycles {
        let (pc, mut input) = if index < rows.len() {
            rows[index]
        } else {
            (
                final_pc,
                MixedAluBranchInput::Fetch {
                    left: 0,
                    right: 0,
                    imm: 0,
                    kind: crate::branch_row::BranchKind::Beq,
                },
            )
        };
        if index + 1 == rows.len() && final_pc == pc {
            input = MixedAluBranchInput::Fetch {
                left: 0,
                right: 0,
                imm: 0,
                kind: crate::branch_row::BranchKind::Beq,
            };
        }
        let mut instance = row.witness_at(pc, &input);
        instance.resize(base_cols, false);
        bits.extend(instance);
    }
    Ok((bits, cycles, row.relation.num_vars, initial_pc, final_pc))
}

pub fn prove_alu_branch_trace<B: magnetar_proof::BitPcs>(
    trace: &magnetar_spec::Trace,
    width: usize,
    backend: &B,
) -> Result<LockstepBatch<B>, RuntimeError> {
    use magnetar_proof::prove_lockstep_bits;

    let rows = mixed_alu_branch_rows_from_trace(trace, width)?;
    let final_pc = trace.final_state.pc;
    let (bits, cycles, _, initial_pc, _) = mixed_trace_bits(width, &rows, final_pc)?;
    let row = MixedAluBranchRow::new(width);
    let (base_cols, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    let layout = segment_layout(cycles * base_cols)?;
    let proof = prove_lockstep_bits(
        &bits, &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], &layout, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((proof, layout))
}

pub fn verify_alu_branch_trace<B: magnetar_proof::BitPcs>(
    trace: &magnetar_spec::Trace,
    proof: &LockstepProof<B::Commitment, B::Opening>,
    layout: &magnetar_constraint::WitnessLayout,
    width: usize,
    backend: &B,
) -> Result<(), RuntimeError> {
    use magnetar_proof::verify_lockstep_bits;

    let rows = mixed_alu_branch_rows_from_trace(trace, width)?;
    let (bits, cycles, _, initial_pc, _) = mixed_trace_bits(width, &rows, trace.final_state.pc)?;
    let expected = backend
        .commit(&bits)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    if backend.commitment_bytes(&expected) != backend.commitment_bytes(&proof.commitment) {
        return Err(RuntimeError::Proof(
            "mixed selected CPU witness does not match the proof commitment".into(),
        ));
    }
    let final_pc = trace.final_state.pc;
    let row = MixedAluBranchRow::new(width);
    let (_, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    verify_lockstep_bits(
        &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], layout, proof, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(())
}

struct SmallAluBranchRow {
    width: usize,
    alu: AluPcRow,
    branch: BranchPcRow,
    mem: Option<MemPcRow>,
    branch_offset: usize,
    mem_offset: usize,
    pc: Vec<magnetar_constraint::VarId>,
    next_pc: Vec<magnetar_constraint::VarId>,
    select_alu: magnetar_constraint::VarId,
    select_branch: magnetar_constraint::VarId,
    select_mem: Option<magnetar_constraint::VarId>,
    and_alu: Vec<magnetar_constraint::VarId>,
    and_branch: Vec<magnetar_constraint::VarId>,
    and_mem: Option<Vec<magnetar_constraint::VarId>>,
    one: magnetar_constraint::VarId,
    relation: BitRelation,
}

impl SmallAluBranchRow {
    fn new(width: usize, with_memory: bool) -> Self {
        use magnetar_constraint::VarId;
        let alu = AluPcRow::new(width);
        let branch = BranchPcRow::new(width);
        let mem = with_memory.then(|| MemPcRow::new(width));
        let branch_offset = alu.relation.num_vars;
        let mem_offset = branch_offset + branch.relation.num_vars;
        let mut relation = alu.relation.clone();
        relation.num_vars += branch.relation.num_vars;
        if let Some(mem) = &mem {
            relation.num_vars += mem.relation.num_vars;
        }
        for (source, offset) in [
            (&branch.relation, branch_offset),
            #[allow(clippy::unnecessary_lazy_evaluations)]
            (
                mem.as_ref()
                    .map(|m| &m.relation)
                    .unwrap_or(&branch.relation),
                mem_offset,
            ),
        ] {
            if !with_memory && offset == mem_offset {
                continue;
            }
            for row in &source.rows {
                let shift = |vars: &[VarId]| vars.iter().map(|v| *v + offset).collect::<Vec<_>>();
                relation.add(BitRow::new(shift(&row.a), shift(&row.b), shift(&row.c)));
            }
        }
        let take = |relation: &mut BitRelation, n: usize| {
            let start = relation.num_vars;
            relation.num_vars += n;
            (start..start + n).map(|v| v as VarId).collect::<Vec<_>>()
        };
        let pc = take(&mut relation, width);
        let next_pc = take(&mut relation, width);
        let select_alu = relation.num_vars as VarId;
        let select_branch = select_alu + 1;
        let select_mem = with_memory.then_some(select_alu + 2);
        relation.num_vars += if with_memory { 3 } else { 2 };
        let and_alu = take(&mut relation, width);
        let and_branch = take(&mut relation, width);
        let and_mem = with_memory.then(|| take(&mut relation, width));
        let one = alu.instr.one;
        for bit in 0..width {
            relation.add(BitRow::new(vec![pc[bit]], vec![pc[bit]], vec![pc[bit]]));
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![next_pc[bit]],
                vec![next_pc[bit]],
            ));
            relation.add(BitRow::new(vec![alu.pc[bit]], vec![one], vec![pc[bit]]));
            relation.add(BitRow::new(
                vec![branch.pc[bit] + branch_offset],
                vec![one],
                vec![pc[bit]],
            ));
            relation.add(BitRow::new(
                vec![select_alu],
                vec![alu.next_pc[bit]],
                vec![and_alu[bit]],
            ));
            relation.add(BitRow::new(
                vec![select_branch],
                vec![branch.next_pc[bit] + branch_offset],
                vec![and_branch[bit]],
            ));
            let mut next_terms = vec![and_alu[bit], and_branch[bit]];
            if let (Some(mem), Some(select), Some(and)) = (&mem, select_mem, &and_mem) {
                relation.add(BitRow::new(
                    vec![mem.pc[bit] + mem_offset],
                    vec![one],
                    vec![pc[bit]],
                ));
                relation.add(BitRow::new(
                    vec![select],
                    vec![mem.next_pc[bit] + mem_offset],
                    vec![and[bit]],
                ));
                next_terms.push(and[bit]);
            }
            relation.add(BitRow::new(vec![next_pc[bit]], vec![one], next_terms));
        }
        relation.add(BitRow::new(
            vec![select_alu],
            vec![select_alu],
            vec![select_alu],
        ));
        relation.add(BitRow::new(
            vec![select_branch],
            vec![select_branch],
            vec![select_branch],
        ));
        if let Some(select) = select_mem {
            relation.add(BitRow::new(vec![select], vec![select], vec![select]));
        }
        let mut selectors = vec![select_alu, select_branch];
        if let Some(select) = select_mem {
            selectors.push(select);
        }
        relation.add(BitRow::new(selectors, vec![one], vec![one]));
        Self {
            width,
            alu,
            branch,
            mem,
            branch_offset,
            mem_offset,
            pc,
            next_pc,
            select_alu,
            select_branch,
            select_mem,
            and_alu,
            and_branch,
            and_mem,
            one,
            relation,
        }
    }

    fn witness_at(
        &self,
        pc: u64,
        input: &MixedAluBranchInput,
        _pc_correction: bool,
    ) -> Result<Vec<bool>, RuntimeError> {
        let (left, right, op) = match input {
            MixedAluBranchInput::Alu { left, right, op } => (*left, *right, *op),
            _ => (0, 0, crate::simd_f2::GatedAluOp::Add),
        };
        let (bl, br, imm, kind) = match input {
            MixedAluBranchInput::Fetch {
                left,
                right,
                imm,
                kind,
            } => (*left, *right, *imm, *kind),
            _ => (0, 1, 0, crate::branch_row::BranchKind::Beq),
        };
        let (rs1, mem_imm, value) = match input {
            MixedAluBranchInput::Memory { rs1, imm, value } => (*rs1, *imm, *value),
            _ => (0x10, 0, 0x40),
        };
        if matches!(input, MixedAluBranchInput::Memory { .. }) && self.mem.is_none() {
            return Err(RuntimeError::Proof(
                "small row was built without a memory component".into(),
            ));
        }
        let mut bits = self.alu.witness_at(pc, left, right, op);
        bits.extend(self.branch.witness_at(pc, imm, bl, br, kind));
        if let Some(mem) = &self.mem {
            bits.extend(mem.witness_at(pc, rs1, mem_imm, value));
        }
        bits.resize(self.relation.num_vars, false);
        let selected = match input {
            MixedAluBranchInput::Alu { .. } => 0usize,
            MixedAluBranchInput::Fetch { .. } => 1,
            MixedAluBranchInput::Memory { .. } => 2,
            _ => {
                return Err(RuntimeError::Proof(
                    "small row only supports ALU/branch/memory".into(),
                ))
            }
        };
        bits[self.select_alu] = selected == 0;
        bits[self.select_branch] = selected == 1;
        if let Some(select) = self.select_mem {
            bits[select] = selected == 2;
        }
        for bit in 0..self.width {
            bits[self.pc[bit]] = (pc >> bit) & 1 == 1;
        }
        for bit in 0..self.width {
            bits[self.and_alu[bit]] = bits[self.select_alu] && bits[self.alu.next_pc[bit]];
            bits[self.and_branch[bit]] =
                bits[self.select_branch] && bits[self.branch.next_pc[bit] + self.branch_offset];
            if let (Some(mem), Some(and), Some(select)) =
                (&self.mem, &self.and_mem, self.select_mem)
            {
                bits[and[bit]] = bits[select] && bits[mem.next_pc[bit] + self.mem_offset];
            }
        }
        let mut next_value = vec![false; self.width];
        for bit in 0..self.width {
            next_value[bit] = bits[self.and_alu[bit]] ^ bits[self.and_branch[bit]];
            if let Some(and) = &self.and_mem {
                next_value[bit] ^= bits[and[bit]];
            }
            bits[self.next_pc[bit]] = next_value[bit];
        }
        Ok(bits)
    }
}

impl GatedRowLike for SmallAluBranchRow {
    fn relation(&self) -> &BitRelation {
        &self.relation
    }
    fn packed_companion_system(&self) -> magnetar_constraint::ConstraintSystem {
        self.relation.to_system()
    }
    fn width(&self) -> usize {
        self.width
    }
    fn pc(&self) -> &[magnetar_constraint::VarId] {
        &self.pc
    }
    fn next_pc(&self) -> &[magnetar_constraint::VarId] {
        &self.next_pc
    }
    fn one(&self) -> magnetar_constraint::VarId {
        self.one
    }
}

fn small_trace_bits(
    width: usize,
    rows: &[(u64, MixedAluBranchInput)],
    final_pc: u64,
    with_memory: bool,
) -> Result<(Vec<bool>, usize, u64), RuntimeError> {
    let row = SmallAluBranchRow::new(width, with_memory);
    let cycles = rows.len().next_power_of_two().max(2);
    let initial_pc = rows[0].0;
    let (base_cols, _, _) = gated_shared_matrices(&row, cycles, None)?;
    let mut bits = Vec::with_capacity(cycles * base_cols);
    for index in 0..cycles {
        let (pc, mut input) = if index < rows.len() {
            rows[index]
        } else {
            (
                final_pc,
                MixedAluBranchInput::Fetch {
                    left: 0,
                    right: 0,
                    imm: 0,
                    kind: crate::branch_row::BranchKind::Beq,
                },
            )
        };
        if index + 1 == rows.len() && final_pc == pc {
            input = MixedAluBranchInput::Fetch {
                left: 0,
                right: 0,
                imm: 0,
                kind: crate::branch_row::BranchKind::Beq,
            };
        }
        let mut instance = row.witness_at(pc, &input, false)?;
        instance.resize(base_cols, false);
        bits.extend(instance);
    }
    Ok((bits, cycles, initial_pc))
}

pub fn prove_small_alu_branch_trace<B: magnetar_proof::BitPcs>(
    trace: &magnetar_spec::Trace,
    width: usize,
    backend: &B,
) -> Result<LockstepBatch<B>, RuntimeError> {
    use magnetar_proof::prove_lockstep_bits;

    let rows = mixed_alu_branch_rows_from_trace(trace, width)?;
    let mask = mixed_rows_component_mask(&rows);
    if mask & !(MIXED_ALU | MIXED_BRANCH | MIXED_MEMORY) != 0 {
        return Err(RuntimeError::Proof(
            "small row only supports ALU/branch/memory rows".into(),
        ));
    }
    let with_memory = mask & MIXED_MEMORY != 0;
    let final_pc = trace.final_state.pc;
    let (bits, cycles, initial_pc) = small_trace_bits(width, &rows, final_pc, with_memory)?;
    let row = SmallAluBranchRow::new(width, with_memory);
    let (base_cols, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    let layout = segment_layout(cycles * base_cols)?;
    let proof = prove_lockstep_bits(
        &bits, &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], &layout, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((proof, layout))
}

pub fn verify_small_alu_branch_trace<B: magnetar_proof::BitPcs>(
    trace: &magnetar_spec::Trace,
    proof: &LockstepProof<B::Commitment, B::Opening>,
    layout: &magnetar_constraint::WitnessLayout,
    width: usize,
    backend: &B,
) -> Result<(), RuntimeError> {
    use magnetar_proof::verify_lockstep_bits;

    let rows = mixed_alu_branch_rows_from_trace(trace, width)?;
    let mask = mixed_rows_component_mask(&rows);
    if mask & !(MIXED_ALU | MIXED_BRANCH | MIXED_MEMORY) != 0 {
        return Err(RuntimeError::Proof(
            "small row only supports ALU/branch/memory rows".into(),
        ));
    }
    let with_memory = mask & MIXED_MEMORY != 0;
    let final_pc = trace.final_state.pc;
    let (bits, cycles, initial_pc) = small_trace_bits(width, &rows, final_pc, with_memory)?;
    let expected = backend
        .commit(&bits)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    if backend.commitment_bytes(&expected) != backend.commitment_bytes(&proof.commitment) {
        return Err(RuntimeError::Proof(
            "small ALU+branch witness does not match the proof commitment".into(),
        ));
    }
    let row = SmallAluBranchRow::new(width, with_memory);
    let (_, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    verify_lockstep_bits(
        &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], layout, proof, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SelectedSegmentClaim {
    pub name: String,
    pub owner: SegmentOwner,
    pub value: magnetar_constraint::F2_128,
}

pub fn selected_segment_claims<C, O>(
    layout: &magnetar_constraint::WitnessLayout,
    proof: &LockstepProof<C, O>,
) -> Result<Vec<SelectedSegmentClaim>, RuntimeError>
where
    C: Clone + std::fmt::Debug,
    O: Clone + std::fmt::Debug,
{
    if layout.segments.len() != proof.segments.len() {
        return Err(RuntimeError::Proof(format!(
            "selected segment claim count mismatch: layout={} proof={}",
            layout.segments.len(),
            proof.segments.len()
        )));
    }
    Ok(layout
        .segments
        .iter()
        .zip(&proof.segments)
        .map(|(segment, claim)| SelectedSegmentClaim {
            name: segment.name.clone(),
            owner: segment.owner,
            value: claim.value,
        })
        .collect())
}

pub fn selected_claim_values_by_owner<C, O>(
    layout: &magnetar_constraint::WitnessLayout,
    proof: &LockstepProof<C, O>,
    owner: SegmentOwner,
) -> Result<Vec<magnetar_constraint::F2_128>, RuntimeError>
where
    C: Clone + std::fmt::Debug,
    O: Clone + std::fmt::Debug,
{
    Ok(selected_segment_claims(layout, proof)?
        .into_iter()
        .filter(|claim| claim.owner == owner)
        .map(|claim| claim.value)
        .collect())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SelectedOp {
    Alu,
    Shift,
    Memory,
    Multiply,
    Divide,
    Branch,
    Dynamic,
}

type SelectedLayoutTuple = (
    usize,
    Vec<(
        usize,
        usize,
        magnetar_constraint::SegmentKind,
        magnetar_constraint::SegmentOwner,
    )>,
);

fn serialize_selected_layout<S>(
    layout: &magnetar_constraint::WitnessLayout,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let segments = layout
        .segments
        .iter()
        .map(|segment| (segment.offset, segment.len, segment.kind, segment.owner))
        .collect::<Vec<_>>();
    (layout.total_bits, segments).serialize(serializer)
}

fn deserialize_selected_layout<'de, D>(
    deserializer: D,
) -> Result<magnetar_constraint::WitnessLayout, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let (total_bits, segments) = SelectedLayoutTuple::deserialize(deserializer)?;
    let segments = segments
        .into_iter()
        .enumerate()
        .map(|(index, (offset, len, kind, owner))| {
            magnetar_constraint::Segment::new(format!("s{index}"), offset, len, kind, owner)
        })
        .collect();
    Ok(magnetar_constraint::WitnessLayout {
        total_bits,
        segments,
    })
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(
    bound = "C: serde::Serialize + serde::de::DeserializeOwned, O: serde::Serialize + serde::de::DeserializeOwned"
)]
pub struct SelectedCpuClaims<C: Clone + std::fmt::Debug, O: Clone + std::fmt::Debug> {
    pub op: SelectedOp,
    pub width: usize,
    pub cycles: usize,
    #[serde(default)]
    pub matrix_cycles: usize,
    #[serde(default)]
    pub mask: u8,
    pub initial_pc: u64,
    pub final_pc: u64,
    #[serde(
        serialize_with = "serialize_selected_layout",
        deserialize_with = "deserialize_selected_layout"
    )]
    pub layout: magnetar_constraint::WitnessLayout,
    #[serde(skip)]
    pub segments: Vec<SelectedSegmentClaim>,
    #[serde(default)]
    pub claim_root: [u8; 32],
    #[serde(skip)]
    pub claim_openings: Vec<crate::trace_claims::TraceClaimOpening>,
    pub proof: LockstepProof<C, O>,
}

/// Verify a selected CPU claim bundle against an independent claim proof,
/// returning the authenticated row claims without reading the trace.
pub fn verify_selected_claim_proof<C: Clone + std::fmt::Debug, O: Clone + std::fmt::Debug>(
    claims: &SelectedCpuClaims<C, O>,
    proof: &crate::trace_claims::ClaimProof,
) -> Option<Vec<crate::trace_claims::TraceClaim>> {
    if !verify_selected_claim_binding(claims, proof) {
        return None;
    }
    proof.verify()
}

/// Check that authenticated row claims agree with the selected CPU claim
/// statement: row count, initial/final PC and consecutive PC linkage.
pub fn verify_selected_claim_consistency<C: Clone + std::fmt::Debug, O: Clone + std::fmt::Debug>(
    claims: &SelectedCpuClaims<C, O>,
    rows: &[crate::trace_claims::TraceClaim],
) -> Result<(), RuntimeError> {
    if rows.is_empty() {
        return Err(RuntimeError::Proof("claim rows are empty".into()));
    }
    let cycles = rows.len().next_power_of_two().max(2);
    if claims.cycles != cycles {
        return Err(RuntimeError::Proof("claim cycle count mismatch".into()));
    }
    if claims.initial_pc != rows[0].pc || claims.final_pc != rows[rows.len() - 1].next_pc {
        return Err(RuntimeError::Proof("claim PC statement mismatch".into()));
    }
    for pair in rows.windows(2) {
        if pair[0].next_pc != pair[1].pc {
            return Err(RuntimeError::Proof("claim PC linkage mismatch".into()));
        }
    }
    if rows.iter().any(|row| !matches!(row.instruction_len, 2 | 4)) {
        return Err(RuntimeError::Proof(
            "claim instruction length mismatch".into(),
        ));
    }
    Ok(())
}

/// Bind a selected CPU claim bundle to an independently serialized claim proof.
pub fn verify_selected_claim_binding<C: Clone + std::fmt::Debug, O: Clone + std::fmt::Debug>(
    claims: &SelectedCpuClaims<C, O>,
    proof: &crate::trace_claims::ClaimProof,
) -> bool {
    if claims.claim_root != proof.root {
        return false;
    }
    let selected = crate::trace_claims::verify_claims(claims.claim_root, &claims.claim_openings);
    let canonical = proof.verify();
    selected.is_some() && selected == canonical
}

/// Verify the trace claim openings carried by a selected CPU claim bundle
/// without reading `trace.rows`.
pub fn verify_selected_claim_openings<C: Clone + std::fmt::Debug, O: Clone + std::fmt::Debug>(
    claims: &SelectedCpuClaims<C, O>,
) -> Option<Vec<crate::trace_claims::TraceClaim>> {
    if claims.claim_openings.is_empty() {
        return None;
    }
    crate::trace_claims::verify_claims(claims.claim_root, &claims.claim_openings)
}

pub fn prove_selected_cpu_claims<B: magnetar_proof::BitPcs>(
    op: SelectedOp,
    width: usize,
    cycles: usize,
    initial_pc: u64,
    final_pc: u64,
    backend: &B,
) -> Result<SelectedCpuClaims<B::Commitment, B::Opening>, RuntimeError> {
    let (proof, layout) = match op {
        SelectedOp::Alu => {
            prove_alu_pc_segmented_batch_bits(width, cycles, initial_pc, final_pc, backend)?
        }
        SelectedOp::Shift => {
            prove_shift_pc_segmented_batch_bits(width, cycles, initial_pc, final_pc, backend)?
        }
        SelectedOp::Memory => {
            prove_mem_pc_segmented_batch_bits(width, cycles, initial_pc, final_pc, backend)?
        }
        SelectedOp::Multiply => {
            prove_mul_pc_segmented_batch_bits(width, cycles, initial_pc, final_pc, backend)?
        }
        SelectedOp::Divide => {
            prove_div_pc_segmented_batch_bits(width, cycles, initial_pc, final_pc, backend)?
        }
        SelectedOp::Branch => {
            prove_branch_pc_segmented_batch_bits(width, cycles, initial_pc, final_pc, backend)?
        }
        SelectedOp::Dynamic => {
            return Err(RuntimeError::Proof(
                "dynamic selected claims must be built from a trace".into(),
            ))
        }
    };
    let segments = selected_segment_claims(&layout, &proof)?;
    Ok(SelectedCpuClaims {
        op,
        width,
        cycles,
        matrix_cycles: cycles,
        mask: 0,
        initial_pc,
        final_pc,
        layout,
        segments,
        claim_root: [0u8; 32],
        claim_openings: Vec::new(),
        proof,
    })
}

pub fn verify_selected_cpu_claims<B: magnetar_proof::BitPcs>(
    claims: &SelectedCpuClaims<B::Commitment, B::Opening>,
    backend: &B,
) -> Result<(), RuntimeError> {
    if !claims.segments.is_empty() {
        let expected = selected_segment_claims(&claims.layout, &claims.proof)?;
        let matches = expected.len() == claims.segments.len()
            && expected
                .iter()
                .zip(&claims.segments)
                .all(|(left, right)| left.owner == right.owner && left.value == right.value);
        if !matches {
            return Err(RuntimeError::Proof(
                "selected CPU claim segments do not match the proof".into(),
            ));
        }
    }
    let (width, cycles) = (claims.width, claims.cycles);
    match claims.op {
        SelectedOp::Alu => verify_alu_pc_segmented_batch_bits(
            width,
            cycles,
            claims.initial_pc,
            claims.final_pc,
            &claims.proof,
            &claims.layout,
            backend,
        ),
        SelectedOp::Shift => verify_shift_pc_segmented_batch_bits(
            width,
            cycles,
            claims.initial_pc,
            claims.final_pc,
            &claims.proof,
            &claims.layout,
            backend,
        ),
        SelectedOp::Memory => verify_mem_pc_segmented_batch_bits(
            width,
            cycles,
            claims.initial_pc,
            claims.final_pc,
            &claims.proof,
            &claims.layout,
            backend,
        ),
        SelectedOp::Multiply => verify_mul_pc_segmented_batch_bits(
            width,
            cycles,
            claims.initial_pc,
            claims.final_pc,
            &claims.proof,
            &claims.layout,
            backend,
        ),
        SelectedOp::Divide => verify_div_pc_segmented_batch_bits(
            width,
            cycles,
            claims.initial_pc,
            claims.final_pc,
            &claims.proof,
            &claims.layout,
            backend,
        ),
        SelectedOp::Branch => verify_branch_pc_segmented_batch_bits(
            width,
            cycles,
            claims.initial_pc,
            claims.final_pc,
            &claims.proof,
            &claims.layout,
            backend,
        ),
        SelectedOp::Dynamic => Err(RuntimeError::Proof(
            "dynamic selected claims require the trace to verify".into(),
        )),
    }
}

pub fn prove_dynamic_cpu_claims<B: magnetar_proof::BitPcs>(
    trace: &magnetar_spec::Trace,
    width: usize,
    backend: &B,
) -> Result<SelectedCpuClaims<B::Commitment, B::Opening>, RuntimeError> {
    let (proof, layout, mask, cycles) = prove_dynamic_segmented_trace(trace, width, backend)?;
    let segments = selected_segment_claims(&layout, &proof)?;
    let claim_tree = crate::trace_claims::TraceClaimTree::build(trace);
    let claim_openings = (0..trace.rows.len())
        .filter_map(|index| claim_tree.open(index))
        .collect();
    // The layout is reconstructed by the verifier from the trace, so do not
    // serialize the per-cycle layout in the dynamic proof.
    let layout = magnetar_constraint::WitnessLayout {
        total_bits: 0,
        segments: Vec::new(),
    };
    Ok(SelectedCpuClaims {
        op: SelectedOp::Dynamic,
        width,
        cycles: trace.rows.len().next_power_of_two().max(2),
        matrix_cycles: cycles,
        mask,
        initial_pc: trace.rows[0].pc,
        final_pc: trace.final_state.pc,
        layout,
        segments,
        claim_root: claim_tree.root(),
        claim_openings,
        proof,
    })
}

pub fn verify_dynamic_cpu_claims<B: magnetar_proof::BitPcs + Sync>(
    trace: &magnetar_spec::Trace,
    claims: &SelectedCpuClaims<B::Commitment, B::Opening>,
    backend: &B,
) -> Result<(), RuntimeError>
where
    B::Commitment: Sync,
    B::Opening: Sync,
{
    if claims.op != SelectedOp::Dynamic {
        return Err(RuntimeError::Proof(
            "not a dynamic selected claim bundle".into(),
        ));
    }
    if !claims.claim_openings.is_empty() {
        let claim_tree = crate::trace_claims::TraceClaimTree::build(trace);
        if claims.claim_root != claim_tree.root()
            || claims.claim_openings.len() != trace.rows.len()
            || crate::trace_claims::verify_claims(claims.claim_root, &claims.claim_openings)
                .is_none()
        {
            return Err(RuntimeError::Proof(
                "dynamic selected claim openings do not match the trace".into(),
            ));
        }
    }
    if !claims.layout.segments.is_empty() && !claims.segments.is_empty() {
        let expected = selected_segment_claims(&claims.layout, &claims.proof)?;
        if expected != claims.segments {
            return Err(RuntimeError::Proof(
                "dynamic selected claim segments do not match the proof".into(),
            ));
        }
    }
    verify_dynamic_segmented_trace(trace, &claims.proof, &claims.layout, claims.width, backend)
}

struct JumpPcRow {
    width: usize,
    pc_add: crate::simd_f2::GatedBitAdder,
    pc: Vec<magnetar_constraint::VarId>,
    next_pc: Vec<magnetar_constraint::VarId>,
    target: Vec<magnetar_constraint::VarId>,
    link: Vec<magnetar_constraint::VarId>,
    one: magnetar_constraint::VarId,
    relation: BitRelation,
}

impl JumpPcRow {
    fn new(width: usize) -> Self {
        use magnetar_constraint::VarId;
        let pc_add = crate::simd_f2::GatedBitAdder::new(width);
        let mut relation = pc_add.relation.clone();
        let take = |relation: &mut BitRelation, n: usize| {
            let start = relation.num_vars;
            relation.num_vars += n;
            (start..start + n)
                .map(|var| var as VarId)
                .collect::<Vec<_>>()
        };
        let pc = take(&mut relation, width);
        let next_pc = take(&mut relation, width);
        let target = take(&mut relation, width);
        let link = take(&mut relation, width);
        let one = (3 * width + 1) as VarId;
        for bit in 0..width {
            relation.add(BitRow::new(vec![pc[bit]], vec![pc[bit]], vec![pc[bit]]));
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![next_pc[bit]],
                vec![next_pc[bit]],
            ));
            relation.add(BitRow::new(
                vec![target[bit]],
                vec![target[bit]],
                vec![target[bit]],
            ));
            relation.add(BitRow::new(
                vec![link[bit]],
                vec![link[bit]],
                vec![link[bit]],
            ));
            relation.add(BitRow::new(
                vec![pc[bit]],
                vec![one],
                vec![pc_add.a[bit] as VarId],
            ));
            relation.add(BitRow::new(
                vec![link[bit]],
                vec![one],
                vec![pc_add.out[bit] as VarId],
            ));
            let constant = pc_add.b[bit] as VarId;
            if bit == 2 {
                relation.add(BitRow::new(vec![constant], vec![one], vec![one]));
            } else {
                relation.add(BitRow::new(vec![constant], vec![one], Vec::new()));
            }
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![one],
                vec![target[bit]],
            ));
        }
        relation.add(BitRow::new(
            vec![pc_add.gate as VarId],
            vec![one],
            vec![one],
        ));
        Self {
            width,
            pc_add,
            pc,
            next_pc,
            target,
            link,
            one,
            relation,
        }
    }

    fn witness_bits(&self, pc: u64, target: u64) -> Vec<bool> {
        // Always drive the adder gate high so the relation holds for inactive
        // rows too; inactive rows are ignored by the selector/PC mux.
        let mut bits = self.pc_add.witness(pc, 4, true);
        bits.resize(self.relation.num_vars, false);
        for bit in 0..self.width {
            bits[self.pc[bit]] = (pc >> bit) & 1 == 1;
            bits[self.link[bit]] = ((pc + 4) >> bit) & 1 == 1;
            bits[self.target[bit]] = (target >> bit) & 1 == 1;
            bits[self.next_pc[bit]] = (target >> bit) & 1 == 1;
        }
        bits
    }

    fn witness_at(&self, pc: u64, target: u64) -> Vec<bool> {
        self.witness_bits(pc, target)
    }
}

impl PcComponent for JumpPcRow {
    fn kind(&self) -> u8 {
        MIXED_JUMP
    }
    fn relation(&self) -> &BitRelation {
        &self.relation
    }
    fn pc(&self) -> &[magnetar_constraint::VarId] {
        &self.pc
    }
    fn next_pc(&self) -> &[magnetar_constraint::VarId] {
        &self.next_pc
    }
    fn one(&self) -> magnetar_constraint::VarId {
        self.one
    }
    fn witness(&self, pc: u64, input: &MixedAluBranchInput) -> Result<Vec<bool>, RuntimeError> {
        match input {
            MixedAluBranchInput::Jump { target } => Ok(self.witness_at(pc, *target)),
            _ => Ok(self.witness_bits(pc, 0)),
        }
    }
}

trait PcComponent: Sync {
    fn kind(&self) -> u8;
    fn relation(&self) -> &BitRelation;
    fn pc(&self) -> &[magnetar_constraint::VarId];
    fn next_pc(&self) -> &[magnetar_constraint::VarId];
    fn one(&self) -> magnetar_constraint::VarId;
    fn witness(&self, pc: u64, input: &MixedAluBranchInput) -> Result<Vec<bool>, RuntimeError>;
}

impl PcComponent for AluPcRow {
    fn kind(&self) -> u8 {
        MIXED_ALU
    }
    fn relation(&self) -> &BitRelation {
        &self.relation
    }
    fn pc(&self) -> &[magnetar_constraint::VarId] {
        &self.pc
    }
    fn next_pc(&self) -> &[magnetar_constraint::VarId] {
        &self.next_pc
    }
    fn one(&self) -> magnetar_constraint::VarId {
        self.instr.one
    }
    fn witness(&self, pc: u64, input: &MixedAluBranchInput) -> Result<Vec<bool>, RuntimeError> {
        Ok(match input {
            MixedAluBranchInput::Alu { left, right, op } => self.witness_at(pc, *left, *right, *op),
            _ => self.witness_at(pc, 0, 0, crate::simd_f2::GatedAluOp::Inactive),
        })
    }
}

impl PcComponent for BranchPcRow {
    fn kind(&self) -> u8 {
        MIXED_BRANCH
    }
    fn relation(&self) -> &BitRelation {
        &self.relation
    }
    fn pc(&self) -> &[magnetar_constraint::VarId] {
        &self.pc
    }
    fn next_pc(&self) -> &[magnetar_constraint::VarId] {
        &self.next_pc
    }
    fn one(&self) -> magnetar_constraint::VarId {
        self.instr.one
    }
    fn witness(&self, pc: u64, input: &MixedAluBranchInput) -> Result<Vec<bool>, RuntimeError> {
        Ok(match input {
            MixedAluBranchInput::Fetch {
                left,
                right,
                imm,
                kind,
            } => self.witness_at(pc, *imm, *left, *right, *kind),
            _ => self.witness_at(pc, 0, 0, 1, crate::branch_row::BranchKind::Beq),
        })
    }
}

impl PcComponent for MemPcRow {
    fn kind(&self) -> u8 {
        MIXED_MEMORY
    }
    fn relation(&self) -> &BitRelation {
        &self.relation
    }
    fn pc(&self) -> &[magnetar_constraint::VarId] {
        &self.pc
    }
    fn next_pc(&self) -> &[magnetar_constraint::VarId] {
        &self.next_pc
    }
    fn one(&self) -> magnetar_constraint::VarId {
        self.instr.adder.gate
    }
    fn witness(&self, pc: u64, input: &MixedAluBranchInput) -> Result<Vec<bool>, RuntimeError> {
        Ok(match input {
            MixedAluBranchInput::Memory { rs1, imm, value } => {
                self.witness_at(pc, *rs1, *imm, *value)
            }
            _ => self.witness_at(pc, 0x10, 0, 0x40),
        })
    }
}

impl PcComponent for ShiftPcRow {
    fn kind(&self) -> u8 {
        MIXED_SHIFT
    }
    fn relation(&self) -> &BitRelation {
        &self.relation
    }
    fn pc(&self) -> &[magnetar_constraint::VarId] {
        &self.pc
    }
    fn next_pc(&self) -> &[magnetar_constraint::VarId] {
        &self.next_pc
    }
    fn one(&self) -> magnetar_constraint::VarId {
        self.instr.one
    }
    fn witness(&self, pc: u64, input: &MixedAluBranchInput) -> Result<Vec<bool>, RuntimeError> {
        Ok(match input {
            MixedAluBranchInput::Shift { left, shamt, kind } => {
                self.witness_at(pc, *left, *shamt, *kind)
            }
            _ => self.witness_at(pc, 0x12, 2, crate::simd_f2::BitShiftKind::Sll),
        })
    }
}

impl PcComponent for MulPcRow {
    fn kind(&self) -> u8 {
        MIXED_MULTIPLY
    }
    fn relation(&self) -> &BitRelation {
        &self.relation
    }
    fn pc(&self) -> &[magnetar_constraint::VarId] {
        &self.pc
    }
    fn next_pc(&self) -> &[magnetar_constraint::VarId] {
        &self.next_pc
    }
    fn one(&self) -> magnetar_constraint::VarId {
        self.instr.one
    }
    fn witness(&self, pc: u64, input: &MixedAluBranchInput) -> Result<Vec<bool>, RuntimeError> {
        Ok(match input {
            MixedAluBranchInput::Multiply {
                left,
                right,
                high,
                signed_a,
                signed_b,
            } => self.witness_with_flags(pc, *left, *right, *high, *signed_a, *signed_b),
            _ => self.witness_at(pc, 0x12, 0x34),
        })
    }
}

impl PcComponent for DivPcRow {
    fn kind(&self) -> u8 {
        MIXED_DIVIDE
    }
    fn relation(&self) -> &BitRelation {
        &self.relation
    }
    fn pc(&self) -> &[magnetar_constraint::VarId] {
        &self.pc
    }
    fn next_pc(&self) -> &[magnetar_constraint::VarId] {
        &self.next_pc
    }
    fn one(&self) -> magnetar_constraint::VarId {
        self.one
    }
    fn witness(&self, pc: u64, input: &MixedAluBranchInput) -> Result<Vec<bool>, RuntimeError> {
        Ok(match input {
            MixedAluBranchInput::Divide { num, den } => self.witness_at(pc, *num, *den),
            _ => self.witness_at(pc, 0x60, 3),
        })
    }
}

impl PcComponent for SDivPcRow {
    fn kind(&self) -> u8 {
        MIXED_SDIV
    }
    fn relation(&self) -> &BitRelation {
        &self.relation
    }
    fn pc(&self) -> &[magnetar_constraint::VarId] {
        &self.pc
    }
    fn next_pc(&self) -> &[magnetar_constraint::VarId] {
        &self.next_pc
    }
    fn one(&self) -> magnetar_constraint::VarId {
        self.one
    }
    fn witness(&self, pc: u64, input: &MixedAluBranchInput) -> Result<Vec<bool>, RuntimeError> {
        Ok(match input {
            MixedAluBranchInput::SignedDivide { num, den } => self.witness_at(pc, *num, *den),
            _ => self.witness_at(pc, 0x20, 3),
        })
    }
}

struct DynamicMixedRow {
    width: usize,
    components: Vec<Box<dyn PcComponent>>,
    offsets: Vec<usize>,
    pc: Vec<magnetar_constraint::VarId>,
    next_pc: Vec<magnetar_constraint::VarId>,
    raw_next: Vec<magnetar_constraint::VarId>,
    pc_correction: magnetar_constraint::VarId,
    pc_step_add: crate::simd_f2::GatedBitAdder,
    pc_step_offset: usize,
    selectors: Vec<magnetar_constraint::VarId>,
    ands: Vec<Vec<magnetar_constraint::VarId>>,
    one: magnetar_constraint::VarId,
    relation: BitRelation,
}

impl DynamicMixedRow {
    fn build(mask: u8, width: usize) -> Result<Self, RuntimeError> {
        use magnetar_constraint::VarId;
        let mut components: Vec<Box<dyn PcComponent>> = Vec::new();
        if mask & MIXED_ALU != 0 {
            components.push(Box::new(AluPcRow::new(width)));
        }
        if mask & MIXED_BRANCH != 0 {
            components.push(Box::new(BranchPcRow::new(width)));
        }
        if mask & MIXED_MEMORY != 0 {
            components.push(Box::new(MemPcRow::new(width)));
        }
        if mask & MIXED_SHIFT != 0 {
            components.push(Box::new(ShiftPcRow::new(width)));
        }
        if mask & MIXED_MULTIPLY != 0 {
            components.push(Box::new(MulPcRow::new(width)));
        }
        if mask & MIXED_DIVIDE != 0 {
            components.push(Box::new(DivPcRow::new(width)));
        }
        if mask & MIXED_SDIV != 0 {
            components.push(Box::new(SDivPcRow::new(width)));
        }
        if mask & MIXED_JUMP != 0 {
            components.push(Box::new(JumpPcRow::new(width)));
        }
        if components.is_empty() {
            return Err(RuntimeError::Proof("empty component mask".into()));
        }
        let mut relation = BitRelation::new(0);
        let mut offsets = Vec::with_capacity(components.len());
        for component in &components {
            let offset = relation.num_vars;
            offsets.push(offset);
            relation.num_vars += component.relation().num_vars;
            for row in &component.relation().rows {
                let shift = |vars: &[VarId]| vars.iter().map(|v| *v + offset).collect::<Vec<_>>();
                relation.add(BitRow::new(shift(&row.a), shift(&row.b), shift(&row.c)));
            }
        }
        let pc_step_add = crate::simd_f2::GatedBitAdder::new(width);
        let pc_step_offset = relation.num_vars;
        relation.num_vars += pc_step_add.relation.num_vars;
        for row in &pc_step_add.relation.rows {
            let shift = |vars: &[VarId]| vars.iter().map(|v| *v + pc_step_offset).collect::<Vec<_>>();
            relation.add(BitRow::new(shift(&row.a), shift(&row.b), shift(&row.c)));
        }
        let take = |relation: &mut BitRelation, n: usize| {
            let start = relation.num_vars;
            relation.num_vars += n;
            (start..start + n).map(|v| v as VarId).collect::<Vec<_>>()
        };
        let pc = take(&mut relation, width);
        let next_pc = take(&mut relation, width);
        let raw_next = take(&mut relation, width);
        let pc_correction = take(&mut relation, 1)[0];
        let selectors = take(&mut relation, components.len());
        let mut ands = Vec::with_capacity(components.len());
        for _ in 0..components.len() {
            ands.push(take(&mut relation, width));
        }
        let one = offsets[0] + components[0].one();
        for bit in 0..width {
            relation.add(BitRow::new(vec![pc[bit]], vec![pc[bit]], vec![pc[bit]]));
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![next_pc[bit]],
                vec![next_pc[bit]],
            ));
            relation.add(BitRow::new(
                vec![raw_next[bit]],
                vec![raw_next[bit]],
                vec![raw_next[bit]],
            ));
            let mut next_terms = Vec::with_capacity(components.len());
            for (index, component) in components.iter().enumerate() {
                relation.add(BitRow::new(
                    vec![component.pc()[bit] + offsets[index]],
                    vec![one],
                    vec![pc[bit]],
                ));
                relation.add(BitRow::new(
                    vec![selectors[index]],
                    vec![component.next_pc()[bit] + offsets[index]],
                    vec![ands[index][bit]],
                ));
                next_terms.push(ands[index][bit]);
            }
            relation.add(BitRow::new(vec![raw_next[bit]], vec![one], next_terms));
        }
        // raw_next = next_pc + 2 * pc_correction:
        // next_pc is corrected by 2 for compressed rows.
        for bit in 0..width {
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![one],
                vec![pc_step_offset as VarId + pc_step_add.a[bit]],
            ));
            relation.add(BitRow::new(
                vec![raw_next[bit]],
                vec![one],
                vec![pc_step_offset as VarId + pc_step_add.out[bit]],
            ));
            if bit == 1 {
                relation.add(BitRow::new(
                    vec![pc_correction],
                    vec![one],
                    vec![pc_step_offset as VarId + pc_step_add.b[bit]],
                ));
            } else {
                relation.add(BitRow::new(
                    vec![pc_step_offset as VarId + pc_step_add.b[bit]],
                    vec![one],
                    Vec::new(),
                ));
            }
        }
        relation.add(BitRow::new(
            vec![pc_step_offset as VarId + pc_step_add.gate],
            vec![one],
            vec![one],
        ));
        for selector in &selectors {
            relation.add(BitRow::new(
                vec![*selector],
                vec![*selector],
                vec![*selector],
            ));
        }
        relation.add(BitRow::new(selectors.clone(), vec![one], vec![one]));
        Ok(Self {
            width,
            components,
            offsets,
            pc,
            next_pc,
            raw_next,
            pc_correction,
            pc_step_add,
            pc_step_offset,
            selectors,
            ands,
            one,
            relation,
        })
    }

    fn witness_at(
        &self,
        pc: u64,
        input: &MixedAluBranchInput,
        pc_correction: bool,
    ) -> Result<Vec<bool>, RuntimeError> {
        let mut bits = Vec::new();
        for component in &self.components {
            let mut instance = component.witness(pc, input)?;
            instance.resize(component.relation().num_vars, false);
            bits.extend(instance);
        }
        bits.resize(self.relation.num_vars, false);
        let kind = input.kind();
        if !self
            .components
            .iter()
            .any(|component| component.kind() == kind)
        {
            return Err(RuntimeError::Proof(
                "trace row needs a component missing from the selected mask".into(),
            ));
        }
        for (index, selector) in self.selectors.iter().enumerate() {
            bits[*selector] = self.components[index].kind() == kind;
        }
        for bit in 0..self.width {
            bits[self.pc[bit]] = (pc >> bit) & 1 == 1;
        }
        for bit in 0..self.width {
            let mut next_value = false;
            for (index, component) in self.components.iter().enumerate() {
                let value = bits[component.next_pc()[bit] + self.offsets[index]];
                bits[self.ands[index][bit]] = bits[self.selectors[index]] && value;
                next_value ^= bits[self.ands[index][bit]];
            }
            bits[self.raw_next[bit]] = next_value;
        }
        bits[self.pc_correction] = pc_correction;
        let raw = (0..self.width).fold(0u64, |value, bit| {
            if bits[self.raw_next[bit]] {
                value | (1 << bit)
            } else {
                value
            }
        });
        let next = raw.wrapping_sub(if pc_correction { 2 } else { 0 });
        for bit in 0..self.width {
            bits[self.next_pc[bit]] = ((next >> bit) & 1) == 1;
        }
        let addition = self
            .pc_step_add
            .witness(next, if pc_correction { 2 } else { 0 }, true);
        for (local, value) in addition.into_iter().enumerate() {
            bits[self.pc_step_offset + local] = value;
        }
        Ok(bits)
    }
}

impl GatedRowLike for DynamicMixedRow {
    fn relation(&self) -> &BitRelation {
        &self.relation
    }
    fn packed_companion_system(&self) -> magnetar_constraint::ConstraintSystem {
        self.relation.to_system()
    }
    fn width(&self) -> usize {
        self.width
    }
    fn pc(&self) -> &[magnetar_constraint::VarId] {
        &self.pc
    }
    fn next_pc(&self) -> &[magnetar_constraint::VarId] {
        &self.next_pc
    }
    fn one(&self) -> magnetar_constraint::VarId {
        self.one
    }
}

fn dynamic_trace_bits(
    width: usize,
    rows: &[(u64, MixedAluBranchInput)],
    final_pc: u64,
    mask: u8,
) -> Result<(Vec<bool>, usize, u64), RuntimeError> {
    let row = DynamicMixedRow::build(mask, width)?;
    let cycles = rows.len().next_power_of_two().max(2);
    let initial_pc = rows[0].0;
    let (base_cols, _, _) = gated_shared_matrices(&row, cycles, None)?;
    let mut bits = Vec::with_capacity(cycles * base_cols);
    for index in 0..cycles {
        let (pc, mut input) = if index < rows.len() {
            rows[index]
        } else {
            (final_pc, dynamic_padding_input(mask, final_pc))
        };
        if index + 1 == rows.len() && final_pc == pc && mask & MIXED_JUMP == 0 {
            input = MixedAluBranchInput::Fetch {
                left: 0,
                right: 0,
                imm: 0,
                kind: crate::branch_row::BranchKind::Beq,
            };
        }
        let mut instance = row.witness_at(pc, &input, false)?;
        instance.resize(base_cols, false);
        bits.extend(instance);
    }
    Ok((bits, cycles, initial_pc))
}

pub fn prove_dynamic_selected_trace<B: magnetar_proof::BitPcs>(
    trace: &magnetar_spec::Trace,
    width: usize,
    backend: &B,
) -> Result<LockstepBatch<B>, RuntimeError> {
    use magnetar_proof::prove_lockstep_bits;

    let rows = mixed_alu_branch_rows_from_trace_dynamic(trace, width)?;
    let final_pc = trace.final_state.pc;
    let mut mask = mixed_rows_component_mask(&rows);
    if rows.len() < rows.len().next_power_of_two().max(2) {
        mask |= MIXED_BRANCH;
    }
    if rows.last().map(|(pc, _)| *pc) == Some(final_pc) && mask & MIXED_JUMP == 0 {
        mask |= MIXED_BRANCH;
    }
    let (bits, cycles, initial_pc) = dynamic_trace_bits(width, &rows, final_pc, mask)?;
    let row = DynamicMixedRow::build(mask, width)?;
    let (base_cols, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    let layout = segment_layout(cycles * base_cols)?;
    let proof = prove_lockstep_bits(
        &bits, &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], &layout, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((proof, layout))
}

pub fn verify_dynamic_selected_trace<B: magnetar_proof::BitPcs>(
    trace: &magnetar_spec::Trace,
    proof: &LockstepProof<B::Commitment, B::Opening>,
    layout: &magnetar_constraint::WitnessLayout,
    width: usize,
    backend: &B,
) -> Result<(), RuntimeError> {
    use magnetar_proof::verify_lockstep_bits;

    let rows = mixed_alu_branch_rows_from_trace_dynamic(trace, width)?;
    let final_pc = trace.final_state.pc;
    let mut mask = mixed_rows_component_mask(&rows);
    if rows.len() < rows.len().next_power_of_two().max(2) {
        mask |= MIXED_BRANCH;
    }
    if rows.last().map(|(pc, _)| *pc) == Some(final_pc) && mask & MIXED_JUMP == 0 {
        mask |= MIXED_BRANCH;
    }
    let (bits, cycles, initial_pc) = dynamic_trace_bits(width, &rows, final_pc, mask)?;
    let expected = backend
        .commit(&bits)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    if backend.commitment_bytes(&expected) != backend.commitment_bytes(&proof.commitment) {
        return Err(RuntimeError::Proof(
            "dynamic selected witness does not match the proof commitment".into(),
        ));
    }
    let row = DynamicMixedRow::build(mask, width)?;
    let (_, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    verify_lockstep_bits(
        &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], layout, proof, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(())
}

struct SegmentedDynamicRow {
    width: usize,
    relation: BitRelation,
    pc: Vec<magnetar_constraint::VarId>,
    next_pc: Vec<magnetar_constraint::VarId>,
    one: magnetar_constraint::VarId,
}

impl GatedRowLike for SegmentedDynamicRow {
    fn relation(&self) -> &BitRelation {
        &self.relation
    }
    fn packed_companion_system(&self) -> magnetar_constraint::ConstraintSystem {
        self.relation.to_system()
    }
    fn width(&self) -> usize {
        self.width
    }
    fn pc(&self) -> &[magnetar_constraint::VarId] {
        &self.pc
    }
    fn next_pc(&self) -> &[magnetar_constraint::VarId] {
        &self.next_pc
    }
    fn one(&self) -> magnetar_constraint::VarId {
        self.one
    }
}

fn segmented_dynamic_row(
    mask: u8,
    width: usize,
    cycles: usize,
) -> Result<
    (
        SegmentedDynamicRow,
        Vec<usize>,
        magnetar_constraint::WitnessLayout,
    ),
    RuntimeError,
> {
    use magnetar_constraint::{Segment, SegmentKind, SegmentOwner, WitnessLayout};
    let original = DynamicMixedRow::build(mask, width)?;
    let mut mapping = vec![usize::MAX; original.relation.num_vars];
    let mut cursor = 0usize;
    for (index, component) in original.components.iter().enumerate() {
        let len = component.relation().num_vars;
        for local in 0..len {
            mapping[original.offsets[index] + local] = cursor + local;
        }
        cursor += len;
    }
    let step_len = original.pc_step_add.relation.num_vars;
    for local in 0..step_len {
        mapping[original.pc_step_offset + local] = cursor + local;
    }
    cursor += step_len;
    for selector in &original.selectors {
        mapping[*selector] = cursor;
        cursor += 1;
    }
    for and in &original.ands {
        for var in and {
            mapping[*var] = cursor;
            cursor += 1;
        }
    }
    for var in &original.raw_next {
        mapping[*var] = cursor;
        cursor += 1;
    }
    mapping[original.pc_correction] = cursor;
    cursor += 1;
    for bit in 0..width {
        mapping[original.pc[bit]] = cursor;
        cursor += 1;
        mapping[original.next_pc[bit]] = cursor;
        cursor += 1;
    }
    if cursor != original.relation.num_vars {
        return Err(RuntimeError::Proof(
            "dynamic segmented mapping size mismatch".into(),
        ));
    }
    let block_cols = (cursor + 1).next_power_of_two().max(2);
    if mapping.contains(&usize::MAX) {
        return Err(RuntimeError::Proof(
            "dynamic segmented mapping is incomplete".into(),
        ));
    }
    let mut relation = BitRelation::new(block_cols - 1);
    let map = |vars: &[magnetar_constraint::VarId]| {
        vars.iter().map(|var| mapping[*var]).collect::<Vec<_>>()
    };
    for row in &original.relation.rows {
        relation.add(BitRow::new(map(&row.a), map(&row.b), map(&row.c)));
    }
    let pc = original
        .pc
        .iter()
        .map(|var| mapping[*var])
        .collect::<Vec<_>>();
    let next_pc = original
        .next_pc
        .iter()
        .map(|var| mapping[*var])
        .collect::<Vec<_>>();
    let one = mapping[original.one];
    let row = SegmentedDynamicRow {
        width,
        relation,
        pc,
        next_pc,
        one,
    };
    let group = if cycles >= 64 { 64 } else { cycles };
    let mut segments = Vec::with_capacity(cycles / group);
    for start in (0..cycles).step_by(group) {
        segments.push(Segment::new(
            format!("group{start}"),
            start * block_cols,
            group * block_cols,
            SegmentKind::Direct,
            SegmentOwner::Cpu,
        ));
    }
    let layout =
        WitnessLayout::new(segments).map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((row, mapping, layout))
}

type DynamicSegmentProof<C, O> = (
    LockstepProof<C, O>,
    magnetar_constraint::WitnessLayout,
    u8,
    usize,
);

pub fn prove_dynamic_segmented_trace<B: magnetar_proof::BitPcs>(
    trace: &magnetar_spec::Trace,
    width: usize,
    backend: &B,
) -> Result<DynamicSegmentProof<B::Commitment, B::Opening>, RuntimeError> {
    use magnetar_proof::prove_lockstep_bits;

    let rows = mixed_alu_branch_rows_from_trace_dynamic(trace, width)?;
    let final_pc = trace.final_state.pc;
    let mut mask = mixed_rows_component_mask(&rows);
    if rows.len() < rows.len().next_power_of_two().max(2) {
        mask |= MIXED_BRANCH;
    }
    if rows.last().map(|(pc, _)| *pc) == Some(final_pc) && mask & MIXED_JUMP == 0 {
        mask |= MIXED_BRANCH;
    }
    let cycles = rows.len().next_power_of_two().max(2);
    let initial_pc = rows[0].0;
    let original = DynamicMixedRow::build(mask, width)?;
    let (row, mapping, layout) = segmented_dynamic_row(mask, width, cycles)?;
    let (base_cols, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    if layout.total_bits != cycles * base_cols {
        return Err(RuntimeError::Proof(
            "dynamic segmented layout mismatch".into(),
        ));
    }
    let mut bits = Vec::with_capacity(cycles * base_cols);
    for index in 0..cycles {
        let (pc, mut input) = if index < rows.len() {
            rows[index]
        } else {
            (final_pc, dynamic_padding_input(mask, final_pc))
        };
        if index + 1 == rows.len() && final_pc == pc && mask & MIXED_JUMP == 0 {
            input = MixedAluBranchInput::Fetch {
                left: 0,
                right: 0,
                imm: 0,
                kind: crate::branch_row::BranchKind::Beq,
            };
        }
        let correction = row_pc_correction(trace.rows.get(index), &input);
        let source = original.witness_at(pc, &input, correction)?;
        let mut block = vec![false; base_cols];
        for (from, to) in mapping.iter().enumerate() {
            if source[from] {
                block[*to] = true;
            }
        }
        if !row.relation.check(&block) {
            return Err(RuntimeError::Proof(format!("dynamic row {index} relation fail")));
        }
        bits.extend(block);
    }
    for instance in 0..cycles.saturating_sub(1) {
        for bit in 0..width {
            let from = bits[instance * base_cols + row.next_pc()[bit]];
            let to = bits[(instance + 1) * base_cols + row.pc()[bit]];
            if from != to {
                return Err(RuntimeError::Proof(format!(
                    "dynamic row {instance} pc chain fail at bit {bit} from={from} to={to} pcvar={} nextvar={} base={base_cols}",
                    row.pc()[bit], row.next_pc()[bit]
                )));
            }
        }
    }
    for (instance, pc) in [(0usize, initial_pc), (cycles - 1, final_pc)] {
        for bit in 0..width {
            let observed = if instance == 0 {
                bits[instance * base_cols + row.pc()[bit]]
            } else {
                bits[instance * base_cols + row.next_pc()[bit]]
            };
            if observed != ((pc >> bit) & 1 == 1) {
                return Err(RuntimeError::Proof(format!(
                    "dynamic statement pc fail at bit {bit}"
                )));
            }
        }
    }
    let proof = prove_lockstep_bits(
        &bits, &s1[0], &s1[1], &s1[2], &s2[0], &s2[1], &s2[2], &layout, backend,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((proof, layout, mask, cycles))
}

/// Verify a dynamic selected proof from its serialized-mask/layout metadata,
/// without rebuilding a trace. Segment-to-claim routing is still performed by
/// the caller; this checks the public CPU matrices, layout and PCS opening.
pub fn verify_dynamic_segments_public<B: magnetar_proof::BitPcs + Sync>(
    claims: &SelectedCpuClaims<B::Commitment, B::Opening>,
    backend: &B,
) -> Result<(), RuntimeError>
where
    B::Commitment: Sync,
    B::Opening: Sync,
{
    verify_dynamic_segments_public_point(claims, backend).map(|_| ())
}

pub fn verify_dynamic_segments_public_point<B: magnetar_proof::BitPcs + Sync>(
    claims: &SelectedCpuClaims<B::Commitment, B::Opening>,
    backend: &B,
) -> Result<Vec<F2_128>, RuntimeError>
where
    B::Commitment: Sync,
    B::Opening: Sync,
{
    use magnetar_proof::verify_lockstep_bits_with_replacements_point;

    if claims.op != SelectedOp::Dynamic {
        return Err(RuntimeError::Proof(
            "public dynamic verifier requires a dynamic claim bundle".into(),
        ));
    }
    let matrix_cycles = if claims.matrix_cycles == 0 {
        claims.cycles
    } else {
        claims.matrix_cycles
    };
    let (row, _mapping, layout) = segmented_dynamic_row(claims.mask, claims.width, matrix_cycles)?;
    let (_, s1, s2) = gated_shared_matrices(
        &row,
        matrix_cycles,
        Some((claims.initial_pc, claims.final_pc)),
    )?;
    verify_lockstep_bits_with_replacements_point(
        &s1[0],
        &s1[1],
        &s1[2],
        &s2[0],
        &s2[1],
        &s2[2],
        &layout,
        &claims.proof,
        backend,
        &[],
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))
}

fn eq_bits(point: &[F2_128], bits: &[F2_128]) -> F2_128 {
    point
        .iter()
        .zip(bits)
        .fold(F2_128::from(1u64), |value, (r, bit)| {
            value * (F2_128::from(1u64) + *r + *bit)
        })
}

/// Route the `pc{cycle}` segment claims back to authenticated claim rows.
/// This binds the proof's PC/next-PC virtual segments to ClaimProof rows.
pub fn verify_dynamic_pc_segments<B: magnetar_proof::BitPcs + Sync>(
    claims: &SelectedCpuClaims<B::Commitment, B::Opening>,
    rows: &[crate::trace_claims::TraceClaim],
    backend: &B,
) -> Result<(), RuntimeError>
where
    B::Commitment: Sync,
    B::Opening: Sync,
{
    let matrix_cycles = if claims.matrix_cycles == 0 {
        claims.cycles
    } else {
        claims.matrix_cycles
    };
    let (_, _, layout) = segmented_dynamic_row(claims.mask, claims.width, matrix_cycles)?;
    let ry = verify_dynamic_segments_public_point(claims, backend)?;
    if claims.proof.segments.len() != layout.segments.len() {
        return Err(RuntimeError::Proof("dynamic segment count mismatch".into()));
    }
    for (segment, value) in layout.segments.iter().zip(&claims.proof.segments) {
        let Some(cycle) = segment
            .name
            .strip_prefix("pc")
            .and_then(|rest| rest.parse::<usize>().ok())
        else {
            continue;
        };
        if cycle >= rows.len() {
            continue;
        }
        let size_bits = segment.len.trailing_zeros() as usize;
        if size_bits == 0 || size_bits > ry.len() {
            return Err(RuntimeError::Proof("invalid pc segment size".into()));
        }
        let row = &rows[cycle];
        let mut bits = Vec::with_capacity(1usize << size_bits);
        for bit in 0..claims.width {
            bits.push(F2_128::from((row.pc >> bit) & 1));
        }
        for bit in 0..claims.width {
            bits.push(F2_128::from((row.next_pc >> bit) & 1));
        }
        bits.resize(1usize << size_bits, F2_128::from(0u64));
        let expected = bits
            .iter()
            .enumerate()
            .fold(F2_128::from(0u64), |sum, (index, bit)| {
                let index_bits = (0..size_bits)
                    .map(|bit| F2_128::from(((index >> bit) & 1) as u64))
                    .collect::<Vec<_>>();
                sum + *bit * eq_bits(&ry[..size_bits], &index_bits)
            });
        if value.value != expected {
            return Err(RuntimeError::Proof(
                "dynamic pc segment does not match claim rows".into(),
            ));
        }
    }
    Ok(())
}

/// Bind every dynamic segment claim to a trace-derived witness source using the
/// public verifier's `ry` point. This is the segment-claim router; the caller
/// should pass a trace rebuilt from the authenticated ClaimProof.
pub fn verify_dynamic_segments_against_trace<B: magnetar_proof::BitPcs + Sync>(
    claims: &SelectedCpuClaims<B::Commitment, B::Opening>,
    trace: &magnetar_spec::Trace,
    backend: &B,
) -> Result<(), RuntimeError>
where
    B::Commitment: Sync,
    B::Opening: Sync,
{
    let matrix_cycles = if claims.matrix_cycles == 0 {
        claims.cycles
    } else {
        claims.matrix_cycles
    };
    let (_, mapping, layout) = segmented_dynamic_row(claims.mask, claims.width, matrix_cycles)?;
    let ry = verify_dynamic_segments_public_point(claims, backend)?;
    if claims.proof.segments.len() != layout.segments.len() {
        return Err(RuntimeError::Proof("dynamic segment count mismatch".into()));
    }
    let block_cols = layout.total_bits / matrix_cycles;
    let rows = mixed_alu_branch_rows_from_trace_dynamic(trace, claims.width)?;
    let final_pc = trace.final_state.pc;
    let original = DynamicMixedRow::build(claims.mask, claims.width)?;
    let block_for = |cycle: usize| -> Result<Vec<bool>, RuntimeError> {
        let (pc, mut input) = if cycle < rows.len() {
            rows[cycle]
        } else {
            (final_pc, dynamic_padding_input(claims.mask, final_pc))
        };
        if cycle + 1 == rows.len() && final_pc == pc && claims.mask & MIXED_JUMP == 0 {
            input = MixedAluBranchInput::Fetch {
                left: 0,
                right: 0,
                imm: 0,
                kind: crate::branch_row::BranchKind::Beq,
            };
        }
        let correction = row_pc_correction(trace.rows.get(cycle), &input);
        let source = original.witness_at(pc, &input, correction)?;
        let mut block = vec![false; block_cols];
        for (from, to) in mapping.iter().enumerate() {
            if source[from] {
                block[*to] = true;
            }
        }
        Ok(block)
    };
    let workers = std::thread::available_parallelism()
        .map(|count| count.get().min(8))
        .unwrap_or(1)
        .max(1);
    let blocks = if matrix_cycles >= 1024 && workers > 1 {
        std::thread::scope(|scope| {
            let chunk = matrix_cycles.div_ceil(workers);
            let mut handles = Vec::with_capacity(workers);
            for start in (0..matrix_cycles).step_by(chunk) {
                let end = (start + chunk).min(matrix_cycles);
                let block_for = &block_for;
                handles.push(scope.spawn(move || {
                    (start..end)
                        .map(block_for)
                        .collect::<Result<Vec<_>, RuntimeError>>()
                }));
            }
            let mut blocks = Vec::with_capacity(matrix_cycles);
            for handle in handles {
                blocks.extend(handle.join().expect("dynamic router worker")?);
            }
            Ok::<_, RuntimeError>(blocks)
        })?
    } else {
        (0..matrix_cycles)
            .map(block_for)
            .collect::<Result<Vec<_>, _>>()?
    };
    let check_segment = |segment_index: usize| -> Result<(), RuntimeError> {
        let segment = &layout.segments[segment_index];
        let start = segment.offset / block_cols;
        let count = segment.len / block_cols;
        if segment.offset % block_cols != 0
            || count == 0
            || start + count > blocks.len()
            || count * block_cols != segment.len
        {
            return Err(RuntimeError::Proof("dynamic segment layout shape".into()));
        }
        let mut bits = Vec::with_capacity(segment.len);
        for block in &blocks[start..start + count] {
            bits.extend_from_slice(block);
        }
        let size_bits = segment.len.trailing_zeros() as usize;
        let expected = bits
            .iter()
            .enumerate()
            .fold(F2_128::from(0u64), |sum, (index, bit)| {
                if !*bit {
                    return sum;
                }
                let index_bits = (0..size_bits)
                    .map(|bit| F2_128::from(((index >> bit) & 1) as u64))
                    .collect::<Vec<_>>();
                sum + eq_bits(&ry[..size_bits], &index_bits)
            });
        if claims.proof.segments[segment_index].value != expected {
            return Err(RuntimeError::Proof(format!(
                "dynamic segment {} does not match claim witness",
                segment.name
            )));
        }
        Ok(())
    };
    if layout.segments.len() >= 1024 && workers > 1 {
        std::thread::scope(|scope| {
            let chunk = layout.segments.len().div_ceil(workers);
            let mut handles = Vec::with_capacity(workers);
            for start in (0..layout.segments.len()).step_by(chunk) {
                let end = (start + chunk).min(layout.segments.len());
                let check_segment = &check_segment;
                handles.push(scope.spawn(move || {
                    for index in start..end {
                        check_segment(index)?;
                    }
                    Ok::<(), RuntimeError>(())
                }));
            }
            for handle in handles {
                handle.join().expect("dynamic segment worker")?;
            }
            Ok(())
        })
    } else {
        for index in 0..layout.segments.len() {
            check_segment(index)?;
        }
        Ok(())
    }
}

/// Proof-only dynamic claim verification: authenticate the ClaimProof rows,
/// rebuild the synthetic trace from them, and run the public segment router.
pub fn verify_dynamic_claim_bundle<B: magnetar_proof::BitPcs + Sync>(
    statement: &crate::Statement,
    claim_proof: &crate::trace_claims::ClaimProof,
    claims: &SelectedCpuClaims<B::Commitment, B::Opening>,
    backend: &B,
) -> Result<(), RuntimeError>
where
    B::Commitment: Sync,
    B::Opening: Sync,
{
    if claim_proof.root != statement.trace_claim_root {
        return Err(RuntimeError::Proof(
            "claim proof root does not match the statement".into(),
        ));
    }
    if claims.claim_root != [0u8; 32] && claims.claim_root != claim_proof.root {
        return Err(RuntimeError::Proof(
            "selected claim root does not match the claim proof".into(),
        ));
    }
    let rows = claim_proof
        .verify()
        .ok_or_else(|| RuntimeError::Proof("claim proof opening mismatch".into()))?;
    if rows.len() as u64 != statement.trace_len {
        return Err(RuntimeError::Proof("claim count mismatch".into()));
    }
    let synthetic = crate::trace_claims::claims_to_trace(statement, &rows)?;
    if statement.initial_state != synthetic.initial_state
        || statement.final_state != synthetic.final_state
        || statement.rom != synthetic.rom
        || statement.initial_ram != synthetic.initial_ram
    {
        return Err(RuntimeError::Proof(
            "claim-derived trace does not match the statement".into(),
        ));
    }
    verify_selected_claim_consistency(claims, &rows)?;
    verify_dynamic_segments_against_trace(claims, &synthetic, backend)
}

pub fn selected_layout_from_claims<C: Clone + std::fmt::Debug, O: Clone + std::fmt::Debug>(
    claims: &SelectedCpuClaims<C, O>,
) -> Result<magnetar_constraint::WitnessLayout, RuntimeError> {
    let matrix_cycles = if claims.matrix_cycles == 0 {
        claims.cycles
    } else {
        claims.matrix_cycles
    };
    let (_, _, layout) = segmented_dynamic_row(claims.mask, claims.width, matrix_cycles)?;
    Ok(layout)
}

pub fn verify_dynamic_segmented_trace<B: magnetar_proof::BitPcs + Sync>(
    trace: &magnetar_spec::Trace,
    proof: &LockstepProof<B::Commitment, B::Opening>,
    _layout: &magnetar_constraint::WitnessLayout,
    width: usize,
    backend: &B,
) -> Result<(), RuntimeError>
where
    B::Commitment: Sync,
    B::Opening: Sync,
{
    use magnetar_proof::verify_lockstep_bits;

    let rows = mixed_alu_branch_rows_from_trace_dynamic(trace, width)?;
    let final_pc = trace.final_state.pc;
    let mut mask = mixed_rows_component_mask(&rows);
    if rows.len() < rows.len().next_power_of_two().max(2) {
        mask |= MIXED_BRANCH;
    }
    if rows.last().map(|(pc, _)| *pc) == Some(final_pc) && mask & MIXED_JUMP == 0 {
        mask |= MIXED_BRANCH;
    }
    let cycles = rows.len().next_power_of_two().max(2);
    let initial_pc = rows[0].0;
    let original = DynamicMixedRow::build(mask, width)?;
    let (row, mapping, expected_layout) = segmented_dynamic_row(mask, width, cycles)?;
    let (base_cols, s1, s2) = gated_shared_matrices(&row, cycles, Some((initial_pc, final_pc)))?;
    let profile = std::env::var_os("MAGNETAR_PROFILE_VERIFY").is_some();
    std::thread::scope(|scope| {
        let verify = scope.spawn(|| {
            let started = std::time::Instant::now();
            let result = verify_lockstep_bits(
                &s1[0],
                &s1[1],
                &s1[2],
                &s2[0],
                &s2[1],
                &s2[2],
                &expected_layout,
                proof,
                backend,
            )
            .map_err(|error| RuntimeError::Proof(error.to_string()));
            if profile {
                eprintln!("selected verify lockstep: {:?}", started.elapsed());
            }
            result
        });
        let bits_started = std::time::Instant::now();
        let mut bits = Vec::with_capacity(cycles * base_cols);
        for index in 0..cycles {
            let (pc, mut input) = if index < rows.len() {
                rows[index]
            } else {
                (
                    final_pc,
                    MixedAluBranchInput::Fetch {
                        left: 0,
                        right: 0,
                        imm: 0,
                        kind: crate::branch_row::BranchKind::Beq,
                    },
                )
            };
            if index + 1 == rows.len() && final_pc == pc && mask & MIXED_JUMP == 0 {
                input = MixedAluBranchInput::Fetch {
                    left: 0,
                    right: 0,
                    imm: 0,
                    kind: crate::branch_row::BranchKind::Beq,
                };
            }
            let correction = row_pc_correction(trace.rows.get(index), &input);
            let source = original.witness_at(pc, &input, correction)?;
            let mut block = vec![false; base_cols];
            for (from, to) in mapping.iter().enumerate() {
                if source[from] {
                    block[*to] = true;
                }
            }
            bits.extend(block);
        }
        if profile {
            eprintln!("selected verify bits: {:?}", bits_started.elapsed());
        }
        let commit_started = std::time::Instant::now();
        let expected = backend
            .commit(&bits)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        if profile {
            eprintln!("selected verify commit: {:?}", commit_started.elapsed());
        }
        verify
            .join()
            .map_err(|_| RuntimeError::Proof("lockstep verifier panicked".into()))??;
        if backend.commitment_bytes(&expected) != backend.commitment_bytes(&proof.commitment) {
            return Err(RuntimeError::Proof(
                "dynamic segmented witness does not match the proof commitment".into(),
            ));
        }
        Ok(())
    })
}

pub fn prove_gated_dual_batch_bits<B: magnetar_proof::BitPcs>(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
    backend: &B,
) -> Result<LockstepBatch<B>, RuntimeError> {
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
    let (base_cols, s1, s2) = gated_shared_matrices(&row, rows.len(), None)?;
    let bits = gated_batch_bits(&row, base_cols, rows);
    let expected = backend
        .commit(&bits)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    if backend.commitment_bytes(&expected) != backend.commitment_bytes(&proof.commitment) {
        return Err(RuntimeError::Proof(
            "gated batch witness does not match the proof commitment".into(),
        ));
    }
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
) -> Result<LockstepBatch<B>, RuntimeError> {
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
    let (base_cols, s1, s2) =
        gated_shared_matrices(&row, rows.len(), Some((initial_pc, final_pc)))?;
    let bits = gated_batch_bits(&row, base_cols, rows);
    let expected = backend
        .commit(&bits)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    if backend.commitment_bytes(&expected) != backend.commitment_bytes(&proof.commitment) {
        return Err(RuntimeError::Proof(
            "gated batch witness does not match the proof commitment".into(),
        ));
    }
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
    fn dynamic_segmented_trace_binds_witness() {
        use magnetar_executor::execute;
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let config = MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x40,
            stack_top: 0x1000_0040,
            max_cycles: 100,
        };
        let programs = [
            ProgramImage::new(
                0x1000,
                vec![
                    Instruction {
                        op: Op::Addi,
                        rd: 1,
                        rs1: 0,
                        rs2: 0,
                        imm: 7,
                        shamt: 0,
                    }
                    .encode(),
                    Instruction::new(Op::Ecall).encode(),
                ],
            ),
            ProgramImage::new(
                0x1000,
                vec![
                    Instruction {
                        op: Op::Lui,
                        rd: 1,
                        rs1: 0,
                        rs2: 0,
                        imm: 0x10,
                        shamt: 0,
                    }
                    .encode(),
                    Instruction {
                        op: Op::Slli,
                        rd: 1,
                        rs1: 1,
                        rs2: 0,
                        imm: 0,
                        shamt: 2,
                    }
                    .encode(),
                    Instruction::new(Op::Ecall).encode(),
                ],
            ),
            ProgramImage::new(
                0x1000,
                vec![
                    Instruction {
                        op: Op::Lui,
                        rd: 20,
                        rs1: 0,
                        rs2: 0,
                        imm: 0x1000_0000,
                        shamt: 0,
                    }
                    .encode(),
                    Instruction {
                        op: Op::Lw,
                        rd: 6,
                        rs1: 20,
                        rs2: 0,
                        imm: 2,
                        shamt: 0,
                    }
                    .encode(),
                    Instruction::new(Op::Ecall).encode(),
                ],
            ),
        ];
        for program in programs {
            let trace = execute(&program, config.clone()).unwrap();
            let (proof, layout, mask, cycles) =
                prove_dynamic_segmented_trace(&trace, 8, &backend).unwrap();
            assert!(!layout.segments.is_empty());
            let claims = selected_segment_claims(&layout, &proof).unwrap();
            assert_eq!(claims.len(), layout.segments.len());
            verify_dynamic_segmented_trace(&trace, &proof, &layout, 8, &backend).unwrap();
            let selected = SelectedCpuClaims {
                op: SelectedOp::Dynamic,
                width: 8,
                cycles: trace.rows.len().next_power_of_two().max(2),
                matrix_cycles: cycles,
                mask,
                initial_pc: trace.rows[0].pc,
                final_pc: trace.final_state.pc,
                layout: magnetar_constraint::WitnessLayout::default(),
                segments: claims,
                claim_root: [0u8; 32],
                claim_openings: Vec::new(),
                proof: proof.clone(),
            };
            verify_dynamic_segments_public(&selected, &backend).unwrap();
            verify_dynamic_segments_against_trace(&selected, &trace, &backend).unwrap();
            let mut bad_trace = trace.clone();
            bad_trace.rows[0].rs1_val ^= 1;
            assert!(
                verify_dynamic_segments_against_trace(&selected, &bad_trace, &backend).is_err()
            );
            let mut tampered = selected;
            tampered.proof.segments[0].value =
                tampered.proof.segments[0].value + magnetar_constraint::F2_128::from(1u64);
            assert!(verify_dynamic_segments_public(&tampered, &backend).is_err());
        }
    }

    #[test]
    fn dynamic_selected_trace_binds_witness() {
        use magnetar_executor::execute;
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};
        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let config = MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x40,
            stack_top: 0x1000_0040,
            max_cycles: 100,
        };
        let programs = [
            ProgramImage::new(
                0x1000,
                vec![
                    Instruction {
                        op: Op::Addi,
                        rd: 1,
                        rs1: 0,
                        rs2: 0,
                        imm: 7,
                        shamt: 0,
                    }
                    .encode(),
                    Instruction::new(Op::Ecall).encode(),
                ],
            ),
            ProgramImage::new(
                0x1000,
                vec![
                    Instruction {
                        op: Op::Lui,
                        rd: 1,
                        rs1: 0,
                        rs2: 0,
                        imm: 0x10,
                        shamt: 0,
                    }
                    .encode(),
                    Instruction {
                        op: Op::Slli,
                        rd: 1,
                        rs1: 1,
                        rs2: 0,
                        imm: 0,
                        shamt: 2,
                    }
                    .encode(),
                    Instruction::new(Op::Ecall).encode(),
                ],
            ),
            ProgramImage::new(
                0x1000,
                vec![
                    Instruction {
                        op: Op::Lui,
                        rd: 20,
                        rs1: 0,
                        rs2: 0,
                        imm: 0x1000_0000,
                        shamt: 0,
                    }
                    .encode(),
                    Instruction {
                        op: Op::Lw,
                        rd: 6,
                        rs1: 20,
                        rs2: 0,
                        imm: 2,
                        shamt: 0,
                    }
                    .encode(),
                    Instruction::new(Op::Ecall).encode(),
                ],
            ),
        ];
        for program in programs {
            let trace = execute(&program, config.clone()).unwrap();
            let (proof, layout) = prove_dynamic_selected_trace(&trace, 8, &backend).unwrap();
            verify_dynamic_selected_trace(&trace, &proof, &layout, 8, &backend).unwrap();
        }
    }

    #[test]
    fn selected_claim_openings_recover_without_trace() {
        use magnetar_executor::execute;
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};
        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 7,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(
            &program,
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 10,
            },
        )
        .unwrap();
        let claims = prove_dynamic_cpu_claims(&trace, 8, &backend).unwrap();
        let recovered = verify_selected_claim_openings(&claims).unwrap();
        assert_eq!(recovered.len(), trace.rows.len());
        assert_eq!(recovered[0].pc, 0x1000);
        let mut tampered = claims.clone();
        tampered.claim_openings[0].claim.instruction_len = 2;
        assert!(verify_selected_claim_openings(&tampered).is_none());
    }

    #[test]
    fn selected_claims_bind_to_independent_proof() {
        use magnetar_executor::execute;
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};
        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 7,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(
            &program,
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 10,
            },
        )
        .unwrap();
        let claims = prove_dynamic_cpu_claims(&trace, 8, &backend).unwrap();
        let proof = crate::trace_claims::ClaimProof::from_trace(&trace);
        assert!(verify_selected_claim_binding(&claims, &proof));
        let recovered = verify_selected_claim_proof(&claims, &proof).unwrap();
        assert_eq!(recovered.len(), trace.rows.len());
        verify_selected_claim_consistency(&claims, &recovered).unwrap();
        let mut bad_link = recovered.clone();
        bad_link[0].next_pc ^= 2;
        assert!(verify_selected_claim_consistency(&claims, &bad_link).is_err());
        let mut bad_len = recovered.clone();
        bad_len[0].instruction_len = 8;
        assert!(verify_selected_claim_consistency(&claims, &bad_len).is_err());
        let mut bad = proof;
        bad.openings[0].claim.pc ^= 2;
        assert!(!verify_selected_claim_binding(&claims, &bad));
    }

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
    fn alu_branch_sdiv_trace_binds_witness() {
        use magnetar_executor::execute;
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

        let addi = |rd, imm| {
            Instruction {
                op: Op::Addi,
                rd,
                rs1: 0,
                rs2: 0,
                imm,
                shamt: 0,
            }
            .encode()
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                addi(1, 32),
                addi(2, 3),
                Instruction {
                    op: Op::Div,
                    rd: 3,
                    rs1: 1,
                    rs2: 2,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(
            &program,
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 100,
            },
        )
        .unwrap();
        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let (proof, layout) = prove_alu_branch_trace(&trace, 8, &backend).unwrap();
        verify_alu_branch_trace(&trace, &proof, &layout, 8, &backend).unwrap();
    }

    #[test]
    fn alu_branch_div_trace_binds_witness() {
        use magnetar_executor::execute;
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

        let addi = |rd, imm| {
            Instruction {
                op: Op::Addi,
                rd,
                rs1: 0,
                rs2: 0,
                imm,
                shamt: 0,
            }
            .encode()
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                addi(1, 96),
                addi(2, 3),
                Instruction {
                    op: Op::Divu,
                    rd: 3,
                    rs1: 1,
                    rs2: 2,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(
            &program,
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 100,
            },
        )
        .unwrap();
        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let (proof, layout) = prove_alu_branch_trace(&trace, 8, &backend).unwrap();
        verify_alu_branch_trace(&trace, &proof, &layout, 8, &backend).unwrap();
    }

    #[test]
    fn alu_branch_mul_trace_binds_witness() {
        use magnetar_executor::execute;
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

        let addi = |rd, imm| {
            Instruction {
                op: Op::Addi,
                rd,
                rs1: 0,
                rs2: 0,
                imm,
                shamt: 0,
            }
            .encode()
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                addi(1, 5),
                addi(2, 3),
                Instruction {
                    op: Op::Mul,
                    rd: 3,
                    rs1: 1,
                    rs2: 2,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(
            &program,
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 100,
            },
        )
        .unwrap();
        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let (proof, layout) = prove_alu_branch_trace(&trace, 8, &backend).unwrap();
        verify_alu_branch_trace(&trace, &proof, &layout, 8, &backend).unwrap();
    }

    #[test]
    fn alu_branch_shift_trace_binds_witness() {
        use magnetar_executor::execute;
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Lui,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x10,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Slli,
                    rd: 1,
                    rs1: 1,
                    rs2: 0,
                    imm: 0,
                    shamt: 2,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(
            &program,
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 100,
            },
        )
        .unwrap();
        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let (proof, layout) = prove_alu_branch_trace(&trace, 8, &backend).unwrap();
        verify_alu_branch_trace(&trace, &proof, &layout, 8, &backend).unwrap();
    }

    #[test]
    fn alu_branch_mem_trace_binds_witness() {
        use magnetar_executor::execute;
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Lui,
                    rd: 20,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x1000_0000,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Lw,
                    rd: 6,
                    rs1: 20,
                    rs2: 0,
                    imm: 2,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(
            &program,
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 100,
            },
        )
        .unwrap();
        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let (proof, layout) = prove_alu_branch_trace(&trace, 8, &backend).unwrap();
        verify_alu_branch_trace(&trace, &proof, &layout, 8, &backend).unwrap();
    }

    #[test]
    fn mixed_trace_component_mask_tracks_used_ops() {
        use magnetar_executor::execute;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

        let config = MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x40,
            stack_top: 0x1000_0040,
            max_cycles: 100,
        };
        let alu_program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 7,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let alu_trace = execute(&alu_program, config.clone()).unwrap();
        assert_eq!(
            mixed_trace_component_mask(&alu_trace, 8).unwrap(),
            MIXED_ALU | MIXED_BRANCH
        );

        let mem_program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Lui,
                    rd: 20,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x1000_0000,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Lw,
                    rd: 6,
                    rs1: 20,
                    rs2: 0,
                    imm: 2,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let mem_trace = execute(&mem_program, config).unwrap();
        assert_eq!(
            mixed_trace_component_mask(&mem_trace, 8).unwrap(),
            MIXED_ALU | MIXED_MEMORY | MIXED_BRANCH
        );
    }

    #[test]
    fn dynamic_compressed_witness_satisfies_relation() {
        use magnetar_executor::execute;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};
        let trace = execute(
            &ProgramImage::new(
                0x1000,
                vec![0x008d_4095, Instruction::new(Op::Ecall).encode()],
            ),
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 100,
            },
        )
        .unwrap();
        let rows = mixed_alu_branch_rows_from_trace_dynamic(&trace, 8).unwrap();
        let mask = mixed_rows_component_mask(&rows);
        let original = DynamicMixedRow::build(mask, 8).unwrap();
        let cycles = rows.len().next_power_of_two().max(2);
        let final_pc = trace.final_state.pc;
        for cycle in 0..cycles {
            let (pc, mut input) = if cycle < rows.len() {
                rows[cycle]
            } else {
                (final_pc, dynamic_padding_input(mask, final_pc))
            };
            if cycle + 1 == rows.len() && final_pc == pc && mask & MIXED_JUMP == 0 {
                input = MixedAluBranchInput::Fetch {
                    left: 0,
                    right: 0,
                    imm: 0,
                    kind: crate::branch_row::BranchKind::Beq,
                };
            }
            let correction = row_pc_correction(trace.rows.get(cycle), &input);
            let bits = original.witness_at(pc, &input, correction).unwrap();
            if !original.relation.check(&bits) {
                let parity = |terms: &[usize]| {
                    terms.iter().filter(|term| bits[**term]).count() % 2 == 1
                };
                for (index, row) in original.relation.rows.iter().enumerate() {
                    let a = parity(&row.a);
                    let b = parity(&row.b);
                    let c = parity(&row.c);
                    if (a && b) != c {
                        eprintln!(
                            "row {index} a={:?} b={:?} c={:?} pc={pc:#x} corr={correction}",
                            row.a, row.b, row.c
                        );
                        eprintln!(
                            "num_vars={} pc={:?} next={:?} raw={:?} corr_var={:?}",
                            original.relation.num_vars,
                            original.pc,
                            original.next_pc,
                            original.raw_next,
                            original.pc_correction
                        );
                        break;
                    }
                }
                panic!(
                    "compressed row {cycle} correction={correction} pc={pc:#x} input_kind={}",
                    input.kind()
                );
            }
        }
    }

    #[test]
    fn dynamic_jump_witness_satisfies_relation() {
        use magnetar_executor::execute;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};
        let trace = execute(
            &ProgramImage::new(
                0x1000,
                vec![
                    Instruction {
                        op: Op::Jal,
                        rd: 1,
                        rs1: 0,
                        rs2: 0,
                        imm: 8,
                        shamt: 0,
                    }
                    .encode(),
                    Instruction {
                        op: Op::Addi,
                        rd: 2,
                        rs1: 0,
                        rs2: 0,
                        imm: 1,
                        shamt: 0,
                    }
                    .encode(),
                    Instruction::new(Op::Ecall).encode(),
                ],
            ),
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 100,
            },
        )
        .unwrap();
        let rows = mixed_alu_branch_rows_from_trace(&trace, 8).unwrap();
        let mask = mixed_rows_component_mask(&rows);
        let original = DynamicMixedRow::build(mask, 8).unwrap();
        for (pc, input) in rows {
            let bits = original.witness_at(pc, &input, false).unwrap();
            if !original.relation.check(&bits) {
                let parity =
                    |terms: &[usize]| terms.iter().filter(|term| bits[**term]).count() % 2 == 1;
                for (index, row) in original.relation.rows.iter().enumerate() {
                    let a = parity(&row.a);
                    let b = parity(&row.b);
                    let c = parity(&row.c);
                    if (a && b) != c {
                        eprintln!(
                            "fail row {index} a={:?} b={:?} c={:?} pc={pc:#x}",
                            row.a, row.b, row.c
                        );
                        break;
                    }
                }
                eprintln!(
                    "num_vars={} offsets={:?} pc={:?} next={:?} selectors={:?}",
                    original.relation.num_vars,
                    original.offsets,
                    original.pc,
                    original.next_pc,
                    original.selectors
                );
                panic!("dynamic jump row relation mask={mask}");
            }
        }
    }

    #[test]
    fn jump_relation_check() {
        let row = JumpPcRow::new(8);
        let active = row.witness_at(0x1000, 0x1008);
        assert!(row.relation.check(&active), "active jump relation");
        let inactive = row.witness_bits(0, 0);
        assert!(row.relation.check(&inactive), "inactive jump relation");
    }

    #[test]
    fn small_alu_branch_mem_trace_binds_witness() {
        use magnetar_executor::execute;
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Lui,
                    rd: 20,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x1000_0000,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Lw,
                    rd: 6,
                    rs1: 20,
                    rs2: 0,
                    imm: 2,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(
            &program,
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 100,
            },
        )
        .unwrap();
        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let (proof, layout) = prove_small_alu_branch_trace(&trace, 8, &backend).unwrap();
        verify_small_alu_branch_trace(&trace, &proof, &layout, 8, &backend).unwrap();
    }

    #[test]
    fn small_alu_branch_rejects_shift_trace() {
        use magnetar_executor::execute;
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Lui,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x10,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Slli,
                    rd: 1,
                    rs1: 1,
                    rs2: 0,
                    imm: 0,
                    shamt: 2,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(
            &program,
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 100,
            },
        )
        .unwrap();
        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        assert!(prove_small_alu_branch_trace(&trace, 8, &backend).is_err());
    }

    #[test]
    fn alu_branch_trace_binds_witness() {
        use magnetar_executor::execute;
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 11,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(
            &program,
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 100,
            },
        )
        .unwrap();
        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        for row in &trace.rows {
            eprintln!(
                "row pc={:x} micro={:?} op={}",
                row.pc,
                row.micro_op,
                row.instruction.op.name()
            );
        }
        eprintln!("final pc={:x}", trace.final_state.pc);
        let (proof, layout) = prove_alu_branch_trace(&trace, 8, &backend).unwrap();
        verify_alu_branch_trace(&trace, &proof, &layout, 8, &backend).unwrap();
    }

    #[test]
    fn alu_branch_pc_batch_round_trips() {
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;

        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let initial = 0x1000;
        let final_pc = initial + 4 * 16;
        let (proof, layout) =
            prove_alu_branch_pc_batch_bits(8, 16, initial, final_pc, &backend).unwrap();
        verify_alu_branch_pc_batch_bits(8, 16, initial, final_pc, &proof, &layout, &backend)
            .unwrap();
    }

    #[test]
    fn branch_pc_batch_round_trips() {
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;

        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let initial = 0x1000;
        let final_pc = initial + 8 * 16;
        let (proof, layout) =
            prove_branch_pc_batch_bits(8, 16, initial, final_pc, &backend).unwrap();
        verify_branch_pc_batch_bits(8, 16, initial, final_pc, &proof, &layout, &backend).unwrap();
    }

    #[test]
    fn sdiv_pc_batch_round_trips() {
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;

        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let initial = 0x1000;
        let final_pc = initial + 4 * 16;
        let (proof, layout) = prove_sdiv_pc_batch_bits(8, 16, initial, final_pc, &backend).unwrap();
        verify_sdiv_pc_batch_bits(8, 16, initial, final_pc, &proof, &layout, &backend).unwrap();
    }

    #[test]
    fn div_pc_batch_round_trips() {
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;

        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let initial = 0x1000;
        let final_pc = initial + 4 * 16;
        let (proof, layout) = prove_div_pc_batch_bits(8, 16, initial, final_pc, &backend).unwrap();
        verify_div_pc_batch_bits(8, 16, initial, final_pc, &proof, &layout, &backend).unwrap();
    }

    #[test]
    fn mem_pc_batch_round_trips() {
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;

        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let initial = 0x1000;
        let final_pc = initial + 4 * 16;
        let (proof, layout) = prove_mem_pc_batch_bits(8, 16, initial, final_pc, &backend).unwrap();
        verify_mem_pc_batch_bits(8, 16, initial, final_pc, &proof, &layout, &backend).unwrap();
        assert!(
            verify_mem_pc_batch_bits(8, 16, initial, final_pc + 4, &proof, &layout, &backend)
                .is_err()
        );
    }

    #[test]
    fn mul_pc_batch_round_trips() {
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;

        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let initial = 0x1000;
        let final_pc = initial + 4 * 16;
        let (proof, layout) = prove_mul_pc_batch_bits(8, 16, initial, final_pc, &backend).unwrap();
        verify_mul_pc_batch_bits(8, 16, initial, final_pc, &proof, &layout, &backend).unwrap();
        assert!(
            verify_mul_pc_batch_bits(8, 16, initial, final_pc + 4, &proof, &layout, &backend)
                .is_err()
        );
    }

    #[test]
    fn shift_pc_batch_round_trips() {
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;

        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let initial = 0x1000;
        let final_pc = initial + 4 * 16;
        let (proof, layout) =
            prove_shift_pc_batch_bits(8, 16, initial, final_pc, &backend).unwrap();
        verify_shift_pc_batch_bits(8, 16, initial, final_pc, &proof, &layout, &backend).unwrap();
        assert!(verify_shift_pc_batch_bits(
            8,
            16,
            initial,
            final_pc + 4,
            &proof,
            &layout,
            &backend
        )
        .is_err());
    }

    #[test]
    fn selected_pc_virtual_specs_partition_their_layouts() {
        let batches = [
            alu_pc_virtual_specs(8, 16),
            shift_pc_virtual_specs(8, 16),
            mem_pc_virtual_specs(8, 16),
            mul_pc_virtual_specs(8, 16),
            div_pc_virtual_specs(8, 16),
            branch_pc_virtual_specs(8, 16),
        ];
        for specs in batches {
            let specs = specs.unwrap();
            let mut ranges = specs
                .iter()
                .flat_map(|spec| spec.sources.iter().copied())
                .collect::<Vec<_>>();
            ranges.sort_by_key(|(start, _)| *start);
            let mut cursor = 0usize;
            for (start, len) in ranges {
                assert_eq!(start, cursor);
                assert!(len > 0);
                cursor += len;
            }
            assert!(cursor > 0);
        }
    }

    #[test]
    fn alu_pc_virtual_specs_partition_the_layout() {
        let specs = alu_pc_virtual_specs(8, 16).unwrap();
        let mut ranges = specs
            .iter()
            .flat_map(|spec| spec.sources.iter().copied())
            .collect::<Vec<_>>();
        ranges.sort_by_key(|(start, _)| *start);
        let mut cursor = 0usize;
        for (start, len) in ranges {
            assert_eq!(start, cursor);
            assert!(len > 0);
            cursor += len;
        }
        assert!(cursor > 0);
    }

    #[test]
    fn selected_pc_segmented_batches_round_trip() {
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;

        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let initial = 0x1000;
        let final_pc = initial + 4 * 16;
        let (proof, layout) =
            prove_shift_pc_segmented_batch_bits(8, 16, initial, final_pc, &backend).unwrap();
        assert!(layout.segments.len() > 2);
        verify_shift_pc_segmented_batch_bits(8, 16, initial, final_pc, &proof, &layout, &backend)
            .unwrap();

        let (proof, layout) =
            prove_mem_pc_segmented_batch_bits(8, 16, initial, final_pc, &backend).unwrap();
        assert!(layout.segments.len() > 2);
        verify_mem_pc_segmented_batch_bits(8, 16, initial, final_pc, &proof, &layout, &backend)
            .unwrap();

        let branch_final = initial + 8 * 16;
        let (proof, layout) =
            prove_branch_pc_segmented_batch_bits(8, 16, initial, branch_final, &backend).unwrap();
        assert!(layout.segments.len() > 2);
        verify_branch_pc_segmented_batch_bits(
            8,
            16,
            initial,
            branch_final,
            &proof,
            &layout,
            &backend,
        )
        .unwrap();
    }

    #[test]
    fn selected_cpu_claims_round_trip() {
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;

        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let initial = 0x1000;
        let final_pc = initial + 4 * 16;
        let claims =
            prove_selected_cpu_claims(SelectedOp::Alu, 8, 16, initial, final_pc, &backend).unwrap();
        assert_eq!(claims.segments.len(), claims.layout.segments.len());
        verify_selected_cpu_claims(&claims, &backend).unwrap();
        let bytes = bincode::serialize(&claims).unwrap();
        let decoded: SelectedCpuClaims<_, _> = bincode::deserialize(&bytes).unwrap();
        verify_selected_cpu_claims(&decoded, &backend).unwrap();
    }

    #[test]
    fn segmented_claims_route_by_owner() {
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;

        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let initial = 0x1000;
        let final_pc = initial + 4 * 16;
        let (proof, layout) =
            prove_alu_pc_segmented_batch_bits(8, 16, initial, final_pc, &backend).unwrap();
        let claims = selected_segment_claims(&layout, &proof).unwrap();
        assert_eq!(claims.len(), layout.segments.len());
        assert!(claims.iter().any(|claim| claim.owner == SegmentOwner::Pcs));
        assert!(claims.iter().any(|claim| claim.owner == SegmentOwner::Cpu));
        let pc_claims = selected_claim_values_by_owner(&layout, &proof, SegmentOwner::Pcs).unwrap();
        assert_eq!(
            pc_claims.len(),
            layout
                .segments
                .iter()
                .filter(|segment| segment.owner == SegmentOwner::Pcs)
                .count()
        );
    }

    #[test]
    fn alu_pc_segmented_batch_round_trips() {
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;

        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let initial = 0x1000;
        let final_pc = initial + 4 * 16;
        let (proof, layout) =
            prove_alu_pc_segmented_batch_bits(8, 16, initial, final_pc, &backend).unwrap();
        assert!(layout.segments.len() > 2);
        verify_alu_pc_segmented_batch_bits(8, 16, initial, final_pc, &proof, &layout, &backend)
            .unwrap();
    }

    #[test]
    fn alu_pc_batch_round_trips() {
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;

        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let initial = 0x1000;
        let final_pc = initial + 4 * 16;
        let (proof, layout) = prove_alu_pc_batch_bits(8, 16, initial, final_pc, &backend).unwrap();
        verify_alu_pc_batch_bits(8, 16, initial, final_pc, &proof, &layout, &backend).unwrap();
        assert!(
            verify_alu_pc_batch_bits(8, 16, initial, final_pc + 4, &proof, &layout, &backend)
                .is_err()
        );
    }

    #[test]
    fn alu_only_batch_round_trips() {
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::RingSwitchPackedBitPcs;

        let backend =
            RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let (proof, layout) = prove_alu_only_batch_bits(8, 16, &backend).unwrap();
        verify_alu_only_batch_bits(8, 16, &proof, &layout, &backend).unwrap();
    }

    #[test]
    fn gated_dual_batch_runs_with_both_backends_on_q2_q4_q8() {
        use magnetar_proof::{DirectBitPcs, RingSwitchPackedBitPcs};

        for cycles in [2usize, 4, 8] {
            let rows = (0..cycles)
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

    #[test]
    fn shared_matrix_cpu_claims_verify() {
        use crate::simd_f2::{GatedAluOp, GatedCpuRowInput};
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::spartan::prove_lockstep_claims_with_matrices;
        use magnetar_proof::spartan::verify_lockstep_claims_with_matrices;
        use magnetar_proof::Pcs;

        let rows = vec![
            (
                0x1000,
                GatedCpuRowInput::Alu {
                    left: 1,
                    right: 2,
                    op: GatedAluOp::Add,
                },
            ),
            (
                0x1004,
                GatedCpuRowInput::Alu {
                    left: 3,
                    right: 1,
                    op: GatedAluOp::Xor,
                },
            ),
            (
                0x1008,
                GatedCpuRowInput::Alu {
                    left: 5,
                    right: 2,
                    op: GatedAluOp::Sub,
                },
            ),
            (
                0x100c,
                GatedCpuRowInput::Alu {
                    left: 6,
                    right: 3,
                    op: GatedAluOp::And,
                },
            ),
        ];
        let (z, a0, a1, layout) = gated_claim_inputs(8, &rows).unwrap();
        let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
        let commitment = pcs.commit(&z).unwrap();
        let (claims, _ry) = prove_lockstep_claims_with_matrices(
            &z, &a0[0], &a0[1], &a0[2], &a1[0], &a1[1], &a1[2], &layout, &pcs, commitment,
        )
        .unwrap();
        verify_lockstep_claims_with_matrices(
            &a0[0], &a0[1], &a0[2], &a1[0], &a1[1], &a1[2], &layout, &claims, &pcs,
        )
        .unwrap();
    }
}

/// A matrix view over a virtual (padded/gathered) witness layout.
///
/// `mapping[original] = virtual` places each original column in the virtual
/// witness; unused virtual columns are padding.
pub struct ScatterMatrix<M: magnetar_proof::SpartanMatrix> {
    pub inner: M,
    pub mapping: Vec<usize>,
    pub cols: usize,
}

impl<M: magnetar_proof::SpartanMatrix> magnetar_proof::SpartanMatrix for ScatterMatrix<M> {
    fn rows(&self) -> usize {
        self.inner.rows()
    }

    fn cols(&self) -> usize {
        self.cols
    }

    fn mul_vec(&self, z: &[F2_128]) -> Result<Vec<F2_128>, magnetar_proof::SpartanError> {
        let mut original = vec![F2_128::from(0u64); self.mapping.len()];
        for (index, virtual_index) in self.mapping.iter().enumerate() {
            original[index] = z[*virtual_index];
        }
        self.inner.mul_vec(&original)
    }

    fn row_combination(
        &self,
        row_point: &[F2_128],
    ) -> Result<Vec<F2_128>, magnetar_proof::SpartanError> {
        let original = self.inner.row_combination(row_point)?;
        let mut virtual_values = vec![F2_128::from(0u64); self.cols];
        for (index, value) in original.into_iter().enumerate() {
            virtual_values[self.mapping[index]] = value;
        }
        Ok(virtual_values)
    }

    fn eval_mle(
        &self,
        row_point: &[F2_128],
        col_point: &[F2_128],
    ) -> Result<F2_128, magnetar_proof::SpartanError> {
        let values = self.row_combination(row_point)?;
        magnetar_proof::Mle::new(values)
            .and_then(|mle| mle.eval(col_point))
            .map_err(magnetar_proof::SpartanError::Proof)
    }
}

#[cfg(test)]
mod virtual_spec_tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    fn config() -> MachineConfig {
        MachineConfig {
            entry: 0x10,
            rom_base: 0x10,
            ram_base: 0x40,
            ram_size: 0x40,
            stack_top: 0x80,
            max_cycles: 8,
        }
    }

    fn simple_trace() -> magnetar_spec::Trace {
        let program = ProgramImage::new(
            0x10,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 7,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        execute(&program, config()).unwrap()
    }

    fn load_trace() -> magnetar_spec::Trace {
        let mut data = vec![0u8; 8];
        data.copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        let program = ProgramImage::new(
            0x10,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x40,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Ld,
                    rd: 2,
                    rs1: 1,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        )
        .with_data(data);
        execute(&program, config()).unwrap()
    }

    fn shift_trace() -> magnetar_spec::Trace {
        let program = ProgramImage::new(
            0x10,
            vec![
                Instruction {
                    op: Op::Slli,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 0,
                    shamt: 5,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        execute(&program, config()).unwrap()
    }

    #[test]
    fn shift_subsegment_is_filled_from_router() {
        let width = 16usize;
        let trace = shift_trace();
        let rows = crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(&trace, width)
            .unwrap();
        let cycles = rows.len();
        let (_, _, layout) = reservation_claim_matrices(width, cycles).unwrap();
        let base_cols = layout.total_bits / cycles;
        let specs = reservation_virtual_specs(width, cycles, base_cols);
        let padded = crate::build_padded_virtual_layout(&specs).unwrap();
        let (z, _, _, _) = reservation_claim_inputs(width, &rows).unwrap();
        let router = crate::binary_router::BinaryRouterWitness::from_trace_mode(
            &trace,
            crate::binary_router::RouterMode::Shifts,
        )
        .unwrap();
        let mut virtual_values = vec![F2_128::from(0u64); padded.layout.total_bits];
        for spec in &specs {
            let map = padded
                .mapping
                .iter()
                .find(|map| map.sources == spec.sources)
                .unwrap();
            let mut cursor = map.padded_offset;
            for (original, len) in &spec.sources {
                virtual_values[cursor..cursor + len]
                    .copy_from_slice(&z[*original..*original + len]);
                cursor += len;
            }
            let target = match spec.name.as_str() {
                "shift_sll" => Some(crate::simd_f2::BitShiftKind::Sll),
                "shift_srl" => Some(crate::simd_f2::BitShiftKind::Srl),
                "shift_sra" => Some(crate::simd_f2::BitShiftKind::Sra),
                _ => None,
            };
            if let Some(target) = target {
                let mut cursor = map.padded_offset;
                for (cycle, (_, len)) in spec.sources.iter().enumerate() {
                    if let crate::simd_f2::GatedCpuRowInput::Shift { kind, .. } = &rows[cycle].1.cpu
                    {
                        if *kind == target {
                            let shamt = (0..64)
                                .find(|value| router.shift_q[*value][cycle].value() == 1)
                                .unwrap_or(0);
                            for bit in 0..*len {
                                virtual_values[cursor + bit] =
                                    F2_128::from(((shamt as u64) >> bit) & 1);
                            }
                        }
                    }
                    cursor += len;
                }
            }
        }
        assert_eq!(padded.unpad_values(&virtual_values), z);
    }

    #[test]
    fn grouped_gated_system_links_consecutive_cycles() {
        let width = 8usize;
        let trace = simple_trace();
        let rows = crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(&trace, width)
            .unwrap();
        let (system, system2, witness, base_cols) =
            super::grouped_gated_system(width, &rows, 2).unwrap();
        magnetar_constraint::Witness::new(witness.clone());
        system
            .check(&magnetar_constraint::Witness::new(witness.clone()))
            .unwrap();
        system2
            .check(&magnetar_constraint::Witness::new(witness.clone()))
            .unwrap();
        let row = crate::reservation_cpu_row::ReservationCpuRow::new(width);
        let mut broken = witness;
        let index = base_cols + row.cpu.pc[0];
        broken[index] = broken[index] + F2_128::from(1u64);
        assert!(system2
            .check(&magnetar_constraint::Witness::new(broken))
            .is_err());
    }

    #[test]
    fn grouped_simd_lockstep_proves() {
        use magnetar_constraint::{Segment, SegmentKind, SegmentOwner, WitnessLayout};
        use magnetar_pcs::P3BinaryPcs;
        use magnetar_proof::spartan::MatrixPart;
        use magnetar_proof::{
            prove_lockstep_bits, verify_lockstep_bits, DirectBitPcs, SharedBlockMatrix,
        };
        let width = 8usize;
        let program = magnetar_spec::ProgramImage::new(
            0x10,
            vec![
                magnetar_spec::Instruction {
                    op: magnetar_spec::Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 1,
                    shamt: 0,
                }
                .encode(),
                magnetar_spec::Instruction {
                    op: magnetar_spec::Op::Addi,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
                    imm: 2,
                    shamt: 0,
                }
                .encode(),
                magnetar_spec::Instruction {
                    op: magnetar_spec::Op::Addi,
                    rd: 3,
                    rs1: 0,
                    rs2: 0,
                    imm: 3,
                    shamt: 0,
                }
                .encode(),
                magnetar_spec::Instruction::new(magnetar_spec::Op::Ecall).encode(),
            ],
        );
        let trace = magnetar_executor::execute(
            &program,
            magnetar_spec::MachineConfig {
                entry: 0x10,
                rom_base: 0x10,
                ram_base: 0x1000_0000,
                ram_size: 0x1000,
                stack_top: 0x1000_1000,
                max_cycles: 100,
            },
        )
        .unwrap();
        let rows = crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(&trace, width)
            .unwrap();
        let cycles = rows.len();
        let group = 2usize;
        let groups = cycles / group;
        let (system, system2, z, row_cols) =
            super::grouped_gated_system(width, &rows, group).unwrap();
        let block_cols = (system.num_vars + 1).next_power_of_two();
        let row = crate::reservation_cpu_row::ReservationCpuRow::new(width);
        let mut extra_a = Vec::new();
        let mut extra_b = Vec::new();
        let mut extra_c = Vec::new();
        for instance in 0..groups - 1 {
            for bit in 0..width {
                extra_a.push(vec![(
                    instance * block_cols + (group - 1) * row_cols + row.cpu.next_pc[bit],
                    F2_128::from(1u64),
                )]);
                extra_b.push(vec![(
                    instance * block_cols + (group - 1) * row_cols + row.cpu.alu.one,
                    F2_128::from(1u64),
                )]);
                extra_c.push(vec![(
                    (instance + 1) * block_cols + row.cpu.pc[bit],
                    F2_128::from(1u64),
                )]);
            }
        }
        let zero = vec![Vec::new(); extra_a.len()];
        let a0 = SharedBlockMatrix::from_system(&system, MatrixPart::A, groups)
            .unwrap()
            .with_extra_rows(zero.clone());
        let b0 = SharedBlockMatrix::from_system(&system, MatrixPart::B, groups)
            .unwrap()
            .with_extra_rows(zero.clone());
        let c0 = SharedBlockMatrix::from_system(&system, MatrixPart::C, groups)
            .unwrap()
            .with_extra_rows(zero);
        let a1 = SharedBlockMatrix::from_system(&system2, MatrixPart::A, groups)
            .unwrap()
            .with_extra_rows(extra_a);
        let b1 = SharedBlockMatrix::from_system(&system2, MatrixPart::B, groups)
            .unwrap()
            .with_extra_rows(extra_b);
        let c1 = SharedBlockMatrix::from_system(&system2, MatrixPart::C, groups)
            .unwrap()
            .with_extra_rows(extra_c);
        let layout = WitnessLayout::new(vec![Segment::new(
            "cpu",
            0,
            z.len(),
            SegmentKind::Direct,
            SegmentOwner::Cpu,
        )])
        .unwrap();
        let bits = z.iter().map(|value| value.value() == 1).collect::<Vec<_>>();
        let backend = DirectBitPcs::new(P3BinaryPcs::new(100));
        let proof =
            prove_lockstep_bits(&bits, &a0, &b0, &c0, &a1, &b1, &c1, &layout, &backend).unwrap();
        verify_lockstep_bits(&a0, &b0, &c0, &a1, &b1, &c1, &layout, &proof, &backend).unwrap();
        let mut broken = z;
        let boundary = block_cols + row.cpu.pc[0];
        broken[boundary] = broken[boundary] + F2_128::from(1u64);
        let bits = broken
            .iter()
            .map(|value| value.value() == 1)
            .collect::<Vec<_>>();
        assert!(
            prove_lockstep_bits(&bits, &a0, &b0, &c0, &a1, &b1, &c1, &layout, &backend,).is_err()
        );
    }

    #[test]
    fn grouped_lockstep_layout_round_trips() {
        use magnetar_pcs::P3BinaryPcs;
        use magnetar_proof::{prove_lockstep_bits, verify_lockstep_bits, DirectBitPcs};
        let width = 8usize;
        let program = magnetar_spec::ProgramImage::new(
            0x10,
            vec![
                magnetar_spec::Instruction {
                    op: magnetar_spec::Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 1,
                    shamt: 0,
                }
                .encode(),
                magnetar_spec::Instruction {
                    op: magnetar_spec::Op::Addi,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
                    imm: 2,
                    shamt: 0,
                }
                .encode(),
                magnetar_spec::Instruction {
                    op: magnetar_spec::Op::Addi,
                    rd: 3,
                    rs1: 0,
                    rs2: 0,
                    imm: 3,
                    shamt: 0,
                }
                .encode(),
                magnetar_spec::Instruction::new(magnetar_spec::Op::Ecall).encode(),
            ],
        );
        let trace = magnetar_executor::execute(
            &program,
            magnetar_spec::MachineConfig {
                entry: 0x10,
                rom_base: 0x10,
                ram_base: 0x1000_0000,
                ram_size: 0x1000,
                stack_top: 0x1000_1000,
                max_cycles: 100,
            },
        )
        .unwrap();
        let rows = crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(&trace, width)
            .unwrap();
        let (z, a0, a1, layout) = super::reservation_grouped_lockstep(width, &rows, 2).unwrap();
        assert_eq!(z.len(), layout.total_bits);
        let bits = z.iter().map(|value| value.value() == 1).collect::<Vec<_>>();
        let backend = DirectBitPcs::new(P3BinaryPcs::new(100));
        let proof = prove_lockstep_bits(
            &bits, &a0[0], &a0[1], &a0[2], &a1[0], &a1[1], &a1[2], &layout, &backend,
        )
        .unwrap();
        verify_lockstep_bits(
            &a0[0], &a0[1], &a0[2], &a1[0], &a1[1], &a1[2], &layout, &proof, &backend,
        )
        .unwrap();
    }

    #[test]
    fn grouped_lockstep_supports_four_cycles_per_instance() {
        use magnetar_pcs::P3BinaryPcs;
        use magnetar_proof::{prove_lockstep_bits, verify_lockstep_bits, DirectBitPcs};
        let width = 8usize;
        let mut rom = (1..=8)
            .map(|index| {
                magnetar_spec::Instruction {
                    op: magnetar_spec::Op::Addi,
                    rd: (index % 8) as u8,
                    rs1: 0,
                    rs2: 0,
                    imm: index,
                    shamt: 0,
                }
                .encode()
            })
            .collect::<Vec<_>>();
        rom.push(magnetar_spec::Instruction::new(magnetar_spec::Op::Ecall).encode());
        let program = magnetar_spec::ProgramImage::new(0x10, rom);
        let trace = magnetar_executor::execute(
            &program,
            magnetar_spec::MachineConfig {
                entry: 0x10,
                rom_base: 0x10,
                ram_base: 0x1000_0000,
                ram_size: 0x1000,
                stack_top: 0x1000_1000,
                max_cycles: 100,
            },
        )
        .unwrap();
        let rows = crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(&trace, width)
            .unwrap();
        let (z, a0, a1, layout) = super::reservation_grouped_lockstep(width, &rows, 4).unwrap();
        assert_eq!(z.len(), layout.total_bits);
        let bits = z.iter().map(|value| value.value() == 1).collect::<Vec<_>>();
        let backend = DirectBitPcs::new(P3BinaryPcs::new(100));
        let proof = prove_lockstep_bits(
            &bits, &a0[0], &a0[1], &a0[2], &a1[0], &a1[1], &a1[2], &layout, &backend,
        )
        .unwrap();
        verify_lockstep_bits(
            &a0[0], &a0[1], &a0[2], &a1[0], &a1[1], &a1[2], &layout, &proof, &backend,
        )
        .unwrap();
    }

    #[test]
    fn grouped_virtual_layout_round_trips() {
        let width = 8usize;
        let program = magnetar_spec::ProgramImage::new(
            0x10,
            vec![
                magnetar_spec::Instruction {
                    op: magnetar_spec::Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 1,
                    shamt: 0,
                }
                .encode(),
                magnetar_spec::Instruction {
                    op: magnetar_spec::Op::Addi,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
                    imm: 2,
                    shamt: 0,
                }
                .encode(),
                magnetar_spec::Instruction {
                    op: magnetar_spec::Op::Addi,
                    rd: 3,
                    rs1: 0,
                    rs2: 0,
                    imm: 3,
                    shamt: 0,
                }
                .encode(),
                magnetar_spec::Instruction::new(magnetar_spec::Op::Ecall).encode(),
            ],
        );
        let trace = magnetar_executor::execute(
            &program,
            magnetar_spec::MachineConfig {
                entry: 0x10,
                rom_base: 0x10,
                ram_base: 0x1000_0000,
                ram_size: 0x1000,
                stack_top: 0x1000_1000,
                max_cycles: 100,
            },
        )
        .unwrap();
        let rows = crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(&trace, width)
            .unwrap();
        let cycles = rows.len();
        let group = 2usize;
        let (z_group, a0, _, _) = super::reservation_grouped_lockstep(width, &rows, group).unwrap();
        let block_cols = a0[0].cols() / (cycles / group);
        let (_, _, layout) = reservation_claim_matrices(width, cycles).unwrap();
        let base_cols = layout.total_bits / cycles;
        let row_vars = crate::reservation_cpu_row::ReservationCpuRow::new(width)
            .cpu
            .relation
            .num_vars;
        let specs = reservation_virtual_specs(width, cycles, base_cols);
        let grouped =
            super::group_virtual_specs(&specs, cycles, base_cols, row_vars, block_cols, group);
        let padded = crate::build_padded_virtual_layout(&grouped).unwrap();
        let virtual_values = padded.pad_values(&z_group);
        assert_eq!(virtual_values.len(), padded.layout.total_bits);
        assert_eq!(padded.unpad_values(&virtual_values), z_group);
    }

    #[test]
    fn grouped_virtual_lockstep_proves() {
        use magnetar_pcs::P3BinaryPcs;
        use magnetar_proof::{prove_lockstep_bits, verify_lockstep_bits, DirectBitPcs};
        let width = 8usize;
        let program = magnetar_spec::ProgramImage::new(
            0x10,
            vec![
                magnetar_spec::Instruction {
                    op: magnetar_spec::Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 1,
                    shamt: 0,
                }
                .encode(),
                magnetar_spec::Instruction {
                    op: magnetar_spec::Op::Addi,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
                    imm: 2,
                    shamt: 0,
                }
                .encode(),
                magnetar_spec::Instruction {
                    op: magnetar_spec::Op::Addi,
                    rd: 3,
                    rs1: 0,
                    rs2: 0,
                    imm: 3,
                    shamt: 0,
                }
                .encode(),
                magnetar_spec::Instruction::new(magnetar_spec::Op::Ecall).encode(),
            ],
        );
        let trace = magnetar_executor::execute(
            &program,
            magnetar_spec::MachineConfig {
                entry: 0x10,
                rom_base: 0x10,
                ram_base: 0x1000_0000,
                ram_size: 0x1000,
                stack_top: 0x1000_1000,
                max_cycles: 100,
            },
        )
        .unwrap();
        let rows = crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(&trace, width)
            .unwrap();
        let cycles = rows.len();
        let group = 2usize;
        let (z_group, a0, a1, _) =
            super::reservation_grouped_lockstep(width, &rows, group).unwrap();
        let block_cols = a0[0].cols() / (cycles / group);
        let (_, _, layout) = reservation_claim_matrices(width, cycles).unwrap();
        let base_cols = layout.total_bits / cycles;
        let row = crate::reservation_cpu_row::ReservationCpuRow::new(width);
        let specs = reservation_virtual_specs(width, cycles, base_cols);
        let grouped = super::group_virtual_specs(
            &specs,
            cycles,
            base_cols,
            row.cpu.relation.num_vars,
            block_cols,
            group,
        );
        let padded = crate::build_padded_virtual_layout(&grouped).unwrap();
        let mut mapping = vec![0usize; z_group.len()];
        for map in &padded.mapping {
            let mut cursor = map.padded_offset;
            for (original, len) in &map.sources {
                for offset in 0..*len {
                    mapping[original + offset] = cursor + offset;
                }
                cursor += len;
            }
        }
        let wrap = |matrix| super::ScatterMatrix {
            inner: matrix,
            mapping: mapping.clone(),
            cols: padded.layout.total_bits,
        };
        let va0 = [
            wrap(a0[0].clone()),
            wrap(a0[1].clone()),
            wrap(a0[2].clone()),
        ];
        let va1 = [
            wrap(a1[0].clone()),
            wrap(a1[1].clone()),
            wrap(a1[2].clone()),
        ];
        let virtual_values = padded.pad_values(&z_group);
        let bits = virtual_values
            .iter()
            .map(|value| value.value() == 1)
            .collect::<Vec<_>>();
        let backend = DirectBitPcs::new(P3BinaryPcs::new(100));
        let proof = prove_lockstep_bits(
            &bits,
            &va0[0],
            &va0[1],
            &va0[2],
            &va1[0],
            &va1[1],
            &va1[2],
            &padded.layout,
            &backend,
        )
        .unwrap();
        verify_lockstep_bits(
            &va0[0],
            &va0[1],
            &va0[2],
            &va1[0],
            &va1[1],
            &va1[2],
            &padded.layout,
            &proof,
            &backend,
        )
        .unwrap();
        let boundary = mapping[block_cols + row.cpu.pc[0]];
        let mut broken = bits;
        broken[boundary] = !broken[boundary];
        assert!(prove_lockstep_bits(
            &broken,
            &va0[0],
            &va0[1],
            &va0[2],
            &va1[0],
            &va1[1],
            &va1[2],
            &padded.layout,
            &backend,
        )
        .is_err());
    }

    #[test]
    fn grouped_component_claims_match_virtual_segments() {
        use magnetar_pcs::P3BinaryPcs;
        use magnetar_proof::{prove_lockstep_bits_with_point, DirectBitPcs};
        let width = 8usize;
        let program = magnetar_spec::ProgramImage::new(
            0x10,
            vec![
                magnetar_spec::Instruction {
                    op: magnetar_spec::Op::Lui,
                    rd: 20,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x1000_0000,
                    shamt: 0,
                }
                .encode(),
                magnetar_spec::Instruction {
                    op: magnetar_spec::Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 1,
                    shamt: 0,
                }
                .encode(),
                magnetar_spec::Instruction {
                    op: magnetar_spec::Op::Sd,
                    rd: 0,
                    rs1: 20,
                    rs2: 1,
                    imm: 8,
                    shamt: 0,
                }
                .encode(),
                magnetar_spec::Instruction::new(magnetar_spec::Op::Ecall).encode(),
            ],
        );
        let trace = magnetar_executor::execute(
            &program,
            magnetar_spec::MachineConfig {
                entry: 0x10,
                rom_base: 0x10,
                ram_base: 0x1000_0000,
                ram_size: 0x1000,
                stack_top: 0x1000_1000,
                max_cycles: 100,
            },
        )
        .unwrap();
        let rows = crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(&trace, width)
            .unwrap();
        let cycles = rows.len();
        let group = 2usize;
        let (z_group, a0, a1, _) =
            super::reservation_grouped_lockstep(width, &rows, group).unwrap();
        let block_cols = a0[0].cols() / (cycles / group);
        let (_, _, layout) = reservation_claim_matrices(width, cycles).unwrap();
        let base_cols = layout.total_bits / cycles;
        let row = crate::reservation_cpu_row::ReservationCpuRow::new(width);
        let specs = reservation_virtual_specs(width, cycles, base_cols);
        let grouped = super::group_virtual_specs(
            &specs,
            cycles,
            base_cols,
            row.cpu.relation.num_vars,
            block_cols,
            group,
        );
        let padded = crate::build_padded_virtual_layout(&grouped).unwrap();
        let mut mapping = vec![0usize; z_group.len()];
        for map in &padded.mapping {
            let mut cursor = map.padded_offset;
            for (original, len) in &map.sources {
                for offset in 0..*len {
                    mapping[original + offset] = cursor + offset;
                }
                cursor += len;
            }
        }
        let wrap = |matrix| super::ScatterMatrix {
            inner: matrix,
            mapping: mapping.clone(),
            cols: padded.layout.total_bits,
        };
        let va0 = [
            wrap(a0[0].clone()),
            wrap(a0[1].clone()),
            wrap(a0[2].clone()),
        ];
        let va1 = [
            wrap(a1[0].clone()),
            wrap(a1[1].clone()),
            wrap(a1[2].clone()),
        ];
        let virtual_values = padded.pad_values(&z_group);
        let bits = virtual_values
            .iter()
            .map(|value| value.value() == 1)
            .collect::<Vec<_>>();
        let backend = DirectBitPcs::new(P3BinaryPcs::new(100));
        let (_, ry) = prove_lockstep_bits_with_point(
            &bits,
            &va0[0],
            &va0[1],
            &va0[2],
            &va1[0],
            &va1[1],
            &va1[2],
            &padded.layout,
            &backend,
        )
        .unwrap();
        let (claims, _) =
            crate::protocol::gated_component_claims(&trace, width, cycles, &padded.layout, &ry)
                .unwrap();
        let mut checked = 0usize;
        for (index, claim) in claims.iter().enumerate() {
            let Some(claim) = claim else { continue };
            let segment = &padded.layout.segments[index];
            let values = virtual_values[segment.offset..segment.end()].to_vec();
            let bits = segment.len.trailing_zeros() as usize;
            let expected = magnetar_proof::Mle::new(values)
                .unwrap()
                .eval(&ry[..bits])
                .unwrap();
            assert_eq!(*claim, expected);
            checked += 1;
        }
        assert!(checked > 0);
    }

    #[test]
    fn grouped_virtual_inputs_prove() {
        use magnetar_pcs::P3BinaryPcs;
        use magnetar_proof::{prove_lockstep_bits, verify_lockstep_bits, DirectBitPcs};
        let width = 8usize;
        let program = magnetar_spec::ProgramImage::new(
            0x10,
            vec![
                magnetar_spec::Instruction {
                    op: magnetar_spec::Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 1,
                    shamt: 0,
                }
                .encode(),
                magnetar_spec::Instruction {
                    op: magnetar_spec::Op::Addi,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
                    imm: 2,
                    shamt: 0,
                }
                .encode(),
                magnetar_spec::Instruction {
                    op: magnetar_spec::Op::Addi,
                    rd: 3,
                    rs1: 0,
                    rs2: 0,
                    imm: 3,
                    shamt: 0,
                }
                .encode(),
                magnetar_spec::Instruction::new(magnetar_spec::Op::Ecall).encode(),
            ],
        );
        let trace = magnetar_executor::execute(
            &program,
            magnetar_spec::MachineConfig {
                entry: 0x10,
                rom_base: 0x10,
                ram_base: 0x1000_0000,
                ram_size: 0x1000,
                stack_top: 0x1000_1000,
                max_cycles: 100,
            },
        )
        .unwrap();
        let rows = crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(&trace, width)
            .unwrap();
        let (z_virtual, a0, a1, layout, mapping, inner) =
            super::reservation_grouped_virtual_inputs(width, &rows, 2).unwrap();
        assert!(inner <= z_virtual.len());
        let wrap = |matrix| super::ScatterMatrix {
            inner: matrix,
            mapping: mapping.clone(),
            cols: layout.total_bits,
        };
        let va0 = [
            wrap(a0[0].clone()),
            wrap(a0[1].clone()),
            wrap(a0[2].clone()),
        ];
        let va1 = [
            wrap(a1[0].clone()),
            wrap(a1[1].clone()),
            wrap(a1[2].clone()),
        ];
        let bits = z_virtual
            .iter()
            .map(|value| value.value() == 1)
            .collect::<Vec<_>>();
        let backend = DirectBitPcs::new(P3BinaryPcs::new(100));
        let proof = prove_lockstep_bits(
            &bits, &va0[0], &va0[1], &va0[2], &va1[0], &va1[1], &va1[2], &layout, &backend,
        )
        .unwrap();
        verify_lockstep_bits(
            &va0[0], &va0[1], &va0[2], &va1[0], &va1[1], &va1[2], &layout, &proof, &backend,
        )
        .unwrap();
    }

    #[test]
    fn reservation_specs_cover_each_gated_instance() {
        let width = 8usize;
        let rows = crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(
            &simple_trace(),
            width,
        )
        .unwrap();
        let cycles = rows.len();
        let (_, _, layout) = reservation_claim_matrices(width, cycles).unwrap();
        let base_cols = layout.total_bits / cycles;
        let specs = reservation_virtual_specs(width, cycles, base_cols);
        let covered = specs
            .iter()
            .map(|spec| spec.sources.iter().map(|(_, len)| *len).sum::<usize>())
            .sum::<usize>();
        assert_eq!(covered, cycles * base_cols);
        assert!(specs
            .iter()
            .any(|spec| spec.owner == SegmentOwner::Memory(MemoryKind::Ram)));
        assert!(specs
            .iter()
            .any(|spec| spec.owner == SegmentOwner::Routing(RoutingKind::Shifts)));
        assert!(specs.iter().any(|spec| spec.owner == SegmentOwner::Pcs));

        let (z, _, _, _) = reservation_claim_inputs(width, &rows).unwrap();
        let padded = crate::build_padded_virtual_layout(&specs).unwrap();
        let mut virtual_values = vec![F2_128::from(0u64); padded.layout.total_bits];
        let pc_row = crate::pc_transition_row::PcTransitionRow::new(width);
        for spec in &specs {
            let map = padded
                .mapping
                .iter()
                .find(|map| map.sources == spec.sources)
                .unwrap();
            let mut cursor = map.padded_offset;
            for (original, len) in &spec.sources {
                virtual_values[cursor..cursor + len]
                    .copy_from_slice(&z[*original..*original + len]);
                cursor += len;
            }
            if let Some(cycle) = spec
                .name
                .strip_prefix("pc")
                .and_then(|suffix| suffix.parse::<usize>().ok())
            {
                let (pc, _) = &rows[cycle];
                let component = pc_row.witness(*pc, *pc, true);
                for bit in 0..spec.sources.iter().map(|(_, len)| *len).sum::<usize>() {
                    virtual_values[map.padded_offset + bit] =
                        F2_128::from(u64::from(component[pc_row.pc[bit]]));
                }
            }
        }
        assert_eq!(padded.unpad_values(&virtual_values), z);
    }

    #[test]
    fn virtual_witness_lockstep_proves() {
        use magnetar_pcs::P3BinaryPcs;
        use magnetar_proof::{prove_lockstep_bits, verify_lockstep_bits, DirectBitPcs};
        let width = 8usize;
        let trace = simple_trace();
        let rows = crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(&trace, width)
            .unwrap();
        let cycles = rows.len();
        let (a0, a1, _) = reservation_claim_matrices(width, cycles).unwrap();
        let (z, _, _, _) = reservation_claim_inputs(width, &rows).unwrap();
        let base_cols = a0[0].cols() / cycles;
        let specs = reservation_virtual_specs(width, cycles, base_cols);
        let padded = crate::build_padded_virtual_layout(&specs).unwrap();
        let z_virtual = padded.pad_values(&z);
        assert_eq!(z_virtual.len(), padded.layout.total_bits);
        let mut mapping = vec![0usize; z.len()];
        for map in &padded.mapping {
            let mut cursor = map.padded_offset;
            for (original, len) in &map.sources {
                for offset in 0..*len {
                    mapping[original + offset] = cursor + offset;
                }
                cursor += len;
            }
        }
        let wrap = |matrix| ScatterMatrix {
            inner: matrix,
            mapping: mapping.clone(),
            cols: padded.layout.total_bits,
        };
        let va0 = [
            wrap(a0[0].clone()),
            wrap(a0[1].clone()),
            wrap(a0[2].clone()),
        ];
        let va1 = [
            wrap(a1[0].clone()),
            wrap(a1[1].clone()),
            wrap(a1[2].clone()),
        ];
        let bits = z_virtual
            .iter()
            .map(|value| value.value() == 1)
            .collect::<Vec<_>>();
        let backend = DirectBitPcs::new(P3BinaryPcs::new(100));
        let proof = prove_lockstep_bits(
            &bits,
            &va0[0],
            &va0[1],
            &va0[2],
            &va1[0],
            &va1[1],
            &va1[2],
            &padded.layout,
            &backend,
        )
        .unwrap();
        verify_lockstep_bits(
            &va0[0],
            &va0[1],
            &va0[2],
            &va1[0],
            &va1[1],
            &va1[2],
            &padded.layout,
            &proof,
            &backend,
        )
        .unwrap();
    }

    #[test]
    fn memory_subsegment_is_filled_from_twist() {
        let width = 16usize;
        let trace = load_trace();
        let rows = crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(&trace, width)
            .unwrap();
        let cycles = rows.len();
        let (_, _, layout) = reservation_claim_matrices(width, cycles).unwrap();
        let base_cols = layout.total_bits / cycles;
        let specs = reservation_virtual_specs(width, cycles, base_cols);
        let padded = crate::build_padded_virtual_layout(&specs).unwrap();
        let (z, _, _, _) = reservation_claim_inputs(width, &rows).unwrap();
        let twist = magnetar_memory::BinaryTwistWitness::from_trace(&trace).unwrap();
        let mut virtual_values = vec![F2_128::from(0u64); padded.layout.total_bits];
        for spec in &specs {
            let map = padded
                .mapping
                .iter()
                .find(|map| map.sources == spec.sources)
                .unwrap();
            let mut cursor = map.padded_offset;
            for (original, len) in &spec.sources {
                virtual_values[cursor..cursor + len]
                    .copy_from_slice(&z[*original..*original + len]);
                cursor += len;
            }
            if spec.name == "memory_addr" {
                let mut cursor = map.padded_offset;
                let mut event = 0usize;
                for (cycle, (_, len)) in spec.sources.iter().enumerate() {
                    if matches!(
                        rows[cycle].1.cpu,
                        crate::simd_f2::GatedCpuRowInput::Memory { .. }
                    ) {
                        let word = twist.read_address[event]
                            .iter()
                            .position(|bit| bit.value() == 1)
                            .unwrap_or(0);
                        let address = trace.config.ram_base + 8 * word as u64;
                        for bit in 0..*len {
                            virtual_values[cursor + bit] = F2_128::from((address >> bit) & 1);
                        }
                        event += 1;
                    }
                    cursor += len;
                }
            } else if spec.name == "memory_data" {
                let mut cursor = map.padded_offset;
                let mut event = 0usize;
                for (cycle, (_, len)) in spec.sources.iter().enumerate() {
                    if matches!(
                        rows[cycle].1.cpu,
                        crate::simd_f2::GatedCpuRowInput::Memory { .. }
                    ) {
                        let value = twist.read_value[event].value();
                        for bit in 0..*len {
                            virtual_values[cursor + bit] = F2_128::from((value >> bit) & 1);
                        }
                        event += 1;
                    }
                    cursor += len;
                }
            }
        }
        assert_eq!(padded.unpad_values(&virtual_values), z);
    }
}

#[cfg(test)]
mod projection_tests {
    use super::*;
    use crate::simd_f2::GatedCpuRowInput;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    #[test]
    fn router_shift_bits_match_gated_shift_subsegment() {
        let program = ProgramImage::new(
            0x10,
            vec![
                Instruction {
                    op: Op::Slli,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 0,
                    shamt: 5,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let config = MachineConfig {
            entry: 0x10,
            rom_base: 0x10,
            ram_base: 0x40,
            ram_size: 0x40,
            stack_top: 0x80,
            max_cycles: 8,
        };
        let trace = execute(&program, config).unwrap();
        let router = crate::binary_router::BinaryRouterWitness::from_trace_mode(
            &trace,
            crate::binary_router::RouterMode::Shifts,
        )
        .unwrap();
        let rows =
            crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(&trace, 16).unwrap();
        let cpu = crate::reservation_cpu_row::ReservationCpuRow::new(16);
        for (index, (pc, input)) in rows.iter().enumerate() {
            let gated_bits = cpu.witness(*pc, *input);
            let is_shift = gated_bits[cpu.cpu.shift_offset + cpu.cpu.shift.is_shift];
            assert_eq!(
                is_shift,
                router.is_shift[index].value() == 1,
                "is_shift mismatch at {index}"
            );
            if is_shift {
                let mut shamt = 0u64;
                for bit in 0..4 {
                    if gated_bits[cpu.cpu.shift_offset + cpu.cpu.shift.sll.shamt[bit]] {
                        shamt |= 1 << bit;
                    }
                }
                let router_shamt = (0..64)
                    .find(|value| router.shift_q[*value][index].value() == 1)
                    .unwrap_or(0) as u64;
                assert_eq!(shamt, router_shamt, "shift shamt mismatch at {index}");
            }
        }
    }

    #[test]
    fn ram_read_value_eval_matches_gated_data_subsegment() {
        use magnetar_proof::Mle;
        let mut data = vec![0u8; 8];
        data.copy_from_slice(&0x7788u64.to_le_bytes());
        let program = ProgramImage::new(
            0x10,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x40,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Ld,
                    rd: 2,
                    rs1: 1,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        )
        .with_data(data);
        let config = MachineConfig {
            entry: 0x10,
            rom_base: 0x10,
            ram_base: 0x40,
            ram_size: 0x40,
            stack_top: 0x80,
            max_cycles: 8,
        };
        let trace = execute(&program, config).unwrap();
        let width = 16usize;
        let rows = crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(&trace, width)
            .unwrap();
        let cycles = rows.len();
        let (_, _, layout) = reservation_claim_matrices(width, cycles).unwrap();
        let base_cols = layout.total_bits / cycles;
        let (z, _, _, _) = reservation_claim_inputs(width, &rows).unwrap();
        let cpu = crate::reservation_cpu_row::ReservationCpuRow::new(width);
        let mut gated_values = Vec::with_capacity(cycles);
        for cycle in 0..cycles {
            let mut value = 0u64;
            for bit in 0..width {
                let index = cycle * base_cols + cpu.cpu.memory_offset + cpu.cpu.memory.data[bit];
                if z[index].value() == 1 {
                    value |= 1 << bit;
                }
            }
            gated_values.push(F2_128::from(value));
        }
        let full = magnetar_memory::BinaryTwistWitness::from_trace_full_cycles(&trace).unwrap();
        let tables = crate::binary_twist::batch_tables(&full).unwrap();
        let point = (0..cycles.trailing_zeros() as usize)
            .map(|bit| F2_128::from((bit * 7 + 3) as u64))
            .collect::<Vec<_>>();
        let gated_eval = Mle::new(gated_values).unwrap().eval(&point).unwrap();
        let twist_eval = Mle::new(tables.read_value.columns[0].clone())
            .unwrap()
            .eval(&point)
            .unwrap();
        assert_eq!(gated_eval, twist_eval);
    }

    #[test]
    fn aggregate_ram_claim_matches_component_bit_columns() {
        use magnetar_proof::{eq, Mle};
        let mut data = vec![0u8; 8];
        data.copy_from_slice(&0x7788u64.to_le_bytes());
        let program = ProgramImage::new(
            0x10,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x40,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Ld,
                    rd: 2,
                    rs1: 1,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        )
        .with_data(data);
        let config = MachineConfig {
            entry: 0x10,
            rom_base: 0x10,
            ram_base: 0x40,
            ram_size: 0x40,
            stack_top: 0x80,
            max_cycles: 8,
        };
        let trace = execute(&program, config).unwrap();
        let width = 16usize;
        let rows = crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(&trace, width)
            .unwrap();
        let cycles = rows.len();
        let (_, _, layout) = reservation_claim_matrices(width, cycles).unwrap();
        let base_cols = layout.total_bits / cycles;
        let (z, _, _, _) = reservation_claim_inputs(width, &rows).unwrap();
        let cpu = crate::reservation_cpu_row::ReservationCpuRow::new(width);
        let mut aggregate = Vec::with_capacity(cycles * width);
        for cycle in 0..cycles {
            for bit in 0..width {
                let index = cycle * base_cols + cpu.cpu.memory_offset + cpu.cpu.memory.data[bit];
                aggregate.push(z[index]);
            }
        }
        let bit_bits = width.trailing_zeros() as usize;
        let cycle_bits = cycles.trailing_zeros() as usize;
        let bit_point = (0..bit_bits)
            .map(|bit| F2_128::from((bit * 5 + 1) as u64))
            .collect::<Vec<_>>();
        let cycle_point = (0..cycle_bits)
            .map(|bit| F2_128::from((bit * 7 + 3) as u64))
            .collect::<Vec<_>>();
        let mut point = bit_point.clone();
        point.extend(cycle_point.iter().copied());
        let aggregate_eval = Mle::new(aggregate).unwrap().eval(&point).unwrap();
        let full = magnetar_memory::BinaryTwistWitness::from_trace_full_cycles(&trace).unwrap();
        let tables = crate::binary_twist::batch_tables(&full).unwrap();
        let mut component_eval = F2_128::from(0u64);
        for bit in 0..width {
            let value = Mle::new(tables.read_value_bits[bit].columns[0].clone())
                .unwrap()
                .eval(&cycle_point)
                .unwrap();
            let bits = (0..bit_bits)
                .map(|index| F2_128::from(((bit >> index) & 1) as u64))
                .collect::<Vec<_>>();
            component_eval = component_eval + eq(&bit_point, &bits) * value;
        }
        assert_eq!(aggregate_eval, component_eval);
    }

    #[test]
    fn ram_bit_columns_commit_and_open() {
        use magnetar_pcs::{P3BinaryPcs, P3MosaicPoint};
        use magnetar_proof::Mle;
        let mut data = vec![0u8; 8];
        data.copy_from_slice(&0x7788u64.to_le_bytes());
        let program = ProgramImage::new(
            0x10,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x40,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Ld,
                    rd: 2,
                    rs1: 1,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        )
        .with_data(data);
        let config = MachineConfig {
            entry: 0x10,
            rom_base: 0x10,
            ram_base: 0x40,
            ram_size: 0x40,
            stack_top: 0x80,
            max_cycles: 8,
        };
        let trace = execute(&program, config).unwrap();
        let full = magnetar_memory::BinaryTwistWitness::from_trace_full_cycles(&trace).unwrap();
        let tables = crate::binary_twist::batch_tables(&full).unwrap();
        let mut bit_tables = tables.read_value_bits.clone();
        bit_tables.extend(tables.read_address_bits.clone());
        let columns = bit_tables
            .iter()
            .flat_map(|table| table.columns.clone())
            .collect::<Vec<_>>();
        let table = magnetar_pcs::P3MosaicTable { columns };
        let cycle_bits = full.cycles.trailing_zeros() as usize;
        let point = (0..cycle_bits)
            .map(|bit| F2_128::from((bit * 11 + 5) as u64))
            .collect::<Vec<_>>();
        let pcs = P3BinaryPcs::new(100);
        let commitment = pcs.commit_mosaic(std::slice::from_ref(&table)).unwrap();
        let expected = table
            .columns
            .iter()
            .map(|column| Mle::new(column.clone()).unwrap().eval(&point).unwrap())
            .collect::<Vec<_>>();
        let points = [P3MosaicPoint {
            table: 0,
            point: point.clone(),
            columns: (0..table.columns.len()).collect(),
            next_columns: Vec::new(),
        }];
        let opening = pcs
            .open_mosaic(std::slice::from_ref(&table), &points)
            .unwrap();
        assert!(pcs.verify_mosaic(&opening, &points, &[expected]).unwrap());
        let _ = commitment;
    }

    #[test]
    fn aggregate_ram_address_claim_matches_component_bit_columns() {
        use magnetar_proof::{eq, Mle};
        let mut data = vec![0u8; 8];
        data.copy_from_slice(&0x7788u64.to_le_bytes());
        let program = ProgramImage::new(
            0x10,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x40,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Ld,
                    rd: 2,
                    rs1: 1,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        )
        .with_data(data);
        let config = MachineConfig {
            entry: 0x10,
            rom_base: 0x10,
            ram_base: 0x40,
            ram_size: 0x40,
            stack_top: 0x80,
            max_cycles: 8,
        };
        let trace = execute(&program, config).unwrap();
        let width = 16usize;
        let rows = crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(&trace, width)
            .unwrap();
        let cycles = rows.len();
        let (_, _, layout) = reservation_claim_matrices(width, cycles).unwrap();
        let base_cols = layout.total_bits / cycles;
        let (z, _, _, _) = reservation_claim_inputs(width, &rows).unwrap();
        let cpu = crate::reservation_cpu_row::ReservationCpuRow::new(width);
        let mut aggregate = Vec::with_capacity(cycles * width);
        for cycle in 0..cycles {
            for bit in 0..width {
                let index =
                    cycle * base_cols + cpu.cpu.memory_offset + cpu.cpu.memory.adder.out[bit];
                aggregate.push(z[index]);
            }
        }
        let bit_bits = width.trailing_zeros() as usize;
        let cycle_bits = cycles.trailing_zeros() as usize;
        let bit_point = (0..bit_bits)
            .map(|bit| F2_128::from((bit * 5 + 1) as u64))
            .collect::<Vec<_>>();
        let cycle_point = (0..cycle_bits)
            .map(|bit| F2_128::from((bit * 7 + 3) as u64))
            .collect::<Vec<_>>();
        let mut point = bit_point.clone();
        point.extend(cycle_point.iter().copied());
        let aggregate_eval = Mle::new(aggregate).unwrap().eval(&point).unwrap();
        let full = magnetar_memory::BinaryTwistWitness::from_trace_full_cycles(&trace).unwrap();
        let tables = crate::binary_twist::batch_tables(&full).unwrap();
        let mut component_eval = F2_128::from(0u64);
        for bit in 0..tables.address_bits {
            let value = Mle::new(tables.read_address_bits[bit].columns[0].clone())
                .unwrap()
                .eval(&cycle_point)
                .unwrap();
            let bits = (0..bit_bits)
                .map(|index| F2_128::from(((bit >> index) & 1) as u64))
                .collect::<Vec<_>>();
            component_eval = component_eval + eq(&bit_point, &bits) * value;
        }
        assert_eq!(aggregate_eval, component_eval);
    }

    #[test]
    fn ram_data_bits_match_twist_read_value() {
        let mut data = vec![0u8; 8];
        data.copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        let program = ProgramImage::new(
            0x10,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x40,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Ld,
                    rd: 2,
                    rs1: 1,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        )
        .with_data(data);
        let config = MachineConfig {
            entry: 0x10,
            rom_base: 0x10,
            ram_base: 0x40,
            ram_size: 0x40,
            stack_top: 0x80,
            max_cycles: 8,
        };
        let trace = execute(&program, config).unwrap();
        let twist = magnetar_memory::BinaryTwistWitness::from_trace(&trace).unwrap();
        let rows =
            crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(&trace, 16).unwrap();
        let cpu = crate::reservation_cpu_row::ReservationCpuRow::new(16);
        let (pc, input) = rows
            .iter()
            .find(|(_, input)| matches!(input.cpu, GatedCpuRowInput::Memory { .. }))
            .unwrap();
        let gated_bits = cpu.witness(*pc, *input);
        let twist_value = twist.read_value[0].value();
        for bit in 0..16 {
            assert_eq!(
                gated_bits[cpu.cpu.memory_offset + cpu.cpu.memory.data[bit]],
                ((twist_value >> bit) & 1) == 1,
                "RAM data bit {bit} projection mismatch"
            );
        }
        let mut gated_addr = 0u64;
        for bit in 0..16 {
            if gated_bits[cpu.cpu.memory_offset + cpu.cpu.memory.adder.out[bit]] {
                gated_addr |= 1 << bit;
            }
        }
        let twist_word = twist.read_address[0]
            .iter()
            .position(|bit| bit.value() == 1)
            .unwrap_or(0);
        assert_eq!(
            gated_addr,
            trace.config.ram_base + 8 * twist_word as u64,
            "RAM address affine projection mismatch"
        );
    }

    #[test]
    fn pc_component_witness_matches_gated_pc_subsegment() {
        let program = ProgramImage::new(
            0x10,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 9,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let config = MachineConfig {
            entry: 0x10,
            rom_base: 0x10,
            ram_base: 0x40,
            ram_size: 0x40,
            stack_top: 0x80,
            max_cycles: 8,
        };
        let trace = execute(&program, config).unwrap();
        let rows =
            crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(&trace, 8).unwrap();
        let cpu = crate::reservation_cpu_row::ReservationCpuRow::new(8);
        let pc_row = crate::pc_transition_row::PcTransitionRow::new(8);
        for (pc, input) in &rows {
            let gated_bits = cpu.witness(*pc, *input);
            let pc_bits = pc_row.witness(*pc, *pc, true);
            for bit in 0..8 {
                assert_eq!(
                    gated_bits[cpu.cpu.pc[bit]], pc_bits[pc_row.pc[bit]],
                    "PC bit {bit} projection mismatch"
                );
            }
        }
    }
    #[test]
    fn p3_component_table_multi_column_point() {
        use magnetar_pcs::{P3BinaryPcs, P3MosaicPoint, P3MosaicTable};
        use magnetar_proof::Mle;
        let cycles = 4usize;
        let width = 8usize;
        let len = cycles * width;
        let data = (0..len)
            .map(|index| F2_128::from((index as u64 * 3 + 1) & 1))
            .collect::<Vec<_>>();
        let address = (0..len)
            .map(|index| F2_128::from((index as u64 * 5 + 2) & 1))
            .collect::<Vec<_>>();
        let table = P3MosaicTable {
            columns: vec![data.clone(), address.clone()],
        };
        let other = P3MosaicTable {
            columns: vec![vec![F2_128::from(7u64); len]],
        };
        let point = (0..len.trailing_zeros() as usize)
            .map(|bit| F2_128::from((bit * 9 + 3) as u64))
            .collect::<Vec<_>>();
        let values = vec![
            Mle::new(data).unwrap().eval(&point).unwrap(),
            Mle::new(address).unwrap().eval(&point).unwrap(),
        ];
        let pcs = P3BinaryPcs::with_params(100, 4, 16, 3);
        let commitment = pcs.commit_mosaic(&[other.clone(), table.clone()]).unwrap();
        let points = [P3MosaicPoint {
            table: 1,
            point: point.clone(),
            columns: vec![0, 1],
            next_columns: Vec::new(),
        }];
        let opening = pcs.open_mosaic(&[other, table], &points).unwrap();
        assert!(pcs.verify_mosaic(&opening, &points, &[values]).unwrap());
        let _ = commitment;
    }
    #[test]
    fn p3_component_point_with_many_tables() {
        use magnetar_pcs::{P3BinaryPcs, P3MosaicPoint, P3MosaicTable};
        use magnetar_proof::Mle;
        let len = 64usize;
        let mut tables = Vec::new();
        for table in 0..12 {
            tables.push(P3MosaicTable {
                columns: vec![(0..len)
                    .map(|index| F2_128::from(((index + table * 3) & 1) as u64))
                    .collect()],
            });
        }
        let data = (0..len)
            .map(|index| F2_128::from(((index * 3 + 1) & 1) as u64))
            .collect::<Vec<_>>();
        let address = (0..len)
            .map(|index| F2_128::from(((index * 5 + 2) & 1) as u64))
            .collect::<Vec<_>>();
        tables.push(P3MosaicTable {
            columns: vec![data.clone(), address.clone()],
        });
        let mut points = Vec::new();
        let mut values = Vec::new();
        for (table, table_data) in tables.iter().take(12).enumerate() {
            let point = (0..len.trailing_zeros() as usize)
                .map(|bit| F2_128::from(((bit + table) & 1) as u64))
                .collect::<Vec<_>>();
            values.push(vec![Mle::new(table_data.columns[0].clone())
                .unwrap()
                .eval(&point)
                .unwrap()]);
            points.push(P3MosaicPoint {
                table,
                point,
                columns: vec![0],
                next_columns: Vec::new(),
            });
        }
        let point = (0..len.trailing_zeros() as usize)
            .map(|bit| F2_128::from(((bit * 9 + 3) & 1) as u64))
            .collect::<Vec<_>>();
        values.push(vec![
            Mle::new(data).unwrap().eval(&point).unwrap(),
            Mle::new(address).unwrap().eval(&point).unwrap(),
        ]);
        points.push(P3MosaicPoint {
            table: 12,
            point,
            columns: vec![0, 1],
            next_columns: Vec::new(),
        });
        let pcs = P3BinaryPcs::with_params(100, 4, 16, 3);
        let commitment = pcs.commit_mosaic(&tables).unwrap();
        let opening = pcs.open_mosaic(&tables, &points).unwrap();
        assert!(pcs.verify_mosaic(&opening, &points, &values).unwrap());
        let _ = commitment;
    }
}
