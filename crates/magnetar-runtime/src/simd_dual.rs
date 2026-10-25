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
        let mut bits = self.instr.witness(left, right);
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
