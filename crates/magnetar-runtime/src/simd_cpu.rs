//! Shared-matrix SIMD CPU proof for the uniform ALU/PC row schema.
//!
//! This is the first runtime wiring of the SIMD schema: q uniform ALU rows,
//! one base row system, q block instances, and cross-cycle PC-chain rows.

use magnetar_constraint::F2_128;
use magnetar_cpu::simd::{uniform_cpu_row_layout, UniformCpuRowLayout, UniformCpuRowWitness};
use magnetar_cpu::CpuVarKind;
use magnetar_pcs::{P3BinaryPcs, P3Commitment, P3Opening};
use magnetar_proof::spartan::MatrixPart;
use magnetar_proof::{
    prove_spartan_with_matrices, verify_spartan_with_matrices, witness_vector, SharedBlockMatrix,
    SpartanProof,
};

use crate::RuntimeError;
use magnetar_spec::Trace;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SimdCpuProof {
    pub width: usize,
    pub cycles: usize,
    pub proof: SpartanProof<P3Commitment, P3Opening>,
}

fn matrices(
    layout: &UniformCpuRowLayout,
    cycles: usize,
) -> Result<(SharedBlockMatrix, SharedBlockMatrix, SharedBlockMatrix), RuntimeError> {
    if cycles == 0 || !cycles.is_power_of_two() {
        return Err(RuntimeError::Proof(
            "SIMD CPU cycle count must be a nonzero power of two".into(),
        ));
    }
    let base_cols = (layout.num_vars + 1).next_power_of_two();
    let groups = layout.var_groups();
    let pc = groups
        .iter()
        .find(|group| group.kind == CpuVarKind::Pc)
        .ok_or_else(|| RuntimeError::Proof("CPU row has no PC group".into()))?;
    let next_pc = groups
        .iter()
        .find(|group| group.kind == CpuVarKind::NextPc)
        .ok_or_else(|| RuntimeError::Proof("CPU row has no NextPc group".into()))?;
    let mut extra_a = Vec::new();
    let mut extra_b = Vec::new();
    let mut extra_c = Vec::new();
    for instance in 0..cycles.saturating_sub(1) {
        for bit in 0..pc.vars.len() {
            extra_a.push(vec![(
                instance * base_cols + next_pc.vars[bit],
                F2_128::from(1u64),
            )]);
            extra_b.push(vec![(
                instance * base_cols + layout.num_vars,
                F2_128::from(1u64),
            )]);
            extra_c.push(vec![(
                (instance + 1) * base_cols + pc.vars[bit],
                F2_128::from(1u64),
            )]);
        }
    }
    let a = SharedBlockMatrix::from_system(&layout.system, MatrixPart::A, cycles)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_a);
    let b = SharedBlockMatrix::from_system(&layout.system, MatrixPart::B, cycles)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_b);
    let c = SharedBlockMatrix::from_system(&layout.system, MatrixPart::C, cycles)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_c);
    Ok((a, b, c))
}

fn batch_witness(
    layout: &UniformCpuRowLayout,
    rows: &[UniformCpuRowWitness],
) -> Result<Vec<F2_128>, RuntimeError> {
    let mut z = Vec::new();
    for row in rows {
        z.extend(
            witness_vector(&layout.system, &row.witness)
                .map_err(|error| RuntimeError::Proof(error.to_string()))?,
        );
    }
    Ok(z)
}

/// Convert a trace prefix consisting only of uniform ALU rows into SIMD
/// instances. Unsupported rows are reported explicitly; the caller decides
/// how to handle the tail (memory/branch/ecall).
pub fn simd_cpu_rows_from_trace(
    trace: &Trace,
    width: usize,
) -> Result<Vec<UniformCpuRowWitness>, RuntimeError> {
    let (_system, layout) = uniform_cpu_row_layout(width);
    let mut rows = Vec::new();
    for row in &trace.rows {
        if row.mem.is_some() || row.instruction.op.amo_width().is_some() {
            return Err(RuntimeError::Proof(
                "SIMD CPU ALU slice does not support memory/AMO rows".into(),
            ));
        }
        let Some(step_op) = crate::step_op_for(row.instruction.op) else {
            break;
        };
        if crate::w_step_op_for(row.instruction.op).is_some()
            || crate::branch_op_for(row.instruction.op).is_some()
        {
            return Err(RuntimeError::Proof(
                "SIMD CPU ALU slice does not support this control/W row".into(),
            ));
        }
        let imm = match row.instruction.op {
            magnetar_spec::Op::Slli | magnetar_spec::Op::Srli | magnetar_spec::Op::Srai => {
                u64::from(row.instruction.shamt)
            }
            _ => row.instruction.imm as u64,
        };
        rows.push(layout.witness(step_op, row.pc, row.rs1_val, row.rs2_val, imm));
    }
    if rows.is_empty() || !rows.len().is_power_of_two() {
        return Err(RuntimeError::Proof(
            "SIMD CPU ALU slice must contain a nonzero power-of-two number of rows".into(),
        ));
    }
    Ok(rows)
}

pub fn prove_simd_cpu_rows(
    width: usize,
    rows: &[UniformCpuRowWitness],
) -> Result<SimdCpuProof, RuntimeError> {
    if rows.is_empty() {
        return Err(RuntimeError::Proof("empty SIMD CPU batch".into()));
    }
    let (_system, layout) = uniform_cpu_row_layout(width);
    let (a, b, c) = matrices(&layout, rows.len())?;
    let z = batch_witness(&layout, rows)?;
    if z.len() != a.cols() {
        return Err(RuntimeError::Proof(
            "SIMD CPU witness width mismatch".into(),
        ));
    }
    let pcs = P3BinaryPcs::new(100);
    let proof = prove_spartan_with_matrices(&z, &a, &b, &c, &pcs)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(SimdCpuProof {
        width,
        cycles: rows.len(),
        proof,
    })
}

pub fn verify_simd_cpu_rows(proof: &SimdCpuProof) -> Result<(), RuntimeError> {
    let (_system, layout) = uniform_cpu_row_layout(proof.width);
    let (a, b, c) = matrices(&layout, proof.cycles)?;
    let pcs = P3BinaryPcs::new(100);
    verify_spartan_with_matrices(&a, &b, &c, &proof.proof, &pcs)
        .map_err(|error| RuntimeError::Proof(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_cpu::StepOp;

    #[test]
    fn simd_cpu_trace_round_trips() {
        let (_system, layout) = uniform_cpu_row_layout(16);
        let rows = [
            layout.witness(StepOp::Add, 0x1000, 3, 4, 0),
            layout.witness(StepOp::Xor, 0x1004, 5, 6, 0),
        ];
        let proof = prove_simd_cpu_rows(16, &rows).expect("prove");
        verify_simd_cpu_rows(&proof).expect("verify");

        let mut tampered = proof;
        tampered.proof.vw = tampered.proof.vw + F2_128::from(1u64);
        assert!(verify_simd_cpu_rows(&tampered).is_err());
    }
    #[test]
    fn simd_cpu_proves_trace_prefix() {
        use magnetar_executor::execute;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Add,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Xor,
                    rd: 2,
                    rs1: 1,
                    rs2: 1,
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
        .expect("trace");
        let rows = simd_cpu_rows_from_trace(&trace, 16).expect("rows");
        assert_eq!(rows.len(), 2);
        let proof = prove_simd_cpu_rows(16, &rows).expect("prove");
        verify_simd_cpu_rows(&proof).expect("verify");
    }
}
