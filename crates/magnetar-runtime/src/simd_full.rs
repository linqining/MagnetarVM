//! Shared-matrix SIMD proof for the combined ALU + load/store CPU schema.

use magnetar_constraint::{Witness, F2_128};
use magnetar_cpu::simd::{uniform_cpu_full_layout, UniformCpuFullLayout};
use magnetar_cpu::CpuVarKind;
use magnetar_pcs::{P3BinaryPcs, P3Commitment, P3Opening};
use magnetar_proof::spartan::MatrixPart;
use magnetar_proof::{
    prove_spartan_with_matrices, verify_spartan_with_matrices, witness_vector, SharedBlockMatrix,
    SpartanProof,
};
use magnetar_spec::Trace;

use crate::RuntimeError;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SimdFullProof {
    pub width: usize,
    pub cycles: usize,
    pub proof: SpartanProof<P3Commitment, P3Opening>,
}

fn matrices(
    layout: &UniformCpuFullLayout,
    cycles: usize,
) -> Result<(SharedBlockMatrix, SharedBlockMatrix, SharedBlockMatrix), RuntimeError> {
    if cycles == 0 || !cycles.is_power_of_two() {
        return Err(RuntimeError::Proof(
            "SIMD full CPU cycle count must be a nonzero power of two".into(),
        ));
    }
    let base_cols = (layout.num_vars + 1).next_power_of_two();
    let groups = layout.var_groups();
    let pc = groups
        .iter()
        .find(|group| group.kind == CpuVarKind::Pc)
        .ok_or_else(|| RuntimeError::Proof("full CPU row has no PC group".into()))?;
    let next_pc = groups
        .iter()
        .find(|group| group.kind == CpuVarKind::NextPc)
        .ok_or_else(|| RuntimeError::Proof("full CPU row has no NextPc group".into()))?;
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

/// Convert a trace prefix of supported ALU/load/store rows into combined
/// schema witnesses. Unsupported rows end the slice; the count must be a
/// nonzero power of two.
pub fn simd_full_rows_from_trace(
    trace: &Trace,
    width: usize,
) -> Result<Vec<Witness>, RuntimeError> {
    let (_system, layout) = uniform_cpu_full_layout(width);
    let mut rows = Vec::new();
    for row in &trace.rows {
        if row.instruction.op.amo_width().is_some()
            || crate::branch_op_for(row.instruction.op).is_some()
        {
            break;
        }
        if let Some(access) = row.mem {
            let imm = row.instruction.imm as u64;
            if access.is_write {
                rows.push(layout.memory_witness(row.pc, row.rs1_val, imm, access.value, false));
            } else {
                rows.push(layout.memory_witness(row.pc, row.rs1_val, imm, row.rd_val, true));
            }
            continue;
        }
        let Some(step_op) = crate::step_op_for(row.instruction.op) else {
            break;
        };
        if crate::w_step_op_for(row.instruction.op).is_some() {
            break;
        }
        let imm = match row.instruction.op {
            magnetar_spec::Op::Slli | magnetar_spec::Op::Srli | magnetar_spec::Op::Srai => {
                u64::from(row.instruction.shamt)
            }
            _ => row.instruction.imm as u64,
        };
        rows.push(layout.alu_witness(step_op, row.pc, row.rs1_val, row.rs2_val, imm));
    }
    if rows.is_empty() || !rows.len().is_power_of_two() {
        return Err(RuntimeError::Proof(
            "SIMD full CPU slice must contain a nonzero power-of-two number of rows".into(),
        ));
    }
    Ok(rows)
}

pub fn prove_simd_full_rows(width: usize, rows: &[Witness]) -> Result<SimdFullProof, RuntimeError> {
    if rows.is_empty() {
        return Err(RuntimeError::Proof("empty SIMD full CPU batch".into()));
    }
    let (_system, layout) = uniform_cpu_full_layout(width);
    let (a, b, c) = matrices(&layout, rows.len())?;
    let mut z = Vec::new();
    for row in rows {
        z.extend(
            witness_vector(&layout.system, row)
                .map_err(|error| RuntimeError::Proof(error.to_string()))?,
        );
    }
    if z.len() != a.cols() {
        return Err(RuntimeError::Proof(
            "SIMD full CPU witness width mismatch".into(),
        ));
    }
    let pcs = P3BinaryPcs::new(100);
    let proof = prove_spartan_with_matrices(&z, &a, &b, &c, &pcs)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(SimdFullProof {
        width,
        cycles: rows.len(),
        proof,
    })
}

pub fn verify_simd_full_rows(proof: &SimdFullProof) -> Result<(), RuntimeError> {
    let (_system, layout) = uniform_cpu_full_layout(proof.width);
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
    fn combined_schema_rows_round_trip() {
        let (_system, layout) = uniform_cpu_full_layout(16);
        let rows = [
            layout.alu_witness(StepOp::Add, 0x1000, 3, 4, 0),
            layout.memory_witness(0x1004, 5, 2, 0x34, true),
        ];
        let proof = prove_simd_full_rows(16, &rows).expect("prove");
        verify_simd_full_rows(&proof).expect("verify");
    }
    #[test]
    fn mixed_trace_slice_round_trips() {
        use magnetar_executor::execute;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};
        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Lui, 10, 0, 0, 0x1000_0000).encode(),
                instruction(Op::Sw, 0, 10, 0, 0).encode(),
                instruction(Op::Lw, 11, 10, 0, 0).encode(),
                instruction(Op::Add, 12, 11, 0, 0).encode(),
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
        let rows = simd_full_rows_from_trace(&trace, 16).expect("rows");
        assert_eq!(rows.len(), 4);
        let proof = prove_simd_full_rows(16, &rows).expect("prove");
        verify_simd_full_rows(&proof).expect("verify");
    }
}

/// Convert a supported trace prefix into gated CPU row inputs.
///
/// Supported rows are ALU XOR/AND/ADD and load/store rows; anything else ends
/// the slice. The slice length is truncated to the largest power of two.
pub fn gated_rows_from_trace(
    trace: &Trace,
    _width: usize,
) -> Result<Vec<(u64, crate::simd_f2::GatedCpuRowInput)>, RuntimeError> {
    use crate::simd_f2::{GatedAluOp, GatedCpuRowInput};
    use magnetar_cpu::StepOp;

    let mut rows = Vec::new();
    for row in &trace.rows {
        let shift_kind = match row.instruction.op {
            magnetar_spec::Op::Sll | magnetar_spec::Op::Slli => {
                Some(crate::simd_f2::BitShiftKind::Sll)
            }
            magnetar_spec::Op::Srl | magnetar_spec::Op::Srli => {
                Some(crate::simd_f2::BitShiftKind::Srl)
            }
            magnetar_spec::Op::Sra | magnetar_spec::Op::Srai => {
                Some(crate::simd_f2::BitShiftKind::Sra)
            }
            _ => None,
        };
        if row.instruction.op == magnetar_spec::Op::Auipc {
            rows.push((
                row.pc,
                GatedCpuRowInput::Alu {
                    left: row.pc,
                    right: row.instruction.imm as u64,
                    op: GatedAluOp::Auipc,
                },
            ));
            continue;
        }
        if row.instruction.op == magnetar_spec::Op::Jal {
            rows.push((
                row.pc,
                GatedCpuRowInput::Alu {
                    left: row.pc,
                    right: row.instruction.imm as u64,
                    op: GatedAluOp::Jal,
                },
            ));
            continue;
        }
        if matches!(
            row.instruction.op,
            magnetar_spec::Op::Beq
                | magnetar_spec::Op::Bne
                | magnetar_spec::Op::Blt
                | magnetar_spec::Op::Bge
                | magnetar_spec::Op::Bltu
                | magnetar_spec::Op::Bgeu
        ) {
            rows.push((
                row.pc,
                GatedCpuRowInput::Branch {
                    left: row.rs1_val,
                    right: row.rs2_val,
                    imm: row.instruction.imm as u64,
                    kind: match row.instruction.op {
                        magnetar_spec::Op::Beq => crate::branch_row::BranchKind::Beq,
                        magnetar_spec::Op::Bne => crate::branch_row::BranchKind::Bne,
                        magnetar_spec::Op::Blt => crate::branch_row::BranchKind::Blt,
                        magnetar_spec::Op::Bge => crate::branch_row::BranchKind::Bge,
                        magnetar_spec::Op::Bltu => crate::branch_row::BranchKind::Bltu,
                        magnetar_spec::Op::Bgeu => crate::branch_row::BranchKind::Bgeu,
                        _ => unreachable!(),
                    },
                },
            ));
            continue;
        }
        if row.instruction.op == magnetar_spec::Op::Jalr {
            rows.push((
                row.pc,
                GatedCpuRowInput::Alu {
                    left: row.rs1_val,
                    right: row.instruction.imm as u64,
                    op: GatedAluOp::Jalr,
                },
            ));
            continue;
        }
        if let Some(kind) = shift_kind {
            let shamt = match row.instruction.op {
                magnetar_spec::Op::Slli | magnetar_spec::Op::Srli | magnetar_spec::Op::Srai => {
                    u64::from(row.instruction.shamt)
                }
                _ => row.rs2_val,
            };
            rows.push((
                row.pc,
                GatedCpuRowInput::Shift {
                    left: row.rs1_val,
                    shamt,
                    kind,
                },
            ));
            continue;
        }
        if let Some(access) = row.mem {
            let imm = row.instruction.imm as u64;
            let value = if access.is_write {
                access.value
            } else {
                row.rd_val
            };
            rows.push((
                row.pc,
                GatedCpuRowInput::Memory {
                    rs1: row.rs1_val,
                    imm,
                    value,
                    is_mem: true,
                },
            ));
            continue;
        }
        let Some(step) = crate::step_op_for(row.instruction.op) else {
            break;
        };
        let op = match step {
            StepOp::Xor => GatedAluOp::Xor,
            StepOp::And => GatedAluOp::And,
            StepOp::Add => GatedAluOp::Add,
            StepOp::Sub => GatedAluOp::Sub,
            StepOp::Sltu => GatedAluOp::Sltu,
            StepOp::Slt => GatedAluOp::Slt,
            StepOp::Lui => GatedAluOp::Lui,
            _ => break,
        };
        if crate::w_step_op_for(row.instruction.op).is_some()
            || row.instruction.op.amo_width().is_some()
            || crate::branch_op_for(row.instruction.op).is_some()
        {
            break;
        }
        rows.push((
            row.pc,
            GatedCpuRowInput::Alu {
                left: row.rs1_val,
                right: row.rs2_val,
                op,
            },
        ));
    }
    if rows.is_empty() {
        return Err(RuntimeError::Proof(
            "trace has no supported gated rows".into(),
        ));
    }
    let power = 1usize << (usize::BITS - 1 - rows.len().leading_zeros()) as usize;
    rows.truncate(power);
    Ok(rows)
}

#[cfg(test)]
mod gated_trace_tests {
    use super::*;

    #[test]
    fn supported_trace_prefix_proves_through_gated_dual() {
        use crate::simd_dual::{prove_gated_dual_batch_bits, verify_gated_dual_batch_bits};
        use magnetar_executor::execute;
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::DirectBitPcs;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Add, 1, 0, 0, 0).encode(),
                instruction(Op::Add, 2, 0, 0, 0).encode(),
                instruction(Op::Xor, 3, 1, 2, 0).encode(),
                instruction(Op::And, 4, 1, 2, 0).encode(),
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
        let rows = gated_rows_from_trace(&trace, 8).expect("rows");
        assert_eq!(rows.len(), 4);
        let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
        let backend = DirectBitPcs::new(pcs);
        let (proof, layout) = prove_gated_dual_batch_bits(8, &rows, &backend).expect("prove");
        verify_gated_dual_batch_bits(8, &rows, &proof, &layout, &backend).expect("verify");
    }
}

#[cfg(test)]
mod auipc_trace_tests {
    use super::*;
    use crate::simd_f2::{GatedAluOp, GatedCpuRowInput};
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    #[test]
    fn jal_trace_maps_to_gated_alu() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Jal,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x4,
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
        let rows = gated_rows_from_trace(&trace, 8).unwrap();
        assert!(matches!(
            rows[0].1,
            GatedCpuRowInput::Alu {
                op: GatedAluOp::Jal,
                ..
            }
        ));
    }

    #[test]
    fn branch_trace_proves_through_gated_dual() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Beq,
                    rd: 0,
                    rs1: 0,
                    rs2: 0,
                    imm: 8,
                    shamt: 0,
                }
                .encode(),
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
                    op: Op::Add,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
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
        let rows = gated_rows_from_trace(&trace, 8).unwrap();
        assert!(matches!(
            rows[0].1,
            GatedCpuRowInput::Branch {
                kind: crate::branch_row::BranchKind::Beq,
                ..
            }
        ));
        use crate::simd_dual::{prove_gated_dual_batch_bits, verify_gated_dual_batch_bits};
        use magnetar_pcs::P3SharedPcs;
        use magnetar_proof::DirectBitPcs;
        let backend = DirectBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
        let (proof, layout) = prove_gated_dual_batch_bits(8, &rows, &backend).unwrap();
        verify_gated_dual_batch_bits(8, &rows, &proof, &layout, &backend).unwrap();
    }

    #[test]
    fn jalr_trace_maps_to_gated_alu() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Lui,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x1000,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Jalr,
                    rd: 0,
                    rs1: 1,
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
        let rows = gated_rows_from_trace(&trace, 8).unwrap();
        assert!(rows.iter().any(|(_, input)| matches!(
            input,
            GatedCpuRowInput::Alu {
                op: GatedAluOp::Jalr,
                ..
            }
        )));
    }

    #[test]
    fn auipc_trace_maps_to_gated_alu() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Auipc,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x20,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Addi,
                    rd: 2,
                    rs1: 1,
                    rs2: 0,
                    imm: 1,
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
        let rows = gated_rows_from_trace(&trace, 8).unwrap();
        assert!(matches!(
            rows[0].1,
            GatedCpuRowInput::Alu {
                op: GatedAluOp::Auipc,
                ..
            }
        ));
    }
}
