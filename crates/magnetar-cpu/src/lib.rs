//! CPU step relation.
//!
//! `check_trace` is the reference semantic checker for every RV64I row.
//! `linear_alu_constraints` demonstrates how the same rows enter the
//! constraint IR; the full uniform SIMD R1CS is intentionally left to the
//! proof-engine milestone.

use magnetar_constraint::{ConstraintSystem, Expr, Field, Witness, F61};
use magnetar_spec::{Addr, Op, Trace, TraceRow, Word};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CpuError {
    #[error("row {row}: {op} produced rd={actual:#x}, expected {expected:#x}")]
    RdValue {
        row: usize,
        op: &'static str,
        expected: Word,
        actual: Word,
    },
    #[error("row {row}: next pc is {actual:#x}, expected {expected:#x}")]
    NextPc {
        row: usize,
        expected: Word,
        actual: Word,
    },
    #[error("row {row}: memory address is {actual:#x}, expected {expected:#x}")]
    MemAddr {
        row: usize,
        expected: Addr,
        actual: Addr,
    },
    #[error("row {row}: expected no memory access")]
    UnexpectedMemory { row: usize },
    #[error("row {row}: expected a memory access")]
    MissingMemory { row: usize },
    #[error("row {row}: store wrote rd={value:#x}, expected 0")]
    StoreRd { row: usize, value: Word },
    #[error("row {row}: memory width is {actual}, expected {expected}")]
    MemWidth {
        row: usize,
        expected: u8,
        actual: u8,
    },
}

/// Check every row against the RV64I step semantics.
pub fn check_trace(trace: &Trace) -> Result<(), CpuError> {
    for (index, row) in trace.rows.iter().enumerate() {
        check_row(index, row)?;
    }
    Ok(())
}

pub fn check_row(index: usize, row: &TraceRow) -> Result<(), CpuError> {
    let pc = row.pc;
    let imm = row.instruction.imm as Word;
    let rs1 = row.rs1_val;
    let rs2 = row.rs2_val;
    let mut expected_next_pc = pc.wrapping_add(4);

    match row.instruction.op {
        Op::Add => check_rd(index, row, rs1.wrapping_add(rs2))?,
        Op::Sub => check_rd(index, row, rs1.wrapping_sub(rs2))?,
        Op::Sll => check_rd(index, row, rs1.wrapping_shl((rs2 & 0x3f) as u32))?,
        Op::Slt => check_rd(index, row, u64::from((rs1 as i64) < (rs2 as i64)))?,
        Op::Sltu => check_rd(index, row, u64::from(rs1 < rs2))?,
        Op::Xor => check_rd(index, row, rs1 ^ rs2)?,
        Op::Srl => check_rd(index, row, rs1.wrapping_shr((rs2 & 0x3f) as u32))?,
        Op::Sra => check_rd(index, row, ((rs1 as i64) >> (rs2 & 0x3f)) as u64)?,
        Op::Or => check_rd(index, row, rs1 | rs2)?,
        Op::And => check_rd(index, row, rs1 & rs2)?,
        Op::Addi => check_rd(index, row, rs1.wrapping_add(imm))?,
        Op::Slti => check_rd(index, row, u64::from((rs1 as i64) < row.instruction.imm))?,
        Op::Sltiu => check_rd(index, row, u64::from(rs1 < imm))?,
        Op::Xori => check_rd(index, row, rs1 ^ imm)?,
        Op::Ori => check_rd(index, row, rs1 | imm)?,
        Op::Andi => check_rd(index, row, rs1 & imm)?,
        Op::Slli => check_rd(
            index,
            row,
            rs1.wrapping_shl(u32::from(row.instruction.shamt)),
        )?,
        Op::Srli => check_rd(
            index,
            row,
            rs1.wrapping_shr(u32::from(row.instruction.shamt)),
        )?,
        Op::Srai => check_rd(index, row, ((rs1 as i64) >> row.instruction.shamt) as u64)?,
        Op::Lui => check_rd(index, row, imm)?,
        Op::Auipc => check_rd(index, row, pc.wrapping_add(imm))?,
        Op::Jal => {
            check_rd(index, row, pc.wrapping_add(4))?;
            expected_next_pc = pc.wrapping_add(imm);
        }
        Op::Jalr => {
            check_rd(index, row, pc.wrapping_add(4))?;
            expected_next_pc = rs1.wrapping_add(imm) & !1;
        }
        Op::Beq => {
            if rs1 == rs2 {
                expected_next_pc = pc.wrapping_add(imm);
            }
            check_no_rd(index, row)?;
        }
        Op::Bne => {
            if rs1 != rs2 {
                expected_next_pc = pc.wrapping_add(imm);
            }
            check_no_rd(index, row)?;
        }
        Op::Blt => {
            if (rs1 as i64) < (rs2 as i64) {
                expected_next_pc = pc.wrapping_add(imm);
            }
            check_no_rd(index, row)?;
        }
        Op::Bge => {
            if (rs1 as i64) >= (rs2 as i64) {
                expected_next_pc = pc.wrapping_add(imm);
            }
            check_no_rd(index, row)?;
        }
        Op::Bltu => {
            if rs1 < rs2 {
                expected_next_pc = pc.wrapping_add(imm);
            }
            check_no_rd(index, row)?;
        }
        Op::Bgeu => {
            if rs1 >= rs2 {
                expected_next_pc = pc.wrapping_add(imm);
            }
            check_no_rd(index, row)?;
        }
        Op::Lb | Op::Lh | Op::Lw | Op::Ld | Op::Lbu | Op::Lhu | Op::Lwu => {
            let width = match row.instruction.op {
                Op::Lb | Op::Lbu => 1,
                Op::Lh | Op::Lhu => 2,
                Op::Lw | Op::Lwu => 4,
                Op::Ld => 8,
                _ => unreachable!(),
            };
            check_memory(index, row, rs1.wrapping_add(imm), width, false)?;
        }
        Op::Sb | Op::Sh | Op::Sw | Op::Sd => {
            let width = match row.instruction.op {
                Op::Sb => 1,
                Op::Sh => 2,
                Op::Sw => 4,
                Op::Sd => 8,
                _ => unreachable!(),
            };
            check_memory(index, row, rs1.wrapping_add(imm), width, true)?;
            if row.rd_val != 0 {
                return Err(CpuError::StoreRd {
                    row: index,
                    value: row.rd_val,
                });
            }
        }
        Op::Fence => {
            check_no_rd(index, row)?;
        }
        Op::Ecall | Op::Ebreak => {
            expected_next_pc = pc;
            check_no_rd(index, row)?;
        }
    }

    if row.next_pc != expected_next_pc {
        return Err(CpuError::NextPc {
            row: index,
            expected: expected_next_pc,
            actual: row.next_pc,
        });
    }
    Ok(())
}

fn fe_i64(value: i64) -> F61 {
    if value < 0 {
        -F61::from_u64(value.unsigned_abs())
    } else {
        F61::from_u64(value as u64)
    }
}

fn check_rd(index: usize, row: &TraceRow, expected: Word) -> Result<(), CpuError> {
    if row.rd_val != expected {
        return Err(CpuError::RdValue {
            row: index,
            op: row.instruction.op.name(),
            expected,
            actual: row.rd_val,
        });
    }
    Ok(())
}

fn check_no_rd(index: usize, row: &TraceRow) -> Result<(), CpuError> {
    if row.rd_val != 0 {
        return Err(CpuError::RdValue {
            row: index,
            op: row.instruction.op.name(),
            expected: 0,
            actual: row.rd_val,
        });
    }
    Ok(())
}

fn check_memory(
    index: usize,
    row: &TraceRow,
    expected_addr: Addr,
    expected_width: u8,
    is_write: bool,
) -> Result<(), CpuError> {
    let access = row.mem.ok_or(CpuError::MissingMemory { row: index })?;
    if access.addr != expected_addr {
        return Err(CpuError::MemAddr {
            row: index,
            expected: expected_addr,
            actual: access.addr,
        });
    }
    if access.width != expected_width {
        return Err(CpuError::MemWidth {
            row: index,
            expected: expected_width,
            actual: access.width,
        });
    }
    if access.is_write != is_write {
        return Err(CpuError::UnexpectedMemory { row: index });
    }
    Ok(())
}

/// Encode the linear subset of the ALU into the reference constraint IR.
///
/// This is a bridge, not the final CPU circuit: comparisons, bitwise ops,
/// shifts, and memory consistency need dedicated reductions.
pub fn linear_alu_constraints(trace: &Trace) -> (ConstraintSystem, Witness) {
    let mut system = ConstraintSystem::new(trace.rows.len() * 4);
    let mut values = Vec::with_capacity(trace.rows.len() * 4);

    for (index, row) in trace.rows.iter().enumerate() {
        let base = index * 4;
        let (rs1, rs2, rd) = (base, base + 1, base + 2);
        values.push(F61::from(row.rs1_val));
        values.push(F61::from(row.rs2_val));
        values.push(F61::from(row.rd_val));
        values.push(F61::from(0));

        let one = Expr::constant(1u64);
        match row.instruction.op {
            Op::Add => {
                system.add_constraint(Expr::var(rs1).add(Expr::var(rs2)), one, Expr::var(rd));
            }
            Op::Sub => {
                system.add_constraint(Expr::var(rs1).sub(Expr::var(rs2)), one, Expr::var(rd));
            }
            Op::Addi => {
                system.add_constraint(
                    Expr::var(rs1).add(Expr::constant(fe_i64(row.instruction.imm))),
                    one,
                    Expr::var(rd),
                );
            }
            Op::Lui => {
                system.add_constraint(
                    Expr::var(rd),
                    one,
                    Expr::constant(fe_i64(row.instruction.imm)),
                );
            }
            Op::Auipc => {
                system.add_constraint(
                    Expr::var(rd),
                    one,
                    Expr::constant(row.pc).add(Expr::constant(fe_i64(row.instruction.imm))),
                );
            }
            _ => {}
        }
    }

    (system, Witness::new(values))
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, ProgramImage};

    fn trace() -> Trace {
        let config = MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x1000,
            stack_top: 0x1000_1000,
            max_cycles: 100,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 5,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Addi,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
                    imm: 7,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Add,
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
        execute(&program, config).unwrap()
    }

    #[test]
    fn checks_reference_trace() {
        let trace = trace();
        check_trace(&trace).unwrap();
        let (system, witness) = linear_alu_constraints(&trace);
        system.check(&witness).unwrap();
    }

    #[test]
    fn detects_bad_alu_result() {
        let mut trace = trace();
        trace.rows[2].rd_val = 99;
        assert!(matches!(check_trace(&trace), Err(CpuError::RdValue { .. })));
    }
}
