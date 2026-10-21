//! Reference RV64I interpreter and trace generator.
//!
//! This is intentionally a reference implementation: it executes the program
//! and records the witness a prover needs. It is not itself a proof system.

use magnetar_spec::{
    decode, Addr, DecodeError, Instruction, MachineConfig, MachineState, MemoryAccess, MemoryEvent,
    Op, ProgramImage, Trace, TraceRow, Word,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExecError {
    #[error("entry pc 0x{0:x} is not in ROM")]
    EntryOutOfBounds(Word),
    #[error("pc 0x{0:x} is not in ROM")]
    PcOutOfBounds(Word),
    #[error("pc 0x{0:x} is not 4-byte aligned")]
    UnalignedPc(Word),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error("cycle limit {0} exceeded")]
    CycleLimit(u64),
    #[error("misaligned {kind} at 0x{addr:x} (width {width})")]
    Misaligned {
        addr: Addr,
        width: usize,
        kind: &'static str,
    },
    #[error("memory access out of bounds at 0x{0:x}")]
    MemoryOutOfBounds(Addr),
    #[error("program data ({} bytes) exceeds RAM size ({} bytes)", .0, .1)]
    DataTooLarge(usize, usize),
}

/// Execute a program and return its reference trace.
pub fn execute(program: &ProgramImage, config: MachineConfig) -> Result<Trace, ExecError> {
    if program.data.len() > config.ram_size {
        return Err(ExecError::DataTooLarge(program.data.len(), config.ram_size));
    }
    if config.rom_index(program.entry).is_none() {
        return Err(ExecError::EntryOutOfBounds(program.entry));
    }

    let mut ram = vec![0u8; config.ram_size];
    ram[..program.data.len()].copy_from_slice(&program.data);
    let initial_ram = ram.clone();

    let mut state = MachineState::new(program.entry);
    let initial_state = state.clone();
    let mut rows = Vec::new();
    let mut events = Vec::new();
    let mut halted = false;
    let mut exit_code = None;

    for cycle in 0..config.max_cycles {
        if !state.pc.is_multiple_of(4) {
            return Err(ExecError::UnalignedPc(state.pc));
        }
        let index = config
            .rom_index(state.pc)
            .ok_or(ExecError::PcOutOfBounds(state.pc))?;
        let instruction_word = *program
            .rom
            .get(index)
            .ok_or(ExecError::PcOutOfBounds(state.pc))?;
        let instruction = decode(instruction_word)?;

        let rs1_val = instruction
            .rs1_index()
            .map(|index| state.reg(index))
            .unwrap_or(0);
        let rs2_val = instruction
            .rs2_index()
            .map(|index| state.reg(index))
            .unwrap_or(0);

        let outcome = execute_one(&config, &mut ram, &state, instruction, rs1_val, rs2_val)?;

        if let Some(access) = outcome.memory {
            events.push(MemoryEvent { cycle, access });
        }

        rows.push(TraceRow {
            cycle,
            pc: state.pc,
            next_pc: outcome.next_pc,
            instruction_word,
            instruction,
            rs1: instruction.rs1_index(),
            rs2: instruction.rs2_index(),
            rd: instruction.rd_index(),
            rs1_val,
            rs2_val,
            rd_val: outcome.rd_val,
            mem: outcome.memory,
        });

        if let Some(rd) = instruction.rd_index() {
            state.set_reg(rd, outcome.rd_val);
        }

        if instruction.op.is_halt() {
            halted = true;
            if instruction.op == Op::Ecall {
                exit_code = Some(state.reg(10));
            }
            state.pc = outcome.next_pc;
            break;
        }

        state.pc = outcome.next_pc;
    }

    if !halted {
        return Err(ExecError::CycleLimit(config.max_cycles));
    }

    debug_assert!(state.regs[0] == 0);

    Ok(Trace {
        config,
        initial_state,
        final_state: state,
        rows,
        memory_events: events,
        initial_ram,
        halted,
        exit_code,
    })
}

struct StepOutcome {
    rd_val: Word,
    next_pc: Word,
    memory: Option<MemoryAccess>,
}

fn execute_one(
    config: &MachineConfig,
    ram: &mut [u8],
    state: &MachineState,
    instruction: Instruction,
    rs1_val: Word,
    rs2_val: Word,
) -> Result<StepOutcome, ExecError> {
    let pc = state.pc;
    let imm = instruction.imm as Word;
    let mut rd_val = 0;
    let mut next_pc = pc.wrapping_add(4);
    let mut memory = None;

    match instruction.op {
        Op::Add => rd_val = rs1_val.wrapping_add(rs2_val),
        Op::Sub => rd_val = rs1_val.wrapping_sub(rs2_val),
        Op::Sll => rd_val = rs1_val.wrapping_shl((rs2_val & 0x3f) as u32),
        Op::Slt => rd_val = u64::from((rs1_val as i64) < (rs2_val as i64)),
        Op::Sltu => rd_val = u64::from(rs1_val < rs2_val),
        Op::Xor => rd_val = rs1_val ^ rs2_val,
        Op::Srl => rd_val = rs1_val.wrapping_shr((rs2_val & 0x3f) as u32),
        Op::Sra => rd_val = ((rs1_val as i64) >> (rs2_val & 0x3f)) as u64,
        Op::Or => rd_val = rs1_val | rs2_val,
        Op::And => rd_val = rs1_val & rs2_val,
        Op::Addi => rd_val = rs1_val.wrapping_add(imm),
        Op::Slti => rd_val = u64::from((rs1_val as i64) < (instruction.imm)),
        Op::Sltiu => rd_val = u64::from(rs1_val < imm),
        Op::Xori => rd_val = rs1_val ^ imm,
        Op::Ori => rd_val = rs1_val | imm,
        Op::Andi => rd_val = rs1_val & imm,
        Op::Slli => rd_val = rs1_val.wrapping_shl(u32::from(instruction.shamt)),
        Op::Srli => rd_val = rs1_val.wrapping_shr(u32::from(instruction.shamt)),
        Op::Srai => rd_val = ((rs1_val as i64) >> instruction.shamt) as u64,
        Op::Lui => rd_val = imm,
        Op::Auipc => rd_val = pc.wrapping_add(imm),
        Op::Jal => {
            rd_val = pc.wrapping_add(4);
            next_pc = pc.wrapping_add(imm);
        }
        Op::Jalr => {
            rd_val = pc.wrapping_add(4);
            next_pc = rs1_val.wrapping_add(imm) & !1;
        }
        Op::Beq => {
            if rs1_val == rs2_val {
                next_pc = pc.wrapping_add(imm);
            }
        }
        Op::Bne => {
            if rs1_val != rs2_val {
                next_pc = pc.wrapping_add(imm);
            }
        }
        Op::Blt => {
            if (rs1_val as i64) < (rs2_val as i64) {
                next_pc = pc.wrapping_add(imm);
            }
        }
        Op::Bge => {
            if (rs1_val as i64) >= (rs2_val as i64) {
                next_pc = pc.wrapping_add(imm);
            }
        }
        Op::Bltu => {
            if rs1_val < rs2_val {
                next_pc = pc.wrapping_add(imm);
            }
        }
        Op::Bgeu => {
            if rs1_val >= rs2_val {
                next_pc = pc.wrapping_add(imm);
            }
        }
        Op::Lb => {
            let addr = rs1_val.wrapping_add(imm);
            let raw = load(config, ram, addr, 1, "load")?;
            rd_val = (raw as u8 as i8 as i64) as u64;
            memory = Some(MemoryAccess {
                addr,
                value: raw,
                width: 1,
                is_write: false,
            });
        }
        Op::Lh => {
            let addr = rs1_val.wrapping_add(imm);
            let raw = load(config, ram, addr, 2, "load")?;
            rd_val = (raw as u16 as i16 as i64) as u64;
            memory = Some(MemoryAccess {
                addr,
                value: raw,
                width: 2,
                is_write: false,
            });
        }
        Op::Lw => {
            let addr = rs1_val.wrapping_add(imm);
            let raw = load(config, ram, addr, 4, "load")?;
            rd_val = (raw as u32 as i32 as i64) as u64;
            memory = Some(MemoryAccess {
                addr,
                value: raw,
                width: 4,
                is_write: false,
            });
        }
        Op::Ld => {
            let addr = rs1_val.wrapping_add(imm);
            let raw = load(config, ram, addr, 8, "load")?;
            rd_val = raw;
            memory = Some(MemoryAccess {
                addr,
                value: raw,
                width: 8,
                is_write: false,
            });
        }
        Op::Lbu => {
            let addr = rs1_val.wrapping_add(imm);
            let raw = load(config, ram, addr, 1, "load")?;
            rd_val = raw as u8 as u64;
            memory = Some(MemoryAccess {
                addr,
                value: raw,
                width: 1,
                is_write: false,
            });
        }
        Op::Lhu => {
            let addr = rs1_val.wrapping_add(imm);
            let raw = load(config, ram, addr, 2, "load")?;
            rd_val = raw as u16 as u64;
            memory = Some(MemoryAccess {
                addr,
                value: raw,
                width: 2,
                is_write: false,
            });
        }
        Op::Lwu => {
            let addr = rs1_val.wrapping_add(imm);
            let raw = load(config, ram, addr, 4, "load")?;
            rd_val = raw as u32 as u64;
            memory = Some(MemoryAccess {
                addr,
                value: raw,
                width: 4,
                is_write: false,
            });
        }
        Op::Sb | Op::Sh | Op::Sw | Op::Sd => {
            let width = match instruction.op {
                Op::Sb => 1,
                Op::Sh => 2,
                Op::Sw => 4,
                Op::Sd => 8,
                _ => unreachable!(),
            };
            let addr = rs1_val.wrapping_add(imm);
            store(config, ram, addr, width, rs2_val, "store")?;
            memory = Some(MemoryAccess {
                addr,
                value: rs2_val,
                width: width as u8,
                is_write: true,
            });
        }
        Op::Fence => {}
        Op::Ecall | Op::Ebreak => {
            next_pc = pc;
        }
    }

    Ok(StepOutcome {
        rd_val,
        next_pc,
        memory,
    })
}

fn load(
    config: &MachineConfig,
    ram: &[u8],
    addr: Addr,
    width: usize,
    kind: &'static str,
) -> Result<Word, ExecError> {
    if !addr.is_multiple_of(width as u64) {
        return Err(ExecError::Misaligned { addr, width, kind });
    }
    let index = config
        .ram_index(addr, width)
        .ok_or(ExecError::MemoryOutOfBounds(addr))?;
    let mut bytes = [0u8; 8];
    bytes[..width].copy_from_slice(&ram[index..index + width]);
    Ok(u64::from_le_bytes(bytes))
}

fn store(
    config: &MachineConfig,
    ram: &mut [u8],
    addr: Addr,
    width: usize,
    value: Word,
    kind: &'static str,
) -> Result<(), ExecError> {
    if !addr.is_multiple_of(width as u64) {
        return Err(ExecError::Misaligned { addr, width, kind });
    }
    let index = config
        .ram_index(addr, width)
        .ok_or(ExecError::MemoryOutOfBounds(addr))?;
    let bytes = value.to_le_bytes();
    ram[index..index + width].copy_from_slice(&bytes[..width]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_spec::Instruction;

    fn config() -> MachineConfig {
        MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x1000,
            stack_top: 0x1000_1000,
            max_cycles: 100,
        }
    }

    fn ins(op: Op) -> Instruction {
        Instruction::new(op)
    }

    #[test]
    fn executes_arithmetic_and_memory() {
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
                Instruction {
                    op: Op::Lui,
                    rd: 4,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x1000_0000,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Sd,
                    rd: 0,
                    rs1: 4,
                    rs2: 3,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Ld,
                    rd: 5,
                    rs1: 4,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                ins(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, config()).expect("program should execute");
        assert!(trace.halted);
        assert_eq!(trace.final_state.reg(5), 12);
        assert_eq!(trace.memory_writes().count(), 1);
        assert_eq!(trace.memory_reads().count(), 1);
        assert_eq!(trace.rows.len(), 7);
    }

    #[test]
    fn branch_skips_next_instruction() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 1,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Beq,
                    rd: 0,
                    rs1: 1,
                    rs2: 1,
                    imm: 8,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Addi,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
                    imm: 99,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Addi,
                    rd: 3,
                    rs1: 0,
                    rs2: 0,
                    imm: 42,
                    shamt: 0,
                }
                .encode(),
                ins(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, config()).expect("program should execute");
        assert_eq!(trace.final_state.reg(2), 0);
        assert_eq!(trace.final_state.reg(3), 42);
    }
}
