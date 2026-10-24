//! Reference RV64I + RV64M interpreter and trace generator.
//!
//! This is intentionally a reference implementation: it executes the program
//! and records the witness a prover needs. It is not itself a proof system.

use magnetar_spec::syscall::{SYS_EXIT, SYS_HINT, SYS_READ, SYS_WRITE};
use magnetar_spec::{
    addw, decode, decode_compressed, div, divu, mulh, mulhsu, mulhu, rem, remu, sllw, sraw, srlw,
    subw, Addr, CompressedError, DecodeError, Instruction, MachineConfig, MachineState,
    MemoryAccess, MemoryEvent, Op, ProgramImage, SyscallTrace, Trace, TraceRow, Word,
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
    #[error(transparent)]
    Compressed(#[from] CompressedError),
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
    #[error("unsupported syscall {0}")]
    UnsupportedSyscall(Word),
    #[error("read length {0} does not fit in the host address space")]
    UnsupportedReadLength(Word),
    #[error("unsupported syscall file descriptor {0}")]
    UnsupportedFd(Word),
    #[error("syscall pointer {ptr:#x} with length {len} is outside RAM")]
    BadSyscallPointer { ptr: Word, len: Word },
}

/// Buffered host I/O used by the reference syscall implementation.
#[derive(Clone, Debug, Default)]
pub struct ExecutionIo {
    pub input: Vec<u8>,
    pub output: Vec<u8>,
    read_cursor: usize,
    consumed: Vec<u8>,
}

impl ExecutionIo {
    pub fn with_input(input: Vec<u8>) -> Self {
        Self {
            input,
            ..Self::default()
        }
    }

    pub fn consumed(&self) -> &[u8] {
        &self.consumed
    }
}

/// Execute a program and return its reference trace.
pub fn execute(program: &ProgramImage, config: MachineConfig) -> Result<Trace, ExecError> {
    execute_with_io(program, config, &mut ExecutionIo::default())
}

fn fetch_instruction(
    program: &ProgramImage,
    config: &MachineConfig,
    pc: Word,
) -> Result<(u32, u8, Instruction), ExecError> {
    let offset = pc
        .checked_sub(config.rom_base)
        .ok_or(ExecError::PcOutOfBounds(pc))?;
    if !offset.is_multiple_of(2) {
        return Err(ExecError::UnalignedPc(pc));
    }
    let index = usize::try_from(offset / 4).map_err(|_| ExecError::PcOutOfBounds(pc))?;
    let word = *program.rom.get(index).ok_or(ExecError::PcOutOfBounds(pc))?;
    if offset % 4 == 2 {
        let half = (word >> 16) as u16;
        if half & 3 == 3 {
            return Err(ExecError::UnalignedPc(pc));
        }
        return Ok((u32::from(half), 2, decode_compressed(half)?));
    }
    let half = (word & 0xffff) as u16;
    if half & 3 == 3 {
        return Ok((word, 4, decode(word)?));
    }
    Ok((u32::from(half), 2, decode_compressed(half)?))
}

pub fn execute_with_io(
    program: &ProgramImage,
    config: MachineConfig,
    io: &mut ExecutionIo,
) -> Result<Trace, ExecError> {
    if program.data.len() > config.ram_size {
        return Err(ExecError::DataTooLarge(program.data.len(), config.ram_size));
    }
    if program
        .entry
        .checked_sub(config.rom_base)
        .filter(|offset| offset.is_multiple_of(2))
        .and_then(|offset| usize::try_from(offset / 4).ok())
        .is_none_or(|index| index >= program.rom.len())
    {
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
    let mut reservation: Option<Addr> = None;

    for cycle in 0..config.max_cycles {
        if !state.pc.is_multiple_of(2) {
            return Err(ExecError::UnalignedPc(state.pc));
        }
        let (instruction_word, instruction_len, instruction) =
            fetch_instruction(program, &config, state.pc)?;
        let syscall = if instruction.op == Op::Ecall {
            Some(SyscallTrace {
                number: state.reg(17),
                args: [state.reg(10), state.reg(11), state.reg(12)],
            })
        } else {
            None
        };

        let rs1_val = instruction
            .rs1_index()
            .map(|index| state.reg(index))
            .unwrap_or(0);
        let rs2_val = instruction
            .rs2_index()
            .map(|index| state.reg(index))
            .unwrap_or(0);

        let reservation_before = reservation;
        let outcome = execute_one(
            &config,
            &mut ram,
            &state,
            instruction,
            instruction_len,
            rs1_val,
            rs2_val,
            io,
            &mut reservation,
        )?;

        if let Some(access) = outcome.memory {
            events.push(MemoryEvent { cycle, access });
        }
        for access in &outcome.extra_memory {
            events.push(MemoryEvent {
                cycle,
                access: *access,
            });
        }

        let (rd, rd_val) = if instruction.op == Op::Ecall {
            match outcome.syscall_return {
                Some(value) => (Some(10), value),
                None => (instruction.rd_index(), outcome.rd_val),
            }
        } else {
            (instruction.rd_index(), outcome.rd_val)
        };

        rows.push(TraceRow {
            cycle,
            micro_pc: state.pc,
            micro_op: magnetar_spec::MicroOpKind::Execute,
            pc: state.pc,
            next_pc: outcome.next_pc,
            instruction_word,
            instruction_len,
            instruction,
            rs1: instruction.rs1_index(),
            rs2: instruction.rs2_index(),
            rd,
            rs1_val,
            rs2_val,
            rd_val,
            mem: outcome.memory,
            extra_mem: outcome.extra_memory,
            reservation_before,
            reservation_after: reservation,
            syscall,
        });

        if let Some(rd) = instruction.rd_index() {
            state.set_reg(rd, outcome.rd_val);
        }
        if instruction.op == Op::Ecall {
            if let Some(value) = outcome.syscall_return {
                state.set_reg(10, value);
            }
        }

        if outcome.halt {
            halted = true;
            if let Some(code) = outcome.exit_code {
                exit_code = Some(code);
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
        rom: program.rom.clone(),
        initial_state,
        final_state: state,
        rows,
        memory_events: events,
        initial_ram,
        halted,
        exit_code,
        io_output: io.output.clone(),
        io_input: io.consumed().to_vec(),
    })
}

struct StepOutcome {
    rd_val: Word,
    next_pc: Word,
    memory: Option<MemoryAccess>,
    extra_memory: Vec<MemoryAccess>,
    halt: bool,
    exit_code: Option<Word>,
    syscall_return: Option<Word>,
}

#[allow(clippy::too_many_arguments)]
fn execute_one(
    config: &MachineConfig,
    ram: &mut [u8],
    state: &MachineState,
    instruction: Instruction,
    instruction_len: u8,
    rs1_val: Word,
    rs2_val: Word,
    io: &mut ExecutionIo,
    reservation: &mut Option<Addr>,
) -> Result<StepOutcome, ExecError> {
    let pc = state.pc;
    let next_pc_increment = pc.wrapping_add(u64::from(instruction_len));
    let imm = instruction.imm as Word;
    let mut rd_val = 0;
    let mut next_pc = next_pc_increment;
    let mut memory = None;
    let mut extra_memory = Vec::new();
    let mut halt = false;
    let mut exit_code = None;
    let mut syscall_return = None;

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
        Op::Addw => rd_val = addw(rs1_val, rs2_val),
        Op::Subw => rd_val = subw(rs1_val, rs2_val),
        Op::Sllw => rd_val = sllw(rs1_val, rs2_val),
        Op::Srlw => rd_val = srlw(rs1_val, rs2_val),
        Op::Sraw => rd_val = sraw(rs1_val, rs2_val),
        Op::Mul => rd_val = rs1_val.wrapping_mul(rs2_val),
        Op::Mulh => rd_val = mulh(rs1_val, rs2_val),
        Op::Mulhsu => rd_val = mulhsu(rs1_val, rs2_val),
        Op::Mulhu => rd_val = mulhu(rs1_val, rs2_val),
        Op::Div => rd_val = div(rs1_val, rs2_val),
        Op::Divu => rd_val = divu(rs1_val, rs2_val),
        Op::Rem => rd_val = rem(rs1_val, rs2_val),
        Op::Remu => rd_val = remu(rs1_val, rs2_val),
        Op::Addi => rd_val = rs1_val.wrapping_add(imm),
        Op::Addiw => rd_val = addw(rs1_val, imm),
        Op::Slti => rd_val = u64::from((rs1_val as i64) < (instruction.imm)),
        Op::Sltiu => rd_val = u64::from(rs1_val < imm),
        Op::Xori => rd_val = rs1_val ^ imm,
        Op::Ori => rd_val = rs1_val | imm,
        Op::Andi => rd_val = rs1_val & imm,
        Op::Slli => rd_val = rs1_val.wrapping_shl(u32::from(instruction.shamt)),
        Op::Slliw => rd_val = sllw(rs1_val, u64::from(instruction.shamt)),
        Op::Srli => rd_val = rs1_val.wrapping_shr(u32::from(instruction.shamt)),
        Op::Srliw => rd_val = srlw(rs1_val, u64::from(instruction.shamt)),
        Op::Srai => rd_val = ((rs1_val as i64) >> instruction.shamt) as u64,
        Op::Sraiw => rd_val = sraw(rs1_val, u64::from(instruction.shamt)),
        Op::Lui => rd_val = imm,
        Op::Auipc => rd_val = pc.wrapping_add(imm),
        Op::Jal => {
            rd_val = next_pc_increment;
            next_pc = pc.wrapping_add(imm);
        }
        Op::Jalr => {
            rd_val = next_pc_increment;
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
            *reservation = None;
            memory = Some(MemoryAccess {
                addr,
                value: rs2_val,
                width: width as u8,
                is_write: true,
            });
        }
        Op::LrW | Op::LrD => {
            let width = if instruction.op == Op::LrW { 4 } else { 8 };
            let addr = rs1_val.wrapping_add(imm);
            let value = load(config, ram, addr, width, "lr")?;
            rd_val = if width == 4 {
                (value as u32 as i32 as i64) as u64
            } else {
                value
            };
            memory = Some(MemoryAccess {
                addr,
                value,
                width: width as u8,
                is_write: false,
            });
            *reservation = Some(addr);
        }
        Op::ScW | Op::ScD => {
            let width = if instruction.op == Op::ScW { 4 } else { 8 };
            let addr = rs1_val.wrapping_add(imm);
            if *reservation == Some(addr) {
                let mask = if width == 4 {
                    (1u64 << 32) - 1
                } else {
                    u64::MAX
                };
                let value = rs2_val & mask;
                store(config, ram, addr, width, value, "sc")?;
                rd_val = 0;
                memory = Some(MemoryAccess {
                    addr,
                    value,
                    width: width as u8,
                    is_write: true,
                });
            } else {
                rd_val = 1;
            }
            *reservation = None;
        }
        Op::AmoswapW
        | Op::AmoswapD
        | Op::AmoaddW
        | Op::AmoaddD
        | Op::AmoxorW
        | Op::AmoxorD
        | Op::AmoandW
        | Op::AmoandD
        | Op::AmoorW
        | Op::AmoorD
        | Op::AmominW
        | Op::AmominD
        | Op::AmomaxW
        | Op::AmomaxD
        | Op::AmominuW
        | Op::AmominuD
        | Op::AmomaxuW
        | Op::AmomaxuD => {
            let width = instruction.op.amo_width().expect("AMO width");
            let addr = rs1_val.wrapping_add(imm);
            let old = load(config, ram, addr, width, "amo")?;
            let new_value = instruction.op.amo_apply(old, rs2_val);
            store(config, ram, addr, width, new_value, "amo")?;
            rd_val = if width == 4 {
                (old as u32 as i32 as i64) as u64
            } else {
                old
            };
            memory = Some(MemoryAccess {
                addr,
                value: new_value,
                width: width as u8,
                is_write: true,
            });
            *reservation = None;
        }
        Op::Fence => {}
        Op::Ecall => {
            let a0 = state.reg(10);
            let a1 = state.reg(11);
            let a2 = state.reg(12);
            let a7 = state.reg(17);
            match a7 {
                0 | SYS_EXIT => {
                    next_pc = pc;
                    halt = true;
                    exit_code = Some(a0);
                }
                SYS_HINT => {
                    next_pc = next_pc_increment;
                    syscall_return = Some(0);
                }
                SYS_WRITE => {
                    if a0 != 1 && a0 != 2 {
                        return Err(ExecError::UnsupportedFd(a0));
                    }
                    let len = usize::try_from(a2)
                        .map_err(|_| ExecError::BadSyscallPointer { ptr: a1, len: a2 })?;
                    let index = config
                        .ram_index(a1, len)
                        .ok_or(ExecError::BadSyscallPointer { ptr: a1, len: a2 })?;
                    io.output.extend_from_slice(&ram[index..index + len]);
                    next_pc = next_pc_increment;
                    syscall_return = Some(a2);
                }
                SYS_READ => {
                    if a0 != 0 {
                        return Err(ExecError::UnsupportedFd(a0));
                    }
                    let len =
                        usize::try_from(a2).map_err(|_| ExecError::UnsupportedReadLength(a2))?;
                    if len == 0 {
                        next_pc = next_pc_increment;
                        syscall_return = Some(0);
                    } else {
                        let available = io.input.len().saturating_sub(io.read_cursor);
                        let count = available.min(len);
                        if count == 0 {
                            next_pc = next_pc_increment;
                            syscall_return = Some(0);
                        } else {
                            let index = config
                                .ram_index(a1, count)
                                .ok_or(ExecError::BadSyscallPointer { ptr: a1, len: a2 })?;
                            ram[index..index + count]
                                .copy_from_slice(&io.input[io.read_cursor..io.read_cursor + count]);
                            let last_byte = a1
                                .checked_add(count as u64 - 1)
                                .ok_or(ExecError::BadSyscallPointer { ptr: a1, len: a2 })?;
                            let mut word = a1 & !7;
                            loop {
                                let start = config
                                    .ram_index(word, 8)
                                    .ok_or(ExecError::BadSyscallPointer { ptr: a1, len: a2 })?;
                                let value = u64::from_le_bytes(
                                    ram[start..start + 8].try_into().expect("eight bytes"),
                                );
                                extra_memory.push(MemoryAccess {
                                    addr: word,
                                    value,
                                    width: 8,
                                    is_write: true,
                                });
                                if word >= last_byte & !7 {
                                    break;
                                }
                                word = word.wrapping_add(8);
                            }
                            io.read_cursor += count;
                            io.consumed.extend_from_slice(
                                &io.input[io.read_cursor - count..io.read_cursor],
                            );
                            next_pc = next_pc_increment;
                            syscall_return = Some(count as u64);
                        }
                    }
                }
                _ => {
                    // Legacy halt behavior for unknown/zero syscall numbers.
                    next_pc = pc;
                    halt = true;
                    exit_code = Some(a0);
                }
            }
        }
        Op::Ebreak => {
            next_pc = pc;
            halt = true;
        }
    }

    Ok(StepOutcome {
        rd_val,
        next_pc,
        memory,
        extra_memory,
        halt,
        exit_code,
        syscall_return,
    })
}

fn within_word(addr: Addr, width: usize) -> bool {
    if width == 0 || width > 8 {
        return false;
    }
    let Some(last) = addr.checked_add(width as u64 - 1) else {
        return false;
    };
    addr & !7 == last & !7
}

fn load(
    config: &MachineConfig,
    ram: &[u8],
    addr: Addr,
    width: usize,
    kind: &'static str,
) -> Result<Word, ExecError> {
    if !within_word(addr, width) {
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
    if !within_word(addr, width) {
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

    fn simple_ins(op: Op) -> Instruction {
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
                simple_ins(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, config()).expect("program should execute");
        assert!(trace.halted);
        assert_eq!(trace.final_state.reg(5), 12);
        assert_eq!(trace.memory_writes().count(), 1);
        assert_eq!(trace.memory_reads().count(), 1);
        assert_eq!(trace.rows.len(), 7);
        assert_eq!(trace.len(), 7);
        assert!(!trace.is_empty());
        assert_eq!(trace.row(0).unwrap().pc, 0x1000);
        assert!(trace.row(7).is_none());
    }

    fn ins(op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64, shamt: u8) -> u32 {
        Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt,
        }
        .encode()
    }

    #[test]
    fn executes_hint_write_and_rejects_unsupported_syscalls() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                ins(Op::Addi, 17, 0, 0, 1000, 0),
                ins(Op::Ecall, 0, 0, 0, 0, 0),
                ins(Op::Addi, 17, 0, 0, 64, 0),
                ins(Op::Lui, 11, 0, 0, 0x1000_0000, 0),
                ins(Op::Addi, 12, 0, 0, 5, 0),
                ins(Op::Addi, 10, 0, 0, 1, 0),
                ins(Op::Ecall, 0, 0, 0, 0, 0),
                ins(Op::Addi, 10, 0, 0, 7, 0),
                ins(Op::Addi, 17, 0, 0, 93, 0),
                ins(Op::Ecall, 0, 0, 0, 0, 0),
            ],
        )
        .with_data(b"hello".to_vec());
        let mut io = ExecutionIo::default();
        let trace = execute_with_io(&program, config(), &mut io).unwrap();
        assert_eq!(io.output, b"hello");
        assert_eq!(trace.io_output, b"hello");
        assert_eq!(trace.exit_code, Some(7));
        assert_eq!(trace.final_state.reg(10), 7);
        assert_eq!(trace.rows[1].next_pc, 0x1008);
        assert_eq!(trace.rows[1].rd, Some(10));
        assert_eq!(trace.rows[1].rd_val, 0);
        assert_eq!(trace.rows[6].next_pc, 0x101c);
        assert_eq!(trace.rows[6].rd, Some(10));
        assert_eq!(trace.rows[6].rd_val, 5);

        let read = ProgramImage::new(
            0x1000,
            vec![
                ins(Op::Lui, 11, 0, 0, 0x1000_0000, 0),
                ins(Op::Addi, 12, 0, 0, 8, 0),
                ins(Op::Addi, 10, 0, 0, 0, 0),
                ins(Op::Addi, 17, 0, 0, 63, 0),
                ins(Op::Ecall, 0, 0, 0, 0, 0),
                ins(Op::Ld, 13, 11, 0, 0, 0),
                ins(Op::Ebreak, 0, 0, 0, 0, 0),
            ],
        );
        let mut io = ExecutionIo::with_input(b"ABCDEFGH".to_vec());
        let trace = execute_with_io(&read, config(), &mut io).unwrap();
        assert_eq!(io.consumed(), b"ABCDEFGH");
        assert_eq!(trace.io_input, b"ABCDEFGH");
        assert_eq!(trace.final_state.reg(10), 8);
        assert_eq!(trace.final_state.reg(13), u64::from_le_bytes(*b"ABCDEFGH"));
        assert!(trace.halted);
        assert_eq!(trace.memory_writes().count(), 1);
        assert_eq!(trace.rows[4].syscall.as_ref().unwrap().number, 63);
        assert_eq!(
            trace.rows[4].syscall.as_ref().unwrap().args,
            [0, 0x1000_0000, 8]
        );
        assert_eq!(trace.rows[4].mem, None);
        assert_eq!(trace.rows[4].extra_mem.len(), 1);
        assert_eq!(trace.rows[4].extra_mem[0].addr, 0x1000_0000);
        assert_eq!(trace.rows[4].extra_mem[0].width, 8);

        let short_read = ProgramImage::new(
            0x1000,
            vec![
                ins(Op::Lui, 11, 0, 0, 0x1000_0000, 0),
                ins(Op::Addi, 12, 0, 0, 4, 0),
                ins(Op::Addi, 10, 0, 0, 0, 0),
                ins(Op::Addi, 17, 0, 0, 63, 0),
                ins(Op::Ecall, 0, 0, 0, 0, 0),
                ins(Op::Ld, 13, 11, 0, 0, 0),
                ins(Op::Ebreak, 0, 0, 0, 0, 0),
            ],
        );
        let mut io = ExecutionIo::with_input(b"WXYZ".to_vec());
        let short = execute_with_io(&short_read, config(), &mut io).unwrap();
        assert_eq!(
            short.final_state.reg(13),
            u64::from_le_bytes([b'W', b'X', b'Y', b'Z', 0, 0, 0, 0])
        );
        assert_eq!(short.rows[4].extra_mem.len(), 1);

        let eof = ProgramImage::new(
            0x1000,
            vec![
                ins(Op::Lui, 11, 0, 0, 0x1000_0000, 0),
                ins(Op::Addi, 12, 0, 0, 8, 0),
                ins(Op::Addi, 10, 0, 0, 0, 0),
                ins(Op::Addi, 17, 0, 0, 63, 0),
                ins(Op::Ecall, 0, 0, 0, 0, 0),
                ins(Op::Ebreak, 0, 0, 0, 0, 0),
            ],
        );
        let empty = execute(&eof, config()).unwrap();
        assert_eq!(empty.final_state.reg(10), 0);
        assert!(empty.io_input.is_empty());
        assert!(empty.rows[4].mem.is_none());

        let bad_fd = ProgramImage::new(
            0x1000,
            vec![
                ins(Op::Addi, 10, 0, 0, 9, 0),
                ins(Op::Addi, 17, 0, 0, 64, 0),
                ins(Op::Ecall, 0, 0, 0, 0, 0),
            ],
        );
        assert!(matches!(
            execute(&bad_fd, config()),
            Err(ExecError::UnsupportedFd(9))
        ));

        let bad_pointer = ProgramImage::new(
            0x1000,
            vec![
                ins(Op::Addi, 10, 0, 0, 1, 0),
                ins(Op::Addi, 11, 0, 0, 0x2000_0000, 0),
                ins(Op::Addi, 12, 0, 0, 5, 0),
                ins(Op::Addi, 17, 0, 0, 64, 0),
                ins(Op::Ecall, 0, 0, 0, 0, 0),
            ],
        );
        assert!(matches!(
            execute(&bad_pointer, config()),
            Err(ExecError::BadSyscallPointer { .. })
        ));
    }

    #[test]
    fn executes_the_alu_instruction_set() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                ins(Op::Addi, 1, 0, 0, 5, 0),
                ins(Op::Addi, 2, 0, 0, 3, 0),
                ins(Op::Add, 3, 1, 2, 0, 0),
                ins(Op::Sub, 4, 1, 2, 0, 0),
                ins(Op::And, 5, 1, 2, 0, 0),
                ins(Op::Or, 6, 1, 2, 0, 0),
                ins(Op::Xor, 7, 1, 2, 0, 0),
                ins(Op::Slt, 8, 2, 1, 0, 0),
                ins(Op::Sltu, 9, 2, 1, 0, 0),
                ins(Op::Slli, 10, 1, 0, 0, 2),
                ins(Op::Srli, 11, 1, 0, 0, 1),
                ins(Op::Srai, 12, 2, 0, 0, 1),
                ins(Op::Slti, 13, 2, 0, 4, 0),
                ins(Op::Sltiu, 14, 2, 0, 4, 0),
                ins(Op::Xori, 15, 1, 0, 1, 0),
                ins(Op::Ori, 16, 1, 0, 8, 0),
                ins(Op::Andi, 17, 1, 0, 7, 0),
                ins(Op::Ecall, 0, 0, 0, 0, 0),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        let regs = &trace.final_state.regs;
        assert_eq!(regs[3], 8);
        assert_eq!(regs[4], 2);
        assert_eq!(regs[5], 1);
        assert_eq!(regs[6], 7);
        assert_eq!(regs[7], 6);
        assert_eq!(regs[8], 1);
        assert_eq!(regs[9], 1);
        assert_eq!(regs[10], 20);
        assert_eq!(regs[11], 2);
        assert_eq!(regs[12], 1);
        assert_eq!(regs[13], 1);
        assert_eq!(regs[14], 1);
        assert_eq!(regs[15], 4);
        assert_eq!(regs[16], 13);
        assert_eq!(regs[17], 5);
    }

    #[test]
    fn executes_lr_and_sc_with_reservations() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                ins(Op::Lui, 4, 0, 0, 0x1000_0000, 0),
                ins(Op::Addi, 1, 0, 0, 7, 0),
                ins(Op::Sd, 0, 4, 1, 0, 0),
                ins(Op::LrD, 2, 4, 0, 0, 0),
                ins(Op::Addi, 3, 0, 0, 9, 0),
                ins(Op::ScD, 5, 4, 3, 0, 0),
                ins(Op::LrD, 6, 4, 0, 0, 0),
                ins(Op::Sd, 0, 4, 1, 0, 0),
                ins(Op::ScD, 7, 4, 3, 0, 0),
                ins(Op::ScD, 8, 4, 3, 0, 0),
                ins(Op::Ld, 9, 4, 0, 0, 0),
                ins(Op::Ecall, 0, 0, 0, 0, 0),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        let regs = &trace.final_state.regs;
        assert_eq!(regs[2], 7);
        assert_eq!(regs[5], 0);
        assert_eq!(regs[6], 9);
        assert_eq!(regs[7], 1);
        assert_eq!(regs[8], 1);
        assert_eq!(regs[9], 7);
    }

    #[test]
    fn executes_amo_operations() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                ins(Op::Lui, 4, 0, 0, 0x1000_0000, 0),
                ins(Op::Addi, 1, 0, 0, 10, 0),
                ins(Op::Sd, 0, 4, 1, 0, 0),
                ins(Op::Addi, 2, 0, 0, 5, 0),
                ins(Op::AmoaddD, 3, 4, 2, 0, 0),
                ins(Op::AmoswapW, 5, 4, 2, 0, 0),
                ins(Op::AmoxorD, 6, 4, 2, 0, 0),
                ins(Op::AmomaxD, 7, 4, 2, 0, 0),
                ins(Op::Ld, 8, 4, 0, 0, 0),
                ins(Op::Ecall, 0, 0, 0, 0, 0),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        let regs = &trace.final_state.regs;
        assert_eq!(regs[3], 10);
        // Amoswap.W returns the old low word and writes the source.
        assert_eq!(regs[5], 15);
        // After the swap the word is 5; xor returns 5 and writes 0.
        assert_eq!(regs[6], 5);
        // max(0, 5) returns 0 and writes 5.
        assert_eq!(regs[7], 0);
        assert_eq!(regs[8], 5);
    }

    #[test]
    fn executes_rv64m_multiplication_and_division() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                ins(Op::Addi, 1, 0, 0, -7, 0),
                ins(Op::Addi, 2, 0, 0, 2, 0),
                ins(Op::Mul, 3, 1, 2, 0, 0),
                ins(Op::Div, 4, 1, 2, 0, 0),
                ins(Op::Rem, 5, 1, 2, 0, 0),
                ins(Op::Divu, 6, 1, 2, 0, 0),
                ins(Op::Remu, 7, 1, 2, 0, 0),
                ins(Op::Mulh, 8, 1, 2, 0, 0),
                ins(Op::Mulhsu, 9, 1, 2, 0, 0),
                ins(Op::Mulhu, 10, 1, 2, 0, 0),
                ins(Op::Ecall, 0, 0, 0, 0, 0),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        let regs = &trace.final_state.regs;
        assert_eq!(regs[3], (-14i64) as u64);
        assert_eq!(regs[4], (-3i64) as u64);
        assert_eq!(regs[5], (-1i64) as u64);
        assert_eq!(regs[6], (1u64 << 63) - 4);
        assert_eq!(regs[7], 1);
        assert_eq!(regs[8], u64::MAX);
        assert_eq!(regs[9], u64::MAX);
        assert_eq!(regs[10], 1);
    }

    #[test]
    fn allows_unaligned_within_word_loads_and_stores() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                ins(Op::Lui, 20, 0, 0, 0x1000_0000, 0),
                ins(Op::Lw, 6, 20, 0, 2, 0),
                ins(Op::Ecall, 0, 0, 0, 0, 0),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        assert_eq!(trace.final_state.regs[6], 0);
    }

    #[test]
    fn executes_signed_and_unsigned_loads_and_subword_stores() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                ins(Op::Lui, 20, 0, 0, 0x1000_0000, 0),
                ins(Op::Addi, 1, 0, 0, -1, 0),
                ins(Op::Sd, 0, 20, 1, 0, 0),
                ins(Op::Lb, 2, 20, 0, 0, 0),
                ins(Op::Lbu, 3, 20, 0, 0, 0),
                ins(Op::Lh, 4, 20, 0, 0, 0),
                ins(Op::Lhu, 5, 20, 0, 0, 0),
                ins(Op::Lw, 6, 20, 0, 0, 0),
                ins(Op::Lwu, 7, 20, 0, 0, 0),
                ins(Op::Ld, 8, 20, 0, 0, 0),
                ins(Op::Sb, 0, 20, 1, 8, 0),
                ins(Op::Sb, 0, 20, 1, 9, 0),
                ins(Op::Sh, 0, 20, 1, 10, 0),
                ins(Op::Sw, 0, 20, 1, 12, 0),
                ins(Op::Ld, 9, 20, 0, 8, 0),
                ins(Op::Ecall, 0, 0, 0, 0, 0),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        let regs = &trace.final_state.regs;
        assert_eq!(regs[2], u64::MAX);
        assert_eq!(regs[3], 255);
        assert_eq!(regs[4], u64::MAX);
        assert_eq!(regs[5], 65535);
        assert_eq!(regs[6], u64::MAX);
        assert_eq!(regs[7], 0xffff_ffff);
        assert_eq!(regs[8], u64::MAX);
        assert_eq!(regs[9], u64::MAX);
        assert_eq!(trace.memory_writes().count(), 5);
        assert_eq!(trace.memory_reads().count(), 8);
    }

    #[test]
    fn executes_all_conditional_branches() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                ins(Op::Addi, 1, 0, 0, 1, 0),
                ins(Op::Addi, 2, 0, 0, 2, 0),
                ins(Op::Beq, 0, 1, 1, 8, 0),
                ins(Op::Addi, 3, 0, 0, 99, 0),
                ins(Op::Bne, 0, 1, 2, 8, 0),
                ins(Op::Addi, 4, 0, 0, 99, 0),
                ins(Op::Blt, 0, 1, 2, 8, 0),
                ins(Op::Addi, 5, 0, 0, 99, 0),
                ins(Op::Bge, 0, 2, 1, 8, 0),
                ins(Op::Addi, 6, 0, 0, 99, 0),
                ins(Op::Bltu, 0, 1, 2, 8, 0),
                ins(Op::Addi, 7, 0, 0, 99, 0),
                ins(Op::Bgeu, 0, 2, 1, 8, 0),
                ins(Op::Addi, 8, 0, 0, 99, 0),
                ins(Op::Bne, 0, 1, 1, 8, 0),
                ins(Op::Addi, 9, 0, 0, 42, 0),
                ins(Op::Ecall, 0, 0, 0, 0, 0),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        let regs = &trace.final_state.regs;
        for (reg, value) in regs.iter().enumerate().take(9).skip(3) {
            assert_eq!(*value, 0, "x{reg} should be skipped");
        }
        assert_eq!(regs[9], 42);
    }

    #[test]
    fn executes_jal_and_jalr() {
        let jal_program = ProgramImage::new(
            0x1000,
            vec![
                ins(Op::Jal, 1, 0, 0, 8, 0),
                ins(Op::Addi, 2, 0, 0, 99, 0),
                ins(Op::Addi, 3, 0, 0, 7, 0),
                ins(Op::Ecall, 0, 0, 0, 0, 0),
            ],
        );
        let trace = execute(&jal_program, config()).unwrap();
        assert_eq!(trace.final_state.regs[1], 0x1004);
        assert_eq!(trace.final_state.regs[2], 0);
        assert_eq!(trace.final_state.regs[3], 7);

        let jalr_program = ProgramImage::new(
            0x1000,
            vec![
                ins(Op::Auipc, 4, 0, 0, 0, 0),
                ins(Op::Addi, 4, 4, 0, 16, 0),
                ins(Op::Jalr, 5, 4, 0, 0, 0),
                ins(Op::Addi, 6, 0, 0, 99, 0),
                ins(Op::Addi, 7, 0, 0, 7, 0),
                ins(Op::Ecall, 0, 0, 0, 0, 0),
            ],
        );
        let trace = execute(&jalr_program, config()).unwrap();
        assert_eq!(trace.final_state.regs[5], 0x100c);
        assert_eq!(trace.final_state.regs[6], 0);
        assert_eq!(trace.final_state.regs[7], 7);
    }

    #[test]
    fn keeps_x0_zero_and_reports_execution_errors() {
        let zero_program = ProgramImage::new(
            0x1000,
            vec![ins(Op::Addi, 0, 0, 0, 5, 0), ins(Op::Ecall, 0, 0, 0, 0, 0)],
        );
        let trace = execute(&zero_program, config()).unwrap();
        assert_eq!(trace.final_state.regs[0], 0);

        let misaligned = ProgramImage::new(
            0x1000,
            vec![
                ins(Op::Lui, 1, 0, 0, 0x1000_0000, 0),
                ins(Op::Ld, 2, 1, 0, 1, 0),
                ins(Op::Ecall, 0, 0, 0, 0, 0),
            ],
        );
        assert!(matches!(
            execute(&misaligned, config()),
            Err(ExecError::Misaligned { .. })
        ));

        let out_of_bounds = ProgramImage::new(
            0x1000,
            vec![
                ins(Op::Lui, 1, 0, 0, 0x2000_0000, 0),
                ins(Op::Ld, 2, 1, 0, 0, 0),
                ins(Op::Ecall, 0, 0, 0, 0, 0),
            ],
        );
        assert!(matches!(
            execute(&out_of_bounds, config()),
            Err(ExecError::MemoryOutOfBounds(_))
        ));

        let infinite = ProgramImage::new(0x1000, vec![ins(Op::Jal, 0, 0, 0, 0, 0)]);
        assert!(matches!(
            execute(&infinite, config()),
            Err(ExecError::CycleLimit(_))
        ));
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
                simple_ins(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, config()).expect("program should execute");
        assert_eq!(trace.final_state.reg(2), 0);
        assert_eq!(trace.final_state.reg(3), 42);
    }
}
