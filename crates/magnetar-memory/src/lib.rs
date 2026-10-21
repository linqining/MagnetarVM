//! Reference memory-consistency checks and Twist-style bookkeeping.
//!
//! The checks here replay the trace. They are the semantic oracle for the
//! BinaryTwist/BinaryShout arguments, not a replacement for them.

use magnetar_spec::{Addr, MemoryEvent, Trace, Word};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct MemoryReport {
    pub final_ram: Vec<u8>,
    pub register_writes: usize,
    pub memory_reads: usize,
    pub memory_writes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TwistEvent {
    pub cycle: u64,
    pub address: Addr,
    pub value: Word,
    pub width: u8,
    pub is_write: bool,
}

#[derive(Clone, Debug, Default)]
pub struct TwistLog {
    pub events: Vec<TwistEvent>,
}

impl TwistLog {
    pub fn from_trace(trace: &Trace) -> Self {
        let events = trace
            .memory_events
            .iter()
            .map(|event| TwistEvent {
                cycle: event.cycle,
                address: event.access.addr,
                value: event.access.value,
                width: event.access.width,
                is_write: event.access.is_write,
            })
            .collect();
        Self { events }
    }

    pub fn reads(&self) -> impl Iterator<Item = &TwistEvent> {
        self.events.iter().filter(|event| !event.is_write)
    }

    pub fn writes(&self) -> impl Iterator<Item = &TwistEvent> {
        self.events.iter().filter(|event| event.is_write)
    }
}

/// Check register reads/writes against the architectural register file.
pub fn check_register_file(trace: &Trace) -> Result<usize, MemoryError> {
    let mut shadow = trace.initial_state.regs;
    let mut writes = 0;
    for (row_index, row) in trace.rows.iter().enumerate() {
        if let Some(reg) = row.rs1 {
            let expected = shadow[reg];
            if row.rs1_val != expected {
                return Err(MemoryError::RegisterRead {
                    row: row_index,
                    reg,
                    expected,
                    actual: row.rs1_val,
                });
            }
        }
        if let Some(reg) = row.rs2 {
            let expected = shadow[reg];
            if row.rs2_val != expected {
                return Err(MemoryError::RegisterRead {
                    row: row_index,
                    reg,
                    expected,
                    actual: row.rs2_val,
                });
            }
        }
        if let Some(reg) = row.rd {
            if reg != 0 {
                shadow[reg] = row.rd_val;
                writes += 1;
            }
        }
    }
    for (reg, expected) in shadow.iter().enumerate() {
        if *expected != trace.final_state.regs[reg] {
            return Err(MemoryError::RegisterFinal {
                reg,
                expected: *expected,
                actual: trace.final_state.regs[reg],
            });
        }
    }
    Ok(writes)
}

/// Replay RAM accesses from the initial image and check every read.
pub fn check_ram(trace: &Trace) -> Result<Vec<u8>, MemoryError> {
    let mut ram = trace.initial_ram.clone();
    for event in &trace.memory_events {
        check_event(trace, &ram, event)?;
        if event.access.is_write {
            write_ram(trace, &mut ram, *event)?;
        }
    }
    Ok(ram)
}

pub fn check_memory(trace: &Trace) -> Result<MemoryReport, MemoryError> {
    let register_writes = check_register_file(trace)?;
    let final_ram = check_ram(trace)?;
    let memory_reads = trace.memory_reads().count();
    let memory_writes = trace.memory_writes().count();
    Ok(MemoryReport {
        final_ram,
        register_writes,
        memory_reads,
        memory_writes,
    })
}

fn check_event(trace: &Trace, ram: &[u8], event: &MemoryEvent) -> Result<(), MemoryError> {
    let access = event.access;
    let width = usize::from(access.width);
    if !access.addr.is_multiple_of(width as u64) {
        return Err(MemoryError::Misaligned {
            cycle: event.cycle,
            addr: access.addr,
            width,
        });
    }
    let index = trace
        .config
        .ram_index(access.addr, width)
        .ok_or(MemoryError::OutOfBounds {
            cycle: event.cycle,
            addr: access.addr,
            width,
        })?;
    if access.is_write {
        return Ok(());
    }
    let actual = read_value(&ram[index..index + width], width);
    if actual != access.value {
        return Err(MemoryError::RamMismatch {
            cycle: event.cycle,
            addr: access.addr,
            expected: access.value,
            actual,
        });
    }
    Ok(())
}

fn write_ram(trace: &Trace, ram: &mut [u8], event: MemoryEvent) -> Result<(), MemoryError> {
    let access = event.access;
    let width = usize::from(access.width);
    let index = trace
        .config
        .ram_index(access.addr, width)
        .ok_or(MemoryError::OutOfBounds {
            cycle: event.cycle,
            addr: access.addr,
            width,
        })?;
    let bytes = access.value.to_le_bytes();
    ram[index..index + width].copy_from_slice(&bytes[..width]);
    Ok(())
}

fn read_value(bytes: &[u8], width: usize) -> Word {
    let mut buffer = [0u8; 8];
    buffer[..width].copy_from_slice(&bytes[..width]);
    u64::from_le_bytes(buffer)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MemoryError {
    #[error("row {row}: register x{reg} read {actual:#x}, expected {expected:#x}")]
    RegisterRead {
        row: usize,
        reg: usize,
        expected: Word,
        actual: Word,
    },
    #[error("final register x{reg} is {actual:#x}, expected {expected:#x}")]
    RegisterFinal {
        reg: usize,
        expected: Word,
        actual: Word,
    },
    #[error("memory access at cycle {cycle} out of bounds: addr={addr:#x}, width={width}")]
    OutOfBounds {
        cycle: u64,
        addr: Addr,
        width: usize,
    },
    #[error("misaligned memory access at cycle {cycle}: addr={addr:#x}, width={width}")]
    Misaligned {
        cycle: u64,
        addr: Addr,
        width: usize,
    },
    #[error(
        "memory read at cycle {cycle} addr={addr:#x} returned {actual:#x}, expected {expected:#x}"
    )]
    RamMismatch {
        cycle: u64,
        addr: Addr,
        expected: Word,
        actual: Word,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

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

    fn program() -> ProgramImage {
        ProgramImage::new(
            0x1000,
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
                    rs2: 1,
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
                Instruction::new(Op::Ecall).encode(),
            ],
        )
    }

    #[test]
    fn replay_matches_trace() {
        let trace = execute(&program(), config()).unwrap();
        let report = check_memory(&trace).unwrap();
        assert_eq!(trace.final_state.reg(5), 9);
        assert_eq!(report.memory_reads, 1);
        assert_eq!(report.memory_writes, 1);
        assert_eq!(report.register_writes, 3);
        assert_eq!(&report.final_ram[0..8], &9u64.to_le_bytes());
    }

    #[test]
    fn corrupt_register_read_is_detected() {
        let mut trace = execute(&program(), config()).unwrap();
        trace.rows[2].rs1_val = 0;
        assert!(matches!(
            check_register_file(&trace),
            Err(MemoryError::RegisterRead { .. })
        ));
    }

    #[test]
    fn twist_log_separates_reads_and_writes() {
        let trace = execute(&program(), config()).unwrap();
        let log = TwistLog::from_trace(&trace);
        assert_eq!(log.reads().count(), 1);
        assert_eq!(log.writes().count(), 1);
    }
}
