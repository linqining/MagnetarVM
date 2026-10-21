//! Reference memory-consistency checks and Twist-style bookkeeping.
//!
//! The checks here replay the trace. They are the semantic oracle for the
//! BinaryTwist/BinaryShout arguments, not a replacement for them.

pub mod mmu;

use magnetar_constraint::F2_128;
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

/// Address width used by the one-hot memory representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressLayout {
    pub bits: usize,
}

impl AddressLayout {
    pub fn new(bits: usize) -> Result<Self, MemoryError> {
        if bits == 0 || bits > 64 {
            return Err(MemoryError::InvalidAddressBits(bits));
        }
        Ok(Self { bits })
    }

    pub fn one_hot(&self, address: Addr) -> Result<Vec<F2_128>, MemoryError> {
        if self.bits < 64 && address >= (1u64 << self.bits) {
            return Err(MemoryError::AddressOutOfRange {
                address,
                bits: self.bits,
            });
        }
        let mut bits = vec![F2_128::from(0u64); self.bits];
        for (index, bit) in bits.iter_mut().enumerate() {
            if (address >> index) & 1 == 1 {
                *bit = F2_128::from(1u64);
            }
        }
        Ok(bits)
    }
}

/// Per-access witness for the BinaryTwist/BinaryShout reductions.
#[derive(Clone, Debug)]
pub struct TwistEventWitness {
    pub cycle: u64,
    pub address: Vec<F2_128>,
    pub old_value: F2_128,
    pub new_value: F2_128,
    pub increment: F2_128,
    pub is_write: bool,
}

#[derive(Clone, Debug, Default)]
pub struct TwistWitness {
    pub address_bits: usize,
    pub events: Vec<TwistEventWitness>,
}

impl TwistWitness {
    /// Build one-hot addresses and write increments by replaying the trace.
    pub fn from_trace(trace: &Trace, address_bits: usize) -> Result<Self, MemoryError> {
        let layout = AddressLayout::new(address_bits)?;
        let mut ram = trace.initial_ram.clone();
        let mut events = Vec::with_capacity(trace.memory_events.len());

        for event in &trace.memory_events {
            check_event(trace, &ram, event)?;
            let access = event.access;
            let width = usize::from(access.width);
            let index =
                trace
                    .config
                    .ram_index(access.addr, width)
                    .ok_or(MemoryError::OutOfBounds {
                        cycle: event.cycle,
                        addr: access.addr,
                        width,
                    })?;
            let old_value = read_value(&ram[index..index + width], width);
            let new_value = if access.is_write {
                access.value
            } else {
                old_value
            };
            let increment = if access.is_write {
                old_value ^ new_value
            } else {
                0
            };
            events.push(TwistEventWitness {
                cycle: event.cycle,
                address: layout.one_hot(access.addr)?,
                old_value: F2_128::from(old_value),
                new_value: F2_128::from(new_value),
                increment: F2_128::from(increment),
                is_write: access.is_write,
            });
            if access.is_write {
                write_ram(trace, &mut ram, *event)?;
            }
        }

        Ok(Self {
            address_bits,
            events,
        })
    }

    pub fn validate(&self) -> Result<(), MemoryError> {
        for event in &self.events {
            let ones = event.address.iter().filter(|bit| bit.value() == 1).count();
            if ones != 1 || event.address.iter().any(|bit| bit.value() > 1) {
                return Err(MemoryError::NotOneHot { cycle: event.cycle });
            }
            if event.old_value + event.new_value != event.increment {
                return Err(MemoryError::IncrementMismatch { cycle: event.cycle });
            }
            if !event.is_write && event.old_value != event.new_value {
                return Err(MemoryError::ReadValueMismatch { cycle: event.cycle });
            }
        }
        Ok(())
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
    #[error("address width {0} must be in 1..=64")]
    InvalidAddressBits(usize),
    #[error("address {address:#x} does not fit in {bits} bits")]
    AddressOutOfRange { address: Addr, bits: usize },
    #[error("cycle {cycle} address is not one-hot")]
    NotOneHot { cycle: u64 },
    #[error("cycle {cycle} increment is not old XOR new")]
    IncrementMismatch { cycle: u64 },
    #[error("cycle {cycle} read changed the value")]
    ReadValueMismatch { cycle: u64 },
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

    #[test]
    fn twist_witness_has_one_hot_addresses_and_increments() {
        let trace = execute(&program(), config()).unwrap();
        let witness = TwistWitness::from_trace(&trace, 32).unwrap();
        witness.validate().unwrap();
        assert_eq!(witness.events.len(), 2);
        let write = &witness.events[0];
        assert!(write.is_write);
        assert_eq!(write.old_value, F2_128::from(0u64));
        assert_eq!(write.new_value, F2_128::from(9u64));
        assert_eq!(write.increment, F2_128::from(9u64));
        let read = &witness.events[1];
        assert!(!read.is_write);
        assert_eq!(read.old_value, F2_128::from(9u64));
        assert_eq!(read.increment, F2_128::from(0u64));
    }

    #[test]
    fn twist_witness_rejects_non_one_hot_addresses() {
        let trace = execute(&program(), config()).unwrap();
        let mut witness = TwistWitness::from_trace(&trace, 32).unwrap();
        for bit in &mut witness.events[0].address {
            *bit = F2_128::from(0u64);
        }
        assert!(matches!(
            witness.validate(),
            Err(MemoryError::NotOneHot { .. })
        ));
    }

    #[test]
    fn twist_witness_rejects_bad_increment() {
        let trace = execute(&program(), config()).unwrap();
        let mut witness = TwistWitness::from_trace(&trace, 32).unwrap();
        witness.events[0].increment = F2_128::from(0u64);
        assert!(matches!(
            witness.validate(),
            Err(MemoryError::IncrementMismatch { .. })
        ));
    }

    #[test]
    fn address_layout_checks_range() {
        let layout = AddressLayout::new(8).unwrap();
        assert!(layout.one_hot(255).is_ok());
        assert!(matches!(
            layout.one_hot(256),
            Err(MemoryError::AddressOutOfRange { .. })
        ));
        assert!(matches!(
            AddressLayout::new(0),
            Err(MemoryError::InvalidAddressBits(0))
        ));
    }
}
