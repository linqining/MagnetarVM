use crate::{Addr, Instruction, MachineConfig, MachineState, RegIdx, Word};

/// A single memory access performed by one instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryAccess {
    pub addr: Addr,
    pub value: Word,
    pub width: u8,
    pub is_write: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryEvent {
    pub cycle: u64,
    pub access: MemoryAccess,
}

/// One executed instruction, including the operands the CPU relation needs.
///
/// This is the reference trace shape. A production prover will columnarize it
/// into the witness layout, but keeping a row-oriented reference trace makes
/// the semantics independently testable.
#[derive(Clone, Debug)]
pub struct TraceRow {
    pub cycle: u64,
    pub pc: Word,
    pub next_pc: Word,
    pub instruction_word: u32,
    pub instruction: Instruction,
    pub rs1: Option<RegIdx>,
    pub rs2: Option<RegIdx>,
    pub rd: Option<RegIdx>,
    pub rs1_val: Word,
    pub rs2_val: Word,
    pub rd_val: Word,
    pub mem: Option<MemoryAccess>,
}

#[derive(Clone, Debug)]
pub struct Trace {
    pub config: MachineConfig,
    pub initial_state: MachineState,
    pub final_state: MachineState,
    pub rows: Vec<TraceRow>,
    pub memory_events: Vec<MemoryEvent>,
    pub initial_ram: Vec<u8>,
    pub halted: bool,
    pub exit_code: Option<Word>,
}

impl Trace {
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn row(&self, index: usize) -> Option<&TraceRow> {
        self.rows.get(index)
    }

    pub fn memory_reads(&self) -> impl Iterator<Item = &MemoryEvent> {
        self.memory_events
            .iter()
            .filter(|event| !event.access.is_write)
    }

    pub fn memory_writes(&self) -> impl Iterator<Item = &MemoryEvent> {
        self.memory_events
            .iter()
            .filter(|event| event.access.is_write)
    }
}
