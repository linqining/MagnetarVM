use crate::{Addr, Instruction, MachineConfig, MachineState, RegIdx, Word};

/// A single memory access performed by one instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MemoryAccess {
    pub addr: Addr,
    pub value: Word,
    pub width: u8,
    pub is_write: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MemoryEvent {
    pub cycle: u64,
    pub access: MemoryAccess,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SyscallTrace {
    pub number: u64,
    pub args: [u64; 3],
}

/// Scheduled micro-op kind. The current executor emits one `Execute` row per
/// instruction; `Fetch` is reserved for C1 instruction expansion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MicroOpKind {
    Fetch,
    Execute,
}

/// One executed instruction, including the operands the CPU relation needs.
///
/// This is the reference trace shape. A production prover will columnarize it
/// into the witness layout, but keeping a row-oriented reference trace makes
/// the semantics independently testable.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TraceRow {
    pub cycle: u64,
    pub pc: Word,
    /// Bytecode/Shout row key for this micro-op.
    pub micro_pc: Word,
    pub micro_op: MicroOpKind,
    pub next_pc: Word,
    pub instruction_word: u32,
    pub instruction_len: u8,
    pub instruction: Instruction,
    pub rs1: Option<RegIdx>,
    pub rs2: Option<RegIdx>,
    pub rd: Option<RegIdx>,
    pub rs1_val: Word,
    pub rs2_val: Word,
    pub rd_val: Word,
    pub mem: Option<MemoryAccess>,
    /// Additional memory writes performed by a syscall in this row.
    pub extra_mem: Vec<MemoryAccess>,
    pub reservation_before: Option<Addr>,
    pub reservation_after: Option<Addr>,
    pub syscall: Option<SyscallTrace>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Trace {
    pub config: MachineConfig,
    pub rom: Vec<u32>,
    pub initial_state: MachineState,
    pub final_state: MachineState,
    pub rows: Vec<TraceRow>,
    pub memory_events: Vec<MemoryEvent>,
    pub initial_ram: Vec<u8>,
    pub halted: bool,
    pub exit_code: Option<Word>,
    /// Bytes emitted by write syscalls during execution.
    pub io_output: Vec<u8>,
    /// Bytes consumed by read syscalls during execution.
    pub io_input: Vec<u8>,
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
