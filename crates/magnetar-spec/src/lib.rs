//! Machine-level specification for MagnetarVM.
//!
//! This crate is deliberately proof-system agnostic: it defines the RV64I
//! instruction semantics, machine state, and trace schema that every other
//! module consumes. The current implementation covers the RV64I base ISA.

pub mod instruction;
pub mod machine;
pub mod program;
pub mod trace;

pub use instruction::{decode, DecodeError, Instruction, Op};
pub use machine::{Addr, MachineConfig, MachineState, RegIdx, Word, NUM_REGS, XLEN};
pub use program::ProgramImage;
pub use trace::{MemoryAccess, MemoryEvent, Trace, TraceRow};
