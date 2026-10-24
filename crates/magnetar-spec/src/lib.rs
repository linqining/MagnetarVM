//! Machine-level specification for MagnetarVM.
//!
//! This crate is deliberately proof-system agnostic: it defines the RV64I
//! base plus RV64M instruction semantics, machine state, and trace schema that
//! every other module consumes.

pub mod arith;
pub mod compressed;
pub mod floating;
pub mod instruction;
pub mod machine;
pub mod program;
pub mod syscall;
pub mod trace;

pub use arith::{addw, div, divu, mulh, mulhsu, mulhu, rem, remu, sllw, sraw, srlw, subw};
pub use compressed::{decode_compressed, CompressedError};
pub use floating::{decode_fp, FpDecodeError, FpFormat, FpInstruction, FpOp};
pub use instruction::{decode, DecodeError, Instruction, Op};
pub use machine::{Addr, MachineConfig, MachineState, RegIdx, Word, NUM_REGS, XLEN};
pub use program::ProgramImage;
pub use trace::{MemoryAccess, MemoryEvent, MicroOpKind, SyscallTrace, Trace, TraceRow};
