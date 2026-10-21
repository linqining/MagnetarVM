//! Guest ABI and syscall boundary.
//!
//! This is the stable contract between a guest program and the zkVM harness.
//! The P0 executor treats `ecall` as a halt; the syscall decoder below defines
//! the richer ABI that later runtimes can implement.

use magnetar_spec::{MachineConfig, Word};
use thiserror::Error;

pub const SYS_EXIT: Word = 93;
pub const SYS_READ: Word = 63;
pub const SYS_WRITE: Word = 64;
pub const SYS_HINT: Word = 1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestAbi {
    pub entry: Word,
    pub stack_top: Word,
    pub heap_start: Word,
    pub heap_size: usize,
    pub ram_base: Word,
    pub ram_size: usize,
}

impl Default for GuestAbi {
    fn default() -> Self {
        let config = MachineConfig::default();
        Self {
            entry: config.entry,
            stack_top: config.stack_top,
            heap_start: config.ram_base,
            heap_size: config.ram_size / 2,
            ram_base: config.ram_base,
            ram_size: config.ram_size,
        }
    }
}

impl GuestAbi {
    pub fn machine_config(&self) -> MachineConfig {
        MachineConfig {
            entry: self.entry,
            rom_base: self.entry,
            ram_base: self.ram_base,
            ram_size: self.ram_size,
            stack_top: self.stack_top,
            max_cycles: 1 << 22,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Syscall {
    Exit { code: Word },
    Read { fd: Word, ptr: Word, len: Word },
    Write { fd: Word, ptr: Word, len: Word },
    Hint { id: Word },
}

/// Decode a Linux-like RISC-V syscall convention.
///
/// `a0/a1/a2` are argument registers and `a7` carries the syscall number.
pub fn decode_syscall(a0: Word, a1: Word, a2: Word, a7: Word) -> Result<Syscall, GuestError> {
    match a7 {
        SYS_EXIT => Ok(Syscall::Exit { code: a0 }),
        SYS_READ => Ok(Syscall::Read {
            fd: a0,
            ptr: a1,
            len: a2,
        }),
        SYS_WRITE => Ok(Syscall::Write {
            fd: a0,
            ptr: a1,
            len: a2,
        }),
        SYS_HINT => Ok(Syscall::Hint { id: a0 }),
        other => Err(GuestError::UnknownSyscall(other)),
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GuestError {
    #[error("unknown syscall {0}")]
    UnknownSyscall(Word),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_exit_and_write() {
        assert_eq!(
            decode_syscall(7, 0, 0, SYS_EXIT),
            Ok(Syscall::Exit { code: 7 })
        );
        assert_eq!(
            decode_syscall(1, 0x1000, 32, SYS_WRITE),
            Ok(Syscall::Write {
                fd: 1,
                ptr: 0x1000,
                len: 32
            })
        );
    }

    #[test]
    fn rejects_unknown_syscall() {
        assert_eq!(
            decode_syscall(0, 0, 0, 999),
            Err(GuestError::UnknownSyscall(999))
        );
    }
}
