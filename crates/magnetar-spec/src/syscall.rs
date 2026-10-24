//! Linux-like RISC-V syscall numbers shared by the guest ABI and executor.

pub const SYS_EXIT: u64 = 93;
pub const SYS_READ: u64 = 63;
pub const SYS_WRITE: u64 = 64;
pub const SYS_HINT: u64 = 1000;
pub const SYS_CLOCK: u64 = 1001;
