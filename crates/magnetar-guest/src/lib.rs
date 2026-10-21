//! Guest ABI and syscall boundary.
//!
//! This is the stable contract between a guest program and the zkVM harness.
//! The P0 executor treats `ecall` as a halt; the syscall decoder below defines
//! the richer ABI that later runtimes can implement.

use goblin::elf::header::EM_RISCV;
use goblin::elf::program_header::PT_LOAD;
use goblin::elf::Elf;
use magnetar_spec::{MachineConfig, ProgramImage, Word};
use thiserror::Error;

pub use magnetar_spec::syscall::{SYS_EXIT, SYS_HINT, SYS_READ, SYS_WRITE};

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

#[derive(Clone, Debug)]
pub struct LoadedGuest {
    pub image: ProgramImage,
    pub config: MachineConfig,
}

/// Buffered guest I/O used by the reference syscall dispatcher.
#[derive(Clone, Debug, Default)]
pub struct GuestIo {
    pub input: Vec<u8>,
    pub output: Vec<u8>,
    read_cursor: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallOutcome {
    Exit(Word),
    Return(Word),
    Hint(Word),
}

/// Execute one decoded syscall against a guest RAM byte slice.
///
/// `memory[0]` is the byte at `config.ram_base`; the dispatcher does not perform
/// address translation beyond that offset.
pub fn handle_syscall(
    syscall: Syscall,
    memory: &mut [u8],
    io: &mut GuestIo,
) -> Result<SyscallOutcome, GuestError> {
    match syscall {
        Syscall::Exit { code } => Ok(SyscallOutcome::Exit(code)),
        Syscall::Write { fd, ptr, len } => {
            if fd != 1 && fd != 2 {
                return Err(GuestError::UnsupportedFd(fd));
            }
            let start = usize::try_from(ptr).map_err(|_| GuestError::BadPointer { ptr, len })?;
            let end = start
                .checked_add(usize::try_from(len).map_err(|_| GuestError::BadPointer { ptr, len })?)
                .ok_or(GuestError::BadPointer { ptr, len })?;
            let bytes = memory
                .get(start..end)
                .ok_or(GuestError::BadPointer { ptr, len })?;
            io.output.extend_from_slice(bytes);
            Ok(SyscallOutcome::Return(len))
        }
        Syscall::Read { fd, ptr, len } => {
            if fd != 0 {
                return Err(GuestError::UnsupportedFd(fd));
            }
            let available = io.input.len().saturating_sub(io.read_cursor);
            let count = usize::try_from(len).unwrap_or(usize::MAX).min(available);
            let start = usize::try_from(ptr).map_err(|_| GuestError::BadPointer { ptr, len })?;
            let end = start
                .checked_add(count)
                .ok_or(GuestError::BadPointer { ptr, len })?;
            let target = memory
                .get_mut(start..end)
                .ok_or(GuestError::BadPointer { ptr, len })?;
            target.copy_from_slice(&io.input[io.read_cursor..io.read_cursor + count]);
            io.read_cursor += count;
            Ok(SyscallOutcome::Return(count as Word))
        }
        Syscall::Hint { id } => Ok(SyscallOutcome::Hint(id)),
    }
}

/// Load a statically linked RV64 ELF into the Harvard machine image.
///
/// Segments below `ram_base` are treated as ROM; segments at or above
/// `ram_base` are copied into the initial RAM image. BSS bytes are zero-filled.
pub fn load_elf(bytes: &[u8], mut config: MachineConfig) -> Result<LoadedGuest, GuestError> {
    let elf = Elf::parse(bytes).map_err(|error| GuestError::ElfParse(error.to_string()))?;
    if !elf.is_64 {
        return Err(GuestError::Not64Bit);
    }
    if !elf.little_endian {
        return Err(GuestError::NotLittleEndian);
    }
    if elf.header.e_machine != EM_RISCV {
        return Err(GuestError::NotRiscv64 {
            machine: elf.header.e_machine,
        });
    }

    let mut rom_bytes = Vec::new();
    let mut ram_bytes = Vec::new();
    let mut load_segments = 0usize;

    for ph in &elf.program_headers {
        if ph.p_type != PT_LOAD {
            continue;
        }
        load_segments += 1;
        let vaddr = ph.p_vaddr;
        let filesz = usize::try_from(ph.p_filesz).map_err(|_| GuestError::SegmentOutOfBounds {
            vaddr,
            size: ph.p_filesz,
        })?;
        let memsz = usize::try_from(ph.p_memsz).map_err(|_| GuestError::SegmentOutOfBounds {
            vaddr,
            size: ph.p_memsz,
        })?;
        let offset = usize::try_from(ph.p_offset).map_err(|_| GuestError::SegmentOutOfBounds {
            vaddr,
            size: ph.p_offset,
        })?;
        let file_end = offset
            .checked_add(filesz)
            .ok_or(GuestError::SegmentOutOfBounds {
                vaddr,
                size: ph.p_filesz,
            })?;
        let source = bytes
            .get(offset..file_end)
            .ok_or(GuestError::SegmentOutOfBounds {
                vaddr,
                size: ph.p_filesz,
            })?;

        if vaddr >= config.ram_base {
            let start = usize::try_from(vaddr - config.ram_base).map_err(|_| {
                GuestError::SegmentOutOfBounds {
                    vaddr,
                    size: ph.p_memsz,
                }
            })?;
            let end = start
                .checked_add(memsz)
                .ok_or(GuestError::SegmentOutOfBounds {
                    vaddr,
                    size: ph.p_memsz,
                })?;
            if end > config.ram_size {
                return Err(GuestError::SegmentOutOfBounds {
                    vaddr,
                    size: ph.p_memsz,
                });
            }
            if ram_bytes.len() < end {
                ram_bytes.resize(end, 0);
            }
            ram_bytes[start..start + filesz].copy_from_slice(source);
        } else if vaddr >= config.rom_base {
            let rom_end = vaddr
                .checked_add(ph.p_memsz)
                .ok_or(GuestError::SegmentOutOfBounds {
                    vaddr,
                    size: ph.p_memsz,
                })?;
            if rom_end > config.ram_base {
                return Err(GuestError::SegmentOutsideRegions {
                    vaddr,
                    size: ph.p_memsz,
                });
            }
            let start = usize::try_from(vaddr - config.rom_base).map_err(|_| {
                GuestError::SegmentOutOfBounds {
                    vaddr,
                    size: ph.p_memsz,
                }
            })?;
            if start % 4 != 0 || filesz % 4 != 0 {
                return Err(GuestError::MisalignedRomSegment { vaddr });
            }
            let end = start
                .checked_add(memsz)
                .ok_or(GuestError::SegmentOutOfBounds {
                    vaddr,
                    size: ph.p_memsz,
                })?;
            if rom_bytes.len() < end {
                rom_bytes.resize(end, 0);
            }
            rom_bytes[start..start + filesz].copy_from_slice(source);
        } else {
            return Err(GuestError::SegmentOutsideRegions {
                vaddr,
                size: ph.p_memsz,
            });
        }
    }

    if load_segments == 0 {
        return Err(GuestError::NoLoadSegments);
    }

    rom_bytes.resize((rom_bytes.len() + 3) & !3, 0);
    let rom: Vec<u32> = rom_bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("four bytes")))
        .collect();

    let entry_offset = elf
        .entry
        .checked_sub(config.rom_base)
        .ok_or(GuestError::EntryOutsideRom(elf.entry))?;
    if entry_offset as usize >= rom_bytes.len() {
        return Err(GuestError::EntryOutsideRom(elf.entry));
    }
    config.entry = elf.entry;

    Ok(LoadedGuest {
        image: ProgramImage::new(elf.entry, rom).with_data(ram_bytes),
        config,
    })
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GuestError {
    #[error("unknown syscall {0}")]
    UnknownSyscall(Word),
    #[error("ELF parse failed: {0}")]
    ElfParse(String),
    #[error("ELF is not 64-bit")]
    Not64Bit,
    #[error("ELF is not little-endian")]
    NotLittleEndian,
    #[error("ELF machine {machine} is not RISC-V")]
    NotRiscv64 { machine: u16 },
    #[error("ELF has no PT_LOAD segments")]
    NoLoadSegments,
    #[error("entry point {0:#x} is outside ROM")]
    EntryOutsideRom(u64),
    #[error("segment vaddr={vaddr:#x} size={size} is outside ROM/RAM regions")]
    SegmentOutsideRegions { vaddr: u64, size: u64 },
    #[error("segment vaddr={vaddr:#x} size={size} is out of bounds")]
    SegmentOutOfBounds { vaddr: u64, size: u64 },
    #[error("ROM segment at {vaddr:#x} is not 4-byte aligned")]
    MisalignedRomSegment { vaddr: u64 },
    #[error("unsupported syscall file descriptor {0}")]
    UnsupportedFd(Word),
    #[error("guest pointer {ptr:#x} with length {len} is outside RAM")]
    BadPointer { ptr: Word, len: Word },
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, Op};

    fn write_u16(buffer: &mut [u8], offset: usize, value: u16) {
        buffer[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(buffer: &mut [u8], offset: usize, value: u32) {
        buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(buffer: &mut [u8], offset: usize, value: u64) {
        buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn build_elf(text: &[u32], data: &[u8], entry: u64, machine: u16) -> Vec<u8> {
        let text_bytes: Vec<u8> = text.iter().flat_map(|word| word.to_le_bytes()).collect();
        let data_offset = 0x2000;
        let phnum = if data.is_empty() { 1 } else { 2 };
        let mut buffer = vec![0u8; data_offset + data.len()];
        buffer[0..4].copy_from_slice(b"\x7fELF");
        buffer[4] = 2;
        buffer[5] = 1;
        buffer[6] = 1;
        write_u16(&mut buffer, 16, 2);
        write_u16(&mut buffer, 18, machine);
        write_u32(&mut buffer, 20, 1);
        write_u64(&mut buffer, 24, entry);
        write_u64(&mut buffer, 32, 64);
        write_u16(&mut buffer, 52, 64);
        write_u16(&mut buffer, 54, 56);
        write_u16(&mut buffer, 56, phnum);
        write_u16(&mut buffer, 58, 64);

        let text_ph = 64;
        write_u32(&mut buffer, text_ph, 1);
        write_u32(&mut buffer, text_ph + 4, 5);
        write_u64(&mut buffer, text_ph + 8, 0x1000);
        write_u64(&mut buffer, text_ph + 16, 0x1000);
        write_u64(&mut buffer, text_ph + 24, 0x1000);
        write_u64(&mut buffer, text_ph + 32, text_bytes.len() as u64);
        write_u64(&mut buffer, text_ph + 40, text_bytes.len() as u64);
        write_u64(&mut buffer, text_ph + 48, 0x1000);
        buffer[0x1000..0x1000 + text_bytes.len()].copy_from_slice(&text_bytes);

        if !data.is_empty() {
            let data_ph = 64 + 56;
            write_u32(&mut buffer, data_ph, 1);
            write_u32(&mut buffer, data_ph + 4, 6);
            write_u64(&mut buffer, data_ph + 8, data_offset as u64);
            write_u64(&mut buffer, data_ph + 16, 0x1000_0000);
            write_u64(&mut buffer, data_ph + 24, 0x1000_0000);
            write_u64(&mut buffer, data_ph + 32, data.len() as u64);
            write_u64(&mut buffer, data_ph + 40, data.len() as u64);
            write_u64(&mut buffer, data_ph + 48, 0x1000);
            buffer[data_offset..data_offset + data.len()].copy_from_slice(data);
        }
        buffer
    }

    fn test_program() -> Vec<u32> {
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
            Instruction::new(Op::Ecall).encode(),
        ]
    }

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

    #[test]
    fn loads_and_executes_a_rv64_elf() {
        let elf = build_elf(&test_program(), &[], 0x1000, EM_RISCV);
        let loaded = load_elf(&elf, config()).unwrap();
        assert_eq!(loaded.image.entry, 0x1000);
        assert_eq!(loaded.image.rom.len(), 3);
        let trace = execute(&loaded.image, loaded.config).unwrap();
        assert_eq!(trace.final_state.reg(2), 7);
    }

    #[test]
    fn loads_a_data_segment() {
        let data = b"hello\0\0\0";
        let elf = build_elf(&test_program(), data, 0x1000, EM_RISCV);
        let loaded = load_elf(&elf, config()).unwrap();
        assert_eq!(loaded.image.data, data);
    }

    #[test]
    fn rejects_non_riscv_elf() {
        let elf = build_elf(&test_program(), &[], 0x1000, 0);
        assert!(matches!(
            load_elf(&elf, config()),
            Err(GuestError::NotRiscv64 { machine: 0 })
        ));
    }

    #[test]
    fn rejects_elf_without_load_segments() {
        let mut elf = build_elf(&test_program(), &[], 0x1000, EM_RISCV);
        write_u16(&mut elf, 56, 0);
        assert!(matches!(
            load_elf(&elf, config()),
            Err(GuestError::NoLoadSegments)
        ));
    }

    #[test]
    fn rejects_entry_outside_rom() {
        let mut elf = build_elf(&test_program(), &[], 0x2000, EM_RISCV);
        write_u64(&mut elf, 24, 0x2000);
        assert!(matches!(
            load_elf(&elf, config()),
            Err(GuestError::EntryOutsideRom(0x2000))
        ));
    }

    #[test]
    fn rejects_malformed_elf() {
        assert!(matches!(
            load_elf(b"not an elf", config()),
            Err(GuestError::ElfParse(_))
        ));
    }

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

    #[test]
    fn decodes_read_and_hint_with_arguments() {
        assert_eq!(
            decode_syscall(0, 0x2000, 16, SYS_READ),
            Ok(Syscall::Read {
                fd: 0,
                ptr: 0x2000,
                len: 16
            })
        );
        assert_eq!(
            decode_syscall(42, 0, 0, SYS_HINT),
            Ok(Syscall::Hint { id: 42 })
        );
    }

    #[test]
    fn guest_abi_round_trips_to_machine_config() {
        let abi = GuestAbi {
            entry: 0x2000,
            stack_top: 0x3000,
            heap_start: 0x1000_0000,
            heap_size: 0x100,
            ram_base: 0x1000_0000,
            ram_size: 0x1000,
        };
        let config = abi.machine_config();
        assert_eq!(config.entry, 0x2000);
        assert_eq!(config.rom_base, 0x2000);
        assert_eq!(config.ram_base, 0x1000_0000);
        assert_eq!(config.ram_size, 0x1000);
        assert_eq!(config.stack_top, 0x3000);

        let default = GuestAbi::default();
        assert_eq!(default.heap_size, default.ram_size / 2);
    }

    fn build_big_endian_elf() -> Vec<u8> {
        fn write_u16_be(buffer: &mut [u8], offset: usize, value: u16) {
            buffer[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
        }
        fn write_u32_be(buffer: &mut [u8], offset: usize, value: u32) {
            buffer[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        fn write_u64_be(buffer: &mut [u8], offset: usize, value: u64) {
            buffer[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        let mut buffer = vec![0u8; 64 + 56];
        buffer[0..4].copy_from_slice(b"\x7fELF");
        buffer[4] = 2;
        buffer[5] = 2;
        buffer[6] = 1;
        write_u16_be(&mut buffer, 16, 2);
        write_u16_be(&mut buffer, 18, EM_RISCV);
        write_u32_be(&mut buffer, 20, 1);
        write_u64_be(&mut buffer, 24, 0x1000);
        write_u64_be(&mut buffer, 32, 64);
        write_u16_be(&mut buffer, 52, 64);
        write_u16_be(&mut buffer, 54, 56);
        write_u16_be(&mut buffer, 56, 1);
        write_u16_be(&mut buffer, 58, 64);
        write_u32_be(&mut buffer, 64, 1);
        write_u32_be(&mut buffer, 68, 5);
        write_u64_be(&mut buffer, 72, 0x1000);
        write_u64_be(&mut buffer, 80, 0x1000);
        write_u64_be(&mut buffer, 88, 0x1000);
        write_u64_be(&mut buffer, 112, 0x1000);
        buffer
    }

    #[test]
    fn rejects_non_64_bit_and_big_endian_elves() {
        let mut elf = build_elf(&test_program(), &[], 0x1000, EM_RISCV);
        elf[4] = 1;
        assert!(matches!(
            load_elf(&elf, config()),
            Err(GuestError::Not64Bit)
        ));

        let elf = build_big_endian_elf();
        assert!(matches!(
            load_elf(&elf, config()),
            Err(GuestError::NotLittleEndian)
        ));
    }

    #[test]
    fn rejects_out_of_region_and_misaligned_segments() {
        let mut elf = build_elf(&test_program(), &[], 0x1000, EM_RISCV);
        write_u64(&mut elf, 64 + 16, 0x800);
        assert!(matches!(
            load_elf(&elf, config()),
            Err(GuestError::SegmentOutsideRegions { vaddr: 0x800, .. })
        ));

        let mut elf = build_elf(&test_program(), &[], 0x1000, EM_RISCV);
        write_u64(&mut elf, 64 + 16, 0x1002);
        assert!(matches!(
            load_elf(&elf, config()),
            Err(GuestError::MisalignedRomSegment { vaddr: 0x1002 })
        ));
    }

    #[test]
    fn zero_fills_bss_bytes() {
        let data = b"abc";
        let mut elf = build_elf(&test_program(), data, 0x1000, EM_RISCV);
        let data_ph = 64 + 56;
        write_u64(&mut elf, data_ph + 40, 8);
        let loaded = load_elf(&elf, config()).unwrap();
        assert_eq!(loaded.image.data, b"abc\0\0\0\0\0");
    }

    #[test]
    fn syscall_dispatcher_handles_write_read_exit_and_hint() {
        let mut memory = vec![0u8; 16];
        let mut io = GuestIo::default();
        memory[0..5].copy_from_slice(b"hello");

        assert_eq!(
            handle_syscall(
                Syscall::Write {
                    fd: 1,
                    ptr: 0,
                    len: 5
                },
                &mut memory,
                &mut io
            )
            .unwrap(),
            SyscallOutcome::Return(5)
        );
        assert_eq!(io.output, b"hello");

        io.input = b"world".to_vec();
        assert_eq!(
            handle_syscall(
                Syscall::Read {
                    fd: 0,
                    ptr: 8,
                    len: 4
                },
                &mut memory,
                &mut io
            )
            .unwrap(),
            SyscallOutcome::Return(4)
        );
        assert_eq!(&memory[8..12], b"worl");
        assert_eq!(
            handle_syscall(
                Syscall::Read {
                    fd: 0,
                    ptr: 12,
                    len: 4
                },
                &mut memory,
                &mut io
            )
            .unwrap(),
            SyscallOutcome::Return(1)
        );
        assert_eq!(memory[12], b'd');
        assert_eq!(
            handle_syscall(
                Syscall::Read {
                    fd: 0,
                    ptr: 13,
                    len: 4
                },
                &mut memory,
                &mut io
            )
            .unwrap(),
            SyscallOutcome::Return(0)
        );

        assert_eq!(
            handle_syscall(Syscall::Exit { code: 7 }, &mut memory, &mut io).unwrap(),
            SyscallOutcome::Exit(7)
        );
        assert_eq!(
            handle_syscall(Syscall::Hint { id: 3 }, &mut memory, &mut io).unwrap(),
            SyscallOutcome::Hint(3)
        );
    }

    #[test]
    fn syscall_dispatcher_rejects_bad_pointers_and_fds() {
        let mut memory = vec![0u8; 8];
        let mut io = GuestIo::default();
        assert!(matches!(
            handle_syscall(
                Syscall::Write {
                    fd: 1,
                    ptr: 4,
                    len: 8
                },
                &mut memory,
                &mut io
            ),
            Err(GuestError::BadPointer { ptr: 4, len: 8 })
        ));
        assert!(matches!(
            handle_syscall(
                Syscall::Write {
                    fd: 9,
                    ptr: 0,
                    len: 1
                },
                &mut memory,
                &mut io
            ),
            Err(GuestError::UnsupportedFd(9))
        ));
        assert!(matches!(
            handle_syscall(
                Syscall::Read {
                    fd: 1,
                    ptr: 0,
                    len: 1
                },
                &mut memory,
                &mut io
            ),
            Err(GuestError::UnsupportedFd(1))
        ));
    }
}
