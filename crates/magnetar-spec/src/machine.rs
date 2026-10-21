pub type Word = u64;
pub type Addr = u64;
pub type RegIdx = usize;

pub const XLEN: usize = 64;
pub const NUM_REGS: usize = 32;

/// Harvard machine configuration.
///
/// ROM is public and read-only; RAM is private and mutable. Addresses are
/// translated linearly from the respective base.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineConfig {
    pub entry: Word,
    pub rom_base: Addr,
    pub ram_base: Addr,
    pub ram_size: usize,
    pub stack_top: Addr,
    pub max_cycles: u64,
}

impl Default for MachineConfig {
    fn default() -> Self {
        Self {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x8000_0000,
            ram_size: 1 << 20,
            stack_top: 0x8000_0000 + (1 << 20),
            max_cycles: 1 << 22,
        }
    }
}

impl MachineConfig {
    pub fn rom_index(&self, pc: Word) -> Option<usize> {
        let offset = pc.checked_sub(self.rom_base)?;
        if !offset.is_multiple_of(4) {
            return None;
        }
        usize::try_from(offset / 4).ok()
    }

    pub fn ram_index(&self, addr: Addr, width: usize) -> Option<usize> {
        let offset = addr.checked_sub(self.ram_base)?;
        let offset = usize::try_from(offset).ok()?;
        if offset.checked_add(width)? > self.ram_size {
            return None;
        }
        Some(offset)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineState {
    pub pc: Word,
    pub regs: [Word; NUM_REGS],
}

impl Default for MachineState {
    fn default() -> Self {
        Self {
            pc: 0,
            regs: [0; NUM_REGS],
        }
    }
}

impl MachineState {
    pub fn new(pc: Word) -> Self {
        Self {
            pc,
            regs: [0; NUM_REGS],
        }
    }

    pub fn reg(&self, index: RegIdx) -> Word {
        if index == 0 {
            0
        } else {
            self.regs[index]
        }
    }

    pub fn set_reg(&mut self, index: RegIdx, value: Word) {
        if index != 0 {
            self.regs[index] = value;
        }
    }
}
