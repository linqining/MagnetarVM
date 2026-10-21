use crate::{Addr, Word};

/// A loaded program image.
///
/// `rom` is indexed by instruction slot; `data` is copied into RAM at
/// `config.ram_base` before execution.
#[derive(Clone, Debug)]
pub struct ProgramImage {
    pub entry: Word,
    pub rom: Vec<u32>,
    pub data: Vec<u8>,
}

impl ProgramImage {
    pub fn new(entry: Addr, rom: Vec<u32>) -> Self {
        Self {
            entry,
            rom,
            data: Vec::new(),
        }
    }

    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    pub fn len(&self) -> usize {
        self.rom.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rom.is_empty()
    }
}
