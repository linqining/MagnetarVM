use crate::{Addr, Word};

/// A loaded program image.
///
/// `rom` is indexed by instruction slot; `data` is copied into RAM at
/// `config.ram_base` before execution.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_image_tracks_length_and_data() {
        let image = ProgramImage::new(0x1000, vec![1, 2, 3]);
        assert_eq!(image.len(), 3);
        assert!(!image.is_empty());
        assert!(image.data.is_empty());

        let image = image.with_data(vec![7, 8]);
        assert_eq!(image.data, vec![7, 8]);
        assert!(ProgramImage::new(0x1000, Vec::new()).is_empty());
    }
}
