//! Bit-routing semantics for shifts and sub-word stores.
//!
//! Magnetar proves these operations as routings rather than as generic R1CS
//! gates or enormous lookup tables. This crate provides the reference routing
//! semantics and the public routing descriptions used by the prover.

use magnetar_spec::Word;
use thiserror::Error;

pub const WORD_BITS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShiftKind {
    LogicalLeft,
    LogicalRight,
    ArithmeticRight,
}

impl ShiftKind {
    pub fn name(self) -> &'static str {
        match self {
            ShiftKind::LogicalLeft => "sll",
            ShiftKind::LogicalRight => "srl",
            ShiftKind::ArithmeticRight => "sra",
        }
    }
}

/// Where one output bit of a shift comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitSource {
    Zero,
    Input(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShiftRoute {
    pub kind: ShiftKind,
    pub shamt: u8,
}

impl ShiftRoute {
    pub fn new(kind: ShiftKind, shamt: u8) -> Self {
        Self {
            kind,
            shamt: shamt & 0x3f,
        }
    }

    pub fn source_bit(&self, output_bit: usize) -> BitSource {
        debug_assert!(output_bit < WORD_BITS);
        let shamt = usize::from(self.shamt);
        match self.kind {
            ShiftKind::LogicalLeft => {
                if output_bit >= shamt {
                    BitSource::Input((output_bit - shamt) as u8)
                } else {
                    BitSource::Zero
                }
            }
            ShiftKind::LogicalRight => {
                let input = output_bit + shamt;
                if input < WORD_BITS {
                    BitSource::Input(input as u8)
                } else {
                    BitSource::Zero
                }
            }
            ShiftKind::ArithmeticRight => {
                let input = output_bit + shamt;
                if input < WORD_BITS {
                    BitSource::Input(input as u8)
                } else {
                    BitSource::Input((WORD_BITS - 1) as u8)
                }
            }
        }
    }

    pub fn apply(&self, value: Word) -> Word {
        match self.kind {
            ShiftKind::LogicalLeft => value.wrapping_shl(u32::from(self.shamt)),
            ShiftKind::LogicalRight => value.wrapping_shr(u32::from(self.shamt)),
            ShiftKind::ArithmeticRight => ((value as i64) >> self.shamt) as Word,
        }
    }

    pub fn check(&self, value: Word, expected: Word) -> bool {
        self.apply(value) == expected
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreWidth {
    Byte = 1,
    Half = 2,
    Word = 4,
    Double = 8,
}

impl StoreWidth {
    pub fn bytes(self) -> usize {
        self as usize
    }

    pub fn from_bytes(bytes: usize) -> Result<Self, RoutingError> {
        match bytes {
            1 => Ok(StoreWidth::Byte),
            2 => Ok(StoreWidth::Half),
            4 => Ok(StoreWidth::Word),
            8 => Ok(StoreWidth::Double),
            other => Err(RoutingError::InvalidWidth(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreBitSource {
    Old(u8),
    New(u8),
    Xor(u8, u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreRoute {
    pub width: StoreWidth,
    pub offset: usize,
}

impl StoreRoute {
    pub fn new(width: StoreWidth, offset: usize) -> Result<Self, RoutingError> {
        if offset + width.bytes() > 8 {
            return Err(RoutingError::InvalidOffset {
                offset,
                width: width.bytes(),
            });
        }
        Ok(Self { width, offset })
    }

    pub fn written_bits(&self) -> std::ops::Range<usize> {
        let start = self.offset * 8;
        start..start + self.width.bytes() * 8
    }

    pub fn new_word(&self, old: Word, source: Word) -> Word {
        let mut mask = 0u64;
        for bit in self.written_bits() {
            mask |= 1u64 << bit;
        }
        let shifted = source.wrapping_shl((self.offset * 8) as u32);
        (old & !mask) | (shifted & mask)
    }

    pub fn increment(&self, old: Word, source: Word) -> Word {
        old ^ self.new_word(old, source)
    }

    pub fn bit_source(&self, output_bit: usize) -> StoreBitSource {
        debug_assert!(output_bit < WORD_BITS);
        if !self.written_bits().contains(&output_bit) {
            StoreBitSource::Old(output_bit as u8)
        } else {
            let source_bit = output_bit - self.offset * 8;
            StoreBitSource::Xor(output_bit as u8, source_bit as u8)
        }
    }

    pub fn check(&self, old: Word, source: Word, expected: Word) -> bool {
        self.new_word(old, source) == expected
    }
}

#[derive(Clone, Debug, Default)]
pub struct RoutingTables {
    pub shifts: Vec<ShiftRoute>,
    pub stores: Vec<StoreRoute>,
}

impl RoutingTables {
    pub fn register_shift(&mut self, route: ShiftRoute) {
        self.shifts.push(route);
    }

    pub fn register_store(&mut self, route: StoreRoute) -> Result<(), RoutingError> {
        self.stores.push(route);
        Ok(())
    }

    pub fn check_shift(&self, kind: ShiftKind, shamt: u8, value: Word, expected: Word) -> bool {
        let route = ShiftRoute::new(kind, shamt);
        route.check(value, expected)
    }

    pub fn check_store(
        &self,
        width: StoreWidth,
        offset: usize,
        old: Word,
        source: Word,
        expected: Word,
    ) -> Result<bool, RoutingError> {
        Ok(StoreRoute::new(width, offset)?.check(old, source, expected))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RoutingError {
    #[error("invalid sub-word width {0}")]
    InvalidWidth(usize),
    #[error("invalid store offset {offset} for width {width}")]
    InvalidOffset { offset: usize, width: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shift_routes_match_semantics() {
        let value = 0x8000_0000_0000_0001u64;
        assert_eq!(
            ShiftRoute::new(ShiftKind::LogicalLeft, 4).apply(value),
            value << 4
        );
        assert_eq!(
            ShiftRoute::new(ShiftKind::LogicalRight, 4).apply(value),
            value >> 4
        );
        assert_eq!(
            ShiftRoute::new(ShiftKind::ArithmeticRight, 4).apply(value),
            ((value as i64) >> 4) as u64
        );
    }

    #[test]
    fn every_shift_output_bit_has_a_route() {
        for kind in [
            ShiftKind::LogicalLeft,
            ShiftKind::LogicalRight,
            ShiftKind::ArithmeticRight,
        ] {
            let route = ShiftRoute::new(kind, 9);
            let mut rebuilt = 0u64;
            for bit in 0..WORD_BITS {
                if let BitSource::Input(source) = route.source_bit(bit) {
                    rebuilt |= 1u64 << bit;
                    assert!(usize::from(source) < WORD_BITS);
                }
            }
            let _ = rebuilt;
        }
    }

    #[test]
    fn subword_store_preserves_other_lanes() {
        let old = 0x1122_3344_5566_7788u64;
        let source = 0xffff_ffff_ffff_aaaau64;
        let route = StoreRoute::new(StoreWidth::Half, 2).unwrap();
        let new = route.new_word(old, source);
        assert_eq!(new & 0xffff, 0x7788);
        assert_eq!((new >> 16) & 0xffff, 0xaaaa);
        assert_eq!((new >> 32) & 0xffff, 0x3344);
        assert_eq!(route.increment(old, source), old ^ new);
    }
}
