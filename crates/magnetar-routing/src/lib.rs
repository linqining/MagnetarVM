//! Bit-routing semantics for shifts and sub-word stores.
//!
//! Magnetar proves these operations as routings rather than as generic R1CS
//! gates or enormous lookup tables. This crate provides the reference routing
//! semantics and the public routing descriptions used by the prover.

use magnetar_constraint::F2_128;
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

#[derive(Clone, Debug)]
pub struct ShiftWitness {
    pub route: ShiftRoute,
    pub input: Vec<F2_128>,
    pub output: Vec<F2_128>,
}

impl ShiftWitness {
    pub fn from_value(route: ShiftRoute, value: Word) -> Self {
        let input = to_bits(value);
        let output = (0..WORD_BITS)
            .map(|bit| match route.source_bit(bit) {
                BitSource::Zero => F2_128::from(0u64),
                BitSource::Input(source) => input[usize::from(source)],
            })
            .collect();
        Self {
            route,
            input,
            output,
        }
    }

    pub fn validate(&self) -> bool {
        if self.input.len() != WORD_BITS || self.output.len() != WORD_BITS {
            return false;
        }
        if !all_bits(&self.input) || !all_bits(&self.output) {
            return false;
        }
        self.output.iter().enumerate().all(|(bit, output)| {
            let expected = match self.route.source_bit(bit) {
                BitSource::Zero => F2_128::from(0u64),
                BitSource::Input(source) => self.input[usize::from(source)],
            };
            *output == expected
        })
    }
}

#[derive(Clone, Debug)]
pub struct StoreWitness {
    pub route: StoreRoute,
    pub old: Vec<F2_128>,
    pub source: Vec<F2_128>,
    pub output: Vec<F2_128>,
    pub increment: Vec<F2_128>,
}

impl StoreWitness {
    pub fn from_values(route: StoreRoute, old: Word, source: Word) -> Self {
        let old_bits = to_bits(old);
        let source_bits = to_bits(source);
        let new_word = route.new_word(old, source);
        let increment = route.increment(old, source);
        Self {
            route,
            old: old_bits,
            source: source_bits,
            output: to_bits(new_word),
            increment: to_bits(increment),
        }
    }

    pub fn validate(&self) -> bool {
        if self.old.len() != WORD_BITS
            || self.source.len() != WORD_BITS
            || self.output.len() != WORD_BITS
            || self.increment.len() != WORD_BITS
        {
            return false;
        }
        if !all_bits(&self.old)
            || !all_bits(&self.source)
            || !all_bits(&self.output)
            || !all_bits(&self.increment)
        {
            return false;
        }
        for bit in 0..WORD_BITS {
            let in_store = self.route.written_bits().contains(&bit);
            let (expected_output, expected_increment) = if in_store {
                let source_bit = bit - self.route.offset * 8;
                (
                    self.source[source_bit],
                    self.old[bit] + self.source[source_bit],
                )
            } else {
                (self.old[bit], F2_128::from(0u64))
            };
            if self.output[bit] != expected_output || self.increment[bit] != expected_increment {
                return false;
            }
        }
        true
    }
}

pub fn to_bits(value: Word) -> Vec<F2_128> {
    (0..WORD_BITS)
        .map(|bit| F2_128::from((value >> bit) & 1))
        .collect()
}

pub fn from_bits(bits: &[F2_128]) -> Word {
    debug_assert_eq!(bits.len(), WORD_BITS);
    bits.iter().enumerate().fold(0u64, |value, (index, bit)| {
        value | ((bit.value() as u64 & 1) << index)
    })
}

fn all_bits(bits: &[F2_128]) -> bool {
    bits.iter().all(|bit| bit.value() <= 1)
}

#[derive(Clone, Debug, Default)]
pub struct RoutingTables {
    pub shifts: Vec<ShiftRoute>,
    pub stores: Vec<StoreRoute>,
}

impl RoutingTables {
    pub fn register_shift(&mut self, route: ShiftRoute) {
        if !self.shifts.contains(&route) {
            self.shifts.push(route);
        }
    }

    pub fn register_store(&mut self, route: StoreRoute) -> Result<(), RoutingError> {
        if !self.stores.contains(&route) {
            self.stores.push(route);
        }
        Ok(())
    }

    pub fn check_shift(&self, kind: ShiftKind, shamt: u8, value: Word, expected: Word) -> bool {
        let route = ShiftRoute::new(kind, shamt);
        self.shifts.contains(&route) && route.check(value, expected)
    }

    pub fn check_store(
        &self,
        width: StoreWidth,
        offset: usize,
        old: Word,
        source: Word,
        expected: Word,
    ) -> Result<bool, RoutingError> {
        let route = StoreRoute::new(width, offset)?;
        Ok(self.stores.contains(&route) && route.check(old, source, expected))
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
    use proptest::prelude::*;

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

    #[test]
    fn shift_witness_matches_route() {
        let route = ShiftRoute::new(ShiftKind::ArithmeticRight, 7);
        let witness = ShiftWitness::from_value(route, 0x8000_0000_0000_0001);
        assert!(witness.validate());
        assert_eq!(
            from_bits(&witness.output),
            route.apply(0x8000_0000_0000_0001)
        );
    }

    #[test]
    fn store_witness_matches_increment() {
        let route = StoreRoute::new(StoreWidth::Word, 4).unwrap();
        let witness = StoreWitness::from_values(route, 0x1122_3344_5566_7788, 0xdead_beef);
        assert!(witness.validate());
        assert_eq!(
            from_bits(&witness.increment),
            route.increment(0x1122_3344_5566_7788, 0xdead_beef)
        );
    }

    #[test]
    fn routing_tables_require_registration() {
        let mut tables = RoutingTables::default();
        assert!(!tables.check_shift(ShiftKind::LogicalLeft, 4, 1, 16));

        tables.register_shift(ShiftRoute::new(ShiftKind::LogicalLeft, 4));
        tables.register_shift(ShiftRoute::new(ShiftKind::LogicalLeft, 4));
        assert_eq!(tables.shifts.len(), 1);
        assert!(tables.check_shift(ShiftKind::LogicalLeft, 4, 1, 16));
        assert!(!tables.check_shift(ShiftKind::LogicalLeft, 4, 1, 17));
        assert!(!tables.check_shift(ShiftKind::LogicalRight, 4, 1, 0));

        assert!(!tables
            .check_store(StoreWidth::Byte, 0, 0, 0xff, 0xff)
            .unwrap());
        tables
            .register_store(StoreRoute::new(StoreWidth::Byte, 0).unwrap())
            .unwrap();
        tables
            .register_store(StoreRoute::new(StoreWidth::Byte, 0).unwrap())
            .unwrap();
        assert_eq!(tables.stores.len(), 1);
        assert!(tables
            .check_store(StoreWidth::Byte, 0, 0, 0xff, 0xff)
            .unwrap());
        assert!(!tables
            .check_store(StoreWidth::Byte, 1, 0, 0xff, 0xff00)
            .unwrap());
        assert!(tables.check_store(StoreWidth::Word, 6, 0, 0, 0).is_err());
    }

    #[test]
    fn store_widths_and_offsets_are_validated() {
        assert_eq!(StoreWidth::from_bytes(1).unwrap(), StoreWidth::Byte);
        assert_eq!(StoreWidth::from_bytes(2).unwrap(), StoreWidth::Half);
        assert_eq!(StoreWidth::from_bytes(4).unwrap(), StoreWidth::Word);
        assert_eq!(StoreWidth::from_bytes(8).unwrap(), StoreWidth::Double);
        assert!(matches!(
            StoreWidth::from_bytes(3),
            Err(RoutingError::InvalidWidth(3))
        ));
        assert_eq!(StoreWidth::Double.bytes(), 8);

        for width in [
            StoreWidth::Byte,
            StoreWidth::Half,
            StoreWidth::Word,
            StoreWidth::Double,
        ] {
            for offset in 0..=8 {
                let expected = offset + width.bytes() <= 8;
                assert_eq!(
                    StoreRoute::new(width, offset).is_ok(),
                    expected,
                    "{width:?} at offset {offset}"
                );
            }
        }
        assert!(matches!(
            StoreRoute::new(StoreWidth::Word, 5),
            Err(RoutingError::InvalidOffset {
                offset: 5,
                width: 4
            })
        ));
    }

    #[test]
    fn witnesses_reject_tampering_and_non_boolean_bits() {
        let route = StoreRoute::new(StoreWidth::Half, 2).unwrap();
        let witness = StoreWitness::from_values(route, 0x1122_3344_5566_7788, 0xaaaa);
        assert!(witness.validate());

        let mut tampered = witness.clone();
        tampered.output[0] = tampered.output[0] + F2_128::from(1u64);
        assert!(!tampered.validate());

        let mut non_boolean = witness.clone();
        non_boolean.old[1] = F2_128::from(2u64);
        assert!(!non_boolean.validate());

        let mut truncated = witness.clone();
        truncated.increment.pop();
        assert!(!truncated.validate());

        let shift = ShiftWitness::from_value(ShiftRoute::new(ShiftKind::LogicalLeft, 3), 0x1234);
        assert!(shift.validate());
        let mut bad_shift = shift.clone();
        bad_shift.output[0] = F2_128::from(2u64);
        assert!(!bad_shift.validate());
        let mut bad_shift = shift;
        bad_shift.input.pop();
        assert!(!bad_shift.validate());
    }

    proptest::proptest! {
        #[test]
        fn shift_witnesses_always_validate(value: u64, kind in 0u8..3, shamt in 0u8..64) {
            let kind = match kind {
                0 => ShiftKind::LogicalLeft,
                1 => ShiftKind::LogicalRight,
                _ => ShiftKind::ArithmeticRight,
            };
            let witness = ShiftWitness::from_value(ShiftRoute::new(kind, shamt), value);
            prop_assert!(witness.validate());
        }

        #[test]
        fn store_witnesses_always_validate(old: u64, source: u64) {
            let route = StoreRoute::new(StoreWidth::Half, 2).unwrap();
            let witness = StoreWitness::from_values(route, old, source);
            prop_assert!(witness.validate());
        }
    }
}
