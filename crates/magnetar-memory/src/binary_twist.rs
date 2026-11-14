//! Event-level BinaryTwist relation for RAM.
//!
//! This is the d=1, word-addressed reference relation from Magnetar §4.4:
//! one-hot read/write addresses, committed write increments, and the word
//! history reconstructed by `Val(k,j+1) = Val(k,j) + wa(k,j)·Inc(j)`.
//! The sum-check and PCS layers consume these tables; this module fixes their
//! semantics and provides the witness validator.

use magnetar_constraint::F2_128;
use magnetar_spec::{Trace, Word};

use crate::MemoryError;

#[derive(Clone, Debug)]
pub struct BinaryTwistWitness {
    pub address_bits: usize,
    pub cell_bits: usize,
    pub cycles: usize,
    pub initial: Vec<F2_128>,
    pub read_address: AddressRows,
    pub write_address: AddressRows,
    pub increment: Vec<F2_128>,
    pub value: Vec<u64>,
    pub read_value: Vec<F2_128>,
    pub write_value: Vec<F2_128>,
    pub final_value: Vec<F2_128>,
    pub idle_word: Option<usize>,
}

/// One-hot address rows packed one bit per slot.
///
/// The twist witness used to hold each cycle's address row as a
/// `Vec<F2_128>`: one 16-byte field element per bit, one heap allocation per
/// cycle. The one-hot rows are the largest witness columns in the register
/// instance (`cells = 32`, two rows per cycle), so at RV64 `2^16` the two
/// matrices were 2 x 64 MiB of pure transient. One bit per slot costs 1/128 of
/// that and removes the per-row allocations; every consumer reads through
/// [`Self::one_hot`], [`Self::bit`] or [`Self::row_into_field`], so the
/// committed tables and the proof bytes are unchanged.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddressRows {
    /// Slots per row (the one-hot width).
    slots: usize,
    /// Rows pushed so far.
    rows: usize,
    /// Bits, row after row, 64 slots per word.
    bits: Vec<u64>,
}

impl AddressRows {
    /// An empty set of one-hot rows with `slots` slots each.
    #[must_use]
    pub fn new(slots: usize) -> Self {
        Self {
            slots,
            rows: 0,
            bits: Vec::new(),
        }
    }

    /// Slots per row.
    #[must_use]
    pub const fn slots(&self) -> usize {
        self.slots
    }

    /// Rows pushed so far.
    #[must_use]
    pub const fn rows(&self) -> usize {
        self.rows
    }

    /// A view of every row, for tests and diagnostics.
    #[must_use]
    pub fn one_hots(&self) -> impl Iterator<Item = Option<usize>> + '_ {
        (0..self.rows).map(|row| self.one_hot(row))
    }

    /// Append one all-zero row.
    pub fn push_zero_row(&mut self) {
        self.rows += 1;
        let words = self.rows * self.slots.div_ceil(64);
        self.bits.resize(words, 0);
    }

    /// Set one slot of one row.
    ///
    /// # Panics
    ///
    /// Panics if `row` is past the rows pushed so far or `slot` is out of range.
    pub fn set(&mut self, row: usize, slot: usize) {
        assert!(row < self.rows, "address row {row} of {}", self.rows);
        assert!(slot < self.slots, "address slot {slot} of {}", self.slots);
        let bit = row * self.slots + slot;
        self.bits[bit >> 6] |= 1u64 << (bit & 63);
    }

    /// Clear one slot of one row.
    pub fn clear(&mut self, row: usize, slot: usize) {
        assert!(row < self.rows, "address row {row} of {}", self.rows);
        assert!(slot < self.slots, "address slot {slot} of {}", self.slots);
        let bit = row * self.slots + slot;
        self.bits[bit >> 6] &= !(1u64 << (bit & 63));
    }

    /// Whether one slot of one row is set.
    #[must_use]
    pub fn bit(&self, row: usize, slot: usize) -> bool {
        debug_assert!(row < self.rows && slot < self.slots);
        let bit = row * self.slots + slot;
        (self.bits[bit >> 6] >> (bit & 63)) & 1 == 1
    }

    /// The single set slot of one row, if it has exactly one.
    #[must_use]
    pub fn one_hot(&self, row: usize) -> Option<usize> {
        debug_assert!(row < self.rows);
        let base = row * self.slots;
        let mut found = None;
        for slot in 0..self.slots {
            let bit = base + slot;
            if (self.bits[bit >> 6] >> (bit & 63)) & 1 == 1 {
                if found.is_some() {
                    return None;
                }
                found = Some(slot);
            }
        }
        found
    }

    /// Whether the row has any set slot.
    #[must_use]
    pub fn any_set(&self, row: usize) -> bool {
        debug_assert!(row < self.rows);
        (0..self.slots).any(|slot| self.bit(row, slot))
    }

    /// The set slot of one row, or zero when the row is empty.
    ///
    /// The twist treats "no write" as slot zero in the position-style readers.
    #[must_use]
    pub fn one_hot_or_zero(&self, row: usize) -> usize {
        self.one_hot(row).unwrap_or(0)
    }

    /// Scatter one row into a column-major `slots x cycles` table:
    /// `table[slot * cycles + row] = 1` for the set slot, nothing else.
    pub fn scatter_column_major(&self, row: usize, table: &mut [F2_128], cycles: usize) {
        if let Some(slot) = self.one_hot(row) {
            table[slot * cycles + row] = F2_128::from(1u64);
        }
    }

    /// Write one row into `out` as 0/1 field elements.
    pub fn row_into_field(&self, row: usize, out: &mut [F2_128]) {
        assert!(out.len() == self.slots, "row slice of {} slots", out.len());
        for (slot, value) in out.iter_mut().enumerate() {
            *value = F2_128::from(u64::from(self.bit(row, slot)));
        }
    }
}

impl BinaryTwistWitness {
    /// Build the relation for word-aligned 8-byte RAM accesses.
    pub fn from_trace(trace: &Trace) -> Result<Self, MemoryError> {
        let cells = trace.config.ram_size / 8;
        if cells == 0 || !cells.is_power_of_two() {
            return Err(MemoryError::InvalidBinaryTwist(
                "RAM must contain a power-of-two number of words".into(),
            ));
        }
        let address_bits = cells.trailing_zeros() as usize;
        let mut current = vec![F2_128::from(0u64); cells];
        for (index, chunk) in trace.initial_ram.chunks_exact(8).enumerate() {
            current[index] =
                F2_128::from(u64::from_le_bytes(chunk.try_into().expect("eight bytes")));
        }
        let initial = current.clone();
        let mut read_address = AddressRows::new(cells);
        let mut write_address = AddressRows::new(cells);
        let mut increment = Vec::new();
        let mut value = Vec::new();
        let mut read_value = Vec::new();
        let mut write_value = Vec::new();

        for event in &trace.memory_events {
            let access = event.access;
            let width = usize::from(access.width);
            if width == 0 || width > 8 {
                return Err(MemoryError::InvalidBinaryTwist(
                    "BinaryTwist supports 1..=8 byte accesses".into(),
                ));
            }
            let offset = access
                .addr
                .checked_sub(trace.config.ram_base)
                .ok_or_else(|| {
                    MemoryError::InvalidBinaryTwist(format!(
                        "address {:#x} is below the RAM base",
                        access.addr
                    ))
                })?;
            let word = usize::try_from(offset / 8)
                .map_err(|_| MemoryError::InvalidBinaryTwist("address overflows usize".into()))?;
            let lane = usize::try_from(offset % 8).expect("lane fits");
            if lane + width > 8 {
                return Err(MemoryError::InvalidBinaryTwist(
                    "BinaryTwist cannot span two words".into(),
                ));
            }
            if word >= cells {
                return Err(MemoryError::InvalidBinaryTwist(format!(
                    "address {:#x} is outside the RAM table",
                    access.addr
                )));
            }
            value.extend(current.iter().map(|cell| cell.value() as u64));
            let old = current[word];
            read_value.push(old);
            let (write_slot, delta, written) = if access.is_write {
                let mask = if width == 8 {
                    u64::MAX
                } else {
                    ((1u64 << (width * 8)) - 1) << (lane * 8)
                };
                let shifted = access.value.wrapping_shl((lane * 8) as u32);
                let new = F2_128::from(((old.value() as u64) & !mask) | (shifted & mask));
                (Some(word), old + new, new)
            } else {
                (None, F2_128::from(0u64), F2_128::from(0u64))
            };
            read_address.push_zero_row();
            write_address.push_zero_row();
            let row = read_address.rows() - 1;
            read_address.set(row, word);
            if let Some(slot) = write_slot {
                write_address.set(row, slot);
            }
            increment.push(delta);
            write_value.push(written);
            if access.is_write {
                current[word] = written;
            }
        }

        Ok(Self {
            address_bits,
            cell_bits: 64,
            cycles: value.len() / cells,
            initial,
            read_address,
            write_address,
            increment,
            value,
            read_value,
            write_value,
            final_value: current,
            idle_word: None,
        })
    }

    /// Full-cycle RAM witness: one Twist cycle per trace row, with idle reads
    /// at word 0 for rows that do not perform a memory access.
    pub fn from_trace_full_cycles(trace: &Trace) -> Result<Self, MemoryError> {
        let cells = trace.config.ram_size / 8;
        if cells == 0 || !cells.is_power_of_two() {
            return Err(MemoryError::InvalidBinaryTwist(
                "RAM must contain a power-of-two number of words".into(),
            ));
        }
        let address_bits = cells.trailing_zeros() as usize;
        let mut current = vec![F2_128::from(0u64); cells];
        for (index, chunk) in trace.initial_ram.chunks_exact(8).enumerate() {
            current[index] =
                F2_128::from(u64::from_le_bytes(chunk.try_into().expect("eight bytes")));
        }
        let initial = current.clone();
        let written = trace
            .memory_events
            .iter()
            .filter(|event| event.access.is_write)
            .filter_map(|event| {
                event
                    .access
                    .addr
                    .checked_sub(trace.config.ram_base)
                    .and_then(|offset| usize::try_from(offset / 8).ok())
            })
            .collect::<std::collections::HashSet<_>>();
        let idle_word = initial
            .iter()
            .enumerate()
            .find(|(index, value)| value.value() == 0 && !written.contains(index))
            .map(|(index, _)| index)
            .ok_or_else(|| {
                MemoryError::InvalidBinaryTwist(
                    "full-cycle RAM witness needs a zero, unwritten idle cell".into(),
                )
            })?;
        let mut read_address = AddressRows::new(cells);
        let mut write_address = AddressRows::new(cells);
        let mut increment = Vec::new();
        let mut value = Vec::new();
        let mut read_value = Vec::new();
        let mut write_value = Vec::new();
        let cycles = trace.rows.len().next_power_of_two().max(2);
        for row in &trace.rows {
            if !row.extra_mem.is_empty() {
                return Err(MemoryError::InvalidBinaryTwist(
                    "full-cycle RAM witness does not support extra_mem rows".into(),
                ));
            }
            value.extend(current.iter().map(|cell| cell.value() as u64));
            let Some(access) = row.mem else {
                read_address.push_zero_row();
                write_address.push_zero_row();
                let cycle = read_address.rows() - 1;
                read_address.set(cycle, idle_word);
                increment.push(F2_128::from(0u64));
                read_value.push(current[idle_word]);
                write_value.push(F2_128::from(0u64));
                continue;
            };
            let width = usize::from(access.width);
            if width == 0 || width > 8 {
                return Err(MemoryError::InvalidBinaryTwist(
                    "BinaryTwist supports 1..=8 byte accesses".into(),
                ));
            }
            let offset = access
                .addr
                .checked_sub(trace.config.ram_base)
                .ok_or_else(|| {
                    MemoryError::InvalidBinaryTwist(format!(
                        "address {:#x} is below the RAM base",
                        access.addr
                    ))
                })?;
            let word = usize::try_from(offset / 8)
                .map_err(|_| MemoryError::InvalidBinaryTwist("address overflows usize".into()))?;
            let lane = usize::try_from(offset % 8).expect("lane fits");
            if lane + width > 8 || word >= cells {
                return Err(MemoryError::InvalidBinaryTwist(
                    "access is outside the RAM table".into(),
                ));
            }
            let old = current[word];
            read_value.push(old);
            let (write_slot, delta, written) = if access.is_write {
                let mask = if width == 8 {
                    u64::MAX
                } else {
                    ((1u64 << (width * 8)) - 1) << (lane * 8)
                };
                let shifted = access.value.wrapping_shl((lane * 8) as u32);
                let new = F2_128::from(((old.value() as u64) & !mask) | (shifted & mask));
                (Some(word), old + new, new)
            } else {
                (None, F2_128::from(0u64), F2_128::from(0u64))
            };
            read_address.push_zero_row();
            write_address.push_zero_row();
            let cycle = read_address.rows() - 1;
            read_address.set(cycle, word);
            if let Some(slot) = write_slot {
                write_address.set(cycle, slot);
            }
            increment.push(delta);
            write_value.push(written);
            if access.is_write {
                current[word] = written;
            }
        }
        while value.len() < cycles * cells {
            value.extend(current.iter().map(|cell| cell.value() as u64));
            read_address.push_zero_row();
            write_address.push_zero_row();
            let cycle = read_address.rows() - 1;
            read_address.set(cycle, idle_word);
            increment.push(F2_128::from(0u64));
            read_value.push(current[idle_word]);
            write_value.push(F2_128::from(0u64));
        }
        Ok(Self {
            address_bits,
            cell_bits: 64,
            cycles: value.len() / cells,
            initial,
            read_address,
            write_address,
            increment,
            value,
            read_value,
            write_value,
            final_value: current,
            idle_word: Some(idle_word),
        })
    }

    pub fn validate(&self) -> Result<(), MemoryError> {
        let cells = self.initial.len();
        if self.cycles != self.value.len() / cells
            || self.cycles != self.read_address.rows()
            || self.cycles != self.write_address.rows()
            || self.cycles != self.increment.len()
            || self.cycles != self.read_value.len()
            || self.cycles != self.write_value.len()
        {
            return Err(MemoryError::InvalidBinaryTwist(
                "BinaryTwist column lengths disagree".into(),
            ));
        }
        if cells != 1usize << self.address_bits || self.final_value.len() != cells {
            return Err(MemoryError::InvalidBinaryTwist(
                "BinaryTwist table shape disagrees".into(),
            ));
        }
        let mut previous = self.initial.clone();
        for cycle in 0..self.cycles {
            if self
                .value_row(cycle)
                .iter()
                .zip(&previous)
                .any(|(word, value)| *word != value.value() as u64)
            {
                return Err(MemoryError::InvalidBinaryTwist(format!(
                    "cycle {cycle} value history is inconsistent"
                )));
            }
            let read_slot = self.read_address.one_hot(cycle).ok_or_else(|| {
                MemoryError::InvalidBinaryTwist(format!(
                    "cycle {cycle} read address is not one-hot"
                ))
            })?;
            let write_slot = match self.write_address.one_hot(cycle) {
                Some(slot) => Some(slot),
                None if self.write_address.any_set(cycle) => {
                    return Err(MemoryError::InvalidBinaryTwist(format!(
                        "cycle {cycle} write address is not one-hot"
                    )))
                }
                None => None,
            };
            if previous[read_slot] != self.read_value[cycle] {
                return Err(MemoryError::InvalidBinaryTwist(format!(
                    "cycle {cycle} read value does not match the address history"
                )));
            }
            if let Some(slot) = write_slot {
                let written = previous[slot] + self.increment[cycle];
                if written != self.write_value[cycle] {
                    return Err(MemoryError::InvalidBinaryTwist(format!(
                        "cycle {cycle} write value does not match the increment"
                    )));
                }
                previous[slot] = written;
            } else if self.write_value[cycle] != F2_128::from(0u64) {
                return Err(MemoryError::InvalidBinaryTwist(format!(
                    "cycle {cycle} write value set without a write address"
                )));
            }
        }
        if previous != self.final_value {
            return Err(MemoryError::InvalidBinaryTwist(
                "final RAM state does not follow the increments".into(),
            ));
        }
        Ok(())
    }

    /// One-hot slots per row, i.e. cells in the value history.
    #[must_use]
    pub fn cells(&self) -> usize {
        1usize << self.address_bits
    }

    /// The value history row of one cycle: one 64-bit word per cell.
    ///
    /// The history is stored as `u64` rather than as 16-byte field elements
    /// because a cell is a 64-bit word: the packed form is half the bytes and
    /// keeps one allocation for the whole matrix.
    #[must_use]
    pub fn value_row(&self, cycle: usize) -> &[u64] {
        let cells = self.cells();
        &self.value[cycle * cells..(cycle + 1) * cells]
    }

    /// Write one value row into `out` as field elements.
    pub fn value_row_into_field(&self, cycle: usize, out: &mut [F2_128]) {
        for (value, word) in out.iter_mut().zip(self.value_row(cycle)) {
            *value = F2_128::from(*word);
        }
    }

    /// One value row as owned field elements, for callers that need a slice.
    #[must_use]
    pub fn value_row_vec(&self, cycle: usize) -> Vec<F2_128> {
        self.value_row(cycle)
            .iter()
            .map(|word| F2_128::from(*word))
            .collect()
    }

    pub fn word_value(&self, cycle: usize, cell: usize) -> Option<Word> {
        self.value_row(cycle).get(cell).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    fn config() -> MachineConfig {
        MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x40,
            stack_top: 0x1000_0040,
            max_cycles: 100,
        }
    }

    fn loading_program() -> ProgramImage {
        ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 7,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Lui,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x1000_0000,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Sd,
                    rd: 0,
                    rs1: 2,
                    rs2: 1,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Ld,
                    rd: 3,
                    rs1: 2,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        )
    }

    #[test]
    fn binary_twist_history_matches_a_store_then_load() {
        let trace = execute(&loading_program(), config()).unwrap();
        let witness = BinaryTwistWitness::from_trace(&trace).unwrap();
        witness.validate().unwrap();
        assert!(witness.cycles >= 2);
        assert_eq!(witness.read_value[0], F2_128::from(0u64));
        assert_eq!(witness.write_value[0], F2_128::from(7u64));
        assert_eq!(witness.read_value[1], F2_128::from(7u64));
        assert_eq!(witness.final_value[0], F2_128::from(7u64));
        assert_eq!(witness.word_value(1, 0), Some(7));
    }

    #[test]
    fn binary_twist_rejects_tampered_columns() {
        let trace = execute(&loading_program(), config()).unwrap();
        let witness = BinaryTwistWitness::from_trace(&trace).unwrap();

        let mut tampered = witness.clone();
        tampered.read_value[0] = tampered.read_value[0] + F2_128::from(1u64);
        assert!(tampered.validate().is_err());

        let mut tampered = witness.clone();
        tampered.increment[0] = tampered.increment[0] + F2_128::from(1u64);
        assert!(tampered.validate().is_err());

        let mut tampered = witness.clone();
        tampered.write_address.set(0, 1);
        assert!(tampered.validate().is_err());

        let cells = witness.cells();
        let mut tampered = witness;
        tampered.value[cells] ^= 1;
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn full_cycle_witness_has_one_cycle_per_trace_row() {
        let trace = execute(&loading_program(), config()).unwrap();
        let witness = BinaryTwistWitness::from_trace_full_cycles(&trace).unwrap();
        witness.validate().unwrap();
        assert_eq!(witness.cycles, trace.rows.len().next_power_of_two().max(2));
        let events = BinaryTwistWitness::from_trace(&trace).unwrap();
        let mut event = 0usize;
        for (cycle, row) in trace.rows.iter().enumerate() {
            if row.mem.is_some() {
                assert_eq!(witness.read_value[cycle], events.read_value[event]);
                assert_eq!(witness.write_value[cycle], events.write_value[event]);
                event += 1;
            }
        }
        assert_eq!(event, events.cycles);
        assert_eq!(witness.final_value[0], F2_128::from(7u64));
    }
}
