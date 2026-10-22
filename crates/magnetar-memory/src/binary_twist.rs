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
    pub read_address: Vec<Vec<F2_128>>,
    pub write_address: Vec<Vec<F2_128>>,
    pub increment: Vec<F2_128>,
    pub value: Vec<Vec<F2_128>>,
    pub read_value: Vec<F2_128>,
    pub write_value: Vec<F2_128>,
    pub final_value: Vec<F2_128>,
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
        let mut read_address = Vec::new();
        let mut write_address = Vec::new();
        let mut increment = Vec::new();
        let mut value = Vec::new();
        let mut read_value = Vec::new();
        let mut write_value = Vec::new();

        for event in &trace.memory_events {
            let access = event.access;
            if access.width != 8 || !access.addr.is_multiple_of(8) {
                return Err(MemoryError::InvalidBinaryTwist(
                    "BinaryTwist reference supports word-aligned 8-byte accesses".into(),
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
            if word >= cells {
                return Err(MemoryError::InvalidBinaryTwist(format!(
                    "address {:#x} is outside the RAM table",
                    access.addr
                )));
            }
            value.push(current.clone());
            read_value.push(current[word]);
            let (read, write, delta, written) = if access.is_write {
                let new = F2_128::from(access.value);
                let delta = current[word] + new;
                let mut one_hot = vec![F2_128::from(0u64); cells];
                one_hot[word] = F2_128::from(1u64);
                let mut read_one_hot = vec![F2_128::from(0u64); cells];
                read_one_hot[word] = F2_128::from(1u64);
                (read_one_hot, one_hot, delta, new)
            } else {
                let mut one_hot = vec![F2_128::from(0u64); cells];
                one_hot[word] = F2_128::from(1u64);
                (
                    one_hot,
                    vec![F2_128::from(0u64); cells],
                    F2_128::from(0u64),
                    F2_128::from(0u64),
                )
            };
            read_address.push(read);
            write_address.push(write);
            increment.push(delta);
            write_value.push(written);
            if access.is_write {
                current[word] = F2_128::from(access.value);
            }
        }

        Ok(Self {
            address_bits,
            cell_bits: 64,
            cycles: value.len(),
            initial,
            read_address,
            write_address,
            increment,
            value,
            read_value,
            write_value,
            final_value: current,
        })
    }

    pub fn validate(&self) -> Result<(), MemoryError> {
        let cells = self.initial.len();
        if self.cycles != self.value.len()
            || self.cycles != self.read_address.len()
            || self.cycles != self.write_address.len()
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
            if self.value[cycle] != previous {
                return Err(MemoryError::InvalidBinaryTwist(format!(
                    "cycle {cycle} value history is inconsistent"
                )));
            }
            check_one_hot(&self.read_address[cycle], cycle, "read")?;
            let is_write = self.write_address[cycle].iter().any(|bit| bit.value() != 0);
            if is_write {
                check_one_hot(&self.write_address[cycle], cycle, "write")?;
            } else if self.write_address[cycle].iter().any(|bit| bit.value() != 0) {
                return Err(MemoryError::InvalidBinaryTwist(format!(
                    "cycle {cycle} write address is neither zero nor one-hot"
                )));
            }
            let read: F2_128 = self.read_address[cycle]
                .iter()
                .zip(&previous)
                .fold(F2_128::from(0u64), |sum, (bit, value)| sum + *bit * *value);
            if read != self.read_value[cycle] {
                return Err(MemoryError::InvalidBinaryTwist(format!(
                    "cycle {cycle} read value does not match the address history"
                )));
            }
            let written: F2_128 = self.write_address[cycle]
                .iter()
                .zip(&previous)
                .fold(F2_128::from(0u64), |sum, (bit, value)| {
                    sum + *bit * (*value + self.increment[cycle])
                });
            if written != self.write_value[cycle] {
                return Err(MemoryError::InvalidBinaryTwist(format!(
                    "cycle {cycle} write value does not match the increment"
                )));
            }
            for (value, &write) in previous.iter_mut().zip(&self.write_address[cycle]) {
                *value = *value + write * self.increment[cycle];
            }
        }
        if previous != self.final_value {
            return Err(MemoryError::InvalidBinaryTwist(
                "final RAM state does not follow the increments".into(),
            ));
        }
        Ok(())
    }

    pub fn word_value(&self, cycle: usize, cell: usize) -> Option<Word> {
        self.value
            .get(cycle)
            .and_then(|row| row.get(cell))
            .map(|value| value.value() as Word)
    }
}

fn check_one_hot(address: &[F2_128], cycle: usize, kind: &str) -> Result<(), MemoryError> {
    if address.iter().any(|bit| bit.value() > 1) {
        return Err(MemoryError::InvalidBinaryTwist(format!(
            "cycle {cycle} {kind} address contains a non-boolean bit"
        )));
    }
    if address.iter().filter(|bit| bit.value() == 1).count() != 1 {
        return Err(MemoryError::InvalidBinaryTwist(format!(
            "cycle {cycle} {kind} address is not one-hot"
        )));
    }
    Ok(())
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
        tampered.write_address[0][1] = F2_128::from(1u64);
        assert!(tampered.validate().is_err());

        let mut tampered = witness;
        tampered.value[1][0] = tampered.value[1][0] + F2_128::from(1u64);
        assert!(tampered.validate().is_err());
    }
}
