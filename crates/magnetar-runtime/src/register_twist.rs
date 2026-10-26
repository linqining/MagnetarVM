//! Register-file BinaryTwist witness.
//!
//! The paper uses a BinaryTwist instance with `p = 2` reads and one write per
//! CPU cycle. This reference implementation encodes the same ordering as two
//! Twist sub-cycles: the first reads `rs1`, the second reads `rs2` and then
//! applies the `rd` write. The resulting one-read/one-write witness can be
//! proved by the existing BinaryTwist reduction without changing its protocol.

use magnetar_constraint::F2_128;
use magnetar_memory::BinaryTwistWitness;
use magnetar_proof::ProofError;
use magnetar_spec::Trace;

const REGISTER_BITS: usize = 5;
const REGISTER_COUNT: usize = 1 << REGISTER_BITS;

/// Build the two-phase register-file Twist witness for a trace.
pub fn register_twist_witness(trace: &Trace) -> Result<BinaryTwistWitness, ProofError> {
    let mut registers = trace.initial_state.regs;
    let initial = registers
        .iter()
        .map(|value| F2_128::from(*value))
        .collect::<Vec<_>>();
    let mut read_address = Vec::with_capacity(trace.rows.len() * 2);
    let mut write_address = Vec::with_capacity(trace.rows.len() * 2);
    let mut increment = Vec::with_capacity(trace.rows.len() * 2);
    let mut value = Vec::with_capacity(trace.rows.len() * 2);
    let mut read_value = Vec::with_capacity(trace.rows.len() * 2);
    let mut write_value = Vec::with_capacity(trace.rows.len() * 2);

    for row in &trace.rows {
        let rs1 = usize::from(row.instruction.rs1) & (REGISTER_COUNT - 1);
        let rs2 = usize::from(row.instruction.rs2) & (REGISTER_COUNT - 1);
        let rd = row.rd.map(|index| index & (REGISTER_COUNT - 1));

        let mut reads = Vec::with_capacity(2);
        if rs1 != 0 {
            reads.push(rs1);
        }
        if rs2 != 0 && rs2 != rs1 {
            reads.push(rs2);
        }
        let write = rd.filter(|index| *index != 0);

        let mut push_phase = |read: Option<usize>, write: Option<usize>| {
            value.push(registers.iter().map(|word| F2_128::from(*word)).collect());
            let mut read_one_hot = vec![F2_128::from(0u64); REGISTER_COUNT];
            let mut write_one_hot = vec![F2_128::from(0u64); REGISTER_COUNT];
            let mut read_scalar = F2_128::from(0u64);
            let mut write_scalar = F2_128::from(0u64);
            let mut increment_scalar = F2_128::from(0u64);
            if let Some(read) = read {
                read_one_hot[read] = F2_128::from(1u64);
                read_scalar = F2_128::from(registers[read]);
            }
            if let Some(write) = write {
                let old = registers[write];
                let new = row.rd_val;
                write_one_hot[write] = F2_128::from(1u64);
                increment_scalar = F2_128::from(old ^ new);
                write_scalar = F2_128::from(new);
                registers[write] = new;
            }
            read_address.push(read_one_hot);
            write_address.push(write_one_hot);
            increment.push(increment_scalar);
            read_value.push(read_scalar);
            write_value.push(write_scalar);
        };

        match (reads.len(), write) {
            (2, Some(write)) => {
                push_phase(Some(reads[0]), None);
                push_phase(Some(reads[1]), Some(write));
            }
            (2, None) => {
                push_phase(Some(reads[0]), None);
                push_phase(Some(reads[1]), None);
            }
            (1, write) => push_phase(Some(reads[0]), write),
            (0, Some(write)) => push_phase(Some(0), Some(write)),
            _ => {}
        }
    }

    let witness = BinaryTwistWitness {
        address_bits: REGISTER_BITS,
        cell_bits: 64,
        cycles: value.len(),
        initial,
        read_address,
        write_address,
        increment,
        value,
        read_value,
        write_value,
        final_value: registers.iter().map(|word| F2_128::from(*word)).collect(),
        idle_word: None,
    };
    witness
        .validate()
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    Ok(witness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{prove_binary_twist_ram, verify_binary_twist_ram};
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    fn trace() -> Trace {
        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Addi, 1, 0, 0, 5).encode(),
                instruction(Op::Addi, 2, 0, 0, 7).encode(),
                instruction(Op::Add, 3, 1, 2, 0).encode(),
                instruction(Op::Xor, 4, 3, 1, 0).encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        execute(
            &program,
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 100,
            },
        )
        .unwrap()
    }

    #[test]
    fn register_twist_compact_shape() {
        let trace = trace();
        let witness = register_twist_witness(&trace).unwrap();
        assert!(witness.cycles > 0);
        assert!(witness.cycles <= trace.rows.len() * 2);
        assert_eq!(
            witness.final_value[3].value(),
            u128::from(trace.final_state.reg(3))
        );
        for address in &witness.read_address {
            assert_eq!(address.iter().filter(|value| value.value() == 1).count(), 1);
        }
    }

    #[test]
    fn register_twist_witness_proves() {
        let trace = trace();
        let witness = register_twist_witness(&trace).unwrap();
        assert!(witness.cycles <= trace.rows.len() * 2);
        assert_eq!(
            witness.final_value[3].value(),
            u128::from(trace.final_state.reg(3))
        );
        let proof = prove_binary_twist_ram(&witness).unwrap();
        assert!(verify_binary_twist_ram(&witness, &proof).unwrap());

        let mut tampered = proof.clone();
        tampered.read_value_eval = tampered.read_value_eval + F2_128::from(1u64);
        assert!(!verify_binary_twist_ram(&witness, &tampered).unwrap());
    }
}
