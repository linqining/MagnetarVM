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

fn one_hot(index: usize) -> Vec<F2_128> {
    let mut address = vec![F2_128::from(0u64); REGISTER_COUNT];
    address[index] = F2_128::from(1u64);
    address
}

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

        // Phase 1: read rs1, no write.
        value.push(registers.iter().map(|word| F2_128::from(*word)).collect());
        read_address.push(one_hot(rs1));
        write_address.push(vec![F2_128::from(0u64); REGISTER_COUNT]);
        increment.push(F2_128::from(0u64));
        read_value.push(F2_128::from(registers[rs1]));
        write_value.push(F2_128::from(0u64));

        // Phase 2: read rs2, then write rd.
        value.push(registers.iter().map(|word| F2_128::from(*word)).collect());
        read_address.push(one_hot(rs2));
        read_value.push(F2_128::from(registers[rs2]));
        if let Some(rd) = rd.filter(|index| *index != 0) {
            let old = registers[rd];
            let new = row.rd_val;
            write_address.push(one_hot(rd));
            increment.push(F2_128::from(old ^ new));
            write_value.push(F2_128::from(new));
            registers[rd] = new;
        } else {
            write_address.push(vec![F2_128::from(0u64); REGISTER_COUNT]);
            increment.push(F2_128::from(0u64));
            write_value.push(F2_128::from(0u64));
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
    fn register_twist_two_phase_shape() {
        let trace = trace();
        let witness = register_twist_witness(&trace).unwrap();
        for (row_index, row) in trace.rows.iter().enumerate() {
            let rs1 = usize::from(row.instruction.rs1) & (REGISTER_COUNT - 1);
            let rs2 = usize::from(row.instruction.rs2) & (REGISTER_COUNT - 1);
            let first = 2 * row_index;
            assert_eq!(witness.read_address[first][rs1], F2_128::from(1u64));
            assert_eq!(
                witness.write_address[first],
                vec![F2_128::from(0u64); REGISTER_COUNT]
            );
            assert_eq!(witness.read_address[first + 1][rs2], F2_128::from(1u64));
            if let Some(rd) = row.rd.filter(|index| *index != 0) {
                assert_eq!(witness.write_address[first + 1][rd], F2_128::from(1u64));
                assert_eq!(witness.write_value[first + 1], F2_128::from(row.rd_val));
            }
        }
    }

    #[test]
    fn register_twist_witness_proves() {
        let trace = trace();
        let witness = register_twist_witness(&trace).unwrap();
        assert_eq!(witness.cycles, trace.rows.len() * 2);
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
