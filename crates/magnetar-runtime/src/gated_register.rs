//! Register-file BinaryTwist witness from selector-gated ALU events.
//!
//! Each ALU event expands into two Twist sub-cycles: read `rs1`, then read
//! `rs2` and write `rd`, matching the paper's p = 2 register-file instance.

use magnetar_constraint::F2_128;
use magnetar_memory::BinaryTwistWitness;
use magnetar_proof::ProofError;

const REGISTER_BITS: usize = 5;
const REGISTER_COUNT: usize = 1 << REGISTER_BITS;

#[derive(Clone, Copy, Debug)]
pub struct GatedRegisterEvent {
    pub rs1: u8,
    pub rs2: u8,
    pub rd: u8,
    pub left: u64,
    pub right: u64,
    pub out: u64,
}

fn one_hot(index: usize) -> Vec<F2_128> {
    let mut address = vec![F2_128::from(0u64); REGISTER_COUNT];
    address[index & (REGISTER_COUNT - 1)] = F2_128::from(1u64);
    address
}

/// Build the two-phase register Twist witness for gated ALU events.
pub fn gated_register_twist_witness(
    events: &[GatedRegisterEvent],
    initial: &[u64; REGISTER_COUNT],
) -> Result<BinaryTwistWitness, ProofError> {
    if events.is_empty() {
        return Err(ProofError::Pcs(
            "register witness needs at least one event".into(),
        ));
    }
    let mut registers = *initial;
    let mut read_address = Vec::with_capacity(events.len() * 2);
    let mut write_address = Vec::with_capacity(events.len() * 2);
    let mut increment = Vec::with_capacity(events.len() * 2);
    let mut value = Vec::with_capacity(events.len() * 2);
    let mut read_value = Vec::with_capacity(events.len() * 2);
    let mut write_value = Vec::with_capacity(events.len() * 2);

    for event in events {
        let rs1 = usize::from(event.rs1);
        let rs2 = usize::from(event.rs2);
        let rd = usize::from(event.rd);

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
        if rd != 0 {
            let old = registers[rd];
            let new = event.out;
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
        initial: initial.iter().map(|word| F2_128::from(*word)).collect(),
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

    #[test]
    fn gated_register_events_prove_through_binary_twist() {
        let events = [
            GatedRegisterEvent {
                rs1: 0,
                rs2: 0,
                rd: 1,
                left: 0,
                right: 0,
                out: 5,
            },
            GatedRegisterEvent {
                rs1: 1,
                rs2: 0,
                rd: 2,
                left: 5,
                right: 0,
                out: 7,
            },
        ];
        let initial = [0u64; REGISTER_COUNT];
        let witness = gated_register_twist_witness(&events, &initial).unwrap();
        let proof = prove_binary_twist_ram(&witness).unwrap();
        assert!(verify_binary_twist_ram(&witness, &proof).unwrap());
    }
}

/// Extract register-file Twist events from a supported trace prefix.
pub fn gated_register_events_from_trace(
    trace: &magnetar_spec::Trace,
) -> Result<(Vec<GatedRegisterEvent>, [u64; REGISTER_COUNT]), ProofError> {
    use magnetar_cpu::StepOp;

    let mut initial = [0u64; REGISTER_COUNT];
    for (index, value) in trace.initial_state.regs.iter().enumerate() {
        initial[index] = *value;
    }
    let mut events = Vec::new();
    for row in &trace.rows {
        if row.mem.is_some() {
            break;
        }
        let Some(step) = crate::step_op_for(row.instruction.op) else {
            break;
        };
        if !matches!(step, StepOp::Add | StepOp::Xor | StepOp::And)
            || crate::w_step_op_for(row.instruction.op).is_some()
            || crate::branch_op_for(row.instruction.op).is_some()
        {
            break;
        }
        if row.instruction.rd == 0 {
            continue;
        }
        events.push(GatedRegisterEvent {
            rs1: row.instruction.rs1,
            rs2: row.instruction.rs2,
            rd: row.instruction.rd,
            left: row.rs1_val,
            right: row.rs2_val,
            out: row.rd_val,
        });
    }
    if events.is_empty() {
        return Err(ProofError::Pcs(
            "trace has no supported register events".into(),
        ));
    }
    Ok((events, initial))
}

#[cfg(test)]
mod trace_tests {
    use super::*;

    #[test]
    fn trace_events_prove_through_register_twist() {
        use crate::{prove_binary_twist_ram, verify_binary_twist_ram};
        use magnetar_executor::execute;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm: 0,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Add, 1, 0, 0).encode(),
                instruction(Op::Add, 2, 1, 0).encode(),
                instruction(Op::Xor, 3, 1, 2).encode(),
                instruction(Op::And, 4, 1, 2).encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(
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
        .unwrap();
        let (events, initial) = gated_register_events_from_trace(&trace).unwrap();
        assert_eq!(events.len(), 4);
        let witness = gated_register_twist_witness(&events, &initial).unwrap();
        let proof = prove_binary_twist_ram(&witness).unwrap();
        assert!(verify_binary_twist_ram(&witness, &proof).unwrap());
    }
}
