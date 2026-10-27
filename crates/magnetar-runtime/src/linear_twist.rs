//! Linear-size Twist read/write-checking prototype.
//!
//! This module starts the Jolt-style local Twist port: it checks the
//! read/write relation over one-hot address matrices and a virtual `Val`
//! table, so the prover only materializes `O(K * T)` data instead of the
//! dense `O(T^2)` pair history.

use magnetar_constraint::F2_128;
use magnetar_memory::BinaryTwistWitness;
use magnetar_proof::ProofError;
use magnetar_transcript::Sha256Transcript;

use crate::binary_twist::{eq_vector, replay_terms_derived, sample_point, sumcheck_terms};

/// Proof of the linear read/write-checking sumcheck for one read and one write
/// address per cycle.
#[derive(Clone, Debug)]
pub struct LinearRwProof {
    pub claimed: F2_128,
    pub rounds: Vec<Vec<F2_128>>,
    pub challenges: Vec<F2_128>,
}

pub struct LinearRwTables {
    pub cells: usize,
    pub cycles: usize,
    pub eq_cycle: Vec<F2_128>,
    pub read_address: Vec<F2_128>,
    pub write_address: Vec<F2_128>,
    pub increment: Vec<F2_128>,
    pub value: Vec<F2_128>,
    pub gamma: F2_128,
}

fn build_tables(
    witness: &BinaryTwistWitness,
    gamma: F2_128,
) -> Result<LinearRwTables, ProofError> {
    let cells = 1usize << witness.address_bits;
    let cycles = witness.cycles.next_power_of_two().max(2);
    let cycle_bits = cycles.trailing_zeros() as usize;
    let mut transcript = Sha256Transcript::new("magnetar-linear-rw-point");
    let cycle_point = sample_point(&mut transcript, cycle_bits);
    let eq = eq_vector(&cycle_point, cycles);
    let mut eq_cycle = vec![F2_128::from(0u64); cells * cycles];
    let mut read_address = vec![F2_128::from(0u64); cells * cycles];
    let mut write_address = vec![F2_128::from(0u64); cells * cycles];
    let mut increment = vec![F2_128::from(0u64); cells * cycles];
    let mut value = vec![F2_128::from(0u64); cells * cycles];
    let mut current = witness.initial.clone();
    current.resize(cells, F2_128::from(0u64));
    for (cycle, (read, write)) in witness
        .read_address
        .iter()
        .zip(&witness.write_address)
        .enumerate()
    {
        let row = cycle * cells;
        eq_cycle[row..row + cells].copy_from_slice(&vec![eq[cycle]; cells]);
        read_address[row..row + cells].copy_from_slice(read);
        write_address[row..row + cells].copy_from_slice(write);
        for (cell, current_cell) in current.iter_mut().enumerate().take(cells) {
            increment[row + cell] = witness.increment[cycle];
            value[row + cell] = *current_cell;
            *current_cell = *current_cell + write[cell] * witness.increment[cycle];
        }
    }
    Ok(LinearRwTables {
        cells,
        cycles,
        eq_cycle,
        read_address,
        write_address,
        increment,
        value,
        gamma,
    })
}

fn summand(factors: &[Vec<F2_128>], gamma: F2_128) -> F2_128 {
    (0..factors[0].len()).fold(F2_128::from(0u64), |sum, index| {
        sum + factors[0][index]
            * (factors[1][index] * factors[2][index]
                + factors[1][index] * factors[3][index]
                + gamma * factors[4][index] * factors[3][index])
    })
}

pub fn prove_linear_rw(witness: &BinaryTwistWitness) -> Result<LinearRwProof, ProofError> {
    let mut transcript = Sha256Transcript::new("magnetar-linear-twist-rw");
    let gamma = sample_point(&mut transcript, 1)[0];
    let tables = build_tables(witness, gamma)?;
    let factors = vec![
        tables.eq_cycle.clone(),
        tables.write_address.clone(),
        tables.increment.clone(),
        tables.value.clone(),
        tables.read_address.clone(),
    ];
    let cycles = tables.cells * tables.cycles;
    let rounds = cycles.trailing_zeros() as usize;
    let degrees = vec![3usize; rounds];
    let claimed = summand(&factors, gamma);
    let gamma_copy = gamma;
    let (rounds, challenges) = sumcheck_terms(&factors, &degrees, &mut transcript, move |folded| {
        summand(folded, gamma_copy)
    })?;
    Ok(LinearRwProof {
        claimed,
        rounds,
        challenges,
    })
}

pub fn verify_linear_rw(
    witness: &BinaryTwistWitness,
    proof: &LinearRwProof,
) -> Result<bool, ProofError> {
    let mut transcript = Sha256Transcript::new("magnetar-linear-twist-rw");
    let gamma = sample_point(&mut transcript, 1)[0];
    let tables = build_tables(witness, gamma)?;
    let factors = vec![
        tables.eq_cycle.clone(),
        tables.write_address.clone(),
        tables.increment.clone(),
        tables.value.clone(),
        tables.read_address.clone(),
    ];
    if proof.claimed != summand(&factors, gamma) {
        return Ok(false);
    }
    let mut transcript = Sha256Transcript::new("magnetar-linear-twist-rw");
    let _ = sample_point(&mut transcript, 1);
    let Some((final_sum, challenges)) =
        replay_terms_derived(&proof.rounds, proof.claimed, &mut transcript)
    else {
        return Ok(false);
    };
    if challenges != proof.challenges {
        return Ok(false);
    }
    let mut folded = factors;
    for challenge in &challenges {
        for factor in &mut folded {
            let mut next = Vec::with_capacity(factor.len() / 2);
            for pair in factor.chunks_exact(2) {
                next.push(pair[0] + *challenge * (pair[1] - pair[0]));
            }
            *factor = next;
        }
    }
    Ok(final_sum == summand(&folded, gamma))
}

#[cfg(test)]
mod tests {
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    use super::*;

    fn register_witness() -> BinaryTwistWitness {
        let mut program = Vec::new();
        for index in 0..1023 {
            program.push(
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 1,
                    rs2: 0,
                    imm: index + 1,
                    shamt: 0,
                }
                .encode(),
            );
        }
        program.push(Instruction::new(Op::Ecall).encode());
        let trace = execute(
            &ProgramImage::new(0x1000, program),
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x100,
                stack_top: 0x1000_0100,
                max_cycles: 10_000,
            },
        )
        .unwrap();
        crate::register_twist::register_twist_witness(&trace).unwrap()
    }

    #[test]
    fn linear_rw_round_trips() {
        let witness = register_witness();
        let proof = prove_linear_rw(&witness).unwrap();
        assert!(verify_linear_rw(&witness, &proof).unwrap());
        let mut tampered = proof;
        tampered.claimed = tampered.claimed + F2_128::from(1u64);
        assert!(!verify_linear_rw(&witness, &tampered).unwrap());
    }
}
