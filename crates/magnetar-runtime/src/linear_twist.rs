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

    pub(super) fn register_witness() -> BinaryTwistWitness {
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

/// Val-evaluation sumcheck prototype.
#[derive(Clone, Debug)]
pub struct ValEvaluationProof {
    pub claimed: F2_128,
    pub rounds: Vec<Vec<F2_128>>,
    pub challenges: Vec<F2_128>,
}

fn eval_mle(values: &[F2_128], point: &[F2_128]) -> F2_128 {
    let mut folded = values.to_vec();
    for coordinate in point {
        let mut next = Vec::with_capacity(folded.len() / 2);
        for pair in folded.chunks_exact(2) {
            next.push(pair[0] + *coordinate * (pair[1] - pair[0]));
        }
        folded = next;
    }
    folded[0]
}

fn build_val_tables(witness: &BinaryTwistWitness) -> (Vec<F2_128>, Vec<F2_128>, Vec<F2_128>) {
    let cells = 1usize << witness.address_bits;
    let cycles = witness.cycles.next_power_of_two().max(2);
    let mut val = vec![F2_128::from(0u64); cells * cycles];
    let mut wa = vec![F2_128::from(0u64); cells * cycles];
    let mut inc = vec![F2_128::from(0u64); cycles];
    let mut current = witness.initial.clone();
    current.resize(cells, F2_128::from(0u64));
    for (cycle, target_inc) in inc.iter_mut().enumerate() {
        let increment = witness
            .increment
            .get(cycle)
            .copied()
            .unwrap_or(F2_128::from(0u64));
        let write = witness.write_address.get(cycle);
        for cell in 0..cells {
            let index = cell * cycles + cycle;
            let write_bit = write.map_or(F2_128::from(0u64), |row| row[cell]);
            wa[index] = write_bit;
            val[index] = current[cell];
            current[cell] = current[cell] + write_bit * increment;
        }
        *target_inc = increment;
    }
    (val, wa, inc)
}

pub fn prove_val_evaluation(
    witness: &BinaryTwistWitness,
) -> Result<ValEvaluationProof, ProofError> {
    let cycles = witness.cycles.next_power_of_two().max(2);
    let cycle_bits = cycles.trailing_zeros() as usize;
    let (val, _, inc) = build_val_tables(witness);
    let mut transcript = Sha256Transcript::new("magnetar-val-evaluation");
    let rk = sample_point(&mut transcript, witness.address_bits);
    let rj = sample_point(&mut transcript, cycle_bits);
    let val_claim = eval_mle(&val, &rj.iter().chain(&rk).copied().collect::<Vec<_>>());
    let init_claim = eval_mle(&witness.initial, &rk);
    let eq_rj = eq_vector(&rj, cycles);
    let mut suffix = vec![F2_128::from(0u64); cycles];
    let mut running = F2_128::from(0u64);
    for previous in (0..cycles).rev() {
        suffix[previous] = running;
        running = running + eq_rj[previous];
    }
    let cells = 1usize << witness.address_bits;
    let mut wa_at_rk = (0..cycles)
        .map(|cycle| {
            witness.write_address.get(cycle).map_or(F2_128::from(0u64), |row| {
                eval_mle(row, &rk)
            })
        })
        .collect::<Vec<_>>();
    wa_at_rk.resize(cycles, F2_128::from(0u64));
    let _ = cells;
    let factors = vec![wa_at_rk, inc, suffix];
    let (rounds, challenges) =
        sumcheck_terms(&factors, &vec![3usize; cycle_bits], &mut transcript, |folded| {
            (0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
                sum + folded[0][index] * folded[1][index] * folded[2][index]
            })
        })?;
    Ok(ValEvaluationProof {
        claimed: val_claim - init_claim,
        rounds,
        challenges,
    })
}

pub fn verify_val_evaluation(
    witness: &BinaryTwistWitness,
    proof: &ValEvaluationProof,
) -> Result<bool, ProofError> {
    let cycles = witness.cycles.next_power_of_two().max(2);
    let cycle_bits = cycles.trailing_zeros() as usize;
    let (val, wa, inc) = build_val_tables(witness);
    let mut transcript = Sha256Transcript::new("magnetar-val-evaluation");
    let rk = sample_point(&mut transcript, witness.address_bits);
    let rj = sample_point(&mut transcript, cycle_bits);
    let val_claim = eval_mle(&val, &rj.iter().chain(&rk).copied().collect::<Vec<_>>());
    let init_claim = eval_mle(&witness.initial, &rk);
    if proof.claimed != val_claim - init_claim {
        return Ok(false);
    }
    let mut transcript = Sha256Transcript::new("magnetar-val-evaluation");
    let _ = sample_point(&mut transcript, witness.address_bits);
    let _ = sample_point(&mut transcript, cycle_bits);
    let Some((final_sum, challenges)) =
        replay_terms_derived(&proof.rounds, proof.claimed, &mut transcript)
    else {
        return Ok(false);
    };
    if challenges != proof.challenges {
        return Ok(false);
    }
    let wa_eval = eval_mle(
        &wa,
        &challenges.iter().chain(&rk).copied().collect::<Vec<_>>(),
    );
    let inc_eval = eval_mle(&inc, &challenges);
    let lt_eval = crate::binary_twist::lt_mle(&challenges, &rj, cycles);
    Ok(final_sum == wa_eval * inc_eval * lt_eval)
}

#[cfg(test)]
mod val_evaluation_tests {
    use super::tests::register_witness;
    use super::*;

    #[test]
    fn val_evaluation_round_trips() {
        let witness = register_witness();
        let proof = prove_val_evaluation(&witness).unwrap();
        assert!(verify_val_evaluation(&witness, &proof).unwrap());
        let mut tampered = proof;
        tampered.claimed = tampered.claimed + F2_128::from(1u64);
        assert!(!verify_val_evaluation(&witness, &tampered).unwrap());
    }
}
