//! Linear-size Twist read/write-checking prototype.
//!
//! This module starts the Jolt-style local Twist port: it checks the
//! read/write relation over one-hot address matrices and a virtual `Val`
//! table, so the prover only materializes `O(K * T)` data instead of the
//! dense `O(T^2)` pair history.

use magnetar_constraint::{Field, F2_128};
use magnetar_pcs::{P3BatchCommitment, P3BatchOpening, P3BatchPoint, P3BinaryPcs};
use magnetar_memory::BinaryTwistWitness;
use magnetar_proof::ProofError;
use magnetar_transcript::Sha256Transcript;

use crate::binary_twist::{eq_vector, replay_terms_derived, sample_point, sumcheck_terms};

/// Public shape of a linear Twist instance, independent of the witness.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct LinearTwistShape {
    pub address_bits: usize,
    pub cycles: usize,
}

/// PCS parameters for the linear Twist tables. Small test instances use the
/// default configuration; the tuned large-instance parameters are only valid
/// once the stacked table has enough variables.
pub(crate) fn linear_pcs(cycles: usize) -> P3BinaryPcs {
    if cycles >= 8192 {
        P3BinaryPcs::with_params(100, 2, 8, 3)
    } else {
        P3BinaryPcs::new(100)
    }
}

impl LinearTwistShape {
    pub fn cells(self) -> usize {
        1usize << self.address_bits
    }

    pub fn cycle_bits(self) -> usize {
        self.cycles.trailing_zeros() as usize
    }
}

pub fn witness_shape(witness: &BinaryTwistWitness) -> LinearTwistShape {
    LinearTwistShape {
        address_bits: witness.address_bits,
        cycles: witness.cycles.next_power_of_two().max(2),
    }
}

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

pub fn eval_mle(values: &[F2_128], point: &[F2_128]) -> F2_128 {
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

pub(crate) fn build_val_tables(witness: &BinaryTwistWitness) -> (Vec<F2_128>, Vec<F2_128>, Vec<F2_128>) {
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
    let mut wa_at_rk = (0..cycles)
        .map(|cycle| {
            witness.write_address.get(cycle).map_or(F2_128::from(0u64), |row| {
                eval_mle(row, &rk)
            })
        })
        .collect::<Vec<_>>();
    wa_at_rk.resize(cycles, F2_128::from(0u64));
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


/// Val-evaluation proof with committed tables and P3 batch openings.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ValPcsProof {
    pub val_wa: P3BatchOpening,
    pub val_wa_values: Vec<Vec<F2_128>>,
    pub inc: P3BatchOpening,
    pub inc_value: F2_128,
    pub initial: P3BatchOpening,
    pub initial_value: F2_128,
    pub rounds: Vec<Vec<F2_128>>,
    pub challenges: Vec<F2_128>,
}

pub fn prove_val_pcs(witness: &BinaryTwistWitness) -> Result<ValPcsProof, ProofError> {
    let cycles = witness.cycles.next_power_of_two().max(2);
    let cycle_bits = cycles.trailing_zeros() as usize;
    let (val, wa, inc) = build_val_tables(witness);
    let cells = 1usize << witness.address_bits;
    let mut initial = witness.initial.clone();
    initial.resize(cells.next_power_of_two(), F2_128::from(0u64));
    let pcs = linear_pcs(cycles);
    let val_wa_commit: P3BatchCommitment = pcs
        .commit_batch(&[val.clone(), wa.clone()])
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let inc_commit: P3BatchCommitment = pcs
        .commit_batch(std::slice::from_ref(&inc))
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let initial_commit: P3BatchCommitment = pcs
        .commit_batch(&[initial.clone()])
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let mut transcript = Sha256Transcript::new("magnetar-val-pcs");
    for commitment in [&val_wa_commit, &inc_commit, &initial_commit] {
        transcript.absorb(
            "commitment",
            &bincode::serialize(commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
        );
    }
    let rk = sample_point(&mut transcript, witness.address_bits);
    let rj = sample_point(&mut transcript, cycle_bits);
    let val_claim = eval_mle(&val, &rj.iter().chain(&rk).copied().collect::<Vec<_>>());
    let init_claim = eval_mle(&initial, &rk);
    let eq_rj = eq_vector(&rj, cycles);
    let mut suffix = vec![F2_128::from(0u64); cycles];
    let mut running = F2_128::from(0u64);
    for previous in (0..cycles).rev() {
        suffix[previous] = running;
        running = running + eq_rj[previous];
    }
    let mut wa_at_rk = (0..cycles)
        .map(|cycle| {
            witness
                .write_address
                .get(cycle)
                .map_or(F2_128::from(0u64), |row| eval_mle(row, &rk))
        })
        .collect::<Vec<_>>();
    wa_at_rk.resize(cycles, F2_128::from(0u64));
    let factors = vec![wa_at_rk, inc.clone(), suffix];
    let (rounds, challenges) =
        sumcheck_terms(&factors, &vec![3usize; cycle_bits], &mut transcript, |folded| {
            (0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
                sum + folded[0][index] * folded[1][index] * folded[2][index]
            })
        })?;
    let val_point = rj.iter().chain(&rk).copied().collect::<Vec<_>>();
    let wa_point = challenges.iter().chain(&rk).copied().collect::<Vec<_>>();
    let val_wa_points = vec![
        P3BatchPoint {
            point: val_point.clone(),
            columns: vec![0],
        },
        P3BatchPoint {
            point: wa_point.clone(),
            columns: vec![1],
        },
    ];
    let inc_points = vec![P3BatchPoint {
        point: challenges.clone(),
        columns: vec![0],
    }];
    let initial_points = vec![P3BatchPoint {
        point: rk.clone(),
        columns: vec![0],
    }];
    let val_wa = pcs
        .open_batch(&[val.clone(), wa.clone()], &val_wa_points)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let inc_opening = pcs
        .open_batch(std::slice::from_ref(&inc), &inc_points)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let initial_opening = pcs
        .open_batch(&[initial.clone()], &initial_points)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let wa_eval = eval_mle(&wa, &wa_point);
    Ok(ValPcsProof {
        val_wa,
        val_wa_values: vec![vec![val_claim], vec![wa_eval]],
        inc: inc_opening,
        inc_value: eval_mle(&inc, &challenges),
        initial: initial_opening,
        initial_value: init_claim,
        rounds,
        challenges,
    })
}

pub fn verify_val_pcs(witness: &BinaryTwistWitness, proof: &ValPcsProof) -> Result<bool, ProofError> {
    verify_val_pcs_shape(witness_shape(witness), proof)
}

pub fn verify_val_pcs_shape(shape: LinearTwistShape, proof: &ValPcsProof) -> Result<bool, ProofError> {
    let cycles = shape.cycles;
    let cycle_bits = shape.cycle_bits();
    let mut transcript = Sha256Transcript::new("magnetar-val-pcs");
    for commitment in [
        &proof.val_wa.commitment,
        &proof.inc.commitment,
        &proof.initial.commitment,
    ] {
        transcript.absorb(
            "commitment",
            &bincode::serialize(commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
        );
    }
    let rk = sample_point(&mut transcript, shape.address_bits);
    let rj = sample_point(&mut transcript, cycle_bits);
    let val_point = rj.iter().chain(&rk).copied().collect::<Vec<_>>();
    let wa_point = proof.challenges.iter().chain(&rk).copied().collect::<Vec<_>>();
    let val_wa_points = vec![
        P3BatchPoint {
            point: val_point.clone(),
            columns: vec![0],
        },
        P3BatchPoint {
            point: wa_point.clone(),
            columns: vec![1],
        },
    ];
    let inc_points = vec![P3BatchPoint {
        point: proof.challenges.clone(),
        columns: vec![0],
    }];
    let initial_points = vec![P3BatchPoint {
        point: rk.clone(),
        columns: vec![0],
    }];
    let pcs = linear_pcs(cycles);
    let vw = pcs
        .verify_batch(&proof.val_wa, &val_wa_points, &proof.val_wa_values)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let vi = pcs
        .verify_batch(&proof.inc, &inc_points, &[vec![proof.inc_value]])
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let vinit = pcs
        .verify_batch(&proof.initial, &initial_points, &[vec![proof.initial_value]])
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    if !(vw && vi && vinit) {
        return Ok(false);
    }
    let val_claim = proof.val_wa_values[0][0];
    let wa_eval = proof.val_wa_values[1][0];
    let claimed = val_claim - proof.initial_value;
    let mut transcript = Sha256Transcript::new("magnetar-val-pcs");
    for commitment in [
        &proof.val_wa.commitment,
        &proof.inc.commitment,
        &proof.initial.commitment,
    ] {
        transcript.absorb(
            "commitment",
            &bincode::serialize(commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
        );
    }
    let _ = sample_point(&mut transcript, shape.address_bits);
    let _ = sample_point(&mut transcript, cycle_bits);
    let Some((final_sum, challenges)) =
        replay_terms_derived(&proof.rounds, claimed, &mut transcript)
    else {
        return Ok(false);
    };
    if challenges != proof.challenges {
        return Ok(false);
    }
    let lt_eval = crate::binary_twist::lt_mle(&challenges, &rj, cycles);
    Ok(final_sum == wa_eval * proof.inc_value * lt_eval)
}

#[cfg(test)]
mod val_pcs_tests {
    use super::tests::register_witness;
    use super::*;

    #[test]
    fn val_pcs_round_trips() {
        let witness = register_witness();
        let proof = prove_val_pcs(&witness).unwrap();
        assert!(verify_val_pcs(&witness, &proof).unwrap());
        let mut tampered = proof;
        tampered.rounds[0][0] = tampered.rounds[0][0] + F2_128::from(1u64);
        assert!(!verify_val_pcs(&witness, &tampered).unwrap());
    }
}

/// RW-checking sumcheck with PCS openings.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RwPcsProof {
    pub tables: P3BatchOpening,
    pub table_values: Vec<Vec<F2_128>>,
    pub inputs: P3BatchOpening,
    pub input_values: Vec<Vec<F2_128>>,
    pub rounds: Vec<Vec<F2_128>>,
    pub challenges: Vec<F2_128>,
}

fn eq_points_local(left: &[F2_128], right: &[F2_128]) -> F2_128 {
    left.iter()
        .zip(right)
        .fold(F2_128::from(1u64), |acc, (a, b)| {
            acc * (*a * *b + (F2_128::from(1u64) + *a) * (F2_128::from(1u64) + *b))
        })
}

pub fn prove_rw_pcs(witness: &BinaryTwistWitness) -> Result<RwPcsProof, ProofError> {
    let cells = 1usize << witness.address_bits;
    let cycles = witness.cycles.next_power_of_two().max(2);
    let cycle_bits = cycles.trailing_zeros() as usize;
    let (val, wa, inc) = build_val_tables(witness);
    let mut ra = vec![F2_128::from(0u64); cells * cycles];
    for (cycle, read) in witness.read_address.iter().enumerate() {
        for cell in 0..cells {
            ra[cell * cycles + cycle] = read[cell];
        }
    }
    let mut read_value = witness.read_value.clone();
    read_value.resize(cycles, F2_128::from(0u64));
    let mut write_value = witness.write_value.clone();
    write_value.resize(cycles, F2_128::from(0u64));
    let pcs = linear_pcs(cycles);
    let table_commit: P3BatchCommitment = pcs
        .commit_batch(&[ra.clone(), wa.clone(), val.clone()])
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let input_commit: P3BatchCommitment = pcs
        .commit_batch(&[inc.clone(), read_value.clone(), write_value.clone()])
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let mut transcript = Sha256Transcript::new("magnetar-rw-pcs");
    for commitment in [&table_commit, &input_commit] {
        transcript.absorb(
            "commitment",
            &bincode::serialize(commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
        );
    }
    let gamma = sample_point(&mut transcript, 1)[0];
    let cycle_point = sample_point(&mut transcript, cycle_bits);
    let eq = eq_vector(&cycle_point, cycles);
    let mut eq_flat = vec![F2_128::from(0u64); cells * cycles];
    for cycle in 0..cycles {
        for cell in 0..cells {
            eq_flat[cell * cycles + cycle] = eq[cycle];
        }
    }
    let mut inc_flat = vec![F2_128::from(0u64); cells * cycles];
    for cycle in 0..cycles {
        for cell in 0..cells {
            inc_flat[cell * cycles + cycle] = inc[cycle];
        }
    }
    let factors = vec![eq_flat, wa.clone(), inc_flat, val.clone(), ra.clone()];

    let gamma_copy = gamma;
    let (rounds, challenges) =
        sumcheck_terms(&factors, &vec![3usize; cells.trailing_zeros() as usize + cycle_bits], &mut transcript, move |folded| {
            (0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
                sum + folded[0][index]
                    * (folded[1][index] * folded[2][index]
                        + folded[1][index] * folded[3][index]
                        + gamma_copy * folded[4][index] * folded[3][index])
            })
        })?;
    let table_points = vec![P3BatchPoint {
        point: challenges.clone(),
        columns: (0..3).collect(),
    }];
    let cycle_challenges = &challenges[..cycle_bits];
    let input_points = vec![
        P3BatchPoint {
            point: cycle_point.clone(),
            columns: vec![1, 2],
        },
        P3BatchPoint {
            point: cycle_challenges.to_vec(),
            columns: vec![0],
        },
    ];
    let tables = pcs
        .open_batch(&[ra.clone(), wa.clone(), val.clone()], &table_points)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let inputs = pcs
        .open_batch(&[inc.clone(), read_value.clone(), write_value.clone()], &input_points)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    Ok(RwPcsProof {
        tables,
        table_values: vec![vec![
            eval_mle(&ra, &challenges),
            eval_mle(&wa, &challenges),
            eval_mle(&val, &challenges),
        ]],
        inputs,
        input_values: vec![
            vec![
                eval_mle(&read_value, &cycle_point),
                eval_mle(&write_value, &cycle_point),
            ],
            vec![eval_mle(&inc, cycle_challenges)],
        ],
        rounds,
        challenges,
    })
}

pub fn verify_rw_pcs(witness: &BinaryTwistWitness, proof: &RwPcsProof) -> Result<bool, ProofError> {
    verify_rw_pcs_shape(witness_shape(witness), proof)
}

pub fn verify_rw_pcs_shape(shape: LinearTwistShape, proof: &RwPcsProof) -> Result<bool, ProofError> {
    let cycles = shape.cycles;
    let cycle_bits = shape.cycle_bits();
    let mut transcript = Sha256Transcript::new("magnetar-rw-pcs");
    for commitment in [&proof.tables.commitment, &proof.inputs.commitment] {
        transcript.absorb(
            "commitment",
            &bincode::serialize(commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
        );
    }
    let gamma = sample_point(&mut transcript, 1)[0];
    let cycle_point = sample_point(&mut transcript, cycle_bits);
    let pcs = linear_pcs(cycles);
    let table_points = vec![P3BatchPoint {
        point: proof.challenges.clone(),
        columns: (0..3).collect(),
    }];
    let cycle_challenges = &proof.challenges[..cycle_bits];
    let input_points = vec![
        P3BatchPoint {
            point: cycle_point.clone(),
            columns: vec![1, 2],
        },
        P3BatchPoint {
            point: cycle_challenges.to_vec(),
            columns: vec![0],
        },
    ];
    let vt = pcs
        .verify_batch(&proof.tables, &table_points, &proof.table_values)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let vi = pcs
        .verify_batch(&proof.inputs, &input_points, &proof.input_values)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    if !(vt && vi) {
        return Ok(false);
    }
    let ra_eval = proof.table_values[0][0];
    let wa_eval = proof.table_values[0][1];
    let val_eval = proof.table_values[0][2];
    let read_eval = proof.input_values[0][0];
    let write_eval = proof.input_values[0][1];
    let inc_eval = proof.input_values[1][0];
    let claimed = write_eval + gamma * read_eval;
    let mut transcript = Sha256Transcript::new("magnetar-rw-pcs");
    for commitment in [&proof.tables.commitment, &proof.inputs.commitment] {
        transcript.absorb(
            "commitment",
            &bincode::serialize(commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
        );
    }
    let _ = sample_point(&mut transcript, 1);
    let _ = sample_point(&mut transcript, cycle_bits);
    let Some((final_sum, challenges)) =
        replay_terms_derived(&proof.rounds, claimed, &mut transcript)
    else {
        eprintln!("rw replay none claimed={:?}", claimed);
        return Ok(false);
    };
    if challenges != proof.challenges {
        return Ok(false);
    }
    let eq_final = eq_points_local(&cycle_point, cycle_challenges);
    let expected = eq_final
        * (wa_eval * (inc_eval + val_eval) + gamma * ra_eval * val_eval);
    Ok(final_sum == expected)
}

#[cfg(test)]
mod rw_pcs_tests {
    use super::tests::register_witness;
    use super::*;

    #[test]
    fn rw_pcs_round_trips() {
        let witness = register_witness();
        let proof = prove_rw_pcs(&witness).unwrap();
        assert!(verify_rw_pcs(&witness, &proof).unwrap());
        let mut tampered = proof;
        tampered.rounds[0][0] = tampered.rounds[0][0] + F2_128::from(1u64);
        assert!(!verify_rw_pcs(&witness, &tampered).unwrap());
    }
}

/// One-hot proof for a committed address matrix: PCS binds the RA/WA columns,
/// logup* proves each row is a basis vector or zero, and a second PCS opening
/// binds the logup position claims to the committed address bits and valid bit.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OneHotPcsProof {
    pub opening: P3BatchOpening,
    pub claims: Vec<F2_128>,
    pub address_opening: P3BatchOpening,
    pub address_values: Vec<F2_128>,
    pub position_point: Vec<F2_128>,
    pub logup: p3_multi_stark::logup_star::LogupStarProof<
        p3_binary_field::BinaryField128,
        p3_binary_field::BinaryField128,
    >,
}

type OneHotB = p3_binary_field::BinaryField128;

fn to_f2(value: OneHotB) -> F2_128 {
    use p3_binary_field::TowerLevel;
    F2_128::new(value.to_repr())
}

fn to_b(value: F2_128) -> OneHotB {
    use p3_binary_field::TowerLevel;
    OneHotB::from_repr(value.value())
}

fn embed_position(position: usize) -> OneHotB {
    use p3_field::Field;
    (0..usize::BITS as usize)
        .filter(|bit| (position >> bit) & 1 == 1)
        .map(|bit| OneHotB::interpolation_node(1 << bit))
        .sum()
}

fn onehot_columns(
    witness: &BinaryTwistWitness,
    write: bool,
) -> (Vec<Vec<F2_128>>, usize, usize) {
    let cells = 1usize << witness.address_bits;
    let cycles = witness.cycles.next_power_of_two().max(2);
    let source = if write {
        &witness.write_address
    } else {
        &witness.read_address
    };
    let mut columns = vec![vec![F2_128::from(0u64); cycles]; cells];
    for (cycle, row) in source.iter().enumerate() {
        for cell in 0..cells {
            columns[cell][cycle] = row[cell];
        }
    }
    (columns, cells, cycles)
}

fn address_bit_columns(
    witness: &BinaryTwistWitness,
    write: bool,
) -> (Vec<Vec<F2_128>>, Vec<F2_128>, usize, usize) {
    let cells = 1usize << witness.address_bits;
    let cycles = witness.cycles.next_power_of_two().max(2);
    let source = if write {
        &witness.write_address
    } else {
        &witness.read_address
    };
    let mut bits = vec![vec![F2_128::from(0u64); cycles]; witness.address_bits];
    let mut valid = vec![F2_128::from(0u64); cycles];
    for (cycle, row) in source.iter().enumerate() {
        let Some(cell) = row.iter().position(|value| value.value() == 1) else {
            continue;
        };
        valid[cycle] = F2_128::from(1u64);
        for (bit, column) in bits.iter_mut().enumerate() {
            column[cycle] = F2_128::from(((cell >> bit) & 1) as u64);
        }
    }
    (bits, valid, cells, cycles)
}

pub fn prove_onehot_pcs(
    witness: &BinaryTwistWitness,
    write: bool,
) -> Result<OneHotPcsProof, ProofError> {
    use p3_binary_field::{BinaryChallenger, BinaryField128, TowerLevel};
    use p3_challenger::HashChallenger;
    use p3_keccak::Keccak256Hash;
    use p3_multi_stark::logup_star::{
        LogupStarProof, Reader, ReaderWitness, TableWitness,
    };
    use p3_multilinear_util::point::Point;
    type B = BinaryField128;
    let (columns, cells, cycles) = onehot_columns(witness, write);
    let mut columns = columns;
    for column in &mut columns {
        for value in column.iter_mut() {
            *value = *value + F2_128::from(1u64);
        }
    }
    let (bits, valid, _, _) = address_bit_columns(witness, write);
    let mut address_columns = bits;
    address_columns.push(valid.clone());
    let pcs = linear_pcs(cycles);
    let commitment = pcs
        .commit_batch(&columns)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let address_commitment = pcs
        .commit_batch(&address_columns)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let mut transcript = Sha256Transcript::new("magnetar-onehot-pcs");
    for commitment in [&commitment, &address_commitment] {
        transcript.absorb(
            "commitment",
            &bincode::serialize(commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
        );
    }
    let point_f2 = sample_point(&mut transcript, cycles.trailing_zeros() as usize);
    let point_b = Point::new(point_f2.iter().rev().map(|value| to_b(*value)).collect());
    let claims = columns
        .iter()
        .map(|column| eval_mle(column, &point_f2))
        .collect::<Vec<_>>();
    let claims_b = claims.iter().map(|value| to_b(*value)).collect::<Vec<_>>();
    let readers = [Reader {
        point: &point_b,
        claims: &claims_b,
    }];
    let lookups = [p3_multi_stark::logup_star::TableLookup {
        num_variables: witness.address_bits + 1,
        readers: &readers,
    }];
    let positions = if write {
        &witness.write_address
    } else {
        &witness.read_address
    }
    .iter()
    .map(|row| {
        row.iter()
            .position(|value| value.value() == 1)
            .map_or(0, |cell| cells + cell)
    })
    .collect::<Vec<_>>();
    let mut positions = positions;
    positions.resize(cycles, 0);
    let reader_witnesses = [ReaderWitness { positions: &positions }];
    let table = (0..cells)
        .map(|column| {
            (0..2 * cells)
                .map(|row| {
                    if row == cells + column {
                        B::from_repr(0)
                    } else {
                        B::from_repr(magnetar_constraint::F2_128::from(1u64).value())
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let table_refs = table.iter().map(|row| row.as_slice()).collect::<Vec<_>>();
    let table_witness = [TableWitness {
        columns: &table_refs,
        readers: &reader_witnesses,
    }];
    let mut challenger = BinaryChallenger::<B, HashChallenger<u8, Keccak256Hash, 32>>::from_hasher(
        b"magnetar-onehot-pcs".to_vec(),
        Keccak256Hash,
    );
    let (logup, output) = LogupStarProof::<B, B>::prove(&lookups, &table_witness, &mut challenger);
    let position_point = Point::new(
        output
            .position_point
            .as_slice()
            .iter()
            .rev()
            .copied()
            .collect::<Vec<_>>(),
    );
    let position_point_f2 = position_point
        .as_slice()
        .iter()
        .map(|value| to_f2(*value))
        .collect::<Vec<_>>();
    let address_values = address_columns
        .iter()
        .map(|column| eval_mle(column, &position_point_f2))
        .collect::<Vec<_>>();
    let expected_position = address_values
        .iter()
        .enumerate()
        .fold(OneHotB::from_repr(0), |sum, (index, value)| {
            let coefficient = if index < witness.address_bits {
                embed_position(1usize << index)
            } else {
                embed_position(cells)
            };
            sum + coefficient * to_b(*value)
        });
    if output.tables[0].position_claims[0] != expected_position {
        return Err(ProofError::FinalOracle);
    }
    let points = vec![P3BatchPoint {
        point: point_f2.clone(),
        columns: (0..cells).collect(),
    }];
    let opening = pcs
        .open_batch(&columns, &points)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let address_points = vec![P3BatchPoint {
        point: position_point_f2.clone(),
        columns: (0..witness.address_bits + 1).collect(),
    }];
    let address_opening = pcs
        .open_batch(&address_columns, &address_points)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    Ok(OneHotPcsProof {
        opening,
        claims,
        address_opening,
        address_values,
        position_point: position_point_f2,
        logup,
    })
}

pub fn verify_onehot_pcs(
    witness: &BinaryTwistWitness,
    write: bool,
    proof: &OneHotPcsProof,
) -> Result<bool, ProofError> {
    verify_onehot_pcs_shape(witness_shape(witness), write, proof)
}

pub fn verify_onehot_pcs_shape(
    shape: LinearTwistShape,
    _write: bool,
    proof: &OneHotPcsProof,
) -> Result<bool, ProofError> {
    use p3_binary_field::{BinaryField128, TowerLevel};
    use p3_multi_stark::logup_star::{Reader, TableLookup};
    use p3_multilinear_util::point::Point;
    type B = BinaryField128;
    let cells = shape.cells();
    let cycles = shape.cycles;
    let address_columns = shape.address_bits + 1;
    let mut transcript = Sha256Transcript::new("magnetar-onehot-pcs");
    for commitment in [&proof.opening.commitment, &proof.address_opening.commitment] {
        transcript.absorb(
            "commitment",
            &bincode::serialize(commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
        );
    }
    let point_f2 = sample_point(&mut transcript, cycles.trailing_zeros() as usize);
    let point_b = Point::new(point_f2.iter().rev().map(|value| to_b(*value)).collect());
    let pcs = linear_pcs(cycles);
    let points = vec![P3BatchPoint {
        point: point_f2.clone(),
        columns: (0..cells).collect(),
    }];
    if !pcs
        .verify_batch(&proof.opening, &points, std::slice::from_ref(&proof.claims))
        .map_err(|error| ProofError::Pcs(error.to_string()))?
    {
        return Ok(false);
    }
    let claims_b = proof.claims.iter().map(|value| to_b(*value)).collect::<Vec<_>>();
    let readers = [Reader {
        point: &point_b,
        claims: &claims_b,
    }];
    let lookups = [TableLookup {
        num_variables: shape.address_bits + 1,
        readers: &readers,
    }];
    let mut challenger = p3_binary_field::BinaryChallenger::<B, p3_challenger::HashChallenger<u8, p3_keccak::Keccak256Hash, 32>>::from_hasher(
        b"magnetar-onehot-pcs".to_vec(),
        p3_keccak::Keccak256Hash,
    );
    let output = match proof.logup.verify(&lookups, &mut challenger) {
        Ok(output) => output,
        Err(_) => return Ok(false),
    };
    let table_point = output.table_point.clone();
    let table = (0..cells)
        .map(|column| {
            (0..2 * cells)
                .map(|row| {
                    if row == cells + column {
                        B::from_repr(0)
                    } else {
                        B::from_repr(magnetar_constraint::F2_128::from(1u64).value())
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    for (column, claim) in output.tables[0].column_claims.iter().enumerate() {
        let direct = p3_multilinear_util::poly::Poly::new(table[column].clone())
            .eval_ext::<B>(&table_point);
        if direct != *claim {
            return Ok(false);
        }
    }
    let position_point_f2 = output
        .position_point
        .as_slice()
        .iter()
        .rev()
        .map(|value| to_f2(*value))
        .collect::<Vec<_>>();
    if position_point_f2 != proof.position_point {
        return Ok(false);
    }
    let address_points = vec![P3BatchPoint {
        point: position_point_f2.clone(),
        columns: (0..address_columns).collect(),
    }];
    if !pcs
        .verify_batch(
            &proof.address_opening,
            &address_points,
            std::slice::from_ref(&proof.address_values),
        )
        .map_err(|error| ProofError::Pcs(error.to_string()))?
    {
        return Ok(false);
    }
    let expected_position = proof
        .address_values
        .iter()
        .enumerate()
        .fold(B::from_repr(0), |sum, (index, value)| {
            let coefficient = if index < shape.address_bits {
                embed_position(1usize << index)
            } else {
                embed_position(cells)
            };
            sum + coefficient * to_b(*value)
        });
    if output.tables[0].position_claims[0] != expected_position {
        return Ok(false);
    }
    Ok(true)
}
#[cfg(test)]
mod onehot_pcs_tests {
    use super::tests::register_witness;
    use super::*;

    #[test]
    fn onehot_pcs_round_trips() {
        let witness = register_witness();
        for write in [false, true] {
            let proof = prove_onehot_pcs(&witness, write).unwrap();
            assert!(verify_onehot_pcs(&witness, write, &proof).unwrap());
        }
        let mut tampered = prove_onehot_pcs(&witness, false).unwrap();
        tampered.claims[0] = tampered.claims[0] + F2_128::from(1u64);
        assert!(!verify_onehot_pcs(&witness, false, &tampered).unwrap());
    }
}

/// Combined standalone linear Twist proof for the read/write history.
///
/// This is the integration boundary used by the runtime bench: the RW and Val
/// relations are PCS-backed, and both address matrices are tied to committed
/// address bits through the one-hot lookup proofs.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LinearTwistProof {
    pub shape: LinearTwistShape,
    pub rw: RwPcsProof,
    pub val: ValPcsProof,
    pub read_onehot: OneHotPcsProof,
    pub write_onehot: OneHotPcsProof,
    pub final_state: FinalStateProof,
}

pub fn prove_linear_twist(
    witness: &BinaryTwistWitness,
) -> Result<LinearTwistProof, ProofError> {
    let shape = witness_shape(witness);
    let rw = prove_rw_pcs(witness)?;
    let final_state = prove_final_state(witness, &rw, shape)?;
    Ok(LinearTwistProof {
        shape,
        rw,
        val: prove_val_pcs(witness)?,
        read_onehot: prove_onehot_pcs(witness, false)?,
        write_onehot: prove_onehot_pcs(witness, true)?,
        final_state,
    })
}

pub fn verify_linear_twist(
    _witness: &BinaryTwistWitness,
    proof: &LinearTwistProof,
) -> Result<bool, ProofError> {
    verify_linear_twist_proof_only(proof)
}

/// Verify the standalone linear Twist proof without a witness.
pub fn verify_linear_twist_proof_only(
    proof: &LinearTwistProof,
) -> Result<bool, ProofError> {
    let shape = proof.shape;
    Ok(verify_rw_pcs_shape(shape, &proof.rw)?
        && verify_val_pcs_shape(shape, &proof.val)?
        && verify_onehot_pcs_shape(shape, false, &proof.read_onehot)?
        && verify_onehot_pcs_shape(shape, true, &proof.write_onehot)?
        && verify_final_state(&proof.rw, shape, &proof.final_state)?)
}

pub fn linear_twist_proof_bytes(proof: &LinearTwistProof) -> Result<usize, ProofError> {
    bincode::serialize(proof)
        .map(|bytes| bytes.len())
        .map_err(|error| ProofError::Pcs(error.to_string()))
}

#[cfg(test)]
mod linear_twist_tests {
    use super::tests::register_witness;
    use super::*;

    #[test]
    fn combined_linear_twist_round_trips() {
        let witness = register_witness();
        let proof = prove_linear_twist(&witness).unwrap();
        assert!(verify_linear_twist(&witness, &proof).unwrap());
        assert!(verify_linear_twist_proof_only(&proof).unwrap());
        let mut tampered = proof.clone();
        tampered.write_onehot.claims[0] =
            tampered.write_onehot.claims[0] + F2_128::from(1u64);
        assert!(!verify_linear_twist(&witness, &tampered).unwrap());
        let mut tampered = proof;
        tampered.final_state.final_value =
            tampered.final_state.final_value + F2_128::from(1u64);
        assert!(!verify_linear_twist(&witness, &tampered).unwrap());
    }
}

/// An outer commitment table that a linear Twist opening must match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LinearOuterTable {
    Address,
    Increment,
    Initial,
    Final,
    ReadValue,
    WriteValue,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LinearOuterClaim {
    pub table: LinearOuterTable,
    pub column: usize,
    pub point: Vec<F2_128>,
    pub value: F2_128,
}

/// Outer-table claims implied by the linear proof, for binding to an Access
/// commitment. Points are low-coordinate-first, as used by `eval_mle`.
pub fn linear_outer_claims(
    proof: &LinearTwistProof,
) -> Result<Vec<LinearOuterClaim>, ProofError> {
    let shape = proof.shape;
    let address_bits = shape.address_bits;
    let cycle_bits = shape.cycle_bits();
    let mut claims = Vec::new();
    // RW: read/write at the cycle point; inc at the final sumcheck point.
    let mut transcript = Sha256Transcript::new("magnetar-rw-pcs");
    for commitment in [&proof.rw.tables.commitment, &proof.rw.inputs.commitment] {
        transcript.absorb(
            "commitment",
            &bincode::serialize(commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
        );
    }
    let _gamma = sample_point(&mut transcript, 1)[0];
    let cycle_point = sample_point(&mut transcript, cycle_bits);
    let read_value = proof.rw.input_values[0][0];
    let write_value = proof.rw.input_values[0][1];
    claims.push(LinearOuterClaim {
        table: LinearOuterTable::ReadValue,
        column: 0,
        point: cycle_point.clone(),
        value: read_value,
    });
    claims.push(LinearOuterClaim {
        table: LinearOuterTable::WriteValue,
        column: 0,
        point: cycle_point.clone(),
        value: write_value,
    });
    let cell_point = proof.rw.challenges[cycle_bits..].to_vec();
    claims.push(LinearOuterClaim {
        table: LinearOuterTable::Initial,
        column: 0,
        point: cell_point.clone(),
        value: proof.final_state.initial,
    });
    let final_cycle = proof.rw.challenges[..cycle_bits].to_vec();
    claims.push(LinearOuterClaim {
        table: LinearOuterTable::Increment,
        column: 0,
        point: final_cycle,
        value: proof.rw.input_values[1][0],
    });
    // Val: initial at rk; inc at the Val sumcheck final point.
    let mut transcript = Sha256Transcript::new("magnetar-val-pcs");
    for commitment in [
        &proof.val.val_wa.commitment,
        &proof.val.inc.commitment,
        &proof.val.initial.commitment,
    ] {
        transcript.absorb(
            "commitment",
            &bincode::serialize(commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
        );
    }
    let rk = sample_point(&mut transcript, address_bits);
    let _rj = sample_point(&mut transcript, cycle_bits);
    claims.push(LinearOuterClaim {
        table: LinearOuterTable::Initial,
        column: 0,
        point: rk,
        value: proof.val.initial_value,
    });
    claims.push(LinearOuterClaim {
        table: LinearOuterTable::Final,
        column: 1,
        point: cell_point.clone(),
        value: proof.final_state.final_value,
    });
    claims.push(LinearOuterClaim {
        table: LinearOuterTable::Increment,
        column: 0,
        point: proof.val.challenges.clone(),
        value: proof.val.inc_value,
    });
    // Address bit/valid columns at the two logup position points.
    for (onehot, write) in [
        (&proof.read_onehot, false),
        (&proof.write_onehot, true),
    ] {
        for (index, value) in onehot.address_values.iter().enumerate() {
            let (table_column, is_valid) = if write {
                if index < address_bits {
                    (address_bits + index, false)
                } else {
                    (2 * address_bits + 1, true)
                }
            } else if index < address_bits {
                (index, false)
            } else {
                (2 * address_bits, true)
            };
            let _ = is_valid;
            claims.push(LinearOuterClaim {
                table: LinearOuterTable::Address,
                column: table_column,
                point: onehot.position_point.clone(),
                value: *value,
            });
        }
    }
    Ok(claims)
}

#[cfg(test)]
mod ram_onehot_tests {
    use magnetar_executor::execute;
    use magnetar_memory::BinaryTwistWitness;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    use super::*;

    #[test]
    fn write_onehot_ram_8192_round_trips() {
        let mut program = vec![
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
        ];
        for _ in 0..4096 {
            program.push(
                Instruction {
                    op: Op::Sd,
                    rd: 0,
                    rs1: 2,
                    rs2: 1,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
            );
            program.push(
                Instruction {
                    op: Op::Ld,
                    rd: 3,
                    rs1: 2,
                    rs2: 0,
                    imm: 0,
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
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 20_000,
            },
        )
        .unwrap();
        let witness = BinaryTwistWitness::from_trace(&trace).unwrap();
        for write in [false, true] {
            let proof = prove_onehot_pcs(&witness, write).unwrap();
            assert!(verify_onehot_pcs(&witness, write, &proof).unwrap());
        }
    }
}

/// Fixed-challenge sumcheck: the challenges are the RW final point, so the
/// terminal WA/Inc evaluations can be reused from the RW proof.
fn fixed_sumcheck(
    mut factors: Vec<Vec<F2_128>>,
    challenges: &[F2_128],
    summand: impl Fn(&[Vec<F2_128>]) -> F2_128,
) -> (Vec<Vec<F2_128>>, F2_128) {
    let mut rounds = Vec::with_capacity(challenges.len());
    let mut point = Vec::with_capacity(2);
    for challenge in challenges {
        let mut evaluations = Vec::with_capacity(3);
        for t in 0..3u64 {
            let t = F2_128::from(t);
            let mut folded = Vec::with_capacity(factors.len());
            for factor in &factors {
                let mut next = Vec::with_capacity(factor.len() / 2);
                for pair in factor.chunks_exact(2) {
                    next.push(pair[0] + t * (pair[1] - pair[0]));
                }
                folded.push(next);
            }
            evaluations.push(summand(&folded));
        }
        rounds.push(evaluations.clone());
        for factor in &mut factors {
            let mut next = Vec::with_capacity(factor.len() / 2);
            for pair in factor.chunks_exact(2) {
                next.push(pair[0] + *challenge * (pair[1] - pair[0]));
            }
            *factor = next;
        }
        point.push(*challenge);
    }
    let _ = point;
    (rounds, summand(&factors))
}

fn replay_fixed(
    rounds: &[Vec<F2_128>],
    claimed: F2_128,
    challenges: &[F2_128],
) -> Option<F2_128> {
    let mut claim = claimed;
    for (round, challenge) in rounds.iter().zip(challenges) {
        if round.len() != 3 || round[0] + round[1] != claim {
            return None;
        }
        claim = interpolate_f2(round, *challenge);
    }
    Some(claim)
}

fn interpolate_f2(values: &[F2_128], r: F2_128) -> F2_128 {
    let points = (0..values.len())
        .map(|index| F2_128::from(index as u64))
        .collect::<Vec<_>>();
    let mut result = F2_128::from(0u64);
    for (i, &value) in values.iter().enumerate() {
        let mut basis = F2_128::from(1u64);
        for (j, &point) in points.iter().enumerate() {
            if i != j {
                basis = basis * (r + point) * (points[i] + point).inv().expect("distinct");
            }
        }
        result = result + value * basis;
    }
    result
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FinalStateProof {
    pub opening: P3BatchOpening,
    pub initial: F2_128,
    pub final_value: F2_128,
    pub rounds: Vec<Vec<F2_128>>,
}

pub fn prove_final_state(
    witness: &BinaryTwistWitness,
    rw: &RwPcsProof,
    shape: LinearTwistShape,
) -> Result<FinalStateProof, ProofError> {
    let cells = shape.cells();
    let cycles = shape.cycles;
    let cycle_bits = shape.cycle_bits();
    let (_, wa, inc) = build_val_tables(witness);
    let cell_point = rw.challenges[cycle_bits..].to_vec();
    let eq_cell = eq_vector(&cell_point, cells);
    let mut eq_flat = vec![F2_128::from(0u64); cells * cycles];
    let mut inc_flat = vec![F2_128::from(0u64); cells * cycles];
    for (cell, eq_value) in eq_cell.iter().enumerate() {
        for (cycle, inc_value) in inc.iter().enumerate() {
            let index = cell * cycles + cycle;
            eq_flat[index] = *eq_value;
            inc_flat[index] = *inc_value;
        }
    }
    let factors = vec![eq_flat, wa, inc_flat];
    let summand = |folded: &[Vec<F2_128>]| {
        (0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
            sum + folded[0][index] * folded[1][index] * folded[2][index]
        })
    };
    let (rounds, _) = fixed_sumcheck(factors, &rw.challenges, summand);
    let mut initial = witness.initial.clone();
    initial.resize(cells, F2_128::from(0u64));
    let mut final_value = witness.final_value.clone();
    final_value.resize(cells, F2_128::from(0u64));
    let pcs = P3BinaryPcs::new(100);
    let columns = vec![initial, final_value];
    let commitment = pcs
        .commit_batch(&columns)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let mut transcript = Sha256Transcript::new("magnetar-final-state");
    transcript.absorb(
        "commitment",
        &bincode::serialize(&commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
    );
    let points = vec![P3BatchPoint {
        point: cell_point.clone(),
        columns: vec![0, 1],
    }];
    let initial_value = eval_mle(&columns[0], &cell_point);
    let final_value = eval_mle(&columns[1], &cell_point);
    let opening = pcs
        .open_batch(&columns, &points)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    Ok(FinalStateProof {
        opening,
        initial: initial_value,
        final_value,
        rounds,
    })
}

pub fn verify_final_state(
    rw: &RwPcsProof,
    shape: LinearTwistShape,
    proof: &FinalStateProof,
) -> Result<bool, ProofError> {
    let cells = shape.cells();
    let cycle_bits = shape.cycle_bits();
    let cell_point = rw.challenges[cycle_bits..].to_vec();
    let mut transcript = Sha256Transcript::new("magnetar-final-state");
    transcript.absorb(
        "commitment",
        &bincode::serialize(&proof.opening.commitment)
            .map_err(|error| ProofError::Pcs(error.to_string()))?,
    );
    let points = vec![P3BatchPoint {
        point: cell_point.clone(),
        columns: vec![0, 1],
    }];
    if !P3BinaryPcs::new(100)
        .verify_batch(
            &proof.opening,
            &points,
            &[vec![proof.initial, proof.final_value]],
        )
        .map_err(|error| ProofError::Pcs(error.to_string()))?
    {
        return Ok(false);
    }
    let claimed = proof.final_value - proof.initial;
    let Some(final_sum) = replay_fixed(&proof.rounds, claimed, &rw.challenges) else {
        return Ok(false);
    };
    let eq_cell = eq_points_local(&cell_point, &cell_point);
    let _ = cells;
    let expected = eq_cell * rw.table_values[0][1] * rw.input_values[1][0];
    Ok(final_sum == expected)
}
