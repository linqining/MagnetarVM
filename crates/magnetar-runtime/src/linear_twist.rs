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
    pub rwval: SharedRwValProof,
    pub onehot: SharedOneHotProof,
    pub final_state: FinalStateProof,
}

pub fn prove_linear_twist(
    witness: &BinaryTwistWitness,
) -> Result<LinearTwistProof, ProofError> {
    let shape = witness_shape(witness);
    let rwval = prove_shared_rwval(witness)?;
    let final_state = prove_final_state(witness, &rwval, shape)?;
    Ok(LinearTwistProof {
        shape,
        rwval,
        onehot: prove_shared_onehot(witness)?,
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
    Ok(verify_shared_rwval(shape, &proof.rwval)?
        && verify_shared_onehot(shape, &proof.onehot)?
        && verify_final_state(&proof.rwval, shape, &proof.final_state)?)
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
        tampered.onehot.write_claims[0] =
            tampered.onehot.write_claims[0] + F2_128::from(1u64);
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
    // Replay the shared RW reduction to recover its cycle point and rk.
    let mut transcript = Sha256Transcript::new("magnetar-rwval-shared");
    for commitment in [
        &proof.rwval.tables_opening.commitment,
        &proof.rwval.inputs_opening.commitment,
        &proof.rwval.initial_opening.commitment,
    ] {
        transcript.absorb(
            "commitment",
            &bincode::serialize(commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
        );
    }
    let gamma = sample_point(&mut transcript, 1)[0];
    let cycle_point = sample_point(&mut transcript, cycle_bits);
    let rw_claimed = proof.rwval.input_values[1][1] + gamma * proof.rwval.input_values[1][0];
    let Some(_) = replay_terms_derived(&proof.rwval.rw_rounds, rw_claimed, &mut transcript)
    else {
        return Err(ProofError::FinalOracle);
    };
    let rk = sample_point(&mut transcript, address_bits);
    claims.push(LinearOuterClaim {
        table: LinearOuterTable::ReadValue,
        column: 0,
        point: cycle_point.clone(),
        value: proof.rwval.input_values[1][0],
    });
    claims.push(LinearOuterClaim {
        table: LinearOuterTable::WriteValue,
        column: 0,
        point: cycle_point.clone(),
        value: proof.rwval.input_values[1][1],
    });
    let cell_point = proof.rwval.rw_challenges[cycle_bits..].to_vec();
    claims.push(LinearOuterClaim {
        table: LinearOuterTable::Initial,
        column: 0,
        point: cell_point.clone(),
        value: proof.final_state.initial,
    });
    claims.push(LinearOuterClaim {
        table: LinearOuterTable::Final,
        column: 1,
        point: cell_point,
        value: proof.final_state.final_value,
    });
    claims.push(LinearOuterClaim {
        table: LinearOuterTable::Increment,
        column: 0,
        point: proof.rwval.rw_challenges[..cycle_bits].to_vec(),
        value: proof.rwval.input_values[0][0],
    });
    claims.push(LinearOuterClaim {
        table: LinearOuterTable::Initial,
        column: 0,
        point: rk,
        value: proof.rwval.initial_value,
    });
    claims.push(LinearOuterClaim {
        table: LinearOuterTable::Increment,
        column: 0,
        point: proof.rwval.val_challenges.clone(),
        value: proof.rwval.input_values[2][0],
    });
    // Address bit/valid columns at the two logup position points.
    for (onehot, write) in [
        (&proof.onehot, false),
        (&proof.onehot, true),
    ] {
        let address_values = if write {
            &onehot.write_address_values
        } else {
            &onehot.read_address_values
        };
        for (index, value) in address_values.iter().enumerate() {
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
    rw: &SharedRwValProof,
    shape: LinearTwistShape,
) -> Result<FinalStateProof, ProofError> {
    let cells = shape.cells();
    let cycles = shape.cycles;
    let cycle_bits = shape.cycle_bits();
    let (_, wa, inc) = build_val_tables(witness);
    let cell_point = rw.rw_challenges[cycle_bits..].to_vec();
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
    let (rounds, _) = fixed_sumcheck(factors, &rw.rw_challenges, summand);
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
    rw: &SharedRwValProof,
    shape: LinearTwistShape,
    proof: &FinalStateProof,
) -> Result<bool, ProofError> {
    let cells = shape.cells();
    let cycle_bits = shape.cycle_bits();
    let cell_point = rw.rw_challenges[cycle_bits..].to_vec();
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
    let Some(final_sum) = replay_fixed(&proof.rounds, claimed, &rw.rw_challenges) else {
        return Ok(false);
    };
    let eq_cell = eq_points_local(&cell_point, &cell_point);
    let _ = cells;
    let expected = eq_cell * rw.table_values[0][1] * rw.input_values[0][0];
    Ok(final_sum == expected)
}

/// Val-evaluation proof that reuses the RW table/input commitments.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SharedValProof {
    pub tables_opening: P3BatchOpening,
    pub table_values: Vec<Vec<F2_128>>,
    pub inputs_opening: P3BatchOpening,
    pub inc_value: F2_128,
    pub initial_opening: P3BatchOpening,
    pub initial_value: F2_128,
    pub rounds: Vec<Vec<F2_128>>,
    pub challenges: Vec<F2_128>,
}

fn shared_rw_columns(
    witness: &BinaryTwistWitness,
) -> (Vec<Vec<F2_128>>, Vec<Vec<F2_128>>, usize, usize) {
    let cells = 1usize << witness.address_bits;
    let cycles = witness.cycles.next_power_of_two().max(2);
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
    (
        vec![ra, wa, val],
        vec![inc, read_value, write_value],
        cells,
        cycles,
    )
}

pub fn prove_val_shared(
    witness: &BinaryTwistWitness,
    rw: &RwPcsProof,
) -> Result<SharedValProof, ProofError> {
    let (tables_columns, input_columns, cells, cycles) = shared_rw_columns(witness);
    let cycle_bits = cycles.trailing_zeros() as usize;
    let (_, _, inc) = build_val_tables(witness);
    let val = &tables_columns[2];
    let wa = &tables_columns[1];
    let pcs = linear_pcs(cycles);
    let mut initial = witness.initial.clone();
    initial.resize(cells.next_power_of_two().max(2), F2_128::from(0u64));
    let initial_commit = pcs
        .commit_batch(std::slice::from_ref(&initial))
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let mut transcript = Sha256Transcript::new("magnetar-val-shared");
    for commitment in [
        &rw.tables.commitment,
        &rw.inputs.commitment,
        &initial_commit,
    ] {
        transcript.absorb(
            "commitment",
            &bincode::serialize(commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
        );
    }
    let rk = sample_point(&mut transcript, witness.address_bits);
    let rj = sample_point(&mut transcript, cycle_bits);
    let val_claim = eval_mle(val, &rj.iter().chain(&rk).copied().collect::<Vec<_>>());
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
    let table_points = vec![
        P3BatchPoint {
            point: val_point.clone(),
            columns: vec![2],
        },
        P3BatchPoint {
            point: wa_point.clone(),
            columns: vec![1],
        },
    ];
    let input_points = vec![P3BatchPoint {
        point: challenges.clone(),
        columns: vec![0],
    }];
    let initial_points = vec![P3BatchPoint {
        point: rk.clone(),
        columns: vec![0],
    }];
    let tables_opening = pcs
        .open_batch(&tables_columns, &table_points)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    if tables_opening.commitment.num_columns != rw.tables.commitment.num_columns
        || tables_opening.commitment.stacked_variables
            != rw.tables.commitment.stacked_variables
    {
        return Err(ProofError::Pcs("shared RW table commitment mismatch".into()));
    }
    let inputs_opening = pcs
        .open_batch(&input_columns, &input_points)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    if inputs_opening.commitment.num_columns != rw.inputs.commitment.num_columns
        || inputs_opening.commitment.stacked_variables
            != rw.inputs.commitment.stacked_variables
    {
        return Err(ProofError::Pcs("shared RW input commitment mismatch".into()));
    }
    let initial_opening = pcs
        .open_batch(std::slice::from_ref(&initial), &initial_points)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    Ok(SharedValProof {
        table_values: vec![vec![val_claim], vec![eval_mle(wa, &wa_point)]],
        inc_value: eval_mle(&inc, &challenges),
        initial_value: init_claim,
        tables_opening,
        inputs_opening,
        initial_opening,
        rounds,
        challenges,
    })
}

pub fn verify_val_shared(
    rw: &RwPcsProof,
    shape: LinearTwistShape,
    proof: &SharedValProof,
) -> Result<bool, ProofError> {
    let cycle_bits = shape.cycle_bits();
    let cycles = shape.cycles;
    let mut transcript = Sha256Transcript::new("magnetar-val-shared");
    for commitment in [
        &rw.tables.commitment,
        &rw.inputs.commitment,
        &proof.initial_opening.commitment,
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
    let table_points = vec![
        P3BatchPoint {
            point: val_point.clone(),
            columns: vec![2],
        },
        P3BatchPoint {
            point: wa_point.clone(),
            columns: vec![1],
        },
    ];
    let input_points = vec![P3BatchPoint {
        point: proof.challenges.clone(),
        columns: vec![0],
    }];
    let initial_points = vec![P3BatchPoint {
        point: rk.clone(),
        columns: vec![0],
    }];
    let pcs = linear_pcs(cycles);
    if !pcs
        .verify_batch(&proof.tables_opening, &table_points, &proof.table_values)
        .map_err(|error| ProofError::Pcs(error.to_string()))?
        || !pcs
            .verify_batch(
                &proof.inputs_opening,
                &input_points,
                &[vec![proof.inc_value]],
            )
            .map_err(|error| ProofError::Pcs(error.to_string()))?
        || !pcs
            .verify_batch(
                &proof.initial_opening,
                &initial_points,
                &[vec![proof.initial_value]],
            )
            .map_err(|error| ProofError::Pcs(error.to_string()))?
    {
        return Ok(false);
    }
    let val_claim = proof.table_values[0][0];
    let wa_eval = proof.table_values[1][0];
    let claimed = val_claim - proof.initial_value;
    let mut transcript = Sha256Transcript::new("magnetar-val-shared");
    for commitment in [
        &rw.tables.commitment,
        &rw.inputs.commitment,
        &proof.initial_opening.commitment,
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
mod shared_val_tests {
    use super::*;

    #[test]
    fn shared_val_reuses_rw_commitments() {
        let witness = crate::linear_twist::tests::register_witness();
        let shape = witness_shape(&witness);
        let rw = prove_rw_pcs(&witness).unwrap();
        let val = prove_val_shared(&witness, &rw).unwrap();
        assert!(verify_val_shared(&rw, shape, &val).unwrap());
        let rw_bytes = bincode::serialize(&rw).unwrap().len();
        let shared_bytes = bincode::serialize(&val).unwrap().len();
        let old_val_bytes = bincode::serialize(&prove_val_pcs(&witness).unwrap()).unwrap().len();
        eprintln!("shared_val={shared_bytes} old_val={old_val_bytes} rw={rw_bytes}");
        assert!(rw_bytes > 0);
    }
}

/// RW and Val sharing one table opening and one input opening.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SharedRwValProof {
    pub tables_opening: P3BatchOpening,
    pub table_values: Vec<Vec<F2_128>>,
    pub inputs_opening: P3BatchOpening,
    pub input_values: Vec<Vec<F2_128>>,
    pub initial_opening: P3BatchOpening,
    pub initial_value: F2_128,
    pub rw_rounds: Vec<Vec<F2_128>>,
    pub rw_challenges: Vec<F2_128>,
    pub val_rounds: Vec<Vec<F2_128>>,
    pub val_challenges: Vec<F2_128>,
}

pub fn prove_shared_rwval(
    witness: &BinaryTwistWitness,
) -> Result<SharedRwValProof, ProofError> {
    let shape = witness_shape(witness);
    let cells = shape.cells();
    let cycles = shape.cycles;
    let cycle_bits = shape.cycle_bits();
    let (tables_columns, input_columns, _, _) = shared_rw_columns(witness);
    let (_, _, inc) = build_val_tables(witness);
    let mut initial = witness.initial.clone();
    initial.resize(cells.next_power_of_two().max(2), F2_128::from(0u64));
    let pcs = linear_pcs(cycles);
    let table_commit = pcs
        .commit_batch(&tables_columns)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let input_commit = pcs
        .commit_batch(&input_columns)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let initial_commit = pcs
        .commit_batch(std::slice::from_ref(&initial))
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let mut transcript = Sha256Transcript::new("magnetar-rwval-shared");
    for commitment in [&table_commit, &input_commit, &initial_commit] {
        transcript.absorb(
            "commitment",
            &bincode::serialize(commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
        );
    }
    // RW sumcheck.
    let gamma = sample_point(&mut transcript, 1)[0];
    let cycle_point = sample_point(&mut transcript, cycle_bits);
    let eq = eq_vector(&cycle_point, cycles);
    let mut eq_flat = vec![F2_128::from(0u64); cells * cycles];
    let mut inc_flat = vec![F2_128::from(0u64); cells * cycles];
    for cycle in 0..cycles {
        for cell in 0..cells {
            eq_flat[cell * cycles + cycle] = eq[cycle];
            inc_flat[cell * cycles + cycle] = inc[cycle];
        }
    }
    let mut factors = vec![
        eq_flat,
        tables_columns[1].clone(),
        inc_flat,
        tables_columns[2].clone(),
        tables_columns[0].clone(),
    ];
    let gamma_copy = gamma;
    let (rw_rounds, rw_challenges) =
        sumcheck_terms(&factors, &vec![3usize; cells.trailing_zeros() as usize + cycle_bits], &mut transcript, move |folded| {
            (0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
                sum + folded[0][index]
                    * (folded[1][index] * folded[2][index]
                        + folded[1][index] * folded[3][index]
                        + gamma_copy * folded[4][index] * folded[3][index])
            })
        })?;
    factors.clear();
    // Val sumcheck.
    let rk = sample_point(&mut transcript, shape.address_bits);
    let rj = sample_point(&mut transcript, cycle_bits);
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
    let val_factors = vec![wa_at_rk, inc.clone(), suffix];
    let (val_rounds, val_challenges) =
        sumcheck_terms(&val_factors, &vec![3usize; cycle_bits], &mut transcript, |folded| {
            (0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
                sum + folded[0][index] * folded[1][index] * folded[2][index]
            })
        })?;
    let rw_cycle = rw_challenges[..cycle_bits].to_vec();
    let val_point = rj.iter().chain(&rk).copied().collect::<Vec<_>>();
    let wa_point = val_challenges.iter().chain(&rk).copied().collect::<Vec<_>>();
    let table_points = vec![
        P3BatchPoint {
            point: rw_challenges.clone(),
            columns: vec![0, 1, 2],
        },
        P3BatchPoint {
            point: val_point.clone(),
            columns: vec![2],
        },
        P3BatchPoint {
            point: wa_point.clone(),
            columns: vec![1],
        },
    ];
    let input_points = vec![
        P3BatchPoint {
            point: rw_cycle.clone(),
            columns: vec![0],
        },
        P3BatchPoint {
            point: cycle_point.clone(),
            columns: vec![1, 2],
        },
        P3BatchPoint {
            point: val_challenges.clone(),
            columns: vec![0],
        },
    ];
    let initial_points = vec![P3BatchPoint {
        point: rk.clone(),
        columns: vec![0],
    }];
    let tables_opening = pcs
        .open_batch(&tables_columns, &table_points)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let inputs_opening = pcs
        .open_batch(&input_columns, &input_points)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let initial_opening = pcs
        .open_batch(std::slice::from_ref(&initial), &initial_points)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    Ok(SharedRwValProof {
        table_values: vec![
            vec![
                eval_mle(&tables_columns[0], &rw_challenges),
                eval_mle(&tables_columns[1], &rw_challenges),
                eval_mle(&tables_columns[2], &rw_challenges),
            ],
            vec![eval_mle(&tables_columns[2], &val_point)],
            vec![eval_mle(&tables_columns[1], &wa_point)],
        ],
        input_values: vec![
            vec![eval_mle(&input_columns[0], &rw_cycle)],
            vec![
                eval_mle(&input_columns[1], &cycle_point),
                eval_mle(&input_columns[2], &cycle_point),
            ],
            vec![eval_mle(&input_columns[0], &val_challenges)],
        ],
        initial_value: eval_mle(&initial, &rk),
        tables_opening,
        inputs_opening,
        initial_opening,
        rw_rounds,
        rw_challenges,
        val_rounds,
        val_challenges,
    })
}

pub fn verify_shared_rwval(
    shape: LinearTwistShape,
    proof: &SharedRwValProof,
) -> Result<bool, ProofError> {
    let cycles = shape.cycles;
    let cycle_bits = shape.cycle_bits();
    let mut transcript = Sha256Transcript::new("magnetar-rwval-shared");
    for commitment in [
        &proof.tables_opening.commitment,
        &proof.inputs_opening.commitment,
        &proof.initial_opening.commitment,
    ] {
        transcript.absorb(
            "commitment",
            &bincode::serialize(commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
        );
    }
    let gamma = sample_point(&mut transcript, 1)[0];
    let cycle_point = sample_point(&mut transcript, cycle_bits);
    let rw_cycle = proof.rw_challenges[..cycle_bits].to_vec();
    let val_point = {
        // rk/rj are sampled after the RW reduction; replay first.
        let mut transcript = transcript.clone();
        let claimed = proof.input_values[1][1] + gamma * proof.input_values[1][0];
        let Some((rw_final, rw_challenges)) =
            replay_terms_derived(&proof.rw_rounds, claimed, &mut transcript)
        else {
            return Ok(false);
        };
        if rw_challenges != proof.rw_challenges {
            return Ok(false);
        }
        let _ = rw_final;
        let rk = sample_point(&mut transcript, shape.address_bits);
        let rj = sample_point(&mut transcript, cycle_bits);
        rj.iter().chain(&rk).copied().collect::<Vec<_>>()
    };
    let wa_point = {
        // Recompute Val point from the transcript after RW replay.
        let mut transcript = Sha256Transcript::new("magnetar-rwval-shared");
        for commitment in [
            &proof.tables_opening.commitment,
            &proof.inputs_opening.commitment,
            &proof.initial_opening.commitment,
        ] {
            transcript.absorb(
                "commitment",
                &bincode::serialize(commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
            );
        }
        let _ = sample_point(&mut transcript, 1);
        let _ = sample_point(&mut transcript, cycle_bits);
        let claimed = proof.input_values[1][1] + gamma * proof.input_values[1][0];
        let Some(_) = replay_terms_derived(&proof.rw_rounds, claimed, &mut transcript) else {
            return Ok(false);
        };
        let rk = sample_point(&mut transcript, shape.address_bits);
        proof.val_challenges.iter().chain(&rk).copied().collect::<Vec<_>>()
    };
    let table_points = vec![
        P3BatchPoint {
            point: proof.rw_challenges.clone(),
            columns: vec![0, 1, 2],
        },
        P3BatchPoint {
            point: val_point,
            columns: vec![2],
        },
        P3BatchPoint {
            point: wa_point,
            columns: vec![1],
        },
    ];
    let input_points = vec![
        P3BatchPoint {
            point: rw_cycle,
            columns: vec![0],
        },
        P3BatchPoint {
            point: cycle_point.clone(),
            columns: vec![1, 2],
        },
        P3BatchPoint {
            point: proof.val_challenges.clone(),
            columns: vec![0],
        },
    ];
    let initial_points = vec![P3BatchPoint {
        point: {
            let mut transcript = Sha256Transcript::new("magnetar-rwval-shared");
            for commitment in [
                &proof.tables_opening.commitment,
                &proof.inputs_opening.commitment,
                &proof.initial_opening.commitment,
            ] {
                transcript.absorb(
                    "commitment",
                    &bincode::serialize(commitment)
                        .map_err(|error| ProofError::Pcs(error.to_string()))?,
                );
            }
            let _ = sample_point(&mut transcript, 1);
            let _ = sample_point(&mut transcript, cycle_bits);
            let claimed = proof.input_values[1][1] + gamma * proof.input_values[1][0];
            let Some(_) = replay_terms_derived(&proof.rw_rounds, claimed, &mut transcript) else {
                return Ok(false);
            };
            sample_point(&mut transcript, shape.address_bits)
        },
        columns: vec![0],
    }];
    let pcs = linear_pcs(cycles);
    let tables_ok = pcs
        .verify_batch(&proof.tables_opening, &table_points, &proof.table_values)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let inputs_ok = pcs
        .verify_batch(&proof.inputs_opening, &input_points, &proof.input_values)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let initial_ok = pcs
        .verify_batch(
            &proof.initial_opening,
            &initial_points,
            &[vec![proof.initial_value]],
        )
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    if !(tables_ok && inputs_ok && initial_ok) {
        return Ok(false);
    }
    // RW reduction.
    let mut transcript = Sha256Transcript::new("magnetar-rwval-shared");
    for commitment in [
        &proof.tables_opening.commitment,
        &proof.inputs_opening.commitment,
        &proof.initial_opening.commitment,
    ] {
        transcript.absorb(
            "commitment",
            &bincode::serialize(commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
        );
    }
    let _ = sample_point(&mut transcript, 1);
    let _ = sample_point(&mut transcript, cycle_bits);
    let claimed = proof.input_values[1][1] + gamma * proof.input_values[1][0];
    let Some((rw_final, rw_challenges)) =
        replay_terms_derived(&proof.rw_rounds, claimed, &mut transcript)
    else {
        return Ok(false);
    };
    if rw_challenges != proof.rw_challenges {
        return Ok(false);
    }
    let eq_final = eq_points_local(&cycle_point, &proof.rw_challenges[..cycle_bits]);
    let rw_expected = eq_final
        * (proof.table_values[0][1]
            * (proof.input_values[0][0] + proof.table_values[0][2])
            + gamma * proof.table_values[0][0] * proof.table_values[0][2]);
    if rw_final != rw_expected {
        return Ok(false);
    }
    // Val reduction.
    let rk = sample_point(&mut transcript, shape.address_bits);
    let rj = sample_point(&mut transcript, cycle_bits);
    let claimed_val = proof.table_values[1][0] - proof.initial_value;
    let Some((val_final, val_challenges)) =
        replay_terms_derived(&proof.val_rounds, claimed_val, &mut transcript)
    else {
        return Ok(false);
    };
    if val_challenges != proof.val_challenges {
        return Ok(false);
    }
    let lt_eval = crate::binary_twist::lt_mle(&val_challenges, &rj, cycles);
    let val_expected = proof.table_values[2][0] * proof.input_values[2][0] * lt_eval;
    let _ = rk;
    Ok(val_final == val_expected)
}

#[cfg(test)]
mod shared_rwval_tests {
    use super::*;

    #[test]
    fn shared_rwval_round_trips() {
        let witness = crate::linear_twist::tests::register_witness();
        let shape = witness_shape(&witness);
        let proof = prove_shared_rwval(&witness).unwrap();
        assert!(verify_shared_rwval(shape, &proof).unwrap());
        let shared = bincode::serialize(&proof).unwrap().len();
        let old = bincode::serialize(&prove_rw_pcs(&witness).unwrap()).unwrap().len()
            + bincode::serialize(&prove_val_pcs(&witness).unwrap()).unwrap().len();
        eprintln!("shared_rwval={shared} old_rw_val={old}");
    }
}

/// One-hot proof covering both read and write address matrices.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SharedOneHotProof {
    pub opening: P3BatchOpening,
    pub read_claims: Vec<F2_128>,
    pub write_claims: Vec<F2_128>,
    pub read_address_values: Vec<F2_128>,
    pub write_address_values: Vec<F2_128>,
    pub position_point: Vec<F2_128>,
    pub logup: p3_multi_stark::logup_star::LogupStarProof<
        p3_binary_field::BinaryField128,
        p3_binary_field::BinaryField128,
    >,
}

pub fn prove_shared_onehot(
    witness: &BinaryTwistWitness,
) -> Result<SharedOneHotProof, ProofError> {
    use p3_binary_field::{BinaryChallenger, BinaryField128, TowerLevel};
    use p3_challenger::HashChallenger;
    use p3_keccak::Keccak256Hash;
    use p3_multi_stark::logup_star::{
        LogupStarProof, Reader, ReaderWitness, TableWitness,
    };
    use p3_multilinear_util::point::Point;
    type B = BinaryField128;
    let (read_columns, cells, cycles) = onehot_columns(witness, false);
    let (write_columns, _, _) = onehot_columns(witness, true);
    let adjust = |mut columns: Vec<Vec<F2_128>>| {
        for column in &mut columns {
            for value in column.iter_mut() {
                *value = *value + F2_128::from(1u64);
            }
        }
        columns
    };
    let read_columns = adjust(read_columns);
    let write_columns = adjust(write_columns);
    let (read_bits, read_valid, _, _) = address_bit_columns(witness, false);
    let (write_bits, write_valid, _, _) = address_bit_columns(witness, true);
    let mut read_address = read_bits;
    read_address.push(read_valid);
    let mut write_address = write_bits;
    write_address.push(write_valid);
    let mut columns = Vec::new();
    columns.extend(read_columns.iter().cloned());
    columns.extend(write_columns.iter().cloned());
    columns.extend(read_address.iter().cloned());
    columns.extend(write_address.iter().cloned());
    let table_count = 2 * cells;
    let address_width = witness.address_bits + 1;
    let pcs = linear_pcs(cycles);
    let commitment = pcs
        .commit_batch(&columns)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let mut transcript = Sha256Transcript::new("magnetar-onehot-shared");
    transcript.absorb(
        "commitment",
        &bincode::serialize(&commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
    );
    let point_f2 = sample_point(&mut transcript, cycles.trailing_zeros() as usize);
    let point_b = Point::new(point_f2.iter().rev().map(|value| to_b(*value)).collect());
    let read_claims = read_columns
        .iter()
        .map(|column| eval_mle(column, &point_f2))
        .collect::<Vec<_>>();
    let write_claims = write_columns
        .iter()
        .map(|column| eval_mle(column, &point_f2))
        .collect::<Vec<_>>();
    let read_claims_b = read_claims.iter().map(|value| to_b(*value)).collect::<Vec<_>>();
    let write_claims_b = write_claims.iter().map(|value| to_b(*value)).collect::<Vec<_>>();
    let readers = [
        Reader {
            point: &point_b,
            claims: &read_claims_b,
        },
        Reader {
            point: &point_b,
            claims: &write_claims_b,
        },
    ];
    let lookups = [p3_multi_stark::logup_star::TableLookup {
        num_variables: witness.address_bits + 1,
        readers: &readers,
    }];
    let read_positions = witness
        .read_address
        .iter()
        .map(|row| {
            row.iter()
                .position(|value| value.value() == 1)
                .map_or(0, |cell| cells + cell)
        })
        .collect::<Vec<_>>();
    let write_positions = witness
        .write_address
        .iter()
        .map(|row| {
            row.iter()
                .position(|value| value.value() == 1)
                .map_or(0, |cell| cells + cell)
        })
        .collect::<Vec<_>>();
    let mut read_positions = read_positions;
    read_positions.resize(cycles, 0);
    let mut write_positions = write_positions;
    write_positions.resize(cycles, 0);
    let reader_witnesses = [
        ReaderWitness {
            positions: &read_positions,
        },
        ReaderWitness {
            positions: &write_positions,
        },
    ];
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
        b"magnetar-onehot-shared".to_vec(),
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
    let read_address_values = read_address
        .iter()
        .map(|column| eval_mle(column, &position_point_f2))
        .collect::<Vec<_>>();
    let write_address_values = write_address
        .iter()
        .map(|column| eval_mle(column, &position_point_f2))
        .collect::<Vec<_>>();
    let expected = |values: &[F2_128]| {
        values
            .iter()
            .enumerate()
            .fold(OneHotB::from_repr(0), |sum, (index, value)| {
                let coefficient = if index < witness.address_bits {
                    embed_position(1usize << index)
                } else {
                    embed_position(cells)
                };
                sum + coefficient * to_b(*value)
            })
    };
    if output.tables[0].position_claims[0] != expected(&read_address_values)
        || output.tables[0].position_claims[1] != expected(&write_address_values)
    {
        return Err(ProofError::FinalOracle);
    }
    let points = vec![
        P3BatchPoint {
            point: point_f2.clone(),
            columns: (0..table_count).collect(),
        },
        P3BatchPoint {
            point: position_point_f2.clone(),
            columns: (table_count..columns.len()).collect(),
        },
    ];
    let values = vec![
        read_claims
            .iter()
            .chain(&write_claims)
            .copied()
            .collect::<Vec<_>>(),
        read_address_values
            .iter()
            .chain(&write_address_values)
            .copied()
            .collect::<Vec<_>>(),
    ];
    let opening = pcs
        .open_batch(&columns, &points)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let _ = pcs
        .verify_batch(&opening, &points, &values)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let _ = address_width;
    Ok(SharedOneHotProof {
        opening,
        read_claims,
        write_claims,
        read_address_values,
        write_address_values,
        position_point: position_point_f2,
        logup,
    })
}

pub fn verify_shared_onehot(
    shape: LinearTwistShape,
    proof: &SharedOneHotProof,
) -> Result<bool, ProofError> {
    use p3_binary_field::{BinaryField128, TowerLevel};
    use p3_multi_stark::logup_star::{Reader, TableLookup};
    use p3_multilinear_util::point::Point;
    type B = BinaryField128;
    let cells = shape.cells();
    let cycles = shape.cycles;
    let table_count = 2 * cells;
    let address_width = shape.address_bits + 1;
    let mut transcript = Sha256Transcript::new("magnetar-onehot-shared");
    transcript.absorb(
        "commitment",
        &bincode::serialize(&proof.opening.commitment)
            .map_err(|error| ProofError::Pcs(error.to_string()))?,
    );
    let point_f2 = sample_point(&mut transcript, cycles.trailing_zeros() as usize);
    let point_b = Point::new(point_f2.iter().rev().map(|value| to_b(*value)).collect());
    let read_claims_b = proof.read_claims.iter().map(|value| to_b(*value)).collect::<Vec<_>>();
    let write_claims_b = proof
        .write_claims
        .iter()
        .map(|value| to_b(*value))
        .collect::<Vec<_>>();
    let readers = [
        Reader {
            point: &point_b,
            claims: &read_claims_b,
        },
        Reader {
            point: &point_b,
            claims: &write_claims_b,
        },
    ];
    let lookups = [TableLookup {
        num_variables: shape.address_bits + 1,
        readers: &readers,
    }];
    let mut challenger = p3_binary_field::BinaryChallenger::<B, p3_challenger::HashChallenger<u8, p3_keccak::Keccak256Hash, 32>>::from_hasher(
        b"magnetar-onehot-shared".to_vec(),
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
    let all_points = vec![
        P3BatchPoint {
            point: point_f2.clone(),
            columns: (0..table_count).collect(),
        },
        P3BatchPoint {
            point: position_point_f2.clone(),
            columns: (table_count..table_count + 2 * address_width).collect(),
        },
    ];
    let all_values = vec![
        proof
            .read_claims
            .iter()
            .chain(&proof.write_claims)
            .copied()
            .collect::<Vec<_>>(),
        proof
            .read_address_values
            .iter()
            .chain(&proof.write_address_values)
            .copied()
            .collect::<Vec<_>>(),
    ];
    let pcs = linear_pcs(cycles);
    if !pcs
        .verify_batch(&proof.opening, &all_points, &all_values)
        .map_err(|error| ProofError::Pcs(error.to_string()))?
    {
        return Ok(false);
    }
    let expected = |values: &[F2_128]| {
        values
            .iter()
            .enumerate()
            .fold(B::from_repr(0), |sum, (index, value)| {
                let coefficient = if index < shape.address_bits {
                    embed_position(1usize << index)
                } else {
                    embed_position(cells)
                };
                sum + coefficient * to_b(*value)
            })
    };
    Ok(output.tables[0].position_claims[0] == expected(&proof.read_address_values)
        && output.tables[0].position_claims[1] == expected(&proof.write_address_values))
}

#[cfg(test)]
mod shared_onehot_tests {
    use super::*;

    #[test]
    fn shared_onehot_round_trips() {
        let witness = crate::linear_twist::tests::register_witness();
        let shape = witness_shape(&witness);
        let proof = prove_shared_onehot(&witness).unwrap();
        assert!(verify_shared_onehot(shape, &proof).unwrap());
        let shared = bincode::serialize(&proof).unwrap().len();
        let old = bincode::serialize(&prove_onehot_pcs(&witness, false).unwrap()).unwrap().len()
            + bincode::serialize(&prove_onehot_pcs(&witness, true).unwrap()).unwrap().len();
        eprintln!("shared_onehot={shared} old_onehot={old}");
        assert!(shared > 0);
    }
}
