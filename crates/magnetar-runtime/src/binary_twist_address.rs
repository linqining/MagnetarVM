//! Address Boolean/multiplicity and collision checks for BinaryTwist (d = 1).
//!
//! `sumcheck_collision` folds the address-restricted polynomial
//! `E_r(J) = eA(r, J)` and cubes the folded polynomial in every round. It does
//! not cube precomputed Boolean values: MLE and pointwise cubing do not commute.

use magnetar_constraint::{Field, F2_128};
use magnetar_memory::BinaryTwistWitness;
use magnetar_pcs::{P3BinaryPcs, P3Commitment, P3Opening};
use magnetar_proof::{Pcs, ProofError};
use magnetar_transcript::Sha256Transcript;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddressMultiplicityProof {
    pub lambda: F2_128,
    pub rounds: Vec<[F2_128; 4]>,
    pub a_eval: F2_128,
    pub opening: P3Opening,
    pub collision_rounds: Vec<[F2_128; 5]>,
    pub a_r_eval: F2_128,
    pub a_rp_eval: F2_128,
    pub r_opening: P3Opening,
    pub rp_opening: P3Opening,
}

pub fn prove_address_multiplicity(
    witness: &BinaryTwistWitness,
    write: bool,
) -> Result<AddressMultiplicityProof, ProofError> {
    let cells = witness.initial.len();
    let cycles = witness.cycles.next_power_of_two();
    let address_bits = cells.trailing_zeros() as usize;
    let cycle_bits = cycles.trailing_zeros() as usize;
    let (table, expected) = table_and_flags(witness, write, cells, cycles);
    let pcs = P3BinaryPcs::new(100);
    let commitment = pcs.commit(&table)?;

    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-address");
    absorb_commitment(&mut transcript, &commitment);
    let lambda = challenge(&mut transcript, "lambda");
    let rho = sample_point(&mut transcript, cycle_bits);
    let eq = eq_index(&rho, address_bits, cycle_bits);
    let target = target_vector(&eq, &expected, cells);
    let (rounds, challenges) =
        sumcheck_boolean_multiplicity(&table, &eq, &target, lambda, &mut transcript)?;
    let a_eval = fold_all(&table, &challenges);
    let opening = pcs.open(&table, &challenges)?;

    let (r, r_prime, c) = sample_collision_point(&mut transcript, address_bits);
    let rho_cycle = sample_point(&mut transcript, cycle_bits);
    let cycle_weights = eq_table(&rho_cycle, cycles);
    let mut a_r = vec![F2_128::from(0u64); cycles];
    let mut a_rp = vec![F2_128::from(0u64); cycles];
    for cycle in 0..cycles {
        for cell in 0..cells {
            let value = table[cell + cells * cycle];
            a_r[cycle] = a_r[cycle] + eq_at(&r, cell) * value;
            a_rp[cycle] = a_rp[cycle] + eq_at(&r_prime, cell) * value;
        }
    }
    let (collision_rounds, collision_challenges) =
        sumcheck_collision(&a_r, &a_rp, &cycle_weights, c, &mut transcript)?;
    let mut r_point = r;
    r_point.extend_from_slice(&collision_challenges);
    let mut rp_point = r_prime;
    rp_point.extend_from_slice(&collision_challenges);
    Ok(AddressMultiplicityProof {
        lambda,
        rounds,
        a_eval,
        opening,
        collision_rounds,
        a_r_eval: fold_all(&table, &r_point),
        a_rp_eval: fold_all(&table, &rp_point),
        r_opening: pcs.open(&table, &r_point)?,
        rp_opening: pcs.open(&table, &rp_point)?,
    })
}

pub fn verify_address_multiplicity(
    proof: &AddressMultiplicityProof,
    write: bool,
    witness: &BinaryTwistWitness,
) -> Result<bool, ProofError> {
    let pcs = P3BinaryPcs::new(100);
    let cells = witness.initial.len();
    let cycles = witness.cycles.next_power_of_two();
    let address_bits = cells.trailing_zeros() as usize;
    let cycle_bits = cycles.trailing_zeros() as usize;
    let (_, expected) = table_and_flags(witness, write, cells, cycles);
    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-address");
    absorb_commitment(&mut transcript, &proof.opening.commitment);
    if challenge(&mut transcript, "lambda") != proof.lambda {
        return Ok(false);
    }
    let rho = sample_point(&mut transcript, cycle_bits);
    let eq = eq_index(&rho, address_bits, cycle_bits);
    let target = target_vector(&eq, &expected, cells);
    let mut sum = F2_128::from(0u64);
    let mut eq_folded = eq;
    let mut target_folded = target;
    let mut challenges = Vec::with_capacity(proof.rounds.len());
    for round in &proof.rounds {
        if round[0] + round[1] != sum {
            return Ok(false);
        }
        for value in round {
            transcript.absorb("round", &value.value().to_le_bytes());
        }
        let challenge = challenge(&mut transcript, "sumcheck");
        challenges.push(challenge);
        sum = evaluate_round4(round, challenge);
        eq_folded = fold(&eq_folded, challenge);
        target_folded = fold(&target_folded, challenge);
    }
    if eq_folded.len() != 1 || target_folded.len() != 1 {
        return Ok(false);
    }
    let expected_sum = proof.a_eval * (proof.a_eval + F2_128::from(1u64))
        + proof.lambda * (proof.a_eval * eq_folded[0] + target_folded[0]);
    if sum != expected_sum {
        return Ok(false);
    }

    let (r, r_prime, c) = sample_collision_point(&mut transcript, address_bits);
    let rho_cycle = sample_point(&mut transcript, cycle_bits);
    let mut cycle_weights = eq_table(&rho_cycle, cycles);
    let mut collision_sum = F2_128::from(0u64);
    let mut collision_challenges = Vec::with_capacity(proof.collision_rounds.len());
    for round in &proof.collision_rounds {
        if round[0] + round[1] != collision_sum {
            return Ok(false);
        }
        for value in round {
            transcript.absorb("round", &value.value().to_le_bytes());
        }
        let challenge = challenge(&mut transcript, "sumcheck");
        collision_challenges.push(challenge);
        collision_sum = evaluate_round5(round, challenge);
        cycle_weights = fold(&cycle_weights, challenge);
    }
    if cycle_weights.len() != 1 {
        return Ok(false);
    }
    let final_collision =
        cycle_weights[0] * (proof.a_r_eval * proof.a_r_eval * proof.a_r_eval + c * proof.a_rp_eval);
    if collision_sum != final_collision {
        return Ok(false);
    }
    let mut r_point = r;
    r_point.extend_from_slice(&collision_challenges);
    let mut rp_point = r_prime;
    rp_point.extend_from_slice(&collision_challenges);
    let boolean_ok = pcs.verify(
        &proof.opening.commitment,
        &challenges,
        proof.a_eval,
        &proof.opening,
    )?;
    let r_ok = pcs.verify(
        &proof.r_opening.commitment,
        &r_point,
        proof.a_r_eval,
        &proof.r_opening,
    )?;
    let rp_ok = pcs.verify(
        &proof.rp_opening.commitment,
        &rp_point,
        proof.a_rp_eval,
        &proof.rp_opening,
    )?;
    Ok(boolean_ok && r_ok && rp_ok)
}

pub(crate) fn sumcheck_boolean_multiplicity(
    table: &[F2_128],
    eq: &[F2_128],
    target: &[F2_128],
    lambda: F2_128,
    transcript: &mut Sha256Transcript,
) -> Result<(Vec<[F2_128; 4]>, Vec<F2_128>), ProofError> {
    let len = table.len();
    if eq.len() != len || target.len() != len {
        return Err(ProofError::DimensionMismatch);
    }
    let rounds = len.trailing_zeros() as usize;
    let mut a = table.to_vec();
    let mut eq = eq.to_vec();
    let mut target = target.to_vec();
    let mut polynomials = Vec::with_capacity(rounds);
    let mut challenges = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let mut polynomial = [F2_128::from(0u64); 4];
        for (t, coefficient) in polynomial.iter_mut().enumerate() {
            let t = F2_128::from(t as u64);
            let a_t = fold(&a, t);
            let eq_t = fold(&eq, t);
            let target_t = fold(&target, t);
            *coefficient = (0..a_t.len()).fold(F2_128::from(0u64), |sum, index| {
                sum + a_t[index] * (a_t[index] + F2_128::from(1u64))
                    + lambda * (a_t[index] * eq_t[index] + target_t[index])
            });
        }
        for value in &polynomial {
            transcript.absorb("round", &value.value().to_le_bytes());
        }
        let challenge = challenge(transcript, "sumcheck");
        a = fold(&a, challenge);
        eq = fold(&eq, challenge);
        target = fold(&target, challenge);
        polynomials.push(polynomial);
        challenges.push(challenge);
    }
    Ok((polynomials, challenges))
}

pub(crate) fn sumcheck_collision(
    a_r: &[F2_128],
    a_rp: &[F2_128],
    eq: &[F2_128],
    c: F2_128,
    transcript: &mut Sha256Transcript,
) -> Result<(Vec<[F2_128; 5]>, Vec<F2_128>), ProofError> {
    let len = a_r.len();
    if a_rp.len() != len || eq.len() != len {
        return Err(ProofError::DimensionMismatch);
    }
    let rounds = len.trailing_zeros() as usize;
    let mut a_r = a_r.to_vec();
    let mut a_rp = a_rp.to_vec();
    let mut eq = eq.to_vec();
    let mut polynomials = Vec::with_capacity(rounds);
    let mut challenges = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let mut polynomial = [F2_128::from(0u64); 5];
        for (t, coefficient) in polynomial.iter_mut().enumerate() {
            let t = F2_128::from(t as u64);
            let r_t = fold(&a_r, t);
            let rp_t = fold(&a_rp, t);
            let eq_t = fold(&eq, t);
            *coefficient = (0..r_t.len()).fold(F2_128::from(0u64), |sum, index| {
                sum + eq_t[index] * (r_t[index] * r_t[index] * r_t[index] + c * rp_t[index])
            });
        }
        for value in &polynomial {
            transcript.absorb("round", &value.value().to_le_bytes());
        }
        let challenge = challenge(transcript, "sumcheck");
        a_r = fold(&a_r, challenge);
        a_rp = fold(&a_rp, challenge);
        eq = fold(&eq, challenge);
        polynomials.push(polynomial);
        challenges.push(challenge);
    }
    Ok((polynomials, challenges))
}

pub(crate) fn table_and_flags(
    witness: &BinaryTwistWitness,
    write: bool,
    cells: usize,
    cycles: usize,
) -> (Vec<F2_128>, Vec<F2_128>) {
    let mut table = vec![F2_128::from(0u64); cells * cycles];
    let mut expected = vec![F2_128::from(0u64); cycles];
    for cycle in 0..witness.cycles {
        let addresses = if write {
            &witness.write_address[cycle]
        } else {
            &witness.read_address[cycle]
        };
        table[cycle * cells..(cycle + 1) * cells].copy_from_slice(addresses);
        expected[cycle] = F2_128::from(u64::from(
            !write || addresses.iter().any(|bit| bit.value() != 0),
        ));
    }
    (table, expected)
}

pub(crate) fn target_vector(eq: &[F2_128], expected: &[F2_128], cells: usize) -> Vec<F2_128> {
    eq.iter()
        .enumerate()
        .map(|(index, weight)| {
            if index % cells == 0 {
                *weight * expected[index / cells]
            } else {
                F2_128::from(0u64)
            }
        })
        .collect()
}

fn absorb_commitment(transcript: &mut Sha256Transcript, commitment: &P3Commitment) {
    transcript.absorb(
        "address",
        &bincode::serialize(commitment).unwrap_or_default(),
    );
}

fn sample_point(transcript: &mut Sha256Transcript, length: usize) -> Vec<F2_128> {
    (0..length)
        .map(|_| challenge(transcript, "point"))
        .collect()
}

pub(crate) fn challenge(transcript: &mut Sha256Transcript, label: &str) -> F2_128 {
    let bytes = transcript.challenge_32(label);
    let mut value = [0u8; 16];
    value.copy_from_slice(&bytes[..16]);
    F2_128::from_bits(u128::from_le_bytes(value))
}

pub(crate) fn eq_table(point: &[F2_128], cycles: usize) -> Vec<F2_128> {
    (0..cycles).map(|index| eq_at(point, index)).collect()
}

pub(crate) fn eq_at(point: &[F2_128], index: usize) -> F2_128 {
    point
        .iter()
        .enumerate()
        .fold(F2_128::from(1u64), |acc, (bit, r)| {
            if (index >> bit) & 1 == 1 {
                acc * *r
            } else {
                acc * (F2_128::from(1u64) + *r)
            }
        })
}

pub(crate) fn eq_index(point: &[F2_128], address_bits: usize, cycle_bits: usize) -> Vec<F2_128> {
    let cycles = 1usize << cycle_bits;
    (0..cycles)
        .flat_map(|index| {
            let weight = eq_at(point, index);
            std::iter::repeat_n(weight, 1usize << address_bits)
        })
        .collect()
}

pub(crate) fn fold(values: &[F2_128], r: F2_128) -> Vec<F2_128> {
    values
        .chunks_exact(2)
        .map(|pair| pair[0] + r * (pair[0] + pair[1]))
        .collect()
}

pub(crate) fn fold_all(values: &[F2_128], challenges: &[F2_128]) -> F2_128 {
    let mut values = values.to_vec();
    for &challenge in challenges {
        values = fold(&values, challenge);
    }
    values[0]
}

fn interpolate<const N: usize>(values: &[F2_128; N], r: F2_128) -> F2_128 {
    let points: Vec<F2_128> = (0..N).map(|i| F2_128::from(i as u64)).collect();
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

fn evaluate_round4(values: &[F2_128; 4], r: F2_128) -> F2_128 {
    interpolate(values, r)
}

fn evaluate_round5(values: &[F2_128; 5], r: F2_128) -> F2_128 {
    interpolate(values, r)
}

pub(crate) fn sample_collision_point(
    transcript: &mut Sha256Transcript,
    address_bits: usize,
) -> (Vec<F2_128>, Vec<F2_128>, F2_128) {
    loop {
        let r = sample_point(transcript, address_bits);
        let mut prime = Vec::with_capacity(address_bits);
        let mut c = F2_128::from(1u64);
        let mut valid = true;
        for &coordinate in &r {
            let square = coordinate * coordinate;
            let factor = F2_128::from(1u64) + coordinate + square;
            if factor == F2_128::from(0u64) {
                valid = false;
                break;
            }
            c = c * factor;
            prime.push(coordinate * square * factor.inv().expect("nonzero"));
        }
        if valid {
            return (r, prime, c);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    fn trace() -> magnetar_spec::Trace {
        let program = ProgramImage::new(
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
    fn address_multiplicity_and_collision_round_trip() {
        let trace = trace();
        let witness = BinaryTwistWitness::from_trace(&trace).unwrap();
        for write in [false, true] {
            let proof = prove_address_multiplicity(&witness, write).unwrap();
            assert!(verify_address_multiplicity(&proof, write, &witness).unwrap());

            let mut tampered = proof.clone();
            tampered.a_eval = tampered.a_eval + F2_128::from(1u64);
            assert!(!verify_address_multiplicity(&tampered, write, &witness).unwrap());

            let mut tampered = proof.clone();
            if let Some(round) = tampered.collision_rounds.first_mut() {
                round[0] = round[0] + F2_128::from(1u64);
            }
            assert!(!verify_address_multiplicity(&tampered, write, &witness).unwrap());
        }
    }
    #[test]
    fn address_proof_binds_the_lambda_challenge() {
        let trace = trace();
        let witness = BinaryTwistWitness::from_trace(&trace).unwrap();
        let proof = prove_address_multiplicity(&witness, true).unwrap();
        assert!(verify_address_multiplicity(&proof, true, &witness).unwrap());

        let mut tampered = proof;
        tampered.lambda = tampered.lambda + F2_128::from(1u64);
        assert!(!verify_address_multiplicity(&tampered, true, &witness).unwrap());
    }
}
