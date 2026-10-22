//! BinaryTwist read-value reduction (d = 1, word-addressed RAM).
//!
//! Proves `Σ_{k,j} eq(r_j, j)·ra(k,j)·val(k,j) = erv(r_j)` where `ra` is the
//! one-hot read address and `val` the committed word history. The sum-check
//! reduces the identity to openings of `ra` and `val` at a random point; the
//! P3 multilinear PCS authenticates those openings.

use magnetar_constraint::{Field, F2_128};
use magnetar_memory::BinaryTwistWitness;
use magnetar_pcs::{P3BinaryPcs, P3Commitment, P3Opening};
use magnetar_proof::{Pcs, ProofError};
use magnetar_transcript::Sha256Transcript;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BinaryTwistReadProof {
    pub address_bits: usize,
    pub cycle_bits: usize,
    pub ra_commitment: P3Commitment,
    pub val_commitment: P3Commitment,
    pub claimed_read: F2_128,
    pub rounds: Vec<[F2_128; 4]>,
    pub challenges: Vec<F2_128>,
    pub ra_eval: F2_128,
    pub val_eval: F2_128,
    pub ra_opening: P3Opening,
    pub val_opening: P3Opening,
}

pub fn prove_read_identity(
    witness: &BinaryTwistWitness,
) -> Result<BinaryTwistReadProof, ProofError> {
    let (ra, val, address_bits, cycle_bits) = tables(witness)?;
    let pcs = P3BinaryPcs::new(100);
    let ra_commitment = pcs.commit(&ra)?;
    let val_commitment = pcs.commit(&val)?;

    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-read");
    absorb_commitment(&mut transcript, "ra", &ra_commitment);
    absorb_commitment(&mut transcript, "val", &val_commitment);
    let cycle_point = sample_point(&mut transcript, cycle_bits);
    let eq = eq_index(&cycle_point, address_bits, cycle_bits);
    let claimed_read = ra
        .iter()
        .zip(&val)
        .zip(&eq)
        .fold(F2_128::from(0u64), |sum, ((a, b), e)| sum + *e * *a * *b);
    transcript.absorb("claimed-read", &claimed_read.value().to_le_bytes());

    let (rounds, challenges) = sumcheck(&ra, &val, &eq, &mut transcript)?;
    let ra_eval = fold_all(&ra, &challenges);
    let val_eval = fold_all(&val, &challenges);
    let ra_opening = pcs.open(&ra, &challenges)?;
    let val_opening = pcs.open(&val, &challenges)?;
    Ok(BinaryTwistReadProof {
        address_bits,
        cycle_bits,
        ra_commitment,
        val_commitment,
        claimed_read,
        rounds,
        challenges,
        ra_eval,
        val_eval,
        ra_opening,
        val_opening,
    })
}

pub fn verify_read_identity(proof: &BinaryTwistReadProof) -> Result<bool, ProofError> {
    let pcs = P3BinaryPcs::new(100);
    let cells = 1usize << proof.address_bits;
    let cycles = 1usize << proof.cycle_bits;
    if proof.challenges.len() != proof.address_bits + proof.cycle_bits
        || proof.rounds.len() != proof.challenges.len()
    {
        return Ok(false);
    }
    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-read");
    absorb_commitment(&mut transcript, "ra", &proof.ra_commitment);
    absorb_commitment(&mut transcript, "val", &proof.val_commitment);
    let cycle_point = sample_point(&mut transcript, proof.cycle_bits);
    let mut eq = eq_index(&cycle_point, proof.address_bits, proof.cycle_bits);
    transcript.absorb("claimed-read", &proof.claimed_read.value().to_le_bytes());

    let mut sum = proof.claimed_read;
    for (round, &expected) in proof.rounds.iter().zip(&proof.challenges) {
        if round[0] + round[1] != sum {
            return Ok(false);
        }
        for coefficient in round {
            transcript.absorb("round", &coefficient.value().to_le_bytes());
        }
        let challenge = challenge(&mut transcript, "sumcheck");
        if challenge != expected {
            return Ok(false);
        }
        sum = evaluate_round(round, challenge);
        eq = fold(&eq, challenge);
    }
    if eq.len() != 1 {
        return Ok(false);
    }
    if sum != eq[0] * proof.ra_eval * proof.val_eval {
        return Ok(false);
    }
    let ra_ok = pcs.verify(
        &proof.ra_commitment,
        &proof.challenges,
        proof.ra_eval,
        &proof.ra_opening,
    )?;
    let val_ok = pcs.verify(
        &proof.val_commitment,
        &proof.challenges,
        proof.val_eval,
        &proof.val_opening,
    )?;
    let _ = (cells, cycles);
    Ok(ra_ok && val_ok)
}

fn tables(
    witness: &BinaryTwistWitness,
) -> Result<(Vec<F2_128>, Vec<F2_128>, usize, usize), ProofError> {
    let cells = witness.initial.len();
    let cycles = witness.cycles.next_power_of_two();
    let address_bits = cells.trailing_zeros() as usize;
    let cycle_bits = cycles.trailing_zeros() as usize;
    let len = cells
        .checked_mul(cycles)
        .ok_or_else(|| ProofError::Pcs("BinaryTwist table overflows".into()))?;
    let mut ra = vec![F2_128::from(0u64); len];
    let mut val = vec![F2_128::from(0u64); len];
    for cycle in 0..witness.cycles {
        ra[cycle * cells..(cycle + 1) * cells].copy_from_slice(&witness.read_address[cycle]);
        val[cycle * cells..(cycle + 1) * cells].copy_from_slice(&witness.value[cycle]);
    }
    Ok((ra, val, address_bits, cycle_bits))
}

fn absorb_commitment(transcript: &mut Sha256Transcript, label: &str, commitment: &P3Commitment) {
    transcript.absorb(label, &bincode::serialize(commitment).unwrap_or_default());
}

fn sample_point(transcript: &mut Sha256Transcript, length: usize) -> Vec<F2_128> {
    (0..length)
        .map(|_| challenge(transcript, "point"))
        .collect()
}

fn challenge(transcript: &mut Sha256Transcript, label: &str) -> F2_128 {
    let bytes = transcript.challenge_32(label);
    let mut value = [0u8; 16];
    value.copy_from_slice(&bytes[..16]);
    F2_128::from_bits(u128::from_le_bytes(value))
}

fn eq_index(point: &[F2_128], address_bits: usize, cycle_bits: usize) -> Vec<F2_128> {
    let cycles = 1usize << cycle_bits;
    (0..cycles)
        .flat_map(|index| {
            let weight = point
                .iter()
                .enumerate()
                .fold(F2_128::from(1u64), |acc, (bit, r)| {
                    if (index >> bit) & 1 == 1 {
                        acc * *r
                    } else {
                        acc * (F2_128::from(1u64) + *r)
                    }
                });
            let _ = address_bits;
            std::iter::repeat_n(weight, 1usize << address_bits)
        })
        .collect()
}

fn fold(values: &[F2_128], r: F2_128) -> Vec<F2_128> {
    values
        .chunks_exact(2)
        .map(|pair| pair[0] + r * (pair[0] + pair[1]))
        .collect()
}

fn fold_all(values: &[F2_128], challenges: &[F2_128]) -> F2_128 {
    let mut values = values.to_vec();
    for &challenge in challenges {
        values = fold(&values, challenge);
    }
    values[0]
}

fn evaluate_round(values: &[F2_128; 4], r: F2_128) -> F2_128 {
    // The prover stores g(0), g(1), g(2), g(3); interpolate at r.
    let points = [
        F2_128::from(0u64),
        F2_128::from(1u64),
        F2_128::from(2u64),
        F2_128::from(3u64),
    ];
    let mut result = F2_128::from(0u64);
    for (i, &value) in values.iter().enumerate() {
        let mut basis = F2_128::from(1u64);
        for (j, &point) in points.iter().enumerate() {
            if i != j {
                basis =
                    basis * (r + point) * (points[i] + point).inv().expect("distinct round points");
            }
        }
        result = result + value * basis;
    }
    result
}

fn sumcheck(
    ra: &[F2_128],
    val: &[F2_128],
    eq: &[F2_128],
    transcript: &mut Sha256Transcript,
) -> Result<(Vec<[F2_128; 4]>, Vec<F2_128>), ProofError> {
    let len = ra.len();
    if len != val.len() || len != eq.len() {
        return Err(ProofError::DimensionMismatch);
    }
    let rounds = len.trailing_zeros() as usize;
    let mut ra = ra.to_vec();
    let mut val = val.to_vec();
    let mut eq = eq.to_vec();
    let mut polynomials = Vec::with_capacity(rounds);
    let mut challenges = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let mut polynomial = [F2_128::from(0u64); 4];
        for (t, coefficient) in polynomial.iter_mut().enumerate() {
            let t = F2_128::from(t as u64);
            let ra_t = fold(&ra, t);
            let val_t = fold(&val, t);
            let eq_t = fold(&eq, t);
            *coefficient = ra_t
                .iter()
                .zip(&val_t)
                .zip(&eq_t)
                .fold(F2_128::from(0u64), |sum, ((a, b), e)| sum + *e * *a * *b);
        }
        for coefficient in &polynomial {
            transcript.absorb("round", &coefficient.value().to_le_bytes());
        }
        let challenge = challenge(transcript, "sumcheck");
        ra = fold(&ra, challenge);
        val = fold(&val, challenge);
        eq = fold(&eq, challenge);
        polynomials.push(polynomial);
        challenges.push(challenge);
    }
    Ok((polynomials, challenges))
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
    fn read_identity_sumcheck_binds_the_history() {
        let trace = trace();
        let witness = BinaryTwistWitness::from_trace(&trace).unwrap();
        witness.validate().unwrap();
        let proof = prove_read_identity(&witness).unwrap();
        assert!(verify_read_identity(&proof).unwrap());

        let mut tampered = proof.clone();
        if let Some(round) = tampered.rounds.first_mut() {
            round[0] = round[0] + F2_128::from(1u64);
        }
        assert!(!verify_read_identity(&tampered).unwrap());
    }
}
