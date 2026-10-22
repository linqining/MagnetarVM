//! BinaryTwist read-value reduction (d = 1, word-addressed RAM).
//!
//! Proves `Σ_{k,j} eq(r_j, j)·ra(k,j)·val(k,j) = erv(r_j)` where `ra` is the
//! one-hot read address and `val` the committed word history. The sum-check
//! reduces the identity to openings of `ra` and `val` at a random point; the
//! P3 multilinear PCS authenticates those openings.

use magnetar_constraint::{Field, F2_128};
use magnetar_memory::BinaryTwistWitness;
use magnetar_pcs::{
    P3BatchCommitment, P3BatchOpening, P3BatchPoint, P3BinaryPcs, P3Commitment, P3Opening,
};
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
    pub cycle_point: Vec<F2_128>,
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
        cycle_point,
        rounds,
        challenges,
        ra_eval,
        val_eval,
        ra_opening,
        val_opening,
    })
}

pub fn verify_read_identity(
    proof: &BinaryTwistReadProof,
    witness: &BinaryTwistWitness,
) -> Result<bool, ProofError> {
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
    if proof.cycle_point != cycle_point {
        return Ok(false);
    }
    let values = padded_values(&witness.read_value, proof.cycle_bits);
    if fold_all(&values, &cycle_point) != proof.claimed_read {
        return Ok(false);
    }
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BinaryTwistWriteProof {
    pub address_bits: usize,
    pub cycle_bits: usize,
    pub wa_commitment: P3Commitment,
    pub val_commitment: P3Commitment,
    pub inc_commitment: P3Commitment,
    pub claimed_write: F2_128,
    pub cycle_point: Vec<F2_128>,
    pub rounds: Vec<[F2_128; 4]>,
    pub challenges: Vec<F2_128>,
    pub wa_eval: F2_128,
    pub val_eval: F2_128,
    pub inc_eval: F2_128,
    pub wa_opening: P3Opening,
    pub val_opening: P3Opening,
    pub inc_opening: P3Opening,
}

pub fn prove_write_identity(
    witness: &BinaryTwistWitness,
) -> Result<BinaryTwistWriteProof, ProofError> {
    let (wa, val, inc, address_bits, cycle_bits) = write_tables(witness)?;
    let pcs = P3BinaryPcs::new(100);
    let wa_commitment = pcs.commit(&wa)?;
    let val_commitment = pcs.commit(&val)?;
    let inc_commitment = pcs.commit(&inc)?;

    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-write");
    absorb_commitment(&mut transcript, "wa", &wa_commitment);
    absorb_commitment(&mut transcript, "val", &val_commitment);
    absorb_commitment(&mut transcript, "inc", &inc_commitment);
    let cycle_point = sample_point(&mut transcript, cycle_bits);
    let eq = eq_index(&cycle_point, address_bits, cycle_bits);
    let payoff: Vec<F2_128> = val.iter().zip(&inc).map(|(v, i)| *v + *i).collect();
    let claimed_write = wa
        .iter()
        .zip(&payoff)
        .zip(&eq)
        .fold(F2_128::from(0u64), |sum, ((a, b), e)| sum + *e * *a * *b);
    transcript.absorb("claimed-write", &claimed_write.value().to_le_bytes());

    let (rounds, challenges) = sumcheck(&wa, &payoff, &eq, &mut transcript)?;
    let wa_eval = fold_all(&wa, &challenges);
    let val_eval = fold_all(&val, &challenges);
    let inc_eval = fold_all(&inc, &challenges);
    let wa_opening = pcs.open(&wa, &challenges)?;
    let val_opening = pcs.open(&val, &challenges)?;
    let inc_opening = pcs.open(&inc, &challenges)?;
    Ok(BinaryTwistWriteProof {
        address_bits,
        cycle_bits,
        wa_commitment,
        val_commitment,
        inc_commitment,
        claimed_write,
        cycle_point,
        rounds,
        challenges,
        wa_eval,
        val_eval,
        inc_eval,
        wa_opening,
        val_opening,
        inc_opening,
    })
}

pub fn verify_write_identity(
    proof: &BinaryTwistWriteProof,
    witness: &BinaryTwistWitness,
) -> Result<bool, ProofError> {
    let pcs = P3BinaryPcs::new(100);
    if proof.challenges.len() != proof.address_bits + proof.cycle_bits
        || proof.rounds.len() != proof.challenges.len()
    {
        return Ok(false);
    }
    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-write");
    absorb_commitment(&mut transcript, "wa", &proof.wa_commitment);
    absorb_commitment(&mut transcript, "val", &proof.val_commitment);
    absorb_commitment(&mut transcript, "inc", &proof.inc_commitment);
    let cycle_point = sample_point(&mut transcript, proof.cycle_bits);
    if proof.cycle_point != cycle_point {
        return Ok(false);
    }
    let values = padded_values(&witness.write_value, proof.cycle_bits);
    if fold_all(&values, &cycle_point) != proof.claimed_write {
        return Ok(false);
    }
    let mut eq = eq_index(&cycle_point, proof.address_bits, proof.cycle_bits);
    transcript.absorb("claimed-write", &proof.claimed_write.value().to_le_bytes());
    let mut sum = proof.claimed_write;
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
    if eq.len() != 1 || sum != eq[0] * proof.wa_eval * (proof.val_eval + proof.inc_eval) {
        return Ok(false);
    }
    let wa_ok = pcs.verify(
        &proof.wa_commitment,
        &proof.challenges,
        proof.wa_eval,
        &proof.wa_opening,
    )?;
    let val_ok = pcs.verify(
        &proof.val_commitment,
        &proof.challenges,
        proof.val_eval,
        &proof.val_opening,
    )?;
    let inc_ok = pcs.verify(
        &proof.inc_commitment,
        &proof.challenges,
        proof.inc_eval,
        &proof.inc_opening,
    )?;
    Ok(wa_ok && val_ok && inc_ok)
}

type WriteTables = (Vec<F2_128>, Vec<F2_128>, Vec<F2_128>, usize, usize);

fn write_tables(witness: &BinaryTwistWitness) -> Result<WriteTables, ProofError> {
    let cells = witness.initial.len();
    let cycles = witness.cycles.next_power_of_two();
    let address_bits = cells.trailing_zeros() as usize;
    let cycle_bits = cycles.trailing_zeros() as usize;
    let len = cells
        .checked_mul(cycles)
        .ok_or_else(|| ProofError::Pcs("BinaryTwist table overflows".into()))?;
    let mut wa = vec![F2_128::from(0u64); len];
    let mut val = vec![F2_128::from(0u64); len];
    let mut inc = vec![F2_128::from(0u64); len];
    for cycle in 0..witness.cycles {
        let start = cycle * cells;
        wa[start..start + cells].copy_from_slice(&witness.write_address[cycle]);
        val[start..start + cells].copy_from_slice(&witness.value[cycle]);
        for cell in 0..cells {
            inc[start + cell] = witness.increment[cycle];
        }
    }
    Ok((wa, val, inc, address_bits, cycle_bits))
}

#[cfg(test)]
mod write_tests {
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
    fn write_identity_sumcheck_round_trips() {
        let trace = trace();
        let witness = BinaryTwistWitness::from_trace(&trace).unwrap();
        let proof = prove_write_identity(&witness).unwrap();
        assert!(verify_write_identity(&proof, &witness).unwrap());
        let mut tampered = proof;
        tampered.inc_eval = tampered.inc_eval + F2_128::from(1u64);
        assert!(!verify_write_identity(&tampered, &witness).unwrap());
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BinaryTwistUpdateProof {
    pub address_bits: usize,
    pub cycle_bits: usize,
    pub next_commitment: P3Commitment,
    pub val_commitment: P3Commitment,
    pub wa_commitment: P3Commitment,
    pub inc_commitment: P3Commitment,
    pub rounds: Vec<[F2_128; 4]>,
    pub challenges: Vec<F2_128>,
    pub next_eval: F2_128,
    pub val_eval: F2_128,
    pub wa_eval: F2_128,
    pub inc_eval: F2_128,
    pub next_opening: P3Opening,
    pub val_opening: P3Opening,
    pub wa_opening: P3Opening,
    pub inc_opening: P3Opening,
}

pub fn prove_update_identity(
    witness: &BinaryTwistWitness,
) -> Result<BinaryTwistUpdateProof, ProofError> {
    let (next, val, wa, inc, address_bits, cycle_bits) = update_tables(witness)?;
    let pcs = P3BinaryPcs::new(100);
    let next_commitment = pcs.commit(&next)?;
    let val_commitment = pcs.commit(&val)?;
    let wa_commitment = pcs.commit(&wa)?;
    let inc_commitment = pcs.commit(&inc)?;
    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-update");
    for (label, commitment) in [
        ("next", &next_commitment),
        ("val", &val_commitment),
        ("wa", &wa_commitment),
        ("inc", &inc_commitment),
    ] {
        absorb_commitment(&mut transcript, label, commitment);
    }
    let cycle_point = sample_point(&mut transcript, cycle_bits);
    let eq = eq_index(&cycle_point, address_bits, cycle_bits);
    let (rounds, challenges) = sumcheck_update(&next, &val, &wa, &inc, &eq, &mut transcript)?;
    let next_eval = fold_all(&next, &challenges);
    let val_eval = fold_all(&val, &challenges);
    let wa_eval = fold_all(&wa, &challenges);
    let inc_eval = fold_all(&inc, &challenges);
    Ok(BinaryTwistUpdateProof {
        address_bits,
        cycle_bits,
        next_commitment,
        val_commitment,
        wa_commitment,
        inc_commitment,
        rounds,
        challenges: challenges.clone(),
        next_eval,
        val_eval,
        wa_eval,
        inc_eval,
        next_opening: pcs.open(&next, &challenges)?,
        val_opening: pcs.open(&val, &challenges)?,
        wa_opening: pcs.open(&wa, &challenges)?,
        inc_opening: pcs.open(&inc, &challenges)?,
    })
}

pub fn verify_update_identity(proof: &BinaryTwistUpdateProof) -> Result<bool, ProofError> {
    let pcs = P3BinaryPcs::new(100);
    if proof.challenges.len() != proof.address_bits + proof.cycle_bits
        || proof.rounds.len() != proof.challenges.len()
    {
        return Ok(false);
    }
    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-update");
    for (label, commitment) in [
        ("next", &proof.next_commitment),
        ("val", &proof.val_commitment),
        ("wa", &proof.wa_commitment),
        ("inc", &proof.inc_commitment),
    ] {
        absorb_commitment(&mut transcript, label, commitment);
    }
    let cycle_point = sample_point(&mut transcript, proof.cycle_bits);
    let mut eq = eq_index(&cycle_point, proof.address_bits, proof.cycle_bits);
    let mut sum = F2_128::from(0u64);
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
    let combined = proof.next_eval + proof.val_eval + proof.wa_eval * proof.inc_eval;
    if eq.len() != 1 || sum != eq[0] * combined {
        return Ok(false);
    }
    let next_ok = pcs.verify(
        &proof.next_commitment,
        &proof.challenges,
        proof.next_eval,
        &proof.next_opening,
    )?;
    let val_ok = pcs.verify(
        &proof.val_commitment,
        &proof.challenges,
        proof.val_eval,
        &proof.val_opening,
    )?;
    let wa_ok = pcs.verify(
        &proof.wa_commitment,
        &proof.challenges,
        proof.wa_eval,
        &proof.wa_opening,
    )?;
    let inc_ok = pcs.verify(
        &proof.inc_commitment,
        &proof.challenges,
        proof.inc_eval,
        &proof.inc_opening,
    )?;
    Ok(next_ok && val_ok && wa_ok && inc_ok)
}

type UpdateTables = (
    Vec<F2_128>,
    Vec<F2_128>,
    Vec<F2_128>,
    Vec<F2_128>,
    usize,
    usize,
);

fn update_tables(witness: &BinaryTwistWitness) -> Result<UpdateTables, ProofError> {
    let cells = witness.initial.len();
    let cycles = witness.cycles.next_power_of_two();
    let address_bits = cells.trailing_zeros() as usize;
    let cycle_bits = cycles.trailing_zeros() as usize;
    let len = cells
        .checked_mul(cycles)
        .ok_or_else(|| ProofError::Pcs("BinaryTwist table overflows".into()))?;
    let mut next = vec![F2_128::from(0u64); len];
    let mut val = vec![F2_128::from(0u64); len];
    let mut wa = vec![F2_128::from(0u64); len];
    let mut inc = vec![F2_128::from(0u64); len];
    for cycle in 0..witness.cycles {
        let start = cycle * cells;
        val[start..start + cells].copy_from_slice(&witness.value[cycle]);
        wa[start..start + cells].copy_from_slice(&witness.write_address[cycle]);
        for cell in 0..cells {
            inc[start + cell] = witness.increment[cycle];
        }
        let following = if cycle + 1 < witness.cycles {
            &witness.value[cycle + 1]
        } else {
            &witness.final_value
        };
        next[start..start + cells].copy_from_slice(following);
    }
    Ok((next, val, wa, inc, address_bits, cycle_bits))
}

fn sumcheck_update(
    next: &[F2_128],
    val: &[F2_128],
    wa: &[F2_128],
    inc: &[F2_128],
    eq: &[F2_128],
    transcript: &mut Sha256Transcript,
) -> Result<(Vec<[F2_128; 4]>, Vec<F2_128>), ProofError> {
    let len = next.len();
    if val.len() != len || wa.len() != len || inc.len() != len || eq.len() != len {
        return Err(ProofError::DimensionMismatch);
    }
    let rounds = len.trailing_zeros() as usize;
    let mut next = next.to_vec();
    let mut val = val.to_vec();
    let mut wa = wa.to_vec();
    let mut inc = inc.to_vec();
    let mut eq = eq.to_vec();
    let mut polynomials = Vec::with_capacity(rounds);
    let mut challenges = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let mut polynomial = [F2_128::from(0u64); 4];
        for (t, coefficient) in polynomial.iter_mut().enumerate() {
            let t = F2_128::from(t as u64);
            let next_t = fold(&next, t);
            let val_t = fold(&val, t);
            let wa_t = fold(&wa, t);
            let inc_t = fold(&inc, t);
            let eq_t = fold(&eq, t);
            *coefficient = (0..next_t.len()).fold(F2_128::from(0u64), |sum, index| {
                sum + eq_t[index] * (next_t[index] + val_t[index] + wa_t[index] * inc_t[index])
            });
        }
        for coefficient in &polynomial {
            transcript.absorb("round", &coefficient.value().to_le_bytes());
        }
        let challenge = challenge(transcript, "sumcheck");
        next = fold(&next, challenge);
        val = fold(&val, challenge);
        wa = fold(&wa, challenge);
        inc = fold(&inc, challenge);
        eq = fold(&eq, challenge);
        polynomials.push(polynomial);
        challenges.push(challenge);
    }
    Ok((polynomials, challenges))
}

#[cfg(test)]
mod update_tests {
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
    fn update_identity_sumcheck_round_trips() {
        let trace = trace();
        let witness = BinaryTwistWitness::from_trace(&trace).unwrap();
        let proof = prove_update_identity(&witness).unwrap();
        assert!(verify_update_identity(&proof).unwrap());
        let mut tampered = proof;
        tampered.next_eval = tampered.next_eval + F2_128::from(1u64);
        assert!(!verify_update_identity(&tampered).unwrap());
    }
}

fn padded_values(values: &[F2_128], cycle_bits: usize) -> Vec<F2_128> {
    let mut padded = values.to_vec();
    padded.resize(1usize << cycle_bits, F2_128::from(0u64));
    padded
}

use crate::binary_twist_address::{
    prove_address_batch_claim, verify_address_batch_claim, AddressMultiplicityClaim,
};

const RA: usize = 0;
const WA: usize = 1;
const VAL: usize = 2;
const INC: usize = 3;
const NEXT: usize = 4;
const RAM_COLUMNS: usize = 5;

struct BatchTables {
    columns: Vec<Vec<F2_128>>,
    address_bits: usize,
    cycle_bits: usize,
}

fn batch_tables(witness: &BinaryTwistWitness) -> Result<BatchTables, ProofError> {
    let cells = witness.initial.len();
    if cells == 0 || !cells.is_power_of_two() {
        return Err(ProofError::Pcs(
            "BinaryTwist RAM must contain a power-of-two number of words".into(),
        ));
    }
    let cycles = witness.cycles.next_power_of_two();
    let address_bits = cells.trailing_zeros() as usize;
    let cycle_bits = cycles.trailing_zeros() as usize;
    let len = cells
        .checked_mul(cycles)
        .ok_or_else(|| ProofError::Pcs("BinaryTwist table overflows".into()))?;
    let mut columns = vec![vec![F2_128::from(0u64); len]; RAM_COLUMNS];
    for cycle in 0..witness.cycles {
        let start = cycle * cells;
        columns[RA][start..start + cells].copy_from_slice(&witness.read_address[cycle]);
        columns[WA][start..start + cells].copy_from_slice(&witness.write_address[cycle]);
        columns[VAL][start..start + cells].copy_from_slice(&witness.value[cycle]);
        let following = if cycle + 1 < witness.cycles {
            &witness.value[cycle + 1]
        } else {
            &witness.final_value
        };
        columns[NEXT][start..start + cells].copy_from_slice(following);
        for cell in 0..cells {
            columns[INC][start + cell] = witness.increment[cycle];
        }
    }
    Ok(BatchTables {
        columns,
        address_bits,
        cycle_bits,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BinaryTwistReadClaim {
    pub claimed_read: F2_128,
    pub cycle_point: Vec<F2_128>,
    pub rounds: Vec<[F2_128; 4]>,
    pub challenges: Vec<F2_128>,
    pub ra_eval: F2_128,
    pub val_eval: F2_128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BinaryTwistWriteClaim {
    pub claimed_write: F2_128,
    pub cycle_point: Vec<F2_128>,
    pub rounds: Vec<[F2_128; 4]>,
    pub challenges: Vec<F2_128>,
    pub wa_eval: F2_128,
    pub val_eval: F2_128,
    pub inc_eval: F2_128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BinaryTwistUpdateClaim {
    pub cycle_point: Vec<F2_128>,
    pub rounds: Vec<[F2_128; 4]>,
    pub challenges: Vec<F2_128>,
    pub next_eval: F2_128,
    pub val_eval: F2_128,
    pub wa_eval: F2_128,
    pub inc_eval: F2_128,
}

/// Batched BinaryTwist RAM proof.
///
/// The read addresses, write addresses, value history, increments, and the
/// successor value history share one P3 commitment. Every identity's terminal
/// claims are discharged by one P3 opening argument.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BinaryTwistRamProof {
    pub address_bits: usize,
    pub cycle_bits: usize,
    pub read: BinaryTwistReadClaim,
    pub write: BinaryTwistWriteClaim,
    pub update: BinaryTwistUpdateClaim,
    pub read_address: AddressMultiplicityClaim,
    pub write_address: AddressMultiplicityClaim,
    pub opening: P3BatchOpening,
}

fn absorb_batch_commitment(transcript: &mut Sha256Transcript, commitment: &P3BatchCommitment) {
    transcript.absorb(
        "commitment",
        &bincode::serialize(commitment).unwrap_or_default(),
    );
}

pub fn prove_binary_twist_ram(
    witness: &BinaryTwistWitness,
) -> Result<BinaryTwistRamProof, ProofError> {
    witness
        .validate()
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let tables = batch_tables(witness)?;
    let pcs = P3BinaryPcs::new(100);
    let commitment = pcs.commit_batch(&tables.columns)?;
    let mut points = Vec::new();
    let mut expected = Vec::new();

    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-read");
    absorb_batch_commitment(&mut transcript, &commitment);
    let cycle_point = sample_point(&mut transcript, tables.cycle_bits);
    let eq = eq_index(&cycle_point, tables.address_bits, tables.cycle_bits);
    let claimed_read = tables.columns[RA]
        .iter()
        .zip(&tables.columns[VAL])
        .zip(&eq)
        .fold(F2_128::from(0u64), |sum, ((a, b), e)| sum + *e * *a * *b);
    transcript.absorb("claimed-read", &claimed_read.value().to_le_bytes());
    let (rounds, challenges) = sumcheck(
        &tables.columns[RA],
        &tables.columns[VAL],
        &eq,
        &mut transcript,
    )?;
    let ra_eval = fold_all(&tables.columns[RA], &challenges);
    let val_eval = fold_all(&tables.columns[VAL], &challenges);
    let read = BinaryTwistReadClaim {
        claimed_read,
        cycle_point: cycle_point.clone(),
        rounds,
        challenges: challenges.clone(),
        ra_eval,
        val_eval,
    };
    points.push(P3BatchPoint {
        point: challenges,
        columns: vec![RA, VAL],
    });
    expected.push(vec![ra_eval, val_eval]);

    let payoff: Vec<F2_128> = tables.columns[VAL]
        .iter()
        .zip(&tables.columns[INC])
        .map(|(value, increment)| *value + *increment)
        .collect();
    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-write");
    absorb_batch_commitment(&mut transcript, &commitment);
    let cycle_point = sample_point(&mut transcript, tables.cycle_bits);
    let eq = eq_index(&cycle_point, tables.address_bits, tables.cycle_bits);
    let claimed_write = tables.columns[WA]
        .iter()
        .zip(&payoff)
        .zip(&eq)
        .fold(F2_128::from(0u64), |sum, ((a, b), e)| sum + *e * *a * *b);
    transcript.absorb("claimed-write", &claimed_write.value().to_le_bytes());
    let (rounds, challenges) = sumcheck(&tables.columns[WA], &payoff, &eq, &mut transcript)?;
    let wa_eval = fold_all(&tables.columns[WA], &challenges);
    let val_eval = fold_all(&tables.columns[VAL], &challenges);
    let inc_eval = fold_all(&tables.columns[INC], &challenges);
    let write = BinaryTwistWriteClaim {
        claimed_write,
        cycle_point: cycle_point.clone(),
        rounds,
        challenges: challenges.clone(),
        wa_eval,
        val_eval,
        inc_eval,
    };
    points.push(P3BatchPoint {
        point: challenges,
        columns: vec![WA, VAL, INC],
    });
    expected.push(vec![wa_eval, val_eval, inc_eval]);

    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-update");
    absorb_batch_commitment(&mut transcript, &commitment);
    let cycle_point = sample_point(&mut transcript, tables.cycle_bits);
    let eq = eq_index(&cycle_point, tables.address_bits, tables.cycle_bits);
    let (rounds, challenges) = sumcheck_update(
        &tables.columns[NEXT],
        &tables.columns[VAL],
        &tables.columns[WA],
        &tables.columns[INC],
        &eq,
        &mut transcript,
    )?;
    let next_eval = fold_all(&tables.columns[NEXT], &challenges);
    let val_eval = fold_all(&tables.columns[VAL], &challenges);
    let wa_eval = fold_all(&tables.columns[WA], &challenges);
    let inc_eval = fold_all(&tables.columns[INC], &challenges);
    let update = BinaryTwistUpdateClaim {
        cycle_point,
        rounds,
        challenges: challenges.clone(),
        next_eval,
        val_eval,
        wa_eval,
        inc_eval,
    };
    points.push(P3BatchPoint {
        point: challenges,
        columns: vec![NEXT, VAL, WA, INC],
    });
    expected.push(vec![next_eval, val_eval, wa_eval, inc_eval]);

    let read_address = prove_address_batch_claim(
        &tables.columns[RA],
        false,
        witness,
        &commitment,
        "magnetar-binary-twist-read-address",
        RA,
    )?;
    let write_address = prove_address_batch_claim(
        &tables.columns[WA],
        true,
        witness,
        &commitment,
        "magnetar-binary-twist-write-address",
        WA,
    )?;
    points.extend(read_address.points);
    expected.extend(read_address.values);
    points.extend(write_address.points);
    expected.extend(write_address.values);

    let opening = pcs.open_batch(&tables.columns, &points)?;
    debug_assert!(pcs.verify_batch(&opening, &points, &expected)?);
    Ok(BinaryTwistRamProof {
        address_bits: tables.address_bits,
        cycle_bits: tables.cycle_bits,
        read,
        write,
        update,
        read_address: read_address.claim,
        write_address: write_address.claim,
        opening,
    })
}

pub fn verify_binary_twist_ram(
    witness: &BinaryTwistWitness,
    proof: &BinaryTwistRamProof,
) -> Result<bool, ProofError> {
    let cells = witness.initial.len();
    let cycles = witness.cycles.next_power_of_two();
    let address_bits = cells.trailing_zeros() as usize;
    let cycle_bits = cycles.trailing_zeros() as usize;
    if proof.address_bits != address_bits
        || proof.cycle_bits != cycle_bits
        || proof.opening.commitment.num_variables != address_bits + cycle_bits
        || proof.opening.commitment.num_columns != RAM_COLUMNS
    {
        return Ok(false);
    }
    let pcs = P3BinaryPcs::new(100);
    let commitment = &proof.opening.commitment;
    let mut points = Vec::new();
    let mut expected = Vec::new();

    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-read");
    absorb_batch_commitment(&mut transcript, commitment);
    let cycle_point = sample_point(&mut transcript, cycle_bits);
    if proof.read.cycle_point != cycle_point {
        return Ok(false);
    }
    let values = padded_values(&witness.read_value, cycle_bits);
    if fold_all(&values, &cycle_point) != proof.read.claimed_read {
        return Ok(false);
    }
    let mut eq = eq_index(&cycle_point, address_bits, cycle_bits);
    transcript.absorb(
        "claimed-read",
        &proof.read.claimed_read.value().to_le_bytes(),
    );
    let mut sum = proof.read.claimed_read;
    for (round, &expected_challenge) in proof.read.rounds.iter().zip(&proof.read.challenges) {
        if round[0] + round[1] != sum {
            return Ok(false);
        }
        for coefficient in round {
            transcript.absorb("round", &coefficient.value().to_le_bytes());
        }
        let challenge = challenge(&mut transcript, "sumcheck");
        if challenge != expected_challenge {
            return Ok(false);
        }
        sum = evaluate_round(round, challenge);
        eq = fold(&eq, challenge);
    }
    if eq.len() != 1 || sum != eq[0] * proof.read.ra_eval * proof.read.val_eval {
        return Ok(false);
    }
    points.push(P3BatchPoint {
        point: proof.read.challenges.clone(),
        columns: vec![RA, VAL],
    });
    expected.push(vec![proof.read.ra_eval, proof.read.val_eval]);

    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-write");
    absorb_batch_commitment(&mut transcript, commitment);
    let cycle_point = sample_point(&mut transcript, cycle_bits);
    if proof.write.cycle_point != cycle_point {
        return Ok(false);
    }
    let values = padded_values(&witness.write_value, cycle_bits);
    if fold_all(&values, &cycle_point) != proof.write.claimed_write {
        return Ok(false);
    }
    let mut eq = eq_index(&cycle_point, address_bits, cycle_bits);
    transcript.absorb(
        "claimed-write",
        &proof.write.claimed_write.value().to_le_bytes(),
    );
    let mut sum = proof.write.claimed_write;
    for (round, &expected_challenge) in proof.write.rounds.iter().zip(&proof.write.challenges) {
        if round[0] + round[1] != sum {
            return Ok(false);
        }
        for coefficient in round {
            transcript.absorb("round", &coefficient.value().to_le_bytes());
        }
        let challenge = challenge(&mut transcript, "sumcheck");
        if challenge != expected_challenge {
            return Ok(false);
        }
        sum = evaluate_round(round, challenge);
        eq = fold(&eq, challenge);
    }
    if eq.len() != 1
        || sum != eq[0] * proof.write.wa_eval * (proof.write.val_eval + proof.write.inc_eval)
    {
        return Ok(false);
    }
    points.push(P3BatchPoint {
        point: proof.write.challenges.clone(),
        columns: vec![WA, VAL, INC],
    });
    expected.push(vec![
        proof.write.wa_eval,
        proof.write.val_eval,
        proof.write.inc_eval,
    ]);

    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-update");
    absorb_batch_commitment(&mut transcript, commitment);
    let cycle_point = sample_point(&mut transcript, cycle_bits);
    if proof.update.cycle_point != cycle_point {
        return Ok(false);
    }
    let mut eq = eq_index(&cycle_point, address_bits, cycle_bits);
    let mut sum = F2_128::from(0u64);
    for (round, &expected_challenge) in proof.update.rounds.iter().zip(&proof.update.challenges) {
        if round[0] + round[1] != sum {
            return Ok(false);
        }
        for coefficient in round {
            transcript.absorb("round", &coefficient.value().to_le_bytes());
        }
        let challenge = challenge(&mut transcript, "sumcheck");
        if challenge != expected_challenge {
            return Ok(false);
        }
        sum = evaluate_round(round, challenge);
        eq = fold(&eq, challenge);
    }
    let combined = proof.update.next_eval
        + proof.update.val_eval
        + proof.update.wa_eval * proof.update.inc_eval;
    if eq.len() != 1 || sum != eq[0] * combined {
        return Ok(false);
    }
    points.push(P3BatchPoint {
        point: proof.update.challenges.clone(),
        columns: vec![NEXT, VAL, WA, INC],
    });
    expected.push(vec![
        proof.update.next_eval,
        proof.update.val_eval,
        proof.update.wa_eval,
        proof.update.inc_eval,
    ]);

    let Some(read_address) = verify_address_batch_claim(
        &proof.read_address,
        false,
        witness,
        commitment,
        "magnetar-binary-twist-read-address",
        RA,
    )?
    else {
        return Ok(false);
    };
    points.extend(read_address.points);
    expected.extend(read_address.values);

    let Some(write_address) = verify_address_batch_claim(
        &proof.write_address,
        true,
        witness,
        commitment,
        "magnetar-binary-twist-write-address",
        WA,
    )?
    else {
        return Ok(false);
    };
    points.extend(write_address.points);
    expected.extend(write_address.values);

    pcs.verify_batch(&proof.opening, &points, &expected)
}

#[cfg(test)]
mod ram_tests {
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
    fn ram_binary_twist_bundle_round_trips() {
        let trace = trace();
        let witness = BinaryTwistWitness::from_trace(&trace).unwrap();
        let proof = prove_binary_twist_ram(&witness).unwrap();
        assert!(verify_binary_twist_ram(&witness, &proof).unwrap());

        let mut tampered = proof.clone();
        tampered.read.claimed_read = tampered.read.claimed_read + F2_128::from(1u64);
        assert!(!verify_binary_twist_ram(&witness, &tampered).unwrap());

        let mut tampered = proof.clone();
        tampered.write.inc_eval = tampered.write.inc_eval + F2_128::from(1u64);
        assert!(!verify_binary_twist_ram(&witness, &tampered).unwrap());

        let mut tampered = proof.clone();
        tampered.update.next_eval = tampered.update.next_eval + F2_128::from(1u64);
        assert!(!verify_binary_twist_ram(&witness, &tampered).unwrap());

        let mut tampered = proof.clone();
        tampered.read_address.a_eval = tampered.read_address.a_eval + F2_128::from(1u64);
        assert!(!verify_binary_twist_ram(&witness, &tampered).unwrap());

        let mut tampered = proof;
        tampered.write_address.a_rp_eval = tampered.write_address.a_rp_eval + F2_128::from(1u64);
        assert!(!verify_binary_twist_ram(&witness, &tampered).unwrap());
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
    fn read_identity_sumcheck_binds_the_history() {
        let trace = trace();
        let witness = BinaryTwistWitness::from_trace(&trace).unwrap();
        witness.validate().unwrap();
        let proof = prove_read_identity(&witness).unwrap();
        assert!(verify_read_identity(&proof, &witness).unwrap());

        let mut tampered = proof.clone();
        if let Some(round) = tampered.rounds.first_mut() {
            round[0] = round[0] + F2_128::from(1u64);
        }
        assert!(!verify_read_identity(&tampered, &witness).unwrap());
    }
}
