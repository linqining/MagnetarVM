//! BinaryTwist read-value reduction (d = 1, word-addressed RAM).
//!
//! Proves `Σ_{k,j} eq(r_j, j)·ra(k,j)·val(k,j) = erv(r_j)` where `ra` is the
//! one-hot read address and `val` the committed word history. The sum-check
//! reduces the identity to openings of `ra` and `val` at a random point; the
//! P3 multilinear PCS authenticates those openings.

use magnetar_constraint::{Field, F2_128};
use magnetar_memory::BinaryTwistWitness;
use magnetar_pcs::{
    P3BinaryPcs, P3Commitment, P3MosaicCommitment, P3MosaicOpening, P3MosaicPoint, P3MosaicTable,
    P3Opening,
};
use magnetar_proof::{Pcs, ProofError};
use magnetar_transcript::Sha256Transcript;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BinaryTwistReadProof {
    pub ra_commitment: P3Commitment,
    pub val_commitment: P3Commitment,
    pub claimed_read: F2_128,
    pub rounds: Vec<[F2_128; 4]>,
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
        ra_commitment,
        val_commitment,
        claimed_read,
        rounds,
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
    let cells = witness.initial.len();
    let cycles = witness.cycles.next_power_of_two();
    let address_bits = cells.trailing_zeros() as usize;
    let cycle_bits = cycles.trailing_zeros() as usize;
    if proof.rounds.len() != address_bits + cycle_bits {
        return Ok(false);
    }
    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-read");
    absorb_commitment(&mut transcript, "ra", &proof.ra_commitment);
    absorb_commitment(&mut transcript, "val", &proof.val_commitment);
    let cycle_point = sample_point(&mut transcript, cycle_bits);
    let values = padded_values(&witness.read_value, cycle_bits);
    if fold_all(&values, &cycle_point) != proof.claimed_read {
        return Ok(false);
    }
    let mut eq = eq_index(&cycle_point, address_bits, cycle_bits);
    transcript.absorb("claimed-read", &proof.claimed_read.value().to_le_bytes());

    let mut sum = proof.claimed_read;
    let mut challenges = Vec::with_capacity(proof.rounds.len());
    for round in &proof.rounds {
        if round[0] + round[1] != sum {
            return Ok(false);
        }
        for coefficient in round {
            transcript.absorb("round", &coefficient.value().to_le_bytes());
        }
        let challenge = challenge(&mut transcript, "sumcheck");
        challenges.push(challenge);
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
        &challenges,
        proof.ra_eval,
        &proof.ra_opening,
    )?;
    let val_ok = pcs.verify(
        &proof.val_commitment,
        &challenges,
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
    pub wa_commitment: P3Commitment,
    pub val_commitment: P3Commitment,
    pub inc_commitment: P3Commitment,
    pub claimed_write: F2_128,
    pub rounds: Vec<[F2_128; 4]>,
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
        wa_commitment,
        val_commitment,
        inc_commitment,
        claimed_write,
        rounds,
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
    let cycles = witness.cycles.next_power_of_two();
    let address_bits = witness.initial.len().trailing_zeros() as usize;
    let cycle_bits = cycles.trailing_zeros() as usize;
    if proof.rounds.len() != address_bits + cycle_bits {
        return Ok(false);
    }
    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-write");
    absorb_commitment(&mut transcript, "wa", &proof.wa_commitment);
    absorb_commitment(&mut transcript, "val", &proof.val_commitment);
    absorb_commitment(&mut transcript, "inc", &proof.inc_commitment);
    let cycle_point = sample_point(&mut transcript, cycle_bits);
    let values = padded_values(&witness.write_value, cycle_bits);
    if fold_all(&values, &cycle_point) != proof.claimed_write {
        return Ok(false);
    }
    let mut eq = eq_index(&cycle_point, address_bits, cycle_bits);
    transcript.absorb("claimed-write", &proof.claimed_write.value().to_le_bytes());
    let mut sum = proof.claimed_write;
    let mut challenges = Vec::with_capacity(proof.rounds.len());
    for round in &proof.rounds {
        if round[0] + round[1] != sum {
            return Ok(false);
        }
        for coefficient in round {
            transcript.absorb("round", &coefficient.value().to_le_bytes());
        }
        let challenge = challenge(&mut transcript, "sumcheck");
        challenges.push(challenge);
        sum = evaluate_round(round, challenge);
        eq = fold(&eq, challenge);
    }
    if eq.len() != 1 || sum != eq[0] * proof.wa_eval * (proof.val_eval + proof.inc_eval) {
        return Ok(false);
    }
    let wa_ok = pcs.verify(
        &proof.wa_commitment,
        &challenges,
        proof.wa_eval,
        &proof.wa_opening,
    )?;
    let val_ok = pcs.verify(
        &proof.val_commitment,
        &challenges,
        proof.val_eval,
        &proof.val_opening,
    )?;
    let inc_ok = pcs.verify(
        &proof.inc_commitment,
        &challenges,
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
    if proof.rounds.len() != proof.address_bits + proof.cycle_bits {
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
    let mut challenges = Vec::with_capacity(proof.rounds.len());
    for round in &proof.rounds {
        if round[0] + round[1] != sum {
            return Ok(false);
        }
        for coefficient in round {
            transcript.absorb("round", &coefficient.value().to_le_bytes());
        }
        let challenge = challenge(&mut transcript, "sumcheck");
        challenges.push(challenge);
        sum = evaluate_round(round, challenge);
        eq = fold(&eq, challenge);
    }
    let combined = proof.next_eval + proof.val_eval + proof.wa_eval * proof.inc_eval;
    if eq.len() != 1 || sum != eq[0] * combined {
        return Ok(false);
    }
    let next_ok = pcs.verify(
        &proof.next_commitment,
        &challenges,
        proof.next_eval,
        &proof.next_opening,
    )?;
    let val_ok = pcs.verify(
        &proof.val_commitment,
        &challenges,
        proof.val_eval,
        &proof.val_opening,
    )?;
    let wa_ok = pcs.verify(
        &proof.wa_commitment,
        &challenges,
        proof.wa_eval,
        &proof.wa_opening,
    )?;
    let inc_ok = pcs.verify(
        &proof.inc_commitment,
        &challenges,
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

/// Opening points and expected values a mosaic owner must discharge.
pub(crate) type MosaicClaims = (Vec<P3MosaicPoint>, Vec<Vec<F2_128>>);
pub(crate) type ClaimedRam = (BinaryTwistRamProof, MosaicClaims);

/// The committed BinaryTwist RAM tables.
///
/// `addr` is the bit-sliced address table: one read bit column and one write
/// bit column per address bit, plus a validity column for each direction. Its
/// arity is the cycle count, so the address commitment is independent of the
/// number of RAM cells. `inc` is the compact cycle-only increment table.
pub(crate) struct BatchTables {
    pub addr: P3MosaicTable,
    pub inc: P3MosaicTable,
    pub initial: P3MosaicTable,
    pub read_value: P3MosaicTable,
    pub write_value: P3MosaicTable,
    #[allow(dead_code)]
    pub read_value_bits: Vec<P3MosaicTable>,
    #[allow(dead_code)]
    pub read_address_bits: Vec<P3MosaicTable>,
    pub address_bits: usize,
    pub cycle_bits: usize,
    pub final_values: Vec<F2_128>,
}

impl BatchTables {
    pub(crate) fn address_columns(&self) -> &[Vec<F2_128>] {
        &self.addr.columns
    }

    pub(crate) fn increments(&self) -> &[F2_128] {
        &self.inc.columns[0]
    }

    pub(crate) fn column_count(&self) -> usize {
        2 * self.address_bits + 2
    }

    pub(crate) fn column_bits(&self) -> usize {
        self.column_count().next_power_of_two().trailing_zeros() as usize
    }
}

fn one_hot_address(bits: &[F2_128]) -> Option<usize> {
    let mut found = None;
    for (index, bit) in bits.iter().enumerate() {
        match bit.value() {
            0 => {}
            1 => {
                if found.is_some() {
                    return None;
                }
                found = Some(index);
            }
            _ => return None,
        }
    }
    found
}

#[allow(clippy::needless_range_loop)]
pub(crate) fn batch_tables(witness: &BinaryTwistWitness) -> Result<BatchTables, ProofError> {
    let cells = witness.initial.len();
    if cells == 0 || !cells.is_power_of_two() {
        return Err(ProofError::Pcs(
            "BinaryTwist RAM must contain a power-of-two number of words".into(),
        ));
    }
    let cycles = witness.cycles.next_power_of_two();
    let address_bits = cells.trailing_zeros() as usize;
    let cycle_bits = cycles.trailing_zeros() as usize;
    let addr_bits = cycles.max(2).trailing_zeros() as usize;
    let mut addr = vec![vec![F2_128::from(0u64); 1usize << addr_bits]; 2 * address_bits + 2];
    let inc_bits = cycles.max(2).trailing_zeros() as usize;
    let mut increments = vec![F2_128::from(0u64); 1usize << inc_bits];
    for cycle in 0..witness.cycles {
        addr[2 * address_bits][cycle] = F2_128::from(1u64);
        if let Some(cell) = one_hot_address(&witness.read_address[cycle]) {
            for bit in 0..address_bits {
                addr[bit][cycle] = F2_128::from(((cell >> bit) & 1) as u64);
            }
        }
        if let Some(cell) = one_hot_address(&witness.write_address[cycle]) {
            addr[2 * address_bits + 1][cycle] = F2_128::from(1u64);
            for bit in 0..address_bits {
                addr[address_bits + bit][cycle] = F2_128::from(((cell >> bit) & 1) as u64);
            }
        }
    }
    increments[..witness.cycles].copy_from_slice(&witness.increment);
    let cycles_padded = cycles.next_power_of_two().max(2);
    let mut read_value = witness.read_value.clone();
    read_value.resize(cycles_padded, F2_128::from(0u64));
    let mut write_value = witness.write_value.clone();
    write_value.resize(cycles_padded, F2_128::from(0u64));
    let mut read_value_bits = vec![vec![F2_128::from(0u64); cycles_padded]; witness.cell_bits];
    let mut read_address_bits = vec![vec![F2_128::from(0u64); cycles_padded]; address_bits];
    for cycle in 0..witness.cycles {
        let value = witness.read_value[cycle].value();
        for bit in 0..witness.cell_bits {
            read_value_bits[bit][cycle] = F2_128::from((value >> bit) & 1);
        }
        if let Some(cell) = one_hot_address(&witness.read_address[cycle]) {
            if witness.idle_word != Some(cell) {
                for bit in 0..address_bits {
                    read_address_bits[bit][cycle] = F2_128::from(((cell >> bit) & 1) as u64);
                }
            }
        }
    }
    let mut initial = witness.initial.clone();
    initial.resize(
        witness.initial.len().next_power_of_two().max(2),
        F2_128::from(0u64),
    );
    Ok(BatchTables {
        addr: P3MosaicTable { columns: addr },
        inc: P3MosaicTable {
            columns: vec![increments],
        },
        initial: P3MosaicTable {
            columns: vec![initial],
        },
        read_value: P3MosaicTable {
            columns: vec![read_value],
        },
        write_value: P3MosaicTable {
            columns: vec![write_value],
        },
        read_value_bits: read_value_bits
            .into_iter()
            .map(|column| P3MosaicTable {
                columns: vec![column],
            })
            .collect(),
        read_address_bits: read_address_bits
            .into_iter()
            .map(|column| P3MosaicTable {
                columns: vec![column],
            })
            .collect(),
        address_bits,
        cycle_bits,
        final_values: witness.final_value.clone(),
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddressBooleanClaim {
    pub rounds: Vec<Vec<F2_128>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadInitialClaim {
    pub claimed: F2_128,
    pub rounds: Vec<Vec<F2_128>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadHistoryClaim {
    pub claimed: F2_128,
    pub rounds: Vec<Vec<F2_128>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BinaryTwistReadClaim {
    pub initial: ReadInitialClaim,
    pub history: ReadHistoryClaim,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WriteBaseClaim {
    pub claimed: F2_128,
    pub rounds: Vec<Vec<F2_128>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WriteHistoryClaim {
    pub claimed: F2_128,
    pub rounds: Vec<Vec<F2_128>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BinaryTwistWriteClaim {
    pub base: WriteBaseClaim,
    pub history: WriteHistoryClaim,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BinaryTwistUpdateClaim {
    pub rounds: Vec<Vec<F2_128>>,
}

/// Batched BinaryTwist RAM proof with virtualized addresses and value history.
///
/// Only bit-sliced address components and the compact increment table are
/// committed. The full one-hot addresses are reconstructed by the verifier,
/// and `Val`/`Next` are reconstructed through the `LT` identity. Standalone
/// proofs carry their own P3 opening; a unified CPU proof leaves `opening`
/// empty and shares the CPU witness's mosaic commitment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BinaryTwistRamProof {
    pub boolean: AddressBooleanClaim,
    pub read: BinaryTwistReadClaim,
    pub write: BinaryTwistWriteClaim,
    pub update: BinaryTwistUpdateClaim,
    pub opening: Option<P3MosaicOpening>,
    pub read_value_eval: F2_128,
    pub write_value_eval: F2_128,
    pub initial_read_eval: F2_128,
    pub initial_write_eval: F2_128,
    pub initial_update_eval: F2_128,
    pub boolean_evals: Vec<F2_128>,
    pub read_initial_addr: Vec<F2_128>,
    pub read_history_values: Vec<F2_128>,
    pub write_base_values: Vec<F2_128>,
    pub write_history_values: Vec<F2_128>,
    pub final_values_evals: Vec<F2_128>,
    pub cycle_bits: usize,
    pub address_bits: usize,
}

fn eq_at_index(point: &[F2_128], index: usize) -> F2_128 {
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

fn eq_points(left: &[F2_128], right: &[F2_128]) -> F2_128 {
    left.iter()
        .zip(right)
        .fold(F2_128::from(1u64), |acc, (a, b)| {
            acc * (*a * *b + (F2_128::from(1u64) + *a) * (F2_128::from(1u64) + *b))
        })
}

fn eq_vector(point: &[F2_128], size: usize) -> Vec<F2_128> {
    (0..size).map(|index| eq_at_index(point, index)).collect()
}

fn inc_point(point: &[F2_128]) -> Vec<F2_128> {
    if point.is_empty() {
        vec![F2_128::from(0u64)]
    } else {
        point.to_vec()
    }
}

fn interpolate_values(values: &[F2_128], r: F2_128) -> F2_128 {
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

fn lt_mle(jp_point: &[F2_128], j_point: &[F2_128], _cycles: usize) -> F2_128 {
    let mut prefix = F2_128::from(1u64);
    let mut sum = F2_128::from(0u64);
    for index in (0..jp_point.len()).rev() {
        let a = jp_point[index];
        let b = j_point[index];
        sum = sum + prefix * (F2_128::from(1u64) + a) * b;
        prefix = prefix * (F2_128::from(1u64) + a + b);
    }
    sum
}

fn address_value(bits: &[F2_128], valid: F2_128, k_point: &[F2_128]) -> F2_128 {
    let mut value = valid;
    for (bit, k) in bits.iter().zip(k_point) {
        value = value * (F2_128::from(1u64) + *bit + *k);
    }
    value
}

fn sumcheck_terms(
    factors: &[Vec<F2_128>],
    degrees: &[usize],
    transcript: &mut Sha256Transcript,
    mut summand: impl FnMut(&[Vec<F2_128>]) -> F2_128,
) -> Result<(Vec<Vec<F2_128>>, Vec<F2_128>), ProofError> {
    let len = factors[0].len();
    if factors.iter().any(|factor| factor.len() != len) {
        return Err(ProofError::DimensionMismatch);
    }
    let rounds = len.trailing_zeros() as usize;
    if degrees.len() != rounds {
        return Err(ProofError::DimensionMismatch);
    }
    let mut factors = factors.to_vec();
    let mut polynomials = Vec::with_capacity(rounds);
    let mut challenges = Vec::with_capacity(rounds);
    for degree in degrees {
        let mut polynomial = Vec::with_capacity(degree + 1);
        for point in 0..=*degree {
            let point = F2_128::from(point as u64);
            let folded = factors
                .iter()
                .map(|factor| fold(factor, point))
                .collect::<Vec<_>>();
            polynomial.push(summand(&folded));
        }
        for coefficient in &polynomial {
            transcript.absorb("round", &coefficient.value().to_le_bytes());
        }
        let challenge = challenge(transcript, "sumcheck");
        for factor in &mut factors {
            *factor = fold(factor, challenge);
        }
        polynomials.push(polynomial);
        challenges.push(challenge);
    }
    Ok((polynomials, challenges))
}

fn replay_terms_derived(
    rounds: &[Vec<F2_128>],
    mut sum: F2_128,
    transcript: &mut Sha256Transcript,
) -> Option<(F2_128, Vec<F2_128>)> {
    let mut challenges = Vec::with_capacity(rounds.len());
    for round in rounds {
        if round.len() < 2 || round[0] + round[1] != sum {
            return None;
        }
        for coefficient in round {
            transcript.absorb("round", &coefficient.value().to_le_bytes());
        }
        let challenge = challenge(transcript, "sumcheck");
        challenges.push(challenge);
        sum = interpolate_values(round, challenge);
    }
    Some((sum, challenges))
}

fn absorb_point(transcript: &mut Sha256Transcript, label: &str, point: &[F2_128]) {
    for value in point {
        transcript.absorb(label, &value.value().to_le_bytes());
    }
}

fn absorb_mosaic_commitment(transcript: &mut Sha256Transcript, commitment: &P3MosaicCommitment) {
    transcript.absorb(
        "commitment",
        &bincode::serialize(commitment).unwrap_or_default(),
    );
}

#[allow(clippy::too_many_arguments)]
struct TwistValueEvals {
    read: F2_128,
    write: F2_128,
    initial_read: F2_128,
    initial_write: F2_128,
    initial_update: F2_128,
}

#[allow(clippy::too_many_arguments, clippy::needless_range_loop)]
fn push_twist_value_points(
    points: &mut Vec<P3MosaicPoint>,
    expected: &mut Vec<Vec<F2_128>>,
    table_index: usize,
    read_point: &[F2_128],
    write_point: &[F2_128],
    initial_read_point: &[F2_128],
    initial_write_point: &[F2_128],
    initial_update_point: &[F2_128],
    evals: TwistValueEvals,
) {
    for (point, value) in [
        (initial_read_point, evals.initial_read),
        (initial_write_point, evals.initial_write),
        (initial_update_point, evals.initial_update),
    ] {
        points.push(P3MosaicPoint {
            table: table_index + 2,
            point: inc_point(point),
            columns: vec![0],
            next_columns: Vec::new(),
        });
        expected.push(vec![value]);
    }
    points.push(P3MosaicPoint {
        table: table_index + 3,
        point: inc_point(read_point),
        columns: vec![0],
        next_columns: Vec::new(),
    });
    expected.push(vec![evals.read]);
    points.push(P3MosaicPoint {
        table: table_index + 4,
        point: inc_point(write_point),
        columns: vec![0],
        next_columns: Vec::new(),
    });
    expected.push(vec![evals.write]);
}

/// Build all BinaryTwist claims against a commitment owned by an outer proof.
///
/// `table_index` is the address table's index in that commitment; the compact
/// increment table sits immediately after it.
#[allow(clippy::needless_range_loop)]
pub(crate) fn prove_binary_twist_claims(
    tables: &BatchTables,
    witness: &BinaryTwistWitness,
    commitment: &P3MosaicCommitment,
    table_index: usize,
) -> Result<ClaimedRam, ProofError> {
    let addr = tables.address_columns();
    let increments = tables.increments();
    let cells = witness.initial.len();
    let cycles = 1usize << tables.cycle_bits;
    let a = tables.address_bits;
    let n = tables.cycle_bits;
    let addr_columns = tables.column_count();
    let col_bits = tables.column_bits();
    let ra_valid = 2 * a;
    let wa_valid = 2 * a + 1;
    let mut addr_points = Vec::new();
    let mut addr_expected = Vec::new();
    let mut inc_points = Vec::new();
    let mut inc_expected = Vec::new();

    // Booleanity of every committed address bit and validity column.
    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-address-boolean");
    absorb_mosaic_commitment(&mut transcript, commitment);
    let rho_c = sample_point(&mut transcript, col_bits);
    let rho_j = sample_point(&mut transcript, n);
    let eq_c = eq_vector(&rho_c, 1usize << col_bits);
    let eq_j = eq_vector(&rho_j, cycles);
    let boolean_terms = (1usize << col_bits) * cycles;
    let mut factors = vec![vec![F2_128::from(0u64); boolean_terms]; 4];
    for column in 0..1usize << col_bits {
        for cycle in 0..cycles {
            let index = column * cycles + cycle;
            factors[0][index] = eq_c[column];
            factors[1][index] = eq_j[cycle];
            let value = if column < addr_columns {
                addr[column][cycle]
            } else {
                F2_128::from(0u64)
            };
            factors[2][index] = value;
            factors[3][index] = value + F2_128::from(1u64);
        }
    }
    let boolean_rounds = boolean_terms.trailing_zeros() as usize;
    let boolean_degrees = vec![4usize; boolean_rounds];
    let (rounds, challenges) =
        sumcheck_terms(&factors, &boolean_degrees, &mut transcript, |folded| {
            (0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
                sum + folded[0][index] * folded[1][index] * folded[2][index] * folded[3][index]
            })
        })?;
    let r_j = &challenges[..n];
    let _r_c = &challenges[n..];
    let bit_evals = (0..addr_columns)
        .map(|column| fold_all(&addr[column], r_j))
        .collect::<Vec<_>>();
    let boolean_evals = bit_evals.clone();
    let boolean = AddressBooleanClaim { rounds };
    addr_points.push(P3MosaicPoint {
        table: table_index,
        point: inc_point(r_j),
        columns: (0..addr_columns).collect(),
        next_columns: Vec::new(),
    });
    addr_expected.push(bit_evals);

    // Read initial part: eq * RA * M0.
    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-read");
    absorb_mosaic_commitment(&mut transcript, commitment);
    let rho_j = sample_point(&mut transcript, n);
    let eq_j = eq_vector(&rho_j, cycles);
    let read_point = rho_j.clone();
    let claimed_read = eq_j
        .iter()
        .zip(&witness.read_value)
        .fold(F2_128::from(0u64), |sum, (weight, value)| {
            sum + *weight * *value
        });
    transcript.absorb("claimed-read", &claimed_read.value().to_le_bytes());

    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-read-initial");
    absorb_mosaic_commitment(&mut transcript, commitment);
    absorb_point(&mut transcript, "cycle", &rho_j);
    let initial_terms = cells * cycles;
    let mut factors = vec![vec![F2_128::from(0u64); initial_terms]; a + 3];
    for cell in 0..cells {
        for cycle in 0..cycles {
            let index = cell * cycles + cycle;
            factors[0][index] = eq_j[cycle];
            factors[1][index] = addr[ra_valid][cycle];
            factors[2][index] = witness.initial[cell];
            for bit in 0..a {
                let k = F2_128::from(((cell >> bit) & 1) as u64);
                factors[3 + bit][index] = F2_128::from(1u64) + addr[bit][cycle] + k;
            }
        }
    }
    let mut initial_degrees = vec![a + 2; initial_terms.trailing_zeros() as usize];
    for degree in initial_degrees.iter_mut().skip(n) {
        *degree = 2;
    }
    let (rounds, challenges) =
        sumcheck_terms(&factors, &initial_degrees, &mut transcript, |folded| {
            (0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
                let mut address = folded[1][index];
                for bit in 0..a {
                    address = address * folded[3 + bit][index];
                }
                sum + folded[0][index] * folded[2][index] * address
            })
        })?;
    let r_j = &challenges[..n];
    let r_k = &challenges[n..];
    let initial_read_point = r_k.to_vec();
    let initial_read_eval = fold_all(&witness.initial, r_k);
    let ra_bit_evals = (0..a)
        .map(|bit| fold_all(&addr[bit], r_j))
        .collect::<Vec<_>>();
    let ra_valid_eval = fold_all(&addr[ra_valid], r_j);
    let read_initial_addr = {
        let mut values = ra_bit_evals.clone();
        values.push(ra_valid_eval);
        values
    };
    let initial_claim = ReadInitialClaim {
        claimed: {
            let mut total = F2_128::from(0u64);
            for cell in 0..cells {
                for cycle in 0..cycles {
                    let mut address = addr[ra_valid][cycle];
                    for bit in 0..a {
                        let k = F2_128::from(((cell >> bit) & 1) as u64);
                        address = address * (F2_128::from(1u64) + addr[bit][cycle] + k);
                    }
                    total = total + eq_j[cycle] * witness.initial[cell] * address;
                }
            }
            total
        },
        rounds,
    };
    let mut read_columns = (0..a).collect::<Vec<_>>();
    read_columns.push(ra_valid);
    addr_points.push(P3MosaicPoint {
        table: table_index,
        point: inc_point(r_j),
        columns: read_columns.clone(),
        next_columns: Vec::new(),
    });
    let mut read_values = ra_bit_evals.clone();
    read_values.push(ra_valid_eval);
    addr_expected.push(read_values);

    // Read history part: eq * LT * Inc * RA * WA.
    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-read-history");
    absorb_mosaic_commitment(&mut transcript, commitment);
    absorb_point(&mut transcript, "cycle", &rho_j);
    let history_terms = cycles * cycles;
    let mut factors = vec![vec![F2_128::from(0u64); history_terms]; a + 5];
    for cycle in 0..cycles {
        for previous in 0..cycles {
            let index = cycle * cycles + previous;
            factors[0][index] = eq_j[cycle];
            factors[1][index] = if previous < cycle {
                F2_128::from(1u64)
            } else {
                F2_128::from(0u64)
            };
            factors[2][index] = increments[previous];
            factors[3][index] = addr[ra_valid][cycle];
            factors[4][index] = addr[wa_valid][previous];
            for bit in 0..a {
                factors[5 + bit][index] =
                    F2_128::from(1u64) + addr[bit][cycle] + addr[a + bit][previous];
            }
        }
    }
    let mut history_degrees = vec![a + 3; history_terms.trailing_zeros() as usize];
    if history_degrees.len() >= 2 * n {
        for degree in history_degrees.iter_mut().skip(n).take(n) {
            *degree = a + 3;
        }
    }
    let (rounds, challenges) =
        sumcheck_terms(&factors, &history_degrees, &mut transcript, |folded| {
            (0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
                let mut equality = F2_128::from(1u64);
                for bit in 0..a {
                    equality = equality * folded[5 + bit][index];
                }
                sum + folded[0][index]
                    * folded[1][index]
                    * folded[2][index]
                    * folded[3][index]
                    * folded[4][index]
                    * equality
            })
        })?;
    let r_previous = &challenges[..n];
    let r_j = &challenges[n..];
    let ra_bit_evals = (0..a)
        .map(|bit| fold_all(&addr[bit], r_j))
        .collect::<Vec<_>>();
    let ra_valid_eval = fold_all(&addr[ra_valid], r_j);
    let wa_bit_evals = (0..a)
        .map(|bit| fold_all(&addr[a + bit], r_previous))
        .collect::<Vec<_>>();
    let wa_valid_eval = fold_all(&addr[wa_valid], r_previous);
    let inc_eval = fold_all(increments, &inc_point(r_previous));
    let read_history_values = {
        let mut values = ra_bit_evals.clone();
        values.push(ra_valid_eval);
        values.extend(wa_bit_evals.iter().copied());
        values.push(wa_valid_eval);
        values.push(inc_eval);
        values
    };
    let history_claim = ReadHistoryClaim {
        claimed: {
            let mut total = F2_128::from(0u64);
            for cycle in 0..cycles {
                for previous in 0..cycles {
                    if previous >= cycle {
                        continue;
                    }
                    let mut equality = F2_128::from(1u64);
                    for bit in 0..a {
                        equality = equality
                            * (F2_128::from(1u64) + addr[bit][cycle] + addr[a + bit][previous]);
                    }
                    total = total
                        + eq_j[cycle]
                            * increments[previous]
                            * addr[ra_valid][cycle]
                            * addr[wa_valid][previous]
                            * equality;
                }
            }
            total
        },
        rounds,
    };
    addr_points.push(P3MosaicPoint {
        table: table_index,
        point: inc_point(r_j),
        columns: read_columns.clone(),
        next_columns: Vec::new(),
    });
    let mut read_values = ra_bit_evals;
    read_values.push(ra_valid_eval);
    addr_expected.push(read_values);
    let mut write_columns = (a..2 * a).collect::<Vec<_>>();
    write_columns.push(wa_valid);
    addr_points.push(P3MosaicPoint {
        table: table_index,
        point: inc_point(r_previous),
        columns: write_columns,
        next_columns: Vec::new(),
    });
    let mut write_values = wa_bit_evals;
    write_values.push(wa_valid_eval);
    addr_expected.push(write_values);
    inc_points.push(P3MosaicPoint {
        table: table_index + 1,
        point: inc_point(r_previous),
        columns: vec![0],
        next_columns: Vec::new(),
    });
    inc_expected.push(vec![inc_eval]);
    let read = BinaryTwistReadClaim {
        initial: initial_claim,
        history: history_claim,
    };

    // Write base part: eq * WA * (M0 + Inc).
    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-write");
    absorb_mosaic_commitment(&mut transcript, commitment);
    let rho_j = sample_point(&mut transcript, n);
    let eq_j = eq_vector(&rho_j, cycles);
    let write_point = rho_j.clone();
    let claimed_write = eq_j
        .iter()
        .zip(&witness.write_value)
        .fold(F2_128::from(0u64), |sum, (weight, value)| {
            sum + *weight * *value
        });
    transcript.absorb("claimed-write", &claimed_write.value().to_le_bytes());

    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-write-base");
    absorb_mosaic_commitment(&mut transcript, commitment);
    absorb_point(&mut transcript, "cycle", &rho_j);
    let base_terms = cells * cycles;
    let mut factors = vec![vec![F2_128::from(0u64); base_terms]; a + 4];
    for cell in 0..cells {
        for cycle in 0..cycles {
            let index = cell * cycles + cycle;
            factors[0][index] = eq_j[cycle];
            factors[1][index] = addr[wa_valid][cycle];
            factors[2][index] = witness.initial[cell];
            factors[3][index] = increments[cycle];
            for bit in 0..a {
                let k = F2_128::from(((cell >> bit) & 1) as u64);
                factors[4 + bit][index] = F2_128::from(1u64) + addr[a + bit][cycle] + k;
            }
        }
    }
    let mut base_degrees = vec![a + 3; base_terms.trailing_zeros() as usize];
    for degree in base_degrees.iter_mut().skip(n) {
        *degree = 2;
    }
    let (rounds, challenges) =
        sumcheck_terms(&factors, &base_degrees, &mut transcript, |folded| {
            (0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
                let mut address = folded[1][index];
                for bit in 0..a {
                    address = address * folded[4 + bit][index];
                }
                sum + folded[0][index] * address * (folded[2][index] + folded[3][index])
            })
        })?;
    let r_j = &challenges[..n];
    let r_k = &challenges[n..];
    let initial_write_point = r_k.to_vec();
    let initial_write_eval = fold_all(&witness.initial, r_k);
    let wa_bit_evals = (0..a)
        .map(|bit| fold_all(&addr[a + bit], r_j))
        .collect::<Vec<_>>();
    let wa_valid_eval = fold_all(&addr[wa_valid], r_j);
    let inc_eval = fold_all(increments, &inc_point(r_j));
    let write_base_values = {
        let mut values = wa_bit_evals.clone();
        values.push(wa_valid_eval);
        values.push(inc_eval);
        values
    };
    let base_claim = WriteBaseClaim {
        claimed: {
            let mut total = F2_128::from(0u64);
            for cell in 0..cells {
                for cycle in 0..cycles {
                    let mut address = addr[wa_valid][cycle];
                    for bit in 0..a {
                        let k = F2_128::from(((cell >> bit) & 1) as u64);
                        address = address * (F2_128::from(1u64) + addr[a + bit][cycle] + k);
                    }
                    total =
                        total + eq_j[cycle] * address * (witness.initial[cell] + increments[cycle]);
                }
            }
            total
        },
        rounds,
    };
    let mut write_columns = (a..2 * a).collect::<Vec<_>>();
    write_columns.push(wa_valid);
    addr_points.push(P3MosaicPoint {
        table: table_index,
        point: inc_point(r_j),
        columns: write_columns.clone(),
        next_columns: Vec::new(),
    });
    let mut base_values = wa_bit_evals;
    base_values.push(wa_valid_eval);
    addr_expected.push(base_values);
    inc_points.push(P3MosaicPoint {
        table: table_index + 1,
        point: inc_point(r_j),
        columns: vec![0],
        next_columns: Vec::new(),
    });
    inc_expected.push(vec![inc_eval]);

    // Write history part: eq * LT * Inc * WA * WA.
    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-write-history");
    absorb_mosaic_commitment(&mut transcript, commitment);
    absorb_point(&mut transcript, "cycle", &rho_j);
    let history_terms = cycles * cycles;
    let mut factors = vec![vec![F2_128::from(0u64); history_terms]; a + 5];
    for cycle in 0..cycles {
        for previous in 0..cycles {
            let index = cycle * cycles + previous;
            factors[0][index] = eq_j[cycle];
            factors[1][index] = if previous < cycle {
                F2_128::from(1u64)
            } else {
                F2_128::from(0u64)
            };
            factors[2][index] = increments[previous];
            factors[3][index] = addr[wa_valid][cycle];
            factors[4][index] = addr[wa_valid][previous];
            for bit in 0..a {
                factors[5 + bit][index] =
                    F2_128::from(1u64) + addr[a + bit][cycle] + addr[a + bit][previous];
            }
        }
    }
    let history_degrees = vec![a + 3; history_terms.trailing_zeros() as usize];
    let (rounds, challenges) =
        sumcheck_terms(&factors, &history_degrees, &mut transcript, |folded| {
            (0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
                let mut equality = F2_128::from(1u64);
                for bit in 0..a {
                    equality = equality * folded[5 + bit][index];
                }
                sum + folded[0][index]
                    * folded[1][index]
                    * folded[2][index]
                    * folded[3][index]
                    * folded[4][index]
                    * equality
            })
        })?;
    let r_previous = &challenges[..n];
    let r_j = &challenges[n..];
    let current_bits = (0..a)
        .map(|bit| fold_all(&addr[a + bit], r_j))
        .collect::<Vec<_>>();
    let current_valid = fold_all(&addr[wa_valid], r_j);
    let current_inc = fold_all(increments, &inc_point(r_j));
    let successor_bits = (0..a)
        .map(|bit| fold_all(&addr[a + bit], r_previous))
        .collect::<Vec<_>>();
    let successor_valid = fold_all(&addr[wa_valid], r_previous);
    let successor_inc = fold_all(increments, &inc_point(r_previous));
    let write_history_values = {
        let mut values = current_bits.clone();
        values.push(current_valid);
        values.push(current_inc);
        values.extend(successor_bits.iter().copied());
        values.push(successor_valid);
        values.push(successor_inc);
        values
    };
    let history_claim = WriteHistoryClaim {
        claimed: {
            let mut total = F2_128::from(0u64);
            for cycle in 0..cycles {
                for previous in 0..cycles {
                    if previous >= cycle {
                        continue;
                    }
                    let mut equality = F2_128::from(1u64);
                    for bit in 0..a {
                        equality = equality
                            * (F2_128::from(1u64) + addr[a + bit][cycle] + addr[a + bit][previous]);
                    }
                    total = total
                        + eq_j[cycle]
                            * increments[previous]
                            * addr[wa_valid][cycle]
                            * addr[wa_valid][previous]
                            * equality;
                }
            }
            total
        },
        rounds,
    };
    addr_points.push(P3MosaicPoint {
        table: table_index,
        point: inc_point(r_j),
        columns: write_columns.clone(),
        next_columns: Vec::new(),
    });
    let mut current_values = current_bits;
    current_values.push(current_valid);
    addr_expected.push(current_values);
    inc_points.push(P3MosaicPoint {
        table: table_index + 1,
        point: inc_point(r_j),
        columns: vec![0],
        next_columns: Vec::new(),
    });
    inc_expected.push(vec![current_inc]);
    addr_points.push(P3MosaicPoint {
        table: table_index,
        point: inc_point(r_previous),
        columns: write_columns,
        next_columns: Vec::new(),
    });
    let mut successor_values = successor_bits;
    successor_values.push(successor_valid);
    addr_expected.push(successor_values);
    inc_points.push(P3MosaicPoint {
        table: table_index + 1,
        point: inc_point(r_previous),
        columns: vec![0],
        next_columns: Vec::new(),
    });
    inc_expected.push(vec![successor_inc]);
    let write = BinaryTwistWriteClaim {
        base: base_claim,
        history: history_claim,
    };

    // Final state: final(k) = M0(k) + sum_j WA(k,j) Inc(j).
    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-final");
    absorb_mosaic_commitment(&mut transcript, commitment);
    let rho_k = sample_point(&mut transcript, a);
    let eq_k = eq_vector(&rho_k, cells);
    let final_terms = cells * cycles;
    let mut factors = vec![vec![F2_128::from(0u64); final_terms]; a + 6];
    for cell in 0..cells {
        for cycle in 0..cycles {
            let index = cell * cycles + cycle;
            factors[0][index] = eq_k[cell];
            factors[1][index] = if cycle == 0 {
                F2_128::from(1u64)
            } else {
                F2_128::from(0u64)
            };
            factors[2][index] = tables.final_values[cell];
            factors[3][index] = witness.initial[cell];
            factors[4][index] = addr[wa_valid][cycle];
            for bit in 0..a {
                let k = F2_128::from(((cell >> bit) & 1) as u64);
                factors[5 + bit][index] = F2_128::from(1u64) + addr[a + bit][cycle] + k;
            }
            factors[5 + a][index] = increments[cycle];
        }
    }
    let final_rounds = final_terms.trailing_zeros() as usize;
    let mut final_degrees = vec![a + 2; final_rounds];
    for degree in final_degrees.iter_mut().skip(n) {
        *degree = 2;
    }
    let (rounds, challenges) =
        sumcheck_terms(&factors, &final_degrees, &mut transcript, |folded| {
            (0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
                let mut write_address = folded[4][index];
                for bit in 0..a {
                    write_address = write_address * folded[5 + bit][index];
                }
                sum + folded[0][index]
                    * (folded[1][index] * (folded[2][index] + folded[3][index])
                        + write_address * folded[5 + a][index])
            })
        })?;
    let r_jp = &challenges[..n];
    let r_k = &challenges[n..];
    let initial_update_point = r_k.to_vec();
    let initial_update_eval = fold_all(&witness.initial, r_k);
    let wa_bit_evals = (0..a)
        .map(|bit| fold_all(&addr[a + bit], r_jp))
        .collect::<Vec<_>>();
    let wa_valid_eval = fold_all(&addr[wa_valid], r_jp);
    let inc_eval = fold_all(increments, &inc_point(r_jp));
    let final_eval = fold_all(&tables.final_values, r_k);
    let final_values_evals = {
        let mut values = wa_bit_evals.clone();
        values.push(wa_valid_eval);
        values.push(inc_eval);
        values.push(final_eval);
        values
    };
    let update = BinaryTwistUpdateClaim { rounds };
    let mut final_columns = (a..2 * a).collect::<Vec<_>>();
    final_columns.push(wa_valid);
    addr_points.push(P3MosaicPoint {
        table: table_index,
        point: inc_point(r_jp),
        columns: final_columns,
        next_columns: Vec::new(),
    });
    let mut final_values = wa_bit_evals;
    final_values.push(wa_valid_eval);
    addr_expected.push(final_values);
    inc_points.push(P3MosaicPoint {
        table: table_index + 1,
        point: inc_point(r_jp),
        columns: vec![0],
        next_columns: Vec::new(),
    });
    inc_expected.push(vec![inc_eval]);

    push_twist_value_points(
        &mut addr_points,
        &mut addr_expected,
        table_index,
        &read_point,
        &write_point,
        &initial_read_point,
        &initial_write_point,
        &initial_update_point,
        TwistValueEvals {
            read: claimed_read,
            write: claimed_write,
            initial_read: initial_read_eval,
            initial_write: initial_write_eval,
            initial_update: initial_update_eval,
        },
    );
    addr_points.extend(inc_points);
    addr_expected.extend(inc_expected);
    Ok((
        BinaryTwistRamProof {
            boolean,
            read,
            write,
            update,
            opening: None,
            read_value_eval: claimed_read,
            write_value_eval: claimed_write,
            initial_read_eval,
            initial_write_eval,
            initial_update_eval,
            boolean_evals,
            read_initial_addr,
            read_history_values,
            write_base_values,
            write_history_values,
            final_values_evals,
            cycle_bits: tables.cycle_bits,
            address_bits: tables.address_bits,
        },
        (addr_points, addr_expected),
    ))
}

pub fn prove_binary_twist_ram(
    witness: &BinaryTwistWitness,
) -> Result<BinaryTwistRamProof, ProofError> {
    witness
        .validate()
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let tables = batch_tables(witness)?;
    let pcs = P3BinaryPcs::new(100);
    let mosaic_tables = vec![
        tables.addr.clone(),
        tables.inc.clone(),
        tables.initial.clone(),
        tables.read_value.clone(),
        tables.write_value.clone(),
    ];
    let commitment = pcs.commit_mosaic(&mosaic_tables)?;
    let (mut proof, (points, expected)) =
        prove_binary_twist_claims(&tables, witness, &commitment, 0)?;
    let mut pairs = points.into_iter().zip(expected).collect::<Vec<_>>();
    pairs.sort_by_key(|(point, _)| point.table);
    let (points, expected): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
    let opening = pcs.open_mosaic(&mosaic_tables, &points)?;
    debug_assert!(pcs.verify_mosaic(&opening, &points, &expected)?);
    proof.opening = Some(opening);
    Ok(proof)
}

pub(crate) fn verify_binary_twist_claims(
    _witness: &BinaryTwistWitness,
    proof: &BinaryTwistRamProof,
    commitment: &P3MosaicCommitment,
    table_index: usize,
) -> Result<Option<MosaicClaims>, ProofError> {
    verify_binary_twist_from_proof(proof, commitment, table_index)
}

pub(crate) fn verify_binary_twist_from_proof(
    proof: &BinaryTwistRamProof,
    commitment: &P3MosaicCommitment,
    table_index: usize,
) -> Result<Option<MosaicClaims>, ProofError> {
    if commitment.tables.len() <= table_index + 4 {
        return Ok(None);
    }
    let cycle_bits = proof.cycle_bits;
    let address_bits = proof.address_bits;
    let addr_columns = 2 * address_bits + 2;
    let cycles = 1usize << cycle_bits;
    if commitment.tables.len() <= table_index + 1
        || commitment.tables[table_index].num_variables != cycle_bits.max(1)
        || commitment.tables[table_index].num_columns != addr_columns
        || commitment.tables[table_index + 1].num_variables != cycle_bits.max(1)
        || commitment.tables[table_index + 1].num_columns != 1
    {
        return Ok(None);
    }
    let mut addr_points = Vec::new();
    let mut addr_expected = Vec::new();
    let mut inc_points = Vec::new();
    let mut inc_expected = Vec::new();
    let col_bits = addr_columns.next_power_of_two().trailing_zeros() as usize;
    let wa_valid = 2 * address_bits + 1;

    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-address-boolean");
    absorb_mosaic_commitment(&mut transcript, commitment);
    let rho_c = sample_point(&mut transcript, col_bits);
    let rho_j = sample_point(&mut transcript, cycle_bits);
    let Some((sum, boolean_challenges)) =
        replay_terms_derived(&proof.boolean.rounds, F2_128::from(0u64), &mut transcript)
    else {
        return Ok(None);
    };
    let r_j = &boolean_challenges[..cycle_bits];
    let r_c = &boolean_challenges[cycle_bits..];
    let bit_evals = proof.boolean_evals.clone();
    let eq_c_eval = eq_points(&rho_c, r_c);
    let eq_j_eval = eq_points(&rho_j, r_j);
    let mut b_eval = F2_128::from(0u64);
    for (column, eval) in bit_evals.iter().enumerate() {
        b_eval = b_eval + eq_at_index(r_c, column) * *eval;
    }
    let terminal = eq_c_eval * eq_j_eval * b_eval * (b_eval + F2_128::from(1u64));
    if sum != terminal {
        return Ok(None);
    }
    addr_points.push(P3MosaicPoint {
        table: table_index,
        point: inc_point(r_j),
        columns: (0..addr_columns).collect(),
        next_columns: Vec::new(),
    });
    addr_expected.push(bit_evals.clone());

    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-read");
    absorb_mosaic_commitment(&mut transcript, commitment);
    let rho_j = sample_point(&mut transcript, cycle_bits);
    let read_point = rho_j.clone();
    let claimed_read = proof.read_value_eval;

    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-read-initial");
    absorb_mosaic_commitment(&mut transcript, commitment);
    absorb_point(&mut transcript, "cycle", &rho_j);
    let Some((sum, initial_challenges)) = replay_terms_derived(
        &proof.read.initial.rounds,
        proof.read.initial.claimed,
        &mut transcript,
    ) else {
        return Ok(None);
    };
    let r_j = &initial_challenges[..cycle_bits];
    let r_k = &initial_challenges[cycle_bits..];
    let initial_read_point = r_k.to_vec();
    let initial_read_eval = proof.initial_read_eval;
    let read_initial_addr = proof.read_initial_addr.clone();
    let ra_bit_evals = read_initial_addr[..address_bits].to_vec();
    let ra_valid_eval = read_initial_addr[address_bits];
    let eq_eval = eq_points(&rho_j, r_j);
    let m0_eval = proof.initial_read_eval;
    let ra_eval = address_value(&ra_bit_evals, ra_valid_eval, r_k);
    if sum != eq_eval * m0_eval * ra_eval {
        return Ok(None);
    }
    let mut read_columns = (0..address_bits).collect::<Vec<_>>();
    read_columns.push(2 * address_bits);
    addr_points.push(P3MosaicPoint {
        table: table_index,
        point: inc_point(r_j),
        columns: read_columns.clone(),
        next_columns: Vec::new(),
    });
    let mut read_values = ra_bit_evals.clone();
    read_values.push(ra_valid_eval);
    addr_expected.push(read_values);

    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-read-history");
    absorb_mosaic_commitment(&mut transcript, commitment);
    absorb_point(&mut transcript, "cycle", &rho_j);
    let Some((sum, history_challenges)) = replay_terms_derived(
        &proof.read.history.rounds,
        proof.read.history.claimed,
        &mut transcript,
    ) else {
        return Ok(None);
    };
    if proof.read.initial.claimed + proof.read.history.claimed != claimed_read {
        return Ok(None);
    }
    let r_previous = &history_challenges[..cycle_bits];
    let r_j = &history_challenges[cycle_bits..];
    let read_history_values = proof.read_history_values.clone();
    let ra_bit_evals = read_history_values[..address_bits].to_vec();
    let ra_valid_eval = read_history_values[address_bits];
    let wa_start = address_bits + 1;
    let wa_bit_evals = read_history_values[wa_start..wa_start + address_bits].to_vec();
    let wa_valid_eval = read_history_values[wa_start + address_bits];
    let inc_eval = read_history_values[wa_start + address_bits + 1];
    let eq_eval = eq_points(&rho_j, r_j);
    let lt_eval = lt_mle(r_previous, r_j, cycles);
    let mut equality = F2_128::from(1u64);
    for (ra, wa) in ra_bit_evals.iter().zip(&wa_bit_evals) {
        equality = equality * (F2_128::from(1u64) + *ra + *wa);
    }
    let read_history_terminal =
        eq_eval * lt_eval * inc_eval * ra_valid_eval * wa_valid_eval * equality;
    if sum != read_history_terminal {
        return Ok(None);
    }
    addr_points.push(P3MosaicPoint {
        table: table_index,
        point: inc_point(r_j),
        columns: read_columns,
        next_columns: Vec::new(),
    });
    let mut read_values = ra_bit_evals.clone();
    read_values.push(ra_valid_eval);
    addr_expected.push(read_values);
    let mut write_columns = (address_bits..2 * address_bits).collect::<Vec<_>>();
    write_columns.push(2 * address_bits + 1);
    addr_points.push(P3MosaicPoint {
        table: table_index,
        point: inc_point(r_previous),
        columns: write_columns.clone(),
        next_columns: Vec::new(),
    });
    let mut write_values = wa_bit_evals.clone();
    write_values.push(wa_valid_eval);
    addr_expected.push(write_values);
    inc_points.push(P3MosaicPoint {
        table: table_index + 1,
        point: inc_point(r_previous),
        columns: vec![0],
        next_columns: Vec::new(),
    });
    inc_expected.push(vec![inc_eval]);

    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-write");
    absorb_mosaic_commitment(&mut transcript, commitment);
    let rho_j = sample_point(&mut transcript, cycle_bits);
    let write_point = rho_j.clone();
    let claimed_write = proof.write_value_eval;

    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-write-base");
    absorb_mosaic_commitment(&mut transcript, commitment);
    absorb_point(&mut transcript, "cycle", &rho_j);
    let Some((sum, base_challenges)) = replay_terms_derived(
        &proof.write.base.rounds,
        proof.write.base.claimed,
        &mut transcript,
    ) else {
        return Ok(None);
    };
    let r_j = &base_challenges[..cycle_bits];
    let r_k = &base_challenges[cycle_bits..];
    let initial_write_point = r_k.to_vec();
    let initial_write_eval = proof.initial_write_eval;
    let write_base_values = proof.write_base_values.clone();
    let wa_bit_evals = write_base_values[..address_bits].to_vec();
    let wa_valid_eval = write_base_values[address_bits];
    let inc_eval = write_base_values[address_bits + 1];
    let eq_eval = eq_points(&rho_j, r_j);
    let m0_eval = proof.initial_write_eval;
    let wa_eval = address_value(&wa_bit_evals, wa_valid_eval, r_k);
    if sum != eq_eval * wa_eval * (m0_eval + inc_eval) {
        return Ok(None);
    }
    let mut write_columns = (address_bits..2 * address_bits).collect::<Vec<_>>();
    write_columns.push(2 * address_bits + 1);
    addr_points.push(P3MosaicPoint {
        table: table_index,
        point: inc_point(r_j),
        columns: write_columns.clone(),
        next_columns: Vec::new(),
    });
    let mut base_values = wa_bit_evals.clone();
    base_values.push(wa_valid_eval);
    addr_expected.push(base_values);
    inc_points.push(P3MosaicPoint {
        table: table_index + 1,
        point: inc_point(r_j),
        columns: vec![0],
        next_columns: Vec::new(),
    });
    inc_expected.push(vec![inc_eval]);

    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-write-history");
    absorb_mosaic_commitment(&mut transcript, commitment);
    absorb_point(&mut transcript, "cycle", &rho_j);
    let Some((sum, history_challenges)) = replay_terms_derived(
        &proof.write.history.rounds,
        proof.write.history.claimed,
        &mut transcript,
    ) else {
        return Ok(None);
    };
    if proof.write.base.claimed + proof.write.history.claimed != claimed_write {
        return Ok(None);
    }
    let r_previous = &history_challenges[..cycle_bits];
    let r_j = &history_challenges[cycle_bits..];
    let write_history_values = proof.write_history_values.clone();
    let current_start = 0;
    let current_bits = write_history_values[current_start..current_start + address_bits].to_vec();
    let current_valid = write_history_values[current_start + address_bits];
    let current_inc = write_history_values[current_start + address_bits + 1];
    let successor_start = current_start + address_bits + 2;
    let successor_bits =
        write_history_values[successor_start..successor_start + address_bits].to_vec();
    let successor_valid = write_history_values[successor_start + address_bits];
    let successor_inc = write_history_values[successor_start + address_bits + 1];
    let eq_eval = eq_points(&rho_j, r_j);
    let lt_eval = lt_mle(r_previous, r_j, cycles);
    let mut equality = F2_128::from(1u64);
    for (current, successor) in current_bits.iter().zip(&successor_bits) {
        equality = equality * (F2_128::from(1u64) + *current + *successor);
    }
    let write_history_terminal =
        eq_eval * lt_eval * successor_inc * current_valid * successor_valid * equality;
    if sum != write_history_terminal {
        return Ok(None);
    }
    addr_points.push(P3MosaicPoint {
        table: table_index,
        point: inc_point(r_j),
        columns: write_columns.clone(),
        next_columns: Vec::new(),
    });
    let mut current_values = current_bits.clone();
    current_values.push(current_valid);
    addr_expected.push(current_values);
    inc_points.push(P3MosaicPoint {
        table: table_index + 1,
        point: inc_point(r_j),
        columns: vec![0],
        next_columns: Vec::new(),
    });
    inc_expected.push(vec![current_inc]);
    addr_points.push(P3MosaicPoint {
        table: table_index,
        point: inc_point(r_previous),
        columns: write_columns,
        next_columns: Vec::new(),
    });
    let mut successor_values = successor_bits.clone();
    successor_values.push(successor_valid);
    addr_expected.push(successor_values);
    inc_points.push(P3MosaicPoint {
        table: table_index + 1,
        point: inc_point(r_previous),
        columns: vec![0],
        next_columns: Vec::new(),
    });
    inc_expected.push(vec![successor_inc]);

    let mut transcript = Sha256Transcript::new("magnetar-binary-twist-final");
    absorb_mosaic_commitment(&mut transcript, commitment);
    let rho_k = sample_point(&mut transcript, address_bits);
    let Some((sum, update_challenges)) =
        replay_terms_derived(&proof.update.rounds, F2_128::from(0u64), &mut transcript)
    else {
        return Ok(None);
    };
    let r_jp = &update_challenges[..cycle_bits];
    let r_k = &update_challenges[cycle_bits..];
    let initial_update_point = r_k.to_vec();
    let initial_update_eval = proof.initial_update_eval;
    let final_values_evals = proof.final_values_evals.clone();
    let wa_bit_evals = final_values_evals[..address_bits].to_vec();
    let wa_valid_eval = final_values_evals[address_bits];
    let inc_eval = final_values_evals[address_bits + 1];
    let final_eval = final_values_evals[address_bits + 2];
    let eq_eval = eq_points(&rho_k, r_k);
    let delta_eval = eq_at_index(r_jp, 0);
    let m0_eval = proof.initial_update_eval;
    let wa_eval = address_value(&wa_bit_evals, wa_valid_eval, r_k);
    let final_terminal = eq_eval * (delta_eval * (final_eval + m0_eval) + wa_eval * inc_eval);
    if sum != final_terminal {
        return Ok(None);
    }
    let mut final_columns = (address_bits..2 * address_bits).collect::<Vec<_>>();
    final_columns.push(wa_valid);
    addr_points.push(P3MosaicPoint {
        table: table_index,
        point: inc_point(r_jp),
        columns: final_columns,
        next_columns: Vec::new(),
    });
    let mut final_values = wa_bit_evals.clone();
    final_values.push(wa_valid_eval);
    addr_expected.push(final_values);
    inc_points.push(P3MosaicPoint {
        table: table_index + 1,
        point: inc_point(r_jp),
        columns: vec![0],
        next_columns: Vec::new(),
    });
    inc_expected.push(vec![inc_eval]);

    push_twist_value_points(
        &mut addr_points,
        &mut addr_expected,
        table_index,
        &read_point,
        &write_point,
        &initial_read_point,
        &initial_write_point,
        &initial_update_point,
        TwistValueEvals {
            read: claimed_read,
            write: claimed_write,
            initial_read: initial_read_eval,
            initial_write: initial_write_eval,
            initial_update: initial_update_eval,
        },
    );
    addr_points.extend(inc_points);
    addr_expected.extend(inc_expected);
    Ok(Some((addr_points, addr_expected)))
}

pub fn verify_binary_twist_ram(
    witness: &BinaryTwistWitness,
    proof: &BinaryTwistRamProof,
) -> Result<bool, ProofError> {
    let Some(opening) = &proof.opening else {
        return Ok(false);
    };
    if opening.commitment.tables.len() != 5 {
        return Ok(false);
    }
    let Some((points, expected)) =
        verify_binary_twist_claims(witness, proof, &opening.commitment, 0)?
    else {
        return Ok(false);
    };
    let mut pairs = points.into_iter().zip(expected).collect::<Vec<_>>();
    pairs.sort_by_key(|(point, _)| point.table);
    let (points, expected): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
    P3BinaryPcs::new(100).verify_mosaic(opening, &points, &expected)
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
        tampered.read.initial.rounds[0][0] =
            tampered.read.initial.rounds[0][0] + F2_128::from(1u64);
        assert!(!verify_binary_twist_ram(&witness, &tampered).unwrap());

        let mut tampered = proof.clone();
        tampered.write.base.rounds[0][0] = tampered.write.base.rounds[0][0] + F2_128::from(1u64);
        assert!(!verify_binary_twist_ram(&witness, &tampered).unwrap());

        let mut tampered = proof.clone();
        tampered.update.rounds[0][0] = tampered.update.rounds[0][0] + F2_128::from(1u64);
        assert!(!verify_binary_twist_ram(&witness, &tampered).unwrap());

        let mut tampered = proof.clone();
        tampered.read.initial.rounds[0][0] =
            tampered.read.initial.rounds[0][0] + F2_128::from(1u64);
        assert!(!verify_binary_twist_ram(&witness, &tampered).unwrap());

        let mut tampered = proof.clone();
        tampered.write.history.rounds[0][0] =
            tampered.write.history.rounds[0][0] + F2_128::from(1u64);
        assert!(!verify_binary_twist_ram(&witness, &tampered).unwrap());

        let mut tampered = proof.clone();
        tampered.boolean.rounds[0][0] = tampered.boolean.rounds[0][0] + F2_128::from(1u64);
        assert!(!verify_binary_twist_ram(&witness, &tampered).unwrap());

        let mut bad_witness = witness.clone();
        bad_witness.final_value[0] = bad_witness.final_value[0] + F2_128::from(1u64);
        assert!(!verify_binary_twist_ram(&bad_witness, &proof).unwrap());

        let mut bad_witness = witness;
        bad_witness.initial[0] = bad_witness.initial[0] + F2_128::from(1u64);
        assert!(!verify_binary_twist_ram(&bad_witness, &proof).unwrap());
    }

    #[test]
    fn lt_mle_matches_quadratic() {
        for bits in 1..6 {
            let cycles = 1usize << bits;
            let jp = (0..bits)
                .map(|index| F2_128::from((index * 7 + 3) as u64))
                .collect::<Vec<_>>();
            let j = (0..bits)
                .map(|index| F2_128::from((index * 5 + 1) as u64))
                .collect::<Vec<_>>();
            let mut quadratic = F2_128::from(0u64);
            for previous in 0..cycles {
                for cycle in 0..cycles {
                    if previous < cycle {
                        quadratic = quadratic + eq_at_index(&jp, previous) * eq_at_index(&j, cycle);
                    }
                }
            }
            assert_eq!(lt_mle(&jp, &j, cycles), quadratic);
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
