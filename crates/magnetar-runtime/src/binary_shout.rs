//! Reference BinaryShout reduction for the public instruction ROM.
//!
//! The prover commits to the bit-sliced address of every fetched instruction.
//! The verifier reconstructs the one-hot address at a random point, evaluates
//! the public ROM table there, and checks the claimed read values with a
//! sum-check. This is a standalone reference component; it is not yet wired
//! into `UnifiedTraceProof`.

use magnetar_constraint::{Field, F2_128};
use magnetar_pcs::{
    P3BinaryPcs, P3MosaicCommitment, P3MosaicOpening, P3MosaicPoint, P3MosaicTable,
};
use magnetar_proof::ProofError;
use magnetar_spec::Trace;
use magnetar_transcript::Sha256Transcript;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct BinaryShoutWitness {
    pub address_bits: usize,
    pub cycle_bits: usize,
    pub cycles: usize,
    pub cells: usize,
    pub rom: Vec<F2_128>,
    pub address: Vec<Vec<F2_128>>,
    pub valid: Vec<F2_128>,
    pub read_value: Vec<F2_128>,
}

impl BinaryShoutWitness {
    #[allow(clippy::needless_range_loop)]
    pub fn from_trace(trace: &Trace) -> Result<Self, ProofError> {
        let cells = trace.rom.len().next_power_of_two().max(2);
        let address_bits = cells.trailing_zeros() as usize;
        let cycles = trace.rows.len().next_power_of_two().max(2);
        let cycle_bits = cycles.trailing_zeros() as usize;
        let mut rom = vec![F2_128::from(0u64); cells];
        for (index, word) in trace.rom.iter().enumerate() {
            rom[index] = F2_128::from(u64::from(*word));
        }
        let mut address = vec![vec![F2_128::from(0u64); cycles]; address_bits];
        let mut valid = vec![F2_128::from(0u64); cycles];
        let mut read_value = vec![F2_128::from(0u64); cycles];
        for (cycle, row) in trace.rows.iter().enumerate() {
            if row.instruction_len != 4 {
                return Err(ProofError::Pcs(
                    "BinaryShout reference supports 32-bit instructions only".into(),
                ));
            }
            let offset = row
                .pc
                .checked_sub(trace.config.rom_base)
                .ok_or_else(|| ProofError::Pcs("row pc is below the ROM base".into()))?;
            let index = usize::try_from(offset / 4)
                .map_err(|_| ProofError::Pcs("ROM index overflows usize".into()))?;
            if index >= cells || offset % 4 != 0 {
                return Err(ProofError::Pcs("row pc is outside the ROM table".into()));
            }
            valid[cycle] = F2_128::from(1u64);
            for bit in 0..address_bits {
                address[bit][cycle] = F2_128::from(((index >> bit) & 1) as u64);
            }
            read_value[cycle] = F2_128::from(u64::from(row.instruction_word));
        }
        Ok(Self {
            address_bits,
            cycle_bits,
            cycles,
            cells,
            rom,
            address,
            valid,
            read_value,
        })
    }

    pub fn validate(&self) -> Result<(), ProofError> {
        if self.cells != 1usize << self.address_bits
            || self.cycles != 1usize << self.cycle_bits
            || self.rom.len() != self.cells
            || self.address.len() != self.address_bits
            || self
                .address
                .iter()
                .any(|column| column.len() != self.cycles)
            || self.read_value.len() != self.cycles
        {
            return Err(ProofError::DimensionMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddressBooleanClaim {
    pub column_point: Vec<F2_128>,
    pub cycle_point: Vec<F2_128>,
    pub rounds: Vec<Vec<F2_128>>,
    pub challenges: Vec<F2_128>,
    pub bit_evals: Vec<F2_128>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BinaryShoutProof {
    pub address_bits: usize,
    pub cycle_bits: usize,
    pub boolean: AddressBooleanClaim,
    pub claimed: F2_128,
    pub cycle_point: Vec<F2_128>,
    pub rounds: Vec<Vec<F2_128>>,
    pub challenges: Vec<F2_128>,
    pub ra_bit_evals: Vec<F2_128>,
    pub valid_eval: F2_128,
    pub opening: P3MosaicOpening,
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

fn interpolate(values: &[F2_128], r: F2_128) -> F2_128 {
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

fn challenge(transcript: &mut Sha256Transcript, label: &str) -> F2_128 {
    let bytes = transcript.challenge_32(label);
    let mut value = [0u8; 16];
    value.copy_from_slice(&bytes[..16]);
    F2_128::from_bits(u128::from_le_bytes(value))
}

fn sample_point(transcript: &mut Sha256Transcript, length: usize) -> Vec<F2_128> {
    (0..length)
        .map(|_| challenge(transcript, "point"))
        .collect()
}

fn absorb_commitment(transcript: &mut Sha256Transcript, commitment: &P3MosaicCommitment) {
    transcript.absorb(
        "commitment",
        &bincode::serialize(commitment).unwrap_or_default(),
    );
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

fn replay_terms(
    rounds: &[Vec<F2_128>],
    challenges: &[F2_128],
    mut sum: F2_128,
    transcript: &mut Sha256Transcript,
) -> Option<F2_128> {
    if rounds.len() != challenges.len() {
        return None;
    }
    for (round, &expected) in rounds.iter().zip(challenges) {
        if round.len() < 2 || round[0] + round[1] != sum {
            return None;
        }
        for coefficient in round {
            transcript.absorb("round", &coefficient.value().to_le_bytes());
        }
        let challenge = challenge(transcript, "sumcheck");
        if challenge != expected {
            return None;
        }
        sum = interpolate(round, challenge);
    }
    Some(sum)
}

fn address_value(bits: &[F2_128], k_point: &[F2_128]) -> F2_128 {
    bits.iter()
        .zip(k_point)
        .fold(F2_128::from(1u64), |acc, (bit, k)| {
            acc * (F2_128::from(1u64) + *bit + *k)
        })
}

#[allow(clippy::needless_range_loop)]
pub fn prove_binary_shout(witness: &BinaryShoutWitness) -> Result<BinaryShoutProof, ProofError> {
    witness.validate()?;
    let a = witness.address_bits;
    let n = witness.cycle_bits;
    let cycles = witness.cycles;
    let pcs = P3BinaryPcs::new(100);
    let mut columns = witness.address.clone();
    columns.push(witness.valid.clone());
    let table = P3MosaicTable { columns };
    let commitment = pcs.commit_mosaic(core::slice::from_ref(&table))?;

    let mut transcript = Sha256Transcript::new("magnetar-binary-shout-boolean");
    absorb_commitment(&mut transcript, commitment_ref(&commitment));
    let col_bits = (a + 1).next_power_of_two().trailing_zeros() as usize;
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
            let value = if column < a {
                witness.address[column][cycle]
            } else if column == a {
                witness.valid[cycle]
            } else {
                F2_128::from(0u64)
            };
            factors[2][index] = value;
            factors[3][index] = value + F2_128::from(1u64);
        }
    }
    let degrees = vec![4usize; boolean_terms.trailing_zeros() as usize];
    let (rounds, challenges) = sumcheck_terms(&factors, &degrees, &mut transcript, |folded| {
        (0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
            sum + folded[0][index] * folded[1][index] * folded[2][index] * folded[3][index]
        })
    })?;
    let r_j = &challenges[..n];
    let mut bit_evals = (0..a)
        .map(|bit| fold_all(&witness.address[bit], r_j))
        .collect::<Vec<_>>();
    bit_evals.push(fold_all(&witness.valid, r_j));
    let boolean = AddressBooleanClaim {
        column_point: rho_c,
        cycle_point: rho_j,
        rounds,
        challenges,
        bit_evals,
    };

    let mut transcript = Sha256Transcript::new("magnetar-binary-shout");
    absorb_commitment(&mut transcript, commitment_ref(&commitment));
    let rho_j = sample_point(&mut transcript, n);
    let eq_j = eq_vector(&rho_j, cycles);
    let claimed = eq_j
        .iter()
        .zip(&witness.read_value)
        .fold(F2_128::from(0u64), |sum, (weight, value)| {
            sum + *weight * *value
        });
    transcript.absorb("claimed", &claimed.value().to_le_bytes());
    let terms = witness.cells * cycles;
    let mut factors = vec![vec![F2_128::from(0u64); terms]; a + 3];
    for cell in 0..witness.cells {
        for cycle in 0..cycles {
            let index = cell * cycles + cycle;
            factors[0][index] = eq_j[cycle];
            factors[1][index] = witness.valid[cycle];
            factors[2][index] = witness.rom[cell];
            for bit in 0..a {
                let k = F2_128::from(((cell >> bit) & 1) as u64);
                factors[3 + bit][index] = F2_128::from(1u64) + witness.address[bit][cycle] + k;
            }
        }
    }
    let mut degrees = vec![a + 2; terms.trailing_zeros() as usize];
    for degree in degrees.iter_mut().skip(n) {
        *degree = 2;
    }
    let (rounds, challenges) = sumcheck_terms(&factors, &degrees, &mut transcript, |folded| {
        (0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
            let mut address = F2_128::from(1u64);
            for bit in 0..a {
                address = address * folded[3 + bit][index];
            }
            sum + folded[0][index] * folded[1][index] * folded[2][index] * address
        })
    })?;
    let r_j = &challenges[..n];
    let ra_bit_evals = (0..a)
        .map(|bit| fold_all(&witness.address[bit], r_j))
        .collect::<Vec<_>>();
    let valid_eval = fold_all(&witness.valid, r_j);
    let point = if r_j.is_empty() {
        vec![F2_128::from(0u64)]
    } else {
        r_j.to_vec()
    };
    let opening = pcs.open_mosaic(
        core::slice::from_ref(&table),
        &[
            P3MosaicPoint {
                table: 0,
                point: if boolean.challenges[..n].is_empty() {
                    vec![F2_128::from(0u64)]
                } else {
                    boolean.challenges[..n].to_vec()
                },
                columns: (0..=a).collect(),
                next_columns: Vec::new(),
            },
            P3MosaicPoint {
                table: 0,
                point,
                columns: (0..=a).collect(),
                next_columns: Vec::new(),
            },
        ],
    )?;
    Ok(BinaryShoutProof {
        address_bits: a,
        cycle_bits: n,
        boolean,
        claimed,
        cycle_point: rho_j,
        rounds,
        challenges,
        ra_bit_evals,
        valid_eval,
        opening,
    })
}

fn commitment_ref(commitment: &P3MosaicCommitment) -> &P3MosaicCommitment {
    commitment
}

#[allow(clippy::needless_range_loop)]
pub fn verify_binary_shout(
    witness: &BinaryShoutWitness,
    proof: &BinaryShoutProof,
) -> Result<bool, ProofError> {
    witness.validate()?;
    if proof.address_bits != witness.address_bits || proof.cycle_bits != witness.cycle_bits {
        return Ok(false);
    }
    let a = witness.address_bits;
    let n = witness.cycle_bits;
    let cycles = witness.cycles;
    let pcs = P3BinaryPcs::new(100);
    let col_bits = (a + 1).next_power_of_two().trailing_zeros() as usize;
    if proof.opening.commitment.tables.len() != 1
        || proof.opening.commitment.tables[0].num_variables != n.max(1)
        || proof.opening.commitment.tables[0].num_columns != a + 1
    {
        return Ok(false);
    }

    let mut transcript = Sha256Transcript::new("magnetar-binary-shout-boolean");
    absorb_commitment(&mut transcript, commitment_ref(&proof.opening.commitment));
    let rho_c = sample_point(&mut transcript, col_bits);
    let rho_j = sample_point(&mut transcript, n);
    if proof.boolean.column_point != rho_c || proof.boolean.cycle_point != rho_j {
        return Ok(false);
    }
    let Some(sum) = replay_terms(
        &proof.boolean.rounds,
        &proof.boolean.challenges,
        F2_128::from(0u64),
        &mut transcript,
    ) else {
        return Ok(false);
    };
    let r_j = &proof.boolean.challenges[..n];
    let r_c = &proof.boolean.challenges[n..];
    let mut b = F2_128::from(0u64);
    for column in 0..=a {
        b = b + eq_at_index(r_c, column) * proof.boolean.bit_evals[column];
    }
    if sum != eq_points(&rho_c, r_c) * eq_points(&rho_j, r_j) * b * (b + F2_128::from(1u64)) {
        return Ok(false);
    }

    let mut transcript = Sha256Transcript::new("magnetar-binary-shout");
    absorb_commitment(&mut transcript, commitment_ref(&proof.opening.commitment));
    let rho_j = sample_point(&mut transcript, n);
    if proof.cycle_point != rho_j {
        return Ok(false);
    }
    let eq_j = eq_vector(&rho_j, cycles);
    let claimed = eq_j
        .iter()
        .zip(&witness.read_value)
        .fold(F2_128::from(0u64), |sum, (weight, value)| {
            sum + *weight * *value
        });
    if proof.claimed != claimed {
        return Ok(false);
    }
    transcript.absorb("claimed", &proof.claimed.value().to_le_bytes());
    if let Some(first) = proof.rounds.first() {
        eprintln!(
            "shout first p0+p1={:?} claim={:?} degrees={:?}",
            first[0] + first[1],
            proof.claimed,
            proof.rounds.iter().map(|r| r.len() - 1).collect::<Vec<_>>()
        );
    }
    let Some(sum) = replay_terms(
        &proof.rounds,
        &proof.challenges,
        proof.claimed,
        &mut transcript,
    ) else {
        return Ok(false);
    };
    let r_j = &proof.challenges[..n];
    let r_k = &proof.challenges[n..];
    let rom_eval = fold_all(&witness.rom, r_k);
    let ra_eval = address_value(&proof.ra_bit_evals, r_k);
    if sum != eq_points(&rho_j, r_j) * proof.valid_eval * rom_eval * ra_eval {
        return Ok(false);
    }

    let point = if r_j.is_empty() {
        vec![F2_128::from(0u64)]
    } else {
        r_j.to_vec()
    };
    let boolean_j = &proof.boolean.challenges[..n];
    let boolean_point = if boolean_j.is_empty() {
        vec![F2_128::from(0u64)]
    } else {
        boolean_j.to_vec()
    };
    let points = vec![
        P3MosaicPoint {
            table: 0,
            point: boolean_point,
            columns: (0..=a).collect(),
            next_columns: Vec::new(),
        },
        P3MosaicPoint {
            table: 0,
            point,
            columns: (0..=a).collect(),
            next_columns: Vec::new(),
        },
    ];
    let mut read_values = proof.ra_bit_evals.clone();
    read_values.push(proof.valid_eval);
    let values = vec![proof.boolean.bit_evals.clone(), read_values];
    pcs.verify_mosaic(&proof.opening, &points, &values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    fn trace() -> Trace {
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
                    op: Op::Addi,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
                    imm: 9,
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
    fn binary_shout_round_trips() {
        let trace = trace();
        let witness = BinaryShoutWitness::from_trace(&trace).unwrap();
        let proof = prove_binary_shout(&witness).unwrap();
        assert!(verify_binary_shout(&witness, &proof).unwrap());

        let mut tampered = proof.clone();
        tampered.claimed = tampered.claimed + F2_128::from(1u64);
        assert!(!verify_binary_shout(&witness, &tampered).unwrap());

        let mut tampered = proof;
        tampered.ra_bit_evals[0] = tampered.ra_bit_evals[0] + F2_128::from(1u64);
        assert!(!verify_binary_shout(&witness, &tampered).unwrap());
    }
}
