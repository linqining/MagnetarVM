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

const HIGH_SCALE: u64 = 1 << 16;

#[derive(Clone, Debug)]
pub struct BinaryShoutWitness {
    pub address_bits: usize,
    pub cycle_bits: usize,
    pub cycles: usize,
    pub cells: usize,
    pub rom: Vec<F2_128>,
    pub address0: Vec<Vec<F2_128>>,
    pub address1: Vec<Vec<F2_128>>,
    pub is_32: Vec<F2_128>,
    pub valid: Vec<F2_128>,
    pub read_value: Vec<F2_128>,
}

impl BinaryShoutWitness {
    #[allow(clippy::needless_range_loop)]
    pub fn from_trace(trace: &Trace) -> Result<Self, ProofError> {
        let halfwords = trace.rom.len().saturating_mul(2);
        let cells = halfwords.next_power_of_two().max(2);
        let address_bits = cells.trailing_zeros() as usize;
        let cycles = trace.rows.len().next_power_of_two().max(2);
        let cycle_bits = cycles.trailing_zeros() as usize;
        let mut rom = vec![F2_128::from(0u64); cells];
        for (index, word) in trace.rom.iter().enumerate() {
            rom[2 * index] = F2_128::from(u64::from(*word & 0xffff));
            rom[2 * index + 1] = F2_128::from(u64::from(*word >> 16));
        }
        let mut address0 = vec![vec![F2_128::from(0u64); cycles]; address_bits];
        let mut address1 = vec![vec![F2_128::from(0u64); cycles]; address_bits];
        let mut is_32 = vec![F2_128::from(0u64); cycles];
        let mut valid = vec![F2_128::from(0u64); cycles];
        let mut read_value = vec![F2_128::from(0u64); cycles];
        for (cycle, row) in trace.rows.iter().enumerate() {
            if row.instruction_len != 2 && row.instruction_len != 4 {
                return Err(ProofError::Pcs(
                    "BinaryShout supports 16-bit and 32-bit instructions".into(),
                ));
            }
            let offset = row
                .pc
                .checked_sub(trace.config.rom_base)
                .ok_or_else(|| ProofError::Pcs("row pc is below the ROM base".into()))?;
            if offset % 2 != 0 {
                return Err(ProofError::Pcs("row pc is not halfword aligned".into()));
            }
            let index = usize::try_from(offset / 2)
                .map_err(|_| ProofError::Pcs("ROM index overflows usize".into()))?;
            let high = index + usize::from(row.instruction_len == 4);
            if high >= cells {
                return Err(ProofError::Pcs("row pc is outside the ROM table".into()));
            }
            valid[cycle] = F2_128::from(1u64);
            is_32[cycle] = F2_128::from(u64::from(row.instruction_len == 4));
            for bit in 0..address_bits {
                address0[bit][cycle] = F2_128::from(((index >> bit) & 1) as u64);
                address1[bit][cycle] = F2_128::from(((high >> bit) & 1) as u64);
            }
            read_value[cycle] = F2_128::from(u64::from(row.instruction_word));
        }
        Ok(Self {
            address_bits,
            cycle_bits,
            cycles,
            cells,
            rom,
            address0,
            address1,
            is_32,
            valid,
            read_value,
        })
    }

    pub fn table(&self) -> P3MosaicTable {
        let mut columns = self.address0.clone();
        columns.extend(self.address1.clone());
        columns.push(self.is_32.clone());
        columns.push(self.valid.clone());
        P3MosaicTable { columns }
    }

    pub fn validate(&self) -> Result<(), ProofError> {
        if self.cells != 1usize << self.address_bits
            || self.cycles != 1usize << self.cycle_bits
            || self.rom.len() != self.cells
            || self.address0.len() != self.address_bits
            || self.address1.len() != self.address_bits
            || self
                .address0
                .iter()
                .any(|column| column.len() != self.cycles)
            || self
                .address1
                .iter()
                .any(|column| column.len() != self.cycles)
            || self.is_32.len() != self.cycles
            || self.valid.len() != self.cycles
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

type ClaimPoints = (Vec<P3MosaicPoint>, Vec<Vec<F2_128>>);
type ClaimBundle<T> = (T, Vec<P3MosaicPoint>, Vec<Vec<F2_128>>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BinaryShoutProof {
    pub address_bits: usize,
    pub cycle_bits: usize,
    pub boolean: AddressBooleanClaim,
    pub claimed: F2_128,
    pub cycle_point: Vec<F2_128>,
    pub rounds: Vec<Vec<F2_128>>,
    pub challenges: Vec<F2_128>,
    pub ra0_bit_evals: Vec<F2_128>,
    pub ra1_bit_evals: Vec<F2_128>,
    pub is_32_eval: F2_128,
    pub valid_eval: F2_128,
    pub opening: Option<P3MosaicOpening>,
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
pub(crate) fn prove_binary_shout_claims(
    witness: &BinaryShoutWitness,
    commitment: &P3MosaicCommitment,
    table_index: usize,
) -> Result<ClaimBundle<BinaryShoutProof>, ProofError> {
    witness.validate()?;
    let a = witness.address_bits;
    let n = witness.cycle_bits;
    let cycles = witness.cycles;

    let mut transcript = Sha256Transcript::new("magnetar-binary-shout-boolean");
    absorb_commitment(&mut transcript, commitment);
    let total_columns = 2 * a + 2;
    let col_bits = total_columns.next_power_of_two().trailing_zeros() as usize;
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
                witness.address0[column][cycle]
            } else if column < 2 * a {
                witness.address1[column - a][cycle]
            } else if column == 2 * a {
                witness.is_32[cycle]
            } else if column == 2 * a + 1 {
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
        .map(|bit| fold_all(&witness.address0[bit], r_j))
        .collect::<Vec<_>>();
    bit_evals.extend((0..a).map(|bit| fold_all(&witness.address1[bit], r_j)));
    bit_evals.push(fold_all(&witness.is_32, r_j));
    bit_evals.push(fold_all(&witness.valid, r_j));
    let boolean = AddressBooleanClaim {
        column_point: rho_c,
        cycle_point: rho_j,
        rounds,
        challenges,
        bit_evals,
    };

    let mut transcript = Sha256Transcript::new("magnetar-binary-shout");
    absorb_commitment(&mut transcript, commitment);
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
    let mut factors = vec![vec![F2_128::from(0u64); terms]; 2 * a + 4];
    for cell in 0..witness.cells {
        for cycle in 0..cycles {
            let index = cell * cycles + cycle;
            factors[0][index] = eq_j[cycle];
            factors[1][index] = witness.valid[cycle];
            factors[2][index] = witness.is_32[cycle];
            factors[3][index] = witness.rom[cell];
            for bit in 0..a {
                let k = F2_128::from(((cell >> bit) & 1) as u64);
                factors[4 + bit][index] = F2_128::from(1u64) + witness.address0[bit][cycle] + k;
                factors[4 + a + bit][index] = F2_128::from(1u64) + witness.address1[bit][cycle] + k;
            }
        }
    }
    let mut degrees = vec![a + 3; terms.trailing_zeros() as usize];
    for degree in degrees.iter_mut().skip(n) {
        *degree = 2;
    }
    let (rounds, challenges) = sumcheck_terms(&factors, &degrees, &mut transcript, |folded| {
        (0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
            let mut low = F2_128::from(1u64);
            for bit in 0..a {
                low = low * folded[4 + bit][index];
            }
            let mut high = F2_128::from(1u64);
            for bit in 0..a {
                high = high * folded[4 + a + bit][index];
            }
            sum + folded[0][index]
                * folded[1][index]
                * folded[3][index]
                * (low + folded[2][index] * high * F2_128::from(HIGH_SCALE))
        })
    })?;
    let r_j = &challenges[..n];
    let ra0_bit_evals = (0..a)
        .map(|bit| fold_all(&witness.address0[bit], r_j))
        .collect::<Vec<_>>();
    let ra1_bit_evals = (0..a)
        .map(|bit| fold_all(&witness.address1[bit], r_j))
        .collect::<Vec<_>>();
    let is_32_eval = fold_all(&witness.is_32, r_j);
    let valid_eval = fold_all(&witness.valid, r_j);
    let point = if r_j.is_empty() {
        vec![F2_128::from(0u64)]
    } else {
        r_j.to_vec()
    };
    let boolean_point = if boolean.challenges[..n].is_empty() {
        vec![F2_128::from(0u64)]
    } else {
        boolean.challenges[..n].to_vec()
    };
    let points = vec![
        P3MosaicPoint {
            table: table_index,
            point: boolean_point,
            columns: (0..total_columns).collect(),
            next_columns: Vec::new(),
        },
        P3MosaicPoint {
            table: table_index,
            point,
            columns: (0..total_columns).collect(),
            next_columns: Vec::new(),
        },
    ];
    let values = vec![boolean.bit_evals.clone(), {
        let mut read_values = ra0_bit_evals.clone();
        read_values.extend(ra1_bit_evals.clone());
        read_values.push(is_32_eval);
        read_values.push(valid_eval);
        read_values
    }];
    Ok((
        BinaryShoutProof {
            address_bits: a,
            cycle_bits: n,
            boolean,
            claimed,
            cycle_point: rho_j,
            rounds,
            challenges,
            ra0_bit_evals,
            ra1_bit_evals,
            is_32_eval,
            valid_eval,
            opening: None,
        },
        points,
        values,
    ))
}

pub fn prove_binary_shout(witness: &BinaryShoutWitness) -> Result<BinaryShoutProof, ProofError> {
    witness.validate()?;
    let pcs = P3BinaryPcs::new(100);
    let table = witness.table();
    let commitment = pcs.commit_mosaic(core::slice::from_ref(&table))?;
    let (mut proof, points, _) = prove_binary_shout_claims(witness, &commitment, 0)?;
    proof.opening = Some(pcs.open_mosaic(core::slice::from_ref(&table), &points)?);
    Ok(proof)
}

#[allow(clippy::needless_range_loop)]
pub(crate) fn verify_binary_shout_claims(
    witness: &BinaryShoutWitness,
    proof: &BinaryShoutProof,
    commitment: &P3MosaicCommitment,
    table_index: usize,
) -> Result<Option<ClaimPoints>, ProofError> {
    witness.validate()?;
    if proof.address_bits != witness.address_bits || proof.cycle_bits != witness.cycle_bits {
        return Ok(None);
    }
    let a = witness.address_bits;
    let n = witness.cycle_bits;
    let cycles = witness.cycles;
    let total_columns = 2 * a + 2;
    let col_bits = total_columns.next_power_of_two().trailing_zeros() as usize;
    if commitment.tables.len() <= table_index
        || commitment.tables[table_index].num_variables != n.max(1)
        || commitment.tables[table_index].num_columns != total_columns
    {
        return Ok(None);
    }

    let mut transcript = Sha256Transcript::new("magnetar-binary-shout-boolean");
    absorb_commitment(&mut transcript, commitment);
    let rho_c = sample_point(&mut transcript, col_bits);
    let rho_j = sample_point(&mut transcript, n);
    if proof.boolean.column_point != rho_c || proof.boolean.cycle_point != rho_j {
        return Ok(None);
    }
    let Some(sum) = replay_terms(
        &proof.boolean.rounds,
        &proof.boolean.challenges,
        F2_128::from(0u64),
        &mut transcript,
    ) else {
        return Ok(None);
    };
    let r_j = &proof.boolean.challenges[..n];
    let r_c = &proof.boolean.challenges[n..];
    let mut b = F2_128::from(0u64);
    for column in 0..total_columns {
        b = b + eq_at_index(r_c, column) * proof.boolean.bit_evals[column];
    }
    if sum != eq_points(&rho_c, r_c) * eq_points(&rho_j, r_j) * b * (b + F2_128::from(1u64)) {
        return Ok(None);
    }

    let mut transcript = Sha256Transcript::new("magnetar-binary-shout");
    absorb_commitment(&mut transcript, commitment);
    let rho_j = sample_point(&mut transcript, n);
    if proof.cycle_point != rho_j {
        return Ok(None);
    }
    let eq_j = eq_vector(&rho_j, cycles);
    let claimed = eq_j
        .iter()
        .zip(&witness.read_value)
        .fold(F2_128::from(0u64), |sum, (weight, value)| {
            sum + *weight * *value
        });
    if proof.claimed != claimed {
        return Ok(None);
    }
    transcript.absorb("claimed", &proof.claimed.value().to_le_bytes());
    let Some(sum) = replay_terms(
        &proof.rounds,
        &proof.challenges,
        proof.claimed,
        &mut transcript,
    ) else {
        return Ok(None);
    };
    let r_j = &proof.challenges[..n];
    let r_k = &proof.challenges[n..];
    let rom_eval = fold_all(&witness.rom, r_k);
    let ra0_eval = address_value(&proof.ra0_bit_evals, r_k);
    let ra1_eval = address_value(&proof.ra1_bit_evals, r_k);
    let read_eval = ra0_eval + proof.is_32_eval * ra1_eval * F2_128::from(HIGH_SCALE);
    if sum != eq_points(&rho_j, r_j) * proof.valid_eval * rom_eval * read_eval {
        return Ok(None);
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
            table: table_index,
            point: boolean_point,
            columns: (0..total_columns).collect(),
            next_columns: Vec::new(),
        },
        P3MosaicPoint {
            table: table_index,
            point,
            columns: (0..total_columns).collect(),
            next_columns: Vec::new(),
        },
    ];
    let mut read_values = proof.ra0_bit_evals.clone();
    read_values.extend(proof.ra1_bit_evals.clone());
    read_values.push(proof.is_32_eval);
    read_values.push(proof.valid_eval);
    let values = vec![proof.boolean.bit_evals.clone(), read_values];
    Ok(Some((points, values)))
}

pub fn verify_binary_shout(
    witness: &BinaryShoutWitness,
    proof: &BinaryShoutProof,
) -> Result<bool, ProofError> {
    let Some(opening) = &proof.opening else {
        return Ok(false);
    };
    let Some((points, values)) =
        verify_binary_shout_claims(witness, proof, &opening.commitment, 0)?
    else {
        return Ok(false);
    };
    P3BinaryPcs::new(100).verify_mosaic(opening, &points, &values)
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
        tampered.ra0_bit_evals[0] = tampered.ra0_bit_evals[0] + F2_128::from(1u64);
        assert!(!verify_binary_shout(&witness, &tampered).unwrap());
    }

    #[test]
    fn binary_shout_handles_compressed_instructions() {
        let program = ProgramImage::new(0x1000, vec![0x008d_4095, 0x0000_9002]);
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
        assert_eq!(trace.rows[0].instruction_len, 2);
        let witness = BinaryShoutWitness::from_trace(&trace).unwrap();
        let proof = prove_binary_shout(&witness).unwrap();
        assert!(verify_binary_shout(&witness, &proof).unwrap());
    }
}
