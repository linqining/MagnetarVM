//! Reference BinaryRouter reduction for 64-bit shift routing.
//!
//! Each row supplies one input word and one output word plus a public
//! `ShiftRoute`. The prover commits to the input bits; the verifier folds the
//! public routing coefficients and checks the routed output with a sum-check.
//! Sub-word store routing can use the same coefficient table later.

use magnetar_constraint::{Field, F2_128};
use magnetar_pcs::{
    P3BinaryPcs, P3MosaicCommitment, P3MosaicOpening, P3MosaicPoint, P3MosaicTable,
};
use magnetar_proof::ProofError;
use magnetar_routing::{BitSource, ShiftKind, ShiftRoute};
use magnetar_spec::{Op, Trace};
use magnetar_transcript::Sha256Transcript;
use serde::{Deserialize, Serialize};

const WORD_BITS: usize = 64;

#[derive(Clone, Debug)]
pub struct BinaryRouterWitness {
    pub cycle_bits: usize,
    pub cycles: usize,
    pub routes: Vec<ShiftRoute>,
    pub input: Vec<Vec<F2_128>>,
    pub output: Vec<Vec<F2_128>>,
}

impl BinaryRouterWitness {
    pub fn from_trace(trace: &Trace) -> Result<Self, ProofError> {
        let mut routes = Vec::new();
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        for row in &trace.rows {
            let route = match row.instruction.op {
                Op::Sll => ShiftRoute::new(ShiftKind::LogicalLeft, (row.rs2_val & 0x3f) as u8),
                Op::Srl => ShiftRoute::new(ShiftKind::LogicalRight, (row.rs2_val & 0x3f) as u8),
                Op::Sra => ShiftRoute::new(ShiftKind::ArithmeticRight, (row.rs2_val & 0x3f) as u8),
                Op::Slli => ShiftRoute::new(ShiftKind::LogicalLeft, row.instruction.shamt),
                Op::Srli => ShiftRoute::new(ShiftKind::LogicalRight, row.instruction.shamt),
                Op::Srai => ShiftRoute::new(ShiftKind::ArithmeticRight, row.instruction.shamt),
                _ => continue,
            };
            routes.push(route);
            inputs.push(row.rs1_val);
            outputs.push(row.rd_val);
        }
        if routes.is_empty() {
            return Err(ProofError::Pcs(
                "BinaryRouter witness contains no 64-bit shift rows".into(),
            ));
        }
        let cycles = routes.len().next_power_of_two().max(2);
        let cycle_bits = cycles.trailing_zeros() as usize;
        let mut input = vec![vec![F2_128::from(0u64); cycles]; WORD_BITS];
        let mut output = vec![vec![F2_128::from(0u64); cycles]; WORD_BITS];
        for cycle in 0..routes.len() {
            for bit in 0..WORD_BITS {
                input[bit][cycle] = F2_128::from((inputs[cycle] >> bit) & 1);
                output[bit][cycle] = F2_128::from((outputs[cycle] >> bit) & 1);
            }
        }
        routes.resize(cycles, ShiftRoute::new(ShiftKind::LogicalLeft, 0));
        Ok(Self {
            cycle_bits,
            cycles,
            routes,
            input,
            output,
        })
    }

    pub fn validate(&self) -> Result<(), ProofError> {
        if self.cycles != 1usize << self.cycle_bits
            || self.routes.len() != self.cycles
            || self.input.len() != WORD_BITS
            || self.output.len() != WORD_BITS
            || self.input.iter().any(|column| column.len() != self.cycles)
            || self.output.iter().any(|column| column.len() != self.cycles)
        {
            return Err(ProofError::DimensionMismatch);
        }
        Ok(())
    }

    fn route_coefficients(&self, rho_o: &[F2_128]) -> Vec<Vec<F2_128>> {
        let mut coefficients = vec![vec![F2_128::from(0u64); self.cycles]; WORD_BITS];
        for (cycle, route) in self.routes.iter().enumerate() {
            for output_bit in 0..WORD_BITS {
                if let BitSource::Input(input_bit) = route.source_bit(output_bit) {
                    coefficients[usize::from(input_bit)][cycle] = coefficients
                        [usize::from(input_bit)][cycle]
                        + eq_at_index(rho_o, output_bit);
                }
            }
        }
        coefficients
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
pub struct BinaryRouterProof {
    pub cycle_bits: usize,
    pub boolean: AddressBooleanClaim,
    pub claimed: F2_128,
    pub cycle_point: Vec<F2_128>,
    pub rounds: Vec<Vec<F2_128>>,
    pub challenges: Vec<F2_128>,
    pub input_bit_evals: Vec<F2_128>,
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

fn sumcheck_product(
    left: &[F2_128],
    right: &[F2_128],
    degrees: &[usize],
    transcript: &mut Sha256Transcript,
) -> Result<(Vec<Vec<F2_128>>, Vec<F2_128>), ProofError> {
    if left.len() != right.len() {
        return Err(ProofError::DimensionMismatch);
    }
    let rounds = left.len().trailing_zeros() as usize;
    if degrees.len() != rounds {
        return Err(ProofError::DimensionMismatch);
    }
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    let mut polynomials = Vec::with_capacity(rounds);
    let mut challenges = Vec::with_capacity(rounds);
    for degree in degrees {
        let mut polynomial = Vec::with_capacity(degree + 1);
        for point in 0..=*degree {
            let point = F2_128::from(point as u64);
            let l = fold(&left, point);
            let r = fold(&right, point);
            polynomial.push(
                l.iter()
                    .zip(&r)
                    .fold(F2_128::from(0u64), |sum, (a, b)| sum + *a * *b),
            );
        }
        for coefficient in &polynomial {
            transcript.absorb("round", &coefficient.value().to_le_bytes());
        }
        let challenge = challenge(transcript, "sumcheck");
        left = fold(&left, challenge);
        right = fold(&right, challenge);
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

#[allow(clippy::needless_range_loop)]
pub fn prove_binary_router(witness: &BinaryRouterWitness) -> Result<BinaryRouterProof, ProofError> {
    witness.validate()?;
    let n = witness.cycle_bits;
    let cycles = witness.cycles;
    let pcs = P3BinaryPcs::new(100);
    let table = P3MosaicTable {
        columns: witness.input.clone(),
    };
    let commitment = pcs.commit_mosaic(core::slice::from_ref(&table))?;

    let mut transcript = Sha256Transcript::new("magnetar-binary-router-boolean");
    absorb_commitment(&mut transcript, commitment_ref(&commitment));
    let col_bits = WORD_BITS.trailing_zeros() as usize;
    let rho_c = sample_point(&mut transcript, col_bits);
    let rho_j = sample_point(&mut transcript, n);
    let eq_c = eq_vector(&rho_c, WORD_BITS);
    let eq_j = eq_vector(&rho_j, cycles);
    let boolean_terms = WORD_BITS * cycles;
    let mut factors = vec![vec![F2_128::from(0u64); boolean_terms]; 4];
    for column in 0..WORD_BITS {
        for cycle in 0..cycles {
            let index = column * cycles + cycle;
            factors[0][index] = eq_c[column];
            factors[1][index] = eq_j[cycle];
            factors[2][index] = witness.input[column][cycle];
            factors[3][index] = witness.input[column][cycle] + F2_128::from(1u64);
        }
    }
    let degrees = vec![4usize; boolean_terms.trailing_zeros() as usize];
    let (rounds, challenges) = sumcheck_two_terms(&factors, &degrees, &mut transcript)?;
    let r_j = &challenges[..n];
    let bit_evals = (0..WORD_BITS)
        .map(|bit| fold_all(&witness.input[bit], r_j))
        .collect::<Vec<_>>();
    let boolean = AddressBooleanClaim {
        column_point: rho_c,
        cycle_point: rho_j.clone(),
        rounds,
        challenges: challenges.clone(),
        bit_evals: bit_evals.clone(),
    };

    let mut transcript = Sha256Transcript::new("magnetar-binary-router");
    absorb_commitment(&mut transcript, commitment_ref(&commitment));
    let rho_o = sample_point(&mut transcript, WORD_BITS.trailing_zeros() as usize);
    let rho_j = sample_point(&mut transcript, n);
    let eq_o = eq_vector(&rho_o, WORD_BITS);
    let eq_j = eq_vector(&rho_j, cycles);
    let mut left = F2_128::from(0u64);
    for bit in 0..WORD_BITS {
        for cycle in 0..cycles {
            left = left + eq_o[bit] * eq_j[cycle] * witness.output[bit][cycle];
        }
    }
    transcript.absorb("claimed", &left.value().to_le_bytes());
    let coefficients = witness.route_coefficients(&rho_o);
    let terms = WORD_BITS * cycles;
    let mut input_flat = vec![F2_128::from(0u64); terms];
    let mut coefficient_flat = vec![F2_128::from(0u64); terms];
    for bit in 0..WORD_BITS {
        for cycle in 0..cycles {
            let index = bit * cycles + cycle;
            input_flat[index] = witness.input[bit][cycle];
            coefficient_flat[index] = coefficients[bit][cycle] * eq_j[cycle];
        }
    }
    let degrees = vec![2usize; terms.trailing_zeros() as usize];
    let (rounds, challenges) =
        sumcheck_product(&coefficient_flat, &input_flat, &degrees, &mut transcript)?;
    let r_j = &challenges[..n];
    let input_bit_evals = (0..WORD_BITS)
        .map(|bit| fold_all(&witness.input[bit], r_j))
        .collect::<Vec<_>>();
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
                columns: (0..WORD_BITS).collect(),
                next_columns: Vec::new(),
            },
            P3MosaicPoint {
                table: 0,
                point,
                columns: (0..WORD_BITS).collect(),
                next_columns: Vec::new(),
            },
        ],
    )?;
    Ok(BinaryRouterProof {
        cycle_bits: n,
        boolean,
        claimed: left,
        cycle_point: rho_j,
        rounds,
        challenges,
        input_bit_evals,
        opening,
    })
}

fn commitment_ref(commitment: &P3MosaicCommitment) -> &P3MosaicCommitment {
    commitment
}

fn sumcheck_two_terms(
    factors: &[Vec<F2_128>],
    degrees: &[usize],
    transcript: &mut Sha256Transcript,
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
            polynomial.push((0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
                sum + folded[0][index] * folded[1][index] * folded[2][index] * folded[3][index]
            }));
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

#[allow(clippy::needless_range_loop)]
pub fn verify_binary_router(
    witness: &BinaryRouterWitness,
    proof: &BinaryRouterProof,
) -> Result<bool, ProofError> {
    witness.validate()?;
    if proof.cycle_bits != witness.cycle_bits {
        return Ok(false);
    }
    let n = witness.cycle_bits;
    let cycles = witness.cycles;
    let pcs = P3BinaryPcs::new(100);
    let col_bits = WORD_BITS.trailing_zeros() as usize;
    if proof.opening.commitment.tables.len() != 1
        || proof.opening.commitment.tables[0].num_variables != n.max(1)
        || proof.opening.commitment.tables[0].num_columns != WORD_BITS
    {
        return Ok(false);
    }

    let mut transcript = Sha256Transcript::new("magnetar-binary-router-boolean");
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
    for column in 0..WORD_BITS {
        b = b + eq_at_index(r_c, column) * proof.boolean.bit_evals[column];
    }
    if sum != eq_points(&rho_c, r_c) * eq_points(&rho_j, r_j) * b * (b + F2_128::from(1u64)) {
        return Ok(false);
    }

    let mut transcript = Sha256Transcript::new("magnetar-binary-router");
    absorb_commitment(&mut transcript, commitment_ref(&proof.opening.commitment));
    let rho_o = sample_point(&mut transcript, WORD_BITS.trailing_zeros() as usize);
    let rho_j = sample_point(&mut transcript, n);
    if proof.cycle_point != rho_j {
        return Ok(false);
    }
    let eq_o = eq_vector(&rho_o, WORD_BITS);
    let eq_j = eq_vector(&rho_j, cycles);
    let mut left = F2_128::from(0u64);
    for bit in 0..WORD_BITS {
        for cycle in 0..cycles {
            left = left + eq_o[bit] * eq_j[cycle] * witness.output[bit][cycle];
        }
    }
    if proof.claimed != left {
        return Ok(false);
    }
    transcript.absorb("claimed", &proof.claimed.value().to_le_bytes());
    let Some(sum) = replay_terms(
        &proof.rounds,
        &proof.challenges,
        proof.claimed,
        &mut transcript,
    ) else {
        return Ok(false);
    };
    let r_j = &proof.challenges[..n];
    let r_i = &proof.challenges[n..];
    let coefficients = witness.route_coefficients(&rho_o);
    let mut coefficient_flat = vec![F2_128::from(0u64); WORD_BITS * cycles];
    for bit in 0..WORD_BITS {
        for cycle in 0..cycles {
            coefficient_flat[bit * cycles + cycle] = coefficients[bit][cycle] * eq_j[cycle];
        }
    }
    let coefficient_eval = fold_all(&coefficient_flat, &proof.challenges);
    let mut input_eval = F2_128::from(0u64);
    for (bit, eval) in proof.input_bit_evals.iter().enumerate() {
        input_eval = input_eval + eq_at_index(r_i, bit) * *eval;
    }
    if sum != coefficient_eval * input_eval {
        return Ok(false);
    }

    let point = if r_j.is_empty() {
        vec![F2_128::from(0u64)]
    } else {
        r_j.to_vec()
    };
    let boolean_point = if proof.boolean.challenges[..n].is_empty() {
        vec![F2_128::from(0u64)]
    } else {
        proof.boolean.challenges[..n].to_vec()
    };
    let points = vec![
        P3MosaicPoint {
            table: 0,
            point: boolean_point,
            columns: (0..WORD_BITS).collect(),
            next_columns: Vec::new(),
        },
        P3MosaicPoint {
            table: 0,
            point,
            columns: (0..WORD_BITS).collect(),
            next_columns: Vec::new(),
        },
    ];
    let values = vec![
        proof.boolean.bit_evals.clone(),
        proof.input_bit_evals.clone(),
    ];
    pcs.verify_mosaic(&proof.opening, &points, &values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, ProgramImage};

    fn trace() -> Trace {
        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Addi, 1, 0, 0, 0x123).encode(),
                instruction(Op::Slli, 2, 1, 0, 12).encode(),
                instruction(Op::Srli, 3, 1, 0, 4).encode(),
                instruction(Op::Srai, 4, 1, 0, 3).encode(),
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
    fn binary_router_round_trips() {
        let trace = trace();
        let witness = BinaryRouterWitness::from_trace(&trace).unwrap();
        let proof = prove_binary_router(&witness).unwrap();
        assert!(verify_binary_router(&witness, &proof).unwrap());

        let mut tampered = proof.clone();
        tampered.claimed = tampered.claimed + F2_128::from(1u64);
        assert!(!verify_binary_router(&witness, &tampered).unwrap());

        let mut tampered = proof;
        tampered.input_bit_evals[0] = tampered.input_bit_evals[0] + F2_128::from(1u64);
        assert!(!verify_binary_router(&witness, &tampered).unwrap());
    }
}
