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
use magnetar_preprocess::preprocess;
use magnetar_proof::ProofError;
use magnetar_routing::ShiftKind;
use magnetar_spec::{MachineConfig, Op, ProgramImage, Trace};
use magnetar_transcript::Sha256Transcript;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const HIGH_SCALE: u64 = 1 << 16;

#[derive(Clone, Debug)]
pub struct BinaryShoutWitness {
    pub address_bits: usize,
    pub cycle_bits: usize,
    pub cycles: usize,
    pub cells: usize,
    pub rom: Vec<Vec<F2_128>>,
    pub address0: Vec<Vec<F2_128>>,
    pub address1: Vec<Vec<F2_128>>,
    pub is_32: Vec<F2_128>,
    pub valid: Vec<F2_128>,
    pub read_value: Vec<Vec<F2_128>>,
}

impl BinaryShoutWitness {
    #[allow(clippy::needless_range_loop)]
    pub fn from_trace(trace: &Trace) -> Result<Self, ProofError> {
        let word_mode = trace.rows.iter().all(|row| row.instruction_len == 4);
        let cells = if word_mode {
            trace.rom.len().next_power_of_two().max(2)
        } else {
            trace.rom.len().saturating_mul(2).next_power_of_two().max(2)
        };
        let address_bits = cells.trailing_zeros() as usize;
        let cycles = trace.rows.len().next_power_of_two().max(2);
        let cycle_bits = cycles.trailing_zeros() as usize;
        let columns = 12usize;
        let mut rom = vec![vec![F2_128::from(0u64); columns]; cells];
        for (index, word) in trace.rom.iter().enumerate() {
            if word_mode {
                rom[index][0] = F2_128::from(u64::from(*word));
            } else {
                rom[2 * index][0] = F2_128::from(u64::from(*word & 0xffff));
                rom[2 * index + 1][0] = F2_128::from(u64::from(*word >> 16));
            }
        }
        let mut address0 = vec![vec![F2_128::from(0u64); cycles]; address_bits];
        let mut address1 = vec![vec![F2_128::from(0u64); cycles]; address_bits];
        let mut is_32 = vec![F2_128::from(0u64); cycles];
        let mut valid = vec![F2_128::from(0u64); cycles];
        let mut read_value = vec![vec![F2_128::from(0u64); columns]; cycles];
        let preprocessed = preprocess(
            &ProgramImage::new(trace.initial_state.pc, trace.rom.clone()),
            MachineConfig {
                entry: trace.config.entry,
                rom_base: trace.config.rom_base,
                ram_base: trace.config.ram_base,
                ram_size: trace.config.ram_size,
                stack_top: trace.config.stack_top,
                max_cycles: trace.config.max_cycles,
            },
        )
        .ok();
        let bytecode = preprocessed.as_ref().map(|program| {
            program
                .bytecode
                .iter()
                .map(|row| (row.micro_pc, row))
                .collect::<HashMap<_, _>>()
        });
        for (cycle, row) in trace.rows.iter().enumerate() {
            if row.instruction_len != 2 && row.instruction_len != 4 {
                return Err(ProofError::Pcs(
                    "BinaryShout supports 16-bit and 32-bit instructions".into(),
                ));
            }
            let offset = row
                .micro_pc
                .checked_sub(trace.config.rom_base)
                .ok_or_else(|| ProofError::Pcs("row pc is below the ROM base".into()))?;
            if offset % 2 != 0 {
                return Err(ProofError::Pcs("row pc is not halfword aligned".into()));
            }
            let index = if word_mode {
                if offset % 4 != 0 {
                    return Err(ProofError::Pcs("word-mode PC is not word aligned".into()));
                }
                usize::try_from(offset / 4)
                    .map_err(|_| ProofError::Pcs("ROM index overflows usize".into()))?
            } else {
                usize::try_from(offset / 2)
                    .map_err(|_| ProofError::Pcs("ROM index overflows usize".into()))?
            };
            let high = if word_mode {
                index
            } else {
                index + usize::from(row.instruction_len == 4)
            };
            if high >= cells {
                return Err(ProofError::Pcs("row pc is outside the ROM table".into()));
            }
            valid[cycle] = F2_128::from(1u64);
            is_32[cycle] = if word_mode {
                F2_128::from(0u64)
            } else {
                F2_128::from(u64::from(row.instruction_len == 4))
            };
            let bytecode_row = bytecode
                .as_ref()
                .and_then(|rows| rows.get(&row.micro_pc).copied());
            let (shift_kind, shift_shamt, store_width, is_halt) = if let Some(bytecode_row) =
                bytecode_row
            {
                let shift_kind = bytecode_row
                    .selectors
                    .shift
                    .map_or(0, |route| match route.kind {
                        ShiftKind::LogicalLeft => 1,
                        ShiftKind::LogicalRight => 2,
                        ShiftKind::ArithmeticRight => 3,
                    });
                let shift_shamt = bytecode_row
                    .selectors
                    .shift
                    .map_or(0, |route| u64::from(route.shamt));
                let store_width = bytecode_row
                    .selectors
                    .store_width
                    .map_or(0, |width| u64::from(width.bytes() as u8));
                (
                    shift_kind,
                    shift_shamt,
                    store_width,
                    u64::from(bytecode_row.selectors.is_halt),
                )
            } else {
                let shift_kind = match row.instruction.op {
                    Op::Sll | Op::Slli => 1u64,
                    Op::Srl | Op::Srli => 2,
                    Op::Sra | Op::Srai => 3,
                    _ => 0,
                };
                let shift_shamt = if shift_kind == 0 {
                    0
                } else if matches!(row.instruction.op, Op::Slli | Op::Srli | Op::Srai) {
                    u64::from(row.instruction.shamt)
                } else {
                    row.rs2_val & 0x3f
                };
                let store_width = row
                    .mem
                    .filter(|access| access.is_write)
                    .map_or(0, |access| u64::from(access.width));
                (shift_kind, shift_shamt, store_width, 0)
            };
            let metadata = vec![
                F2_128::from(u64::from(row.instruction_word)),
                F2_128::from(u64::from(row.instruction_len)),
                F2_128::from(row.instruction.op as u64),
                F2_128::from(u64::from(row.instruction.rd)),
                F2_128::from(u64::from(row.instruction.rs1)),
                F2_128::from(u64::from(row.instruction.rs2)),
                F2_128::from(row.instruction.imm as u64),
                F2_128::from(shift_kind),
                F2_128::from(shift_shamt),
                F2_128::from(store_width),
                F2_128::from(row.pc),
                F2_128::from(is_halt),
            ];
            for column in 1..columns {
                rom[index][column] = metadata[column];
                if row.instruction_len == 4 {
                    rom[high][column] = metadata[column];
                }
            }
            for bit in 0..address_bits {
                address0[bit][cycle] = F2_128::from(((index >> bit) & 1) as u64);
                address1[bit][cycle] = F2_128::from(((high >> bit) & 1) as u64);
            }
            read_value[cycle] = metadata;
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

    pub fn link_columns(&self) -> Vec<Vec<F2_128>> {
        let mut columns = vec![vec![F2_128::from(0u64); self.cycles]; 12];
        for (cycle, row) in self.read_value.iter().enumerate() {
            let store_width = row[9].value() as u64;
            let width = match store_width {
                1 => Some(0usize),
                2 => Some(1),
                4 => Some(2),
                8 => Some(3),
                _ => None,
            };
            if let Some(width) = width {
                columns[width][cycle] = F2_128::from(1u64);
            }
            let kind = row[7].value() as u64;
            let shamt = row[8].value() as u64 & 0x3f;
            let code = if kind == 0 {
                0
            } else {
                (kind - 1) * 64 + shamt
            };
            for bit in 0..8 {
                columns[4 + bit][cycle] = F2_128::from((code >> bit) & 1);
            }
        }
        columns
    }

    pub fn table(&self) -> P3MosaicTable {
        let mut columns = self.address0.clone();
        columns.extend(self.address1.clone());
        columns.push(self.is_32.clone());
        columns.push(self.valid.clone());
        columns.extend(self.link_columns());
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
    pub rounds: Vec<Vec<F2_128>>,
    pub bit_evals: Vec<F2_128>,
}

type ClaimPoints = (Vec<P3MosaicPoint>, Vec<Vec<F2_128>>);
type ClaimBundle<T> = (T, Vec<P3MosaicPoint>, Vec<Vec<F2_128>>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BinaryShoutProof {
    pub boolean: AddressBooleanClaim,
    pub rounds: Vec<Vec<F2_128>>,
    pub boolean_column_point: Vec<F2_128>,
    pub read_address_point: Vec<F2_128>,
    pub opening: Option<P3MosaicOpening>,
    pub address_bits: usize,
    pub cycle_bits: usize,
    pub cycles: usize,
    pub columns: usize,
    pub claimed_read: F2_128,
    pub ra0_evals: Vec<F2_128>,
    pub ra1_evals: Vec<F2_128>,
    pub is_32_eval: F2_128,
    pub valid_eval: F2_128,
    pub column_evals: Vec<F2_128>,
    pub link_evals: Vec<F2_128>,
    pub link_point: Vec<F2_128>,
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
    summand: impl Fn(&[Vec<F2_128>]) -> F2_128 + Sync,
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
    let per_point_bytes = factors.len().saturating_mul(len).saturating_mul(16);
    let requested = std::env::var("MAGNETAR_SUMCHECK_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|count| count.get())
                .unwrap_or(1)
        });
    let memory_gb = std::env::var("MAGNETAR_SUMCHECK_MEMORY_GB")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(8);
    let memory_budget = memory_gb.saturating_mul(1usize << 30);
    let memory_threads = memory_budget
        .checked_div(per_point_bytes)
        .unwrap_or(1)
        .max(1);
    let threads = requested.max(1).min(memory_threads);
    for degree in degrees {
        let points = (0..=*degree)
            .map(|point| F2_128::from(point as u64))
            .collect::<Vec<_>>();
        let mut polynomial = vec![F2_128::from(0u64); points.len()];
        if threads > 1 && points.len() > 1 {
            std::thread::scope(|scope| {
                let mut handles = Vec::with_capacity(points.len());
                for (index, point) in points.iter().enumerate() {
                    let factors = &factors;
                    let summand = &summand;
                    handles.push(scope.spawn(move || {
                        let folded = factors
                            .iter()
                            .map(|factor| fold(factor, *point))
                            .collect::<Vec<_>>();
                        (index, summand(&folded))
                    }));
                }
                for handle in handles {
                    let (index, value) = handle.join().expect("sumcheck worker");
                    polynomial[index] = value;
                }
            });
        } else {
            for (index, point) in points.iter().enumerate() {
                let folded = factors
                    .iter()
                    .map(|factor| fold(factor, *point))
                    .collect::<Vec<_>>();
                polynomial[index] = summand(&folded);
            }
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
        sum = interpolate(round, challenge);
    }
    Some((sum, challenges))
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
    binding: &[u8],
) -> Result<ClaimBundle<BinaryShoutProof>, ProofError> {
    witness.validate()?;
    let a = witness.address_bits;
    let n = witness.cycle_bits;
    let cycles = witness.cycles;

    let mut transcript = Sha256Transcript::new("magnetar-binary-shout-boolean");
    absorb_commitment(&mut transcript, commitment);
    transcript.absorb("packed-binding", binding);
    let total_columns = 2 * a + 2 + 12;
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
    let boolean_challenges = challenges;
    let boolean = AddressBooleanClaim { rounds, bit_evals };

    let mut transcript = Sha256Transcript::new("magnetar-binary-shout");
    absorb_commitment(&mut transcript, commitment);
    transcript.absorb("packed-binding", binding);
    let rho_j = sample_point(&mut transcript, n);
    let columns = witness.rom.first().map_or(0, |row| row.len());
    let gammas = (0..columns)
        .map(|_| challenge(&mut transcript, "column"))
        .collect::<Vec<_>>();
    let eq_j = eq_vector(&rho_j, cycles);
    let claimed =
        eq_j.iter()
            .zip(&witness.read_value)
            .fold(F2_128::from(0u64), |sum, (weight, value)| {
                sum + *weight
                    * value
                        .iter()
                        .zip(&gammas)
                        .fold(F2_128::from(0u64), |acc, (value, gamma)| {
                            acc + *value * *gamma
                        })
            });
    transcript.absorb("claimed", &claimed.value().to_le_bytes());
    let terms = witness.cells * cycles;
    let mut factors = vec![vec![F2_128::from(0u64); terms]; 2 * a + 3 + columns];
    for cell in 0..witness.cells {
        for cycle in 0..cycles {
            let index = cell * cycles + cycle;
            factors[0][index] = eq_j[cycle];
            factors[1][index] = witness.valid[cycle];
            factors[2][index] = witness.is_32[cycle];
            for column in 0..columns {
                factors[3 + column][index] = witness.rom[cell][column];
            }
            for bit in 0..a {
                let k = F2_128::from(((cell >> bit) & 1) as u64);
                factors[3 + columns + bit][index] =
                    F2_128::from(1u64) + witness.address0[bit][cycle] + k;
                factors[3 + columns + a + bit][index] =
                    F2_128::from(1u64) + witness.address1[bit][cycle] + k;
            }
        }
    }
    let read_degree = if witness.is_32.iter().any(|value| value.value() != 0) {
        a + 4
    } else {
        a + 2
    };
    let mut degrees = vec![read_degree; terms.trailing_zeros() as usize];
    for degree in degrees.iter_mut().skip(n) {
        *degree = 2;
    }
    let (rounds, challenges) = sumcheck_terms(&factors, &degrees, &mut transcript, |folded| {
        (0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
            let mut low = F2_128::from(1u64);
            for bit in 0..a {
                low = low * folded[3 + columns + bit][index];
            }
            let mut high = F2_128::from(1u64);
            for bit in 0..a {
                high = high * folded[3 + columns + a + bit][index];
            }
            let word = gammas[0]
                * folded[3][index]
                * (low + folded[2][index] * high * F2_128::from(HIGH_SCALE));
            let mut metadata = F2_128::from(0u64);
            for column in 1..columns {
                metadata = metadata + gammas[column] * low * folded[3 + column][index];
            }
            sum + folded[0][index] * folded[1][index] * (word + metadata)
        })
    })?;
    let r_j = &challenges[..n];
    let r_k = &challenges[n..];
    let column_evals = (0..columns)
        .map(|column| {
            let values = witness
                .rom
                .iter()
                .map(|row| row[column])
                .collect::<Vec<_>>();
            fold_all(&values, r_k)
        })
        .collect::<Vec<_>>();
    let link_evals = witness
        .link_columns()
        .iter()
        .map(|column| fold_all(column, r_j))
        .collect::<Vec<_>>();
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
    let boolean_point = if boolean_challenges[..n].is_empty() {
        vec![F2_128::from(0u64)]
    } else {
        boolean_challenges[..n].to_vec()
    };
    let points = vec![
        P3MosaicPoint {
            table: table_index,
            point: boolean_point,
            columns: (0..2 * a + 2).collect(),
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
        read_values.extend(link_evals.iter().copied());
        read_values
    }];
    Ok((
        BinaryShoutProof {
            boolean,
            rounds,
            boolean_column_point: boolean_challenges[n..].to_vec(),
            read_address_point: challenges[n..].to_vec(),
            opening: None,
            address_bits: a,
            cycle_bits: n,
            cycles,
            columns,
            claimed_read: claimed,
            ra0_evals: ra0_bit_evals.clone(),
            ra1_evals: ra1_bit_evals.clone(),
            is_32_eval,
            valid_eval,
            column_evals,
            link_evals,
            link_point: r_j.to_vec(),
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
    let (mut proof, points, _) = prove_binary_shout_claims(witness, &commitment, 0, b"")?;
    proof.opening = Some(pcs.open_mosaic(core::slice::from_ref(&table), &points)?);
    Ok(proof)
}

#[allow(clippy::needless_range_loop)]
pub(crate) fn verify_binary_shout_claims(
    _witness: &BinaryShoutWitness,
    proof: &BinaryShoutProof,
    commitment: &P3MosaicCommitment,
    table_index: usize,
    binding: &[u8],
) -> Result<Option<ClaimPoints>, ProofError> {
    verify_binary_shout_from_proof(proof, commitment, table_index, binding)
}

pub(crate) fn verify_binary_shout_from_proof(
    proof: &BinaryShoutProof,
    commitment: &P3MosaicCommitment,
    table_index: usize,
    binding: &[u8],
) -> Result<Option<ClaimPoints>, ProofError> {
    let a = proof.address_bits;
    let n = proof.cycle_bits;
    let total_columns = 2 * a + 2 + 12;
    let col_bits = total_columns.next_power_of_two().trailing_zeros() as usize;
    if commitment.tables.len() <= table_index
        || commitment.tables[table_index].num_variables != n.max(1)
        || commitment.tables[table_index].num_columns != total_columns
    {
        return Ok(None);
    }

    let mut transcript = Sha256Transcript::new("magnetar-binary-shout-boolean");
    absorb_commitment(&mut transcript, commitment);
    transcript.absorb("packed-binding", binding);
    let rho_c = sample_point(&mut transcript, col_bits);
    let rho_j = sample_point(&mut transcript, n);
    let Some((sum, boolean_challenges)) =
        replay_terms_derived(&proof.boolean.rounds, F2_128::from(0u64), &mut transcript)
    else {
        return Ok(None);
    };
    let r_j = &boolean_challenges[..n];
    let r_c = &boolean_challenges[n..];
    let mut b = F2_128::from(0u64);
    for column in 0..2 * a + 2 {
        b = b + eq_at_index(r_c, column) * proof.boolean.bit_evals[column];
    }
    if sum != eq_points(&rho_c, r_c) * eq_points(&rho_j, r_j) * b * (b + F2_128::from(1u64)) {
        return Ok(None);
    }

    let mut transcript = Sha256Transcript::new("magnetar-binary-shout");
    absorb_commitment(&mut transcript, commitment);
    transcript.absorb("packed-binding", binding);
    let rho_j = sample_point(&mut transcript, n);
    let columns = proof.columns;
    let gammas = (0..columns)
        .map(|_| challenge(&mut transcript, "column"))
        .collect::<Vec<_>>();
    let claimed = proof.claimed_read;
    transcript.absorb("claimed", &claimed.value().to_le_bytes());
    let Some((sum, challenges)) = replay_terms_derived(&proof.rounds, claimed, &mut transcript)
    else {
        return Ok(None);
    };
    let r_j = &challenges[..n];
    let r_k = &challenges[n..];
    let ra0_bit_evals = proof.ra0_evals.clone();
    let ra1_bit_evals = proof.ra1_evals.clone();
    let is_32_eval = proof.is_32_eval;
    let valid_eval = proof.valid_eval;
    let column_evals = proof.column_evals.clone();
    let ra0_eval = address_value(&ra0_bit_evals, r_k);
    let ra1_eval = address_value(&ra1_bit_evals, r_k);
    let word_eval =
        gammas[0] * column_evals[0] * (ra0_eval + is_32_eval * ra1_eval * F2_128::from(HIGH_SCALE));
    let mut metadata_eval = F2_128::from(0u64);
    for column in 1..columns {
        metadata_eval = metadata_eval + gammas[column] * ra0_eval * column_evals[column];
    }
    if sum != eq_points(&rho_j, r_j) * valid_eval * (word_eval + metadata_eval) {
        return Ok(None);
    }

    let point = if r_j.is_empty() {
        vec![F2_128::from(0u64)]
    } else {
        r_j.to_vec()
    };
    let boolean_j = &boolean_challenges[..n];
    let boolean_point = if boolean_j.is_empty() {
        vec![F2_128::from(0u64)]
    } else {
        boolean_j.to_vec()
    };
    let points = vec![
        P3MosaicPoint {
            table: table_index,
            point: boolean_point,
            columns: (0..2 * a + 2).collect(),
            next_columns: Vec::new(),
        },
        P3MosaicPoint {
            table: table_index,
            point,
            columns: (0..total_columns).collect(),
            next_columns: Vec::new(),
        },
    ];
    let mut read_values = ra0_bit_evals.clone();
    read_values.extend(ra1_bit_evals.clone());
    read_values.push(is_32_eval);
    read_values.push(valid_eval);
    read_values.extend(proof.link_evals.iter().copied());
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
        verify_binary_shout_claims(witness, proof, &opening.commitment, 0, b"")?
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
        tampered.rounds[0][0] = tampered.rounds[0][0] + F2_128::from(1u64);
        assert!(!verify_binary_shout(&witness, &tampered).unwrap());

        let mut tampered = proof;
        tampered.rounds[0][0] = tampered.rounds[0][0] + F2_128::from(1u64);
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
