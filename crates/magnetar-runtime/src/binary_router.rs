//! Reference BinaryRouter reduction for 64-bit shifts and sub-word stores.
//!
//! Each routed row supplies a 128-bit input (64 old/input bits followed by 64
//! source bits) and a 64-bit output. For shifts the output is the shifted word;
//! for sub-word stores it is the RAM increment (old XOR new), matching the
//! committed `Inc` table of BinaryTwist. The public route maps every output
//! bit to zero, one, or two input bits; the two-bit case is the XOR route of a
//! store increment. The prover commits to the input bits; the verifier folds
//! the public routing coefficients and checks the output with a sum-check.

use magnetar_constraint::{Field, F2_128};
use magnetar_pcs::{
    P3BinaryPcs, P3MosaicCommitment, P3MosaicOpening, P3MosaicPoint, P3MosaicTable,
};
use magnetar_proof::ProofError;
use magnetar_routing::{BitSource, ShiftKind, ShiftRoute, StoreRoute, StoreWidth};
use magnetar_spec::{Op, Trace};
use magnetar_transcript::Sha256Transcript;
use serde::{Deserialize, Serialize};

const WORD_BITS: usize = 64;
const INPUT_BITS: usize = 128;
const SOURCE_OFFSET: usize = WORD_BITS;

#[derive(Clone, Copy, Debug)]
pub enum RouterRoute {
    Shift(ShiftRoute),
    Store(StoreRoute),
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouterMode {
    Shifts,
    Stores,
    Both,
}

impl RouterRoute {
    fn offset(&self) -> usize {
        match self {
            RouterRoute::Shift(_) | RouterRoute::None => 0,
            RouterRoute::Store(route) => route.offset,
        }
    }

    fn shift_code(&self) -> u64 {
        match self {
            RouterRoute::Shift(route) => {
                let kind = match route.kind {
                    ShiftKind::LogicalLeft => 0,
                    ShiftKind::LogicalRight => 1,
                    ShiftKind::ArithmeticRight => 2,
                };
                kind * 64 + u64::from(route.shamt)
            }
            RouterRoute::Store(_) | RouterRoute::None => 0,
        }
    }

    #[cfg(test)]
    fn coefficients(&self, output_bit: usize) -> Vec<usize> {
        match self {
            RouterRoute::Shift(route) => match route.source_bit(output_bit) {
                BitSource::Zero => Vec::new(),
                BitSource::Input(bit) => vec![usize::from(bit)],
            },
            RouterRoute::None => Vec::new(),
            RouterRoute::Store(route) => {
                let written = route.written_bits();
                if written.contains(&output_bit) {
                    vec![output_bit, SOURCE_OFFSET + (output_bit - route.offset * 8)]
                } else {
                    Vec::new()
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct BinaryRouterWitness {
    pub cycle_bits: usize,
    pub cycles: usize,
    pub routes: Vec<RouterRoute>,
    pub input: Vec<Vec<F2_128>>,
    pub offset_bits: Vec<Vec<F2_128>>,
    pub width_bits: Vec<Vec<F2_128>>,
    pub shift_code: Vec<F2_128>,
    pub shift_q: Vec<Vec<F2_128>>,
    pub shift_hq: Vec<Vec<F2_128>>,
    pub is_shift: Vec<F2_128>,
    pub is_store: Vec<F2_128>,
    pub output: Vec<Vec<F2_128>>,
}

fn store_word(old: u64, lane: usize, width: usize, value: u64) -> u64 {
    if width == 8 {
        return value;
    }
    let bits = width * 8;
    let mask = (1u64 << bits) - 1;
    let shifted_mask = mask << (lane * 8);
    (old & !shifted_mask) | ((value & mask) << (lane * 8))
}

fn read_word(ram: &[u8], word: usize) -> u64 {
    let start = word * 8;
    u64::from_le_bytes(ram[start..start + 8].try_into().expect("eight bytes"))
}

fn write_word(ram: &mut [u8], word: usize, value: u64) {
    let start = word * 8;
    ram[start..start + 8].copy_from_slice(&value.to_le_bytes());
}

impl BinaryRouterWitness {
    pub fn from_trace(trace: &Trace) -> Result<Self, ProofError> {
        Self::from_trace_mode(trace, RouterMode::Both)
    }

    pub fn from_trace_mode(trace: &Trace, mode: RouterMode) -> Result<Self, ProofError> {
        let mut routes = Vec::new();
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        let mut ram = trace.initial_ram.clone();
        for row in &trace.rows {
            let is_shift = matches!(
                row.instruction.op,
                Op::Sll | Op::Srl | Op::Sra | Op::Slli | Op::Srli | Op::Srai
            );
            let is_store = matches!(row.instruction.op, Op::Sb | Op::Sh | Op::Sw | Op::Sd);
            if (is_shift && mode == RouterMode::Stores) || (is_store && mode == RouterMode::Shifts)
            {
                if let Some(access) = row.mem {
                    if access.is_write {
                        let offset = access.addr.wrapping_sub(trace.config.ram_base);
                        let word = usize::try_from(offset / 8)
                            .map_err(|_| ProofError::Pcs("RAM word overflows usize".into()))?;
                        let lane = (offset % 8) as usize;
                        if word * 8 + 8 <= ram.len() {
                            let old = read_word(&ram, word);
                            let width = usize::from(access.width);
                            let source = if row.instruction.op.amo_width().is_some() {
                                access.value
                            } else {
                                row.rs2_val
                            };
                            write_word(&mut ram, word, store_word(old, lane, width, source));
                        }
                    }
                }
                continue;
            }
            match row.instruction.op {
                Op::Sll | Op::Srl | Op::Sra | Op::Slli | Op::Srli | Op::Srai => {
                    let route = match row.instruction.op {
                        Op::Sll => {
                            ShiftRoute::new(ShiftKind::LogicalLeft, (row.rs2_val & 0x3f) as u8)
                        }
                        Op::Srl => {
                            ShiftRoute::new(ShiftKind::LogicalRight, (row.rs2_val & 0x3f) as u8)
                        }
                        Op::Sra => {
                            ShiftRoute::new(ShiftKind::ArithmeticRight, (row.rs2_val & 0x3f) as u8)
                        }
                        Op::Slli => ShiftRoute::new(ShiftKind::LogicalLeft, row.instruction.shamt),
                        Op::Srli => ShiftRoute::new(ShiftKind::LogicalRight, row.instruction.shamt),
                        Op::Srai => {
                            ShiftRoute::new(ShiftKind::ArithmeticRight, row.instruction.shamt)
                        }
                        _ => unreachable!(),
                    };
                    routes.push(RouterRoute::Shift(route));
                    inputs.push((row.rs1_val, 0u64));
                    outputs.push(row.rd_val);
                }
                Op::Sb | Op::Sh | Op::Sw | Op::Sd => {
                    let access = row
                        .mem
                        .ok_or_else(|| ProofError::Pcs("store row has no memory access".into()))?;
                    let offset = access
                        .addr
                        .checked_sub(trace.config.ram_base)
                        .ok_or_else(|| ProofError::Pcs("store address below RAM base".into()))?;
                    let word = usize::try_from(offset / 8)
                        .map_err(|_| ProofError::Pcs("store word overflows usize".into()))?;
                    let lane = (offset % 8) as usize;
                    if lane + usize::from(access.width) > 8 || word * 8 + 8 > ram.len() {
                        return Err(ProofError::Pcs("store access is outside RAM".into()));
                    }
                    let old = read_word(&ram, word);
                    let source = row.rs2_val;
                    let width = usize::from(access.width);
                    let new = store_word(old, lane, width, source);
                    let store_width = StoreWidth::from_bytes(width)
                        .map_err(|error| ProofError::Pcs(error.to_string()))?;
                    let route = StoreRoute::new(store_width, lane)
                        .map_err(|error| ProofError::Pcs(error.to_string()))?;
                    routes.push(RouterRoute::Store(route));
                    inputs.push((old, source));
                    outputs.push(old ^ new);
                    write_word(&mut ram, word, new);
                }
                _ => {
                    if let Some(access) = row.mem {
                        if access.is_write {
                            let offset = access.addr.wrapping_sub(trace.config.ram_base);
                            let word = usize::try_from(offset / 8)
                                .map_err(|_| ProofError::Pcs("RAM word overflows usize".into()))?;
                            let lane = (offset % 8) as usize;
                            if word * 8 + 8 <= ram.len() {
                                let old = read_word(&ram, word);
                                let width = usize::from(access.width);
                                let source = if row.instruction.op.amo_width().is_some() {
                                    access.value
                                } else {
                                    row.rs2_val
                                };
                                write_word(&mut ram, word, store_word(old, lane, width, source));
                            }
                        }
                    }
                }
            }
            for access in &row.extra_mem {
                let offset = access.addr.wrapping_sub(trace.config.ram_base);
                let word = usize::try_from(offset / 8)
                    .map_err(|_| ProofError::Pcs("RAM word overflows usize".into()))?;
                let lane = (offset % 8) as usize;
                if word * 8 + 8 <= ram.len() {
                    let old = read_word(&ram, word);
                    let width = usize::from(access.width);
                    write_word(&mut ram, word, store_word(old, lane, width, access.value));
                }
            }
        }
        if routes.is_empty() {
            return Err(ProofError::Pcs(
                "BinaryRouter witness contains no shift or store rows".into(),
            ));
        }
        let cycles = routes.len().next_power_of_two().max(2);
        let cycle_bits = cycles.trailing_zeros() as usize;
        let mut input = vec![vec![F2_128::from(0u64); cycles]; INPUT_BITS];
        let mut output = vec![vec![F2_128::from(0u64); cycles]; WORD_BITS];
        let mut offset_bits = vec![vec![F2_128::from(0u64); cycles]; 3];
        let mut width_bits = vec![vec![F2_128::from(0u64); cycles]; 4];
        let mut shift_code = vec![F2_128::from(0u64); cycles];
        let mut shift_q = vec![vec![F2_128::from(0u64); cycles]; 64];
        let mut shift_hq = vec![vec![F2_128::from(0u64); cycles]; 64];
        let mut is_shift = vec![F2_128::from(0u64); cycles];
        let mut is_store = vec![F2_128::from(0u64); cycles];
        for cycle in 0..routes.len() {
            let offset = routes[cycle].offset();
            for (bit, column) in offset_bits.iter_mut().enumerate() {
                column[cycle] = F2_128::from(((offset >> bit) & 1) as u64);
            }
            if let RouterRoute::Store(route) = routes[cycle] {
                let width = match route.width {
                    StoreWidth::Byte => 0,
                    StoreWidth::Half => 1,
                    StoreWidth::Word => 2,
                    StoreWidth::Double => 3,
                };
                width_bits[width][cycle] = F2_128::from(1u64);
            }
            shift_code[cycle] = F2_128::from(routes[cycle].shift_code());
            if let RouterRoute::Shift(_) = routes[cycle] {
                let code = routes[cycle].shift_code() as usize;
                let shamt = code % 64;
                shift_q[shamt][cycle] = F2_128::from(1u64);
                shift_hq[shamt][cycle] = F2_128::from(shamt as u64);
            }
            is_shift[cycle] =
                F2_128::from(u64::from(matches!(routes[cycle], RouterRoute::Shift(_))));
            is_store[cycle] =
                F2_128::from(u64::from(matches!(routes[cycle], RouterRoute::Store(_))));
            let (old, source) = inputs[cycle];
            for bit in 0..WORD_BITS {
                input[bit][cycle] = F2_128::from((old >> bit) & 1);
                input[SOURCE_OFFSET + bit][cycle] = F2_128::from((source >> bit) & 1);
                output[bit][cycle] = F2_128::from((outputs[cycle] >> bit) & 1);
            }
        }
        routes.resize(cycles, RouterRoute::None);
        for cycle in 0..cycles {
            is_shift[cycle] =
                F2_128::from(u64::from(matches!(routes[cycle], RouterRoute::Shift(_))));
            is_store[cycle] =
                F2_128::from(u64::from(matches!(routes[cycle], RouterRoute::Store(_))));
        }
        Ok(Self {
            cycle_bits,
            cycles,
            routes,
            input,
            offset_bits,
            width_bits,
            shift_code,
            shift_q,
            shift_hq,
            is_shift,
            is_store,
            output,
        })
    }

    pub fn table(&self) -> P3MosaicTable {
        let mut columns = self.input.clone();
        columns.extend(self.offset_bits.clone());
        columns.extend(self.width_bits.clone());
        columns.push(self.is_shift.clone());
        columns.push(self.is_store.clone());
        columns.extend(self.shift_q.clone());
        columns.extend(self.shift_hq.clone());
        columns.push(self.shift_code.clone());
        P3MosaicTable { columns }
    }

    pub fn validate(&self) -> Result<(), ProofError> {
        if self.cycles != 1usize << self.cycle_bits
            || self.routes.len() != self.cycles
            || self.input.len() != INPUT_BITS
            || self.output.len() != WORD_BITS
            || self.input.iter().any(|column| column.len() != self.cycles)
            || self.offset_bits.len() != 3
            || self
                .offset_bits
                .iter()
                .any(|column| column.len() != self.cycles)
            || self.width_bits.len() != 4
            || self
                .width_bits
                .iter()
                .any(|column| column.len() != self.cycles)
            || self.shift_code.len() != self.cycles
            || self.shift_q.len() != 64
            || self
                .shift_q
                .iter()
                .any(|column| column.len() != self.cycles)
            || self.shift_hq.len() != 64
            || self
                .shift_hq
                .iter()
                .any(|column| column.len() != self.cycles)
            || self.is_shift.len() != self.cycles
            || self.is_store.len() != self.cycles
            || self.output.iter().any(|column| column.len() != self.cycles)
        {
            return Err(ProofError::DimensionMismatch);
        }
        Ok(())
    }

    fn route_coefficients_from_selectors(&self, rho_o: &[F2_128]) -> Vec<Vec<F2_128>> {
        let mut coefficients = vec![vec![F2_128::from(0u64); self.cycles]; INPUT_BITS];
        for cycle in 0..self.cycles {
            let is_shift = self.is_shift[cycle].value() == 1;
            let is_store = self.is_store[cycle].value() == 1;
            if is_shift {
                let code = self.shift_code[cycle].value() as u64;
                let kind = match code / 64 {
                    0 => ShiftKind::LogicalLeft,
                    1 => ShiftKind::LogicalRight,
                    2 => ShiftKind::ArithmeticRight,
                    _ => continue,
                };
                let route = ShiftRoute::new(kind, (code % 64) as u8);
                for output_bit in 0..WORD_BITS {
                    if let BitSource::Input(input_bit) = route.source_bit(output_bit) {
                        coefficients[usize::from(input_bit)][cycle] = coefficients
                            [usize::from(input_bit)][cycle]
                            + eq_at_index(rho_o, output_bit);
                    }
                }
            } else if is_store {
                let mut width = 0usize;
                for (bit, column) in self.width_bits.iter().enumerate() {
                    if column[cycle].value() == 1 {
                        width = [1usize, 2, 4, 8][bit];
                    }
                }
                if width == 0 {
                    continue;
                }
                let offset =
                    self.offset_bits
                        .iter()
                        .enumerate()
                        .fold(0usize, |value, (bit, column)| {
                            if column[cycle].value() == 1 {
                                value | (1 << bit)
                            } else {
                                value
                            }
                        });
                let start = offset * 8;
                for output_bit in start..start + width * 8 {
                    let source = output_bit - start;
                    coefficients[SOURCE_OFFSET + source][cycle] = coefficients
                        [SOURCE_OFFSET + source][cycle]
                        + eq_at_index(rho_o, output_bit);
                    coefficients[output_bit][cycle] =
                        coefficients[output_bit][cycle] + eq_at_index(rho_o, output_bit);
                }
            }
        }
        coefficients
    }

    #[cfg(test)]
    fn route_coefficients(&self, rho_o: &[F2_128]) -> Vec<Vec<F2_128>> {
        let mut coefficients = vec![vec![F2_128::from(0u64); self.cycles]; INPUT_BITS];
        for (cycle, route) in self.routes.iter().enumerate() {
            for output_bit in 0..WORD_BITS {
                for input_bit in route.coefficients(output_bit) {
                    coefficients[input_bit][cycle] =
                        coefficients[input_bit][cycle] + eq_at_index(rho_o, output_bit);
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

type ClaimPoints = (Vec<P3MosaicPoint>, Vec<Vec<F2_128>>);
type ClaimBundle<T> = (T, Vec<P3MosaicPoint>, Vec<Vec<F2_128>>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BinaryRouterProof {
    pub cycle_bits: usize,
    pub boolean: AddressBooleanClaim,
    pub claimed: F2_128,
    pub cycle_point: Vec<F2_128>,
    pub rounds: Vec<Vec<F2_128>>,
    pub challenges: Vec<F2_128>,
    pub input_bit_evals: Vec<F2_128>,
    pub offset_rounds: Vec<Vec<F2_128>>,
    pub offset_challenges: Vec<F2_128>,
    pub offset_cycle_point: Vec<F2_128>,
    pub offset_evals: Vec<F2_128>,
    pub width_rounds: Vec<Vec<F2_128>>,
    pub width_challenges: Vec<F2_128>,
    pub width_cycle_point: Vec<F2_128>,
    pub width_evals: Vec<F2_128>,
    pub shift_rounds: Vec<Vec<F2_128>>,
    pub shift_challenges: Vec<F2_128>,
    pub shift_cycle_point: Vec<F2_128>,
    pub shift_eval: F2_128,
    pub q_rounds: Vec<Vec<F2_128>>,
    pub q_challenges: Vec<F2_128>,
    pub q_cycle_point: Vec<F2_128>,
    pub q_evals: Vec<F2_128>,
    pub hq_rounds: Vec<Vec<F2_128>>,
    pub hq_challenges: Vec<F2_128>,
    pub hq_cycle_point: Vec<F2_128>,
    pub hq_evals: Vec<F2_128>,
    pub valid_rounds: Vec<Vec<F2_128>>,
    pub valid_challenges: Vec<F2_128>,
    pub valid_cycle_point: Vec<F2_128>,
    pub valid_evals: Vec<F2_128>,
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

fn sumcheck_offset(
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
                sum + folded[0][index] * folded[1][index] * (folded[2][index] - folded[3][index])
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
pub(crate) fn prove_binary_router_claims(
    witness: &BinaryRouterWitness,
    commitment: &P3MosaicCommitment,
    table_index: usize,
) -> Result<ClaimBundle<BinaryRouterProof>, ProofError> {
    witness.validate()?;
    let n = witness.cycle_bits;
    let cycles = witness.cycles;
    let bit_columns = INPUT_BITS + 9 + 64;
    let hq_columns = bit_columns + 64;
    let total_columns = hq_columns + 1;

    let mut transcript = Sha256Transcript::new("magnetar-binary-router-boolean");
    absorb_commitment(&mut transcript, commitment);
    let col_bits = bit_columns.next_power_of_two().trailing_zeros() as usize;
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
            let value = if column < INPUT_BITS {
                witness.input[column][cycle]
            } else if column < INPUT_BITS + 3 {
                witness.offset_bits[column - INPUT_BITS][cycle]
            } else if column < INPUT_BITS + 7 {
                witness.width_bits[column - INPUT_BITS - 3][cycle]
            } else if column == INPUT_BITS + 7 {
                witness.is_shift[cycle]
            } else if column == INPUT_BITS + 8 {
                witness.is_store[cycle]
            } else if column < bit_columns {
                witness.shift_q[column - INPUT_BITS - 9][cycle]
            } else {
                F2_128::from(0u64)
            };
            factors[2][index] = value;
            factors[3][index] = value + F2_128::from(1u64);
        }
    }
    let degrees = vec![4usize; boolean_terms.trailing_zeros() as usize];
    let (rounds, challenges) = sumcheck_two_terms(&factors, &degrees, &mut transcript)?;
    let r_j = &challenges[..n];
    let mut bit_evals = (0..INPUT_BITS)
        .map(|bit| fold_all(&witness.input[bit], r_j))
        .collect::<Vec<_>>();
    bit_evals.extend((0..3).map(|bit| fold_all(&witness.offset_bits[bit], r_j)));
    bit_evals.extend((0..4).map(|bit| fold_all(&witness.width_bits[bit], r_j)));
    bit_evals.push(fold_all(&witness.is_shift, r_j));
    bit_evals.push(fold_all(&witness.is_store, r_j));
    bit_evals.extend((0..64).map(|bit| fold_all(&witness.shift_q[bit], r_j)));
    let boolean = AddressBooleanClaim {
        column_point: rho_c,
        cycle_point: rho_j.clone(),
        rounds,
        challenges: challenges.clone(),
        bit_evals: bit_evals.clone(),
    };

    let mut transcript = Sha256Transcript::new("magnetar-binary-router");
    absorb_commitment(&mut transcript, commitment);
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
    let coefficients = witness.route_coefficients_from_selectors(&rho_o);
    let terms = INPUT_BITS * cycles;
    let mut input_flat = vec![F2_128::from(0u64); terms];
    let mut coefficient_flat = vec![F2_128::from(0u64); terms];
    for bit in 0..INPUT_BITS {
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
    let input_bit_evals = (0..INPUT_BITS)
        .map(|bit| fold_all(&witness.input[bit], r_j))
        .collect::<Vec<_>>();
    let point = if r_j.is_empty() {
        vec![F2_128::from(0u64)]
    } else {
        r_j.to_vec()
    };
    let mut transcript = Sha256Transcript::new("magnetar-binary-router-offset");
    absorb_commitment(&mut transcript, commitment);
    let offset_rho_j = sample_point(&mut transcript, n);
    let deltas = (0..3)
        .map(|_| challenge(&mut transcript, "delta"))
        .collect::<Vec<_>>();
    let offset_eq_j = eq_vector(&offset_rho_j, cycles);
    let offset_terms = 4 * cycles;
    let mut offset_factors = vec![vec![F2_128::from(0u64); offset_terms]; 4];
    for bit in 0..4 {
        for cycle in 0..cycles {
            let index = bit * cycles + cycle;
            let delta = if bit < 3 {
                deltas[bit]
            } else {
                F2_128::from(0u64)
            };
            offset_factors[0][index] = offset_eq_j[cycle];
            offset_factors[1][index] = delta;
            offset_factors[2][index] = if bit < 3 {
                witness.offset_bits[bit][cycle]
            } else {
                F2_128::from(0u64)
            };
            offset_factors[3][index] = if bit < 3 {
                F2_128::from(((witness.routes[cycle].offset() >> bit) & 1) as u64)
            } else {
                F2_128::from(0u64)
            };
        }
    }
    let offset_degrees = vec![2usize; offset_terms.trailing_zeros() as usize];
    let (offset_rounds, offset_challenges) =
        sumcheck_offset(&offset_factors, &offset_degrees, &mut transcript)?;
    let offset_r_j = &offset_challenges[..n];
    let offset_evals = (0..3)
        .map(|bit| fold_all(&witness.offset_bits[bit], offset_r_j))
        .collect::<Vec<_>>();
    let offset_point = if offset_r_j.is_empty() {
        vec![F2_128::from(0u64)]
    } else {
        offset_r_j.to_vec()
    };

    let mut transcript = Sha256Transcript::new("magnetar-binary-router-width");
    absorb_commitment(&mut transcript, commitment);
    let width_rho_j = sample_point(&mut transcript, n);
    let width_deltas = (0..4)
        .map(|_| challenge(&mut transcript, "delta"))
        .collect::<Vec<_>>();
    let width_eq_j = eq_vector(&width_rho_j, cycles);
    let width_terms = 4 * cycles;
    let mut width_factors = vec![vec![F2_128::from(0u64); width_terms]; 4];
    for bit in 0..4 {
        for cycle in 0..cycles {
            let index = bit * cycles + cycle;
            width_factors[0][index] = width_eq_j[cycle];
            width_factors[1][index] = width_deltas[bit];
            width_factors[2][index] = witness.width_bits[bit][cycle];
            let expected = if let RouterRoute::Store(route) = witness.routes[cycle] {
                let width = match route.width {
                    StoreWidth::Byte => 0,
                    StoreWidth::Half => 1,
                    StoreWidth::Word => 2,
                    StoreWidth::Double => 3,
                };
                u64::from(width == bit)
            } else {
                0
            };
            width_factors[3][index] = F2_128::from(expected);
        }
    }
    let width_degrees = vec![2usize; width_terms.trailing_zeros() as usize];
    let (width_rounds, width_challenges) =
        sumcheck_offset(&width_factors, &width_degrees, &mut transcript)?;
    let width_r_j = &width_challenges[..n];
    let width_evals = (0..4)
        .map(|bit| fold_all(&witness.width_bits[bit], width_r_j))
        .collect::<Vec<_>>();
    let width_point = if width_r_j.is_empty() {
        vec![F2_128::from(0u64)]
    } else {
        width_r_j.to_vec()
    };

    let mut transcript = Sha256Transcript::new("magnetar-binary-router-shift");
    absorb_commitment(&mut transcript, commitment);
    let shift_rho_j = sample_point(&mut transcript, n);
    let shift_eq_j = eq_vector(&shift_rho_j, cycles);
    let mut shift_factors = vec![vec![F2_128::from(0u64); cycles]; 4];
    for cycle in 0..cycles {
        shift_factors[0][cycle] = shift_eq_j[cycle];
        shift_factors[1][cycle] = F2_128::from(1u64);
        shift_factors[2][cycle] = witness.shift_code[cycle];
        shift_factors[3][cycle] = F2_128::from(witness.routes[cycle].shift_code());
    }
    let shift_degrees = vec![2usize; cycles.trailing_zeros() as usize];
    let (shift_rounds, shift_challenges) =
        sumcheck_offset(&shift_factors, &shift_degrees, &mut transcript)?;
    let shift_r_j = &shift_challenges[..n];
    let shift_eval = fold_all(&witness.shift_code, shift_r_j);
    let shift_point = if shift_r_j.is_empty() {
        vec![F2_128::from(0u64)]
    } else {
        shift_r_j.to_vec()
    };

    let mut transcript = Sha256Transcript::new("magnetar-binary-router-valid");
    absorb_commitment(&mut transcript, commitment);
    let valid_rho_j = sample_point(&mut transcript, n);
    let valid_deltas = (0..2)
        .map(|_| challenge(&mut transcript, "delta"))
        .collect::<Vec<_>>();
    let valid_eq_j = eq_vector(&valid_rho_j, cycles);
    let valid_terms = 2 * cycles;
    let mut valid_factors = vec![vec![F2_128::from(0u64); valid_terms]; 4];
    for bit in 0..2 {
        for cycle in 0..cycles {
            let index = bit * cycles + cycle;
            valid_factors[0][index] = valid_eq_j[cycle];
            valid_factors[1][index] = valid_deltas[bit];
            valid_factors[2][index] = if bit == 0 {
                witness.is_shift[cycle]
            } else {
                witness.is_store[cycle]
            };
            valid_factors[3][index] = if bit == 0 {
                F2_128::from(u64::from(matches!(
                    witness.routes[cycle],
                    RouterRoute::Shift(_)
                )))
            } else {
                F2_128::from(u64::from(matches!(
                    witness.routes[cycle],
                    RouterRoute::Store(_)
                )))
            };
        }
    }
    let valid_degrees = vec![2usize; valid_terms.trailing_zeros() as usize];
    let (valid_rounds, valid_challenges) =
        sumcheck_offset(&valid_factors, &valid_degrees, &mut transcript)?;
    let valid_r_j = &valid_challenges[..n];
    let valid_evals = [&witness.is_shift, &witness.is_store]
        .into_iter()
        .map(|column| fold_all(column, valid_r_j))
        .collect::<Vec<_>>();
    let valid_point = if valid_r_j.is_empty() {
        vec![F2_128::from(0u64)]
    } else {
        valid_r_j.to_vec()
    };
    let mut transcript = Sha256Transcript::new("magnetar-binary-router-q");
    absorb_commitment(&mut transcript, commitment);
    let q_rho_j = sample_point(&mut transcript, n);
    let _q_rho_h = sample_point(&mut transcript, 8);
    let q_eq_j = eq_vector(&q_rho_j, cycles);
    let q_terms = 64 * cycles;
    let mut q_left = vec![F2_128::from(0u64); q_terms];
    let mut q_right = vec![F2_128::from(0u64); q_terms];
    for h in 0..64usize {
        for cycle in 0..cycles {
            q_left[h * cycles + cycle] = q_eq_j[cycle];
            if h < 64 {
                q_right[h * cycles + cycle] = witness.shift_q[h][cycle];
            }
        }
    }
    let q_degrees = vec![2usize; q_terms.trailing_zeros() as usize];
    let (q_rounds, q_challenges) =
        sumcheck_product(&q_left, &q_right, &q_degrees, &mut transcript)?;
    let q_r_j = &q_challenges[..n];
    let q_evals = (0..64)
        .map(|h| fold_all(&witness.shift_q[h], q_r_j))
        .collect::<Vec<_>>();
    let q_point = if q_r_j.is_empty() {
        vec![F2_128::from(0u64)]
    } else {
        q_r_j.to_vec()
    };
    let mut transcript = Sha256Transcript::new("magnetar-binary-router-hq");
    absorb_commitment(&mut transcript, commitment);
    let hq_rho_j = sample_point(&mut transcript, n);
    let _hq_rho_h = sample_point(&mut transcript, 8);
    let hq_eq_j = eq_vector(&hq_rho_j, cycles);
    let hq_terms = 64 * cycles;
    let mut hq_left = vec![F2_128::from(0u64); hq_terms];
    let mut hq_right = vec![F2_128::from(0u64); hq_terms];
    for h in 0..64usize {
        for cycle in 0..cycles {
            hq_left[h * cycles + cycle] = hq_eq_j[cycle];
            if h < 64 {
                hq_right[h * cycles + cycle] = witness.shift_hq[h][cycle];
            }
        }
    }
    let hq_degrees = vec![2usize; hq_terms.trailing_zeros() as usize];
    let (hq_rounds, hq_challenges) =
        sumcheck_product(&hq_left, &hq_right, &hq_degrees, &mut transcript)?;
    let hq_r_j = &hq_challenges[..n];
    let hq_evals = (0..64)
        .map(|h| fold_all(&witness.shift_hq[h], hq_r_j))
        .collect::<Vec<_>>();
    let hq_point = if hq_r_j.is_empty() {
        vec![F2_128::from(0u64)]
    } else {
        hq_r_j.to_vec()
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
            columns: (0..bit_columns).collect(),
            next_columns: Vec::new(),
        },
        P3MosaicPoint {
            table: table_index,
            point,
            columns: (0..INPUT_BITS).collect(),
            next_columns: Vec::new(),
        },
        P3MosaicPoint {
            table: table_index,
            point: offset_point,
            columns: (INPUT_BITS..INPUT_BITS + 3).collect(),
            next_columns: Vec::new(),
        },
        P3MosaicPoint {
            table: table_index,
            point: width_point,
            columns: (INPUT_BITS + 3..INPUT_BITS + 7).collect(),
            next_columns: Vec::new(),
        },
        P3MosaicPoint {
            table: table_index,
            point: shift_point,
            columns: (hq_columns..total_columns).collect(),
            next_columns: Vec::new(),
        },
        P3MosaicPoint {
            table: table_index,
            point: valid_point,
            columns: (INPUT_BITS + 7..INPUT_BITS + 9).collect(),
            next_columns: Vec::new(),
        },
        P3MosaicPoint {
            table: table_index,
            point: q_point,
            columns: (INPUT_BITS + 9..bit_columns).collect(),
            next_columns: Vec::new(),
        },
        P3MosaicPoint {
            table: table_index,
            point: hq_point,
            columns: (bit_columns..hq_columns).collect(),
            next_columns: Vec::new(),
        },
    ];
    let values = vec![
        boolean.bit_evals.clone(),
        input_bit_evals.clone(),
        offset_evals.clone(),
        width_evals.clone(),
        vec![shift_eval],
        valid_evals.clone(),
        q_evals.clone(),
        hq_evals.clone(),
    ];
    Ok((
        BinaryRouterProof {
            cycle_bits: n,
            boolean,
            claimed: left,
            cycle_point: rho_j,
            rounds,
            challenges,
            input_bit_evals,
            offset_rounds,
            offset_challenges,
            offset_cycle_point: offset_rho_j,
            offset_evals,
            width_rounds,
            width_challenges,
            width_cycle_point: width_rho_j,
            width_evals,
            shift_rounds,
            shift_challenges,
            shift_cycle_point: shift_rho_j,
            shift_eval,
            q_rounds,
            q_challenges,
            q_cycle_point: q_rho_j,
            q_evals,
            hq_rounds,
            hq_challenges,
            hq_cycle_point: hq_rho_j,
            hq_evals,
            valid_rounds,
            valid_challenges,
            valid_cycle_point: valid_rho_j,
            valid_evals,
            opening: None,
        },
        points,
        values,
    ))
}

pub fn prove_binary_router(witness: &BinaryRouterWitness) -> Result<BinaryRouterProof, ProofError> {
    witness.validate()?;
    let pcs = P3BinaryPcs::new(100);
    let table = witness.table();
    let commitment = pcs.commit_mosaic(core::slice::from_ref(&table))?;
    let (mut proof, points, _) = prove_binary_router_claims(witness, &commitment, 0)?;
    proof.opening = Some(pcs.open_mosaic(core::slice::from_ref(&table), &points)?);
    Ok(proof)
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

fn hq_eq_claimed(witness: &BinaryRouterWitness, point: &[F2_128]) -> F2_128 {
    let eq = eq_vector(point, witness.cycles);
    eq.iter()
        .zip(&witness.shift_code)
        .fold(F2_128::from(0u64), |sum, (weight, value)| {
            sum + *weight * F2_128::from(value.value() as u64 % 64)
        })
}

fn q_eq_claimed(witness: &BinaryRouterWitness, point: &[F2_128]) -> F2_128 {
    let eq = eq_vector(point, witness.cycles);
    eq.iter()
        .zip(&witness.is_shift)
        .fold(F2_128::from(0u64), |sum, (weight, value)| {
            sum + *weight * *value
        })
}

#[allow(clippy::needless_range_loop)]
pub(crate) fn verify_binary_router_claims(
    witness: &BinaryRouterWitness,
    proof: &BinaryRouterProof,
    commitment: &P3MosaicCommitment,
    table_index: usize,
) -> Result<Option<ClaimPoints>, ProofError> {
    witness.validate()?;
    if proof.cycle_bits != witness.cycle_bits {
        return Ok(None);
    }
    let n = witness.cycle_bits;
    let cycles = witness.cycles;
    let bit_columns = INPUT_BITS + 9 + 64;
    let hq_columns = bit_columns + 64;
    let total_columns = hq_columns + 1;
    let col_bits = bit_columns.next_power_of_two().trailing_zeros() as usize;
    if commitment.tables.len() <= table_index
        || commitment.tables[table_index].num_variables != n.max(1)
        || commitment.tables[table_index].num_columns != total_columns
    {
        return Ok(None);
    }

    let mut transcript = Sha256Transcript::new("magnetar-binary-router-boolean");
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
    for column in 0..bit_columns {
        b = b + eq_at_index(r_c, column) * proof.boolean.bit_evals[column];
    }
    if sum != eq_points(&rho_c, r_c) * eq_points(&rho_j, r_j) * b * (b + F2_128::from(1u64)) {
        return Ok(None);
    }

    let mut transcript = Sha256Transcript::new("magnetar-binary-router");
    absorb_commitment(&mut transcript, commitment);
    let rho_o = sample_point(&mut transcript, WORD_BITS.trailing_zeros() as usize);
    let rho_j = sample_point(&mut transcript, n);
    if proof.cycle_point != rho_j {
        return Ok(None);
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
    let r_i = &proof.challenges[n..];
    let coefficients = witness.route_coefficients_from_selectors(&rho_o);
    let mut coefficient_flat = vec![F2_128::from(0u64); INPUT_BITS * cycles];
    for bit in 0..INPUT_BITS {
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
        return Ok(None);
    }

    let mut transcript = Sha256Transcript::new("magnetar-binary-router-offset");
    absorb_commitment(&mut transcript, commitment);
    let offset_rho_j = sample_point(&mut transcript, n);
    let deltas = (0..3)
        .map(|_| challenge(&mut transcript, "delta"))
        .collect::<Vec<_>>();
    if proof.offset_cycle_point != offset_rho_j {
        return Ok(None);
    }
    let Some(sum) = replay_terms(
        &proof.offset_rounds,
        &proof.offset_challenges,
        F2_128::from(0u64),
        &mut transcript,
    ) else {
        return Ok(None);
    };
    let offset_r_j = &proof.offset_challenges[..n];
    let mut expected = F2_128::from(0u64);
    for bit in 0..3 {
        let public = (0..cycles)
            .map(|cycle| F2_128::from(((witness.routes[cycle].offset() >> bit) & 1) as u64))
            .collect::<Vec<_>>();
        expected =
            expected + deltas[bit] * (proof.offset_evals[bit] - fold_all(&public, offset_r_j));
    }
    if sum != eq_points(&offset_rho_j, offset_r_j) * expected {
        return Ok(None);
    }

    let mut transcript = Sha256Transcript::new("magnetar-binary-router-width");
    absorb_commitment(&mut transcript, commitment);
    let width_rho_j = sample_point(&mut transcript, n);
    let width_deltas = (0..4)
        .map(|_| challenge(&mut transcript, "delta"))
        .collect::<Vec<_>>();
    if proof.width_cycle_point != width_rho_j {
        return Ok(None);
    }
    let Some(sum) = replay_terms(
        &proof.width_rounds,
        &proof.width_challenges,
        F2_128::from(0u64),
        &mut transcript,
    ) else {
        return Ok(None);
    };
    let width_r_j = &proof.width_challenges[..n];
    let mut expected = F2_128::from(0u64);
    for bit in 0..4 {
        let public = (0..cycles)
            .map(|cycle| {
                let expected = if let RouterRoute::Store(route) = witness.routes[cycle] {
                    let width = match route.width {
                        StoreWidth::Byte => 0,
                        StoreWidth::Half => 1,
                        StoreWidth::Word => 2,
                        StoreWidth::Double => 3,
                    };
                    u64::from(width == bit)
                } else {
                    0
                };
                F2_128::from(expected)
            })
            .collect::<Vec<_>>();
        expected =
            expected + width_deltas[bit] * (proof.width_evals[bit] - fold_all(&public, width_r_j));
    }
    if sum != eq_points(&width_rho_j, width_r_j) * expected {
        return Ok(None);
    }

    let mut transcript = Sha256Transcript::new("magnetar-binary-router-shift");
    absorb_commitment(&mut transcript, commitment);
    let shift_rho_j = sample_point(&mut transcript, n);
    if proof.shift_cycle_point != shift_rho_j {
        return Ok(None);
    }
    let Some(sum) = replay_terms(
        &proof.shift_rounds,
        &proof.shift_challenges,
        F2_128::from(0u64),
        &mut transcript,
    ) else {
        return Ok(None);
    };
    let shift_r_j = &proof.shift_challenges[..n];
    let public = (0..cycles)
        .map(|cycle| F2_128::from(witness.routes[cycle].shift_code()))
        .collect::<Vec<_>>();
    if sum != eq_points(&shift_rho_j, shift_r_j) * (proof.shift_eval - fold_all(&public, shift_r_j))
    {
        return Ok(None);
    }

    let mut transcript = Sha256Transcript::new("magnetar-binary-router-valid");
    absorb_commitment(&mut transcript, commitment);
    let valid_rho_j = sample_point(&mut transcript, n);
    let valid_deltas = (0..2)
        .map(|_| challenge(&mut transcript, "delta"))
        .collect::<Vec<_>>();
    if proof.valid_cycle_point != valid_rho_j {
        return Ok(None);
    }
    let Some(sum) = replay_terms(
        &proof.valid_rounds,
        &proof.valid_challenges,
        F2_128::from(0u64),
        &mut transcript,
    ) else {
        return Ok(None);
    };
    let valid_r_j = &proof.valid_challenges[..n];
    let mut expected = F2_128::from(0u64);
    for bit in 0..2 {
        let public = (0..cycles)
            .map(|cycle| {
                F2_128::from(u64::from(if bit == 0 {
                    matches!(witness.routes[cycle], RouterRoute::Shift(_))
                } else {
                    matches!(witness.routes[cycle], RouterRoute::Store(_))
                }))
            })
            .collect::<Vec<_>>();
        expected =
            expected + valid_deltas[bit] * (proof.valid_evals[bit] - fold_all(&public, valid_r_j));
    }
    if sum != eq_points(&valid_rho_j, valid_r_j) * expected {
        return Ok(None);
    }

    let mut transcript = Sha256Transcript::new("magnetar-binary-router-q");
    absorb_commitment(&mut transcript, commitment);
    let q_rho_j = sample_point(&mut transcript, n);
    let _q_rho_h = sample_point(&mut transcript, 8);
    if proof.q_cycle_point != q_rho_j {
        return Ok(None);
    }
    let Some(sum) = replay_terms(
        &proof.q_rounds,
        &proof.q_challenges,
        q_eq_claimed(witness, &q_rho_j),
        &mut transcript,
    ) else {
        return Ok(None);
    };
    let q_r_j = &proof.q_challenges[..n];
    let q_r_h = &proof.q_challenges[n..];
    let mut q_eval = F2_128::from(0u64);
    for (h, eval) in proof.q_evals.iter().enumerate() {
        q_eval = q_eval + eq_at_index(q_r_h, h) * *eval;
    }
    if sum != eq_points(&q_rho_j, q_r_j) * q_eval {
        return Ok(None);
    }

    let mut transcript = Sha256Transcript::new("magnetar-binary-router-hq");
    absorb_commitment(&mut transcript, commitment);
    let hq_rho_j = sample_point(&mut transcript, n);
    let _hq_rho_h = sample_point(&mut transcript, 8);
    if proof.hq_cycle_point != hq_rho_j {
        return Ok(None);
    }
    let Some(sum) = replay_terms(
        &proof.hq_rounds,
        &proof.hq_challenges,
        hq_eq_claimed(witness, &hq_rho_j),
        &mut transcript,
    ) else {
        return Ok(None);
    };
    let hq_r_j = &proof.hq_challenges[..n];
    let hq_r_h = &proof.hq_challenges[n..];
    let mut hq_eval = F2_128::from(0u64);
    for (h, eval) in proof.hq_evals.iter().enumerate() {
        hq_eval = hq_eval + eq_at_index(hq_r_h, h) * *eval;
    }
    if sum != eq_points(&hq_rho_j, hq_r_j) * hq_eval {
        return Ok(None);
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
            table: table_index,
            point: boolean_point,
            columns: (0..bit_columns).collect(),
            next_columns: Vec::new(),
        },
        P3MosaicPoint {
            table: table_index,
            point,
            columns: (0..INPUT_BITS).collect(),
            next_columns: Vec::new(),
        },
        P3MosaicPoint {
            table: table_index,
            point: if offset_r_j.is_empty() {
                vec![F2_128::from(0u64)]
            } else {
                offset_r_j.to_vec()
            },
            columns: (INPUT_BITS..INPUT_BITS + 3).collect(),
            next_columns: Vec::new(),
        },
        P3MosaicPoint {
            table: table_index,
            point: if width_r_j.is_empty() {
                vec![F2_128::from(0u64)]
            } else {
                width_r_j.to_vec()
            },
            columns: (INPUT_BITS + 3..INPUT_BITS + 7).collect(),
            next_columns: Vec::new(),
        },
        P3MosaicPoint {
            table: table_index,
            point: if shift_r_j.is_empty() {
                vec![F2_128::from(0u64)]
            } else {
                shift_r_j.to_vec()
            },
            columns: (hq_columns..total_columns).collect(),
            next_columns: Vec::new(),
        },
        P3MosaicPoint {
            table: table_index,
            point: if valid_r_j.is_empty() {
                vec![F2_128::from(0u64)]
            } else {
                valid_r_j.to_vec()
            },
            columns: (INPUT_BITS + 7..INPUT_BITS + 9).collect(),
            next_columns: Vec::new(),
        },
        P3MosaicPoint {
            table: table_index,
            point: if q_r_j.is_empty() {
                vec![F2_128::from(0u64)]
            } else {
                q_r_j.to_vec()
            },
            columns: (INPUT_BITS + 9..bit_columns).collect(),
            next_columns: Vec::new(),
        },
        P3MosaicPoint {
            table: table_index,
            point: if hq_r_j.is_empty() {
                vec![F2_128::from(0u64)]
            } else {
                hq_r_j.to_vec()
            },
            columns: (bit_columns..hq_columns).collect(),
            next_columns: Vec::new(),
        },
    ];
    let values = vec![
        proof.boolean.bit_evals.clone(),
        proof.input_bit_evals.clone(),
        proof.offset_evals.clone(),
        proof.width_evals.clone(),
        vec![proof.shift_eval],
        proof.valid_evals.clone(),
        proof.q_evals.clone(),
        proof.hq_evals.clone(),
    ];
    Ok(Some((points, values)))
}

pub fn verify_binary_router(
    witness: &BinaryRouterWitness,
    proof: &BinaryRouterProof,
) -> Result<bool, ProofError> {
    let Some(opening) = &proof.opening else {
        return Ok(false);
    };
    let Some((points, values)) =
        verify_binary_router_claims(witness, proof, &opening.commitment, 0)?
    else {
        return Ok(false);
    };
    P3BinaryPcs::new(100).verify_mosaic(opening, &points, &values)
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
                instruction(Op::Addi, 2, 0, 0, 0x456).encode(),
                instruction(Op::Slli, 4, 1, 0, 8).encode(),
                instruction(Op::Lui, 3, 0, 0, 0x1000_0000).encode(),
                instruction(Op::Sd, 0, 3, 2, 0).encode(),
                instruction(Op::Sh, 0, 3, 1, 4).encode(),
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
        assert_eq!(
            witness.routes.len().count_ones(),
            witness.routes.len().count_ones()
        );
        assert!(witness
            .routes
            .iter()
            .any(|route| matches!(route, RouterRoute::Store(_))));
        assert!(witness
            .routes
            .iter()
            .any(|route| matches!(route, RouterRoute::Shift(_))));
        let proof = prove_binary_router(&witness).unwrap();
        assert!(verify_binary_router(&witness, &proof).unwrap());

        let mut tampered = proof.clone();
        tampered.claimed = tampered.claimed + F2_128::from(1u64);
        assert!(!verify_binary_router(&witness, &tampered).unwrap());

        let mut tampered = proof.clone();
        tampered.q_evals[0] = tampered.q_evals[0] + F2_128::from(1u64);
        assert!(!verify_binary_router(&witness, &tampered).unwrap());

        let mut tampered = proof.clone();
        tampered.hq_evals[0] = tampered.hq_evals[0] + F2_128::from(1u64);
        assert!(!verify_binary_router(&witness, &tampered).unwrap());

        let mut tampered = proof;
        tampered.input_bit_evals[0] = tampered.input_bit_evals[0] + F2_128::from(1u64);
        assert!(!verify_binary_router(&witness, &tampered).unwrap());
    }
    #[test]
    fn router_modes_round_trip() {
        let trace = trace();
        for mode in [RouterMode::Shifts, RouterMode::Stores] {
            let witness = BinaryRouterWitness::from_trace_mode(&trace, mode).unwrap();
            let expected = match mode {
                RouterMode::Shifts => {
                    RouterRoute::Shift(ShiftRoute::new(ShiftKind::LogicalLeft, 0))
                }
                RouterMode::Stores => {
                    RouterRoute::Store(StoreRoute::new(StoreWidth::Byte, 0).unwrap())
                }
                RouterMode::Both => unreachable!(),
            };
            assert!(witness
                .routes
                .iter()
                .any(|route| std::mem::discriminant(route) == std::mem::discriminant(&expected)));
            let proof = prove_binary_router(&witness).unwrap();
            assert!(verify_binary_router(&witness, &proof).unwrap());
        }
    }
    #[test]
    fn selector_coefficients_match_public_routes() {
        let trace = trace();
        let witness = BinaryRouterWitness::from_trace(&trace).unwrap();
        let rho_o = (0..WORD_BITS)
            .map(|bit| F2_128::from((bit as u64 * 5 + 3) & 1))
            .collect::<Vec<_>>();
        assert_eq!(
            witness.route_coefficients(&rho_o),
            witness.route_coefficients_from_selectors(&rho_o)
        );
        let store_witness =
            BinaryRouterWitness::from_trace_mode(&trace, RouterMode::Stores).unwrap();
        assert_eq!(
            store_witness.route_coefficients(&rho_o),
            store_witness.route_coefficients_from_selectors(&rho_o)
        );
    }
    #[test]
    fn store_mode_handles_amo_between_stores() {
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
                instruction(Op::Lui, 4, 0, 0, 0x1000_0000).encode(),
                instruction(Op::Lui, 1, 0, 0, 0x8000_0000).encode(),
                instruction(Op::Sd, 0, 4, 1, 0).encode(),
                instruction(Op::Addi, 2, 0, 0, 7).encode(),
                instruction(Op::AmoswapW, 3, 4, 2, 0).encode(),
                instruction(Op::Addi, 1, 0, 0, 10).encode(),
                instruction(Op::Sd, 0, 4, 1, 0).encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
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
        let witness = BinaryRouterWitness::from_trace_mode(&trace, RouterMode::Stores).unwrap();
        let rho_o = (0..WORD_BITS)
            .map(|bit| F2_128::from((bit as u64 * 7 + 1) & 1))
            .collect::<Vec<_>>();
        assert_eq!(
            witness.route_coefficients(&rho_o),
            witness.route_coefficients_from_selectors(&rho_o)
        );
        let proof = prove_binary_router(&witness).unwrap();
        assert!(verify_binary_router(&witness, &proof).unwrap());
    }
}
