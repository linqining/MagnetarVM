//! Streaming prover for the lockstep relation over shared block matrices.
//!
//! The eager lockstep prover materializes six `rows`-length matvec vectors,
//! six MLE copies of them, a `rows`-length equality vector, six `cols`-length
//! row-combination vectors and the `cols`-length inner left vector. At RV64
//! `2^16` that is well over 100 GB. This module derives every one of those
//! values from the bit witness on demand and keeps only
//!
//! * one bounded "level" array per vector (the first `level` sumcheck rounds
//!   are recomputed from the witness, the remaining rounds fold the level
//!   arrays in memory), and
//! * one chunk buffer per worker.
//!
//! Folding is linear, so the level-`k` value of a vector is the same whether
//! it is obtained by folding `k` times from level zero or by folding once from
//! a level-`k-1` array; the round polynomials, the challenges and the produced
//! proof are therefore identical to the eager path.

use magnetar_constraint::F2_128;

use crate::simd::{LazyExtraRows, SharedBlockMatrix};
use crate::spartan::eq_vector_tensor;
use crate::{eq, SpartanError, SumcheckProof};

type F = F2_128;

#[inline]
fn zero() -> F {
    F::from(0u64)
}

#[inline]
fn one() -> F {
    F::from(1u64)
}

#[inline]
fn bit_to_field(bit: bool) -> F {
    if bit {
        one()
    } else {
        zero()
    }
}

pub fn profile() -> bool {
    std::env::var_os("MAGNETAR_PROFILE_STREAM").is_some()
}

fn workers() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
}

/// Split `count` items into one contiguous range per worker.
fn worker_ranges(count: usize) -> Vec<(usize, usize)> {
    let workers = workers().min(count.max(1)).max(1);
    (0..workers)
        .map(|worker| (count * worker / workers, count * (worker + 1) / workers))
        .filter(|(start, end)| start < end)
        .collect()
}

/// Number of recomputed sumcheck rounds for a vector of `2^bits` entries.
///
/// The level array holds `2^(bits - level + 1)` entries; the budget caps that
/// at `2^22` entries (64 MiB per vector) so the prover peak stays bounded while
/// keeping the number of full witness scans small.
pub fn auto_level(bits: usize) -> usize {
    if std::env::var_os("MAGNETAR_STREAM_EAGER").is_some() {
        return 0;
    }
    let budget = std::env::var("MAGNETAR_STREAM_BUDGET_LOG")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(22);
    bits.saturating_sub(budget.saturating_sub(1))
}

/// Equality values `eq(point, bits(index))` for `index = 0, 1, 2, ...`
/// without materializing the whole hypercube.
struct EqTable {
    low: Vec<F>,
    low_mask: usize,
    low_bits: usize,
    high: Vec<F>,
}

impl EqTable {
    fn new(point: &[F]) -> Self {
        let low_bits = point.len().min(16);
        let low = eq_vector_tensor(&point[..low_bits]);
        let high = if point.len() > low_bits {
            eq_vector_tensor(&point[low_bits..])
        } else {
            vec![one()]
        };
        Self {
            low,
            low_mask: (1usize << low_bits) - 1,
            low_bits,
            high,
        }
    }

    #[inline]
    fn at(&self, index: usize) -> F {
        let low = self.low[index & self.low_mask];
        if self.high.len() == 1 {
            low
        } else {
            low * self.high[index >> self.low_bits]
        }
    }

    fn len(&self) -> usize {
        self.high.len() * self.low.len()
    }
}

/// Row-value source for the six lockstep matrices.
///
/// Row `r < base_rows * instances` is the block-diagonal row
/// `(r / base_rows, r % base_rows)`; rows after that are the shared extra rows
/// (lazy gated pattern), and the remaining rows up to the padded power of two
/// are zero.
pub struct LockstepRows<'a> {
    bits: &'a crate::PackedBits,
    matrices: [&'a SharedBlockMatrix; 6],
    base_rows: usize,
    log_base_rows: usize,
    log_base_cols: usize,
    instance_rows: usize,
    rows: usize,
    log_rows: usize,
    /// Base-matrix nonzeros grouped by local row: `(slot, column, coefficient)`
    /// for slots `0..6` in `A0, B0, C0, A1, B1, C1` order. Most base rows are
    /// empty, so one flat pass beats six sparse-row probes per row.
    base_offsets: Vec<u32>,
    base_entries: Vec<(u8, u32, F)>,
}

impl<'a> LockstepRows<'a> {
    pub fn new(
        bits: &'a crate::PackedBits,
        matrices: [&'a SharedBlockMatrix; 6],
    ) -> Result<Self, SpartanError> {
        let first = matrices[0];
        if bits.len() != first.cols() {
            return Err(SpartanError::Dimensions);
        }
        let base_rows = first.base_row_count();
        let base_cols = first.base_col_count();
        let instances = first.instances();
        if !base_rows.is_power_of_two() || !base_cols.is_power_of_two() {
            return Err(SpartanError::Dimensions);
        }
        for matrix in matrices {
            if matrix.rows() != first.rows()
                || matrix.cols() != first.cols()
                || matrix.base_row_count() != base_rows
                || matrix.base_col_count() != base_cols
                || matrix.instances() != instances
            {
                return Err(SpartanError::Dimensions);
            }
            if matrix.lazy_extra_rows().is_none() && matrix.extra_row_count() != 0 {
                return Err(SpartanError::Streaming(
                    "streaming prover requires lazy extra rows".into(),
                ));
            }
        }
        let rows = first.rows();
        if !rows.is_power_of_two() {
            return Err(SpartanError::Dimensions);
        }
        let instance_rows = base_rows * instances;
        let extra_len = matrices
            .iter()
            .map(|matrix| matrix.extra_row_count())
            .max()
            .unwrap_or(0);
        if instance_rows + extra_len > rows {
            return Err(SpartanError::Dimensions);
        }
        let mut counts = vec![0u32; base_rows + 1];
        for (slot, matrix) in matrices.iter().enumerate() {
            for (local, row) in matrix.base_matrix().rows.iter().enumerate() {
                counts[local + 1] += row.len() as u32;
                let _ = slot;
            }
        }
        for local in 0..base_rows {
            counts[local + 1] += counts[local];
        }
        let total = counts[base_rows] as usize;
        let mut entries = Vec::with_capacity(total);
        for (slot, matrix) in matrices.iter().enumerate() {
            for row in matrix.base_matrix().rows.iter() {
                for (column, coefficient) in row {
                    entries.push((slot as u8, *column as u32, *coefficient));
                }
            }
        }
        // Sort each row's entries into the CSR order (stable by local row, then
        // slot), matching the previous per-slot accumulation order.
        let mut cursor = counts.clone();
        let mut sorted = vec![(0u8, 0u32, zero()); total];
        for (slot, matrix) in matrices.iter().enumerate() {
            for (local, row) in matrix.base_matrix().rows.iter().enumerate() {
                for (column, coefficient) in row {
                    let position = &mut cursor[local];
                    sorted[*position as usize] = (slot as u8, *column as u32, *coefficient);
                    *position += 1;
                }
            }
        }
        if profile() {
            eprintln!(
                "lockstep rows: base_rows={base_rows} base_cols={base_cols} entries={total} per_row={:.2} instance_rows={instance_rows} rows={rows}",
                total as f64 / base_rows as f64
            );
        }
        Ok(Self {
            bits,
            matrices,
            base_rows,
            log_base_rows: base_rows.trailing_zeros() as usize,
            log_base_cols: base_cols.trailing_zeros() as usize,
            instance_rows,
            rows,
            log_rows: rows.trailing_zeros() as usize,
            base_offsets: counts,
            base_entries: sorted,
        })
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn row_bits(&self) -> usize {
        self.log_rows
    }

    pub fn matrices(&self) -> [&'a SharedBlockMatrix; 6] {
        self.matrices
    }

    #[inline]
    pub fn row_values(&self, row: usize, out: &mut [F; 6]) {
        if row < self.instance_rows {
            let instance = row >> self.log_base_rows;
            let local = row & (self.base_rows - 1);
            let offset = instance << self.log_base_cols;
            let bits = self.bits;
            *out = [zero(); 6];
            let first = self.base_offsets[local] as usize;
            let last = self.base_offsets[local + 1] as usize;
            for &(slot, column, coefficient) in &self.base_entries[first..last] {
                if bits.get(offset + column as usize) {
                    out[slot as usize] = out[slot as usize] + coefficient;
                }
            }
        } else {
            let extra = row - self.instance_rows;
            for (slot, matrix) in out.iter_mut().zip(self.matrices) {
                *slot = matrix.extra_row_value(extra, self.bits);
            }
        }
    }

    /// Accumulate `weight * row_values(row)` into `out` without materialising the
    /// six values: every set CSR entry adds `weight * coefficient` to its slot.
    /// Distributivity makes this bit-identical to `accumulate_weighted` over
    /// `row_values` (addition is XOR in the binary tower field).
    #[inline]
    pub fn accumulate_row_values(&self, row: usize, weight: F, out: &mut [F; 6]) {
        if row < self.instance_rows {
            let instance = row >> self.log_base_rows;
            let local = row & (self.base_rows - 1);
            let offset = instance << self.log_base_cols;
            let bits = self.bits;
            let first = self.base_offsets[local] as usize;
            let last = self.base_offsets[local + 1] as usize;
            for &(slot, column, coefficient) in &self.base_entries[first..last] {
                if bits.get(offset + column as usize) {
                    let term = if coefficient == one() {
                        weight
                    } else {
                        weight * coefficient
                    };
                    out[slot as usize] = out[slot as usize] + term;
                }
            }
        } else {
            let extra = row - self.instance_rows;
            let mut value = [zero(); 6];
            for (slot, matrix) in value.iter_mut().zip(self.matrices) {
                *slot = matrix.extra_row_value(extra, self.bits);
            }
            accumulate_weighted(out, weight, &value);
        }
    }
}

/// Coefficients of the `t^0..t^3` round polynomial contributed by one pair of
/// rows, matching `prove_product6`.
#[inline]
fn product6_pair(even: &[F; 6], odd: &[F; 6], eq0: F, eq1: F, alpha: F) -> [F; 4] {
    let eqd = eq1 - eq0;
    let a0 = even[0];
    let da0 = odd[0] - even[0];
    let b0 = even[1];
    let db0 = odd[1] - even[1];
    let c0 = even[2];
    let dc0 = odd[2] - even[2];
    let a1 = even[3];
    let da1 = odd[3] - even[3];
    let b1 = even[4];
    let db1 = odd[4] - even[4];
    let c1 = even[5];
    let dc1 = odd[5] - even[5];
    let p0 = a0 * b0 - c0 + alpha * (a1 * b1 - c1);
    let p1 = a0 * db0 + da0 * b0 - dc0 + alpha * (a1 * db1 + da1 * b1 - dc1);
    let p2 = da0 * db0 + alpha * (da1 * db1);
    let mut values = [zero(); 4];
    values[0] = eq0 * p0;
    values[1] = eq0 * p1 + eqd * p0;
    values[2] = eq0 * p2 + eqd * p1;
    values[3] = eqd * p2;
    values
}

#[inline]
fn eval_univariate4(coefficients: &[F; 4]) -> [F; 4] {
    let mut values = [zero(); 4];
    for (point, value) in values.iter_mut().enumerate() {
        let t = F::from(point as u64);
        *value = coefficients[0]
            + coefficients[1] * t
            + coefficients[2] * t * t
            + coefficients[3] * t * t * t;
    }
    values
}

pub struct OuterSumcheck {
    pub proof: SumcheckProof<F>,
    pub challenges: Vec<F>,
    /// Terminal values `MLE(az0), MLE(bz0), .., MLE(cz1)` at the challenges.
    pub terminal: [F; 6],
}

fn add_poly<const N: usize>(target: &mut [F; N], values: &[F; N]) {
    for point in 0..N {
        target[point] = target[point] + values[point];
    }
}

/// Streaming `eq * (a0*b0 - c0 + alpha*(a1*b1 - c1))` sumcheck over `rows`.
pub fn prove_product6_rows<C>(
    rows: &LockstepRows<'_>,
    tau: &[F],
    alpha: F,
    level: usize,
    mut challenge: C,
) -> Result<OuterSumcheck, SpartanError>
where
    C: FnMut(usize, &[F]) -> F,
{
    let n = rows.row_bits();
    if tau.len() != n {
        return Err(SpartanError::Dimensions);
    }
    let level = level.min(n);
    let total = rows.rows();
    let started = std::time::Instant::now();
    let mut challenges: Vec<F> = Vec::with_capacity(n);
    let mut round_polys: Vec<Vec<F>> = Vec::with_capacity(n);

    // Phase 1: rounds `0..level` are recomputed from the witness block by
    // block; the last pass also stores the level-(level-1) values.
    let mut stored: Vec<[F; 6]> = Vec::new();
    let mut eq_factor = one();
    for round in 0..level {
        let block = 1usize << (round + 1);
        let blocks = total >> (round + 1);
        let eq_table = EqTable::new(&tau[round + 1..]);
        if eq_table.len() != blocks {
            return Err(SpartanError::Dimensions);
        }
        let f0 = one() - tau[round];
        let f1 = tau[round];
        let scale = eq_factor;
        let store = round + 1 == level;
        if store {
            stored = vec![[zero(); 6]; blocks * 2];
        }
        let ranges = worker_ranges(blocks);
        let weights = fold_weights(&challenges[..]);
        let mut partials: Vec<[F; 4]> = Vec::with_capacity(ranges.len());
        std::thread::scope(|scope| {
            let mut rest: &mut [[F; 6]] = &mut stored[..];
            let mut handles = Vec::with_capacity(ranges.len());
            let eq_table = &eq_table;
            let weights = &weights;
            for &(start, end) in &ranges {
                let take = if store { (end - start) * 2 } else { 0 };
                let (head, tail) = rest.split_at_mut(take);
                rest = tail;
                handles.push(scope.spawn(move || {
                    let mut polynomial = [zero(); 4];
                    for (offset, block_index) in (start..end).enumerate() {
                        let first = block_index << (round + 1);
                        let mut even = [zero(); 6];
                        let mut odd = [zero(); 6];
                        for slot in 0..block {
                            let weight = weights[slot & (weights.len() - 1)];
                            let target = if slot & weights.len() == 0 {
                                &mut even
                            } else {
                                &mut odd
                            };
                            rows.accumulate_row_values(first + slot, weight, target);
                        }
                        let high = eq_table.at(block_index) * scale;
                        add_poly(
                            &mut polynomial,
                            &product6_pair(&even, &odd, high * f0, high * f1, alpha),
                        );
                        if store {
                            head[offset * 2] = even;
                            head[offset * 2 + 1] = odd;
                        }
                    }
                    polynomial
                }));
            }
            for handle in handles {
                partials.push(handle.join().expect("stream worker"));
            }
        });
        let mut coefficients = [zero(); 4];
        for polynomial in partials {
            add_poly(&mut coefficients, &polynomial);
        }
        let evaluated = eval_univariate4(&coefficients);
        let r = challenge(round, &evaluated);
        challenges.push(r);
        round_polys.push(evaluated.to_vec());
        eq_factor = eq_factor * ((one() - r) * (one() - tau[round]) + r * tau[round]);
    }
    if profile() {
        eprintln!(
            "stream outer recompute ({level} rounds, {} rows): {:?}",
            total,
            started.elapsed()
        );
    }

    // Fold the stored level-(level-1) values once so phase 2 starts at `level`.
    let mut arrays = if level > 0 {
        let challenge = challenges[level - 1];
        let stored_len = stored.len();
        fold_rows(&mut stored, stored_len, challenge);
        let half = stored_len / 2;
        let mut arrays = vec![[zero(); 6]; half];
        for (slot, value) in arrays.iter_mut().zip(&stored) {
            *slot = *value;
        }
        arrays
    } else {
        let mut arrays = vec![[zero(); 6]; total];
        let ranges = worker_ranges(total);
        std::thread::scope(|scope| {
            let mut rest: &mut [[F; 6]] = &mut arrays[..];
            let mut handles = Vec::with_capacity(ranges.len());
            for &(start, end) in &ranges {
                let (head, tail) = rest.split_at_mut(end - start);
                rest = tail;
                handles.push(scope.spawn(move || {
                    for (offset, slot) in head.iter_mut().enumerate() {
                        rows.row_values(start + offset, slot);
                    }
                }));
            }
            for handle in handles {
                handle.join().expect("stream worker");
            }
        });
        arrays
    };
    let remaining = n - level;
    if arrays.len() != 1usize << remaining {
        return Err(SpartanError::Dimensions);
    }
    let mut eq_values = eq_vector_tensor(&tau[level..]);
    for value in &mut eq_values {
        *value = *value * eq_factor;
    }
    let mut claimed_sum = if level > 0 {
        round_polys[0][0] + round_polys[0][1]
    } else {
        zero()
    };
    let started = std::time::Instant::now();
    for round in level..n {
        let pairs = arrays.len() / 2;
        let ranges = worker_ranges(pairs);
        let mut partials: Vec<[F; 4]> = Vec::with_capacity(ranges.len());
        std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(ranges.len());
            for &(start, end) in &ranges {
                let arrays = &arrays;
                let eq_values = &eq_values;
                handles.push(scope.spawn(move || {
                    let mut polynomial = [zero(); 4];
                    for index in start..end {
                        add_poly(
                            &mut polynomial,
                            &product6_pair(
                                &arrays[index * 2],
                                &arrays[index * 2 + 1],
                                eq_values[index * 2],
                                eq_values[index * 2 + 1],
                                alpha,
                            ),
                        );
                    }
                    polynomial
                }));
            }
            for handle in handles {
                partials.push(handle.join().expect("stream worker"));
            }
        });
        let mut coefficients = [zero(); 4];
        for polynomial in partials {
            add_poly(&mut coefficients, &polynomial);
        }
        let evaluated = eval_univariate4(&coefficients);
        if round == 0 {
            claimed_sum = evaluated[0] + evaluated[1];
        }
        let r = challenge(round, &evaluated);
        challenges.push(r);
        round_polys.push(evaluated.to_vec());
        for index in 0..pairs {
            let low = arrays[index * 2];
            let high = arrays[index * 2 + 1];
            for slot in 0..6 {
                arrays[index][slot] = low[slot] + r * (high[slot] - low[slot]);
            }
            let low = eq_values[index * 2];
            let high = eq_values[index * 2 + 1];
            eq_values[index] = low + r * (high - low);
        }
        arrays.truncate(pairs);
        eq_values.truncate(pairs);
    }
    if profile() {
        eprintln!(
            "stream outer fold ({remaining} rounds): {:?}",
            started.elapsed()
        );
    }
    if n == 0 {
        let value = &arrays[0];
        claimed_sum = eq_values[0]
            * (value[0] * value[1] - value[2] + alpha * (value[3] * value[4] - value[5]));
    }
    Ok(OuterSumcheck {
        proof: SumcheckProof {
            claimed_sum,
            round_polys,
        },
        challenges,
        terminal: arrays[0],
    })
}

/// Fold weights `w(s) = prod_{b<k} (s_b ? r_b : 1-r_b)` for `s < 2^k`.
///
/// Folding a length-`2^k` block `k` times is the same as one weighted sum with
/// these weights, which removes the repeated buffer passes that dominate the
/// recompute scans.
fn fold_weights(challenges: &[F]) -> Vec<F> {
    let mut weights = vec![one(); 1usize << challenges.len()];
    for (bit, challenge) in challenges.iter().enumerate() {
        let half = 1usize << bit;
        let zero_weight = one() - *challenge;
        for slot in 0..half {
            let weight = weights[slot];
            weights[slot + half] = weight * *challenge;
            weights[slot] = weight * zero_weight;
        }
    }
    weights
}

/// Accumulate `weight * value`, skipping the zero/one cases that a bit-valued
/// matrix product hits almost always (`F2_128` multiplication is expensive
/// relative to the addition it feeds).
#[inline]
fn accumulate_weighted(target: &mut [F; 6], weight: F, value: &[F; 6]) {
    for slot in 0..6 {
        let entry = value[slot];
        let term = if entry == one() {
            weight
        } else if entry == zero() {
            zero()
        } else {
            weight * entry
        };
        target[slot] = target[slot] + term;
    }
}

#[inline]
fn accumulate_scalar(target: &mut F, weight: F, value: F) {
    *target = *target
        + if value == one() {
            weight
        } else if value == zero() {
            zero()
        } else {
            weight * value
        };
}

#[inline]
fn fold_rows(values: &mut [[F; 6]], length: usize, challenge: F) {
    let half = length / 2;
    for index in 0..half {
        let low = values[index * 2];
        let high = values[index * 2 + 1];
        let mut folded = [zero(); 6];
        for slot in 0..6 {
            folded[slot] = low[slot] + challenge * (high[slot] - low[slot]);
        }
        values[index] = folded;
    }
}

/// A batched linear claim over the committed witness.
///
/// The claim asserts
/// `Σ_{(row, col)} eq(row_point, row) · α^{slot(col)} · w[row, col] = target`
/// for the committed witness `w`, where `row` is the block instance and `col`
/// the column inside the block. Its coefficient is a product of a row factor
/// and a small per-column table, so both sides can evaluate it cheaply: the
/// prover adds it to the inner sum-check's left vector (one pass it already
/// does), the verifier evaluates its MLE at the inner point in
/// `O(#columns · log)` and multiplies by the existing witness opening.
#[derive(Clone, Debug)]
pub struct LinearClaim {
    /// Claim point over the block instances.
    pub row_point: Vec<F>,
    /// `(column, weight)` for the claimed columns, weight `α^{slot}`.
    pub columns: Vec<(usize, F)>,
    /// Right-hand side `Σ eq(row_point, row) · Σ α^{slot} · value[row, slot]`.
    pub target: F,
}

impl LinearClaim {
    /// MLE of the claim coefficient at an inner point, split as
    /// `(column point, instance point)`.
    pub fn eval(&self, column_point: &[F], instance_point: &[F]) -> F {
        let row_factor = eq(self.row_point.as_slice(), instance_point);
        let mut column_sum = zero();
        for (column, weight) in &self.columns {
            let bits = crate::spartan::bits(*column, column_point.len());
            column_sum = column_sum + *weight * eq(column_point, &bits);
        }
        row_factor * column_sum
    }

    /// Dense per-column weights inside one block (`α^slot`, zero elsewhere).
    pub fn slot_weights(&self, block_cols: usize) -> Vec<F> {
        let mut weights = vec![zero(); block_cols];
        for (column, weight) in &self.columns {
            if *column < block_cols {
                weights[*column] = *weight;
            }
        }
        weights
    }
}

/// Column-value source for the inner product sumcheck.
///
/// The left vector is the batched row combination of the six matrices at the
/// outer point `rx`; column `c = instance * base_cols + local` evaluates to
/// `instance_weight(instance) * combined(local)` plus the sparse contribution
/// of the gated extra rows.
pub struct ColumnRows<'a> {
    bits: &'a crate::PackedBits,
    base_cols: usize,
    log_base_cols: usize,
    instance_rows: usize,
    combined: Vec<F>,
    instance_weight: Vec<F>,
    extras: Vec<(&'a LazyExtraRows, F)>,
    /// Local column window that the lazy extra rows can touch.
    extras_local: Option<(usize, usize)>,
    eq_low: Vec<F>,
    eq_low_mask: usize,
    eq_low_bits: usize,
    eq_high: Vec<F>,
    columns: usize,
    /// Folded claim coefficient: `+ instance_weight[instance] · (γ·α^slot)`.
    claim: Option<(&'a LinearClaim, F)>,
    claim_instance_weight: Vec<F>,
    claim_columns: Vec<(usize, F)>,
}

impl<'a> ColumnRows<'a> {
    pub fn new(
        bits: &'a crate::PackedBits,
        rows: &LockstepRows<'a>,
        scales: [F; 6],
        row_point: &[F],
    ) -> Result<Self, SpartanError> {
        let matrices = rows.matrices();
        let base_cols = matrices[0].base_col_count();
        let base_rows = matrices[0].base_row_count();
        let instances = matrices[0].instances();
        if row_point.len() != rows.row_bits() || bits.len() != matrices[0].cols() {
            return Err(SpartanError::Dimensions);
        }
        let log_base_rows = base_rows.trailing_zeros() as usize;
        let log_base_cols = base_cols.trailing_zeros() as usize;
        let instance_bits = instances.trailing_zeros() as usize;
        if row_point.len() < log_base_rows + instance_bits {
            return Err(SpartanError::Dimensions);
        }
        let local_point = &row_point[..log_base_rows];
        let mut combined = vec![zero(); base_cols];
        for (matrix, scale) in matrices.iter().zip(scales) {
            let local = matrix.base_matrix().row_combination(local_point)?;
            for (slot, value) in combined.iter_mut().zip(local) {
                *slot = *slot + scale * value;
            }
        }
        let instance_eq = eq_vector_tensor(&row_point[log_base_rows..log_base_rows + instance_bits]);
        let block_high = &row_point[log_base_rows + instance_bits..];
        let high_zero = eq(block_high, &vec![zero(); block_high.len()]);
        let instance_weight = instance_eq
            .iter()
            .map(|value| *value * high_zero)
            .collect::<Vec<_>>();
        let mut extras = Vec::new();
        let mut extras_local: Option<(usize, usize)> = None;
        for (matrix, scale) in matrices.iter().zip(scales) {
            if let Some(lazy) = matrix.lazy_extra_rows() {
                if !lazy.is_empty() {
                    let (low, high) = lazy.local_column_range();
                    extras_local = Some(match extras_local {
                        Some((current_low, current_high)) => {
                            (current_low.min(low), current_high.max(high))
                        }
                        None => (low, high),
                    });
                    extras.push((lazy, scale));
                }
            }
        }
        let eq_low_bits = row_point.len().min(16);
        let eq_low = eq_vector_tensor(&row_point[..eq_low_bits]);
        let eq_high = if row_point.len() > eq_low_bits {
            eq_vector_tensor(&row_point[eq_low_bits..])
        } else {
            vec![one()]
        };
        Ok(Self {
            bits,
            base_cols,
            log_base_cols,
            instance_rows: base_rows * instances,
            combined,
            instance_weight,
            extras,
            extras_local,
            eq_low,
            eq_low_mask: (1usize << eq_low_bits) - 1,
            eq_low_bits,
            eq_high,
            columns: bits.len(),
            claim: None,
            claim_instance_weight: Vec::new(),
            claim_columns: Vec::new(),
        })
    }

    /// Fold a batched linear claim into the left vector as `+ γ·coefficient`.
    ///
    /// The claim coefficient factorizes into a row factor and a small set of
    /// claimed columns, so this costs one multiply-add per claimed column per
    /// instance instead of a dense pass over the block.
    pub fn with_claim(mut self, claim: &'a LinearClaim, gamma: F) -> Result<Self, SpartanError> {
        let instances = self.instance_weight.len();
        if claim.row_point.len() != instances.trailing_zeros() as usize {
            return Err(SpartanError::Dimensions);
        }
        if claim.columns.iter().any(|(column, _)| *column >= self.base_cols) {
            return Err(SpartanError::Dimensions);
        }
        self.claim_instance_weight = eq_vector_tensor(&claim.row_point);
        self.claim_columns = claim
            .columns
            .iter()
            .map(|(column, weight)| (*column, gamma * *weight))
            .collect();
        self.claim = Some((claim, gamma));
        Ok(self)
    }

    pub fn len(&self) -> usize {
        self.columns
    }

    pub fn column_bits(&self) -> usize {
        self.columns.trailing_zeros() as usize
    }

    #[inline]
    fn row_eq(&self, index: usize) -> F {
        let low = self.eq_low[index & self.eq_low_mask];
        if self.eq_high.len() == 1 {
            low
        } else {
            low * self.eq_high[index >> self.eq_low_bits]
        }
    }

    /// Fill the left-vector values for the column range `start..start + out.len()`.
    pub fn fill_left(&self, start: usize, out: &mut [F]) {
        let mask = self.base_cols - 1;
        let mut position = 0;
        while position < out.len() {
            let column = start + position;
            let instance = column >> self.log_base_cols;
            let local = column & mask;
            let take = (out.len() - position).min(self.base_cols - local);
            let weight = self.instance_weight[instance];
            let combined = &self.combined[local..local + take];
            for (slot, value) in out[position..position + take].iter_mut().zip(combined) {
                *slot = weight * *value;
            }
            position += take;
        }
        if out.is_empty() {
            return;
        }
        let start_instance = start >> self.log_base_cols;
        let last_instance = (start + out.len() - 1) >> self.log_base_cols;
        if self.claim.is_some() {
            // Only the claimed columns inside the requested window, found by
            // binary search: early sum-check rounds ask for two columns at a
            // time, so a full scan of the claim would dominate.
            let mut position = 0;
            while position < out.len() {
                let column = start + position;
                let instance = column >> self.log_base_cols;
                let local = column & mask;
                let take = (out.len() - position).min(self.base_cols - local);
                let weight = self.claim_instance_weight[instance];
                let first = self
                    .claim_columns
                    .partition_point(|(claimed, _)| *claimed < local);
                let last = self
                    .claim_columns
                    .partition_point(|(claimed, _)| *claimed < local + take);
                for &(claimed, coefficient) in &self.claim_columns[first..last] {
                    let index = position + (claimed - local);
                    out[index] = out[index] + weight * coefficient;
                }
                position += take;
            }
        }
        if self.extras.is_empty() {
            return;
        }
        let first = start_instance.saturating_sub(1);
        let last = last_instance;
        let end = start + out.len();
        // The lazy rows only touch `extras_local` columns inside a block, so
        // blocks outside that window skip the per-entry scan entirely. Early
        // sum-check rounds ask for two columns at a time, so this is the
        // difference between one scan per block and one per round.
        let (extras_low, extras_high) = match self.extras_local {
            Some(window) => window,
            None => return,
        };
        let touches = |instance: usize| {
            // Part-2 rows can land in this instance's block (statement rows) or
            // in the next one (chain rows), so both are checked.
            for block in [instance * self.base_cols, (instance + 1) * self.base_cols] {
                let local_lo = start.saturating_sub(block);
                let local_hi = end.saturating_sub(block).min(self.base_cols);
                if local_hi > local_lo && local_hi > extras_low && local_lo <= extras_high {
                    return true;
                }
            }
            false
        };
        for instance in first..=last {
            if !touches(instance) {
                continue;
            }
            for (lazy, scale) in &self.extras {
                lazy.for_each_instance_entry(instance, |offset, column, coefficient| {
                    if column >= start && column < end {
                        let weight =
                            self.row_eq(self.instance_rows + offset) * *scale * coefficient;
                        out[column - start] = out[column - start] + weight;
                    }
                });
            }
        }
    }

    #[inline]
    pub fn fill_right(&self, start: usize, out: &mut [F]) {
        for (offset, slot) in out.iter_mut().enumerate() {
            *slot = bit_to_field(self.bits.get(start + offset));
        }
    }

}

pub struct InnerSumcheck {
    pub proof: SumcheckProof<F>,
    pub challenges: Vec<F>,
    /// Terminal left value (row combination at the inner point).
    pub left: F,
    /// Terminal right value, i.e. the witness MLE at the inner point.
    pub right: F,
}

#[inline]
fn product2_pair(left: &[F], right: &[F], index: usize) -> [F; 3] {
    let l0 = left[index * 2];
    let ld = left[index * 2 + 1] - left[index * 2];
    let r0 = right[index * 2];
    let rd = right[index * 2 + 1] - right[index * 2];
    [l0 * r0, l0 * rd + ld * r0, ld * rd]
}

#[inline]
fn eval_univariate3(coefficients: &[F; 3]) -> [F; 3] {
    let mut values = [zero(); 3];
    for (point, value) in values.iter_mut().enumerate() {
        let t = F::from(point as u64);
        *value = coefficients[0] + coefficients[1] * t + coefficients[2] * t * t;
    }
    values
}

#[inline]
fn fold_scalars(values: &mut [F], length: usize, challenge: F) {
    let half = length / 2;
    for index in 0..half {
        let low = values[index * 2];
        let high = values[index * 2 + 1];
        values[index] = low + challenge * (high - low);
    }
}

/// Streaming `left * right` sumcheck over the witness columns.
pub fn prove_product2_columns<C>(
    columns: &ColumnRows<'_>,
    level: usize,
    mut challenge: C,
) -> Result<InnerSumcheck, SpartanError>
where
    C: FnMut(usize, &[F]) -> F,
{
    let total = columns.len();
    if total == 0 || !total.is_power_of_two() {
        return Err(SpartanError::Dimensions);
    }
    let n = columns.column_bits();
    let level = level.min(n);
    let started = std::time::Instant::now();
    let mut challenges: Vec<F> = Vec::with_capacity(n);
    let mut round_polys: Vec<Vec<F>> = Vec::with_capacity(n);
    let mut stored_left: Vec<F> = Vec::new();
    let mut stored_right: Vec<F> = Vec::new();
    for round in 0..level {
        let block = 1usize << (round + 1);
        let blocks = total >> (round + 1);
        let store = round + 1 == level;
        if store {
            stored_left = vec![zero(); blocks * 2];
            stored_right = vec![zero(); blocks * 2];
        }
        let ranges = worker_ranges(blocks);
        let weights = fold_weights(&challenges[..]);
        let mut partials: Vec<[F; 3]> = Vec::with_capacity(ranges.len());
        std::thread::scope(|scope| {
            let mut left_rest: &mut [F] = &mut stored_left[..];
            let mut right_rest: &mut [F] = &mut stored_right[..];
            let mut handles = Vec::with_capacity(ranges.len());
            let weights = &weights;
            for &(start, end) in &ranges {
                let take = if store { (end - start) * 2 } else { 0 };
                let (left_head, left_tail) = left_rest.split_at_mut(take);
                left_rest = left_tail;
                let (right_head, right_tail) = right_rest.split_at_mut(take);
                right_rest = right_tail;
                handles.push(scope.spawn(move || {
                    let mut left = vec![zero(); block];
                    let mut right = vec![zero(); block];
                    let mut polynomial = [zero(); 3];
                    for (offset, block_index) in (start..end).enumerate() {
                        let first = block_index << (round + 1);
                        columns.fill_left(first, &mut left);
                        columns.fill_right(first, &mut right);
                        let (mut even_left, mut odd_left) = (zero(), zero());
                        let (mut even_right, mut odd_right) = (zero(), zero());
                        for slot in 0..block {
                            let weight = weights[slot & (weights.len() - 1)];
                            if slot & weights.len() == 0 {
                                accumulate_scalar(&mut even_left, weight, left[slot]);
                                accumulate_scalar(&mut even_right, weight, right[slot]);
                            } else {
                                accumulate_scalar(&mut odd_left, weight, left[slot]);
                                accumulate_scalar(&mut odd_right, weight, right[slot]);
                            }
                        }
                        let pair_left = [even_left, odd_left];
                        let pair_right = [even_right, odd_right];
                        add_poly(&mut polynomial, &product2_pair(&pair_left, &pair_right, 0));
                        if store {
                            left_head[offset * 2] = even_left;
                            left_head[offset * 2 + 1] = odd_left;
                            right_head[offset * 2] = even_right;
                            right_head[offset * 2 + 1] = odd_right;
                        }
                    }
                    polynomial
                }));
            }
            for handle in handles {
                partials.push(handle.join().expect("stream worker"));
            }
        });
        let mut coefficients = [zero(); 3];
        for polynomial in partials {
            add_poly(&mut coefficients, &polynomial);
        }
        let evaluated = eval_univariate3(&coefficients);
        let r = challenge(round, &evaluated);
        challenges.push(r);
        round_polys.push(evaluated.to_vec());
    }
    if profile() {
        eprintln!(
            "stream inner recompute ({level} rounds, {} columns): {:?}",
            total,
            started.elapsed()
        );
    }

    let (mut left, mut right) = if level > 0 {
        let challenge = challenges[level - 1];
        let stored_len = stored_left.len();
        fold_scalars(&mut stored_left, stored_len, challenge);
        fold_scalars(&mut stored_right, stored_len, challenge);
        let half = stored_len / 2;
        let mut left = vec![zero(); half];
        let mut right = vec![zero(); half];
        left.copy_from_slice(&stored_left[..half]);
        right.copy_from_slice(&stored_right[..half]);
        (left, right)
    } else {
        let mut left = vec![zero(); total];
        let mut right = vec![zero(); total];
        columns.fill_left(0, &mut left);
        columns.fill_right(0, &mut right);
        (left, right)
    };
    let mut claimed_sum = if level > 0 {
        round_polys[0][0] + round_polys[0][1]
    } else {
        zero()
    };
    let started = std::time::Instant::now();
    for round in level..n {
        let pairs = left.len() / 2;
        let ranges = worker_ranges(pairs);
        let mut partials: Vec<[F; 3]> = Vec::with_capacity(ranges.len());
        std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(ranges.len());
            for &(start, end) in &ranges {
                let left = &left;
                let right = &right;
                handles.push(scope.spawn(move || {
                    let mut polynomial = [zero(); 3];
                    for index in start..end {
                        add_poly(&mut polynomial, &product2_pair(left, right, index));
                    }
                    polynomial
                }));
            }
            for handle in handles {
                partials.push(handle.join().expect("stream worker"));
            }
        });
        let mut coefficients = [zero(); 3];
        for polynomial in partials {
            add_poly(&mut coefficients, &polynomial);
        }
        let evaluated = eval_univariate3(&coefficients);
        if round == 0 {
            claimed_sum = evaluated[0] + evaluated[1];
        }
        let r = challenge(round, &evaluated);
        challenges.push(r);
        round_polys.push(evaluated.to_vec());
        let current = left.len();
        fold_scalars(&mut left, current, r);
        fold_scalars(&mut right, current, r);
        left.truncate(pairs);
        right.truncate(pairs);
    }
    if profile() {
        eprintln!(
            "stream inner fold ({} rounds): {:?}",
            n - level,
            started.elapsed()
        );
    }
    if n == 0 {
        claimed_sum = left[0] * right[0];
    }
    Ok(InnerSumcheck {
        proof: SumcheckProof {
            claimed_sum,
            round_polys,
        },
        challenges,
        left: left[0],
        right: right[0],
    })
}
