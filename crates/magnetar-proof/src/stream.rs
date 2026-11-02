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

/// All-ones mask when `bit`, zero otherwise: turns a set-bit test into a
/// branch-free masked XOR.
#[inline]
fn bit_mask(bit: bool) -> u128 {
    0u128.wrapping_sub(bit as u128)
}

pub fn profile() -> bool {
    std::env::var_os("MAGNETAR_PROFILE_STREAM").is_some()
}

fn workers() -> usize {
    if let Some(count) = std::env::var("MAGNETAR_STREAM_WORKERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
    {
        return count.max(1);
    }
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

/// A raw pointer that may be shared across workers that write disjoint ranges.
struct SharedPtr<T>(*mut T);

// SAFETY: every user of this wrapper splits the underlying range into disjoint
// chunks (one shared atomic counter hands out each chunk exactly once), so no
// two workers ever touch the same element.
unsafe impl<T> Sync for SharedPtr<T> {}
unsafe impl<T> Send for SharedPtr<T> {}

impl<T> SharedPtr<T> {
    /// Mutable view of `len` elements starting at `index`.
    ///
    /// # Safety
    /// The caller must own the range exclusively: no other thread may read or
    /// write it for the duration of the returned borrow.
    #[allow(clippy::mut_from_ref)]
    unsafe fn slice_mut(&self, index: usize, len: usize) -> &mut [T] {
        // SAFETY: the caller guarantees exclusive ownership of `index..index+len`.
        unsafe { std::slice::from_raw_parts_mut(self.0.add(index), len) }
    }
}

/// Work-stealing parallel loop over `count` items.
///
/// A fixed split of the work between workers leaves the efficiency cores
/// straggling: this host has 6 performance and 6 efficiency cores, so an even
/// split makes a round 1.3x longer than the work / total-throughput bound. Each
/// worker here claims the next chunk from a shared counter, and the returned
/// partials are folded by the caller. Field addition is XOR, so the fold is
/// independent of which worker got which chunk: proof bytes do not change.
fn parallel_chunks<T, M, B>(count: usize, make: M, body: B) -> Vec<T>
where
    T: Send,
    M: Fn() -> T + Sync,
    B: Fn(&mut T, usize, usize) + Sync,
{
    if count == 0 {
        return Vec::new();
    }
    let workers = workers().min(count).max(1);
    let chunk = (count / (workers * 8)).max(1);
    let chunks = count.div_ceil(chunk);
    let next = std::sync::atomic::AtomicUsize::new(0);
    let mut partials = Vec::with_capacity(workers);
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let make = &make;
            let body = &body;
            let next = &next;
            handles.push(scope.spawn(move || {
                let mut accumulator = make();
                loop {
                    let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if index >= chunks {
                        break;
                    }
                    let start = index * chunk;
                    let end = (start + chunk).min(count);
                    body(&mut accumulator, start, end);
                }
                accumulator
            }));
        }
        for handle in handles {
            partials.push(handle.join().expect("stream worker"));
        }
    });
    partials
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

/// Recompute rounds for the inner (column space) sum-check.
///
/// The inner level arrays are two `2^budget`-entry field vectors, so one extra
/// bit of budget costs `2^(budget+1) * 32` bytes (`MAGNETAR_INNER_BUDGET_LOG`,
/// default 22) and saves one full scan of the witness columns.
pub fn auto_level_inner(bits: usize) -> usize {
    if std::env::var_os("MAGNETAR_STREAM_EAGER").is_some() {
        return 0;
    }
    // Two extra bits vs the outer default: a 2^16 run measured -25% of the
    // inner stage (-7 s of prove) for +0.5 GiB of level arrays, which is well
    // inside the memory envelope. `MAGNETAR_INNER_BUDGET_LOG` overrides.
    let budget = std::env::var("MAGNETAR_INNER_BUDGET_LOG")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(24);
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
    /// Number of rows that can be non-zero: the block-diagonal instance rows
    /// followed by the (unpadded) extra rows. Rows past this point are the
    /// zero padding that rounds the matrix up to a power of two; every outer
    /// sum-check pass over them is pure overhead (they are half the rows at
    /// RV64 `2^16`: `2^29` instance rows plus ~`2^22` extras pad to `2^30`).
    live_rows: usize,
    /// `base_cols / 64` when a base block is a whole number of words, which
    /// makes the bit lookup `words[instance * words_per_block + column / 64]`.
    /// Zero when the block is not word aligned (small unit-test shapes), which
    /// selects the generic bit lookup.
    words_per_base_block: usize,
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
            let live = (instance_rows + extra_len).min(rows);
            eprintln!(
                "lockstep rows: base_rows={base_rows} base_cols={base_cols} entries={total} per_row={:.2} instance_rows={instance_rows} extra_rows={extra_len} live_rows={live} rows={rows} padding={:.1}%",
                total as f64 / base_rows as f64,
                (rows - live) as f64 * 100.0 / rows as f64
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
            live_rows: if std::env::var_os("MAGNETAR_LIVE_FULL").is_some() {
                rows
            } else {
                (instance_rows + extra_len).min(rows)
            },
            words_per_base_block: if base_cols % 64 == 0 { base_cols / 64 } else { 0 },
            base_offsets: counts,
            base_entries: sorted,
        })
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    /// First row index that is zero padding: every row at or past it has all
    /// six values equal to zero, so sum-check passes can stop there.
    pub fn live_rows(&self) -> usize {
        self.live_rows
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

    /// Accumulate one block-diagonal row with a branch-free set-bit test.
    ///
    /// The witness bits of a base block are word aligned for every RV64 shape,
    /// so the set-bit test is one word load plus a masked, arithmetic-shift
    /// free 0/all-ones mask. Folding the mask into the add removes the ~50 %
    /// unpredictable branch the previous `if bit { add }` form had, which is
    /// the single most expensive instruction in the scan.
    #[inline]
    fn accumulate_row_words(&self, row: usize, weight: F, out: &mut [F; 6]) {
        let instance = row >> self.log_base_rows;
        let local = row & (self.base_rows - 1);
        let words = self.bits.words();
        let base = instance * self.words_per_base_block;
        let first = self.base_offsets[local] as usize;
        let last = self.base_offsets[local + 1] as usize;
        for &(slot, column, coefficient) in &self.base_entries[first..last] {
            let word = words[base + ((column as usize) >> 6)];
            let mask = 0u128.wrapping_sub(((word >> (column & 63)) & 1) as u128);
            let term = if coefficient == one() {
                weight
            } else {
                weight * coefficient
            };
            let entry = &mut out[slot as usize];
            *entry = F::from_bits(entry.value() ^ (term.value() & mask));
        }
    }

    /// Generic variant of `accumulate_row_words` for shapes whose base block is
    /// not word aligned.
    #[inline]
    fn accumulate_row_general(&self, row: usize, weight: F, out: &mut [F; 6]) {
        if row < self.instance_rows {
            let instance = row >> self.log_base_rows;
            let local = row & (self.base_rows - 1);
            let offset = instance << self.log_base_cols;
            let bits = self.bits;
            let first = self.base_offsets[local] as usize;
            let last = self.base_offsets[local + 1] as usize;
            for &(slot, column, coefficient) in &self.base_entries[first..last] {
                let mask = 0u128.wrapping_sub(bits.get(offset + column as usize) as u128);
                let term = if coefficient == one() {
                    weight
                } else {
                    weight * coefficient
                };
                let entry = &mut out[slot as usize];
                *entry = F::from_bits(entry.value() ^ (term.value() & mask));
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

    /// Fold the weights of one length-`block` run of rows into the even/odd
    /// accumulators of a single sum-check block: `even` receives rows
    /// `first..first + half` with `weights[t]`, `odd` the next `half`.
    ///
    /// The whole block sits inside one instance and inside one base block for
    /// every shape the streaming prover runs at scale (block <= base rows and
    /// power-of-two aligned), so the fast path avoids the per-row instance and
    /// extra-row dispatch entirely.
    #[inline]
    pub fn accumulate_block(
        &self,
        first: usize,
        block: usize,
        weights: &[F],
        even: &mut [F; 6],
        odd: &mut [F; 6],
    ) {
        let half = weights.len();
        debug_assert_eq!(half * 2, block);
        let local0 = first & (self.base_rows - 1);
        let fast = self.words_per_base_block != 0
            && first + block <= self.instance_rows
            && local0 + block <= self.base_rows;
        if fast {
            for (slot, weight) in weights.iter().enumerate() {
                self.accumulate_row_words(first + slot, *weight, even);
                self.accumulate_row_words(first + half + slot, *weight, odd);
            }
        } else {
            for (slot, weight) in weights.iter().enumerate() {
                self.accumulate_row_general(first + slot, *weight, even);
                self.accumulate_row_general(first + half + slot, *weight, odd);
            }
        }
    }

    /// Accumulate `weight * row_values(row)` into `out` without materialising the
    /// six values: every set CSR entry adds `weight * coefficient` to its slot.
    /// Distributivity makes this bit-identical to `accumulate_weighted` over
    /// `row_values` (addition is XOR in the binary tower field).
    #[inline]
    pub fn accumulate_row_values(&self, row: usize, weight: F, out: &mut [F; 6]) {
        self.accumulate_row_general(row, weight, out);
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
    //
    // Only the live rows (block-diagonal instance rows plus the unpadded extra
    // rows) can be non-zero: everything past them is the power-of-two padding
    // of `SharedBlockMatrix`. At RV64 `2^16` that padding is half of `rows`
    // (`2^29 + ~2^22` pad to `2^30`), and a fully padded block contributes
    // `product6_pair(0, 0, ..) = 0` for any equality weight, so every pass can
    // stop at the last live block. Byte-identical by construction.
    let live_rows = rows.live_rows();
    let mut stored: Vec<[F; 6]> = Vec::new();
    let mut eq_factor = one();
    for round in 0..level {
        let block = 1usize << (round + 1);
        let full_blocks = total >> (round + 1);
        let blocks = live_rows.div_ceil(block);
        let eq_table = EqTable::new(&tau[round + 1..]);
        if eq_table.len() != full_blocks {
            return Err(SpartanError::Dimensions);
        }
        let f0 = one() - tau[round];
        let f1 = tau[round];
        let scale = eq_factor;
        let store = round + 1 == level;
        if store {
            stored = vec![[zero(); 6]; blocks * 2];
        }
        let weights = fold_weights(&challenges[..]);
        let weights = &weights;
        let eq_table = &eq_table;
        let stored_ptr = SharedPtr(stored.as_mut_ptr());
        let partials = parallel_chunks(
            blocks,
            || [zero(); 4],
            |polynomial, start, end| {
                for block_index in start..end {
                    let first = block_index << (round + 1);
                    let mut even = [zero(); 6];
                    let mut odd = [zero(); 6];
                    rows.accumulate_block(first, block, weights, &mut even, &mut odd);
                    let high = eq_table.at(block_index) * scale;
                    add_poly(
                        polynomial,
                        &product6_pair(&even, &odd, high * f0, high * f1, alpha),
                    );
                    if store {
                        // SAFETY: the shared counter hands every block index to
                        // exactly one worker, so the two slots written per block
                        // are disjoint and inside `stored` (`blocks * 2` long).
                        unsafe {
                            let head = stored_ptr.slice_mut(block_index * 2, 2);
                            head[0] = even;
                            head[1] = odd;
                        }
                    }
                }
            },
        );
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
            "stream outer recompute ({level} rounds, live {live_rows} / {total} rows): {:?} cpu={:.2}s",
            started.elapsed(),
            crate::process_cpu_seconds()
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
        let mut arrays = vec![[zero(); 6]; live_rows];
        let ranges = worker_ranges(live_rows);
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
    // The live prefix is more than half of `rows`, so ceil-halving it
    // `remaining` times lands on exactly one entry: the trailing entries of the
    // conceptual full array are zero, and a zero pair contributes a zero round
    // polynomial, so the folds below can carry the short (live) length and
    // treat an out-of-range odd entry as zero.
    if remaining == 0 {
        if arrays.len() != 1 {
            return Err(SpartanError::Dimensions);
        }
    } else if arrays.len() <= 1usize << (remaining - 1) || arrays.len() > 1usize << remaining {
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
        let length = arrays.len();
        let pairs = length.div_ceil(2);
        let eq_pairs = eq_values.len() / 2;
        let partials = parallel_chunks(
            pairs,
            || [zero(); 4],
            |polynomial, start, end| {
                for index in start..end {
                    let odd = index * 2 + 1;
                    // Past the live prefix every row value is zero, so the
                    // out-of-range odd value is zero. The equality value is
                    // *not* zero there and is kept at full length: the
                    // boundary element is folded with it in later rounds.
                    let high = if odd < length { arrays[odd] } else { [zero(); 6] };
                    add_poly(
                        polynomial,
                        &product6_pair(
                            &arrays[index * 2],
                            &high,
                            eq_values[index * 2],
                            eq_values[odd],
                            alpha,
                        ),
                    );
                }
            },
        );
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
            let odd = index * 2 + 1;
            let high = if odd < length { arrays[odd] } else { [zero(); 6] };
            let low = arrays[index * 2];
            for slot in 0..6 {
                arrays[index][slot] = low[slot] + r * (high[slot] - low[slot]);
            }
        }
        for index in 0..eq_pairs {
            let low = eq_values[index * 2];
            let high = eq_values[index * 2 + 1];
            eq_values[index] = low + r * (high - low);
        }
        arrays.truncate(pairs);
        eq_values.truncate(eq_pairs);
    }
    if profile() {
        eprintln!(
            "stream outer fold ({remaining} rounds): {:?} cpu={:.2}s",
            started.elapsed(),
            crate::process_cpu_seconds()
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

    /// Even/odd weighted sums of one inner sum-check block, without
    /// materialising the two column vectors.
    ///
    /// Returns `[even_left, odd_left, even_right, odd_right]`. The block is
    /// `weights.len() * 2` columns, even side first. A block at RV64 scale sits
    /// inside one instance block, so the left multiplicand factors as
    /// `instance_weight(instance) * combined(local)`; the weight is hoisted out
    /// of the per-column loop (one multiply per block instead of two per
    /// column) and the right side uses a mask instead of a branch. Both are
    /// exact by distributivity: field addition is XOR.
    pub fn block_values(&self, first: usize, block: usize, weights: &[F]) -> [F; 4] {
        let half = weights.len();
        debug_assert_eq!(half * 2, block);
        let mask = self.base_cols - 1;
        let local0 = first & mask;
        let fast = block <= self.base_cols && local0 + block <= self.base_cols;
        if !fast {
            let mut left = vec![zero(); block];
            let mut right = vec![zero(); block];
            self.fill_left(first, &mut left);
            self.fill_right(first, &mut right);
            let (mut even_left, mut odd_left) = (zero(), zero());
            let (mut even_right, mut odd_right) = (zero(), zero());
            for (slot, weight) in weights.iter().enumerate() {
                accumulate_scalar(&mut even_left, *weight, left[slot]);
                accumulate_scalar(&mut odd_left, *weight, left[half + slot]);
                accumulate_scalar(&mut even_right, *weight, right[slot]);
                accumulate_scalar(&mut odd_right, *weight, right[half + slot]);
            }
            return [even_left, odd_left, even_right, odd_right];
        }
        let instance = first >> self.log_base_cols;
        let (mut even_left, mut odd_left) = (zero(), zero());
        let (mut even_right, mut odd_right) = (zero(), zero());
        let base = &self.combined[local0..local0 + block];
        for (slot, weight) in weights.iter().enumerate() {
            let weight = *weight;
            even_left = even_left + weight * base[slot];
            odd_left = odd_left + weight * base[half + slot];
            let even_mask = bit_mask(self.bits.get(first + slot));
            let odd_mask = bit_mask(self.bits.get(first + half + slot));
            even_right = F::from_bits(even_right.value() ^ (weight.value() & even_mask));
            odd_right = F::from_bits(odd_right.value() ^ (weight.value() & odd_mask));
        }
        let instance_weight = self.instance_weight[instance];
        let mut even_left = instance_weight * even_left;
        let mut odd_left = instance_weight * odd_left;
        if self.claim.is_some() {
            let end_col = local0 + block;
            let low = self
                .claim_columns
                .partition_point(|(column, _)| *column < local0);
            let high = self
                .claim_columns
                .partition_point(|(column, _)| *column < end_col);
            let (mut even_claim, mut odd_claim) = (zero(), zero());
            for &(column, coefficient) in &self.claim_columns[low..high] {
                let position = column - local0;
                if position < half {
                    even_claim = even_claim + weights[position] * coefficient;
                } else {
                    odd_claim = odd_claim + weights[position - half] * coefficient;
                }
            }
            let claim_instance_weight = self.claim_instance_weight[instance];
            even_left = even_left + claim_instance_weight * even_claim;
            odd_left = odd_left + claim_instance_weight * odd_claim;
        }
        if !self.extras.is_empty() {
            if let Some((extras_low, extras_high)) = self.extras_local {
                // Extra rows written by instance `i` land in instance `i`'s
                // block (parts A/B) or in the next block (part C, whose column
                // is `(i + 1) * base_cols + pc`), so both the previous and the
                // current instance can touch this window. This mirrors
                // `fill_left`'s `touches` predicate exactly.
                let candidates: &[usize] = if instance == 0 {
                    &[0]
                } else {
                    &[instance - 1, instance]
                };
                for &candidate in candidates {
                    let mut touched = false;
                    for block_start in [
                        candidate * self.base_cols,
                        (candidate + 1) * self.base_cols,
                    ] {
                        let window_low = first.saturating_sub(block_start);
                        let window_high = (first + block)
                            .saturating_sub(block_start)
                            .min(self.base_cols);
                        if window_high > window_low
                            && window_high > extras_low
                            && window_low <= extras_high
                        {
                            touched = true;
                            break;
                        }
                    }
                    if !touched {
                        continue;
                    }
                    for (lazy, scale) in &self.extras {
                        lazy.for_each_instance_entry(candidate, |offset, column, coefficient| {
                            if column >= first && column < first + block {
                                let position = column - first;
                                let value = self.row_eq(self.instance_rows + offset) * *scale
                                    * coefficient;
                                if position < half {
                                    even_left = even_left + weights[position] * value;
                                } else {
                                    odd_left = odd_left + weights[position - half] * value;
                                }
                            }
                        });
                    }
                }
            }
        }
        [even_left, odd_left, even_right, odd_right]
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
    // Measured on this host (RV64 `2^14`, interleaved CPU-time A/B in one
    // binary): the fused `block_values` loop is ~35% slower than the
    // materialise-and-accumulate loop it replaced -- at the small block sizes
    // of the early rounds the per-block hoisting/claim/extras overhead
    // dominates the one multiply per column it saves. The fused path stays
    // behind an opt-in switch for a host with different cache behaviour.
    let fused = std::env::var_os("MAGNETAR_P2_FUSED").is_some();
    // Default: fill one large column chunk per call. `fill_left` carries
    // per-block bookkeeping (instance bounds, the claim-window binary search,
    // the extras touch test) that costs more than the two columns of the first
    // round; filling 512 columns at once amortises it ~256x while keeping the
    // exact per-column arithmetic order (so proof bytes do not change).
    // `MAGNETAR_P2_BLOCKWISE=1` restores the per-block fill for A/B.
    let blockwise = fused || std::env::var_os("MAGNETAR_P2_BLOCKWISE").is_some();
    for round in 0..level {
        let block = 1usize << (round + 1);
        let blocks = total >> (round + 1);
        let store = round + 1 == level;
        if store {
            stored_left = vec![zero(); blocks * 2];
            stored_right = vec![zero(); blocks * 2];
        }
        let weights = fold_weights(&challenges[..]);
        let weights = &weights;
        let left_ptr = SharedPtr(stored_left.as_mut_ptr());
        let right_ptr = SharedPtr(stored_right.as_mut_ptr());
        let mut coefficients = [zero(); 3];
        if blockwise {
            let partials = parallel_chunks(
                blocks,
                || [zero(); 3],
                |polynomial, start, end| {
                    let mut legacy_left = vec![zero(); block];
                    let mut legacy_right = vec![zero(); block];
                    for block_index in start..end {
                        let first = block_index << (round + 1);
                        let (pair_left, pair_right) = if !fused {
                            columns.fill_left(first, &mut legacy_left);
                            columns.fill_right(first, &mut legacy_right);
                            let (mut even_left, mut odd_left) = (zero(), zero());
                            let (mut even_right, mut odd_right) = (zero(), zero());
                            for slot in 0..block {
                                let weight = weights[slot & (weights.len() - 1)];
                                if slot & weights.len() == 0 {
                                    accumulate_scalar(&mut even_left, weight, legacy_left[slot]);
                                    accumulate_scalar(&mut even_right, weight, legacy_right[slot]);
                                } else {
                                    accumulate_scalar(&mut odd_left, weight, legacy_left[slot]);
                                    accumulate_scalar(&mut odd_right, weight, legacy_right[slot]);
                                }
                            }
                            ([even_left, odd_left], [even_right, odd_right])
                        } else {
                            let values = columns.block_values(first, block, weights);
                            ([values[0], values[1]], [values[2], values[3]])
                        };
                        add_poly(polynomial, &product2_pair(&pair_left, &pair_right, 0));
                        if store {
                            // SAFETY: every block index is claimed by exactly one
                            // worker, so the two slots written per block are
                            // disjoint and inside the `blocks * 2` arrays.
                            unsafe {
                                left_ptr
                                    .slice_mut(block_index * 2, 2)
                                    .copy_from_slice(&pair_left);
                                right_ptr
                                    .slice_mut(block_index * 2, 2)
                                    .copy_from_slice(&pair_right);
                            }
                        }
                    }
                },
            );
            for polynomial in partials {
                add_poly(&mut coefficients, &polynomial);
            }
        } else {
            let chunk_cols = block.max(512).min(total);
            let blocks_per_chunk = chunk_cols >> (round + 1);
            let chunks = blocks.div_ceil(blocks_per_chunk);
            let partials = parallel_chunks(
                chunks,
                || {
                    (
                        [zero(); 3],
                        vec![zero(); chunk_cols],
                        vec![zero(); chunk_cols],
                    )
                },
                |accumulator, start, end| {
                    let (polynomial, left_buf, right_buf) = accumulator;
                    for chunk in start..end {
                        let first = chunk * chunk_cols;
                        let cols = (total - first).min(chunk_cols);
                        columns.fill_left(first, &mut left_buf[..cols]);
                        columns.fill_right(first, &mut right_buf[..cols]);
                        let first_block = chunk * blocks_per_chunk;
                        let last_block = (first_block + blocks_per_chunk).min(blocks);
                        for block_index in first_block..last_block {
                            let base = block_index * block - first;
                            let (mut even_left, mut odd_left) = (zero(), zero());
                            let (mut even_right, mut odd_right) = (zero(), zero());
                            for slot in 0..block {
                                let weight = weights[slot & (weights.len() - 1)];
                                if slot & weights.len() == 0 {
                                    accumulate_scalar(&mut even_left, weight, left_buf[base + slot]);
                                    accumulate_scalar(
                                        &mut even_right,
                                        weight,
                                        right_buf[base + slot],
                                    );
                                } else {
                                    accumulate_scalar(&mut odd_left, weight, left_buf[base + slot]);
                                    accumulate_scalar(&mut odd_right, weight, right_buf[base + slot]);
                                }
                            }
                            let pair_left = [even_left, odd_left];
                            let pair_right = [even_right, odd_right];
                            add_poly(polynomial, &product2_pair(&pair_left, &pair_right, 0));
                            if store {
                                // SAFETY: block indices are claimed by exactly one
                                // worker, so the slots written per block are
                                // disjoint and inside the `blocks * 2` arrays.
                                unsafe {
                                    left_ptr
                                        .slice_mut(block_index * 2, 2)
                                        .copy_from_slice(&pair_left);
                                    right_ptr
                                        .slice_mut(block_index * 2, 2)
                                        .copy_from_slice(&pair_right);
                                }
                            }
                        }
                    }
                },
            );
            for (polynomial, _, _) in partials {
                add_poly(&mut coefficients, &polynomial);
            }
        }
        let evaluated = eval_univariate3(&coefficients);
        let r = challenge(round, &evaluated);
        challenges.push(r);
        round_polys.push(evaluated.to_vec());
    }
    if profile() {
        eprintln!(
            "stream inner recompute ({level} rounds, {} columns): {:?} cpu={:.2}s",
            total,
            started.elapsed(),
            crate::process_cpu_seconds()
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
        let partials = parallel_chunks(
            pairs,
            || [zero(); 3],
            |polynomial, start, end| {
                for index in start..end {
                    add_poly(polynomial, &product2_pair(&left, &right, index));
                }
            },
        );
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
            "stream inner fold ({} rounds): {:?} cpu={:.2}s",
            n - level,
            started.elapsed(),
            crate::process_cpu_seconds()
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
