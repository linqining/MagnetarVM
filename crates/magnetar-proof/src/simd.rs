//! Shared-matrix representation for SIMD R1CS instances.
//!
//! A block-diagonal batch of q copies of the same row relation is represented
//! by one base sparse matrix plus an instance count. Products, row
//! combinations, and MLE evaluations are computed blockwise without
//! materializing q copies of the matrix.

use magnetar_constraint::{ConstraintSystem, F2_128};

use crate::spartan::{bits, eq_vector_tensor, MatrixPart, SparseMatrix, SpartanMatrix};
use crate::{eq, SpartanError};

#[derive(Clone, Debug)]
pub enum LazyExtraRows {
    /// PC-chain + statement rows for one part of the gated matrices.
    ///
    /// `part` is 0 for A, 1 for B and 2 for C. A/B rows always have coefficient
    /// one; C has a zero coefficient for statement rows whose public PC bit is
    /// zero.
    Gated {
        part: u8,
        width: usize,
        cycles: usize,
        base_cols: usize,
        pc: Vec<usize>,
        next_pc: Vec<usize>,
        one: usize,
        statement: Option<(u64, u64)>,
    },
}

/// `Σ_{i<2^k} eq(r, i)·eq(c, i)` in O(k).
///
/// Summing the product over the hypercube factorises per bit:
/// `Π_j ((1+r_j)(1+c_j) + r_j c_j) = Π_j (1 + r_j + c_j)`.
fn eq_dot_full(r: &[F2_128], c: &[F2_128]) -> F2_128 {
    let one = F2_128::from(1u64);
    let mut acc = one;
    for (a, b) in r.iter().zip(c) {
        acc = acc * (one + *a + *b);
    }
    acc
}

/// `Σ_{i<2^k} eq(r, i)·eq(c, i+1)` in O(k).
///
/// Split `i = 2j + b`: the `b = 0` half contributes
/// `(1+r_0)c_0 · Σ_j eq(r_hi,j)eq(c_hi,j)` and the `b = 1` half contributes
/// `r_0(1+c_0) · Σ_j eq(r_hi,j)eq(c_hi,j+1)`, so the shifted sum recurses on
/// half the bits with a closed-form unshifted term.
fn eq_dot_shifted_full(r: &[F2_128], c: &[F2_128]) -> F2_128 {
    let k = r.len().min(c.len());
    if k == 0 {
        return F2_128::from(0u64);
    }
    // suffix[j] = Π_{t>=j} (1 + r_t c_t) for the unshifted term of each level.
    let mut suffix = vec![F2_128::from(1u64); k + 1];
    for j in (0..k).rev() {
        suffix[j] = suffix[j + 1] * (F2_128::from(1u64) + r[j] + c[j]);
    }
    let one = F2_128::from(1u64);
    // T_j = S on the suffix starting at bit j; T_k = 0 (no bits left).
    // T_j = (1+r_j)c_j · U_{j+1} + r_j(1+c_j) · T_{j+1}, with
    // U_{j+1} = Π_{t>j}(1+r_t+c_t) = suffix[j+1].
    let mut shifted = F2_128::from(0u64);
    for j in (0..k).rev() {
        shifted = (one + r[j]) * c[j] * suffix[j + 1]
            + r[j] * (one + c[j]) * shifted;
    }
    shifted
}

impl LazyExtraRows {
    /// Evaluate the extra-row sum using precomputed row weights and the
    /// factorized column-equality vectors.
    pub fn eval_sum(
        &self,
        row_weights: &[F2_128],
        col_local_eq: &[F2_128],
        col_instance_eq: &[F2_128],
        base_cols: usize,
    ) -> F2_128 {
        let LazyExtraRows::Gated {
            part,
            width,
            cycles,
            pc,
            next_pc,
            one,
            statement,
            ..
        } = self;
        let mut sum = F2_128::from(0u64);
        let chain_instances = cycles.saturating_sub(1);
        match part {
            1 => {
                let local_weight = col_local_eq[*one];
                for instance in 0..chain_instances {
                    let mut row_weight = F2_128::from(0u64);
                    for bit in 0..*width {
                        row_weight = row_weight + row_weights[instance * width + bit];
                    }
                    sum = sum + local_weight * col_instance_eq[instance] * row_weight;
                }
            }
            _ => {
                let locals = if *part == 0 { next_pc } else { pc };
                for bit in 0..*width {
                    let local_weight = col_local_eq[locals[bit]];
                    let mut dot = F2_128::from(0u64);
                    for instance in 0..chain_instances {
                        let weight = row_weights[instance * width + bit];
                        let column_weight = if *part == 0 {
                            col_instance_eq[instance]
                        } else {
                            col_instance_eq[instance + 1]
                        };
                        dot = dot + weight * column_weight;
                    }
                    sum = sum + local_weight * dot;
                }
            }
        }
        if let Some((initial, final_pc)) = statement {
            let mut offset = chain_instances * width;
            for instance in [0usize, cycles.saturating_sub(1)] {
                let pc_value = if instance == 0 { *initial } else { *final_pc };
                for bit in 0..*width {
                    let local = match *part {
                        0 => {
                            if instance == 0 {
                                pc[bit]
                            } else {
                                next_pc[bit]
                            }
                        }
                        1 => *one,
                        _ => *one,
                    };
                    let coefficient = if *part == 2 && (pc_value >> bit) & 1 == 0 {
                        F2_128::from(0u64)
                    } else {
                        F2_128::from(1u64)
                    };
                    let _ = base_cols;
                    sum = sum
                        + coefficient
                            * row_weights[offset]
                            * col_local_eq[local]
                            * col_instance_eq[instance];
                    offset += 1;
                }
            }
        }
        sum
    }

    /// Factorized chain evaluation: for a power-of-two width the PC-chain row
    /// index is `(instance << log_width) | bit`, so the row equality factors into
    /// bit and instance parts. The chain contribution then collapses from
    /// O(cycles * width) to O(cycles + width).
    #[allow(clippy::too_many_arguments)]
    pub fn eval_sum_factorized(
        &self,
        row_point: &[F2_128],
        col_point: &[F2_128],
        local_col_bits: usize,
        extra_base: usize,
        extra_bits: usize,
        high_eq: F2_128,
        col_local_eq: &[F2_128],
        col_instance_point: &[F2_128],
        base_cols: usize,
    ) -> Option<F2_128> {
        let LazyExtraRows::Gated {
            part,
            width,
            cycles,
            pc,
            next_pc,
            one,
            statement,
            ..
        } = self;
        if !width.is_power_of_two() || !extra_base.is_multiple_of(1usize << extra_bits) {
            return None;
        }
        let log_width = width.trailing_zeros() as usize;
        if log_width > extra_bits {
            return None;
        }
        let chain_instances = cycles.saturating_sub(1);
        if chain_instances > (1usize << (extra_bits - log_width)) {
            return None;
        }
        let bit_eq = eq_vector_tensor(&row_point[..log_width]);
        let high = high_eq;
        let mut sum = F2_128::from(0u64);
        // The instance dot is the O(cycles) term. Both factors are equality
        // tensors over the instance bits, so the sum has a closed form in
        // O(log) (see `eq_dot_full` / `eq_dot_shifted_full`). The row side has
        // one extra bit (the extra-row count is `(cycles+1)*width`), which is
        // zero for every instance index, so it factors out as `1 + r_top`.
        let instances_bits = col_instance_point.len();
        let instance_bits = extra_bits - log_width;
        let closed = if instance_bits == instances_bits + 1 {
            let r = &row_point[log_width..extra_bits];
            let c = &col_point[local_col_bits..];
            let one = F2_128::from(1u64);
            let top = one + r[instance_bits - 1];
            let r_lo = &r[..instance_bits - 1];
            Some(match part {
                1 | 0 => {
                    // The loop covers instances `0..cycles-1`, i.e. all but the
                    // last index of the 2^instances_bits hypercube.
                    let full = eq_dot_full(r_lo, c);
                    let tail = r_lo.iter().fold(one, |acc, value| acc * *value)
                        * c.iter().fold(one, |acc, value| acc * *value);
                    top * (full + tail)
                }
                _ => top * eq_dot_shifted_full(r_lo, c),
            })
        } else {
            None
        };
        let instance_dot = match closed {
            Some(value) => {
                if std::env::var_os("MAGNETAR_EVAL_CHECK").is_some() {
                    let instance_eq = eq_vector_tensor(&row_point[log_width..extra_bits]);
                    let col_instance_eq = eq_vector_tensor(col_instance_point);
                    let mut dot = F2_128::from(0u64);
                    for instance in 0..chain_instances {
                        let column_weight = if *part == 1 || *part == 0 {
                            col_instance_eq[instance]
                        } else {
                            col_instance_eq[instance + 1]
                        };
                        dot = dot + instance_eq[instance] * column_weight;
                    }
                    if dot != value {
                        eprintln!(
                            "eval closed mismatch: part={} instance_bits={} instances_bits={} chain={} cycles={} width={} closed={:?} loop={:?}",
                            part, instance_bits, instances_bits, chain_instances, cycles, width, value, dot
                        );
                    }
                }
                value
            }
            None => {
                let instance_eq = eq_vector_tensor(&row_point[log_width..extra_bits]);
                let col_instance_eq = eq_vector_tensor(col_instance_point);
                let mut dot = F2_128::from(0u64);
                for instance in 0..chain_instances {
                    let column_weight = if *part == 1 || *part == 0 {
                        col_instance_eq[instance]
                    } else {
                        col_instance_eq[instance + 1]
                    };
                    dot = dot + instance_eq[instance] * column_weight;
                }
                dot
            }
        };
        match part {
            1 => {
                let bit_sum = bit_eq.iter().copied().fold(F2_128::from(0u64), |acc, value| acc + value);
                sum = sum + instance_dot * bit_sum * col_local_eq[*one] * high;
            }
            _ => {
                let locals = if *part == 0 { next_pc } else { pc };
                let mut bit_sum = F2_128::from(0u64);
                for bit in 0..*width {
                    bit_sum = bit_sum + bit_eq[bit] * col_local_eq[locals[bit]];
                }
                sum = sum + instance_dot * bit_sum * high;
            }
        }
        if let Some((initial, final_pc)) = statement {
            let col_instance_eq = eq_vector_tensor(col_instance_point);
            let mut offset = chain_instances * width;
            for instance in [0usize, cycles.saturating_sub(1)] {
                let pc_value = if instance == 0 { *initial } else { *final_pc };
                for bit in 0..*width {
                    let local = match *part {
                        0 => {
                            if instance == 0 {
                                pc[bit]
                            } else {
                                next_pc[bit]
                            }
                        }
                        1 => *one,
                        _ => *one,
                    };
                    let coefficient = if *part == 2 && (pc_value >> bit) & 1 == 0 {
                        F2_128::from(0u64)
                    } else {
                        F2_128::from(1u64)
                    };
                    let row_index = extra_base + offset;
                    let row_weight = eq(row_point, &bits(row_index, row_point.len()));
                    let _ = base_cols;
                    sum = sum
                        + coefficient
                            * row_weight
                            * col_local_eq[local]
                            * col_instance_eq[instance];
                    offset += 1;
                }
            }
        }
        Some(sum)
    }

    pub fn len(&self) -> usize {
        match self {
            LazyExtraRows::Gated {
                width,
                cycles,
                statement,
                ..
            } => {
                cycles.saturating_sub(1) * width
                    + if statement.is_some() { 2 * width } else { 0 }
            }
        }
    }

    /// Single entry of the extra row at `offset`, if the row is nonzero.
    ///
    /// Every gated extra row carries at most one column, so streaming callers
    /// can recover the row value without materializing the row list.
    pub fn entry(&self, offset: usize) -> Option<(usize, F2_128)> {
        let LazyExtraRows::Gated {
            part,
            width,
            cycles,
            base_cols,
            pc,
            next_pc,
            one,
            statement,
        } = self;
        let chain = cycles.saturating_sub(1);
        if offset < chain * width {
            let instance = offset / width;
            let bit = offset % width;
            let column = match part {
                0 => instance * base_cols + next_pc[bit],
                1 => instance * base_cols + one,
                _ => (instance + 1) * base_cols + pc[bit],
            };
            return Some((column, F2_128::from(1u64)));
        }
        statement.as_ref()?;
        let rest = offset - chain * width;
        let which = rest / width;
        let bit = rest % width;
        if which > 1 || bit >= *width {
            return None;
        }
        let (initial, final_pc) = statement.as_ref()?;
        let (instance, pc_value) = if which == 0 {
            (0usize, *initial)
        } else {
            (cycles.saturating_sub(1), *final_pc)
        };
        let local = match part {
            0 => {
                if which == 0 {
                    pc[bit]
                } else {
                    next_pc[bit]
                }
            }
            1 => *one,
            _ => *one,
        };
        if *part == 2 && (pc_value >> bit) & 1 == 0 {
            return Some((instance * base_cols + local, F2_128::from(0u64)));
        }
        Some((instance * base_cols + local, F2_128::from(1u64)))
    }

    /// Visit every entry of the extra rows owned by `instance`, in row order.
    /// Local (inside one instance block) column range the lazy rows can touch.
    /// A sum-check block outside this range has no extra-row contribution, so
    /// callers can skip [`Self::for_each_instance_entry`] entirely.
    pub fn local_column_range(&self) -> (usize, usize) {
        let LazyExtraRows::Gated {
            width, pc, next_pc, one, ..
        } = self;
        if *width == 0 {
            return (0, 0);
        }
        let mut low = (*one).min(pc[0]).min(next_pc[0]);
        let mut high = (*one).max(pc[*width - 1]).max(next_pc[*width - 1]);
        if low > high {
            std::mem::swap(&mut low, &mut high);
        }
        (low, high)
    }

    pub fn for_each_instance_entry(
        &self,
        instance: usize,
        mut f: impl FnMut(usize, usize, F2_128),
    ) {
        let LazyExtraRows::Gated {
            part,
            width,
            cycles,
            base_cols,
            pc,
            next_pc,
            one,
            statement,
        } = self;
        let chain = cycles.saturating_sub(1);
        if instance < chain {
            for bit in 0..*width {
                let column = match part {
                    0 => instance * base_cols + next_pc[bit],
                    1 => instance * base_cols + one,
                    _ => (instance + 1) * base_cols + pc[bit],
                };
                f(instance * width + bit, column, F2_128::from(1u64));
            }
        }
        let Some((initial, final_pc)) = statement else {
            return;
        };
        for (which, pc_value) in [(0usize, *initial), (1usize, *final_pc)] {
            let target = if which == 0 {
                0
            } else {
                cycles.saturating_sub(1)
            };
            if target != instance {
                continue;
            }
            for bit in 0..*width {
                let local = match part {
                    0 => {
                        if which == 0 {
                            pc[bit]
                        } else {
                            next_pc[bit]
                        }
                    }
                    1 => *one,
                    _ => *one,
                };
                if *part == 2 && (pc_value >> bit) & 1 == 0 {
                    continue;
                }
                f(chain * width + which * width + bit, instance * base_cols + local, F2_128::from(1u64));
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn for_each(&self, mut f: impl FnMut(usize, usize, F2_128)) {
        let LazyExtraRows::Gated {
            part,
            width,
            cycles,
            base_cols,
            pc,
            next_pc,
            one,
            statement,
        } = self;
        let mut offset = 0usize;
        for instance in 0..cycles.saturating_sub(1) {
            for bit in 0..*width {
                let column = match part {
                    0 => instance * base_cols + next_pc[bit],
                    1 => instance * base_cols + one,
                    _ => (instance + 1) * base_cols + pc[bit],
                };
                f(offset, column, F2_128::from(1u64));
                offset += 1;
            }
        }
        if let Some((initial, final_pc)) = statement {
            for instance in [0usize, cycles.saturating_sub(1)] {
                let pc_value = if instance == 0 { *initial } else { *final_pc };
                for bit in 0..*width {
                    let column = match part {
                        0 => {
                            let variable = if instance == 0 {
                                pc[bit]
                            } else {
                                next_pc[bit]
                            };
                            instance * base_cols + variable
                        }
                        1 => instance * base_cols + one,
                        _ => instance * base_cols + one,
                    };
                    let coefficient = match part {
                        2 if (pc_value >> bit) & 1 == 0 => F2_128::from(0u64),
                        _ => F2_128::from(1u64),
                    };
                    f(offset, column, coefficient);
                    offset += 1;
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct SharedBlockMatrix {
    base: SparseMatrix,
    instances: usize,
    extra: Vec<Vec<(usize, F2_128)>>,
    extra_zero_rows: usize,
    lazy_extra: Option<LazyExtraRows>,
}

impl SpartanMatrix for SharedBlockMatrix {
    fn rows(&self) -> usize {
        SharedBlockMatrix::rows(self)
    }

    fn cols(&self) -> usize {
        SharedBlockMatrix::cols(self)
    }

    fn mul_vec(&self, z: &[F2_128]) -> Result<Vec<F2_128>, SpartanError> {
        SharedBlockMatrix::mul_vec(self, z)
    }

    fn row_combination(&self, row_point: &[F2_128]) -> Result<Vec<F2_128>, SpartanError> {
        SharedBlockMatrix::row_combination(self, row_point)
    }

    fn eval_mle(&self, row_point: &[F2_128], col_point: &[F2_128]) -> Result<F2_128, SpartanError> {
        SharedBlockMatrix::eval_mle(self, row_point, col_point)
    }

    fn eval_mle_with_eq(
        &self,
        row_point: &[F2_128],
        col_point: &[F2_128],
        row_eq: &[F2_128],
        col_eq: &[F2_128],
    ) -> Result<F2_128, SpartanError> {
        SharedBlockMatrix::eval_mle_with_eq(self, row_point, col_point, row_eq, col_eq)
    }

    fn eval_mle_fast(
        &self,
        row_point: &[F2_128],
        col_point: &[F2_128],
    ) -> Result<Option<F2_128>, SpartanError> {
        SharedBlockMatrix::eval_mle_fast(self, row_point, col_point)
    }

    fn block_shape(&self) -> Option<(usize, usize, usize)> {
        Some((self.base.rows.len(), self.base.cols, self.instances))
    }

    fn eval_mle_shared(
        &self,
        row_point: &[F2_128],
        col_point: &[F2_128],
        shared: &crate::spartan::BlockEvalShared,
    ) -> Result<Option<F2_128>, SpartanError> {
        SharedBlockMatrix::eval_mle_fast_inner(self, row_point, col_point, Some(shared))
    }
}

impl SharedBlockMatrix {
    pub fn from_system(
        system: &ConstraintSystem,
        part: MatrixPart,
        instances: usize,
    ) -> Result<Self, SpartanError> {
        if instances == 0 || !instances.is_power_of_two() {
            return Err(SpartanError::Dimensions);
        }
        Ok(Self {
            base: SparseMatrix::from_system(system, part)?,
            instances,
            extra: Vec::new(),
            extra_zero_rows: 0,
            lazy_extra: None,
        })
    }

    pub fn instances(&self) -> usize {
        self.instances
    }

    /// Append sparse rows after the block-diagonal rows. Rows are padded to
    /// the next power of two so the matrix can be evaluated as an MLE.
    ///
    /// The padding is counted, not materialized: `base_rows * instances` is
    /// already a large power of two at RV64 scale, so resizing to the next one
    /// would transiently allocate hundreds of millions of empty rows (6 GiB at
    /// `2^14`, ~100 GiB at `2^16`).
    pub fn with_extra_rows(mut self, mut extra: Vec<Vec<(usize, F2_128)>>) -> Self {
        let base_rows = self.base.rows.len() * self.instances;
        let total = (base_rows + extra.len()).next_power_of_two();
        while extra.last().is_some_and(|row| row.is_empty()) {
            extra.pop();
        }
        self.extra_zero_rows = total - base_rows - extra.len();
        self.extra = extra;
        self
    }

    pub fn with_lazy_extra(mut self, lazy: LazyExtraRows) -> Self {
        self.extra.clear();
        let base_rows = self.base.rows.len() * self.instances;
        self.extra_zero_rows = (base_rows + lazy.len()).next_power_of_two() - base_rows;
        self.lazy_extra = Some(lazy);
        self
    }

    pub fn with_extra_zero_rows(mut self, rows: usize) -> Self {
        let total = (self.base.rows.len() * self.instances + rows).next_power_of_two();
        self.extra = Vec::new();
        self.extra_zero_rows = total - self.base.rows.len() * self.instances;
        self
    }

    pub fn rows(&self) -> usize {
        self.base.rows.len() * self.instances + self.extra.len() + self.extra_zero_rows
    }

    pub fn cols(&self) -> usize {
        self.base.cols * self.instances
    }

    /// Base (shared) sparse matrix of the block-diagonal rows.
    pub fn base_matrix(&self) -> &SparseMatrix {
        &self.base
    }

    pub fn base_row_count(&self) -> usize {
        self.base.rows.len()
    }

    pub fn base_col_count(&self) -> usize {
        self.base.cols
    }

    /// Number of extra rows (before zero padding).
    pub fn extra_row_count(&self) -> usize {
        match &self.lazy_extra {
            Some(lazy) => lazy.len(),
            None => self.extra.len(),
        }
    }

    pub fn lazy_extra_rows(&self) -> Option<&LazyExtraRows> {
        self.lazy_extra.as_ref()
    }

    /// Value of the extra row at `offset` against a bit witness. Offsets past
    /// the extra rows (zero padding) evaluate to zero.
    pub fn extra_row_value(&self, offset: usize, bits: &crate::PackedBits) -> F2_128 {
        if let Some(lazy) = &self.lazy_extra {
            if offset >= lazy.len() {
                return F2_128::from(0u64);
            }
            return match lazy.entry(offset) {
                Some((column, coefficient)) => {
                    if bits.get(column) {
                        coefficient
                    } else {
                        F2_128::from(0u64)
                    }
                }
                None => F2_128::from(0u64),
            };
        }
        match self.extra.get(offset) {
            Some(row) => dot_bits(row, bits),
            None => F2_128::from(0u64),
        }
    }

    pub fn mul_vec(&self, z: &[F2_128]) -> Result<Vec<F2_128>, SpartanError> {
        if z.len() != self.cols() {
            return Err(SpartanError::Dimensions);
        }
        let mut result = Vec::with_capacity(self.rows());
        for instance in 0..self.instances {
            let start = instance * self.base.cols;
            result.extend(self.base.mul_vec(&z[start..start + self.base.cols])?);
        }
        for row in &self.extra {
            result.push(
                row.iter()
                    .fold(F2_128::from(0u64), |sum, (column, coefficient)| {
                        sum + *coefficient * z[*column]
                    }),
            );
        }
        result.resize(self.rows(), F2_128::from(0u64));
        Ok(result)
    }

    pub fn row_combination(&self, row_point: &[F2_128]) -> Result<Vec<F2_128>, SpartanError> {
        let row_bits = self.rows().trailing_zeros() as usize;
        if row_point.len() != row_bits {
            return Err(SpartanError::Dimensions);
        }
        let local_bits = self.base.rows.len().trailing_zeros() as usize;
        let instance_bits = self.instances.trailing_zeros() as usize;
        let block_high = &row_point[local_bits + instance_bits..];
        let instance_point = &row_point[local_bits..local_bits + instance_bits];
        let zero_high = vec![F2_128::from(0u64); block_high.len()];
        let local = self.base.row_combination(&row_point[..local_bits])?;
        let mut result = vec![F2_128::from(0u64); self.cols()];
        for instance in 0..self.instances {
            let weight =
                eq(instance_point, &bits(instance, instance_bits)) * eq(block_high, &zero_high);
            for (column, coefficient) in local.iter().enumerate() {
                result[instance * self.base.cols + column] = *coefficient * weight;
            }
        }
        for (offset, row) in self.extra.iter().enumerate() {
            let row_index = self.base.rows.len() * self.instances + offset;
            let weight = eq(row_point, &bits(row_index, row_bits));
            for (column, coefficient) in row {
                result[*column] = result[*column] + *coefficient * weight;
            }
        }
        Ok(result)
    }

    pub fn eval_mle_fast(
        &self,
        row_point: &[F2_128],
        col_point: &[F2_128],
    ) -> Result<Option<F2_128>, SpartanError> {
        self.eval_mle_fast_inner(row_point, col_point, None)
    }

    /// Block-aware evaluation that can reuse the instance equality vectors and
    /// `Σ eq·eq` term shared by every block matrix at the same point.
    pub fn eval_mle_fast_inner(
        &self,
        row_point: &[F2_128],
        col_point: &[F2_128],
        shared: Option<&crate::spartan::BlockEvalShared>,
    ) -> Result<Option<F2_128>, SpartanError> {
        let row_bits = self.rows().trailing_zeros() as usize;
        let col_bits = self.cols().trailing_zeros() as usize;
        if row_point.len() != row_bits || col_point.len() != col_bits {
            return Err(SpartanError::Dimensions);
        }
        if !self.rows().is_power_of_two()
            || !self.cols().is_power_of_two()
            || !self.base.rows.len().is_power_of_two()
            || !self.base.cols.is_power_of_two()
            || !self.instances.is_power_of_two()
        {
            return Ok(None);
        }
        let profile = std::env::var_os("MAGNETAR_PROFILE_EVAL").is_some();
        let started = std::time::Instant::now();
        let owned;
        let shared = match shared {
            Some(shared) => shared,
            None => {
                let Some(shared) = crate::spartan::BlockEvalShared::new(
                    (self.base.rows.len(), self.base.cols, self.instances),
                    row_point,
                    col_point,
                ) else {
                    return Ok(None);
                };
                owned = shared;
                &owned
            }
        };
        let prepare = started.elapsed();
        let base = self
            .base
            .eval_mle(&row_point[..shared.local_bits], &col_point[..shared.local_col_bits])?;
        let base_time = started.elapsed();
        let mut sum = base * shared.instance_sum * shared.block_weight;
        let extra_len = self
            .lazy_extra
            .as_ref()
            .map_or(self.extra.len(), LazyExtraRows::len);
        if extra_len == 0 {
            return Ok(Some(sum));
        }
        let extra_bits = extra_len.next_power_of_two().trailing_zeros() as usize;
        let extra_base = self.base.rows.len() * self.instances;
        if !extra_base.is_multiple_of(1usize << extra_bits) {
            return Ok(None);
        }
        let high_point = &row_point[extra_bits..];
        let high_index = extra_base >> extra_bits;
        let high_bits = bits(high_index, high_point.len());
        let high_eq = eq(high_point, &high_bits);
        let col_local_eq = &shared.col_local_eq;
        if profile {
            eprintln!(
                "eval phase: prepare {:?} base {:?} extra-setup {:?}",
                prepare,
                base_time - prepare,
                started.elapsed() - base_time
            );
        }
        if let Some(lazy) = &self.lazy_extra {
            if let Some(extra_sum) = lazy.eval_sum_factorized(
                row_point,
                col_point,
                shared.local_col_bits,
                extra_base,
                extra_bits,
                high_eq,
                col_local_eq,
                &shared.col_instance_point,
                self.base.cols,
            ) {
                sum = sum + extra_sum;
                return Ok(Some(sum));
            }
        }
        let row_low_eq = eq_vector_tensor(&row_point[..extra_bits]);
        let row_weights = row_low_eq
            .iter()
            .map(|weight| *weight * high_eq)
            .collect::<Vec<_>>();
        let col_instance_eq = eq_vector_tensor(&shared.col_instance_point);
        if let Some(lazy) = &self.lazy_extra {
            sum = sum
                + lazy.eval_sum(
                    &row_weights,
                    col_local_eq,
                    &col_instance_eq,
                    self.base.cols,
                );
        } else {
            for (offset, row) in self.extra.iter().enumerate() {
                let row_weight = row_weights[offset];
                for (column, coefficient) in row {
                    let instance = column / self.base.cols;
                    let local = column % self.base.cols;
                    sum = sum
                        + *coefficient
                            * row_weight
                            * col_local_eq[local]
                            * col_instance_eq[instance];
                }
            }
        }
        Ok(Some(sum))
    }

    pub fn eval_mle(
        &self,
        row_point: &[F2_128],
        col_point: &[F2_128],
    ) -> Result<F2_128, SpartanError> {
        let row_eq = eq_vector_tensor(row_point);
        let col_eq = eq_vector_tensor(col_point);
        self.eval_mle_with_eq(row_point, col_point, &row_eq, &col_eq)
    }

    pub fn eval_mle_with_eq(
        &self,
        row_point: &[F2_128],
        col_point: &[F2_128],
        row_eq: &[F2_128],
        col_eq: &[F2_128],
    ) -> Result<F2_128, SpartanError> {
        let row_bits = self.rows().trailing_zeros() as usize;
        let col_bits = self.cols().trailing_zeros() as usize;
        if row_point.len() != row_bits || col_point.len() != col_bits {
            return Err(SpartanError::Dimensions);
        }
        let local_bits = self.base.rows.len().trailing_zeros() as usize;
        let base = self.base.eval_mle(
            &row_point[..local_bits],
            &col_point[..self.base.cols.trailing_zeros() as usize],
        )?;
        let instance_bits = self.instances.trailing_zeros() as usize;
        let block_high = &row_point[local_bits + instance_bits..];
        let zero_high = vec![F2_128::from(0u64); block_high.len()];
        let row_instance = &row_point[local_bits..local_bits + instance_bits];
        let col_instance = &col_point[self.base.cols.trailing_zeros() as usize..];
        let row_instance_eq = eq_vector_tensor(row_instance);
        let col_instance_eq = eq_vector_tensor(col_instance);
        let block_weight = eq(block_high, &zero_high);
        let mut instance_sum = F2_128::from(0u64);
        for instance in 0..self.instances {
            instance_sum =
                instance_sum + row_instance_eq[instance] * col_instance_eq[instance];
        }
        let mut sum = base * instance_sum * block_weight;
        let extra_base = self.base.rows.len() * self.instances;
        let chunks = if self.extra.len() >= 1 << 16 {
            std::thread::available_parallelism()
                .map(|count| count.get().min(4))
                .unwrap_or(2)
        } else {
            1
        };
        if chunks <= 1 {
            for (offset, row) in self.extra.iter().enumerate() {
                let row_weight = row_eq[extra_base + offset];
                for (column, coefficient) in row {
                    sum = sum + *coefficient * row_weight * col_eq[*column];
                }
            }
        } else {
            let extra = &self.extra;
            let partial = std::thread::scope(|scope| {
                let handles = (0..chunks)
                    .map(|chunk| {
                        scope.spawn(move || {
                            let start = extra.len() * chunk / chunks;
                            let end = extra.len() * (chunk + 1) / chunks;
                            let mut partial = F2_128::from(0u64);
                            for offset in start..end {
                                let row_weight = row_eq[extra_base + offset];
                                for (column, coefficient) in &extra[offset] {
                                    partial =
                                        partial + *coefficient * row_weight * col_eq[*column];
                                }
                            }
                            partial
                        })
                    })
                    .collect::<Vec<_>>();
                handles
                    .into_iter()
                    .fold(F2_128::from(0u64), |sum, handle| {
                        sum + handle.join().expect("extra-row worker")
                    })
            });
            sum = sum + partial;
        }
        Ok(sum)
    }
}

fn dot_bits(row: &[(usize, F2_128)], bits: &crate::PackedBits) -> F2_128 {
    row.iter().fold(F2_128::from(0u64), |sum, (column, coefficient)| {
        if bits.get(*column) {
            sum + *coefficient
        } else {
            sum
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_constraint::Expr;

    #[test]
    fn shared_block_matrix_matches_an_explicit_batch() {
        let mut base = ConstraintSystem::new(3);
        base.add_constraint(
            Expr::var(0).add(Expr::var(1)),
            Expr::constant(1u64),
            Expr::var(2),
        );
        let base_matrix = SparseMatrix::from_system(&base, MatrixPart::A).unwrap();
        let mut rows = base_matrix.rows.clone();
        let shifted = base_matrix
            .rows
            .iter()
            .map(|row| {
                row.iter()
                    .map(|(column, coefficient)| (column + base_matrix.cols, *coefficient))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        rows.extend(shifted);
        let explicit = SparseMatrix {
            rows,
            cols: base_matrix.cols * 2,
        };
        let values = vec![
            F2_128::from(1u64),
            F2_128::from(2u64),
            F2_128::from(3u64),
            F2_128::from(4u64),
            F2_128::from(5u64),
            F2_128::from(6u64),
            F2_128::from(7u64),
            F2_128::from(8u64),
        ];
        let shared = SharedBlockMatrix::from_system(&base, MatrixPart::A, 2).unwrap();
        assert_eq!(shared.rows(), explicit.rows.len());
        assert_eq!(shared.cols(), explicit.cols);
        assert_eq!(
            shared.mul_vec(&values).unwrap(),
            explicit.mul_vec(&values).unwrap()
        );

        let row_point = (0..shared.rows().trailing_zeros() as usize)
            .map(|index| F2_128::from(index as u64 + 1))
            .collect::<Vec<_>>();
        let col_point = (0..shared.cols().trailing_zeros() as usize)
            .map(|index| F2_128::from(index as u64 + 9))
            .collect::<Vec<_>>();
        assert_eq!(
            shared.row_combination(&row_point).unwrap(),
            explicit.row_combination(&row_point).unwrap()
        );
        assert_eq!(
            shared.eval_mle(&row_point, &col_point).unwrap(),
            explicit.eval_mle(&row_point, &col_point).unwrap()
        );
    }

    fn eq_at(point: &[F2_128], index: usize) -> F2_128 {
        let one = F2_128::from(1u64);
        point
            .iter()
            .enumerate()
            .fold(one, |acc, (bit, value)| {
                if (index >> bit) & 1 == 1 {
                    acc * *value
                } else {
                    acc * (one + *value)
                }
            })
    }

    #[test]
    fn closed_form_eq_dots_match_the_loops() {
        let one = F2_128::from(1u64);
        for k in 1..=8usize {
            let mut state = 0x1234_5678_9abc_def0u64 ^ (k as u64);
            let mut next = || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                F2_128::from(state)
            };
            let r: Vec<F2_128> = (0..=k).map(|_| next()).collect();
            let c: Vec<F2_128> = (0..k).map(|_| next()).collect();
            let instances = 1usize << k;
            let chain = instances - 1;
            let top = one + r[k];
            let r_lo = &r[..k];

            let mut naive_unshifted = F2_128::from(0u64);
            let mut naive_shifted = F2_128::from(0u64);
            for instance in 0..chain {
                let row = eq_at(&r, instance);
                naive_unshifted = naive_unshifted + row * eq_at(&c, instance);
                naive_shifted = naive_shifted + row * eq_at(&c, instance + 1);
            }
            let full = eq_dot_full(r_lo, &c);
            let tail = r_lo.iter().fold(one, |acc, value| acc * *value)
                * c.iter().fold(one, |acc, value| acc * *value);
            assert_eq!(
                naive_unshifted,
                top * (full + tail),
                "unshifted closed form mismatch at k={k}"
            );
            assert_eq!(
                naive_shifted,
                top * eq_dot_shifted_full(r_lo, &c),
                "shifted closed form mismatch at k={k}"
            );
        }
    }
}
