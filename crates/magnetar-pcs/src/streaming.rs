//! Streaming (incremental) commitment of the PCS codeword.
//!
//! The batch path materialises two things in full before anything else happens:
//!
//! ```text
//!     magnetar-pcs/src/p3_pcs.rs  commit / commit_batch / commit_mosaic
//!       -> P3BinaryPcs backend
//!          -> encoder.encode_batch_borrowed      one full codeword matrix
//!          -> mmcs.commit_matrix(encoded)        one full Merkle tree (every level kept)
//! ```
//!
//! At RV64 `2^16` the single-column table is `2^22` field elements, so at rate
//! `1/8` the codeword alone is `2^25` values (512 MiB) and the Merkle tree is
//! the same order again. Both are transients for a commitment that sends only
//! the cap: [`P3Mmcs`] has `cap_height = 0`, so the caller receives one root.
//!
//! This module builds that root in one pass:
//!
//! 1. **Encoder seam.** The Reed-Solomon codeword of a padded message is a
//!    concatenation of `2^log_inv_rate` cosets, each the message transformed on
//!    its own shifted subspace (`PolyBasisNtt::ntt_batch_padded` states the same
//!    identity). [`streamed_codeword_root`] copies the message into one scratch
//!    buffer per coset, transforms it, and hands the rows to the root builder.
//!    Cost and output are identical to the batch encoder; the peak is one coset
//!    plus the message instead of the whole codeword.
//! 2. **Merkle seam.** [`StreamingRoot`] hashes codeword rows as they arrive,
//!    builds one perfect subtree per fixed-size row block, and keeps only a
//!    logarithmic frontier of completed subtree roots.
//!
//! The root is identical by construction: the same leaf order, the same leaf
//! hashing (`CryptographicHasher::hash_many` over the contiguous rows of a
//! block), and the same binary compression over the same subtree boundaries.
//! [`StreamingRoot::finish`] returns the same [`P3Cap`] `Mmcs::commit_matrix`
//! would, and the `streaming_root_matches_mmcs` / `streaming_codeword_*` tests
//! pin that against the real tree.
//!
//! Only power-of-two row counts are supported, which is what the PCS always
//! commits: a codeword height is `2^(stacked_variables + log_inv_rate)`.

use p3_binary_dft::{domain_point, AdditiveNtt, PolyBasisNtt};
use p3_binary_field::BinaryField128 as F;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

use crate::p3_pcs::{P3Cap, P3Compress, P3Hash};

/// One Merkle digest of the PCS tree: Keccak-256 truncated to 16 bytes.
type Digest = [u8; 16];

/// Base-two logarithm of the rows one independently built subtree block holds.
///
/// A block is the unit of parallelism for leaf hashing and in-block compression:
/// `2^15` rows of one field element is a 512 KiB digest buffer, so a worker's
/// live block set stays small while `2^22` rows still split into 128 blocks.
const BLOCK_LOG: usize = 15;

/// Upper bound on one block's buffered rows in bytes, so wide messages keep the
/// same small per-worker footprint. The PCS commits `folding = 0` (one column),
/// so this only guards the generic path.
const BLOCK_BYTES: usize = 2 << 20;

/// Incremental binary Merkle root over codeword rows.
///
/// Feed rows with [`Self::push_rows`] and finish with [`Self::finish`]. The
/// digest of one row is the leaf hash of its `width` field elements, exactly as
/// the tree's leaf layer hashes it.
pub(crate) struct StreamingRoot {
    hash: P3Hash,
    compress: P3Compress,
    /// Columns per codeword row.
    width: usize,
    /// Rows one block subtree holds.
    block_rows: usize,
    /// Field elements of one block subtree (`block_rows * width`).
    block_elems: usize,
    /// Rows of the next unfinished block, laid out row after row.
    row_buffer: Vec<F>,
    /// Completed subtree roots, one per level above the block subtrees.
    ///
    /// Only the rightmost unfinished node of each level is ever held, so the
    /// frontier costs at most one digest per level.
    pending: Vec<Option<Digest>>,
    /// Rows received so far.
    rows: usize,
    /// Rows the caller promised up front.
    total_rows: usize,
}

impl StreamingRoot {
    /// Plan a root over `total_rows` codeword rows of `width` field elements.
    ///
    /// # Panics
    ///
    /// - `total_rows` must be a power of two and at least one.
    /// - `width` must be at least one.
    pub(crate) fn new(width: usize, total_rows: usize) -> Self {
        assert!(total_rows > 0, "streaming root needs at least one row");
        let log_rows = total_rows.trailing_zeros() as usize;
        Self::with_block_log(width, total_rows, BLOCK_LOG.min(log_rows))
    }

    /// Plan a root whose block subtrees span `1 << block_log` rows.
    ///
    /// [`Self::new`] passes the production [`BLOCK_LOG`]; the explicit form
    /// exists so tests can exercise the multi-block frontier at small sizes
    /// (and at the production block size on a fixture small enough to keep the
    /// gate cheap).
    ///
    /// # Panics
    ///
    /// - `total_rows` must be a power of two and at least one.
    /// - `width` must be at least one.
    /// - `block_log` must not exceed `log2(total_rows)`.
    pub(crate) fn with_block_log(width: usize, total_rows: usize, block_log: usize) -> Self {
        assert!(width > 0, "codeword rows must have a width");
        assert!(
            total_rows.is_power_of_two(),
            "streaming root expects a power-of-two row count, got {total_rows}"
        );
        let log_rows = total_rows.trailing_zeros() as usize;
        assert!(
            block_log <= log_rows,
            "block log {block_log} exceeds the tree's {log_rows}"
        );

        // One block is as large as the row-bytes budget allows, but never larger
        // than the whole tree.
        let row_bytes = width
            .checked_mul(size_of::<F>())
            .expect("codeword row bytes overflow");
        let max_block_log = BLOCK_BYTES
            .checked_div(row_bytes)
            .filter(|rows| *rows > 0)
            .map_or(0, |rows| rows.trailing_zeros() as usize);
        let block_log = block_log.min(max_block_log);
        let block_rows = 1usize << block_log;
        let block_elems = block_rows
            .checked_mul(width)
            .expect("block elements overflow");

        Self {
            hash: P3Hash::new(crate::p3_pcs::Keccak256Hash16),
            compress: P3Compress::new(crate::p3_pcs::Keccak256Hash16),
            width,
            block_rows,
            block_elems,
            row_buffer: Vec::with_capacity(block_elems),
            pending: Vec::new(),
            rows: 0,
            total_rows,
        }
    }

    /// Hand the next run of codeword rows to the root.
    ///
    /// Rows are consumed in order; chunking is free, because leaf hashing and
    /// block subtrees do not depend on where a chunk ends.
    ///
    /// # Panics
    ///
    /// - `values.len()` must be a whole number of rows.
    /// - The caller must not push more rows than [`Self::new`] was told.
    pub(crate) fn push_rows(&mut self, values: &[F]) {
        assert!(
            values.len().is_multiple_of(self.width),
            "row chunk {} is not a whole number of {}-wide rows",
            values.len(),
            self.width
        );
        let incoming_rows = values.len() / self.width;
        assert!(
            self.rows + incoming_rows <= self.total_rows,
            "more rows pushed than the planned {}",
            self.total_rows
        );
        self.rows += incoming_rows;

        let mut values = values;
        // A partial block left over from an earlier chunk is finished first.
        if !self.row_buffer.is_empty() {
            let needed = self.block_elems - self.row_buffer.len();
            let take = needed.min(values.len());
            self.row_buffer.extend_from_slice(&values[..take]);
            values = &values[take..];
            if self.row_buffer.len() == self.block_elems {
                let block = core::mem::take(&mut self.row_buffer);
                let root = self.block_root(&block);
                self.row_buffer = block;
                self.row_buffer.clear();
                self.push_subtree_root(root);
            }
        }

        // Whole blocks hash and compress in parallel; only their roots are ordered
        // by the frontier, so the root is the same as a sequential sweep.
        let whole = values.len() / self.block_elems;
        if whole > 0 {
            let roots: Vec<Digest> = values[..whole * self.block_elems]
                .par_chunks(self.block_elems)
                .map(|block| self.block_root(block))
                .collect();
            for root in roots {
                self.push_subtree_root(root);
            }
            values = &values[whole * self.block_elems..];
        }

        self.row_buffer.extend_from_slice(values);
    }

    /// Root of one block subtree: hash every row, then halve the digests in place.
    fn block_root(&self, block: &[F]) -> Digest {
        let mut digests = vec![Digest::default(); self.block_rows];
        self.hash.hash_many(block, &mut digests);
        let mut len = digests.len();
        while len > 1 {
            let half = len / 2;
            // In place: pair `i` reads slots `2i, 2i+1`, which are only written
            // after every read of them, so no slot is clobbered before use.
            for i in 0..half {
                digests[i] = self.compress.compress([digests[2 * i], digests[2 * i + 1]]);
            }
            len = half;
        }
        digests[0]
    }

    /// Insert one completed subtree root into the frontier.
    fn push_subtree_root(&mut self, root: Digest) {
        let mut node = root;
        let mut level = 0;
        loop {
            if level == self.pending.len() {
                self.pending.push(None);
            }
            match self.pending[level].take() {
                None => {
                    self.pending[level] = Some(node);
                    return;
                }
                Some(left) => {
                    node = self.compress.compress([left, node]);
                    level += 1;
                }
            }
        }
    }

    /// Finish the tree and return the Merkle cap (`cap_height = 0`, one root).
    ///
    /// # Panics
    ///
    /// Panics unless every promised row was pushed.
    pub(crate) fn finish(mut self) -> P3Cap {
        assert_eq!(
            self.rows, self.total_rows,
            "streaming root finished after {} rows of {}",
            self.rows, self.total_rows
        );

        // The row count is a power of two and the block size divides it, so
        // every block was flushed by `push_rows`; this only guards a future
        // caller whose two are not in that relation.
        if !self.row_buffer.is_empty() {
            let block = core::mem::take(&mut self.row_buffer);
            let root = self.block_root(&block);
            self.push_subtree_root(root);
        }

        // A tree of one block has its root already; otherwise the frontier has
        // exactly one completed node, at the top level.
        let mut root = None;
        for level in 0..self.pending.len() {
            if let Some(node) = self.pending[level].take() {
                assert!(
                    root.is_none(),
                    "frontier holds more than one root at level {level}"
                );
                root = Some(node);
            }
        }
        P3Cap::new(vec![root.expect("streaming root over no rows")])
    }
}

/// Commit to `message` (a `height x width` codeword message) with a streamed
/// Reed-Solomon encode and an incremental Merkle root.
///
/// The returned cap is the same [`P3Cap`] the batch path produces for the same
/// message; only the live set differs.
pub(crate) fn streamed_codeword_root(message: &[F], width: usize, log_inv_rate: usize) -> P3Cap {
    assert!(width > 0, "codeword rows must have a width");
    assert!(
        message.len().is_multiple_of(width),
        "message length {} is not a whole number of {}-wide rows",
        message.len(),
        width
    );
    let height = message.len() / width;
    assert!(
        height.is_power_of_two(),
        "message height {height} is not a power of two"
    );
    let log_height = height.trailing_zeros() as usize;

    let codeword_height = height
        .checked_shl(log_inv_rate as u32)
        .expect("codeword height overflows usize");
    let mut root = StreamingRoot::new(width, codeword_height);

    // Each coset is the message transformed on its own shifted subspace; the
    // batch encoder writes exactly these cosets back to back.
    let ntt = PolyBasisNtt::default();
    let mut scratch = vec![F::ZERO; message.len()];
    let cosets = 1usize
        .checked_shl(log_inv_rate as u32)
        .expect("log inverse rate exceeds usize");
    for coset in 0..cosets {
        // Every coset starts from its own copy of the message; the buffer the
        // previous transform returned is reused, so only one coset is live.
        scratch.copy_from_slice(message);
        let shift = domain_point::<F>(
            coset
                .checked_shl(log_height as u32)
                .expect("coset offset overflows usize"),
        );
        let encoded = ntt.shifted_ntt_batch(RowMajorMatrix::new(scratch, width), shift);
        root.push_rows(&encoded.values);
        scratch = encoded.values;
    }

    root.finish()
}

#[cfg(test)]
mod tests {
    use magnetar_constraint::F2_128;
    use p3_binary_dft::EncodableLevel;
    use p3_binary_field::TowerLevel;
    use p3_commit::{Encoder, Mmcs};
    use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};

    use super::*;
    use crate::p3_pcs::{P3Mmcs, P3MosaicTable};
    use crate::P3BinaryPcs;
    use magnetar_proof::Pcs;

    fn mmcs() -> P3Mmcs {
        P3Mmcs::new(
            P3Hash::new(crate::p3_pcs::Keccak256Hash16),
            P3Compress::new(crate::p3_pcs::Keccak256Hash16),
            0,
        )
    }

    fn f2_values(count: usize, seed: u64) -> Vec<F2_128> {
        (0..count)
            .map(|index| {
                F2_128::from(
                    (index as u128)
                        .wrapping_mul(0x9e37_79b9_7f4a_7c15_9e37_79b9)
                        .wrapping_add(seed as u128)
                        .wrapping_mul(0xd6e8_feb8_6659_fd93),
                )
            })
            .collect()
    }

    fn values(count: usize, seed: u64) -> Vec<F> {
        (0..count)
            .map(|index| {
                F::from_repr(
                    (index as u128)
                        .wrapping_mul(0x9e37_79b9_7f4a_7c15_9e37_79b9)
                        .wrapping_add(seed as u128)
                        .wrapping_mul(0xd6e8_feb8_6659_fd93),
                )
            })
            .collect()
    }

    /// The cap of the batch encoder and the real Merkle tree over one message.
    fn batch_cap(message: &[F], width: usize, log_inv_rate: usize) -> P3Cap {
        let encoder = <F as EncodableLevel>::Encoder::default();
        let encoded =
            encoder.encode_batch_borrowed(RowMajorMatrixView::new(message, width), log_inv_rate);
        mmcs().commit_matrix(encoded).0
    }

    /// The incremental root must equal the tree the MMCS builds, for every
    /// power-of-two height, several widths, and several push chunkings.
    #[test]
    fn streaming_root_matches_mmcs() {
        for log_rows in 0..=10 {
            for width in [1usize, 2, 3, 5, 8] {
                let rows = 1usize << log_rows;
                let values = values(rows * width, log_rows as u64 * 31 + width as u64);
                let matrix = RowMajorMatrix::new(values.clone(), width);
                let (expected, _) = mmcs().commit_matrix(matrix);

                for chunk_rows in [1usize, 3, 7, 64, rows] {
                    let mut root = StreamingRoot::new(width, rows);
                    for chunk in values.chunks(chunk_rows.min(rows) * width) {
                        root.push_rows(chunk);
                    }
                    assert_eq!(
                        root.finish(),
                        expected,
                        "root mismatch rows={rows} width={width} chunk_rows={chunk_rows}"
                    );
                }
            }
        }
    }

    /// The block split and the frontier collapse must equal the tree once the
    /// root spans several blocks, at the production block size as well as
    /// smaller ones (the `streaming_root_matches_mmcs` sweep never leaves a
    /// single block, because it stops at `2^10` rows).
    #[test]
    fn streaming_root_frontier_spans_blocks() {
        for (log_rows, block_log) in [
            (16usize, 15usize),
            (16, 6),
            (17, 15),
            (17, 8),
            (10, 3),
            (4, 0),
        ] {
            let rows = 1usize << log_rows;
            let values = values(rows, log_rows as u64 * 17 + block_log as u64);
            let (expected, _) = mmcs().commit_matrix(RowMajorMatrix::new(values.clone(), 1));

            let block_rows = 1usize << block_log;
            let mut chunk_sizes = vec![rows, block_rows];
            if !chunk_sizes.contains(&997) {
                chunk_sizes.push(997);
            }
            if !chunk_sizes.contains(&1) {
                chunk_sizes.push(1);
            }
            for chunk_rows in chunk_sizes {
                let mut root = StreamingRoot::with_block_log(1, rows, block_log);
                for chunk in values.chunks(chunk_rows) {
                    root.push_rows(chunk);
                }
                assert_eq!(
                    root.finish(),
                    expected,
                    "root mismatch rows={rows} block_log={block_log} chunk_rows={chunk_rows}"
                );
            }
        }
    }

    /// The streamed encoder must produce the batch encoder's codeword exactly,
    /// and the streamed commitment the tree's root over it.
    #[test]
    fn streaming_codeword_root_matches_batch_encoder() {
        for log_height in 0..=7 {
            for width in [1usize, 2, 3] {
                if log_height == 0 && width > 1 {
                    continue;
                }
                for log_inv_rate in 0..=3 {
                    let height = 1usize << log_height;
                    let message = values(height * width, log_height as u64 + width as u64);
                    assert_eq!(
                        streamed_codeword_root(&message, width, log_inv_rate),
                        batch_cap(&message, width, log_inv_rate),
                        "codeword root mismatch height={height} width={width} rate={log_inv_rate}"
                    );
                }
            }
        }
    }

    /// The wrapper entry points that keep only the cap must return the root the
    /// retained (batch-commit) path builds over the same message, at the real
    /// call sites the RV64 prover uses.
    #[test]
    fn streaming_root_matches_pcs_commit_entry_points() {
        let pcs = P3BinaryPcs::with_params(100, 2, 21, 2);

        // Single-column: `Pcs::commit` is cap-only; `Pcs::open` re-commits through
        // the batch path and returns that commitment, which must be the same one.
        let table = f2_values(1 << 12, 3);
        let point: Vec<F2_128> = (0..12u64).map(F2_128::from).collect();
        let commitment = pcs.commit(&table).unwrap();
        let opening = pcs.open(&table, &point).unwrap();
        assert_eq!(commitment.cap, opening.commitment.cap);
        assert_eq!(commitment.num_variables, opening.commitment.num_variables);
        assert_eq!(commitment.num_variables, 12);

        // Batch: `commit_batch` is cap-only, `commit_batch_prepared` retains the
        // batch-built codeword and tree for its opening.
        let columns: Vec<Vec<F2_128>> =
            (0..3u64).map(|seed| f2_values(1 << 10, 5 + seed)).collect();
        let batch = pcs.commit_batch(&columns).unwrap();
        let prepared = pcs.commit_batch_prepared(&columns).unwrap();
        assert_eq!(batch.cap, prepared.commitment.cap);
        assert_eq!(batch.num_variables, prepared.commitment.num_variables);
        assert_eq!(
            batch.stacked_variables,
            prepared.commitment.stacked_variables
        );
        assert_eq!(batch.num_columns, prepared.commitment.num_columns);

        // Mosaic: `commit_mosaic` is cap-only, `open_mosaic` re-commits the same
        // 12-table stack through the batch path.
        let tables = [
            P3MosaicTable {
                columns: vec![f2_values(1 << 2, 11)],
            },
            P3MosaicTable {
                columns: vec![f2_values(1 << 4, 12), f2_values(1 << 4, 13)],
            },
            P3MosaicTable {
                columns: vec![f2_values(1 << 3, 14)],
            },
        ];
        let points = vec![
            crate::P3MosaicPoint {
                table: 0,
                point: vec![F2_128::from(1u64), F2_128::from(0u64)],
                columns: vec![0],
                next_columns: Vec::new(),
            },
            crate::P3MosaicPoint {
                table: 1,
                point: (0..4u64).map(F2_128::from).collect(),
                columns: vec![0, 1],
                next_columns: Vec::new(),
            },
            crate::P3MosaicPoint {
                table: 2,
                point: (0..3u64).map(F2_128::from).collect(),
                columns: vec![0],
                next_columns: Vec::new(),
            },
        ];
        let mosaic = pcs.commit_mosaic(&tables).unwrap();
        let opening = pcs.open_mosaic(&tables, &points).unwrap();
        assert_eq!(mosaic.cap, opening.commitment.cap);
        assert_eq!(mosaic.tables, opening.commitment.tables);
        assert_eq!(
            mosaic.stacked_variables,
            opening.commitment.stacked_variables
        );
    }
}
