//! Streaming pruned multiproofs for [`MerkleTreeMmcs`].
//!
//! [`MerkleTreeMmcs::open_multi_batch`] opens rows against a committed
//! [`MerkleTree`](crate::MerkleTree), which owns the leaves *and* every digest
//! layer. A prover that does not want to materialise the committed matrix at
//! all can instead re-derive it one row run at a time, hash the runs as they
//! arrive, and keep only what the proof sends: the opened rows and the boundary
//! sibling digests of the pruned frontier. [`MerkleStreamingOpener`] does that
//! for the tree shape the `binary-pcs` codeword uses: one matrix, binary
//! compression, `cap_height = 0`, power-of-two height.
//!
//! The plan is built in *index* space from the queried leaves before any
//! hashing starts, by mirroring the frontier walk in
//! [`pruning`](crate::pruning): fold the queried leaves up level by level and
//! send every child with no queried leaf beneath it. Every sent node is
//! finalized exactly once during a single left-to-right pass, so its digest can
//! be dropped straight into the wire slot the plan reserved for it. The result
//! is bit-identical to `open_multi_batch`: same opened rows in the caller's
//! index order, same sibling digests in the same order.
//!
//! Only geometry the crate can build is accepted; anything else panics at the
//! streamed opener's construction rather than producing a proof that differs
//! from `open_multi_batch`.

use alloc::vec;
use alloc::vec::Vec;

use p3_commit::{StreamingMmcs, StreamingOpener};
use p3_field::PackedValue;
use p3_maybe_rayon::prelude::*;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

use crate::{MerkleTreeMmcs, PrunedMerklePaths};

/// Base-two logarithm of the rows one independently built subtree block holds.
///
/// A block is the unit of parallelism for leaf hashing and in-block compression:
/// `2^15` rows of one field element is a 512 KiB digest buffer, so a worker's
/// live block set stays small while a `2^22`-row codeword still splits into 128
/// blocks.
const BLOCK_LOG: usize = 15;

/// Upper bound on one block's buffered rows in bytes, so wide matrices keep the
/// same small per-worker footprint.
const BLOCK_BYTES: usize = 2 << 20;

/// Base-two logarithm of the largest block one worker may hash at once.
fn max_block_log(row_bytes: usize) -> usize {
    BLOCK_BYTES
        .checked_div(row_bytes.max(1))
        .filter(|rows| *rows > 0)
        .map_or(0, |rows| rows.trailing_zeros() as usize)
}

/// The wire plan of a pruned Merkle multi-opening for a binary tree.
///
/// Mirrors [`crate::pruning`]'s frontier walk with arity two: the walk folds
/// the queried leaves up the tree level by level, and sends every child that
/// has no queried leaf beneath it. Keeping the plan in *index* space (no
/// digests) lets one streaming pass fill the proof: every sent node is
/// finalized exactly once, and its wire slot is fixed before hashing starts.
struct OpeningPlan {
    /// `levels[level]`: ascending node indices at that level whose digest is sent.
    levels: Vec<Vec<usize>>,
    /// `slots[level][j]`: the wire slot of `levels[level][j]`.
    slots: Vec<Vec<usize>>,
    /// Digests sent in total, i.e. the flat proof length.
    wire_len: usize,
}

impl OpeningPlan {
    /// Plan the frontier over `sorted_unique` queried leaf indices.
    fn new(sorted_unique: &[usize], log_height: usize) -> Self {
        let mut levels: Vec<Vec<usize>> = vec![Vec::new(); log_height];
        let mut slots: Vec<Vec<usize>> = vec![Vec::new(); log_height];
        let mut wire_len = 0;
        let mut nodes = sorted_unique.to_vec();

        for level in 0..log_height {
            let mut parents = Vec::with_capacity(nodes.len());
            let mut i = 0;
            while i < nodes.len() {
                let group = nodes[i] / 2;
                let start = i;
                while i < nodes.len() && nodes[i] / 2 == group {
                    i += 1;
                }
                // Every child of the group without a frontier node beneath it
                // is a boundary digest, in ascending child order.
                for k in 0..2 {
                    if !nodes[start..i].contains(&(group * 2 + k)) {
                        levels[level].push(group * 2 + k);
                        slots[level].push(wire_len);
                        wire_len += 1;
                    }
                }
                parents.push(group);
            }
            nodes = parents;
        }

        Self {
            levels,
            slots,
            wire_len,
        }
    }

    /// Wire slot of one node's digest, when the plan sends it.
    fn slot(&self, level: usize, node: usize) -> Option<usize> {
        let nodes = self.levels.get(level)?;
        let position = nodes.binary_search(&node).ok()?;
        Some(self.slots[level][position])
    }
}

/// One streamed matrix's pruned multiproof builder for [`MerkleTreeMmcs`].
///
/// Built by [`MerkleTreeMmcs::streaming_opener`]; see [`StreamingMmcs`].
pub struct MerkleStreamingOpener<P, PW, H, C, const N: usize, const DIGEST_ELEMS: usize>
where
    P: PackedValue,
    PW: PackedValue,
{
    /// Row hasher, the tree's own leaf arm.
    hash: H,
    /// N-to-one digest compression.
    compress: C,
    /// Columns per matrix row.
    width: usize,
    /// Base-two logarithm of the rows one block subtree holds.
    block_log: usize,
    /// Rows one block subtree holds.
    block_rows: usize,
    /// Field elements of one block subtree (`block_rows * width`).
    block_elems: usize,
    /// Rows of the next unfinished block, laid out row after row.
    row_buffer: Vec<P::Value>,
    /// Rows received so far.
    rows: usize,
    /// Rows the caller promised up front.
    total_rows: usize,
    /// Planned digests, indexed by wire slot.
    digests: Vec<Option<[PW::Value; DIGEST_ELEMS]>>,
    /// Planned nodes below the block level, bucketed per block as
    /// `(level, index within the block's subtree, wire slot)`.
    block_plans: Vec<Vec<(usize, usize, usize)>>,
    /// Completed block roots, in block order.
    block_roots: Vec<[PW::Value; DIGEST_ELEMS]>,
    /// Rows to keep, as `(leaf index, output position)`, ascending by index.
    capture: Vec<(usize, usize)>,
    /// Next capture entry not yet copied.
    next_capture: usize,
    /// Kept rows, in the caller's index order.
    opened: Vec<Vec<P::Value>>,
    /// The pruned frontier plan.
    plan: OpeningPlan,
}

impl<P, PW, H, C, const N: usize, const DIGEST_ELEMS: usize>
    MerkleStreamingOpener<P, PW, H, C, N, DIGEST_ELEMS>
where
    P: PackedValue,
    PW: PackedValue,
    PW::Value: Copy + Default,
{
    /// Plan a streamed multiproof over `total_rows` rows of `width` elements.
    fn new(
        hash: H,
        compress: C,
        width: usize,
        total_rows: usize,
        indices: &[usize],
    ) -> Self {
        assert!(
            width > 0,
            "streaming opener needs rows with at least one column"
        );
        assert!(
            total_rows > 0 && total_rows.is_power_of_two(),
            "streaming opener expects a power-of-two row count, got {total_rows}"
        );
        assert!(
            indices.iter().all(|&index| index < total_rows),
            "opened index out of bounds for {total_rows} rows"
        );
        let log_rows = total_rows.trailing_zeros() as usize;
        let row_bytes = width
            .checked_mul(core::mem::size_of::<P::Value>())
            .expect("matrix row bytes overflow");
        let block_log = log_rows.min(BLOCK_LOG).min(max_block_log(row_bytes));
        let block_rows = 1usize << block_log;
        let block_elems = block_rows
            .checked_mul(width)
            .expect("block elements overflow");

        let mut sorted_unique = indices.to_vec();
        sorted_unique.sort_unstable();
        sorted_unique.dedup();
        let plan = OpeningPlan::new(&sorted_unique, log_rows);

        // Bucket the planned nodes at or below the block level into their block,
        // so a block never searches the plan.
        let num_blocks = 1usize << (log_rows - block_log);
        let mut block_plans: Vec<Vec<(usize, usize, usize)>> = vec![Vec::new(); num_blocks];
        for level in 0..block_log {
            let nodes = &plan.levels[level];
            for (j, &node) in nodes.iter().enumerate() {
                let block = node >> (block_log - level);
                let local = node & ((1usize << (block_log - level)) - 1);
                block_plans[block].push((level, local, plan.slots[level][j]));
            }
        }

        let mut capture: Vec<(usize, usize)> = indices
            .iter()
            .copied()
            .enumerate()
            .map(|(position, index)| (index, position))
            .collect();
        capture.sort_unstable_by_key(|&(index, _)| index);

        Self {
            hash,
            compress,
            width,
            block_log,
            block_rows,
            block_elems,
            row_buffer: Vec::with_capacity(block_elems),
            rows: 0,
            total_rows,
            digests: vec![None; plan.wire_len],
            block_plans,
            block_roots: Vec::new(),
            capture,
            next_capture: 0,
            opened: vec![Vec::new(); indices.len()],
            plan,
        }
    }
}

impl<P, PW, H, C, const N: usize, const DIGEST_ELEMS: usize> StreamingOpener<P::Value>
    for MerkleStreamingOpener<P, PW, H, C, N, DIGEST_ELEMS>
where
    P: PackedValue,
    PW: PackedValue,
    H: CryptographicHasher<P::Value, [PW::Value; DIGEST_ELEMS]> + Sync,
    C: PseudoCompressionFunction<[PW::Value; DIGEST_ELEMS], N> + Sync,
    PW::Value: Copy + Default + Send + Sync,
    P::Value: Send + Sync,
{
    type MultiProof = PrunedMerklePaths<PW::Value, DIGEST_ELEMS>;

    fn push_rows(&mut self, values: &[P::Value]) {
        assert!(
            values.len().is_multiple_of(self.width),
            "row run {} is not a whole number of {}-wide rows",
            values.len(),
            self.width
        );
        let incoming_rows = values.len() / self.width;
        assert!(
            self.rows + incoming_rows <= self.total_rows,
            "more rows pushed than the planned {}",
            self.total_rows
        );

        // Keep the rows the caller opens: they are exactly the symbols the
        // query phase needs, so the matrix itself never stays live.
        let start_row = self.rows;
        let end_row = start_row + incoming_rows;
        while self.next_capture < self.capture.len() && self.capture[self.next_capture].0 < end_row
        {
            let (index, position) = self.capture[self.next_capture];
            assert!(
                index >= start_row,
                "opened row {index} was not captured when it streamed past"
            );
            let offset = (index - start_row) * self.width;
            self.opened[position] = values[offset..offset + self.width].to_vec();
            self.next_capture += 1;
        }
        self.rows = end_row;

        let mut values = values;
        // A partial block left over from an earlier run is finished first.
        if !self.row_buffer.is_empty() {
            let needed = self.block_elems - self.row_buffer.len();
            let take = needed.min(values.len());
            self.row_buffer.extend_from_slice(&values[..take]);
            values = &values[take..];
            if self.row_buffer.len() == self.block_elems {
                let block = core::mem::take(&mut self.row_buffer);
                let block_index = self.block_roots.len();
                let (root, records) = self.block_root(&block, block_index);
                self.row_buffer = block;
                self.row_buffer.clear();
                for (slot, digest) in records {
                    self.digests[slot] = Some(digest);
                }
                self.block_roots.push(root);
            }
        }

        // Whole blocks hash and compress in parallel; their records land in wire
        // slots, which are order-free, so block order only affects the roots.
        let whole = values.len() / self.block_elems;
        if whole > 0 {
            let first_block = self.block_roots.len();
            let computed: Vec<(_, Vec<(usize, _)>)> = values[..whole * self.block_elems]
                .par_chunks(self.block_elems)
                .enumerate()
                .map(|(offset, block)| self.block_root(block, first_block + offset))
                .collect();
            for (root, records) in computed {
                for (slot, digest) in records {
                    self.digests[slot] = Some(digest);
                }
                self.block_roots.push(root);
            }
            values = &values[whole * self.block_elems..];
        }

        self.row_buffer.extend_from_slice(values);
    }

    fn finish(mut self) -> (Vec<Vec<P::Value>>, Self::MultiProof) {
        assert_eq!(
            self.rows, self.total_rows,
            "streaming opener finished after {} rows of {}",
            self.rows, self.total_rows
        );
        assert_eq!(
            self.next_capture,
            self.capture.len(),
            "not every opened row streamed past"
        );
        assert!(
            self.row_buffer.is_empty(),
            "the block size must divide the row count"
        );

        // Fold the block roots up, recording every planned node on the way; the
        // last node is the root, which the cap commits and no path sends.
        let mut nodes = core::mem::take(&mut self.block_roots);
        let mut level = self.block_log;
        while nodes.len() > 1 {
            for (index, digest) in nodes.iter().enumerate() {
                if let Some(slot) = self.plan.slot(level, index) {
                    self.digests[slot] = Some(*digest);
                }
            }
            let mut parents = Vec::with_capacity(nodes.len() / 2);
            for pair in nodes.chunks_exact(2) {
                parents.push(self.compress.compress(core::array::from_fn(|slot| {
                    if slot == 0 { pair[0] } else { pair[1] }
                })));
            }
            nodes = parents;
            level += 1;
        }

        let sibling_hashes = self
            .digests
            .into_iter()
            .map(|digest| digest.expect("every planned digest is filled"))
            .collect();
        (self.opened, PrunedMerklePaths { sibling_hashes })
    }
}

impl<P, PW, H, C, const N: usize, const DIGEST_ELEMS: usize>
    MerkleStreamingOpener<P, PW, H, C, N, DIGEST_ELEMS>
where
    P: PackedValue,
    PW: PackedValue,
    H: CryptographicHasher<P::Value, [PW::Value; DIGEST_ELEMS]> + Sync,
    C: PseudoCompressionFunction<[PW::Value; DIGEST_ELEMS], N> + Sync,
    PW::Value: Copy + Default + Eq + Send + Sync,
{
    /// Root of one block subtree plus the planned digests inside it.
    fn block_root(
        &self,
        block: &[P::Value],
        block_index: usize,
    ) -> (
        [PW::Value; DIGEST_ELEMS],
        Vec<(usize, [PW::Value; DIGEST_ELEMS])>,
    ) {
        let mut digests = vec![[PW::Value::default(); DIGEST_ELEMS]; self.block_rows];
        self.hash.hash_many(block, &mut digests);
        let mut records = Vec::new();
        let mut len = digests.len();
        let mut level = 0;
        loop {
            for &(entry_level, local, slot) in &self.block_plans[block_index] {
                if entry_level == level {
                    records.push((slot, digests[local]));
                }
            }
            if len == 1 {
                return (digests[0], records);
            }

            // Compress the whole level in one batched call. The scalar
            // `compress` would be one sponge per node; `compress_many` hands
            // the concatenated preimages to the hasher's lane-batched backend,
            // which is the same batching the tree builder's own levels get.
            let half = len / 2;
            let default = PW::Value::default();
            let groups: Vec<[[PW::Value; DIGEST_ELEMS]; N]> = (0..half)
                .map(|i| {
                    core::array::from_fn(|slot| match slot {
                        0 => digests[2 * i],
                        1 => digests[2 * i + 1],
                        _ => [default; DIGEST_ELEMS],
                    })
                })
                .collect();
            self.compress.compress_many(&groups, &mut digests[..half]);
            len = half;
            level += 1;
        }
    }
}

impl<P, PW, H, C, const N: usize, const DIGEST_ELEMS: usize>
    MerkleTreeMmcs<P, PW, H, C, N, DIGEST_ELEMS>
where
    P: PackedValue,
    PW: PackedValue,
    H: CryptographicHasher<P::Value, [PW::Value; DIGEST_ELEMS]> + Sync,
    C: PseudoCompressionFunction<[PW::Value; DIGEST_ELEMS], N> + Sync,
    PW::Value: Copy + Default + Eq + Send + Sync,
    P::Value: Send + Sync,
{
    /// Plan a streamed pruned multiproof over a `height x width` matrix.
    ///
    /// See [`StreamingMmcs::streaming_opener`]; this is that method's body.
    ///
    /// # Panics
    ///
    /// - `cap_height` must be zero (a cap of one root), the shape the binary
    ///   PCS commits.
    /// - The tree must be binary (`N == 2`) and the height a power of two.
    pub fn streaming_opener(
        &self,
        height: usize,
        width: usize,
        indices: &[usize],
    ) -> MerkleStreamingOpener<P, PW, H, C, N, DIGEST_ELEMS> {
        assert_eq!(
            self.cap_height(), 0,
            "the streamed opener plans a cap-height-zero tree"
        );
        assert_eq!(
            N, 2,
            "the streamed opener plans a binary frontier, not a {N}-ary one"
        );
        let (hash, compress) = self.hash_and_compress();
        MerkleStreamingOpener::new(hash.clone(), compress.clone(), width, height, indices)
    }
}

impl<P, PW, H, C, const N: usize, const DIGEST_ELEMS: usize> StreamingMmcs<P::Value>
    for MerkleTreeMmcs<P, PW, H, C, N, DIGEST_ELEMS>
where
    P: PackedValue,
    PW: PackedValue,
    H: CryptographicHasher<P::Value, [PW::Value; DIGEST_ELEMS]>
        + CryptographicHasher<P, [PW; DIGEST_ELEMS]>
        + Sync
        + Clone,
    C: PseudoCompressionFunction<[PW::Value; DIGEST_ELEMS], N>
        + PseudoCompressionFunction<[PW; DIGEST_ELEMS], N>
        + Sync
        + Clone,
    PW::Value: Copy + Default + Eq + Send + Sync,
    P::Value: Send + Sync + Clone,
    [PW::Value; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    type Opener = MerkleStreamingOpener<P, PW, H, C, N, DIGEST_ELEMS>;

    fn streaming_opener(&self, height: usize, width: usize, indices: &[usize]) -> Self::Opener {
        Self::streaming_opener(self, height, width, indices)
    }
}
