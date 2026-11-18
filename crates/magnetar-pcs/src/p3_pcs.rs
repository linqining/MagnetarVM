//! Multilinear PCS over the binary tower via `p3-binary-pcs`.
//!
//! Ligerito 0.8.0 exposes Boolean-index claims only. Plonky3's binary PCS
//! provides real multilinear point openings, which is what the Spartan
//! reduction needs.

use magnetar_constraint::F2_128;
use magnetar_proof::{Pcs, ProofError};
use p3_binary_field::{BinaryChallenger, BinaryField128, TowerLevel};
use p3_binary_pcs::{
    BinaryPcs, BinaryPcsConfig, BinaryPcsConfigError, BinaryPcsParams, BinaryPcsProof,
    BinaryPcsProverData,
};
use p3_challenger::HashChallenger;
use p3_commit::{Mmcs, MultilinearPcs};
use p3_field::PrimeCharacteristicRing;
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::point::Point;
use p3_sumcheck::layout::{Layout, SuffixProver, Table, Witness};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher, SerializingHasher};

type F = BinaryField128;

/// Env-gated sub-stage profiling for the P3 wrapper (`MAGNETAR_PROFILE_PCS=1`).
///
/// One env lookup per PCS entry point (never inside a row loop); the timers only
/// report, they do not change the prover's behaviour or output.
fn profile_pcs() -> bool {
    std::env::var_os("MAGNETAR_PROFILE_PCS").is_some()
}

/// Keccak-256 truncated to 16 bytes. The Merkle tree over the codeword is the
/// largest single term of the prover peak (`2^(N+12)` B at 32 B per node), so
/// halving the digest halves it; 128-bit collision resistance still exceeds
/// the protocol's 100-bit target.
#[derive(Clone)]
pub struct Keccak256Hash16;

impl CryptographicHasher<u8, [u8; 16]> for Keccak256Hash16 {
    const LANES: usize = <Keccak256Hash as CryptographicHasher<u8, [u8; 32]>>::LANES;

    fn hash_iter<I>(&self, input: I) -> [u8; 16]
    where
        I: IntoIterator<Item = u8>,
    {
        let digest = Keccak256Hash.hash_iter(input);
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest[..16]);
        out
    }

    fn hash_iter_slices<'a, I>(&self, input: I) -> [u8; 16]
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let digest = Keccak256Hash.hash_iter_slices(input);
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest[..16]);
        out
    }

    /// Hash equal-length messages in groups through the wide Keccak backend.
    ///
    /// The trait default hashes one message per call, which leaves the batched
    /// (NEON/SHA3, AVX2, ...) drivers of `Keccak256Hash` unused. Every Merkle
    /// node of every PCS commitment is a 16-byte leaf or a 32-byte pair, so the
    /// whole commitment's hashing went down the scalar sponge path even though
    /// `LANES` reports the wide backend. Truncation is applied after the batch,
    /// so the digests are the same bytes as the scalar path.
    fn hash_many(&self, input: &[u8], out: &mut [[u8; 16]]) {
        if out.is_empty() {
            return;
        }
        // The batch contract: one equal-length message per requested digest.
        assert!(
            input.len().is_multiple_of(out.len()),
            "batched hash input must split evenly across the digests"
        );
        let message_len = input.len() / out.len();
        // A chunk small enough to stay out of the allocator's way; the wide
        // backend pulls far more speed from a full lane group than from depth.
        const DIGEST_CHUNK: usize = 256;
        let mut wide = vec![[0u8; 32]; out.len().min(DIGEST_CHUNK)];
        let mut consumed = 0usize;
        for digests in out.chunks_mut(DIGEST_CHUNK) {
            let count = digests.len();
            let bytes = &input[consumed..consumed + count * message_len];
            consumed += count * message_len;
            Keccak256Hash.hash_many(bytes, &mut wide[..count]);
            for (digest, wide_digest) in digests.iter_mut().zip(&wide[..count]) {
                digest.copy_from_slice(&wide_digest[..16]);
            }
        }
    }
}

pub(crate) type P3Hash = SerializingHasher<Keccak256Hash16>;
pub(crate) type P3Compress = CompressionFunctionFromHasher<Keccak256Hash16, 2, 16>;
pub(crate) type P3Mmcs = MerkleTreeMmcs<F, u8, P3Hash, P3Compress, 2, 16>;
type P3Challenger = BinaryChallenger<F, HashChallenger<u8, Keccak256Hash, 32>>;
type P3PcsBackend = BinaryPcs<F, F, P3Mmcs, P3Mmcs>;
type P3Proof = BinaryPcsProof<F, F, P3Mmcs, P3Mmcs>;
pub type P3Cap = <P3Mmcs as Mmcs<F>>::Commitment;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct P3Commitment {
    pub cap: P3Cap,
    pub num_variables: usize,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct P3Opening {
    pub commitment: P3Commitment,
    pub proof: P3Proof,
}

/// One commitment to a packed batch of equally sized columns.
///
/// The columns are stacked into the PCS layout, so the commitment and its
/// opening proof are shared by every column. `num_variables` is the local
/// arity of a column; `stacked_variables` is the arity of the stacked
/// polynomial after slot selectors are added.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct P3BatchCommitment {
    pub cap: P3Cap,
    pub num_variables: usize,
    pub stacked_variables: usize,
    pub num_columns: usize,
}

/// A batch commitment whose codeword and Merkle tree are retained for opening.
pub struct P3CommittedBatch {
    pub commitment: P3BatchCommitment,
    backend: P3PcsBackend,
    data: BinaryPcsProverData<F, F, P3Mmcs>,
    challenger: P3Challenger,
}

/// One PCS opening proof covering every column and every point in a batch.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct P3BatchOpening {
    pub commitment: P3BatchCommitment,
    pub proof: P3Proof,
}

impl std::fmt::Debug for P3BatchOpening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P3BatchOpening")
            .field("commitment", &self.commitment)
            .field(
                "proof_bytes",
                &bincode::serialize(&self.proof).map(|b| b.len()),
            )
            .finish()
    }
}

/// A point and the columns opened there.
#[derive(Clone, Debug)]
pub struct P3BatchPoint {
    pub point: Vec<F2_128>,
    pub columns: Vec<usize>,
}

/// Batch-column backend for `magnetar_proof::BatchedRingSwitch`.
///
/// It commits several equally tall columns as one batch (one cap) and opens all
/// of them at one point with a single proof, which is what the batched
/// ring-switch needs for its packed address-bit columns.
#[derive(Clone, Debug)]
pub struct P3BatchColumnPcs {
    pub pcs: P3BinaryPcs,
}

impl P3BatchColumnPcs {
    pub fn new(pcs: P3BinaryPcs) -> Self {
        Self { pcs }
    }
}

impl magnetar_proof::BatchColumnPcs for P3BatchColumnPcs {
    type Commitment = P3BatchCommitment;
    type Opening = P3BatchOpening;

    fn commit_columns(
        &self,
        columns: &[Vec<F2_128>],
    ) -> Result<Self::Commitment, ProofError> {
        self.pcs.commit_batch(columns)
    }

    fn open_columns_at(
        &self,
        columns: &[Vec<F2_128>],
        point: &[F2_128],
        known: Option<&Self::Commitment>,
    ) -> Result<Self::Opening, ProofError> {
        let points = [P3BatchPoint {
            point: point.to_vec(),
            columns: (0..columns.len()).collect(),
        }];
        match known {
            Some(commitment) => self
                .pcs
                .open_batch_with_cap(columns, &points, &commitment.cap),
            None => self.pcs.open_batch(columns, &points),
        }
    }

    fn verify_columns_at(
        &self,
        _commitment: &Self::Commitment,
        point: &[F2_128],
        values: &[F2_128],
        opening: &Self::Opening,
    ) -> Result<bool, ProofError> {
        let points = [P3BatchPoint {
            point: point.to_vec(),
            columns: (0..values.len()).collect(),
        }];
        self.pcs
            .verify_batch(opening, &points, std::slice::from_ref(&values.to_vec()))
    }

    fn commitment_bytes(&self, commitment: &Self::Commitment) -> Vec<u8> {
        bincode::serialize(commitment).unwrap_or_default()
    }
}

/// Shape of one source table inside a mosaic commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct P3MosaicTableShape {
    pub num_variables: usize,
    pub num_columns: usize,
}

/// A commitment to several source tables of different arities.
///
/// The tables are stacked into one PCS polynomial, so one commitment and one
/// opening argument cover every table and every point. Local table points are
/// lifted by the P3 stacked layout.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct P3MosaicCommitment {
    pub cap: P3Cap,
    pub tables: Vec<P3MosaicTableShape>,
    pub stacked_variables: usize,
    #[serde(default)]
    pub binding: [u8; 32],
}

/// One PCS opening proof covering every mosaic table and point.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct P3MosaicOpening {
    pub commitment: P3MosaicCommitment,
    pub proof: P3Proof,
}

impl std::fmt::Debug for P3MosaicOpening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P3MosaicOpening")
            .field("commitment", &self.commitment)
            .field(
                "proof_bytes",
                &bincode::serialize(&self.proof).map(|b| b.len()),
            )
            .finish()
    }
}

/// Source columns of one table in a mosaic commitment.
#[derive(Clone, Debug)]
pub struct P3MosaicTable {
    pub columns: Vec<Vec<F2_128>>,
}

/// A local opening point owned by one mosaic table.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct P3MosaicPoint {
    pub table: usize,
    pub point: Vec<F2_128>,
    pub columns: Vec<usize>,
    /// Columns evaluated through the repeat-last successor view at the same point.
    pub next_columns: Vec<usize>,
}

impl std::fmt::Debug for P3Opening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P3Opening")
            .field("commitment", &self.commitment)
            .field(
                "proof_bytes",
                &bincode::serialize(&self.proof).map(|b| b.len()),
            )
            .finish()
    }
}

/// Multilinear PCS over the 128-bit binary tower.
#[derive(Clone, Copy, Debug)]
pub struct P3BinaryPcs {
    pub security_level: usize,
    pub log_inv_rate: usize,
    pub pow_bits: usize,
    pub log_folding_factor: usize,
}

impl Default for P3BinaryPcs {
    fn default() -> Self {
        Self::new(100)
    }
}

impl P3BinaryPcs {
    pub fn new(security_level: usize) -> Self {
        Self {
            security_level,
            log_inv_rate: 2,
            pow_bits: 4,
            log_folding_factor: 1,
        }
    }

    pub fn with_params(
        security_level: usize,
        log_inv_rate: usize,
        pow_bits: usize,
        log_folding_factor: usize,
    ) -> Self {
        Self {
            security_level,
            log_inv_rate,
            pow_bits,
            log_folding_factor,
        }
    }

    fn mmcs() -> P3Mmcs {
        P3Mmcs::new(
            P3Hash::new(Keccak256Hash16),
            P3Compress::new(Keccak256Hash16),
            0,
        )
    }

    fn challenger() -> P3Challenger {
        P3Challenger::from_hasher(Vec::new(), Keccak256Hash)
    }

    fn backend_with(
        num_variables: usize,
        security_level: usize,
        log_inv_rate: usize,
        pow_bits: usize,
        log_folding_factor: usize,
    ) -> Result<P3PcsBackend, ProofError> {
        let params = BinaryPcsParams {
            log_inv_rate,
            pow_bits,
            security_level,
        };
        let build = |params: BinaryPcsParams| {
            BinaryPcsConfig::try_new_with_folding::<F, F>(num_variables, params, log_folding_factor)
        };
        let config = match build(params) {
            Ok(config) => config,
            // A target above what the binary field can deliver at this domain
            // size is unreachable at any query count. Large witnesses (RV64
            // 2^16 packs the witness into 2^22 field elements) hit this cap, so
            // clamp the target to the achievable ceiling. Prover and verifier
            // derive the schedule from the same domain size and therefore agree.
            Err(BinaryPcsConfigError::SecurityLevelExceedsFieldCapacity { max, .. }) => {
                build(BinaryPcsParams {
                    security_level: max,
                    ..params
                })
                .map_err(|error| ProofError::Pcs(error.to_string()))?
            }
            Err(error) => return Err(ProofError::Pcs(error.to_string())),
        };
        if profile_pcs() {
            eprintln!(
                "pcs backend: vars={num_variables} security={} rate={} pow={} fold={} queries={}",
                config.security_level(),
                config.log_inv_rate(),
                config.pow_bits(),
                config.log_folding_factor(),
                config.num_queries()
            );
        }
        P3PcsBackend::new(config, Self::mmcs(), Self::mmcs())
            .map_err(|error| ProofError::Pcs(error.to_string()))
    }

    /// Shape of a single-column table without materialising the column.
    ///
    /// `table` copies the values into the P3 field type, so callers that only
    /// need the arity used to pay a full copy (64 MiB at RV64 `2^16`) and then
    /// drop it before the real conversion inside `commit_with`. This returns
    /// the same `(logical, pcs_log)` pair with no allocation.
    fn table_shape(values: &[F2_128]) -> Result<(usize, usize), ProofError> {
        if values.is_empty() || !values.len().is_power_of_two() {
            return Err(ProofError::NotPowerOfTwo(values.len()));
        }
        let logical = values.len().trailing_zeros() as usize;
        let pcs_log = logical.max(1);
        Ok((logical, pcs_log))
    }

    fn table(values: &[F2_128]) -> Result<(Table<F>, usize, usize), ProofError> {
        if values.is_empty() || !values.len().is_power_of_two() {
            return Err(ProofError::NotPowerOfTwo(values.len()));
        }
        let logical = values.len().trailing_zeros() as usize;
        let mut converted: Vec<F> = values
            .iter()
            .map(|value| F::from_repr(value.value()))
            .collect();
        let pcs_log = if values.len() == 1 {
            converted.push(F::ZERO);
            1
        } else {
            logical
        };
        Ok((
            Table::new(RowMajorMatrix::new(converted, 1usize << pcs_log)),
            logical,
            pcs_log,
        ))
    }

    fn protocol(num_variables: usize) -> OpeningProtocol {
        OpeningProtocol::new(vec![TableSpec::new(
            TableShape::new(num_variables, 1),
            vec![OpeningBatch::new(vec![0], Vec::new())],
        )])
    }

    fn point(point: &[F2_128]) -> Point<F> {
        if point.is_empty() {
            return Point::new(vec![F::ZERO]);
        }
        Point::new(
            point
                .iter()
                .rev()
                .map(|value| F::from_repr(value.value()))
                .collect::<Vec<_>>(),
        )
    }

    fn commit_with(
        backend: &P3PcsBackend,
        values: &[F2_128],
        challenger: &mut P3Challenger,
    ) -> Result<(P3Cap, p3_binary_pcs::BinaryPcsProverData<F, F, P3Mmcs>), ProofError> {
        let (table, _, _) = Self::table(values)?;
        let witness = SuffixProver::<F, F>::new_witness(vec![table], 0);
        backend
            .commit(witness, challenger)
            .map_err(|error| ProofError::Pcs(error.to_string()))
    }

    /// Whether the batch commit path is forced for a same-binary memory A/B.
    ///
    /// Streaming is the default: it returns the same cap (pinned by the
    /// `streaming` module's tests) while keeping only the message, one codeword
    /// coset and a logarithmic Merkle frontier live.
    ///
    /// The switch follows the repo's env-flag convention: *any* value of
    /// `MAGNETAR_LEGACY_PCS_COMMIT`, including `0` or an empty string, forces
    /// the batch path. There is no unit test for the branch itself because the
    /// variable is process-wide and would race the parallel test runner; the
    /// equivalence it selects between is covered by
    /// `streaming_root_matches_pcs_commit_entry_points`, and the switch is
    /// exercised by `p3_stage_probe` and `paper_unified_bench` A/Bs.
    fn legacy_commit() -> bool {
        std::env::var_os("MAGNETAR_LEGACY_PCS_COMMIT").is_some()
    }

    /// Whether the streamed opening path is selected (`MAGNETAR_STREAM_PCS_OPEN=1`).
    ///
    /// The streamed opening re-derives the codeword from the stacked message one
    /// coset at a time, so neither the codeword nor its Merkle tree is
    /// materialised (see `open_at_streaming` in the vendored binary PCS). It is
    /// byte-identical but costs one extra codeword re-encode and one extra leaf
    /// hash pass today (the cap is recomputed inside the opening), so it stays
    /// opt-in for memory-bound runs: at `2^17` it takes the peak footprint from
    /// 3.02 to 2.10 GiB for ~+4 % prove CPU, and at `2^16` the peak floor is the
    /// selected product phase, so it moves no peak there.
    fn stream_open() -> bool {
        std::env::var_os("MAGNETAR_STREAM_PCS_OPEN").is_some()
    }

    /// The stacked message for a witness: one cell per stacked evaluation.
    fn stacked_message(
        witness: &Witness<F>,
        stacked_variables: usize,
    ) -> Result<Vec<F>, ProofError> {
        let len = 1usize
            .checked_shl(stacked_variables as u32)
            .ok_or_else(|| ProofError::Pcs("stacked variable count overflows usize".into()))?;
        let mut message = F::zero_vec(len);
        <SuffixProver<F, F> as Layout<F, F>>::write_message(witness, 0, &mut message);
        Ok(message)
    }

    /// Whether the out-of-core message spill is enabled.
    fn oot_enabled() -> bool {
        std::env::var_os("MAGNETAR_OOT_PCS").is_some()
    }

    /// Spill the stacked message to a temp file and map it read-only.
    ///
    /// The streamed opening re-encodes the message three times (cap, fold,
    /// query), so the message is the largest anonymous transient. Mapping it
    /// from a file makes those pages file-backed (reclaimable) instead of
    /// anonymous, which is the first out-of-core step; the bytes are identical,
    /// so the proof is unchanged.
    fn spill_message(message: &[F]) -> Result<(std::fs::File, std::path::PathBuf, *mut u8, usize), ProofError> {
        use std::io::Write;
        let path = std::env::temp_dir().join(format!(
            "magnetar-oot-{}-{}.bin",
            std::process::id(),
            message.len()
        ));
        let mut file = std::fs::File::create(&path)
            .map_err(|error| ProofError::Pcs(format!("oot spill create: {error}")))?;
        let mut buffer = Vec::with_capacity(1 << 20);
        for chunk in message.chunks(1 << 16) {
            buffer.clear();
            for value in chunk {
                buffer.extend_from_slice(&value.to_repr().to_le_bytes());
            }
            file.write_all(&buffer)
                .map_err(|error| ProofError::Pcs(format!("oot spill write: {error}")))?;
        }
        file.flush()
            .map_err(|error| ProofError::Pcs(format!("oot spill flush: {error}")))?;
        drop(file);
        // `File::create` opens write-only; mmap(PROT_READ) needs a read handle.
        let file = std::fs::File::open(&path)
            .map_err(|error| ProofError::Pcs(format!("oot spill reopen: {error}")))?;
        let len = message.len() * core::mem::size_of::<F>();
        let ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                std::os::unix::io::AsRawFd::as_raw_fd(&file),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(ProofError::Pcs("oot spill mmap failed".into()));
        }
        Ok((file, path, ptr as *mut u8, len))
    }

    /// Streamed commit + streamed opening.
    ///
    /// Returns the same `(cap, proof)` the retained path returns: the cap comes
    /// from [`crate::streaming::streamed_codeword_root`] over the same message,
    /// it is observed into a fresh transcript exactly as `commit` observes the
    /// batch root, and the vendored `open_at_streaming` runs the same fold and
    /// query phases over a streamed re-encode.
    fn streamed_open(
        &self,
        backend: &P3PcsBackend,
        witness: Witness<F>,
        stacked_variables: usize,
        protocol: &OpeningProtocol,
        points: &[Point<F>],
        known_cap: Option<P3Cap>,
    ) -> Result<(P3Cap, P3Proof), ProofError> {
        let message = Self::stacked_message(&witness, stacked_variables)?;
        let cap = match known_cap {
            Some(cap) => cap,
            None => crate::streaming::streamed_codeword_root(&message, 1, self.log_inv_rate),
        };
        let mut challenger = Self::challenger();
        backend.observe_commitment(&cap, &mut challenger);
        let proof = if Self::oot_enabled() {
            let (file, path, ptr, len) = Self::spill_message(&message)?;
            let mapped: &[F] = unsafe { core::slice::from_raw_parts(ptr as *const F, message.len()) };
            let result = backend
                .open_at_streaming(witness, mapped, 0, protocol, points, &mut challenger)
                .map_err(|error| ProofError::Pcs(error.to_string()));
            unsafe {
                libc::munmap(ptr as *mut libc::c_void, len);
            }
            drop(file);
            let _ = std::fs::remove_file(&path);
            result?
        } else {
            backend
                .open_at_streaming(witness, &message, 0, protocol, points, &mut challenger)
                .map_err(|error| ProofError::Pcs(error.to_string()))?
        };
        Ok((cap, proof))
    }

    /// Root-only commitment of a stacked witness: streamed encode + incremental root.
    ///
    /// The commit-only entry points (`Pcs::commit`, `commit_batch`,
    /// `commit_mosaic`) drop the prover data immediately, so the full codeword
    /// and the full Merkle tree they used to build are pure transients.
    fn streamed_commit(
        &self,
        witness: &Witness<F>,
        stacked_variables: usize,
    ) -> Result<P3Cap, ProofError> {
        // The retained path asserts this against the backend config; streaming
        // never builds that config, so check the same invariant here and report
        // it as an error rather than letting `write_message` catch a bad shape.
        if witness.num_variables() != stacked_variables {
            return Err(ProofError::Pcs(format!(
                "streamed commit: witness has {} variables but the schedule stacks {stacked_variables}",
                witness.num_variables()
            )));
        }
        let len = 1usize
            .checked_shl(stacked_variables as u32)
            .ok_or_else(|| ProofError::Pcs("stacked variable count overflows usize".into()))?;
        let mut owned;
        let message: &[F] = match <SuffixProver<F, F> as Layout<F, F>>::borrowed_message(witness) {
            Some(values) if values.len() == len => values,
            _ => {
                owned = F::zero_vec(len);
                <SuffixProver<F, F> as Layout<F, F>>::write_message(witness, 0, &mut owned);
                &owned
            }
        };
        // A codeword row is `1 << folding` cells and binary-pcs pins
        // `const FOLDING: usize = 0` (vendor/plonky3/binary-pcs/src/prover.rs),
        // so the base message is one column wide. The small-shape entry-point
        // test pins this against the retained path, which would diverge first
        // if that constant ever changed.
        Ok(crate::streaming::streamed_codeword_root(
            message,
            1,
            self.log_inv_rate,
        ))
    }

    /// Open a single column against a commitment the caller already owns.
    ///
    /// The streamed opening re-derives the codeword from the message, so it can
    /// bind the given cap instead of recomputing it; the retained path ignores
    /// the supplied cap and recomputes, so both return the retained path's
    /// byte-identical proof.
    pub fn open_with_cap(
        &self,
        values: &[F2_128],
        point: &[F2_128],
        cap: &P3Cap,
    ) -> Result<P3Opening, ProofError> {
        if !Self::stream_open() {
            return <Self as Pcs>::open(self, values, point);
        }
        let (num_variables, pcs_log) = Self::table_shape(values)?;
        if point.len() != num_variables {
            return Err(ProofError::PointLength {
                expected: num_variables,
                actual: point.len(),
            });
        }
        let backend = Self::backend_with(
            pcs_log,
            self.security_level,
            self.log_inv_rate,
            self.pow_bits,
            self.log_folding_factor,
        )?;
        let (table, _, _) = Self::table(values)?;
        let witness = SuffixProver::<F, F>::new_witness(vec![table], 0);
        let (cap, proof) = self.streamed_open(
            &backend,
            witness,
            pcs_log,
            &Self::protocol(pcs_log),
            core::slice::from_ref(&Self::point(point)),
            Some(cap.clone()),
        )?;
        Ok(P3Opening {
            commitment: P3Commitment { cap, num_variables },
            proof,
        })
    }

    /// Open a batch against a commitment the caller already owns.
    pub fn open_batch_with_cap(
        &self,
        columns: &[Vec<F2_128>],
        points: &[P3BatchPoint],
        cap: &P3Cap,
    ) -> Result<P3BatchOpening, ProofError> {
        if !Self::stream_open() {
            return self.open_batch(columns, points);
        }
        let (table, num_variables, num_columns) = Self::batch_table(columns)?;
        let stacked_variables = Self::stacked_variables(num_variables, num_columns);
        let protocol = Self::batch_protocol(num_variables, num_columns, points)?;
        let backend = Self::backend_with(
            stacked_variables,
            self.security_level,
            self.log_inv_rate,
            self.pow_bits,
            self.log_folding_factor,
        )?;
        let witness = SuffixProver::<F, F>::new_witness(vec![table], 0);
        let p3_points = points
            .iter()
            .map(|point| Self::point(&point.point))
            .collect::<Vec<_>>();
        let (cap, proof) = self.streamed_open(
            &backend,
            witness,
            stacked_variables,
            &protocol,
            &p3_points,
            Some(cap.clone()),
        )?;
        Ok(P3BatchOpening {
            commitment: P3BatchCommitment {
                cap,
                num_variables,
                stacked_variables,
                num_columns,
            },
            proof,
        })
    }

    /// Open a mosaic against a commitment the caller already owns.
    pub fn open_mosaic_with_cap(
        &self,
        tables: &[P3MosaicTable],
        points: &[P3MosaicPoint],
        cap: &P3Cap,
    ) -> Result<P3MosaicOpening, ProofError> {
        if !Self::stream_open() {
            return self.open_mosaic(tables, points);
        }
        let mut p3_tables = Vec::with_capacity(tables.len());
        let mut shapes = Vec::with_capacity(tables.len());
        for table in tables {
            let (p3_table, shape) = Self::mosaic_table(table)?;
            p3_tables.push(p3_table);
            shapes.push(shape);
        }
        let stacked_variables = Self::mosaic_stacked_variables(&shapes)?;
        let (protocol, p3_points) = Self::mosaic_schedule(&shapes, points)?;
        let backend = Self::backend_with(
            stacked_variables,
            self.security_level,
            self.log_inv_rate,
            self.pow_bits,
            self.log_folding_factor,
        )?;
        let witness = SuffixProver::<F, F>::new_witness(p3_tables, 0);
        let (cap, proof) = self.streamed_open(
            &backend,
            witness,
            stacked_variables,
            &protocol,
            &p3_points,
            Some(cap.clone()),
        )?;
        Ok(P3MosaicOpening {
            commitment: P3MosaicCommitment {
                cap,
                tables: shapes,
                stacked_variables,
                binding: [0u8; 32],
            },
            proof,
        })
    }

    fn batch_table(columns: &[Vec<F2_128>]) -> Result<(Table<F>, usize, usize), ProofError> {
        if columns.is_empty() {
            return Err(ProofError::DimensionMismatch);
        }
        let len = columns[0].len();
        if len < 2 || !len.is_power_of_two() {
            return Err(ProofError::NotPowerOfTwo(len));
        }
        if columns.iter().any(|column| column.len() != len) {
            return Err(ProofError::DimensionMismatch);
        }
        let logical = len.trailing_zeros() as usize;
        let mut converted = Vec::with_capacity(len * columns.len());
        for column in columns {
            // Extend straight from the iterator: the intermediate `collect` used
            // to allocate and copy every column a second time.
            converted.extend(column.iter().map(|value| F::from_repr(value.value())));
        }
        Ok((
            Table::new(RowMajorMatrix::new(converted, len)),
            logical,
            columns.len(),
        ))
    }

    fn stacked_variables(num_variables: usize, num_columns: usize) -> usize {
        let slots = num_columns.next_power_of_two();
        num_variables + slots.trailing_zeros() as usize
    }

    fn batch_protocol(
        num_variables: usize,
        num_columns: usize,
        points: &[P3BatchPoint],
    ) -> Result<OpeningProtocol, ProofError> {
        let mut schedule = Vec::with_capacity(points.len());
        for (index, point) in points.iter().enumerate() {
            if point.point.len() != num_variables {
                return Err(ProofError::PointLength {
                    expected: num_variables,
                    actual: point.point.len(),
                });
            }
            if point.columns.is_empty() || point.columns.iter().any(|column| *column >= num_columns)
            {
                return Err(ProofError::Pcs(format!(
                    "batch point {index} names an invalid column"
                )));
            }
            let mut seen = point.columns.clone();
            seen.sort_unstable();
            seen.dedup();
            if seen.len() != point.columns.len() {
                return Err(ProofError::Pcs(format!(
                    "batch point {index} repeats a column"
                )));
            }
            schedule.push(OpeningBatch::new(point.columns.clone(), Vec::new()));
        }
        Ok(OpeningProtocol::new(vec![TableSpec::new(
            TableShape::new(num_variables, num_columns),
            schedule,
        )]))
    }

    /// Commit to a set of equally sized columns with a single PCS commitment.
    pub fn commit_batch(&self, columns: &[Vec<F2_128>]) -> Result<P3BatchCommitment, ProofError> {
        let (table, num_variables, num_columns) = Self::batch_table(columns)?;
        let stacked_variables = Self::stacked_variables(num_variables, num_columns);
        let backend = Self::backend_with(
            stacked_variables,
            self.security_level,
            self.log_inv_rate,
            self.pow_bits,
            self.log_folding_factor,
        )?;
        let witness = SuffixProver::<F, F>::new_witness(vec![table], 0);
        let cap = if Self::legacy_commit() {
            let mut challenger = Self::challenger();
            backend
                .commit(witness, &mut challenger)
                .map_err(|error| ProofError::Pcs(error.to_string()))?
                .0
        } else {
            self.streamed_commit(&witness, stacked_variables)?
        };
        Ok(P3BatchCommitment {
            cap,
            num_variables,
            stacked_variables,
            num_columns,
        })
    }

    /// Commit a batch and retain the committed prover data for a later opening.
    /// `open_batch` re-encodes and re-hashes the table; a caller that needs the
    /// commitment before sampling its opening points (the usual Fiat-Shamir
    /// order) can use this to encode once.
    pub fn commit_batch_prepared(
        &self,
        columns: &[Vec<F2_128>],
    ) -> Result<P3CommittedBatch, ProofError> {
        let profile = profile_pcs();
        let tables_started = std::time::Instant::now();
        let (table, num_variables, num_columns) = Self::batch_table(columns)?;
        let tables_time = tables_started.elapsed();
        let stacked_variables = Self::stacked_variables(num_variables, num_columns);
        let backend = Self::backend_with(
            stacked_variables,
            self.security_level,
            self.log_inv_rate,
            self.pow_bits,
            self.log_folding_factor,
        )?;
        let mut challenger = Self::challenger();
        let witness = SuffixProver::<F, F>::new_witness(vec![table], 0);
        let commit_started = std::time::Instant::now();
        let (cap, data) = backend
            .commit(witness, &mut challenger)
            .map_err(|error| ProofError::Pcs(error.to_string()))?;
        let commit_time = commit_started.elapsed();
        if profile {
            let cells = num_columns as u64 * (1u64 << num_variables);
            eprintln!(
                "pcs commit_batch_prepared: tables {tables_time:?} commit {commit_time:?} cells={cells} stacked_vars={stacked_variables}"
            );
        }
        Ok(P3CommittedBatch {
            commitment: P3BatchCommitment {
                cap,
                num_variables,
                stacked_variables,
                num_columns,
            },
            backend,
            data,
            challenger,
        })
    }

    /// Open a prepared batch; the codeword and Merkle tree are reused.
    ///
    /// Takes the prepared batch by value: the prover data (the retained codeword and
    /// Merkle tree) moves into the opening instead of being deep-copied. The local
    /// Twist PCS commits one batch and opens it once, so nothing needs the copy.
    pub fn open_batch_prepared(
        &self,
        prepared: P3CommittedBatch,
        points: &[P3BatchPoint],
    ) -> Result<P3BatchOpening, ProofError> {
        let profile = profile_pcs();
        let protocol = Self::batch_protocol(
            prepared.commitment.num_variables,
            prepared.commitment.num_columns,
            points,
        )?;
        let p3_points = points
            .iter()
            .map(|point| Self::point(&point.point))
            .collect::<Vec<_>>();
        let mut challenger = prepared.challenger.clone();
        let open_started = std::time::Instant::now();
        let proof = prepared
            .backend
            .open_at(prepared.data, &protocol, &p3_points, &mut challenger)
            .map_err(|error| ProofError::Pcs(error.to_string()))?;
        let open_time = open_started.elapsed();
        if profile {
            eprintln!(
                "pcs open_batch_prepared: open_at {open_time:?} points={}",
                points.len()
            );
        }
        Ok(P3BatchOpening {
            commitment: prepared.commitment,
            proof,
        })
    }

    /// Open every listed column at each point with one PCS opening argument.
    pub fn open_batch(
        &self,
        columns: &[Vec<F2_128>],
        points: &[P3BatchPoint],
    ) -> Result<P3BatchOpening, ProofError> {
        let (table, num_variables, num_columns) = Self::batch_table(columns)?;
        if columns.len() != num_columns {
            return Err(ProofError::DimensionMismatch);
        }
        let stacked_variables = Self::stacked_variables(num_variables, num_columns);
        let protocol = Self::batch_protocol(num_variables, num_columns, points)?;
        let backend = Self::backend_with(
            stacked_variables,
            self.security_level,
            self.log_inv_rate,
            self.pow_bits,
            self.log_folding_factor,
        )?;
        let witness = SuffixProver::<F, F>::new_witness(vec![table], 0);
        let p3_points = points
            .iter()
            .map(|point| Self::point(&point.point))
            .collect::<Vec<_>>();
        let (cap, proof) = if !Self::stream_open() {
            let mut challenger = Self::challenger();
            let (cap, data) = backend
                .commit(witness, &mut challenger)
                .map_err(|error| ProofError::Pcs(error.to_string()))?;
            let proof = backend
                .open_at(data, &protocol, &p3_points, &mut challenger)
                .map_err(|error| ProofError::Pcs(error.to_string()))?;
            (cap, proof)
        } else {
            self.streamed_open(&backend, witness, stacked_variables, &protocol, &p3_points, None)?
        };
        Ok(P3BatchOpening {
            commitment: P3BatchCommitment {
                cap,
                num_variables,
                stacked_variables,
                num_columns,
            },
            proof,
        })
    }

    /// Verify a batched opening against the values expected at each point.
    pub fn verify_batch(
        &self,
        opening: &P3BatchOpening,
        points: &[P3BatchPoint],
        values: &[Vec<F2_128>],
    ) -> Result<bool, ProofError> {
        let commitment = &opening.commitment;
        if points.len() != values.len() {
            return Ok(false);
        }
        let expected_stacked =
            Self::stacked_variables(commitment.num_variables, commitment.num_columns);
        if commitment.stacked_variables != expected_stacked {
            return Ok(false);
        }
        let protocol =
            match Self::batch_protocol(commitment.num_variables, commitment.num_columns, points) {
                Ok(protocol) => protocol,
                Err(_) => return Ok(false),
            };
        let backend = Self::backend_with(
            commitment.stacked_variables,
            self.security_level,
            self.log_inv_rate,
            self.pow_bits,
            self.log_folding_factor,
        )?;
        let mut challenger = Self::challenger();
        backend.observe_commitment(&commitment.cap, &mut challenger);
        let p3_points = points
            .iter()
            .map(|point| Self::point(&point.point))
            .collect::<Vec<_>>();
        let Ok(evals) = backend.verify_at(
            &commitment.cap,
            &opening.proof,
            &protocol,
            &p3_points,
            &mut challenger,
        ) else {
            return Ok(false);
        };
        if evals.len() != values.len() {
            return Ok(false);
        }
        for ((batch, expected), point) in evals.iter().zip(values).zip(points) {
            if expected.len() != point.columns.len()
                || batch.current().len() != expected.len()
                || batch
                    .current()
                    .iter()
                    .zip(expected)
                    .any(|(observed, value)| *observed != F::from_repr(value.value()))
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn mosaic_table(table: &P3MosaicTable) -> Result<(Table<F>, P3MosaicTableShape), ProofError> {
        let (p3_table, num_variables, num_columns) = Self::batch_table(&table.columns)?;
        Ok((
            p3_table,
            P3MosaicTableShape {
                num_variables,
                num_columns,
            },
        ))
    }

    fn mosaic_stacked_variables(shapes: &[P3MosaicTableShape]) -> Result<usize, ProofError> {
        if shapes.is_empty() {
            return Err(ProofError::DimensionMismatch);
        }
        let mut total = 0usize;
        for shape in shapes {
            let rows = 1usize
                .checked_shl(shape.num_variables as u32)
                .ok_or_else(|| ProofError::Pcs("mosaic table arity overflows usize".into()))?;
            let cells = rows
                .checked_mul(shape.num_columns)
                .ok_or_else(|| ProofError::Pcs("mosaic table cells overflow usize".into()))?;
            total = total
                .checked_add(cells)
                .ok_or_else(|| ProofError::Pcs("mosaic cell count overflows usize".into()))?;
        }
        if total == 0 {
            return Err(ProofError::Pcs("mosaic has no cells".into()));
        }
        Ok(total.next_power_of_two().trailing_zeros() as usize)
    }

    fn mosaic_schedule(
        shapes: &[P3MosaicTableShape],
        points: &[P3MosaicPoint],
    ) -> Result<(OpeningProtocol, Vec<Point<F>>), ProofError> {
        let mut per_table: Vec<Vec<usize>> = vec![Vec::new(); shapes.len()];
        let mut last_table = 0usize;
        for (index, point) in points.iter().enumerate() {
            if point.table >= shapes.len() {
                return Err(ProofError::Pcs(format!(
                    "mosaic point {index} names an invalid table"
                )));
            }
            if point.table < last_table {
                return Err(ProofError::Pcs(
                    "mosaic points must be grouped by table".into(),
                ));
            }
            last_table = point.table;
            let shape = shapes[point.table];
            if point.point.len() != shape.num_variables {
                return Err(ProofError::PointLength {
                    expected: shape.num_variables,
                    actual: point.point.len(),
                });
            }
            if point.columns.is_empty()
                || point
                    .columns
                    .iter()
                    .any(|column| *column >= shape.num_columns)
            {
                return Err(ProofError::Pcs(format!(
                    "mosaic point {index} names an invalid column"
                )));
            }
            let mut seen = point.columns.clone();
            seen.sort_unstable();
            seen.dedup();
            if seen.len() != point.columns.len() {
                return Err(ProofError::Pcs(format!(
                    "mosaic point {index} repeats a column"
                )));
            }
            per_table[point.table].push(index);
        }

        let mut ordered = Vec::with_capacity(points.len());
        let mut specs = Vec::with_capacity(shapes.len());
        for (table, shape) in shapes.iter().enumerate() {
            let mut schedule = Vec::with_capacity(per_table[table].len());
            for &index in &per_table[table] {
                schedule.push(OpeningBatch::new(
                    points[index].columns.clone(),
                    points[index].next_columns.clone(),
                ));
                ordered.push(Self::point(&points[index].point));
            }
            specs.push(TableSpec::new(
                TableShape::new(shape.num_variables, shape.num_columns),
                schedule,
            ));
        }
        Ok((OpeningProtocol::new(specs), ordered))
    }

    /// Commit to several tables of different arities with one PCS commitment.
    pub fn commit_mosaic(
        &self,
        tables: &[P3MosaicTable],
    ) -> Result<P3MosaicCommitment, ProofError> {
        let profile = profile_pcs();
        let tables_started = std::time::Instant::now();
        let mut p3_tables = Vec::with_capacity(tables.len());
        let mut shapes = Vec::with_capacity(tables.len());
        for table in tables {
            let (p3_table, shape) = Self::mosaic_table(table)?;
            p3_tables.push(p3_table);
            shapes.push(shape);
        }
        let tables_time = tables_started.elapsed();
        let stacked_variables = Self::mosaic_stacked_variables(&shapes)?;
        let backend = Self::backend_with(
            stacked_variables,
            self.security_level,
            self.log_inv_rate,
            self.pow_bits,
            self.log_folding_factor,
        )?;
        let witness = SuffixProver::<F, F>::new_witness(p3_tables, 0);
        let commit_started = std::time::Instant::now();
        let cap = if Self::legacy_commit() {
            let mut challenger = Self::challenger();
            backend
                .commit(witness, &mut challenger)
                .map_err(|error| ProofError::Pcs(error.to_string()))?
                .0
        } else {
            self.streamed_commit(&witness, stacked_variables)?
        };
        let commit_time = commit_started.elapsed();
        if profile {
            let cells: u64 = tables
                .iter()
                .map(|table| {
                    table
                        .columns
                        .first()
                        .map_or(0, |column| column.len() as u64)
                        * table.columns.len() as u64
                })
                .sum();
            eprintln!(
                "pcs commit_mosaic: tables {tables_time:?} commit {commit_time:?} tables={} cells={} stacked_vars={stacked_variables}",
                tables.len(),
                cells
            );
            // Per-table composition: which tables dominate, and how many of
            // their columns are pure bits (the (h)/(c) packing candidates).
            let mut packable = 0u64;
            for (index, table) in tables.iter().enumerate() {
                let rows = table.columns.first().map_or(0, |column| column.len());
                let columns = table.columns.len();
                let bit_columns = table
                    .columns
                    .iter()
                    .filter(|column| column.iter().all(|value| value.value() <= 1))
                    .count();
                let table_cells = rows as u64 * columns as u64;
                if bit_columns == columns && columns > 0 {
                    packable += table_cells;
                }
                eprintln!(
                    "pcs mosaic table {index}: rows={rows} cols={columns} cells={table_cells} bit_cols={bit_columns}/{columns}"
                );
            }
            eprintln!(
                "pcs mosaic packing: cells={cells} all-bit cells={packable} packed-total={} (if every all-bit table packs 128:1)",
                cells - packable + packable.div_ceil(128)
            );
        }
        Ok(P3MosaicCommitment {
            cap,
            tables: shapes,
            stacked_variables,
            binding: [0u8; 32],
        })
    }

    /// Open every mosaic table at its listed local points with one proof.
    pub fn open_mosaic(
        &self,
        tables: &[P3MosaicTable],
        points: &[P3MosaicPoint],
    ) -> Result<P3MosaicOpening, ProofError> {
        let profile = profile_pcs();
        let tables_started = std::time::Instant::now();
        let mut p3_tables = Vec::with_capacity(tables.len());
        let mut shapes = Vec::with_capacity(tables.len());
        for table in tables {
            let (p3_table, shape) = Self::mosaic_table(table)?;
            p3_tables.push(p3_table);
            shapes.push(shape);
        }
        let tables_time = tables_started.elapsed();
        let stacked_variables = Self::mosaic_stacked_variables(&shapes)?;
        let (protocol, p3_points) = Self::mosaic_schedule(&shapes, points)?;
        let backend = Self::backend_with(
            stacked_variables,
            self.security_level,
            self.log_inv_rate,
            self.pow_bits,
            self.log_folding_factor,
        )?;
        let witness = SuffixProver::<F, F>::new_witness(p3_tables, 0);
        let streamed = Self::stream_open();
        let open_started = std::time::Instant::now();
        let (cap, proof) = if !streamed {
            let mut challenger = Self::challenger();
            let (cap, data) = backend
                .commit(witness, &mut challenger)
                .map_err(|error| ProofError::Pcs(error.to_string()))?;
            let proof = backend
                .open_at(data, &protocol, &p3_points, &mut challenger)
                .map_err(|error| ProofError::Pcs(error.to_string()))?;
            (cap, proof)
        } else {
            self.streamed_open(&backend, witness, stacked_variables, &protocol, &p3_points, None)?
        };
        let open_time = open_started.elapsed();
        if profile {
            eprintln!(
                "pcs open_mosaic: tables {tables_time:?} open {open_time:?} tables={} points={} stacked_vars={stacked_variables} streamed={}",
                tables.len(),
                points.len(),
                streamed
            );
        }
        Ok(P3MosaicOpening {
            commitment: P3MosaicCommitment {
                cap,
                tables: shapes,
                stacked_variables,
                binding: [0u8; 32],
            },
            proof,
        })
    }

    /// Verify a mosaic opening against the values expected at each point.
    pub fn verify_mosaic(
        &self,
        opening: &P3MosaicOpening,
        points: &[P3MosaicPoint],
        values: &[Vec<F2_128>],
    ) -> Result<bool, ProofError> {
        if points.len() != values.len() {
            return Ok(false);
        }
        let commitment = &opening.commitment;
        let expected_stacked = match Self::mosaic_stacked_variables(&commitment.tables) {
            Ok(stacked) => stacked,
            Err(_) => return Ok(false),
        };
        if commitment.stacked_variables != expected_stacked {
            return Ok(false);
        }
        let (protocol, p3_points) = match Self::mosaic_schedule(&commitment.tables, points) {
            Ok(schedule) => schedule,
            Err(_) => return Ok(false),
        };
        let backend = Self::backend_with(
            commitment.stacked_variables,
            self.security_level,
            self.log_inv_rate,
            self.pow_bits,
            self.log_folding_factor,
        )?;
        let mut challenger = Self::challenger();
        backend.observe_commitment(&commitment.cap, &mut challenger);
        let Ok(evals) = backend.verify_at(
            &commitment.cap,
            &opening.proof,
            &protocol,
            &p3_points,
            &mut challenger,
        ) else {
            return Ok(false);
        };
        if evals.len() != values.len() {
            return Ok(false);
        }
        for ((batch, expected), point) in evals.iter().zip(values).zip(points) {
            let current_len = point.columns.len();
            let next_len = point.next_columns.len();
            if expected.len() != current_len + next_len
                || batch.current().len() != current_len
                || batch.next().len() != next_len
                || batch
                    .current()
                    .iter()
                    .chain(batch.next())
                    .zip(expected)
                    .any(|(observed, value)| *observed != F::from_repr(value.value()))
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl Pcs for P3BinaryPcs {
    type Commitment = P3Commitment;
    type Opening = P3Opening;

    fn commit(&self, values: &[F2_128]) -> Result<Self::Commitment, ProofError> {
        let profile = profile_pcs();
        let (num_variables, pcs_log) = Self::table_shape(values)?;
        let backend = Self::backend_with(
            pcs_log,
            self.security_level,
            self.log_inv_rate,
            self.pow_bits,
            self.log_folding_factor,
        )?;
        let legacy = Self::legacy_commit();
        let started = std::time::Instant::now();
        let cap = if legacy {
            let mut challenger = Self::challenger();
            Self::commit_with(&backend, values, &mut challenger)?.0
        } else {
            let (table, _, _) = Self::table(values)?;
            let witness = SuffixProver::<F, F>::new_witness(vec![table], 0);
            self.streamed_commit(&witness, pcs_log)?
        };
        if profile {
            eprintln!(
                "pcs commit: {:?} values={} pcs_log={pcs_log} streamed={}",
                started.elapsed(),
                values.len(),
                !legacy
            );
        }
        Ok(P3Commitment { cap, num_variables })
    }

    fn open(&self, values: &[F2_128], point: &[F2_128]) -> Result<Self::Opening, ProofError> {
        let profile = profile_pcs();
        let (num_variables, pcs_log) = Self::table_shape(values)?;
        if point.len() != num_variables {
            return Err(ProofError::PointLength {
                expected: num_variables,
                actual: point.len(),
            });
        }
        let backend = Self::backend_with(
            pcs_log,
            self.security_level,
            self.log_inv_rate,
            self.pow_bits,
            self.log_folding_factor,
        )?;
        let streamed = Self::stream_open();
        let open_started = std::time::Instant::now();
        let (cap, proof) = if !streamed {
            let mut challenger = Self::challenger();
            let (cap, data) = Self::commit_with(&backend, values, &mut challenger)?;
            let proof = backend
                .open_at(
                    data,
                    &Self::protocol(pcs_log),
                    core::slice::from_ref(&Self::point(point)),
                    &mut challenger,
                )
                .map_err(|error| ProofError::Pcs(error.to_string()))?;
            (cap, proof)
        } else {
            let (table, _, _) = Self::table(values)?;
            let witness = SuffixProver::<F, F>::new_witness(vec![table], 0);
            self.streamed_open(
                &backend,
                witness,
                pcs_log,
                &Self::protocol(pcs_log),
                core::slice::from_ref(&Self::point(point)),
                None,
            )?
        };
        let open_time = open_started.elapsed();
        if profile {
            eprintln!(
                "pcs open: {open_time:?} values={} pcs_log={pcs_log} streamed={}",
                values.len(),
                streamed
            );
        }
        Ok(P3Opening {
            commitment: P3Commitment { cap, num_variables },
            proof,
        })
    }

    fn open_with_commitment(
        &self,
        values: &[F2_128],
        point: &[F2_128],
        commitment: &Self::Commitment,
    ) -> Result<Self::Opening, ProofError> {
        self.open_with_cap(values, point, &commitment.cap)
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &[F2_128],
        value: F2_128,
        opening: &Self::Opening,
    ) -> Result<bool, ProofError> {
        if commitment.num_variables != opening.commitment.num_variables
            || commitment.cap != opening.commitment.cap
            || point.len() != commitment.num_variables
        {
            return Ok(false);
        }
        let pcs_log = commitment.num_variables.max(1);
        let backend = Self::backend_with(
            pcs_log,
            self.security_level,
            self.log_inv_rate,
            self.pow_bits,
            self.log_folding_factor,
        )?;
        let mut challenger = Self::challenger();
        backend.observe_commitment(&commitment.cap, &mut challenger);
        let Ok(evals) = backend.verify_at(
            &commitment.cap,
            &opening.proof,
            &Self::protocol(pcs_log),
            core::slice::from_ref(&Self::point(point)),
            &mut challenger,
        ) else {
            return Ok(false);
        };
        let expected = F::from_repr(value.value());
        Ok(evals
            .first()
            .and_then(|batch| batch.current().first())
            .is_some_and(|observed| *observed == expected))
    }

    fn commitment_bytes(&self, commitment: &Self::Commitment) -> Vec<u8> {
        bincode::serialize(commitment).unwrap_or_default()
    }
}

/// A PCS adapter that commits a primary vector together with auxiliary tables
/// and opens all of them in one P3 proof.
///
/// The primary vector is mosaic table 0 and opens at the single point of the
/// `Pcs` interface. Auxiliary points must name their absolute table indices
/// (`1..`); their expected values are supplied by the verifier.
#[derive(Clone, Debug)]
pub struct P3SharedPcs {
    pub security_level: usize,
    pub aux_tables: Vec<P3MosaicTable>,
    pub aux_points: Vec<P3MosaicPoint>,
    pub aux_values: Vec<Vec<F2_128>>,
}

impl P3SharedPcs {
    pub fn new(
        security_level: usize,
        aux_tables: Vec<P3MosaicTable>,
        aux_points: Vec<P3MosaicPoint>,
        aux_values: Vec<Vec<F2_128>>,
    ) -> Self {
        Self {
            security_level,
            aux_tables,
            aux_points,
            aux_values,
        }
    }

    fn pcs_for(bits: usize) -> P3BinaryPcs {
        if bits == 9 {
            P3BinaryPcs::with_params(100, 3, 16, 2)
        } else if bits == 12 {
            P3BinaryPcs::with_params(100, 3, 21, 2)
        } else if bits >= 4 {
            P3BinaryPcs::with_params(100, 4, 16, 3)
        } else {
            P3BinaryPcs::new(100)
        }
    }

    fn tables(&self, values: &[F2_128]) -> Vec<P3MosaicTable> {
        let mut tables = Vec::with_capacity(1 + self.aux_tables.len());
        tables.push(P3MosaicTable {
            columns: vec![values.to_vec()],
        });
        tables.extend(self.aux_tables.clone());
        tables
    }

    fn points(&self, point: &[F2_128]) -> Vec<P3MosaicPoint> {
        let mut points = Vec::with_capacity(1 + self.aux_points.len());
        points.push(P3MosaicPoint {
            table: 0,
            point: point.to_vec(),
            columns: vec![0],
            next_columns: Vec::new(),
        });
        points.extend(self.aux_points.clone());
        points
    }
}

impl Pcs for P3SharedPcs {
    type Commitment = P3MosaicCommitment;
    type Opening = P3MosaicOpening;

    fn commit(&self, values: &[F2_128]) -> Result<Self::Commitment, ProofError> {
        let tables = self.tables(values);
        let bits = tables
            .iter()
            .map(|table| table.columns[0].len().trailing_zeros() as usize)
            .max()
            .unwrap_or(0);
        Self::pcs_for(bits).commit_mosaic(&tables)
    }

    fn open(&self, values: &[F2_128], point: &[F2_128]) -> Result<Self::Opening, ProofError> {
        let tables = self.tables(values);
        let bits = tables
            .iter()
            .map(|table| table.columns[0].len().trailing_zeros() as usize)
            .max()
            .unwrap_or(0);
        Self::pcs_for(bits).open_mosaic(&tables, &self.points(point))
    }

    fn open_with_commitment(
        &self,
        values: &[F2_128],
        point: &[F2_128],
        commitment: &Self::Commitment,
    ) -> Result<Self::Opening, ProofError> {
        let tables = self.tables(values);
        let bits = tables
            .iter()
            .map(|table| table.columns[0].len().trailing_zeros() as usize)
            .max()
            .unwrap_or(0);
        Self::pcs_for(bits).open_mosaic_with_cap(
            &tables,
            &self.points(point),
            &commitment.cap,
        )
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &[F2_128],
        value: F2_128,
        opening: &Self::Opening,
    ) -> Result<bool, ProofError> {
        if opening.commitment != *commitment {
            return Ok(false);
        }
        let mut values = Vec::with_capacity(1 + self.aux_values.len());
        values.push(vec![value]);
        values.extend(self.aux_values.clone());
        Self::pcs_for(
            commitment
                .tables
                .iter()
                .map(|table| table.num_variables)
                .max()
                .unwrap_or(0),
        )
        .verify_mosaic(opening, &self.points(point), &values)
    }

    fn commitment_bytes(&self, commitment: &Self::Commitment) -> Vec<u8> {
        bincode::serialize(commitment).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    fn eval_at(values: &[F2_128], point: &[F2_128]) -> F2_128 {
        let mut folded = values.to_vec();
        for coordinate in point {
            let next = folded
                .chunks_exact(2)
                .map(|pair| pair[0] + *coordinate * (pair[1] - pair[0]))
                .collect::<Vec<_>>();
            folded = next;
        }
        folded[0]
    }

    #[test]
    fn mosaic_opens_a_twelve_column_table_with_repeated_points() {
        let shapes = [(1usize, 12usize), (1, 1), (5, 1), (1, 1), (4, 1)];
        let tables = shapes
            .iter()
            .map(|(variables, columns)| P3MosaicTable {
                columns: (0..*columns)
                    .map(|column| {
                        (0..(1usize << variables))
                            .map(|row| F2_128::from((row * 3 + column + 1) as u64))
                            .collect()
                    })
                    .collect(),
            })
            .collect::<Vec<_>>();
        let pcs = P3BinaryPcs::with_params(100, 2, 21, 2);
        pcs.commit_mosaic(&tables).unwrap();
        let point = |variables: usize| -> Vec<F2_128> {
            (0..variables)
                .map(|index| F2_128::from(index as u64 + 1))
                .collect()
        };
        let points = vec![
            P3MosaicPoint {
                table: 0,
                point: point(1),
                columns: (0..12).collect(),
                next_columns: Vec::new(),
            },
            P3MosaicPoint {
                table: 1,
                point: point(1),
                columns: vec![0],
                next_columns: Vec::new(),
            },
            P3MosaicPoint {
                table: 2,
                point: point(5),
                columns: vec![0],
                next_columns: Vec::new(),
            },
            P3MosaicPoint {
                table: 2,
                point: point(5),
                columns: vec![0],
                next_columns: Vec::new(),
            },
            P3MosaicPoint {
                table: 2,
                point: point(5),
                columns: vec![0],
                next_columns: Vec::new(),
            },
            P3MosaicPoint {
                table: 3,
                point: point(1),
                columns: vec![0],
                next_columns: Vec::new(),
            },
            P3MosaicPoint {
                table: 4,
                point: point(4),
                columns: vec![0],
                next_columns: Vec::new(),
            },
            P3MosaicPoint {
                table: 4,
                point: point(4),
                columns: vec![0],
                next_columns: Vec::new(),
            },
        ];
        let values = points
            .iter()
            .map(|point| {
                point
                    .columns
                    .iter()
                    .map(|column| eval_at(&tables[point.table].columns[*column], &point.point))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let opening = pcs.open_mosaic(&tables, &points).unwrap();
        let verified = pcs.verify_mosaic(&opening, &points, &values).unwrap();
        assert!(verified);
    }

    use super::*;
    use magnetar_proof::Mle;

    fn values(size: usize) -> Vec<F2_128> {
        (0..size)
            .map(|index| F2_128::from((index as u64).wrapping_mul(0x9e37_79b9)))
            .collect()
    }

    /// Pins the Merkle digest width: the tree and every path node scale with it
    /// and it was the largest single term of the prover peak (`2^16`: 1.52 GiB
    /// at 16 bytes against 2.01-2.61 GiB at 32 bytes).
    #[test]
    fn merkle_digest_is_sixteen_bytes() {
        // `P3Cap` is the 16-byte root plus `usize` metadata; a 32-byte digest
        // would make it 40. The tree and every path node scale with the digest,
        // and it was the largest single term of the prover peak (`2^16`:
        // 1.52 GiB at 16 bytes against 2.01-2.61 GiB at 32 bytes).
        assert_eq!(core::mem::size_of::<P3Cap>(), 24);
    }

    #[test]
    fn p3_field_multiplication_matches_magnetar_tower() {
        for index in 0..64u128 {
            let a = F2_128::from((index.wrapping_mul(0x0123_4567_89ab_cdef)) & 0xffff);
            let b = F2_128::from((index.wrapping_mul(0xfedc_ba98_7654_3210)) & 0xffff);
            let pa = F::from_repr(a.value());
            let pb = F::from_repr(b.value());
            let product = F::as_repr_slice(&[pa * pb])[0];
            assert_eq!((a * b).value(), product, "index {index}");
        }
    }

    #[test]
    fn p3_multilinear_opening_round_trips() {
        let pcs = P3BinaryPcs::new(100);
        let values = values(1 << 10);
        let point: Vec<F2_128> = (0..10u64).map(|index| F2_128::from(index & 1)).collect();
        let opening = pcs.open(&values, &point).unwrap();
        let commitment = opening.commitment.clone();
        let value = magnetar_proof::Mle::new(values.clone())
            .unwrap()
            .eval(&point)
            .unwrap();
        match pcs.verify(&commitment, &point, value, &opening) {
            Ok(valid) => assert!(valid, "value mismatch"),
            Err(error) => panic!("verify error: {error}"),
        }

        let mut wrong_point = point.clone();
        wrong_point[0] = wrong_point[0] + F2_128::from(1u64);
        assert!(!pcs
            .verify(&commitment, &wrong_point, value, &opening)
            .unwrap());
        assert!(!pcs
            .verify(&commitment, &point, value + F2_128::from(1u64), &opening)
            .unwrap());
    }

    #[test]
    fn p3_batch_opening_covers_columns_and_points_once() {
        let pcs = P3BinaryPcs::new(100);
        let columns = vec![values(1 << 10), values(1 << 10), values(1 << 10)];
        let points = vec![
            P3BatchPoint {
                point: (0..10u64).map(|index| F2_128::from(index & 1)).collect(),
                columns: vec![0, 2],
            },
            P3BatchPoint {
                point: (0..10u64)
                    .map(|index| F2_128::from((index + 1) & 1))
                    .collect(),
                columns: vec![1],
            },
        ];
        let opening = pcs.open_batch(&columns, &points).unwrap();
        let expected: Vec<Vec<F2_128>> = points
            .iter()
            .map(|batch| {
                batch
                    .columns
                    .iter()
                    .map(|column| {
                        magnetar_proof::Mle::new(columns[*column].clone())
                            .unwrap()
                            .eval(&batch.point)
                            .unwrap()
                    })
                    .collect()
            })
            .collect();
        assert!(pcs.verify_batch(&opening, &points, &expected).unwrap());

        let mut bad = expected.clone();
        bad[0][0] = bad[0][0] + F2_128::from(1u64);
        assert!(!pcs.verify_batch(&opening, &points, &bad).unwrap());

        let mut bad_point = points.clone();
        bad_point[1].point[0] = bad_point[1].point[0] + F2_128::from(1u64);
        assert!(!pcs.verify_batch(&opening, &bad_point, &expected).unwrap());
    }

    #[test]
    fn p3_mosaic_stacks_different_arities_into_one_opening() {
        let pcs = P3BinaryPcs::new(100);
        let primary = values(1 << 9);
        let aux = vec![values(1 << 10), values(1 << 10)];
        let tables = vec![
            P3MosaicTable {
                columns: vec![primary.clone()],
            },
            P3MosaicTable {
                columns: aux.clone(),
            },
        ];
        let commitment = pcs.commit_mosaic(&tables).unwrap();
        assert_eq!(commitment.tables.len(), 2);
        assert_eq!(commitment.tables[0].num_variables, 9);
        assert_eq!(commitment.tables[1].num_variables, 10);

        let primary_point = (0..9u64)
            .map(|index| F2_128::from(index & 1))
            .collect::<Vec<_>>();
        let aux_point = (0..10u64)
            .map(|index| F2_128::from((index + 1) & 1))
            .collect::<Vec<_>>();
        let points = vec![
            P3MosaicPoint {
                table: 0,
                point: primary_point.clone(),
                columns: vec![0],
                next_columns: Vec::new(),
            },
            P3MosaicPoint {
                table: 1,
                point: aux_point.clone(),
                columns: vec![0, 1],
                next_columns: Vec::new(),
            },
        ];
        let opening = pcs.open_mosaic(&tables, &points).unwrap();
        let expected = vec![
            vec![magnetar_proof::Mle::new(primary.clone())
                .unwrap()
                .eval(&primary_point)
                .unwrap()],
            aux.iter()
                .map(|column| {
                    magnetar_proof::Mle::new(column.clone())
                        .unwrap()
                        .eval(&aux_point)
                        .unwrap()
                })
                .collect(),
        ];
        assert!(pcs.verify_mosaic(&opening, &points, &expected).unwrap());

        let mut bad = expected.clone();
        bad[1][1] = bad[1][1] + F2_128::from(1u64);
        assert!(!pcs.verify_mosaic(&opening, &points, &bad).unwrap());
    }

    #[test]
    fn p3_mosaic_successor_view_matches_shifted_mle() {
        let pcs = P3BinaryPcs::new(100);
        let values = values(1 << 8);
        let table = P3MosaicTable {
            columns: vec![values.clone()],
        };
        let point: Vec<F2_128> = (0..8u64)
            .map(|index| F2_128::from((index * 7 + 3) & 1))
            .collect();
        let current = magnetar_proof::Mle::new(values.clone())
            .unwrap()
            .eval(&point)
            .unwrap();
        let mut shifted = values[1..].to_vec();
        shifted.push(*values.last().unwrap());
        let next = magnetar_proof::Mle::new(shifted)
            .unwrap()
            .eval(&point)
            .unwrap();
        let points = vec![P3MosaicPoint {
            table: 0,
            point: point.clone(),
            columns: vec![0],
            next_columns: vec![0],
        }];
        let opening = pcs
            .open_mosaic(core::slice::from_ref(&table), &points)
            .unwrap();
        assert!(pcs
            .verify_mosaic(&opening, &points, &[vec![current, next]])
            .unwrap());
    }

    #[test]
    fn p3_shared_pcs_batches_primary_and_auxiliary_claims() {
        let primary = values(1 << 9);
        let aux = values(1 << 10);
        let primary_point: Vec<F2_128> = (0..9u64).map(|index| F2_128::from(index & 1)).collect();
        let aux_point: Vec<F2_128> = (0..10u64)
            .map(|index| F2_128::from((index + 1) & 1))
            .collect();
        let aux_value = magnetar_proof::Mle::new(aux.clone())
            .unwrap()
            .eval(&aux_point)
            .unwrap();
        let pcs = P3SharedPcs::new(
            100,
            vec![P3MosaicTable {
                columns: vec![aux.clone()],
            }],
            vec![P3MosaicPoint {
                table: 1,
                point: aux_point.clone(),
                columns: vec![0],
                next_columns: Vec::new(),
            }],
            vec![vec![aux_value]],
        );
        let primary_value = magnetar_proof::Mle::new(primary.clone())
            .unwrap()
            .eval(&primary_point)
            .unwrap();
        let commitment = pcs.commit(&primary).unwrap();
        let opening = pcs.open(&primary, &primary_point).unwrap();
        assert!(pcs
            .verify(&commitment, &primary_point, primary_value, &opening)
            .unwrap());
        assert!(!pcs
            .verify(
                &commitment,
                &primary_point,
                primary_value + F2_128::from(1u64),
                &opening,
            )
            .unwrap());
    }
    #[test]
    fn shared_commitment_matches_mosaic_commitment() {
        let z = values(8);
        let aux = vec![P3MosaicTable {
            columns: vec![values(4), values(4)],
        }];
        let shared = P3SharedPcs::new(90, aux.clone(), Vec::new(), Vec::new());
        let shared_commitment = shared.commit(&z).unwrap();
        let mut tables = vec![P3MosaicTable { columns: vec![z] }];
        tables.extend(aux);
        let mosaic_commitment = P3BinaryPcs::new(90).commit_mosaic(&tables).unwrap();
        assert_eq!(
            bincode::serialize(&shared_commitment).unwrap(),
            bincode::serialize(&mosaic_commitment).unwrap()
        );
    }
    #[test]
    fn router_shape_plus_large_table_round_trips() {
        let pcs = P3BinaryPcs::with_params(100, 4, 16, 3);
        let mut router = Vec::with_capacity(276);
        for column in 0..276usize {
            router.push(
                (0..8)
                    .map(|row| F2_128::from(((row * 17 + column * 5 + 1) & 1) as u64))
                    .collect::<Vec<_>>(),
            );
        }
        let mut large = Vec::with_capacity(3);
        for column in 0..3usize {
            large.push(
                (0..512)
                    .map(|row| F2_128::from(((row * 13 + column * 7 + 2) & 1) as u64))
                    .collect::<Vec<_>>(),
            );
        }
        let tables = vec![
            P3MosaicTable {
                columns: router.clone(),
            },
            P3MosaicTable {
                columns: large.clone(),
            },
        ];
        let point_a = vec![F2_128::from(1u64), F2_128::from(0u64), F2_128::from(1u64)];
        let point_link = vec![F2_128::from(0u64), F2_128::from(1u64), F2_128::from(1u64)];
        let point_b = (0..9)
            .map(|bit| F2_128::from(((bit * 3 + 1) & 1) as u64))
            .collect::<Vec<_>>();
        let groups = [201usize, 128, 3, 4, 1, 2, 3, 4, 1, 2, 64, 64];
        let mut points = Vec::new();
        let mut values = Vec::new();
        let mut cursor = 0usize;
        for (group, size) in groups.into_iter().enumerate() {
            let row_point = if group == 0 { &point_link } else { &point_a };
            let columns = (0..size)
                .map(|offset| (cursor + offset) % 276)
                .collect::<Vec<_>>();
            cursor += size;
            let expected = columns
                .iter()
                .map(|column| {
                    Mle::new(router[*column].clone())
                        .unwrap()
                        .eval(row_point)
                        .unwrap()
                })
                .collect::<Vec<_>>();
            points.push(P3MosaicPoint {
                table: 0,
                point: row_point.clone(),
                columns,
                next_columns: Vec::new(),
            });
            values.push(expected);
        }
        points.push(P3MosaicPoint {
            table: 1,
            point: point_b.clone(),
            columns: vec![0, 1, 2],
            next_columns: Vec::new(),
        });
        values.push(
            (0..3)
                .map(|column| {
                    Mle::new(large[column].clone())
                        .unwrap()
                        .eval(&point_b)
                        .unwrap()
                })
                .collect(),
        );
        let commitment = pcs.commit_mosaic(&tables).unwrap();
        let opening = pcs.open_mosaic(&tables, &points).unwrap();
        assert!(pcs.verify_mosaic(&opening, &points, &values).unwrap());
        let _ = commitment;
    }

    /// The streamed opening must reproduce the retained path byte for byte: the
    /// same commitment root, and a proof whose transcript, fold batches and
    /// query openings are identical.
    #[test]
    fn streamed_opening_matches_the_retained_path() {
        for bits in [8usize, 10] {
            for rate in [1usize, 2] {
                let pcs = P3BinaryPcs::with_params(100, rate, 16, 1);
                let values = values(1 << bits);
                let point = (0..bits as u64).map(F2_128::from).collect::<Vec<_>>();
                let protocol = P3BinaryPcs::protocol(bits);
                let at = [P3BinaryPcs::point(&point)];

                // Retained path: materialise the codeword and its Merkle tree.
                let backend = P3BinaryPcs::backend_with(
                    bits,
                    pcs.security_level,
                    pcs.log_inv_rate,
                    pcs.pow_bits,
                    pcs.log_folding_factor,
                )
                .unwrap();
                let mut challenger = P3BinaryPcs::challenger();
                let (retained_cap, data) =
                    P3BinaryPcs::commit_with(&backend, &values, &mut challenger).unwrap();
                let retained_proof = backend
                    .open_at(data, &protocol, &at, &mut challenger)
                    .unwrap();

                // Streamed path: the same message, re-derived one coset at a time.
                let (table, _, _) = P3BinaryPcs::table(&values).unwrap();
                let witness = SuffixProver::<F, F>::new_witness(vec![table], 0);
                let message = P3BinaryPcs::stacked_message(&witness, bits).unwrap();
                let streamed_cap =
                    crate::streaming::streamed_codeword_root(&message, 1, rate);
                let mut streamed_challenger = P3BinaryPcs::challenger();
                backend.observe_commitment(&streamed_cap, &mut streamed_challenger);
                let streamed_proof = backend
                    .open_at_streaming(
                        witness,
                        &message,
                        0,
                        &protocol,
                        &at,
                        &mut streamed_challenger,
                    )
                    .unwrap();

                assert_eq!(retained_cap, streamed_cap, "cap bits={bits} rate={rate}");
                assert_eq!(
                    bincode::serialize(&retained_proof).unwrap(),
                    bincode::serialize(&streamed_proof).unwrap(),
                    "proof bytes bits={bits} rate={rate}"
                );

                // The streamed proof still verifies, against the streamed cap.
                let mut verifier = P3BinaryPcs::challenger();
                backend.observe_commitment(&streamed_cap, &mut verifier);
                let evals = backend
                    .verify_at(&streamed_cap, &streamed_proof, &protocol, &at, &mut verifier)
                    .unwrap();
                assert!(!evals.is_empty());
            }
        }
    }
}


    #[test]
    fn ring_switch_claims_round_trip_without_pcs_opening() {
        use magnetar_proof::{BatchedRingSwitch, PackedBits};
        let bits = PackedBits::from_bools(
            &(0..(1usize << 12)).map(|index| index % 5 == 0).collect::<Vec<_>>(),
        );
        let point: Vec<F2_128> = (0..12)
            .map(|bit| F2_128::from((bit * 7 + 3) as u64))
            .collect();
        let backend = P3BatchColumnPcs::new(P3BinaryPcs::with_params(100, 2, 21, 2));
        let switch = BatchedRingSwitch::new(backend);
        let (claims, _ry, proof) = switch.open_claims(&[bits], &point).expect("open claims");
        let verified = switch
            .verify_claims(&point, &claims, &proof)
            .expect("verify claims")
            .expect("claims accepted");
        assert!(switch.finish_claims(&verified));
        // A tampered packed value is rejected by the final check.
        let mut tampered = proof.clone();
        tampered.packed_values[0] = tampered.packed_values[0] + F2_128::from(1u64);
        let verified = switch
            .verify_claims(&point, &claims, &tampered)
            .expect("verify claims")
            .expect("claims accepted");
        assert!(!switch.finish_claims(&verified));
    }
#[cfg(test)]
mod batched_ring_switch_tests {
    use super::{P3BatchColumnPcs, P3BinaryPcs};
    use magnetar_proof::{
        BatchColumnPcs, BatchedRingSwitch, PackedBits, eval_bits_mle,
    };

    const LOG_BITS: usize = 12;
    const COLUMNS: usize = 5;

    fn fixture() -> (
        BatchedRingSwitch<P3BatchColumnPcs>,
        P3BatchColumnPcs,
        Vec<PackedBits>,
        Vec<Vec<bool>>,
        Vec<magnetar_constraint::F2_128>,
    ) {
        let len = 1usize << LOG_BITS;
        let point: Vec<magnetar_constraint::F2_128> = (0..LOG_BITS)
            .map(|bit| magnetar_constraint::F2_128::from(((bit * 11 + 5) % 2) as u64))
            .collect();
        let bit_columns: Vec<Vec<bool>> = (0..COLUMNS)
            .map(|column| {
                (0..len)
                    .map(|cycle| (cycle.wrapping_mul(17) + column * 13 + cycle / 128) % 3 == 0)
                    .collect()
            })
            .collect();
        let packed: Vec<PackedBits> = bit_columns
            .iter()
            .map(|bits| PackedBits::from_bools(bits))
            .collect();
        let pcs = P3BatchColumnPcs::new(P3BinaryPcs::with_params(100, 2, 21, 2));
        (
            BatchedRingSwitch::new(pcs.clone()),
            pcs,
            packed,
            bit_columns,
            point,
        )
    }

    fn commit(
        backend: &P3BatchColumnPcs,
        bit_columns: &[Vec<bool>],
    ) -> P3BatchColumnPcsCommitment {
        let packed_columns: Vec<Vec<magnetar_constraint::F2_128>> = bit_columns
            .iter()
            .map(|bits| {
                bits.chunks(128)
                    .map(|chunk| {
                        let mut word = 0u128;
                        for (index, bit) in chunk.iter().enumerate() {
                            if *bit {
                                word |= 1u128 << index;
                            }
                        }
                        magnetar_constraint::F2_128::from(word)
                    })
                    .collect()
            })
            .collect();
        backend.commit_columns(&packed_columns).expect("commit")
    }

    type P3BatchColumnPcsCommitment = <P3BatchColumnPcs as BatchColumnPcs>::Commitment;

    #[test]
    fn batched_ring_switch_proves_every_column() {
        let (batched, backend, packed, bit_columns, point) = fixture();
        let commitment = commit(&backend, &bit_columns);
        let (claims, opening) = batched
            .open(&packed, &point, Some(&commitment))
            .expect("open");
        assert_eq!(claims.len(), COLUMNS);
        for (column, claim) in claims.iter().enumerate() {
            assert_eq!(
                *claim,
                eval_bits_mle(&bit_columns[column], &point).expect("mle"),
                "column {column} claim must be its bit MLE"
            );
        }
        assert!(batched
            .verify(&commitment, &point, &claims, &opening)
            .expect("verify"));

        // A wrong claim is refused.
        let mut tampered = claims.clone();
        tampered[2] = tampered[2] + magnetar_constraint::F2_128::from(1u64);
        assert!(!batched
            .verify(&commitment, &point, &tampered, &opening)
            .expect("verify"));

        // A wrong packed value is refused.
        let mut tampered_opening = opening.clone();
        tampered_opening.packed_values[1] =
            tampered_opening.packed_values[1] + magnetar_constraint::F2_128::from(1u64);
        assert!(!batched
            .verify(&commitment, &point, &claims, &tampered_opening)
            .expect("verify"));
    }

    #[test]
    fn batched_ring_switch_rejects_a_foreign_commitment() {
        let (batched, backend, packed, bit_columns, point) = fixture();
        let commitment = commit(&backend, &bit_columns);
        let (claims, opening) = batched
            .open(&packed, &point, Some(&commitment))
            .expect("open");
        let mut other_bits = bit_columns.clone();
        other_bits[0][0] = !other_bits[0][0];
        let other = commit(&backend, &other_bits);
        assert!(!batched
            .verify(&other, &point, &claims, &opening)
            .expect("verify"));
    }
}
