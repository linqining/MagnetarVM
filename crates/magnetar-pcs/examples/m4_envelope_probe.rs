//! M4 feasibility demo: what a 64-bit committed alphabet and a smaller
//! (bit-packed) mosaic message do to the streamed PCS's peak envelope.
//!
//! The paper envelope is 6.4 GiB at RV64 `2^22` cycles. The current snapshot
//! measures 5.74 GiB at `2^19` and ~7.66 GiB RSS at `2^20`, so the question for
//! M4 is whether the architecture can shrink enough at `2^22`. Two candidate
//! levers are measured here on the *real* streamed commit + streamed opening
//! path, without changing the protocol:
//!
//! 1. **Committed alphabet.** The base codeword is a `BinaryField128` column
//!    today. A `BinaryField64` base halves every message/codeword buffer; the
//!    challenge field stays 128-bit. The vendored `binary-pcs` already supports
//!    that pairing, and the streamed opening added in this tree is generic over
//!    the base alphabet, so the demo can commit and open a 64-bit witness for
//!    real.
//! 2. **Message size.** The mosaic message is `next_pow2(cells)`; the (h)/(c)
//!    routes shrink `cells` by bit-packing committed bit tables. The demo cannot
//!    change the protocol, so it varies the PCS arity (cells) instead, which has
//!    exactly the same memory effect, and reports the per-cell coefficients so
//!    the 2^22 projection can be composed.
//!
//! Run:
//! ```sh
//! cargo build --release -p magnetar-pcs --example m4_envelope_probe
//! CASES=small target/release/examples/m4_envelope_probe
//! CASES=target target/release/examples/m4_envelope_probe
//! ```
//!
//! `CASES=small` runs `2^20`-cell cases so the host survives; `CASES=target`
//! runs the largest cases that fit a 36 GiB host, one at a time.

use std::time::Instant;

use magnetar_pcs::p3_pcs::Keccak256Hash16;
use p3_binary_dft::EncodableLevel;
use p3_binary_field::{BinaryChallenger, BinaryField128, BinaryField64, TowerLevel};
use p3_binary_pcs::{BinaryPcs, BinaryPcsConfig, BinaryPcsParams};
use p3_challenger::HashChallenger;
use p3_commit::{Encoder, MultilinearPcs};
use p3_field::PrimeCharacteristicRing;
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::point::Point;
use p3_sumcheck::layout::{Layout, SuffixProver, Table};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
use p3_symmetric::{
    CompressionFunctionFromHasher, CryptographicHasher, MerkleCap, PseudoCompressionFunction,
    SerializingHasher,
};

/// Keccak-256 truncated to 16 bytes, the PCS digest of this tree.
type Digest = [u8; 16];
type Hash = SerializingHasher<Keccak256Hash16>;
type Compress = CompressionFunctionFromHasher<Keccak256Hash16, 2, 16>;

/// One `MerkleTreeMmcs` over field `F`.
type MTree<F> = MerkleTreeMmcs<F, u8, Hash, Compress, 2, 16>;

/// The transcript challenger over one field.
type Challenger<F> = BinaryChallenger<F, HashChallenger<u8, Keccak256Hash, 32>>;

/// Rows one Merkle block hashes at a time (the production block size).
const BLOCK_LOG: usize = 15;

/// A field this demo can fill from a 128-bit seed, one element per index.
trait Seeded: TowerLevel {
    fn seeded(index: u128, seed: u128) -> Self;
}

impl Seeded for BinaryField128 {
    fn seeded(index: u128, seed: u128) -> Self {
        let bits = index
            .wrapping_mul(0x9e37_79b9_7f4a_7c15_9e37_79b9)
            .wrapping_add(seed)
            .wrapping_mul(0xd6e8_feb8_6659_fd93_4a1c_2f7b);
        Self::from_repr(bits)
    }
}

impl Seeded for BinaryField64 {
    fn seeded(index: u128, seed: u128) -> Self {
        let bits = index
            .wrapping_mul(0x9e37_79b9_7f4a_7c15_9e37_79b9)
            .wrapping_add(seed)
            .wrapping_mul(0xd6e8_feb8_6659_fd93_4a1c_2f7b);
        Self::from_repr(bits as u64)
    }
}

fn mtree<F>() -> MTree<F> {
    MTree::<F>::new(Hash::new(Keccak256Hash16), Compress::new(Keccak256Hash16), 0)
}

/// Peak RSS of this process (macOS: bytes; elsewhere KiB scaled).
fn peak_rss_bytes() -> u64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return 0;
    }
    let peak = usage.ru_maxrss as u64;
    #[cfg(not(target_os = "macos"))]
    let peak = peak.saturating_mul(1024);
    peak
}

/// Current `phys_footprint` (macOS), zero elsewhere.
fn footprint_bytes() -> u64 {
    #[cfg(target_os = "macos")]
    {
        let mut info: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
        let count: libc::mach_msg_type_number_t =
            (std::mem::size_of::<libc::rusage_info_v4>() / std::mem::size_of::<libc::c_int>())
                as libc::mach_msg_type_number_t;
        let _ = count;
        let status = unsafe {
            libc::proc_pid_rusage(
                libc::getpid(),
                libc::RUSAGE_INFO_V4,
                &mut info as *mut libc::rusage_info_v4 as *mut libc::rusage_info_t,
            )
        };
        if status == 0 {
            info.ri_phys_footprint
        } else {
            0
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        0
    }
}

/// Stream a codeword and return its Merkle cap, hashing one block subtree at a
/// time and keeping only a logarithmic frontier of completed roots.
///
/// This is the production `streaming.rs` root reduced to the monomorphic field
/// and MMCS the demo needs, so the measured peak includes the real encoding
/// buffers.
fn streamed_cap<F, E>(encoder: &E, message: &[F], log_inv_rate: usize) -> MerkleCap<F, Digest>
where
    F: TowerLevel + Send + Sync,
    E: Encoder<F>,
{
    let hash = Hash::new(Keccak256Hash16);
    let compress = Compress::new(Keccak256Hash16);
    let block_rows = 1usize << BLOCK_LOG;
    let mut pending: Vec<Option<Digest>> = Vec::new();
    let mut block: Vec<F> = Vec::with_capacity(block_rows);
    let mut roots = 0usize;

    let push_root = |root: Digest, pending: &mut Vec<Option<Digest>>, roots: &mut usize| {
        *roots += 1;
        let mut node = root;
        let mut level = 0;
        loop {
            if level == pending.len() {
                pending.push(None);
            }
            match pending[level].take() {
                None => {
                    pending[level] = Some(node);
                    return;
                }
                Some(left) => {
                    node = compress.compress([left, node]);
                    level += 1;
                }
            }
        }
    };

    let flush = |block: &mut Vec<F>,
                     pending: &mut Vec<Option<Digest>>,
                     roots: &mut usize| {
        if block.is_empty() {
            return;
        }
        let rows = block.len();
        let mut digests = vec![[0u8; 16]; rows];
        hash.hash_many(block, &mut digests);
        let mut len = rows;
        while len > 1 {
            let half = len / 2;
            let groups: Vec<[Digest; 2]> = (0..half)
                .map(|index| [digests[2 * index], digests[2 * index + 1]])
                .collect();
            compress.compress_many(&groups, &mut digests[..half]);
            len = half;
        }
        block.clear();
        let root = digests[0];
        push_root(root, pending, roots);
    };

    encoder.encode_batch_chunks(
        RowMajorMatrixView::new(message, 1),
        log_inv_rate,
        &mut |chunk| {
            for &symbol in chunk {
                block.push(symbol);
                if block.len() == block_rows {
                    flush(&mut block, &mut pending, &mut roots);
                }
            }
        },
    );
    flush(&mut block, &mut pending, &mut roots);
    assert!(roots.is_power_of_two(), "a codeword has 2^k leaf blocks");
    let root = pending
        .into_iter()
        .flatten()
        .next()
        .expect("a codeword has a root");
    MerkleCap::new(vec![root])
}

/// Build the PCS config, clamping the security target exactly as the magnetar
/// wrapper does when the domain cannot deliver it.
fn config_for<F, EF>(log_cells: usize, log_inv_rate: usize, folding: usize) -> BinaryPcsConfig
where
    F: p3_binary_dft::EncodableLevel,
    EF: TowerLevel,
{
    use p3_binary_pcs::BinaryPcsConfigError;
    let params = |security_level| BinaryPcsParams {
        log_inv_rate,
        pow_bits: 16,
        security_level,
    };
    match BinaryPcsConfig::try_new_with_folding::<F, EF>(log_cells, params(100), folding) {
        Ok(config) => config,
        Err(BinaryPcsConfigError::SecurityLevelExceedsFieldCapacity { max, .. }) => {
            BinaryPcsConfig::try_new_with_folding::<F, EF>(log_cells, params(max), folding)
                .expect("the clamped security level must be accepted")
        }
        Err(error) => panic!("pcs config rejected: {error:?}"),
    }
}

fn message_values<F: Seeded>(len: usize, seed: u64) -> Vec<F> {
    (0..len)
        .map(|index| F::seeded(index as u128, seed as u128))
        .collect()
}

fn point_of<F: Seeded>(len: usize) -> Point<F> {
    Point::new(
        (0..len)
            .map(|index| F::seeded(index as u128 + 1, 0x51ed_2701_9e37_79b9))
            .collect(),
    )
}

fn protocol(log_cells: usize) -> OpeningProtocol {
    OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(log_cells, 1),
        vec![OpeningBatch::new(vec![0], Vec::new())],
    )])
}

/// One measured case.
struct Case {
    name: &'static str,
    log_cells: usize,
    log_inv_rate: usize,
    folding: usize,
    wall_ms: f64,
    peak_rss_mib: f64,
    footprint_mib: f64,
    proof_bytes: usize,
    verified: bool,
}

/// Run the 128-bit-alphabet case with the streamed commit + streamed opening.
fn run_128(name: &'static str, log_cells: usize, log_inv_rate: usize, folding: usize) -> Case {
    type F = BinaryField128;
    let config = config_for::<F, F>(log_cells, log_inv_rate, folding);
    let pcs = BinaryPcs::<F, F, MTree<F>, MTree<F>>::new(config, mtree(), mtree()).unwrap();

    let table = Table::new(RowMajorMatrix::new(
        message_values::<F>(1usize << log_cells, 1),
        1usize << log_cells,
    ));
    let witness = SuffixProver::<F, F>::new_witness(vec![table], 0);
    let message = <SuffixProver<F, F> as Layout<F, F>>::borrowed_message(&witness)
        .map(<[F]>::to_vec)
        .unwrap_or_else(|| {
            let mut message = vec![F::ZERO; 1 << log_cells];
            <SuffixProver<F, F> as Layout<F, F>>::write_message(&witness, 0, &mut message);
            message
        });
    let encoder = <F as EncodableLevel>::Encoder::default();
    let point = point_of::<F>(log_cells);
    let started = Instant::now();
    let cap = streamed_cap(&encoder, &message, log_inv_rate);
    let mut challenger: Challenger<F> = Challenger::from_hasher(Vec::new(), Keccak256Hash);
    pcs.observe_commitment(&cap, &mut challenger);
    let protocol = protocol(log_cells);
    let proof = pcs
        .open_at_streaming(
            witness,
            &message,
            0,
            &protocol,
            std::slice::from_ref(&point),
            &mut challenger,
        )
        .unwrap();
    let wall_ms = started.elapsed().as_secs_f64() * 1000.0;
    let mut verifier: Challenger<F> = Challenger::from_hasher(Vec::new(), Keccak256Hash);
    pcs.observe_commitment(&cap, &mut verifier);
    pcs.verify_at(
        &cap,
        &proof,
        &protocol,
        std::slice::from_ref(&point),
        &mut verifier,
    )
    .expect("the 128-bit proof must verify");
    Case {
        name,
        log_cells,
        log_inv_rate,
        folding,
        wall_ms,
        peak_rss_mib: peak_rss_bytes() as f64 / 1048576.0,
        footprint_mib: footprint_bytes() as f64 / 1048576.0,
        proof_bytes: bincode::serialize(&proof).map(|bytes| bytes.len()).unwrap_or(0),
        verified: true,
    }
}

/// Run the 64-bit-alphabet case (128-bit challenges) with the same streamed
/// commit + streamed opening.
fn run_64(name: &'static str, log_cells: usize, log_inv_rate: usize, folding: usize) -> Case {
    type F = BinaryField64;
    type EF = BinaryField128;
    let config = config_for::<F, EF>(log_cells, log_inv_rate, folding);
    let pcs = BinaryPcs::<F, EF, MTree<F>, MTree<EF>>::new(config, mtree(), mtree()).unwrap();

    let table = Table::new(RowMajorMatrix::new(
        message_values::<F>(1usize << log_cells, 2),
        1usize << log_cells,
    ));
    let witness = SuffixProver::<F, EF>::new_witness(vec![table], 0);
    let message = <SuffixProver<F, EF> as Layout<F, EF>>::borrowed_message(&witness)
        .map(<[F]>::to_vec)
        .unwrap_or_else(|| {
            let mut message = vec![F::ZERO; 1 << log_cells];
            <SuffixProver<F, EF> as Layout<F, EF>>::write_message(&witness, 0, &mut message);
            message
        });
    let encoder = <F as EncodableLevel>::Encoder::default();
    let point = point_of::<EF>(log_cells);
    let started = Instant::now();
    let cap = streamed_cap(&encoder, &message, log_inv_rate);
    let mut challenger: Challenger<F> = Challenger::from_hasher(Vec::new(), Keccak256Hash);
    pcs.observe_commitment(&cap, &mut challenger);
    let protocol = protocol(log_cells);
    let proof = pcs
        .open_at_streaming(
            witness,
            &message,
            0,
            &protocol,
            std::slice::from_ref(&point),
            &mut challenger,
        )
        .unwrap();
    let wall_ms = started.elapsed().as_secs_f64() * 1000.0;
    let mut verifier: Challenger<F> = Challenger::from_hasher(Vec::new(), Keccak256Hash);
    pcs.observe_commitment(&cap, &mut verifier);
    pcs.verify_at(
        &cap,
        &proof,
        &protocol,
        std::slice::from_ref(&point),
        &mut verifier,
    )
    .expect("the 128-bit proof must verify");
    Case {
        name,
        log_cells,
        log_inv_rate,
        folding,
        wall_ms,
        peak_rss_mib: peak_rss_bytes() as f64 / 1048576.0,
        footprint_mib: footprint_bytes() as f64 / 1048576.0,
        proof_bytes: bincode::serialize(&proof).map(|bytes| bytes.len()).unwrap_or(0),
        verified: true,
    }
}

fn report(case: &Case) {
    let message_mib = (1u64 << case.log_cells) as f64
        * if case.name.contains("64-bit") {
            8.0
        } else {
            16.0
        }
        / 1048576.0;
    println!(
        "{name:<28} log={log:>2} rate_log={rate} fold={fold} message={message_mib:>8.1} MiB \
         wall={wall:>8.1} ms peak_rss={rss:>8.1} MiB footprint={fp:>8.1} MiB proof={proof:>8} B verified={verified}",
        name = case.name,
        log = case.log_cells,
        rate = case.log_inv_rate,
        fold = case.folding,
        wall = case.wall_ms,
        rss = case.peak_rss_mib,
        fp = case.footprint_mib,
        proof = case.proof_bytes,
        verified = case.verified,
    );
}

fn main() {
    let cases = std::env::var("CASES").unwrap_or_else(|_| "small".into());
    let rate = std::env::var("RATE_LOG")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2usize);
    let mut list = Vec::new();
    match cases.as_str() {
        // 2^20 cells: 16 MiB (128-bit) / 8 MiB (64-bit) message, the safe smoke set.
        "small" => {
            list.push(run_128("128-bit, 2^20 cells", 20, rate, 2));
            list.push(run_64("64-bit, 2^20 cells", 20, rate, 2));
            list.push(run_64("64-bit, 2^21 cells", 21, rate, 2));
        }
        // Goal-shaped: 2^27/2^28 cells, one case at a time.
        "target" => {
            list.push(run_128("128-bit, 2^26 cells", 26, rate, 2));
        }
        "target64" => {
            list.push(run_64("64-bit, 2^27 cells", 27, rate, 2));
        }
        // Equal-cell / equal-message-byte ladder: 128-bit at 2^22..2^24 cells
        // against 64-bit at 2^23..2^25 cells, so the two alphabets can be
        // compared at the same message bytes (and the 64-bit at the same cells).
        // Equal-cell comparison at 2^25 cells: the envelope question is the
        // peak for a fixed committed arity, so this is the direct A/B.
        "cells" => {
            list.push(run_128("128-bit, 2^25 cells", 25, rate, 2));
            list.push(run_64("64-bit, 2^25 cells", 25, rate, 2));
        }
        "scale" => {
            list.push(run_128("128-bit, 2^22 cells", 22, rate, 2));
            list.push(run_64("64-bit, 2^22 cells", 22, rate, 2));
            list.push(run_64("64-bit, 2^23 cells", 23, rate, 2));
            list.push(run_128("128-bit, 2^23 cells", 23, rate, 2));
            list.push(run_64("64-bit, 2^24 cells", 24, rate, 2));
            list.push(run_128("128-bit, 2^24 cells", 24, rate, 2));
        }
        "all" => {
            list.push(run_128("128-bit, 2^20 cells", 20, rate, 2));
            list.push(run_64("64-bit, 2^20 cells", 20, rate, 2));
            list.push(run_128("128-bit, 2^26 cells", 26, rate, 2));
            list.push(run_64("64-bit, 2^27 cells", 27, rate, 2));
        }
        other => {
            eprintln!("unknown CASES={other:?}; expected small, target, target64 or all");
            std::process::exit(2);
        }
    }
    for case in &list {
        report(case);
    }
}
