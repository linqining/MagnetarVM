//! M4c feasibility demo: out-of-core codeword cache.
//!
//! The streamed opening needs three passes over the message: commit (cap),
//! fold (round codewords), query (base rows + Merkle multiproof). Each pass
//! re-encodes the message, so the process peak is ~6x the message bytes
//! (`docs/M4_ENVELOPE_DEMO.md` measured 6.1x). A prover-side **out-of-core
//! codeword cache** cuts that without touching the protocol: encode once, spill
//! the codeword to disk while hashing the cap, then stream the file back for
//! the fold and the query pass. The bytes are identical, so the proof is
//! identical; only the peak moves.
//!
//! This probe measures the resulting peak against the same in-memory case, and
//! checks (at small sizes, and end-to-end at every size) that the disk path is
//! consistent:
//!
//! * the cap written from the encode pass is the real Merkle cap (checked
//!   against `MerkleTreeMmcs::verify_multi_batch` with the multiproof the disk
//!   query pass produces, so cap and multiproof must agree);
//! * at `CHECK` sizes the whole codeword is also built in memory and compared:
//!   cap, folded codeword symbol for symbol, and the pruned multiproof.
//!
//! Run:
//! ```sh
//! cargo build --release -p magnetar-pcs --example m4_oot_probe
//! CASES=small  target/release/examples/m4_oot_probe
//! CASES=target target/release/examples/m4_oot_probe
//! ```

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::time::Instant;

use magnetar_pcs::p3_pcs::Keccak256Hash16;
use p3_binary_dft::EncodableLevel;
use p3_binary_field::{BinaryField128 as F, TowerLevel};
use p3_binary_pcs::{fold_codeword, fold_pair};
use p3_commit::{Encoder, Mmcs, StreamingOpener};
use p3_matrix::Dimensions;
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{
    CompressionFunctionFromHasher, CryptographicHasher, MerkleCap, PseudoCompressionFunction,
    SerializingHasher,
};

type EF = F;
type Digest = [u8; 16];
type Hash = SerializingHasher<Keccak256Hash16>;
type Compress = CompressionFunctionFromHasher<Keccak256Hash16, 2, 16>;
type Mtree = MerkleTreeMmcs<F, u8, Hash, Compress, 2, 16>;

const BLOCK_LOG: usize = 15;
const FOLD_ARITY: usize = 2;
const REPRESENTATIVE_QUERIES: usize = 32;

fn mtree() -> Mtree {
    Mtree::new(Hash::new(Keccak256Hash16), Compress::new(Keccak256Hash16), 0)
}

fn peak_rss_bytes() -> u64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return 0;
    }
    usage.ru_maxrss as u64
}

fn footprint_bytes() -> u64 {
    #[cfg(target_os = "macos")]
    {
        let mut info: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
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

fn seeded(len: usize, seed: u64) -> Vec<F> {
    (0..len)
        .map(|index| {
            let bits = (index as u128)
                .wrapping_mul(0x9e37_79b9_7f4a_7c15_9e37_79b9)
                .wrapping_add(seed as u128)
                .wrapping_mul(0xd6e8_feb8_6659_fd93_4a1c_2f7b);
            F::from_repr(bits)
        })
        .collect()
}

/// Little-endian bytes of one codeword symbol.
fn symbol_bytes(symbol: F) -> [u8; 16] {
    symbol.to_repr().to_le_bytes()
}

fn symbol_from_bytes(bytes: &[u8]) -> F {
    F::from_repr(u128::from_le_bytes(bytes.try_into().expect("16 bytes")))
}

/// Incremental binary root over codeword rows: hash a 2^15-row subtree at a
/// time and keep one pending digest per level.
struct Root {
    hash: Hash,
    compress: Compress,
    block: Vec<F>,
    block_rows: usize,
    pending: Vec<Option<Digest>>,
    blocks: usize,
}

impl Root {
    fn new() -> Self {
        Self {
            hash: Hash::new(Keccak256Hash16),
            compress: Compress::new(Keccak256Hash16),
            block: Vec::with_capacity(1 << BLOCK_LOG),
            block_rows: 1 << BLOCK_LOG,
            pending: Vec::new(),
            blocks: 0,
        }
    }

    fn push_symbol(&mut self, symbol: F) {
        self.block.push(symbol);
        if self.block.len() == self.block_rows {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if self.block.is_empty() {
            return;
        }
        let rows = self.block.len();
        let mut digests = vec![[0u8; 16]; rows];
        self.hash.hash_many(&self.block, &mut digests);
        self.block.clear();
        let mut len = rows;
        while len > 1 {
            let half = len / 2;
            let groups: Vec<[Digest; 2]> = (0..half)
                .map(|index| [digests[2 * index], digests[2 * index + 1]])
                .collect();
            self.compress.compress_many(&groups, &mut digests[..half]);
            len = half;
        }
        self.blocks += 1;
        self.push_root(digests[0]);
    }

    fn push_root(&mut self, root: Digest) {
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

    fn finish(mut self) -> MerkleCap<F, Digest> {
        self.flush();
        assert!(
            self.blocks.is_power_of_two(),
            "a codeword has 2^k leaf blocks, got {}",
            self.blocks
        );
        let root = self
            .pending
            .into_iter()
            .flatten()
            .next()
            .expect("a codeword has a root");
        MerkleCap::new(vec![root])
    }
}

/// Fold one aligned coset of `2^arity` symbols, including the global offsets.
fn fold_run(coset_index: usize, values: &[F], challenges: &[EF], scratch: &mut Vec<EF>) -> EF {
    assert_eq!(values.len(), 1usize << challenges.len());
    let mut len = values.len() / 2;
    scratch.clear();
    scratch.extend((0..len).map(|index| {
        fold_pair(
            coset_index * len + index,
            challenges[0],
            values[2 * index],
            values[2 * index + 1],
        )
    }));
    for &beta in &challenges[1..] {
        len /= 2;
        for index in 0..len {
            scratch[index] = fold_pair::<EF, EF>(
                coset_index * len + index,
                beta,
                scratch[2 * index],
                scratch[2 * index + 1],
            );
        }
    }
    scratch[0]
}

struct Case {
    name: &'static str,
    log_cells: usize,
    rate_log: usize,
    codeword_mib: f64,
    peak_rss_mib: f64,
    footprint_mib: f64,
    encode_ms: f64,
    fold_ms: f64,
    query_ms: f64,
    verified: bool,
    matched_in_memory: Option<bool>,
}

/// Fill `buffer` from `reader` until it is full or the file ends.
fn read_full<R: Read>(reader: &mut R, buffer: &mut [u8]) -> usize {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]).expect("read codeword") {
            0 => break,
            got => filled += got,
        }
    }
    filled
}

fn query_indices(codeword_rows: usize, seed: u64) -> Vec<usize> {
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(1);
    let mut indices = Vec::with_capacity(REPRESENTATIVE_QUERIES);
    while indices.len() < REPRESENTATIVE_QUERIES.min(codeword_rows) {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let index = ((state >> 33) as usize) % codeword_rows;
        if !indices.contains(&index) {
            indices.push(index);
        }
    }
    indices.sort_unstable();
    indices
}

/// Run one case: encode once into a temp file, fold and open from the file.
///
/// `check` also builds the codeword in memory and compares cap, folded
/// codeword and multiproof symbol for symbol.
fn run_case(
    name: &'static str,
    log_cells: usize,
    rate_log: usize,
    chunk_symbols: usize,
    check: bool,
) -> Case {
    let cells = 1usize << log_cells;
    let codeword_rows = cells << rate_log;
    let message = seeded(cells, 7);
    let encoder = <F as EncodableLevel>::Encoder::default();
    let path = PathBuf::from(format!(
        "{}/m4_oot_{}x{}.bin",
        std::env::temp_dir().display(),
        std::process::id(),
        log_cells
    ));

    // ---- pass 1: encode once, spill the codeword, hash the cap ----
    let encode_started = Instant::now();
    let mut writer = BufWriter::new(File::create(&path).expect("temp codeword file"));
    let mut root = Root::new();
    let mut byte_buffer: Vec<u8> = Vec::with_capacity(chunk_symbols * 16);
    encoder.encode_batch_chunks(
        RowMajorMatrixView::new(&message, 1),
        rate_log,
        &mut |chunk| {
            byte_buffer.clear();
            for &symbol in chunk {
                for byte in symbol_bytes(symbol) {
                    byte_buffer.push(byte);
                }
                root.push_symbol(symbol);
            }
            writer.write_all(&byte_buffer).expect("spill codeword");
        },
    );
    writer.flush().expect("flush codeword");
    let cap = root.finish();
    let encode_ms = encode_started.elapsed().as_secs_f64() * 1000.0;
    // The message lives only for the encode pass in this demo, as a prover
    // spilling the codeword could drop it here.
    drop(message);

    // ---- pass 2: fold from the file ----
    let fold_started = Instant::now();
    let challenges: Vec<EF> = (0..FOLD_ARITY)
        .map(|index| F::from_repr(0x51ed_2701_9e37_79b9u128 + index as u128 * 0x9e37))
        .collect();
    let coset_len = 1usize << FOLD_ARITY;
    let mut folded: Vec<EF> = Vec::with_capacity(codeword_rows / coset_len);
    let mut scratch = Vec::new();
    let mut reader = BufReader::new(File::open(&path).expect("codeword file"));
    let symbols_per_read = chunk_symbols - chunk_symbols % coset_len;
    let mut raw = vec![0u8; symbols_per_read * 16];
    loop {
        let got = read_full(&mut reader, &mut raw);
        if got == 0 {
            break;
        }
        assert_eq!(got % 16, 0, "a codeword read must end on a symbol");
        let symbols = got / 16;
        let mut values = Vec::with_capacity(symbols);
        for offset in (0..got).step_by(16) {
            values.push(symbol_from_bytes(&raw[offset..offset + 16]));
        }
        assert_eq!(symbols % coset_len, 0, "fold cosets must not straddle reads");
        let base = folded.len();
        for (index, run) in values.chunks_exact(coset_len).enumerate() {
            folded.push(fold_run(base + index, run, &challenges, &mut scratch));
        }
    }
    let fold_ms = fold_started.elapsed().as_secs_f64() * 1000.0;

    // ---- pass 3: query rows + pruned multiproof from the file ----
    let query_started = Instant::now();
    let indices = query_indices(codeword_rows, 11);
    let mut opener = mtree().streaming_opener(codeword_rows, 1, &indices);
    let mut reader = BufReader::new(File::open(&path).expect("codeword file"));
    let mut raw = vec![0u8; symbols_per_read * 16];
    loop {
        let got = read_full(&mut reader, &mut raw);
        if got == 0 {
            break;
        }
        let mut values = Vec::with_capacity(got / 16);
        for offset in (0..got).step_by(16) {
            values.push(symbol_from_bytes(&raw[offset..offset + 16]));
        }
        opener.push_rows(&values);
    }
    let (opened, multi_proof) = opener.finish();
    let dims = [Dimensions {
        width: 1,
        height: codeword_rows,
    }];
    let opened_values: Vec<Vec<Vec<F>>> = opened.into_iter().map(|row| vec![row]).collect();
    mtree()
        .verify_multi_batch(&cap, &dims, &indices, &opened_values, &multi_proof)
        .expect("the spilled codeword's multiproof must verify against the encode-pass cap");
    let query_ms = query_started.elapsed().as_secs_f64() * 1000.0;

    // The pipeline's own high-water mark: the in-memory check below allocates
    // a full codeword and tree, so it must not be counted.
    let peak_rss_mib = peak_rss_bytes() as f64 / 1048576.0;
    let footprint_mib = footprint_bytes() as f64 / 1048576.0;

    // ---- optional in-memory equality check ----
    let matched_in_memory = check.then(|| {
        let in_memory_codeword: Vec<F> = {
            let mut codeword = Vec::with_capacity(codeword_rows);
            encoder.encode_batch_chunks(
                RowMajorMatrixView::new(&seeded(cells, 7), 1),
                rate_log,
                &mut |chunk| codeword.extend_from_slice(chunk),
            );
            codeword
        };
        let (expected_cap, tree_data) = mtree()
            .commit_matrix(RowMajorMatrix::new(in_memory_codeword.clone(), 1));
        assert_eq!(
            expected_cap, cap,
            "the spilled codeword's cap must equal the in-memory commit"
        );
        // Folded codeword: sequential public folds of the in-memory codeword.
        let mut expected: Vec<EF> = in_memory_codeword;
        for &beta in &challenges {
            expected = fold_codeword(&expected, beta);
        }
        assert_eq!(
            expected.len(),
            folded.len(),
            "the file-backed fold must cover the same symbols"
        );
        if let Some(index) = expected
            .iter()
            .zip(&folded)
            .position(|(want, got)| want != got)
        {
            panic!(
                "file-backed fold differs at symbol {index}: {:?} != {:?}",
                expected[index], folded[index]
            );
        }
        // Multiproof: the real tree's pruned opening.
        let (expected_opened, expected_proof) =
            mtree().open_multi_batch(&indices, &tree_data);
        let expected_opened: Vec<Vec<F>> = expected_opened
            .into_iter()
            .map(|mut per_matrix| per_matrix.swap_remove(0))
            .collect();
        assert_eq!(
            expected_opened.len(),
            opened_values.len(),
            "the multiproof must open the same rows"
        );
        assert_eq!(
            expected_opened,
            opened_values.iter().map(|per| per[0].clone()).collect::<Vec<_>>(),
            "the multiproof rows must match the in-memory opening"
        );
        assert_eq!(
            expected_proof.sibling_hashes, multi_proof.sibling_hashes,
            "the file-backed multiproof must equal the in-memory one"
        );
        true
    });

    let _ = std::fs::remove_file(&path);
    Case {
        name,
        log_cells,
        rate_log,
        codeword_mib: codeword_rows as f64 * 16.0 / 1048576.0,
        peak_rss_mib,
        footprint_mib,
        encode_ms,
        fold_ms,
        query_ms,
        verified: true,
        matched_in_memory,
    }
}

fn report(case: &Case) {
    println!(
        "{name:<26} cells=2^{log:<2} rate_log={rate} codeword={code:>7.1} MiB \
         peak_rss={rss:>8.1} MiB footprint={fp:>8.1} MiB \
         encode={enc:>7.1} ms fold={fold:>7.1} ms query={q:>7.1} ms \
         verified={verified} in_memory={checked:?}",
        name = case.name,
        log = case.log_cells,
        rate = case.rate_log,
        code = case.codeword_mib,
        rss = case.peak_rss_mib,
        fp = case.footprint_mib,
        enc = case.encode_ms,
        fold = case.fold_ms,
        q = case.query_ms,
        verified = case.verified,
        checked = case.matched_in_memory,
    );
}

fn main() {
    // One case per process: the peak is a monotonic high-water mark, so two
    // cases in one process would report the first one's retained pages.
    let log_cells: usize = std::env::var("LOG")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(20);
    let rate_log = std::env::var("RATE_LOG")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2usize);
    let chunk_mib = std::env::var("CHUNK_MIB")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(32);
    let check = std::env::var("CHECK").map(|value| value != "0").unwrap_or(false);
    let chunk_symbols = chunk_mib * 1024 * 1024 / 16;
    let case = run_case(
        "128-bit out-of-core",
        log_cells,
        rate_log,
        chunk_symbols,
        check,
    );
    report(&case);
}
