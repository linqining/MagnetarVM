//! M4a feasibility demo: bit-pack the committed twist address tables.
//!
//! The unified mosaic commits the twist `addr` tables as `2*address_bits+2`
//! bit columns stored one **16-byte field element per bit**. At RV64 `2^16`
//! those two tables are ~1.57 M of the 2.29 M mosaic cells (69 %); the same
//! ratio holds at every scale because the table is `12 x 2*cycles`. This probe
//! measures the two effects M4a needs:
//!
//! **Part A — cells and memory.** Build the `2^16`-cycle mosaic replica the
//! PCS probes use (`p3_stage_probe::mosaic()`, generalised to any cycle log),
//! once as committed today and once with the two 12-column address tables
//! bit-packed 128 bits per cell. Commit and open both through the real
//! `P3BinaryPcs` streamed paths and report cells, stacked variables, message
//! bytes, peak and wall. This is the memory/format half of M4a.
//!
//! **Part B — the verifier relation.** A packed address table is a table of
//! 128-bit words, not of 0/1 cells, so the Access verifier must evaluate
//! individual bit columns without unpacking them. The repo already owns that
//! machinery: `magnetar_proof::RingSwitchPackedBitPcs` commits 128 bits per
//! field element and proves evaluations of the *bit* vector with a ring-switch
//! sum-check. Part B runs exactly that on the 12 address columns: commit, open
//! and verify each, and compare the claimed value with the MLE of the unpacked
//! column. This is the soundness half of M4a and needs no new cryptography.
//!
//! Run (one part per process keeps the peak honest):
//! ```sh
//! cargo build --release -p magnetar-pcs --example m4a_packed_mosaic_probe
//! RUN=partA LOG=16 PACKED=0 target/release/examples/m4a_packed_mosaic_probe
//! RUN=partA LOG=16 PACKED=1 target/release/examples/m4a_packed_mosaic_probe
//! RUN=partB LOG=16 target/release/examples/m4a_packed_mosaic_probe
//! ```

use std::time::Instant;

use magnetar_constraint::F2_128;
use magnetar_pcs::{P3BinaryPcs, P3MosaicPoint, P3MosaicTable};
use magnetar_proof::{
    BitPcs, Mle, PackedBits, RingSwitchPackedBitPcs, eval_bits_mle,
};
use magnetar_pcs::P3SharedPcs;

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

fn seeded(index: usize, seed: u64) -> F2_128 {
    F2_128::from(
        (index as u128)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15_9e37_79b9)
            .wrapping_add(seed as u128)
            .wrapping_mul(0xd6e8_feb8_6659_fd93_4a1c_2f7b),
    )
}

/// The `p3_stage_probe::mosaic()` table list, generalised from `2^16` cycles
/// to `2^log_cycles`: `(log2 rows, columns, bit-valued)`.
///
/// At `LOG=16` this is exactly the RV64 `2^16` replica: the two 12-column
/// address tables (16,12) x2, the small address tables (1,12)/(5,2) x2, the
/// scalar twist columns, and the (19,1) trace table. Total 2,293,760 cells,
/// within 0.01 % of the production 2,293,918.
fn replica_shapes(log_cycles: usize) -> Vec<(usize, usize, bool)> {
    let small = |delta: usize| log_cycles.saturating_sub(delta);
    vec![
        (small(15), 12, true),
        (small(15), 1, false),
        (small(11), 2, true),
        (small(15), 1, false),
        (small(15), 1, false),
        (log_cycles, 12, true),
        (log_cycles, 12, true),
        (log_cycles, 1, false),
        (small(11), 2, true),
        (log_cycles, 1, false),
        (log_cycles, 1, false),
        (log_cycles + 3, 1, false),
    ]
}

/// Build the replica tables. `packed` bit-packs the two large 12-column
/// address tables 128 bits per cell, the M4a change; everything else is
/// identical.
fn replica_tables(log_cycles: usize, packed: bool) -> Vec<P3MosaicTable> {
    let mut tables = Vec::new();
    for (index, &(log_rows, columns, bits)) in replica_shapes(log_cycles).iter().enumerate() {
        // Only the two big address tables are packed in this demo; they are
        // the ones that dominate the mosaic (12 x 2*cycles cells each).
        let pack_this = packed && bits && columns == 12 && log_rows == log_cycles;
        let rows = if pack_this {
            1usize << (log_rows - 7)
        } else {
            1usize << log_rows
        };
        let mut table = Vec::with_capacity(columns);
        for column in 0..columns {
            let values = if pack_this {
                // 128 packed bits per cell; the bit pattern is irrelevant to
                // the memory measurement, so reuse the seeded field values.
                (0..rows)
                    .map(|row| seeded(row * 131 + column * 7 + index, 3))
                    .collect()
            } else if bits {
                (0..rows)
                    .map(|row| F2_128::from(((row * 17 + column * 5 + index) % 2) as u64))
                    .collect()
            } else {
                (0..rows)
                    .map(|row| seeded(row * 17 + column * 3 + index, 11))
                    .collect()
            };
            table.push(values);
        }
        tables.push(P3MosaicTable { columns: table });
    }
    tables
}

/// One opening point per table, covering every column.
fn replica_points(tables: &[P3MosaicTable]) -> Vec<P3MosaicPoint> {
    tables
        .iter()
        .enumerate()
        .map(|(table, source)| {
            let rows = source.columns[0].len();
            let point = (0..rows.trailing_zeros() as usize)
                .map(|bit| F2_128::from(((bit * 7 + table * 3) % 2) as u64))
                .collect();
            P3MosaicPoint {
                table,
                point,
                columns: (0..source.columns.len()).collect(),
                next_columns: Vec::new(),
            }
        })
        .collect()
}

fn run_part_a(log_cycles: usize, packed: bool) {
    // Measure the streamed opening, the shipped memory mode.
    std::env::set_var("MAGNETAR_STREAM_PCS_OPEN", "1");
    let tables = replica_tables(log_cycles, packed);
    let points = replica_points(&tables);
    let cells: usize = tables
        .iter()
        .map(|table| table.columns[0].len() * table.columns.len())
        .sum();
    let pcs = P3BinaryPcs::with_params(100, 2, 21, 2);

    let commit_started = Instant::now();
    let commitment = pcs.commit_mosaic(&tables).expect("commit");
    let commit_ms = commit_started.elapsed().as_secs_f64() * 1000.0;
    let open_started = Instant::now();
    let opening = pcs
        .open_mosaic_with_cap(&tables, &points, &commitment.cap)
        .expect("open");
    let open_ms = open_started.elapsed().as_secs_f64() * 1000.0;

    // Verify the opening against the MLE of every listed column.
    let mut expected = Vec::with_capacity(points.len());
    for point in &points {
        let table = &tables[point.table];
        let mut values = Vec::with_capacity(point.columns.len());
        for &column in &point.columns {
            let mle = Mle::new(table.columns[column].clone()).expect("mle");
            values.push(mle.eval(&point.point).expect("eval"));
        }
        expected.push(values);
    }
    let verified = pcs
        .verify_mosaic(&opening, &points, &expected)
        .expect("verify");
    let proof_bytes = bincode::serialize(&opening.proof)
        .map(|bytes| bytes.len())
        .unwrap_or(0);
    println!(
        "partA packed={packed:<1} LOG={log_cycles:<2} cells={cells:>10} stacked_vars={sv:<2} \
         message={message_mib:>7.1} MiB peak_rss={rss:>8.1} MiB footprint={fp:>8.1} MiB \
         commit={commit:>7.1} ms open={open:>7.1} ms proof={proof:>8} B verified={verified}",
        packed = u8::from(packed),
        sv = commitment.stacked_variables,
        message_mib = (1u64 << commitment.stacked_variables) as f64 * 16.0 / 1048576.0,
        rss = peak_rss_bytes() as f64 / 1048576.0,
        fp = footprint_bytes() as f64 / 1048576.0,
        commit = commit_ms,
        open = open_ms,
        proof = proof_bytes,
        verified = verified,
    );
}

/// The Access verifier relation on packed address bits: commit `bits.len()`
/// bits as `bits.len()/128` field elements with ring-switch, open at a point,
/// verify, and compare with the MLE of the unpacked bit column.
fn run_part_b(log_bits: usize) {
    let len = 1usize << log_bits;
    let backend = RingSwitchPackedBitPcs::new(P3SharedPcs::new(
        100,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ));
    let point: Vec<F2_128> = (0..log_bits)
        .map(|bit| F2_128::from(((bit * 11 + 5) % 2) as u64))
        .collect();
    let mut packed_cells = 0usize;
    let mut unpacked_cells = 0usize;
    let mut commit_bytes = 0usize;
    let mut opening_bytes = 0usize;
    let mut worst_ratio = 0.0f64;
    let mut verified_all = true;
    let started = Instant::now();
    for column in 0..12 {
        let bits: Vec<bool> = (0..len)
            .map(|index| (index.wrapping_mul(17) + column * 13 + index / 128) % 3 == 0)
            .collect();
        let packed = PackedBits::from_bools(&bits);
        let commitment = backend.commit(&packed).expect("bit commit");
        let (value, opening) = backend
            .open_with_commitment(&packed, &point, &commitment)
            .expect("bit open");
        let expected = eval_bits_mle(&bits, &point).expect("bit mle");
        verified_all &= backend
            .verify(&commitment, &point, expected, &opening)
            .expect("bit verify");
        assert_eq!(value, expected, "packed evaluation must equal the bit MLE");
        packed_cells += len / 128;
        unpacked_cells += len;
        commit_bytes += backend.commitment_bytes(&commitment).len();
        opening_bytes += bincode::serialize(&opening)
            .map(|bytes| bytes.len())
            .unwrap_or(0);
        worst_ratio = worst_ratio.max(
            bincode::serialize(&opening)
                .map(|bytes| bytes.len() as f64)
                .unwrap_or(0.0),
        );
    }
    let wall_ms = started.elapsed().as_secs_f64() * 1000.0;
    println!(
        "partB bits_log={log_bits:<2} columns=12 packed_cells={packed_cells:>8} \
         unpacked_cells={unpacked_cells:>9} ({ratio:.0}x fewer) commit={commit_bytes:>7} B \
         openings={opening_bytes:>8} B largest_opening={largest:>7} B \
         wall={wall_ms:>8.1} ms verified={verified_all}",
        ratio = unpacked_cells as f64 / packed_cells as f64,
        largest = worst_ratio as usize,
        verified_all = verified_all,
    );
    // The point of part B: the ring-switch opening is a real proof of the
    // packed bit vector, not a re-encoding of it.
    assert!(verified_all, "ring-switch bit opening must verify");
}

fn main() {
    let run = std::env::var("RUN").unwrap_or_else(|_| "both".into());
    let log_cycles: usize = std::env::var("LOG")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(16);
    let packed = std::env::var("PACKED")
        .map(|value| value != "0")
        .unwrap_or(false);
    if run == "partA" || run == "both" {
        // One variant per process in normal use; `both` is only a smoke run.
        run_part_a(log_cycles, packed);
    }
    if run == "partB" || run == "both" {
        run_part_b(log_cycles);
    }
}
