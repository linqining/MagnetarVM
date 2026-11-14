//! M4a real-table-set projection test.
//!
//! The M4a prototype (`magnetar-pcs/examples/m4a_packed_mosaic_probe`) packed a
//! synthetic replica. This test reconstructs the **real** unified-mosaic table
//! set for the paper trace and projects committed cells and stacked message
//! sizes through the M4a steps, so the plan in `docs/M4_ENVELOPE_DEMO.md` §8 can
//! be checked against the builders the prover actually uses (they are private to
//! this crate, which is why this lives here rather than in an example).
//!
//! Run (the test builds a real `2^16` trace and is ignored by default):
//! ```sh
//! cargo test -p magnetar-runtime --release m4a_real -- --ignored --nocapture
//! ```
//!
//! The steps:
//! 1. pack the fully bit-valued register address table 128:1;
//! 2. split the ROM table by bit-ness and pack its bit columns 128:1;
//! 3. drop the duplicated Access-batch bit columns (the Access proof would use
//!    ring-switch claims against the single packed table);
//! 4. pack the trace table 2x (two 64-bit fields per cell).
//!
//! `2^16` table set is measured against the production profile (2,293,918
//! cells); larger sizes are projected by scaling the cycle-proportional tables
//! and keeping the small (RAM/initial) tables fixed, which is what the profile
//! at `2^18` showed to be exact.

use magnetar_constraint::F2_128;
use magnetar_executor::execute;
use magnetar_memory::BinaryTwistWitness;
use magnetar_pcs::P3MosaicTable;
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage, Trace};

use crate::binary_router::{BinaryRouterWitness, RouterMode};
use crate::binary_shout::BinaryShoutWitness;
use crate::binary_twist::batch_tables_committed_only;
use crate::register_twist::register_twist_witness;
use crate::trace_commitment::trace_witness;

/// Cycle log of the trace the test actually builds; larger sizes are projected.
const BUILT_LOG_CYCLES: usize = 16;

/// How a table's row count moves when the program gets longer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Scaling {
    /// Rows are proportional to the trace length.
    Cycles,
    /// Rows are a property of the machine (registers, RAM size), not the trace.
    Fixed,
}

/// Which M4a step applies to this table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role {
    /// The fully bit-valued register address table (12 columns).
    RegisterAddress,
    /// The ROM table: a mix of bit and scalar columns.
    Rom,
    /// The trace table: eight 64-bit fields per row.
    Trace,
    /// Everything else (scalar twist columns, small RAM tables).
    Other,
}

#[derive(Clone)]
struct TableShape {
    name: String,
    rows: usize,
    columns: usize,
    /// True where a column only holds 0/1 (a packing candidate).
    bits: Vec<bool>,
    scaling: Scaling,
    role: Role,
}

impl TableShape {
    fn new(name: &str, table: &P3MosaicTable, scaling: Scaling, role: Role) -> Self {
        let rows = table.columns.first().map_or(0, |column| column.len());
        let bits = table
            .columns
            .iter()
            .map(|column| column.iter().all(|value| value.value() <= 1))
            .collect();
        Self {
            name: name.to_string(),
            rows,
            columns: table.columns.len(),
            bits,
            scaling,
            role,
        }
    }

    fn rows_at(&self, factor: usize) -> usize {
        match self.scaling {
            Scaling::Cycles => self.rows * factor,
            Scaling::Fixed => self.rows,
        }
    }

    fn cells_at(&self, factor: usize) -> usize {
        self.rows_at(factor) * self.columns
    }

    /// Cells after the M4a steps up to and including `step` (0 = today).
    fn packed_cells_at(&self, factor: usize, step: usize) -> usize {
        let rows = self.rows_at(factor);
        if step >= 1 && self.role == Role::RegisterAddress && rows.is_multiple_of(128) {
            return rows / 128 * self.columns;
        }
        if step >= 2 && self.role == Role::Rom {
            let bit_columns = self.bits.iter().filter(|&&bit| bit).count();
            let bit_rows = if rows.is_multiple_of(128) { rows / 128 } else { rows };
            return bit_columns * bit_rows + (self.columns - bit_columns) * rows;
        }
        if step >= 4 && self.role == Role::Trace && rows.is_multiple_of(2) {
            return rows / 2 * self.columns;
        }
        rows * self.columns
    }
}

fn bench_trace(adds: usize) -> Trace {
    let mut rom = Vec::with_capacity(adds + 1);
    for index in 0..adds {
        rom.push(
            Instruction {
                op: Op::Addi,
                rd: 1,
                rs1: 1,
                rs2: 0,
                imm: index as i64 + 1,
                shamt: 0,
            }
            .encode(),
        );
    }
    rom.push(Instruction::new(Op::Ecall).encode());
    let program = ProgramImage::new(0x1000, rom);
    let config = MachineConfig {
        entry: 0x1000,
        rom_base: 0x1000,
        ram_base: 0x1000_0000,
        ram_size: 0x100,
        stack_top: 0x1000_0100,
        max_cycles: 1_000_000,
    };
    execute(&program, config).expect("the paper trace must execute")
}

/// Rebuild the unified mosaic's table list in the order `protocol.rs` pushes it:
/// the five RAM-twist tables, the ROM table, the five register-twist tables and
/// the trace table. Router tables are included only when the trace produces
/// them (they are absent for the paper trace, matching the 12-table profile).
fn real_tables(trace: &Trace) -> Vec<(TableShape, P3MosaicTable)> {
    let mut shapes: Vec<(TableShape, P3MosaicTable)> = Vec::new();

    let ram_witness = BinaryTwistWitness::from_trace(trace).expect("RAM twist witness");
    let ram = batch_tables_committed_only(&ram_witness).expect("RAM batch tables");
    for (name, table) in [
        ("ram.addr", &ram.addr),
        ("ram.inc", &ram.inc),
        ("ram.initial", &ram.initial),
        ("ram.read_value", &ram.read_value),
        ("ram.write_value", &ram.write_value),
    ] {
        shapes.push((
            TableShape::new(name, table, Scaling::Fixed, Role::Other),
            table.clone(),
        ));
    }

    if let Ok(shout) = BinaryShoutWitness::from_trace(trace) {
        if let Some(first) = shout.rom.first() {
            let columns = (0..first.len())
                .map(|column| shout.rom.iter().map(|row| row[column]).collect())
                .collect();
            let rom = P3MosaicTable { columns };
            // The ROM table is fixed (the program's instructions), but its rows
            // still scale with the trace length in this bench (one ROM row per
            // cycle); the profile shows rows == cycles at both sizes.
            let shape = TableShape::new("rom", &rom, Scaling::Cycles, Role::Rom);
            shapes.push((shape, rom));
        }
    }
    if let Ok(shift) = BinaryRouterWitness::from_trace_mode(trace, RouterMode::Shifts) {
        let table = shift.table();
        shapes.push((
            TableShape::new("shift_router", &table, Scaling::Cycles, Role::Other),
            table,
        ));
    }
    if let Ok(store) = BinaryRouterWitness::from_trace_mode(trace, RouterMode::Stores) {
        let table = store.table();
        shapes.push((
            TableShape::new("store_router", &table, Scaling::Cycles, Role::Other),
            table,
        ));
    }

    let register_witness = register_twist_witness(trace).expect("register twist witness");
    let register = batch_tables_committed_only(&register_witness).expect("register batch tables");
    for (name, table, scaling, role) in [
        ("register.addr", &register.addr, Scaling::Cycles, Role::RegisterAddress),
        ("register.inc", &register.inc, Scaling::Cycles, Role::Other),
        ("register.initial", &register.initial, Scaling::Fixed, Role::Other),
        ("register.read_value", &register.read_value, Scaling::Cycles, Role::Other),
        ("register.write_value", &register.write_value, Scaling::Cycles, Role::Other),
    ] {
        shapes.push((TableShape::new(name, table, scaling, role), table.clone()));
    }

    let trace_witness = trace_witness(trace).expect("trace witness");
    let trace_table = P3MosaicTable {
        columns: vec![trace_witness.values],
    };
    shapes.push((
        TableShape::new("trace", &trace_table, Scaling::Cycles, Role::Trace),
        trace_table,
    ));

    shapes
}

fn mosaic_cells(shapes: &[TableShape], factor: usize, step: usize) -> usize {
    shapes
        .iter()
        .map(|shape| shape.packed_cells_at(factor, step))
        .sum()
}

/// Stacked message bytes for a cell count: the PCS stacks the tables into one
/// message padded to the next power of two of 16-byte cells.
fn message_bytes(cells: usize) -> u64 {
    let stacked_variables = cells.next_power_of_two().trailing_zeros() as usize;
    (1u64 << stacked_variables) * 16
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / 1048576.0
}


// ---------------------------------------------------------------------------
// Measured peak: commit + open the real table set, current vs M4a-packed.
// ---------------------------------------------------------------------------

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

/// Apply M4a steps to the real mosaic tables through the shared packing module.
fn packed_real_tables(shapes: &[TableShape], tables: &[P3MosaicTable]) -> Vec<P3MosaicTable> {
    let mut packed = Vec::new();
    for (shape, table) in shapes.iter().zip(tables) {
        match shape.role {
            Role::RegisterAddress => {
                packed.push(crate::m4a_tables::packed_bit_table(&table.columns).expect("pack addr"));
            }
            Role::Rom => {
                let (bits, scalars, _) = crate::m4a_tables::split_and_pack(table).expect("split rom");
                if let Some(bits) = bits {
                    packed.push(bits);
                }
                if let Some(scalars) = scalars {
                    packed.push(scalars);
                }
            }
            Role::Trace => {
                let values = crate::m4a_tables::pack_word_pairs(&table.columns[0]).expect("pack trace");
                packed.push(P3MosaicTable {
                    columns: vec![values],
                });
            }
            _ => packed.push(table.clone()),
        }
    }
    packed
}

/// Measure commit + streamed open of the real table set.
fn measure_pcs(log_cycles: usize, packed: bool) {
    // The M4a-packed table set only makes sense on the shipped streaming
    // opening, so measure that path.
    std::env::set_var("MAGNETAR_STREAM_PCS_OPEN", "1");
    let trace = bench_trace((1 << log_cycles) - 1);
    let pairs = real_tables(&trace);
    let shapes: Vec<TableShape> = pairs.iter().map(|(shape, _)| shape.clone()).collect();
    let tables_current: Vec<P3MosaicTable> = pairs.into_iter().map(|(_, table)| table).collect();
    let tables = if packed {
        packed_real_tables(&shapes, &tables_current)
    } else {
        tables_current
    };
    let pcs = magnetar_pcs::P3BinaryPcs::with_params(100, 2, 21, 2);
    let mosaic_points: Vec<magnetar_pcs::P3MosaicPoint> = tables
        .iter()
        .enumerate()
        .map(|(table, source)| magnetar_pcs::P3MosaicPoint {
            table,
            point: (0..source.columns[0].len().trailing_zeros() as usize)
                .map(|bit| F2_128::from(((bit * 5 + table * 3) % 2) as u64))
                .collect(),
            columns: (0..source.columns.len()).collect(),
            next_columns: Vec::new(),
        })
        .collect();
    let cells: usize = tables
        .iter()
        .map(|table| table.columns[0].len() * table.columns.len())
        .sum();
    let commitment = pcs
        .commit_mosaic(&tables)
        .expect("mosaic commit must succeed");
    let _opening = pcs
        .open_mosaic_with_cap(&tables, &mosaic_points, &commitment.cap)
        .expect("mosaic open must succeed");
    println!(
        "m4a pcs peak: log_cycles=2^{log_cycles} packed={packed} tables={} cells={cells} \
         stacked_vars={} message={:.1} MiB peak_rss={:.1} MiB footprint={:.1} MiB",
        tables.len(),
        commitment.stacked_variables,
        (1u64 << commitment.stacked_variables) as f64 * 16.0 / 1048576.0,
        peak_rss_bytes() as f64 / 1048576.0,
        footprint_bytes() as f64 / 1048576.0,
    );
}

#[test]
#[ignore = "measures the real table set; run with --ignored --nocapture"]
fn m4a_pcs_peak() {
    let log_cycles: usize = std::env::var("LOG")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(16);
    let packed = std::env::var("PACKED").map(|value| value != "0").unwrap_or(false);
    measure_pcs(log_cycles, packed);
}

#[test]
#[ignore = "builds a real 2^16 trace; run with --ignored --nocapture"]
fn m4a_real_table_set_projection() {
    let trace = bench_trace((1 << BUILT_LOG_CYCLES) - 1);
    assert_eq!(trace.len(), 1 << BUILT_LOG_CYCLES, "one row per cycle");

    let pairs = real_tables(&trace);
    let shapes: Vec<TableShape> = pairs.iter().map(|(shape, _)| shape.clone()).collect();
    let tables: Vec<P3MosaicTable> = pairs.into_iter().map(|(_, table)| table).collect();
    let register_witness = register_twist_witness(&trace).expect("register witness");
    let register_tables =
        batch_tables_committed_only(&register_witness).expect("register batch tables");
    let address_bits = crate::linear_twist::witness_shape(&register_witness).address_bits;

    // M4a step 1/3 on the real tables, through the shared packing module.
    let unpacked_cells: usize = tables
        .iter()
        .map(|table| table.columns[0].len() * table.columns.len())
        .sum();
    let packed_tables = packed_real_tables(&shapes, &tables);
    let packed_cells: usize = packed_tables
        .iter()
        .map(|table| table.columns[0].len() * table.columns.len())
        .sum();
    assert_eq!(unpacked_cells, 2_293_918, "real mosaic cells");
    assert_eq!(packed_cells, 796_318, "packed mosaic cells");

    // The Access batch drops its duplicated bit columns: three scalar columns
    // plus the one packed bit table that the mosaic address table already owns.
    let access = crate::m4a_tables::pack_access_batch(&register_witness)
        .expect("packed access batch");
    assert_eq!(access.columns_before, 3 + 2 * address_bits + 2);
    assert_eq!(access.scalars.len(), 3);
    assert_eq!(access.bits.columns.len(), 2 * address_bits + 2);
    let mosaic_address = crate::m4a_tables::pack_twist_tables(&register_tables)
        .expect("packed twist tables")[0]
        .columns
        .clone();
    for column in &access.bits.columns {
        assert!(
            mosaic_address.iter().any(|candidate| candidate == column),
            "every Access bit column must be the mosaic address table's, so the data is committed once"
        );
    }
    // The bit data itself is lossless against the unpacked Access columns.
    let (read_bits, read_valid, _) = crate::virtual_onehot::bit_columns_pub(&register_witness, false);
    let same = |left: &[F2_128], right: &[F2_128]| {
        left.len() == right.len()
            && left.iter().zip(right).all(|(a, b)| a == b)
    };
    let unpacked = crate::m4a_tables::unpack_bit_column(&access.bits.columns[0], read_bits[0].len());
    assert!(
        same(&unpacked, &read_bits[0]),
        "packing must preserve the read bit 0 column"
    );
    // Access bit columns are ordered read bits, read valid, write bits, write
    // valid, so the read-valid column sits right after the read bits.
    let valid_unpacked =
        crate::m4a_tables::unpack_bit_column(&access.bits.columns[address_bits], read_valid.len());
    assert!(
        same(&valid_unpacked, &read_valid),
        "packing must preserve the read-valid column"
    );

    for shape in &shapes {
        let bit_columns = shape.bits.iter().filter(|&&bit| bit).count();
        println!(
            "{:<20} rows={:>8} cols={:>2} cells={:>9} bit_cols={bit_columns}/{} {:?} {:?}",
            shape.name,
            shape.rows,
            shape.columns,
            shape.cells_at(1),
            shape.columns,
            shape.scaling,
            shape.role,
        );
    }

    // The Access batch: three scalar columns plus `2*address_bits + 2` bit
    // columns, all trace-proportional. M4a step 3 drops the bit columns in
    // favour of ring-switch claims against the packed table.
    let access_columns_today = 3 + 2 * address_bits + 2;
    let access_columns_packed = 3;

    println!("\naddress_bits={address_bits}, access batch {} -> {} columns", access_columns_today, access_columns_packed);
    println!(
        "{:<6} {:>10} {:>9} {:>10} {:>9} {:>10} {:>9} {:>10} {:>9} {:>10} {:>9}",
        "cycles", "current", "msg_MiB", "step1", "step2", "packed_msg", "step4", "final_msg", "access", "acc_pack", "acc_msg"
    );
    for log_cycles in [16usize, 18, 22] {
        let factor = 1usize << (log_cycles - BUILT_LOG_CYCLES);
        let current = mosaic_cells(&shapes, factor, 0);
        let step1 = mosaic_cells(&shapes, factor, 1);
        let step2 = mosaic_cells(&shapes, factor, 2);
        let step4 = mosaic_cells(&shapes, factor, 4);
        let cycles_at = 1usize << log_cycles;
        let access_today = access_columns_today * cycles_at;
        let access_packed = access_columns_packed * cycles_at;
        println!(
            "{:<6} {:>10} {:>9.1} {:>10} {:>9} {:>10.1} {:>9} {:>10.1} {:>10} {:>10} {:>9.1}",
            format!("2^{log_cycles}"),
            current,
            mib(message_bytes(current)),
            step1,
            step2,
            mib(message_bytes(step2)),
            step4,
            mib(message_bytes(step4)),
            access_today,
            access_packed,
            mib(message_bytes(access_packed)),
        );

        // Padding is the point: the mosaic message is next_pow2(cells).
        if log_cycles == 16 {
            assert_eq!(
                current, 2_293_918,
                "the reconstruction must match the production profile's mosaic cells"
            );
            assert!(
                step4 <= 1 << 20,
                "at 2^16 the packed set must fit a 2^20-cell message"
            );
        }
        if log_cycles == 22 {
            assert!(
                step2 > 1 << 26,
                "at 2^22 steps 1-2 land above 2^26, so trace packing decides the message size"
            );
            assert!(
                step4 <= 1 << 26,
                "at 2^22 with trace packing the message must fit 2^26 cells (1 GiB)"
            );
        }
    }

    // The combined committed-cell reduction at 2^22 (mosaic + Access batch).
    let factor = 1usize << (22 - BUILT_LOG_CYCLES);
    let cycles_at = 1usize << 22;
    let before = mosaic_cells(&shapes, factor, 0) + access_columns_today * cycles_at;
    let after = mosaic_cells(&shapes, factor, 4) + access_columns_packed * cycles_at;
    println!(
        "\n2^22 committed cells: {before} -> {after} ({:.0}% reduction)",
        100.0 * (1.0 - after as f64 / before as f64)
    );
    assert!(
        after * 100 <= before * 40,
        "M4a must remove at least 60% of the committed cells"
    );
}


/// M4a step 1 wiring evidence: the Access batch's 12 bit-column evaluations can
/// be produced by one batched ring-switch proof instead of the PCS batch.
///
/// Run the existing Access prover, take the terminal bit evaluations its
/// verifier consumes (`proof.values[3]`), then prove the same 12 evaluations
/// from the packed bit table with a batched ring-switch and compare element by
/// element. This is the drop-in equivalence for the Access verifier change, with
/// no proof-format change yet.
#[test]
#[ignore = "runs the full Access prover; --ignored --nocapture"]
fn m4a_access_bit_claims_match_the_pcs_terminal_values() {
    use magnetar_pcs::P3BatchColumnPcs;
    use magnetar_proof::{BatchColumnPcs, BatchedRingSwitch, PackedBits};

    let trace = bench_trace((1 << BUILT_LOG_CYCLES) - 1);
    let witness = register_twist_witness(&trace).expect("register witness");
    let proof = crate::local_shared::prove_local_shared(&witness).expect("access proof");
    assert_eq!(proof.values.len(), 4, "Access PCS batches: rw, rj, val, virtual");
    let terminal = &proof.values[3];
    let address_bits = crate::linear_twist::witness_shape(&witness).address_bits;
    assert_eq!(terminal.len(), 2 * address_bits + 2);

    let packed_access = crate::m4a_tables::pack_access_batch(&witness).expect("packed bits");
    assert_eq!(packed_access.bits.columns.len(), terminal.len());
    let mut packed_bits = Vec::with_capacity(packed_access.bits.columns.len());
    for column in &packed_access.bits.columns {
        let bits = crate::m4a_tables::unpack_bit_column(column, witness.cycles.next_power_of_two());
        packed_bits.push(PackedBits::from_bools(
            &bits.iter().map(|value| value.value() & 1 == 1).collect::<Vec<_>>(),
        ));
    }

    let backend = P3BatchColumnPcs::new(magnetar_pcs::P3BinaryPcs::with_params(100, 2, 21, 2));
    let batched = BatchedRingSwitch::new(backend.clone());
    let commitment = backend
        .commit_columns(&packed_access.bits.columns)
        .expect("bits commit");
    let (claims, opening) = batched
        .open(&packed_bits, &proof.virtual_challenges, Some(&commitment))
        .expect("batched ring switch");
    for (index, (claim, expected)) in claims.iter().zip(terminal).enumerate() {
        assert_eq!(
            *claim, *expected,
            "M4a bit claim {index} must equal the Access verifier's terminal value"
        );
    }
    assert!(
        batched
            .verify(&commitment, &proof.virtual_challenges, &claims, &opening)
            .expect("verify"),
        "the batched ring-switch proof must verify"
    );
    let proof_bytes = bincode::serialize(&opening).map(|bytes| bytes.len()).unwrap_or(0);
    println!(
        "m4a access bits: columns={} ring_switch_proof={} B (vs PCS opening for the same 12 columns)",
        claims.len(),
        proof_bytes
    );
}


/// M4a step 1 proof-size budget: replace the Access PCS opening's 15 columns
/// (four point groups) with a 3-column scalar batch plus one batched ring-switch
/// for the 12 packed bit columns, and measure the net opening size.
///
/// This measures the actual replacement parts without changing the proof format
/// yet: the rest of the Access proof (sum-checks, endpoints) is unchanged, so
/// `new_total = old_total - old_opening + new_scalars_opening + bits_commitment
/// + bits_ring_switch_opening`.
#[test]
#[ignore = "runs the Access prover at LOG cycles; --ignored --nocapture"]
fn m4a_access_opening_size_budget() {
    use magnetar_pcs::P3BatchColumnPcs;
    use magnetar_proof::{BatchColumnPcs, BatchedRingSwitch, Mle, PackedBits, Pcs};
    use magnetar_pcs::P3BatchPoint;

    let log_cycles: usize = std::env::var("LOG")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(16);
    let trace = bench_trace((1 << log_cycles) - 1);
    let witness = register_twist_witness(&trace).expect("register witness");
    let proof = crate::local_shared::prove_local_shared(&witness).expect("access proof");
    let old_total = bincode::serialize(&proof).map(|bytes| bytes.len()).unwrap_or(0);
    let old_opening = bincode::serialize(&proof.opening)
        .map(|bytes| bytes.len())
        .unwrap_or(0);

    // Scalar columns: inc, read_value, write_value (columns 0..3).
    let packed_access = crate::m4a_tables::pack_access_batch(&witness).expect("packed bits");
    let scalars = &packed_access.scalars;
    let cycle_bits = proof.shape.cycle_bits();
    let cycle_point = {
        // The Access prover derives it from the commitment transcript; recompute
        // it the same way to keep the batch points valid.
        use magnetar_transcript::Sha256Transcript;
        let mut transcript = Sha256Transcript::new("magnetar-local-shared");
        transcript.absorb(
            "commitment",
            &bincode::serialize(&proof.opening.commitment).expect("serialize"),
        );
        let _gamma = crate::binary_twist::sample_point(&mut transcript, 1)[0];
        crate::binary_twist::sample_point(&mut transcript, cycle_bits)
    };
    let rj = proof.rw_challenges[..cycle_bits].to_vec();
    let points = vec![
        P3BatchPoint {
            point: cycle_point.clone(),
            columns: vec![1, 2],
        },
        P3BatchPoint {
            point: rj.clone(),
            columns: vec![0],
        },
        P3BatchPoint {
            point: proof.val_challenges.clone(),
            columns: vec![0],
        },
    ];
    let pcs = crate::linear_twist::linear_pcs(proof.shape.cycles);
    let commitment = pcs.commit_batch(scalars).expect("scalar commit");
    let opening = pcs
        .open_batch_with_cap(scalars, &points, &commitment.cap)
        .expect("scalar open");
    let evaluate = |column: &Vec<magnetar_constraint::F2_128>, point: &[magnetar_constraint::F2_128]| {
        Mle::new(column.clone()).expect("mle").eval(point).expect("eval")
    };
    let values = vec![
        vec![evaluate(&scalars[1], &cycle_point), evaluate(&scalars[2], &cycle_point)],
        vec![evaluate(&scalars[0], &rj)],
        vec![evaluate(&scalars[0], &proof.val_challenges)],
    ];
    assert!(
        pcs.verify_batch(&opening, &points, &values).expect("verify"),
        "the 3-column scalar batch must verify"
    );
    let scalars_bytes = bincode::serialize(&opening).map(|bytes| bytes.len()).unwrap_or(0);

    // Packed bit columns: one batched ring-switch at the virtual point.
    let mut packed_bits = Vec::with_capacity(packed_access.bits.columns.len());
    for column in &packed_access.bits.columns {
        let bits = crate::m4a_tables::unpack_bit_column(column, 1usize << cycle_bits);
        packed_bits.push(PackedBits::from_bools(
            &bits.iter().map(|value| value.value() & 1 == 1).collect::<Vec<_>>(),
        ));
    }
    let backend = P3BatchColumnPcs::new(magnetar_pcs::P3BinaryPcs::with_params(100, 2, 21, 2));
    let batched = BatchedRingSwitch::new(backend.clone());
    let bits_commitment = backend
        .commit_columns(&packed_access.bits.columns)
        .expect("bits commit");
    let (claims, bits_opening) = batched
        .open(&packed_bits, &proof.virtual_challenges, Some(&bits_commitment))
        .expect("bits ring switch");
    assert!(
        batched
            .verify(&bits_commitment, &proof.virtual_challenges, &claims, &bits_opening)
            .expect("verify"),
        "the batched ring-switch must verify"
    );
    assert_eq!(claims.len(), proof.values[3].len());
    for (claim, expected) in claims.iter().zip(&proof.values[3]) {
        assert_eq!(*claim, *expected, "bit claims must equal the Access terminal values");
    }
    let bits_commitment_bytes = bincode::serialize(&bits_commitment)
        .map(|bytes| bytes.len())
        .unwrap_or(0);
    let bits_opening_bytes = bincode::serialize(&bits_opening)
        .map(|bytes| bytes.len())
        .unwrap_or(0);
    let new_opening = scalars_bytes + bits_commitment_bytes + bits_opening_bytes;
    let new_total = old_total - old_opening + new_opening;
    println!(
        "m4a access budget: log=2^{log_cycles} old_opening={old_opening} B \
         old_total={old_total} B | scalars={scalars_bytes} B bits_commitment={bits_commitment_bytes} B \
         bits_ring_switch={bits_opening_bytes} B new_opening={new_opening} B new_total={new_total} B \
         delta={delta:+} B ({percent:+.1}%)",
        delta = new_total as i64 - old_total as i64,
        percent = 100.0 * (new_total as f64 - old_total as f64) / old_total as f64,
    );
}


/// M4a Access proof (version 5) round trip, semantic checks and size comparison.
#[test]
#[ignore = "runs both Access provers; --ignored --nocapture"]
fn m4a_access_proof_round_trips() {
    let trace = bench_trace((1 << BUILT_LOG_CYCLES) - 1);
    let witness = register_twist_witness(&trace).expect("register witness");
    let old = crate::local_shared::prove_local_shared(&witness).expect("old access proof");
    let m4a = crate::local_shared::prove_access_m4a(&witness).expect("m4a access proof");
    assert_eq!(m4a.version, crate::local_shared::M4A_ACCESS_VERSION);
    let verify_started = std::time::Instant::now();
    let verified = crate::local_shared::verify_access_m4a(&m4a).expect("verify");
    let m4a_verify_ms = verify_started.elapsed().as_secs_f64() * 1000.0;
    assert!(verified, "the M4a Access proof must verify");
    let old_verify_started = std::time::Instant::now();
    let old_verified = crate::local_shared::verify_local_shared(&old).expect("verify");
    let old_verify_ms = old_verify_started.elapsed().as_secs_f64() * 1000.0;
    assert!(old_verified, "the old Access proof must verify");
    println!(
        "m4a access verify: old={old_verify_ms:.2} ms m4a={m4a_verify_ms:.2} ms"
    );

    // The ring-switch claims must be the real address-bit MLEs at the proof's
    // virtual point (recompute from the witness).
    let address_bits = crate::linear_twist::witness_shape(&witness).address_bits;
    let cycles = witness.cycles.next_power_of_two();
    let (read_bits, read_valid, _) = crate::virtual_onehot::bit_columns_pub(&witness, false);
    let (write_bits, write_valid, _) = crate::virtual_onehot::bit_columns_pub(&witness, true);
    let mut columns = read_bits.clone();
    columns.push(read_valid.clone());
    columns.extend(write_bits.clone());
    columns.push(write_valid.clone());
    assert_eq!(columns.len(), address_bits * 2 + 2);
    assert_eq!(m4a.bits_claims.len(), columns.len());
    for (column, claim) in columns.iter().zip(&m4a.bits_claims) {
        let expected = crate::linear_twist::eval_mle(column, &m4a.virtual_challenges);
        assert_eq!(*claim, expected, "claim must be the address-bit MLE");
    }
    let _ = cycles;

    // Tampered claims and values are refused.
    let mut tampered = m4a.clone();
    tampered.bits_claims[0] = tampered.bits_claims[0] + magnetar_constraint::F2_128::from(1u64);
    assert!(!crate::local_shared::verify_access_m4a(&tampered).expect("verify"));
    let mut tampered = m4a.clone();
    tampered.values[0][0] = tampered.values[0][0] + magnetar_constraint::F2_128::from(1u64);
    assert!(!crate::local_shared::verify_access_m4a(&tampered).expect("verify"));

    // Size comparison: the packed variant is bigger by the ring-switch, but the
    // scalar batch is smaller. Report both.
    let old_bytes = bincode::serialize(&old).map(|bytes| bytes.len()).unwrap_or(0);
    let m4a_bytes = bincode::serialize(&m4a).map(|bytes| bytes.len()).unwrap_or(0);
    let old_opening = bincode::serialize(&old.opening).map(|bytes| bytes.len()).unwrap_or(0);
    let scalars = bincode::serialize(&m4a.opening).map(|bytes| bytes.len()).unwrap_or(0);
    let bits = bincode::serialize(&m4a.bits_opening).map(|bytes| bytes.len()).unwrap_or(0);
    println!(
        "m4a access proof: old={old_bytes} B opening={old_opening} B | m4a={m4a_bytes} B \
         scalars={scalars} B bits_ring_switch={bits} B bits_commitment={} B delta={:+} B",
        bincode::serialize(&m4a.bits_commitment).map(|bytes| bytes.len()).unwrap_or(0),
        m4a_bytes as i64 - old_bytes as i64,
    );
}


/// Peak of the Access prover only: old 15-column batch vs the M4a packed
/// variant. One variant per process, because the peak is monotonic.
#[test]
#[ignore = "measures the Access prover peak; LOG and M4A=0/1, --ignored --nocapture"]
fn m4a_access_peak() {
    let log_cycles: usize = std::env::var("LOG")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(16);
    let use_m4a = std::env::var("M4A").map(|value| value != "0").unwrap_or(false);
    let trace = bench_trace((1 << log_cycles) - 1);
    let witness = register_twist_witness(&trace).expect("register witness");
    let started = std::time::Instant::now();
    if use_m4a {
        let proof = crate::local_shared::prove_access_m4a(&witness).expect("m4a access");
        assert!(crate::local_shared::verify_access_m4a(&proof).expect("verify"));
    } else {
        let proof = crate::local_shared::prove_local_shared(&witness).expect("old access");
        assert!(crate::local_shared::verify_local_shared(&proof).expect("verify"));
    }
    let wall_ms = started.elapsed().as_secs_f64() * 1000.0;
    println!(
        "m4a access peak: log=2^{log_cycles} m4a={use_m4a} wall={wall_ms:.1} ms \
         peak_rss={:.1} MiB footprint={:.1} MiB",
        peak_rss_bytes() as f64 / 1048576.0,
        footprint_bytes() as f64 / 1048576.0,
    );
}


/// Binding-audit experiment E1: tamper the Access claims in an in-memory proof
/// and record which verifier stage rejects it (see docs/M4A_BINDING_AUDIT.md).
///
/// Runs at the linear-twist minimum (8192 cycles) so `prove_local_shared` /
/// `prove_access_m4a` are active. In-memory mutation matches the benchmark's
/// trust boundary (it verifies the in-memory proof).
#[test]
#[ignore = "runs a small unified proof; --ignored --nocapture"]
fn binding_audit_tamper_matrix() {
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    let adds: u32 = std::env::var("ADDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8191);
    let mut rom = (0..adds)
        .map(|index| {
            Instruction {
                op: Op::Addi,
                rd: 1,
                rs1: 1,
                rs2: 0,
                imm: i64::from(index) + 1,
                shamt: 0,
            }
            .encode()
        })
        .collect::<Vec<_>>();
    rom.push(Instruction::new(Op::Ecall).encode());
    let program = ProgramImage::new(0x1000, rom);
    let config = MachineConfig {
        entry: 0x1000,
        rom_base: 0x1000,
        ram_base: 0x1000_0000,
        ram_size: 0x100,
        stack_top: 0x1000_0100,
        max_cycles: 1_000_000,
    };
    let trace = magnetar_executor::execute(&program, config).expect("trace");
    let statement = crate::Statement {
        program_hash: crate::program_hash(&program),
        rom: trace.rom.clone(),
        trace_commitment: crate::trace_digest(&trace),
        trace_claim_root: crate::claim_table::statement_claim_root(&trace),
        access_statement_digest: crate::statement_access_digest(&trace),
        config: trace.config.clone(),
        initial_state: trace.initial_state.clone(),
        initial_ram: trace.initial_ram.clone(),
        final_state: trace.final_state.clone(),
        trace_len: trace.len() as u64,
        output: trace.io_output.clone(),
        input: trace.io_input.clone(),
        halted: trace.halted,
        exit_code: trace.exit_code,
    };
    let proof = crate::prove_unified_trace_dynamic_native(&trace, 64).expect("prove");
    let baseline_full = crate::verify_unified_trace(&trace, &proof, 64).is_ok();
    let baseline_statement = crate::verify_native_unified(&statement, &proof, 64).is_ok();
    println!(
        "binding audit E1 baseline: trace-carrying={baseline_full} statement={baseline_statement}"
    );
    assert!(baseline_full && baseline_statement, "baseline proof must verify");

    let outcome = |label: &str, candidate: &crate::UnifiedTraceProof| {
        let full = crate::verify_unified_trace(&trace, candidate, 64);
        let statement = crate::verify_native_unified(&statement, candidate, 64);
        println!(
            "binding audit E1 {label:<42} trace-carrying={:<5} statement={:<5} ({})",
            full.is_ok(),
            statement.is_ok(),
            full.as_ref()
                .err()
                .map(|error| error.to_string())
                .or_else(|| statement.as_ref().err().map(|error| error.to_string()))
                .unwrap_or_default()
                .chars()
                .take(70)
                .collect::<String>(),
        );
    };

    let plus_one = magnetar_constraint::F2_128::from(1u64);
    println!(
        "binding audit E1 branches: ram.linear={} ram.m4a={} reg.linear={} reg.m4a={}",
        proof.access.ram.linear.is_some(),
        proof.access.ram.linear_m4a.is_some(),
        proof.access.registers.linear.is_some(),
        proof.access.registers.linear_m4a.is_some(),
    );
    if proof.access.ram.linear.is_some() {
        let mut tampered = proof.clone();
        let value = tampered.access.ram.linear.as_ref().unwrap().local.values[3][0];
        tampered.access.ram.linear.as_mut().unwrap().local.values[3][0] = value + plus_one;
        outcome("ram linear values[3][0] (address terminal) += 1", &tampered);
    }
    if proof.access.registers.linear.is_some() {
        let mut tampered = proof.clone();
        let value = tampered.access.registers.linear.as_ref().unwrap().local.values[3][0];
        tampered.access.registers.linear.as_mut().unwrap().local.values[3][0] = value + plus_one;
        outcome("register linear values[3][0] (address) += 1", &tampered);

        let mut tampered = proof.clone();
        let value = tampered.access.registers.linear.as_ref().unwrap().local.endpoints[0];
        tampered.access.registers.linear.as_mut().unwrap().local.endpoints[0] = value + plus_one;
        outcome("register linear endpoints[0] (initial) += 1", &tampered);

        let mut tampered = proof.clone();
        let value = tampered.access.registers.linear.as_ref().unwrap().local.values[2][0];
        tampered.access.registers.linear.as_mut().unwrap().local.values[2][0] = value + plus_one;
        outcome("register linear values[2][0] (increment) += 1", &tampered);
    }
}
