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
fn real_shapes(trace: &Trace) -> Vec<TableShape> {
    let mut shapes = Vec::new();

    let ram_witness = BinaryTwistWitness::from_trace(trace).expect("RAM twist witness");
    let ram = batch_tables_committed_only(&ram_witness).expect("RAM batch tables");
    for (name, table) in [
        ("ram.addr", &ram.addr),
        ("ram.inc", &ram.inc),
        ("ram.initial", &ram.initial),
        ("ram.read_value", &ram.read_value),
        ("ram.write_value", &ram.write_value),
    ] {
        shapes.push(TableShape::new(name, table, Scaling::Fixed, Role::Other));
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
            shapes.push(TableShape::new("rom", &rom, Scaling::Cycles, Role::Rom));
        }
    }
    if let Ok(shift) = BinaryRouterWitness::from_trace_mode(trace, RouterMode::Shifts) {
        shapes.push(TableShape::new(
            "shift_router",
            &shift.table(),
            Scaling::Cycles,
            Role::Other,
        ));
    }
    if let Ok(store) = BinaryRouterWitness::from_trace_mode(trace, RouterMode::Stores) {
        shapes.push(TableShape::new(
            "store_router",
            &store.table(),
            Scaling::Cycles,
            Role::Other,
        ));
    }

    let register_witness = register_twist_witness(trace).expect("register twist witness");
    let register = batch_tables_committed_only(&register_witness).expect("register batch tables");
    shapes.push(TableShape::new(
        "register.addr",
        &register.addr,
        Scaling::Cycles,
        Role::RegisterAddress,
    ));
    shapes.push(TableShape::new(
        "register.inc",
        &register.inc,
        Scaling::Cycles,
        Role::Other,
    ));
    shapes.push(TableShape::new(
        "register.initial",
        &register.initial,
        Scaling::Fixed,
        Role::Other,
    ));
    shapes.push(TableShape::new(
        "register.read_value",
        &register.read_value,
        Scaling::Cycles,
        Role::Other,
    ));
    shapes.push(TableShape::new(
        "register.write_value",
        &register.write_value,
        Scaling::Cycles,
        Role::Other,
    ));

    let trace_witness = trace_witness(trace).expect("trace witness");
    shapes.push(TableShape::new(
        "trace",
        &P3MosaicTable {
            columns: vec![trace_witness.values],
        },
        Scaling::Cycles,
        Role::Trace,
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

#[test]
#[ignore = "builds a real 2^16 trace; run with --ignored --nocapture"]
fn m4a_real_table_set_projection() {
    let trace = bench_trace((1 << BUILT_LOG_CYCLES) - 1);
    assert_eq!(trace.len(), 1 << BUILT_LOG_CYCLES, "one row per cycle");

    let shapes = real_shapes(&trace);
    let register_witness = register_twist_witness(&trace).expect("register witness");
    let address_bits = crate::linear_twist::witness_shape(&register_witness).address_bits;

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
