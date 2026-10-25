use std::time::Instant;

use magnetar_pcs::P3SharedPcs;
use magnetar_proof::RingSwitchPackedBitPcs;
use magnetar_runtime::simd_dual::{prove_alu_only_batch_bits, verify_alu_only_batch_bits};
use magnetar_runtime::simd_f2::{GatedAluRow, GatedCpuRow};

fn main() {
    let width = 16usize;
    let full = GatedCpuRow::new(width);
    let alu = GatedAluRow::new(width);
    let full_cols = (full.relation.num_vars + 1).next_power_of_two();
    let alu_cols = (alu.relation.num_vars + 2).next_power_of_two();
    println!(
        "width={width} full_vars={} full_base={} alu_vars={} alu_base={} reduction={}x",
        full.relation.num_vars,
        full_cols,
        alu.relation.num_vars,
        alu_cols,
        full_cols / alu_cols
    );

    let backend =
        RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
    for cycles in [16usize, 64, 256] {
        let started = Instant::now();
        let (proof, layout) = prove_alu_only_batch_bits(width, cycles, &backend).unwrap();
        let prove_time = started.elapsed();
        let bytes = bincode::serialize(&proof).unwrap().len();
        let started = Instant::now();
        verify_alu_only_batch_bits(width, cycles, &proof, &layout, &backend).unwrap();
        println!(
            "cycles={cycles} bits={} proof={bytes} prove={prove_time:?} verify={:?}",
            cycles * alu_cols,
            started.elapsed()
        );
    }
}
