use std::time::Instant;

use magnetar_pcs::P3SharedPcs;
use magnetar_proof::RingSwitchPackedBitPcs;
use magnetar_runtime::simd_dual::{
    prove_alu_only_batch_bits, prove_alu_pc_batch_bits, prove_gated_dual_batch_bits,
    verify_alu_only_batch_bits, verify_alu_pc_batch_bits,
};
use magnetar_runtime::simd_f2::{GatedAluOp, GatedCpuRowInput};
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
    let full_rows = (0..16usize)
        .map(|index| {
            (
                0x1000 + 4 * index as u64,
                GatedCpuRowInput::Alu {
                    left: 0x12 + index as u64,
                    right: 0x34 + index as u64,
                    op: if index % 2 == 0 {
                        GatedAluOp::Add
                    } else {
                        GatedAluOp::Xor
                    },
                },
            )
        })
        .collect::<Vec<_>>();
    let started = Instant::now();
    let (full_proof, _) = prove_gated_dual_batch_bits(16, &full_rows, &backend).unwrap();
    let full_time = started.elapsed();
    let full_bytes = bincode::serialize(&full_proof).unwrap().len();
    println!(
        "full gated batch cycles=16 bits={} proof={} prove={:?}",
        full_cols * 16,
        full_bytes,
        full_time
    );

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

        let started = Instant::now();
        let initial_pc = 0x1000;
        let final_pc = initial_pc + 4 * cycles as u64;
        let (proof, layout) =
            prove_alu_pc_batch_bits(width, cycles, initial_pc, final_pc, &backend).unwrap();
        let prove_time = started.elapsed();
        let bytes = bincode::serialize(&proof).unwrap().len();
        let started = Instant::now();
        verify_alu_pc_batch_bits(
            width, cycles, initial_pc, final_pc, &proof, &layout, &backend,
        )
        .unwrap();
        println!(
            "  alu+pc cycles={cycles} proof={bytes} prove={prove_time:?} verify={:?}",
            started.elapsed()
        );
    }
}
