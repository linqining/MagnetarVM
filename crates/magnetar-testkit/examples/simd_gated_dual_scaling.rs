use std::time::Instant;

use magnetar_runtime::simd_dual::{prove_gated_dual_batch, verify_gated_dual_batch};
use magnetar_runtime::simd_f2::{GatedAluOp, GatedCpuRowInput};

fn rows(cycles: usize) -> Vec<(u64, GatedCpuRowInput)> {
    (0..cycles)
        .map(|index| {
            let pc = 0x1000 + 4 * index as u64;
            let input = if index % 2 == 0 {
                GatedCpuRowInput::Alu {
                    left: 0x12 + index as u64,
                    right: 0x34 + index as u64,
                    op: GatedAluOp::Add,
                }
            } else {
                GatedCpuRowInput::Memory {
                    rs1: 0x10 + index as u64,
                    imm: 2,
                    value: 0x40 + index as u64,
                    is_mem: true,
                }
            };
            (pc, input)
        })
        .collect()
}

fn main() {
    for cycles in [2usize, 4, 8] {
        let rows = rows(cycles);
        let started = Instant::now();
        let (proof, layout) = prove_gated_dual_batch(8, &rows).expect("prove");
        let prove_time = started.elapsed();
        let bytes = bincode::serialize(&proof).expect("encode").len();
        let started = Instant::now();
        verify_gated_dual_batch(8, &rows, &proof, &layout).expect("verify");
        let verify_time = started.elapsed();
        println!("cycles={cycles}: proof={bytes} prove={prove_time:?} verify={verify_time:?}");
    }
}
