use std::time::Instant;

use magnetar_pcs::P3SharedPcs;
use magnetar_proof::{BitPcs, DirectBitPcs, RingSwitchPackedBitPcs};
use magnetar_runtime::simd_dual::{prove_gated_dual_batch_bits, verify_gated_dual_batch_bits};
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

fn run<B>(name: &str, cycles: usize, backend: &B)
where
    B: BitPcs,
    B::Commitment: serde::Serialize,
    B::Opening: serde::Serialize,
{
    let rows = rows(cycles);
    let started = Instant::now();
    let (proof, layout) = prove_gated_dual_batch_bits(8, &rows, backend).expect("prove");
    let prove_time = started.elapsed();
    let bytes = bincode::serialize(&proof).expect("encode").len();
    let started = Instant::now();
    verify_gated_dual_batch_bits(8, &rows, &proof, &layout, backend).expect("verify");
    let verify_time = started.elapsed();
    println!("{name} q={cycles}: proof={bytes} prove={prove_time:?} verify={verify_time:?}");
}

fn main() {
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    let direct = DirectBitPcs::new(pcs.clone());
    let ring = RingSwitchPackedBitPcs::new(pcs);
    for cycles in [2usize, 4, 8] {
        run("M4", cycles, &direct);
        run("M5-ring", cycles, &ring);
    }
}
