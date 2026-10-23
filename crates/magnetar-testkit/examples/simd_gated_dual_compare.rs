use std::time::Instant;

use magnetar_cpu::StepOp;
use magnetar_runtime::simd_dual::{
    prove_dual_batch, prove_gated_dual_batch, verify_gated_dual_batch,
};
use magnetar_runtime::simd_f2::{GatedAluOp, GatedCpuRowInput};

fn main() {
    let started = Instant::now();
    let (old, old_layout) = prove_dual_batch(8, StepOp::Add, 2).expect("old prove");
    let old_time = started.elapsed();
    let old_bytes = bincode::serialize(&old).expect("encode").len();
    let started = Instant::now();
    magnetar_runtime::simd_dual::verify_dual_batch(8, StepOp::Add, 2, &old, &old_layout)
        .expect("old verify");
    let old_verify = started.elapsed();

    let rows = [
        (
            0x1000,
            GatedCpuRowInput::Alu {
                left: 0x12,
                right: 0x34,
                op: GatedAluOp::Add,
            },
        ),
        (
            0x1004,
            GatedCpuRowInput::Alu {
                left: 0x13,
                right: 0x35,
                op: GatedAluOp::Add,
            },
        ),
    ];
    let started = Instant::now();
    let (gated, gated_layout) = prove_gated_dual_batch(8, &rows).expect("gated prove");
    let gated_time = started.elapsed();
    let gated_bytes = bincode::serialize(&gated).expect("encode").len();
    let started = Instant::now();
    verify_gated_dual_batch(8, &rows, &gated, &gated_layout).expect("gated verify");
    let gated_verify = started.elapsed();

    let mixed = [
        rows[0],
        (
            0x1004,
            GatedCpuRowInput::Memory {
                rs1: 0x10,
                imm: 2,
                value: 0x34,
                is_mem: true,
            },
        ),
    ];
    let (mixed_proof, mixed_layout) = prove_gated_dual_batch(8, &mixed).expect("mixed prove");
    let mixed_bytes = bincode::serialize(&mixed_proof).expect("encode").len();
    verify_gated_dual_batch(8, &mixed, &mixed_proof, &mixed_layout).expect("mixed verify");

    println!("always-active dual q=2: {old_bytes} B prove={old_time:?} verify={old_verify:?}");
    println!(
        "gated dual q=2:         {gated_bytes} B prove={gated_time:?} verify={gated_verify:?}"
    );
    println!("gated dual mixed q=2:   {mixed_bytes} B");
}
