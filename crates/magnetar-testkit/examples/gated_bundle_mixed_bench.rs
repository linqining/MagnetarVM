use std::time::Instant;

use magnetar_runtime::gated_bundle::{prove_mixed_gated_bundle, verify_mixed_gated_bundle};
use magnetar_runtime::simd_f2::{GatedAluOp, GatedCpuRowInput};

fn main() {
    let rows = [
        (
            0x1000,
            GatedCpuRowInput::Alu {
                left: 5,
                right: 3,
                op: GatedAluOp::Add,
            },
        ),
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
    let started = Instant::now();
    let bundle = prove_mixed_gated_bundle(8, &rows).expect("prove");
    let prove_time = started.elapsed();
    let alu = bincode::serialize(&bundle.alu_cpu).expect("alu").len();
    let memory = bincode::serialize(&bundle.memory_cpu)
        .expect("memory")
        .len();
    let ram = bincode::serialize(&bundle.ram).expect("ram").len();
    let claims = bincode::serialize(&bundle.claims).expect("claims").len();
    let started = Instant::now();
    verify_mixed_gated_bundle(8, &rows, &bundle).expect("verify");
    let verify_time = started.elapsed();
    println!(
        "alu_m4={alu} memory_m5={memory} ram={ram} claims={claims} total={} prove={prove_time:?} verify={verify_time:?}",
        alu + memory + ram + claims
    );
}
