use std::time::Instant;

use magnetar_runtime::gated_bundle::{prove_gated_bundle, verify_gated_bundle};
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
    let bundle = prove_gated_bundle(8, &rows).expect("prove");
    let prove_time = started.elapsed();
    let cpu = bincode::serialize(&bundle.cpu).expect("cpu").len();
    let ram = bundle
        .ram
        .as_ref()
        .map(|proof| bincode::serialize(proof).expect("ram").len())
        .unwrap_or(0);
    let claims = bincode::serialize(&bundle.claims).expect("claims").len();
    let started = Instant::now();
    verify_gated_bundle(8, &rows, &bundle).expect("verify");
    let verify_time = started.elapsed();
    println!(
        "cpu={cpu} ram={ram} claims={claims} total={} prove={prove_time:?} verify={verify_time:?}",
        cpu + ram + claims
    );
}
