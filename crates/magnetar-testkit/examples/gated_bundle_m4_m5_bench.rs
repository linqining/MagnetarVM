use std::time::Instant;

use magnetar_pcs::P3SharedPcs;
use magnetar_proof::{BitPcs, DirectBitPcs, RingSwitchPackedBitPcs};
use magnetar_runtime::gated_bundle::{
    prove_gated_bundle_with_backend, verify_gated_bundle_with_backend,
};
use magnetar_runtime::simd_f2::{GatedAluOp, GatedCpuRowInput};

fn rows() -> Vec<(u64, GatedCpuRowInput)> {
    vec![
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
    ]
}

fn run<B>(name: &str, backend: &B)
where
    B: BitPcs,
    B::Commitment: serde::Serialize,
    B::Opening: serde::Serialize,
{
    let rows = rows();
    let started = Instant::now();
    let bundle = prove_gated_bundle_with_backend(8, &rows, backend).expect("prove");
    let prove_time = started.elapsed();
    let cpu = bincode::serialize(&bundle.cpu).expect("cpu").len();
    let ram = bundle
        .ram
        .as_ref()
        .map(|proof| bincode::serialize(proof).expect("ram").len())
        .unwrap_or(0);
    let claims = bincode::serialize(&bundle.claims).expect("claims").len();
    let started = Instant::now();
    verify_gated_bundle_with_backend(8, &rows, &bundle, backend).expect("verify");
    let verify_time = started.elapsed();
    println!(
        "{name}: cpu={cpu} ram={ram} claims={claims} total={} prove={prove_time:?} verify={verify_time:?}",
        cpu + ram + claims
    );
}

fn main() {
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    run("M4", &DirectBitPcs::new(pcs.clone()));
    run("M5-ring", &RingSwitchPackedBitPcs::new(pcs));
}
