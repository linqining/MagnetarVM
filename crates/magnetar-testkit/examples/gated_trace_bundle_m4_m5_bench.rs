use std::time::Instant;

use magnetar_executor::execute;
use magnetar_pcs::P3SharedPcs;
use magnetar_proof::{BitPcs, DirectBitPcs, RingSwitchPackedBitPcs};
use magnetar_runtime::gated_bundle::{
    prove_gated_bundle_from_trace, verify_gated_bundle_from_trace,
};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn trace() -> magnetar_spec::Trace {
    let program = ProgramImage::new(
        0x1000,
        vec![
            Instruction {
                op: Op::Add,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Xor,
                rd: 2,
                rs1: 1,
                rs2: 0,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Slli,
                rd: 3,
                rs1: 2,
                rs2: 0,
                imm: 0,
                shamt: 2,
            }
            .encode(),
            Instruction::new(Op::Ecall).encode(),
        ],
    );
    execute(
        &program,
        MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x40,
            stack_top: 0x1000_0040,
            max_cycles: 100,
        },
    )
    .unwrap()
}

fn run<B>(name: &str, backend: &B)
where
    B: BitPcs,
    B::Commitment: serde::Serialize,
    B::Opening: serde::Serialize,
{
    let trace = trace();
    let started = Instant::now();
    let bundle = prove_gated_bundle_from_trace(&trace, 8, backend).expect("prove");
    let prove_time = started.elapsed();
    let cpu = bincode::serialize(&bundle.cpu).expect("cpu").len();
    let register = bundle
        .register
        .as_ref()
        .map(|proof| bincode::serialize(proof).expect("register").len())
        .unwrap_or(0);
    let aux = bundle
        .aux
        .as_ref()
        .map(|proof| format!("{proof:?}").len())
        .unwrap_or(0);
    let shift = bincode::serialize(&bundle.shift_proofs)
        .expect("shift")
        .len();
    let claims = bincode::serialize(&bundle.claims).expect("claims").len();
    let started = Instant::now();
    verify_gated_bundle_from_trace(&trace, 8, &bundle, backend).expect("verify");
    let verify_time = started.elapsed();
    println!(
        "{name}: cpu={cpu} register={register} aux={aux} shift={shift} claims={claims} total={} prove={prove_time:?} verify={verify_time:?}",
        cpu + register + aux + shift + claims
    );
}

fn main() {
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    run("M4", &DirectBitPcs::new(pcs.clone()));
    run("M5-ring", &RingSwitchPackedBitPcs::new(pcs));
}
