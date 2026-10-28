use std::time::Instant;

use magnetar_executor::execute;
use magnetar_runtime::binary_twist::{
    prove_binary_twist_ram_linear, verify_binary_twist_ram_linear,
};
use magnetar_runtime::register_twist::register_twist_witness;
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn main() {
    let rows = std::env::var("ROWS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1024);
    let mut rom = Vec::new();
    for index in 0..rows.saturating_sub(1) {
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
    let trace = execute(
        &ProgramImage::new(0x1000, rom),
        MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x100,
            stack_top: 0x1000_0100,
            max_cycles: 10_000_000,
        },
    )
    .unwrap();
    let witness = register_twist_witness(&trace).unwrap();
    let started = Instant::now();
    let proof = prove_binary_twist_ram_linear(&witness).unwrap();
    let prove_time = started.elapsed();
    let bytes = bincode::serialize(&proof).unwrap().len();
    let started = Instant::now();
    assert!(verify_binary_twist_ram_linear(&witness, &proof).unwrap());
    let verify_time = started.elapsed();
    let inner = &proof.local;
    let components = vec![
        ("values", bincode::serialize(&inner.values_opening).unwrap().len()),
        ("endpoints", bincode::serialize(&inner.endpoints_opening).unwrap().len()),
        ("virtual_address", bincode::serialize(&inner.virtual_address).unwrap().len()),
    ];
    println!(
        "rows={rows} bytes={bytes} prove={prove_time:?} verify={verify_time:?} components={components:?}"
    );
}
