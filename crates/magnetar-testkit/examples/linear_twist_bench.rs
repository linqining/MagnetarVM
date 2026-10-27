use std::time::Instant;

use magnetar_executor::execute;
use magnetar_runtime::linear_twist::{
    prove_linear_rw, prove_val_evaluation, verify_linear_rw, verify_val_evaluation,
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
    let rw = prove_linear_rw(&witness).unwrap();
    let rw_prove = started.elapsed();
    let started = Instant::now();
    assert!(verify_linear_rw(&witness, &rw).unwrap());
    let rw_verify = started.elapsed();
    let started = Instant::now();
    let val = prove_val_evaluation(&witness).unwrap();
    let val_prove = started.elapsed();
    let started = Instant::now();
    assert!(verify_val_evaluation(&witness, &val).unwrap());
    let val_verify = started.elapsed();
    println!(
        "rows={rows} rw_rounds={} val_rounds={} rw_prove={rw_prove:?} rw_verify={rw_verify:?} val_prove={val_prove:?} val_verify={val_verify:?}",
        rw.rounds.len(),
        val.rounds.len(),
    );
}
