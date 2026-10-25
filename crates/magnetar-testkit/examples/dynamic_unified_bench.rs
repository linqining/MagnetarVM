use std::time::Instant;

use magnetar_executor::execute;
use magnetar_runtime::{
    prove_unified_trace, prove_unified_trace_dynamic, prove_unified_trace_dynamic_native,
    verify_unified_trace,
};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn main() {
    let program = ProgramImage::new(
        0x1000,
        vec![
            Instruction {
                op: Op::Addi,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 11,
                shamt: 0,
            }
            .encode(),
            Instruction::new(Op::Ecall).encode(),
        ],
    );
    let trace = execute(
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
    .unwrap();

    let started = Instant::now();
    let full = prove_unified_trace(&trace, 8).unwrap();
    let full_time = started.elapsed();
    let full_bytes = bincode::serialize(&full).unwrap().len();
    let started = Instant::now();
    verify_unified_trace(&trace, &full, 8).unwrap();
    let full_verify = started.elapsed();

    let started = Instant::now();
    let dynamic = prove_unified_trace_dynamic(&trace, 8).unwrap();
    let dynamic_time = started.elapsed();
    let dynamic_bytes = bincode::serialize(&dynamic).unwrap().len();
    let started = Instant::now();
    verify_unified_trace(&trace, &dynamic, 8).unwrap();
    let dynamic_verify = started.elapsed();

    println!("full={full_bytes}B prove={full_time:?} verify={full_verify:?}");
    println!("dynamic={dynamic_bytes}B prove={dynamic_time:?} verify={dynamic_verify:?}");

    let started = Instant::now();
    let native = prove_unified_trace_dynamic_native(&trace, 8).unwrap();
    let native_time = started.elapsed();
    let native_bytes = bincode::serialize(&native).unwrap().len();
    let started = Instant::now();
    verify_unified_trace(&trace, &native, 8).unwrap();
    let native_verify = started.elapsed();
    println!("native={native_bytes}B prove={native_time:?} verify={native_verify:?}");
}
