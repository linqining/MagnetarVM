use std::time::Instant;

use magnetar_executor::execute;
use magnetar_runtime::{prove_unified_trace_profile, verify_unified_trace};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn instruction(op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64) -> u32 {
    Instruction {
        op,
        rd,
        rs1,
        rs2,
        imm,
        shamt: 0,
    }
    .encode()
}

fn loop_program(iterations: i64) -> ProgramImage {
    let mut rom = vec![instruction(Op::Addi, 1, 0, 0, 1)];
    for _ in 0..iterations {
        rom.push(instruction(Op::Slli, 3, 1, 0, 1));
        rom.push(instruction(Op::Xor, 1, 3, 1, 0));
    }
    rom.push(Instruction::new(Op::Ecall).encode());
    ProgramImage::new(0x1000, rom)
}

fn main() {
    let row = magnetar_runtime::simd_f2::GatedCpuRow::new(16);
    println!(
        "gated row vars {} base cols {}",
        row.relation.num_vars,
        (row.relation.num_vars + 1).next_power_of_two()
    );
    for iterations in [4i64, 8, 16, 32] {
        let program = loop_program(iterations);
        let trace = execute(
            &program,
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x1000,
                stack_top: 0x1000_1000,
                max_cycles: 10_000,
            },
        )
        .unwrap();
        let started = Instant::now();
        let (proof, timings) = prove_unified_trace_profile(&trace, 16).unwrap();
        let total = started.elapsed();
        verify_unified_trace(&trace, &proof, 16).unwrap();
        let bytes = bincode::serialize(&proof).unwrap().len();
        println!(
            "iterations={iterations} rows={} bytes={bytes} total={total:?}",
            trace.rows.len()
        );
        for timing in timings {
            println!("  {:>18} {:?}", timing.stage, timing.duration);
        }
    }
}
