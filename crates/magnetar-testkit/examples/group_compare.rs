//! Compare unified proof size/time for SIMD group 2 vs 4.

use std::time::Instant;

use magnetar_executor::execute;
use magnetar_runtime::{prove_unified_trace_group, unified_proof_sizes, verify_unified_proof};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rom = (1..=64)
        .map(|index| {
            Instruction {
                op: Op::Addi,
                rd: (index % 8) as u8,
                rs1: 0,
                rs2: 0,
                imm: index,
                shamt: 0,
            }
            .encode()
        })
        .collect::<Vec<_>>();
    rom.push(Instruction::new(Op::Ecall).encode());
    let program = ProgramImage::new(0x1000, rom);
    let config = MachineConfig {
        entry: 0x1000,
        rom_base: 0x1000,
        ram_base: 0x1000_0000,
        ram_size: 0x1000,
        stack_top: 0x1000_1000,
        max_cycles: 100_000,
    };
    let trace = execute(&program, config)?;
    println!(" group  bytes   prove_ms  verify_ms");
    for group in [2usize, 4] {
        let started = Instant::now();
        let proof = prove_unified_trace_group(&trace, 8, group)?;
        let prove_ms = started.elapsed().as_secs_f64() * 1000.0;
        let started = Instant::now();
        verify_unified_proof(&proof)?;
        let verify_ms = started.elapsed().as_secs_f64() * 1000.0;
        println!(
            " {group:>5}  {:>6}  {prove_ms:>8.1}  {verify_ms:>9.1}",
            unified_proof_sizes(&proof)?.total()
        );
    }
    Ok(())
}
