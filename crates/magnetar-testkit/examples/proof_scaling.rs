//! Print unified-proof size and prover/verifier time as the trace grows.
//!
//! This is a reference scaling probe, not a benchmark harness. It makes the
//! current trace-length-linear part of the proof (the carried rows) visible.

use std::time::Instant;

use magnetar_executor::execute;
use magnetar_runtime::{
    chunked_proof_sizes, prove_chunked_trace, prove_unified_trace, unified_proof_sizes,
    verify_unified_trace,
};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn program(rows: usize) -> ProgramImage {
    let mut rom = Vec::with_capacity(rows + 1);
    for index in 0..rows {
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
    ProgramImage::new(0x1000, rom)
}

fn config() -> MachineConfig {
    MachineConfig {
        entry: 0x1000,
        rom_base: 0x1000,
        ram_base: 0x1000_0000,
        ram_size: 0x100,
        stack_top: 0x1000_0100,
        max_cycles: 100_000,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!(" rows  unified_bytes  chunked_bytes  prove_ms  verify_ms");
    for rows in [2usize, 4, 8, 16, 32] {
        let trace = execute(&program(rows), config())?;
        let started = Instant::now();
        let proof = prove_unified_trace(&trace, 64)?;
        let prove_ms = started.elapsed().as_secs_f64() * 1000.0;
        let started = Instant::now();
        verify_unified_trace(&trace, &proof, 64)?;
        let verify_ms = started.elapsed().as_secs_f64() * 1000.0;
        let sizes = unified_proof_sizes(&proof)?;
        let chunked = prove_chunked_trace(&trace, 64, 4)
            .ok()
            .and_then(|proof| chunked_proof_sizes(&proof).ok())
            .map_or(0, |sizes| sizes.total());
        println!(
            "{rows:5}  {:13}  {chunked:13}  {prove_ms:8.1}  {verify_ms:9.1}",
            sizes.total()
        );
    }
    Ok(())
}
