use std::time::Instant;

use magnetar_executor::execute;
use magnetar_runtime::{
    prove_chunked_trace, prove_chunked_trace_compact_sequential, prove_chunked_trace_streaming,
    prove_chunked_trace_streaming_sequential, verify_chunked_trace,
};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn main() {
    let mut rom = (0..16)
        .map(|index| {
            Instruction {
                op: Op::Addi,
                rd: 1 + (index % 8),
                rs1: 0,
                rs2: 0,
                imm: (index + 1) as i64,
                shamt: 0,
            }
            .encode()
        })
        .collect::<Vec<_>>();
    rom.push(Instruction::new(Op::Ecall).encode());
    let program = ProgramImage::new(0x1000, rom);
    let trace = execute(
        &program,
        MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x100,
            stack_top: 0x1000_0100,
            max_cycles: 100,
        },
    )
    .unwrap();

    for chunk_size in [2usize, 4, 8] {
        for (name, parallel) in [("sequential", false), ("parallel", true)] {
            let started = Instant::now();
            let proof = if parallel {
                prove_chunked_trace_streaming(&trace, 8, chunk_size).unwrap()
            } else {
                prove_chunked_trace_streaming_sequential(&trace, 8, chunk_size).unwrap()
            };
            let prove_time = started.elapsed();
            let started = Instant::now();
            verify_chunked_trace(&trace, &proof, 8).unwrap();
            let bytes = bincode::serialize(&proof).unwrap().len();
            println!(
                "stream chunk={chunk_size} {name}: proof={bytes} prove={prove_time:?} verify={:?}",
                started.elapsed()
            );
        }
    }

    for chunk_size in [2usize, 4] {
        for (name, parallel) in [("sequential", false), ("parallel", true)] {
            let started = Instant::now();
            let proof = if parallel {
                prove_chunked_trace(&trace, 8, chunk_size).unwrap()
            } else {
                prove_chunked_trace_compact_sequential(&trace, 8, chunk_size).unwrap()
            };
            let prove_time = started.elapsed();
            let started = Instant::now();
            verify_chunked_trace(&trace, &proof, 8).unwrap();
            let bytes = bincode::serialize(&proof).unwrap().len();
            println!(
                "compact chunk={chunk_size} {name}: proof={bytes} prove={prove_time:?} verify={:?}",
                started.elapsed()
            );
        }
    }
}
