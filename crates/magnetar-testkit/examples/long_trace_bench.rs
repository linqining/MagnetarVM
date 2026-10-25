use std::time::Instant;

use magnetar_executor::execute;
use magnetar_runtime::{prove_chunked_trace_streaming, verify_chunked_trace};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn program(instructions: i64) -> ProgramImage {
    let mut rom = vec![Instruction {
        op: Op::Addi,
        rd: 1,
        rs1: 0,
        rs2: 0,
        imm: 1,
        shamt: 0,
    }
    .encode()];
    for index in 0..instructions {
        rom.push(
            Instruction {
                op: Op::Slli,
                rd: 3,
                rs1: 1,
                rs2: 0,
                imm: 1,
                shamt: 0,
            }
            .encode(),
        );
        if index % 4 == 0 {
            rom.push(
                Instruction {
                    op: Op::Xor,
                    rd: 1,
                    rs1: 3,
                    rs2: 1,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
            );
        }
    }
    rom.push(Instruction::new(Op::Ecall).encode());
    ProgramImage::new(0x1000, rom)
}

fn main() {
    for instructions in [32i64, 64, 128] {
        let program = program(instructions);
        let trace = execute(
            &program,
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x100,
                stack_top: 0x1000_0100,
                max_cycles: 10_000,
            },
        )
        .unwrap();
        for chunk in [8usize, 16] {
            let started = Instant::now();
            let proof = prove_chunked_trace_streaming(&trace, 16, chunk).unwrap();
            let prove_time = started.elapsed();
            let started = Instant::now();
            verify_chunked_trace(&trace, &proof, 16).unwrap();
            let verify_time = started.elapsed();
            let bytes = bincode::serialize(&proof).unwrap().len();
            println!(
                "instructions={instructions} rows={} chunk={chunk} chunks={} proof={bytes} prove={prove_time:?} verify={verify_time:?}",
                trace.rows.len(),
                proof.chunks.len()
            );
        }
    }
}
