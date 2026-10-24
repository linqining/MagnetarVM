//! Small representative workload suite for the unified proof path.
//!
//! Covers arithmetic, RAM traffic, and shifts. This is an incremental step
//! toward the paper's 15-workload suite.

use std::time::Instant;

use magnetar_executor::execute;
use magnetar_runtime::{prove_unified_trace, unified_proof_sizes, verify_unified_proof};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn config() -> MachineConfig {
    MachineConfig {
        entry: 0x1000,
        rom_base: 0x1000,
        ram_base: 0x1000_0000,
        ram_size: 0x1000,
        stack_top: 0x1000_1000,
        max_cycles: 100_000,
    }
}

fn addi(rd: usize, rs1: usize, imm: i64) -> u32 {
    Instruction {
        op: Op::Addi,
        rd: rd as u8,
        rs1: rs1 as u8,
        rs2: 0,
        imm,
        shamt: 0,
    }
    .encode()
}

fn program(body: Vec<u32>) -> ProgramImage {
    let mut rom = body;
    rom.push(Instruction::new(Op::Ecall).encode());
    ProgramImage::new(0x1000, rom)
}

fn workloads() -> Vec<(&'static str, ProgramImage)> {
    let fib = program(vec![
        addi(1, 0, 0),
        addi(2, 0, 1),
        addi(3, 1, 2),
        addi(2, 2, 3),
        addi(3, 2, 1),
        addi(2, 2, 3),
        addi(3, 2, 1),
        addi(2, 2, 3),
        addi(3, 2, 1),
    ]);
    let memory = program(vec![
        Instruction {
            op: Op::Lui,
            rd: 20,
            rs1: 0,
            rs2: 0,
            imm: 0x1000_0000,
            shamt: 0,
        }
        .encode(),
        addi(5, 0, 0x1234),
        Instruction {
            op: Op::Sd,
            rd: 0,
            rs1: 20,
            rs2: 5,
            imm: 8,
            shamt: 0,
        }
        .encode(),
        Instruction {
            op: Op::Ld,
            rd: 6,
            rs1: 20,
            rs2: 0,
            imm: 8,
            shamt: 0,
        }
        .encode(),
    ]);
    let shifts = program(vec![
        addi(1, 0, 0x5a5),
        Instruction {
            op: Op::Slli,
            rd: 2,
            rs1: 1,
            rs2: 0,
            imm: 0,
            shamt: 3,
        }
        .encode(),
        Instruction {
            op: Op::Srli,
            rd: 3,
            rs1: 2,
            rs2: 0,
            imm: 0,
            shamt: 2,
        }
        .encode(),
        Instruction {
            op: Op::Xor,
            rd: 4,
            rs1: 1,
            rs2: 3,
            imm: 0,
            shamt: 0,
        }
        .encode(),
    ]);
    let loop_workload = program(vec![
        addi(1, 0, 3),
        addi(1, 1, -1),
        Instruction {
            op: Op::Bne,
            rd: 0,
            rs1: 1,
            rs2: 0,
            imm: -4,
            shamt: 0,
        }
        .encode(),
    ]);
    let mem_loop = program(vec![
        Instruction {
            op: Op::Lui,
            rd: 20,
            rs1: 0,
            rs2: 0,
            imm: 0x1000_0000,
            shamt: 0,
        }
        .encode(),
        addi(1, 0, 0),
        addi(2, 0, 8),
        Instruction {
            op: Op::Sd,
            rd: 0,
            rs1: 20,
            rs2: 1,
            imm: 0,
            shamt: 0,
        }
        .encode(),
        Instruction {
            op: Op::Ld,
            rd: 3,
            rs1: 20,
            rs2: 0,
            imm: 0,
            shamt: 0,
        }
        .encode(),
        addi(1, 1, 1),
        addi(2, 2, -1),
        Instruction {
            op: Op::Bne,
            rd: 0,
            rs1: 2,
            rs2: 0,
            imm: -16,
            shamt: 0,
        }
        .encode(),
    ]);
    let clock = program(vec![
        addi(17, 0, 1001),
        Instruction::new(Op::Ecall).encode(),
        addi(17, 0, 93),
        Instruction::new(Op::Ecall).encode(),
    ]);
    let branchy = program(vec![
        addi(1, 0, 5),
        addi(2, 0, 0),
        Instruction {
            op: Op::Beq,
            rd: 0,
            rs1: 2,
            rs2: 1,
            imm: 8,
            shamt: 0,
        }
        .encode(),
        addi(2, 2, 1),
        Instruction {
            op: Op::Bne,
            rd: 0,
            rs1: 2,
            rs2: 1,
            imm: -8,
            shamt: 0,
        }
        .encode(),
        addi(2, 2, 3),
    ]);
    let alu = program(
        (1..=24)
            .map(|index| {
                Instruction {
                    op: if index % 3 == 0 { Op::Add } else { Op::Addi },
                    rd: (index % 8) as u8,
                    rs1: ((index + 1) % 8) as u8,
                    rs2: (index % 8) as u8,
                    imm: index as i64,
                    shamt: 0,
                }
                .encode()
            })
            .collect(),
    );
    vec![
        ("fibonacci", fib),
        ("memory", memory),
        ("shifts", shifts),
        ("branchy", branchy),
        ("loop", loop_workload),
        ("clock", clock),
        ("mem-loop", mem_loop),
        ("alu", alu),
    ]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!(" workload     rows  bytes   prove_ms  verify_ms");
    for (name, program) in workloads() {
        let trace = execute(&program, config())?;
        let started = Instant::now();
        let proof = prove_unified_trace(&trace, 16)?;
        let prove_ms = started.elapsed().as_secs_f64() * 1000.0;
        let started = Instant::now();
        verify_unified_proof(&proof)?;
        let verify_ms = started.elapsed().as_secs_f64() * 1000.0;
        let bytes = unified_proof_sizes(&proof)?.total();
        println!(
            " {name:<12} {:>4}  {bytes:>6}  {prove_ms:>8.1}  {verify_ms:>9.1}",
            trace.rows.len()
        );
    }
    Ok(())
}
