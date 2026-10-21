//! Shared programs and fixtures for integration tests.

use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

pub fn sample_config() -> MachineConfig {
    MachineConfig {
        entry: 0x1000,
        rom_base: 0x1000,
        ram_base: 0x1000_0000,
        ram_size: 0x1000,
        stack_top: 0x1000_1000,
        max_cycles: 100,
    }
}

/// `x3 = 5 + 7; ram[0x10000000] = x3; x5 = ram[0x10000000]; exit(0)`.
pub fn arith_memory_program() -> ProgramImage {
    ProgramImage::new(
        0x1000,
        vec![
            Instruction {
                op: Op::Addi,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 5,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Addi,
                rd: 2,
                rs1: 0,
                rs2: 0,
                imm: 7,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Add,
                rd: 3,
                rs1: 1,
                rs2: 2,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Lui,
                rd: 4,
                rs1: 0,
                rs2: 0,
                imm: 0x1000_0000,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Sd,
                rd: 0,
                rs1: 4,
                rs2: 3,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Ld,
                rd: 5,
                rs1: 4,
                rs2: 0,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction::new(Op::Ecall).encode(),
        ],
    )
}
