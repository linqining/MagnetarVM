use magnetar_executor::execute;
use magnetar_runtime::{prove_unified_trace, verify_unified_proof};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn ins(op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64, shamt: u8) -> u32 {
    Instruction {
        op,
        rd,
        rs1,
        rs2,
        imm,
        shamt,
    }
    .encode()
}

fn main() {
    let config = MachineConfig {
        entry: 0x1000,
        rom_base: 0x1000,
        ram_base: 0x1000_0000,
        ram_size: 0x1000,
        stack_top: 0x1000_1000,
        max_cycles: 1000,
    };
    let cases = [
        ("xor", Op::Xor, 0x5a5i64, 0x3c3i64, 0u8),
        ("and", Op::And, 0x5a5, 0x3c3, 0),
        ("or", Op::Or, 0x5a5, 0x3c3, 0),
        ("slli", Op::Slli, 0x5a5, 0, 5),
        ("srli", Op::Srli, 0x5a5, 0, 2),
        ("srai", Op::Srai, -8, 0, 1),
        ("mul", Op::Mul, 12, 10, 0),
        ("div", Op::Div, 100, 10, 0),
        ("rem", Op::Rem, 105, 10, 0),
        ("mulh", Op::Mulh, 12, 10, 0),
    ];
    for (name, op, left, right, shamt) in cases {
        let program = ProgramImage::new(
            0x1000,
            vec![
                ins(Op::Addi, 1, 0, 0, left, 0),
                ins(Op::Addi, 2, 0, 0, right, 0),
                ins(op, 3, 1, 2, 0, shamt),
                ins(Op::Ecall, 0, 0, 0, 0, 0),
            ],
        );
        let trace = execute(&program, config.clone()).unwrap();
        let proof = prove_unified_trace(&trace, 8).unwrap();
        match verify_unified_proof(&proof) {
            Ok(()) => println!("{name} ok"),
            Err(error) => println!("{name} FAIL {error}"),
        }
    }
}
