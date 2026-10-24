//! End-to-end unified proof probe over the supported RISC-V ALU/memory forms.

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

fn program(body: Vec<u32>) -> ProgramImage {
    let mut rom = body;
    rom.push(ins(Op::Ecall, 0, 0, 0, 0, 0));
    ProgramImage::new(0x1000, rom)
}

fn cases() -> Vec<(&'static str, ProgramImage)> {
    let mut cases = Vec::new();
    for (name, op, left, right, shamt) in [
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
        ("addw", Op::Addw, 12, 10, 0),
        ("subw", Op::Subw, 12, 10, 0),
        ("sllw", Op::Sllw, 12, 2, 0),
        ("srlw", Op::Srlw, 12, 2, 0),
        ("sraw", Op::Sraw, -8, 1, 0),
    ] {
        cases.push((
            name,
            program(vec![
                ins(Op::Addi, 1, 0, 0, left, 0),
                ins(Op::Addi, 2, 0, 0, right, 0),
                ins(op, 3, 1, 2, 0, shamt),
            ]),
        ));
    }
    cases.push(("auipc", program(vec![ins(Op::Auipc, 1, 0, 0, 1, 0)])));
    cases.push((
        "jal",
        program(vec![
            ins(Op::Jal, 2, 0, 0, 8, 0),
            ins(Op::Addi, 3, 0, 0, 99, 0),
        ]),
    ));
    cases.push((
        "jalr",
        program(vec![
            ins(Op::Auipc, 1, 0, 0, 0, 0),
            ins(Op::Addi, 1, 1, 0, 16, 0),
            ins(Op::Jalr, 2, 1, 0, 0, 0),
            ins(Op::Addi, 3, 0, 0, 99, 0),
        ]),
    ));
    cases.push((
        "amoswapd",
        program(vec![
            ins(Op::Lui, 20, 0, 0, 0x1000_0000, 0),
            ins(Op::Addi, 2, 0, 0, 5, 0),
            ins(Op::Sd, 0, 20, 2, 0, 0),
            ins(Op::Addi, 3, 0, 0, 7, 0),
            ins(Op::AmoswapD, 4, 20, 3, 0, 0),
        ]),
    ));
    for (name, op) in [
        ("amoaddd", Op::AmoaddD),
        ("amoandd", Op::AmoandD),
        ("amoord", Op::AmoorD),
        ("amoxord", Op::AmoxorD),
        ("amomind", Op::AmominD),
        ("amomaxd", Op::AmomaxD),
        ("amominud", Op::AmominuD),
        ("amomaxud", Op::AmomaxuD),
        ("amoaddw", Op::AmoaddW),
        ("amoandw", Op::AmoandW),
        ("amoorw", Op::AmoorW),
        ("amoxorw", Op::AmoxorW),
        ("amominw", Op::AmominW),
        ("amomaxw", Op::AmomaxW),
        ("amominuw", Op::AmominuW),
        ("amomaxuw", Op::AmomaxuW),
    ] {
        cases.push((
            name,
            program(vec![
                ins(Op::Lui, 20, 0, 0, 0x1000_0000, 0),
                ins(Op::Addi, 2, 0, 0, 5, 0),
                ins(Op::Sd, 0, 20, 2, 0, 0),
                ins(Op::Addi, 3, 0, 0, 3, 0),
                ins(op, 4, 20, 3, 0, 0),
            ]),
        ));
    }
    cases.push((
        "lrd_scd",
        program(vec![
            ins(Op::Lui, 20, 0, 0, 0x1000_0000, 0),
            ins(Op::Addi, 2, 0, 0, 5, 0),
            ins(Op::Sd, 0, 20, 2, 0, 0),
            ins(Op::LrD, 4, 20, 0, 0, 0),
            ins(Op::Addi, 5, 0, 0, 9, 0),
            ins(Op::ScD, 6, 20, 5, 0, 0),
        ]),
    ));
    cases.push((
        "lrw_scw",
        program(vec![
            ins(Op::Lui, 20, 0, 0, 0x1000_0000, 0),
            ins(Op::Addi, 2, 0, 0, 5, 0),
            ins(Op::Sd, 0, 20, 2, 0, 0),
            ins(Op::LrW, 4, 20, 0, 0, 0),
            ins(Op::Addi, 5, 0, 0, 9, 0),
            ins(Op::ScW, 6, 20, 5, 0, 0),
        ]),
    ));
    for (name, op, left, imm) in [
        ("xori", Op::Xori, 0x5a5i64, 0x3c3i64),
        ("ori", Op::Ori, 0x5a5, 0x3c3),
        ("andi", Op::Andi, 0x5a5, 0x3c3),
        ("slti", Op::Slti, -5, 3),
        ("sltiu", Op::Sltiu, 5, 3),
    ] {
        cases.push((
            name,
            program(vec![
                ins(Op::Addi, 1, 0, 0, left, 0),
                ins(op, 3, 1, 0, imm, 0),
            ]),
        ));
    }
    for (name, op) in [
        ("beq", Op::Beq),
        ("bne", Op::Bne),
        ("blt", Op::Blt),
        ("bge", Op::Bge),
        ("bltu", Op::Bltu),
        ("bgeu", Op::Bgeu),
    ] {
        let taken = matches!(op, Op::Beq | Op::Bge | Op::Bgeu);
        let (left, right) = if taken { (1i64, 1i64) } else { (1i64, 2i64) };
        cases.push((
            name,
            program(vec![
                ins(Op::Addi, 1, 0, 0, left, 0),
                ins(Op::Addi, 2, 0, 0, right, 0),
                ins(op, 0, 1, 2, 8, 0),
                ins(Op::Addi, 3, 0, 0, 1, 0),
            ]),
        ));
    }
    for (name, load) in [
        ("lb", Op::Lb),
        ("lh", Op::Lh),
        ("lw", Op::Lw),
        ("ld", Op::Ld),
        ("lbu", Op::Lbu),
        ("lhu", Op::Lhu),
        ("lwu", Op::Lwu),
    ] {
        cases.push((
            name,
            program(vec![
                ins(Op::Lui, 20, 0, 0, 0x1000_0000, 0),
                ins(Op::Addi, 1, 0, 0, 0x5a, 0),
                ins(Op::Sd, 0, 20, 1, 0, 0),
                ins(load, 2, 20, 0, 0, 0),
            ]),
        ));
    }
    for (name, value, load, offset) in [
        ("lb_neg", 0xffi64, Op::Lb, 0i64),
        ("lh_neg", 0x8000, Op::Lh, 0),
        ("lw_neg", 0x8000_0000, Op::Lw, 0),
        ("unaligned_lw2", 0x1122_3344, Op::Lw, 2),
        ("unaligned_lw4", 0x1122_3344, Op::Lw, 4),
    ] {
        cases.push((
            name,
            program(vec![
                ins(Op::Lui, 20, 0, 0, 0x1000_0000, 0),
                ins(Op::Addi, 1, 0, 0, value, 0),
                ins(Op::Sd, 0, 20, 1, 0, 0),
                ins(load, 2, 20, 0, offset, 0),
            ]),
        ));
    }
    for (name, store) in [
        ("sb", Op::Sb),
        ("sh", Op::Sh),
        ("sw", Op::Sw),
        ("sd", Op::Sd),
    ] {
        cases.push((
            name,
            program(vec![
                ins(Op::Lui, 20, 0, 0, 0x1000_0000, 0),
                ins(Op::Addi, 1, 0, 0, 0x5a, 0),
                ins(store, 0, 20, 1, 0, 0),
                ins(Op::Ld, 2, 20, 0, 0, 0),
            ]),
        ));
    }
    cases
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
    for (name, program) in cases() {
        let trace = execute(&program, config.clone()).unwrap();
        let proof = prove_unified_trace(&trace, 8).unwrap();
        match verify_unified_proof(&proof) {
            Ok(()) => println!("{name} ok"),
            Err(error) => println!("{name} FAIL {error}"),
        }
    }
}
