use magnetar_executor::{execute_with_io, ExecutionIo};
use magnetar_runtime::{prove_unified_trace, verify_unified_proof};
use magnetar_spec::{syscall, Instruction, MachineConfig, Op, ProgramImage};

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
    for (name, number) in [
        ("hint", syscall::SYS_HINT),
        ("clock", syscall::SYS_CLOCK),
        ("write", syscall::SYS_WRITE),
        ("read", syscall::SYS_READ),
    ] {
        let mut body = vec![
            ins(Op::Lui, 20, 0, 0, 0x1000_0000, 0),
            ins(
                Op::Addi,
                10,
                0,
                0,
                if number == syscall::SYS_WRITE { 1 } else { 0 },
                0,
            ),
            ins(Op::Addi, 11, 20, 0, 0, 0),
            ins(Op::Addi, 12, 0, 0, 2, 0),
            ins(Op::Addi, 17, 0, 0, number as i64, 0),
            ins(Op::Ecall, 0, 0, 0, 0, 0),
        ];
        body.push(ins(Op::Ebreak, 0, 0, 0, 0, 0));
        let program = ProgramImage::new(0x1000, body);
        let mut io = ExecutionIo::default();
        io.input = vec![0x41, 0x42];
        let trace = execute_with_io(&program, config.clone(), &mut io).unwrap();
        println!(
            "{name} rows {} a0 {:#x}",
            trace.rows.len(),
            trace.final_state.reg(10)
        );
        match prove_unified_trace(&trace, 8).and_then(|proof| verify_unified_proof(&proof)) {
            Ok(()) => println!("{name} proof ok"),
            Err(error) => println!("{name} proof FAIL {error}"),
        }
    }
}
