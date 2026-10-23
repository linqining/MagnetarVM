use magnetar_executor::execute;
use magnetar_runtime::unified_gated::{prove_unified_gated, verify_unified_gated};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn main() {
    let program = ProgramImage::new(
        0x1000,
        vec![
            Instruction {
                op: Op::Add,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Xor,
                rd: 2,
                rs1: 1,
                rs2: 0,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction::new(Op::Ecall).encode(),
        ],
    );
    let trace = execute(
        &program,
        MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x40,
            stack_top: 0x1000_0040,
            max_cycles: 100,
        },
    )
    .unwrap();
    let proof = prove_unified_gated(&trace, 8).unwrap();
    verify_unified_gated(&trace, &proof, 8).unwrap();
    println!(
        "unified gated: {} B, gated claims={}",
        bincode::serialize(&proof.unified).unwrap().len(),
        proof.unified.gated.is_some()
    );
}
