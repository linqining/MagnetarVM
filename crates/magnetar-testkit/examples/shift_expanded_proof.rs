//! Proof over a program transformed by the fixed register-shift expansion.

use magnetar_runtime::{
    prove_unified_trace, unified_proof_sizes, verify_unified_trace_statement, ReferencePipeline,
};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn main() {
    let program = ProgramImage::new(
        0x1000,
        vec![
            Instruction {
                op: Op::Addi,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 0x234,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Addi,
                rd: 2,
                rs1: 0,
                rs2: 0,
                imm: 9,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Sll,
                rd: 3,
                rs1: 1,
                rs2: 2,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction::new(Op::Ebreak).encode(),
        ],
    );
    let config = MachineConfig {
        entry: 0x1000,
        rom_base: 0x1000,
        ram_base: 0x1000_0000,
        ram_size: 0x1000,
        stack_top: 0x1000_1000,
        max_cycles: 1000,
    };
    let outcome = ReferencePipeline::run_expanded(&program, config, 8).unwrap();
    let trace = outcome.trace;
    assert_eq!(trace.final_state.reg(3), 0x234u64 << 9);
    let proof = prove_unified_trace(&trace, 8).unwrap();
    verify_unified_trace_statement(&outcome.statement, &trace, &proof, 8).unwrap();
    println!(
        "expanded rows {} size {} B",
        trace.rows.len(),
        unified_proof_sizes(&proof).unwrap().total()
    );
}
