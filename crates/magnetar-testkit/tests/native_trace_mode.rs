use magnetar_executor::execute;
use magnetar_runtime::{prove_unified_trace_dynamic_native_trace, verify_unified_trace};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

#[test]
fn native_trace_mode_omits_claim_proof() {
    let mut rom = Vec::new();
    for index in 0..63 {
        rom.push(
            Instruction {
                op: Op::Addi,
                rd: 1,
                rs1: 1,
                rs2: 0,
                imm: index + 1,
                shamt: 0,
            }
            .encode(),
        );
    }
    rom.push(Instruction::new(Op::Ecall).encode());
    let trace = execute(
        &ProgramImage::new(0x1000, rom),
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
    let proof = prove_unified_trace_dynamic_native_trace(&trace, 8).unwrap();
    assert!(proof.claim_proof.is_none());
    assert!(proof.trace_logup_shout.is_some());
    verify_unified_trace(&trace, &proof, 8).unwrap();
}
