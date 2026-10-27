use magnetar_executor::execute;
use magnetar_runtime::{
    access_statement::AccessStatement, program_hash, prove_unified_trace_paper, trace_digest,
    verify_native_unified, Statement,
};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

#[test]
fn paper_mode_committed_shout_round_trips() {
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
    let program = ProgramImage::new(0x1000, rom);
    let config = MachineConfig {
        entry: 0x1000,
        rom_base: 0x1000,
        ram_base: 0x1000_0000,
        ram_size: 0x100,
        stack_top: 0x1000_0100,
        max_cycles: 10_000,
    };
    let trace = execute(&program, config).unwrap();
    let proof = prove_unified_trace_paper(&trace, 8).unwrap();
    assert!(proof.logup_shout.is_some());
    assert!(proof.trace_logup_shout.is_none());
    assert!(proof.claim_proof.is_some());
    assert!(proof.selected_cpu.is_some());

    let statement = Statement {
        program_hash: program_hash(&program),
        rom: trace.rom.clone(),
        trace_commitment: trace_digest(&trace),
        trace_claim_root: magnetar_runtime::trace_claims::TraceClaimTree::build(&trace).root(),
        access_statement_digest: AccessStatement::from_trace(&trace).digest(),
        config: trace.config.clone(),
        initial_state: trace.initial_state.clone(),
        initial_ram: trace.initial_ram.clone(),
        final_state: trace.final_state.clone(),
        trace_len: trace.len() as u64,
        output: trace.io_output.clone(),
        input: trace.io_input.clone(),
        halted: trace.halted,
        exit_code: trace.exit_code,
    };
    verify_native_unified(&statement, &proof, 8).unwrap();

    let mut bad_root = proof.clone();
    bad_root.virtual_claim_root[0] ^= 1;
    assert!(verify_native_unified(&statement, &bad_root, 8).is_err());
}
