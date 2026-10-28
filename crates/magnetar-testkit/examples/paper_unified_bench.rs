use std::time::Instant;

use magnetar_executor::execute;
use magnetar_runtime::{
    access_statement::AccessStatement, program_hash, prove_unified_trace_paper, trace_digest,
    unified_proof_sizes, verify_native_unified, Statement,
};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn main() {
    let adds = std::env::var("ADDS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1023);
    let mut rom = Vec::new();
    for index in 0..adds {
        rom.push(
            Instruction {
                op: Op::Addi,
                rd: 1,
                rs1: 1,
                rs2: 0,
                imm: index as i64 + 1,
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
        max_cycles: 10_000_000,
    };
    let trace = execute(&program, config).unwrap();
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
    let started = Instant::now();
    let proof = prove_unified_trace_paper(&trace, 8).unwrap();
    let prove = started.elapsed();
    let sizes = unified_proof_sizes(&proof).unwrap();
    let serialized = bincode::serialize(&proof).unwrap();
    let bytes = serialized.len();
    let compressed = miniz_oxide::deflate::compress_to_vec_zlib(&serialized, 6).len();
    let started = Instant::now();
    verify_native_unified(&statement, &proof, 8).unwrap();
    let verify = started.elapsed();
    eprintln!("{sizes:?}");
    println!(
        "adds={adds} rows={} proof={bytes}B compressed={compressed}B access={}B logup={}B selected={}B claim={}B shape={}B prove={prove:?} verify={verify:?}",
        trace.rows.len(),
        sizes.access,
        // compressed,
        sizes.logup_shout,
        sizes.selected_cpu,
        sizes.claim_proof,
        sizes.shape,
    );
}
