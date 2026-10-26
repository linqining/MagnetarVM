use std::time::Instant;

use magnetar_executor::execute;
use magnetar_runtime::claim_native::{prove_claim_native, verify_claim_native};
use magnetar_runtime::{program_hash, trace_digest, Statement};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn main() {
    let rows = std::env::var("ROWS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1024);
    let adds = rows.saturating_sub(1);
    let mut rom = Vec::with_capacity(adds + 1);
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
    let image = ProgramImage::new(0x1000, rom);
    let trace = execute(
        &image,
        MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x100,
            stack_top: 0x1000_0100,
            max_cycles: 10_000_000,
        },
    )
    .unwrap();
    let statement =
        Statement {
            program_hash: program_hash(&image),
            rom: trace.rom.clone(),
            trace_commitment: trace_digest(&trace),
            trace_claim_root: magnetar_runtime::trace_claims::TraceClaimTree::build(&trace).root(),
            access_statement_digest:
                magnetar_runtime::access_statement::AccessStatement::from_trace(&trace).digest(),
            config: trace.config.clone(),
            initial_state: trace.initial_state.clone(),
            initial_ram: trace.initial_ram.clone(),
            final_state: trace.final_state.clone(),
            trace_len: trace.rows.len() as u64,
            output: trace.io_output.clone(),
            input: trace.io_input.clone(),
            halted: trace.halted,
            exit_code: trace.exit_code,
        };
    let started = Instant::now();
    let proof = prove_claim_native(&trace, 8).unwrap();
    let prove = started.elapsed();
    let started = Instant::now();
    verify_claim_native(&statement, &proof, 8).unwrap();
    let verify = started.elapsed();
    let bytes = bincode::serialize(&proof).unwrap().len();
    let claim_bytes = bincode::serialize(&proof.claim_proof).unwrap().len();
    let selected_bytes = bincode::serialize(&proof.selected_cpu).unwrap().len();
    println!(
        "rows={} proof={} claim={} selected={} prove={:?} verify={:?} cycles_per_s={:.2}",
        trace.rows.len(),
        bytes,
        claim_bytes,
        selected_bytes,
        prove,
        verify,
        trace.rows.len() as f64 / prove.as_secs_f64()
    );
}
