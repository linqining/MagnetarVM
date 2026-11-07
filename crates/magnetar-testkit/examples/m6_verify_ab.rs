//! M6 verify-latency A/B: one proof, then interleaved serial/parallel
//! verification in the same process.
//!
//! The host is shared and drifting, so a "run serial binary, then parallel
//! binary" comparison is not trustworthy (HANDOFF §6). This harness proves
//! once and then alternates `MAGNETAR_VERIFY_SERIAL` on/off every iteration,
//! reporting per-iteration wall and process CPU so the parallel speed-up can be
//! read off a single time window. Both modes must accept the proof, otherwise
//! the harness aborts.
//!
//! Run the M5/M4b statement-only path at RV64 `2^16` with:
//!
//! ```sh
//! ADDS=65535 MAGNETAR_CLAIM_V4=1 MAGNETAR_ACCESS_COLUMNS=1 \
//!   MAGNETAR_LINEAR_SHOUT=1 target/release/examples/m6_verify_ab
//! ```
//!
//! `M6_AB_ROUNDS` sets the number of pairs (default 10, i.e. 20 verifications).

use std::time::Instant;

use magnetar_executor::execute;
use magnetar_runtime::{
    program_hash, prove_unified_trace_dynamic_native, trace_digest, verify_native_unified, Statement,
};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn add_program(adds: usize) -> ProgramImage {
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
    ProgramImage::new(0x1000, rom)
}

fn main() {
    let _memory_watchdog = magnetar_testkit::install_memory_watchdog(4.0);
    let adds = std::env::var("ADDS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(65535);
    let rounds = std::env::var("M6_AB_ROUNDS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(10)
        .max(1);
    let program = add_program(adds);
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
        trace_claim_root: magnetar_runtime::claim_table::statement_claim_root(&trace),
        access_statement_digest: magnetar_runtime::statement_access_digest(&trace),
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
    let proof = prove_unified_trace_dynamic_native(&trace, 64).unwrap();
    eprintln!("prove: {:?}", started.elapsed());

    // Warm both paths once and require them to accept the proof.
    std::env::set_var("MAGNETAR_VERIFY_SERIAL", "1");
    verify_native_unified(&statement, &proof, 64).expect("serial verifier rejected the proof");
    std::env::remove_var("MAGNETAR_VERIFY_SERIAL");
    verify_native_unified(&statement, &proof, 64).expect("parallel verifier rejected the proof");

    let mut serial = Vec::with_capacity(rounds);
    let mut parallel = Vec::with_capacity(rounds);
    for round in 0..rounds {
        // Alternate which mode goes first so any drift inside the window is
        // shared between the two samples instead of biasing one of them.
        let serial_first = round % 2 == 0;
        for serial_mode in [serial_first, !serial_first] {
            if serial_mode {
                std::env::set_var("MAGNETAR_VERIFY_SERIAL", "1");
            } else {
                std::env::remove_var("MAGNETAR_VERIFY_SERIAL");
            }
            let cpu = magnetar_proof::process_cpu_seconds();
            let started = Instant::now();
            verify_native_unified(&statement, &proof, 64).expect("verifier rejected the proof");
            let wall = started.elapsed();
            let cpu = magnetar_proof::process_cpu_seconds() - cpu;
            if serial_mode {
                serial.push((wall, cpu));
            } else {
                parallel.push((wall, cpu));
            }
        }
    }
    std::env::remove_var("MAGNETAR_VERIFY_SERIAL");

    let report = |label: &str, samples: &[(std::time::Duration, f64)]| {
        let mut walls = samples
            .iter()
            .map(|(wall, _)| wall.as_secs_f64() * 1000.0)
            .collect::<Vec<_>>();
        let mut cpus = samples
            .iter()
            .map(|(_, cpu)| cpu * 1000.0)
            .collect::<Vec<_>>();
        walls.sort_by(|a, b| a.partial_cmp(b).unwrap());
        cpus.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = |values: &[f64]| values[values.len() / 2];
        eprintln!(
            "{label}: wall median {:.2} ms, wall min {:.2} ms, cpu median {:.2} ms (n={})",
            median(&walls),
            walls[0],
            median(&cpus),
            samples.len()
        );
        (median(&walls), median(&cpus))
    };
    eprintln!("adds={adds} rounds={rounds}");
    let (serial_wall, serial_cpu) = report("verify serial  ", &serial);
    let (parallel_wall, parallel_cpu) = report("verify parallel", &parallel);
    eprintln!(
        "speed-up: wall {:.2}x (cpu {:.2}x) -- proof {} B",
        serial_wall / parallel_wall,
        serial_cpu / parallel_cpu,
        bincode::serialize(&proof).unwrap().len()
    );
}
