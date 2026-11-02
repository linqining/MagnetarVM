use std::sync::atomic::{AtomicUsize, Ordering};

use magnetar_executor::execute;
use magnetar_runtime::protocol::{Orchestrator, ProtocolPlan};
use magnetar_runtime::prove_unified_trace;
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};
use magnetar_testkit::{install_memory_watchdog, peak_rss_bytes};

fn trace() -> magnetar_spec::Trace {
    let program = ProgramImage::new(
        0x1000,
        vec![
            Instruction {
                op: Op::Addi,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 11,
                shamt: 0,
            }
            .encode(),
            Instruction::new(Op::Ecall).encode(),
        ],
    );
    execute(
        &program,
        MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x40,
            stack_top: 0x1000_0040,
            max_cycles: 10,
        },
    )
    .unwrap()
}

/// Read a positive `usize` knob from the environment.
fn env_count(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn main() {
    // The default is a small concurrency budget: each concurrent pair of
    // two-row proofs holds ~0.85 GiB, so 12 threads x 10 rounds peaked near
    // 5.8 GiB on a 36 GiB host. Two concurrent pairs keep the peak under
    // 2 GiB while still racing the allocator, the thread pool and the
    // scheduler (the nondeterminism this gate targets is the parallel grind
    // inside one proof, which two racing proves already exercise); raise it
    // with `PROTOCOL_THREADS` when the host is known to have room.
    let _watchdog = install_memory_watchdog(4.0);
    let failures = AtomicUsize::new(0);
    let runs = AtomicUsize::new(0);
    let identical = AtomicUsize::new(0);
    let threads = env_count("PROTOCOL_THREADS", 2);
    let rounds = env_count("PROTOCOL_ROUNDS", 10);
    eprintln!(
        "protocol determinism: threads={threads} rounds={rounds} pairs={}",
        threads * rounds
    );
    std::thread::scope(|scope| {
        // Shared references, not moves: every worker bumps the same counters.
        let failures = &failures;
        let runs = &runs;
        let identical = &identical;
        for thread in 0..threads {
            scope.spawn(move || {
                for round in 0..rounds {
                    let trace = trace();
                    let direct = prove_unified_trace(&trace, 64).unwrap();
                    let orchestrator = Orchestrator::new(ProtocolPlan::unified())
                        .prove(&trace, 64)
                        .unwrap();
                    let left = bincode::serialize(&direct).unwrap();
                    let right = bincode::serialize(&orchestrator).unwrap();
                    runs.fetch_add(1, Ordering::Relaxed);
                    if left != right {
                        failures.fetch_add(1, Ordering::Relaxed);
                        let first = left.iter().zip(&right).position(|(a, b)| a != b);
                        eprintln!(
                            "mismatch len {} {} first {:?}",
                            left.len(),
                            right.len(),
                            first
                        );
                        macro_rules! diff {
                            ($field:ident) => {
                                if bincode::serialize(&direct.$field).unwrap()
                                    != bincode::serialize(&orchestrator.$field).unwrap()
                                {
                                    eprintln!("field differs: {}", stringify!($field));
                                }
                            };
                        }
                        diff!(access);
                        diff!(trace_commitment);
                        diff!(trace_claim_root);
                        diff!(claim_proof);
                        diff!(cpu);
                        diff!(gated);
                        diff!(selected_cpu);
                        diff!(opening);
                        diff!(e5_opening);
                        diff!(field_opening);
                        diff!(field_pcs_commitment);
                        diff!(field_tables);
                        diff!(shout);
                        diff!(shift_router);
                        diff!(store_router);
                        diff!(amo);
                        diff!(shape);
                        diff!(register_index);
                        diff!(ram_index);
                        diff!(rom_index);
                        diff!(shout_index);
                        diff!(shift_router_index);
                        diff!(store_router_index);
                        diff!(trace_index);
                        diff!(trace_claims);
                        diff!(table_batches);
                        diff!(width);
                        diff!(commitment);
                        diff!(packed_shout);
                    } else {
                        identical.fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "thread {thread} round {round}: {} B proof, byte-identical",
                            left.len()
                        );
                    }
                }
            });
        }
    });
    let peak = peak_rss_bytes()
        .map(|bytes| format!("{:.2} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0)))
        .unwrap_or_else(|| "unknown".into());
    println!(
        "runs={} identical={} failures={} peak_rss={peak}",
        runs.load(Ordering::Relaxed),
        identical.load(Ordering::Relaxed),
        failures.load(Ordering::Relaxed)
    );
}
