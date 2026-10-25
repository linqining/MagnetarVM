use std::sync::atomic::{AtomicUsize, Ordering};

use magnetar_executor::execute;
use magnetar_runtime::protocol::{Orchestrator, ProtocolPlan};
use magnetar_runtime::prove_unified_trace;
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

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

fn main() {
    let failures = AtomicUsize::new(0);
    let runs = AtomicUsize::new(0);
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                for _ in 0..10 {
                    let trace = trace();
                    let direct = prove_unified_trace(&trace, 8).unwrap();
                    let orchestrator = Orchestrator::new(ProtocolPlan::unified())
                        .prove(&trace, 8)
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
                    }
                }
            });
        }
    });
    println!(
        "runs={} failures={}",
        runs.load(Ordering::Relaxed),
        failures.load(Ordering::Relaxed)
    );
}
