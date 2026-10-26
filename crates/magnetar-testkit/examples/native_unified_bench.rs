use std::time::Instant;

use magnetar_executor::execute;
use magnetar_runtime::{prove_unified_trace_auto, unified_proof_sizes, verify_unified_trace};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn main() {
    for adds in [511u64, 1023] {
        let mut rom = Vec::new();
        for index in 0..adds {
            rom.push(
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: index as i64 + 1,
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
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 10_000,
            },
        )
        .unwrap();
        let started = Instant::now();
        let proof = prove_unified_trace_auto(&trace, 8).unwrap();
        let prove = started.elapsed();
        let bytes = bincode::serialize(&proof).unwrap().len();
        let sizes = unified_proof_sizes(&proof).unwrap();
        let started = Instant::now();
        verify_unified_trace(&trace, &proof, 8).unwrap();
        let verify = started.elapsed();
        println!(
            "adds={adds} rows={} proof={bytes}B logup={}B packed={}B selected={}B claim={}B prove={prove:?} verify={verify:?}",
            trace.rows.len(),
            sizes.logup_shout,
            sizes.packed_shout,
            sizes.selected_cpu,
            sizes.claim_proof
        );
    }
}
