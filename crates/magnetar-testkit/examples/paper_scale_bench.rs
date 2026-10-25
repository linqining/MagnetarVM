use std::time::Instant;

use magnetar_executor::execute;
use magnetar_runtime::{prove_unified_trace_auto, unified_proof_sizes, verify_unified_trace};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn main() {
    let rows = std::env::var("ROWS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter_map(|part| part.parse::<usize>().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec![16, 64, 256, 512]);
    for rows in rows {
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
        let trace = execute(
            &ProgramImage::new(0x1000, rom),
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
        let started = Instant::now();
        let proof = prove_unified_trace_auto(&trace, 8).unwrap();
        let prove = started.elapsed();
        let started = Instant::now();
        verify_unified_trace(&trace, &proof, 8).unwrap();
        let verify = started.elapsed();
        let bytes = bincode::serialize(&proof).unwrap().len();
        let sizes = unified_proof_sizes(&proof).unwrap();
        println!(
            "rows={} bincode={} sizes_total={} access={} selected={} claim={} packed_shout={} shape={} opening={} prove={:?} verify={:?} cycles_per_s={:.2}",
            trace.rows.len(),
            bytes,
            sizes.total(),
            sizes.access,
            sizes.selected_cpu,
            sizes.claim_proof,
            sizes.packed_shout,
            sizes.shape,
            sizes.opening,
            prove,
            verify,
            trace.rows.len() as f64 / prove.as_secs_f64(),
        );
        if let Some(selected) = &proof.selected_cpu {
            println!(
                "  selected_proof={} layout={} segments={}",
                bincode::serialize(&selected.proof).unwrap().len(),
                bincode::serialize(&selected.layout).unwrap().len(),
                bincode::serialize(&selected.segments).unwrap().len()
            );
        }
    }
}
