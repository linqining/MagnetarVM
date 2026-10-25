use std::time::Instant;

use magnetar_executor::execute;
use magnetar_pcs::P3BinaryPcs;
use magnetar_proof::RingSwitchPackedBitPcs;
use magnetar_runtime::simd_dual::prove_dynamic_cpu_claims;
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn main() {
    let rows = std::env::var("ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(64usize);
    let adds = rows.saturating_sub(1);
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
    let trace = execute(
        &ProgramImage::new(0x1000, rom),
        MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x100,
            stack_top: 0x1000_0100,
            max_cycles: 1_000_000,
        },
    )
    .unwrap();
    let configs = [
        ("default(2,4,1)", 100usize, 2usize, 4usize, 1usize),
        ("rate1-pow8-f1", 100, 1, 8, 1),
        ("rate1-pow16-f1", 100, 1, 16, 1),
        ("rate1-pow16-f2", 100, 1, 16, 2),
        ("rate1-pow16-f3", 100, 1, 16, 3),
        ("rate2-pow8-f2", 100, 2, 8, 2),
        ("rate4-pow16-f3", 100, 4, 16, 3),
    ];
    for (name, security, inv_rate, pow, folding) in configs {
        let backend =
            RingSwitchPackedBitPcs::new(P3BinaryPcs::with_params(security, inv_rate, pow, folding));
        let started = Instant::now();
        match prove_dynamic_cpu_claims(&trace, 8, &backend) {
            Ok(claims) => {
                let elapsed = started.elapsed();
                let bytes = bincode::serialize(&claims).unwrap().len();
                let proof = bincode::serialize(&claims.proof).unwrap().len();
                let opening = bincode::serialize(&claims.proof.opening).unwrap().len();
                println!(
                    "{name:<18} bytes={bytes:8} proof={proof:8} opening={opening:8} time={elapsed:?}"
                );
            }
            Err(error) => println!("{name:<18} error={error}"),
        }
    }
}
