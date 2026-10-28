use std::time::Instant;

use magnetar_constraint::F2_128;
use magnetar_executor::execute;
use magnetar_pcs::P3BatchPoint;
use magnetar_runtime::register_twist::register_twist_witness;
use magnetar_runtime::shared_twist::SharedTwistTables;
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn main() {
    let rows = std::env::var("ROWS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1024);
    let mut rom = Vec::new();
    for index in 0..rows.saturating_sub(1) {
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
    let witness = register_twist_witness(&trace).unwrap();
    let started = Instant::now();
    let tables = SharedTwistTables::build(&witness).unwrap();
    let commitment = tables.commit().unwrap();
    let commit_time = started.elapsed();
    let height = tables.shape.cells() * tables.shape.cycles;
    let point = (0..height.trailing_zeros() as usize)
        .map(|index| F2_128::from((index * 3 + 2) as u64))
        .collect::<Vec<_>>();
    let points = vec![P3BatchPoint {
        point: point.clone(),
        columns: (0..tables.columns.len()).collect(),
    }];
    let values = vec![tables
        .columns
        .iter()
        .map(|column| magnetar_runtime::linear_twist::eval_mle(column, &point))
        .collect::<Vec<_>>()];
    let started = Instant::now();
    let opening = tables.open(&points).unwrap();
    let open_time = started.elapsed();
    let bytes = bincode::serialize(&opening).unwrap().len();
    let started = Instant::now();
    assert!(tables.verify(&opening, &points, &values).unwrap());
    let verify_time = started.elapsed();
    println!(
        "rows={rows} columns={} commit={commit_time:?} open={open_time:?} verify={verify_time:?} proof_bytes={bytes} commit_vars={}",
        tables.columns.len(),
        commitment.stacked_variables,
    );
}
