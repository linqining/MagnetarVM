use std::time::Instant;

use magnetar_constraint::F2_128;
use magnetar_executor::execute;
use magnetar_pcs::{P3BatchPoint, P3BinaryPcs};
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
    let tables = SharedTwistTables::build(&witness).unwrap();
    let cells = tables.shape.cells();
    let cycles = tables.shape.cycles;
    let kt = 3usize;
    let cell_start = tables.columns.len() - 2;
    let groups = [
        tables.columns[..kt].to_vec(),
        tables.columns[kt..cell_start].to_vec(),
        tables.columns[cell_start..].to_vec(),
    ];
    let point = |height: usize| {
        (0..height.trailing_zeros() as usize)
            .map(|index| F2_128::from((index * 3 + 2) as u64))
            .collect::<Vec<_>>()
    };
    let heights = [cells * cycles; 3];
    let pcs = P3BinaryPcs::new(100);
    let mut total = 0usize;
    let mut elapsed_commit = std::time::Duration::ZERO;
    let mut elapsed_open = std::time::Duration::ZERO;
    for (group, height) in groups.iter().zip(heights) {
        let started = Instant::now();
        let commitment = pcs.commit_batch(group).unwrap();
        elapsed_commit += started.elapsed();
        let point = point(height);
        let points = vec![P3BatchPoint {
            point: point.clone(),
            columns: (0..group.len()).collect(),
        }];
        let values = vec![group
            .iter()
            .map(|column| magnetar_runtime::linear_twist::eval_mle(column, &point))
            .collect::<Vec<_>>()];
        let started = Instant::now();
        let opening = pcs.open_batch(group, &points).unwrap();
        elapsed_open += started.elapsed();
        total += bincode::serialize(&opening).unwrap().len();
        assert!(pcs.verify_batch(&opening, &points, &values).unwrap());
        let _ = commitment;
    }
    println!(
        "rows={rows} groups={} commit={elapsed_commit:?} open={elapsed_open:?} bytes={total}",
        groups.len()
    );
}
