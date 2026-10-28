use std::time::Instant;

use magnetar_constraint::F2_128;
use magnetar_executor::execute;
use magnetar_pcs::{P3BatchPoint, P3BinaryPcs};
use magnetar_runtime::linear_twist::{prove_rw_pcs, prove_val_pcs};
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
    let old = bincode::serialize(&prove_rw_pcs(&witness).unwrap()).unwrap().len()
        + bincode::serialize(&prove_val_pcs(&witness).unwrap()).unwrap().len();
    let tables = SharedTwistTables::build(&witness).unwrap();
    let height = tables.shape.cells() * tables.shape.cycles;
    let point = |salt: usize| {
        (0..height.trailing_zeros() as usize)
            .map(|index| F2_128::from((index * 3 + salt) as u64))
            .collect::<Vec<_>>()
    };
    let table_columns = tables.columns[..3].to_vec();
    let input_columns = tables.columns[3..6].to_vec();
    let table_points = vec![
        P3BatchPoint {
            point: point(1),
            columns: vec![0, 1, 2],
        },
        P3BatchPoint {
            point: point(2),
            columns: vec![2],
        },
        P3BatchPoint {
            point: point(3),
            columns: vec![0, 2],
        },
    ];
    let input_points = vec![
        P3BatchPoint {
            point: point(4),
            columns: vec![0, 1, 2],
        },
        P3BatchPoint {
            point: point(5),
            columns: vec![0],
        },
        P3BatchPoint {
            point: point(6),
            columns: vec![1, 2],
        },
    ];
    let values = |columns: &[Vec<F2_128>], points: &[P3BatchPoint]| {
        points
            .iter()
            .map(|point| {
                point
                    .columns
                    .iter()
                    .map(|column| {
                        magnetar_runtime::linear_twist::eval_mle(
                            &columns[*column],
                            &point.point,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    };
    let pcs = P3BinaryPcs::new(100);
    let _tables_commit = pcs.commit_batch(&table_columns).unwrap();
    let _inputs_commit = pcs.commit_batch(&input_columns).unwrap();
    let started = Instant::now();
    let table_opening = pcs.open_batch(&table_columns, &table_points).unwrap();
    let input_opening = pcs.open_batch(&input_columns, &input_points).unwrap();
    let open_time = started.elapsed();
    let table_values = values(&table_columns, &table_points);
    let input_values = values(&input_columns, &input_points);
    let bytes = bincode::serialize(&table_opening).unwrap().len()
        + bincode::serialize(&input_opening).unwrap().len();
    let started = Instant::now();
    assert!(pcs
        .verify_batch(&table_opening, &table_points, &table_values)
        .unwrap());
    assert!(pcs
        .verify_batch(&input_opening, &input_points, &input_values)
        .unwrap());
    let verify_time = started.elapsed();
    println!(
        "rows={rows} old_rw_val={old} shared_open={bytes} open={open_time:?} verify={verify_time:?}"
    );
}
