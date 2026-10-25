use std::time::Instant;

use magnetar_executor::execute;
use magnetar_pcs::P3SharedPcs;
use magnetar_proof::RingSwitchPackedBitPcs;
use magnetar_runtime::simd_dual::{
    prove_alu_branch_pc_batch_bits, prove_alu_branch_trace, prove_gated_dual_batch_bits,
    verify_alu_branch_pc_batch_bits, verify_alu_branch_trace, verify_gated_dual_batch_bits,
};
use magnetar_runtime::simd_full::gated_rows_from_trace;
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn main() {
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
    let trace = execute(
        &program,
        MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x40,
            stack_top: 0x1000_0040,
            max_cycles: 100,
        },
    )
    .unwrap();
    let width = 8;
    let backend =
        RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));

    let rows = gated_rows_from_trace(&trace, width).unwrap();
    let cycles = rows.len().next_power_of_two();
    let mut padded = rows.clone();
    while padded.len() < cycles {
        let last = padded.last().unwrap().0;
        padded.push((
            last,
            magnetar_runtime::simd_f2::GatedCpuRowInput::Alu {
                left: 0,
                right: 0,
                op: magnetar_runtime::simd_f2::GatedAluOp::Inactive,
            },
        ));
    }
    let started = Instant::now();
    let (gated_proof, gated_layout) =
        prove_gated_dual_batch_bits(width, &padded, &backend).unwrap();
    let gated_prove = started.elapsed();
    let gated_bytes = bincode::serialize(&gated_proof).unwrap().len();
    let started = Instant::now();
    verify_gated_dual_batch_bits(width, &padded, &gated_proof, &gated_layout, &backend).unwrap();
    let gated_verify = started.elapsed();

    let started = Instant::now();
    let (mixed_proof, mixed_layout) = prove_alu_branch_trace(&trace, width, &backend).unwrap();
    let mixed_prove = started.elapsed();
    let mixed_bytes = bincode::serialize(&mixed_proof).unwrap().len();
    let started = Instant::now();
    verify_alu_branch_trace(&trace, &mixed_proof, &mixed_layout, width, &backend).unwrap();
    let mixed_verify = started.elapsed();

    let started = Instant::now();
    let initial = trace.rows[0].pc;
    let final_pc = initial + 4 * 4;
    let (batch, batch_layout) =
        prove_alu_branch_pc_batch_bits(width, 4, initial, final_pc, &backend).unwrap();
    let batch_prove = started.elapsed();
    let batch_bytes = bincode::serialize(&batch).unwrap().len();
    let started = Instant::now();
    verify_alu_branch_pc_batch_bits(width, 4, initial, final_pc, &batch, &batch_layout, &backend)
        .unwrap();
    let batch_verify = started.elapsed();

    println!(
        "rows={} padded={} gated:  bytes={gated_bytes} prove={gated_prove:?} verify={gated_verify:?}",
        trace.rows.len(),
        cycles
    );
    println!("mixed trace: bytes={mixed_bytes} prove={mixed_prove:?} verify={mixed_verify:?}");
    println!("mixed batch: bytes={batch_bytes} prove={batch_prove:?} verify={batch_verify:?}");
}
