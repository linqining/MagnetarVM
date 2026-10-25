use std::time::Instant;

use magnetar_executor::execute;
use magnetar_pcs::P3SharedPcs;
use magnetar_proof::RingSwitchPackedBitPcs;
use magnetar_runtime::simd_dual::{
    prove_alu_branch_trace, prove_gated_dual_batch_bits, verify_alu_branch_trace,
    verify_gated_dual_batch_bits,
};
use magnetar_runtime::simd_full::gated_rows_from_trace;
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn main() {
    let width = 8;
    let backend =
        RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
    for adds in [1u64, 3, 7, 15] {
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
        let program = ProgramImage::new(0x1000, rom);
        let trace = execute(
            &program,
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 1000,
            },
        )
        .unwrap();
        assert!(trace.rows.len().is_power_of_two());
        let rows = gated_rows_from_trace(&trace, width).unwrap();

        let started = Instant::now();
        let (gated_proof, gated_layout) =
            prove_gated_dual_batch_bits(width, &rows, &backend).unwrap();
        let gated_prove = started.elapsed();
        let gated_bytes = bincode::serialize(&gated_proof).unwrap().len();
        let started = Instant::now();
        verify_gated_dual_batch_bits(width, &rows, &gated_proof, &gated_layout, &backend).unwrap();
        let gated_verify = started.elapsed();

        let started = Instant::now();
        let (mixed_proof, mixed_layout) = prove_alu_branch_trace(&trace, width, &backend).unwrap();
        let mixed_prove = started.elapsed();
        let mixed_bytes = bincode::serialize(&mixed_proof).unwrap().len();
        let started = Instant::now();
        verify_alu_branch_trace(&trace, &mixed_proof, &mixed_layout, width, &backend).unwrap();
        let mixed_verify = started.elapsed();

        println!(
            "adds={adds} rows={} gated={}B/{:?}/{:?} mixed={}B/{:?}/{:?} speedup={:.2}x",
            trace.rows.len(),
            gated_bytes,
            gated_prove,
            gated_verify,
            mixed_bytes,
            mixed_prove,
            mixed_verify,
            gated_prove.as_secs_f64() / mixed_prove.as_secs_f64()
        );
    }
}
