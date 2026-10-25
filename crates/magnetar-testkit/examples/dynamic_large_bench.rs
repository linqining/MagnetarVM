use std::time::Instant;

use magnetar_executor::execute;
use magnetar_runtime::{
    prove_chunked_trace_dynamic, prove_chunked_trace_streaming_dynamic, verify_chunked_trace,
};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn main() {
    let adds = 1023usize;
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
    {
        let chunk = 256usize;
        let started = Instant::now();
        let compact = prove_chunked_trace_dynamic(&trace, 8, chunk).unwrap();
        let compact_time = started.elapsed();
        let compact_bytes = bincode::serialize(&compact).unwrap().len();
        verify_chunked_trace(&trace, &compact, 8).unwrap();

        let started = Instant::now();
        let streaming = prove_chunked_trace_streaming_dynamic(&trace, 8, chunk).unwrap();
        let streaming_time = started.elapsed();
        let streaming_bytes = bincode::serialize(&streaming).unwrap().len();
        verify_chunked_trace(&trace, &streaming, 8).unwrap();

        println!(
            "rows={} chunk={chunk} compact={compact_bytes}B/{compact_time:?} streaming={streaming_bytes}B/{streaming_time:?}",
            trace.rows.len()
        );
    }
}
