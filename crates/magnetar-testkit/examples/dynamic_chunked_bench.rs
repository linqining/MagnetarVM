use std::time::Instant;

use magnetar_executor::execute;
use magnetar_runtime::{
    prove_chunked_trace, prove_chunked_trace_dynamic, prove_chunked_trace_streaming,
    prove_chunked_trace_streaming_dynamic, verify_chunked_trace,
};
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
                imm: 7,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Slli,
                rd: 2,
                rs1: 1,
                rs2: 0,
                imm: 0,
                shamt: 3,
            }
            .encode(),
            Instruction {
                op: Op::Addi,
                rd: 3,
                rs1: 2,
                rs2: 0,
                imm: 1,
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
    for chunk in [1usize, 2] {
        let started = Instant::now();
        let compact = prove_chunked_trace(&trace, 8, chunk).unwrap();
        let compact_time = started.elapsed();
        let compact_bytes = bincode::serialize(&compact).unwrap().len();
        verify_chunked_trace(&trace, &compact, 8).unwrap();

        let started = Instant::now();
        let dynamic = prove_chunked_trace_dynamic(&trace, 8, chunk).unwrap();
        let dynamic_time = started.elapsed();
        let dynamic_bytes = bincode::serialize(&dynamic).unwrap().len();
        verify_chunked_trace(&trace, &dynamic, 8).unwrap();

        let started = Instant::now();
        let streaming = prove_chunked_trace_streaming(&trace, 8, chunk).unwrap();
        let streaming_time = started.elapsed();
        let streaming_bytes = bincode::serialize(&streaming).unwrap().len();
        verify_chunked_trace(&trace, &streaming, 8).unwrap();

        let started = Instant::now();
        let stream_dynamic = prove_chunked_trace_streaming_dynamic(&trace, 8, chunk).unwrap();
        let stream_dynamic_time = started.elapsed();
        let stream_dynamic_bytes = bincode::serialize(&stream_dynamic).unwrap().len();
        verify_chunked_trace(&trace, &stream_dynamic, 8).unwrap();

        println!(
            "chunk={chunk} rows={} compact={compact_bytes}B/{compact_time:?} dynamic={dynamic_bytes}B/{dynamic_time:?} stream={streaming_bytes}B/{streaming_time:?} stream_dynamic={stream_dynamic_bytes}B/{stream_dynamic_time:?}",
            trace.rows.len()
        );
    }
}
