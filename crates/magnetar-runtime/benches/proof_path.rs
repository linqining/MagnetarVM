use std::hint::black_box;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use magnetar_executor::execute;
use magnetar_runtime::{
    decode_unified_proof, encode_unified_proof, prove_trace_access, prove_trace_proof,
    prove_unified_trace, ConstraintProofBackend, Prover, Verifier,
};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn config() -> MachineConfig {
    MachineConfig {
        entry: 0x1000,
        rom_base: 0x1000,
        ram_base: 0x1000_0000,
        ram_size: 0x1000,
        stack_top: 0x1000_1000,
        max_cycles: 100,
    }
}

fn program() -> ProgramImage {
    ProgramImage::new(
        0x1000,
        vec![
            Instruction {
                op: Op::Addi,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 5,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Addi,
                rd: 2,
                rs1: 0,
                rs2: 0,
                imm: 7,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Add,
                rd: 3,
                rs1: 1,
                rs2: 2,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction::new(Op::Ecall).encode(),
        ],
    )
}

fn proof_path_benchmarks(c: &mut Criterion) {
    let trace = execute(&program(), config()).unwrap();
    let mut group = c.benchmark_group("proof_path");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("trace_access_three_rows", |bench| {
        bench.iter(|| prove_trace_access(black_box(&trace)).unwrap())
    });

    let (system, layout) =
        magnetar_cpu::uniform_alu_row_relation(16, magnetar_cpu::StepOp::Add, 5, 7, 12, 0);
    let witness = layout.witness(magnetar_cpu::StepOp::Add, 5, 7, 0);
    let backend = ConstraintProofBackend::default();
    group.bench_function("spartan_alu_row_w16_prove", |bench| {
        bench.iter(|| {
            backend
                .prove(black_box(&system), black_box(&witness))
                .unwrap()
        })
    });
    let proof = backend.prove(&system, &witness).unwrap();
    group.bench_function("spartan_alu_row_w16_verify", |bench| {
        bench.iter(|| {
            backend
                .verify(black_box(&system), black_box(&proof))
                .unwrap()
        })
    });

    let (mul_system, mul_layout) = magnetar_cpu::uniform_mul_row_relation(8, 13, 11, 143);
    let mul_witness = mul_layout.witness(13, 11);
    group.bench_function("spartan_mul_row_w8_prove", |bench| {
        bench.iter(|| {
            backend
                .prove(black_box(&mul_system), black_box(&mul_witness))
                .unwrap()
        })
    });
    let mul_proof = backend.prove(&mul_system, &mul_witness).unwrap();
    group.bench_function("spartan_mul_row_w8_verify", |bench| {
        bench.iter(|| {
            backend
                .verify(black_box(&mul_system), black_box(&mul_proof))
                .unwrap()
        })
    });

    let (div_system, div_layout) = magnetar_cpu::uniform_divu_row_relation(8, 100, 7, 14);
    let div_witness = div_layout.witness(100, 7);
    group.bench_function("spartan_divu_row_w8_prove", |bench| {
        bench.iter(|| {
            backend
                .prove(black_box(&div_system), black_box(&div_witness))
                .unwrap()
        })
    });
    let div_proof = backend.prove(&div_system, &div_witness).unwrap();
    group.bench_function("spartan_divu_row_w8_verify", |bench| {
        bench.iter(|| {
            backend
                .verify(black_box(&div_system), black_box(&div_proof))
                .unwrap()
        })
    });
    group.finish();

    let mut trace_group = c.benchmark_group("trace_proof");
    trace_group.sample_size(10);
    trace_group.measurement_time(Duration::from_secs(30));
    trace_group.bench_function("three_alu_rows_w8", |bench| {
        bench.iter(|| prove_trace_proof(black_box(&trace), 8).unwrap())
    });
    trace_group.bench_function("unified_three_rows_w8", |bench| {
        bench.iter(|| prove_unified_trace(black_box(&trace), 8).unwrap())
    });
    trace_group.finish();

    let unified = prove_unified_trace(&trace, 8).unwrap();
    let encoded = encode_unified_proof(&unified).unwrap();
    eprintln!("unified proof bytes: {}", encoded.len());
    let mut encoding_group = c.benchmark_group("proof_encoding");
    encoding_group.sample_size(10);
    encoding_group.measurement_time(Duration::from_secs(5));
    encoding_group.bench_function("encode_unified", |bench| {
        bench.iter(|| encode_unified_proof(black_box(&unified)).unwrap())
    });
    encoding_group.bench_function("decode_unified", |bench| {
        bench.iter(|| decode_unified_proof(black_box(&encoded)).unwrap())
    });
    encoding_group.finish();
}

criterion_group!(benches, proof_path_benchmarks);
criterion_main!(benches);
