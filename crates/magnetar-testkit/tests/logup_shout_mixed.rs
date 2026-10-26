use magnetar_executor::execute;
use magnetar_runtime::binary_shout::BinaryShoutWitness;
use magnetar_runtime::logup_shout::{prove_logup_shout, verify_logup_shout};
use magnetar_runtime::{prove_unified_trace_auto, verify_unified_trace};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

#[test]
fn logup_shout_and_native_handle_compressed_trace() {
    // c.li x1, 5; c.addi x1, x1, 3; c.ebreak
    let program = ProgramImage::new(
        0x1000,
        vec![0x008d_4095, Instruction::new(Op::Ecall).encode()],
    );
    let config = MachineConfig {
        entry: 0x1000,
        rom_base: 0x1000,
        ram_base: 0x1000_0000,
        ram_size: 0x100,
        stack_top: 0x1000_0100,
        max_cycles: 100,
    };
    let trace = execute(&program, config).unwrap();
    for row in &trace.rows {
        eprintln!(
            "row pc={:#x} next={:#x} len={} op={:?}",
            row.pc, row.next_pc, row.instruction_len, row.instruction.op
        );
    }
    eprintln!(
        "final pc={:#x} halted={}",
        trace.final_state.pc, trace.halted
    );
    let witness = BinaryShoutWitness::from_trace(&trace).unwrap();
    assert!(witness.is_32.iter().any(|bit| bit.value() != 0));
    let proof = prove_logup_shout(&witness).unwrap();
    verify_logup_shout(&proof, &witness.rom).unwrap();

    // Native selected CPU still lacks compressed PC rows; auto must fall back
    // to the reference proof and verify.
    let dynamic = magnetar_runtime::prove_unified_trace_dynamic_native(&trace, 8);
    eprintln!(
        "dynamic compressed result: {:?}",
        dynamic.as_ref().map(|_| ())
    );
    let dynamic = magnetar_runtime::prove_unified_trace_dynamic_native(&trace, 8);
    eprintln!(
        "dynamic compressed result: {:?}",
        dynamic.as_ref().map(|_| ())
    );
    let started = std::time::Instant::now();
    let native = prove_unified_trace_auto(&trace, 8).unwrap();
    let prove = started.elapsed();
    let bytes = bincode::serialize(&native).unwrap().len();
    let started = std::time::Instant::now();
    verify_unified_trace(&trace, &native, 8).unwrap();
    eprintln!(
        "compressed native fallback proof={bytes}B prove={prove:?} verify={:?}",
        started.elapsed()
    );
}

#[test]
fn native_dynamic_handles_more_compressed_programs() {
    use magnetar_executor::execute;
    let config = MachineConfig {
        entry: 0x1000,
        rom_base: 0x1000,
        ram_base: 0x1000_0000,
        ram_size: 0x1000,
        stack_top: 0x1000_1000,
        max_cycles: 100,
    };
    let lui = |rd, imm| {
        Instruction {
            op: Op::Lui,
            rd,
            rs1: 0,
            rs2: 0,
            imm,
            shamt: 0,
        }
        .encode()
    };
    let addi = |rd, rs1, imm| {
        Instruction {
            op: Op::Addi,
            rd,
            rs1,
            rs2: 0,
            imm,
            shamt: 0,
        }
        .encode()
    };
    let programs = vec![
        ("branches", vec![0xc011_4481, 0x9002_9002]),
        ("jalr", vec![lui(5, 0x1000), addi(5, 5, 10), 0x9002_9282]),
        (
            "memory",
            vec![lui(9, 0x1000_0000), 0xc080_4429, 0x9002_4088],
        ),
    ];
    for (name, rom) in programs {
        let trace = execute(&ProgramImage::new(0x1000, rom), config.clone())
            .unwrap_or_else(|error| panic!("{name} execute: {error:?}"));
        let proof = magnetar_runtime::prove_unified_trace_auto(&trace, 8)
            .unwrap_or_else(|error| panic!("{name} prove: {error:?}"));
        assert!(
            proof.logup_shout.is_some(),
            "{name} did not use logup Shout"
        );
        magnetar_runtime::verify_unified_trace(&trace, &proof, 8)
            .unwrap_or_else(|error| panic!("{name} verify: {error:?}"));
    }
}
