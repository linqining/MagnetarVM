use magnetar_constraint::F2_128;
use magnetar_constraint::{SegmentKind, WitnessLayout};
use magnetar_cpu::check_trace;
use magnetar_executor::ExecutionIo;
use magnetar_guest::{decode_syscall, Syscall, SYS_EXIT};
use magnetar_memory::check_memory;
use magnetar_pcs::{MerkleTree, NaiveMerklePcs, PolynomialCommitment};
use magnetar_privacy::{HidingCommitment, NoPrivacy};
use magnetar_proof::{prove, verify, Mle};
use magnetar_recursion::ChunkPlan;
use magnetar_routing::{ShiftKind, ShiftRoute, StoreRoute, StoreWidth};
use magnetar_runtime::{
    prove_unified_trace, run_guest_elf, verify_unified_trace, ReferencePipeline,
};
use magnetar_spec::{Instruction, Op};
use magnetar_testkit::{arith_memory_program, sample_config};

#[test]
fn reference_pipeline_is_consistent() {
    let outcome = ReferencePipeline::run(&arith_memory_program(), sample_config(), 4).unwrap();
    assert_eq!(outcome.trace.final_state.reg(3), 12);
    assert_eq!(outcome.trace.final_state.reg(5), 12);
    assert_eq!(outcome.memory.memory_writes, 1);
    assert_eq!(outcome.memory.memory_reads, 1);
    check_trace(&outcome.trace).unwrap();
    check_memory(&outcome.trace).unwrap();
    assert!(outcome.layout.direct_segments().count() > 0);
    assert!(outcome
        .layout
        .segments
        .iter()
        .any(|segment| segment.kind == SegmentKind::Virtual));
}

#[test]
fn witness_layout_is_aligned() {
    let outcome = ReferencePipeline::run(&arith_memory_program(), sample_config(), 4).unwrap();
    let layout: &WitnessLayout = &outcome.layout;
    for segment in &layout.segments {
        assert!(segment.len.is_power_of_two());
        assert_eq!(segment.offset % segment.len, 0);
    }
}

#[test]
fn sumcheck_executes_and_verifies() {
    let poly = |point: &[F2_128]| point[0] * point[1] + point[0] + F2_128::from(1u64);
    let (proof, _, final_eval) =
        prove(poly, 2, 2, |round, _| F2_128::from(round as u64 + 4)).unwrap();
    verify(&proof, 2, 2, final_eval, |round, _| {
        F2_128::from(round as u64 + 4)
    })
    .unwrap();
}

#[test]
fn merkle_and_naive_pcs_work() {
    let tree = MerkleTree::from_leaves(vec![b"a".to_vec(), b"b".to_vec()]).unwrap();
    let path = tree.proof(0).unwrap();
    assert!(MerkleTree::verify(tree.root(), b"a", &path));

    let mle = Mle::new(vec![
        F2_128::from(1u64),
        F2_128::from(2u64),
        F2_128::from(3u64),
        F2_128::from(4u64),
    ])
    .unwrap();
    let pcs = NaiveMerklePcs;
    let commitment = pcs.commit(&mle).unwrap();
    let point = [F2_128::from(1u64), F2_128::from(1u64)];
    let value = mle.eval(&point).unwrap();
    let opening = pcs.open(&mle, &point).unwrap();
    assert!(pcs.verify(&commitment, &point, value, &opening).unwrap());
}

#[test]
fn routing_and_store_routes_are_consistent() {
    let value = 0x8000_0000_0000_0001u64;
    assert_eq!(
        ShiftRoute::new(ShiftKind::LogicalRight, 4).apply(value),
        value >> 4
    );
    let store = StoreRoute::new(StoreWidth::Half, 2).unwrap();
    let old = 0x1122_3344_5566_7788u64;
    let source = 0xffff_ffff_ffff_aaaau64;
    let new = store.new_word(old, source);
    assert_eq!(new, 0x1122_3344_aaaa_7788);
}

#[test]
fn recursion_and_privacy_boundaries_are_explicit() {
    let plan = ChunkPlan::new(1000, 256).unwrap();
    assert_eq!(plan.ranges().len(), 4);

    let scheme = NoPrivacy;
    let (commitment, blinding) = scheme.commit(b"payload").unwrap();
    assert!(scheme.verify(&commitment, b"payload", &blinding).unwrap());
}

#[test]
fn guest_abi_decodes_exit() {
    assert_eq!(
        decode_syscall(0, 0, 0, SYS_EXIT),
        Ok(Syscall::Exit { code: 0 })
    );
}

#[test]
fn guest_elf_reads_and_writes_through_the_pipeline() {
    let text = vec![
        Instruction {
            op: Op::Lui,
            rd: 11,
            rs1: 0,
            rs2: 0,
            imm: 0x1000_0000,
            shamt: 0,
        }
        .encode(),
        Instruction {
            op: Op::Addi,
            rd: 10,
            rs1: 0,
            rs2: 0,
            imm: 0,
            shamt: 0,
        }
        .encode(),
        Instruction {
            op: Op::Addi,
            rd: 12,
            rs1: 0,
            rs2: 0,
            imm: 8,
            shamt: 0,
        }
        .encode(),
        Instruction {
            op: Op::Addi,
            rd: 17,
            rs1: 0,
            rs2: 0,
            imm: 63,
            shamt: 0,
        }
        .encode(),
        Instruction {
            op: Op::Ecall,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
            shamt: 0,
        }
        .encode(),
        Instruction {
            op: Op::Addi,
            rd: 10,
            rs1: 0,
            rs2: 0,
            imm: 1,
            shamt: 0,
        }
        .encode(),
        Instruction {
            op: Op::Addi,
            rd: 17,
            rs1: 0,
            rs2: 0,
            imm: 64,
            shamt: 0,
        }
        .encode(),
        Instruction {
            op: Op::Ecall,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
            shamt: 0,
        }
        .encode(),
        Instruction {
            op: Op::Addi,
            rd: 10,
            rs1: 0,
            rs2: 0,
            imm: 0,
            shamt: 0,
        }
        .encode(),
        Instruction {
            op: Op::Addi,
            rd: 17,
            rs1: 0,
            rs2: 0,
            imm: 93,
            shamt: 0,
        }
        .encode(),
        Instruction {
            op: Op::Ecall,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
            shamt: 0,
        }
        .encode(),
    ];
    let elf = minimal_guest_elf(&text);
    let outcome = run_guest_elf(
        &elf,
        sample_config(),
        4,
        &mut ExecutionIo::with_input(b"ABCDEFGH".to_vec()),
    )
    .unwrap();
    assert_eq!(outcome.statement.input, b"ABCDEFGH");
    assert_eq!(outcome.statement.output, b"ABCDEFGH");
    assert_eq!(outcome.trace.exit_code, Some(0));

    let proof = prove_unified_trace(&outcome.trace, 8).unwrap();
    verify_unified_trace(&outcome.trace, &proof, 8).unwrap();
}

fn write_u16(buffer: &mut [u8], offset: usize, value: u16) {
    buffer[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(buffer: &mut [u8], offset: usize, value: u64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn minimal_guest_elf(text: &[u32]) -> Vec<u8> {
    let text_bytes: Vec<u8> = text.iter().flat_map(|word| word.to_le_bytes()).collect();
    let mut buffer = vec![0u8; 0x1000 + text_bytes.len()];
    buffer[0..4].copy_from_slice(b"\x7fELF");
    buffer[4] = 2;
    buffer[5] = 1;
    buffer[6] = 1;
    write_u16(&mut buffer, 16, 2);
    write_u16(&mut buffer, 18, 243);
    write_u32(&mut buffer, 20, 1);
    write_u64(&mut buffer, 24, 0x1000);
    write_u64(&mut buffer, 32, 64);
    write_u16(&mut buffer, 52, 64);
    write_u16(&mut buffer, 54, 56);
    write_u16(&mut buffer, 56, 1);
    write_u16(&mut buffer, 58, 64);

    write_u32(&mut buffer, 64, 1);
    write_u32(&mut buffer, 68, 5);
    write_u64(&mut buffer, 72, 0x1000);
    write_u64(&mut buffer, 80, 0x1000);
    write_u64(&mut buffer, 88, 0x1000);
    write_u64(&mut buffer, 96, text_bytes.len() as u64);
    write_u64(&mut buffer, 104, text_bytes.len() as u64);
    write_u64(&mut buffer, 112, 0x1000);
    buffer[0x1000..].copy_from_slice(&text_bytes);
    buffer
}

#[test]
fn compressed_guest_elf_runs_through_the_pipeline() {
    // c.li x1, 5; c.addi x1, x1, 3; c.ebreak
    let text = vec![0x008d_4095, 0x0000_9002];
    let elf = minimal_guest_elf(&text);
    let outcome = run_guest_elf(&elf, sample_config(), 4, &mut ExecutionIo::default()).unwrap();
    assert_eq!(outcome.trace.len(), 3);
    assert_eq!(outcome.trace.final_state.reg(1), 8);
    assert!(outcome.trace.halted);

    let proof = prove_unified_trace(&outcome.trace, 8).unwrap();
    verify_unified_trace(&outcome.trace, &proof, 8).unwrap();
}

#[test]
fn malformed_guest_elf_is_rejected() {
    let error = run_guest_elf(
        b"not an elf",
        sample_config(),
        4,
        &mut ExecutionIo::default(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        magnetar_runtime::RuntimeError::Guest(magnetar_guest::GuestError::ElfParse(_))
    ));
}

#[test]
fn guest_elf_runs_through_the_reference_pipeline() {
    let text = vec![
        Instruction {
            op: Op::Addi,
            rd: 10,
            rs1: 0,
            rs2: 0,
            imm: 42,
            shamt: 0,
        }
        .encode(),
        Instruction {
            op: Op::Addi,
            rd: 17,
            rs1: 0,
            rs2: 0,
            imm: 93,
            shamt: 0,
        }
        .encode(),
        Instruction {
            op: Op::Ecall,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
            shamt: 0,
        }
        .encode(),
    ];
    let elf = minimal_guest_elf(&text);
    let outcome = run_guest_elf(&elf, sample_config(), 4, &mut ExecutionIo::default()).unwrap();
    assert_eq!(outcome.trace.exit_code, Some(42));
    assert_eq!(outcome.statement.exit_code, Some(42));
    assert!(outcome.trace.halted);
    check_trace(&outcome.trace).unwrap();

    let proof = prove_unified_trace(&outcome.trace, 8).unwrap();
    verify_unified_trace(&outcome.trace, &proof, 8).unwrap();
}
