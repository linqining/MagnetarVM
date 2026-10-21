use magnetar_constraint::F61;
use magnetar_constraint::{SegmentKind, WitnessLayout};
use magnetar_cpu::check_trace;
use magnetar_guest::{decode_syscall, Syscall, SYS_EXIT};
use magnetar_memory::check_memory;
use magnetar_pcs::{MerkleTree, NaiveMerklePcs, PolynomialCommitment};
use magnetar_privacy::{HidingCommitment, NoPrivacy};
use magnetar_proof::{prove, verify, Mle};
use magnetar_recursion::ChunkPlan;
use magnetar_routing::{ShiftKind, ShiftRoute, StoreRoute, StoreWidth};
use magnetar_runtime::ReferencePipeline;
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
    let poly = |point: &[F61]| point[0] * point[1] + point[0] + F61::from(1);
    let (proof, _, final_eval) = prove(poly, 2, 2, |round, _| F61::from(round as u64 + 4)).unwrap();
    verify(&proof, 2, 2, final_eval, |round, _| {
        F61::from(round as u64 + 4)
    })
    .unwrap();
}

#[test]
fn merkle_and_naive_pcs_work() {
    let tree = MerkleTree::from_leaves(vec![b"a".to_vec(), b"b".to_vec()]).unwrap();
    let path = tree.proof(0).unwrap();
    assert!(MerkleTree::verify(tree.root(), b"a", &path));

    let mle = Mle::new(vec![F61::from(1), F61::from(2), F61::from(3), F61::from(4)]).unwrap();
    let pcs = NaiveMerklePcs;
    let commitment = pcs.commit(&mle).unwrap();
    let point = [F61::from(1), F61::from(1)];
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
