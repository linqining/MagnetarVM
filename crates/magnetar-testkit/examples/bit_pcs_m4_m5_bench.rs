use std::time::Instant;

use magnetar_constraint::F2_128;
use magnetar_pcs::P3SharedPcs;
use magnetar_proof::spartan::MatrixPart;
use magnetar_proof::{
    prove_spartan_bits, verify_spartan_bits, DirectBitPcs, PackedBitPcs, SparseMatrix,
};
use magnetar_runtime::packed_select::PackedSelectLayout;

fn run<B>(name: &str, backend: &B)
where
    B: magnetar_proof::BitPcs,
    B::Commitment: serde::Serialize,
    B::Opening: serde::Serialize,
{
    let width = 63;
    let layout = PackedSelectLayout::new(width);
    let system = layout.bit_relation.to_system();
    let mut bits = layout.witness_bits(true, 0x5555_5555_5555_5555);
    bits.resize((system.num_vars + 1).next_power_of_two(), false);
    let a = SparseMatrix::from_system(&system, MatrixPart::A).unwrap();
    let b = SparseMatrix::from_system(&system, MatrixPart::B).unwrap();
    let c = SparseMatrix::from_system(&system, MatrixPart::C).unwrap();
    let started = Instant::now();
    let proof = prove_spartan_bits(&bits, &a, &b, &c, backend).expect("prove");
    let prove_time = started.elapsed();
    let bytes = bincode::serialize(&proof).expect("encode").len();
    let started = Instant::now();
    verify_spartan_bits(&a, &b, &c, &proof, backend).expect("verify");
    let verify_time = started.elapsed();
    println!("{name}: proof={bytes} prove={prove_time:?} verify={verify_time:?}");
    let _ = F2_128::from(0u64);
}

fn main() {
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    run("M4-direct", &DirectBitPcs::new(pcs.clone()));
    run("M5-packed", &PackedBitPcs::new(pcs));
}
