use std::time::Instant;

use magnetar_pcs::P3SharedPcs;
use magnetar_proof::{prove_spartan, verify_spartan};
use magnetar_runtime::packed_select::{
    prove_packed_select, verify_packed_select, PackedSelectLayout,
};

fn main() {
    let layout = PackedSelectLayout::new(64);
    let witness = layout.witness(true, 0xAAAA_AAAA_AAAA_AAAA);
    let s1 = layout.bit_relation.to_system();
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());

    let started = Instant::now();
    let bit_proof = prove_spartan(&s1, &witness, &pcs).expect("bit prove");
    let bit_time = started.elapsed();
    let bit_bytes = bincode::serialize(&bit_proof).expect("encode").len();
    let started = Instant::now();
    verify_spartan(&s1, &bit_proof, &pcs).expect("bit verify");
    let bit_verify = started.elapsed();

    let started = Instant::now();
    let packed_proof = prove_spartan(&layout.packed_system, &witness, &pcs).expect("packed prove");
    let packed_time = started.elapsed();
    let packed_bytes = bincode::serialize(&packed_proof).expect("encode").len();
    let started = Instant::now();
    verify_spartan(&layout.packed_system, &packed_proof, &pcs).expect("packed verify");
    let packed_verify = started.elapsed();

    let started = Instant::now();
    let (dual, segments) =
        prove_packed_select(64, true, 0xAAAA_AAAA_AAAA_AAAA).expect("dual prove");
    let dual_time = started.elapsed();
    let dual_bytes = bincode::serialize(&dual).expect("encode").len();
    let started = Instant::now();
    verify_packed_select(64, &dual, &segments).expect("dual verify");
    let dual_verify = started.elapsed();

    println!("s1 bit select:   {bit_bytes} B prove={bit_time:?} verify={bit_verify:?}");
    println!("s2 packed select:{packed_bytes} B prove={packed_time:?} verify={packed_verify:?}");
    println!("dual same-W:     {dual_bytes} B prove={dual_time:?} verify={dual_verify:?}");
}
