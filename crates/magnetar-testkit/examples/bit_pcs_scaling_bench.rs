use std::time::Instant;

use magnetar_constraint::{ConstraintSystem, Expr};
use magnetar_pcs::P3SharedPcs;
use magnetar_proof::spartan::MatrixPart;
use magnetar_proof::{
    prove_spartan_bits, verify_spartan_bits, BitPcs, DirectBitPcs, PackedBitPcs,
    RevealingPackedBitPcs, SparseMatrix,
};

fn system(bits: usize) -> (ConstraintSystem, Vec<bool>) {
    let mut system = ConstraintSystem::new(bits);
    let mut witness = vec![false; bits];
    for (bit, slot) in witness.iter_mut().enumerate() {
        system.add_constraint(Expr::var(bit), Expr::var(bit), Expr::var(bit));
        *slot = bit % 3 != 0;
    }
    (system, witness)
}

fn run<B>(name: &str, bits: usize, backend: &B)
where
    B: BitPcs,
    B::Commitment: serde::Serialize,
    B::Opening: serde::Serialize,
{
    let (system, mut witness) = system(bits);
    witness.resize((system.num_vars + 1).next_power_of_two(), false);
    let a = SparseMatrix::from_system(&system, MatrixPart::A).unwrap();
    let b = SparseMatrix::from_system(&system, MatrixPart::B).unwrap();
    let c = SparseMatrix::from_system(&system, MatrixPart::C).unwrap();
    let started = Instant::now();
    let proof = prove_spartan_bits(&witness, &a, &b, &c, backend).expect("prove");
    let prove_time = started.elapsed();
    let bytes = bincode::serialize(&proof).expect("encode").len();
    let started = Instant::now();
    verify_spartan_bits(&a, &b, &c, &proof, backend).expect("verify");
    let verify_time = started.elapsed();
    println!("{name} bits={bits}: proof={bytes} prove={prove_time:?} verify={verify_time:?}");
}

fn main() {
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    let direct = DirectBitPcs::new(pcs.clone());
    let packed = PackedBitPcs::new(pcs.clone());
    let reveal = RevealingPackedBitPcs::new(pcs);
    for bits in [64usize, 96, 128, 256, 512] {
        run("M4", bits, &direct);
        if bits <= 96 {
            run("M5", bits, &packed);
        } else {
            println!("M5 bits={bits}: unsupported (single-field limit)");
        }
        run("M5-reveal", bits, &reveal);
    }
}
