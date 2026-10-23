use std::time::Instant;

use magnetar_constraint::{ConstraintSystem, Expr, Witness, F2_128};
use magnetar_pcs::P3SharedPcs;
use magnetar_proof::{prove_spartan, verify_spartan};

fn bit_xor() -> (ConstraintSystem, Witness) {
    let width = 64usize;
    let a = 0..width;
    let b = width..2 * width;
    let out = 2 * width..3 * width;
    let one = 3 * width;
    let mut system = ConstraintSystem::new(3 * width + 1);
    let mut values = vec![F2_128::from(0u64); 3 * width + 1];
    values[one] = F2_128::from(1u64);
    system.add_constraint(Expr::var(one), Expr::var(one), Expr::var(one));
    for bit in 0..width {
        system.add_constraint(
            Expr::var(a.start + bit).add(Expr::var(b.start + bit)),
            Expr::var(one),
            Expr::var(out.start + bit),
        );
        let left = if bit % 3 == 0 { 1u64 } else { 0 };
        let right = if bit % 5 == 0 { 1u64 } else { 0 };
        values[a.start + bit] = F2_128::from(left);
        values[b.start + bit] = F2_128::from(right);
        values[out.start + bit] = F2_128::from(left ^ right);
    }
    (system, Witness::new(values))
}

fn packed_xor() -> (ConstraintSystem, Witness) {
    let a = 0;
    let b = 1;
    let out = 2;
    let one = 3;
    let mut system = ConstraintSystem::new(4);
    system.add_constraint(Expr::var(one), Expr::var(one), Expr::var(one));
    system.add_constraint(
        Expr::var(a).add(Expr::var(b)),
        Expr::var(one),
        Expr::var(out),
    );
    let mut values = vec![F2_128::from(0u64); 4];
    values[one] = F2_128::from(1u64);
    values[a] = F2_128::from(0xAAAA_AAAA_AAAA_AAAAu64);
    values[b] = F2_128::from(0xFFFF_0000_FFFF_0000u64);
    values[out] = values[a] + values[b];
    (system, Witness::new(values))
}

fn packed_select() -> (ConstraintSystem, Witness) {
    let a = 0;
    let b = 1;
    let out = 2;
    let sel = 3;
    let one = 4;
    let sel_a = 5;
    let not_b = 6;
    let mut system = ConstraintSystem::new(7);
    system.add_constraint(Expr::var(one), Expr::var(one), Expr::var(one));
    system.add_constraint(Expr::var(sel), Expr::var(sel), Expr::var(sel));
    system.add_constraint(Expr::var(sel), Expr::var(a), Expr::var(sel_a));
    system.add_constraint(
        Expr::constant(1u64).add(Expr::var(sel)),
        Expr::var(b),
        Expr::var(not_b),
    );
    system.add_constraint(
        Expr::var(sel_a).add(Expr::var(not_b)),
        Expr::var(one),
        Expr::var(out),
    );
    let mut values = vec![F2_128::from(0u64); 7];
    values[one] = F2_128::from(1u64);
    values[sel] = F2_128::from(1u64);
    values[a] = F2_128::from(0xAAAA_AAAA_AAAA_AAAAu64);
    values[b] = F2_128::from(0x1234_5678_9ABC_DEF0u64);
    values[sel_a] = values[a];
    values[not_b] = F2_128::from(0u64);
    values[out] = values[a];
    (system, Witness::new(values))
}

fn run(name: &str, system: &ConstraintSystem, witness: &Witness) {
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    let started = Instant::now();
    let proof = prove_spartan(system, witness, &pcs).expect("prove");
    let prove_time = started.elapsed();
    let bytes = bincode::serialize(&proof).expect("encode").len();
    let started = Instant::now();
    verify_spartan(system, &proof, &pcs).expect("verify");
    let verify_time = started.elapsed();
    println!(
        "{name}: vars={} rows={} proof={bytes} prove={prove_time:?} verify={verify_time:?}",
        system.num_vars,
        system.constraints.len()
    );
}

fn main() {
    let (bit_system, bit_witness) = bit_xor();
    let (packed_system, packed_witness) = packed_xor();
    let (select_system, select_witness) = packed_select();
    run("bit-xor-64", &bit_system, &bit_witness);
    run("packed-xor-64", &packed_system, &packed_witness);
    run("packed-select-64", &select_system, &select_witness);
}
