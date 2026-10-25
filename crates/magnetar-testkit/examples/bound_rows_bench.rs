use std::time::Instant;

use magnetar_constraint::F2_128;
use magnetar_pcs::P3BinaryPcs;
use magnetar_runtime::bound_rows::{prove_bound_rows, verify_bound_rows};
use magnetar_transcript::Sha256Transcript;

fn values(seed: u64, len: usize) -> Vec<F2_128> {
    (0..len)
        .map(|index| F2_128::from(index as u64 * 31 + seed))
        .collect()
}

fn main() {
    for log_size in [4usize, 8, 10] {
        let len = 1usize << log_size;
        let weights = values(7, len);
        let values = values(11, len);
        let expected = weights
            .iter()
            .zip(&values)
            .fold(F2_128::from(0u64), |sum, (weight, value)| {
                sum + *weight * *value
            });
        let pcs = P3BinaryPcs::new(100);
        let mut prover = Sha256Transcript::new("bound-bench");
        let started = Instant::now();
        let proof = prove_bound_rows(&weights, &values, &pcs, &mut prover).unwrap();
        let prove_time = started.elapsed();
        let bytes = bincode::serialize(&proof).unwrap().len();
        let mut verifier = Sha256Transcript::new("bound-bench");
        let started = Instant::now();
        assert!(verify_bound_rows(&weights, expected, &proof, &pcs, &mut verifier).unwrap());
        println!(
            "log_size={log_size} rows={len} proof={bytes} prove={prove_time:?} verify={:?}",
            started.elapsed()
        );
    }
}
