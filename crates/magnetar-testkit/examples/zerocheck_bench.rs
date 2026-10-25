use std::time::Instant;

use magnetar_constraint::F2_128;
use magnetar_pcs::P3BinaryPcs;
use magnetar_runtime::zerocheck::{prove_booleanity, verify_booleanity};
use magnetar_transcript::Sha256Transcript;

fn main() {
    for log_size in [8usize, 10, 12] {
        let len = 1usize << log_size;
        let values = (0..len)
            .map(|index| F2_128::from(((index as u64 * 17 + 3) >> 1) & 1))
            .collect::<Vec<_>>();
        let pcs = P3BinaryPcs::new(100);
        let mut prover = Sha256Transcript::new("booleanity-bench");
        let started = Instant::now();
        let proof = prove_booleanity(&values, &pcs, &mut prover).unwrap();
        let prove_time = started.elapsed();
        let bytes = bincode::serialize(&proof).unwrap().len();
        let mut verifier = Sha256Transcript::new("booleanity-bench");
        let started = Instant::now();
        assert!(verify_booleanity(&proof, &pcs, &mut verifier).unwrap());
        println!(
            "log_size={log_size} rows={len} proof={bytes} prove={prove_time:?} verify={:?}",
            started.elapsed()
        );
    }
}
