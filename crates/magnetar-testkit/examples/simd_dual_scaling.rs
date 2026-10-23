use std::time::Instant;

use magnetar_cpu::StepOp;
use magnetar_runtime::simd_dual::{prove_dual_batch, verify_dual_batch};

fn main() {
    for cycles in [2usize, 4, 8] {
        let started = Instant::now();
        let (proof, layout) = prove_dual_batch(8, StepOp::Add, cycles).expect("prove");
        let prove_time = started.elapsed();
        let bytes = bincode::serialize(&proof).expect("encode").len();
        let started = Instant::now();
        verify_dual_batch(8, StepOp::Add, cycles, &proof, &layout).expect("verify");
        let verify_time = started.elapsed();
        println!("cycles={cycles}: proof={bytes} prove={prove_time:?} verify={verify_time:?}");
    }
}
