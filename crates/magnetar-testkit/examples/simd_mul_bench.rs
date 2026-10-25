use std::time::Instant;

use magnetar_constraint::{Field, F2_128};

fn main() {
    let scalar = F2_128::from(0x1234_5678_9abc_def0u64);
    let values = (0..1_000_000u128)
        .map(|index| F2_128::from(index.wrapping_mul(0x9e37_79b9_7f4a_7c15)))
        .collect::<Vec<_>>();
    for _ in 0..3 {
        let mut scalar_values = values.clone();
        let started = Instant::now();
        for value in &mut scalar_values {
            *value = *value * scalar;
        }
        let scalar_time = started.elapsed();
        let mut packed = values.clone();
        let started = Instant::now();
        <F2_128 as Field>::mul_slice_assign(&mut packed, scalar);
        let packed_time = started.elapsed();
        assert_eq!(scalar_values, packed);
        println!(
            "values={} scalar={scalar_time:?} packed={packed_time:?} speedup={:.2}x",
            values.len(),
            scalar_time.as_secs_f64() / packed_time.as_secs_f64()
        );
    }
}
