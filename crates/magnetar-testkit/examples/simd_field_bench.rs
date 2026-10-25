use std::hint::black_box;
use std::time::Instant;

use magnetar_constraint::F2_128;

fn main() {
    let left = (0..1_000_000u128)
        .map(|index| F2_128::from(index.wrapping_mul(0x9e37_79b9_7f4a_7c15)))
        .collect::<Vec<_>>();
    let right = (0..1_000_000u128)
        .map(|index| F2_128::from(index ^ 0xdead_beef))
        .collect::<Vec<_>>();
    for _ in 0..3 {
        let mut scalar = left.clone();
        let started = Instant::now();
        for (value, other) in scalar.iter_mut().zip(&right) {
            *value = F2_128::from(value.value() ^ other.value());
        }
        let scalar_time = started.elapsed();
        let mut simd = left.clone();
        let started = Instant::now();
        F2_128::add_assign_slice(&mut simd, black_box(&right));
        let simd_time = started.elapsed();
        assert_eq!(scalar, simd);
        println!(
            "values={} scalar={scalar_time:?} simd={simd_time:?} speedup={:.2}x",
            left.len(),
            scalar_time.as_secs_f64() / simd_time.as_secs_f64()
        );
    }
}
