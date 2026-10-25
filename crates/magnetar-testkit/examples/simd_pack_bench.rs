use std::time::Instant;

use magnetar_pcs::P3SharedPcs;
use magnetar_proof::bit_pcs::pack_bits_bench;

fn main() {
    let bits = (0..(1usize << 22))
        .map(|index| (index * index + 3 * index + 1) % 7 < 3)
        .collect::<Vec<_>>();
    for _ in 0..3 {
        let started = Instant::now();
        let scalar = pack_bits_bench::<P3SharedPcs>(&bits, false).unwrap();
        let scalar_time = started.elapsed();
        let started = Instant::now();
        let hardware = pack_bits_bench::<P3SharedPcs>(&bits, true).unwrap();
        let hardware_time = started.elapsed();
        assert_eq!(scalar, hardware);
        println!(
            "bits={} scalar={scalar_time:?} hardware={hardware_time:?} speedup={:.2}x",
            bits.len(),
            scalar_time.as_secs_f64() / hardware_time.as_secs_f64()
        );
    }
}
