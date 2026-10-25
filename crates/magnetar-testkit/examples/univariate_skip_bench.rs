use std::time::Instant;

use magnetar_constraint::F2_128;
use magnetar_runtime::univariate_skip::{SkipRound, SubspaceDomain};

fn main() {
    for log_size in [4usize, 8, 10, 12] {
        let started = Instant::now();
        let domain = SubspaceDomain::new(log_size).unwrap();
        let values = (0..domain.points().len())
            .map(|index| F2_128::from(index as u64 * 17 + 3))
            .collect::<Vec<_>>();
        let at = F2_128::from(0x1234_5678u64);
        let interpolated = domain.interpolate(&values, at).unwrap();
        let interpolate_time = started.elapsed();
        let started = Instant::now();
        let round = SkipRound::new(log_size).unwrap();
        let message = round.message(&values).unwrap();
        let skip_value = round.evaluate(&message, at).unwrap();
        println!(
            "log_size={log_size} points={} interpolation={:?} value={} skip_message={:?} skip_value={}",
            domain.points().len(),
            interpolate_time,
            interpolated.value(),
            started.elapsed(),
            skip_value.value()
        );
    }
}
