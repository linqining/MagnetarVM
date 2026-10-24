use magnetar_constraint::F2_128;
use magnetar_pcs::P3BinaryPcs;
use magnetar_proof::{Mle, Pcs};

fn main() {
    let log = 12usize;
    let values = (0..(1usize << log))
        .map(|i| F2_128::from((i as u64).wrapping_mul(0x9e3779b97f4a7c15)))
        .collect::<Vec<_>>();
    let point = (0..log)
        .map(|i| F2_128::from(((i * 7 + 3) % 251) as u64))
        .collect::<Vec<_>>();
    let value = Mle::new(values.clone()).unwrap().eval(&point).unwrap();
    println!("rate pow fold opening verified");
    for rate in [2usize, 3, 4] {
        for pow in [4usize, 8, 12, 16] {
            for fold in [1usize, 2, 3, 4] {
                let pcs = P3BinaryPcs::with_params(100, rate, pow, fold);
                let Ok(commitment) = pcs.commit(&values) else {
                    continue;
                };
                let Ok(opening) = pcs.open(&values, &point) else {
                    continue;
                };
                let bytes = bincode::serialize(&opening).unwrap().len();
                let verified = pcs
                    .verify(&commitment, &point, value, &opening)
                    .unwrap_or(false);
                println!("{rate} {pow} {fold} {bytes} {verified}");
            }
        }
    }
}
