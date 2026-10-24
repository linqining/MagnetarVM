use magnetar_constraint::F2_128;
use magnetar_pcs::P3BinaryPcs;
use magnetar_proof::{Mle, Pcs};

fn main() {
    for log in [7usize, 9, 12] {
        let values = (0..(1usize << log))
            .map(|i| F2_128::from((i as u64) * 0x9e37 + 1))
            .collect::<Vec<_>>();
        let point = (0..log)
            .map(|i| F2_128::from((i % 2) as u64))
            .collect::<Vec<_>>();
        let pcs = P3BinaryPcs::new(100);
        let commitment = pcs.commit(&values).unwrap();
        let opening = pcs.open(&values, &point).unwrap();
        let _ = Mle::new(values).unwrap().eval(&point).unwrap();
        println!(
            "log {log}: commitment {} opening {}",
            bincode::serialize(&commitment).unwrap().len(),
            bincode::serialize(&opening).unwrap().len()
        );
    }
}
