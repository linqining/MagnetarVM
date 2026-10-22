use std::marker::PhantomData;
use std::time::Instant;

use ligerito::eval_proof::EvalClaim;
use ligerito::{
    hardcoded_config_16, hardcoded_config_16_verifier, prove_with_evaluations,
    verify_with_evaluations, FiatShamir,
};
use ligerito_binary_fields::BinaryElem128;

fn main() {
    let size = 1usize << 16;
    let poly: Vec<BinaryElem128> = (0..size)
        .map(|index| BinaryElem128::from((index as u128).wrapping_mul(0x9e37_79b9)))
        .collect();
    let claims = vec![EvalClaim {
        index: 42,
        value: poly[42],
    }];
    let config = hardcoded_config_16(PhantomData::<BinaryElem128>, PhantomData::<BinaryElem128>);
    let verifier_config = hardcoded_config_16_verifier();

    let started = Instant::now();
    let proof =
        prove_with_evaluations(&config, &poly, &claims, FiatShamir::new_sha256(0)).expect("prove");
    let prove_time = started.elapsed();

    let started = Instant::now();
    let valid = verify_with_evaluations::<BinaryElem128, BinaryElem128>(
        &verifier_config,
        &proof,
        &claims,
        FiatShamir::new_sha256(0),
    )
    .expect("verify");
    let verify_time = started.elapsed();

    println!(
        "ligerito 2^{}: proof={} bytes prove={:?} verify={:?} valid={}",
        size.trailing_zeros(),
        proof.size_of(),
        prove_time,
        verify_time,
        valid
    );
}
