use std::time::Instant;

use p3_binary_field::{BinaryChallenger, BinaryField128};
use p3_binary_pcs::{BinaryPcs, BinaryPcsConfig, BinaryPcsParams};
use p3_challenger::HashChallenger;
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::point::Point;
use p3_sumcheck::layout::{Layout, SuffixProver, Table};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};

type F = BinaryField128;
type MyHash = SerializingHasher<Keccak256Hash>;
type MyCompress = CompressionFunctionFromHasher<Keccak256Hash, 2, 32>;
type MyMmcs = MerkleTreeMmcs<F, u8, MyHash, MyCompress, 2, 32>;
type MyChallenger = BinaryChallenger<F, HashChallenger<u8, Keccak256Hash, 32>>;
type MyPcs = BinaryPcs<F, F, MyMmcs, MyMmcs>;

fn mmcs() -> MyMmcs {
    MyMmcs::new(
        MyHash::new(Keccak256Hash),
        MyCompress::new(Keccak256Hash),
        0,
    )
}

fn challenger() -> MyChallenger {
    MyChallenger::from_hasher(Vec::new(), Keccak256Hash)
}

fn main() {
    let num_variables = std::env::args()
        .nth(1)
        .map(|value| value.parse().expect("log size"))
        .unwrap_or(16usize);
    let size = 1usize << num_variables;
    let values: Vec<F> = (0..size)
        .map(|index| F::from_u32((index as u32).wrapping_mul(0x9e37_79b9)))
        .collect();
    let table = Table::new(RowMajorMatrix::new(values.clone(), size));
    let witness = SuffixProver::<F, F>::new_witness(vec![table], 0);
    let params = BinaryPcsParams {
        log_inv_rate: 2,
        pow_bits: 4,
        security_level: 100,
    };
    let config = BinaryPcsConfig::try_new::<F, F>(num_variables, params).expect("config");
    let pcs = MyPcs::new(config, mmcs(), mmcs()).expect("pcs");
    let protocol = OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(num_variables, 1),
        vec![OpeningBatch::new(vec![0], Vec::new())],
    )]);
    let point = Point::new(
        (0..num_variables)
            .rev()
            .map(|index| F::from_u16((index as u16).wrapping_mul(7).wrapping_add(3)))
            .collect::<Vec<_>>(),
    );

    let mut prover_challenger = challenger();
    let (commitment, data) = pcs.commit(witness, &mut prover_challenger).expect("commit");
    let started = Instant::now();
    let proof = pcs
        .open_at(
            data,
            &protocol,
            core::slice::from_ref(&point),
            &mut prover_challenger,
        )
        .expect("open_at");
    let prove_time = started.elapsed();
    let proof_bytes = bincode::serialize(&proof).expect("serialize").len();

    let mut verifier_challenger = challenger();
    pcs.observe_commitment(&commitment, &mut verifier_challenger);
    let started = Instant::now();
    let evals = pcs
        .verify_at(
            &commitment,
            &proof,
            &protocol,
            core::slice::from_ref(&point),
            &mut verifier_challenger,
        )
        .expect("verify_at");
    let verify_time = started.elapsed();
    println!(
        "p3 binary pcs 2^{num_variables}: proof={proof_bytes} bytes prove={prove_time:?} verify={verify_time:?} evals={} first={:?}",
        evals.len(),
        evals.first().map(|batch| batch.current())
    );
}
