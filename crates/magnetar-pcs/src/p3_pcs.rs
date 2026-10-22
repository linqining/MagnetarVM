//! Multilinear PCS over the binary tower via `p3-binary-pcs`.
//!
//! Ligerito 0.8.0 exposes Boolean-index claims only. Plonky3's binary PCS
//! provides real multilinear point openings, which is what the Spartan
//! reduction needs.

use magnetar_constraint::F2_128;
use magnetar_proof::{Pcs, ProofError};
use p3_binary_field::{BinaryChallenger, BinaryField128, TowerLevel};
use p3_binary_pcs::{BinaryPcs, BinaryPcsConfig, BinaryPcsParams, BinaryPcsProof};
use p3_challenger::HashChallenger;
use p3_commit::{Mmcs, MultilinearPcs};
use p3_field::PrimeCharacteristicRing;
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::point::Point;
use p3_sumcheck::layout::{Layout, SuffixProver, Table};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};

type F = BinaryField128;
type P3Hash = SerializingHasher<Keccak256Hash>;
type P3Compress = CompressionFunctionFromHasher<Keccak256Hash, 2, 32>;
type P3Mmcs = MerkleTreeMmcs<F, u8, P3Hash, P3Compress, 2, 32>;
type P3Challenger = BinaryChallenger<F, HashChallenger<u8, Keccak256Hash, 32>>;
type P3PcsBackend = BinaryPcs<F, F, P3Mmcs, P3Mmcs>;
type P3Proof = BinaryPcsProof<F, F, P3Mmcs, P3Mmcs>;
type P3Cap = <P3Mmcs as Mmcs<F>>::Commitment;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct P3Commitment {
    pub cap: P3Cap,
    pub num_variables: usize,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct P3Opening {
    pub commitment: P3Commitment,
    pub proof: P3Proof,
}

impl std::fmt::Debug for P3Opening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P3Opening")
            .field("commitment", &self.commitment)
            .field(
                "proof_bytes",
                &bincode::serialize(&self.proof).map(|b| b.len()),
            )
            .finish()
    }
}

/// Multilinear PCS over the 128-bit binary tower.
#[derive(Clone, Copy, Debug, Default)]
pub struct P3BinaryPcs {
    pub security_level: usize,
}

impl P3BinaryPcs {
    pub fn new(security_level: usize) -> Self {
        Self { security_level }
    }

    fn mmcs() -> P3Mmcs {
        P3Mmcs::new(
            P3Hash::new(Keccak256Hash),
            P3Compress::new(Keccak256Hash),
            0,
        )
    }

    fn challenger() -> P3Challenger {
        P3Challenger::from_hasher(Vec::new(), Keccak256Hash)
    }

    fn backend(num_variables: usize, security_level: usize) -> Result<P3PcsBackend, ProofError> {
        let params = BinaryPcsParams {
            log_inv_rate: 2,
            pow_bits: 4,
            security_level,
        };
        let config = BinaryPcsConfig::try_new::<F, F>(num_variables, params)
            .map_err(|error| ProofError::Pcs(error.to_string()))?;
        P3PcsBackend::new(config, Self::mmcs(), Self::mmcs())
            .map_err(|error| ProofError::Pcs(error.to_string()))
    }

    fn table(values: &[F2_128]) -> Result<(Table<F>, usize, usize), ProofError> {
        if values.is_empty() || !values.len().is_power_of_two() {
            return Err(ProofError::NotPowerOfTwo(values.len()));
        }
        let logical = values.len().trailing_zeros() as usize;
        let mut converted: Vec<F> = values
            .iter()
            .map(|value| F::from_repr(value.value()))
            .collect();
        let pcs_log = if values.len() == 1 {
            converted.push(F::ZERO);
            1
        } else {
            logical
        };
        Ok((
            Table::new(RowMajorMatrix::new(converted, 1usize << pcs_log)),
            logical,
            pcs_log,
        ))
    }

    fn protocol(num_variables: usize) -> OpeningProtocol {
        OpeningProtocol::new(vec![TableSpec::new(
            TableShape::new(num_variables, 1),
            vec![OpeningBatch::new(vec![0], Vec::new())],
        )])
    }

    fn point(point: &[F2_128]) -> Point<F> {
        if point.is_empty() {
            return Point::new(vec![F::ZERO]);
        }
        Point::new(
            point
                .iter()
                .rev()
                .map(|value| F::from_repr(value.value()))
                .collect::<Vec<_>>(),
        )
    }

    fn commit_with(
        backend: &P3PcsBackend,
        values: &[F2_128],
        challenger: &mut P3Challenger,
    ) -> Result<(P3Cap, p3_binary_pcs::BinaryPcsProverData<F, F, P3Mmcs>), ProofError> {
        let (table, _, _) = Self::table(values)?;
        let witness = SuffixProver::<F, F>::new_witness(vec![table], 0);
        backend
            .commit(witness, challenger)
            .map_err(|error| ProofError::Pcs(error.to_string()))
    }
}

impl Pcs for P3BinaryPcs {
    type Commitment = P3Commitment;
    type Opening = P3Opening;

    fn commit(&self, values: &[F2_128]) -> Result<Self::Commitment, ProofError> {
        let (_, num_variables, pcs_log) = Self::table(values)?;
        let backend = Self::backend(pcs_log, self.security_level)?;
        let mut challenger = Self::challenger();
        let (cap, _) = Self::commit_with(&backend, values, &mut challenger)?;
        Ok(P3Commitment { cap, num_variables })
    }

    fn open(&self, values: &[F2_128], point: &[F2_128]) -> Result<Self::Opening, ProofError> {
        let (_, num_variables, pcs_log) = Self::table(values)?;
        if point.len() != num_variables {
            return Err(ProofError::PointLength {
                expected: num_variables,
                actual: point.len(),
            });
        }
        let backend = Self::backend(pcs_log, self.security_level)?;
        let mut challenger = Self::challenger();
        let (cap, data) = Self::commit_with(&backend, values, &mut challenger)?;
        let proof = backend
            .open_at(
                data,
                &Self::protocol(pcs_log),
                core::slice::from_ref(&Self::point(point)),
                &mut challenger,
            )
            .map_err(|error| ProofError::Pcs(error.to_string()))?;
        Ok(P3Opening {
            commitment: P3Commitment { cap, num_variables },
            proof,
        })
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &[F2_128],
        value: F2_128,
        opening: &Self::Opening,
    ) -> Result<bool, ProofError> {
        if commitment.num_variables != opening.commitment.num_variables
            || commitment.cap != opening.commitment.cap
            || point.len() != commitment.num_variables
        {
            return Ok(false);
        }
        let pcs_log = commitment.num_variables.max(1);
        let backend = Self::backend(pcs_log, self.security_level)?;
        let mut challenger = Self::challenger();
        backend.observe_commitment(&commitment.cap, &mut challenger);
        let Ok(evals) = backend.verify_at(
            &commitment.cap,
            &opening.proof,
            &Self::protocol(pcs_log),
            core::slice::from_ref(&Self::point(point)),
            &mut challenger,
        ) else {
            return Ok(false);
        };
        let expected = F::from_repr(value.value());
        Ok(evals
            .first()
            .and_then(|batch| batch.current().first())
            .is_some_and(|observed| *observed == expected))
    }

    fn commitment_bytes(&self, commitment: &Self::Commitment) -> Vec<u8> {
        bincode::serialize(commitment).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(size: usize) -> Vec<F2_128> {
        (0..size)
            .map(|index| F2_128::from((index as u64).wrapping_mul(0x9e37_79b9)))
            .collect()
    }

    #[test]
    fn p3_field_multiplication_matches_magnetar_tower() {
        for index in 0..64u128 {
            let a = F2_128::from((index.wrapping_mul(0x0123_4567_89ab_cdef)) & 0xffff);
            let b = F2_128::from((index.wrapping_mul(0xfedc_ba98_7654_3210)) & 0xffff);
            let pa = F::from_repr(a.value());
            let pb = F::from_repr(b.value());
            let product = F::as_repr_slice(&[pa * pb])[0];
            assert_eq!((a * b).value(), product, "index {index}");
        }
    }

    #[test]
    fn p3_multilinear_opening_round_trips() {
        let pcs = P3BinaryPcs::new(100);
        let values = values(1 << 10);
        let point: Vec<F2_128> = (0..10u64).map(|index| F2_128::from(index & 1)).collect();
        let opening = pcs.open(&values, &point).unwrap();
        let commitment = opening.commitment.clone();
        let value = magnetar_proof::Mle::new(values.clone())
            .unwrap()
            .eval(&point)
            .unwrap();
        match pcs.verify(&commitment, &point, value, &opening) {
            Ok(valid) => assert!(valid, "value mismatch"),
            Err(error) => panic!("verify error: {error}"),
        }

        let mut wrong_point = point.clone();
        wrong_point[0] = wrong_point[0] + F2_128::from(1u64);
        assert!(!pcs
            .verify(&commitment, &wrong_point, value, &opening)
            .unwrap());
        assert!(!pcs
            .verify(&commitment, &point, value + F2_128::from(1u64), &opening)
            .unwrap());
    }
}
