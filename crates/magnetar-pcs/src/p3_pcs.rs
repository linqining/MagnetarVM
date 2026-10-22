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

/// One commitment to a packed batch of equally sized columns.
///
/// The columns are stacked into the PCS layout, so the commitment and its
/// opening proof are shared by every column. `num_variables` is the local
/// arity of a column; `stacked_variables` is the arity of the stacked
/// polynomial after slot selectors are added.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct P3BatchCommitment {
    pub cap: P3Cap,
    pub num_variables: usize,
    pub stacked_variables: usize,
    pub num_columns: usize,
}

/// One PCS opening proof covering every column and every point in a batch.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct P3BatchOpening {
    pub commitment: P3BatchCommitment,
    pub proof: P3Proof,
}

impl std::fmt::Debug for P3BatchOpening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P3BatchOpening")
            .field("commitment", &self.commitment)
            .field(
                "proof_bytes",
                &bincode::serialize(&self.proof).map(|b| b.len()),
            )
            .finish()
    }
}

/// A point and the columns opened there.
#[derive(Clone, Debug)]
pub struct P3BatchPoint {
    pub point: Vec<F2_128>,
    pub columns: Vec<usize>,
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

    fn batch_table(columns: &[Vec<F2_128>]) -> Result<(Table<F>, usize, usize), ProofError> {
        if columns.is_empty() {
            return Err(ProofError::DimensionMismatch);
        }
        let len = columns[0].len();
        if len < 2 || !len.is_power_of_two() {
            return Err(ProofError::NotPowerOfTwo(len));
        }
        if columns.iter().any(|column| column.len() != len) {
            return Err(ProofError::DimensionMismatch);
        }
        let logical = len.trailing_zeros() as usize;
        let mut converted = Vec::with_capacity(len * columns.len());
        for column in columns {
            converted.extend(
                column
                    .iter()
                    .map(|value| F::from_repr(value.value()))
                    .collect::<Vec<_>>(),
            );
        }
        Ok((
            Table::new(RowMajorMatrix::new(converted, len)),
            logical,
            columns.len(),
        ))
    }

    fn stacked_variables(num_variables: usize, num_columns: usize) -> usize {
        let slots = num_columns.next_power_of_two();
        num_variables + slots.trailing_zeros() as usize
    }

    fn batch_protocol(
        num_variables: usize,
        num_columns: usize,
        points: &[P3BatchPoint],
    ) -> Result<OpeningProtocol, ProofError> {
        let mut schedule = Vec::with_capacity(points.len());
        for (index, point) in points.iter().enumerate() {
            if point.point.len() != num_variables {
                return Err(ProofError::PointLength {
                    expected: num_variables,
                    actual: point.point.len(),
                });
            }
            if point.columns.is_empty() || point.columns.iter().any(|column| *column >= num_columns)
            {
                return Err(ProofError::Pcs(format!(
                    "batch point {index} names an invalid column"
                )));
            }
            let mut seen = point.columns.clone();
            seen.sort_unstable();
            seen.dedup();
            if seen.len() != point.columns.len() {
                return Err(ProofError::Pcs(format!(
                    "batch point {index} repeats a column"
                )));
            }
            schedule.push(OpeningBatch::new(point.columns.clone(), Vec::new()));
        }
        Ok(OpeningProtocol::new(vec![TableSpec::new(
            TableShape::new(num_variables, num_columns),
            schedule,
        )]))
    }

    /// Commit to a set of equally sized columns with a single PCS commitment.
    pub fn commit_batch(&self, columns: &[Vec<F2_128>]) -> Result<P3BatchCommitment, ProofError> {
        let (table, num_variables, num_columns) = Self::batch_table(columns)?;
        let stacked_variables = Self::stacked_variables(num_variables, num_columns);
        let backend = Self::backend(stacked_variables, self.security_level)?;
        let mut challenger = Self::challenger();
        let witness = SuffixProver::<F, F>::new_witness(vec![table], 0);
        let (cap, _) = backend
            .commit(witness, &mut challenger)
            .map_err(|error| ProofError::Pcs(error.to_string()))?;
        Ok(P3BatchCommitment {
            cap,
            num_variables,
            stacked_variables,
            num_columns,
        })
    }

    /// Open every listed column at each point with one PCS opening argument.
    pub fn open_batch(
        &self,
        columns: &[Vec<F2_128>],
        points: &[P3BatchPoint],
    ) -> Result<P3BatchOpening, ProofError> {
        let (table, num_variables, num_columns) = Self::batch_table(columns)?;
        if columns.len() != num_columns {
            return Err(ProofError::DimensionMismatch);
        }
        let stacked_variables = Self::stacked_variables(num_variables, num_columns);
        let protocol = Self::batch_protocol(num_variables, num_columns, points)?;
        let backend = Self::backend(stacked_variables, self.security_level)?;
        let mut challenger = Self::challenger();
        let witness = SuffixProver::<F, F>::new_witness(vec![table], 0);
        let (cap, data) = backend
            .commit(witness, &mut challenger)
            .map_err(|error| ProofError::Pcs(error.to_string()))?;
        let p3_points = points
            .iter()
            .map(|point| Self::point(&point.point))
            .collect::<Vec<_>>();
        let proof = backend
            .open_at(data, &protocol, &p3_points, &mut challenger)
            .map_err(|error| ProofError::Pcs(error.to_string()))?;
        Ok(P3BatchOpening {
            commitment: P3BatchCommitment {
                cap,
                num_variables,
                stacked_variables,
                num_columns,
            },
            proof,
        })
    }

    /// Verify a batched opening against the values expected at each point.
    pub fn verify_batch(
        &self,
        opening: &P3BatchOpening,
        points: &[P3BatchPoint],
        values: &[Vec<F2_128>],
    ) -> Result<bool, ProofError> {
        let commitment = &opening.commitment;
        if points.len() != values.len() {
            return Ok(false);
        }
        let expected_stacked =
            Self::stacked_variables(commitment.num_variables, commitment.num_columns);
        if commitment.stacked_variables != expected_stacked {
            return Ok(false);
        }
        let protocol =
            match Self::batch_protocol(commitment.num_variables, commitment.num_columns, points) {
                Ok(protocol) => protocol,
                Err(_) => return Ok(false),
            };
        let backend = Self::backend(commitment.stacked_variables, self.security_level)?;
        let mut challenger = Self::challenger();
        backend.observe_commitment(&commitment.cap, &mut challenger);
        let p3_points = points
            .iter()
            .map(|point| Self::point(&point.point))
            .collect::<Vec<_>>();
        let Ok(evals) = backend.verify_at(
            &commitment.cap,
            &opening.proof,
            &protocol,
            &p3_points,
            &mut challenger,
        ) else {
            return Ok(false);
        };
        if evals.len() != values.len() {
            return Ok(false);
        }
        for ((batch, expected), point) in evals.iter().zip(values).zip(points) {
            if expected.len() != point.columns.len()
                || batch.current().len() != expected.len()
                || batch
                    .current()
                    .iter()
                    .zip(expected)
                    .any(|(observed, value)| *observed != F::from_repr(value.value()))
            {
                return Ok(false);
            }
        }
        Ok(true)
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

    #[test]
    fn p3_batch_opening_covers_columns_and_points_once() {
        let pcs = P3BinaryPcs::new(100);
        let columns = vec![values(1 << 10), values(1 << 10), values(1 << 10)];
        let points = vec![
            P3BatchPoint {
                point: (0..10u64).map(|index| F2_128::from(index & 1)).collect(),
                columns: vec![0, 2],
            },
            P3BatchPoint {
                point: (0..10u64)
                    .map(|index| F2_128::from((index + 1) & 1))
                    .collect(),
                columns: vec![1],
            },
        ];
        let opening = pcs.open_batch(&columns, &points).unwrap();
        let expected: Vec<Vec<F2_128>> = points
            .iter()
            .map(|batch| {
                batch
                    .columns
                    .iter()
                    .map(|column| {
                        magnetar_proof::Mle::new(columns[*column].clone())
                            .unwrap()
                            .eval(&batch.point)
                            .unwrap()
                    })
                    .collect()
            })
            .collect();
        assert!(pcs.verify_batch(&opening, &points, &expected).unwrap());

        let mut bad = expected.clone();
        bad[0][0] = bad[0][0] + F2_128::from(1u64);
        assert!(!pcs.verify_batch(&opening, &points, &bad).unwrap());

        let mut bad_point = points.clone();
        bad_point[1].point[0] = bad_point[1].point[0] + F2_128::from(1u64);
        assert!(!pcs.verify_batch(&opening, &bad_point, &expected).unwrap());
    }
}
