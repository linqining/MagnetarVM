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

/// Shape of one source table inside a mosaic commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct P3MosaicTableShape {
    pub num_variables: usize,
    pub num_columns: usize,
}

/// A commitment to several source tables of different arities.
///
/// The tables are stacked into one PCS polynomial, so one commitment and one
/// opening argument cover every table and every point. Local table points are
/// lifted by the P3 stacked layout.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct P3MosaicCommitment {
    pub cap: P3Cap,
    pub tables: Vec<P3MosaicTableShape>,
    pub stacked_variables: usize,
}

/// One PCS opening proof covering every mosaic table and point.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct P3MosaicOpening {
    pub commitment: P3MosaicCommitment,
    pub proof: P3Proof,
}

impl std::fmt::Debug for P3MosaicOpening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P3MosaicOpening")
            .field("commitment", &self.commitment)
            .field(
                "proof_bytes",
                &bincode::serialize(&self.proof).map(|b| b.len()),
            )
            .finish()
    }
}

/// Source columns of one table in a mosaic commitment.
#[derive(Clone, Debug)]
pub struct P3MosaicTable {
    pub columns: Vec<Vec<F2_128>>,
}

/// A local opening point owned by one mosaic table.
#[derive(Clone, Debug)]
pub struct P3MosaicPoint {
    pub table: usize,
    pub point: Vec<F2_128>,
    pub columns: Vec<usize>,
    /// Columns evaluated through the repeat-last successor view at the same point.
    pub next_columns: Vec<usize>,
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

    fn mosaic_table(table: &P3MosaicTable) -> Result<(Table<F>, P3MosaicTableShape), ProofError> {
        let (p3_table, num_variables, num_columns) = Self::batch_table(&table.columns)?;
        Ok((
            p3_table,
            P3MosaicTableShape {
                num_variables,
                num_columns,
            },
        ))
    }

    fn mosaic_stacked_variables(shapes: &[P3MosaicTableShape]) -> Result<usize, ProofError> {
        if shapes.is_empty() {
            return Err(ProofError::DimensionMismatch);
        }
        let mut total = 0usize;
        for shape in shapes {
            let rows = 1usize
                .checked_shl(shape.num_variables as u32)
                .ok_or_else(|| ProofError::Pcs("mosaic table arity overflows usize".into()))?;
            let cells = rows
                .checked_mul(shape.num_columns)
                .ok_or_else(|| ProofError::Pcs("mosaic table cells overflow usize".into()))?;
            total = total
                .checked_add(cells)
                .ok_or_else(|| ProofError::Pcs("mosaic cell count overflows usize".into()))?;
        }
        if total == 0 {
            return Err(ProofError::Pcs("mosaic has no cells".into()));
        }
        Ok(total.next_power_of_two().trailing_zeros() as usize)
    }

    fn mosaic_schedule(
        shapes: &[P3MosaicTableShape],
        points: &[P3MosaicPoint],
    ) -> Result<(OpeningProtocol, Vec<Point<F>>), ProofError> {
        let mut per_table: Vec<Vec<usize>> = vec![Vec::new(); shapes.len()];
        let mut last_table = 0usize;
        for (index, point) in points.iter().enumerate() {
            if point.table >= shapes.len() {
                return Err(ProofError::Pcs(format!(
                    "mosaic point {index} names an invalid table"
                )));
            }
            if point.table < last_table {
                return Err(ProofError::Pcs(
                    "mosaic points must be grouped by table".into(),
                ));
            }
            last_table = point.table;
            let shape = shapes[point.table];
            if point.point.len() != shape.num_variables {
                return Err(ProofError::PointLength {
                    expected: shape.num_variables,
                    actual: point.point.len(),
                });
            }
            if point.columns.is_empty()
                || point
                    .columns
                    .iter()
                    .any(|column| *column >= shape.num_columns)
            {
                return Err(ProofError::Pcs(format!(
                    "mosaic point {index} names an invalid column"
                )));
            }
            let mut seen = point.columns.clone();
            seen.sort_unstable();
            seen.dedup();
            if seen.len() != point.columns.len() {
                return Err(ProofError::Pcs(format!(
                    "mosaic point {index} repeats a column"
                )));
            }
            per_table[point.table].push(index);
        }

        let mut ordered = Vec::with_capacity(points.len());
        let mut specs = Vec::with_capacity(shapes.len());
        for (table, shape) in shapes.iter().enumerate() {
            let mut schedule = Vec::with_capacity(per_table[table].len());
            for &index in &per_table[table] {
                schedule.push(OpeningBatch::new(
                    points[index].columns.clone(),
                    points[index].next_columns.clone(),
                ));
                ordered.push(Self::point(&points[index].point));
            }
            specs.push(TableSpec::new(
                TableShape::new(shape.num_variables, shape.num_columns),
                schedule,
            ));
        }
        Ok((OpeningProtocol::new(specs), ordered))
    }

    /// Commit to several tables of different arities with one PCS commitment.
    pub fn commit_mosaic(
        &self,
        tables: &[P3MosaicTable],
    ) -> Result<P3MosaicCommitment, ProofError> {
        let mut p3_tables = Vec::with_capacity(tables.len());
        let mut shapes = Vec::with_capacity(tables.len());
        for table in tables {
            let (p3_table, shape) = Self::mosaic_table(table)?;
            p3_tables.push(p3_table);
            shapes.push(shape);
        }
        let stacked_variables = Self::mosaic_stacked_variables(&shapes)?;
        let backend = Self::backend(stacked_variables, self.security_level)?;
        let mut challenger = Self::challenger();
        let witness = SuffixProver::<F, F>::new_witness(p3_tables, 0);
        let (cap, _) = backend
            .commit(witness, &mut challenger)
            .map_err(|error| ProofError::Pcs(error.to_string()))?;
        Ok(P3MosaicCommitment {
            cap,
            tables: shapes,
            stacked_variables,
        })
    }

    /// Open every mosaic table at its listed local points with one proof.
    pub fn open_mosaic(
        &self,
        tables: &[P3MosaicTable],
        points: &[P3MosaicPoint],
    ) -> Result<P3MosaicOpening, ProofError> {
        let mut p3_tables = Vec::with_capacity(tables.len());
        let mut shapes = Vec::with_capacity(tables.len());
        for table in tables {
            let (p3_table, shape) = Self::mosaic_table(table)?;
            p3_tables.push(p3_table);
            shapes.push(shape);
        }
        let stacked_variables = Self::mosaic_stacked_variables(&shapes)?;
        let (protocol, p3_points) = Self::mosaic_schedule(&shapes, points)?;
        let backend = Self::backend(stacked_variables, self.security_level)?;
        let mut challenger = Self::challenger();
        let witness = SuffixProver::<F, F>::new_witness(p3_tables, 0);
        let (cap, data) = backend
            .commit(witness, &mut challenger)
            .map_err(|error| ProofError::Pcs(error.to_string()))?;
        let proof = backend
            .open_at(data, &protocol, &p3_points, &mut challenger)
            .map_err(|error| ProofError::Pcs(error.to_string()))?;
        Ok(P3MosaicOpening {
            commitment: P3MosaicCommitment {
                cap,
                tables: shapes,
                stacked_variables,
            },
            proof,
        })
    }

    /// Verify a mosaic opening against the values expected at each point.
    pub fn verify_mosaic(
        &self,
        opening: &P3MosaicOpening,
        points: &[P3MosaicPoint],
        values: &[Vec<F2_128>],
    ) -> Result<bool, ProofError> {
        if points.len() != values.len() {
            return Ok(false);
        }
        let commitment = &opening.commitment;
        let expected_stacked = match Self::mosaic_stacked_variables(&commitment.tables) {
            Ok(stacked) => stacked,
            Err(_) => return Ok(false),
        };
        if commitment.stacked_variables != expected_stacked {
            return Ok(false);
        }
        let (protocol, p3_points) = match Self::mosaic_schedule(&commitment.tables, points) {
            Ok(schedule) => schedule,
            Err(_) => return Ok(false),
        };
        let backend = Self::backend(commitment.stacked_variables, self.security_level)?;
        let mut challenger = Self::challenger();
        backend.observe_commitment(&commitment.cap, &mut challenger);
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
            let current_len = point.columns.len();
            let next_len = point.next_columns.len();
            if expected.len() != current_len + next_len
                || batch.current().len() != current_len
                || batch.next().len() != next_len
                || batch
                    .current()
                    .iter()
                    .chain(batch.next())
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

/// A PCS adapter that commits a primary vector together with auxiliary tables
/// and opens all of them in one P3 proof.
///
/// The primary vector is mosaic table 0 and opens at the single point of the
/// `Pcs` interface. Auxiliary points must name their absolute table indices
/// (`1..`); their expected values are supplied by the verifier.
#[derive(Clone, Debug)]
pub struct P3SharedPcs {
    pub security_level: usize,
    pub aux_tables: Vec<P3MosaicTable>,
    pub aux_points: Vec<P3MosaicPoint>,
    pub aux_values: Vec<Vec<F2_128>>,
}

impl P3SharedPcs {
    pub fn new(
        security_level: usize,
        aux_tables: Vec<P3MosaicTable>,
        aux_points: Vec<P3MosaicPoint>,
        aux_values: Vec<Vec<F2_128>>,
    ) -> Self {
        Self {
            security_level,
            aux_tables,
            aux_points,
            aux_values,
        }
    }

    fn tables(&self, values: &[F2_128]) -> Vec<P3MosaicTable> {
        let mut tables = Vec::with_capacity(1 + self.aux_tables.len());
        tables.push(P3MosaicTable {
            columns: vec![values.to_vec()],
        });
        tables.extend(self.aux_tables.clone());
        tables
    }

    fn points(&self, point: &[F2_128]) -> Vec<P3MosaicPoint> {
        let mut points = Vec::with_capacity(1 + self.aux_points.len());
        points.push(P3MosaicPoint {
            table: 0,
            point: point.to_vec(),
            columns: vec![0],
            next_columns: Vec::new(),
        });
        points.extend(self.aux_points.clone());
        points
    }
}

impl Pcs for P3SharedPcs {
    type Commitment = P3MosaicCommitment;
    type Opening = P3MosaicOpening;

    fn commit(&self, values: &[F2_128]) -> Result<Self::Commitment, ProofError> {
        P3BinaryPcs::new(self.security_level).commit_mosaic(&self.tables(values))
    }

    fn open(&self, values: &[F2_128], point: &[F2_128]) -> Result<Self::Opening, ProofError> {
        P3BinaryPcs::new(self.security_level).open_mosaic(&self.tables(values), &self.points(point))
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &[F2_128],
        value: F2_128,
        opening: &Self::Opening,
    ) -> Result<bool, ProofError> {
        if opening.commitment != *commitment {
            return Ok(false);
        }
        let mut values = Vec::with_capacity(1 + self.aux_values.len());
        values.push(vec![value]);
        values.extend(self.aux_values.clone());
        P3BinaryPcs::new(self.security_level).verify_mosaic(opening, &self.points(point), &values)
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

    #[test]
    fn p3_mosaic_stacks_different_arities_into_one_opening() {
        let pcs = P3BinaryPcs::new(100);
        let primary = values(1 << 9);
        let aux = vec![values(1 << 10), values(1 << 10)];
        let tables = vec![
            P3MosaicTable {
                columns: vec![primary.clone()],
            },
            P3MosaicTable {
                columns: aux.clone(),
            },
        ];
        let commitment = pcs.commit_mosaic(&tables).unwrap();
        assert_eq!(commitment.tables.len(), 2);
        assert_eq!(commitment.tables[0].num_variables, 9);
        assert_eq!(commitment.tables[1].num_variables, 10);

        let primary_point = (0..9u64)
            .map(|index| F2_128::from(index & 1))
            .collect::<Vec<_>>();
        let aux_point = (0..10u64)
            .map(|index| F2_128::from((index + 1) & 1))
            .collect::<Vec<_>>();
        let points = vec![
            P3MosaicPoint {
                table: 0,
                point: primary_point.clone(),
                columns: vec![0],
                next_columns: Vec::new(),
            },
            P3MosaicPoint {
                table: 1,
                point: aux_point.clone(),
                columns: vec![0, 1],
                next_columns: Vec::new(),
            },
        ];
        let opening = pcs.open_mosaic(&tables, &points).unwrap();
        let expected = vec![
            vec![magnetar_proof::Mle::new(primary.clone())
                .unwrap()
                .eval(&primary_point)
                .unwrap()],
            aux.iter()
                .map(|column| {
                    magnetar_proof::Mle::new(column.clone())
                        .unwrap()
                        .eval(&aux_point)
                        .unwrap()
                })
                .collect(),
        ];
        assert!(pcs.verify_mosaic(&opening, &points, &expected).unwrap());

        let mut bad = expected.clone();
        bad[1][1] = bad[1][1] + F2_128::from(1u64);
        assert!(!pcs.verify_mosaic(&opening, &points, &bad).unwrap());
    }

    #[test]
    fn p3_mosaic_successor_view_matches_shifted_mle() {
        let pcs = P3BinaryPcs::new(100);
        let values = values(1 << 8);
        let table = P3MosaicTable {
            columns: vec![values.clone()],
        };
        let point: Vec<F2_128> = (0..8u64)
            .map(|index| F2_128::from((index * 7 + 3) & 1))
            .collect();
        let current = magnetar_proof::Mle::new(values.clone())
            .unwrap()
            .eval(&point)
            .unwrap();
        let mut shifted = values[1..].to_vec();
        shifted.push(*values.last().unwrap());
        let next = magnetar_proof::Mle::new(shifted)
            .unwrap()
            .eval(&point)
            .unwrap();
        let points = vec![P3MosaicPoint {
            table: 0,
            point: point.clone(),
            columns: vec![0],
            next_columns: vec![0],
        }];
        let opening = pcs
            .open_mosaic(core::slice::from_ref(&table), &points)
            .unwrap();
        assert!(pcs
            .verify_mosaic(&opening, &points, &[vec![current, next]])
            .unwrap());
    }

    #[test]
    fn p3_shared_pcs_batches_primary_and_auxiliary_claims() {
        let primary = values(1 << 9);
        let aux = values(1 << 10);
        let primary_point: Vec<F2_128> = (0..9u64).map(|index| F2_128::from(index & 1)).collect();
        let aux_point: Vec<F2_128> = (0..10u64)
            .map(|index| F2_128::from((index + 1) & 1))
            .collect();
        let aux_value = magnetar_proof::Mle::new(aux.clone())
            .unwrap()
            .eval(&aux_point)
            .unwrap();
        let pcs = P3SharedPcs::new(
            100,
            vec![P3MosaicTable {
                columns: vec![aux.clone()],
            }],
            vec![P3MosaicPoint {
                table: 1,
                point: aux_point.clone(),
                columns: vec![0],
                next_columns: Vec::new(),
            }],
            vec![vec![aux_value]],
        );
        let primary_value = magnetar_proof::Mle::new(primary.clone())
            .unwrap()
            .eval(&primary_point)
            .unwrap();
        let commitment = pcs.commit(&primary).unwrap();
        let opening = pcs.open(&primary, &primary_point).unwrap();
        assert!(pcs
            .verify(&commitment, &primary_point, primary_value, &opening)
            .unwrap());
        assert!(!pcs
            .verify(
                &commitment,
                &primary_point,
                primary_value + F2_128::from(1u64),
                &opening,
            )
            .unwrap());
    }
    #[test]
    fn shared_commitment_matches_mosaic_commitment() {
        let z = values(8);
        let aux = vec![P3MosaicTable {
            columns: vec![values(4), values(4)],
        }];
        let shared = P3SharedPcs::new(90, aux.clone(), Vec::new(), Vec::new());
        let shared_commitment = shared.commit(&z).unwrap();
        let mut tables = vec![P3MosaicTable { columns: vec![z] }];
        tables.extend(aux);
        let mosaic_commitment = P3BinaryPcs::new(90).commit_mosaic(&tables).unwrap();
        assert_eq!(
            bincode::serialize(&shared_commitment).unwrap(),
            bincode::serialize(&mosaic_commitment).unwrap()
        );
    }
}
