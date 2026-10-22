//! Reference MosaicPCS packing and lift.
//!
//! Components are placed on disjoint aligned subcubes of one packed
//! polynomial `G`. A claim on component `i` at point `r` lifts to a claim on
//! `G` at `r || suffix_i` without an adapter sum-check. Batching and ring
//! switching are not yet implemented.

use crate::p3_pcs::{P3BinaryPcs, P3Commitment, P3MosaicPoint, P3MosaicTable, P3Opening};
use magnetar_constraint::F2_128;
use magnetar_proof::{eq, prove, verify_rounds, Mle, Pcs, ProofError, SumcheckProof};
use magnetar_transcript::Sha256Transcript;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct MosaicComponent {
    pub size_bits: usize,
    pub offset: usize,
    pub suffix: Vec<F2_128>,
}

#[derive(Clone, Debug)]
pub struct PackedMosaic {
    pub total_bits: usize,
    pub components: Vec<MosaicComponent>,
    pub values: Vec<F2_128>,
}

/// Stable binding of the committed table columns, independent of the PCS
/// commitment format. Claim transcripts can absorb this instead of a
/// `P3MosaicCommitment` so the same claim can be verified by a packed PCS.
pub fn table_binding(tables: &[P3MosaicTable]) -> [u8; 32] {
    let mut bytes = Vec::new();
    for table in tables {
        bytes.extend_from_slice(&(table.columns.len() as u64).to_le_bytes());
        for column in &table.columns {
            bytes.extend_from_slice(&(column.len() as u64).to_le_bytes());
            for value in column {
                bytes.extend_from_slice(&value.value().to_le_bytes());
            }
        }
    }
    magnetar_transcript::sha256(&bytes)
}

#[derive(Debug, Error)]
pub enum MosaicError {
    #[error("mosaic needs at least one component")]
    Empty,
    #[error("component size must be a nonzero power of two, got {0}")]
    InvalidSize(usize),
    #[error("component sizes overflow the packed table")]
    Overflow,
    #[error("component index {0} is out of range")]
    Index(usize),
    #[error(transparent)]
    Proof(#[from] ProofError),
    #[error("batching needs at least one claim")]
    EmptyBatch,
    #[error("batching claim point has the wrong arity")]
    PointArity,
    #[error("batched sumcheck failed")]
    BatchSumcheck,
    #[error("aux claim shapes disagree")]
    AuxShape,
    #[error("successor columns are not supported by the packed adapter")]
    SuccessorColumns,
}

impl PackedMosaic {
    pub fn layout(sizes: &[usize]) -> Result<(usize, Vec<MosaicComponent>), MosaicError> {
        if sizes.is_empty() {
            return Err(MosaicError::Empty);
        }
        for size in sizes {
            if *size == 0 || !size.is_power_of_two() {
                return Err(MosaicError::InvalidSize(*size));
            }
        }
        let total_size = sizes
            .iter()
            .try_fold(0usize, |sum, size| sum.checked_add(*size))
            .ok_or(MosaicError::Overflow)?;
        let total_bits = total_size.next_power_of_two().trailing_zeros() as usize;
        let total = 1usize << total_bits;
        let mut layout = Vec::with_capacity(sizes.len());
        let mut offset = 0usize;
        for size in sizes {
            let size_bits = size.trailing_zeros() as usize;
            let aligned = (offset + size - 1) & !(size - 1);
            if aligned + size > total {
                return Err(MosaicError::Overflow);
            }
            let suffix_bits = total_bits - size_bits;
            let suffix_value = aligned >> size_bits;
            let suffix = (0..suffix_bits)
                .map(|bit| F2_128::from(((suffix_value >> bit) & 1) as u64))
                .collect();
            layout.push(MosaicComponent {
                size_bits,
                offset: aligned,
                suffix,
            });
            offset = aligned + size;
        }
        Ok((total_bits, layout))
    }

    pub fn new(components: &[Vec<F2_128>]) -> Result<Self, MosaicError> {
        let sizes = components.iter().map(Vec::len).collect::<Vec<_>>();
        let (total_bits, layout) = Self::layout(&sizes)?;
        let mut values = vec![F2_128::from(0u64); 1usize << total_bits];
        for (component, slot) in components.iter().zip(&layout) {
            values[slot.offset..slot.offset + component.len()].copy_from_slice(component);
        }
        Ok(Self {
            total_bits,
            components: layout,
            values,
        })
    }

    /// Lift a component point to a point on the packed polynomial.
    pub fn lift(&self, index: usize, point: &[F2_128]) -> Result<Vec<F2_128>, MosaicError> {
        let component = self
            .components
            .get(index)
            .ok_or(MosaicError::Index(index))?;
        if point.len() != component.size_bits {
            return Err(MosaicError::Index(index));
        }
        let mut lifted = point.to_vec();
        lifted.extend_from_slice(&component.suffix);
        Ok(lifted)
    }

    pub fn eval_component(&self, index: usize, point: &[F2_128]) -> Result<F2_128, MosaicError> {
        let component = self
            .components
            .get(index)
            .ok_or(MosaicError::Index(index))?;
        let values =
            &self.values[component.offset..component.offset + (1usize << component.size_bits)];
        Ok(Mle::new(values.to_vec())?.eval(point)?)
    }

    pub fn eval_packed(&self, point: &[F2_128]) -> Result<F2_128, MosaicError> {
        Ok(Mle::new(self.values.clone())?.eval(point)?)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MosaicBatchingProof {
    pub sumcheck: SumcheckProof<F2_128>,
    pub point: Vec<F2_128>,
    pub value: F2_128,
}

fn challenge(transcript: &mut Sha256Transcript, label: &str) -> F2_128 {
    let bytes = transcript.challenge_32(label);
    let mut value = [0u8; 16];
    value.copy_from_slice(&bytes[..16]);
    F2_128::from_bits(u128::from_le_bytes(value))
}

fn absorb_claims(transcript: &mut Sha256Transcript, claims: &[(Vec<F2_128>, F2_128)]) {
    transcript.absorb("claims", &(claims.len() as u64).to_le_bytes());
    for (point, value) in claims {
        transcript.absorb("arity", &(point.len() as u64).to_le_bytes());
        for coordinate in point {
            transcript.absorb("point", &coordinate.value().to_le_bytes());
        }
        transcript.absorb("value", &value.value().to_le_bytes());
    }
}

/// Batch several claims `G(r_i) = v_i` into one claim `G(r) = v`.
///
/// Prover side. The verifier samples the batching coefficients and replays the
/// sum-check; the output is a single evaluation claim for the PCS.
pub fn batch_claims(
    values: &[F2_128],
    claims: &[(Vec<F2_128>, F2_128)],
    transcript: &mut Sha256Transcript,
) -> Result<MosaicBatchingProof, MosaicError> {
    if claims.is_empty() {
        return Err(MosaicError::EmptyBatch);
    }
    let total_bits = values.len().trailing_zeros() as usize;
    if values.len() != 1usize << total_bits {
        return Err(MosaicError::InvalidSize(values.len()));
    }
    absorb_claims(transcript, claims);
    let alphas = (0..claims.len())
        .map(|_| challenge(transcript, "batch"))
        .collect::<Vec<_>>();
    let mle = Mle::new(values.to_vec())?;
    let poly = |point: &[F2_128]| {
        let weight = claims
            .iter()
            .zip(&alphas)
            .fold(F2_128::from(0u64), |sum, ((claim_point, _), alpha)| {
                sum + *alpha * eq(claim_point, point)
            });
        weight * mle.eval(point).unwrap_or(F2_128::from(0u64))
    };
    let (sumcheck, point, _) = prove(poly, total_bits, 2, |round, values| {
        for coefficient in values {
            transcript.absorb("round", &coefficient.value().to_le_bytes());
        }
        transcript.absorb("round", &(round as u64).to_le_bytes());
        challenge(transcript, "sumcheck")
    })?;
    let value = mle.eval(&point)?;
    Ok(MosaicBatchingProof {
        sumcheck,
        point,
        value,
    })
}

pub fn verify_batching(
    proof: &MosaicBatchingProof,
    claims: &[(Vec<F2_128>, F2_128)],
    total_bits: usize,
    transcript: &mut Sha256Transcript,
) -> Result<(), MosaicError> {
    if claims.is_empty() {
        return Err(MosaicError::EmptyBatch);
    }
    absorb_claims(transcript, claims);
    let alphas = (0..claims.len())
        .map(|_| challenge(transcript, "batch"))
        .collect::<Vec<_>>();
    let expected = claims
        .iter()
        .zip(&alphas)
        .fold(F2_128::from(0u64), |sum, ((_, value), alpha)| {
            sum + *alpha * *value
        });
    if proof.sumcheck.claimed_sum != expected {
        return Err(MosaicError::BatchSumcheck);
    }
    let (point, current) = verify_rounds(&proof.sumcheck, total_bits, 2, |round, values| {
        for coefficient in values {
            transcript.absorb("round", &coefficient.value().to_le_bytes());
        }
        transcript.absorb("round", &(round as u64).to_le_bytes());
        challenge(transcript, "sumcheck")
    })?;
    if point != proof.point {
        return Err(MosaicError::BatchSumcheck);
    }
    let weight = claims
        .iter()
        .zip(&alphas)
        .fold(F2_128::from(0u64), |sum, ((claim_point, _), alpha)| {
            sum + *alpha * eq(claim_point, &point)
        });
    if current != weight * proof.value {
        return Err(MosaicError::BatchSumcheck);
    }
    Ok(())
}

impl PackedMosaic {
    /// Commit the packed polynomial as one field-element vector.
    ///
    /// This reference layer commits one field element per bit. It still gives
    /// the single-commitment/single-evaluation structure of MosaicPCS; the
    /// paper's 128-bits-per-element packing and ring switching are separate.
    pub fn commit(&self, pcs: &P3BinaryPcs) -> Result<P3Commitment, MosaicError> {
        Ok(pcs.commit(&self.values)?)
    }

    pub fn open(&self, pcs: &P3BinaryPcs, point: &[F2_128]) -> Result<P3Opening, MosaicError> {
        Ok(pcs.open(&self.values, point)?)
    }

    pub fn verify(
        &self,
        pcs: &P3BinaryPcs,
        commitment: &P3Commitment,
        point: &[F2_128],
        value: F2_128,
        opening: &P3Opening,
    ) -> Result<bool, MosaicError> {
        Ok(pcs.verify(commitment, point, value, opening)?)
    }
}

/// Convert a multi-column mosaic opening claim into one claim per column.
///
/// Each column becomes a single-column component at the same point; this is
/// the representation expected by `PackedSharedPcs`.
pub fn flatten_table_claims(
    mosaic: &PackedMosaic,
    columns: usize,
    point: &[F2_128],
    values: &[F2_128],
) -> Result<Vec<(Vec<F2_128>, F2_128)>, MosaicError> {
    if columns != values.len() || columns > mosaic.components.len() {
        return Err(MosaicError::AuxShape);
    }
    (0..columns)
        .map(|index| Ok((mosaic.lift(index, point)?, values[index])))
        .collect()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackedOpening {
    pub batch: MosaicBatchingProof,
    pub pcs: P3Opening,
}

/// PCS adapter: one primary vector plus single-column aux components are
/// packed into one `G`, batched to one point, and opened with one P3 proof.
#[derive(Clone, Debug)]
pub struct PackedSharedPcs {
    pub security_level: usize,
    pub aux_tables: Vec<Vec<F2_128>>,
    pub aux_points: Vec<Vec<F2_128>>,
    pub aux_values: Vec<F2_128>,
}

impl PackedSharedPcs {
    pub fn new(
        security_level: usize,
        aux_tables: Vec<Vec<F2_128>>,
        aux_points: Vec<Vec<F2_128>>,
        aux_values: Vec<F2_128>,
    ) -> Result<Self, MosaicError> {
        if aux_tables.len() != aux_points.len() || aux_tables.len() != aux_values.len() {
            return Err(MosaicError::AuxShape);
        }
        Ok(Self {
            security_level,
            aux_tables,
            aux_points,
            aux_values,
        })
    }

    /// Build the adapter from existing multi-column mosaic points/values.
    ///
    /// Each selected column becomes a single-column component. Successor
    /// columns are not supported yet.
    pub fn from_mosaic(
        security_level: usize,
        tables: Vec<P3MosaicTable>,
        points: Vec<P3MosaicPoint>,
        values: Vec<Vec<F2_128>>,
    ) -> Result<Self, MosaicError> {
        if points.len() != values.len() {
            return Err(MosaicError::AuxShape);
        }
        let mut aux_tables = Vec::new();
        let mut aux_points = Vec::new();
        let mut aux_values = Vec::new();
        for (point, expected) in points.iter().zip(&values) {
            if !point.next_columns.is_empty() || point.columns.len() != expected.len() {
                return Err(MosaicError::AuxShape);
            }
            let table = tables.get(point.table).ok_or(MosaicError::AuxShape)?;
            for (column, value) in point.columns.iter().zip(expected) {
                aux_tables.push(
                    table
                        .columns
                        .get(*column)
                        .cloned()
                        .ok_or(MosaicError::AuxShape)?,
                );
                aux_points.push(point.point.clone());
                aux_values.push(*value);
            }
        }
        Self::new(security_level, aux_tables, aux_points, aux_values)
    }

    fn mosaic(&self, primary: &[F2_128]) -> Result<PackedMosaic, MosaicError> {
        let mut components = Vec::with_capacity(1 + self.aux_tables.len());
        components.push(primary.to_vec());
        components.extend(self.aux_tables.iter().cloned());
        PackedMosaic::new(&components)
    }

    fn claims(
        &self,
        mosaic: &PackedMosaic,
        primary_point: &[F2_128],
        primary_value: F2_128,
    ) -> Result<Vec<(Vec<F2_128>, F2_128)>, MosaicError> {
        let mut claims = Vec::with_capacity(1 + self.aux_points.len());
        claims.push((mosaic.lift(0, primary_point)?, primary_value));
        for (index, point) in self.aux_points.iter().enumerate() {
            claims.push((mosaic.lift(index + 1, point)?, self.aux_values[index]));
        }
        Ok(claims)
    }
}

impl Pcs for PackedSharedPcs {
    type Commitment = P3Commitment;
    type Opening = PackedOpening;

    fn commit(&self, values: &[F2_128]) -> Result<Self::Commitment, ProofError> {
        let mosaic = self
            .mosaic(values)
            .map_err(|error| ProofError::Pcs(error.to_string()))?;
        P3BinaryPcs::new(self.security_level).commit(&mosaic.values)
    }

    fn open(&self, values: &[F2_128], point: &[F2_128]) -> Result<Self::Opening, ProofError> {
        let mosaic = self
            .mosaic(values)
            .map_err(|error| ProofError::Pcs(error.to_string()))?;
        let primary_value = Mle::new(values.to_vec())?
            .eval(point)
            .map_err(|error| ProofError::Pcs(error.to_string()))?;
        let claims = self
            .claims(&mosaic, point, primary_value)
            .map_err(|error| ProofError::Pcs(error.to_string()))?;
        let pcs = P3BinaryPcs::new(self.security_level);
        let commitment = pcs.commit(&mosaic.values)?;
        let mut transcript = Sha256Transcript::new("packed-shared-pcs");
        transcript.absorb(
            "commitment",
            &bincode::serialize(&commitment).unwrap_or_default(),
        );
        let batch = batch_claims(&mosaic.values, &claims, &mut transcript)
            .map_err(|error| ProofError::Pcs(error.to_string()))?;
        let pcs_opening = pcs.open(&mosaic.values, &batch.point)?;
        Ok(PackedOpening {
            batch,
            pcs: pcs_opening,
        })
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &[F2_128],
        value: F2_128,
        opening: &Self::Opening,
    ) -> Result<bool, ProofError> {
        let mut sizes = Vec::with_capacity(1 + self.aux_tables.len());
        sizes.push(1usize << point.len());
        sizes.extend(self.aux_tables.iter().map(Vec::len));
        let (total_bits, components) =
            PackedMosaic::layout(&sizes).map_err(|error| ProofError::Pcs(error.to_string()))?;
        let mosaic = PackedMosaic {
            total_bits,
            components,
            values: Vec::new(),
        };
        let claims = self
            .claims(&mosaic, point, value)
            .map_err(|error| ProofError::Pcs(error.to_string()))?;
        let mut transcript = Sha256Transcript::new("packed-shared-pcs");
        transcript.absorb(
            "commitment",
            &bincode::serialize(commitment).unwrap_or_default(),
        );
        verify_batching(&opening.batch, &claims, total_bits, &mut transcript)
            .map_err(|error| ProofError::Pcs(error.to_string()))?;
        P3BinaryPcs::new(self.security_level).verify(
            commitment,
            &opening.batch.point,
            opening.batch.value,
            &opening.pcs,
        )
    }

    fn commitment_bytes(&self, commitment: &Self::Commitment) -> Vec<u8> {
        bincode::serialize(commitment).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_constraint::{ConstraintSystem, Expr, Witness};
    use magnetar_proof::{prove_spartan, verify_spartan};

    fn values(size: usize, seed: u64) -> Vec<F2_128> {
        (0..size)
            .map(|index| F2_128::from(index as u64 * 17 + seed))
            .collect()
    }

    #[test]
    fn packed_components_lift_without_adapter() {
        let components = vec![values(2, 1), values(4, 2), values(8, 3)];
        let mosaic = PackedMosaic::new(&components).unwrap();
        let points = [
            vec![F2_128::from(5u64)],
            vec![F2_128::from(7u64), F2_128::from(11u64)],
            vec![
                F2_128::from(13u64),
                F2_128::from(17u64),
                F2_128::from(19u64),
            ],
        ];
        for (index, point) in points.iter().enumerate() {
            let lifted = mosaic.lift(index, point).unwrap();
            assert_eq!(
                mosaic.eval_component(index, point).unwrap(),
                mosaic.eval_packed(&lifted).unwrap()
            );
        }
    }

    #[test]
    fn packing_rejects_invalid_shapes() {
        assert!(PackedMosaic::new(&[]).is_err());
        assert!(PackedMosaic::new(&[vec![F2_128::from(1u64); 3]]).is_err());
    }
    #[test]
    fn batching_reduces_claims_to_one_point() {
        let components = vec![values(2, 1), values(4, 2), values(8, 3)];
        let mosaic = PackedMosaic::new(&components).unwrap();
        let point0 = mosaic.lift(0, &[F2_128::from(5u64)]).unwrap();
        let point1 = mosaic
            .lift(1, &[F2_128::from(7u64), F2_128::from(11u64)])
            .unwrap();
        let claims = vec![
            (point0.clone(), mosaic.eval_packed(&point0).unwrap()),
            (point1.clone(), mosaic.eval_packed(&point1).unwrap()),
        ];
        let mut prover_transcript = Sha256Transcript::new("mosaic-batch-test");
        let proof = batch_claims(&mosaic.values, &claims, &mut prover_transcript).unwrap();
        let mut verifier_transcript = Sha256Transcript::new("mosaic-batch-test");
        verify_batching(&proof, &claims, mosaic.total_bits, &mut verifier_transcript).unwrap();
        assert_eq!(proof.value, mosaic.eval_packed(&proof.point).unwrap());
    }
    #[test]
    fn packed_mosaic_commits_and_opens_once() {
        let components = vec![values(2, 1), values(4, 2), values(8, 3)];
        let mosaic = PackedMosaic::new(&components).unwrap();
        let pcs = P3BinaryPcs::new(100);
        let commitment = mosaic.commit(&pcs).unwrap();
        let point = vec![
            F2_128::from(3u64),
            F2_128::from(5u64),
            F2_128::from(7u64),
            F2_128::from(11u64),
        ];
        let value = mosaic.eval_packed(&point).unwrap();
        let opening = mosaic.open(&pcs, &point).unwrap();
        assert!(mosaic
            .verify(&pcs, &commitment, &point, value, &opening)
            .unwrap());
        assert!(!mosaic
            .verify(
                &pcs,
                &commitment,
                &point,
                value + F2_128::from(1u64),
                &opening,
            )
            .unwrap());
    }
    #[test]
    fn packed_shared_pcs_batches_primary_and_aux() {
        let primary = values(8, 11);
        let aux_tables = vec![vec![F2_128::from(42u64); 2], vec![F2_128::from(99u64); 4]];
        let aux_values = vec![F2_128::from(42u64), F2_128::from(99u64)];
        let aux_points = vec![
            vec![F2_128::from(3u64)],
            vec![F2_128::from(5u64), F2_128::from(7u64)],
        ];
        let adapter = PackedSharedPcs::new(100, aux_tables, aux_points, aux_values).unwrap();
        let point = vec![
            F2_128::from(13u64),
            F2_128::from(17u64),
            F2_128::from(19u64),
        ];
        let value = Mle::new(primary.clone()).unwrap().eval(&point).unwrap();
        let commitment = adapter.commit(&primary).unwrap();
        let opening = adapter.open(&primary, &point).unwrap();
        assert!(adapter
            .verify(&commitment, &point, value, &opening)
            .unwrap());
        assert!(!adapter
            .verify(&commitment, &point, value + F2_128::from(1u64), &opening,)
            .unwrap_or(false));
    }
    #[test]
    fn multi_column_claims_flatten_to_packed_components() {
        let columns = vec![values(4, 21), values(4, 22)];
        let point = vec![F2_128::from(5u64), F2_128::from(9u64)];
        let claim_values = columns
            .iter()
            .map(|column| Mle::new(column.clone()).unwrap().eval(&point).unwrap())
            .collect::<Vec<_>>();
        let mosaic = PackedMosaic::new(&columns).unwrap();
        let claims = flatten_table_claims(&mosaic, 2, &point, &claim_values).unwrap();
        assert_eq!(claims.len(), 2);
        let mut transcript = Sha256Transcript::new("flatten-table-test");
        let proof = batch_claims(&mosaic.values, &claims, &mut transcript).unwrap();
        let mut verifier = Sha256Transcript::new("flatten-table-test");
        verify_batching(&proof, &claims, mosaic.total_bits, &mut verifier).unwrap();
        assert_eq!(proof.value, mosaic.eval_packed(&proof.point).unwrap());
    }
    #[test]
    fn packed_shared_pcs_drives_spartan() {
        let mut system = ConstraintSystem::new(3);
        system.add_constraint(
            Expr::var(0).add(Expr::var(1)),
            Expr::constant(1u64),
            Expr::var(2),
        );
        let witness = Witness::new(vec![
            F2_128::from(1u64),
            F2_128::from(2u64),
            F2_128::from(3u64),
        ]);
        let aux_value = F2_128::from(77u64);
        let aux_point = vec![F2_128::from(5u64), F2_128::from(9u64)];
        let adapter = PackedSharedPcs::new(
            100,
            vec![vec![aux_value; 4]],
            vec![aux_point],
            vec![aux_value],
        )
        .unwrap();
        let proof = prove_spartan(&system, &witness, &adapter).unwrap();
        verify_spartan(&system, &proof, &adapter).unwrap();
    }
    #[test]
    fn packed_adapter_accepts_mosaic_columns() {
        let primary = values(4, 31);
        let table = P3MosaicTable {
            columns: vec![values(4, 32), values(4, 33)],
        };
        let point = P3MosaicPoint {
            table: 0,
            point: vec![F2_128::from(5u64), F2_128::from(9u64)],
            columns: vec![0, 1],
            next_columns: Vec::new(),
        };
        let expected = table
            .columns
            .iter()
            .map(|column| {
                Mle::new(column.clone())
                    .unwrap()
                    .eval(&point.point)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let adapter =
            PackedSharedPcs::from_mosaic(100, vec![table], vec![point.clone()], vec![expected])
                .unwrap();
        let value = Mle::new(primary.clone())
            .unwrap()
            .eval(&point.point)
            .unwrap();
        let commitment = adapter.commit(&primary).unwrap();
        let opening = adapter.open(&primary, &point.point).unwrap();
        assert!(adapter
            .verify(&commitment, &point.point, value, &opening)
            .unwrap());
    }
    #[test]
    fn table_binding_is_stable_and_content_addressed() {
        let table = P3MosaicTable {
            columns: vec![values(4, 7), values(4, 9)],
        };
        let first = table_binding(std::slice::from_ref(&table));
        let second = table_binding(std::slice::from_ref(&table));
        assert_eq!(first, second);

        let mut changed = table.clone();
        changed.columns[0][0] = changed.columns[0][0] + F2_128::from(1u64);
        assert_ne!(first, table_binding(&[changed]));
    }
}
