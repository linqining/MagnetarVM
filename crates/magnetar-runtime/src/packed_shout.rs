//! Packed BinaryShout final evaluations.
//!
//! The Shout sum-checks still run over the bit-sliced witness, but the final
//! table evaluations are proved with packed column commitments and the DP24
//! ring-switch backend instead of a Mosaic bit-table opening. Packed column
//! commitments are fixed before the Shout challenges are derived, so the
//! challenges bind both the bit table commitment and the packed columns.

use magnetar_constraint::F2_128;
use magnetar_pcs::{P3BinaryPcs, P3MosaicCommitment, P3MosaicOpening, P3SharedPcs};
use magnetar_proof::{BitPcs, RingSwitchOpening, RingSwitchPackedBitPcs};

use crate::binary_shout::{
    prove_binary_shout_claims, verify_binary_shout_claims, BinaryShoutProof, BinaryShoutWitness,
};
use crate::RuntimeError;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PackedShoutColumnOpening {
    pub point: Vec<F2_128>,
    pub value: F2_128,
    pub opening: RingSwitchOpening<P3MosaicOpening>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PackedShoutProof {
    pub claims: BinaryShoutProof,
    pub table_commitment: P3MosaicCommitment,
    pub column_commitments: Vec<P3MosaicCommitment>,
    pub column_points: Vec<Vec<Vec<F2_128>>>,
    pub column_values: Vec<Vec<F2_128>>,
    pub column_openings: Vec<Vec<PackedShoutColumnOpening>>,
}

fn padded_point(point: &[F2_128], target_bits: usize) -> Vec<F2_128> {
    let mut padded = point.to_vec();
    padded.resize(target_bits, F2_128::from(0u64));
    padded
}

fn pad_bits(bits: &[F2_128]) -> Vec<bool> {
    let mut packed = bits
        .iter()
        .map(|value| value.value() == 1)
        .collect::<Vec<_>>();
    packed.resize(packed.len().next_power_of_two().max(256), false);
    packed
}

fn binding(table: &P3MosaicCommitment, columns: &[P3MosaicCommitment]) -> [u8; 32] {
    let mut bytes = bincode::serialize(table).unwrap_or_default();
    for column in columns {
        bytes.extend_from_slice(&bincode::serialize(column).unwrap_or_default());
    }
    magnetar_transcript::sha256(&bytes)
}

pub fn prove_packed_shout(witness: &BinaryShoutWitness) -> Result<PackedShoutProof, RuntimeError> {
    witness
        .validate()
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let table = witness.table();
    let pcs = P3BinaryPcs::new(100);
    let table_commitment = pcs
        .commit_mosaic(core::slice::from_ref(&table))
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let backend =
        RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
    let mut column_commitments = Vec::new();
    let mut column_bits = Vec::new();
    for column in &table.columns {
        let bits = pad_bits(column);
        column_commitments.push(
            backend
                .commit(&bits)
                .map_err(|error| RuntimeError::Proof(error.to_string()))?,
        );
        column_bits.push(bits);
    }
    let binding = binding(&table_commitment, &column_commitments);
    let (claims, points, values) =
        prove_binary_shout_claims(witness, &table_commitment, 0, &binding)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;

    let mut column_points = Vec::new();
    let mut column_values = Vec::new();
    let mut column_openings = Vec::new();
    for (point_index, point) in points.iter().enumerate() {
        let mut p_values = Vec::new();
        let mut p_openings = Vec::new();
        let mut p_points = Vec::new();
        for (column_index, _commitment) in column_commitments.iter().enumerate() {
            let target_bits = column_bits[column_index].len().trailing_zeros() as usize;
            let p = padded_point(&point.point, target_bits);
            let (value, opening) = backend
                .open(&column_bits[column_index], &p)
                .map_err(|error| RuntimeError::Proof(error.to_string()))?;
            if value != values[point_index][column_index] {
                return Err(RuntimeError::Proof(
                    "packed Shout packed value disagrees with claim".into(),
                ));
            }
            p_values.push(value);
            p_openings.push(PackedShoutColumnOpening {
                point: p.clone(),
                value,
                opening,
            });
            p_points.push(p);
        }
        column_points.push(p_points);
        column_values.push(p_values);
        column_openings.push(p_openings);
    }
    Ok(PackedShoutProof {
        claims,
        table_commitment,
        column_commitments,
        column_points,
        column_values,
        column_openings,
    })
}

pub fn verify_packed_shout(
    witness: &BinaryShoutWitness,
    proof: &PackedShoutProof,
) -> Result<(), RuntimeError> {
    let binding = binding(&proof.table_commitment, &proof.column_commitments);
    let Some((points, values)) =
        verify_binary_shout_claims(witness, &proof.claims, &proof.table_commitment, 0, &binding)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?
    else {
        return Err(RuntimeError::Proof("packed Shout claims rejected".into()));
    };
    if points.len() != proof.column_openings.len() {
        return Err(RuntimeError::Proof(
            "packed Shout point count mismatch".into(),
        ));
    }
    let backend =
        RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
    for (point_index, point) in points.iter().enumerate() {
        for (column_index, column) in point.columns.iter().enumerate() {
            let opening = &proof.column_openings[point_index][column_index];
            if padding_count(&opening.point) != 0 {
                // Points are already padded; the helper is only for shape checks.
            }
            if opening.value != values[point_index][*column] {
                return Err(RuntimeError::Proof(
                    "packed Shout value does not match claim".into(),
                ));
            }
            if opening.point.len() != proof.column_points[point_index][column_index].len() {
                return Err(RuntimeError::Proof(
                    "packed Shout point shape mismatch".into(),
                ));
            }
            if !backend
                .verify(
                    &proof.column_commitments[column_index],
                    &opening.point,
                    opening.value,
                    &opening.opening,
                )
                .map_err(|error| RuntimeError::Proof(error.to_string()))?
            {
                return Err(RuntimeError::Proof("packed Shout opening rejected".into()));
            }
        }
    }
    Ok(())
}

fn padding_count(point: &[F2_128]) -> usize {
    point.iter().filter(|value| value.value() == 0).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    #[test]
    fn packed_shout_round_trips() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 7,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(
            &program,
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 100,
            },
        )
        .unwrap();
        let witness = BinaryShoutWitness::from_trace(&trace).unwrap();
        let proof = prove_packed_shout(&witness).unwrap();
        verify_packed_shout(&witness, &proof).unwrap();
    }
}
