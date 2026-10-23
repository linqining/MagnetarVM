//! Packed BinaryShout final evaluations with leaf batching.
//!
//! The Shout sum-checks still use the bit-sliced witness. The address/valid
//! columns are packed into one 128-bit table, and the verifier checks the
//! address product from the folded leaves. A random row-batch challenge binds
//! the leaves to the packed table with one ring-switch opening:
//!
//!   Σ_col eq(r_col, col) · leaf_col = MLE(packed_table)(r_col, r_j)

use magnetar_constraint::F2_128;
use magnetar_pcs::{P3BinaryPcs, P3MosaicCommitment, P3MosaicOpening, P3SharedPcs};
use magnetar_proof::{BitPcs, RingSwitchOpening, RingSwitchPackedBitPcs};
use magnetar_transcript::Sha256Transcript;

use crate::binary_shout::{
    prove_binary_shout_claims, verify_binary_shout_claims, BinaryShoutProof, BinaryShoutWitness,
};
use crate::RuntimeError;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PackedShoutProof {
    pub claims: BinaryShoutProof,
    pub table_commitment: P3MosaicCommitment,
    pub leaves: Vec<F2_128>,
    pub packed_commitment: P3MosaicCommitment,
    pub packed_point: Vec<F2_128>,
    pub packed_value: F2_128,
    pub packed_opening: RingSwitchOpening<P3MosaicOpening>,
}

fn pad_bits(mut bits: Vec<bool>) -> Vec<bool> {
    bits.resize(bits.len().next_power_of_two().max(256), false);
    bits
}

fn table_bits(witness: &BinaryShoutWitness) -> (Vec<bool>, usize, usize) {
    let table = witness.table();
    let col_bits = table.columns.len().next_power_of_two().trailing_zeros() as usize;
    let mut bits = vec![false; (1usize << col_bits) * witness.cycles];
    for (column, values) in table.columns.iter().enumerate() {
        for (cycle, value) in values.iter().enumerate() {
            bits[cycle * (1usize << col_bits) + column] = value.value() == 1;
        }
    }
    (pad_bits(bits), col_bits, witness.cycle_bits)
}

fn eq_at(point: &[F2_128], index: usize) -> F2_128 {
    point
        .iter()
        .enumerate()
        .fold(F2_128::from(1u64), |acc, (bit, r)| {
            if (index >> bit) & 1 == 1 {
                acc * *r
            } else {
                acc * (F2_128::from(1u64) + *r)
            }
        })
}

fn challenge_field(transcript: &mut Sha256Transcript, label: &str) -> F2_128 {
    let bytes = transcript.challenge_bytes(label, 16);
    F2_128::from_bits(u128::from_le_bytes(bytes.try_into().expect("16 bytes")))
}

fn column_challenge(
    table: &P3MosaicCommitment,
    packed: &P3MosaicCommitment,
    leaves: &[F2_128],
    col_bits: usize,
) -> Vec<F2_128> {
    let mut transcript = Sha256Transcript::new("magnetar-packed-shout-columns");
    transcript.absorb("table", &bincode::serialize(table).unwrap_or_default());
    transcript.absorb("packed", &bincode::serialize(packed).unwrap_or_default());
    for leaf in leaves {
        transcript.absorb("leaf", &leaf.value().to_le_bytes());
    }
    (0..col_bits)
        .map(|_| challenge_field(&mut transcript, "col"))
        .collect()
}

pub fn prove_packed_shout(witness: &BinaryShoutWitness) -> Result<PackedShoutProof, RuntimeError> {
    witness
        .validate()
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let table = witness.table();
    let bit_commitment = P3BinaryPcs::new(100)
        .commit_mosaic(core::slice::from_ref(&table))
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let (packed_bits, col_bits, cycle_bits) = table_bits(witness);
    let backend =
        RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
    let packed_commitment = backend
        .commit(&packed_bits)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let mut binding = bincode::serialize(&bit_commitment).unwrap_or_default();
    binding.extend_from_slice(&bincode::serialize(&packed_commitment).unwrap_or_default());
    let binding = magnetar_transcript::sha256(&binding);
    let (claims, points, values) = prove_binary_shout_claims(witness, &bit_commitment, 0, &binding)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let leaves = values[1].clone();
    let r_col = column_challenge(&bit_commitment, &packed_commitment, &leaves, col_bits);
    let point = [r_col.clone(), points[1].point.clone()].concat();
    let mut padded_point = point.clone();
    padded_point.resize(
        packed_bits.len().trailing_zeros() as usize,
        F2_128::from(0u64),
    );
    let (packed_value, packed_opening) = backend
        .open(&packed_bits, &padded_point)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let expected = leaves
        .iter()
        .enumerate()
        .fold(F2_128::from(0u64), |sum, (column, leaf)| {
            sum + eq_at(&r_col, column) * *leaf
        });
    if packed_value != expected {
        return Err(RuntimeError::Proof(format!(
            "packed Shout leaf batch disagrees: packed={packed_value:?} expected={expected:?} leaves={} col_bits={col_bits} point={} r_col={r_col:?}",
            leaves.len(),
            padded_point.len()
        )));
    }
    let _ = cycle_bits;
    Ok(PackedShoutProof {
        claims,
        table_commitment: bit_commitment,
        leaves,
        packed_commitment,
        packed_point: padded_point,
        packed_value,
        packed_opening,
    })
}

pub fn verify_packed_shout(
    witness: &BinaryShoutWitness,
    proof: &PackedShoutProof,
) -> Result<(), RuntimeError> {
    let mut binding = bincode::serialize(&proof.table_commitment).unwrap_or_default();
    binding.extend_from_slice(&bincode::serialize(&proof.packed_commitment).unwrap_or_default());
    let binding = magnetar_transcript::sha256(&binding);
    let Some((_points, values)) =
        verify_binary_shout_claims(witness, &proof.claims, &proof.table_commitment, 0, &binding)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?
    else {
        return Err(RuntimeError::Proof("packed Shout claims rejected".into()));
    };
    if proof.leaves.len() != values[1].len() || proof.leaves != values[1] {
        return Err(RuntimeError::Proof(
            "packed Shout leaves disagree with read claims".into(),
        ));
    }
    let col_bits = proof.leaves.len().next_power_of_two().trailing_zeros() as usize;
    let r_col = column_challenge(
        &proof.table_commitment,
        &proof.packed_commitment,
        &proof.leaves,
        col_bits,
    );
    let expected_batch = proof
        .leaves
        .iter()
        .enumerate()
        .fold(F2_128::from(0u64), |sum, (column, leaf)| {
            sum + eq_at(&r_col, column) * *leaf
        });
    if expected_batch != proof.packed_value {
        return Err(RuntimeError::Proof(
            "packed Shout leaf batch value mismatch".into(),
        ));
    }
    let backend =
        RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
    if !backend
        .verify(
            &proof.packed_commitment,
            &proof.packed_point,
            proof.packed_value,
            &proof.packed_opening,
        )
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
    {
        return Err(RuntimeError::Proof(
            "packed Shout table opening rejected".into(),
        ));
    }
    Ok(())
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

        let mut tampered = proof.clone();
        tampered.leaves[0] = tampered.leaves[0] + F2_128::from(1u64);
        assert!(verify_packed_shout(&witness, &tampered).is_err());

        let mut tampered = proof;
        tampered.packed_value = tampered.packed_value + F2_128::from(1u64);
        assert!(verify_packed_shout(&witness, &tampered).is_err());
    }
}
