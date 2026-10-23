//! Minimal packed BinaryRouter group prototype.
//!
//! This isolates the `valid` group (point 5, columns 135..137) from the full
//! Router claim set. It intentionally keeps the reference claims only as a
//! source of the point/leaf values; no Router proof is replaced yet.

use magnetar_constraint::F2_128;
use magnetar_pcs::{P3BinaryPcs, P3MosaicCommitment, P3MosaicOpening, P3SharedPcs};
use magnetar_proof::{BitPcs, RingSwitchOpening, RingSwitchPackedBitPcs};

use crate::binary_router::{prove_binary_router_claims, BinaryRouterWitness};
use crate::RuntimeError;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PackedRouterGroup5Proof {
    pub commitment: P3MosaicCommitment,
    pub point: Vec<F2_128>,
    pub value: F2_128,
    pub opening: RingSwitchOpening<P3MosaicOpening>,
}

pub struct Group5Context {
    pub point: Vec<F2_128>,
    pub leaves: Vec<F2_128>,
}

fn group_bits(witness: &BinaryRouterWitness) -> Vec<bool> {
    let table = witness.table();
    let width = 2usize;
    let mut bits = vec![false; width * witness.cycles];
    for offset in 0..2 {
        for (cycle, value) in table.columns[135 + offset].iter().enumerate() {
            bits[cycle * width + offset] = value.value() == 1;
        }
    }
    bits.resize(bits.len().next_power_of_two().max(256), false);
    bits
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

fn challenge_field(t: &mut magnetar_transcript::Sha256Transcript, label: &str) -> F2_128 {
    F2_128::from_bits(u128::from_le_bytes(
        t.challenge_bytes(label, 16).try_into().expect("16"),
    ))
}

fn context(witness: &BinaryRouterWitness) -> Result<Group5Context, RuntimeError> {
    let table = witness.table();
    let commitment = P3BinaryPcs::new(100)
        .commit_mosaic(core::slice::from_ref(&table))
        .map_err(|e| RuntimeError::Proof(e.to_string()))?;
    let (_, points, values) = prove_binary_router_claims(witness, &commitment, 0)
        .map_err(|e| RuntimeError::Proof(e.to_string()))?;
    Ok(Group5Context {
        point: points[5].point.clone(),
        leaves: values[5].clone(),
    })
}

pub fn prove_group5(
    witness: &BinaryRouterWitness,
) -> Result<PackedRouterGroup5Proof, RuntimeError> {
    let context = context(witness)?;
    let bits = group_bits(witness);
    let backend =
        RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
    let commitment = backend
        .commit(&bits)
        .map_err(|e| RuntimeError::Proof(e.to_string()))?;
    let mut transcript = magnetar_transcript::Sha256Transcript::new("packed-router-group5");
    transcript.absorb(
        "commitment",
        &bincode::serialize(&commitment).unwrap_or_default(),
    );
    for leaf in &context.leaves {
        transcript.absorb("leaf", &leaf.value().to_le_bytes());
    }
    let r = challenge_field(&mut transcript, "col");
    let mut point = [vec![r], context.point.clone()].concat();
    point.resize(bits.len().trailing_zeros() as usize, F2_128::from(0u64));
    let (value, opening) = backend
        .open(&bits, &point)
        .map_err(|e| RuntimeError::Proof(e.to_string()))?;
    let expected = context
        .leaves
        .iter()
        .enumerate()
        .fold(F2_128::from(0u64), |sum, (c, leaf)| {
            sum + eq_at(&[r], c) * *leaf
        });
    if value != expected {
        return Err(RuntimeError::Proof("group5 batch mismatch".into()));
    }
    Ok(PackedRouterGroup5Proof {
        commitment,
        point,
        value,
        opening,
    })
}

pub fn verify_group5(
    witness: &BinaryRouterWitness,
    proof: &PackedRouterGroup5Proof,
) -> Result<(), RuntimeError> {
    let context = context(witness)?;
    let mut transcript = magnetar_transcript::Sha256Transcript::new("packed-router-group5");
    transcript.absorb(
        "commitment",
        &bincode::serialize(&proof.commitment).unwrap_or_default(),
    );
    for leaf in &context.leaves {
        transcript.absorb("leaf", &leaf.value().to_le_bytes());
    }
    let r = challenge_field(&mut transcript, "col");
    let expected = context
        .leaves
        .iter()
        .enumerate()
        .fold(F2_128::from(0u64), |sum, (c, leaf)| {
            sum + eq_at(&[r], c) * *leaf
        });
    if proof.value != expected {
        return Err(RuntimeError::Proof("group5 value mismatch".into()));
    }
    let backend =
        RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
    if !backend
        .verify(&proof.commitment, &proof.point, proof.value, &proof.opening)
        .map_err(|e| RuntimeError::Proof(e.to_string()))?
    {
        return Err(RuntimeError::Proof("group5 opening rejected".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary_router::RouterMode;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    #[test]
    fn group5_packed_round_trips() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Slli,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 0,
                    shamt: 2,
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
        let witness = BinaryRouterWitness::from_trace_mode(&trace, RouterMode::Shifts).unwrap();
        let proof = prove_group5(&witness).unwrap();
        verify_group5(&witness, &proof).unwrap();
    }
}
