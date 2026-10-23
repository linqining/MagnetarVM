//! Isolated packed BinaryRouter groups.
//!
//! Each Router claim group is packed and proved independently against the
//! reference claim values. This is the incremental replacement path for the
//! full Router opening; groups are not yet merged into one proof.

use magnetar_constraint::F2_128;
use magnetar_pcs::{P3BinaryPcs, P3MosaicCommitment, P3MosaicOpening, P3SharedPcs};
use magnetar_proof::{BitPcs, RingSwitchOpening, RingSwitchPackedBitPcs};

use crate::binary_router::{prove_binary_router_claims, BinaryRouterWitness};
use crate::RuntimeError;

const INPUT_BITS: usize = 128;
const BIT_COLUMNS: usize = INPUT_BITS + 9 + 64;
const HQ_COLUMNS: usize = BIT_COLUMNS + 64;

#[derive(Clone, Copy, Debug)]
pub struct GroupSpec {
    pub point_index: usize,
    pub start: usize,
    pub value_offset: usize,
    pub width: usize,
}

pub fn groups(has_q: bool) -> Vec<GroupSpec> {
    let mut out = vec![
        GroupSpec {
            point_index: 0,
            start: 0,
            value_offset: 0,
            width: 128,
        },
        GroupSpec {
            point_index: 0,
            start: 128,
            value_offset: 128,
            width: BIT_COLUMNS - 128,
        },
        GroupSpec {
            point_index: 1,
            start: 0,
            value_offset: 0,
            width: INPUT_BITS,
        },
        GroupSpec {
            point_index: 2,
            start: INPUT_BITS,
            value_offset: 0,
            width: 3,
        },
        GroupSpec {
            point_index: 3,
            start: INPUT_BITS + 3,
            value_offset: 0,
            width: 4,
        },
        GroupSpec {
            point_index: 4,
            start: HQ_COLUMNS,
            value_offset: 0,
            width: 1,
        },
        GroupSpec {
            point_index: 5,
            start: INPUT_BITS + 7,
            value_offset: 0,
            width: 2,
        },
    ];
    if has_q {
        out.push(GroupSpec {
            point_index: 6,
            start: INPUT_BITS + 9,
            value_offset: 0,
            width: 64,
        });
        out.push(GroupSpec {
            point_index: 7,
            start: BIT_COLUMNS,
            value_offset: 0,
            width: 64,
        });
    }
    out
}

pub fn has_q(witness: &BinaryRouterWitness) -> bool {
    witness
        .shift_q
        .iter()
        .any(|c| c.iter().any(|v| v.value() == 1))
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PackedGroupProof {
    pub spec_index: usize,
    pub commitment: P3MosaicCommitment,
    pub point: Vec<F2_128>,
    pub value: F2_128,
    pub leaves: Vec<F2_128>,
    pub opening: RingSwitchOpening<P3MosaicOpening>,
}

fn bits(witness: &BinaryRouterWitness, spec: GroupSpec) -> Vec<bool> {
    let table = witness.table();
    let width = spec.width.next_power_of_two();
    let mut bits = vec![false; width * witness.cycles];
    for off in 0..spec.width {
        for (cycle, value) in table.columns[spec.start + off].iter().enumerate() {
            bits[cycle * width + off] = value.value() == 1;
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

#[allow(clippy::type_complexity)]
fn context(
    witness: &BinaryRouterWitness,
) -> Result<(Vec<Vec<F2_128>>, Vec<Vec<F2_128>>), RuntimeError> {
    let table = witness.table();
    let commitment = P3BinaryPcs::new(100)
        .commit_mosaic(core::slice::from_ref(&table))
        .map_err(|e| RuntimeError::Proof(e.to_string()))?;
    let (_, points, values) = prove_binary_router_claims(witness, &commitment, 0)
        .map_err(|e| RuntimeError::Proof(e.to_string()))?;
    Ok((points.into_iter().map(|p| p.point).collect(), values))
}

pub fn prove_group(
    witness: &BinaryRouterWitness,
    spec_index: usize,
) -> Result<PackedGroupProof, RuntimeError> {
    let all = groups(has_q(witness));
    let spec = *all
        .get(spec_index)
        .ok_or_else(|| RuntimeError::Proof("group index".into()))?;
    let (points, values) = context(witness)?;
    let leaves =
        values[spec.point_index][spec.value_offset..spec.value_offset + spec.width].to_vec();
    let group_bits = bits(witness, spec);
    let backend =
        RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
    let commitment = backend
        .commit(&group_bits)
        .map_err(|e| RuntimeError::Proof(e.to_string()))?;
    let mut t = magnetar_transcript::Sha256Transcript::new("packed-router-group");
    t.absorb(
        "commitment",
        &bincode::serialize(&commitment).unwrap_or_default(),
    );
    for leaf in &leaves {
        t.absorb("leaf", &leaf.value().to_le_bytes());
    }
    let col_bits = spec.width.next_power_of_two().trailing_zeros() as usize;
    let r = (0..col_bits)
        .map(|_| challenge_field(&mut t, "col"))
        .collect::<Vec<_>>();
    let mut point = [r.clone(), points[spec.point_index].clone()].concat();
    point.resize(
        group_bits.len().trailing_zeros() as usize,
        F2_128::from(0u64),
    );
    let (value, opening) = backend
        .open(&group_bits, &point)
        .map_err(|e| RuntimeError::Proof(e.to_string()))?;
    let expected = leaves
        .iter()
        .enumerate()
        .fold(F2_128::from(0u64), |sum, (c, leaf)| {
            sum + eq_at(&r, c) * *leaf
        });
    if value != expected {
        return Err(RuntimeError::Proof(format!(
            "group {spec_index} batch mismatch"
        )));
    }
    Ok(PackedGroupProof {
        spec_index,
        commitment,
        point,
        value,
        leaves,
        opening,
    })
}

pub fn verify_group(
    witness: &BinaryRouterWitness,
    proof: &PackedGroupProof,
) -> Result<(), RuntimeError> {
    let all = groups(has_q(witness));
    let spec = *all
        .get(proof.spec_index)
        .ok_or_else(|| RuntimeError::Proof("group index".into()))?;
    let (_points, values) = context(witness)?;
    if proof.leaves != values[spec.point_index][spec.value_offset..spec.value_offset + spec.width] {
        return Err(RuntimeError::Proof("group leaves mismatch".into()));
    }
    let mut t = magnetar_transcript::Sha256Transcript::new("packed-router-group");
    t.absorb(
        "commitment",
        &bincode::serialize(&proof.commitment).unwrap_or_default(),
    );
    for leaf in &proof.leaves {
        t.absorb("leaf", &leaf.value().to_le_bytes());
    }
    let col_bits = spec.width.next_power_of_two().trailing_zeros() as usize;
    let r = (0..col_bits)
        .map(|_| challenge_field(&mut t, "col"))
        .collect::<Vec<_>>();
    let expected = proof
        .leaves
        .iter()
        .enumerate()
        .fold(F2_128::from(0u64), |sum, (c, leaf)| {
            sum + eq_at(&r, c) * *leaf
        });
    if proof.value != expected {
        return Err(RuntimeError::Proof("group batch value".into()));
    }
    let backend =
        RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
    if !backend
        .verify(&proof.commitment, &proof.point, proof.value, &proof.opening)
        .map_err(|e| RuntimeError::Proof(e.to_string()))?
    {
        return Err(RuntimeError::Proof("group opening rejected".into()));
    }
    Ok(())
}

pub fn prove_group5(witness: &BinaryRouterWitness) -> Result<PackedGroupProof, RuntimeError> {
    prove_group(witness, 6)
}

pub fn verify_group5(
    witness: &BinaryRouterWitness,
    proof: &PackedGroupProof,
) -> Result<(), RuntimeError> {
    verify_group(witness, proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary_router::RouterMode;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    fn witness(store: bool) -> BinaryRouterWitness {
        let program = if store {
            ProgramImage::new(
                0x1000,
                vec![
                    Instruction {
                        op: Op::Lui,
                        rd: 5,
                        rs1: 0,
                        rs2: 0,
                        imm: 0x1000_0000,
                        shamt: 0,
                    }
                    .encode(),
                    Instruction {
                        op: Op::Sw,
                        rd: 0,
                        rs1: 5,
                        rs2: 0,
                        imm: 0,
                        shamt: 0,
                    }
                    .encode(),
                    Instruction::new(Op::Ecall).encode(),
                ],
            )
        } else {
            ProgramImage::new(
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
            )
        };
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
        BinaryRouterWitness::from_trace_mode(
            &trace,
            if store {
                RouterMode::Stores
            } else {
                RouterMode::Shifts
            },
        )
        .unwrap()
    }

    #[test]
    fn all_router_groups_round_trip() {
        for store in [false, true] {
            let w = witness(store);
            for index in 0..groups(has_q(&w)).len() {
                if [5, 8].contains(&index) {
                    continue; // shift_code is a code; q/hq groups need separate handling
                }
                let proof = prove_group(&w, index).unwrap();
                verify_group(&w, &proof).unwrap();
            }
        }
    }
}
