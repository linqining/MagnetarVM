//! Isolated packed BinaryRouter groups.
//!
//! Each Router claim group is packed and proved independently against the
//! reference claim values. This is the incremental replacement path for the
//! full Router opening; groups are not yet merged into one proof.

use magnetar_constraint::F2_128;
use magnetar_pcs::{P3BinaryPcs, P3MosaicCommitment, P3MosaicOpening, P3SharedPcs};
use magnetar_proof::{BitPcs, Mle, Pcs, RingSwitchOpening, RingSwitchPackedBitPcs};

use crate::binary_router::{
    prove_binary_router_claims, verify_binary_router_claims, BinaryRouterWitness,
};
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
            point_index: 10,
            start: INPUT_BITS + 9,
            value_offset: 0,
            width: 64,
        });
        out.push(GroupSpec {
            point_index: 11,
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
pub struct FieldGroupProof {
    pub spec_index: usize,
    pub commitment: P3MosaicCommitment,
    pub point: Vec<F2_128>,
    pub value: F2_128,
    pub leaves: Vec<F2_128>,
    pub opening: P3MosaicOpening,
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
    let (_, points, values) = prove_binary_router_claims(witness, &commitment, 0, b"")
        .map_err(|e| RuntimeError::Proof(e.to_string()))?;
    Ok((points.into_iter().map(|p| p.point).collect(), values))
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PackedRouterProof {
    pub claims: crate::binary_router::BinaryRouterProof,
    pub table_commitment: P3MosaicCommitment,
    pub bit_groups: Vec<PackedGroupProof>,
    pub field_groups: Vec<FieldGroupProof>,
}

fn group_flat(witness: &BinaryRouterWitness, spec: GroupSpec) -> Vec<F2_128> {
    let table = witness.table();
    let width = spec.width.next_power_of_two();
    let mut flat = vec![F2_128::from(0u64); width * witness.cycles];
    for off in 0..spec.width {
        for (cycle, value) in table.columns[spec.start + off].iter().enumerate() {
            flat[cycle * width + off] = *value;
        }
    }
    flat
}

pub fn prove_packed_router(
    witness: &BinaryRouterWitness,
) -> Result<PackedRouterProof, RuntimeError> {
    let all = groups(has_q(witness));
    let table = witness.table();
    let table_commitment = P3BinaryPcs::new(100)
        .commit_mosaic(core::slice::from_ref(&table))
        .map_err(|e| RuntimeError::Proof(e.to_string()))?;
    let backend =
        RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    let mut bit_bits = Vec::new();
    let mut bit_commitments = Vec::new();
    let mut field_flats = Vec::new();
    let mut field_commitments = Vec::new();
    let mut binding = bincode::serialize(&table_commitment).unwrap_or_default();
    for (index, spec) in all.iter().enumerate() {
        if is_field_group(index) {
            let flat = group_flat(witness, *spec);
            let commitment = pcs
                .commit(&flat)
                .map_err(|e| RuntimeError::Proof(e.to_string()))?;
            field_commitments.push(commitment);
            field_flats.push(flat);
        } else {
            let bits = bits(witness, *spec);
            let commitment = backend
                .commit(&bits)
                .map_err(|e| RuntimeError::Proof(e.to_string()))?;
            bit_commitments.push(commitment);
            bit_bits.push(bits);
        }
    }
    for commitment in &bit_commitments {
        binding.extend_from_slice(&bincode::serialize(commitment).unwrap_or_default());
    }
    for commitment in &field_commitments {
        binding.extend_from_slice(&bincode::serialize(commitment).unwrap_or_default());
    }
    let binding = magnetar_transcript::sha256(&binding);
    let (claims, points, values) =
        prove_binary_router_claims(witness, &table_commitment, 0, &binding)
            .map_err(|e| RuntimeError::Proof(e.to_string()))?;
    let mut bit_groups = Vec::new();
    let mut field_groups = Vec::new();
    let mut bit_index = 0;
    let mut field_index = 0;
    for (index, spec) in all.iter().enumerate() {
        let leaves =
            values[spec.point_index][spec.value_offset..spec.value_offset + spec.width].to_vec();
        let col_bits = spec.width.next_power_of_two().trailing_zeros() as usize;
        if is_field_group(index) {
            let commitment = &field_commitments[field_index];
            let mut t = magnetar_transcript::Sha256Transcript::new("packed-router-field-group");
            t.absorb(
                "commitment",
                &bincode::serialize(commitment).unwrap_or_default(),
            );
            for leaf in &leaves {
                t.absorb("leaf", &leaf.value().to_le_bytes());
            }
            let r = (0..col_bits)
                .map(|_| challenge_field(&mut t, "col"))
                .collect::<Vec<_>>();
            let mut point = [r.clone(), points[spec.point_index].point.clone()].concat();
            point.resize(
                field_flats[field_index].len().trailing_zeros() as usize,
                F2_128::from(0u64),
            );
            let flat = &field_flats[field_index];
            let value = Mle::new(flat.clone())
                .map_err(|e| RuntimeError::Proof(e.to_string()))?
                .eval(&point)
                .map_err(|e| RuntimeError::Proof(e.to_string()))?;
            let opening = pcs
                .open(flat, &point)
                .map_err(|e| RuntimeError::Proof(e.to_string()))?;
            let expected = leaves
                .iter()
                .enumerate()
                .fold(F2_128::from(0u64), |sum, (c, leaf)| {
                    sum + eq_at(&r, c) * *leaf
                });
            if value != expected {
                return Err(RuntimeError::Proof("router field batch".into()));
            }
            field_groups.push(FieldGroupProof {
                spec_index: index,
                commitment: commitment.clone(),
                point,
                value,
                leaves,
                opening,
            });
            field_index += 1;
        } else {
            let commitment = &bit_commitments[bit_index];
            let mut t = magnetar_transcript::Sha256Transcript::new("packed-router-group");
            t.absorb(
                "commitment",
                &bincode::serialize(commitment).unwrap_or_default(),
            );
            for leaf in &leaves {
                t.absorb("leaf", &leaf.value().to_le_bytes());
            }
            let r = (0..col_bits)
                .map(|_| challenge_field(&mut t, "col"))
                .collect::<Vec<_>>();
            let mut point = [r.clone(), points[spec.point_index].point.clone()].concat();
            point.resize(
                bit_bits[bit_index].len().trailing_zeros() as usize,
                F2_128::from(0u64),
            );
            let (value, opening) = backend
                .open(&bit_bits[bit_index], &point)
                .map_err(|e| RuntimeError::Proof(e.to_string()))?;
            let expected = leaves
                .iter()
                .enumerate()
                .fold(F2_128::from(0u64), |sum, (c, leaf)| {
                    sum + eq_at(&r, c) * *leaf
                });
            if value != expected {
                return Err(RuntimeError::Proof("router bit batch".into()));
            }
            bit_groups.push(PackedGroupProof {
                spec_index: index,
                commitment: commitment.clone(),
                point,
                value,
                leaves,
                opening,
            });
            bit_index += 1;
        }
    }
    Ok(PackedRouterProof {
        claims,
        table_commitment,
        bit_groups,
        field_groups,
    })
}

pub fn verify_packed_router(
    witness: &BinaryRouterWitness,
    proof: &PackedRouterProof,
) -> Result<(), RuntimeError> {
    let all = groups(has_q(witness));
    let mut binding = bincode::serialize(&proof.table_commitment).unwrap_or_default();
    for g in &proof.bit_groups {
        binding.extend_from_slice(&bincode::serialize(&g.commitment).unwrap_or_default());
    }
    for g in &proof.field_groups {
        binding.extend_from_slice(&bincode::serialize(&g.commitment).unwrap_or_default());
    }
    let binding = magnetar_transcript::sha256(&binding);
    let Some((_points, values)) =
        verify_binary_router_claims(witness, &proof.claims, &proof.table_commitment, 0, &binding)
            .map_err(|e| RuntimeError::Proof(e.to_string()))?
    else {
        return Err(RuntimeError::Proof("packed Router claims rejected".into()));
    };
    let backend =
        RingSwitchPackedBitPcs::new(P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new()));
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    for g in &proof.bit_groups {
        let spec = all[g.spec_index];
        if g.leaves != values[spec.point_index][spec.value_offset..spec.value_offset + spec.width] {
            return Err(RuntimeError::Proof("router bit leaves".into()));
        }
        let r = {
            let mut t = magnetar_transcript::Sha256Transcript::new("packed-router-group");
            t.absorb(
                "commitment",
                &bincode::serialize(&g.commitment).unwrap_or_default(),
            );
            for leaf in &g.leaves {
                t.absorb("leaf", &leaf.value().to_le_bytes());
            }
            (0..spec.width.next_power_of_two().trailing_zeros() as usize)
                .map(|_| challenge_field(&mut t, "col"))
                .collect::<Vec<_>>()
        };
        if g.value
            != g.leaves
                .iter()
                .enumerate()
                .fold(F2_128::from(0u64), |s, (c, l)| s + eq_at(&r, c) * *l)
        {
            return Err(RuntimeError::Proof("router bit batch".into()));
        }
        if !backend
            .verify(&g.commitment, &g.point, g.value, &g.opening)
            .map_err(|e| RuntimeError::Proof(e.to_string()))?
        {
            return Err(RuntimeError::Proof("router bit opening".into()));
        }
    }
    for g in &proof.field_groups {
        let spec = all[g.spec_index];
        if g.leaves != values[spec.point_index][spec.value_offset..spec.value_offset + spec.width] {
            return Err(RuntimeError::Proof("router field leaves".into()));
        }
        let r = {
            let mut t = magnetar_transcript::Sha256Transcript::new("packed-router-field-group");
            t.absorb(
                "commitment",
                &bincode::serialize(&g.commitment).unwrap_or_default(),
            );
            for leaf in &g.leaves {
                t.absorb("leaf", &leaf.value().to_le_bytes());
            }
            (0..spec.width.next_power_of_two().trailing_zeros() as usize)
                .map(|_| challenge_field(&mut t, "col"))
                .collect::<Vec<_>>()
        };
        if g.value
            != g.leaves
                .iter()
                .enumerate()
                .fold(F2_128::from(0u64), |s, (c, l)| s + eq_at(&r, c) * *l)
        {
            return Err(RuntimeError::Proof("router field batch".into()));
        }
        if !pcs
            .verify(&g.commitment, &g.point, g.value, &g.opening)
            .map_err(|e| RuntimeError::Proof(e.to_string()))?
        {
            return Err(RuntimeError::Proof("router field opening".into()));
        }
    }
    Ok(())
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

pub fn is_field_group(spec_index: usize) -> bool {
    matches!(spec_index, 5 | 8)
}

pub fn prove_field_group(
    witness: &BinaryRouterWitness,
    spec_index: usize,
) -> Result<FieldGroupProof, RuntimeError> {
    let all = groups(has_q(witness));
    let spec = *all
        .get(spec_index)
        .ok_or_else(|| RuntimeError::Proof("group index".into()))?;
    let (points, values) = context(witness)?;
    let table = witness.table();
    let cycles = witness.cycles;
    let width = spec.width.next_power_of_two();
    let mut flat = vec![F2_128::from(0u64); width * cycles];
    for off in 0..spec.width {
        flat[off..]
            .iter_mut()
            .step_by(width)
            .zip(table.columns[spec.start + off].iter())
            .for_each(|(slot, value)| *slot = *value);
    }
    let leaves =
        values[spec.point_index][spec.value_offset..spec.value_offset + spec.width].to_vec();
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    let commitment = pcs
        .commit(&flat)
        .map_err(|e| RuntimeError::Proof(e.to_string()))?;
    let col_bits = spec.width.next_power_of_two().trailing_zeros() as usize;
    let mut t = magnetar_transcript::Sha256Transcript::new("packed-router-field-group");
    t.absorb(
        "commitment",
        &bincode::serialize(&commitment).unwrap_or_default(),
    );
    for leaf in &leaves {
        t.absorb("leaf", &leaf.value().to_le_bytes());
    }
    let r = (0..col_bits)
        .map(|_| challenge_field(&mut t, "col"))
        .collect::<Vec<_>>();
    let mut point = [r.clone(), points[spec.point_index].clone()].concat();
    point.resize(flat.len().trailing_zeros() as usize, F2_128::from(0u64));
    let value = Mle::new(flat.clone())
        .map_err(|e| RuntimeError::Proof(e.to_string()))?
        .eval(&point)
        .map_err(|e| RuntimeError::Proof(e.to_string()))?;
    let opening = pcs
        .open(&flat, &point)
        .map_err(|e| RuntimeError::Proof(e.to_string()))?;
    let expected = leaves
        .iter()
        .enumerate()
        .fold(F2_128::from(0u64), |sum, (c, leaf)| {
            sum + eq_at(&r, c) * *leaf
        });
    if value != expected {
        return Err(RuntimeError::Proof(format!(
            "field group {spec_index} batch mismatch"
        )));
    }
    Ok(FieldGroupProof {
        spec_index,
        commitment,
        point,
        value,
        leaves,
        opening,
    })
}

pub fn verify_field_group(
    witness: &BinaryRouterWitness,
    proof: &FieldGroupProof,
) -> Result<(), RuntimeError> {
    let all = groups(has_q(witness));
    let spec = *all
        .get(proof.spec_index)
        .ok_or_else(|| RuntimeError::Proof("group index".into()))?;
    let (_points, values) = context(witness)?;
    if proof.leaves != values[spec.point_index][spec.value_offset..spec.value_offset + spec.width] {
        return Err(RuntimeError::Proof("field group leaves mismatch".into()));
    }
    let col_bits = spec.width.next_power_of_two().trailing_zeros() as usize;
    let mut t = magnetar_transcript::Sha256Transcript::new("packed-router-field-group");
    t.absorb(
        "commitment",
        &bincode::serialize(&proof.commitment).unwrap_or_default(),
    );
    for leaf in &proof.leaves {
        t.absorb("leaf", &leaf.value().to_le_bytes());
    }
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
        return Err(RuntimeError::Proof("field group batch value".into()));
    }
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    if !pcs
        .verify(&proof.commitment, &proof.point, proof.value, &proof.opening)
        .map_err(|e| RuntimeError::Proof(e.to_string()))?
    {
        return Err(RuntimeError::Proof("field group opening rejected".into()));
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
    fn full_packed_router_round_trips() {
        for store in [false, true] {
            let w = witness(store);
            let proof = prove_packed_router(&w).unwrap();
            verify_packed_router(&w, &proof).unwrap();
        }
    }

    #[test]
    fn all_router_groups_round_trip() {
        for store in [false, true] {
            let w = witness(store);
            for index in 0..groups(has_q(&w)).len() {
                if is_field_group(index) {
                    let proof = prove_field_group(&w, index).unwrap();
                    verify_field_group(&w, &proof).unwrap();
                } else {
                    let proof = prove_group(&w, index).unwrap();
                    verify_group(&w, &proof).unwrap();
                }
            }
        }
    }
}
