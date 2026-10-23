//! End-to-end gated CPU bundle: gated dual CPU proof + BinaryTwist RAM proof
//! + Register/Ram claims routed through `ProtocolPlan`.

use magnetar_constraint::{WitnessLayout, F2_128};
use magnetar_pcs::{P3MosaicCommitment, P3MosaicOpening, P3SharedPcs};
use magnetar_proof::{BitPcs, DirectBitPcs, LockstepProof};

use crate::binary_twist::{prove_binary_twist_ram, verify_binary_twist_ram, BinaryTwistRamProof};
use crate::protocol::{Claim, ClaimKind, ClaimSet, ProtocolPlan, SegmentId};
use crate::simd_dual::{prove_gated_dual_batch_bits, verify_gated_dual_batch_bits};
use crate::simd_f2::{gated_memory_twist_witness, GatedCpuRowInput};
use crate::RuntimeError;

#[derive(Clone, Debug)]
pub struct GatedBundle<C: Clone + std::fmt::Debug, O: Clone + std::fmt::Debug> {
    pub cpu: LockstepProof<C, O>,
    pub cpu_layout: WitnessLayout,
    pub ram: Option<BinaryTwistRamProof>,
    pub claims: Vec<Claim>,
}

pub type P3GatedBundle = GatedBundle<P3MosaicCommitment, P3MosaicOpening>;

fn claims_for(rows: &[(u64, GatedCpuRowInput)]) -> Vec<Claim> {
    rows.iter()
        .map(|(pc, input)| {
            let kind = match input {
                GatedCpuRowInput::Alu { .. } => ClaimKind::Register,
                GatedCpuRowInput::Memory { .. } => ClaimKind::Ram,
            };
            Claim::new(
                kind,
                SegmentId(0),
                vec![F2_128::from(*pc)],
                F2_128::from(1u64),
            )
        })
        .collect()
}

pub fn prove_gated_bundle_with_backend<B: BitPcs>(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
    backend: &B,
) -> Result<GatedBundle<B::Commitment, B::Opening>, RuntimeError> {
    let (cpu, cpu_layout) = prove_gated_dual_batch_bits(width, rows, backend)?;
    let ram = match gated_memory_twist_witness(width, rows) {
        Ok(witness) => Some(
            prove_binary_twist_ram(&witness)
                .map_err(|error| RuntimeError::Proof(error.to_string()))?,
        ),
        Err(_) => None,
    };
    let claims = claims_for(rows);
    let plan = ProtocolPlan::unified();
    let set = ClaimSet::with_claims(claims.clone());
    plan.check_virtual_claims(&set)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(GatedBundle {
        cpu,
        cpu_layout,
        ram,
        claims,
    })
}

pub fn verify_gated_bundle_with_backend<B: BitPcs>(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
    bundle: &GatedBundle<B::Commitment, B::Opening>,
    backend: &B,
) -> Result<(), RuntimeError> {
    verify_gated_dual_batch_bits(width, rows, &bundle.cpu, &bundle.cpu_layout, backend)?;
    if let Some(ram) = &bundle.ram {
        let witness = gated_memory_twist_witness(width, rows)?;
        verify_binary_twist_ram(&witness, ram)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    }
    let plan = ProtocolPlan::unified();
    let mut set = ClaimSet::with_claims(bundle.claims.clone());
    plan.check_virtual_claims(&set)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    plan.consume_virtual_claims(&mut set)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    if set.remaining() != 0 {
        return Err(RuntimeError::Proof(
            "gated bundle left unconsumed claims".into(),
        ));
    }
    Ok(())
}

pub fn prove_gated_bundle(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
) -> Result<P3GatedBundle, RuntimeError> {
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    prove_gated_bundle_with_backend(width, rows, &DirectBitPcs::new(pcs))
}

pub fn verify_gated_bundle(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
    bundle: &P3GatedBundle,
) -> Result<(), RuntimeError> {
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    verify_gated_bundle_with_backend(width, rows, bundle, &DirectBitPcs::new(pcs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simd_f2::GatedAluOp;
    use magnetar_proof::RingSwitchPackedBitPcs;

    fn rows() -> Vec<(u64, GatedCpuRowInput)> {
        vec![
            (
                0x1000,
                GatedCpuRowInput::Alu {
                    left: 5,
                    right: 3,
                    op: GatedAluOp::Add,
                },
            ),
            (
                0x1004,
                GatedCpuRowInput::Memory {
                    rs1: 0x10,
                    imm: 2,
                    value: 0x34,
                    is_mem: true,
                },
            ),
        ]
    }

    #[test]
    fn gated_bundle_covers_alu_memory_and_twist() {
        let rows = rows();
        let bundle = prove_gated_bundle(8, &rows).unwrap();
        assert!(bundle.ram.is_some());
        verify_gated_bundle(8, &rows, &bundle).unwrap();
    }

    #[test]
    fn mixed_backend_bundle_proves_alu_m4_memory_m5() {
        let rows = rows();
        let bundle = prove_mixed_gated_bundle(8, &rows).unwrap();
        verify_mixed_gated_bundle(8, &rows, &bundle).unwrap();
    }

    #[test]
    fn gated_bundle_runs_with_ring_switch_backend() {
        let rows = rows();
        let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
        let backend = RingSwitchPackedBitPcs::new(pcs);
        let bundle = prove_gated_bundle_with_backend(8, &rows, &backend).unwrap();
        assert!(bundle.ram.is_some());
        verify_gated_bundle_with_backend(8, &rows, &bundle, &backend).unwrap();
    }
}

/// Mixed backend bundle: ALU rows use M4 DirectBitPcs, memory rows use M5
/// RingSwitchPackedBitPcs, and the RAM consistency proof remains BinaryTwist.
#[derive(Clone, Debug)]
pub struct MixedGatedBundle<AO: Clone + std::fmt::Debug, MO: Clone + std::fmt::Debug> {
    pub alu_cpu: LockstepProof<P3MosaicCommitment, AO>,
    pub alu_layout: WitnessLayout,
    pub memory_cpu: LockstepProof<P3MosaicCommitment, MO>,
    pub memory_layout: WitnessLayout,
    pub ram: BinaryTwistRamProof,
    pub claims: Vec<Claim>,
}

pub fn prove_mixed_gated_bundle(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
) -> Result<
    MixedGatedBundle<P3MosaicOpening, magnetar_proof::RingSwitchOpening<P3MosaicOpening>>,
    RuntimeError,
> {
    use magnetar_proof::RingSwitchPackedBitPcs;

    let alu_rows = rows
        .iter()
        .filter(|(_, input)| matches!(input, GatedCpuRowInput::Alu { .. }))
        .copied()
        .collect::<Vec<_>>();
    let memory_rows = rows
        .iter()
        .filter(|(_, input)| matches!(input, GatedCpuRowInput::Memory { .. }))
        .copied()
        .collect::<Vec<_>>();
    if alu_rows.is_empty() || memory_rows.is_empty() {
        return Err(RuntimeError::Proof(
            "mixed bundle needs both ALU and memory rows".into(),
        ));
    }
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    let direct = DirectBitPcs::new(pcs.clone());
    let ring = RingSwitchPackedBitPcs::new(pcs);
    let (alu_cpu, alu_layout) = prove_gated_dual_batch_bits(width, &alu_rows, &direct)?;
    let (memory_cpu, memory_layout) = prove_gated_dual_batch_bits(width, &memory_rows, &ring)?;
    let memory_witness = gated_memory_twist_witness(width, &memory_rows)?;
    let ram = prove_binary_twist_ram(&memory_witness)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let claims = claims_for(rows);
    let plan = ProtocolPlan::unified();
    let set = ClaimSet::with_claims(claims.clone());
    plan.check_virtual_claims(&set)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(MixedGatedBundle {
        alu_cpu,
        alu_layout,
        memory_cpu,
        memory_layout,
        ram,
        claims,
    })
}

pub fn verify_mixed_gated_bundle(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
    bundle: &MixedGatedBundle<P3MosaicOpening, magnetar_proof::RingSwitchOpening<P3MosaicOpening>>,
) -> Result<(), RuntimeError> {
    use magnetar_proof::RingSwitchPackedBitPcs;

    let alu_rows = rows
        .iter()
        .filter(|(_, input)| matches!(input, GatedCpuRowInput::Alu { .. }))
        .copied()
        .collect::<Vec<_>>();
    let memory_rows = rows
        .iter()
        .filter(|(_, input)| matches!(input, GatedCpuRowInput::Memory { .. }))
        .copied()
        .collect::<Vec<_>>();
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    let direct = DirectBitPcs::new(pcs.clone());
    let ring = RingSwitchPackedBitPcs::new(pcs);
    verify_gated_dual_batch_bits(
        width,
        &alu_rows,
        &bundle.alu_cpu,
        &bundle.alu_layout,
        &direct,
    )?;
    verify_gated_dual_batch_bits(
        width,
        &memory_rows,
        &bundle.memory_cpu,
        &bundle.memory_layout,
        &ring,
    )?;
    let memory_witness = gated_memory_twist_witness(width, &memory_rows)?;
    verify_binary_twist_ram(&memory_witness, &bundle.ram)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let plan = ProtocolPlan::unified();
    let mut set = ClaimSet::with_claims(bundle.claims.clone());
    plan.check_virtual_claims(&set)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    plan.consume_virtual_claims(&mut set)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    if set.remaining() != 0 {
        return Err(RuntimeError::Proof(
            "mixed bundle left unconsumed claims".into(),
        ));
    }
    Ok(())
}
