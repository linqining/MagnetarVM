//! End-to-end gated CPU bundle: gated dual CPU proof + BinaryTwist RAM proof
//! + Register/Ram claims routed through `ProtocolPlan`.
//!
//! This is the first bundle that ties the selector-gated CPU path to the
//! memory-checking path without falling back to the legacy unified prover.

use magnetar_constraint::{WitnessLayout, F2_128};
use magnetar_pcs::{P3MosaicCommitment, P3MosaicOpening};
use magnetar_proof::LockstepProof;

use crate::binary_twist::{prove_binary_twist_ram, verify_binary_twist_ram, BinaryTwistRamProof};
use crate::protocol::{Claim, ClaimKind, ClaimSet, ProtocolPlan, SegmentId};
use crate::simd_dual::{prove_gated_dual_batch, verify_gated_dual_batch};
use crate::simd_f2::{gated_memory_twist_witness, GatedCpuRowInput};
use crate::RuntimeError;

#[derive(Clone, Debug)]
pub struct GatedBundle {
    pub cpu: LockstepProof<P3MosaicCommitment, P3MosaicOpening>,
    pub cpu_layout: WitnessLayout,
    pub ram: Option<BinaryTwistRamProof>,
    pub claims: Vec<Claim>,
}

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

pub fn prove_gated_bundle(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
) -> Result<GatedBundle, RuntimeError> {
    let (cpu, cpu_layout) = prove_gated_dual_batch(width, rows)?;
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

pub fn verify_gated_bundle(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
    bundle: &GatedBundle,
) -> Result<(), RuntimeError> {
    verify_gated_dual_batch(width, rows, &bundle.cpu, &bundle.cpu_layout)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simd_f2::GatedAluOp;

    #[test]
    fn gated_bundle_covers_alu_memory_and_twist() {
        let rows = [
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
        ];
        let bundle = prove_gated_bundle(8, &rows).unwrap();
        assert!(bundle.ram.is_some());
        verify_gated_bundle(8, &rows, &bundle).unwrap();
    }
}
