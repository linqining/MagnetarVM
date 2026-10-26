//! Canonical virtual-segment claim set for the BinarySpartan rewrite.
//!
//! This is the first step away from a full-trace `ClaimProof`: the selected CPU
//! proof already commits to a witness layout and to one claim per segment. We
//! can canonicalize those claims, hash them into a single root, and later route
//! them through BinaryShout/BinaryTwist instead of rebuilding every row.

use magnetar_constraint::{SegmentOwner, WitnessLayout, F2_128};
use serde::{Deserialize, Serialize};

use crate::{RuntimeError, SelectedCpuProof};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualClaim {
    pub owner: SegmentOwner,
    pub value: F2_128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualClaimSet {
    pub claims: Vec<VirtualClaim>,
    pub root: [u8; 32],
}

impl VirtualClaimSet {
    pub fn from_selected(claims: &SelectedCpuProof) -> Result<Self, RuntimeError> {
        let layout = crate::simd_dual::selected_layout_from_claims(claims)?;
        if claims.proof.segments.len() != layout.segments.len() {
            return Err(RuntimeError::Proof(
                "virtual claim segment count mismatch".into(),
            ));
        }
        let values = crate::simd_dual::selected_segment_claims(&layout, &claims.proof)?;
        let claims = values
            .into_iter()
            .map(|claim| VirtualClaim {
                owner: claim.owner,
                value: claim.value,
            })
            .collect::<Vec<_>>();
        let root = root_of(&claims);
        Ok(Self { claims, root })
    }

    pub fn verify_root(&self) -> bool {
        root_of(&self.claims) == self.root
    }
}

fn owner_tag(owner: SegmentOwner) -> u8 {
    match owner {
        SegmentOwner::Cpu => 0,
        SegmentOwner::Memory(_) => 1,
        SegmentOwner::Routing(_) => 2,
        SegmentOwner::Pcs => 3,
    }
}

fn root_of(claims: &[VirtualClaim]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(1 + claims.len() * 17);
    bytes.push(claims.len() as u8);
    bytes.extend_from_slice(&(claims.len() as u64).to_le_bytes());
    for claim in claims {
        bytes.push(owner_tag(claim.owner));
        bytes.extend_from_slice(&claim.value.value().to_le_bytes());
    }
    magnetar_transcript::sha256(&bytes)
}

/// Rebuild a layout for a selected proof without a trace.
pub fn layout_from_selected(claims: &SelectedCpuProof) -> Result<WitnessLayout, RuntimeError> {
    crate::simd_dual::selected_layout_from_claims(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    #[test]
    fn virtual_claim_root_is_canonical() {
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
        let backend = crate::protocol::selected_backend();
        let proof = crate::simd_dual::prove_dynamic_cpu_claims(&trace, 8, &backend).unwrap();
        let set = VirtualClaimSet::from_selected(&proof).unwrap();
        assert!(set.verify_root());
        assert!(!set.claims.is_empty());
        let mut tampered = set.clone();
        tampered.claims[0].value = tampered.claims[0].value + F2_128::from(1u64);
        assert!(!tampered.verify_root());
        let rebuilt = VirtualClaimSet::from_selected(&proof).unwrap();
        assert_eq!(set.root, rebuilt.root);
    }
}
