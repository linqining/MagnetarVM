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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VirtualCpuProof {
    pub width: usize,
    pub cycles: usize,
    pub trace_commitment: [u8; 32],
    pub initial_pc: u64,
    pub final_pc: u64,
    pub claims: VirtualClaimSet,
    pub selected_cpu: SelectedCpuProof,
}

/// Proof-format step 1: selected CPU proof + canonical virtual claim set.
/// This verifies the CPU matrices/opening and the virtual claim root without
/// rebuilding a full trace. Memory/bytecode consistency is not yet attached.
pub fn prove_virtual_cpu(
    trace: &magnetar_spec::Trace,
    width: usize,
) -> Result<VirtualCpuProof, RuntimeError> {
    let backend = crate::protocol::selected_backend();
    let selected_cpu = crate::simd_dual::prove_dynamic_cpu_claims(trace, width, &backend)?;
    let claims = VirtualClaimSet::from_selected(&selected_cpu)?;
    Ok(VirtualCpuProof {
        width,
        cycles: selected_cpu.cycles,
        trace_commitment: crate::trace_digest(trace),
        initial_pc: selected_cpu.initial_pc,
        final_pc: selected_cpu.final_pc,
        claims,
        selected_cpu,
    })
}

pub fn verify_virtual_cpu(
    statement: &crate::Statement,
    proof: &VirtualCpuProof,
    width: usize,
) -> Result<(), RuntimeError> {
    if proof.width != width {
        return Err(RuntimeError::Proof("virtual CPU width mismatch".into()));
    }
    if proof.initial_pc != statement.initial_state.pc || proof.final_pc != statement.final_state.pc
    {
        return Err(RuntimeError::Proof(
            "virtual CPU PC does not match the statement".into(),
        ));
    }
    if proof.claims.claims.is_empty() || !proof.claims.verify_root() {
        return Err(RuntimeError::Proof("virtual claim root invalid".into()));
    }
    let recomputed = VirtualClaimSet::from_selected(&proof.selected_cpu)?;
    if recomputed.root != proof.claims.root || recomputed.claims != proof.claims.claims {
        return Err(RuntimeError::Proof(
            "virtual claim set does not match the selected proof".into(),
        ));
    }
    let backend = crate::protocol::selected_backend();
    crate::simd_dual::verify_dynamic_segments_public(&proof.selected_cpu, &backend)
}

#[cfg(test)]
mod virtual_cpu_tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    fn statement(trace: &magnetar_spec::Trace) -> crate::Statement {
        crate::Statement {
            program_hash: crate::program_hash(&ProgramImage::new(
                trace.config.entry,
                trace.rom.clone(),
            )),
            rom: trace.rom.clone(),
            trace_commitment: crate::trace_digest(trace),
            trace_claim_root: crate::trace_claims::TraceClaimTree::build(trace).root(),
            access_statement_digest: crate::access_statement::AccessStatement::from_trace(trace)
                .digest(),
            config: trace.config.clone(),
            initial_state: trace.initial_state.clone(),
            initial_ram: trace.initial_ram.clone(),
            final_state: trace.final_state.clone(),
            trace_len: trace.rows.len() as u64,
            output: trace.io_output.clone(),
            input: trace.io_input.clone(),
            halted: trace.halted,
            exit_code: trace.exit_code,
        }
    }

    #[test]
    fn virtual_cpu_proof_round_trips_without_trace() {
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
        let statement = statement(&trace);
        let proof = prove_virtual_cpu(&trace, 8).unwrap();
        verify_virtual_cpu(&statement, &proof, 8).unwrap();
        let mut tampered = proof.clone();
        tampered.claims.claims[0].value = tampered.claims.claims[0].value + F2_128::from(1u64);
        assert!(verify_virtual_cpu(&statement, &tampered, 8).is_err());
        let mut tampered = proof;
        tampered.final_pc ^= 1;
        assert!(verify_virtual_cpu(&statement, &tampered, 8).is_err());
    }
}
