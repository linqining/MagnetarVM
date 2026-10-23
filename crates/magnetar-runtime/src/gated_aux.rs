//! Auxiliary bytecode/shift/store proofs for the gated CPU path.

use magnetar_spec::Trace;

use crate::binary_router::{
    prove_binary_router, verify_binary_router, BinaryRouterProof, BinaryRouterWitness, RouterMode,
};
use crate::binary_shout::{
    prove_binary_shout, verify_binary_shout, BinaryShoutProof, BinaryShoutWitness,
};
use crate::protocol::{Claim, ClaimKind, ClaimSet, ProtocolPlan, SegmentId};
use crate::RuntimeError;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct GatedAuxProof {
    pub shout: BinaryShoutProof,
    pub shifts: Option<BinaryRouterProof>,
    pub stores: Option<BinaryRouterProof>,
}

pub fn prove_gated_aux(trace: &Trace) -> Result<GatedAuxProof, RuntimeError> {
    let shout_witness = BinaryShoutWitness::from_trace(trace)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let shout = prove_binary_shout(&shout_witness)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;

    let shifts = BinaryRouterWitness::from_trace_mode(trace, RouterMode::Shifts)
        .ok()
        .and_then(|witness| prove_binary_router(&witness).ok());
    let stores = BinaryRouterWitness::from_trace_mode(trace, RouterMode::Stores)
        .ok()
        .and_then(|witness| prove_binary_router(&witness).ok());
    Ok(GatedAuxProof {
        shout,
        shifts,
        stores,
    })
}

pub fn verify_gated_aux(trace: &Trace, proof: &GatedAuxProof) -> Result<(), RuntimeError> {
    let shout_witness = BinaryShoutWitness::from_trace(trace)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    verify_binary_shout(&shout_witness, &proof.shout)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;

    if let Some(shifts) = &proof.shifts {
        let witness = BinaryRouterWitness::from_trace_mode(trace, RouterMode::Shifts)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        verify_binary_router(&witness, shifts)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    }
    if let Some(stores) = &proof.stores {
        let witness = BinaryRouterWitness::from_trace_mode(trace, RouterMode::Stores)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        verify_binary_router(&witness, stores)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    }
    Ok(())
}

/// Build the Shift/Store/Bytecode claim set for the auxiliary proofs and route
/// it through the standard protocol consumers.
pub fn gated_aux_claims(trace: &Trace) -> Result<ClaimSet, RuntimeError> {
    let mut claims = ClaimSet::new();
    for row in &trace.rows {
        let kind = match row.instruction.op {
            magnetar_spec::Op::Sll
            | magnetar_spec::Op::Srl
            | magnetar_spec::Op::Sra
            | magnetar_spec::Op::Slli
            | magnetar_spec::Op::Srli
            | magnetar_spec::Op::Srai => Some(ClaimKind::Shift),
            magnetar_spec::Op::Sb
            | magnetar_spec::Op::Sh
            | magnetar_spec::Op::Sw
            | magnetar_spec::Op::Sd => Some(ClaimKind::Store),
            magnetar_spec::Op::Ecall => Some(ClaimKind::Bytecode),
            _ => None,
        };
        if let Some(kind) = kind {
            claims.push(Claim::new(
                kind,
                SegmentId(0),
                vec![magnetar_constraint::F2_128::from(row.pc)],
                magnetar_constraint::F2_128::from(1u64),
            ));
        }
    }
    let plan = ProtocolPlan::unified();
    plan.check_virtual_claims(&claims)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(claims)
}

pub fn verify_gated_aux_claims(mut claims: ClaimSet) -> Result<(), RuntimeError> {
    let plan = ProtocolPlan::unified();
    plan.check_virtual_claims(&claims)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    plan.consume_virtual_claims(&mut claims)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    #[test]
    fn gated_aux_proves_shout_and_shift() {
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
        let proof = prove_gated_aux(&trace).unwrap();
        assert!(proof.shifts.is_some());
        verify_gated_aux(&trace, &proof).unwrap();
    }
    #[test]
    fn aux_claims_route_through_protocol() {
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
        let claims = gated_aux_claims(&trace).unwrap();
        assert!(claims.len() >= 2);
        verify_gated_aux_claims(claims).unwrap();
    }

    #[test]
    fn gated_aux_proves_store_router() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Lui,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x1000_0000,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Slli,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
                    imm: 0,
                    shamt: 2,
                }
                .encode(),
                Instruction {
                    op: Op::Sw,
                    rd: 0,
                    rs1: 1,
                    rs2: 2,
                    imm: 0,
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
        let proof = prove_gated_aux(&trace).unwrap();
        assert!(proof.stores.is_some());
        verify_gated_aux(&trace, &proof).unwrap();
    }
}
