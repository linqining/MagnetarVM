//! Auxiliary bytecode/shift/store proofs for the gated CPU path.

use magnetar_spec::Trace;

use crate::binary_router::{
    prove_binary_router, verify_binary_router, BinaryRouterProof, BinaryRouterWitness, RouterMode,
};
use crate::binary_shout::{
    prove_binary_shout, verify_binary_shout, BinaryShoutProof, BinaryShoutWitness,
};
use crate::RuntimeError;

#[derive(Clone, Debug)]
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
}
