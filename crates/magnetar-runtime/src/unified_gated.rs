//! Unified proof object for the legacy claim-bound trace proof and the gated
//! SIMD CPU proof.
//!
//! `UnifiedTraceProof` already shares one commitment/opening across the CPU,
//! register Twist, RAM Twist, Shout, Router, and gated SIMD CPU claims. This
//! wrapper keeps a stable trace-commitment-bound entry point.

use magnetar_spec::Trace;

use crate::{prove_unified_trace, verify_unified_trace, RuntimeError, UnifiedTraceProof};

#[derive(Clone, Debug)]
pub struct UnifiedGatedProof {
    pub trace_commitment: [u8; 32],
    pub unified: UnifiedTraceProof,
}

fn trace_commitment(trace: &Trace) -> [u8; 32] {
    magnetar_transcript::sha256(&bincode::serialize(trace).unwrap_or_default())
}

pub fn prove_unified_gated(trace: &Trace, width: usize) -> Result<UnifiedGatedProof, RuntimeError> {
    let unified = prove_unified_trace(trace, width)?;
    Ok(UnifiedGatedProof {
        trace_commitment: trace_commitment(trace),
        unified,
    })
}

pub fn verify_unified_gated(
    trace: &Trace,
    proof: &UnifiedGatedProof,
    width: usize,
) -> Result<(), RuntimeError> {
    if proof.trace_commitment != trace_commitment(trace) {
        return Err(RuntimeError::Proof("unified gated trace commitment".into()));
    }
    verify_unified_trace(trace, &proof.unified, width)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    #[test]
    fn unified_gated_round_trips() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Add,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Xori,
                    rd: 2,
                    rs1: 1,
                    rs2: 0,
                    imm: 3,
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
        let proof = prove_unified_gated(&trace, 8).unwrap();
        assert!(proof.unified.gated.is_some());
        verify_unified_gated(&trace, &proof, 8).unwrap();
    }
}
