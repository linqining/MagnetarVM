//! Shift-row proof component using the existing native F2 barrel-shift
//! relation. Shift rows are proved separately from the gated ALU row; this is
//! the shift component needed by the gated CPU path before full row fusion.

use magnetar_pcs::{P3BinaryPcs, P3Commitment, P3Opening};
use magnetar_proof::SpartanProof;

use crate::simd_f2::{BitProofBackend, BitShiftKind, EmbeddedBitBackend, UniformBitShiftRelation};
use crate::RuntimeError;

#[derive(Clone, Copy, Debug)]
pub struct GatedShiftEvent {
    pub left: u64,
    pub shamt: u64,
    pub kind: BitShiftKind,
}

pub fn prove_gated_shift_row(
    width: usize,
    event: GatedShiftEvent,
) -> Result<SpartanProof<P3Commitment, P3Opening>, RuntimeError> {
    let relation = UniformBitShiftRelation::shift(width, event.kind);
    let bits = relation.witness(event.left, event.shamt);
    let backend = EmbeddedBitBackend {
        pcs: P3BinaryPcs::new(100),
    };
    backend
        .prove(&relation.relation, &bits)
        .map_err(|error| RuntimeError::Proof(error.to_string()))
}

pub fn verify_gated_shift_row(
    width: usize,
    event: GatedShiftEvent,
    proof: &SpartanProof<P3Commitment, P3Opening>,
) -> Result<(), RuntimeError> {
    let relation = UniformBitShiftRelation::shift(width, event.kind);
    let backend = EmbeddedBitBackend {
        pcs: P3BinaryPcs::new(100),
    };
    if backend
        .verify(&relation.relation, proof)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
    {
        Ok(())
    } else {
        Err(RuntimeError::Proof("gated shift proof rejected".into()))
    }
}

/// Extract shift events from a supported trace prefix.
pub fn gated_shift_events_from_trace(
    trace: &magnetar_spec::Trace,
) -> Result<Vec<GatedShiftEvent>, RuntimeError> {
    use magnetar_spec::Op;

    let mut events = Vec::new();
    for row in &trace.rows {
        if row.mem.is_some() {
            break;
        }
        let kind = match row.instruction.op {
            Op::Sll | Op::Slli => BitShiftKind::Sll,
            Op::Srl | Op::Srli => BitShiftKind::Srl,
            Op::Sra | Op::Srai => BitShiftKind::Sra,
            _ => break,
        };
        let shamt = match row.instruction.op {
            Op::Slli | Op::Srli | Op::Srai => u64::from(row.instruction.shamt),
            _ => row.rs2_val,
        };
        events.push(GatedShiftEvent {
            left: row.rs1_val,
            shamt,
            kind,
        });
    }
    if events.is_empty() {
        return Err(RuntimeError::Proof("trace has no shift rows".into()));
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    #[test]
    fn shift_rows_prove() {
        for (kind, left, shamt, expected) in [
            (BitShiftKind::Sll, 5u64, 2u64, 20u64),
            (BitShiftKind::Srl, 20, 2, 5),
            (BitShiftKind::Sra, 248, 1, 252),
        ] {
            let event = GatedShiftEvent { left, shamt, kind };
            let proof = prove_gated_shift_row(8, event).unwrap();
            verify_gated_shift_row(8, event, &proof).unwrap();
            let relation = UniformBitShiftRelation::shift(8, kind);
            let bits = relation.witness(left, shamt);
            let rd = relation
                .rd
                .iter()
                .enumerate()
                .fold(0u64, |value, (bit, var)| {
                    value | (u64::from(bits[*var]) << bit)
                });
            assert_eq!(rd, expected);
        }
    }

    #[test]
    fn shift_events_from_trace_prove() {
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
        let events = gated_shift_events_from_trace(&trace).unwrap();
        assert_eq!(events.len(), 1);
        let proof = prove_gated_shift_row(8, events[0]).unwrap();
        verify_gated_shift_row(8, events[0], &proof).unwrap();
    }
}
