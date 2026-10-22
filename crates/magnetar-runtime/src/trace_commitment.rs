//! Committed trace polynomial prototype.
//!
//! This is A2 groundwork: flatten the public trace fields into one
//! multilinear polynomial, commit it with the P3 PCS, and open it at a
//! digest-derived point. The unified proof does not use it yet; this module
//! makes the trace commitment/opening path concrete and testable.

use magnetar_constraint::{Segment, SegmentKind, SegmentOwner, WitnessLayout, F2_128};
use magnetar_pcs::P3BinaryPcs;
use magnetar_proof::{Mle, Pcs};
use magnetar_spec::Trace;

use crate::RuntimeError;

#[derive(Clone, Debug)]
pub struct TraceWitness {
    pub values: Vec<F2_128>,
    pub layout: WitnessLayout,
    pub point: Vec<F2_128>,
}

pub fn trace_witness(trace: &Trace) -> Result<TraceWitness, RuntimeError> {
    let mut values = Vec::new();
    for row in &trace.rows {
        values.push(F2_128::from(row.pc));
        values.push(F2_128::from(row.next_pc));
        values.push(F2_128::from(row.rd_val));
        values.push(F2_128::from(row.rs1_val));
        values.push(F2_128::from(row.rs2_val));
        if let Some(access) = row.mem {
            values.push(F2_128::from(access.addr));
            values.push(F2_128::from(access.value));
            values.push(F2_128::from(u64::from(access.width)));
        } else {
            values.extend([F2_128::from(0u64); 3]);
        }
    }
    let len = values.len().next_power_of_two().max(1);
    values.resize(len, F2_128::from(0u64));
    let chunk = if len >= 4 { len / 4 } else { len };
    let mut segments = Vec::new();
    let mut offset = 0;
    let mut index = 0;
    while offset < len {
        let size = chunk.min(len - offset);
        segments.push(Segment::new(
            format!("trace{index}"),
            offset,
            size,
            SegmentKind::Direct,
            SegmentOwner::Cpu,
        ));
        offset += size;
        index += 1;
    }
    let layout =
        WitnessLayout::new(segments).map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let digest = crate::trace_digest(trace);
    let point = (0..layout.total_bits.trailing_zeros() as usize)
        .map(|index| F2_128::from(u64::from(digest[index % 32])))
        .collect();
    Ok(TraceWitness {
        values,
        layout,
        point,
    })
}

pub fn prove_trace_commitment(
    trace: &Trace,
) -> Result<
    (
        TraceWitness,
        magnetar_pcs::P3Commitment,
        magnetar_pcs::P3Opening,
    ),
    RuntimeError,
> {
    let witness = trace_witness(trace)?;
    let pcs = P3BinaryPcs::new(100);
    let commitment = pcs
        .commit(&witness.values)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let opening = pcs
        .open(&witness.values, &witness.point)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((witness, commitment, opening))
}

pub fn verify_trace_commitment(
    trace: &Trace,
    commitment: &magnetar_pcs::P3Commitment,
    opening: &magnetar_pcs::P3Opening,
) -> Result<(), RuntimeError> {
    let witness = trace_witness(trace)?;
    let expected = Mle::new(witness.values.clone())
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .eval(&witness.point)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let pcs = P3BinaryPcs::new(100);
    let valid = pcs
        .verify(commitment, &witness.point, expected, opening)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    if !valid {
        return Err(RuntimeError::Proof(
            "trace commitment opening rejected".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    fn trace() -> Trace {
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 5,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        execute(
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
        .unwrap()
    }

    #[test]
    fn trace_commitment_round_trips() {
        let trace = trace();
        let (witness, commitment, opening) = prove_trace_commitment(&trace).unwrap();
        assert_eq!(witness.values.len(), witness.layout.total_bits);
        verify_trace_commitment(&trace, &commitment, &opening).unwrap();

        let mut tampered = commitment.clone();
        tampered.num_variables += 1;
        assert!(verify_trace_commitment(&trace, &tampered, &opening).is_err());

        let claims = magnetar_proof::virtual_spartan::split_segment_claims(
            &witness.layout,
            &witness.values,
            &witness.point,
        )
        .unwrap();
        let value = Mle::new(witness.values.clone())
            .unwrap()
            .eval(&witness.point)
            .unwrap();
        magnetar_proof::virtual_spartan::verify_segment_claims(
            &witness.layout,
            &claims,
            &witness.point,
            value,
        )
        .unwrap();
    }
}
