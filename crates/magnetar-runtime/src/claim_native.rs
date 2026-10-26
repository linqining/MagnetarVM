//! Linear native proof path over authenticated claims.
//!
//! This is a native optimization, not the paper's BinaryShout/BinaryTwist path:
//! it keeps the ClaimProof and the proof-only selected-CPU bundle, and checks
//! ROM fetch, register consistency and memory consistency directly over the
//! authenticated rows.

use serde::{Deserialize, Serialize};

use crate::{RuntimeError, SelectedCpuProof, Statement};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimNativeProof {
    pub trace_commitment: [u8; 32],
    pub trace_claim_root: [u8; 32],
    pub claim_proof: crate::trace_claims::ClaimProof,
    pub selected_cpu: SelectedCpuProof,
    pub width: usize,
}

pub fn prove_claim_native(
    trace: &magnetar_spec::Trace,
    width: usize,
) -> Result<ClaimNativeProof, RuntimeError> {
    let backend = crate::protocol::selected_backend();
    let selected_cpu = crate::simd_dual::prove_dynamic_cpu_claims(trace, width, &backend)?;
    Ok(ClaimNativeProof {
        trace_commitment: crate::trace_digest(trace),
        trace_claim_root: crate::trace_claims::TraceClaimTree::build(trace).root(),
        claim_proof: crate::trace_claims::ClaimProof::from_trace(trace),
        selected_cpu,
        width,
    })
}

pub fn verify_claim_native(
    statement: &Statement,
    proof: &ClaimNativeProof,
    width: usize,
) -> Result<(), RuntimeError> {
    if proof.width != width {
        return Err(RuntimeError::Proof("claim-native width mismatch".into()));
    }
    if proof.trace_claim_root != statement.trace_claim_root {
        return Err(RuntimeError::Proof(
            "claim root does not match the public statement".into(),
        ));
    }
    if proof.trace_commitment != statement.trace_commitment {
        return Err(RuntimeError::Proof(
            "trace commitment does not match the public statement".into(),
        ));
    }
    if !statement.output.is_empty() || !statement.input.is_empty() {
        return Err(RuntimeError::Proof(
            "claim-native fast path does not yet bind syscall IO".into(),
        ));
    }
    let rows = proof
        .claim_proof
        .verify()
        .ok_or_else(|| RuntimeError::Proof("claim proof opening mismatch".into()))?;
    if rows.len() as u64 != statement.trace_len {
        return Err(RuntimeError::Proof("claim count mismatch".into()));
    }
    let backend = crate::protocol::selected_backend();
    crate::simd_dual::verify_dynamic_claim_bundle(
        statement,
        &proof.claim_proof,
        &proof.selected_cpu,
        &backend,
    )?;
    check_claim_semantics(statement, &rows)
}

fn load_le(ram: &[u8], offset: usize, width: u8) -> Option<u64> {
    let width = width as usize;
    let bytes = ram.get(offset..offset.checked_add(width)?)?;
    let mut value = 0u64;
    for (index, byte) in bytes.iter().enumerate() {
        value |= u64::from(*byte) << (8 * index);
    }
    Some(value)
}

fn store_le(ram: &mut [u8], offset: usize, width: u8, value: u64) -> bool {
    let width = width as usize;
    let Some(bytes) = ram.get_mut(offset..offset.saturating_add(width)) else {
        return false;
    };
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = ((value >> (8 * index)) & 0xff) as u8;
    }
    true
}

fn check_claim_semantics(
    statement: &Statement,
    rows: &[crate::trace_claims::TraceClaim],
) -> Result<(), RuntimeError> {
    let mut registers = statement.initial_state.regs;
    let mut ram = statement.initial_ram.clone();
    for (row_index, claim) in rows.iter().enumerate() {
        if claim.instruction_len != 2 && claim.instruction_len != 4 {
            return Err(RuntimeError::Proof(
                "invalid claim instruction length".into(),
            ));
        }
        let offset = claim
            .pc
            .checked_sub(statement.config.rom_base)
            .ok_or_else(|| RuntimeError::Proof("claim PC below ROM base".into()))?;
        if offset % 2 != 0 {
            return Err(RuntimeError::Proof(
                "claim PC is not halfword aligned".into(),
            ));
        }
        let word_index = usize::try_from(offset / 4)
            .map_err(|_| RuntimeError::Proof("claim PC overflows".into()))?;
        let word = *statement
            .rom
            .get(word_index)
            .ok_or_else(|| RuntimeError::Proof("claim PC outside ROM".into()))?;
        let expected = if claim.instruction_len == 4 {
            if offset % 4 != 0 {
                return Err(RuntimeError::Proof(
                    "32-bit claim is not word aligned".into(),
                ));
            }
            word
        } else if offset % 4 == 0 {
            word & 0xffff
        } else {
            word >> 16
        };
        if claim.instruction_word != expected {
            return Err(RuntimeError::Proof(
                "claim instruction does not match ROM".into(),
            ));
        }
        if claim.rs1_present {
            if usize::from(claim.rs1) >= registers.len()
                || registers[usize::from(claim.rs1)] != claim.rs1_value
            {
                return Err(RuntimeError::Proof("claim rs1 value mismatch".into()));
            }
        }
        if claim.rs2_present {
            if usize::from(claim.rs2) >= registers.len()
                || registers[usize::from(claim.rs2)] != claim.rs2_value
            {
                return Err(RuntimeError::Proof("claim rs2 value mismatch".into()));
            }
        }
        if claim.rd_present {
            let rd = usize::from(claim.rd);
            if rd >= registers.len() {
                return Err(RuntimeError::Proof("claim rd out of range".into()));
            }
            if rd == 0 {
                if claim.rd_value != 0 {
                    return Err(RuntimeError::Proof("x0 write is nonzero".into()));
                }
            } else {
                registers[rd] = claim.rd_value;
            }
        }
        for event in &claim.memory {
            if event.cycle != row_index as u64 {
                return Err(RuntimeError::Proof("claim memory cycle mismatch".into()));
            }
            if event.width != 1 && event.width != 2 && event.width != 4 && event.width != 8 {
                return Err(RuntimeError::Proof("claim memory width invalid".into()));
            }
            let address = event
                .addr
                .checked_sub(statement.config.ram_base)
                .ok_or_else(|| RuntimeError::Proof("claim memory below RAM base".into()))?;
            let offset = usize::try_from(address)
                .map_err(|_| RuntimeError::Proof("claim memory address overflows".into()))?;
            if event.is_write {
                if !store_le(&mut ram, offset, event.width, event.value) {
                    return Err(RuntimeError::Proof("claim memory write outside RAM".into()));
                }
            } else {
                let Some(value) = load_le(&ram, offset, event.width) else {
                    return Err(RuntimeError::Proof("claim memory read outside RAM".into()));
                };
                let mask = if event.width >= 8 {
                    u64::MAX
                } else {
                    (1u64 << (8 * u32::from(event.width))) - 1
                };
                if value != event.value & mask {
                    return Err(RuntimeError::Proof("claim memory read mismatch".into()));
                }
            }
        }
    }
    if registers != statement.final_state.regs {
        return Err(RuntimeError::Proof(
            "claim register file does not reach final state".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    fn trace() -> magnetar_spec::Trace {
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

    fn statement(trace: &magnetar_spec::Trace) -> Statement {
        Statement {
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
    fn native_claim_path_round_trips() {
        let trace = trace();
        let statement = statement(&trace);
        let proof = prove_claim_native(&trace, 8).unwrap();
        verify_claim_native(&statement, &proof, 8).unwrap();
        let mut tampered = proof.clone();
        tampered.trace_commitment[0] ^= 1;
        assert!(verify_claim_native(&statement, &tampered, 8).is_err());
        let mut tampered = proof;
        tampered.claim_proof.openings[0].claim.rd_value ^= 1;
        assert!(verify_claim_native(&statement, &tampered, 8).is_err());
    }
}
