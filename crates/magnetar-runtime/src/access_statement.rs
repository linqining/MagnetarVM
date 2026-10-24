//! Compact statement for trace-free access verification.

use magnetar_spec::{
    Instruction, MachineConfig, MachineState, MemoryEvent, Op, RegIdx, Trace, TraceRow,
};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RegisterOp {
    pub rs1: Option<RegIdx>,
    pub rs2: Option<RegIdx>,
    pub rd: Option<RegIdx>,
    pub rs1_val: u64,
    pub rs2_val: u64,
    pub rd_val: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AccessStatement {
    pub config: MachineConfig,
    pub initial_ram: Vec<u8>,
    pub initial_state: MachineState,
    pub memory_events: Vec<MemoryEvent>,
    pub register_ops: Vec<RegisterOp>,
}

impl AccessStatement {
    pub fn digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(bincode::serialize(self).expect("access statement serializes")).into()
    }

    pub fn from_trace(trace: &Trace) -> Self {
        Self {
            config: trace.config.clone(),
            initial_ram: trace.initial_ram.clone(),
            initial_state: trace.initial_state.clone(),
            memory_events: trace.memory_events.clone(),
            register_ops: trace
                .rows
                .iter()
                .map(|row| RegisterOp {
                    rs1: row.rs1,
                    rs2: row.rs2,
                    rd: row.rd,
                    rs1_val: row.rs1_val,
                    rs2_val: row.rs2_val,
                    rd_val: row.rd_val,
                })
                .collect(),
        }
    }

    pub fn synthetic_trace(&self) -> Trace {
        let rows = self
            .register_ops
            .iter()
            .enumerate()
            .map(|(index, op)| TraceRow {
                cycle: index as u64,
                pc: 0,
                next_pc: 0,
                instruction_word: 0,
                instruction_len: 4,
                instruction: Instruction {
                    op: Op::Add,
                    rd: op.rd.unwrap_or(0) as u8,
                    rs1: op.rs1.unwrap_or(0) as u8,
                    rs2: op.rs2.unwrap_or(0) as u8,
                    imm: 0,
                    shamt: 0,
                },
                rs1: op.rs1,
                rs2: op.rs2,
                rd: op.rd,
                rs1_val: op.rs1_val,
                rs2_val: op.rs2_val,
                rd_val: op.rd_val,
                mem: None,
                extra_mem: Vec::new(),
                reservation_before: None,
                reservation_after: None,
                syscall: None,
            })
            .collect();
        Trace {
            config: self.config.clone(),
            rom: Vec::new(),
            initial_state: self.initial_state.clone(),
            final_state: self.initial_state.clone(),
            rows,
            memory_events: self.memory_events.clone(),
            initial_ram: self.initial_ram.clone(),
            halted: false,
            exit_code: None,
            io_output: Vec::new(),
            io_input: Vec::new(),
        }
    }

    pub fn memory_witness(
        &self,
    ) -> Result<magnetar_memory::BinaryTwistWitness, crate::RuntimeError> {
        magnetar_memory::BinaryTwistWitness::from_trace(&self.synthetic_trace())
            .map_err(|error| crate::RuntimeError::Proof(error.to_string()))
    }

    pub fn verify_access_claims(
        &self,
        proof: &crate::UnifiedTraceProof,
    ) -> Result<
        (
            crate::binary_twist::MosaicClaims,
            crate::binary_twist::MosaicClaims,
        ),
        crate::RuntimeError,
    > {
        let synthetic = self.synthetic_trace();
        let memory = self.memory_witness()?;
        let registers = self.register_witness()?;
        crate::verify_trace_access_shared(
            &synthetic,
            &proof.access,
            &memory,
            &proof.commitment,
            &registers,
            proof.register_index,
        )
    }

    pub fn verify_access(
        &self,
        proof: &crate::UnifiedTraceProof,
    ) -> Result<crate::binary_twist::MosaicClaims, crate::RuntimeError> {
        self.verify_access_claims(proof)
            .map(|(ram_claims, _register_claims)| ram_claims)
    }

    pub fn register_witness(
        &self,
    ) -> Result<magnetar_memory::BinaryTwistWitness, crate::RuntimeError> {
        crate::register_twist::register_twist_witness(&self.synthetic_trace())
            .map_err(|error| crate::RuntimeError::Proof(error.to_string()))
    }
}

/// Verify RAM and register access claims directly from the proof, with no witness.
pub fn access_claims_from_proof(
    proof: &crate::UnifiedTraceProof,
) -> Result<
    (
        crate::binary_twist::MosaicClaims,
        crate::binary_twist::MosaicClaims,
    ),
    crate::RuntimeError,
> {
    let ram = crate::binary_twist::verify_binary_twist_from_proof(
        &proof.access.ram,
        &proof.commitment,
        1,
    )
    .map_err(|error| crate::RuntimeError::Proof(error.to_string()))?
    .ok_or_else(|| crate::RuntimeError::Proof("RAM access claims rejected".into()))?;
    let registers = crate::binary_twist::verify_binary_twist_from_proof(
        &proof.access.registers,
        &proof.commitment,
        proof.register_index,
    )
    .map_err(|error| crate::RuntimeError::Proof(error.to_string()))?
    .ok_or_else(|| crate::RuntimeError::Proof("register access claims rejected".into()))?;
    Ok((ram, registers))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_statement_rebuilds_witnesses() {
        use magnetar_executor::execute;
        use magnetar_spec::ProgramImage;

        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Lui,
                    rd: 4,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x1000_0000,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 7,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Sd,
                    rd: 0,
                    rs1: 4,
                    rs2: 1,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Ld,
                    rd: 2,
                    rs1: 4,
                    rs2: 0,
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
        let real_mem = magnetar_memory::BinaryTwistWitness::from_trace(&trace).unwrap();
        let real_reg = crate::register_twist::register_twist_witness(&trace).unwrap();
        let statement = AccessStatement::from_trace(&trace);
        let mem = statement.memory_witness().unwrap();
        let reg = statement.register_witness().unwrap();
        assert_eq!(format!("{real_mem:?}"), format!("{mem:?}"));
        assert_eq!(format!("{real_reg:?}"), format!("{reg:?}"));
        let proof = crate::prove_unified_trace(&trace, 8).unwrap();
        statement.verify_access(&proof).unwrap();
    }
}
