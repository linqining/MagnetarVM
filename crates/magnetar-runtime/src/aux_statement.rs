//! Compact statement for Shout/Router witness reconstruction.

use magnetar_spec::{Instruction, MachineConfig, MachineState, MemoryAccess, Op, Trace, TraceRow};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AuxRow {
    pub pc: u64,
    pub instruction_word: u32,
    pub instruction_len: u8,
    pub op: Op,
    pub rd: u8,
    pub rs1: u8,
    pub rs2: u8,
    pub imm: i64,
    pub shamt: u8,
    pub rs1_val: u64,
    pub rs2_val: u64,
    pub rd_val: u64,
    pub mem: Option<MemoryAccess>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AuxStatement {
    pub config: MachineConfig,
    pub rom: Vec<u32>,
    pub initial_ram: Vec<u8>,
    pub initial_pc: u64,
    pub rows: Vec<AuxRow>,
}

impl AuxStatement {
    pub fn digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(bincode::serialize(self).expect("aux statement serializes")).into()
    }

    pub fn from_trace(trace: &Trace) -> Self {
        Self {
            config: trace.config.clone(),
            rom: trace.rom.clone(),
            initial_ram: trace.initial_ram.clone(),
            initial_pc: trace.initial_state.pc,
            rows: trace
                .rows
                .iter()
                .map(|row| AuxRow {
                    pc: row.pc,
                    instruction_word: row.instruction_word,
                    instruction_len: row.instruction_len,
                    op: row.instruction.op,
                    rd: row.instruction.rd,
                    rs1: row.instruction.rs1,
                    rs2: row.instruction.rs2,
                    imm: row.instruction.imm,
                    shamt: row.instruction.shamt,
                    rs1_val: row.rs1_val,
                    rs2_val: row.rs2_val,
                    rd_val: row.rd_val,
                    mem: row.mem,
                })
                .collect(),
        }
    }

    pub fn synthetic_trace(&self) -> Trace {
        let rows = self
            .rows
            .iter()
            .enumerate()
            .map(|(index, row)| TraceRow {
                cycle: index as u64,
                pc: row.pc,
                next_pc: row.pc.wrapping_add(u64::from(row.instruction_len)),
                instruction_word: row.instruction_word,
                instruction_len: row.instruction_len,
                instruction: Instruction {
                    op: row.op,
                    rd: row.rd,
                    rs1: row.rs1,
                    rs2: row.rs2,
                    imm: row.imm,
                    shamt: row.shamt,
                },
                rs1: Some(row.rs1 as usize),
                rs2: Some(row.rs2 as usize),
                rd: Some(row.rd as usize),
                rs1_val: row.rs1_val,
                rs2_val: row.rs2_val,
                rd_val: row.rd_val,
                mem: row.mem,
                extra_mem: Vec::new(),
                reservation_before: None,
                reservation_after: None,
                syscall: None,
            })
            .collect();
        Trace {
            config: self.config.clone(),
            rom: self.rom.clone(),
            initial_state: MachineState {
                pc: self.initial_pc,
                ..MachineState::default()
            },
            final_state: MachineState::default(),
            rows,
            memory_events: Vec::new(),
            initial_ram: self.initial_ram.clone(),
            halted: false,
            exit_code: None,
            io_output: Vec::new(),
            io_input: Vec::new(),
        }
    }

    pub fn shout_witness(
        &self,
    ) -> Result<crate::binary_shout::BinaryShoutWitness, crate::RuntimeError> {
        crate::binary_shout::BinaryShoutWitness::from_trace(&self.synthetic_trace())
            .map_err(|error| crate::RuntimeError::Proof(error.to_string()))
    }

    pub fn verify_shout(
        &self,
        proof: &crate::UnifiedTraceProof,
    ) -> Result<
        (
            Vec<magnetar_pcs::P3MosaicPoint>,
            Vec<Vec<magnetar_constraint::F2_128>>,
        ),
        crate::RuntimeError,
    > {
        let witness = self.shout_witness()?;
        let Some(shout) = &proof.shout else {
            return Err(crate::RuntimeError::Proof("missing Shout proof".into()));
        };
        let Some(index) = proof.shout_index else {
            return Err(crate::RuntimeError::Proof("missing Shout index".into()));
        };
        crate::binary_shout::verify_binary_shout_claims(
            &witness,
            shout,
            &proof.commitment,
            index,
            b"",
        )
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))?
        .ok_or_else(|| crate::RuntimeError::Proof("Shout claims rejected".into()))
    }

    pub fn verify_router(
        &self,
        proof: &crate::UnifiedTraceProof,
        mode: crate::binary_router::RouterMode,
    ) -> Result<
        (
            Vec<magnetar_pcs::P3MosaicPoint>,
            Vec<Vec<magnetar_constraint::F2_128>>,
        ),
        crate::RuntimeError,
    > {
        let witness = self.router_witness(mode)?;
        let (router, index) = match mode {
            crate::binary_router::RouterMode::Shifts => {
                (&proof.shift_router, proof.shift_router_index)
            }
            crate::binary_router::RouterMode::Stores => {
                (&proof.store_router, proof.store_router_index)
            }
            crate::binary_router::RouterMode::Both => {
                return Err(crate::RuntimeError::Proof(
                    "combined Router mode is not a table".into(),
                ));
            }
        };
        let Some(router) = router else {
            return Err(crate::RuntimeError::Proof("missing Router proof".into()));
        };
        let Some(index) = index else {
            return Err(crate::RuntimeError::Proof("missing Router index".into()));
        };
        crate::binary_router::verify_binary_router_claims(
            &witness,
            router,
            &proof.commitment,
            index,
            b"",
        )
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))?
        .ok_or_else(|| crate::RuntimeError::Proof("Router claims rejected".into()))
    }

    pub fn router_witness(
        &self,
        mode: crate::binary_router::RouterMode,
    ) -> Result<crate::binary_router::BinaryRouterWitness, crate::RuntimeError> {
        crate::binary_router::BinaryRouterWitness::from_trace_mode(&self.synthetic_trace(), mode)
            .map_err(|error| crate::RuntimeError::Proof(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aux_statement_rebuilds_witnesses() {
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
                    op: Op::Slli,
                    rd: 2,
                    rs1: 1,
                    rs2: 0,
                    imm: 0,
                    shamt: 3,
                }
                .encode(),
                Instruction {
                    op: Op::Sd,
                    rd: 0,
                    rs1: 4,
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
        let real_shout = crate::binary_shout::BinaryShoutWitness::from_trace(&trace).unwrap();
        let real_shift = crate::binary_router::BinaryRouterWitness::from_trace_mode(
            &trace,
            crate::binary_router::RouterMode::Shifts,
        )
        .unwrap();
        let statement = AuxStatement::from_trace(&trace);
        let shout = statement.shout_witness().unwrap();
        let shift = statement
            .router_witness(crate::binary_router::RouterMode::Shifts)
            .unwrap();
        assert_eq!(format!("{real_shout:?}"), format!("{shout:?}"));
        assert_eq!(format!("{real_shift:?}"), format!("{shift:?}"));
        let proof = crate::prove_unified_trace(&trace, 8).unwrap();
        crate::packed_shout::verify_packed_shout(proof.packed_shout.as_ref().unwrap()).unwrap();
        statement
            .verify_router(&proof, crate::binary_router::RouterMode::Shifts)
            .unwrap();
    }
}
