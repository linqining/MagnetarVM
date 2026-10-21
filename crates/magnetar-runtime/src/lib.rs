//! Reference runtime and proof-backend boundary.
//!
//! `ReferencePipeline` executes and checks a trace end to end. It is not a
//! prover: `UnimplementedBackend` makes the missing cryptographic backend
//! explicit rather than returning a misleading "proof".

use magnetar_constraint::{LayoutError, WitnessLayout};
use magnetar_cpu::{check_trace, CpuError};
use magnetar_executor::{execute, ExecError};
use magnetar_memory::{check_memory, MemoryError, MemoryReport};
use magnetar_preprocess::{preprocess, PreprocessError, PreprocessedProgram};
use magnetar_recursion::{ChunkPlan, RecursionError};
use magnetar_spec::{MachineConfig, MachineState, ProgramImage, Trace};
use magnetar_transcript::sha256;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub program_hash: [u8; 32],
    pub initial_state: MachineState,
    pub final_state: MachineState,
    pub trace_len: u64,
}

#[derive(Clone, Debug)]
pub struct ReferenceOutcome {
    pub preprocessed: PreprocessedProgram,
    pub trace: Trace,
    pub memory: MemoryReport,
    pub layout: WitnessLayout,
    pub chunk_plan: ChunkPlan,
    pub statement: Statement,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ReferencePipeline;

impl ReferencePipeline {
    pub fn run(
        image: &ProgramImage,
        config: MachineConfig,
        chunk_size: usize,
    ) -> Result<ReferenceOutcome, RuntimeError> {
        let preprocessed = preprocess(image, config)?;
        let trace = execute(image, preprocessed.config.clone())?;
        check_trace(&trace)?;
        let memory = check_memory(&trace)?;
        let layout = preprocessed.layout(trace.len())?;
        let chunk_plan = ChunkPlan::new(trace.len(), chunk_size)?;
        let statement = Statement {
            program_hash: program_hash(image),
            initial_state: trace.initial_state.clone(),
            final_state: trace.final_state.clone(),
            trace_len: trace.len() as u64,
        };
        Ok(ReferenceOutcome {
            preprocessed,
            trace,
            memory,
            layout,
            chunk_plan,
            statement,
        })
    }
}

pub fn program_hash(image: &ProgramImage) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(image.rom.len() * 4);
    for word in &image.rom {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    sha256(&bytes)
}

pub trait Prover {
    type Statement;
    type Witness;
    type Proof;
    type Error;

    fn prove(
        &self,
        statement: &Self::Statement,
        witness: &Self::Witness,
    ) -> Result<Self::Proof, Self::Error>;
}

pub trait Verifier {
    type Statement;
    type Proof;
    type Error;

    fn verify(&self, statement: &Self::Statement, proof: &Self::Proof)
        -> Result<bool, Self::Error>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UnimplementedBackend;

impl Prover for UnimplementedBackend {
    type Statement = Statement;
    type Witness = Trace;
    type Proof = ();
    type Error = RuntimeError;

    fn prove(&self, _statement: &Statement, _witness: &Trace) -> Result<(), RuntimeError> {
        Err(RuntimeError::ProofBackendUnimplemented)
    }
}

impl Verifier for UnimplementedBackend {
    type Statement = Statement;
    type Proof = ();
    type Error = RuntimeError;

    fn verify(&self, _statement: &Statement, _proof: &()) -> Result<bool, RuntimeError> {
        Err(RuntimeError::ProofBackendUnimplemented)
    }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Preprocess(#[from] PreprocessError),
    #[error(transparent)]
    Exec(#[from] ExecError),
    #[error(transparent)]
    Cpu(#[from] CpuError),
    #[error(transparent)]
    Memory(#[from] MemoryError),
    #[error(transparent)]
    Layout(#[from] LayoutError),
    #[error(transparent)]
    Recursion(#[from] RecursionError),
    #[error("proof backend is not implemented")]
    ProofBackendUnimplemented,
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_spec::{Instruction, Op};

    fn program() -> ProgramImage {
        ProgramImage::new(
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
                Instruction {
                    op: Op::Addi,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
                    imm: 7,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Add,
                    rd: 3,
                    rs1: 1,
                    rs2: 2,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        )
    }

    fn config() -> MachineConfig {
        MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x1000,
            stack_top: 0x1000_1000,
            max_cycles: 100,
        }
    }

    #[test]
    fn reference_pipeline_runs_end_to_end() {
        let outcome = ReferencePipeline::run(&program(), config(), 2).unwrap();
        assert_eq!(outcome.trace.final_state.reg(3), 12);
        assert_eq!(outcome.statement.trace_len, 4);
        assert_eq!(outcome.chunk_plan.num_chunks, 2);
        assert!(outcome.layout.total_bits >= 12);
        assert_eq!(outcome.memory.memory_reads, 0);
    }

    #[test]
    fn backend_is_explicitly_unimplemented() {
        let outcome = ReferencePipeline::run(&program(), config(), 2).unwrap();
        assert!(matches!(
            UnimplementedBackend.prove(&outcome.statement, &outcome.trace),
            Err(RuntimeError::ProofBackendUnimplemented)
        ));
    }
}
