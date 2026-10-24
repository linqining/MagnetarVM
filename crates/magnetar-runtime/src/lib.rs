//! Reference runtime and proof-backend boundary.
//!
//! `ReferencePipeline` executes and checks a trace end to end. It is not a
//! prover: `UnimplementedBackend` makes the missing cryptographic backend
//! explicit rather than returning a misleading "proof".

pub mod access_statement;
pub mod amo_add_row;
pub mod amo_bundle;
pub mod amo_logic_row;
pub mod amo_minmax_row;
pub mod aux_statement;
pub mod binary_router;
pub mod binary_shout;
pub mod binary_twist;
pub mod binary_twist_address;
pub mod branch_row;
pub mod cpu_shape;
pub mod div_row;
pub mod gated_aux;
pub mod gated_bundle;
pub mod gated_recursion;
pub mod gated_register;
pub mod gated_shift;
pub mod lr_row;
pub mod mul_row;
pub mod packed_router;
pub mod packed_select;
pub mod packed_shout;
pub mod pc_row;
pub mod pc_target_row;
pub mod pc_transition_row;
pub mod protocol;
pub mod register_twist;
pub mod reservation_cpu_row;
pub mod reservation_row;
pub mod sc_row;
pub mod signed_div_row;
pub mod simd_cpu;
pub mod simd_dual;
pub mod simd_f2;
pub mod simd_full;
pub mod simd_memory;
pub mod trace_commitment;
pub mod unified_gated;
pub mod word_div_row;

use crate::binary_router::{
    prove_binary_router_claims, verify_binary_router_claims, BinaryRouterWitness, RouterMode,
};
use crate::binary_shout::{
    prove_binary_shout_claims, verify_binary_shout_claims, BinaryShoutWitness,
};
use crate::binary_twist::{
    prove_binary_twist_claims, prove_binary_twist_ram, verify_binary_twist_claims,
    verify_binary_twist_ram, BatchTables, BinaryTwistRamProof, MosaicClaims,
};

use magnetar_constraint::{
    Constraint, ConstraintSystem, Expr, LayoutError, Segment, SegmentKind, SegmentOwner, Witness,
    WitnessLayout, F2_128,
};
use magnetar_cpu::{check_trace, CpuError};
use magnetar_executor::{execute_with_io, ExecError, ExecutionIo};
use magnetar_memory::{check_memory, BinaryTwistWitness, MemoryError, MemoryReport};
use magnetar_pcs::{
    MerklePath, MerkleTree, NaiveCommitment, NaiveMerklePcs, P3BinaryPcs, P3Commitment,
    P3MosaicCommitment, P3MosaicOpening, P3Opening,
};
use magnetar_preprocess::{preprocess, PreprocessError, PreprocessedProgram};
use magnetar_proof::{
    prove_lockstep, prove_spartan, verify_lockstep, verify_spartan, witness_vector, LockstepClaims,
    LockstepProof, Pcs, SpartanError, SpartanProof,
};
use magnetar_recursion::{ChainedChunk, ChainedProof, ChainedRecursion, ChunkPlan, RecursionError};
use magnetar_spec::{decode, decode_compressed, MachineConfig, MachineState, ProgramImage, Trace};
use magnetar_transcript::sha256;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Statement {
    pub program_hash: [u8; 32],
    pub rom: Vec<u32>,
    pub trace_commitment: [u8; 32],
    pub config: MachineConfig,
    pub initial_state: MachineState,
    pub initial_ram: Vec<u8>,
    pub final_state: MachineState,
    pub trace_len: u64,
    pub output: Vec<u8>,
    pub input: Vec<u8>,
    pub halted: bool,
    pub exit_code: Option<u64>,
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
        Self::run_with_io(image, config, chunk_size, &mut ExecutionIo::default())
    }

    pub fn run_with_io(
        image: &ProgramImage,
        config: MachineConfig,
        chunk_size: usize,
        io: &mut ExecutionIo,
    ) -> Result<ReferenceOutcome, RuntimeError> {
        let preprocessed = preprocess(image, config)?;
        let trace = execute_with_io(image, preprocessed.config.clone(), io)?;
        check_trace(&trace)?;
        let memory = check_memory(&trace)?;
        let layout = preprocessed.layout(trace.len())?;
        let chunk_plan = ChunkPlan::new(trace.len(), chunk_size)?;
        let statement = Statement {
            program_hash: program_hash(image),
            rom: trace.rom.clone(),
            trace_commitment: trace_digest(&trace),
            config: trace.config.clone(),
            initial_state: trace.initial_state.clone(),
            initial_ram: trace.initial_ram.clone(),
            final_state: trace.final_state.clone(),
            trace_len: trace.len() as u64,
            output: trace.io_output.clone(),
            input: trace.io_input.clone(),
            halted: trace.halted,
            exit_code: trace.exit_code,
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

/// Load a statically linked RV64 ELF into the Harvard image and run the
/// reference pipeline over it.
pub fn run_guest_elf(
    bytes: &[u8],
    config: MachineConfig,
    chunk_size: usize,
    io: &mut ExecutionIo,
) -> Result<ReferenceOutcome, RuntimeError> {
    let loaded = magnetar_guest::load_elf(bytes, config)?;
    ReferencePipeline::run_with_io(&loaded.image, loaded.config, chunk_size, io)
}

pub fn program_hash(image: &ProgramImage) -> [u8; 32] {
    rom_hash(&image.rom)
}

pub fn rom_hash(rom: &[u32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(rom.len() * 4);
    for word in rom {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    sha256(&bytes)
}

/// Canonical digest of every row field used by the CPU and access proofs.
pub fn trace_digest(trace: &Trace) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(160 + trace.rows.len() * 80);
    bytes.extend_from_slice(b"magnetar-trace-v6");
    bytes.extend_from_slice(&trace.config.entry.to_le_bytes());
    bytes.extend_from_slice(&trace.config.rom_base.to_le_bytes());
    bytes.extend_from_slice(&trace.config.ram_base.to_le_bytes());
    bytes.extend_from_slice(&(trace.config.ram_size as u64).to_le_bytes());
    bytes.extend_from_slice(&trace.config.stack_top.to_le_bytes());
    bytes.extend_from_slice(&trace.config.max_cycles.to_le_bytes());
    bytes.extend_from_slice(&(trace.rom.len() as u64).to_le_bytes());
    for word in &trace.rom {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    for state in [&trace.initial_state, &trace.final_state] {
        bytes.extend_from_slice(&state.pc.to_le_bytes());
        for register in state.regs {
            bytes.extend_from_slice(&register.to_le_bytes());
        }
    }
    bytes.extend_from_slice(&(trace.initial_ram.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&trace.initial_ram);
    bytes.extend_from_slice(&(trace.rows.len() as u64).to_le_bytes());
    for row in &trace.rows {
        bytes.extend_from_slice(&row.cycle.to_le_bytes());
        bytes.extend_from_slice(&row.pc.to_le_bytes());
        bytes.extend_from_slice(&row.next_pc.to_le_bytes());
        bytes.extend_from_slice(&row.instruction_word.to_le_bytes());
        bytes.push(row.instruction_len);
        bytes.extend_from_slice(&row.rs1_val.to_le_bytes());
        bytes.extend_from_slice(&row.rs2_val.to_le_bytes());
        bytes.extend_from_slice(&row.rd_val.to_le_bytes());
        for slot in [row.rs1, row.rs2, row.rd] {
            match slot {
                Some(index) => {
                    bytes.push(1);
                    bytes.push(index as u8);
                }
                None => bytes.push(0),
            }
        }
        match row.mem {
            Some(access) => {
                bytes.push(1);
                bytes.extend_from_slice(&access.addr.to_le_bytes());
                bytes.extend_from_slice(&access.value.to_le_bytes());
                bytes.push(access.width);
                bytes.push(u8::from(access.is_write));
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(&(row.extra_mem.len() as u64).to_le_bytes());
        for access in &row.extra_mem {
            bytes.extend_from_slice(&access.addr.to_le_bytes());
            bytes.extend_from_slice(&access.value.to_le_bytes());
            bytes.push(access.width);
            bytes.push(u8::from(access.is_write));
        }
        for reservation in [row.reservation_before, row.reservation_after] {
            match reservation {
                Some(addr) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&addr.to_le_bytes());
                }
                None => bytes.push(0),
            }
        }
        match row.syscall {
            Some(syscall) => {
                bytes.push(1);
                bytes.extend_from_slice(&syscall.number.to_le_bytes());
                for arg in syscall.args {
                    bytes.extend_from_slice(&arg.to_le_bytes());
                }
            }
            None => bytes.push(0),
        }
    }
    bytes.push(u8::from(trace.halted));
    match trace.exit_code {
        Some(code) => {
            bytes.push(1);
            bytes.extend_from_slice(&code.to_le_bytes());
        }
        None => bytes.push(0),
    }
    bytes.extend_from_slice(&(trace.io_output.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&trace.io_output);
    bytes.extend_from_slice(&(trace.io_input.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&trace.io_input);
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

pub type CpuSpartanProof = SpartanProof<P3Commitment, P3Opening>;

/// A CPU Spartan proof whose PCS opening also carries auxiliary tables.
pub type MosaicSpartanProof = LockstepProof<P3MosaicCommitment, P3MosaicOpening>;

/// Reference proof backend: Spartan over the constraint IR with the P3
/// multilinear binary-field PCS.
#[derive(Clone, Copy, Debug)]
pub struct ConstraintProofBackend {
    pub pcs: P3BinaryPcs,
}

impl Default for ConstraintProofBackend {
    fn default() -> Self {
        Self {
            pcs: P3BinaryPcs::new(100),
        }
    }
}

impl Prover for ConstraintProofBackend {
    type Statement = ConstraintSystem;
    type Witness = Witness;
    type Proof = CpuSpartanProof;
    type Error = RuntimeError;

    fn prove(
        &self,
        statement: &ConstraintSystem,
        witness: &Witness,
    ) -> Result<Self::Proof, Self::Error> {
        Ok(prove_spartan(statement, witness, &self.pcs)?)
    }
}

impl Verifier for ConstraintProofBackend {
    type Statement = ConstraintSystem;
    type Proof = CpuSpartanProof;
    type Error = RuntimeError;

    fn verify(
        &self,
        statement: &ConstraintSystem,
        proof: &Self::Proof,
    ) -> Result<bool, Self::Error> {
        verify_spartan(statement, proof, &self.pcs)?;
        Ok(true)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CommittedMemory {
    pub addr_bits: usize,
    pub values: Vec<F2_128>,
    pub commitment: NaiveCommitment,
    pub pcs: NaiveMerklePcs,
    #[serde(skip)]
    pub tree: Option<MerkleTree>,
}

impl CommittedMemory {
    pub fn new(addr_bits: usize, values: Vec<F2_128>) -> Result<Self, RuntimeError> {
        let len = 1usize
            .checked_shl(addr_bits as u32)
            .ok_or(RuntimeError::InvalidMemoryTable)?;
        if values.len() != len {
            return Err(RuntimeError::InvalidMemoryTable);
        }
        let leaves = values
            .iter()
            .map(|value| value.value().to_le_bytes().to_vec())
            .collect();
        let tree = MerkleTree::from_leaves(leaves)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        let pcs = NaiveMerklePcs;
        let commitment =
            Pcs::commit(&pcs, &values).map_err(|error| RuntimeError::Proof(error.to_string()))?;
        Ok(Self {
            addr_bits,
            values,
            commitment,
            pcs,
            tree: Some(tree),
        })
    }

    pub fn value(&self, addr: u64) -> Option<F2_128> {
        usize::try_from(addr)
            .ok()
            .and_then(|index| self.values.get(index))
            .copied()
    }

    fn tree(&self) -> Result<&MerkleTree, RuntimeError> {
        self.tree
            .as_ref()
            .ok_or_else(|| RuntimeError::Proof("committed table has no Merkle tree".into()))
    }

    /// Replace one cell and update only the affected Merkle path.
    pub fn updated(&self, index: usize, value: F2_128) -> Result<Self, RuntimeError> {
        if index >= self.values.len() {
            return Err(RuntimeError::AddressOutOfTable(index as u64));
        }
        let mut values = self.values.clone();
        values[index] = value;
        let mut tree = self
            .tree
            .clone()
            .ok_or_else(|| RuntimeError::Proof("committed table has no Merkle tree".into()))?;
        tree.update(index, &value.value().to_le_bytes())
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        let commitment = NaiveCommitment {
            root: tree.root(),
            num_vars: self.addr_bits,
            len: values.len(),
        };
        Ok(Self {
            addr_bits: self.addr_bits,
            values,
            commitment,
            pcs: NaiveMerklePcs,
            tree: Some(tree),
        })
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LoadProof {
    pub path: MerklePath,
    pub addr: u64,
    pub value: F2_128,
}

pub fn prove_load(memory: &CommittedMemory, rs1: u64, imm: u64) -> Result<LoadProof, RuntimeError> {
    let addr = rs1.wrapping_add(imm);
    let value = memory
        .value(addr)
        .ok_or(RuntimeError::AddressOutOfTable(addr))?;
    let index = usize::try_from(addr).map_err(|_| RuntimeError::AddressOutOfTable(addr))?;
    let path = memory
        .tree()?
        .proof(index)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(LoadProof { path, addr, value })
}

pub fn verify_load(memory: &CommittedMemory, proof: &LoadProof) -> Result<(), RuntimeError> {
    let index =
        usize::try_from(proof.addr).map_err(|_| RuntimeError::AddressOutOfTable(proof.addr))?;
    let leaf = proof.value.value().to_le_bytes();
    if proof.path.index != index || !MerkleTree::verify(memory.commitment.root, &leaf, &proof.path)
    {
        return Err(RuntimeError::Proof("memory opening rejected".into()));
    }
    Ok(())
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StoreProof {
    pub old_path: MerklePath,
    pub new_path: MerklePath,
    pub new_commitment: NaiveCommitment,
    pub addr: u64,
    pub old_value: F2_128,
    pub new_value: F2_128,
}

pub fn prove_store(
    memory: &CommittedMemory,
    rs1: u64,
    imm: u64,
    new_value: F2_128,
) -> Result<StoreProof, RuntimeError> {
    let addr = rs1.wrapping_add(imm);
    let old_value = memory
        .value(addr)
        .ok_or(RuntimeError::AddressOutOfTable(addr))?;
    let index = usize::try_from(addr).map_err(|_| RuntimeError::AddressOutOfTable(addr))?;
    let old_path = memory
        .tree()?
        .proof(index)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let new_memory = memory.updated(index, new_value)?;
    let new_path = new_memory
        .tree()?
        .proof(index)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;

    Ok(StoreProof {
        old_path,
        new_path,
        new_commitment: new_memory.commitment,
        addr,
        old_value,
        new_value,
    })
}

pub fn verify_store(memory: &CommittedMemory, proof: &StoreProof) -> Result<(), RuntimeError> {
    let index =
        usize::try_from(proof.addr).map_err(|_| RuntimeError::AddressOutOfTable(proof.addr))?;
    if proof.old_path.index != index || proof.new_path.index != index {
        return Err(RuntimeError::Proof("store path index mismatch".into()));
    }
    if proof.old_path.siblings != proof.new_path.siblings {
        return Err(RuntimeError::Proof(
            "store changed more than one cell".into(),
        ));
    }
    if proof.new_commitment.num_vars != memory.commitment.num_vars
        || proof.new_commitment.len != memory.commitment.len
    {
        return Err(RuntimeError::Proof("memory table shape mismatch".into()));
    }
    let old_leaf = proof.old_value.value().to_le_bytes();
    let new_leaf = proof.new_value.value().to_le_bytes();
    if !MerkleTree::verify(memory.commitment.root, &old_leaf, &proof.old_path)
        || !MerkleTree::verify(proof.new_commitment.root, &new_leaf, &proof.new_path)
    {
        return Err(RuntimeError::Proof("memory opening rejected".into()));
    }

    Ok(())
}

#[derive(Clone, Debug)]
pub enum MemoryStepProof {
    Load(LoadProof),
    Store(StoreProof),
}

#[derive(Clone, Copy, Debug)]
pub enum MemoryAccess {
    Load { rs1: u64, imm: u64 },
    Store { rs1: u64, imm: u64, value: F2_128 },
}

#[derive(Clone, Debug)]
pub struct MemoryChainProof {
    pub initial: CommittedMemory,
    pub steps: Vec<MemoryStepProof>,
    pub final_commitment: NaiveCommitment,
}

pub fn prove_memory_chain(
    initial: &CommittedMemory,
    accesses: &[MemoryAccess],
) -> Result<MemoryChainProof, RuntimeError> {
    let mut current = initial.clone();
    let mut steps = Vec::with_capacity(accesses.len());
    for access in accesses {
        match *access {
            MemoryAccess::Load { rs1, imm } => {
                let proof = prove_load(&current, rs1, imm)?;
                steps.push(MemoryStepProof::Load(proof));
            }
            MemoryAccess::Store { rs1, imm, value } => {
                let proof = prove_store(&current, rs1, imm, value)?;
                let index = usize::try_from(proof.addr)
                    .map_err(|_| RuntimeError::AddressOutOfTable(proof.addr))?;
                current = current.updated(index, value)?;
                if current.commitment != proof.new_commitment {
                    return Err(RuntimeError::Proof(
                        "store proof commitment mismatch".into(),
                    ));
                }
                steps.push(MemoryStepProof::Store(proof));
            }
        }
    }
    Ok(MemoryChainProof {
        initial: initial.clone(),
        steps,
        final_commitment: current.commitment,
    })
}

pub fn verify_memory_chain(proof: &MemoryChainProof) -> Result<(), RuntimeError> {
    let mut current = proof.initial.clone();
    for (step_index, step) in proof.steps.iter().enumerate() {
        match step {
            MemoryStepProof::Load(load) => {
                verify_load(&current, load)?;
                let _ = step_index;
            }
            MemoryStepProof::Store(store) => {
                verify_store(&current, store)?;
                current.commitment = store.new_commitment.clone();
            }
        }
    }
    if current.commitment != proof.final_commitment {
        return Err(RuntimeError::Proof(
            "final memory commitment mismatch".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub enum RegisterOp {
    Read { index: u64, expected: F2_128 },
    Write { index: u64, value: F2_128 },
}

#[derive(Clone, Debug)]
pub enum RegisterStepProof {
    Read { proof: LoadProof, expected: F2_128 },
    Write(StoreProof),
}

#[derive(Clone, Debug)]
pub struct RegisterChainProof {
    pub initial: CommittedMemory,
    pub steps: Vec<RegisterStepProof>,
    pub final_commitment: NaiveCommitment,
    pub final_values: Vec<F2_128>,
}

pub fn prove_register_chain(
    initial: &CommittedMemory,
    operations: &[RegisterOp],
) -> Result<RegisterChainProof, RuntimeError> {
    let mut current = initial.clone();
    let mut steps = Vec::with_capacity(operations.len());
    for operation in operations {
        match *operation {
            RegisterOp::Read { index, expected } => {
                let proof = prove_load(&current, 0, index)?;
                if proof.value != expected {
                    return Err(RuntimeError::Proof(format!(
                        "register x{index} read mismatch"
                    )));
                }
                steps.push(RegisterStepProof::Read { proof, expected });
            }
            RegisterOp::Write { index, value } => {
                let proof = prove_store(&current, 0, index, value)?;
                let cell =
                    usize::try_from(index).map_err(|_| RuntimeError::AddressOutOfTable(index))?;
                current = current.updated(cell, value)?;
                if current.commitment != proof.new_commitment {
                    return Err(RuntimeError::Proof(
                        "register proof commitment mismatch".into(),
                    ));
                }
                steps.push(RegisterStepProof::Write(proof));
            }
        }
    }
    Ok(RegisterChainProof {
        initial: initial.clone(),
        steps,
        final_commitment: current.commitment,
        final_values: current.values,
    })
}

pub fn verify_register_chain(proof: &RegisterChainProof) -> Result<(), RuntimeError> {
    let mut current = proof.initial.clone();
    for (step_index, step) in proof.steps.iter().enumerate() {
        match step {
            RegisterStepProof::Read { proof, expected } => {
                verify_load(&current, proof)?;
                if proof.value != *expected {
                    return Err(RuntimeError::Proof(format!(
                        "register step {step_index} read mismatch"
                    )));
                }
            }
            RegisterStepProof::Write(proof) => {
                verify_store(&current, proof)?;
                current.commitment = proof.new_commitment.clone();
            }
        }
    }
    if current.commitment != proof.final_commitment {
        return Err(RuntimeError::Proof(
            "final register commitment mismatch".into(),
        ));
    }
    let final_commitment = Pcs::commit(&proof.initial.pcs, &proof.final_values)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    if final_commitment != proof.final_commitment
        || proof.final_values.len() != current.values.len()
    {
        return Err(RuntimeError::Proof(
            "final register values do not match commitment".into(),
        ));
    }
    Ok(())
}

pub fn register_ops_from_trace(trace: &Trace) -> Vec<RegisterOp> {
    let mut operations = Vec::new();
    for row in &trace.rows {
        if let Some(index) = row.rs1 {
            operations.push(RegisterOp::Read {
                index: index as u64,
                expected: F2_128::from(row.rs1_val),
            });
        }
        if let Some(index) = row.rs2 {
            operations.push(RegisterOp::Read {
                index: index as u64,
                expected: F2_128::from(row.rs2_val),
            });
        }
        if let Some(index) = row.rd {
            if index != 0 {
                operations.push(RegisterOp::Write {
                    index: index as u64,
                    value: F2_128::from(row.rd_val),
                });
            }
        }
    }
    operations
}

pub fn prove_trace_registers(trace: &Trace) -> Result<RegisterChainProof, RuntimeError> {
    let initial_values = trace
        .initial_state
        .regs
        .iter()
        .map(|value| F2_128::from(*value))
        .collect::<Vec<_>>();
    let registers = CommittedMemory::new(5, initial_values)?;
    let operations = register_ops_from_trace(trace);
    prove_register_chain(&registers, &operations)
}

pub fn verify_trace_registers(
    trace: &Trace,
    proof: &RegisterChainProof,
) -> Result<(), RuntimeError> {
    verify_register_chain(proof)?;
    let initial_values = trace
        .initial_state
        .regs
        .iter()
        .map(|value| F2_128::from(*value))
        .collect::<Vec<_>>();
    let final_values = trace
        .final_state
        .regs
        .iter()
        .map(|value| F2_128::from(*value))
        .collect::<Vec<_>>();
    if proof.initial.values != initial_values || proof.final_values != final_values {
        return Err(RuntimeError::Proof(
            "register boundary values do not match trace".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TraceAccessProof {
    pub registers: BinaryTwistRamProof,
    pub ram: BinaryTwistRamProof,
}

fn memory_span(
    trace: &Trace,
    access: magnetar_spec::MemoryAccess,
) -> Result<(u64, u8, u8), RuntimeError> {
    if !matches!(access.width, 1 | 2 | 4 | 8) {
        return Err(RuntimeError::Proof(format!(
            "unsupported memory access width {}",
            access.width
        )));
    }
    let offset = access
        .addr
        .checked_sub(trace.config.ram_base)
        .ok_or(RuntimeError::AddressOutOfTable(access.addr))?;
    let word = offset / 8;
    let lane = (offset % 8) as u8;
    if word >= (trace.config.ram_size / 8) as u64 {
        return Err(RuntimeError::AddressOutOfTable(access.addr));
    }
    if u64::from(lane) + u64::from(access.width) > 8 {
        return Err(RuntimeError::Proof(
            "trace access proof does not support accesses crossing an aligned word".into(),
        ));
    }
    Ok((word, lane, access.width))
}

fn load_result(raw_word: u64, lane: u8, width: u8, signed: bool) -> u64 {
    if width == 8 {
        return raw_word;
    }
    let bits = u32::from(width) * 8;
    let mask = (1u64 << bits) - 1;
    let raw = (raw_word >> (u32::from(lane) * 8)) & mask;
    if signed {
        let shift = 64 - bits;
        (((raw << shift) as i64) >> shift) as u64
    } else {
        raw
    }
}

fn store_word(old_word: u64, lane: u8, width: u8, value: u64) -> u64 {
    if width == 8 {
        return value;
    }
    let bits = u32::from(width) * 8;
    let mask = (1u64 << bits) - 1;
    let shifted_mask = mask << (u32::from(lane) * 8);
    (old_word & !shifted_mask) | ((value & mask) << (u32::from(lane) * 8))
}

fn twist_word(witness: &BinaryTwistWitness, event: usize, word: u64) -> Result<u64, RuntimeError> {
    witness
        .value
        .get(event)
        .and_then(|values| values.get(word as usize))
        .map(|value| value.value() as u64)
        .ok_or_else(|| RuntimeError::Proof("BinaryTwist history is missing an event".into()))
}

fn twist_read_value(witness: &BinaryTwistWitness, event: usize) -> Result<u64, RuntimeError> {
    witness
        .read_value
        .get(event)
        .map(|value| value.value() as u64)
        .ok_or_else(|| RuntimeError::Proof("BinaryTwist read value is missing".into()))
}

fn twist_write_value(witness: &BinaryTwistWitness, event: usize) -> Result<u64, RuntimeError> {
    witness
        .write_value
        .get(event)
        .map(|value| value.value() as u64)
        .ok_or_else(|| RuntimeError::Proof("BinaryTwist write value is missing".into()))
}

fn check_trace_access_bindings(
    trace: &Trace,
    witness: &BinaryTwistWitness,
) -> Result<(), RuntimeError> {
    let mut event = 0usize;

    for row in &trace.rows {
        if let Some(access) = row.mem {
            let (word, lane, width) = memory_span(trace, access)?;
            let memory_event = event;
            event += 1;
            let old_word = twist_word(witness, memory_event, word)?;
            if access.is_write {
                let is_amo = row.instruction.op.amo_width().is_some();
                let is_read = row.instruction.op == magnetar_spec::Op::Ecall
                    && matches!(row.syscall, Some(syscall) if syscall.number == magnetar_spec::syscall::SYS_READ);
                if is_amo {
                    let observed = load_result(old_word, lane, width, width == 4);
                    if observed != row.rd_val {
                        return Err(RuntimeError::Proof("atomic read mismatch".into()));
                    }
                }
                let write_value = if is_amo || is_read {
                    access.value
                } else {
                    row.rs2_val
                };
                let new_word = store_word(old_word, lane, width, write_value);
                if twist_write_value(witness, memory_event)? != new_word {
                    return Err(RuntimeError::Proof(
                        "memory write does not match BinaryTwist".into(),
                    ));
                }
            } else {
                let read_word = twist_read_value(witness, memory_event)?;
                let signed = matches!(
                    row.instruction.op,
                    magnetar_spec::Op::Lb
                        | magnetar_spec::Op::Lh
                        | magnetar_spec::Op::Lw
                        | magnetar_spec::Op::LrW
                );
                let value = load_result(read_word, lane, width, signed);
                if value != row.rd_val {
                    return Err(RuntimeError::Proof("memory read mismatch".into()));
                }
            }
        }
        for access in &row.extra_mem {
            if !access.is_write {
                return Err(RuntimeError::Proof(
                    "syscall extra memory access is not a write".into(),
                ));
            }
            let (word, lane, width) = memory_span(trace, *access)?;
            let memory_event = event;
            event += 1;
            let old_word = twist_word(witness, memory_event, word)?;
            let new_word = store_word(old_word, lane, width, access.value);
            if twist_write_value(witness, memory_event)? != new_word {
                return Err(RuntimeError::Proof(
                    "syscall write does not match BinaryTwist".into(),
                ));
            }
        }
    }

    Ok(())
}

pub fn prove_trace_access(trace: &Trace) -> Result<TraceAccessProof, RuntimeError> {
    let witness = BinaryTwistWitness::from_trace(trace)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    check_trace_access_bindings(trace, &witness)?;
    let ram =
        prove_binary_twist_ram(&witness).map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let register_witness = crate::register_twist::register_twist_witness(trace)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let registers = prove_binary_twist_ram(&register_witness)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(TraceAccessProof { registers, ram })
}

pub(crate) fn prove_trace_access_shared(
    trace: &Trace,
    witness: &BinaryTwistWitness,
    tables: &BatchTables,
    commitment: &P3MosaicCommitment,
    register_witness: &BinaryTwistWitness,
    register_tables: &BatchTables,
    register_index: usize,
) -> Result<(TraceAccessProof, MosaicClaims, MosaicClaims), RuntimeError> {
    check_trace_access_bindings(trace, witness)?;
    let (ram, ram_claims) = prove_binary_twist_claims(tables, witness, commitment, 1)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let (registers, register_claims) = prove_binary_twist_claims(
        register_tables,
        register_witness,
        commitment,
        register_index,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((
        TraceAccessProof { registers, ram },
        ram_claims,
        register_claims,
    ))
}

pub fn verify_trace_access(trace: &Trace, proof: &TraceAccessProof) -> Result<(), RuntimeError> {
    let witness = BinaryTwistWitness::from_trace(trace)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    if !verify_binary_twist_ram(&witness, &proof.ram)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
    {
        return Err(RuntimeError::Proof("BinaryTwist RAM proof rejected".into()));
    }
    let register_witness = crate::register_twist::register_twist_witness(trace)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    if !verify_binary_twist_ram(&register_witness, &proof.registers)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
    {
        return Err(RuntimeError::Proof(
            "BinaryTwist register proof rejected".into(),
        ));
    }
    check_trace_access_bindings(trace, &witness)
}

pub(crate) fn verify_trace_access_shared(
    trace: &Trace,
    proof: &TraceAccessProof,
    witness: &BinaryTwistWitness,
    commitment: &P3MosaicCommitment,
    register_witness: &BinaryTwistWitness,
    register_index: usize,
) -> Result<(MosaicClaims, MosaicClaims), RuntimeError> {
    if proof.ram.opening.is_some() {
        return Err(RuntimeError::Proof(
            "shared access proof carries a standalone RAM opening".into(),
        ));
    }
    if proof.registers.opening.is_some() {
        return Err(RuntimeError::Proof(
            "shared access proof carries a standalone register opening".into(),
        ));
    }
    check_trace_access_bindings(trace, witness)?;
    let Some(ram_claims) = verify_binary_twist_claims(witness, &proof.ram, commitment, 1)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
    else {
        return Err(RuntimeError::Proof(
            "BinaryTwist RAM claims rejected against the shared commitment".into(),
        ));
    };
    let Some(register_claims) = verify_binary_twist_claims(
        register_witness,
        &proof.registers,
        commitment,
        register_index,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?
    else {
        return Err(RuntimeError::Proof(
            "BinaryTwist register claims rejected against the shared commitment".into(),
        ));
    };
    Ok((ram_claims, register_claims))
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum RowCpuProof {
    Alu(CpuSpartanProof),
    Mul(CpuSpartanProof),
    Mulh(CpuSpartanProof),
    Mulhsu(CpuSpartanProof),
    Mulhu(CpuSpartanProof),
    Divu(CpuSpartanProof),
    Remu(CpuSpartanProof),
    Div(CpuSpartanProof),
    Rem(CpuSpartanProof),
    W(CpuSpartanProof),
    Amo(CpuSpartanProof),
    Load(CpuSpartanProof),
    Store(CpuSpartanProof),
    Jal(CpuSpartanProof),
    Jalr(CpuSpartanProof),
    Auipc(CpuSpartanProof),
    Branch(CpuSpartanProof),
    Skip,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TraceProof {
    pub access: TraceAccessProof,
    pub trace_commitment: [u8; 32],
    pub rows: Vec<RowCpuProof>,
}

/// A single CPU proof for every row, obtained by merging the row systems.
///
/// This removes the per-row proof overhead but keeps the same reference trust
/// model: the verifier reconstructs the merged system from the trace.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UnifiedTraceProof {
    pub access: TraceAccessProof,
    pub trace_commitment: [u8; 32],
    pub cpu: LockstepClaims<P3MosaicCommitment>,
    pub gated: Option<GatedCpuClaims>,
    pub opening: Option<P3MosaicOpening>,
    pub shout: Option<crate::binary_shout::BinaryShoutProof>,
    pub shift_router: Option<crate::binary_router::BinaryRouterProof>,
    pub store_router: Option<crate::binary_router::BinaryRouterProof>,
    pub amo: Option<crate::amo_bundle::AmoBundleProof>,
    pub shape: crate::cpu_shape::CpuShape,
    pub register_index: usize,
    pub shout_index: Option<usize>,
    pub shift_router_index: Option<usize>,
    pub store_router_index: Option<usize>,
    pub trace_index: usize,
    pub trace_claims: Vec<(magnetar_pcs::P3MosaicPoint, Vec<F2_128>)>,
    pub width: usize,
}

pub(crate) struct GatedProveInput {
    pub z: Vec<F2_128>,
    pub a0: [magnetar_proof::SharedBlockMatrix; 3],
    pub a1: [magnetar_proof::SharedBlockMatrix; 3],
    pub layout: magnetar_constraint::WitnessLayout,
    pub table: usize,
    pub cycles: usize,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct GatedCpuClaims {
    pub claims: LockstepClaims<P3MosaicCommitment>,
    pub table: usize,
    pub value: F2_128,
    pub cycles: usize,
}

fn step_op_for(op: magnetar_spec::Op) -> Option<magnetar_cpu::StepOp> {
    use magnetar_cpu::StepOp;
    use magnetar_spec::Op;
    match op {
        Op::Add => Some(StepOp::Add),
        Op::Sub => Some(StepOp::Sub),
        Op::Addi => Some(StepOp::Addi),
        Op::Xor => Some(StepOp::Xor),
        Op::Lui => Some(StepOp::Lui),
        Op::And => Some(StepOp::And),
        Op::Or => Some(StepOp::Or),
        Op::Slt => Some(StepOp::Slt),
        Op::Sltu => Some(StepOp::Sltu),
        Op::Slti => Some(StepOp::Slti),
        Op::Sltiu => Some(StepOp::Sltiu),
        Op::Sll => Some(StepOp::Sll),
        Op::Srl => Some(StepOp::Srl),
        Op::Sra => Some(StepOp::Sra),
        Op::Slli => Some(StepOp::Slli),
        Op::Srli => Some(StepOp::Srli),
        Op::Srai => Some(StepOp::Srai),
        Op::Xori => Some(StepOp::Xori),
        Op::Ori => Some(StepOp::Ori),
        Op::Andi => Some(StepOp::Andi),
        _ => None,
    }
}

fn w_step_op_for(op: magnetar_spec::Op) -> Option<magnetar_cpu::StepOp> {
    use magnetar_cpu::StepOp;
    use magnetar_spec::Op;
    match op {
        Op::Addiw => Some(StepOp::Addi),
        Op::Addw => Some(StepOp::Add),
        Op::Subw => Some(StepOp::Sub),
        Op::Slliw => Some(StepOp::Slli),
        Op::Sllw => Some(StepOp::Sll),
        Op::Srliw => Some(StepOp::Srli),
        Op::Srlw => Some(StepOp::Srl),
        Op::Sraiw => Some(StepOp::Srai),
        Op::Sraw => Some(StepOp::Sra),
        _ => None,
    }
}

fn branch_op_for(op: magnetar_spec::Op) -> Option<magnetar_cpu::BranchOp> {
    use magnetar_cpu::BranchOp;
    use magnetar_spec::Op;
    match op {
        Op::Beq => Some(BranchOp::Beq),
        Op::Bne => Some(BranchOp::Bne),
        Op::Blt => Some(BranchOp::Blt),
        Op::Bge => Some(BranchOp::Bge),
        Op::Bltu => Some(BranchOp::Bltu),
        Op::Bgeu => Some(BranchOp::Bgeu),
        _ => None,
    }
}

pub(crate) fn row_cpu_relation(
    row: &magnetar_spec::TraceRow,
    width: usize,
) -> Result<Option<(ConstraintSystem, Witness)>, RuntimeError> {
    let imm = row.instruction.imm as u64;
    if row.instruction.op.amo_width().is_some() {
        let access = row
            .mem
            .ok_or_else(|| RuntimeError::UnsupportedRow(row.instruction.op.name()))?;
        return magnetar_cpu::uniform_amo_row_relation(
            width,
            row.instruction.op,
            access.addr,
            row.rd_val,
            row.rs2_val,
            access.value,
            row.rs1_val,
            imm,
        )
        .map(Some)
        .ok_or_else(|| RuntimeError::UnsupportedRow(row.instruction.op.name()));
    }
    if matches!(row.instruction.op, magnetar_spec::Op::Mul) {
        let (system, layout) = magnetar_cpu::uniform_mul_relation(width);
        return Ok(Some((system, layout.witness(row.rs1_val, row.rs2_val))));
    }
    if matches!(row.instruction.op, magnetar_spec::Op::Mulh) {
        let (system, layout) = magnetar_cpu::uniform_mulh_relation(width, true, true);
        return Ok(Some((system, layout.witness(row.rs1_val, row.rs2_val))));
    }
    if matches!(row.instruction.op, magnetar_spec::Op::Mulhsu) {
        let (system, layout) = magnetar_cpu::uniform_mulh_relation(width, true, false);
        return Ok(Some((system, layout.witness(row.rs1_val, row.rs2_val))));
    }
    if matches!(row.instruction.op, magnetar_spec::Op::Mulhu) {
        let (system, layout) = magnetar_cpu::uniform_mulh_relation(width, false, false);
        return Ok(Some((system, layout.witness(row.rs1_val, row.rs2_val))));
    }
    if matches!(
        row.instruction.op,
        magnetar_spec::Op::Divu | magnetar_spec::Op::Remu
    ) {
        let (system, layout) = magnetar_cpu::uniform_div_relation(width);
        return Ok(Some((system, layout.witness(row.rs1_val, row.rs2_val))));
    }
    if matches!(
        row.instruction.op,
        magnetar_spec::Op::Div | magnetar_spec::Op::Rem
    ) {
        let (system, layout) = magnetar_cpu::uniform_signed_div_relation(width);
        return Ok(Some((system, layout.witness(row.rs1_val, row.rs2_val))));
    }
    if let Some(step_op) = w_step_op_for(row.instruction.op) {
        let imm = match row.instruction.op {
            magnetar_spec::Op::Slliw | magnetar_spec::Op::Srliw | magnetar_spec::Op::Sraiw => {
                u64::from(row.instruction.shamt)
            }
            _ => imm,
        };
        let (system, witness) = magnetar_cpu::uniform_w_row_relation(
            step_op,
            row.rs1_val,
            row.rs2_val,
            row.rd_val,
            imm,
        );
        return Ok(Some((system, witness)));
    }
    if let Some(step_op) = step_op_for(row.instruction.op) {
        let alu_imm = match row.instruction.op {
            magnetar_spec::Op::Slli | magnetar_spec::Op::Srli | magnetar_spec::Op::Srai => {
                u64::from(row.instruction.shamt)
            }
            _ => imm,
        };
        let (system, layout) = magnetar_cpu::uniform_alu_relation(width);
        return Ok(Some((
            system,
            layout.witness(step_op, row.rs1_val, row.rs2_val, alu_imm),
        )));
    }
    if let Some(branch_op) = branch_op_for(row.instruction.op) {
        let (system, layout) = magnetar_cpu::uniform_branch_layout(width);
        return Ok(Some((
            system,
            layout.witness(branch_op, row.pc, row.rs1_val, row.rs2_val, imm),
        )));
    }
    if matches!(
        row.instruction.op,
        magnetar_spec::Op::ScW | magnetar_spec::Op::ScD
    ) {
        let Some(access) = row.mem else {
            return Ok(None);
        };
        let (system, layout) = magnetar_cpu::simd::uniform_memory_row_layout(64);
        return Ok(Some((
            system,
            layout.witness(row.pc, row.rs1_val, imm, access.value, false),
        )));
    }
    if matches!(
        row.instruction.op,
        magnetar_spec::Op::Ecall | magnetar_spec::Op::Ebreak | magnetar_spec::Op::Fence
    ) {
        return Ok(None);
    }
    if let Some(access) = row.mem {
        if access.is_write {
            let (system, layout) = magnetar_cpu::simd::uniform_memory_row_layout(64);
            return Ok(Some((
                system,
                layout.witness(row.pc, row.rs1_val, imm, access.value, false),
            )));
        }
        let (system, layout) = magnetar_cpu::simd::uniform_memory_row_layout(64);
        return Ok(Some((
            system,
            layout.witness(row.pc, row.rs1_val, imm, row.rd_val, true),
        )));
    }
    match row.instruction.op {
        magnetar_spec::Op::Jal => {
            let (system, layout) =
                magnetar_cpu::uniform_jal_layout(width, u64::from(row.instruction_len));
            Ok(Some((system, layout.witness(row.pc, imm))))
        }
        magnetar_spec::Op::Jalr => {
            let (system, layout) =
                magnetar_cpu::uniform_jalr_layout(width, u64::from(row.instruction_len));
            Ok(Some((system, layout.witness_at(row.pc, row.rs1_val, imm))))
        }
        magnetar_spec::Op::Auipc => {
            let (system, layout) = magnetar_cpu::uniform_auipc_layout(width);
            Ok(Some((system, layout.witness_at(row.pc, imm))))
        }
        magnetar_spec::Op::Ecall | magnetar_spec::Op::Ebreak | magnetar_spec::Op::Fence => Ok(None),
        other => Err(RuntimeError::UnsupportedRow(other.name())),
    }
}

/// One contiguous variable range contributed by a trace row to the merged CPU
/// system. This is the metadata hook for component-aware Virtual Spartan
/// segments; the initial version tags each row as CPU-owned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpuRowKind {
    Alu,
    MulDiv,
    Load,
    Store,
    Amo,
    Branch,
    Jump,
    Auipc,
    System,
}

#[derive(Clone, Debug)]
pub struct CpuWitnessSegment {
    pub cycle: u64,
    pub offset: usize,
    pub len: usize,
    pub owner: SegmentOwner,
    pub kind: SegmentKind,
    pub row_kind: CpuRowKind,
    pub vars: Vec<magnetar_cpu::CpuVarGroup>,
    pub fetch_pc: u64,
    pub rom_word: Option<u32>,
}

fn cpu_row_kind(op: magnetar_spec::Op) -> CpuRowKind {
    use magnetar_spec::Op;
    match op {
        Op::Mul | Op::Mulh | Op::Mulhsu | Op::Mulhu | Op::Div | Op::Divu | Op::Rem | Op::Remu => {
            CpuRowKind::MulDiv
        }
        Op::Lb | Op::Lbu | Op::Lh | Op::Lhu | Op::Lw | Op::Lwu | Op::Ld => CpuRowKind::Load,
        Op::Sb | Op::Sh | Op::Sw | Op::Sd => CpuRowKind::Store,
        Op::AmoswapW
        | Op::AmoswapD
        | Op::AmoaddW
        | Op::AmoaddD
        | Op::AmoxorW
        | Op::AmoxorD
        | Op::AmoandW
        | Op::AmoandD
        | Op::AmoorW
        | Op::AmoorD
        | Op::AmominW
        | Op::AmominD
        | Op::AmomaxW
        | Op::AmomaxD
        | Op::AmominuW
        | Op::AmominuD
        | Op::AmomaxuW
        | Op::AmomaxuD => CpuRowKind::Amo,
        Op::Beq | Op::Bne | Op::Blt | Op::Bge | Op::Bltu | Op::Bgeu => CpuRowKind::Branch,
        Op::Jal | Op::Jalr => CpuRowKind::Jump,
        Op::Auipc => CpuRowKind::Auipc,
        Op::Ecall | Op::Ebreak => CpuRowKind::System,
        _ => CpuRowKind::Alu,
    }
}

#[derive(Clone, Debug, Default)]
pub struct CpuWitnessMetadata {
    pub segments: Vec<CpuWitnessSegment>,
}

impl CpuWitnessMetadata {
    pub fn total_len(&self) -> usize {
        self.segments
            .last()
            .map(|segment| segment.offset + segment.len)
            .unwrap_or(0)
    }
}

fn row_cpu_var_groups(
    row: &magnetar_spec::TraceRow,
    width: usize,
) -> Vec<magnetar_cpu::CpuVarGroup> {
    if row.instruction.op.amo_width().is_some() {
        let Some(access) = row.mem else {
            return Vec::new();
        };
        return magnetar_cpu::uniform_amo_row_groups(
            access.addr,
            access.value,
            row.rs1_val,
            row.instruction.imm as u64,
        );
    }
    if let Some(access) = row.mem {
        let imm = row.instruction.imm as u64;
        if access.is_write {
            let (_system, layout) = magnetar_cpu::uniform_store_row_relation(
                64,
                access.addr,
                row.rs2_val,
                row.rs1_val,
                imm,
            );
            return layout.var_groups();
        }
        let (_system, layout) =
            magnetar_cpu::uniform_load_row_relation(64, access.addr, row.rd_val, row.rs1_val, imm);
        return layout.var_groups();
    }
    if let Some(branch_op) = branch_op_for(row.instruction.op) {
        let imm = row.instruction.imm as u64;
        let (_system, layout) = magnetar_cpu::uniform_branch_row_relation(
            width,
            branch_op,
            row.pc,
            imm,
            row.rs1_val,
            row.rs2_val,
            row.next_pc,
        );
        return layout.var_groups();
    }
    if row.instruction.op == magnetar_spec::Op::Jal {
        let imm = row.instruction.imm as u64;
        let (_system, layout) =
            magnetar_cpu::uniform_jal_row_relation(width, row.pc, imm, row.next_pc, row.rd_val);
        return layout.var_groups();
    }
    if row.instruction.op == magnetar_spec::Op::Jalr {
        let imm = row.instruction.imm as u64;
        let (_system, layout) = magnetar_cpu::uniform_jalr_row_relation(
            width,
            row.pc,
            row.rs1_val,
            imm,
            row.next_pc,
            row.rd_val,
        );
        return layout.var_groups();
    }
    let Some(step_op) = step_op_for(row.instruction.op) else {
        return Vec::new();
    };
    let imm = match row.instruction.op {
        magnetar_spec::Op::Slli | magnetar_spec::Op::Srli | magnetar_spec::Op::Srai => {
            u64::from(row.instruction.shamt)
        }
        _ => row.instruction.imm as u64,
    };
    if let Some((_system, _witness, layout)) = magnetar_cpu::simple_alu_row_relation_with_layout(
        width,
        step_op,
        row.rs1_val,
        row.rs2_val,
        row.rd_val,
        imm,
    ) {
        return layout.var_groups();
    }
    let (_system, layout) = magnetar_cpu::uniform_alu_row_relation(
        width,
        step_op,
        row.rs1_val,
        row.rs2_val,
        row.rd_val,
        imm,
    );
    if matches!(
        row.instruction.op,
        magnetar_spec::Op::Sll
            | magnetar_spec::Op::Srl
            | magnetar_spec::Op::Sra
            | magnetar_spec::Op::Slli
            | magnetar_spec::Op::Srli
            | magnetar_spec::Op::Srai
    ) {
        layout.shift_var_groups()
    } else {
        layout.var_groups()
    }
}

pub(crate) fn merged_cpu_system_with_metadata(
    trace: &Trace,
    width: usize,
) -> Result<(ConstraintSystem, Witness, CpuWitnessMetadata), RuntimeError> {
    let mut merged = ConstraintSystem::new(0);
    let mut values = Vec::new();
    let mut metadata = CpuWitnessMetadata::default();
    for row in &trace.rows {
        if let Some((system, witness)) = row_cpu_relation(row, width)? {
            let offset = merged.merge(system);
            if values.len() != offset {
                return Err(RuntimeError::Proof(
                    "row witness layout does not match the merged system".into(),
                ));
            }
            let len = witness.values().len();
            values.extend_from_slice(witness.values());
            if len != 0 {
                let vars = row_cpu_var_groups(row, width)
                    .into_iter()
                    .map(|group| magnetar_cpu::CpuVarGroup {
                        kind: group.kind,
                        vars: group.vars.iter().map(|var| var + offset).collect(),
                    })
                    .collect();
                let word_index = ((row.pc.saturating_sub(trace.config.rom_base)) / 4) as usize;
                metadata.segments.push(CpuWitnessSegment {
                    cycle: row.cycle,
                    offset,
                    len,
                    owner: SegmentOwner::Cpu,
                    kind: SegmentKind::Direct,
                    row_kind: cpu_row_kind(row.instruction.op),
                    vars,
                    fetch_pc: row.pc,
                    rom_word: trace.rom.get(word_index).copied(),
                });
            }
        }
    }
    Ok((merged, Witness::new(values), metadata))
}

pub(crate) fn merged_cpu_system(
    trace: &Trace,
    width: usize,
) -> Result<(ConstraintSystem, Witness), RuntimeError> {
    let (system, witness, _metadata) = merged_cpu_system_with_metadata(trace, width)?;
    Ok((system, witness))
}

fn merged_cpu_system_for_rows(
    rows: &[magnetar_spec::TraceRow],
    width: usize,
) -> Result<(ConstraintSystem, Witness), RuntimeError> {
    let mut merged = ConstraintSystem::new(0);
    let mut values = Vec::new();
    for row in rows {
        if let Some((system, witness)) = row_cpu_relation(row, width)? {
            let offset = merged.merge(system);
            if values.len() != offset {
                return Err(RuntimeError::Proof(
                    "row witness layout does not match the merged system".into(),
                ));
            }
            values.extend_from_slice(witness.values());
        }
    }
    Ok((merged, Witness::new(values)))
}

/// Constraint-system size of one CPU row (zero for rows without a CPU relation).
#[derive(Clone, Debug, Default)]
pub struct RowCpuStats {
    pub cycle: u64,
    pub pc: u64,
    pub op: &'static str,
    pub variables: usize,
    pub constraints: usize,
}

/// Merged CPU constraint-system size for a whole trace at a witness width.
#[derive(Clone, Debug, Default)]
pub struct TraceCpuStats {
    pub width: usize,
    pub variables: usize,
    pub constraints: usize,
    pub rows: Vec<RowCpuStats>,
}

/// Report per-row and total CPU constraint sizes without constructing a proof.
pub fn trace_cpu_stats(trace: &Trace, width: usize) -> Result<TraceCpuStats, RuntimeError> {
    let mut stats = TraceCpuStats {
        width,
        ..TraceCpuStats::default()
    };
    for row in &trace.rows {
        let (variables, constraints) = match row_cpu_relation(row, width)? {
            Some((system, _)) => (system.num_vars, system.constraints.len()),
            None => (0, 0),
        };
        stats.variables = stats
            .variables
            .checked_add(variables)
            .ok_or_else(|| RuntimeError::Proof("constraint statistics overflow".into()))?;
        stats.constraints = stats
            .constraints
            .checked_add(constraints)
            .ok_or_else(|| RuntimeError::Proof("constraint statistics overflow".into()))?;
        stats.rows.push(RowCpuStats {
            cycle: row.cycle,
            pc: row.pc,
            op: row.instruction.op.name(),
            variables,
            constraints,
        });
    }
    Ok(stats)
}

fn apply_trace_write(
    trace: &Trace,
    ram: &mut [u8],
    access: magnetar_spec::MemoryAccess,
) -> Result<(), RuntimeError> {
    let width = usize::from(access.width);
    let start = trace
        .config
        .ram_index(access.addr, width)
        .ok_or(RuntimeError::AddressOutOfTable(access.addr))?;
    let bytes = access.value.to_le_bytes();
    let target = ram
        .get_mut(start..start + width)
        .ok_or_else(|| RuntimeError::Proof("trace RAM is too short".into()))?;
    target.copy_from_slice(&bytes[..width]);
    Ok(())
}

fn check_io_reads(trace: &Trace) -> Result<(), RuntimeError> {
    let mut ram = trace.initial_ram.clone();
    let mut cursor = 0usize;
    for (index, row) in trace.rows.iter().enumerate() {
        if let Some(access) = row.mem {
            if access.is_write {
                apply_trace_write(trace, &mut ram, access)?;
            }
        }
        if row.instruction.op != magnetar_spec::Op::Ecall && row.syscall.is_some() {
            return Err(RuntimeError::Proof(format!(
                "row {index} records syscall metadata on a non-ecall row"
            )));
        }
        let Some(syscall) = row.syscall else {
            if !row.extra_mem.is_empty() {
                return Err(RuntimeError::Proof(format!(
                    "row {index} has extra memory writes without a syscall"
                )));
            }
            continue;
        };
        if syscall.number != magnetar_spec::syscall::SYS_READ {
            if row.mem.is_some() || !row.extra_mem.is_empty() {
                return Err(RuntimeError::Proof(format!(
                    "row {index} non-read syscall wrote memory"
                )));
            }
            continue;
        }
        if syscall.args[0] != 0 || row.rd != Some(10) || row.mem.is_some() {
            return Err(RuntimeError::Proof(format!(
                "row {index} has an unsupported read shape"
            )));
        }
        let requested = syscall.args[2];
        let actual = row.rd_val;
        if actual > requested {
            return Err(RuntimeError::Proof(format!(
                "row {index} short read returned more than requested"
            )));
        }
        let remaining = trace.io_input.len().saturating_sub(cursor);
        if actual == 0 {
            if requested != 0 && remaining != 0 {
                return Err(RuntimeError::Proof(format!(
                    "row {index} read returned zero while input remained"
                )));
            }
            if !row.extra_mem.is_empty() {
                return Err(RuntimeError::Proof(format!(
                    "row {index} zero-length read wrote memory"
                )));
            }
            continue;
        }
        if actual < requested && usize::try_from(actual).ok() != Some(remaining) {
            return Err(RuntimeError::Proof(format!(
                "row {index} short read did not consume the remaining input"
            )));
        }
        let len = usize::try_from(actual)
            .map_err(|_| RuntimeError::Proof(format!("row {index} read length is too large")))?;
        if row.extra_mem.is_empty() {
            continue;
        }
        let ptr = syscall.args[1];
        let end = ptr
            .checked_add(actual)
            .ok_or_else(|| RuntimeError::Proof(format!("row {index} read pointer overflow")))?;
        let lane = usize::try_from(ptr & 7).expect("lane fits");
        let first = ptr & !7;
        let words = lane
            .checked_add(len)
            .and_then(|value| value.checked_add(7))
            .map(|value| value / 8)
            .ok_or_else(|| RuntimeError::Proof(format!("row {index} read length overflow")))?;
        if row.extra_mem.len() != words {
            return Err(RuntimeError::Proof(format!(
                "row {index} read write-back count does not match its length"
            )));
        }
        let input = trace
            .io_input
            .get(cursor..cursor + len)
            .ok_or_else(|| RuntimeError::Proof("trace read input is truncated".into()))?;
        for (chunk, access) in row.extra_mem.iter().enumerate() {
            let expected_addr = first
                .checked_add(8 * chunk as u64)
                .ok_or_else(|| RuntimeError::Proof(format!("row {index} read address overflow")))?;
            if access.addr != expected_addr || !access.is_write || access.width != 8 {
                return Err(RuntimeError::Proof(format!(
                    "row {index} read write-back does not match its arguments"
                )));
            }
            let start = trace
                .config
                .ram_index(expected_addr, 8)
                .ok_or(RuntimeError::AddressOutOfTable(expected_addr))?;
            let mut expected = [0u8; 8];
            expected.copy_from_slice(
                ram.get(start..start + 8)
                    .ok_or_else(|| RuntimeError::Proof("trace RAM is too short".into()))?,
            );
            for (offset, byte) in expected.iter_mut().enumerate() {
                let address = expected_addr
                    .checked_add(offset as u64)
                    .ok_or_else(|| RuntimeError::Proof(format!("row {index} read overflow")))?;
                if address >= ptr && address < end {
                    *byte = input[(address - ptr) as usize];
                }
            }
            if access.value.to_le_bytes() != expected {
                return Err(RuntimeError::Proof(format!(
                    "row {index} read write-back does not preserve surrounding bytes"
                )));
            }
        }
        for access in &row.extra_mem {
            apply_trace_write(trace, &mut ram, *access)?;
        }
        cursor += len;
    }
    if cursor != trace.io_input.len() {
        return Err(RuntimeError::Proof(
            "trace read data does not match consumed input".into(),
        ));
    }
    Ok(())
}

fn check_io_writes(trace: &Trace) -> Result<(), RuntimeError> {
    let mut ram = trace.initial_ram.clone();
    let mut cursor = 0usize;
    for (index, row) in trace.rows.iter().enumerate() {
        if let Some(access) = row.mem {
            if access.is_write {
                let width = usize::from(access.width);
                let start = trace
                    .config
                    .ram_index(access.addr, width)
                    .ok_or(RuntimeError::AddressOutOfTable(access.addr))?;
                let bytes = access.value.to_le_bytes();
                let target = ram
                    .get_mut(start..start + width)
                    .ok_or_else(|| RuntimeError::Proof("trace RAM is too short".into()))?;
                target.copy_from_slice(&bytes[..width]);
            }
        }
        for access in &row.extra_mem {
            let width = usize::from(access.width);
            let start = trace
                .config
                .ram_index(access.addr, width)
                .ok_or(RuntimeError::AddressOutOfTable(access.addr))?;
            let bytes = access.value.to_le_bytes();
            let target = ram
                .get_mut(start..start + width)
                .ok_or_else(|| RuntimeError::Proof("trace RAM is too short".into()))?;
            target.copy_from_slice(&bytes[..width]);
        }
        let Some(syscall) = row.syscall else {
            continue;
        };
        if syscall.number != magnetar_spec::syscall::SYS_WRITE {
            continue;
        }
        if syscall.args[0] != 1 && syscall.args[0] != 2 {
            return Err(RuntimeError::Proof(format!(
                "row {index} write syscall has an unsupported fd"
            )));
        }
        let len = usize::try_from(syscall.args[2]).map_err(|_| {
            RuntimeError::Proof(format!("row {index} write syscall length is too large"))
        })?;
        let start = trace
            .config
            .ram_index(syscall.args[1], len)
            .ok_or(RuntimeError::AddressOutOfTable(syscall.args[1]))?;
        let end = cursor
            .checked_add(len)
            .ok_or_else(|| RuntimeError::Proof("write syscall output overflow".into()))?;
        let written = trace
            .io_output
            .get(cursor..end)
            .ok_or_else(|| RuntimeError::Proof("write syscall output is truncated".into()))?;
        let buffer = ram
            .get(start..start + len)
            .ok_or_else(|| RuntimeError::Proof("trace RAM is too short".into()))?;
        if written != buffer {
            return Err(RuntimeError::Proof(format!(
                "row {index} write syscall output does not match RAM"
            )));
        }
        cursor = end;
    }
    if cursor != trace.io_output.len() {
        return Err(RuntimeError::Proof(
            "trace output contains bytes from an unknown syscall".into(),
        ));
    }
    Ok(())
}

pub(crate) fn check_trace_linkage(trace: &Trace) -> Result<(), RuntimeError> {
    check_trace(trace)?;
    check_io_reads(trace)?;
    check_io_writes(trace)?;
    let mut expected_pc = trace.config.entry;
    let mut expected_reservation = None;
    for (index, row) in trace.rows.iter().enumerate() {
        if row.pc != expected_pc {
            return Err(RuntimeError::Proof(format!(
                "row {index} pc {:#x} does not follow the previous row",
                row.pc
            )));
        }
        let offset = row
            .pc
            .checked_sub(trace.config.rom_base)
            .ok_or_else(|| RuntimeError::Proof(format!("row {index} pc is below ROM base")))?;
        if !offset.is_multiple_of(2) {
            return Err(RuntimeError::Proof(format!(
                "row {index} pc is not 2-byte aligned"
            )));
        }
        let rom_index = usize::try_from(offset / 4)
            .map_err(|_| RuntimeError::Proof(format!("row {index} pc is out of ROM range")))?;
        let word =
            trace.rom.get(rom_index).copied().ok_or_else(|| {
                RuntimeError::Proof(format!("row {index} pc is out of ROM range"))
            })?;
        let raw = if offset % 4 == 2 {
            (word >> 16) & 0xffff
        } else {
            word & 0xffff
        };
        let expected_len = if offset % 4 == 0 && raw & 0x3 == 0x3 {
            4
        } else {
            2
        };
        let expected_word = if expected_len == 4 { word } else { raw };
        let decoded = if expected_len == 4 {
            decode(word).map_err(|_| {
                RuntimeError::Proof(format!("row {index} has an illegal instruction"))
            })?
        } else {
            decode_compressed(raw as u16).map_err(|_| {
                RuntimeError::Proof(format!(
                    "row {index} has an unsupported compressed instruction"
                ))
            })?
        };
        if row.instruction_len != expected_len
            || row.instruction_word != expected_word
            || row.instruction != decoded
        {
            return Err(RuntimeError::Proof(format!(
                "row {index} instruction does not match the ROM image"
            )));
        }
        if row.reservation_before != expected_reservation {
            return Err(RuntimeError::Proof(format!(
                "row {index} reservation does not follow the previous row"
            )));
        }
        expected_pc = row.next_pc;
        expected_reservation = row.reservation_after;
    }
    if let Some(last) = trace.rows.last() {
        if last.next_pc != trace.final_state.pc {
            return Err(RuntimeError::Proof(
                "last row does not link to the final machine pc".into(),
            ));
        }
    }
    Ok(())
}

pub fn prove_trace_proof(trace: &Trace, width: usize) -> Result<TraceProof, RuntimeError> {
    check_trace_linkage(trace)?;
    let access = prove_trace_access(trace)?;
    let mut rows = Vec::with_capacity(trace.rows.len());
    let backend = ConstraintProofBackend::default();

    for row in &trace.rows {
        let Some((system, witness)) = row_cpu_relation(row, width)? else {
            rows.push(RowCpuProof::Skip);
            continue;
        };
        let proof = backend.prove(&system, &witness)?;
        let row_proof = if matches!(row.instruction.op, magnetar_spec::Op::Mul) {
            RowCpuProof::Mul(proof)
        } else if matches!(row.instruction.op, magnetar_spec::Op::Mulh) {
            RowCpuProof::Mulh(proof)
        } else if matches!(row.instruction.op, magnetar_spec::Op::Mulhsu) {
            RowCpuProof::Mulhsu(proof)
        } else if matches!(row.instruction.op, magnetar_spec::Op::Mulhu) {
            RowCpuProof::Mulhu(proof)
        } else if matches!(row.instruction.op, magnetar_spec::Op::Divu) {
            RowCpuProof::Divu(proof)
        } else if matches!(row.instruction.op, magnetar_spec::Op::Remu) {
            RowCpuProof::Remu(proof)
        } else if matches!(row.instruction.op, magnetar_spec::Op::Div) {
            RowCpuProof::Div(proof)
        } else if matches!(row.instruction.op, magnetar_spec::Op::Rem) {
            RowCpuProof::Rem(proof)
        } else if w_step_op_for(row.instruction.op).is_some() {
            RowCpuProof::W(proof)
        } else if row.instruction.op.amo_width().is_some() {
            RowCpuProof::Amo(proof)
        } else if step_op_for(row.instruction.op).is_some() {
            RowCpuProof::Alu(proof)
        } else if branch_op_for(row.instruction.op).is_some() {
            RowCpuProof::Branch(proof)
        } else if let Some(access) = row.mem {
            if access.is_write {
                RowCpuProof::Store(proof)
            } else {
                RowCpuProof::Load(proof)
            }
        } else {
            match row.instruction.op {
                magnetar_spec::Op::Jal => RowCpuProof::Jal(proof),
                magnetar_spec::Op::Jalr => RowCpuProof::Jalr(proof),
                magnetar_spec::Op::Auipc => RowCpuProof::Auipc(proof),
                _ => {
                    return Err(RuntimeError::Proof(
                        "row has a CPU relation but no proof variant".into(),
                    ))
                }
            }
        };
        rows.push(row_proof);
    }

    Ok(TraceProof {
        access,
        trace_commitment: trace_digest(trace),
        rows,
    })
}

pub fn verify_trace_proof(
    trace: &Trace,
    proof: &TraceProof,
    width: usize,
) -> Result<(), RuntimeError> {
    check_trace_linkage(trace)?;
    if proof.trace_commitment != trace_digest(trace) {
        return Err(RuntimeError::Proof(
            "trace proof does not match the supplied trace".into(),
        ));
    }
    verify_trace_access(trace, &proof.access)?;
    if proof.rows.len() != trace.rows.len() {
        return Err(RuntimeError::Proof("trace row count mismatch".into()));
    }
    let backend = ConstraintProofBackend::default();
    for (index, (row, row_proof)) in trace.rows.iter().zip(proof.rows.iter()).enumerate() {
        let Some((system, _)) = row_cpu_relation(row, width)? else {
            if !matches!(row_proof, RowCpuProof::Skip) {
                return Err(RuntimeError::Proof(format!(
                    "row {index} expected skip proof"
                )));
            }
            continue;
        };
        let verified = if matches!(row.instruction.op, magnetar_spec::Op::Mul) {
            matches!(row_proof, RowCpuProof::Mul(_))
        } else if matches!(row.instruction.op, magnetar_spec::Op::Mulh) {
            matches!(row_proof, RowCpuProof::Mulh(_))
        } else if matches!(row.instruction.op, magnetar_spec::Op::Mulhsu) {
            matches!(row_proof, RowCpuProof::Mulhsu(_))
        } else if matches!(row.instruction.op, magnetar_spec::Op::Mulhu) {
            matches!(row_proof, RowCpuProof::Mulhu(_))
        } else if matches!(row.instruction.op, magnetar_spec::Op::Divu) {
            matches!(row_proof, RowCpuProof::Divu(_))
        } else if matches!(row.instruction.op, magnetar_spec::Op::Remu) {
            matches!(row_proof, RowCpuProof::Remu(_))
        } else if matches!(row.instruction.op, magnetar_spec::Op::Div) {
            matches!(row_proof, RowCpuProof::Div(_))
        } else if matches!(row.instruction.op, magnetar_spec::Op::Rem) {
            matches!(row_proof, RowCpuProof::Rem(_))
        } else if w_step_op_for(row.instruction.op).is_some() {
            matches!(row_proof, RowCpuProof::W(_))
        } else if row.instruction.op.amo_width().is_some() {
            matches!(row_proof, RowCpuProof::Amo(_))
        } else if step_op_for(row.instruction.op).is_some() {
            matches!(row_proof, RowCpuProof::Alu(_))
        } else if branch_op_for(row.instruction.op).is_some() {
            matches!(row_proof, RowCpuProof::Branch(_))
        } else if let Some(access) = row.mem {
            if access.is_write {
                matches!(row_proof, RowCpuProof::Store(_))
            } else {
                matches!(row_proof, RowCpuProof::Load(_))
            }
        } else {
            match row.instruction.op {
                magnetar_spec::Op::Jal => matches!(row_proof, RowCpuProof::Jal(_)),
                magnetar_spec::Op::Jalr => matches!(row_proof, RowCpuProof::Jalr(_)),
                magnetar_spec::Op::Auipc => matches!(row_proof, RowCpuProof::Auipc(_)),
                _ => false,
            }
        };
        if !verified {
            return Err(RuntimeError::Proof(format!(
                "row {index} has the wrong CPU proof variant"
            )));
        }
        match row_proof {
            RowCpuProof::Alu(spartan)
            | RowCpuProof::Mul(spartan)
            | RowCpuProof::Mulh(spartan)
            | RowCpuProof::Mulhsu(spartan)
            | RowCpuProof::Mulhu(spartan)
            | RowCpuProof::Divu(spartan)
            | RowCpuProof::Remu(spartan)
            | RowCpuProof::Div(spartan)
            | RowCpuProof::Rem(spartan)
            | RowCpuProof::W(spartan)
            | RowCpuProof::Amo(spartan)
            | RowCpuProof::Branch(spartan)
            | RowCpuProof::Store(spartan)
            | RowCpuProof::Load(spartan)
            | RowCpuProof::Jal(spartan)
            | RowCpuProof::Jalr(spartan)
            | RowCpuProof::Auipc(spartan) => {
                backend.verify(&system, spartan)?;
            }
            RowCpuProof::Skip => {
                return Err(RuntimeError::Proof(format!(
                    "row {index} expected a CPU proof"
                )))
            }
        }
    }
    Ok(())
}

pub(crate) fn split_cpu_relations(
    system: &ConstraintSystem,
) -> (ConstraintSystem, ConstraintSystem) {
    let mut even = ConstraintSystem::new(system.num_vars);
    let mut odd = ConstraintSystem::new(system.num_vars);
    even.public_inputs = system.public_inputs.clone();
    odd.public_inputs = system.public_inputs.clone();
    for (index, constraint) in system.constraints.iter().enumerate() {
        if index % 2 == 0 {
            even.constraints.push(constraint.clone());
        } else {
            odd.constraints.push(constraint.clone());
        }
    }
    let rows = even.constraints.len().max(odd.constraints.len());
    let zero = || {
        Constraint::new(
            Expr::constant(0u64),
            Expr::constant(0u64),
            Expr::constant(0u64),
        )
    };
    while even.constraints.len() < rows {
        even.constraints.push(zero());
    }
    while odd.constraints.len() < rows {
        odd.constraints.push(zero());
    }
    (even, odd)
}

pub(crate) fn cpu_segment_layout(len: usize) -> Result<WitnessLayout, RuntimeError> {
    let chunk = if len >= 2 { len / 2 } else { len };
    let mut segments = Vec::new();
    let mut offset = 0;
    let mut index = 0;
    while offset < len {
        let size = chunk.min(len - offset);
        segments.push(Segment::new(
            format!("cpu{index}"),
            offset,
            size,
            SegmentKind::Direct,
            SegmentOwner::Cpu,
        ));
        offset += size;
        index += 1;
    }
    WitnessLayout::new(segments).map_err(|error| RuntimeError::Proof(error.to_string()))
}

/// Standalone lockstep CPU proof over the merged row system.
///
/// The reference has one packed relation, so both sides use the same system;
/// this exercises the lockstep outer/inner path and segment claim routing on
/// the real CPU witness.
pub fn prove_cpu_lockstep(
    trace: &Trace,
    width: usize,
) -> Result<LockstepProof<P3Commitment, P3Opening>, RuntimeError> {
    let (system, witness) = merged_cpu_system(trace, width)?;
    let (system_a, system_b) = split_cpu_relations(&system);
    let z = witness_vector(&system, &witness)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let layout = cpu_segment_layout(z.len())?;
    let pcs = P3BinaryPcs::new(100);
    prove_lockstep(&system_a, &system_b, &witness, &layout, &pcs)
        .map_err(|error| RuntimeError::Proof(error.to_string()))
}

pub fn verify_cpu_lockstep(
    trace: &Trace,
    proof: &LockstepProof<P3Commitment, P3Opening>,
    width: usize,
) -> Result<(), RuntimeError> {
    let (system, witness) = merged_cpu_system(trace, width)?;
    let (system_a, system_b) = split_cpu_relations(&system);
    let z = witness_vector(&system, &witness)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let layout = cpu_segment_layout(z.len())?;
    let pcs = P3BinaryPcs::new(100);
    verify_lockstep(&system_a, &system_b, &layout, proof, &pcs)
        .map_err(|error| RuntimeError::Proof(error.to_string()))
}

pub(crate) fn prove_unified_with_plan(
    trace: &Trace,
    width: usize,
    plan: &crate::protocol::ProtocolPlan,
) -> Result<UnifiedTraceProof, RuntimeError> {
    let mut context = crate::protocol::UnifiedProveContext::new(trace, width)?;
    for stage in plan.execution() {
        match stage {
            crate::protocol::ExecutionStage::Commit => context.commit()?,
            crate::protocol::ExecutionStage::Access => context.prove_access()?,
            crate::protocol::ExecutionStage::Shout => context.prove_shout()?,
            crate::protocol::ExecutionStage::ShiftRouter => context.prove_shift_router()?,
            crate::protocol::ExecutionStage::StoreRouter => context.prove_store_router()?,
            crate::protocol::ExecutionStage::RegisterAndTrace => {
                context.prove_register_and_trace()?
            }
            crate::protocol::ExecutionStage::Cpu => context.prove_cpu()?,
            crate::protocol::ExecutionStage::Opening => context.prove_opening()?,
        }
    }
    context.finish()
}

#[allow(dead_code)]
pub(crate) fn prove_unified_inner(
    trace: &Trace,
    width: usize,
) -> Result<UnifiedTraceProof, RuntimeError> {
    prove_unified_with_plan(trace, width, &crate::protocol::ProtocolPlan::unified())
}

pub fn prove_unified_trace(trace: &Trace, width: usize) -> Result<UnifiedTraceProof, RuntimeError> {
    crate::protocol::Orchestrator::default().prove(trace, width)
}

pub(crate) fn verify_unified_with_plan(
    trace: &Trace,
    proof: &UnifiedTraceProof,
    width: usize,
    plan: &crate::protocol::ProtocolPlan,
) -> Result<(), RuntimeError> {
    let mut context = crate::protocol::UnifiedVerifyContext::new(trace, proof, width)?;
    for stage in plan.execution() {
        match stage {
            crate::protocol::ExecutionStage::Commit => {}
            crate::protocol::ExecutionStage::Access => context.verify_access()?,
            crate::protocol::ExecutionStage::Shout => context.verify_shout()?,
            crate::protocol::ExecutionStage::ShiftRouter => context.verify_shift_router()?,
            crate::protocol::ExecutionStage::StoreRouter => context.verify_store_router()?,
            crate::protocol::ExecutionStage::RegisterAndTrace => {
                context.verify_register_and_trace()?
            }
            crate::protocol::ExecutionStage::Cpu => context.verify_cpu()?,
            crate::protocol::ExecutionStage::Opening => context.verify_opening()?,
        }
    }
    let has_amo = crate::amo_bundle::has_amo_events(trace);
    if has_amo != proof.amo.is_some() {
        return Err(RuntimeError::Proof(
            "AMO bundle presence does not match the trace".into(),
        ));
    }
    if let Some(amo) = &proof.amo {
        crate::amo_bundle::verify_amo_bundle(trace, width, amo)?;
    }
    if let Some(mut routed) = context.take_routed_claims() {
        plan.check_virtual_claims(&routed)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        plan.consume_virtual_claims(&mut routed)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn verify_unified_inner(
    trace: &Trace,
    proof: &UnifiedTraceProof,
    width: usize,
) -> Result<(), RuntimeError> {
    verify_unified_with_plan(
        trace,
        proof,
        width,
        &crate::protocol::ProtocolPlan::unified(),
    )
}

/// Verify a unified proof against the public statement before rebuilding the
/// row systems. Program identity is bound through the ROM carried by the trace.
pub fn prove_unified_revealed(
    trace: &Trace,
    width: usize,
) -> Result<UnifiedTraceProof, RuntimeError> {
    let mut proof = prove_unified_trace(trace, width)?;
    proof.opening = None;
    Ok(proof)
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CpuStatement {
    pub width: usize,
    pub shape: crate::cpu_shape::CpuShape,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CoreStatement {
    pub width: usize,
    pub shape: crate::cpu_shape::CpuShape,
}

/// Verify the whole core proof with no trace or statement.
pub fn verify_core_proof(proof: &UnifiedTraceProof) -> Result<(), RuntimeError> {
    let statement = CoreStatement {
        width: proof.width,
        shape: proof.shape.clone(),
    };
    verify_core_statement(proof, &statement)
}

/// Verify CPU, gated, and access claims without a trace.
pub fn verify_core_statement(
    proof: &UnifiedTraceProof,
    statement: &CoreStatement,
) -> Result<(), RuntimeError> {
    let cpu = CpuStatement {
        width: statement.width,
        shape: statement.shape.clone(),
    };
    let (ry, cpu_value, gated_ry) = cpu_statement_claims(proof, &cpu)?;
    let (ram_claims, register_claims) = crate::access_statement::access_claims_from_proof(proof)?;
    let (mut points, mut values) = ram_claims;
    points.extend(register_claims.0);
    values.extend(register_claims.1);
    points.push(magnetar_pcs::P3MosaicPoint {
        table: 0,
        point: ry,
        columns: vec![0],
        next_columns: Vec::new(),
    });
    values.push(vec![cpu_value]);
    if let (Some(gated), Some(gated_ry)) = (&proof.gated, gated_ry) {
        points.push(magnetar_pcs::P3MosaicPoint {
            table: gated.table,
            point: gated_ry,
            columns: vec![0],
            next_columns: Vec::new(),
        });
        values.push(vec![gated.value]);
    }
    if let (Some(shout), Some(index)) = (&proof.shout, proof.shout_index) {
        let (aux_points, aux_values) = crate::binary_shout::verify_binary_shout_from_proof(
            shout,
            &proof.cpu.commitment,
            index,
            b"",
        )
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .ok_or_else(|| RuntimeError::Proof("Shout claims rejected".into()))?;
        points.extend(aux_points);
        values.extend(aux_values);
    }
    for (router, index) in [
        (&proof.shift_router, proof.shift_router_index),
        (&proof.store_router, proof.store_router_index),
    ] {
        if let (Some(router), Some(index)) = (router, index) {
            let (aux_points, aux_values) = crate::binary_router::verify_binary_router_from_proof(
                router,
                &proof.cpu.commitment,
                index,
                b"",
            )
            .map_err(|error| RuntimeError::Proof(error.to_string()))?
            .ok_or_else(|| RuntimeError::Proof("Router claims rejected".into()))?;
            points.extend(aux_points);
            values.extend(aux_values);
        }
    }
    for point in &points {
        eprintln!("core point table {} cols {:?}", point.table, point.columns);
    }
    for (point, value) in &proof.trace_claims {
        points.push(point.clone());
        values.push(value.clone());
    }
    let mut pairs = points.into_iter().zip(values).collect::<Vec<_>>();
    pairs.sort_by_key(|(point, _)| point.table);
    let (points, values): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
    if let Some(opening) = &proof.opening {
        let pcs = magnetar_pcs::P3BinaryPcs::with_params(100, 4, 16, 3);
        if !pcs
            .verify_mosaic(opening, &points, &values)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?
        {
            return Err(RuntimeError::Proof("core opening rejected".into()));
        }
    }
    Ok(())
}

/// Verify only the CPU lockstep claims, without a trace.
pub fn verify_cpu_statement(
    proof: &UnifiedTraceProof,
    statement: &CpuStatement,
) -> Result<(), RuntimeError> {
    cpu_statement_claims(proof, statement).map(|_| ())
}

#[allow(clippy::type_complexity)]
pub(crate) fn cpu_statement_claims(
    proof: &UnifiedTraceProof,
    statement: &CpuStatement,
) -> Result<(Vec<F2_128>, F2_128, Option<Vec<F2_128>>), RuntimeError> {
    if proof.shape != statement.shape {
        return Err(RuntimeError::Proof("CPU statement shape mismatch".into()));
    }
    let (system, witness_len) = statement.shape.system_without_trace(statement.width)?;
    let (system_a, system_b) = split_cpu_relations(&system);
    let layout = cpu_segment_layout(witness_len)?;
    let pcs = magnetar_pcs::P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    let (ry, _segments, value) =
        magnetar_proof::verify_lockstep_claims(&system_a, &system_b, &layout, &proof.cpu, &pcs)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let gated_ry = if let Some(gated) = &proof.gated {
        let (a0, a1, gated_layout) =
            crate::simd_dual::reservation_claim_matrices(statement.width, gated.cycles)?;
        let (gated_ry, _segments, _value) =
            magnetar_proof::spartan::verify_lockstep_claims_with_matrices(
                &a0[0],
                &a0[1],
                &a0[2],
                &a1[0],
                &a1[1],
                &a1[2],
                &gated_layout,
                &gated.claims,
                &pcs,
            )
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        Some(gated_ry)
    } else {
        None
    };
    Ok((ry, value, gated_ry))
}

pub fn verify_unified_trace(
    trace: &Trace,
    proof: &UnifiedTraceProof,
    width: usize,
) -> Result<(), RuntimeError> {
    crate::protocol::Orchestrator::default().verify(trace, proof, width)
}

pub fn verify_unified_trace_statement(
    statement: &Statement,
    trace: &Trace,
    proof: &UnifiedTraceProof,
    width: usize,
) -> Result<(), RuntimeError> {
    if statement.trace_len != trace.rows.len() as u64
        || statement.initial_state != trace.initial_state
        || statement.initial_ram != trace.initial_ram
        || statement.final_state != trace.final_state
        || statement.trace_commitment != proof.trace_commitment
        || statement.rom != trace.rom
        || statement.program_hash != rom_hash(&statement.rom)
        || statement.output != trace.io_output
        || statement.input != trace.io_input
    {
        return Err(RuntimeError::Proof(
            "public statement does not match the trace".into(),
        ));
    }
    verify_unified_trace(trace, proof, width)
}

/// Canonical proof-format encoding for the per-row trace proof.
pub fn encode_trace_proof(proof: &TraceProof) -> Result<Vec<u8>, RuntimeError> {
    bincode::serialize(proof).map_err(|error| RuntimeError::Proof(error.to_string()))
}

pub fn decode_trace_proof(bytes: &[u8]) -> Result<TraceProof, RuntimeError> {
    bincode::deserialize(bytes).map_err(|error| RuntimeError::Proof(error.to_string()))
}

/// Canonical proof-format encoding for a unified trace proof.
pub fn encode_unified_proof(proof: &UnifiedTraceProof) -> Result<Vec<u8>, RuntimeError> {
    bincode::serialize(proof).map_err(|error| RuntimeError::Proof(error.to_string()))
}

/// Serialized size of each unified-proof component.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnifiedProofSizes {
    pub access: usize,
    pub cpu: usize,
    pub opening: usize,
    pub shout: usize,
    pub shift_router: usize,
    pub store_router: usize,
}

impl UnifiedProofSizes {
    pub fn total(&self) -> usize {
        self.access + self.cpu + self.opening + self.shout + self.shift_router + self.store_router
    }
}

pub fn unified_proof_sizes(proof: &UnifiedTraceProof) -> Result<UnifiedProofSizes, RuntimeError> {
    let size = |bytes: Result<Vec<u8>, bincode::Error>| -> Result<usize, RuntimeError> {
        bytes
            .map(|bytes| bytes.len())
            .map_err(|error| RuntimeError::Proof(error.to_string()))
    };
    Ok(UnifiedProofSizes {
        access: size(bincode::serialize(&proof.access))?,
        cpu: size(bincode::serialize(&proof.cpu))?,
        opening: size(bincode::serialize(&proof.opening))?,
        shout: size(bincode::serialize(&proof.shout))?,
        shift_router: size(bincode::serialize(&proof.shift_router))?,
        store_router: size(bincode::serialize(&proof.store_router))?,
    })
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ChunkedProofSizes {
    pub access: usize,
    pub cpu: usize,
    pub aux: usize,
    pub chain: usize,
}

impl ChunkedProofSizes {
    pub fn total(&self) -> usize {
        self.access + self.cpu + self.aux + self.chain
    }
}

pub fn chunked_proof_sizes(proof: &ChunkedTraceProof) -> Result<ChunkedProofSizes, RuntimeError> {
    let size = |bytes: Result<Vec<u8>, bincode::Error>| {
        bytes
            .map(|bytes| bytes.len())
            .map_err(|error| RuntimeError::Proof(error.to_string()))
    };
    Ok(ChunkedProofSizes {
        access: size(bincode::serialize(&proof.access))?,
        cpu: size(bincode::serialize(&proof.chunks))?,
        aux: size(bincode::serialize(&proof.aux))?,
        chain: size(bincode::serialize(&proof.chain))?,
    })
}

pub fn decode_unified_proof(bytes: &[u8]) -> Result<UnifiedTraceProof, RuntimeError> {
    bincode::deserialize(bytes).map_err(|error| RuntimeError::Proof(error.to_string()))
}

pub fn encode_chunked_proof(proof: &ChunkedTraceProof) -> Result<Vec<u8>, RuntimeError> {
    bincode::serialize(proof).map_err(|error| RuntimeError::Proof(error.to_string()))
}

pub fn decode_chunked_proof(bytes: &[u8]) -> Result<ChunkedTraceProof, RuntimeError> {
    bincode::deserialize(bytes).map_err(|error| RuntimeError::Proof(error.to_string()))
}

#[allow(dead_code)]
fn trace_from_statement(
    statement: &Statement,
    rows: &[magnetar_spec::TraceRow],
    rom: &[u32],
) -> Result<Trace, RuntimeError> {
    if !statement.config.ram_size.is_multiple_of(8) {
        return Err(RuntimeError::Proof(
            "standalone verification requires an 8-byte-aligned RAM size".into(),
        ));
    }
    if statement.initial_ram.len() != statement.config.ram_size {
        return Err(RuntimeError::Proof(
            "statement initial RAM does not match the machine config".into(),
        ));
    }
    let initial_ram = statement.initial_ram.clone();
    let memory_events = rows
        .iter()
        .flat_map(|row| {
            row.mem
                .into_iter()
                .chain(row.extra_mem.iter().copied())
                .map(|access| magnetar_spec::MemoryEvent {
                    cycle: row.cycle,
                    access,
                })
        })
        .collect();
    Ok(Trace {
        config: statement.config.clone(),
        rom: rom.to_vec(),
        initial_state: statement.initial_state.clone(),
        final_state: statement.final_state.clone(),
        rows: rows.to_vec(),
        memory_events,
        initial_ram,
        halted: statement.halted,
        exit_code: statement.exit_code,
        io_output: statement.output.clone(),
        io_input: statement.input.clone(),
    })
}

/// BinaryShout/BinaryRouter claims for a chunked proof, sharing one P3
/// commitment and opening. Chunk CPU proofs keep their own P3 proofs.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AuxTraceProof {
    pub shout: Option<crate::binary_shout::BinaryShoutProof>,
    pub shift_router: Option<crate::binary_router::BinaryRouterProof>,
    pub store_router: Option<crate::binary_router::BinaryRouterProof>,
    pub opening: P3MosaicOpening,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChunkCpuProof {
    pub start: usize,
    pub end: usize,
    pub cpu: CpuSpartanProof,
}

/// Per-chunk CPU proofs linked by register/PC state digests.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChunkedTraceProof {
    pub access: TraceAccessProof,
    pub trace_commitment: [u8; 32],
    pub aux: Option<AuxTraceProof>,
    pub chunks: Vec<ChunkCpuProof>,
    pub chain: ChainedProof,
}

fn chunk_state_digest(trace: &Trace, end_row: usize) -> [u8; 32] {
    let mut regs = trace.initial_state.regs;
    let mut pc = trace.initial_state.pc;
    let mut reservation = None;
    for row in &trace.rows[..end_row] {
        if let Some(rd) = row.rd {
            if rd != 0 {
                regs[rd] = row.rd_val;
            }
        }
        pc = row.next_pc;
        reservation = row.reservation_after;
    }
    let mut bytes = Vec::with_capacity(8 + 32 * 8 + 9);
    bytes.extend_from_slice(&pc.to_le_bytes());
    for value in regs {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    match reservation {
        Some(addr) => {
            bytes.push(1);
            bytes.extend_from_slice(&addr.to_le_bytes());
        }
        None => bytes.push(0),
    }
    sha256(&bytes)
}

fn chunk_proof_digest(
    trace_commitment: &[u8; 32],
    start: usize,
    end: usize,
    proof: &CpuSpartanProof,
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(160);
    bytes.extend_from_slice(trace_commitment);
    bytes.extend_from_slice(&(start as u64).to_le_bytes());
    bytes.extend_from_slice(&(end as u64).to_le_bytes());
    bytes.extend_from_slice(
        &bincode::serialize(&proof.commitment)
            .map_err(|error| RuntimeError::Proof(error.to_string()))
            .unwrap_or_default(),
    );
    for value in [proof.v_a, proof.v_b, proof.v_c, proof.vw] {
        bytes.extend_from_slice(&value.value().to_le_bytes());
    }
    bytes.extend_from_slice(&proof.outer.claimed_sum.value().to_le_bytes());
    bytes.extend_from_slice(&proof.inner.claimed_sum.value().to_le_bytes());
    sha256(&bytes)
}

fn prove_aux_trace(trace: &Trace) -> Result<Option<AuxTraceProof>, RuntimeError> {
    let shout_witness = BinaryShoutWitness::from_trace(trace).ok();
    let shift_router_witness = BinaryRouterWitness::from_trace_mode(trace, RouterMode::Shifts).ok();
    let store_router_witness = BinaryRouterWitness::from_trace_mode(trace, RouterMode::Stores).ok();
    if shout_witness.is_none() && shift_router_witness.is_none() && store_router_witness.is_none() {
        return Ok(None);
    }
    let pcs = P3BinaryPcs::new(100);
    let mut tables = Vec::new();
    let mut shout_index = None;
    let mut shift_router_index = None;
    let mut store_router_index = None;
    if let Some(witness) = &shout_witness {
        shout_index = Some(tables.len());
        tables.push(witness.table());
    }
    if let Some(witness) = &shift_router_witness {
        shift_router_index = Some(tables.len());
        tables.push(witness.table());
    }
    if let Some(witness) = &store_router_witness {
        store_router_index = Some(tables.len());
        tables.push(witness.table());
    }
    let commitment = pcs
        .commit_mosaic(&tables)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let mut points = Vec::new();
    let mut values = Vec::new();
    let shout = if let (Some(witness), Some(index)) = (&shout_witness, shout_index) {
        let (claim, claim_points, claim_values) =
            prove_binary_shout_claims(witness, &commitment, index, b"")
                .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        points.extend(claim_points);
        values.extend(claim_values);
        Some(claim)
    } else {
        None
    };
    let shift_router =
        if let (Some(witness), Some(index)) = (&shift_router_witness, shift_router_index) {
            let (claim, claim_points, claim_values) =
                prove_binary_router_claims(witness, &commitment, index, b"")
                    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
            points.extend(claim_points);
            values.extend(claim_values);
            Some(claim)
        } else {
            None
        };
    let store_router =
        if let (Some(witness), Some(index)) = (&store_router_witness, store_router_index) {
            let (claim, claim_points, claim_values) =
                prove_binary_router_claims(witness, &commitment, index, b"")
                    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
            points.extend(claim_points);
            values.extend(claim_values);
            Some(claim)
        } else {
            None
        };
    let opening = pcs
        .open_mosaic(&tables, &points)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(Some(AuxTraceProof {
        shout,
        shift_router,
        store_router,
        opening,
    }))
}

fn verify_aux_trace(trace: &Trace, aux: Option<&AuxTraceProof>) -> Result<(), RuntimeError> {
    let shout_witness = BinaryShoutWitness::from_trace(trace).ok();
    let shift_router_witness = BinaryRouterWitness::from_trace_mode(trace, RouterMode::Shifts).ok();
    let store_router_witness = BinaryRouterWitness::from_trace_mode(trace, RouterMode::Stores).ok();
    let expected =
        shout_witness.is_some() || shift_router_witness.is_some() || store_router_witness.is_some();
    if !expected {
        if aux.is_some() {
            return Err(RuntimeError::Proof(
                "chunked aux proof present for a trace without routed rows".into(),
            ));
        }
        return Ok(());
    }
    let Some(aux) = aux else {
        return Err(RuntimeError::Proof(
            "chunked proof is missing its aux claims".into(),
        ));
    };
    match (&shout_witness, &aux.shout) {
        (Some(_), None) | (None, Some(_)) => {
            return Err(RuntimeError::Proof(
                "BinaryShout presence does not match the trace".into(),
            ));
        }
        _ => {}
    }
    match (&shift_router_witness, &aux.shift_router) {
        (Some(_), None) | (None, Some(_)) => {
            return Err(RuntimeError::Proof(
                "shift BinaryRouter presence does not match the trace".into(),
            ));
        }
        _ => {}
    }
    match (&store_router_witness, &aux.store_router) {
        (Some(_), None) | (None, Some(_)) => {
            return Err(RuntimeError::Proof(
                "store BinaryRouter presence does not match the trace".into(),
            ));
        }
        _ => {}
    }
    let commitment = &aux.opening.commitment;
    let mut next_table = 0usize;
    let shout_index = shout_witness.as_ref().map(|_| {
        let index = next_table;
        next_table += 1;
        index
    });
    let shift_router_index = shift_router_witness.as_ref().map(|_| {
        let index = next_table;
        next_table += 1;
        index
    });
    let store_router_index = store_router_witness.as_ref().map(|_| {
        let index = next_table;
        next_table += 1;
        index
    });
    let mut points = Vec::new();
    let mut values = Vec::new();
    if let (Some(witness), Some(claim), Some(index)) = (&shout_witness, &aux.shout, shout_index) {
        let Some((claim_points, claim_values)) =
            verify_binary_shout_claims(witness, claim, commitment, index, b"")
                .map_err(|error| RuntimeError::Proof(error.to_string()))?
        else {
            return Err(RuntimeError::Proof("BinaryShout proof rejected".into()));
        };
        points.extend(claim_points);
        values.extend(claim_values);
    }
    if let (Some(witness), Some(claim), Some(index)) =
        (&shift_router_witness, &aux.shift_router, shift_router_index)
    {
        let Some((claim_points, claim_values)) =
            verify_binary_router_claims(witness, claim, commitment, index, b"")
                .map_err(|error| RuntimeError::Proof(error.to_string()))?
        else {
            return Err(RuntimeError::Proof(
                "shift BinaryRouter proof rejected".into(),
            ));
        };
        points.extend(claim_points);
        values.extend(claim_values);
    }
    if let (Some(witness), Some(claim), Some(index)) =
        (&store_router_witness, &aux.store_router, store_router_index)
    {
        let Some((claim_points, claim_values)) =
            verify_binary_router_claims(witness, claim, commitment, index, b"")
                .map_err(|error| RuntimeError::Proof(error.to_string()))?
        else {
            return Err(RuntimeError::Proof(
                "store BinaryRouter proof rejected".into(),
            ));
        };
        points.extend(claim_points);
        values.extend(claim_values);
    }
    let verified = P3BinaryPcs::new(100)
        .verify_mosaic(&aux.opening, &points, &values)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    if !verified {
        return Err(RuntimeError::Proof("chunked aux opening rejected".into()));
    }
    Ok(())
}

pub fn prove_chunked_trace(
    trace: &Trace,
    width: usize,
    chunk_size: usize,
) -> Result<ChunkedTraceProof, RuntimeError> {
    check_trace_linkage(trace)?;
    if trace.rows.is_empty() || chunk_size == 0 {
        return Err(RuntimeError::Proof(
            "chunked proofs require rows and a nonzero chunk size".into(),
        ));
    }
    let access = prove_trace_access(trace)?;
    let trace_commitment = trace_digest(trace);
    let backend = ConstraintProofBackend::default();
    let mut chunks = Vec::new();
    let mut chained = Vec::new();
    let mut start = 0;
    while start < trace.rows.len() {
        let end = (start + chunk_size).min(trace.rows.len());
        let (system, witness) = merged_cpu_system_for_rows(&trace.rows[start..end], width)?;
        let cpu = backend.prove(&system, &witness)?;
        let proof_digest = chunk_proof_digest(&trace_commitment, start, end, &cpu);
        chained.push(ChainedChunk::new(
            chained.len(),
            (end - start) as u64,
            chunk_state_digest(trace, start),
            chunk_state_digest(trace, end),
            proof_digest,
        ));
        chunks.push(ChunkCpuProof { start, end, cpu });
        start = end;
    }
    let chain = ChainedRecursion.aggregate(&chained)?;
    let aux = prove_aux_trace(trace)?;
    Ok(ChunkedTraceProof {
        access,
        trace_commitment,
        aux,
        chunks,
        chain,
    })
}

pub fn verify_chunked_trace(
    trace: &Trace,
    proof: &ChunkedTraceProof,
    width: usize,
) -> Result<(), RuntimeError> {
    check_trace_linkage(trace)?;
    if proof.trace_commitment != trace_digest(trace) {
        return Err(RuntimeError::Proof(
            "chunked proof does not match the supplied trace".into(),
        ));
    }
    verify_trace_access(trace, &proof.access)?;
    verify_aux_trace(trace, proof.aux.as_ref())?;
    if proof.chunks.len() != proof.chain.chunks.len() || proof.chunks.is_empty() {
        return Err(RuntimeError::Proof("chunked proof shape mismatch".into()));
    }
    if !ChainedRecursion.verify(&proof.chain)? {
        return Err(RuntimeError::Proof("chunk state chain mismatch".into()));
    }
    let backend = ConstraintProofBackend::default();
    let mut expected_start = 0;
    for (index, (chunk, chained)) in proof
        .chunks
        .iter()
        .zip(proof.chain.chunks.iter())
        .enumerate()
    {
        if chunk.start != expected_start
            || chunk.end <= chunk.start
            || (chained.trace_len as usize) != chunk.end - chunk.start
            || chained.index != index
            || chained.state_before != chunk_state_digest(trace, chunk.start)
            || chained.state_after != chunk_state_digest(trace, chunk.end)
        {
            return Err(RuntimeError::Proof(format!(
                "chunk {index} metadata mismatch"
            )));
        }
        let digest =
            chunk_proof_digest(&proof.trace_commitment, chunk.start, chunk.end, &chunk.cpu);
        if digest != chained.proof_digest {
            return Err(RuntimeError::Proof(format!(
                "chunk {index} proof digest mismatch"
            )));
        }
        let (system, _) = merged_cpu_system_for_rows(&trace.rows[chunk.start..chunk.end], width)?;
        backend.verify(&system, &chunk.cpu)?;
        expected_start = chunk.end;
    }
    if expected_start != trace.rows.len() {
        return Err(RuntimeError::Proof(
            "chunks do not cover the whole trace".into(),
        ));
    }
    Ok(())
}

/// Standalone verifier for chunked proofs; rows come from the proof and are

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
    #[error(transparent)]
    Guest(#[from] magnetar_guest::GuestError),
    #[error(transparent)]
    Spartan(#[from] SpartanError),
    #[error("invalid memory table")]
    InvalidMemoryTable,
    #[error("address {0} is outside the memory table")]
    AddressOutOfTable(u64),
    #[error("proof error: {0}")]
    Proof(String),
    #[error("unsupported trace row: {0}")]
    UnsupportedRow(&'static str),
    #[error("proof backend is not implemented")]
    ProofBackendUnimplemented,
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_executor::execute;
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

    #[test]
    fn spartan_backend_proves_and_verifies_a_64_bit_branch() {
        use magnetar_cpu::BranchOp;

        let (system, layout) = magnetar_cpu::uniform_branch_relation(64, 0x1000, 0x20);
        let witness = layout.witness(BranchOp::Blt, 0x1000, u64::MAX, 0, 0x20);
        let backend = ConstraintProofBackend::default();
        let proof = backend.prove(&system, &witness).unwrap();
        assert!(backend.verify(&system, &proof).unwrap());
    }

    #[test]
    fn spartan_backend_proves_and_verifies_a_64_bit_beq() {
        let (system, layout) = magnetar_cpu::uniform_beq_relation(64, 0x1000, 0x20);
        let witness = layout.witness(0x1000, u64::MAX, u64::MAX, 0x20);
        let backend = ConstraintProofBackend::default();
        let proof = backend.prove(&system, &witness).unwrap();
        assert!(backend.verify(&system, &proof).unwrap());
    }

    #[test]
    fn spartan_backend_proves_auipc_and_jalr() {
        let backend = ConstraintProofBackend::default();

        let (auipc_system, auipc) = magnetar_cpu::uniform_auipc_relation(64, 0x1000, 0x1020);
        let auipc_proof = backend.prove(&auipc_system, &auipc.witness(0x20)).unwrap();
        assert!(backend.verify(&auipc_system, &auipc_proof).unwrap());

        let (jalr_system, jalr) = magnetar_cpu::uniform_jalr_relation(64, 0x1020, 0x1004, 0x1000);
        let jalr_proof = backend
            .prove(&jalr_system, &jalr.witness(0x1000, 0x21))
            .unwrap();
        assert!(backend.verify(&jalr_system, &jalr_proof).unwrap());
    }

    #[test]
    fn spartan_backend_proves_and_verifies_a_64_bit_jal() {
        let (system, layout) = magnetar_cpu::uniform_jal_relation(64, 0x1000, 0x20);
        let witness = layout.witness(0x1000, 0x20);
        let backend = ConstraintProofBackend::default();
        let proof = backend.prove(&system, &witness).unwrap();
        assert!(backend.verify(&system, &proof).unwrap());
    }

    #[test]
    fn spartan_backend_proves_and_verifies_a_64_bit_step() {
        use magnetar_cpu::StepOp;

        let (system, layout) = magnetar_cpu::uniform_step_relation(64);
        let witness = layout.witness(StepOp::And, 0x1000, u64::MAX, 1, 0);
        let backend = ConstraintProofBackend::default();
        let proof = backend.prove(&system, &witness).unwrap();
        assert!(backend.verify(&system, &proof).unwrap());
    }

    #[test]
    fn spartan_backend_proves_and_verifies_a_64_bit_alu() {
        use magnetar_cpu::StepOp;

        let (system, layout) = magnetar_cpu::uniform_alu_relation(64);
        let witness = layout.witness(StepOp::Add, u64::MAX, 1, 0);
        let backend = ConstraintProofBackend::default();
        let proof = backend.prove(&system, &witness).unwrap();
        assert!(backend.verify(&system, &proof).unwrap());
    }

    #[test]
    fn load_proof_binds_committed_memory_value() {
        let values = (0..16u64)
            .map(|index| magnetar_constraint::F2_128::from(index * 10))
            .collect();
        let memory = CommittedMemory::new(4, values).unwrap();
        let proof = prove_load(&memory, 2, 3).unwrap();
        assert_eq!(proof.addr, 5);
        assert_eq!(proof.value, magnetar_constraint::F2_128::from(50u64));
        verify_load(&memory, &proof).unwrap();

        let mut tampered = proof.clone();
        tampered.value = magnetar_constraint::F2_128::from(51u64);
        assert!(verify_load(&memory, &tampered).is_err());

        let mut tampered_path = proof.clone();
        tampered_path.path.siblings[0][0] ^= 1;
        assert!(verify_load(&memory, &tampered_path).is_err());
    }

    #[test]
    fn trace_proof_binds_cpu_rows_and_access_log() {
        use magnetar_spec::{Instruction, Op};

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
        );
        let trace = execute(&program, config()).unwrap();
        let proof = prove_trace_proof(&trace, 16).unwrap();
        verify_trace_proof(&trace, &proof, 16).unwrap();

        let mut tampered = proof.clone();
        if let RowCpuProof::Alu(spartan) = &mut tampered.rows[0] {
            spartan.vw = spartan.vw + F2_128::from(1u64);
        }
        assert!(verify_trace_proof(&trace, &tampered, 16).is_err());
    }

    #[test]
    fn trace_proof_covers_control_flow_rows() {
        use magnetar_spec::{Instruction, Op};

        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 1,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Beq,
                    rd: 0,
                    rs1: 1,
                    rs2: 1,
                    imm: 8,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Addi,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
                    imm: 99,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Jal,
                    rd: 3,
                    rs1: 0,
                    rs2: 0,
                    imm: 8,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Addi,
                    rd: 4,
                    rs1: 0,
                    rs2: 0,
                    imm: 99,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Auipc,
                    rd: 5,
                    rs1: 0,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Jalr,
                    rd: 6,
                    rs1: 5,
                    rs2: 0,
                    imm: 8,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        let ops = trace
            .rows
            .iter()
            .map(|row| row.instruction.op)
            .collect::<Vec<_>>();
        assert_eq!(
            ops,
            vec![Op::Addi, Op::Beq, Op::Jal, Op::Auipc, Op::Jalr, Op::Ecall]
        );
        assert_eq!(trace.final_state.reg(5), 0x1014);
        assert_eq!(trace.final_state.reg(6), 0x101c);

        let proof = prove_trace_proof(&trace, 16).unwrap();
        assert!(matches!(proof.rows[1], RowCpuProof::Branch(_)));
        assert!(matches!(proof.rows[2], RowCpuProof::Jal(_)));
        assert!(matches!(proof.rows[3], RowCpuProof::Auipc(_)));
        assert!(matches!(proof.rows[4], RowCpuProof::Jalr(_)));
        verify_trace_proof(&trace, &proof, 16).unwrap();

        let mut tampered = proof.clone();
        if let RowCpuProof::Branch(spartan) = &mut tampered.rows[1] {
            spartan.vw = spartan.vw + F2_128::from(1u64);
        }
        assert!(verify_trace_proof(&trace, &tampered, 16).is_err());

        let mut wrong_variant = proof.clone();
        wrong_variant.rows[2] = RowCpuProof::Skip;
        assert!(verify_trace_proof(&trace, &wrong_variant, 16).is_err());

        let mut broken_pc = trace.clone();
        broken_pc.rows[1].pc += 4;
        assert!(verify_trace_proof(&broken_pc, &proof, 16).is_err());

        let mut broken_word = trace.clone();
        broken_word.rows[0].instruction_word ^= 1;
        assert!(verify_trace_proof(&broken_word, &proof, 16).is_err());
    }

    #[test]
    fn lane_extraction_and_update_match_rv64_semantics() {
        let word = 0x1122_3344_5566_7788u64;
        assert_eq!(load_result(word, 0, 1, false), 0x88);
        assert_eq!(load_result(word, 0, 1, true), 0xffff_ffff_ffff_ff88);
        assert_eq!(load_result(word, 7, 1, true), 0x11);
        assert_eq!(load_result(word, 6, 2, false), 0x1122);
        assert_eq!(load_result(word, 4, 4, false), 0x1122_3344);
        assert_eq!(load_result(word, 0, 8, false), word);

        assert_eq!(store_word(word, 0, 1, 0xaa), 0x1122_3344_5566_77aa);
        assert_eq!(store_word(word, 7, 1, 0xbb), 0xbb22_3344_5566_7788);
        assert_eq!(store_word(word, 6, 2, 0xccdd), 0xccdd_3344_5566_7788);
        assert_eq!(store_word(word, 4, 4, 0xdead_beef), 0xdead_beef_5566_7788);
        assert_eq!(store_word(word, 0, 8, 0x0123), 0x0123);
    }

    #[test]
    fn trace_proof_covers_immediate_logic_and_fence() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Addi, 1, 0, 0, 5).encode(),
                instruction(Op::Addi, 2, 0, 0, 7).encode(),
                instruction(Op::Xori, 3, 1, 0, 7).encode(),
                instruction(Op::Ori, 4, 1, 0, 7).encode(),
                instruction(Op::Andi, 5, 1, 0, 3).encode(),
                Instruction::new(Op::Fence).encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        assert_eq!(trace.final_state.reg(3), 2);
        assert_eq!(trace.final_state.reg(4), 7);
        assert_eq!(trace.final_state.reg(5), 1);

        let proof = prove_trace_proof(&trace, 8).unwrap();
        assert!(matches!(proof.rows[5], RowCpuProof::Skip));
        verify_trace_proof(&trace, &proof, 8).unwrap();
    }

    #[test]
    fn trace_digest_binds_rows_and_configuration() {
        let trace = execute(&program(), config()).unwrap();
        let digest = trace_digest(&trace);
        assert_eq!(digest, trace_digest(&trace));

        let mut changed = trace.clone();
        changed.rows[0].rd_val ^= 1;
        assert_ne!(digest, trace_digest(&changed));

        let mut changed = trace.clone();
        changed.rows[1].rs1_val ^= 1;
        assert_ne!(digest, trace_digest(&changed));

        let mut changed = trace.clone();
        changed.config.max_cycles += 1;
        assert_ne!(digest, trace_digest(&changed));

        let mut changed = trace.clone();
        changed.halted = false;
        assert_ne!(digest, trace_digest(&changed));
    }

    #[test]
    fn trace_statistics_match_the_merged_cpu_system() {
        let trace = execute(&program(), config()).unwrap();
        let stats = trace_cpu_stats(&trace, 8).unwrap();
        let (system, witness) = merged_cpu_system(&trace, 8).unwrap();
        assert_eq!(stats.rows.len(), trace.rows.len());
        assert_eq!(stats.variables, system.num_vars);
        assert_eq!(stats.constraints, system.constraints.len());
        assert_eq!(witness.len(), system.num_vars);
        assert!(stats
            .rows
            .iter()
            .any(|row| row.op == "addi" && row.constraints > 0));

        let proof = prove_unified_trace(&trace, 8).unwrap();
        let sizes = unified_proof_sizes(&proof).unwrap();
        let encoded = encode_unified_proof(&proof).unwrap();
        assert!(sizes.cpu > 0 && sizes.access > 0);
        assert!(sizes.total() <= encoded.len());
    }

    #[test]
    fn unified_trace_merges_gated_cpu_claims() {
        use magnetar_spec::{Instruction, Op};

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
                    op: Op::Add,
                    rd: 2,
                    rs1: 1,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        let proof = prove_unified_trace(&trace, 8).unwrap();
        assert!(proof.gated.is_some());
        assert_eq!(
            proof.cpu.commitment.tables.len(),
            7 + usize::from(proof.shout.is_some())
                + usize::from(proof.shift_router.is_some())
                + usize::from(proof.store_router.is_some())
        );
        verify_unified_trace(&trace, &proof, 8).unwrap();
    }

    #[test]
    fn unified_amo_bundle_round_trips() {
        use magnetar_executor::execute;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

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
                    imm: 10,
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
                    op: Op::Addi,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
                    imm: 5,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::AmoaddD,
                    rd: 3,
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
                ram_size: 0x100,
                stack_top: 0x1000_0080,
                max_cycles: 100,
            },
        )
        .unwrap();
        let proof = prove_unified_trace(&trace, 8).unwrap();
        assert!(proof.amo.is_some());
        verify_unified_trace(&trace, &proof, 8).unwrap();
    }

    #[test]
    fn unified_lr_sc_bundle_round_trips() {
        use magnetar_executor::execute;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

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
                    op: Op::LrD,
                    rd: 2,
                    rs1: 4,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Addi,
                    rd: 3,
                    rs1: 0,
                    rs2: 0,
                    imm: 9,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::ScD,
                    rd: 5,
                    rs1: 4,
                    rs2: 3,
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
                ram_size: 0x100,
                stack_top: 0x1000_0080,
                max_cycles: 100,
            },
        )
        .unwrap();
        let proof = prove_unified_trace(&trace, 8).unwrap();
        let amo = proof.amo.as_ref().expect("LR/SC bundle");
        assert!(amo.lr.is_some());
        assert!(amo.sc.is_some());
        verify_unified_trace(&trace, &proof, 8).unwrap();
    }

    #[test]
    fn unified_amo_lr_sc_bundle_round_trips() {
        use magnetar_executor::execute;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

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
                    imm: 10,
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
                    op: Op::Addi,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
                    imm: 5,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::AmoaddD,
                    rd: 3,
                    rs1: 4,
                    rs2: 2,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::LrD,
                    rd: 6,
                    rs1: 4,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Addi,
                    rd: 7,
                    rs1: 0,
                    rs2: 0,
                    imm: 9,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::ScD,
                    rd: 8,
                    rs1: 4,
                    rs2: 7,
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
                ram_size: 0x100,
                stack_top: 0x1000_0080,
                max_cycles: 100,
            },
        )
        .unwrap();
        let proof = prove_unified_trace(&trace, 8).unwrap();
        let amo = proof.amo.as_ref().expect("AMO bundle");
        assert!(amo.add.is_some());
        assert!(amo.lr.is_some());
        assert!(amo.sc.is_some());
        verify_unified_trace(&trace, &proof, 8).unwrap();
        let bundle = crate::protocol::ProofBundle::from_unified(&proof);
        let restored = bundle.into_unified().unwrap();
        verify_unified_trace(&trace, &restored, 8).unwrap();
    }

    #[test]
    fn unified_branch_round_trips() {
        use magnetar_executor::execute;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 1,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Beq,
                    rd: 0,
                    rs1: 0,
                    rs2: 0,
                    imm: 4,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Addi,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
                    imm: 2,
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
        let proof = prove_unified_trace(&trace, 8).unwrap();
        verify_unified_trace(&trace, &proof, 8).unwrap();
    }

    #[test]
    fn unified_mul_div_round_trips() {
        use magnetar_executor::execute;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

        let mul_program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 6,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Mul,
                    rd: 2,
                    rs1: 1,
                    rs2: 1,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let div_program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 17,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Addi,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
                    imm: 5,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Divu,
                    rd: 3,
                    rs1: 1,
                    rs2: 2,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        for program in [mul_program, div_program] {
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
            let proof = prove_unified_trace(&trace, 8).unwrap();
            verify_unified_trace(&trace, &proof, 8).unwrap();
        }
    }

    #[test]
    fn unified_jal_round_trips() {
        use magnetar_executor::execute;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Jal,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 4,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Addi,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
                    imm: 2,
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
        let proof = prove_unified_trace(&trace, 8).unwrap();
        verify_unified_trace(&trace, &proof, 8).unwrap();
    }

    #[test]
    fn unified_auipc_round_trips() {
        use magnetar_executor::execute;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Auipc,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x1000,
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
        let proof = prove_unified_trace(&trace, 8).unwrap();
        verify_unified_trace(&trace, &proof, 8).unwrap();
    }

    #[test]
    fn unified_jalr_round_trips() {
        use magnetar_executor::execute;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Lui,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x1000,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Jalr,
                    rd: 2,
                    rs1: 1,
                    rs2: 0,
                    imm: 8,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Addi,
                    rd: 3,
                    rs1: 0,
                    rs2: 0,
                    imm: 1,
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
        let proof = prove_unified_trace(&trace, 8).unwrap();
        verify_unified_trace(&trace, &proof, 8).unwrap();
    }

    #[test]
    fn revealed_unified_proof_round_trips() {
        use magnetar_spec::{Instruction, Op};

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
                    op: Op::Xor,
                    rd: 2,
                    rs1: 1,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        let proof = prove_unified_revealed(&trace, 8).unwrap();
        assert!(proof.opening.is_none());
        verify_unified_trace(&trace, &proof, 8).unwrap();
        let mut tampered = proof;
        tampered.cpu.commitment.tables[0].num_columns += 1;
        assert!(verify_unified_trace(&trace, &tampered, 8).is_err());
    }

    #[test]
    fn unified_trace_proof_merges_row_constraints() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Addi, 1, 0, 0, 5).encode(),
                instruction(Op::Addi, 2, 0, 0, 7).encode(),
                instruction(Op::Add, 3, 1, 2, 0).encode(),
                instruction(Op::Mul, 4, 1, 2, 0).encode(),
                Instruction::new(Op::Fence).encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        assert_eq!(trace.final_state.reg(3), 12);
        assert_eq!(trace.final_state.reg(4), 35);

        let proof = prove_unified_trace(&trace, 8).unwrap();
        assert!(proof.amo.is_none());
        assert!(proof.access.ram.opening.is_none());
        assert_eq!(
            proof.cpu.commitment.tables.len(),
            6 + usize::from(proof.gated.is_some())
                + usize::from(proof.shout.is_some())
                + usize::from(proof.shift_router.is_some())
                + usize::from(proof.store_router.is_some())
        );
        verify_unified_trace(&trace, &proof, 8).unwrap();

        let statement = Statement {
            program_hash: program_hash(&program),
            rom: trace.rom.clone(),
            trace_commitment: trace_digest(&trace),
            config: config(),
            initial_state: trace.initial_state.clone(),
            initial_ram: trace.initial_ram.clone(),
            final_state: trace.final_state.clone(),
            trace_len: trace.rows.len() as u64,
            output: trace.io_output.clone(),
            input: trace.io_input.clone(),
            halted: trace.halted,
            exit_code: trace.exit_code,
        };
        verify_unified_trace_statement(&statement, &trace, &proof, 8).unwrap();
        verify_unified_trace_statement(&statement, &trace, &proof, 8).unwrap();

        let bytes = encode_unified_proof(&proof).unwrap();
        assert!(!bytes.is_empty());
        let decoded = decode_unified_proof(&bytes).unwrap();
        verify_unified_trace_statement(&statement, &trace, &decoded, 8).unwrap();
        assert!(decode_unified_proof(&bytes[..bytes.len() / 2]).is_err());

        let mut wrong_length = statement.clone();
        wrong_length.trace_len += 1;
        assert!(verify_unified_trace_statement(&wrong_length, &trace, &proof, 8).is_err());
        let mut wrong_commitment = statement.clone();
        wrong_commitment.trace_commitment[0] ^= 1;
        assert!(verify_unified_trace_statement(&wrong_commitment, &trace, &proof, 8).is_err());
        let mut wrong_program = statement.clone();
        wrong_program.program_hash[0] ^= 1;
        assert!(verify_unified_trace_statement(&wrong_program, &trace, &proof, 8).is_err());
        assert!(verify_unified_trace_statement(&wrong_program, &trace, &proof, 8).is_err());
        let mut wrong_ram = statement.clone();
        wrong_ram.initial_ram[0] ^= 1;
        assert!(verify_unified_trace_statement(&wrong_ram, &trace, &proof, 8).is_err());
        assert!(verify_unified_trace_statement(&wrong_ram, &trace, &proof, 8).is_err());
        let mut wrong_state = statement;
        wrong_state.final_state.pc += 4;
        assert!(verify_unified_trace_statement(&wrong_state, &trace, &proof, 8).is_err());

        let mut tampered = proof.clone();
        tampered.cpu.segments[0].value = tampered.cpu.segments[0].value + F2_128::from(1u64);
        assert!(verify_unified_trace(&trace, &tampered, 8).is_err());

        let mut tampered = proof.clone();
        tampered.access.ram.read.initial.rounds[0][0] =
            tampered.access.ram.read.initial.rounds[0][0] + F2_128::from(1u64);
        assert!(verify_unified_trace(&trace, &tampered, 8).is_err());

        let mut broken = trace.clone();
        broken.rows[2].rd_val = 99;
        assert!(verify_unified_trace(&broken, &proof, 8).is_err());

        let mut broken_rom = trace;
        broken_rom.rom[0] ^= 1;
        assert!(verify_unified_trace(&broken_rom, &proof, 8).is_err());
    }

    #[test]
    fn trace_proof_covers_low_multiplication() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Addi, 1, 0, 0, 13).encode(),
                instruction(Op::Addi, 2, 0, 0, 11).encode(),
                instruction(Op::Mul, 3, 1, 2, 0).encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        assert_eq!(trace.final_state.reg(3), 143);

        let proof = prove_trace_proof(&trace, 8).unwrap();
        assert!(matches!(proof.rows[2], RowCpuProof::Mul(_)));
        verify_trace_proof(&trace, &proof, 8).unwrap();

        let mut tampered = proof;
        if let RowCpuProof::Mul(spartan) = &mut tampered.rows[2] {
            spartan.vw = spartan.vw + F2_128::from(1u64);
        }
        assert!(verify_trace_proof(&trace, &tampered, 8).is_err());
    }

    #[test]
    fn trace_proof_covers_high_multiplication() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Addi, 1, 0, 0, -7).encode(),
                instruction(Op::Addi, 2, 0, 0, 2).encode(),
                instruction(Op::Mulh, 3, 1, 2, 0).encode(),
                instruction(Op::Mulhsu, 4, 1, 2, 0).encode(),
                instruction(Op::Mulhu, 5, 1, 2, 0).encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        assert_eq!(trace.final_state.reg(3), u64::MAX);
        assert_eq!(trace.final_state.reg(4), u64::MAX);
        assert_eq!(trace.final_state.reg(5), 1);

        let proof = prove_trace_proof(&trace, 8).unwrap();
        assert!(matches!(proof.rows[2], RowCpuProof::Mulh(_)));
        assert!(matches!(proof.rows[3], RowCpuProof::Mulhsu(_)));
        assert!(matches!(proof.rows[4], RowCpuProof::Mulhu(_)));
        verify_trace_proof(&trace, &proof, 8).unwrap();

        let bytes = encode_trace_proof(&proof).unwrap();
        let decoded = decode_trace_proof(&bytes).unwrap();
        verify_trace_proof(&trace, &decoded, 8).unwrap();
        assert!(decode_trace_proof(&bytes[..bytes.len() / 2]).is_err());

        let mut wrong_rom = trace.clone();
        wrong_rom.rom[0] ^= 1;
        assert!(verify_trace_proof(&wrong_rom, &proof, 8).is_err());

        let mut tampered = proof;
        if let RowCpuProof::Mulh(spartan) = &mut tampered.rows[2] {
            spartan.vw = spartan.vw + F2_128::from(1u64);
        }
        assert!(verify_trace_proof(&trace, &tampered, 8).is_err());
    }

    #[test]
    fn trace_proof_covers_atomic_read_modify_write() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64, shamt: u8| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Lui, 4, 0, 0, 0x1000_0000, 0).encode(),
                instruction(Op::Lui, 1, 0, 0, 0x8000_0000, 0).encode(),
                instruction(Op::Sd, 0, 4, 1, 0, 0).encode(),
                instruction(Op::Addi, 2, 0, 0, 7, 0).encode(),
                instruction(Op::AmoswapW, 3, 4, 2, 0, 0).encode(),
                instruction(Op::Addi, 1, 0, 0, 10, 0).encode(),
                instruction(Op::Sd, 0, 4, 1, 0, 0).encode(),
                instruction(Op::Addi, 2, 0, 0, 5, 0).encode(),
                instruction(Op::AmoaddD, 5, 4, 2, 0, 0).encode(),
                instruction(Op::AmoxorD, 6, 4, 2, 0, 0).encode(),
                instruction(Op::AmoandD, 7, 4, 2, 0, 0).encode(),
                instruction(Op::AmoorD, 8, 4, 2, 0, 0).encode(),
                instruction(Op::Addi, 2, 0, 0, -1, 0).encode(),
                instruction(Op::AmomaxD, 9, 4, 2, 0, 0).encode(),
                instruction(Op::AmominD, 10, 4, 2, 0, 0).encode(),
                instruction(Op::Addi, 2, 0, 0, 5, 0).encode(),
                instruction(Op::AmomaxuD, 11, 4, 2, 0, 0).encode(),
                instruction(Op::AmominuD, 12, 4, 2, 0, 0).encode(),
                instruction(Op::Ld, 13, 4, 0, 0, 0).encode(),
                instruction(Op::Ecall, 0, 0, 0, 0, 0).encode(),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        assert_eq!(trace.final_state.reg(3), 0xffff_ffff_8000_0000);
        assert_eq!(trace.final_state.reg(5), 10);
        assert_eq!(trace.final_state.reg(6), 15);
        assert_eq!(trace.final_state.reg(7), 10);
        assert_eq!(trace.final_state.reg(8), 0);
        assert_eq!(trace.final_state.reg(9), 5);
        assert_eq!(trace.final_state.reg(10), 5);
        assert_eq!(trace.final_state.reg(11), u64::MAX);
        assert_eq!(trace.final_state.reg(12), u64::MAX);
        assert_eq!(trace.final_state.reg(13), 5);

        for (index, row) in trace.rows.iter().enumerate() {
            if let Some((system, witness)) = row_cpu_relation(row, 8).unwrap() {
                system.check(&witness).unwrap_or_else(|error| {
                    panic!("row {index} {}: {error}", row.instruction.op.name())
                });
            }
        }

        let unified = prove_unified_trace(&trace, 8).unwrap();
        verify_unified_trace(&trace, &unified, 8).unwrap();
        let mut tampered = unified;
        tampered.cpu.segments[0].value = tampered.cpu.segments[0].value + F2_128::from(1u64);
        assert!(verify_unified_trace(&trace, &tampered, 8).is_err());
    }

    #[test]
    fn trace_proof_covers_lr_sign_extension() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Lui, 4, 0, 0, 0x1000_0000).encode(),
                instruction(Op::Addi, 1, 0, 0, -1).encode(),
                instruction(Op::Sd, 0, 4, 1, 0).encode(),
                instruction(Op::LrW, 2, 4, 0, 0).encode(),
                instruction(Op::Ecall, 0, 0, 0, 0).encode(),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        assert_eq!(trace.final_state.reg(2), u64::MAX);

        let proof = prove_trace_proof(&trace, 8).unwrap();
        assert!(matches!(proof.rows[3], RowCpuProof::Load(_)));
        verify_trace_proof(&trace, &proof, 8).unwrap();
    }

    #[test]
    fn per_row_trace_proof_covers_atomic_operation() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Lui, 4, 0, 0, 0x1000_0000).encode(),
                instruction(Op::Addi, 1, 0, 0, 10).encode(),
                instruction(Op::Sd, 0, 4, 1, 0).encode(),
                instruction(Op::Addi, 2, 0, 0, 5).encode(),
                instruction(Op::AmoaddD, 3, 4, 2, 0).encode(),
                instruction(Op::Ecall, 0, 0, 0, 0).encode(),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        assert_eq!(trace.final_state.reg(3), 10);

        let proof = prove_trace_proof(&trace, 8).unwrap();
        assert!(matches!(proof.rows[4], RowCpuProof::Amo(_)));
        verify_trace_proof(&trace, &proof, 8).unwrap();

        let mut tampered = proof;
        if let RowCpuProof::Amo(spartan) = &mut tampered.rows[4] {
            spartan.vw = spartan.vw + F2_128::from(1u64);
        }
        assert!(verify_trace_proof(&trace, &tampered, 8).is_err());
    }

    #[test]
    fn trace_proof_covers_lr_sc_reservations() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Lui, 4, 0, 0, 0x1000_0000).encode(),
                instruction(Op::Addi, 1, 0, 0, 10).encode(),
                instruction(Op::Sd, 0, 4, 1, 0).encode(),
                instruction(Op::LrD, 3, 4, 0, 0).encode(),
                instruction(Op::Addi, 2, 0, 0, 20).encode(),
                instruction(Op::ScD, 5, 4, 2, 0).encode(),
                instruction(Op::Ecall, 0, 0, 0, 0).encode(),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        assert_eq!(trace.final_state.reg(3), 10);
        assert_eq!(trace.final_state.reg(5), 0);
        assert_eq!(trace.rows[3].reservation_after, Some(0x1000_0000));
        assert_eq!(trace.rows[5].reservation_before, Some(0x1000_0000));
        assert_eq!(trace.rows[5].reservation_after, None);

        let proof = prove_trace_proof(&trace, 8).unwrap();
        assert!(matches!(proof.rows[3], RowCpuProof::Load(_)));
        assert!(matches!(proof.rows[5], RowCpuProof::Store(_)));
        verify_trace_proof(&trace, &proof, 8).unwrap();

        let mut broken_reservation = trace.clone();
        broken_reservation.rows[3].reservation_after = None;
        assert!(verify_trace_proof(&broken_reservation, &proof, 8).is_err());

        let failed_program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Lui, 4, 0, 0, 0x1000_0000).encode(),
                instruction(Op::Addi, 1, 0, 0, 10).encode(),
                instruction(Op::Sd, 0, 4, 1, 0).encode(),
                instruction(Op::LrD, 3, 4, 0, 0).encode(),
                instruction(Op::Addi, 2, 0, 0, 20).encode(),
                instruction(Op::Addi, 6, 4, 0, 8).encode(),
                instruction(Op::ScD, 5, 6, 2, 0).encode(),
                instruction(Op::Ecall, 0, 0, 0, 0).encode(),
            ],
        );
        let failed_trace = execute(&failed_program, config()).unwrap();
        assert_eq!(failed_trace.final_state.reg(5), 1);
        assert!(failed_trace.rows[6].mem.is_none());
        assert_eq!(failed_trace.rows[6].reservation_after, None);

        let failed_proof = prove_trace_proof(&failed_trace, 8).unwrap();
        assert!(matches!(failed_proof.rows[6], RowCpuProof::Skip));
        verify_trace_proof(&failed_trace, &failed_proof, 8).unwrap();
    }

    #[test]
    fn trace_proof_binds_immediate_shift_amounts() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64, shamt: u8| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Addi, 1, 0, 0, 1, 0).encode(),
                instruction(Op::Slli, 2, 1, 0, 0, 7).encode(),
                instruction(Op::Srli, 3, 2, 0, 0, 3).encode(),
                instruction(Op::Addi, 4, 0, 0, -128, 0).encode(),
                instruction(Op::Srai, 5, 4, 0, 0, 1).encode(),
                instruction(Op::Ecall, 0, 0, 0, 0, 0).encode(),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        assert_eq!(trace.final_state.reg(2), 128);
        assert_eq!(trace.final_state.reg(3), 16);
        assert_eq!(trace.final_state.reg(5), (-64i64) as u64);

        let proof = prove_trace_proof(&trace, 8).unwrap();
        verify_trace_proof(&trace, &proof, 8).unwrap();
    }

    #[test]
    fn row_relations_support_full_width_m_operations() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Addi, 1, 0, 0, -7).encode(),
                instruction(Op::Addi, 2, 0, 0, 2).encode(),
                instruction(Op::Mul, 3, 1, 2, 0).encode(),
                instruction(Op::Mulh, 4, 1, 2, 0).encode(),
                instruction(Op::Mulhsu, 5, 1, 2, 0).encode(),
                instruction(Op::Mulhu, 6, 1, 2, 0).encode(),
                instruction(Op::Div, 7, 1, 2, 0).encode(),
                instruction(Op::Rem, 8, 1, 2, 0).encode(),
                instruction(Op::Divu, 9, 1, 2, 0).encode(),
                instruction(Op::Remu, 10, 1, 2, 0).encode(),
                instruction(Op::Ecall, 0, 0, 0, 0).encode(),
            ],
        );
        let trace = execute(&program, config()).unwrap();

        for (index, row) in trace.rows.iter().enumerate() {
            if let Some((system, witness)) = row_cpu_relation(row, 64).unwrap() {
                system.check(&witness).unwrap_or_else(|error| {
                    panic!("row {index} {}: {error}", row.instruction.op.name())
                });
            }
        }
    }

    #[test]
    fn trace_proof_covers_compressed_instructions() {
        // c.li x1, 5; c.addi x1, x1, 3; c.ebreak
        let program = ProgramImage::new(0x1000, vec![0x008d_4095, 0x0000_9002]);
        let outcome = ReferencePipeline::run(&program, config(), 2).unwrap();
        assert_eq!(outcome.trace.len(), 3);
        assert_eq!(outcome.trace.final_state.reg(1), 8);
        assert_eq!(outcome.trace.rows[0].instruction_len, 2);
        assert_eq!(outcome.trace.rows[1].pc, 0x1002);
        assert_eq!(outcome.trace.rows[2].pc, 0x1004);
        assert!(outcome.trace.halted);

        let proof = prove_unified_trace(&outcome.trace, 8).unwrap();
        verify_unified_trace(&outcome.trace, &proof, 8).unwrap();
        verify_unified_trace_statement(&outcome.statement, &outcome.trace, &proof, 8).unwrap();
    }

    #[test]
    fn trace_proof_covers_compressed_branches() {
        // c.li x8, 0; c.beqz x8, +4; c.ebreak (at both fallthrough and target)
        let program = ProgramImage::new(0x1000, vec![0xc011_4481, 0x9002_9002]);
        let outcome = ReferencePipeline::run(&program, config(), 2).unwrap();
        assert_eq!(outcome.trace.len(), 3);
        assert_eq!(outcome.trace.rows[1].next_pc, 0x1006);
        assert_eq!(outcome.trace.final_state.pc, 0x1006);
        assert!(outcome.trace.halted);

        let proof = prove_unified_trace(&outcome.trace, 8).unwrap();
        verify_unified_trace(&outcome.trace, &proof, 8).unwrap();
    }

    #[test]
    fn trace_proof_covers_compressed_jalr_link() {
        let lui = Instruction {
            op: Op::Lui,
            rd: 5,
            rs1: 0,
            rs2: 0,
            imm: 0x1000,
            shamt: 0,
        }
        .encode();
        let addi = Instruction {
            op: Op::Addi,
            rd: 5,
            rs1: 5,
            rs2: 0,
            imm: 10,
            shamt: 0,
        }
        .encode();
        // lui x5; addi x5,x5,10; c.jalr x5; c.ebreak (target)
        let program = ProgramImage::new(0x1000, vec![lui, addi, 0x9002_9282]);
        let outcome = ReferencePipeline::run(&program, config(), 2).unwrap();
        assert_eq!(outcome.trace.len(), 4);
        assert_eq!(outcome.trace.final_state.reg(1), 0x100a);
        assert_eq!(outcome.trace.final_state.pc, 0x100a);

        for (index, row) in outcome.trace.rows.iter().enumerate() {
            if let Some((system, witness)) = row_cpu_relation(row, 8).unwrap() {
                system.check(&witness).unwrap_or_else(|error| {
                    panic!("row {index} {}: {error}", row.instruction.op.name())
                });
            }
        }

        let proof = prove_unified_trace(&outcome.trace, 8).unwrap();
        verify_unified_trace(&outcome.trace, &proof, 8).unwrap();
    }

    #[test]
    fn trace_proof_covers_compressed_memory_operations() {
        let lui = Instruction {
            op: Op::Lui,
            rd: 9,
            rs1: 0,
            rs2: 0,
            imm: 0x1000_0000,
            shamt: 0,
        }
        .encode();
        // lui x9; c.li x8,10; c.sw x8,0(x9); c.lw x10,0(x9); c.ebreak
        let program = ProgramImage::new(0x1000, vec![lui, 0xc080_4429, 0x9002_4088]);
        let outcome = ReferencePipeline::run(&program, config(), 2).unwrap();
        assert_eq!(outcome.trace.len(), 5);
        assert_eq!(outcome.trace.final_state.reg(10), 10);
        assert_eq!(outcome.trace.memory_writes().count(), 1);
        assert_eq!(outcome.trace.memory_reads().count(), 1);

        let proof = prove_unified_trace(&outcome.trace, 8).unwrap();
        verify_unified_trace(&outcome.trace, &proof, 8).unwrap();
    }

    #[test]
    fn trace_proof_covers_word_operations() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64, shamt: u8| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Addi, 1, 0, 0, -1, 0).encode(),
                instruction(Op::Addi, 2, 0, 0, 1, 0).encode(),
                instruction(Op::Addw, 3, 1, 2, 0, 0).encode(),
                instruction(Op::Subw, 4, 2, 1, 0, 0).encode(),
                instruction(Op::Sllw, 5, 1, 2, 0, 0).encode(),
                instruction(Op::Srlw, 6, 1, 2, 0, 0).encode(),
                instruction(Op::Sraw, 7, 1, 2, 0, 0).encode(),
                instruction(Op::Addiw, 8, 1, 0, 2, 0).encode(),
                instruction(Op::Slliw, 9, 1, 0, 0, 1).encode(),
                instruction(Op::Srliw, 10, 1, 0, 0, 1).encode(),
                instruction(Op::Sraiw, 11, 1, 0, 0, 1).encode(),
                instruction(Op::Ecall, 0, 0, 0, 0, 0).encode(),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        assert_eq!(trace.final_state.reg(3), 0);
        assert_eq!(trace.final_state.reg(4), 2);
        assert_eq!(trace.final_state.reg(5), (-2i64) as u64);
        assert_eq!(trace.final_state.reg(6), 0x7fff_ffff);
        assert_eq!(trace.final_state.reg(7), u64::MAX);
        assert_eq!(trace.final_state.reg(8), 1);
        assert_eq!(trace.final_state.reg(9), (-2i64) as u64);
        assert_eq!(trace.final_state.reg(10), 0x7fff_ffff);
        assert_eq!(trace.final_state.reg(11), u64::MAX);

        let proof = prove_trace_proof(&trace, 8).unwrap();
        for index in 2..=10 {
            assert!(matches!(proof.rows[index], RowCpuProof::W(_)));
        }
        verify_trace_proof(&trace, &proof, 8).unwrap();
    }

    #[test]
    fn trace_proof_covers_unsigned_division() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Addi, 1, 0, 0, 100).encode(),
                instruction(Op::Addi, 2, 0, 0, 7).encode(),
                instruction(Op::Divu, 3, 1, 2, 0).encode(),
                instruction(Op::Remu, 4, 1, 2, 0).encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        assert_eq!(trace.final_state.reg(3), 14);
        assert_eq!(trace.final_state.reg(4), 2);

        let proof = prove_trace_proof(&trace, 8).unwrap();
        assert!(matches!(proof.rows[2], RowCpuProof::Divu(_)));
        assert!(matches!(proof.rows[3], RowCpuProof::Remu(_)));
        verify_trace_proof(&trace, &proof, 8).unwrap();

        let mut tampered = proof;
        if let RowCpuProof::Divu(spartan) = &mut tampered.rows[2] {
            spartan.vw = spartan.vw + F2_128::from(1u64);
        }
        assert!(verify_trace_proof(&trace, &tampered, 8).is_err());
    }

    #[test]
    fn chunked_trace_proof_carries_aux_claims() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Addi, 1, 0, 0, 0x123).encode(),
                instruction(Op::Slli, 2, 1, 0, 8).encode(),
                instruction(Op::Lui, 3, 0, 0, 0x1000_0000).encode(),
                instruction(Op::Sd, 0, 3, 2, 0).encode(),
                instruction(Op::Sh, 0, 3, 1, 4).encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        let proof = prove_chunked_trace(&trace, 8, 2).unwrap();
        let sizes = chunked_proof_sizes(&proof).unwrap();
        assert!(sizes.total() > 0 && sizes.access > 0 && sizes.cpu > 0);
        let aux = proof.aux.as_ref().expect("aux claims");
        assert!(aux.shout.is_some() && aux.shift_router.is_some() && aux.store_router.is_some());
        verify_chunked_trace(&trace, &proof, 8).unwrap();

        let mut tampered = proof;
        tampered
            .aux
            .as_mut()
            .unwrap()
            .store_router
            .as_mut()
            .unwrap()
            .rounds[0][0] = tampered
            .aux
            .as_ref()
            .unwrap()
            .store_router
            .as_ref()
            .unwrap()
            .rounds[0][0]
            + F2_128::from(1u64);
        assert!(verify_chunked_trace(&trace, &tampered, 8).is_err());
    }

    #[test]
    fn chunked_trace_proof_covers_reserved_updates() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Lui, 4, 0, 0, 0x1000_0000).encode(),
                instruction(Op::Addi, 1, 0, 0, 10).encode(),
                instruction(Op::Sd, 0, 4, 1, 0).encode(),
                instruction(Op::LrD, 3, 4, 0, 0).encode(),
                instruction(Op::Addi, 2, 0, 0, 20).encode(),
                instruction(Op::ScD, 5, 4, 2, 0).encode(),
                instruction(Op::Ecall, 0, 0, 0, 0).encode(),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        let proof = prove_chunked_trace(&trace, 8, 2).unwrap();
        assert_eq!(proof.chunks.len(), 4);
        verify_chunked_trace(&trace, &proof, 8).unwrap();
    }

    #[test]
    fn chunked_trace_proof_chains_row_ranges() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Addi, 1, 0, 0, 5).encode(),
                instruction(Op::Addi, 2, 0, 0, 7).encode(),
                instruction(Op::Add, 3, 1, 2, 0).encode(),
                instruction(Op::Andi, 4, 1, 0, 3).encode(),
                instruction(Op::Xori, 5, 1, 0, 6).encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        let proof = prove_chunked_trace(&trace, 8, 2).unwrap();
        assert_eq!(proof.chunks.len(), 3);
        assert_eq!(proof.chunks[0].end, 2);
        assert_eq!(proof.chunks[2].end, trace.rows.len());

        let _statement = Statement {
            program_hash: program_hash(&program),
            rom: trace.rom.clone(),
            trace_commitment: trace_digest(&trace),
            config: config(),
            initial_state: trace.initial_state.clone(),
            initial_ram: trace.initial_ram.clone(),
            final_state: trace.final_state.clone(),
            trace_len: trace.rows.len() as u64,
            output: trace.io_output.clone(),
            input: trace.io_input.clone(),
            halted: trace.halted,
            exit_code: trace.exit_code,
        };
        verify_chunked_trace(&trace, &proof, 8).unwrap();

        let bytes = encode_chunked_proof(&proof).unwrap();
        assert!(!bytes.is_empty());
        let decoded = decode_chunked_proof(&bytes).unwrap();
        verify_chunked_trace(&trace, &decoded, 8).unwrap();
        assert!(decode_chunked_proof(&bytes[..bytes.len() / 2]).is_err());

        let mut tampered = proof.clone();
        tampered.chunks[1].cpu.vw = tampered.chunks[1].cpu.vw + F2_128::from(1u64);
        assert!(verify_chunked_trace(&trace, &tampered, 8).is_err());

        let mut tampered = proof;
        tampered.chain.chunks[1].state_after[0] ^= 1;
        assert!(verify_chunked_trace(&trace, &tampered, 8).is_err());
    }

    #[test]
    fn trace_proof_covers_signed_division() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Addi, 1, 0, 0, -100).encode(),
                instruction(Op::Addi, 2, 0, 0, 7).encode(),
                instruction(Op::Div, 3, 1, 2, 0).encode(),
                instruction(Op::Rem, 4, 1, 2, 0).encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        assert_eq!(trace.final_state.reg(3), (-14i64) as u64);
        assert_eq!(trace.final_state.reg(4), (-2i64) as u64);

        let proof = prove_trace_proof(&trace, 8).unwrap();
        assert!(matches!(proof.rows[2], RowCpuProof::Div(_)));
        assert!(matches!(proof.rows[3], RowCpuProof::Rem(_)));
        verify_trace_proof(&trace, &proof, 8).unwrap();

        let mut tampered = proof;
        if let RowCpuProof::Div(spartan) = &mut tampered.rows[2] {
            spartan.vw = spartan.vw + F2_128::from(1u64);
        }
        assert!(verify_trace_proof(&trace, &tampered, 8).is_err());
    }

    #[test]
    fn reference_pipeline_binds_write_output() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Addi, 11, 0, 0, 0x80).encode(),
                instruction(Op::Addi, 12, 0, 0, 5).encode(),
                instruction(Op::Addi, 10, 0, 0, 1).encode(),
                instruction(Op::Addi, 17, 0, 0, 64).encode(),
                Instruction::new(Op::Ecall).encode(),
                instruction(Op::Addi, 10, 0, 0, 3).encode(),
                instruction(Op::Addi, 17, 0, 0, 93).encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        )
        .with_data(b"hello".to_vec());
        let config = MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x80,
            ram_size: 0x100,
            stack_top: 0x180,
            max_cycles: 100,
        };
        let mut io = ExecutionIo::default();
        let outcome = ReferencePipeline::run_with_io(&program, config, 2, &mut io).unwrap();
        assert_eq!(outcome.trace.io_output, b"hello");
        assert_eq!(outcome.statement.output, b"hello");
        assert_eq!(outcome.trace.exit_code, Some(3));

        let proof = prove_unified_trace(&outcome.trace, 8).unwrap();
        verify_unified_trace_statement(&outcome.statement, &outcome.trace, &proof, 8).unwrap();

        let mut tampered = outcome.statement.clone();
        tampered.output.push(b'!');
        assert!(verify_unified_trace_statement(&tampered, &outcome.trace, &proof, 8).is_err());

        let mut bad_output = outcome.trace.clone();
        bad_output.io_output[0] ^= 1;
        assert!(check_io_writes(&bad_output).is_err());

        let mut bad_ram = outcome.trace.clone();
        bad_ram.initial_ram[0] ^= 1;
        assert!(check_io_writes(&bad_ram).is_err());
    }

    #[test]
    fn trace_proof_covers_read_syscalls() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Lui, 11, 0, 0, 0x1000_0000).encode(),
                instruction(Op::Addi, 12, 0, 0, 16).encode(),
                instruction(Op::Addi, 10, 0, 0, 0).encode(),
                instruction(Op::Addi, 17, 0, 0, 63).encode(),
                instruction(Op::Ecall, 0, 0, 0, 0).encode(),
                instruction(Op::Ld, 13, 11, 0, 0).encode(),
                instruction(Op::Ld, 14, 11, 0, 8).encode(),
                instruction(Op::Ebreak, 0, 0, 0, 0).encode(),
            ],
        );
        let mut io = ExecutionIo::with_input(b"ABCDEFGHIJKLMNOP".to_vec());
        let outcome = ReferencePipeline::run_with_io(&program, config(), 2, &mut io).unwrap();
        assert_eq!(outcome.statement.input, b"ABCDEFGHIJKLMNOP");
        assert_eq!(outcome.trace.io_input, b"ABCDEFGHIJKLMNOP");
        assert_eq!(
            outcome.trace.final_state.reg(13),
            u64::from_le_bytes(*b"ABCDEFGH")
        );
        assert_eq!(
            outcome.trace.final_state.reg(14),
            u64::from_le_bytes(*b"IJKLMNOP")
        );
        assert_eq!(outcome.trace.rows[4].extra_mem.len(), 2);

        for (index, row) in outcome.trace.rows.iter().enumerate() {
            if let Some((system, witness)) = row_cpu_relation(row, 8).unwrap() {
                system.check(&witness).unwrap_or_else(|error| {
                    panic!("row {index} {}: {error}", row.instruction.op.name())
                });
            }
        }

        let proof = prove_unified_trace(&outcome.trace, 8).unwrap();
        verify_unified_trace_statement(&outcome.statement, &outcome.trace, &proof, 8).unwrap();

        let mut tampered = outcome.statement.clone();
        tampered.input[0] ^= 1;
        assert!(verify_unified_trace_statement(&tampered, &outcome.trace, &proof, 8).is_err());

        let mut bad_trace = outcome.trace.clone();
        bad_trace.rows[4].extra_mem[0].value ^= 1;
        assert!(check_io_reads(&bad_trace).is_err());

        let mut bad_args = outcome.trace.clone();
        bad_args.rows[4].syscall.as_mut().unwrap().args[2] = 0;
        assert!(check_io_reads(&bad_args).is_err());
    }

    #[test]
    fn trace_proof_covers_unaligned_reads() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Lui, 11, 0, 0, 0x1000_0000).encode(),
                instruction(Op::Addi, 11, 11, 0, 3).encode(),
                instruction(Op::Addi, 12, 0, 0, 13).encode(),
                instruction(Op::Addi, 10, 0, 0, 0).encode(),
                instruction(Op::Addi, 17, 0, 0, 63).encode(),
                instruction(Op::Ecall, 0, 0, 0, 0).encode(),
                instruction(Op::Lui, 15, 0, 0, 0x1000_0000).encode(),
                instruction(Op::Ld, 13, 15, 0, 0).encode(),
                instruction(Op::Ld, 14, 15, 0, 8).encode(),
                instruction(Op::Ebreak, 0, 0, 0, 0).encode(),
            ],
        );
        let mut io = ExecutionIo::with_input(b"ABCDEFGHIJKLM".to_vec());
        let outcome = ReferencePipeline::run_with_io(&program, config(), 2, &mut io).unwrap();
        assert_eq!(outcome.statement.input, b"ABCDEFGHIJKLM");
        assert_eq!(
            outcome.trace.final_state.reg(13),
            u64::from_le_bytes([0, 0, 0, b'A', b'B', b'C', b'D', b'E'])
        );
        assert_eq!(
            outcome.trace.final_state.reg(14),
            u64::from_le_bytes(*b"FGHIJKLM")
        );
        let read_row = &outcome.trace.rows[5];
        assert_eq!(read_row.extra_mem.len(), 2);
        assert_eq!(read_row.extra_mem[0].addr, 0x1000_0000);
        assert_eq!(read_row.extra_mem[1].addr, 0x1000_0008);

        let proof = prove_unified_trace(&outcome.trace, 8).unwrap();
        verify_unified_trace_statement(&outcome.statement, &outcome.trace, &proof, 8).unwrap();
    }

    #[test]
    fn trace_proof_covers_short_reads() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Lui, 11, 0, 0, 0x1000_0000).encode(),
                instruction(Op::Addi, 12, 0, 0, 8).encode(),
                instruction(Op::Addi, 10, 0, 0, 0).encode(),
                instruction(Op::Addi, 17, 0, 0, 63).encode(),
                instruction(Op::Ecall, 0, 0, 0, 0).encode(),
                instruction(Op::Ld, 13, 11, 0, 0).encode(),
                instruction(Op::Ebreak, 0, 0, 0, 0).encode(),
            ],
        );
        let mut io = ExecutionIo::with_input(b"ABCDE".to_vec());
        let outcome = ReferencePipeline::run_with_io(&program, config(), 2, &mut io).unwrap();
        assert_eq!(outcome.trace.final_state.reg(10), 5);
        assert_eq!(outcome.statement.input, b"ABCDE");
        assert_eq!(
            outcome.trace.final_state.reg(13),
            u64::from_le_bytes([b'A', b'B', b'C', b'D', b'E', 0, 0, 0])
        );
        assert_eq!(outcome.trace.rows[4].extra_mem.len(), 1);

        let proof = prove_unified_trace(&outcome.trace, 8).unwrap();
        verify_unified_trace_statement(&outcome.statement, &outcome.trace, &proof, 8).unwrap();
    }

    #[test]
    fn trace_proof_handles_eof_reads() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Lui, 11, 0, 0, 0x1000_0000).encode(),
                instruction(Op::Addi, 12, 0, 0, 8).encode(),
                instruction(Op::Addi, 10, 0, 0, 0).encode(),
                instruction(Op::Addi, 17, 0, 0, 63).encode(),
                instruction(Op::Ecall, 0, 0, 0, 0).encode(),
                instruction(Op::Ebreak, 0, 0, 0, 0).encode(),
            ],
        );
        let outcome = ReferencePipeline::run(&program, config(), 2).unwrap();
        assert_eq!(outcome.statement.input, Vec::<u8>::new());
        assert_eq!(outcome.trace.final_state.reg(10), 0);
        assert!(outcome.trace.rows[4].extra_mem.is_empty());

        let proof = prove_unified_trace(&outcome.trace, 8).unwrap();
        verify_unified_trace_statement(&outcome.statement, &outcome.trace, &proof, 8).unwrap();
    }

    #[test]
    fn trace_proof_covers_continuing_ecall_syscalls() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Addi, 17, 0, 0, 1000).encode(),
                Instruction::new(Op::Ecall).encode(),
                instruction(Op::Addi, 1, 0, 0, 5).encode(),
                instruction(Op::Addi, 17, 0, 0, 0).encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        assert_eq!(trace.rows[1].next_pc, 0x1008);
        assert_eq!(trace.rows[1].rd, Some(10));
        assert_eq!(trace.final_state.reg(1), 5);

        let proof = prove_trace_proof(&trace, 8).unwrap();
        assert!(matches!(proof.rows[1], RowCpuProof::Skip));
        assert!(matches!(proof.rows[4], RowCpuProof::Skip));
        verify_trace_proof(&trace, &proof, 8).unwrap();
    }

    #[test]
    fn trace_access_rejects_crossing_word_access() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Lui, 4, 0, 0, 0x2000).encode(),
                instruction(Op::Lw, 2, 4, 0, 0).encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let config = MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x2000,
            ram_size: 0x1000,
            stack_top: 0x3000,
            max_cycles: 100,
        };
        let mut trace = execute(&program, config).unwrap();
        let row = trace
            .rows
            .iter_mut()
            .find(|row| row.mem.is_some())
            .expect("load row");
        row.mem.as_mut().expect("load access").addr = 0x2006;
        assert!(matches!(
            prove_trace_access(&trace),
            Err(RuntimeError::Proof(_))
        ));
    }

    #[test]
    fn trace_proof_covers_subword_memory_operations() {
        use magnetar_spec::{Instruction, Op};

        fn subword_config() -> MachineConfig {
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x2000,
                ram_size: 0x1000,
                stack_top: 0x3000,
                max_cycles: 100,
            }
        }

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Addi, 1, 0, 0, 0x1ff).encode(),
                instruction(Op::Lui, 4, 0, 0, 0x2000).encode(),
                instruction(Op::Sb, 0, 4, 1, 3).encode(),
                instruction(Op::Lb, 2, 4, 0, 3).encode(),
                instruction(Op::Lbu, 3, 4, 0, 3).encode(),
                instruction(Op::Sh, 0, 4, 1, 4).encode(),
                instruction(Op::Lh, 5, 4, 0, 4).encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, subword_config()).unwrap();
        assert_eq!(trace.final_state.reg(2), u64::MAX);
        assert_eq!(trace.final_state.reg(3), 0xff);
        assert_eq!(trace.final_state.reg(5), 0x1ff);

        let proof = prove_trace_proof(&trace, 16).unwrap();
        verify_trace_proof(&trace, &proof, 16).unwrap();

        let mut tampered = proof.clone();
        if let RowCpuProof::Store(spartan) = &mut tampered.rows[2] {
            spartan.vw = spartan.vw + F2_128::from(1u64);
        }
        assert!(verify_trace_proof(&trace, &tampered, 16).is_err());
    }

    #[test]
    fn trace_access_proof_interleaves_registers_and_memory() {
        use magnetar_spec::{Instruction, Op};

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
        let trace = execute(&program, config()).unwrap();
        let proof = prove_trace_access(&trace).unwrap();
        verify_trace_access(&trace, &proof).unwrap();

        let mut tampered = proof.clone();
        tampered.ram.read.initial.rounds[0][0] =
            tampered.ram.read.initial.rounds[0][0] + F2_128::from(1u64);
        assert!(verify_trace_access(&trace, &tampered).is_err());

        let mut tampered = proof.clone();
        tampered.registers.read.initial.rounds[0][0] =
            tampered.registers.read.initial.rounds[0][0] + F2_128::from(1u64);
        assert!(verify_trace_access(&trace, &tampered).is_err());

        assert!(verify_trace_access(&trace, &tampered).is_err());
    }

    #[test]
    fn trace_register_chain_matches_execution() {
        use magnetar_spec::{Instruction, Op};

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
        let trace = execute(&program, config()).unwrap();
        let proof = prove_trace_registers(&trace).unwrap();
        verify_trace_registers(&trace, &proof).unwrap();

        let mut tampered = proof.clone();
        tampered.final_values[1] = tampered.final_values[1] + F2_128::from(1u64);
        assert!(verify_trace_registers(&trace, &tampered).is_err());
    }

    #[test]
    fn register_chain_tracks_reads_and_writes() {
        let registers =
            CommittedMemory::new(5, vec![magnetar_constraint::F2_128::from(0u64); 32]).unwrap();
        let operations = [
            RegisterOp::Write {
                index: 1,
                value: magnetar_constraint::F2_128::from(5u64),
            },
            RegisterOp::Read {
                index: 1,
                expected: magnetar_constraint::F2_128::from(5u64),
            },
            RegisterOp::Write {
                index: 2,
                value: magnetar_constraint::F2_128::from(7u64),
            },
        ];
        let proof = prove_register_chain(&registers, &operations).unwrap();
        verify_register_chain(&proof).unwrap();

        let mut tampered = proof.clone();
        if let RegisterStepProof::Read { expected, .. } = &mut tampered.steps[1] {
            *expected = magnetar_constraint::F2_128::from(6u64);
        }
        assert!(verify_register_chain(&tampered).is_err());
    }

    #[test]
    fn memory_chain_tracks_loads_and_stores() {
        let values = (0..16u64)
            .map(|index| magnetar_constraint::F2_128::from(index * 10))
            .collect();
        let memory = CommittedMemory::new(4, values).unwrap();
        let accesses = [
            MemoryAccess::Load { rs1: 2, imm: 3 },
            MemoryAccess::Store {
                rs1: 2,
                imm: 3,
                value: magnetar_constraint::F2_128::from(999u64),
            },
            MemoryAccess::Load { rs1: 2, imm: 3 },
        ];
        let proof = prove_memory_chain(&memory, &accesses).unwrap();
        verify_memory_chain(&proof).unwrap();

        let mut tampered = proof.clone();
        if let MemoryStepProof::Store(store) = &mut tampered.steps[1] {
            store.new_value = magnetar_constraint::F2_128::from(998u64);
        }
        assert!(verify_memory_chain(&tampered).is_err());
    }

    #[test]
    fn runtime_rejects_tampered_chains_and_invalid_tables() {
        let values = (0..16u64)
            .map(|index| F2_128::from(index * 10))
            .collect::<Vec<_>>();
        let memory = CommittedMemory::new(4, values).unwrap();

        let chain = prove_memory_chain(&memory, &[MemoryAccess::Load { rs1: 2, imm: 3 }]).unwrap();
        let mut tampered = chain.clone();
        tampered.final_commitment.root[0] ^= 1;
        assert!(verify_memory_chain(&tampered).is_err());
        assert!(matches!(
            prove_memory_chain(&memory, &[MemoryAccess::Load { rs1: 100, imm: 0 }]),
            Err(RuntimeError::AddressOutOfTable(_))
        ));

        let new_value = F2_128::from(999u64);
        let mut store = prove_store(&memory, 2, 3, new_value).unwrap();
        store.old_value = store.old_value + F2_128::from(1u64);
        assert!(verify_store(&memory, &store).is_err());

        let mut other_values = memory.values.clone();
        other_values[0] = other_values[0] + F2_128::from(1u64);
        other_values[5] = new_value;
        let other = CommittedMemory::new(4, other_values).unwrap();
        let mut store = prove_store(&memory, 2, 3, new_value).unwrap();
        store.new_path = other.tree.as_ref().unwrap().proof(5).unwrap();
        store.new_commitment = other.commitment.clone();
        assert!(verify_store(&memory, &store).is_err());

        let mut store = prove_store(&memory, 2, 3, new_value).unwrap();
        store.new_path.siblings[0][0] ^= 1;
        assert!(verify_store(&memory, &store).is_err());

        let initial_registers =
            CommittedMemory::new(5, (0..32u64).map(F2_128::from).collect::<Vec<_>>()).unwrap();
        let register_proof = prove_register_chain(
            &initial_registers,
            &[RegisterOp::Write {
                index: 5,
                value: F2_128::from(42u64),
            }],
        )
        .unwrap();
        let mut tampered = register_proof.clone();
        tampered.final_values[5] = F2_128::from(43u64);
        assert!(verify_register_chain(&tampered).is_err());
        let mut tampered = register_proof;
        tampered.final_commitment.root[0] ^= 1;
        assert!(verify_register_chain(&tampered).is_err());
    }

    #[test]
    fn trace_access_rejects_invalid_ram_and_access_widths() {
        use magnetar_spec::{Instruction, Op};

        let program = ProgramImage::new(0x1000, vec![Instruction::new(Op::Ecall).encode()]);
        let bad_ram = MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x1ff,
            stack_top: 0x1000_1000,
            max_cycles: 10,
        };
        let trace = execute(&program, bad_ram).unwrap();
        assert!(matches!(
            prove_trace_access(&trace),
            Err(RuntimeError::Proof(_))
        ));

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
                    op: Op::Ld,
                    rd: 2,
                    rs1: 1,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let mut trace = execute(&program, config()).unwrap();
        let row = trace.rows.iter_mut().find(|row| row.mem.is_some()).unwrap();
        row.mem.as_mut().unwrap().width = 3;
        assert!(matches!(
            prove_trace_access(&trace),
            Err(RuntimeError::Proof(_))
        ));

        let mut trace = execute(&program, config()).unwrap();
        let row = trace.rows.iter_mut().find(|row| row.mem.is_some()).unwrap();
        row.mem.as_mut().unwrap().addr = 0x2000_0000;
        assert!(matches!(
            prove_trace_access(&trace),
            Err(RuntimeError::AddressOutOfTable(_))
        ));
    }

    #[test]
    fn register_ops_include_rs2_reads() {
        use magnetar_spec::{Instruction, Op};

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
                Instruction {
                    op: Op::Add,
                    rd: 2,
                    rs1: 1,
                    rs2: 3,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        let operations = register_ops_from_trace(&trace);
        assert!(operations.iter().any(|operation| matches!(
            operation,
            RegisterOp::Read {
                index: 3,
                expected
            } if *expected == F2_128::from(0u64)
        )));
    }

    #[test]
    fn store_proof_updates_exactly_one_cell() {
        let values = (0..16u64)
            .map(|index| magnetar_constraint::F2_128::from(index * 10))
            .collect();
        let memory = CommittedMemory::new(4, values).unwrap();
        let new_value = magnetar_constraint::F2_128::from(999u64);
        let proof = prove_store(&memory, 2, 3, new_value).unwrap();
        assert_eq!(proof.addr, 5);
        assert_eq!(proof.old_value, magnetar_constraint::F2_128::from(50u64));
        verify_store(&memory, &proof).unwrap();

        let mut tampered = proof.clone();
        tampered.new_value = magnetar_constraint::F2_128::from(998u64);
        assert!(verify_store(&memory, &tampered).is_err());

        let mut tampered_path = proof.clone();
        tampered_path.new_path.siblings[0][0] ^= 1;
        assert!(verify_store(&memory, &tampered_path).is_err());
    }

    #[test]
    fn spartan_backend_proves_and_verifies_a_bit_adder() {
        let (system, layout) = magnetar_cpu::bit_addition_constraints(4);
        let witness = layout.witness(3, 5);
        let backend = ConstraintProofBackend::default();
        let proof = backend.prove(&system, &witness).unwrap();
        assert!(backend.verify(&system, &proof).unwrap());
    }

    #[test]
    fn spartan_backend_proves_and_verifies_a_constraint_system() {
        use magnetar_constraint::{Expr, F2_128};

        let a = F2_128::from(6u64);
        let b = F2_128::from(7u64);
        let product = a * b;
        let mut system = ConstraintSystem::new(3);
        system.add_constraint(Expr::var(0), Expr::var(1), Expr::var(2));
        let witness = Witness::new(vec![a, b, product]);

        let backend = ConstraintProofBackend::default();
        let proof = backend.prove(&system, &witness).unwrap();
        assert!(backend.verify(&system, &proof).unwrap());

        let mut tampered = proof.clone();
        tampered.vw = tampered.vw + F2_128::from(1u64);
        assert!(backend.verify(&system, &tampered).is_err());
    }
    #[test]
    fn cpu_lockstep_round_trips() {
        use magnetar_spec::{Instruction, Op};

        let instruction = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Addi, 1, 0, 0, 5).encode(),
                instruction(Op::Addi, 2, 0, 0, 7).encode(),
                instruction(Op::Add, 3, 1, 2, 0).encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, config()).unwrap();
        let proof = prove_cpu_lockstep(&trace, 16).unwrap();
        verify_cpu_lockstep(&trace, &proof, 16).unwrap();

        let mut tampered = proof;
        tampered.segments[0].value = tampered.segments[0].value + F2_128::from(1u64);
        assert!(verify_cpu_lockstep(&trace, &tampered, 16).is_err());
    }
    #[test]
    fn uniform_cpu_batch_proves_with_shared_matrices() {
        use magnetar_cpu::simd::{uniform_cpu_row_layout, UniformCpuRowWitness};
        use magnetar_proof::{prove_shared_simd_spartan, verify_shared_simd_spartan};

        let (_system, layout) = uniform_cpu_row_layout(16);
        let rows: Vec<UniformCpuRowWitness> = vec![
            layout.witness(magnetar_cpu::StepOp::Add, 0x1000, 3, 4, 0),
            layout.witness(magnetar_cpu::StepOp::Xor, 0x1004, 5, 6, 0),
        ];
        let witnesses = rows
            .iter()
            .map(|row| row.witness.clone())
            .collect::<Vec<_>>();
        let pcs = P3BinaryPcs::new(100);
        let proof = prove_shared_simd_spartan(&layout.system, &witnesses, &pcs).unwrap();
        verify_shared_simd_spartan(&layout.system, witnesses.len(), &proof, &pcs).unwrap();
    }
    #[test]
    fn uniform_cpu_batch_enforces_pc_chain_with_shared_matrices() {
        use magnetar_cpu::simd::uniform_cpu_row_layout;
        use magnetar_proof::spartan::MatrixPart;
        use magnetar_proof::{
            prove_spartan_with_matrices, verify_spartan_with_matrices, witness_vector,
            SharedBlockMatrix,
        };

        let (_system, layout) = uniform_cpu_row_layout(16);
        let rows = [
            layout.witness(magnetar_cpu::StepOp::Add, 0x1000, 3, 4, 0),
            layout.witness(magnetar_cpu::StepOp::Xor, 0x1004, 5, 6, 0),
        ];
        let base_cols = witness_vector(&layout.system, &rows[0].witness)
            .unwrap()
            .len();
        let groups = layout.var_groups();
        let pc = groups
            .iter()
            .find(|group| group.kind == magnetar_cpu::CpuVarKind::Pc)
            .unwrap();
        let next_pc = groups
            .iter()
            .find(|group| group.kind == magnetar_cpu::CpuVarKind::NextPc)
            .unwrap();

        let mut extra_a = Vec::new();
        let mut extra_b = Vec::new();
        let mut extra_c = Vec::new();
        for instance in 0..rows.len() - 1 {
            for bit in 0..pc.vars.len() {
                extra_a.push(vec![(
                    instance * base_cols + next_pc.vars[bit],
                    F2_128::from(1u64),
                )]);
                // The constant column of the same instance is 1 in z.
                extra_b.push(vec![(
                    instance * base_cols + layout.num_vars,
                    F2_128::from(1u64),
                )]);
                extra_c.push(vec![(
                    (instance + 1) * base_cols + pc.vars[bit],
                    F2_128::from(1u64),
                )]);
            }
        }
        let a = SharedBlockMatrix::from_system(&layout.system, MatrixPart::A, rows.len())
            .unwrap()
            .with_extra_rows(extra_a);
        let b = SharedBlockMatrix::from_system(&layout.system, MatrixPart::B, rows.len())
            .unwrap()
            .with_extra_rows(extra_b);
        let c = SharedBlockMatrix::from_system(&layout.system, MatrixPart::C, rows.len())
            .unwrap()
            .with_extra_rows(extra_c);
        let mut z = Vec::new();
        for row in &rows {
            z.extend(witness_vector(&layout.system, &row.witness).unwrap());
        }
        assert_eq!(z.len(), a.cols());
        let pcs = P3BinaryPcs::new(100);
        let proof = prove_spartan_with_matrices(&z, &a, &b, &c, &pcs).unwrap();
        verify_spartan_with_matrices(&a, &b, &c, &proof, &pcs).unwrap();
    }
}

#[cfg(test)]
mod cpu_statement_tests {
    use super::*;

    #[test]
    fn core_statement_verifies_without_trace() {
        use magnetar_executor::execute;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

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
        let proof = prove_unified_trace(&trace, 8).unwrap();
        let statement = CoreStatement {
            width: 8,
            shape: proof.shape.clone(),
        };
        let encoded = bincode::serialize(&statement).unwrap();
        let decoded: CoreStatement = bincode::deserialize(&encoded).unwrap();
        verify_core_statement(&proof, &decoded).unwrap();
        let mut bad = statement.clone();
        bad.shape.rows[0].pc = bad.shape.rows[0].pc.wrapping_add(4);
        assert!(verify_core_statement(&proof, &bad).is_err());
        let mut bad = statement;
        bad.shape.rows[0].pc = bad.shape.rows[0].pc.wrapping_add(4);
        assert!(verify_core_statement(&proof, &bad).is_err());
    }

    #[test]
    fn lr_sc_cpu_statement_verifies_without_trace() {
        use magnetar_executor::execute;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

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
                    op: Op::LrD,
                    rd: 2,
                    rs1: 4,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::ScD,
                    rd: 5,
                    rs1: 4,
                    rs2: 2,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Add,
                    rd: 7,
                    rs1: 0,
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
        let proof = prove_unified_trace(&trace, 8).unwrap();
        assert!(proof.gated.is_some());
        let statement = CpuStatement {
            width: 8,
            shape: proof.shape.clone(),
        };
        verify_cpu_statement(&proof, &statement).unwrap();
    }

    #[test]
    fn cpu_statement_verifies_without_trace() {
        use magnetar_executor::execute;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

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
                Instruction {
                    op: Op::Xor,
                    rd: 2,
                    rs1: 1,
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
        let proof = prove_unified_trace(&trace, 8).unwrap();
        assert!(proof.gated.is_some());
        let statement = CpuStatement {
            width: 8,
            shape: proof.shape.clone(),
        };
        verify_cpu_statement(&proof, &statement).unwrap();
    }
}
