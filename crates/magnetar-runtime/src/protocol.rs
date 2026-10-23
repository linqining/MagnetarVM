//! Protocol-level data model for staged component boundaries.
//!
//! Phase 1 of the trait refactor: identify witness segments, carry claims
//! between stages, and wrap component proofs in a serializable bundle. The
//! existing prover/verifier entry points are unchanged; this module is the
//! seam that later `SegmentReducer`/`CpuReduction` implementations use.

use std::collections::HashSet;

use magnetar_constraint::{WitnessLayout, F2_128};
use thiserror::Error;

use crate::binary_router::BinaryRouterProof;
use crate::binary_shout::BinaryShoutProof;
use crate::binary_twist::BinaryTwistRamProof;
use crate::{MosaicSpartanProof, UnifiedTraceProof};

/// Stable identifier for a witness segment within one protocol layout.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct SegmentId(pub u16);

/// Claim family. This is the wire-level tag used to route a claim to the
/// component that consumes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ClaimKind {
    Direct,
    Register,
    Ram,
    RegisterIndex,
    Shift,
    Store,
    Bytecode,
    FetchAddress,
    Increment,
}

impl ClaimKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Register => "register",
            Self::Ram => "ram",
            Self::RegisterIndex => "register-index",
            Self::Shift => "shift",
            Self::Store => "store",
            Self::Bytecode => "bytecode",
            Self::FetchAddress => "fetch-address",
            Self::Increment => "increment",
        }
    }
}

/// One evaluation claim produced by a stage.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Claim {
    pub kind: ClaimKind,
    pub segment: SegmentId,
    pub point: Vec<F2_128>,
    pub value: F2_128,
}

impl Claim {
    pub fn new(kind: ClaimKind, segment: SegmentId, point: Vec<F2_128>, value: F2_128) -> Self {
        Self {
            kind,
            segment,
            point,
            value,
        }
    }
}

/// A set of claims moving between stages. Claims are explicitly consumed so
/// that a missing Shout/Router/PCS step is a hard error rather than silently
/// dropped work.
#[derive(Clone, Debug, Default)]
pub struct ClaimSet {
    claims: Vec<Claim>,
    consumed: HashSet<usize>,
}

impl ClaimSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_claims(claims: Vec<Claim>) -> Self {
        Self {
            claims,
            consumed: HashSet::new(),
        }
    }

    pub fn push(&mut self, claim: Claim) {
        self.claims.push(claim);
    }

    pub fn extend(&mut self, claims: impl IntoIterator<Item = Claim>) {
        self.claims.extend(claims);
    }

    pub fn len(&self) -> usize {
        self.claims.len()
    }

    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }

    pub fn remaining(&self) -> usize {
        self.claims.len() - self.consumed.len()
    }

    pub fn claims(&self) -> &[Claim] {
        &self.claims
    }

    /// Take the first unconsumed claim of `kind`.
    pub fn take(&mut self, kind: ClaimKind) -> Option<Claim> {
        let index = self
            .claims
            .iter()
            .enumerate()
            .position(|(index, claim)| claim.kind == kind && !self.consumed.contains(&index))?;
        self.consumed.insert(index);
        Some(self.claims[index].clone())
    }

    /// Take every unconsumed claim of `kind`.
    pub fn take_all(&mut self, kind: ClaimKind) -> Vec<Claim> {
        let mut taken = Vec::new();
        for index in 0..self.claims.len() {
            if self.claims[index].kind == kind && !self.consumed.contains(&index) {
                self.consumed.insert(index);
                taken.push(self.claims[index].clone());
            }
        }
        taken
    }

    /// Take every remaining claim.
    pub fn drain(&mut self) -> Vec<Claim> {
        let mut taken = Vec::new();
        for index in 0..self.claims.len() {
            if !self.consumed.contains(&index) {
                self.consumed.insert(index);
                taken.push(self.claims[index].clone());
            }
        }
        taken
    }

    pub fn unconsumed(&self) -> impl Iterator<Item = &Claim> {
        self.claims
            .iter()
            .enumerate()
            .filter(move |(index, _)| !self.consumed.contains(index))
            .map(|(_, claim)| claim)
    }

    pub fn expect_consumed(&self) -> Result<(), ClaimError> {
        let remaining = self.remaining();
        if remaining == 0 {
            return Ok(());
        }
        let first = self
            .unconsumed()
            .next()
            .expect("remaining count is nonzero");
        Err(ClaimError::Unconsumed {
            remaining,
            first_kind: first.kind,
            segment: first.segment,
        })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClaimError {
    #[error("unconsumed claim ({remaining} remaining), first {first_kind:?} on {segment:?}")]
    Unconsumed {
        remaining: usize,
        first_kind: ClaimKind,
        segment: SegmentId,
    },
}

/// Maps existing layout segment names to stable ids without changing the
/// constraint crate's layout representation.
#[derive(Clone, Debug, Default)]
pub struct SegmentCatalog {
    names: Vec<String>,
}

impl SegmentCatalog {
    pub fn from_layout(layout: &WitnessLayout) -> Self {
        Self {
            names: layout
                .segments
                .iter()
                .map(|segment| segment.name.clone())
                .collect(),
        }
    }

    pub fn from_names(names: Vec<String>) -> Self {
        Self { names }
    }

    pub fn id(&self, name: &str) -> Option<SegmentId> {
        self.names
            .iter()
            .position(|candidate| candidate == name)
            .map(|index| SegmentId(index as u16))
    }

    pub fn name(&self, id: SegmentId) -> Option<&str> {
        self.names.get(usize::from(id.0)).map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

/// Component proof boundary. Algorithms stay in the components; this enum is
/// the serializable wire format used by the orchestrator.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum StageProof {
    Cpu(MosaicSpartanProof),
    Registers(BinaryTwistRamProof),
    Ram(BinaryTwistRamProof),
    Shout(BinaryShoutProof),
    ShiftRouter(BinaryRouterProof),
    StoreRouter(BinaryRouterProof),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum StageId {
    Cpu,
    Registers,
    Ram,
    Shout,
    ShiftRouter,
    StoreRouter,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("missing stage {0:?}")]
    MissingStage(StageId),
    #[error("duplicate stage {0:?}")]
    DuplicateStage(StageId),
    #[error("unexpected stage {0:?}")]
    UnexpectedStage(StageId),
}

/// Serializable proof bundle. `from_unified`/`into_unified` preserve the
/// existing `UnifiedTraceProof` wire format exactly (same proof structs, same
/// commitment), they only expose the component boundaries.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProofBundle {
    pub trace_commitment: [u8; 32],
    pub stages: Vec<(StageId, StageProof)>,
}

impl ProofBundle {
    pub fn from_unified(proof: &UnifiedTraceProof) -> Self {
        let mut stages = vec![
            (StageId::Cpu, StageProof::Cpu(proof.cpu.clone())),
            (
                StageId::Registers,
                StageProof::Registers(proof.access.registers.clone()),
            ),
            (StageId::Ram, StageProof::Ram(proof.access.ram.clone())),
        ];
        if let Some(shout) = &proof.shout {
            stages.push((StageId::Shout, StageProof::Shout(shout.clone())));
        }
        if let Some(router) = &proof.shift_router {
            stages.push((
                StageId::ShiftRouter,
                StageProof::ShiftRouter(router.clone()),
            ));
        }
        if let Some(router) = &proof.store_router {
            stages.push((
                StageId::StoreRouter,
                StageProof::StoreRouter(router.clone()),
            ));
        }
        Self {
            trace_commitment: proof.trace_commitment,
            stages,
        }
    }

    pub fn into_unified(self) -> Result<UnifiedTraceProof, ProtocolError> {
        let mut cpu = None;
        let mut registers = None;
        let mut ram = None;
        let mut shout = None;
        let mut shift_router = None;
        let mut store_router = None;
        for (stage, proof) in self.stages {
            match (stage, proof) {
                (StageId::Cpu, StageProof::Cpu(value)) => set_once(&mut cpu, value, stage)?,
                (StageId::Registers, StageProof::Registers(value)) => {
                    set_once(&mut registers, value, stage)?
                }
                (StageId::Ram, StageProof::Ram(value)) => set_once(&mut ram, value, stage)?,
                (StageId::Shout, StageProof::Shout(value)) => set_once(&mut shout, value, stage)?,
                (StageId::ShiftRouter, StageProof::ShiftRouter(value)) => {
                    set_once(&mut shift_router, value, stage)?
                }
                (StageId::StoreRouter, StageProof::StoreRouter(value)) => {
                    set_once(&mut store_router, value, stage)?
                }
                (stage, _) => return Err(ProtocolError::UnexpectedStage(stage)),
            }
        }
        Ok(UnifiedTraceProof {
            access: crate::TraceAccessProof {
                registers: registers.ok_or(ProtocolError::MissingStage(StageId::Registers))?,
                ram: ram.ok_or(ProtocolError::MissingStage(StageId::Ram))?,
            },
            trace_commitment: self.trace_commitment,
            cpu: cpu.ok_or(ProtocolError::MissingStage(StageId::Cpu))?,
            shout,
            shift_router,
            store_router,
        })
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T, stage: StageId) -> Result<(), ProtocolError> {
    if slot.is_some() {
        return Err(ProtocolError::DuplicateStage(stage));
    }
    *slot = Some(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_constraint::WitnessLayout;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    #[test]
    fn claim_set_consumes_and_rejects_forgotten_claims() {
        let segment = SegmentId(3);
        let mut claims = ClaimSet::new();
        claims.push(Claim::new(
            ClaimKind::Register,
            segment,
            vec![F2_128::from(1u64)],
            F2_128::from(2u64),
        ));
        claims.push(Claim::new(
            ClaimKind::Ram,
            segment,
            vec![F2_128::from(3u64)],
            F2_128::from(4u64),
        ));
        assert_eq!(claims.remaining(), 2);

        let register = claims.take(ClaimKind::Register).expect("register claim");
        assert_eq!(register.kind, ClaimKind::Register);
        assert_eq!(claims.remaining(), 1);
        assert!(claims.expect_consumed().is_err());

        let ram = claims.take(ClaimKind::Ram).expect("ram claim");
        assert_eq!(ram.kind, ClaimKind::Ram);
        assert!(claims.expect_consumed().is_ok());
    }

    #[test]
    fn segment_catalog_maps_layout_names_to_ids() {
        let layout = WitnessLayout::new(vec![
            magnetar_constraint::Segment::new(
                "cpu.state",
                0,
                8,
                magnetar_constraint::SegmentKind::Direct,
                magnetar_constraint::SegmentOwner::Cpu,
            ),
            magnetar_constraint::Segment::new(
                "ram.value",
                8,
                8,
                magnetar_constraint::SegmentKind::Virtual,
                magnetar_constraint::SegmentOwner::Memory(magnetar_constraint::MemoryKind::Ram),
            ),
        ])
        .expect("valid layout");
        let catalog = SegmentCatalog::from_layout(&layout);
        assert_eq!(catalog.len(), 2);
        let id = catalog.id("ram.value").expect("segment");
        assert_eq!(id, SegmentId(1));
        assert_eq!(catalog.name(id), Some("ram.value"));
        assert!(catalog.id("missing").is_none());
    }

    #[test]
    fn proof_bundle_preserves_unified_proof_bytes() {
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
        .expect("trace");
        let proof = crate::prove_unified_trace(&trace, 8).expect("proof");
        let expected = bincode::serialize(&proof).expect("encode");

        let bundle = ProofBundle::from_unified(&proof);
        let encoded = bincode::serialize(&bundle).expect("encode bundle");
        let decoded: ProofBundle = bincode::deserialize(&encoded).expect("decode bundle");
        assert!(decoded.stages.len() >= 3);

        let restored = decoded.into_unified().expect("restore unified proof");
        let actual = bincode::serialize(&restored).expect("encode restored");
        assert_eq!(expected, actual);
        crate::verify_unified_trace(&trace, &restored, 8).expect("verify restored");
    }
    #[test]
    fn twist_reducer_is_a_claim_reducer() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 9,
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
        .expect("trace");
        let witness = magnetar_memory::BinaryTwistWitness::from_trace(&trace).expect("witness");
        let reducer = TwistReducer;
        let (proof, ()) = reducer.prove(&witness, &()).expect("prove");
        reducer.verify(&witness, &(), &proof).expect("verify");
    }
}

/// Minimal Phase-1 component boundary: a reducer turns a witness into a proof
/// and verified claims. `Input`/`Output` are placeholders until the
/// orchestrator passes typed `ClaimSet` values (Phase 2); the key property is
/// that each component implements the same trait without owning protocol
/// sequencing.
pub trait ClaimReducer<W> {
    type Proof;
    type Input;
    type Output;
    type Error;

    fn prove(
        &self,
        witness: &W,
        input: &Self::Input,
    ) -> Result<(Self::Proof, Self::Output), Self::Error>;

    fn verify(
        &self,
        witness: &W,
        input: &Self::Input,
        proof: &Self::Proof,
    ) -> Result<Self::Output, Self::Error>;
}

/// BinaryTwist RAM/register reducer.
#[derive(Clone, Copy, Debug, Default)]
pub struct TwistReducer;

impl ClaimReducer<magnetar_memory::BinaryTwistWitness> for TwistReducer {
    type Proof = BinaryTwistRamProof;
    type Input = ();
    type Output = ();
    type Error = crate::RuntimeError;

    fn prove(
        &self,
        witness: &magnetar_memory::BinaryTwistWitness,
        _input: &Self::Input,
    ) -> Result<(Self::Proof, Self::Output), Self::Error> {
        let proof = crate::binary_twist::prove_binary_twist_ram(witness)
            .map_err(|error| crate::RuntimeError::Proof(error.to_string()))?;
        Ok((proof, ()))
    }

    fn verify(
        &self,
        witness: &magnetar_memory::BinaryTwistWitness,
        _input: &Self::Input,
        proof: &Self::Proof,
    ) -> Result<Self::Output, Self::Error> {
        let valid = crate::binary_twist::verify_binary_twist_ram(witness, proof)
            .map_err(|error| crate::RuntimeError::Proof(error.to_string()))?;
        if !valid {
            return Err(crate::RuntimeError::Proof(
                "BinaryTwist proof rejected".into(),
            ));
        }
        Ok(())
    }
}

/// BinaryShout bytecode reducer.
#[derive(Clone, Copy, Debug, Default)]
pub struct ShoutReducer;

impl ClaimReducer<crate::binary_shout::BinaryShoutWitness> for ShoutReducer {
    type Proof = BinaryShoutProof;
    type Input = ();
    type Output = ();
    type Error = magnetar_proof::ProofError;

    fn prove(
        &self,
        witness: &crate::binary_shout::BinaryShoutWitness,
        _input: &Self::Input,
    ) -> Result<(Self::Proof, Self::Output), Self::Error> {
        Ok((crate::binary_shout::prove_binary_shout(witness)?, ()))
    }

    fn verify(
        &self,
        witness: &crate::binary_shout::BinaryShoutWitness,
        _input: &Self::Input,
        proof: &Self::Proof,
    ) -> Result<Self::Output, Self::Error> {
        if !crate::binary_shout::verify_binary_shout(witness, proof)? {
            return Err(magnetar_proof::ProofError::Pcs(
                "BinaryShout proof rejected".into(),
            ));
        }
        Ok(())
    }
}

/// BinaryRouter shift/store reducer.
#[derive(Clone, Copy, Debug, Default)]
pub struct RouterReducer;

impl ClaimReducer<crate::binary_router::BinaryRouterWitness> for RouterReducer {
    type Proof = BinaryRouterProof;
    type Input = ();
    type Output = ();
    type Error = magnetar_proof::ProofError;

    fn prove(
        &self,
        witness: &crate::binary_router::BinaryRouterWitness,
        _input: &Self::Input,
    ) -> Result<(Self::Proof, Self::Output), Self::Error> {
        Ok((crate::binary_router::prove_binary_router(witness)?, ()))
    }

    fn verify(
        &self,
        witness: &crate::binary_router::BinaryRouterWitness,
        _input: &Self::Input,
        proof: &Self::Proof,
    ) -> Result<Self::Output, Self::Error> {
        if !crate::binary_router::verify_binary_router(witness, proof)? {
            return Err(magnetar_proof::ProofError::Pcs(
                "BinaryRouter proof rejected".into(),
            ));
        }
        Ok(())
    }
}
