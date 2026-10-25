//! Protocol-level data model for staged component boundaries.
//!
//! Phase 1 of the trait refactor: identify witness segments, carry claims
//! between stages, and wrap component proofs in a serializable bundle. The
//! existing prover/verifier entry points are unchanged; this module is the
//! seam that later `SegmentReducer`/`CpuReduction` implementations use.

use std::collections::HashSet;

use magnetar_constraint::{
    ConstraintSystem, MemoryKind, RoutingKind, Segment, SegmentKind, SegmentOwner, Witness,
    WitnessLayout, F2_128,
};
use magnetar_pcs::mosaic::PackedMosaic;
use magnetar_proof::{
    prove_lockstep, verify_lockstep, BitPcs, LockstepProof, Pcs, RingSwitchPackedBitPcs,
    SpartanError,
};
use thiserror::Error;

use crate::binary_router::BinaryRouterProof;
use crate::binary_shout::BinaryShoutProof;
use crate::binary_twist::BinaryTwistRamProof;
use crate::UnifiedTraceProof;

use magnetar_memory::BinaryTwistWitness;
use magnetar_pcs::{P3BinaryPcs, P3MosaicCommitment, P3MosaicPoint, P3MosaicTable, P3SharedPcs};
use magnetar_proof::virtual_spartan::SegmentClaim;
use magnetar_proof::{verify_lockstep_claims, witness_vector, LockstepClaims, Mle};
use magnetar_spec::Trace;

use crate::binary_router::{
    prove_binary_router_claims, verify_binary_router_claims, BinaryRouterWitness, RouterMode,
};
use crate::binary_shout::{
    prove_binary_shout_claims, verify_binary_shout_claims, BinaryShoutWitness,
};
use crate::binary_twist::{batch_tables, BatchTables};
use crate::{
    check_trace_linkage, cpu_segment_layout, merged_cpu_system, prove_trace_access_shared,
    split_cpu_relations, trace_digest, verify_trace_access_shared, RuntimeError, TraceAccessProof,
};

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
    Selector,
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
            Self::Selector => "selector",
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
    Cpu(LockstepClaims<magnetar_pcs::P3MosaicCommitment>),
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
    #[error("Virtual Spartan produced an unrouted claim {0:?}")]
    UnroutedClaim(ClaimKind),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimSink {
    MosaicPcs,
    TwistRegisters,
    TwistRam,
    RouterShift,
    RouterStore,
    Shout,
}

pub const CLAIM_CONSUMERS: &[(ClaimKind, ClaimSink)] = &[
    (ClaimKind::Direct, ClaimSink::MosaicPcs),
    (ClaimKind::Register, ClaimSink::TwistRegisters),
    (ClaimKind::Increment, ClaimSink::MosaicPcs),
    (ClaimKind::Ram, ClaimSink::TwistRam),
    (ClaimKind::Shift, ClaimSink::RouterShift),
    (ClaimKind::Store, ClaimSink::RouterStore),
    (ClaimKind::Bytecode, ClaimSink::Shout),
    (ClaimKind::RegisterIndex, ClaimSink::Shout),
    (ClaimKind::Selector, ClaimSink::Shout),
    (ClaimKind::FetchAddress, ClaimSink::MosaicPcs),
];

/// Serializable proof bundle. `from_unified`/`into_unified` preserve the
/// existing `UnifiedTraceProof` wire format exactly (same proof structs, same
/// commitment), they only expose the component boundaries.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProofBundle {
    pub trace_commitment: [u8; 32],
    pub trace_claim_root: [u8; 32],
    pub claim_proof: Option<crate::trace_claims::ClaimProof>,
    pub opening: Option<magnetar_pcs::P3MosaicOpening>,
    pub e5_opening: Option<crate::E5Opening>,
    pub field_opening: Option<magnetar_pcs::P3MosaicOpening>,
    pub field_pcs_commitment: Option<P3MosaicCommitment>,
    pub field_tables: Vec<usize>,
    pub stages: Vec<(StageId, StageProof)>,
    pub amo: Option<crate::amo_bundle::AmoBundleProof>,
    pub gated: Option<crate::GatedCpuClaims>,
    pub shape: crate::cpu_shape::CpuShape,
    pub register_index: usize,
    pub ram_index: usize,
    pub rom_index: usize,
    pub shout_index: Option<usize>,
    pub shift_router_index: Option<usize>,
    pub store_router_index: Option<usize>,
    pub trace_index: usize,
    pub trace_claims: Vec<(magnetar_pcs::P3MosaicPoint, Vec<F2_128>)>,
    pub table_batches: Vec<crate::TableBatchProof>,
    pub width: usize,
    pub commitment: P3MosaicCommitment,
    pub packed_shout: Option<crate::packed_shout::PackedShoutProof>,
}

impl ProofBundle {
    pub fn from_unified(proof: &UnifiedTraceProof) -> Self {
        let mut stages = Vec::new();
        if let Some(cpu) = &proof.cpu {
            stages.push((StageId::Cpu, StageProof::Cpu(cpu.clone())));
        }
        stages.push((
            StageId::Registers,
            StageProof::Registers(proof.access.registers.clone()),
        ));
        stages.push((StageId::Ram, StageProof::Ram(proof.access.ram.clone())));
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
            trace_claim_root: proof.trace_claim_root,
            claim_proof: proof.claim_proof.clone(),
            opening: proof.opening.clone(),
            e5_opening: proof.e5_opening.clone(),
            field_opening: proof.field_opening.clone(),
            field_pcs_commitment: proof.field_pcs_commitment.clone(),
            field_tables: proof.field_tables.clone(),
            stages,
            amo: proof.amo.clone(),
            gated: proof.gated.clone(),
            shape: proof.shape.clone(),
            register_index: proof.register_index,
            ram_index: proof.ram_index,
            rom_index: proof.rom_index,
            shout_index: proof.shout_index,
            shift_router_index: proof.shift_router_index,
            store_router_index: proof.store_router_index,
            trace_index: proof.trace_index,
            trace_claims: proof.trace_claims.clone(),
            table_batches: proof.table_batches.clone(),
            width: proof.width,
            commitment: proof.commitment.clone(),
            packed_shout: proof.packed_shout.clone(),
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
            trace_claim_root: self.trace_claim_root,
            claim_proof: self.claim_proof,
            opening: self.opening,
            e5_opening: self.e5_opening,
            field_opening: self.field_opening,
            field_pcs_commitment: self.field_pcs_commitment,
            field_tables: self.field_tables,
            amo: self.amo,
            gated: self.gated,
            selected_cpu: None,
            shape: self.shape,
            register_index: self.register_index,
            ram_index: self.ram_index,
            rom_index: self.rom_index,
            shout_index: self.shout_index,
            shift_router_index: self.shift_router_index,
            store_router_index: self.store_router_index,
            trace_index: self.trace_index,
            trace_claims: self.trace_claims,
            table_batches: self.table_batches,
            width: self.width,
            commitment: self.commitment,
            packed_shout: self.packed_shout,
            cpu,
            shout: None,
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
        .expect("trace");
        let proof = crate::prove_unified_trace(&trace, 8).expect("proof");
        let expected = bincode::serialize(&proof).expect("encode");

        let bundle = ProofBundle::from_unified(&proof);
        let encoded = bincode::serialize(&bundle).expect("encode bundle");
        let decoded: ProofBundle = bincode::deserialize(&encoded).expect("decode bundle");
        assert!(decoded.stages.len() >= 2);

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

/// PCS extension used by the protocol orchestrator. The default digest is
/// stable across P3/packed/Ligerito implementations as long as the
/// implementation exposes canonical commitment bytes.
pub trait MosaicPcs: Pcs {
    fn commitment_digest(&self, commitment: &Self::Commitment) -> [u8; 32] {
        magnetar_transcript::sha256(&self.commitment_bytes(commitment))
    }
}

impl<P: Pcs> MosaicPcs for P {}

/// CPU reduction boundary: two relations over one witness, one lockstep
/// proof. This is the trait Virtual Spartan will eventually implement.
pub trait CpuReduction<P: Pcs> {
    type Layout;

    fn prove(
        &self,
        system_a: &ConstraintSystem,
        system_b: &ConstraintSystem,
        witness: &Witness,
        layout: &Self::Layout,
        pcs: &P,
    ) -> Result<LockstepProof<P::Commitment, P::Opening>, SpartanError>;

    fn verify(
        &self,
        system_a: &ConstraintSystem,
        system_b: &ConstraintSystem,
        layout: &Self::Layout,
        proof: &LockstepProof<P::Commitment, P::Opening>,
        pcs: &P,
    ) -> Result<(), SpartanError>;
}

/// Current binary-field lockstep CPU reduction.
#[derive(Clone, Copy, Debug, Default)]
pub struct LockstepReduction;

impl<P: Pcs> CpuReduction<P> for LockstepReduction {
    type Layout = WitnessLayout;

    fn prove(
        &self,
        system_a: &ConstraintSystem,
        system_b: &ConstraintSystem,
        witness: &Witness,
        layout: &Self::Layout,
        pcs: &P,
    ) -> Result<LockstepProof<P::Commitment, P::Opening>, SpartanError> {
        prove_lockstep(system_a, system_b, witness, layout, pcs)
    }

    fn verify(
        &self,
        system_a: &ConstraintSystem,
        system_b: &ConstraintSystem,
        layout: &Self::Layout,
        proof: &LockstepProof<P::Commitment, P::Opening>,
        pcs: &P,
    ) -> Result<(), SpartanError> {
        verify_lockstep(system_a, system_b, layout, proof, pcs)
    }
}

/// One stage in the protocol plan. `consumes`/`produces` are the claim
/// families at that boundary; they make the claim routing explicit instead of
/// relying on the order of calls in the prover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StageSpec {
    pub id: StageId,
    pub consumes: &'static [ClaimKind],
    pub produces: &'static [ClaimKind],
    pub optional: bool,
}

#[derive(Clone, Debug)]
pub struct ProtocolPlan {
    stages: Vec<StageSpec>,
    execution: Vec<ExecutionStage>,
}

impl ProtocolPlan {
    pub fn unified() -> Self {
        Self {
            execution: UNIFIED_EXECUTION_STAGES.to_vec(),
            stages: vec![
                StageSpec {
                    id: StageId::Cpu,
                    consumes: &[],
                    produces: &[
                        ClaimKind::Direct,
                        ClaimKind::Register,
                        ClaimKind::Ram,
                        ClaimKind::Shift,
                        ClaimKind::Store,
                        ClaimKind::Bytecode,
                    ],
                    optional: true,
                },
                StageSpec {
                    id: StageId::Registers,
                    consumes: &[ClaimKind::Register],
                    produces: &[ClaimKind::Increment, ClaimKind::RegisterIndex],
                    optional: false,
                },
                StageSpec {
                    id: StageId::Ram,
                    consumes: &[ClaimKind::Ram],
                    produces: &[ClaimKind::Increment],
                    optional: false,
                },
                StageSpec {
                    id: StageId::ShiftRouter,
                    consumes: &[ClaimKind::Shift],
                    produces: &[ClaimKind::Selector, ClaimKind::Direct],
                    optional: true,
                },
                StageSpec {
                    id: StageId::StoreRouter,
                    consumes: &[ClaimKind::Store, ClaimKind::Increment],
                    produces: &[ClaimKind::Selector, ClaimKind::Direct],
                    optional: true,
                },
                StageSpec {
                    id: StageId::Shout,
                    consumes: &[
                        ClaimKind::Bytecode,
                        ClaimKind::RegisterIndex,
                        ClaimKind::Selector,
                    ],
                    produces: &[ClaimKind::FetchAddress],
                    optional: true,
                },
            ],
        }
    }

    pub fn with_execution(mut self, execution: Vec<ExecutionStage>) -> Self {
        self.execution = execution;
        self
    }

    pub fn stages(&self) -> &[StageSpec] {
        &self.stages
    }

    pub fn execution(&self) -> &[ExecutionStage] {
        &self.execution
    }

    pub fn stage(&self, id: StageId) -> Option<&StageSpec> {
        self.stages.iter().find(|stage| stage.id == id)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        let mut seen = HashSet::new();
        for stage in &self.stages {
            if !seen.insert(stage.id) {
                return Err(ProtocolError::DuplicateStage(stage.id));
            }
        }
        Ok(())
    }

    /// Claim sinks corresponding to the specialized arguments. This is the
    /// bookkeeping side of consumption: the cryptographic reducers still have
    /// their own inputs until the CPU/aux openings are split, but every routed
    /// claim must have an owner.
    pub fn consume_virtual_claims(&self, claims: &mut ClaimSet) -> Result<(), ProtocolError> {
        for (kind, _sink) in CLAIM_CONSUMERS {
            let _ = claims.take_all(*kind);
        }
        claims.expect_consumed().map_err(|_| {
            ProtocolError::UnroutedClaim(
                claims
                    .unconsumed()
                    .next()
                    .map(|claim| claim.kind)
                    .unwrap_or(ClaimKind::Direct),
            )
        })
    }

    pub fn check_virtual_claims(&self, claims: &ClaimSet) -> Result<(), ProtocolError> {
        let produced: HashSet<ClaimKind> = if let Some(stage) = self.stage(StageId::Cpu) {
            stage.produces.iter().copied().collect()
        } else {
            self.stages
                .iter()
                .flat_map(|stage| stage.produces.iter().copied())
                .collect()
        };
        for claim in claims.claims() {
            if !produced.contains(&claim.kind) {
                return Err(ProtocolError::UnroutedClaim(claim.kind));
            }
        }
        Ok(())
    }

    pub fn check_bundle(&self, bundle: &ProofBundle) -> Result<(), ProtocolError> {
        let mut seen = HashSet::new();
        for (stage, _) in &bundle.stages {
            if !seen.insert(*stage) {
                return Err(ProtocolError::DuplicateStage(*stage));
            }
        }
        for stage in &self.stages {
            if !stage.optional && !seen.contains(&stage.id) {
                return Err(ProtocolError::MissingStage(stage.id));
            }
        }
        Ok(())
    }
}

/// Phase-3 orchestrator. The inner proof/verification routines still execute
/// the established sequence; the plan is the single declaration of stage
/// order, required stages, and claim routing. Future components register in
/// the plan and the inner routine shrinks to plan-driven dispatch.
#[derive(Clone, Debug)]
pub struct Orchestrator {
    plan: ProtocolPlan,
}

impl Default for Orchestrator {
    fn default() -> Self {
        Self::new(ProtocolPlan::unified())
    }
}

impl Orchestrator {
    pub fn new(plan: ProtocolPlan) -> Self {
        Self { plan }
    }

    pub fn plan(&self) -> &ProtocolPlan {
        &self.plan
    }

    pub fn prove(
        &self,
        trace: &magnetar_spec::Trace,
        width: usize,
    ) -> Result<UnifiedTraceProof, crate::RuntimeError> {
        self.prove_group_opt(trace, width, None)
    }

    pub fn prove_group(
        &self,
        trace: &magnetar_spec::Trace,
        width: usize,
        group: usize,
    ) -> Result<UnifiedTraceProof, crate::RuntimeError> {
        self.prove_group_opt(trace, width, Some(group))
    }

    fn prove_group_opt(
        &self,
        trace: &magnetar_spec::Trace,
        width: usize,
        group: Option<usize>,
    ) -> Result<UnifiedTraceProof, crate::RuntimeError> {
        let proof = crate::prove_unified_with_plan_group(trace, width, &self.plan, group)?;
        let bundle = ProofBundle::from_unified(&proof);
        self.plan
            .check_bundle(&bundle)
            .map_err(|error| crate::RuntimeError::Proof(error.to_string()))?;
        Ok(proof)
    }

    pub fn verify(
        &self,
        trace: &magnetar_spec::Trace,
        proof: &UnifiedTraceProof,
        width: usize,
    ) -> Result<(), crate::RuntimeError> {
        let bundle = ProofBundle::from_unified(proof);
        self.plan
            .check_bundle(&bundle)
            .map_err(|error| crate::RuntimeError::Proof(error.to_string()))?;
        crate::verify_unified_with_plan(trace, proof, width, &self.plan)
    }
}

#[cfg(test)]
mod phase_tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_pcs::{P3BinaryPcs, P3SharedPcs};
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
                    imm: 11,
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
        .expect("trace")
    }

    #[test]
    fn unified_auto_handles_high_multiply() {
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};
        let addi = |rd, imm| {
            Instruction {
                op: Op::Addi,
                rd,
                rs1: 0,
                rs2: 0,
                imm,
                shamt: 0,
            }
            .encode()
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                addi(1, 5),
                addi(2, 3),
                Instruction {
                    op: Op::Mulh,
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
        let proof = crate::prove_unified_trace_auto(&trace, 8).expect("high-mul proof");
        assert!(proof.selected_cpu.is_some());
        assert!(proof.gated.is_none());
        crate::verify_unified_trace(&trace, &proof, 8).expect("verify high-mul");
    }

    #[test]
    fn unified_auto_selects_native_dynamic() {
        let trace = trace();
        let proof = crate::prove_unified_trace_auto(&trace, 8).expect("auto proof");
        assert!(proof.selected_cpu.is_some());
        assert!(proof.gated.is_none());
        crate::verify_unified_trace(&trace, &proof, 8).expect("verify auto proof");
    }

    #[test]
    fn unified_dynamic_native_round_trips() {
        let trace = trace();
        let full = crate::prove_unified_trace(&trace, 8).expect("full");
        eprintln!(
            "full shout={} packed={} shift={} store={}",
            full.shout.is_some(),
            full.packed_shout.is_some(),
            full.shift_router.is_some(),
            full.store_router.is_some()
        );
        let proof =
            crate::prove_unified_trace_dynamic_native(&trace, 8).expect("native dynamic proof");
        eprintln!(
            "native shout={} packed={} shift={} store={}",
            proof.shout.is_some(),
            proof.packed_shout.is_some(),
            proof.shift_router.is_some(),
            proof.store_router.is_some()
        );
        let result = crate::verify_unified_trace(&trace, &proof, 8);
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn unified_dynamic_variant_round_trips() {
        let trace = trace();
        let proof = crate::prove_unified_trace_dynamic(&trace, 8).expect("dynamic proof");
        crate::verify_unified_trace(&trace, &proof, 8).expect("verify dynamic proof");
        assert!(proof.gated.is_none());
        assert!(proof.cpu.is_none());
        assert!(proof.e5_opening.is_none());
        assert!(proof.selected_cpu.is_some());
    }

    #[test]
    fn unified_dynamic_selected_without_e5_opening() {
        let trace = trace();
        let mut proof = crate::prove_unified_trace(&trace, 8).expect("unified proof");
        proof.gated = None;
        proof.cpu = None;
        proof.e5_opening = None;
        proof.opening = None;
        let claims = crate::simd_dual::prove_dynamic_cpu_claims(&trace, 8, &selected_backend())
            .expect("dynamic selected claims");
        proof.selected_cpu = Some(claims);
        let result = crate::verify_unified_trace(&trace, &proof, 8);
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn unified_proof_verifies_dynamic_selected_cpu_claims() {
        let trace = trace();
        let mut proof = crate::prove_unified_trace(&trace, 8).expect("unified proof");
        let claims = crate::simd_dual::prove_dynamic_cpu_claims(&trace, 8, &selected_backend())
            .expect("dynamic selected claims");
        proof.selected_cpu = Some(claims);
        crate::verify_unified_trace(&trace, &proof, 8)
            .expect("verify with dynamic selected claims");
    }

    #[test]
    fn unified_proof_verifies_attached_selected_cpu_claims() {
        let trace = trace();
        let mut proof = crate::prove_unified_trace(&trace, 8).expect("unified proof");
        let initial = trace.rows[0].pc;
        let claims = crate::simd_dual::prove_selected_cpu_claims(
            crate::simd_dual::SelectedOp::Alu,
            8,
            16,
            initial,
            initial + 4 * 16,
            &selected_backend(),
        )
        .expect("selected claims");
        proof.selected_cpu = Some(claims);
        crate::verify_unified_trace(&trace, &proof, 8).expect("verify with selected claims");
    }

    #[test]
    fn protocol_plan_and_orchestrator_preserve_proof_bytes() {
        let trace = trace();
        let plan = ProtocolPlan::unified();
        plan.validate().expect("valid plan");
        let direct = crate::prove_unified_inner(&trace, 8).expect("inner proof");
        let orchestrator = Orchestrator::new(plan);
        let proof = orchestrator.prove(&trace, 8).expect("orchestrated proof");
        assert_eq!(
            bincode::serialize(&direct).unwrap(),
            bincode::serialize(&proof).unwrap()
        );
        let bundle = ProofBundle::from_unified(&proof);
        orchestrator.plan().check_bundle(&bundle).expect("bundle");
        orchestrator.verify(&trace, &proof, 8).expect("verify");
    }

    #[test]
    fn cpu_reduction_and_mosaic_pcs_are_wired() {
        fn assert_cpu<P: Pcs, R: CpuReduction<P>>() {}
        assert_cpu::<P3BinaryPcs, LockstepReduction>();

        let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
        let values = vec![F2_128::from(1u64); 8];
        let commitment = pcs.commit(&values).unwrap();
        let first = pcs.commitment_digest(&commitment);
        let second = pcs.commitment_digest(&commitment);
        assert_eq!(first, second);
        let other = P3BinaryPcs::new(100).commit(&values).unwrap();
        assert_ne!(
            first,
            magnetar_transcript::sha256(&bincode::serialize(&other).unwrap())
        );
    }
}

/// One executable stage shared by the prover and verifier. `Commit` is
/// prover-only; the verifier skips it because the commitment is in the proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionStage {
    Commit,
    Access,
    Shout,
    ShiftRouter,
    StoreRouter,
    RegisterAndTrace,
    Cpu,
    Opening,
}

pub const UNIFIED_EXECUTION_STAGES: &[ExecutionStage] = &[
    ExecutionStage::Commit,
    ExecutionStage::Cpu,
    ExecutionStage::Access,
    ExecutionStage::Shout,
    ExecutionStage::ShiftRouter,
    ExecutionStage::StoreRouter,
    ExecutionStage::RegisterAndTrace,
    ExecutionStage::Opening,
];

#[cfg(test)]
mod plan_tests {
    use super::*;

    #[test]
    fn execution_plan_is_actually_driven_by_the_plan() {
        let program = magnetar_spec::ProgramImage::new(
            0x1000,
            vec![
                magnetar_spec::Instruction {
                    op: magnetar_spec::Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 3,
                    shamt: 0,
                }
                .encode(),
                magnetar_spec::Instruction::new(magnetar_spec::Op::Ecall).encode(),
            ],
        );
        let trace = magnetar_executor::execute(
            &program,
            magnetar_spec::MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 100,
            },
        )
        .expect("trace");
        let broken = ProtocolPlan::unified()
            .with_execution(vec![ExecutionStage::Access, ExecutionStage::Cpu]);
        let error = Orchestrator::new(broken)
            .prove(&trace, 8)
            .expect_err("access before commit must fail");
        assert!(error.to_string().contains("access stage before commit"));
    }
}
pub(crate) struct UnifiedProveContext<'a> {
    trace: &'a Trace,
    width: usize,
    witness: BinaryTwistWitness,
    tables: BatchTables,
    system: ConstraintSystem,
    cpu_witness: magnetar_constraint::Witness,
    z: Vec<F2_128>,
    shout_witness: Option<BinaryShoutWitness>,
    shift_router_witness: Option<BinaryRouterWitness>,
    store_router_witness: Option<BinaryRouterWitness>,
    register_witness: BinaryTwistWitness,
    register_tables: BatchTables,
    pcs: P3BinaryPcs,
    mosaic_tables: Vec<P3MosaicTable>,
    shout_table: Option<(usize, P3MosaicTable)>,
    shift_router_table: Option<(usize, P3MosaicTable)>,
    store_router_table: Option<(usize, P3MosaicTable)>,
    register_index: usize,
    ram_index: usize,
    rom_index: usize,
    trace_witness: crate::trace_commitment::TraceWitness,
    trace_index: usize,
    trace_table: P3MosaicTable,
    commitment: Option<P3MosaicCommitment>,
    access: Option<TraceAccessProof>,
    register_claims: Option<crate::binary_twist::MosaicClaims>,
    points: Vec<P3MosaicPoint>,
    values: Vec<Vec<F2_128>>,
    aux_tables: Vec<P3MosaicTable>,
    shout: Option<crate::binary_shout::BinaryShoutProof>,
    shift_router: Option<crate::binary_router::BinaryRouterProof>,
    store_router: Option<crate::binary_router::BinaryRouterProof>,
    cpu: Option<LockstepClaims<magnetar_pcs::P3MosaicCommitment>>,
    cpu_ry: Option<Vec<F2_128>>,
    gated_input: Option<crate::GatedProveInput>,
    component_index: Option<usize>,
    shift_index: Option<usize>,
    active_index: Option<usize>,
    component_ry: Option<Vec<F2_128>>,
    gated_claims: Option<crate::GatedCpuClaims>,
    gated_ry: Option<Vec<F2_128>>,
    packed_shout: Option<crate::packed_shout::PackedShoutProof>,
    table_batches: Vec<crate::TableBatchProof>,
    opening: Option<magnetar_pcs::P3MosaicOpening>,
    e5: Option<E5Prepared>,
    e5_opening: Option<crate::E5Opening>,
    field_opening: Option<magnetar_pcs::P3MosaicOpening>,
    field_pcs_commitment: Option<P3MosaicCommitment>,
    field_tables: Vec<usize>,
}

#[allow(clippy::type_complexity)]
fn gated_component_columns(
    trace: &magnetar_spec::Trace,
    width: usize,
    cycles: usize,
) -> Result<(Vec<F2_128>, Vec<F2_128>, Vec<F2_128>), RuntimeError> {
    let rows = crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(trace, width)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    if rows.len() != cycles {
        return Err(RuntimeError::Proof(
            "gated component cycles do not match trace rows".into(),
        ));
    }
    let mut data = vec![F2_128::from(0u64); cycles * width];
    let mut address = vec![F2_128::from(0u64); cycles * width];
    let mut pc = vec![F2_128::from(0u64); cycles * width];
    for (cycle, (pc_value, input)) in rows.iter().enumerate() {
        for bit in 0..width {
            pc[cycle * width + bit] = F2_128::from((pc_value >> bit) & 1);
        }
        if let crate::simd_f2::GatedCpuRowInput::Memory {
            rs1, imm, value, ..
        } = input.cpu
        {
            let byte_address = rs1.wrapping_add(imm);
            for bit in 0..width {
                data[cycle * width + bit] = F2_128::from((value >> bit) & 1);
                address[cycle * width + bit] = F2_128::from((byte_address >> bit) & 1);
            }
        }
    }
    Ok((data, address, pc))
}

#[allow(clippy::type_complexity)]
fn gated_shift_columns(
    trace: &magnetar_spec::Trace,
    width: usize,
    cycles: usize,
) -> Result<(Vec<F2_128>, Vec<F2_128>, Vec<F2_128>), RuntimeError> {
    let rows = crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(trace, width)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    if rows.len() != cycles {
        return Err(RuntimeError::Proof(
            "gated shift cycles do not match trace rows".into(),
        ));
    }
    let stages = width.trailing_zeros() as usize;
    let len = (cycles * stages).next_power_of_two();
    let mut sll = vec![F2_128::from(0u64); len];
    let mut srl = vec![F2_128::from(0u64); len];
    let mut sra = vec![F2_128::from(0u64); len];
    for (cycle, (_, input)) in rows.iter().enumerate() {
        if let crate::simd_f2::GatedCpuRowInput::Shift { shamt, kind, .. } = input.cpu {
            let target = match kind {
                crate::simd_f2::BitShiftKind::Sll => &mut sll,
                crate::simd_f2::BitShiftKind::Srl => &mut srl,
                crate::simd_f2::BitShiftKind::Sra => &mut sra,
            };
            for bit in 0..stages {
                target[cycle * stages + bit] = F2_128::from((shamt >> bit) & 1);
            }
        }
    }
    Ok((sll, srl, sra))
}

#[allow(clippy::type_complexity)]
fn gated_active_column(
    trace: &magnetar_spec::Trace,
    width: usize,
    cycles: usize,
) -> Result<Vec<F2_128>, RuntimeError> {
    let rows = crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(trace, width)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let mut active = vec![F2_128::from(0u64); cycles.next_power_of_two()];
    for (cycle, (_, input)) in rows.iter().enumerate() {
        if matches!(input.cpu, crate::simd_f2::GatedCpuRowInput::Shift { .. }) {
            active[cycle] = F2_128::from(1u64);
        }
    }
    Ok(active)
}

fn gated_active_claims(
    trace: &magnetar_spec::Trace,
    width: usize,
    cycles: usize,
    layout: &magnetar_constraint::WitnessLayout,
    ry: &[F2_128],
) -> Result<Vec<Option<F2_128>>, RuntimeError> {
    let active = gated_active_column(trace, width, cycles)?;
    let active_mle =
        magnetar_proof::Mle::new(active).map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let mut claims = vec![None; layout.segments.len()];
    for (index, segment) in layout.segments.iter().enumerate() {
        if segment.name != "shift_active" {
            continue;
        }
        let bits = segment.len.trailing_zeros() as usize;
        claims[index] = Some(
            active_mle
                .eval(&ry[..bits])
                .map_err(|error| RuntimeError::Proof(error.to_string()))?,
        );
    }
    Ok(claims)
}

#[allow(clippy::type_complexity)]
fn gated_shift_claims(
    trace: &magnetar_spec::Trace,
    width: usize,
    cycles: usize,
    layout: &magnetar_constraint::WitnessLayout,
    ry: &[F2_128],
) -> Result<(Vec<Option<F2_128>>, Vec<(usize, usize)>), RuntimeError> {
    let (sll, srl, sra) = gated_shift_columns(trace, width, cycles)?;
    let sll_mle =
        magnetar_proof::Mle::new(sll).map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let srl_mle =
        magnetar_proof::Mle::new(srl).map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let sra_mle =
        magnetar_proof::Mle::new(sra).map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let mut claims = vec![None; layout.segments.len()];
    let mut columns = Vec::new();
    for (index, segment) in layout.segments.iter().enumerate() {
        let (column, mle) = match segment.name.as_str() {
            "shift_sll" => (0usize, &sll_mle),
            "shift_srl" => (1usize, &srl_mle),
            "shift_sra" => (2usize, &sra_mle),
            _ => continue,
        };
        let bits = segment.len.trailing_zeros() as usize;
        let claim = mle
            .eval(&ry[..bits])
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        columns.push((column, bits));
        claims[index] = Some(claim);
    }
    Ok((claims, columns))
}

#[allow(clippy::type_complexity)]
pub(crate) fn gated_component_claims(
    trace: &magnetar_spec::Trace,
    width: usize,
    cycles: usize,
    layout: &magnetar_constraint::WitnessLayout,
    ry: &[F2_128],
) -> Result<(Vec<Option<F2_128>>, Vec<(usize, usize)>), RuntimeError> {
    let (data, address, pc) = gated_component_columns(trace, width, cycles)?;
    let data_mle =
        magnetar_proof::Mle::new(data).map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let address_mle = magnetar_proof::Mle::new(address)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let pc_mle =
        magnetar_proof::Mle::new(pc).map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let mut replacements = vec![None; layout.segments.len()];
    let mut columns = Vec::new();
    for (index, segment) in layout.segments.iter().enumerate() {
        if segment.name != "memory_data"
            && segment.name != "memory_addr"
            && segment.name != "pc_bits"
        {
            continue;
        }
        let bits = segment.len.trailing_zeros() as usize;
        if bits > ry.len() {
            return Err(RuntimeError::Proof("component segment point arity".into()));
        }
        let point = &ry[..bits];
        let component = if segment.name == "memory_data" {
            data_mle.eval(point)
        } else if segment.name == "memory_addr" {
            address_mle.eval(point)
        } else {
            pc_mle.eval(point)
        }
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        let column = if segment.name == "memory_data" {
            0
        } else if segment.name == "memory_addr" {
            1
        } else {
            2
        };
        columns.push((column, bits));
        replacements[index] = Some(component);
    }
    Ok((replacements, columns))
}

fn opening_pcs_from_bits(max_bits: usize) -> P3BinaryPcs {
    if max_bits <= 5 {
        P3BinaryPcs::with_params(100, 3, 24, 2)
    } else {
        P3BinaryPcs::with_params(100, 3, 21, 2)
    }
}

fn opening_pcs(tables: &[P3MosaicTable]) -> P3BinaryPcs {
    let max_bits = tables
        .iter()
        .map(|table| table.columns[0].len().trailing_zeros() as usize)
        .max()
        .unwrap_or(0);
    opening_pcs_from_bits(max_bits)
}

#[derive(Clone, Debug)]
struct E5Prepared {
    mosaic: PackedMosaic,
    component_of: std::collections::BTreeMap<(usize, usize), usize>,
    bits: Vec<bool>,
    field_tables: Vec<usize>,
}

fn e5_prepare(
    tables: &[P3MosaicTable],
    trace_index: usize,
) -> Result<Option<E5Prepared>, RuntimeError> {
    let mut components = Vec::new();
    let mut component_of = std::collections::BTreeMap::new();
    let mut field_tables = Vec::new();
    for (table_index, table) in tables.iter().enumerate() {
        let bit_table = table_index != trace_index
            && table.columns.iter().all(|column| {
                column
                    .iter()
                    .all(|value| *value == F2_128::from(0u64) || *value == F2_128::from(1u64))
            });
        if !bit_table {
            field_tables.push(table_index);
            continue;
        }
        for (column_index, column) in table.columns.iter().enumerate() {
            component_of.insert((table_index, column_index), components.len());
            components.push(column.clone());
        }
    }
    if components.is_empty() {
        return Ok(None);
    }
    let mosaic =
        PackedMosaic::new(&components).map_err(|error| RuntimeError::Proof(error.to_string()))?;
    if mosaic.values.len() < 256 {
        return Ok(None);
    }
    let bits = mosaic
        .values
        .iter()
        .map(|value| value.value() & 1 == 1)
        .collect();
    Ok(Some(E5Prepared {
        mosaic,
        component_of,
        bits,
        field_tables,
    }))
}

fn e5_backend() -> RingSwitchPackedBitPcs<P3BinaryPcs> {
    RingSwitchPackedBitPcs::new(P3BinaryPcs::new(100))
}

pub(crate) fn selected_backend() -> RingSwitchPackedBitPcs<P3BinaryPcs> {
    e5_backend()
}

type E5Layout = (
    usize,
    Vec<magnetar_pcs::mosaic::MosaicComponent>,
    std::collections::BTreeMap<(usize, usize), usize>,
);

fn e5_layout_for_shapes(
    shapes: &[magnetar_pcs::P3MosaicTableShape],
    field_tables: &[usize],
) -> Result<E5Layout, RuntimeError> {
    let mut sizes = Vec::new();
    let mut component_of = std::collections::BTreeMap::new();
    for (table_index, shape) in shapes.iter().enumerate() {
        if field_tables.contains(&table_index) {
            continue;
        }
        let size = 1usize
            .checked_shl(shape.num_variables as u32)
            .ok_or_else(|| RuntimeError::Proof("E5 table shape overflow".into()))?;
        for column in 0..shape.num_columns {
            component_of.insert((table_index, column), sizes.len());
            sizes.push(size);
        }
    }
    let (total_bits, components) =
        PackedMosaic::layout(&sizes).map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((total_bits, components, component_of))
}

fn e5_binding_commitment(
    tables: &[P3MosaicTable],
    cap: magnetar_pcs::p3_pcs::P3Cap,
    binding: [u8; 32],
) -> P3MosaicCommitment {
    let shapes = tables
        .iter()
        .map(|table| magnetar_pcs::P3MosaicTableShape {
            num_variables: table.columns[0].len().trailing_zeros() as usize,
            num_columns: table.columns.len(),
        })
        .collect::<Vec<_>>();
    let stacked_variables = shapes
        .iter()
        .map(|shape| shape.num_variables)
        .max()
        .unwrap_or(0);
    magnetar_pcs::P3MosaicCommitment {
        cap,
        tables: shapes,
        stacked_variables,
        binding,
    }
}

fn e5_binding_hash(
    e5: &magnetar_pcs::P3Commitment,
    field: Option<&P3MosaicCommitment>,
) -> Result<[u8; 32], RuntimeError> {
    let mut bytes =
        bincode::serialize(e5).map_err(|error| RuntimeError::Proof(error.to_string()))?;
    if let Some(field) = field {
        bytes.extend(
            bincode::serialize(field).map_err(|error| RuntimeError::Proof(error.to_string()))?,
        );
    }
    Ok(magnetar_transcript::sha256(&bytes))
}

fn e5_claims(
    prepared: &E5Prepared,
    points: &[P3MosaicPoint],
    values: &[Vec<F2_128>],
) -> Result<Vec<(Vec<F2_128>, F2_128)>, RuntimeError> {
    let mut claims = Vec::new();
    for (point, point_values) in points.iter().zip(values) {
        if prepared.field_tables.contains(&point.table) {
            continue;
        }
        if !point.next_columns.is_empty() {
            return Err(RuntimeError::Proof(
                "E5 opening does not support successor columns".into(),
            ));
        }
        for (offset, column) in point.columns.iter().enumerate() {
            let value = point_values
                .get(offset)
                .ok_or_else(|| RuntimeError::Proof("E5 claim value count mismatch".into()))?;
            let component = prepared
                .component_of
                .get(&(point.table, *column))
                .ok_or_else(|| RuntimeError::Proof("E5 component index".into()))?;
            claims.push((
                prepared
                    .mosaic
                    .lift(*component, &point.point)
                    .map_err(|error| RuntimeError::Proof(error.to_string()))?,
                *value,
            ));
        }
    }
    Ok(claims)
}

fn opening_pcs_for_commitment(commitment: &P3MosaicCommitment) -> P3BinaryPcs {
    let max_bits = commitment
        .tables
        .iter()
        .map(|table| table.num_variables)
        .max()
        .unwrap_or(0);
    opening_pcs_from_bits(max_bits)
}

impl<'a> UnifiedProveContext<'a> {
    pub(crate) fn new(trace: &'a Trace, width: usize) -> Result<Self, RuntimeError> {
        Self::new_with_group(trace, width, None)
    }

    pub(crate) fn new_with_group(
        trace: &'a Trace,
        width: usize,
        group: Option<usize>,
    ) -> Result<Self, RuntimeError> {
        check_trace_linkage(trace)?;
        let witness = BinaryTwistWitness::from_trace(trace)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        witness
            .validate()
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        let tables =
            batch_tables(&witness).map_err(|error| RuntimeError::Proof(error.to_string()))?;
        let (system, cpu_witness) = merged_cpu_system(trace, width)?;
        let z = witness_vector(&system, &cpu_witness)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;

        let shout_witness = BinaryShoutWitness::from_trace(trace).ok();
        let shift_router_witness =
            BinaryRouterWitness::from_trace_mode(trace, RouterMode::Shifts).ok();
        let store_router_witness =
            BinaryRouterWitness::from_trace_mode(trace, RouterMode::Stores).ok();
        let register_witness = crate::register_twist::register_twist_witness(trace)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        let register_tables = batch_tables(&register_witness)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        let shared_cpu = width <= 128
            && crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(trace, width)
                .ok()
                .filter(|rows| !rows.is_empty() && rows.len().is_power_of_two())
                .is_some();
        let mut mosaic_tables = Vec::new();
        let ram_index = if shared_cpu {
            0usize
        } else {
            mosaic_tables.push(P3MosaicTable {
                columns: vec![z.clone()],
            });
            1usize
        };
        mosaic_tables.extend([
            tables.addr.clone(),
            tables.inc.clone(),
            tables.initial.clone(),
            tables.read_value.clone(),
            tables.write_value.clone(),
        ]);
        let rom_table = shout_witness.as_ref().map(|witness| P3MosaicTable {
            columns: (0..witness.rom.first().map_or(0, |row| row.len()))
                .map(|column| witness.rom.iter().map(|row| row[column]).collect())
                .collect(),
        });
        let rom_index = mosaic_tables.len();
        if let Some(table) = &rom_table {
            mosaic_tables.push(table.clone());
        }
        let shout_table: Option<(usize, P3MosaicTable)> = None;
        let shift_router_table = shift_router_witness.as_ref().map(|witness| {
            let table = witness.table();
            let index = mosaic_tables.len();
            mosaic_tables.push(table.clone());
            (index, table)
        });
        let store_router_table = store_router_witness.as_ref().map(|witness| {
            let table = witness.table();
            let index = mosaic_tables.len();
            mosaic_tables.push(table.clone());
            (index, table)
        });
        let register_index = mosaic_tables.len();
        mosaic_tables.push(register_tables.addr.clone());
        mosaic_tables.push(register_tables.inc.clone());
        mosaic_tables.push(register_tables.initial.clone());
        mosaic_tables.push(register_tables.read_value.clone());
        mosaic_tables.push(register_tables.write_value.clone());
        let trace_witness = crate::trace_commitment::trace_witness(trace)?;
        let trace_index = mosaic_tables.len();
        let trace_table = P3MosaicTable {
            columns: vec![trace_witness.values.clone()],
        };
        mosaic_tables.push(trace_table.clone());
        let pcs = opening_pcs(&mosaic_tables);

        let gated_input =
            crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(trace, width)
                .ok()
                .filter(|rows| width <= 128 && !rows.is_empty() && rows.len().is_power_of_two())
                .and_then(|rows| {
                    let cycles = rows.len();
                    let group = group.unwrap_or_else(|| crate::simd_dual::choose_group(cycles));
                    if group > 1
                        && (!group.is_power_of_two()
                            || group > cycles
                            || !cycles.is_multiple_of(group))
                    {
                        return None;
                    }
                    let inputs = if group > 1 {
                        crate::simd_dual::reservation_grouped_virtual_inputs(width, &rows, group)
                            .ok()
                            .map(|(z, a0, a1, layout, mapping, _)| (z, a0, a1, layout, mapping))
                    } else {
                        crate::simd_dual::reservation_virtual_inputs(width, &rows).ok()
                    };
                    inputs.map(|(z, a0, a1, layout, mapping)| {
                        (z, a0, a1, layout, mapping, cycles, group)
                    })
                })
                .map(
                    |(z, a0, a1, layout, mapping, cycles, group)| crate::GatedProveInput {
                        z,
                        a0,
                        a1,
                        layout,
                        mapping,
                        table: 0,
                        cycles,
                        group,
                    },
                );
        let component_index = if let Some(input) = &gated_input {
            let (data, address, pc) = gated_component_columns(trace, width, input.cycles)?;
            let index = mosaic_tables.len();
            mosaic_tables.push(magnetar_pcs::P3MosaicTable {
                columns: vec![data, address, pc],
            });
            Some(index)
        } else {
            None
        };
        let shift_index = if let Some(input) = &gated_input {
            let (sll, srl, sra) = gated_shift_columns(trace, width, input.cycles)?;
            let index = mosaic_tables.len();
            mosaic_tables.push(magnetar_pcs::P3MosaicTable {
                columns: vec![sll, srl, sra],
            });
            Some(index)
        } else {
            None
        };
        let active_index = if let Some(input) = &gated_input {
            let active = gated_active_column(trace, width, input.cycles)?;
            let index = mosaic_tables.len();
            mosaic_tables.push(magnetar_pcs::P3MosaicTable {
                columns: vec![active],
            });
            Some(index)
        } else {
            None
        };

        Ok(Self {
            trace,
            width,
            witness,
            tables,
            system,
            cpu_witness,
            z,
            shout_witness,
            shift_router_witness,
            store_router_witness,
            register_witness,
            register_tables,
            pcs,
            mosaic_tables,
            shout_table,
            shift_router_table,
            store_router_table,
            register_index,
            ram_index,
            rom_index,
            trace_witness,
            trace_index,
            trace_table,
            commitment: None,
            access: None,
            register_claims: None,
            points: Vec::new(),
            values: Vec::new(),
            aux_tables: Vec::new(),
            shout: None,
            shift_router: None,
            store_router: None,
            cpu: None,
            cpu_ry: None,
            gated_input,
            component_index,
            shift_index,
            active_index,
            component_ry: None,
            gated_claims: None,
            gated_ry: None,
            packed_shout: None,
            table_batches: Vec::new(),
            opening: None,
            e5: None,
            e5_opening: None,
            field_opening: None,
            field_pcs_commitment: None,
            field_tables: Vec::new(),
        })
    }

    pub(crate) fn commit(&mut self) -> Result<(), RuntimeError> {
        if let Some(prepared) = e5_prepare(&self.mosaic_tables, self.trace_index)? {
            let backend = e5_backend();
            let e5_commitment = backend
                .commit(&prepared.bits)
                .map_err(|error| RuntimeError::Proof(error.to_string()))?;
            let field_tables = prepared
                .field_tables
                .iter()
                .filter_map(|index| self.mosaic_tables.get(*index).cloned())
                .collect::<Vec<_>>();
            let field_commitment = if field_tables.is_empty() {
                None
            } else {
                Some(
                    self.pcs
                        .commit_mosaic(&field_tables)
                        .map_err(|error| RuntimeError::Proof(error.to_string()))?,
                )
            };
            let binding = e5_binding_hash(&e5_commitment, field_commitment.as_ref())?;
            let synthetic = e5_binding_commitment(&self.mosaic_tables, e5_commitment.cap, binding);
            self.commitment = Some(synthetic);
            self.field_tables = prepared.field_tables.clone();
            self.e5 = Some(prepared);
            self.field_pcs_commitment = field_commitment;
            return Ok(());
        }
        let commitment = self
            .pcs
            .commit_mosaic(&self.mosaic_tables)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        self.commitment = Some(commitment);
        Ok(())
    }

    pub(crate) fn prove_access(&mut self) -> Result<(), RuntimeError> {
        let commitment = self
            .commitment
            .as_ref()
            .ok_or_else(|| RuntimeError::Proof("access stage before commit".into()))?;
        let (access, (points, values), register_claims) = prove_trace_access_shared(
            self.trace,
            &self.witness,
            &self.tables,
            commitment,
            &self.register_witness,
            &self.register_tables,
            self.ram_index,
            self.register_index,
        )?;
        self.access = Some(access);
        self.points = points;
        self.values = values;
        self.register_claims = Some(register_claims);
        self.aux_tables = vec![
            self.mosaic_tables[self.ram_index].clone(),
            self.mosaic_tables[self.ram_index + 1].clone(),
        ];
        Ok(())
    }

    pub(crate) fn prove_shout(&mut self) -> Result<(), RuntimeError> {
        let (Some(witness), Some((index, _)), Some(commitment)) =
            (&self.shout_witness, &self.shout_table, &self.commitment)
        else {
            return Ok(());
        };
        let (claim, claim_points, claim_values) =
            prove_binary_shout_claims(witness, commitment, *index, b"")
                .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        self.points.extend(claim_points);
        self.values.extend(claim_values);
        self.aux_tables.push(witness.table());
        self.shout = Some(claim);
        Ok(())
    }

    pub(crate) fn prove_shift_router(&mut self) -> Result<(), RuntimeError> {
        let (Some(witness), Some((index, _)), Some(commitment)) = (
            &self.shift_router_witness,
            &self.shift_router_table,
            &self.commitment,
        ) else {
            return Ok(());
        };
        let (claim, claim_points, claim_values) =
            prove_binary_router_claims(witness, commitment, *index, b"")
                .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        self.points.extend(claim_points);
        self.values.extend(claim_values);
        self.aux_tables.push(witness.table());
        self.shift_router = Some(claim);
        Ok(())
    }

    pub(crate) fn prove_store_router(&mut self) -> Result<(), RuntimeError> {
        let (Some(witness), Some((index, _)), Some(commitment)) = (
            &self.store_router_witness,
            &self.store_router_table,
            &self.commitment,
        ) else {
            return Ok(());
        };
        let (claim, claim_points, claim_values) =
            prove_binary_router_claims(witness, commitment, *index, b"")
                .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        self.points.extend(claim_points);
        self.values.extend(claim_values);
        self.aux_tables.push(witness.table());
        self.store_router = Some(claim);
        Ok(())
    }

    pub(crate) fn prove_register_and_trace(&mut self) -> Result<(), RuntimeError> {
        let (register_points, register_values) = self
            .register_claims
            .take()
            .ok_or_else(|| RuntimeError::Proof("register claims before access".into()))?;
        self.points.extend(register_points);
        self.values.extend(register_values);
        self.aux_tables.push(self.register_tables.addr.clone());
        self.aux_tables.push(self.register_tables.inc.clone());
        self.aux_tables.push(self.trace_table.clone());

        let trace_claims = magnetar_proof::virtual_spartan::split_segment_claims(
            &self.trace_witness.layout,
            &self.trace_witness.values,
            &self.trace_witness.point,
        )
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        let total_bits = self.trace_witness.layout.total_bits.trailing_zeros() as usize;
        for (segment, claim) in self.trace_witness.layout.segments.iter().zip(&trace_claims) {
            let size_bits = segment.len.trailing_zeros() as usize;
            let suffix = segment.offset >> size_bits;
            let mut point = self.trace_witness.point[..size_bits].to_vec();
            for bit in 0..total_bits - size_bits {
                point.push(F2_128::from(((suffix >> bit) & 1) as u64));
            }
            self.points.push(P3MosaicPoint {
                table: self.trace_index,
                point,
                columns: vec![0],
                next_columns: Vec::new(),
            });
            self.values.push(vec![claim.value]);
        }
        if let (Some(index), Some(ry), Some(gated)) = (
            self.component_index,
            self.component_ry.as_ref(),
            self.gated_claims.as_ref(),
        ) {
            let component_values = gated
                .component_claims
                .iter()
                .filter_map(|value| *value)
                .collect::<Vec<_>>();
            if let Some((_, bits)) = gated.component_columns.first() {
                let mut pairs = gated
                    .component_columns
                    .iter()
                    .copied()
                    .zip(component_values)
                    .collect::<Vec<_>>();
                pairs.sort_by_key(|(column, _)| column.0);
                self.points.push(P3MosaicPoint {
                    table: index,
                    point: ry[..*bits].to_vec(),
                    columns: pairs.iter().map(|(column, _)| column.0).collect(),
                    next_columns: Vec::new(),
                });
                self.values
                    .push(pairs.into_iter().map(|(_, value)| value).collect());
            }
            if let Some(index) = gated.shift_index {
                let values = gated
                    .shift_claims
                    .iter()
                    .filter_map(|value| *value)
                    .collect::<Vec<_>>();
                if let Some((_, bits)) = gated.shift_columns.first() {
                    let mut pairs = gated
                        .shift_columns
                        .iter()
                        .copied()
                        .zip(values)
                        .collect::<Vec<_>>();
                    pairs.sort_by_key(|(column, _)| column.0);
                    self.points.push(P3MosaicPoint {
                        table: index,
                        point: ry[..*bits].to_vec(),
                        columns: pairs.iter().map(|(column, _)| column.0).collect(),
                        next_columns: Vec::new(),
                    });
                    self.values
                        .push(pairs.into_iter().map(|(_, value)| value).collect());
                }
            }
            if let Some(index) = gated.active_index {
                if let Some(value) = gated.active_claims.iter().filter_map(|value| *value).next() {
                    self.points.push(P3MosaicPoint {
                        table: index,
                        point: ry[..gated.cycles.trailing_zeros() as usize].to_vec(),
                        columns: vec![0],
                        next_columns: Vec::new(),
                    });
                    self.values.push(vec![value]);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn prove_cpu(&mut self) -> Result<(), RuntimeError> {
        let commitment = self
            .commitment
            .clone()
            .ok_or_else(|| RuntimeError::Proof("CPU stage before commit".into()))?;
        let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
        let (system_a, system_b) = split_cpu_relations(&self.system);
        let layout = cpu_segment_layout(self.z.len())?;
        if self.gated_input.is_none() {
            let (claims, ry) = magnetar_proof::prove_lockstep_claims(
                &system_a,
                &system_b,
                &self.cpu_witness,
                &layout,
                &pcs,
                commitment,
            )
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
            self.cpu = Some(claims);
            self.cpu_ry = Some(ry);
        } else {
            self.cpu = None;
            self.cpu_ry = None;
        }
        if let Some(input) = &self.gated_input {
            let bits = input
                .z
                .iter()
                .map(|value| value.value() == 1)
                .collect::<Vec<_>>();
            let backend = magnetar_proof::RingSwitchPackedBitPcs::new(P3SharedPcs::new(
                100,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ));
            let wrap = |matrix| crate::simd_dual::ScatterMatrix {
                inner: matrix,
                mapping: input.mapping.clone(),
                cols: input.layout.total_bits,
            };
            let va0 = [
                wrap(input.a0[0].clone()),
                wrap(input.a0[1].clone()),
                wrap(input.a0[2].clone()),
            ];
            let va1 = [
                wrap(input.a1[0].clone()),
                wrap(input.a1[1].clone()),
                wrap(input.a1[2].clone()),
            ];
            let (proof, gated_ry) = magnetar_proof::prove_lockstep_bits_with_point(
                &bits,
                &va0[0],
                &va0[1],
                &va0[2],
                &va1[0],
                &va1[1],
                &va1[2],
                &input.layout,
                &backend,
            )
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
            let (component_claims, component_columns) = gated_component_claims(
                self.trace,
                self.width,
                input.cycles,
                &input.layout,
                &gated_ry,
            )?;
            let (shift_claims, shift_columns) = gated_shift_claims(
                self.trace,
                self.width,
                input.cycles,
                &input.layout,
                &gated_ry,
            )?;
            let active_claims = gated_active_claims(
                self.trace,
                self.width,
                input.cycles,
                &input.layout,
                &gated_ry,
            )?;
            self.component_ry = Some(gated_ry.clone());
            self.gated_claims = Some(crate::GatedCpuClaims {
                proof,
                cycles: input.cycles,
                component_claims,
                component_columns,
                component_index: self.component_index,
                group: input.group,
                shift_claims,
                shift_columns,
                shift_index: self.shift_index,
                active_claims,
                active_index: self.active_index,
            });
            self.gated_ry = None;
        }
        if let Some(witness) = &self.shout_witness {
            let packed = crate::packed_shout::prove_packed_shout(witness)?;
            let commitment = self
                .commitment
                .as_ref()
                .ok_or_else(|| RuntimeError::Proof("missing commitment".into()))?;
            let _ = commitment;
            self.packed_shout = Some(packed);
        }
        Ok(())
    }

    pub(crate) fn prove_opening(&mut self) -> Result<(), RuntimeError> {
        if let Some(ry) = self.cpu_ry.as_ref() {
            let value = Mle::new(self.z.clone())
                .map_err(|error| RuntimeError::Proof(error.to_string()))?
                .eval(ry)
                .map_err(|error| RuntimeError::Proof(error.to_string()))?;
            self.points.push(P3MosaicPoint {
                table: 0,
                point: ry.clone(),
                columns: vec![0],
                next_columns: Vec::new(),
            });
            self.values.push(vec![value]);
        }
        if let (Some(input), Some(gated_ry)) = (&self.gated_input, &self.gated_ry) {
            let gated_value = Mle::new(input.z.clone())
                .map_err(|error| RuntimeError::Proof(error.to_string()))?
                .eval(gated_ry)
                .map_err(|error| RuntimeError::Proof(error.to_string()))?;
            self.points.push(P3MosaicPoint {
                table: input.table,
                point: gated_ry.clone(),
                columns: vec![0],
                next_columns: Vec::new(),
            });
            self.values.push(vec![gated_value]);
        }
        if let Some(packed) = &self.packed_shout {
            let commitment = self
                .commitment
                .as_ref()
                .ok_or_else(|| RuntimeError::Proof("missing commitment".into()))?;
            let links = crate::shout_router_link_claims(
                commitment,
                self.rom_index,
                self.shift_router_table.as_ref().map(|(index, _)| *index),
                self.store_router_table.as_ref().map(|(index, _)| *index),
                packed,
            )?;
            for (point, values) in links {
                self.points.push(point);
                self.values.push(values);
            }
        }
        let mut pairs = self
            .points
            .drain(..)
            .zip(self.values.drain(..))
            .collect::<Vec<_>>();
        pairs.sort_by_key(|(point, _)| crate::point_sort_key(point));
        let mut counts = vec![0usize; self.mosaic_tables.len()];
        for (point, _) in &pairs {
            counts[point.table] += 1;
        }
        let selected = counts
            .iter()
            .enumerate()
            .filter(|(index, count)| {
                **count >= 6 && !self.field_tables.contains(index) && {
                    let bits =
                        self.mosaic_tables[*index].columns[0].len().trailing_zeros() as usize;
                    bits <= 3 || (bits == 4 && **count <= 8)
                }
            })
            .map(|(index, _)| index)
            .collect::<std::collections::HashSet<_>>();
        let mut pairs = crate::merge_point_claims(pairs, &selected);
        pairs.sort_by_key(|(point, _)| crate::point_sort_key(point));
        if selected.is_empty() {
            let (points, values): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
            self.points = points;
            self.values = values;
        } else {
            let commitment = self
                .commitment
                .as_ref()
                .ok_or_else(|| RuntimeError::Proof("missing commitment".into()))?;
            let mut grouped = vec![Vec::new(); self.mosaic_tables.len()];
            let mut kept_points = Vec::new();
            let mut kept_values = Vec::new();
            for (point, values) in pairs {
                if selected.contains(&point.table) {
                    for (offset, column) in point.columns.iter().enumerate() {
                        if let Some(value) = values.get(offset) {
                            grouped[point.table].push((point.point.clone(), *column, *value));
                        }
                    }
                } else {
                    kept_points.push(point);
                    kept_values.push(values);
                }
            }
            let mut selected_indices = selected.iter().copied().collect::<Vec<_>>();
            selected_indices.sort_unstable();
            for index in selected_indices {
                let table = &self.mosaic_tables[index];
                let mosaic = magnetar_pcs::mosaic::PackedMosaic::new(&table.columns)
                    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
                let claims = grouped[index]
                    .iter()
                    .map(|(row, column, value)| Ok((mosaic.lift(*column, row)?, *value)))
                    .collect::<Result<Vec<_>, magnetar_pcs::mosaic::MosaicError>>()
                    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
                let mut transcript = magnetar_transcript::Sha256Transcript::new("table-batch");
                transcript.absorb(
                    "commitment",
                    &bincode::serialize(commitment).unwrap_or_default(),
                );
                transcript.absorb("table", &(index as u64).to_le_bytes());
                let batch =
                    magnetar_pcs::mosaic::batch_claims(&mosaic.values, &claims, &mut transcript)
                        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
                let row_bits = table.columns[0].len().trailing_zeros() as usize;
                let row_point = batch.point[..row_bits].to_vec();
                let column_values = table
                    .columns
                    .iter()
                    .map(|column| {
                        Mle::new(column.clone())
                            .and_then(|mle| mle.eval(&row_point))
                            .map_err(|error| RuntimeError::Proof(error.to_string()))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                kept_points.push(P3MosaicPoint {
                    table: index,
                    point: row_point.clone(),
                    columns: (0..table.columns.len()).collect(),
                    next_columns: Vec::new(),
                });
                kept_values.push(column_values.clone());
                self.table_batches.push(crate::TableBatchProof {
                    table: index,
                    row_point,
                    values: column_values,
                    batch,
                });
            }
            let mut pairs = kept_points.into_iter().zip(kept_values).collect::<Vec<_>>();
            pairs.sort_by_key(|(point, _)| crate::point_sort_key(point));
            let (points, values): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
            self.points = points;
            self.values = values;
        }
        if let Some(prepared) = self.e5.take() {
            let claims = e5_claims(&prepared, &self.points, &self.values)?;
            let commitment = self
                .commitment
                .as_ref()
                .ok_or_else(|| RuntimeError::Proof("missing E5 commitment".into()))?;
            let mut transcript = magnetar_transcript::Sha256Transcript::new("e5-batch");
            transcript.absorb(
                "commitment",
                &bincode::serialize(commitment).unwrap_or_default(),
            );
            let batch = magnetar_pcs::mosaic::batch_claims(
                &prepared.mosaic.values,
                &claims,
                &mut transcript,
            )
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
            let backend = e5_backend();
            let (claim, ring) = backend
                .open(&prepared.bits, &batch.point)
                .map_err(|error| RuntimeError::Proof(error.to_string()))?;
            if claim != batch.value {
                return Err(RuntimeError::Proof("E5 ring/batch value mismatch".into()));
            }
            let field_index = self
                .field_tables
                .iter()
                .enumerate()
                .map(|(position, table)| (*table, position))
                .collect::<std::collections::BTreeMap<_, _>>();
            let (field_points, _field_values) = self
                .points
                .iter()
                .zip(&self.values)
                .filter(|(point, _)| field_index.contains_key(&point.table))
                .map(|(point, values)| {
                    let mut point = point.clone();
                    point.table = field_index[&point.table];
                    (point, values.clone())
                })
                .unzip::<_, _, Vec<_>, Vec<_>>();
            let field_tables = self
                .field_tables
                .iter()
                .filter_map(|index| self.mosaic_tables.get(*index).cloned())
                .collect::<Vec<_>>();
            let field_opening = if field_tables.is_empty() {
                None
            } else {
                Some(
                    self.pcs
                        .open_mosaic(&field_tables, &field_points)
                        .map_err(|error| RuntimeError::Proof(error.to_string()))?,
                )
            };
            self.field_pcs_commitment = field_opening
                .as_ref()
                .map(|opening| opening.commitment.clone());
            self.e5_opening = Some(crate::E5Opening { batch, ring });
            self.field_opening = field_opening;
            self.opening = None;
            return Ok(());
        }
        let opening = self
            .pcs
            .open_mosaic(&self.mosaic_tables, &self.points)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        self.opening = Some(opening);
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<UnifiedTraceProof, RuntimeError> {
        let amo = if crate::amo_bundle::has_amo_events(self.trace) {
            Some(crate::amo_bundle::prove_amo_bundle(self.trace, self.width)?)
        } else {
            None
        };
        let (trace_points, trace_values) =
            crate::trace_commitment::trace_claim_points(&self.trace_witness, self.trace_index)?;
        let trace_claims = trace_points.into_iter().zip(trace_values).collect();
        let packed_shout = self.packed_shout;
        let claim_tree = crate::trace_claims::TraceClaimTree::build(self.trace);
        Ok(UnifiedTraceProof {
            shape: crate::cpu_shape::CpuShape::from_trace(self.trace).zeroed(),
            trace_claim_root: claim_tree.root(),
            claim_proof: Some(crate::trace_claims::ClaimProof::from_trace(self.trace)),
            register_index: self.register_index,
            ram_index: self.ram_index,
            rom_index: self.rom_index,
            shout_index: self.shout_table.as_ref().map(|(index, _)| *index),
            shift_router_index: self.shift_router_table.as_ref().map(|(index, _)| *index),
            store_router_index: self.store_router_table.as_ref().map(|(index, _)| *index),
            trace_index: self.trace_index,
            trace_claims,
            table_batches: self.table_batches,
            width: self.width,
            selected_cpu: None,
            e5_opening: self.e5_opening,
            field_opening: self.field_opening,
            field_pcs_commitment: self.field_pcs_commitment,
            field_tables: self.field_tables,
            commitment: self
                .commitment
                .clone()
                .ok_or_else(|| RuntimeError::Proof("missing CPU commitment".into()))?,
            packed_shout,
            access: self
                .access
                .ok_or_else(|| RuntimeError::Proof("missing access proof".into()))?,
            trace_commitment: trace_digest(self.trace),
            cpu: self.cpu,
            gated: self.gated_claims,
            opening: self.opening,
            shout: self.shout,
            shift_router: self.shift_router,
            store_router: self.store_router,
            amo,
        })
    }
}

pub(crate) struct UnifiedVerifyContext<'a> {
    trace: &'a Trace,
    proof: &'a UnifiedTraceProof,
    width: usize,
    shout_witness: Option<BinaryShoutWitness>,
    shift_router_witness: Option<BinaryRouterWitness>,
    store_router_witness: Option<BinaryRouterWitness>,
    shout_index: Option<usize>,
    shift_router_index: Option<usize>,
    store_router_index: Option<usize>,
    register_index: usize,
    register_witness: BinaryTwistWitness,
    witness: BinaryTwistWitness,
    points: Vec<P3MosaicPoint>,
    values: Vec<Vec<F2_128>>,
    register_claims: Option<crate::binary_twist::MosaicClaims>,
    routed_claims: Option<ClaimSet>,
    cpu_ry: Option<Vec<F2_128>>,
    cpu_value: Option<F2_128>,
    gated_input: Option<crate::GatedProveInput>,
    gated_ry: Option<Vec<F2_128>>,
    component_points: Vec<(P3MosaicPoint, Vec<F2_128>)>,
}

impl<'a> UnifiedVerifyContext<'a> {
    pub(crate) fn new(
        trace: &'a Trace,
        proof: &'a UnifiedTraceProof,
        width: usize,
    ) -> Result<Self, RuntimeError> {
        check_trace_linkage(trace)?;
        if !proof.shape.matches_structure(trace) {
            return Err(RuntimeError::Proof(
                "CPU shape does not match the trace".into(),
            ));
        }
        if proof.trace_commitment != trace_digest(trace) {
            return Err(RuntimeError::Proof(
                "unified proof does not match the supplied trace".into(),
            ));
        }
        let shout_witness = BinaryShoutWitness::from_trace(trace).ok();
        let shift_router_witness =
            BinaryRouterWitness::from_trace_mode(trace, RouterMode::Shifts).ok();
        let store_router_witness =
            BinaryRouterWitness::from_trace_mode(trace, RouterMode::Stores).ok();
        if proof.packed_shout.is_none() {
            match (&shout_witness, &proof.shout) {
                (Some(_), None) | (None, Some(_)) => {
                    return Err(RuntimeError::Proof(
                        "BinaryShout proof presence does not match the trace".into(),
                    ));
                }
                _ => {}
            }
        }
        match (&shift_router_witness, &proof.shift_router) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(RuntimeError::Proof(
                    "shift BinaryRouter proof presence does not match the trace".into(),
                ));
            }
            _ => {}
        }
        match (&store_router_witness, &proof.store_router) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(RuntimeError::Proof(
                    "store BinaryRouter proof presence does not match the trace".into(),
                ));
            }
            _ => {}
        }
        let gated_rows =
            crate::reservation_cpu_row::reservation_cpu_rows_from_trace_full(trace, width)
                .ok()
                .filter(|rows| width <= 128 && !rows.is_empty() && rows.len().is_power_of_two());
        let dynamic_selected = proof
            .selected_cpu
            .as_ref()
            .is_some_and(|selected| selected.op == crate::simd_dual::SelectedOp::Dynamic);
        match (gated_rows.is_some(), proof.gated.is_some()) {
            (true, false) if dynamic_selected => {}
            (true, false) | (false, true) => {
                return Err(RuntimeError::Proof(
                    "gated CPU claims presence does not match the trace".into(),
                ));
            }
            _ => {}
        }
        let gated_input = gated_rows.as_ref().and_then(|rows| {
            let cycles = rows.len();
            let group = proof
                .gated
                .as_ref()
                .map(|gated| gated.group)
                .unwrap_or_else(|| crate::simd_dual::choose_group(cycles));
            if group > 1 {
                crate::simd_dual::reservation_grouped_virtual_view(width, cycles, group)
                    .ok()
                    .map(|(a0, a1, layout, mapping, _)| crate::GatedProveInput {
                        z: Vec::new(),
                        a0,
                        a1,
                        layout,
                        mapping,
                        table: 0,
                        cycles,
                        group,
                    })
            } else {
                crate::simd_dual::reservation_claim_matrices(width, cycles)
                    .ok()
                    .map(|(a0, a1, layout)| crate::GatedProveInput {
                        z: Vec::new(),
                        a0,
                        a1,
                        layout,
                        mapping: Vec::new(),
                        table: 0,
                        cycles,
                        group,
                    })
            }
        });
        let shout_index = proof.shout_index;
        let shift_router_index = proof.shift_router_index;
        let store_router_index = proof.store_router_index;
        let register_index = proof.register_index;
        let register_witness = crate::register_twist::register_twist_witness(trace)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        let witness = BinaryTwistWitness::from_trace(trace)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        witness
            .validate()
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;

        Ok(Self {
            trace,
            proof,
            width,
            shout_witness,
            shift_router_witness,
            store_router_witness,
            shout_index,
            shift_router_index,
            store_router_index,
            register_index,
            register_witness,
            witness,
            points: Vec::new(),
            values: Vec::new(),
            register_claims: None,
            routed_claims: None,
            cpu_ry: None,
            cpu_value: None,
            gated_input,
            gated_ry: None,
            component_points: Vec::new(),
        })
    }

    pub(crate) fn verify_access(&mut self) -> Result<(), RuntimeError> {
        let (ram_claims, register_claims) = verify_trace_access_shared(
            self.trace,
            &self.proof.access,
            &self.witness,
            &self.proof.commitment,
            &self.register_witness,
            self.proof.ram_index,
            self.register_index,
        )?;
        self.points = ram_claims.0;
        self.values = ram_claims.1;
        self.register_claims = Some(register_claims);
        Ok(())
    }

    pub(crate) fn verify_shout(&mut self) -> Result<(), RuntimeError> {
        let (Some(witness), Some(claim), Some(index)) =
            (&self.shout_witness, &self.proof.shout, self.shout_index)
        else {
            return Ok(());
        };
        let Some((points, values)) =
            verify_binary_shout_claims(witness, claim, &self.proof.commitment, index, b"")
                .map_err(|error| RuntimeError::Proof(error.to_string()))?
        else {
            return Err(RuntimeError::Proof("BinaryShout proof rejected".into()));
        };
        self.points.extend(points);
        self.values.extend(values);
        Ok(())
    }

    pub(crate) fn verify_shift_router(&mut self) -> Result<(), RuntimeError> {
        let (Some(witness), Some(claim), Some(index)) = (
            &self.shift_router_witness,
            &self.proof.shift_router,
            self.shift_router_index,
        ) else {
            return Ok(());
        };
        let Some((points, values)) =
            verify_binary_router_claims(witness, claim, &self.proof.commitment, index, b"")
                .map_err(|error| RuntimeError::Proof(error.to_string()))?
        else {
            return Err(RuntimeError::Proof(
                "shift BinaryRouter proof rejected".into(),
            ));
        };
        self.points.extend(points);
        self.values.extend(values);
        Ok(())
    }

    pub(crate) fn verify_store_router(&mut self) -> Result<(), RuntimeError> {
        let (Some(witness), Some(claim), Some(index)) = (
            &self.store_router_witness,
            &self.proof.store_router,
            self.store_router_index,
        ) else {
            return Ok(());
        };
        let Some((points, values)) =
            verify_binary_router_claims(witness, claim, &self.proof.commitment, index, b"")
                .map_err(|error| RuntimeError::Proof(error.to_string()))?
        else {
            return Err(RuntimeError::Proof(
                "store BinaryRouter proof rejected".into(),
            ));
        };
        self.points.extend(points);
        self.values.extend(values);
        Ok(())
    }

    pub(crate) fn verify_register_and_trace(&mut self) -> Result<(), RuntimeError> {
        let (register_points, register_values) = self
            .register_claims
            .take()
            .ok_or_else(|| RuntimeError::Proof("register claims before access".into()))?;
        self.points.extend(register_points);
        self.values.extend(register_values);

        let trace_witness = crate::trace_commitment::trace_witness(self.trace)?;
        let trace_index = self.proof.trace_index;
        let trace_claims = magnetar_proof::virtual_spartan::split_segment_claims(
            &trace_witness.layout,
            &trace_witness.values,
            &trace_witness.point,
        )
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        let trace_value = Mle::new(trace_witness.values.clone())
            .map_err(|error| RuntimeError::Proof(error.to_string()))?
            .eval(&trace_witness.point)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        magnetar_proof::virtual_spartan::verify_segment_claims(
            &trace_witness.layout,
            &trace_claims,
            &trace_witness.point,
            trace_value,
        )
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        let total_bits = trace_witness.layout.total_bits.trailing_zeros() as usize;
        for (segment, claim) in trace_witness.layout.segments.iter().zip(&trace_claims) {
            let size_bits = segment.len.trailing_zeros() as usize;
            let suffix = segment.offset >> size_bits;
            let mut point = trace_witness.point[..size_bits].to_vec();
            for bit in 0..total_bits - size_bits {
                point.push(F2_128::from(((suffix >> bit) & 1) as u64));
            }
            self.points.push(P3MosaicPoint {
                table: trace_index,
                point,
                columns: vec![0],
                next_columns: Vec::new(),
            });
            self.values.push(vec![claim.value]);
        }
        Ok(())
    }

    pub(crate) fn verify_cpu(&mut self) -> Result<(), RuntimeError> {
        if self.proof.gated.is_none()
            && self
                .proof
                .selected_cpu
                .as_ref()
                .is_some_and(|selected| selected.op == crate::simd_dual::SelectedOp::Dynamic)
        {
            return Ok(());
        }

        let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
        if let Some(cpu) = &self.proof.cpu {
            let (system, witness_len) = if self
                .trace
                .rows
                .iter()
                .any(|row| row.instruction.op.amo_width().is_some())
            {
                let (system, witness) = merged_cpu_system(self.trace, self.width)?;
                let z = witness_vector(&system, &witness)
                    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
                (system, z.len())
            } else {
                self.proof.shape.system_with_len(self.trace, self.width)?
            };
            let (system_a, system_b) = split_cpu_relations(&system);
            let layout = cpu_segment_layout(witness_len)?;
            let (ry, segments, value) =
                verify_lockstep_claims(&system_a, &system_b, &layout, cpu, &pcs)
                    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
            self.cpu_ry = Some(ry.clone());
            self.cpu_value = Some(value);
            let catalog = SegmentCatalog::from_layout(&layout);
            self.routed_claims = Some(
                route_segment_claims(&layout, &ry, &segments, &catalog)
                    .map_err(|error| RuntimeError::Proof(error.to_string()))?,
            );
        }
        if let (Some(input), Some(gated)) = (&self.gated_input, &self.proof.gated) {
            let backend = magnetar_proof::RingSwitchPackedBitPcs::new(P3SharedPcs::new(
                100,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ));
            let (layout, mapping) = if input.group > 1 {
                (input.layout.clone(), input.mapping.clone())
            } else {
                let base_cols = input.a0[0].cols() / input.cycles;
                let (layout, mapping, _) = crate::simd_dual::reservation_virtual_view(
                    self.width,
                    input.cycles,
                    base_cols,
                )?;
                (layout, mapping)
            };
            let wrap = |matrix| crate::simd_dual::ScatterMatrix {
                inner: matrix,
                mapping: mapping.clone(),
                cols: layout.total_bits,
            };
            let va0 = [
                wrap(input.a0[0].clone()),
                wrap(input.a0[1].clone()),
                wrap(input.a0[2].clone()),
            ];
            let va1 = [
                wrap(input.a1[0].clone()),
                wrap(input.a1[1].clone()),
                wrap(input.a1[2].clone()),
            ];
            let gated_point = magnetar_proof::verify_lockstep_bits_with_replacements_point(
                &va0[0],
                &va0[1],
                &va0[2],
                &va1[0],
                &va1[1],
                &va1[2],
                &layout,
                &gated.proof,
                &backend,
                &gated.component_claims,
            )
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
            if let Some(index) = gated.component_index {
                let component_values = gated
                    .component_claims
                    .iter()
                    .filter_map(|value| *value)
                    .collect::<Vec<_>>();
                if let Some((_, bits)) = gated.component_columns.first() {
                    let mut pairs = gated
                        .component_columns
                        .iter()
                        .copied()
                        .zip(component_values)
                        .collect::<Vec<_>>();
                    pairs.sort_by_key(|(column, _)| column.0);
                    self.component_points.push((
                        P3MosaicPoint {
                            table: index,
                            point: gated_point[..*bits].to_vec(),
                            columns: pairs.iter().map(|(column, _)| column.0).collect(),
                            next_columns: Vec::new(),
                        },
                        pairs.into_iter().map(|(_, value)| value).collect(),
                    ));
                }
            }
            if let Some(index) = gated.shift_index {
                let shift_values = gated
                    .shift_claims
                    .iter()
                    .filter_map(|value| *value)
                    .collect::<Vec<_>>();
                if let Some((_, bits)) = gated.shift_columns.first() {
                    let mut pairs = gated
                        .shift_columns
                        .iter()
                        .copied()
                        .zip(shift_values)
                        .collect::<Vec<_>>();
                    pairs.sort_by_key(|(column, _)| column.0);
                    self.component_points.push((
                        P3MosaicPoint {
                            table: index,
                            point: gated_point[..*bits].to_vec(),
                            columns: pairs.iter().map(|(column, _)| column.0).collect(),
                            next_columns: Vec::new(),
                        },
                        pairs.into_iter().map(|(_, value)| value).collect(),
                    ));
                }
            }
            if let Some(index) = gated.active_index {
                if let Some(value) = gated.active_claims.iter().filter_map(|value| *value).next() {
                    self.component_points.push((
                        P3MosaicPoint {
                            table: index,
                            point: gated_point[..gated.cycles.trailing_zeros() as usize].to_vec(),
                            columns: vec![0],
                            next_columns: Vec::new(),
                        },
                        vec![value],
                    ));
                }
            }
            self.gated_ry = Some(gated_point);
        } else if self.proof.gated.is_some() {
            return Err(RuntimeError::Proof("gated input missing".into()));
        }
        Ok(())
    }

    pub(crate) fn verify_opening(&mut self) -> Result<(), RuntimeError> {
        if let (Some(ry), Some(value)) = (self.cpu_ry.as_ref(), self.cpu_value) {
            self.points.push(P3MosaicPoint {
                table: 0,
                point: ry.clone(),
                columns: vec![0],
                next_columns: Vec::new(),
            });
            self.values.push(vec![value]);
        }
        if let Some(packed) = &self.proof.packed_shout {
            let links = crate::shout_router_link_claims(
                &self.proof.commitment,
                self.proof.rom_index,
                self.proof.shift_router_index,
                self.proof.store_router_index,
                packed,
            )?;
            for (point, values) in links {
                self.points.push(point);
                self.values.push(values);
            }
        }
        for (point, values) in &self.component_points {
            self.points.push(point.clone());
            self.values.push(values.clone());
        }
        let mut base_pairs = self
            .points
            .drain(..)
            .zip(self.values.drain(..))
            .collect::<Vec<_>>();
        base_pairs.sort_by_key(|(point, _)| crate::point_sort_key(point));
        let selected = self
            .proof
            .table_batches
            .iter()
            .map(|batch| batch.table)
            .collect::<std::collections::HashSet<_>>();
        let original = base_pairs.clone();
        let mut pairs = crate::merge_point_claims(base_pairs, &selected);
        pairs.sort_by_key(|(point, _)| crate::point_sort_key(point));
        if !self.proof.table_batches.is_empty() {
            pairs.retain(|(point, _)| !selected.contains(&point.table));
            for batch in &self.proof.table_batches {
                pairs.push((
                    P3MosaicPoint {
                        table: batch.table,
                        point: batch.row_point.clone(),
                        columns: (0..batch.values.len()).collect(),
                        next_columns: Vec::new(),
                    },
                    batch.values.clone(),
                ));
            }
        }
        pairs.sort_by_key(|(point, _)| crate::point_sort_key(point));
        let (points, values): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
        self.points = points;
        self.values = values;
        if let (Some(e5), Some(_field_opening)) =
            (&self.proof.e5_opening, &self.proof.field_opening)
        {
            let (total_bits, components, component_of) =
                e5_layout_for_shapes(&self.proof.commitment.tables, &self.proof.field_tables)?;
            let mut claims = Vec::new();
            for (point, point_values) in self.points.iter().zip(&self.values) {
                if self.proof.field_tables.contains(&point.table) {
                    continue;
                }
                if !point.next_columns.is_empty() {
                    return Err(RuntimeError::Proof(
                        "E5 opening does not support successor columns".into(),
                    ));
                }
                for (offset, column) in point.columns.iter().enumerate() {
                    let value = point_values.get(offset).ok_or_else(|| {
                        RuntimeError::Proof("E5 claim value count mismatch".into())
                    })?;
                    let component = component_of
                        .get(&(point.table, *column))
                        .ok_or_else(|| RuntimeError::Proof("E5 component index".into()))?;
                    let mut lifted = point.point.clone();
                    lifted.extend_from_slice(&components[*component].suffix);
                    claims.push((lifted, *value));
                }
            }
            let mut transcript = magnetar_transcript::Sha256Transcript::new("e5-batch");
            transcript.absorb(
                "commitment",
                &bincode::serialize(&self.proof.commitment).unwrap_or_default(),
            );
            magnetar_pcs::mosaic::verify_batching(&e5.batch, &claims, total_bits, &mut transcript)
                .map_err(|error| RuntimeError::Proof(error.to_string()))?;
            let packed_commitment = &e5.ring.pcs_opening.commitment;
            if packed_commitment.cap != self.proof.commitment.cap {
                return Err(RuntimeError::Proof("E5 commitment binding mismatch".into()));
            }
            let expected_binding =
                e5_binding_hash(packed_commitment, self.proof.field_pcs_commitment.as_ref())?;
            if self.proof.commitment.binding != expected_binding {
                return Err(RuntimeError::Proof("E5 field binding mismatch".into()));
            }
            let backend = e5_backend();
            if !backend
                .verify(packed_commitment, &e5.batch.point, e5.batch.value, &e5.ring)
                .map_err(|error| RuntimeError::Proof(error.to_string()))?
            {
                return Err(RuntimeError::Proof("E5 ring opening rejected".into()));
            }
            if let Some(stored_field) = &self.proof.field_pcs_commitment {
                let field_opening = self
                    .proof
                    .field_opening
                    .as_ref()
                    .ok_or_else(|| RuntimeError::Proof("missing field opening".into()))?;
                if field_opening.commitment != *stored_field {
                    return Err(RuntimeError::Proof("field commitment mismatch".into()));
                }
                if field_opening.commitment.tables.len() != self.proof.field_tables.len() {
                    return Err(RuntimeError::Proof("field table count mismatch".into()));
                }
                for (position, table) in self.proof.field_tables.iter().enumerate() {
                    let expected = self
                        .proof
                        .commitment
                        .tables
                        .get(*table)
                        .ok_or_else(|| RuntimeError::Proof("field table index".into()))?;
                    let actual = &field_opening.commitment.tables[position];
                    if actual.num_variables != expected.num_variables
                        || actual.num_columns != expected.num_columns
                    {
                        return Err(RuntimeError::Proof("field table shape mismatch".into()));
                    }
                }
                let field_index = self
                    .proof
                    .field_tables
                    .iter()
                    .enumerate()
                    .map(|(position, table)| (*table, position))
                    .collect::<std::collections::BTreeMap<_, _>>();
                let (field_points, field_values) = self
                    .points
                    .iter()
                    .zip(&self.values)
                    .filter(|(point, _)| field_index.contains_key(&point.table))
                    .map(|(point, values)| {
                        let mut point = point.clone();
                        point.table = field_index[&point.table];
                        (point, values.clone())
                    })
                    .unzip::<_, _, Vec<_>, Vec<_>>();
                if !opening_pcs_for_commitment(&self.proof.commitment)
                    .verify_mosaic(field_opening, &field_points, &field_values)
                    .map_err(|error| RuntimeError::Proof(error.to_string()))?
                {
                    return Err(RuntimeError::Proof("field opening rejected".into()));
                }
            } else if self.proof.field_opening.is_some() {
                return Err(RuntimeError::Proof("unexpected field opening".into()));
            }
        } else if let Some(opening) = &self.proof.opening {
            if !opening_pcs_for_commitment(&opening.commitment)
                .verify_mosaic(opening, &self.points, &self.values)
                .map_err(|error| RuntimeError::Proof(error.to_string()))?
            {
                return Err(RuntimeError::Proof("unified opening rejected".into()));
            }
        }
        crate::verify_table_batch_claims(self.proof, &original)?;
        Ok(())
    }

    #[allow(dead_code)]
    fn verify_revealed_opening(&self) -> Result<(), RuntimeError> {
        let context = UnifiedProveContext::new(self.trace, self.width)?;
        let commitment = opening_pcs(&context.mosaic_tables)
            .commit_mosaic(&context.mosaic_tables)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        if commitment != self.proof.commitment {
            return Err(RuntimeError::Proof(
                "revealed tables do not match the committed mosaic".into(),
            ));
        }
        for (point, expected) in self.points.iter().zip(&self.values) {
            if !point.next_columns.is_empty() {
                return Err(RuntimeError::Proof(
                    "revealed opening does not support successor columns".into(),
                ));
            }
            let table = context
                .mosaic_tables
                .get(point.table)
                .ok_or_else(|| RuntimeError::Proof("revealed table index".into()))?;
            if point.columns.len() != expected.len() {
                return Err(RuntimeError::Proof("revealed column count".into()));
            }
            for (column, value) in point.columns.iter().zip(expected) {
                let column = table
                    .columns
                    .get(*column)
                    .ok_or_else(|| RuntimeError::Proof("revealed column index".into()))?;
                let actual = Mle::new(column.clone())
                    .map_err(|error| RuntimeError::Proof(error.to_string()))?
                    .eval(&point.point)
                    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
                if actual != *value {
                    return Err(RuntimeError::Proof("revealed opening value".into()));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn take_routed_claims(&mut self) -> Option<ClaimSet> {
        self.routed_claims.take()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClaimRouteError {
    #[error("segment {0:?} is missing from the catalog")]
    MissingSegment(String),
    #[error("claim count {claims} does not match layout segment count {segments}")]
    Shape { claims: usize, segments: usize },
    #[error("claim point has {actual} coordinates, segment {segment:?} needs {expected}")]
    PointLength {
        segment: String,
        expected: usize,
        actual: usize,
    },
}

/// Map a public witness-layout segment to the claim family consumed by the
/// specialized argument that owns it.
pub fn segment_claim_kind(segment: &Segment) -> ClaimKind {
    match segment.owner {
        SegmentOwner::Memory(MemoryKind::Registers) => ClaimKind::Register,
        SegmentOwner::Memory(MemoryKind::Ram) => ClaimKind::Ram,
        SegmentOwner::Memory(MemoryKind::Rom) => ClaimKind::Bytecode,
        SegmentOwner::Routing(RoutingKind::Shifts) => ClaimKind::Shift,
        SegmentOwner::Routing(RoutingKind::Stores) => ClaimKind::Store,
        SegmentOwner::Cpu | SegmentOwner::Pcs => match segment.kind {
            SegmentKind::Direct => ClaimKind::Direct,
            SegmentKind::Virtual => ClaimKind::Direct,
        },
    }
}

/// Convert lockstep/Virtual-Spartan segment claims into routed claims.
///
/// `point` is the inner sum-check challenge (`ry`), and each segment's local
/// point is its low `log2(len)` coordinates. The returned `ClaimSet` is keyed
/// by the layout names so specialized reducers can consume the families they
/// own.
pub fn route_segment_claims(
    layout: &WitnessLayout,
    point: &[F2_128],
    claims: &[SegmentClaim],
    catalog: &SegmentCatalog,
) -> Result<ClaimSet, ClaimRouteError> {
    if claims.len() != layout.segments.len() {
        return Err(ClaimRouteError::Shape {
            claims: claims.len(),
            segments: layout.segments.len(),
        });
    }
    let mut routed = ClaimSet::new();
    for (segment, claim) in layout.segments.iter().zip(claims) {
        let size_bits = segment.len.trailing_zeros() as usize;
        if point.len() < size_bits {
            return Err(ClaimRouteError::PointLength {
                segment: segment.name.clone(),
                expected: size_bits,
                actual: point.len(),
            });
        }
        let id = catalog
            .id(&segment.name)
            .ok_or_else(|| ClaimRouteError::MissingSegment(segment.name.clone()))?;
        routed.push(Claim::new(
            segment_claim_kind(segment),
            id,
            point[..size_bits].to_vec(),
            claim.value,
        ));
    }
    Ok(routed)
}

#[cfg(test)]
mod routing_tests {
    use super::*;
    use magnetar_constraint::{MemoryKind, RoutingKind, SegmentKind, SegmentOwner};
    use magnetar_proof::virtual_spartan::SegmentClaim;

    fn segment(name: &str, offset: usize, owner: SegmentOwner, kind: SegmentKind) -> Segment {
        Segment::new(name, offset, 2, kind, owner)
    }

    #[test]
    fn virtual_spartan_segment_claims_route_to_components() {
        let layout = WitnessLayout::new(vec![
            segment("cpu.pc", 0, SegmentOwner::Cpu, SegmentKind::Direct),
            segment(
                "regs.read",
                2,
                SegmentOwner::Memory(MemoryKind::Registers),
                SegmentKind::Virtual,
            ),
            segment(
                "ram.read",
                4,
                SegmentOwner::Memory(MemoryKind::Ram),
                SegmentKind::Virtual,
            ),
            segment(
                "shift.out",
                6,
                SegmentOwner::Routing(RoutingKind::Shifts),
                SegmentKind::Virtual,
            ),
            segment(
                "store.out",
                8,
                SegmentOwner::Routing(RoutingKind::Stores),
                SegmentKind::Virtual,
            ),
            segment(
                "rom.fetch",
                10,
                SegmentOwner::Memory(MemoryKind::Rom),
                SegmentKind::Virtual,
            ),
            segment("cpu.rd", 12, SegmentOwner::Cpu, SegmentKind::Direct),
            segment("cpu.rs1", 14, SegmentOwner::Cpu, SegmentKind::Direct),
        ])
        .expect("layout");
        let catalog = SegmentCatalog::from_layout(&layout);
        let claims = (0..layout.segments.len())
            .map(|index| SegmentClaim {
                value: F2_128::from(index as u64 + 1),
            })
            .collect::<Vec<_>>();
        let point = (0..4)
            .map(|index| F2_128::from(index as u64 + 7))
            .collect::<Vec<_>>();
        let mut routed = route_segment_claims(&layout, &point, &claims, &catalog).expect("route");
        assert_eq!(routed.len(), layout.segments.len());
        assert_eq!(
            routed.take(ClaimKind::Register).unwrap().segment,
            SegmentId(1)
        );
        assert_eq!(routed.take(ClaimKind::Ram).unwrap().segment, SegmentId(2));
        assert_eq!(routed.take(ClaimKind::Shift).unwrap().segment, SegmentId(3));
        assert_eq!(routed.take(ClaimKind::Store).unwrap().segment, SegmentId(4));
        assert_eq!(
            routed.take(ClaimKind::Bytecode).unwrap().segment,
            SegmentId(5)
        );
        assert_eq!(routed.remaining(), 3);
        assert!(routed.take(ClaimKind::Direct).is_some());
        let mut routed = route_segment_claims(&layout, &point, &claims, &catalog).expect("route");
        ProtocolPlan::unified()
            .consume_virtual_claims(&mut routed)
            .expect("all claims have a consumer");
    }
}

#[cfg(test)]
mod metadata_tests {
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    #[test]
    fn cpu_witness_metadata_covers_the_merged_system() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
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
        .expect("trace");
        let (system, witness, metadata) =
            crate::merged_cpu_system_with_metadata(&trace, 8).expect("merged system");
        assert_eq!(metadata.total_len(), witness.values().len());
        assert!(metadata.total_len() <= system.num_vars);
        let mut expected_offset = 0;
        for segment in &metadata.segments {
            assert_eq!(segment.offset, expected_offset);
            expected_offset += segment.len;
        }
        assert!(metadata
            .segments
            .iter()
            .any(|segment| segment.row_kind == crate::CpuRowKind::Alu));
        assert!(metadata
            .segments
            .iter()
            .any(|segment| !segment.vars.is_empty()));
        let padded = metadata.padded_virtual_layout().unwrap();
        let values = padded.pad_values(witness.values());
        assert_eq!(values.len(), padded.layout.total_bits);
        assert_eq!(padded.unpad_values(&values), witness.values());
        let point = vec![
            magnetar_constraint::F2_128::from(0u64);
            padded.layout.total_bits.trailing_zeros() as usize
        ];
        let claims =
            magnetar_proof::virtual_spartan::split_segment_claims(&padded.layout, &values, &point)
                .unwrap();
        let groups =
            magnetar_proof::virtual_spartan::route_segment_claims_by_owner(&padded.layout, &claims)
                .unwrap();
        magnetar_proof::virtual_spartan::VirtualClaimRouter::new(&padded.layout)
            .verify(&groups)
            .unwrap();
    }
    #[test]
    fn opening_pcs_scale_with_table_bits() {
        let table = |bits: usize| magnetar_pcs::P3MosaicTable {
            columns: vec![vec![
                magnetar_constraint::F2_128::from(0u64);
                1usize << bits
            ]],
        };
        let small = super::opening_pcs(&[table(5)]);
        assert_eq!(
            (small.log_inv_rate, small.pow_bits, small.log_folding_factor),
            (3, 24, 2)
        );
        let large = super::opening_pcs(&[table(6)]);
        assert_eq!(
            (large.log_inv_rate, large.pow_bits, large.log_folding_factor),
            (3, 21, 2)
        );
    }
}
