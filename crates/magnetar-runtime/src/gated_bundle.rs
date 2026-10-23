//! End-to-end gated CPU bundle: gated dual CPU proof + BinaryTwist RAM proof
//! + Register/Ram claims routed through `ProtocolPlan`.

use magnetar_constraint::{WitnessLayout, F2_128};
use magnetar_pcs::{P3MosaicCommitment, P3MosaicOpening, P3SharedPcs};
use magnetar_proof::{BitPcs, DirectBitPcs, LockstepProof, SpartanProof};

use crate::binary_twist::{prove_binary_twist_ram, verify_binary_twist_ram, BinaryTwistRamProof};
use crate::gated_aux::{prove_gated_aux, verify_gated_aux, GatedAuxProof};
use crate::gated_register::{gated_register_twist_witness, GatedRegisterEvent};
use crate::gated_shift::{
    gated_shift_events_from_trace, prove_gated_shift_row, verify_gated_shift_row, GatedShiftEvent,
};
use crate::protocol::{Claim, ClaimKind, ClaimSet, ProtocolPlan, SegmentId};
use crate::simd_dual::{prove_gated_dual_batch_bits, verify_gated_dual_batch_bits};
use crate::simd_f2::{gated_memory_twist_witness, GatedCpuRowInput};
use crate::RuntimeError;

#[derive(Clone, Debug)]
pub struct GatedBundle<C: Clone + std::fmt::Debug, O: Clone + std::fmt::Debug> {
    pub cpu: LockstepProof<C, O>,
    pub cpu_layout: WitnessLayout,
    pub ram: Option<BinaryTwistRamProof>,
    pub register: Option<BinaryTwistRamProof>,
    pub register_events: Vec<GatedRegisterEvent>,
    pub register_initial: [u64; 32],
    pub aux: Option<GatedAuxProof>,
    pub shift_events: Vec<GatedShiftEvent>,
    pub shift_proofs: Vec<SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>>,
    pub claims: Vec<Claim>,
}

pub type P3GatedBundle = GatedBundle<P3MosaicCommitment, P3MosaicOpening>;

fn claims_for(rows: &[(u64, GatedCpuRowInput)]) -> Vec<Claim> {
    rows.iter()
        .map(|(pc, input)| {
            let kind = match input {
                GatedCpuRowInput::Alu { .. } => ClaimKind::Register,
                GatedCpuRowInput::Memory { .. } => ClaimKind::Ram,
            };
            Claim::new(
                kind,
                SegmentId(0),
                vec![F2_128::from(*pc)],
                F2_128::from(1u64),
            )
        })
        .collect()
}

pub fn prove_gated_bundle_with_backend<B: BitPcs>(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
    backend: &B,
) -> Result<GatedBundle<B::Commitment, B::Opening>, RuntimeError> {
    let (cpu, cpu_layout) = prove_gated_dual_batch_bits(width, rows, backend)?;
    let ram = match gated_memory_twist_witness(width, rows) {
        Ok(witness) => Some(
            prove_binary_twist_ram(&witness)
                .map_err(|error| RuntimeError::Proof(error.to_string()))?,
        ),
        Err(_) => None,
    };
    let claims = claims_for(rows);
    let plan = ProtocolPlan::unified();
    let set = ClaimSet::with_claims(claims.clone());
    plan.check_virtual_claims(&set)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(GatedBundle {
        cpu,
        cpu_layout,
        ram,
        register: None,
        register_events: Vec::new(),
        register_initial: [0u64; 32],
        aux: None,
        shift_events: Vec::new(),
        shift_proofs: Vec::new(),
        claims,
    })
}

pub fn verify_gated_bundle_with_backend<B: BitPcs>(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
    bundle: &GatedBundle<B::Commitment, B::Opening>,
    backend: &B,
) -> Result<(), RuntimeError> {
    verify_gated_dual_batch_bits(width, rows, &bundle.cpu, &bundle.cpu_layout, backend)?;
    if let Some(ram) = &bundle.ram {
        let witness = gated_memory_twist_witness(width, rows)?;
        verify_binary_twist_ram(&witness, ram)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    }
    if let Some(register) = &bundle.register {
        let witness =
            gated_register_twist_witness(&bundle.register_events, &bundle.register_initial)
                .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        verify_binary_twist_ram(&witness, register)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    }
    let plan = ProtocolPlan::unified();
    let mut set = ClaimSet::with_claims(bundle.claims.clone());
    plan.check_virtual_claims(&set)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    plan.consume_virtual_claims(&mut set)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    if set.remaining() != 0 {
        return Err(RuntimeError::Proof(
            "gated bundle left unconsumed claims".into(),
        ));
    }
    Ok(())
}

pub fn prove_gated_bundle(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
) -> Result<P3GatedBundle, RuntimeError> {
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    prove_gated_bundle_with_backend(width, rows, &DirectBitPcs::new(pcs))
}

pub fn prove_gated_bundle_with_registers<B: BitPcs>(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
    backend: &B,
    events: Vec<GatedRegisterEvent>,
    initial: [u64; 32],
) -> Result<GatedBundle<B::Commitment, B::Opening>, RuntimeError> {
    let mut bundle = prove_gated_bundle_with_backend(width, rows, backend)?;
    if !events.is_empty() {
        let witness = gated_register_twist_witness(&events, &initial)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        let proof = prove_binary_twist_ram(&witness)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        bundle.register = Some(proof);
        bundle.register_events = events;
        bundle.register_initial = initial;
    }
    Ok(bundle)
}

pub fn verify_gated_bundle(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
    bundle: &P3GatedBundle,
) -> Result<(), RuntimeError> {
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    verify_gated_bundle_with_backend(width, rows, bundle, &DirectBitPcs::new(pcs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simd_f2::GatedAluOp;
    use magnetar_proof::RingSwitchPackedBitPcs;

    fn rows() -> Vec<(u64, GatedCpuRowInput)> {
        vec![
            (
                0x1000,
                GatedCpuRowInput::Alu {
                    left: 5,
                    right: 3,
                    op: GatedAluOp::Add,
                },
            ),
            (
                0x1004,
                GatedCpuRowInput::Memory {
                    rs1: 0x10,
                    imm: 2,
                    value: 0x34,
                    is_mem: true,
                },
            ),
        ]
    }

    #[test]
    fn gated_bundle_covers_alu_memory_and_twist() {
        let rows = rows();
        let bundle = prove_gated_bundle(8, &rows).unwrap();
        assert!(bundle.ram.is_some());
        verify_gated_bundle(8, &rows, &bundle).unwrap();
    }

    #[test]
    fn mixed_backend_bundle_proves_alu_m4_memory_m5() {
        let rows = rows();
        let bundle = prove_mixed_gated_bundle(8, &rows).unwrap();
        verify_mixed_gated_bundle(8, &rows, &bundle).unwrap();
    }

    #[test]
    fn gated_bundle_attaches_register_twist() {
        use crate::gated_register::GatedRegisterEvent;
        use magnetar_proof::DirectBitPcs;

        let rows = rows();
        let events = vec![GatedRegisterEvent {
            rs1: 0,
            rs2: 0,
            rd: 1,
            left: 5,
            right: 3,
            out: 8,
        }];
        let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
        let backend = DirectBitPcs::new(pcs);
        let bundle =
            prove_gated_bundle_with_registers(8, &rows, &backend, events, [0u64; 32]).unwrap();
        assert!(bundle.register.is_some());
        verify_gated_bundle_with_backend(8, &rows, &bundle, &backend).unwrap();
    }

    #[test]
    fn gated_bundle_runs_with_ring_switch_backend() {
        let rows = rows();
        let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
        let backend = RingSwitchPackedBitPcs::new(pcs);
        let bundle = prove_gated_bundle_with_backend(8, &rows, &backend).unwrap();
        assert!(bundle.ram.is_some());
        verify_gated_bundle_with_backend(8, &rows, &bundle, &backend).unwrap();
    }
}

/// Mixed backend bundle: ALU rows use M4 DirectBitPcs, memory rows use M5
/// RingSwitchPackedBitPcs, and the RAM consistency proof remains BinaryTwist.
#[derive(Clone, Debug)]
pub struct MixedGatedBundle<AO: Clone + std::fmt::Debug, MO: Clone + std::fmt::Debug> {
    pub alu_cpu: LockstepProof<P3MosaicCommitment, AO>,
    pub alu_layout: WitnessLayout,
    pub memory_cpu: LockstepProof<P3MosaicCommitment, MO>,
    pub memory_layout: WitnessLayout,
    pub ram: BinaryTwistRamProof,
    pub claims: Vec<Claim>,
}

pub fn prove_mixed_gated_bundle(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
) -> Result<
    MixedGatedBundle<P3MosaicOpening, magnetar_proof::RingSwitchOpening<P3MosaicOpening>>,
    RuntimeError,
> {
    use magnetar_proof::RingSwitchPackedBitPcs;

    let alu_rows = rows
        .iter()
        .filter(|(_, input)| matches!(input, GatedCpuRowInput::Alu { .. }))
        .copied()
        .collect::<Vec<_>>();
    let memory_rows = rows
        .iter()
        .filter(|(_, input)| matches!(input, GatedCpuRowInput::Memory { .. }))
        .copied()
        .collect::<Vec<_>>();
    if alu_rows.is_empty() || memory_rows.is_empty() {
        return Err(RuntimeError::Proof(
            "mixed bundle needs both ALU and memory rows".into(),
        ));
    }
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    let direct = DirectBitPcs::new(pcs.clone());
    let ring = RingSwitchPackedBitPcs::new(pcs);
    let (alu_cpu, alu_layout) = prove_gated_dual_batch_bits(width, &alu_rows, &direct)?;
    let (memory_cpu, memory_layout) = prove_gated_dual_batch_bits(width, &memory_rows, &ring)?;
    let memory_witness = gated_memory_twist_witness(width, &memory_rows)?;
    let ram = prove_binary_twist_ram(&memory_witness)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let claims = claims_for(rows);
    let plan = ProtocolPlan::unified();
    let set = ClaimSet::with_claims(claims.clone());
    plan.check_virtual_claims(&set)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(MixedGatedBundle {
        alu_cpu,
        alu_layout,
        memory_cpu,
        memory_layout,
        ram,
        claims,
    })
}

pub fn verify_mixed_gated_bundle(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
    bundle: &MixedGatedBundle<P3MosaicOpening, magnetar_proof::RingSwitchOpening<P3MosaicOpening>>,
) -> Result<(), RuntimeError> {
    use magnetar_proof::RingSwitchPackedBitPcs;

    let alu_rows = rows
        .iter()
        .filter(|(_, input)| matches!(input, GatedCpuRowInput::Alu { .. }))
        .copied()
        .collect::<Vec<_>>();
    let memory_rows = rows
        .iter()
        .filter(|(_, input)| matches!(input, GatedCpuRowInput::Memory { .. }))
        .copied()
        .collect::<Vec<_>>();
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    let direct = DirectBitPcs::new(pcs.clone());
    let ring = RingSwitchPackedBitPcs::new(pcs);
    verify_gated_dual_batch_bits(
        width,
        &alu_rows,
        &bundle.alu_cpu,
        &bundle.alu_layout,
        &direct,
    )?;
    verify_gated_dual_batch_bits(
        width,
        &memory_rows,
        &bundle.memory_cpu,
        &bundle.memory_layout,
        &ring,
    )?;
    let memory_witness = gated_memory_twist_witness(width, &memory_rows)?;
    verify_binary_twist_ram(&memory_witness, &bundle.ram)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let plan = ProtocolPlan::unified();
    let mut set = ClaimSet::with_claims(bundle.claims.clone());
    plan.check_virtual_claims(&set)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    plan.consume_virtual_claims(&mut set)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    if set.remaining() != 0 {
        return Err(RuntimeError::Proof(
            "mixed bundle left unconsumed claims".into(),
        ));
    }
    Ok(())
}

pub fn prove_gated_bundle_from_trace<B: BitPcs>(
    trace: &magnetar_spec::Trace,
    width: usize,
    backend: &B,
) -> Result<GatedBundle<B::Commitment, B::Opening>, RuntimeError> {
    let rows = crate::simd_full::gated_rows_from_trace(trace, width)?;
    let mut bundle = prove_gated_bundle_with_backend(width, &rows, backend)?;
    if let Ok((events, initial)) = crate::gated_register::gated_register_events_from_trace(trace) {
        let witness = gated_register_twist_witness(&events, &initial)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        let proof = prove_binary_twist_ram(&witness)
            .map_err(|error| RuntimeError::Proof(error.to_string()))?;
        bundle.register = Some(proof);
        bundle.register_events = events;
        bundle.register_initial = initial;
    }
    bundle.aux = Some(prove_gated_aux(trace)?);
    if let Ok(events) = gated_shift_events_from_trace(trace) {
        let mut proofs = Vec::new();
        for event in &events {
            proofs.push(prove_gated_shift_row(width, *event)?);
        }
        bundle.shift_events = events;
        bundle.shift_proofs = proofs;
    }
    Ok(bundle)
}

pub fn verify_gated_bundle_from_trace<B: BitPcs>(
    trace: &magnetar_spec::Trace,
    width: usize,
    bundle: &GatedBundle<B::Commitment, B::Opening>,
    backend: &B,
) -> Result<(), RuntimeError> {
    let rows = crate::simd_full::gated_rows_from_trace(trace, width)?;
    verify_gated_bundle_with_backend(width, &rows, bundle, backend)?;
    if let Some(aux) = &bundle.aux {
        verify_gated_aux(trace, aux)?;
    }
    for (event, proof) in bundle.shift_events.iter().zip(&bundle.shift_proofs) {
        verify_gated_shift_row(width, *event, proof)?;
    }
    Ok(())
}

#[cfg(test)]
mod trace_tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_proof::DirectBitPcs;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    #[test]
    fn trace_bundle_includes_aux_and_register() {
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
                    op: Op::Slli,
                    rd: 2,
                    rs1: 1,
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
        let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
        let backend = DirectBitPcs::new(pcs);
        let bundle = prove_gated_bundle_from_trace(&trace, 8, &backend).unwrap();
        assert!(bundle.aux.is_some());
        assert!(bundle.register.is_some());
        assert!(!bundle.shift_proofs.is_empty());
        verify_gated_bundle_from_trace(&trace, 8, &bundle, &backend).unwrap();
    }
}
