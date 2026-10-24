//! Isolated PC transition row: `next = sequential ? pc+4 : target`.

use magnetar_constraint::VarId;
use magnetar_proof::dual_field::{BitRelation, BitRow};

use crate::simd_f2::{GatedAluOp, GatedAluRow};

#[derive(Clone, Debug)]
pub struct PcTransitionRow {
    pub width: usize,
    pub pc: Vec<VarId>,
    pub target: Vec<VarId>,
    pub next: Vec<VarId>,
    pub sequential: VarId,
    pub add: GatedAluRow,
    pub add_offset: usize,
    pub relation: BitRelation,
}

impl PcTransitionRow {
    pub fn packed_system(&self) -> magnetar_constraint::ConstraintSystem {
        self.relation.to_system()
    }

    pub fn new(width: usize) -> Self {
        let add = GatedAluRow::new(width);
        let mut relation = BitRelation::new(add.relation.num_vars);
        for row in &add.relation.rows {
            relation.add(row.clone());
        }
        let mut cursor = relation.num_vars;
        let pc = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let target = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let next = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let sequential = cursor;
        let zero = cursor + 1;
        let one = cursor + 2;
        relation.num_vars = cursor + 3;
        relation.add(BitRow::new(vec![zero], vec![one], Vec::new()));
        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        relation.add(BitRow::new(
            vec![sequential],
            vec![sequential, one],
            Vec::new(),
        ));
        for var in pc.iter().chain(&target).chain(&next) {
            relation.add(BitRow::new(vec![*var], vec![*var, one], Vec::new()));
        }
        for bit in 0..width {
            relation.add(BitRow::new(vec![add.a[bit]], vec![one], vec![pc[bit]]));
            if bit == 2 {
                relation.add(BitRow::new(vec![add.b[bit]], vec![one], vec![one]));
            } else {
                relation.add(BitRow::new(vec![add.b[bit]], vec![one], Vec::new()));
            }
            relation.add(BitRow::new(
                vec![sequential],
                vec![add.out[bit], target[bit]],
                vec![next[bit], target[bit]],
            ));
        }
        Self {
            width,
            pc,
            target,
            next,
            sequential,
            add,
            add_offset: 0,
            relation,
        }
    }

    pub fn witness(&self, pc: u64, target: u64, sequential: bool) -> Vec<bool> {
        let mut bits = self.add.witness(pc, 4, GatedAluOp::Add);
        bits.resize(self.relation.num_vars, false);
        bits[self.relation.num_vars - 2] = false;
        bits[self.relation.num_vars - 1] = true;
        bits[self.sequential] = sequential;
        let mask = (1u64 << self.width) - 1;
        let next = if sequential {
            pc.wrapping_add(4)
        } else {
            target
        } & mask;
        for bit in 0..self.width {
            bits[self.pc[bit]] = (pc >> bit) & 1 == 1;
            bits[self.target[bit]] = (target >> bit) & 1 == 1;
            bits[self.next[bit]] = (next >> bit) & 1 == 1;
        }
        bits
    }
}

pub fn prove_pc_transition_batch(
    width: usize,
    rows: &[(u64, u64, bool)],
) -> Result<
    magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
    crate::RuntimeError,
> {
    use magnetar_proof::{prove_shared_simd_spartan, witness_vector};
    if rows.is_empty() || !rows.len().is_power_of_two() {
        return Err(crate::RuntimeError::Proof(
            "PC batch must be a nonzero power of two".into(),
        ));
    }
    let row = PcTransitionRow::new(width);
    let system = row.packed_system();
    let mut witnesses = Vec::new();
    for (pc, target, sequential) in rows {
        let bits = row.witness(*pc, *target, *sequential);
        witnesses.push(row.relation.to_witness(&bits));
    }
    let _ = witness_vector(&system, &witnesses[0])
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))?;
    let pcs = magnetar_pcs::P3BinaryPcs::new(100);
    prove_shared_simd_spartan(&system, &witnesses, &pcs)
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))
}

pub fn verify_pc_transition_batch(
    width: usize,
    instances: usize,
    proof: &magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
) -> Result<(), crate::RuntimeError> {
    use magnetar_proof::verify_shared_simd_spartan;
    let row = PcTransitionRow::new(width);
    let system = row.packed_system();
    let pcs = magnetar_pcs::P3BinaryPcs::new(100);
    verify_shared_simd_spartan(&system, instances, proof, &pcs)
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pc_batch_binds_branch_target() {
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
        let batch = prove_pc_batch(&trace, 16).unwrap().unwrap();
        assert!(batch.targets.is_some());
        verify_pc_batch(&trace, 16, Some(&batch)).unwrap();
        let mut bad = trace.clone();
        bad.rows[0].next_pc = bad.rows[0].next_pc.wrapping_add(4);
        assert!(verify_pc_batch(&bad, 16, Some(&batch)).is_err());
    }

    #[test]
    fn pc_transition_selects_target() {
        let row = PcTransitionRow::new(16);
        for (pc, target, sequential, expected) in [
            (0x1000u64, 0x2000u64, true, 0x1004u64),
            (0x1000, 0x2000, false, 0x2000),
        ] {
            let bits = row.witness(pc, target, sequential);
            assert!(row.relation.check(&bits));
            let next = row
                .next
                .iter()
                .enumerate()
                .fold(0u64, |v, (bit, var)| v | (u64::from(bits[*var]) << bit));
            assert_eq!(next, expected);
        }
        let rows = [
            (0x1000u64, 0x2000u64, true),
            (0x1004, 0x2000, false),
            (0x1008, 0x3000, true),
            (0x100c, 0x3000, false),
        ];
        let proof = prove_pc_transition_batch(16, &rows).unwrap();
        verify_pc_transition_batch(16, rows.len(), &proof).unwrap();
    }
}

pub fn verify_pc_transition_batch_bound(
    width: usize,
    rows: &[(u64, u64, bool)],
    proof: &magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
) -> Result<(), crate::RuntimeError> {
    use magnetar_proof::{verify_shared_simd_spartan_with_witnesses, witness_vector};
    let row = PcTransitionRow::new(width);
    let system = row.packed_system();
    let mut witnesses = Vec::new();
    for (pc, target, sequential) in rows {
        let bits = row.witness(*pc, *target, *sequential);
        witnesses.push(row.relation.to_witness(&bits));
    }
    let _ = witness_vector(&system, &witnesses[0])
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))?;
    let pcs = magnetar_pcs::P3BinaryPcs::new(100);
    verify_shared_simd_spartan_with_witnesses(&system, &witnesses, proof, &pcs)
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PcBatchProof {
    pub proof: magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
    pub instances: usize,
    pub targets:
        Option<magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>>,
    pub target_instances: usize,
}

pub fn prove_pc_batch(
    trace: &magnetar_spec::Trace,
    width: usize,
) -> Result<Option<PcBatchProof>, crate::RuntimeError> {
    if trace.rows.is_empty() {
        return Ok(None);
    }
    let mut rows = trace
        .rows
        .iter()
        .map(|row| {
            let sequential = row.next_pc == row.pc.wrapping_add(4);
            (row.pc, if sequential { 0 } else { row.next_pc }, sequential)
        })
        .collect::<Vec<_>>();
    while !rows.len().is_power_of_two() {
        rows.push((0, 0, true));
    }
    let proof = prove_pc_transition_batch(width, &rows)?;
    let mut targets = trace
        .rows
        .iter()
        .filter(|row| row.next_pc != row.pc.wrapping_add(4))
        .map(|row| {
            let jalr = matches!(row.instruction.op, magnetar_spec::Op::Jalr);
            (
                if jalr { row.rs1_val } else { row.pc },
                row.instruction.imm as u64,
                jalr,
                row.next_pc,
            )
        })
        .collect::<Vec<_>>();
    let target_instances = if targets.is_empty() {
        0
    } else {
        while !targets.len().is_power_of_two() {
            targets.push((0, 0, false, 0));
        }
        targets.len()
    };
    let targets = if targets.is_empty() {
        None
    } else {
        Some(crate::pc_target_row::prove_pc_target_batch(
            width, &targets,
        )?)
    };
    Ok(Some(PcBatchProof {
        proof,
        instances: rows.len(),
        targets,
        target_instances,
    }))
}

pub fn verify_pc_batch(
    trace: &magnetar_spec::Trace,
    width: usize,
    batch: Option<&PcBatchProof>,
) -> Result<(), crate::RuntimeError> {
    if trace.rows.is_empty() {
        if batch.is_some() {
            return Err(crate::RuntimeError::Proof("unexpected PC batch".into()));
        }
        return Ok(());
    }
    let Some(batch) = batch else {
        return Err(crate::RuntimeError::Proof("missing PC batch".into()));
    };
    let mut count = trace.rows.len();
    while !count.is_power_of_two() {
        count += 1;
    }
    if count != batch.instances {
        return Err(crate::RuntimeError::Proof("PC batch instance count".into()));
    }
    let target_count = trace
        .rows
        .iter()
        .filter(|row| row.next_pc != row.pc.wrapping_add(4))
        .count();
    let target_count = if target_count == 0 {
        0
    } else {
        target_count.next_power_of_two()
    };
    if target_count != batch.target_instances {
        return Err(crate::RuntimeError::Proof(
            "PC target instance count".into(),
        ));
    }
    if target_count > 0 {
        let Some(proof) = &batch.targets else {
            return Err(crate::RuntimeError::Proof("missing PC target proof".into()));
        };
        let mut target_rows = trace
            .rows
            .iter()
            .filter(|row| row.next_pc != row.pc.wrapping_add(4))
            .map(|row| {
                let jalr = matches!(row.instruction.op, magnetar_spec::Op::Jalr);
                (
                    if jalr { row.rs1_val } else { row.pc },
                    row.instruction.imm as u64,
                    jalr,
                    row.next_pc,
                )
            })
            .collect::<Vec<_>>();
        while !target_rows.len().is_power_of_two() {
            target_rows.push((0, 0, false, 0));
        }
        crate::pc_target_row::verify_pc_target_batch_bound(width, &target_rows, proof)?;
    } else if batch.targets.is_some() {
        return Err(crate::RuntimeError::Proof(
            "unexpected PC target proof".into(),
        ));
    }
    let mut rows = trace
        .rows
        .iter()
        .map(|row| {
            let sequential = row.next_pc == row.pc.wrapping_add(4);
            (row.pc, if sequential { 0 } else { row.next_pc }, sequential)
        })
        .collect::<Vec<_>>();
    while !rows.len().is_power_of_two() {
        rows.push((0, 0, true));
    }
    verify_pc_transition_batch_bound(width, &rows, &batch.proof)
}
