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
