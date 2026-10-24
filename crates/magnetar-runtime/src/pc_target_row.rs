//! Isolated PC-relative / JALR target row.

use magnetar_constraint::VarId;
use magnetar_proof::dual_field::{BitRelation, BitRow};

use crate::simd_f2::{GatedAluOp, GatedAluRow};

#[derive(Clone, Debug)]
pub struct PcTargetRow {
    pub width: usize,
    pub base: Vec<VarId>,
    pub imm: Vec<VarId>,
    pub target: Vec<VarId>,
    pub expected: Vec<VarId>,
    pub align: VarId,
    pub add: GatedAluRow,
    pub relation: BitRelation,
}

impl PcTargetRow {
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
        let base = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let imm = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let target = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let expected = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let align = cursor;
        let one = cursor + 1;
        relation.num_vars = cursor + 2;
        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        relation.add(BitRow::new(vec![align], vec![align, one], Vec::new()));
        for var in base.iter().chain(&imm).chain(&target).chain(&expected) {
            relation.add(BitRow::new(vec![*var], vec![*var, one], Vec::new()));
        }
        for bit in 0..width {
            relation.add(BitRow::new(vec![add.a[bit]], vec![one], vec![base[bit]]));
            relation.add(BitRow::new(vec![add.b[bit]], vec![one], vec![imm[bit]]));
            relation.add(BitRow::new(
                vec![target[bit]],
                vec![one],
                vec![expected[bit]],
            ));
            if bit == 0 {
                relation.add(BitRow::new(
                    vec![align],
                    vec![add.out[bit]],
                    vec![target[bit], add.out[bit]],
                ));
            } else {
                relation.add(BitRow::new(
                    vec![add.out[bit]],
                    vec![one],
                    vec![target[bit]],
                ));
            }
        }
        Self {
            width,
            base,
            imm,
            target,
            expected,
            align,
            add,
            relation,
        }
    }

    pub fn witness(&self, base: u64, imm: u64, align: bool, expected: u64) -> Vec<bool> {
        let mut bits = self.add.witness(base, imm, GatedAluOp::Add);
        bits.resize(self.relation.num_vars, false);
        bits[self.relation.num_vars - 1] = true;
        bits[self.align] = align;
        let mask = (1u64 << self.width) - 1;
        let target = if align {
            base.wrapping_add(imm) & !1
        } else {
            base.wrapping_add(imm)
        } & mask;
        for bit in 0..self.width {
            bits[self.base[bit]] = (base >> bit) & 1 == 1;
            bits[self.imm[bit]] = (imm >> bit) & 1 == 1;
            bits[self.target[bit]] = (target >> bit) & 1 == 1;
            bits[self.expected[bit]] = (expected >> bit) & 1 == 1;
        }
        bits
    }
}

pub fn prove_pc_target_batch(
    width: usize,
    rows: &[(u64, u64, bool, u64)],
) -> Result<
    magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
    crate::RuntimeError,
> {
    use magnetar_proof::{prove_shared_simd_spartan, witness_vector};
    if rows.is_empty() || !rows.len().is_power_of_two() {
        return Err(crate::RuntimeError::Proof(
            "PC target batch must be a nonzero power of two".into(),
        ));
    }
    let row = PcTargetRow::new(width);
    let system = row.packed_system();
    let mut witnesses = Vec::new();
    for (base, imm, align, expected) in rows {
        let bits = row.witness(*base, *imm, *align, *expected);
        witnesses.push(row.relation.to_witness(&bits));
    }
    let _ = witness_vector(&system, &witnesses[0])
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))?;
    let pcs = magnetar_pcs::P3BinaryPcs::new(100);
    prove_shared_simd_spartan(&system, &witnesses, &pcs)
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))
}

pub fn verify_pc_target_batch(
    width: usize,
    instances: usize,
    proof: &magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
) -> Result<(), crate::RuntimeError> {
    use magnetar_proof::verify_shared_simd_spartan;
    let row = PcTargetRow::new(width);
    let system = row.packed_system();
    let pcs = magnetar_pcs::P3BinaryPcs::new(100);
    verify_shared_simd_spartan(&system, instances, proof, &pcs)
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pc_target_rows() {
        let row = PcTargetRow::new(16);
        for (base, imm, align, expected) in [
            (0x1000u64, 8u64, false, 0x1008u64),
            (0x2000, 5, true, 0x2004),
        ] {
            let bits = row.witness(base, imm, align, expected);
            assert!(row.relation.check(&bits));
            let target = row
                .target
                .iter()
                .enumerate()
                .fold(0u64, |v, (bit, var)| v | (u64::from(bits[*var]) << bit));
            assert_eq!(target, expected);
        }
        let rows = [
            (0x1000u64, 8u64, false, 0x1008u64),
            (0x1004, 0, false, 0x1004),
            (0x2000, 5, true, 0x2004),
            (0x2004, 0, false, 0x2004),
        ];
        let proof = prove_pc_target_batch(16, &rows).unwrap();
        verify_pc_target_batch(16, rows.len(), &proof).unwrap();
    }
}
