//! Isolated AMOADD operation row prototype.
//!
//! Constrains `new = old + operand`; memory read/write binding is added when the
//! row is fused into the CPU.

use magnetar_constraint::VarId;
use magnetar_proof::dual_field::{BitRelation, BitRow};

use crate::simd_f2::{GatedAluOp, GatedAluRow};

#[derive(Clone, Debug)]
pub struct AmoAddRow {
    pub width: usize,
    pub old: Vec<VarId>,
    pub operand: Vec<VarId>,
    pub new: Vec<VarId>,
    pub add: GatedAluRow,
    pub offset: usize,
    pub relation: BitRelation,
}

impl AmoAddRow {
    pub fn new(width: usize) -> Self {
        let add = GatedAluRow::new(width);
        let mut relation = BitRelation::new(add.relation.num_vars);
        for row in &add.relation.rows {
            relation.add(row.clone());
        }
        let offset = 0;
        let mut cursor = relation.num_vars;
        let old = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let operand = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let new = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let one = cursor;
        relation.num_vars = cursor + 1;
        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        for var in old.iter().chain(&operand).chain(&new) {
            relation.add(BitRow::new(vec![*var], vec![*var, one], Vec::new()));
        }
        for bit in 0..width {
            relation.add(BitRow::new(
                vec![add.a[bit] + offset],
                vec![one],
                vec![old[bit]],
            ));
            relation.add(BitRow::new(
                vec![add.b[bit] + offset],
                vec![one],
                vec![operand[bit]],
            ));
            relation.add(BitRow::new(
                vec![add.out[bit] + offset],
                vec![one],
                vec![new[bit]],
            ));
        }
        Self {
            width,
            old,
            operand,
            new,
            add,
            offset,
            relation,
        }
    }

    pub fn witness(&self, old: u64, operand: u64) -> Vec<bool> {
        let mut bits = self.add.witness(old, operand, GatedAluOp::Add);
        bits.resize(self.relation.num_vars, false);
        bits[self.relation.num_vars - 1] = true;
        let mask = (1u64 << self.width) - 1;
        for bit in 0..self.width {
            bits[self.old[bit]] = (old >> bit) & 1 == 1;
            bits[self.operand[bit]] = (operand >> bit) & 1 == 1;
            bits[self.new[bit]] = ((old.wrapping_add(operand) & mask) >> bit) & 1 == 1;
        }
        bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amo_add_row_adds() {
        let row = AmoAddRow::new(8);
        for (old, operand) in [(5u64, 3u64), (255, 1), (0, 7), (17, 13)] {
            let bits = row.witness(old, operand);
            assert!(row.relation.check(&bits), "{old}+{operand}");
            let value = row.new.iter().enumerate().fold(0u64, |value, (bit, var)| {
                value | (u64::from(bits[*var]) << bit)
            });
            assert_eq!(value, old.wrapping_add(operand) & 0xff);
        }
    }
}
