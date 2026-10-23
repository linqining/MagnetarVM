//! Isolated BEQ/BNE branch row prototype.
//!
//! Two ALU adders compute `pc + imm` and `pc + 4`; an XOR/OR reduction computes
//! equality; a final mux selects `next_pc = taken ? target : sequential`.

use magnetar_constraint::VarId;
use magnetar_proof::dual_field::{BitRelation, BitRow};

use crate::simd_f2::{GatedAluOp, GatedAluRow};

#[derive(Clone, Debug)]
pub struct GatedBranchRow {
    pub width: usize,
    pub target_alu: GatedAluRow,
    pub seq_alu: GatedAluRow,
    pub target_offset: usize,
    pub seq_offset: usize,
    pub rs1: Vec<VarId>,
    pub rs2: Vec<VarId>,
    pub diff: Vec<VarId>,
    pub or_bits: Vec<VarId>,
    pub or_products: Vec<VarId>,
    pub is_beq: VarId,
    pub is_bne: VarId,
    pub beq_eq: VarId,
    pub bne_or: VarId,
    pub taken: VarId,
    pub next: Vec<VarId>,
    pub one: VarId,
    pub relation: BitRelation,
}

impl GatedBranchRow {
    pub fn new(width: usize) -> Self {
        let target_alu = GatedAluRow::new(width);
        let seq_alu = GatedAluRow::new(width);
        let mut relation = target_alu.relation.clone();
        let target_offset = 0usize;
        let seq_offset = target_alu.relation.num_vars;
        relation.num_vars += seq_alu.relation.num_vars;
        for row in &seq_alu.relation.rows {
            let shift = |vars: &[VarId]| vars.iter().map(|v| *v + seq_offset).collect::<Vec<_>>();
            relation.add(BitRow::new(shift(&row.a), shift(&row.b), shift(&row.c)));
        }
        let mut cursor = relation.num_vars;
        let rs1 = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let rs2 = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let diff = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let or_bits = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let or_products = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let is_beq = cursor;
        let is_bne = cursor + 1;
        let beq_eq = cursor + 2;
        let bne_or = cursor + 3;
        let taken = cursor + 4;
        let one = cursor + 5;
        cursor += 6;
        let next = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        relation.num_vars = cursor;

        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        for selector in [is_beq, is_bne, beq_eq, bne_or, taken] {
            relation.add(BitRow::new(vec![selector], vec![selector, one], Vec::new()));
        }
        for var in rs1
            .iter()
            .chain(&rs2)
            .chain(&diff)
            .chain(&or_bits)
            .chain(&or_products)
        {
            relation.add(BitRow::new(vec![*var], vec![*var, one], Vec::new()));
        }
        for var in &next {
            relation.add(BitRow::new(vec![*var], vec![*var, one], Vec::new()));
        }
        for bit in 0..width {
            relation.add(BitRow::new(
                vec![rs1[bit], rs2[bit]],
                vec![one],
                vec![diff[bit]],
            ));
        }
        relation.add(BitRow::new(vec![or_bits[0]], vec![one], vec![diff[0]]));
        for bit in 1..width {
            relation.add(BitRow::new(
                vec![or_bits[bit - 1]],
                vec![diff[bit]],
                vec![or_products[bit]],
            ));
            relation.add(BitRow::new(
                vec![or_bits[bit - 1], diff[bit], or_products[bit]],
                vec![one],
                vec![or_bits[bit]],
            ));
        }
        relation.add(BitRow::new(
            vec![is_beq],
            vec![one, or_bits[width - 1]],
            vec![beq_eq],
        ));
        relation.add(BitRow::new(
            vec![is_bne],
            vec![or_bits[width - 1]],
            vec![bne_or],
        ));
        relation.add(BitRow::new(vec![beq_eq, bne_or], vec![one], vec![taken]));
        relation.add(BitRow::new(vec![is_beq, is_bne], vec![one], vec![one]));
        for (bit, next_var) in next.iter().enumerate() {
            relation.add(BitRow::new(
                vec![taken],
                vec![target_alu.out[bit], seq_alu.out[bit] + seq_offset],
                vec![*next_var, seq_alu.out[bit] + seq_offset],
            ));
        }

        Self {
            width,
            target_alu,
            seq_alu,
            target_offset,
            seq_offset,
            rs1,
            rs2,
            diff,
            or_bits,
            or_products,
            is_beq,
            is_bne,
            beq_eq,
            bne_or,
            taken,
            next,
            one,
            relation,
        }
    }

    pub fn witness(&self, pc: u64, imm: u64, rs1: u64, rs2: u64, beq: bool) -> Vec<bool> {
        let mut bits = self.target_alu.witness(pc, imm, GatedAluOp::Add);
        let seq = self.seq_alu.witness(pc, 4, GatedAluOp::Add);
        bits.extend(seq);
        bits.resize(self.relation.num_vars, false);
        bits[self.one] = true;
        bits[self.is_beq] = beq;
        bits[self.is_bne] = !beq;
        let mut or_value = false;
        for bit in 0..self.width {
            let a = (rs1 >> bit) & 1 == 1;
            let b = (rs2 >> bit) & 1 == 1;
            let diff = a ^ b;
            bits[self.rs1[bit]] = a;
            bits[self.rs2[bit]] = b;
            bits[self.diff[bit]] = diff;
            if bit == 0 {
                bits[self.or_bits[0]] = diff;
                or_value = diff;
            } else {
                let product = or_value && diff;
                bits[self.or_products[bit]] = product;
                or_value = or_value ^ diff ^ product;
                bits[self.or_bits[bit]] = or_value;
            }
        }
        let taken = if beq { !or_value } else { or_value };
        bits[self.beq_eq] = beq && !or_value;
        bits[self.bne_or] = !beq && or_value;
        bits[self.taken] = taken;
        for bit in 0..self.width {
            let target = bits[self.target_alu.out[bit]];
            let sequential = bits[self.seq_offset + self.seq_alu.out[bit]];
            bits[self.next[bit]] = if taken { target } else { sequential };
        }
        bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_row_selects_equal_and_not_equal() {
        let row = GatedBranchRow::new(8);
        let taken = row.witness(0x10, 8, 5, 5, true);
        assert!(row.relation.check(&taken));
        let next = row.next.iter().enumerate().fold(0u64, |value, (bit, var)| {
            value | (u64::from(taken[*var]) << bit)
        });
        assert_eq!(next, 0x18);

        let not_taken = row.witness(0x10, 8, 5, 6, true);
        assert!(row.relation.check(&not_taken));
        let next = row.next.iter().enumerate().fold(0u64, |value, (bit, var)| {
            value | (u64::from(not_taken[*var]) << bit)
        });
        assert_eq!(next, 0x14);

        let bne_taken = row.witness(0x10, 8, 5, 6, false);
        assert!(row.relation.check(&bne_taken));
        let next = row.next.iter().enumerate().fold(0u64, |value, (bit, var)| {
            value | (u64::from(bne_taken[*var]) << bit)
        });
        assert_eq!(next, 0x18);
    }
}
