//! Branch row: target/sequential adders, equality and signed/unsigned compares.

use magnetar_constraint::VarId;
use magnetar_proof::dual_field::{BitRelation, BitRow};

use crate::simd_f2::{GatedAluOp, GatedAluRow};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BranchKind {
    Beq,
    Bne,
    Blt,
    Bge,
    Bltu,
    Bgeu,
}

#[derive(Clone, Debug)]
pub struct GatedBranchRow {
    pub width: usize,
    pub target_alu: GatedAluRow,
    pub seq_alu: GatedAluRow,
    pub signed_alu: GatedAluRow,
    pub unsigned_alu: GatedAluRow,
    pub target_offset: usize,
    pub seq_offset: usize,
    pub signed_offset: usize,
    pub unsigned_offset: usize,
    pub rs1: Vec<VarId>,
    pub rs2: Vec<VarId>,
    pub diff: Vec<VarId>,
    pub or_bits: Vec<VarId>,
    pub or_products: Vec<VarId>,
    pub is_beq: VarId,
    pub is_bne: VarId,
    pub is_blt: VarId,
    pub is_bge: VarId,
    pub is_bltu: VarId,
    pub is_bgeu: VarId,
    pub taken_terms: Vec<VarId>,
    pub taken: VarId,
    pub is_branch: VarId,
    pub next: Vec<VarId>,
    pub one: VarId,
    pub relation: BitRelation,
}

impl GatedBranchRow {
    pub fn new(width: usize) -> Self {
        let target_alu = GatedAluRow::new(width);
        let seq_alu = GatedAluRow::new(width);
        let signed_alu = GatedAluRow::new(width);
        let unsigned_alu = GatedAluRow::new(width);
        let target_offset = 0usize;
        let seq_offset = target_alu.relation.num_vars;
        let signed_offset = seq_offset + seq_alu.relation.num_vars;
        let unsigned_offset = signed_offset + signed_alu.relation.num_vars;
        let mut relation = target_alu.relation.clone();
        let append = |relation: &mut BitRelation, source: &GatedAluRow, offset: usize| {
            relation.num_vars += source.relation.num_vars;
            for row in &source.relation.rows {
                let shift = |vars: &[VarId]| vars.iter().map(|v| *v + offset).collect::<Vec<_>>();
                relation.add(BitRow::new(shift(&row.a), shift(&row.b), shift(&row.c)));
            }
        };
        append(&mut relation, &seq_alu, seq_offset);
        append(&mut relation, &signed_alu, signed_offset);
        append(&mut relation, &unsigned_alu, unsigned_offset);

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
        let is_blt = cursor + 2;
        let is_bge = cursor + 3;
        let is_bltu = cursor + 4;
        let is_bgeu = cursor + 5;
        let taken_terms = (cursor + 6..cursor + 12).collect::<Vec<_>>();
        let taken = cursor + 12;
        let is_branch = cursor + 13;
        let one = cursor + 14;
        cursor += 15;
        let next = (cursor..cursor + width).collect::<Vec<_>>();
        relation.num_vars = cursor + width;

        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        for selector in [
            is_beq, is_bne, is_blt, is_bge, is_bltu, is_bgeu, taken, is_branch,
        ] {
            relation.add(BitRow::new(vec![selector], vec![selector, one], Vec::new()));
        }
        for var in rs1
            .iter()
            .chain(&rs2)
            .chain(&diff)
            .chain(&or_bits)
            .chain(&or_products)
            .chain(&taken_terms)
            .chain(&next)
        {
            relation.add(BitRow::new(vec![*var], vec![*var, one], Vec::new()));
        }
        for bit in 0..width {
            relation.add(BitRow::new(
                vec![rs1[bit], rs2[bit]],
                vec![one],
                vec![diff[bit]],
            ));
            relation.add(BitRow::new(
                vec![signed_alu.a[bit] + signed_offset],
                vec![one],
                vec![rs1[bit]],
            ));
            relation.add(BitRow::new(
                vec![signed_alu.b[bit] + signed_offset],
                vec![one],
                vec![rs2[bit]],
            ));
            relation.add(BitRow::new(
                vec![unsigned_alu.a[bit] + unsigned_offset],
                vec![one],
                vec![rs1[bit]],
            ));
            relation.add(BitRow::new(
                vec![unsigned_alu.b[bit] + unsigned_offset],
                vec![one],
                vec![rs2[bit]],
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
        let slt = signed_alu.out[0] + signed_offset;
        let sltu = unsigned_alu.out[0] + unsigned_offset;
        relation.add(BitRow::new(
            vec![is_beq],
            vec![one, or_bits[width - 1]],
            vec![taken_terms[0]],
        ));
        relation.add(BitRow::new(
            vec![is_bne],
            vec![or_bits[width - 1]],
            vec![taken_terms[1]],
        ));
        relation.add(BitRow::new(vec![is_blt], vec![slt], vec![taken_terms[2]]));
        relation.add(BitRow::new(
            vec![is_bge],
            vec![one, slt],
            vec![taken_terms[3]],
        ));
        relation.add(BitRow::new(vec![is_bltu], vec![sltu], vec![taken_terms[4]]));
        relation.add(BitRow::new(
            vec![is_bgeu],
            vec![one, sltu],
            vec![taken_terms[5]],
        ));
        relation.add(BitRow::new(taken_terms.clone(), vec![one], vec![taken]));
        relation.add(BitRow::new(
            vec![is_beq, is_bne, is_blt, is_bge, is_bltu, is_bgeu],
            vec![one],
            vec![is_branch],
        ));
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
            signed_alu,
            unsigned_alu,
            target_offset,
            seq_offset,
            signed_offset,
            unsigned_offset,
            rs1,
            rs2,
            diff,
            or_bits,
            or_products,
            is_beq,
            is_bne,
            is_blt,
            is_bge,
            is_bltu,
            is_bgeu,
            taken_terms,
            taken,
            is_branch,
            next,
            one,
            relation,
        }
    }

    pub fn inactive_witness(&self) -> Vec<bool> {
        let mut bits = self.target_alu.witness(0, 0, GatedAluOp::Inactive);
        bits.extend(self.seq_alu.witness(0, 0, GatedAluOp::Inactive));
        bits.extend(self.signed_alu.witness(0, 0, GatedAluOp::Inactive));
        bits.extend(self.unsigned_alu.witness(0, 0, GatedAluOp::Inactive));
        bits.resize(self.relation.num_vars, false);
        bits[self.one] = true;
        bits
    }

    pub fn witness(&self, pc: u64, imm: u64, rs1: u64, rs2: u64, kind: BranchKind) -> Vec<bool> {
        let mut bits = self.target_alu.witness(pc, imm, GatedAluOp::Add);
        bits.extend(self.seq_alu.witness(pc, 4, GatedAluOp::Add));
        bits.extend(self.signed_alu.witness(rs1, rs2, GatedAluOp::Slt));
        bits.extend(self.unsigned_alu.witness(rs1, rs2, GatedAluOp::Sltu));
        bits.resize(self.relation.num_vars, false);
        bits[self.one] = true;
        bits[self.is_beq] = kind == BranchKind::Beq;
        bits[self.is_bne] = kind == BranchKind::Bne;
        bits[self.is_blt] = kind == BranchKind::Blt;
        bits[self.is_bge] = kind == BranchKind::Bge;
        bits[self.is_bltu] = kind == BranchKind::Bltu;
        bits[self.is_bgeu] = kind == BranchKind::Bgeu;
        bits[self.is_branch] = true;

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
        let slt = bits[self.signed_offset + self.signed_alu.out[0]];
        let sltu = bits[self.unsigned_offset + self.unsigned_alu.out[0]];
        let terms = [
            kind == BranchKind::Beq && !or_value,
            kind == BranchKind::Bne && or_value,
            kind == BranchKind::Blt && slt,
            kind == BranchKind::Bge && !slt,
            kind == BranchKind::Bltu && sltu,
            kind == BranchKind::Bgeu && !sltu,
        ];
        for (term, value) in self.taken_terms.iter().zip(terms) {
            bits[*term] = value;
        }
        let taken = terms.iter().any(|value| *value);
        bits[self.taken] = taken;
        for bit in 0..self.width {
            let target = bits[self.target_offset + self.target_alu.out[bit]];
            let sequential = bits[self.seq_offset + self.seq_alu.out[bit]];
            bits[self.next[bit]] = if taken { target } else { sequential };
        }
        bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn next(row: &GatedBranchRow, bits: &[bool]) -> u64 {
        row.next.iter().enumerate().fold(0u64, |value, (bit, var)| {
            value | (u64::from(bits[*var]) << bit)
        })
    }

    #[test]
    fn branch_row_selects_all_kinds() {
        let row = GatedBranchRow::new(8);
        for (kind, a, b, expected) in [
            (BranchKind::Beq, 5u64, 5u64, 0x18u64),
            (BranchKind::Beq, 5, 6, 0x14),
            (BranchKind::Bne, 5, 6, 0x18),
            (BranchKind::Blt, 3, 5, 0x18),
            (BranchKind::Bge, 5, 3, 0x18),
            (BranchKind::Bltu, 5, 3, 0x14),
            (BranchKind::Bgeu, 3, 5, 0x14),
        ] {
            let bits = row.witness(0x10, 8, a, b, kind);
            assert!(row.relation.check(&bits), "{kind:?}");
            assert_eq!(next(&row, &bits), expected, "{kind:?}");
        }
    }
}
