//! Isolated unsigned DIV/REM row prototype.
//!
//! Proves `num = q*den + rem` with `rem < den` by reusing the multiplication
//! row and two ALU datapaths.

use magnetar_constraint::VarId;
use magnetar_proof::dual_field::{BitRelation, BitRow};

use crate::mul_row::GatedMulRow;
use crate::simd_f2::{GatedAluOp, GatedAluRow};

#[derive(Clone, Debug)]
pub struct GatedDivRow {
    pub width: usize,
    pub num: Vec<VarId>,
    pub den: Vec<VarId>,
    pub rem: Vec<VarId>,
    pub mul: GatedMulRow,
    pub mul_offset: usize,
    pub add_alu: GatedAluRow,
    pub add_offset: usize,
    pub cmp_alu: GatedAluRow,
    pub cmp_offset: usize,
    pub is_div: VarId,
    pub q: Vec<VarId>,
    pub relation: BitRelation,
}

fn append_alu(relation: &mut BitRelation, alu: &GatedAluRow, offset: usize) {
    relation.num_vars += alu.relation.num_vars;
    for row in &alu.relation.rows {
        let shift = |vars: &[VarId]| vars.iter().map(|v| *v + offset).collect::<Vec<_>>();
        relation.add(BitRow::new(shift(&row.a), shift(&row.b), shift(&row.c)));
    }
}

impl GatedDivRow {
    pub fn new(width: usize) -> Self {
        let mul = GatedMulRow::new(width);
        let add_alu = GatedAluRow::new(width);
        let cmp_alu = GatedAluRow::new(width);
        let mut relation = BitRelation::new(mul.relation.num_vars);
        for row in &mul.relation.rows {
            relation.add(row.clone());
        }
        let add_offset = relation.num_vars;
        append_alu(&mut relation, &add_alu, add_offset);
        let cmp_offset = relation.num_vars;
        append_alu(&mut relation, &cmp_alu, cmp_offset);
        let mut cursor = relation.num_vars;
        let num = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let den = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let rem = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let is_div = cursor;
        let one = cursor + 1;
        relation.num_vars = cursor + 2;
        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        relation.add(BitRow::new(vec![is_div], vec![is_div, one], Vec::new()));
        for var in num.iter().chain(&den).chain(&rem) {
            relation.add(BitRow::new(vec![*var], vec![*var, one], Vec::new()));
        }
        for bit in 0..width {
            relation.add(BitRow::new(
                vec![mul.product[width + bit]],
                vec![one],
                Vec::new(),
            ));
            relation.add(BitRow::new(
                vec![add_alu.a[bit] + add_offset],
                vec![one],
                vec![mul.product[bit]],
            ));
            relation.add(BitRow::new(
                vec![add_alu.b[bit] + add_offset],
                vec![one],
                vec![rem[bit]],
            ));
            relation.add(BitRow::new(
                vec![add_alu.out[bit] + add_offset],
                vec![one],
                vec![num[bit]],
            ));
            relation.add(BitRow::new(
                vec![cmp_alu.a[bit] + cmp_offset],
                vec![one],
                vec![rem[bit]],
            ));
            relation.add(BitRow::new(
                vec![cmp_alu.b[bit] + cmp_offset],
                vec![one],
                vec![den[bit]],
            ));
        }
        relation.add(BitRow::new(
            vec![cmp_alu.lt + cmp_offset],
            vec![one],
            vec![one],
        ));
        let q = mul.a.clone();
        Self {
            width,
            num,
            den,
            rem,
            mul,
            mul_offset: 0,
            add_alu,
            add_offset,
            cmp_alu,
            cmp_offset,
            is_div,
            q,
            relation,
        }
    }

    pub fn inactive_witness(&self) -> Vec<bool> {
        let mut bits = self.witness(0, 1);
        bits[self.is_div] = false;
        bits
    }

    pub fn witness(&self, num: u64, den: u64) -> Vec<bool> {
        let q = num / den;
        let r = num % den;
        let mut bits = self.mul.witness(q, den);
        bits.resize(self.relation.num_vars, false);
        bits[self.relation.num_vars - 1] = true;
        bits[self.is_div] = true;
        let product = self
            .mul
            .product
            .iter()
            .take(self.width)
            .enumerate()
            .fold(0u64, |value, (bit, var)| {
                value | (u64::from(bits[*var]) << bit)
            });
        let add = self.add_alu.witness(product, r, GatedAluOp::Add);
        bits[self.add_offset..self.add_offset + add.len()].copy_from_slice(&add);
        let cmp = self.cmp_alu.witness(r, den, GatedAluOp::Sub);
        bits[self.cmp_offset..self.cmp_offset + cmp.len()].copy_from_slice(&cmp);
        for bit in 0..self.width {
            bits[self.num[bit]] = (num >> bit) & 1 == 1;
            bits[self.den[bit]] = (den >> bit) & 1 == 1;
            bits[self.rem[bit]] = (r >> bit) & 1 == 1;
        }
        bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn div_row_divides() {
        let row = GatedDivRow::new(8);
        for (num, den) in [(17u64, 5u64), (255, 7), (100, 10), (1, 3)] {
            let bits = row.witness(num, den);
            assert!(row.relation.check(&bits), "{num}/{den}");
            let q = row
                .mul
                .a
                .iter()
                .enumerate()
                .fold(0u64, |value, (bit, var)| {
                    value | (u64::from(bits[*var]) << bit)
                });
            let r = row.rem.iter().enumerate().fold(0u64, |value, (bit, var)| {
                value | (u64::from(bits[*var]) << bit)
            });
            assert_eq!((q, r), (num / den, num % den));
        }
    }
}
