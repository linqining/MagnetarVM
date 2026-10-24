//! Isolated signed DIV/REM row prototype.
//!
//! Takes absolute values, runs unsigned DIV/REM, then restores quotient and
//! remainder signs. The RISC-V INT_MIN/-1 wrap case is covered by two's
//! complement negation.

use magnetar_constraint::VarId;
use magnetar_proof::dual_field::{BitRelation, BitRow};

use crate::div_row::GatedDivRow;
use crate::simd_f2::{GatedAluOp, GatedAluRow};

#[derive(Clone, Debug)]
pub struct SignedDivRow {
    pub width: usize,
    pub num: Vec<VarId>,
    pub den: Vec<VarId>,
    pub abs_num: Vec<VarId>,
    pub abs_den: Vec<VarId>,
    pub quotient: Vec<VarId>,
    pub remainder: Vec<VarId>,
    pub div: GatedDivRow,
    pub absn_alu: GatedAluRow,
    pub absd_alu: GatedAluRow,
    pub negq_alu: GatedAluRow,
    pub negr_alu: GatedAluRow,
    pub absn_offset: usize,
    pub absd_offset: usize,
    pub negq_offset: usize,
    pub negr_offset: usize,
    pub sign_num: VarId,
    pub sign_den: VarId,
    pub sign_q: VarId,
    pub zero: VarId,
    pub one: VarId,
    pub is_sdiv: VarId,
    pub relation: BitRelation,
}

fn append_alu(relation: &mut BitRelation, alu: &GatedAluRow, offset: usize) {
    relation.num_vars += alu.relation.num_vars;
    for row in &alu.relation.rows {
        let shift = |vars: &[VarId]| vars.iter().map(|v| *v + offset).collect::<Vec<_>>();
        relation.add(BitRow::new(shift(&row.a), shift(&row.b), shift(&row.c)));
    }
}

impl SignedDivRow {
    pub fn new(width: usize) -> Self {
        let div = GatedDivRow::new(width);
        let absn_alu = GatedAluRow::new(width);
        let absd_alu = GatedAluRow::new(width);
        let negq_alu = GatedAluRow::new(width);
        let negr_alu = GatedAluRow::new(width);
        let mut relation = BitRelation::new(div.relation.num_vars);
        for row in &div.relation.rows {
            relation.add(row.clone());
        }
        let absn_offset = relation.num_vars;
        append_alu(&mut relation, &absn_alu, absn_offset);
        let absd_offset = relation.num_vars;
        append_alu(&mut relation, &absd_alu, absd_offset);
        let negq_offset = relation.num_vars;
        append_alu(&mut relation, &negq_alu, negq_offset);
        let negr_offset = relation.num_vars;
        append_alu(&mut relation, &negr_alu, negr_offset);
        let mut cursor = relation.num_vars;
        let num = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let den = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let abs_num = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let abs_den = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let quotient = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let remainder = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let sign_num = cursor;
        let sign_den = cursor + 1;
        let sign_q = cursor + 2;
        let zero = cursor + 3;
        let one = cursor + 4;
        let is_sdiv = cursor + 5;
        relation.num_vars = cursor + 6;
        relation.add(BitRow::new(vec![zero], vec![one], Vec::new()));
        relation.add(BitRow::new(vec![is_sdiv], vec![is_sdiv, one], Vec::new()));
        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        for selector in [sign_num, sign_den, sign_q] {
            relation.add(BitRow::new(vec![selector], vec![selector, one], Vec::new()));
        }
        for var in num
            .iter()
            .chain(&den)
            .chain(&abs_num)
            .chain(&abs_den)
            .chain(&quotient)
            .chain(&remainder)
        {
            relation.add(BitRow::new(vec![*var], vec![*var, one], Vec::new()));
        }
        relation.add(BitRow::new(
            vec![sign_num, sign_den],
            vec![one],
            vec![sign_q],
        ));
        for bit in 0..width {
            // abs ALUs: 0 - num / 0 - den
            relation.add(BitRow::new(
                vec![absn_alu.a[bit] + absn_offset],
                vec![one],
                vec![zero],
            ));
            relation.add(BitRow::new(
                vec![absn_alu.b[bit] + absn_offset],
                vec![one],
                vec![num[bit]],
            ));
            relation.add(BitRow::new(
                vec![absd_alu.a[bit] + absd_offset],
                vec![one],
                vec![zero],
            ));
            relation.add(BitRow::new(
                vec![absd_alu.b[bit] + absd_offset],
                vec![one],
                vec![den[bit]],
            ));
            relation.add(BitRow::new(
                vec![sign_num],
                vec![absn_alu.out[bit] + absn_offset, num[bit]],
                vec![abs_num[bit], num[bit]],
            ));
            relation.add(BitRow::new(
                vec![sign_den],
                vec![absd_alu.out[bit] + absd_offset, den[bit]],
                vec![abs_den[bit], den[bit]],
            ));
            relation.add(BitRow::new(
                vec![div.num[bit]],
                vec![one],
                vec![abs_num[bit]],
            ));
            relation.add(BitRow::new(
                vec![div.den[bit]],
                vec![one],
                vec![abs_den[bit]],
            ));
            // negate abs quotient/remainder
            relation.add(BitRow::new(
                vec![negq_alu.a[bit] + negq_offset],
                vec![one],
                vec![zero],
            ));
            relation.add(BitRow::new(
                vec![negq_alu.b[bit] + negq_offset],
                vec![one],
                vec![div.q[bit]],
            ));
            relation.add(BitRow::new(
                vec![negr_alu.a[bit] + negr_offset],
                vec![one],
                vec![zero],
            ));
            relation.add(BitRow::new(
                vec![negr_alu.b[bit] + negr_offset],
                vec![one],
                vec![div.rem[bit]],
            ));
            relation.add(BitRow::new(
                vec![sign_q],
                vec![negq_alu.out[bit] + negq_offset, div.q[bit]],
                vec![quotient[bit], div.q[bit]],
            ));
            relation.add(BitRow::new(
                vec![sign_num],
                vec![negr_alu.out[bit] + negr_offset, div.rem[bit]],
                vec![remainder[bit], div.rem[bit]],
            ));
        }
        Self {
            width,
            num,
            den,
            abs_num,
            abs_den,
            quotient,
            remainder,
            div,
            absn_alu,
            absd_alu,
            negq_alu,
            negr_alu,
            absn_offset,
            absd_offset,
            negq_offset,
            negr_offset,
            sign_num,
            sign_den,
            sign_q,
            zero,
            one,
            is_sdiv,
            relation,
        }
    }

    pub fn inactive_witness(&self) -> Vec<bool> {
        let mut bits = self.witness(0, 1);
        bits[self.is_sdiv] = false;
        bits
    }

    #[allow(clippy::too_many_arguments)]
    pub fn witness(&self, num: u64, den: u64) -> Vec<bool> {
        let mask = if self.width == 64 {
            u64::MAX
        } else {
            (1u64 << self.width) - 1
        };
        let sign_num = ((num >> (self.width - 1)) & 1) == 1;
        let sign_den = ((den >> (self.width - 1)) & 1) == 1;
        let abs_num = if sign_num { num.wrapping_neg() } else { num } & mask;
        let abs_den = if sign_den { den.wrapping_neg() } else { den } & mask;
        let mut bits = self.div.witness(abs_num, abs_den);
        bits.resize(self.relation.num_vars, false);
        bits[self.one] = true;
        bits[self.zero] = false;
        bits[self.sign_num] = sign_num;
        bits[self.sign_den] = sign_den;
        bits[self.sign_q] = sign_num ^ sign_den;
        bits[self.is_sdiv] = true;
        let q_abs = self
            .div
            .q
            .iter()
            .enumerate()
            .fold(0u64, |v, (bit, var)| v | (u64::from(bits[*var]) << bit));
        let r_abs = self
            .div
            .rem
            .iter()
            .enumerate()
            .fold(0u64, |v, (bit, var)| v | (u64::from(bits[*var]) << bit));
        let absn = self.absn_alu.witness(0, num, GatedAluOp::Sub);
        bits[self.absn_offset..self.absn_offset + absn.len()].copy_from_slice(&absn);
        let absd = self.absd_alu.witness(0, den, GatedAluOp::Sub);
        bits[self.absd_offset..self.absd_offset + absd.len()].copy_from_slice(&absd);
        let negq = self.negq_alu.witness(0, q_abs, GatedAluOp::Sub);
        bits[self.negq_offset..self.negq_offset + negq.len()].copy_from_slice(&negq);
        let negr = self.negr_alu.witness(0, r_abs, GatedAluOp::Sub);
        bits[self.negr_offset..self.negr_offset + negr.len()].copy_from_slice(&negr);
        let q = if sign_num ^ sign_den {
            q_abs.wrapping_neg()
        } else {
            q_abs
        } & mask;
        let r = if sign_num {
            r_abs.wrapping_neg()
        } else {
            r_abs
        } & mask;
        for bit in 0..self.width {
            bits[self.num[bit]] = (num >> bit) & 1 == 1;
            bits[self.den[bit]] = (den >> bit) & 1 == 1;
            bits[self.abs_num[bit]] = (abs_num >> bit) & 1 == 1;
            bits[self.abs_den[bit]] = (abs_den >> bit) & 1 == 1;
            bits[self.quotient[bit]] = (q >> bit) & 1 == 1;
            bits[self.remainder[bit]] = (r >> bit) & 1 == 1;
        }
        bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_div_row_divides() {
        let row = SignedDivRow::new(8);
        for (num, den) in [(0xfbu64, 5u64), (17, 0xfb), (0xfb, 0xfb), (1, 3)] {
            let bits = row.witness(num, den);
            assert!(row.relation.check(&bits), "{num}/{den}");
            let q = row
                .quotient
                .iter()
                .enumerate()
                .fold(0u64, |v, (bit, var)| v | (u64::from(bits[*var]) << bit));
            let r = row
                .remainder
                .iter()
                .enumerate()
                .fold(0u64, |v, (bit, var)| v | (u64::from(bits[*var]) << bit));
            let signed_num = (num as u8 as i8) as i64;
            let signed_den = (den as u8 as i8) as i64;
            assert_eq!(q as u8 as i8 as i64, signed_num / signed_den);
            assert_eq!(r as u8 as i8 as i64, signed_num % signed_den);
        }
    }
}
