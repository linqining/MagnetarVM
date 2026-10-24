//! Isolated 32-bit DIVW/REMW/DIVUW/REMUW row prototype.
//!
//! Runs 32-bit signed and unsigned division on the low halves, selects the
//! requested result, then sign-extends the 32-bit result to 64 bits.

use magnetar_constraint::VarId;
use magnetar_proof::dual_field::{BitRelation, BitRow};

use crate::div_row::GatedDivRow;
use crate::signed_div_row::SignedDivRow;

#[derive(Clone, Debug)]
pub struct WordDivRow {
    pub signed: SignedDivRow,
    pub unsigned: GatedDivRow,
    pub signed_offset: usize,
    pub unsigned_offset: usize,
    pub quotient: Vec<VarId>,
    pub remainder: Vec<VarId>,
    pub signed_sel: VarId,
    pub relation: BitRelation,
}

impl WordDivRow {
    pub fn new() -> Self {
        let signed = SignedDivRow::new(32);
        let unsigned = GatedDivRow::new(32);
        let mut relation = BitRelation::new(signed.relation.num_vars);
        for row in &signed.relation.rows {
            relation.add(row.clone());
        }
        let unsigned_offset = relation.num_vars;
        relation.num_vars += unsigned.relation.num_vars;
        for row in &unsigned.relation.rows {
            let shift = |vars: &[VarId]| {
                vars.iter()
                    .map(|v| *v + unsigned_offset)
                    .collect::<Vec<_>>()
            };
            relation.add(BitRow::new(shift(&row.a), shift(&row.b), shift(&row.c)));
        }
        let mut cursor = relation.num_vars;
        let quotient = (cursor..cursor + 64).collect::<Vec<_>>();
        cursor += 64;
        let remainder = (cursor..cursor + 64).collect::<Vec<_>>();
        cursor += 64;
        let signed_sel = cursor;
        let one = cursor + 1;
        relation.num_vars = cursor + 2;
        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        relation.add(BitRow::new(
            vec![signed_sel],
            vec![signed_sel, one],
            Vec::new(),
        ));
        for var in quotient.iter().chain(&remainder) {
            relation.add(BitRow::new(vec![*var], vec![*var, one], Vec::new()));
        }
        for bit in 0..32 {
            relation.add(BitRow::new(
                vec![signed_sel],
                vec![signed.quotient[bit], unsigned_offset + unsigned.q[bit]],
                vec![quotient[bit], unsigned_offset + unsigned.q[bit]],
            ));
            relation.add(BitRow::new(
                vec![signed_sel],
                vec![signed.remainder[bit], unsigned_offset + unsigned.rem[bit]],
                vec![remainder[bit], unsigned_offset + unsigned.rem[bit]],
            ));
        }
        for bit in 32..64 {
            relation.add(BitRow::new(
                vec![quotient[bit], quotient[31]],
                vec![one],
                Vec::new(),
            ));
            relation.add(BitRow::new(
                vec![remainder[bit], remainder[31]],
                vec![one],
                Vec::new(),
            ));
        }
        Self {
            signed,
            unsigned,
            signed_offset: 0,
            unsigned_offset,
            quotient,
            remainder,
            signed_sel,
            relation,
        }
    }

    pub fn witness(&self, num: u64, den: u64, signed: bool) -> Vec<bool> {
        let mask = u32::MAX as u64;
        let n = num & mask;
        let d = den & mask;
        let mut bits = if signed {
            self.signed.witness(n, d)
        } else {
            self.signed.inactive_witness()
        };
        bits.resize(self.relation.num_vars, false);
        let tail = if signed {
            self.unsigned.inactive_witness()
        } else {
            self.unsigned.witness(n, d)
        };
        bits[self.unsigned_offset..self.unsigned_offset + tail.len()].copy_from_slice(&tail);
        let one = self.relation.num_vars - 1;
        bits[one] = true;
        bits[self.signed_sel] = signed;
        let q32 = if signed {
            self.signed
                .quotient
                .iter()
                .take(32)
                .enumerate()
                .fold(0u64, |v, (bit, var)| v | (u64::from(bits[*var]) << bit))
        } else {
            self.unsigned
                .q
                .iter()
                .take(32)
                .enumerate()
                .fold(0u64, |v, (bit, var)| {
                    v | (u64::from(bits[var + self.unsigned_offset]) << bit)
                })
        };
        let r32 = if signed {
            self.signed
                .remainder
                .iter()
                .take(32)
                .enumerate()
                .fold(0u64, |v, (bit, var)| v | (u64::from(bits[*var]) << bit))
        } else {
            self.unsigned
                .rem
                .iter()
                .take(32)
                .enumerate()
                .fold(0u64, |v, (bit, var)| {
                    v | (u64::from(bits[var + self.unsigned_offset]) << bit)
                })
        };
        let q = if q32 & 0x8000_0000 != 0 {
            q32 | 0xffff_ffff_0000_0000
        } else {
            q32
        };
        let r = if r32 & 0x8000_0000 != 0 {
            r32 | 0xffff_ffff_0000_0000
        } else {
            r32
        };
        for bit in 0..64 {
            bits[self.quotient[bit]] = (q >> bit) & 1 == 1;
            bits[self.remainder[bit]] = (r >> bit) & 1 == 1;
        }
        bits
    }
}

impl Default for WordDivRow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_div_rows_divide() {
        let row = WordDivRow::new();
        for (num, den, signed) in [
            (100u64, 7u64, true),
            (100, 7, false),
            (0x8000_0000, 0xffff_ffff, true),
            (0x8000_0000, 0xffff_ffff, false),
        ] {
            let bits = row.witness(num, den, signed);
            assert!(row.relation.check(&bits), "{num}/{den} signed={signed}");
            let q = row
                .quotient
                .iter()
                .take(32)
                .enumerate()
                .fold(0u64, |v, (bit, var)| v | (u64::from(bits[*var]) << bit));
            if !(signed && num == 0x8000_0000 && den == 0xffff_ffff) {
                let expected = if signed {
                    ((num as u32 as i32) / (den as u32 as i32)) as u32 as u64
                } else {
                    ((num as u32) / (den as u32)) as u64
                };
                assert_eq!(q, expected & 0xffff_ffff, "{num}/{den} signed={signed}");
            }
        }
    }
}
