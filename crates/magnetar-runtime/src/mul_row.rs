//! Schoolbook multiplication row (reference prototype).
//!
//! `width` shift-add rounds over a `2*width` accumulator. Full adders use
//! explicit carry-majority OR gates so the relation is a real F2 circuit.

use magnetar_constraint::VarId;
use magnetar_proof::dual_field::{BitRelation, BitRow};

#[derive(Clone, Debug)]
pub struct FullAdder {
    pub sum: VarId,
    pub carry: VarId,
    pub p1: VarId,
    pub p2: VarId,
    pub p3: VarId,
    pub or12: VarId,
    pub or12p: VarId,
    pub carryp: VarId,
}

#[derive(Clone, Debug)]
pub struct GatedMulRow {
    pub width: usize,
    pub a: Vec<VarId>,
    pub b: Vec<VarId>,
    pub product: Vec<VarId>,
    pub is_mul: VarId,
    pub zero: VarId,
    pub one: VarId,
    pub pp: Vec<Vec<VarId>>,
    pub acc: Vec<Vec<VarId>>,
    pub adders: Vec<Vec<FullAdder>>,
    pub relation: BitRelation,
}

fn alloc(relation: &mut BitRelation, count: usize) -> Vec<VarId> {
    let start = relation.num_vars;
    relation.num_vars += count;
    (start..start + count).collect()
}

impl GatedMulRow {
    pub fn new(width: usize) -> Self {
        let mut relation = BitRelation::new(0);
        let a = alloc(&mut relation, width);
        let b = alloc(&mut relation, width);
        let zero = alloc(&mut relation, 1)[0];
        let one = alloc(&mut relation, 1)[0];
        let is_mul = alloc(&mut relation, 1)[0];
        relation.add(BitRow::new(vec![zero], vec![one], Vec::new()));
        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        relation.add(BitRow::new(vec![is_mul], vec![is_mul, one], Vec::new()));
        for var in a.iter().chain(&b) {
            relation.add(BitRow::new(vec![*var], vec![*var, one], Vec::new()));
        }

        let mut pp = Vec::with_capacity(width);
        for a_bit in &a {
            let row = alloc(&mut relation, width);
            for (j, b_bit) in b.iter().enumerate() {
                relation.add(BitRow::new(vec![*a_bit], vec![*b_bit], vec![row[j]]));
            }
            pp.push(row);
        }

        let mut acc = Vec::with_capacity(width + 1);
        acc.push(vec![zero; 2 * width]);
        let mut adders = Vec::with_capacity(width);
        for i in 0..width {
            let mut carry = zero;
            let mut next = Vec::with_capacity(2 * width);
            let mut row_adders = Vec::with_capacity(2 * width);
            for k in 0..2 * width {
                let addend = if k >= i && k < i + width {
                    pp[i][k - i]
                } else {
                    zero
                };
                let left = acc[i][k];
                let sum = alloc(&mut relation, 1)[0];
                let p1 = alloc(&mut relation, 1)[0];
                let p2 = alloc(&mut relation, 1)[0];
                let p3 = alloc(&mut relation, 1)[0];
                let or12 = alloc(&mut relation, 1)[0];
                let or12p = alloc(&mut relation, 1)[0];
                let carryp = alloc(&mut relation, 1)[0];
                let next_carry = alloc(&mut relation, 1)[0];
                relation.add(BitRow::new(vec![left, addend, carry], vec![one], vec![sum]));
                relation.add(BitRow::new(vec![left], vec![addend], vec![p1]));
                relation.add(BitRow::new(vec![left], vec![carry], vec![p2]));
                relation.add(BitRow::new(vec![addend], vec![carry], vec![p3]));
                relation.add(BitRow::new(vec![p1], vec![p2], vec![or12p]));
                relation.add(BitRow::new(vec![p1, p2, or12p], vec![one], vec![or12]));
                relation.add(BitRow::new(vec![or12], vec![p3], vec![carryp]));
                relation.add(BitRow::new(
                    vec![or12, p3, carryp],
                    vec![one],
                    vec![next_carry],
                ));
                row_adders.push(FullAdder {
                    sum,
                    carry: next_carry,
                    p1,
                    p2,
                    p3,
                    or12,
                    or12p,
                    carryp,
                });
                next.push(sum);
                carry = next_carry;
            }
            acc.push(next);
            adders.push(row_adders);
        }
        let product = acc[width].clone();
        for var in &product {
            relation.add(BitRow::new(vec![*var], vec![*var, one], Vec::new()));
        }
        Self {
            width,
            a,
            b,
            product,
            is_mul,
            zero,
            one,
            pp,
            acc,
            adders,
            relation,
        }
    }

    pub fn inactive_witness(&self) -> Vec<bool> {
        let mut bits = self.witness(0, 0);
        bits[self.is_mul] = false;
        bits
    }

    pub fn witness(&self, left: u64, right: u64) -> Vec<bool> {
        let mut bits = vec![false; self.relation.num_vars];
        bits[self.one] = true;
        bits[self.is_mul] = true;
        for bit in 0..self.width {
            bits[self.a[bit]] = (left >> bit) & 1 == 1;
            bits[self.b[bit]] = (right >> bit) & 1 == 1;
        }
        for i in 0..self.width {
            for j in 0..self.width {
                bits[self.pp[i][j]] = bits[self.a[i]] && bits[self.b[j]];
            }
        }
        for i in 0..self.width {
            let mut carry = false;
            for (k, adder) in self.adders[i].iter().enumerate() {
                let left = bits[self.acc[i][k]];
                let addend = if k >= i && k < i + self.width {
                    bits[self.pp[i][k - i]]
                } else {
                    false
                };
                let sum = left ^ addend ^ carry;
                let p1 = left && addend;
                let p2 = left && carry;
                let p3 = addend && carry;
                let or12 = p1 || p2;
                let carryp = or12 && p3;
                bits[adder.sum] = sum;
                bits[adder.p1] = p1;
                bits[adder.p2] = p2;
                bits[adder.p3] = p3;
                bits[adder.or12p] = p1 && p2;
                bits[adder.or12] = or12;
                bits[adder.carryp] = carryp;
                let next_carry = or12 || p3;
                bits[adder.carry] = next_carry;
                carry = next_carry;
            }
        }
        bits[self.zero] = false;
        bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(row: &GatedMulRow, bits: &[bool]) -> u64 {
        row.product
            .iter()
            .enumerate()
            .fold(0u64, |value, (bit, var)| {
                value | (u64::from(bits[*var]) << bit)
            })
    }

    #[test]
    fn mul_row_multiplies() {
        let row = GatedMulRow::new(8);
        for (a, b) in [(5u64, 3u64), (255, 255), (0, 7), (17, 13)] {
            let bits = row.witness(a, b);
            assert!(row.relation.check(&bits), "{a}*{b}");
            assert_eq!(value(&row, &bits), a * b);
        }
    }
}
