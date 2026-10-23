//! Minimal sequential-PC row used to validate conditional PC+4 gating.

use magnetar_constraint::VarId;
use magnetar_proof::dual_field::{BitRelation, BitRow};

#[derive(Clone, Debug)]
pub struct SequentialPcRow {
    pub width: usize,
    pub pc: Vec<VarId>,
    pub next_pc: Vec<VarId>,
    pub sequential: VarId,
    pub carry: Vec<VarId>,
    pub one: VarId,
    pub relation: BitRelation,
}

impl SequentialPcRow {
    pub fn new(width: usize) -> Self {
        assert!(width >= 2);
        let pc = (0..width).collect::<Vec<_>>();
        let next_pc = (width..2 * width).collect::<Vec<_>>();
        let sequential = 2 * width;
        let carry = (2 * width + 1..3 * width + 1).collect::<Vec<_>>();
        let one = 3 * width + 1;
        let mut relation = BitRelation::new(3 * width + 2);
        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        for bit in 0..width {
            relation.add(BitRow::new(vec![pc[bit]], vec![pc[bit], one], Vec::new()));
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![next_pc[bit], one],
                Vec::new(),
            ));
        }
        for bit in 0..width {
            if bit < 2 {
                relation.add(BitRow::new(
                    vec![next_pc[bit], pc[bit]],
                    vec![sequential],
                    Vec::new(),
                ));
            } else if bit == 2 {
                relation.add(BitRow::new(
                    vec![next_pc[bit], pc[bit]],
                    vec![sequential],
                    vec![sequential],
                ));
                relation.add(BitRow::new(
                    vec![pc[bit]],
                    vec![sequential],
                    vec![carry[bit]],
                ));
            } else {
                relation.add(BitRow::new(
                    vec![next_pc[bit], pc[bit], carry[bit - 1]],
                    vec![sequential],
                    Vec::new(),
                ));
                relation.add(BitRow::new(
                    vec![pc[bit]],
                    vec![carry[bit - 1]],
                    vec![carry[bit]],
                ));
            }
        }
        Self {
            width,
            pc,
            next_pc,
            sequential,
            carry,
            one,
            relation,
        }
    }

    pub fn witness(&self, pc: u64, next_pc: u64, sequential: bool) -> Vec<bool> {
        let mut bits = vec![false; self.relation.num_vars];
        for bit in 0..self.width {
            bits[self.pc[bit]] = (pc >> bit) & 1 == 1;
            bits[self.next_pc[bit]] = (next_pc >> bit) & 1 == 1;
        }
        bits[self.sequential] = sequential;
        bits[self.one] = true;
        if sequential {
            bits[self.carry[2]] = (pc >> 2) & 1 == 1;
            for bit in 3..self.width {
                bits[self.carry[bit]] = ((pc >> bit) & 1 == 1) && bits[self.carry[bit - 1]];
            }
        }
        bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequential_pc_row_matches_pc_plus_four() {
        let row = SequentialPcRow::new(8);
        for pc in 0u64..256 {
            let bits = row.witness(pc, (pc + 4) & 0xff, true);
            if !row.relation.check(&bits) {
                for (index, bit_row) in row.relation.rows.iter().enumerate() {
                    let parity =
                        |vars: &[VarId]| vars.iter().filter(|v| bits[**v]).count() % 2 == 1;
                    if (parity(&bit_row.a) && parity(&bit_row.b)) != parity(&bit_row.c) {
                        eprintln!(
                            "pc={pc} bad row {index}: {:?} {:?} {:?}",
                            bit_row.a, bit_row.b, bit_row.c
                        );
                    }
                }
            }
            assert!(row.relation.check(&bits), "pc={pc}");
            let bits = row.witness(pc, 0x77, false);
            assert!(row.relation.check(&bits), "free pc={pc}");
        }
    }
}
