//! Isolated load-reserved (LR) row prototype.

use magnetar_constraint::VarId;
use magnetar_proof::dual_field::{BitRelation, BitRow};

use crate::simd_f2::GatedMemoryRow;

#[derive(Clone, Debug)]
pub struct LrRow {
    pub width: usize,
    pub old: Vec<VarId>,
    pub rd: Vec<VarId>,
    pub reservation: VarId,
    pub read: GatedMemoryRow,
    pub address: Vec<VarId>,
    pub zero: VarId,
    pub one: VarId,
    pub relation: BitRelation,
}

impl LrRow {
    pub fn new(width: usize) -> Self {
        let read = GatedMemoryRow::new(width);
        let mut relation = BitRelation::new(read.relation.num_vars);
        for row in &read.relation.rows {
            relation.add(row.clone());
        }
        let mut cursor = relation.num_vars;
        let old = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let rd = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let address = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let reservation = cursor;
        let zero = cursor + 1;
        let one = cursor + 2;
        relation.num_vars = cursor + 3;
        relation.add(BitRow::new(vec![zero], vec![one], Vec::new()));
        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        relation.add(BitRow::new(vec![reservation], vec![one], vec![one]));
        for var in old.iter().chain(&rd).chain(&address) {
            relation.add(BitRow::new(vec![*var], vec![*var, one], Vec::new()));
        }
        for bit in 0..width {
            relation.add(BitRow::new(
                vec![read.adder.a[bit]],
                vec![one],
                vec![address[bit]],
            ));
            relation.add(BitRow::new(vec![read.adder.b[bit]], vec![one], vec![zero]));
            relation.add(BitRow::new(vec![read.adder.gate], vec![one], vec![one]));
            relation.add(BitRow::new(vec![read.data[bit]], vec![one], vec![old[bit]]));
            relation.add(BitRow::new(vec![rd[bit]], vec![one], vec![old[bit]]));
        }
        Self {
            width,
            old,
            rd,
            reservation,
            read,
            address,
            zero,
            one,
            relation,
        }
    }

    pub fn witness(&self, old: u64, address: u64) -> Vec<bool> {
        let mut bits = self.read.witness(address, 0, old, true);
        bits.resize(self.relation.num_vars, false);
        bits[self.zero] = false;
        bits[self.one] = true;
        bits[self.reservation] = true;
        for bit in 0..self.width {
            bits[self.old[bit]] = (old >> bit) & 1 == 1;
            bits[self.rd[bit]] = (old >> bit) & 1 == 1;
            bits[self.address[bit]] = (address >> bit) & 1 == 1;
        }
        bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lr_row_loads_and_reserves() {
        let row = LrRow::new(8);
        let bits = row.witness(42, 0x100);
        assert!(row.relation.check(&bits));
        let rd = row
            .rd
            .iter()
            .enumerate()
            .fold(0u64, |v, (bit, var)| v | (u64::from(bits[*var]) << bit));
        assert_eq!(rd, 42);
        assert!(bits[row.reservation]);
    }
}
