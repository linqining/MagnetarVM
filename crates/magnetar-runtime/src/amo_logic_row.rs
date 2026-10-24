//! Isolated AMOXOR / AMOAND / AMOOR / AMOSWAP rows with memory read/write.

use magnetar_constraint::VarId;
use magnetar_proof::dual_field::{BitRelation, BitRow};

use crate::simd_f2::GatedMemoryRow;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmoLogicKind {
    Xor,
    And,
    Or,
    Swap,
}

#[derive(Clone, Debug)]
pub struct AmoLogicRow {
    pub width: usize,
    pub kind: AmoLogicKind,
    pub old: Vec<VarId>,
    pub operand: Vec<VarId>,
    pub new: Vec<VarId>,
    pub and: Vec<VarId>,
    pub read: GatedMemoryRow,
    pub write: GatedMemoryRow,
    pub read_offset: usize,
    pub write_offset: usize,
    pub address: Vec<VarId>,
    pub zero: VarId,
    pub one: VarId,
    pub relation: BitRelation,
}

impl AmoLogicRow {
    pub fn new(width: usize, kind: AmoLogicKind) -> Self {
        let read = GatedMemoryRow::new(width);
        let mut relation = BitRelation::new(read.relation.num_vars);
        for row in &read.relation.rows {
            relation.add(row.clone());
        }
        let read_offset = 0;
        let write = GatedMemoryRow::new(width);
        let write_offset = relation.num_vars;
        relation.num_vars += write.relation.num_vars;
        for row in &write.relation.rows {
            let shift = |vars: &[VarId]| vars.iter().map(|v| *v + write_offset).collect::<Vec<_>>();
            relation.add(BitRow::new(shift(&row.a), shift(&row.b), shift(&row.c)));
        }
        let mut cursor = relation.num_vars;
        let old = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let operand = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let new = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let address = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let zero = cursor;
        let one = cursor + 1;
        relation.num_vars = cursor + 2;
        relation.add(BitRow::new(vec![zero], vec![one], Vec::new()));
        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        for var in old.iter().chain(&operand).chain(&new).chain(&address) {
            relation.add(BitRow::new(vec![*var], vec![*var, one], Vec::new()));
        }
        let and = (relation.num_vars..relation.num_vars + width).collect::<Vec<_>>();
        relation.num_vars += width;
        for bit in 0..width {
            match kind {
                AmoLogicKind::Xor => {
                    relation.add(BitRow::new(
                        vec![old[bit], operand[bit]],
                        vec![one],
                        vec![new[bit]],
                    ));
                }
                AmoLogicKind::And => {
                    relation.add(BitRow::new(
                        vec![old[bit]],
                        vec![operand[bit]],
                        vec![new[bit]],
                    ));
                }
                AmoLogicKind::Or => {
                    relation.add(BitRow::new(
                        vec![old[bit]],
                        vec![operand[bit]],
                        vec![and[bit]],
                    ));
                    relation.add(BitRow::new(
                        vec![old[bit], operand[bit], and[bit]],
                        vec![one],
                        vec![new[bit]],
                    ));
                }
                AmoLogicKind::Swap => {
                    relation.add(BitRow::new(vec![operand[bit]], vec![one], vec![new[bit]]));
                }
            }
            for adder in [&read.adder, &write.adder] {
                let base = if std::ptr::eq(adder, &read.adder) {
                    read_offset
                } else {
                    write_offset
                };
                relation.add(BitRow::new(
                    vec![adder.a[bit] + base],
                    vec![one],
                    vec![address[bit]],
                ));
                relation.add(BitRow::new(
                    vec![adder.b[bit] + base],
                    vec![one],
                    vec![zero],
                ));
                relation.add(BitRow::new(vec![adder.gate + base], vec![one], vec![one]));
            }
            relation.add(BitRow::new(
                vec![read.data[bit] + read_offset],
                vec![one],
                vec![old[bit]],
            ));
            relation.add(BitRow::new(
                vec![write.data_in[bit] + write_offset],
                vec![one],
                vec![new[bit]],
            ));
            relation.add(BitRow::new(
                vec![write.data[bit] + write_offset],
                vec![one],
                vec![new[bit]],
            ));
        }
        Self {
            width,
            kind,
            old,
            operand,
            new,
            and,
            read,
            write,
            read_offset,
            write_offset,
            address,
            zero,
            one,
            relation,
        }
    }

    pub fn witness(&self, old: u64, operand: u64, address: u64) -> Vec<bool> {
        let mut bits = self.read.witness(address, 0, old, true);
        bits.resize(self.relation.num_vars, false);
        bits[self.zero] = false;
        bits[self.one] = true;
        let mask = (1u64 << self.width) - 1;
        let value = match self.kind {
            AmoLogicKind::Xor => old ^ operand,
            AmoLogicKind::And => old & operand,
            AmoLogicKind::Or => old | operand,
            AmoLogicKind::Swap => operand,
        } & mask;
        let and_value = old & operand;
        for (bit, and_bit) in self.and.iter().enumerate() {
            bits[*and_bit] = (and_value >> bit) & 1 == 1;
        }
        for bit in 0..self.width {
            bits[self.old[bit]] = (old >> bit) & 1 == 1;
            bits[self.operand[bit]] = (operand >> bit) & 1 == 1;
            bits[self.new[bit]] = (value >> bit) & 1 == 1;
            bits[self.address[bit]] = (address >> bit) & 1 == 1;
        }
        let write = self.write.witness(address, 0, value, true);
        bits[self.write_offset..self.write_offset + write.len()].copy_from_slice(&write);
        bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amo_logic_rows_compute() {
        for (kind, expected) in [
            (AmoLogicKind::Xor, 0b0110u64),
            (AmoLogicKind::And, 0b1000),
            (AmoLogicKind::Or, 0b1110),
            (AmoLogicKind::Swap, 0b1010),
        ] {
            let row = AmoLogicRow::new(8, kind);
            let bits = row.witness(0b1100, 0b1010, 0x100);
            assert!(row.relation.check(&bits), "{kind:?}");
            let value = row
                .new
                .iter()
                .enumerate()
                .fold(0u64, |v, (bit, var)| v | (u64::from(bits[*var]) << bit));
            assert_eq!(value, expected, "{kind:?}");
        }
    }
}
