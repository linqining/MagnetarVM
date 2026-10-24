//! Isolated AMOADD operation row prototype.
//!
//! Constrains `new = old + operand`; memory read/write binding is added when the
//! row is fused into the CPU.

use magnetar_constraint::VarId;
use magnetar_proof::dual_field::{BitRelation, BitRow};

use crate::simd_f2::{GatedAluOp, GatedAluRow, GatedMemoryRow};

#[derive(Clone, Debug)]
pub struct AmoAddRow {
    pub width: usize,
    pub old: Vec<VarId>,
    pub operand: Vec<VarId>,
    pub new: Vec<VarId>,
    pub add: GatedAluRow,
    pub offset: usize,
    pub read: GatedMemoryRow,
    pub write: GatedMemoryRow,
    pub read_offset: usize,
    pub write_offset: usize,
    pub address: Vec<VarId>,
    pub zero: VarId,
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
        let read = GatedMemoryRow::new(width);
        let read_offset = relation.num_vars;
        relation.num_vars += read.relation.num_vars;
        for row in &read.relation.rows {
            let shift = |vars: &[VarId]| vars.iter().map(|v| *v + read_offset).collect::<Vec<_>>();
            relation.add(BitRow::new(shift(&row.a), shift(&row.b), shift(&row.c)));
        }
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
        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        for var in old.iter().chain(&operand).chain(&new).chain(&address) {
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
        for bit in 0..width {
            relation.add(BitRow::new(vec![zero], vec![one], Vec::new()));
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
            old,
            operand,
            new,
            add,
            offset,
            read,
            write,
            read_offset,
            write_offset,
            address,
            zero,
            relation,
        }
    }

    pub fn witness(&self, old: u64, operand: u64, address: u64) -> Vec<bool> {
        let mut bits = self.add.witness(old, operand, GatedAluOp::Add);
        bits.resize(self.relation.num_vars, false);
        bits[self.relation.num_vars - 1] = true;
        let mask = (1u64 << self.width) - 1;
        let value = old.wrapping_add(operand) & mask;
        for bit in 0..self.width {
            bits[self.old[bit]] = (old >> bit) & 1 == 1;
            bits[self.operand[bit]] = (operand >> bit) & 1 == 1;
            bits[self.new[bit]] = (value >> bit) & 1 == 1;
            bits[self.address[bit]] = (address >> bit) & 1 == 1;
        }
        let read = self.read.witness(address, 0, old, true);
        bits[self.read_offset..self.read_offset + read.len()].copy_from_slice(&read);
        let write = self.write.witness(address, 0, value, true);
        bits[self.write_offset..self.write_offset + write.len()].copy_from_slice(&write);
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
            let bits = row.witness(old, operand, 0x100);
            assert!(row.relation.check(&bits), "{old}+{operand}");
            let value = row.new.iter().enumerate().fold(0u64, |value, (bit, var)| {
                value | (u64::from(bits[*var]) << bit)
            });
            assert_eq!(value, old.wrapping_add(operand) & 0xff);
        }
    }
}
