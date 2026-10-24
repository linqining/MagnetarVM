//! Isolated store-conditional (SC) row prototype.
//!
//! Proves: read `old` at `addr`; if `success`, write `operand`; `rd = !success`.
//! Cross-row reservation validity is not yet chained.

use magnetar_constraint::VarId;
use magnetar_proof::dual_field::{BitRelation, BitRow};

use crate::simd_f2::GatedMemoryRow;

#[derive(Clone, Debug)]
pub struct ScRow {
    pub width: usize,
    pub old: Vec<VarId>,
    pub operand: Vec<VarId>,
    pub rd: Vec<VarId>,
    pub success: VarId,
    pub read: GatedMemoryRow,
    pub write: GatedMemoryRow,
    pub read_offset: usize,
    pub write_offset: usize,
    pub address: Vec<VarId>,
    pub zero: VarId,
    pub one: VarId,
    pub relation: BitRelation,
}

impl ScRow {
    pub fn packed_system(&self) -> magnetar_constraint::ConstraintSystem {
        self.relation.to_system()
    }

    pub fn new(width: usize) -> Self {
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
        let address = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let rd = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let success = cursor;
        let zero = cursor + 1;
        let one = cursor + 2;
        relation.num_vars = cursor + 3;
        relation.add(BitRow::new(vec![zero], vec![one], Vec::new()));
        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        relation.add(BitRow::new(vec![success], vec![success, one], Vec::new()));
        for var in old.iter().chain(&operand).chain(&address).chain(&rd) {
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
            relation.add(BitRow::new(
                vec![write.adder.a[bit] + write_offset],
                vec![one],
                vec![address[bit]],
            ));
            relation.add(BitRow::new(
                vec![write.adder.b[bit] + write_offset],
                vec![one],
                vec![zero],
            ));
            relation.add(BitRow::new(
                vec![write.adder.gate + write_offset],
                vec![one],
                vec![success],
            ));
            relation.add(BitRow::new(
                vec![write.data_in[bit] + write_offset],
                vec![one],
                vec![operand[bit]],
            ));
        }
        relation.add(BitRow::new(vec![rd[0], success], vec![one], vec![one]));
        for var in &rd[1..] {
            relation.add(BitRow::new(vec![*var], vec![one], Vec::new()));
        }
        Self {
            width,
            old,
            operand,
            rd,
            success,
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

    pub fn witness(&self, old: u64, operand: u64, address: u64, success: bool) -> Vec<bool> {
        let mut bits = self.read.witness(address, 0, old, true);
        bits.resize(self.relation.num_vars, false);
        bits[self.zero] = false;
        bits[self.one] = true;
        bits[self.success] = success;
        let rd = if success { 0 } else { 1 };
        for bit in 0..self.width {
            bits[self.old[bit]] = (old >> bit) & 1 == 1;
            bits[self.operand[bit]] = (operand >> bit) & 1 == 1;
            bits[self.address[bit]] = (address >> bit) & 1 == 1;
            bits[self.rd[bit]] = (rd >> bit) & 1 == 1;
        }
        let write = self.write.witness(address, 0, operand, success);
        bits[self.write_offset..self.write_offset + write.len()].copy_from_slice(&write);
        bits
    }
}

pub fn prove_sc_batch(
    width: usize,
    rows: &[(u64, u64, u64, bool)],
) -> Result<
    magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
    crate::RuntimeError,
> {
    use magnetar_proof::{prove_shared_simd_spartan, witness_vector};
    if rows.is_empty() || !rows.len().is_power_of_two() {
        return Err(crate::RuntimeError::Proof(
            "SC batch must be a nonzero power of two".into(),
        ));
    }
    let row = ScRow::new(width);
    let system = row.packed_system();
    let mut witnesses = Vec::new();
    for (old, operand, address, success) in rows {
        let bits = row.witness(*old, *operand, *address, *success);
        witnesses.push(row.relation.to_witness(&bits));
    }
    let _ = witness_vector(&system, &witnesses[0])
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))?;
    let pcs = magnetar_pcs::P3BinaryPcs::new(100);
    prove_shared_simd_spartan(&system, &witnesses, &pcs)
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))
}

pub fn verify_sc_batch(
    width: usize,
    instances: usize,
    proof: &magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
) -> Result<(), crate::RuntimeError> {
    use magnetar_proof::verify_shared_simd_spartan;
    let row = ScRow::new(width);
    let system = row.packed_system();
    let pcs = magnetar_pcs::P3BinaryPcs::new(100);
    verify_shared_simd_spartan(&system, instances, proof, &pcs)
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))
}

pub fn verify_sc_batch_bound(
    width: usize,
    rows: &[(u64, u64, u64, bool)],
    proof: &magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
) -> Result<(), crate::RuntimeError> {
    use magnetar_proof::{verify_shared_simd_spartan_with_witnesses, witness_vector};
    let row = ScRow::new(width);
    let system = row.packed_system();
    let mut witnesses = Vec::new();
    for (old, operand, address, success) in rows {
        let bits = row.witness(*old, *operand, *address, *success);
        witnesses.push(row.relation.to_witness(&bits));
    }
    let _ = witness_vector(&system, &witnesses[0])
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))?;
    let pcs = magnetar_pcs::P3BinaryPcs::new(100);
    verify_shared_simd_spartan_with_witnesses(&system, &witnesses, proof, &pcs)
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sc_row_writes_only_on_success() {
        let row = ScRow::new(8);
        for success in [true, false] {
            let bits = row.witness(5, 7, 0x100, success);
            assert!(row.relation.check(&bits), "success={success}");
            let rd = row
                .rd
                .iter()
                .enumerate()
                .fold(0u64, |v, (bit, var)| v | (u64::from(bits[*var]) << bit));
            assert_eq!(rd, u64::from(!success));
        }
        let rows = [
            (5u64, 7u64, 0x100u64, true),
            (5, 9, 0x108, false),
            (1, 2, 0x110, true),
            (3, 4, 0x118, false),
        ];
        let proof = prove_sc_batch(8, &rows).unwrap();
        verify_sc_batch(8, rows.len(), &proof).unwrap();
    }
}
