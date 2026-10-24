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
    pub fn packed_system(&self) -> magnetar_constraint::ConstraintSystem {
        self.relation.to_system()
    }

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

pub fn prove_lr_batch(
    width: usize,
    rows: &[(u64, u64)],
) -> Result<
    magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
    crate::RuntimeError,
> {
    use magnetar_proof::{prove_shared_simd_spartan, witness_vector};
    if rows.is_empty() || !rows.len().is_power_of_two() {
        return Err(crate::RuntimeError::Proof(
            "LR batch must be a nonzero power of two".into(),
        ));
    }
    let row = LrRow::new(width);
    let system = row.packed_system();
    let mut witnesses = Vec::new();
    for (old, address) in rows {
        let bits = row.witness(*old, *address);
        witnesses.push(row.relation.to_witness(&bits));
    }
    let _ = witness_vector(&system, &witnesses[0])
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))?;
    let pcs = magnetar_pcs::P3BinaryPcs::new(100);
    prove_shared_simd_spartan(&system, &witnesses, &pcs)
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))
}

pub fn verify_lr_batch(
    width: usize,
    instances: usize,
    proof: &magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
) -> Result<(), crate::RuntimeError> {
    use magnetar_proof::verify_shared_simd_spartan;
    let row = LrRow::new(width);
    let system = row.packed_system();
    let pcs = magnetar_pcs::P3BinaryPcs::new(100);
    verify_shared_simd_spartan(&system, instances, proof, &pcs)
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))
}

pub fn verify_lr_batch_bound(
    width: usize,
    rows: &[(u64, u64)],
    proof: &magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
) -> Result<(), crate::RuntimeError> {
    use magnetar_proof::{verify_shared_simd_spartan_with_witnesses, witness_vector};
    let row = LrRow::new(width);
    let system = row.packed_system();
    let mut witnesses = Vec::new();
    for (old, address) in rows {
        let bits = row.witness(*old, *address);
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
        let rows = [(42u64, 0x100u64), (1, 0x108), (2, 0x110), (3, 0x118)];
        let proof = prove_lr_batch(8, &rows).unwrap();
        verify_lr_batch(8, rows.len(), &proof).unwrap();
    }
}
