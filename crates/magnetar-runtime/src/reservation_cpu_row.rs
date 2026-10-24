//! CPU row combined with a row-local reservation transition.

use magnetar_constraint::VarId;
use magnetar_proof::dual_field::{BitRelation, BitRow};

use crate::reservation_row::ReservationRow;
use crate::simd_f2::{GatedCpuRow, GatedCpuRowInput};

#[derive(Clone, Copy, Debug)]
pub struct ReservationCpuInput {
    pub cpu: GatedCpuRowInput,
    pub addr: u64,
    pub res_addr: u64,
    pub pre_valid: bool,
    pub is_lr: bool,
    pub is_sc: bool,
    pub is_invalidate: bool,
}

#[derive(Clone, Debug)]
pub struct ReservationCpuRow {
    pub width: usize,
    pub cpu: GatedCpuRow,
    pub reservation: ReservationRow,
    pub reservation_offset: usize,
    pub relation: BitRelation,
}

impl ReservationCpuRow {
    pub fn packed_system(&self) -> magnetar_constraint::ConstraintSystem {
        self.relation.to_system()
    }

    pub fn new(width: usize) -> Self {
        let cpu = GatedCpuRow::new(width);
        let reservation = ReservationRow::new(width);
        let reservation_offset = cpu.relation.num_vars;
        let mut relation = BitRelation::new(cpu.relation.num_vars + reservation.relation.num_vars);
        for row in &cpu.relation.rows {
            relation.add(row.clone());
        }
        for row in &reservation.relation.rows {
            let shift = |vars: &[VarId]| {
                vars.iter()
                    .map(|v| *v + reservation_offset)
                    .collect::<Vec<_>>()
            };
            relation.add(BitRow::new(shift(&row.a), shift(&row.b), shift(&row.c)));
        }
        Self {
            width,
            cpu,
            reservation,
            reservation_offset,
            relation,
        }
    }

    pub fn witness(&self, pc: u64, input: ReservationCpuInput) -> Vec<bool> {
        let mut bits = crate::simd_dual::gated_batch_bits(
            &self.cpu,
            self.cpu.relation.num_vars,
            &[(pc, input.cpu)],
        );
        let reservation = self.reservation.witness(
            input.addr,
            input.res_addr,
            input.pre_valid,
            input.is_lr,
            input.is_sc,
            input.is_invalidate,
        );
        bits.extend(reservation);
        bits
    }

    pub fn relation_check(&self, bits: &[bool]) -> bool {
        self.relation.check(bits)
    }
}

pub fn prove_reservation_cpu_batch(
    width: usize,
    rows: &[(u64, ReservationCpuInput)],
) -> Result<
    magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
    crate::RuntimeError,
> {
    use magnetar_proof::{prove_shared_simd_spartan, witness_vector};
    if rows.is_empty() || !rows.len().is_power_of_two() {
        return Err(crate::RuntimeError::Proof(
            "reservation CPU batch must be a nonzero power of two".into(),
        ));
    }
    let row = ReservationCpuRow::new(width);
    let system = row.packed_system();
    let mut witnesses = Vec::new();
    for (pc, input) in rows {
        let bits = row.witness(*pc, *input);
        witnesses.push(row.relation.to_witness(&bits));
    }
    let _ = witness_vector(&system, &witnesses[0])
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))?;
    let pcs = magnetar_pcs::P3BinaryPcs::new(100);
    prove_shared_simd_spartan(&system, &witnesses, &pcs)
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))
}

pub fn verify_reservation_cpu_batch(
    width: usize,
    rows: &[(u64, ReservationCpuInput)],
    proof: &magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
) -> Result<(), crate::RuntimeError> {
    use magnetar_proof::{verify_shared_simd_spartan_with_witnesses, witness_vector};
    let row = ReservationCpuRow::new(width);
    let system = row.packed_system();
    let mut witnesses = Vec::new();
    for (pc, input) in rows {
        let bits = row.witness(*pc, *input);
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
    use crate::simd_f2::GatedAluOp;

    #[test]
    fn reservation_cpu_row_checks_both_relations() {
        let row = ReservationCpuRow::new(8);
        let input = ReservationCpuInput {
            cpu: GatedCpuRowInput::Alu {
                left: 5,
                right: 3,
                op: GatedAluOp::Add,
            },
            addr: 5,
            res_addr: 0,
            pre_valid: false,
            is_lr: true,
            is_sc: false,
            is_invalidate: false,
        };
        let bits = row.witness(0x1000, input);
        assert!(row.relation_check(&bits));
        let mut bad = input;
        bad.res_addr = 6;
        bad.pre_valid = true;
        bad.is_lr = false;
        bad.is_sc = true;
        bad.addr = 5;
        bad.res_addr = 5;
        let bits = row.witness(0x1000, bad);
        assert!(row.relation_check(&bits));
        let rows = [
            (0x1000u64, input),
            (0x1004, bad),
            (0x1008, input),
            (0x100c, bad),
        ];
        let proof = prove_reservation_cpu_batch(8, &rows).unwrap();
        verify_reservation_cpu_batch(8, &rows, &proof).unwrap();
    }
}
