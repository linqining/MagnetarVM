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
    pub next_pre_valid: bool,
    pub next_pre_addr: u64,
    pub value: u64,
    pub has_value: bool,
}

#[derive(Clone, Debug)]
pub struct ReservationCpuRow {
    pub width: usize,
    pub cpu: GatedCpuRow,
    pub reservation: ReservationRow,
    pub reservation_offset: usize,
    pub next_pre_valid: VarId,
    pub next_pre_addr: Vec<VarId>,
    pub value: Vec<VarId>,
    pub has_value: VarId,
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
        let mut cursor = relation.num_vars;
        let next_pre_addr = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let next_pre_valid = cursor;
        cursor += 1;
        let value = (cursor..cursor + width).collect::<Vec<_>>();
        cursor += width;
        let has_value = cursor;
        relation.num_vars = cursor + 1;
        let one = reservation_offset + reservation.one;
        let post_valid = reservation_offset + reservation.post_valid;
        for bit in 0..width {
            relation.add(BitRow::new(
                vec![reservation_offset + reservation.addr[bit]],
                vec![cpu.alu.one],
                vec![cpu.memory_offset + cpu.memory.adder.out[bit]],
            ));
        }
        relation.add(BitRow::new(
            vec![post_valid, next_pre_valid],
            vec![one],
            Vec::new(),
        ));
        for (bit, next) in next_pre_addr.iter().enumerate() {
            let post = reservation_offset + reservation.post_addr[bit];
            relation.add(BitRow::new(vec![post, *next], vec![post_valid], Vec::new()));
            relation.add(BitRow::new(
                vec![*next],
                vec![one, next_pre_valid],
                Vec::new(),
            ));
        }
        relation.add(BitRow::new(
            vec![has_value],
            vec![has_value, one],
            Vec::new(),
        ));
        for value_bit in &value {
            relation.add(BitRow::new(
                vec![*value_bit],
                vec![*value_bit, one],
                Vec::new(),
            ));
        }
        for (bit, value_bit) in value.iter().enumerate() {
            relation.add(BitRow::new(
                vec![*value_bit, cpu.memory_offset + cpu.memory.data_in[bit]],
                vec![has_value],
                Vec::new(),
            ));
        }
        Self {
            width,
            cpu,
            reservation,
            reservation_offset,
            next_pre_valid,
            next_pre_addr,
            value,
            has_value,
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
        bits.resize(self.relation.num_vars, false);
        bits[self.next_pre_valid] = input.next_pre_valid;
        for (bit, var) in self.next_pre_addr.iter().enumerate() {
            bits[*var] = (input.next_pre_addr >> bit) & 1 == 1;
        }
        bits[self.has_value] = input.has_value;
        for (bit, var) in self.value.iter().enumerate() {
            bits[*var] = (input.value >> bit) & 1 == 1;
        }
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

pub fn reservation_cpu_rows_from_trace(
    trace: &magnetar_spec::Trace,
    width: usize,
) -> Result<Vec<(u64, ReservationCpuInput)>, crate::RuntimeError> {
    let rows = crate::simd_full::gated_rows_from_trace(trace, width)?;
    let mut result = Vec::with_capacity(rows.len());
    for (index, (pc, cpu)) in rows.iter().enumerate() {
        let row = trace
            .rows
            .get(index)
            .ok_or_else(|| crate::RuntimeError::Proof("reservation trace row".into()))?;
        let next_pre = trace
            .rows
            .get(index + 1)
            .and_then(|next| next.reservation_before);
        result.push((
            *pc,
            ReservationCpuInput {
                cpu: *cpu,
                addr: row.mem.map(|mem| mem.addr).unwrap_or(0),
                res_addr: row.reservation_before.unwrap_or(0),
                pre_valid: row.reservation_before.is_some(),
                is_lr: matches!(
                    row.instruction.op,
                    magnetar_spec::Op::LrW | magnetar_spec::Op::LrD
                ),
                is_sc: matches!(
                    row.instruction.op,
                    magnetar_spec::Op::ScW | magnetar_spec::Op::ScD
                ),
                is_invalidate: matches!(
                    row.instruction.op,
                    magnetar_spec::Op::Sb
                        | magnetar_spec::Op::Sh
                        | magnetar_spec::Op::Sw
                        | magnetar_spec::Op::Sd
                ),
                next_pre_valid: next_pre.is_some(),
                next_pre_addr: next_pre.unwrap_or(0),
                value: if matches!(
                    row.instruction.op,
                    magnetar_spec::Op::LrW | magnetar_spec::Op::LrD
                ) {
                    row.rd_val
                } else if matches!(
                    row.instruction.op,
                    magnetar_spec::Op::ScW | magnetar_spec::Op::ScD
                ) {
                    row.mem.map(|mem| mem.value).unwrap_or(0)
                } else {
                    0
                },
                has_value: matches!(
                    row.instruction.op,
                    magnetar_spec::Op::LrW
                        | magnetar_spec::Op::LrD
                        | magnetar_spec::Op::ScW
                        | magnetar_spec::Op::ScD
                ),
            },
        ));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservation_cpu_row_checks_both_relations() {
        let row = ReservationCpuRow::new(8);
        let input = ReservationCpuInput {
            cpu: GatedCpuRowInput::Memory {
                rs1: 5,
                imm: 0,
                value: 5,
                is_mem: true,
            },
            addr: 5,
            res_addr: 0,
            pre_valid: false,
            is_lr: true,
            is_sc: false,
            is_invalidate: false,
            next_pre_valid: true,
            next_pre_addr: 5,
            value: 5,
            has_value: true,
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
        bad.next_pre_valid = false;
        bad.next_pre_addr = 0;
        bad.value = 7;
        bad.cpu = GatedCpuRowInput::Memory {
            rs1: 5,
            imm: 0,
            value: 7,
            is_mem: true,
        };
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
        let mut tampered = rows;
        tampered[1].1.pre_valid = false;
        assert!(verify_reservation_cpu_batch(8, &tampered, &proof).is_err());

        use magnetar_executor::execute;
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Lui,
                    rd: 4,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x1000_0000,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::LrD,
                    rd: 5,
                    rs1: 4,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::ScD,
                    rd: 6,
                    rs1: 4,
                    rs2: 5,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Add,
                    rd: 7,
                    rs1: 0,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(
            &program,
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x100,
                stack_top: 0x1000_0080,
                max_cycles: 100,
            },
        )
        .unwrap();
        let rows = reservation_cpu_rows_from_trace(&trace, 8).unwrap();
        assert_eq!(rows.len(), 4);
        let proof = prove_reservation_cpu_batch(8, &rows).unwrap();
        verify_reservation_cpu_batch(8, &rows, &proof).unwrap();
    }
}
