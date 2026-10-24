//! Isolated AMOMIN/AMOMAX/AMOMINU/AMOMAXU rows.

use magnetar_constraint::VarId;
use magnetar_proof::dual_field::{BitRelation, BitRow};

use crate::simd_f2::{GatedAluOp, GatedAluRow, GatedMemoryRow};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmoMinMaxKind {
    Min,
    Max,
    Minu,
    Maxu,
}

impl AmoMinMaxKind {
    fn is_max(self) -> bool {
        matches!(self, Self::Max | Self::Maxu)
    }

    fn is_signed(self) -> bool {
        matches!(self, Self::Min | Self::Max)
    }
}

#[derive(Clone, Debug)]
pub struct AmoMinMaxRow {
    pub width: usize,
    pub kind: AmoMinMaxKind,
    pub old: Vec<VarId>,
    pub operand: Vec<VarId>,
    pub new: Vec<VarId>,
    pub cmp: GatedAluRow,
    pub read: GatedMemoryRow,
    pub write: GatedMemoryRow,
    pub read_offset: usize,
    pub write_offset: usize,
    pub address: Vec<VarId>,
    pub zero: VarId,
    pub one: VarId,
    pub relation: BitRelation,
}

impl AmoMinMaxRow {
    pub fn packed_system(&self) -> magnetar_constraint::ConstraintSystem {
        self.relation.to_system()
    }

    pub fn new(width: usize, kind: AmoMinMaxKind) -> Self {
        let cmp = GatedAluRow::new(width);
        let mut relation = BitRelation::new(cmp.relation.num_vars);
        for row in &cmp.relation.rows {
            relation.add(row.clone());
        }
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
        relation.add(BitRow::new(vec![zero], vec![one], Vec::new()));
        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        for var in old.iter().chain(&operand).chain(&new).chain(&address) {
            relation.add(BitRow::new(vec![*var], vec![*var, one], Vec::new()));
        }
        for bit in 0..width {
            relation.add(BitRow::new(vec![cmp.a[bit]], vec![one], vec![old[bit]]));
            relation.add(BitRow::new(vec![cmp.b[bit]], vec![one], vec![operand[bit]]));
            if kind.is_max() {
                relation.add(BitRow::new(
                    vec![cmp.lt],
                    vec![old[bit], operand[bit]],
                    vec![new[bit], old[bit]],
                ));
            } else {
                relation.add(BitRow::new(
                    vec![cmp.lt],
                    vec![old[bit], operand[bit]],
                    vec![new[bit], operand[bit]],
                ));
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
            cmp,
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
        let op = if self.kind.is_signed() {
            GatedAluOp::Slt
        } else {
            GatedAluOp::Sltu
        };
        let mut bits = self.cmp.witness(old, operand, op);
        bits.resize(self.relation.num_vars, false);
        bits[self.zero] = false;
        bits[self.one] = true;
        let mask = if self.width == 64 {
            u64::MAX
        } else {
            (1u64 << self.width) - 1
        };
        let value = if self.kind.is_signed() {
            let a = if self.width == 64 {
                old as i64
            } else {
                (old as u8 as i8) as i64
            };
            let b = if self.width == 64 {
                operand as i64
            } else {
                (operand as u8 as i8) as i64
            };
            match self.kind {
                AmoMinMaxKind::Min => {
                    if a < b {
                        old
                    } else {
                        operand
                    }
                }
                AmoMinMaxKind::Max => {
                    if a < b {
                        operand
                    } else {
                        old
                    }
                }
                _ => unreachable!(),
            }
        } else {
            match self.kind {
                AmoMinMaxKind::Minu => old.min(operand),
                AmoMinMaxKind::Maxu => old.max(operand),
                _ => unreachable!(),
            }
        } & mask;
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

pub fn prove_amo_minmax_batch(
    width: usize,
    kind: AmoMinMaxKind,
    rows: &[(u64, u64, u64)],
) -> Result<
    magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
    crate::RuntimeError,
> {
    use magnetar_proof::{prove_shared_simd_spartan, witness_vector};
    if rows.is_empty() || !rows.len().is_power_of_two() {
        return Err(crate::RuntimeError::Proof(
            "AMO batch must be a nonzero power of two".into(),
        ));
    }
    let row = AmoMinMaxRow::new(width, kind);
    let system = row.packed_system();
    let mut witnesses = Vec::new();
    for (old, operand, address) in rows {
        let bits = row.witness(*old, *operand, *address);
        witnesses.push(row.relation.to_witness(&bits));
    }
    let _ = witness_vector(&system, &witnesses[0])
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))?;
    let pcs = magnetar_pcs::P3BinaryPcs::new(100);
    prove_shared_simd_spartan(&system, &witnesses, &pcs)
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))
}

pub fn verify_amo_minmax_batch(
    width: usize,
    kind: AmoMinMaxKind,
    instances: usize,
    proof: &magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
) -> Result<(), crate::RuntimeError> {
    use magnetar_proof::verify_shared_simd_spartan;
    let row = AmoMinMaxRow::new(width, kind);
    let system = row.packed_system();
    let pcs = magnetar_pcs::P3BinaryPcs::new(100);
    verify_shared_simd_spartan(&system, instances, proof, &pcs)
        .map_err(|error| crate::RuntimeError::Proof(error.to_string()))
}

pub fn verify_amo_minmax_batch_bound(
    width: usize,
    kind: AmoMinMaxKind,
    rows: &[(u64, u64, u64)],
    proof: &magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
) -> Result<(), crate::RuntimeError> {
    use magnetar_proof::{verify_shared_simd_spartan_with_witnesses, witness_vector};
    let row = AmoMinMaxRow::new(width, kind);
    let system = row.packed_system();
    let mut witnesses = Vec::new();
    for (old, operand, address) in rows {
        let bits = row.witness(*old, *operand, *address);
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
    fn amo_minmax_rows_compute() {
        for (kind, expected) in [
            (AmoMinMaxKind::Min, 0xfbu64),
            (AmoMinMaxKind::Max, 3),
            (AmoMinMaxKind::Minu, 3),
            (AmoMinMaxKind::Maxu, 0xfb),
        ] {
            let row = AmoMinMaxRow::new(8, kind);
            let bits = row.witness(0xfb, 3, 0x100);
            assert!(row.relation.check(&bits), "{kind:?}");
            let value = row
                .new
                .iter()
                .enumerate()
                .fold(0u64, |v, (bit, var)| v | (u64::from(bits[*var]) << bit));
            assert_eq!(value, expected, "{kind:?}");
            let rows = [
                (0xfbu64, 3u64, 0x100u64),
                (5, 6, 0x108),
                (7, 3, 0x110),
                (1, 2, 0x118),
            ];
            let proof = prove_amo_minmax_batch(8, kind, &rows).unwrap();
            verify_amo_minmax_batch(8, kind, rows.len(), &proof).unwrap();
        }
    }
}
