//! Shared commitment layout for the linear Twist proof.
//!
//! All tables are flattened to `K * T` columns so a single PCS batch can bind
//! the address, value, increment, read/write and endpoint tables. Cycle-only
//! tables are broadcast across cells; cell-only tables are broadcast across
//! cycles. This is the commitment sharing step of the proof-size redesign.

use magnetar_constraint::F2_128;
use magnetar_memory::BinaryTwistWitness;
use magnetar_pcs::{P3BatchPoint, P3BinaryPcs};
use magnetar_proof::ProofError;

use crate::linear_twist::{witness_shape, LinearTwistShape};

/// One flattened column per shared table.
#[derive(Clone, Debug)]
pub struct SharedTwistTables {
    pub shape: LinearTwistShape,
    pub columns: Vec<Vec<F2_128>>,
}

impl SharedTwistTables {
    pub fn build(witness: &BinaryTwistWitness) -> Result<Self, ProofError> {
        let shape = witness_shape(witness);
        let cells = shape.cells();
        let cycles = shape.cycles;
        let (val, wa, inc) = crate::linear_twist::build_val_tables(witness);
        let mut columns = vec![vec![F2_128::from(0u64); cells * cycles]; 6];
        let mut read_bits = vec![vec![F2_128::from(0u64); cells * cycles]; shape.address_bits];
        let mut write_bits = vec![vec![F2_128::from(0u64); cells * cycles]; shape.address_bits];
        let mut read_valid = vec![F2_128::from(0u64); cells * cycles];
        let mut write_valid = vec![F2_128::from(0u64); cells * cycles];
        let mut initial = vec![F2_128::from(0u64); cells * cycles];
        let mut final_value = vec![F2_128::from(0u64); cells * cycles];
        for (cycle, &increment) in inc.iter().enumerate().take(witness.cycles) {
            let read_row = &witness.read_address[cycle];
            let write_row = &witness.write_address[cycle];
            let read_cell = read_row.iter().position(|value| value.value() == 1);
            let write_cell = write_row.iter().position(|value| value.value() == 1);
            for (cell, read_bit) in read_row.iter().enumerate() {
                let index = cell * cycles + cycle;
                columns[0][index] = *read_bit;
                columns[1][index] = wa[index];
                columns[2][index] = val[index];
                columns[3][index] = increment;
                columns[4][index] = witness.read_value[cycle];
                columns[5][index] = witness.write_value[cycle];
                if let Some(cell_index) = read_cell {
                    read_valid[index] = F2_128::from(1u64);
                    for (bit, column) in read_bits.iter_mut().enumerate() {
                        column[index] = F2_128::from(((cell_index >> bit) & 1) as u64);
                    }
                }
                if let Some(cell_index) = write_cell {
                    write_valid[index] = F2_128::from(1u64);
                    for (bit, column) in write_bits.iter_mut().enumerate() {
                        column[index] = F2_128::from(((cell_index >> bit) & 1) as u64);
                    }
                }
                initial[index] = witness
                    .initial
                    .get(cell)
                    .copied()
                    .unwrap_or(F2_128::from(0u64));
                final_value[index] = witness
                    .final_value
                    .get(cell)
                    .copied()
                    .unwrap_or(F2_128::from(0u64));
            }
        }
        columns.extend(read_bits);
        columns.extend(write_bits);
        columns.push(read_valid);
        columns.push(write_valid);
        columns.push(initial);
        columns.push(final_value);
        Ok(Self { shape, columns })
    }

    pub fn commit(&self) -> Result<magnetar_pcs::P3BatchCommitment, ProofError> {
        P3BinaryPcs::new(100)
            .commit_batch(&self.columns)
            .map_err(|error| ProofError::Pcs(error.to_string()))
    }

    pub fn open(
        &self,
        points: &[P3BatchPoint],
    ) -> Result<magnetar_pcs::P3BatchOpening, ProofError> {
        P3BinaryPcs::new(100)
            .open_batch(&self.columns, points)
            .map_err(|error| ProofError::Pcs(error.to_string()))
    }

    pub fn verify(
        &self,
        opening: &magnetar_pcs::P3BatchOpening,
        points: &[P3BatchPoint],
        values: &[Vec<F2_128>],
    ) -> Result<bool, ProofError> {
        P3BinaryPcs::new(100)
            .verify_batch(opening, points, values)
            .map_err(|error| ProofError::Pcs(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    #[test]
    fn shared_tables_open() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 7,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Lui,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x1000_0000,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Sd,
                    rd: 0,
                    rs1: 2,
                    rs2: 1,
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
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 100,
            },
        )
        .unwrap();
        let witness = BinaryTwistWitness::from_trace(&trace).unwrap();
        let tables = SharedTwistTables::build(&witness).unwrap();
        let _ = tables.commit().unwrap();
        let height = tables.shape.cells() * tables.shape.cycles;
        let point = (0..height.trailing_zeros() as usize)
            .map(|index| F2_128::from((index * 3 + 2) as u64))
            .collect::<Vec<_>>();
        let points = vec![P3BatchPoint {
            point: point.clone(),
            columns: (0..tables.columns.len()).collect(),
        }];
        let values = vec![tables
            .columns
            .iter()
            .map(|column| crate::linear_twist::eval_mle(column, &point))
            .collect::<Vec<_>>()];
        let opening = tables.open(&points).unwrap();
        assert!(tables.verify(&opening, &points, &values).unwrap());
    }
}


#[cfg(test)]
mod multi_point_tests {
    use super::*;
    use magnetar_pcs::{P3BatchPoint, P3BinaryPcs};

    #[test]
    fn multi_point_batch_opens() {
        let cells = 8usize;
        let cycles = 1024usize;
        let height = cells * cycles;
        let columns = (0..3)
            .map(|column| {
                (0..height)
                    .map(|index| F2_128::from(((index + column) % 5) as u64))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let pcs = P3BinaryPcs::new(100);
        let _commitment = pcs.commit_batch(&columns).unwrap();
        let point = |salt: usize| {
            (0..height.trailing_zeros() as usize)
                .map(|index| F2_128::from((index * 3 + salt) as u64))
                .collect::<Vec<_>>()
        };
        let points = vec![
            P3BatchPoint {
                point: point(1),
                columns: vec![0, 1, 2],
            },
            P3BatchPoint {
                point: point(2),
                columns: vec![0, 2],
            },
        ];
        let values = points
            .iter()
            .map(|point| {
                point
                    .columns
                    .iter()
                    .map(|column| crate::linear_twist::eval_mle(&columns[*column], &point.point))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let opening = pcs.open_batch(&columns, &points).unwrap();
        assert!(pcs.verify_batch(&opening, &points, &values).unwrap());
    }
}
