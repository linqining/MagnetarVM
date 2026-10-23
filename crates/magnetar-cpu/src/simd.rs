//! Uniform (SIMD-ready) CPU row schema.
//!
//! The legacy runtime builds a different constraint system per row
//! (`simple_alu`, specialized load/store, ...). SIMD needs one fixed row
//! schema: every cycle instantiates the same matrix and selects its operation
//! through witness selectors. This module is the first slice of that schema
//! (ALU + PC); load/store and the dual F2 / F2^128 split build on it.

use magnetar_constraint::{ConstraintSystem, Witness};

use crate::{uniform_step_relation, CpuVarGroup, StepOp, UniformStepLayout};

/// Fixed-column CPU row. `relation` is identical for every instance; only the
/// witness (selectors and operands) changes per cycle.
#[derive(Clone, Debug)]
pub struct UniformCpuRowLayout {
    pub width: usize,
    pub step: UniformStepLayout,
    pub num_vars: usize,
    pub system: ConstraintSystem,
}

impl UniformCpuRowLayout {
    pub fn witness(
        &self,
        op: StepOp,
        pc: u64,
        rs1: u64,
        rs2: u64,
        imm: u64,
    ) -> UniformCpuRowWitness {
        UniformCpuRowWitness {
            op,
            pc,
            rs1,
            rs2,
            imm,
            witness: self.step.witness(op, pc, rs1, rs2, imm),
        }
    }

    pub fn var_groups(&self) -> Vec<CpuVarGroup> {
        self.step.var_groups()
    }
}

#[derive(Clone, Debug)]
pub struct UniformCpuRowWitness {
    pub op: StepOp,
    pub pc: u64,
    pub rs1: u64,
    pub rs2: u64,
    pub imm: u64,
    pub witness: Witness,
}

/// Build the one row relation/layout shared by all ALU cycles.
pub fn uniform_cpu_row_layout(width: usize) -> (ConstraintSystem, UniformCpuRowLayout) {
    let (system, step) = uniform_step_relation(width);
    let num_vars = system.num_vars;
    let row_system = system.clone();
    (
        system,
        UniformCpuRowLayout {
            width,
            step,
            num_vars,
            system: row_system,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alu_rows_share_one_fixed_schema() {
        let (system, layout) = uniform_cpu_row_layout(8);
        let rows = [
            layout.witness(StepOp::Add, 0x1000, 5, 7, 0),
            layout.witness(StepOp::Xor, 0x1004, 5, 7, 0),
            layout.witness(StepOp::Addi, 0x1008, 5, 0, 3),
        ];
        for row in &rows {
            assert_eq!(row.witness.values().len(), layout.num_vars);
            system
                .check(&row.witness)
                .expect("uniform row satisfies relation");
        }
        // Every row has the same column groups; only selector/operand values
        // differ.
        let groups = layout.var_groups();
        assert!(groups
            .iter()
            .any(|group| group.kind == crate::CpuVarKind::Rs1));
        assert!(groups
            .iter()
            .any(|group| group.kind == crate::CpuVarKind::Rd));
    }
}

/// Batch layout for q independent instances of the same uniform row relation.
/// The witness is `cycle-major`: row `c` occupies
/// `[c*num_vars, (c+1)*num_vars)`.
#[derive(Clone, Debug)]
pub struct UniformCpuBatchLayout {
    pub row: UniformCpuRowLayout,
    pub cycles: usize,
}

#[derive(Clone, Debug)]
pub struct UniformCpuBatchWitness {
    pub values: Vec<magnetar_constraint::F2_128>,
}

impl UniformCpuBatchLayout {
    pub fn new(row: UniformCpuRowLayout, cycles: usize) -> Self {
        Self { row, cycles }
    }

    pub fn witness_len(&self) -> usize {
        self.cycles * self.row.num_vars
    }

    pub fn row_offset(&self, cycle: usize) -> Option<usize> {
        (cycle < self.cycles).then_some(cycle * self.row.num_vars)
    }

    pub fn batch_witness(
        &self,
        rows: &[UniformCpuRowWitness],
    ) -> Result<UniformCpuBatchWitness, SimdError> {
        if rows.len() != self.cycles {
            return Err(SimdError::CycleCount {
                expected: self.cycles,
                actual: rows.len(),
            });
        }
        let mut values = Vec::with_capacity(self.witness_len());
        for (cycle, row) in rows.iter().enumerate() {
            if row.witness.values().len() != self.row.num_vars {
                return Err(SimdError::RowWidth {
                    cycle,
                    expected: self.row.num_vars,
                    actual: row.witness.values().len(),
                });
            }
            values.extend_from_slice(row.witness.values());
        }
        Ok(UniformCpuBatchWitness { values })
    }

    pub fn row_values<'a>(
        &self,
        witness: &'a UniformCpuBatchWitness,
        cycle: usize,
    ) -> Result<&'a [magnetar_constraint::F2_128], SimdError> {
        let offset = self
            .row_offset(cycle)
            .ok_or(SimdError::CycleOutOfRange(cycle))?;
        Ok(&witness.values[offset..offset + self.row.num_vars])
    }

    /// Build a block-diagonal batch system for the instances plus PC-chain
    /// equality constraints. This is the batched baseline; a shared-matrix
    /// SIMD encoding replaces the block-diagonal matrices later.
    pub fn batch_system(
        &self,
        rows: &[UniformCpuRowWitness],
    ) -> Result<(ConstraintSystem, magnetar_constraint::Witness), SimdError> {
        if rows.len() != self.cycles {
            return Err(SimdError::CycleCount {
                expected: self.cycles,
                actual: rows.len(),
            });
        }
        let mut system = ConstraintSystem::new(0);
        let mut values = Vec::new();
        let mut offsets = Vec::with_capacity(rows.len());
        for (cycle, row) in rows.iter().enumerate() {
            if row.witness.values().len() != self.row.num_vars {
                return Err(SimdError::RowWidth {
                    cycle,
                    expected: self.row.num_vars,
                    actual: row.witness.values().len(),
                });
            }
            let offset = system.merge(self.row.system.clone());
            offsets.push(offset);
            values.extend_from_slice(row.witness.values());
        }
        let groups = self.row.var_groups();
        let pc = groups
            .iter()
            .find(|group| group.kind == crate::CpuVarKind::Pc)
            .ok_or(SimdError::MissingPcGroup)?;
        let next_pc = groups
            .iter()
            .find(|group| group.kind == crate::CpuVarKind::NextPc)
            .ok_or(SimdError::MissingPcGroup)?;
        let one = magnetar_constraint::Expr::constant(1u64);
        for pair in offsets.windows(2) {
            for (pc_bit, next_bit) in pc.vars.iter().zip(next_pc.vars.iter()) {
                system.add_constraint(
                    magnetar_constraint::Expr::var(pair[0] + *next_bit),
                    one.clone(),
                    magnetar_constraint::Expr::var(pair[1] + *pc_bit),
                );
            }
        }
        Ok((system, magnetar_constraint::Witness::new(values)))
    }

    /// Semantic PC-chain check for the ALU/PC schema slice. Cross-cycle
    /// constraints will move into the SIMD matrix later; this keeps the batch
    /// construction honest in the meantime.
    pub fn validate_pc_chain(&self, rows: &[UniformCpuRowWitness]) -> Result<(), SimdError> {
        for (cycle, pair) in rows.windows(2).enumerate() {
            let expected = pair[0].pc.wrapping_add(4);
            if pair[1].pc != expected {
                return Err(SimdError::PcChain {
                    cycle: cycle + 1,
                    pc: pair[1].pc,
                    expected,
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SimdError {
    #[error("expected {expected} cycles, got {actual}")]
    CycleCount { expected: usize, actual: usize },
    #[error("cycle {cycle} row width {actual}, expected {expected}")]
    RowWidth {
        cycle: usize,
        expected: usize,
        actual: usize,
    },
    #[error("cycle {0} out of range")]
    CycleOutOfRange(usize),
    #[error("row layout has no PC/NextPc group")]
    MissingPcGroup,
    #[error("PC chain break at cycle {cycle}: row pc {pc}, expected {expected}")]
    PcChain {
        cycle: usize,
        pc: u64,
        expected: u64,
    },
}

impl UniformCpuRowLayout {
    pub fn selectors(&self) -> &[magnetar_constraint::VarId; 20] {
        &self.step.alu.selectors
    }
}

#[cfg(test)]
mod batch_tests {
    use super::*;
    use crate::StepOp;

    #[test]
    fn batch_layout_is_cycle_major() {
        let (_system, row) = uniform_cpu_row_layout(8);
        let rows = [
            row.witness(StepOp::Add, 0, 1, 2, 0),
            row.witness(StepOp::Xor, 4, 3, 4, 0),
            row.witness(StepOp::Addi, 8, 5, 0, 6),
        ];
        let batch_layout = UniformCpuBatchLayout::new(row.clone(), rows.len());
        let batch = batch_layout.batch_witness(&rows).expect("batch");
        assert_eq!(batch.values.len(), batch_layout.witness_len());
        for (cycle, expected) in rows.iter().enumerate() {
            assert_eq!(
                batch_layout.row_values(&batch, cycle).unwrap(),
                expected.witness.values()
            );
        }
        assert_eq!(
            batch_layout.row_values(&batch, 3).unwrap_err(),
            SimdError::CycleOutOfRange(3)
        );
    }

    #[test]
    fn alu_batch_enforces_the_pc_chain() {
        let (_system, row) = uniform_cpu_row_layout(8);
        let rows = [
            row.witness(StepOp::Add, 0x1000, 1, 2, 0),
            row.witness(StepOp::Xor, 0x1004, 3, 4, 0),
            row.witness(StepOp::Addi, 0x1008, 5, 0, 6),
        ];
        let batch = UniformCpuBatchLayout::new(row.clone(), rows.len());
        batch.validate_pc_chain(&rows).expect("contiguous PCs");

        let broken = [
            row.witness(StepOp::Add, 0x1000, 1, 2, 0),
            row.witness(StepOp::Xor, 0x1008, 3, 4, 0),
        ];
        assert!(matches!(
            batch.validate_pc_chain(&broken),
            Err(SimdError::PcChain { .. })
        ));
    }

    #[test]
    fn batch_system_enforces_pc_chain() {
        let (_system, row) = uniform_cpu_row_layout(8);
        let rows = [
            row.witness(StepOp::Add, 0, 1, 2, 0),
            row.witness(StepOp::Xor, 4, 3, 4, 0),
            row.witness(StepOp::Addi, 8, 5, 0, 6),
        ];
        let batch = UniformCpuBatchLayout::new(row.clone(), rows.len());
        let (system, witness) = batch.batch_system(&rows).expect("batch system");
        system.check(&witness).expect("valid PC chain");

        let broken = [
            row.witness(StepOp::Add, 0, 1, 2, 0),
            row.witness(StepOp::Xor, 8, 3, 4, 0),
        ];
        let broken_batch = UniformCpuBatchLayout::new(row.clone(), broken.len());
        let (system, witness) = broken_batch.batch_system(&broken).expect("batch system");
        assert!(system.check(&witness).is_err());
    }

    #[test]
    fn each_row_activates_one_operation_selector() {
        let (_system, row) = uniform_cpu_row_layout(8);
        let witness = row.witness(StepOp::Xor, 0, 1, 2, 0);
        let active = row
            .selectors()
            .iter()
            .filter(|selector| witness.witness.values()[**selector].value() == 1)
            .count();
        assert_eq!(active, 1);
    }
}
