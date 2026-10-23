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
    (
        system,
        UniformCpuRowLayout {
            width,
            step,
            num_vars,
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
