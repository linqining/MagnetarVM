//! Uniform (SIMD-ready) CPU row schema.
//!
//! The legacy runtime builds a different constraint system per row
//! (`simple_alu`, specialized load/store, ...). SIMD needs one fixed row
//! schema: every cycle instantiates the same matrix and selects its operation
//! through witness selectors. This module is the first slice of that schema
//! (ALU + PC); load/store and the dual F2 / F2^128 split build on it.

use crate::{
    bit_addition_constraints, uniform_step_relation, BitAdderLayout, CpuVarGroup, CpuVarKind,
    StepOp, UniformStepLayout,
};
use magnetar_constraint::{ConstraintSystem, Expr, VarId, Witness, F2_128};

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

/// Single fixed CPU schema that instantiates both the ALU/PC relation and the
/// load/store column relation. The two sub-relations are always active; the
/// witness builders fill the inactive side with a consistent default (ALU rows
/// use a load-shaped memory row with data 0; memory rows use `Add` with
/// `rd = rs1 + imm`). Equality constraints tie the duplicated PC/rs1/imm
/// columns together.
#[derive(Clone, Debug)]
pub struct UniformCpuFullLayout {
    pub width: usize,
    pub alu: UniformCpuRowLayout,
    pub memory: UniformMemoryRowLayout,
    pub memory_offset: usize,
    pub is_alu: VarId,
    pub num_vars: usize,
    pub system: ConstraintSystem,
}

impl UniformCpuFullLayout {
    pub fn alu_witness(&self, op: StepOp, pc: u64, rs1: u64, rs2: u64, imm: u64) -> Witness {
        let alu = self.alu.witness(op, pc, rs1, rs2, imm);
        let memory = self.memory.inactive_witness(pc, rs1, imm);
        self.combine(&alu.witness, &memory, true)
    }

    pub fn memory_witness(&self, pc: u64, rs1: u64, imm: u64, data: u64, is_load: bool) -> Witness {
        let alu = self.alu.witness(StepOp::Addi, pc, rs1, 0, imm);
        let memory = self.memory.witness(pc, rs1, imm, data, is_load);
        self.combine(&alu.witness, &memory, false)
    }

    fn combine(&self, alu: &Witness, memory: &Witness, is_alu: bool) -> Witness {
        let mut values = alu.values().to_vec();
        values.resize(self.memory_offset, F2_128::from(0u64));
        values.extend_from_slice(memory.values());
        values.resize(self.num_vars, F2_128::from(0u64));
        values[self.is_alu] = F2_128::from(u64::from(is_alu));
        Witness::new(values)
    }

    pub fn var_groups(&self) -> Vec<CpuVarGroup> {
        self.alu.var_groups()
    }
}

pub fn uniform_cpu_full_layout(width: usize) -> (ConstraintSystem, UniformCpuFullLayout) {
    let (mut system, alu) = uniform_cpu_row_layout(width);
    let (memory_system, memory) = uniform_memory_row_layout(width);
    let memory_offset = system.merge(memory_system);
    let one = Expr::constant(1u64);
    let alu_pc = alu.step.pc_adder.a.clone();
    let alu_rs1 = alu.step.alu.adder.a.clone();
    let alu_imm = alu.step.alu.imm.clone();
    for (left, right) in [
        (alu_pc, memory.pc.a.clone()),
        (alu_rs1, memory.addr.a.clone()),
        (alu_imm, memory.addr.b.clone()),
    ] {
        for (left, right) in left.iter().zip(right.iter()) {
            system.add_constraint(
                Expr::var(*left),
                one.clone(),
                Expr::var(memory_offset + *right),
            );
        }
    }
    let is_alu = system.alloc(1).start;
    system.add_constraint(
        Expr::var(is_alu).add(Expr::var(memory_offset + memory.is_mem)),
        one.clone(),
        Expr::constant(1u64),
    );
    system.add_constraint(
        Expr::var(is_alu),
        Expr::var(is_alu).add(one.clone()),
        Expr::constant(0u64),
    );
    let num_vars = system.num_vars;
    let row_system = system.clone();
    (
        system,
        UniformCpuFullLayout {
            width,
            alu,
            memory,
            memory_offset,
            is_alu,
            num_vars,
            system: row_system,
        },
    )
}

#[derive(Clone, Debug)]
pub struct UniformMemoryRowLayout {
    pub width: usize,
    pub addr: BitAdderLayout,
    pub data: Vec<VarId>,
    pub pc: BitAdderLayout,
    pub is_load: VarId,
    pub is_store: VarId,
    pub is_mem: VarId,
    pub num_vars: usize,
    pub system: ConstraintSystem,
}

impl UniformMemoryRowLayout {
    pub fn witness(&self, pc: u64, rs1: u64, imm: u64, data: u64, is_load: bool) -> Witness {
        let mut values = vec![F2_128::from(0u64); self.num_vars];
        self.addr.fill_witness(&mut values, rs1, imm);
        self.pc.fill_witness(&mut values, pc, 4);
        for (bit, var) in self.data.iter().enumerate() {
            values[*var] = F2_128::from((data >> bit) & 1);
        }
        values[self.is_load] = F2_128::from(u64::from(is_load));
        values[self.is_store] = F2_128::from(u64::from(!is_load));
        values[self.is_mem] = F2_128::from(1u64);
        Witness::new(values)
    }

    /// Memory-side witness for an ALU row: the selector is off and the
    /// load/store bits are both zero.
    pub fn inactive_witness(&self, pc: u64, rs1: u64, imm: u64) -> Witness {
        let mut values = vec![F2_128::from(0u64); self.num_vars];
        self.addr.fill_witness(&mut values, rs1, imm);
        self.pc.fill_witness(&mut values, pc, 4);
        values[self.is_load] = F2_128::from(0u64);
        values[self.is_store] = F2_128::from(0u64);
        values[self.is_mem] = F2_128::from(0u64);
        Witness::new(values)
    }

    pub fn var_groups(&self) -> Vec<CpuVarGroup> {
        vec![
            CpuVarGroup {
                kind: CpuVarKind::Rs1,
                vars: self.addr.a.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::Imm,
                vars: self.addr.b.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::RamAddr,
                vars: self.addr.sum.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::RamValue,
                vars: self.data.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::Pc,
                vars: self.pc.a.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::NextPc,
                vars: self.pc.sum.clone(),
            },
        ]
    }
}

pub fn uniform_memory_row_layout(width: usize) -> (ConstraintSystem, UniformMemoryRowLayout) {
    assert!(width > 0 && width <= 64);
    let (mut system, addr) = bit_addition_constraints(width);
    let data: Vec<VarId> = system.alloc(width).collect();
    let (pc_system, pc) = bit_addition_constraints(width);
    let pc_offset = system.merge(pc_system);
    let pc = pc.shifted(pc_offset);
    let is_load = system.alloc(1).start;
    let is_store = system.alloc(1).start;
    let is_mem = system.alloc(1).start;
    let one = Expr::constant(1u64);
    for var in data.iter().chain([is_load, is_store, is_mem].iter()) {
        system.add_constraint(
            Expr::var(*var),
            Expr::var(*var).add(one.clone()),
            Expr::constant(0u64),
        );
    }
    system.add_constraint(
        Expr::var(is_load).add(Expr::var(is_store)),
        one,
        Expr::var(is_mem),
    );
    let num_vars = system.num_vars;
    let row_system = system.clone();
    (
        system,
        UniformMemoryRowLayout {
            width,
            addr,
            data,
            pc,
            is_load,
            is_store,
            is_mem,
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
    #[test]
    fn memory_rows_share_one_uniform_schema() {
        let (system, layout) = uniform_memory_row_layout(8);
        let rows = [
            layout.witness(0x1000, 0x10, 0x02, 0x34, true),
            layout.witness(0x1004, 0x20, 0x04, 0x56, false),
        ];
        for row in &rows {
            assert_eq!(row.values().len(), layout.num_vars);
            system.check(row).expect("uniform memory row");
            assert_eq!(row.values()[layout.is_mem].value(), 1);
        }
        let inactive = layout.inactive_witness(0x1008, 0x30, 0x06);
        system.check(&inactive).expect("inactive memory row");
        assert_eq!(inactive.values()[layout.is_mem].value(), 0);
        assert_eq!(inactive.values()[layout.is_load].value(), 0);
        assert_eq!(inactive.values()[layout.is_store].value(), 0);
        for (group, expected) in [
            (crate::CpuVarKind::RamAddr, 0x12u64),
            (crate::CpuVarKind::RamValue, 0x34u64),
        ] {
            let group = layout
                .var_groups()
                .into_iter()
                .find(|candidate| candidate.kind == group)
                .unwrap();
            for (bit, var) in group.vars.iter().enumerate() {
                assert_eq!(rows[0].values()[*var].value() as u64, (expected >> bit) & 1);
            }
        }
    }
    #[test]
    fn combined_schema_accepts_alu_and_memory_rows() {
        let (system, layout) = uniform_cpu_full_layout(8);
        let alu = layout.alu_witness(StepOp::Add, 0x1000, 3, 4, 0);
        let memory = layout.memory_witness(0x1004, 5, 2, 0x34, true);
        assert_eq!(alu.values().len(), layout.num_vars);
        assert_eq!(memory.values().len(), layout.num_vars);
        system.check(&alu).expect("ALU row");
        system.check(&memory).expect("memory row");
        assert_eq!(alu.values()[layout.is_alu].value(), 1);
        assert_eq!(memory.values()[layout.is_alu].value(), 0);
        assert_eq!(
            memory.values()[layout.memory_offset + layout.memory.is_mem].value(),
            1
        );
    }
}
