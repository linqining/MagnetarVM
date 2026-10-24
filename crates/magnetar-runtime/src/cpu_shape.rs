//! Value-carrying CPU shape experiment for A2.
//!
//! This is not succinct: it records the per-row values. It tests whether the CPU
//! system can be reconstructed outside the trace at all.

use magnetar_spec::{MemoryAccess, Op, Trace, TraceRow};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CpuShapeRow {
    pub pc: u64,
    pub op: Op,
    pub imm: i64,
    pub mem_width: Option<u8>,
    pub mem_write: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct CpuShape {
    pub rows: Vec<CpuShapeRow>,
}

impl CpuShape {
    pub fn from_trace(trace: &Trace) -> Self {
        Self {
            rows: trace
                .rows
                .iter()
                .map(|row| CpuShapeRow {
                    pc: row.pc,
                    op: row.instruction.op,
                    imm: row.instruction.imm,
                    mem_width: row.mem.map(|m| m.width),
                    mem_write: row.mem.is_some_and(|m| m.is_write),
                })
                .collect(),
        }
    }

    pub fn zeroed(&self) -> Self {
        self.clone()
    }

    pub fn matches_structure(&self, trace: &Trace) -> bool {
        self.rows.len() == trace.rows.len()
            && self.rows.iter().zip(trace.rows.iter()).all(|(shape, row)| {
                shape.pc == row.pc
                    && shape.op == row.instruction.op
                    && shape.imm == row.instruction.imm
                    && shape.mem_width == row.mem.map(|m| m.width)
                    && shape.mem_write == row.mem.is_some_and(|m| m.is_write)
            })
    }

    fn synthetic_rows(&self, trace: &Trace) -> Vec<TraceRow> {
        self.rows
            .iter()
            .zip(trace.rows.iter())
            .map(|(shape, row)| {
                let mut synthetic = row.clone();
                synthetic.instruction.op = shape.op;
                synthetic.instruction.imm = shape.imm;
                synthetic.rs1_val = 0;
                synthetic.rs2_val = 0;
                synthetic.rd_val = 0;
                synthetic.mem = shape.mem_width.map(|width| MemoryAccess {
                    addr: 0,
                    value: 0,
                    width,
                    is_write: shape.mem_write,
                });
                synthetic
            })
            .collect()
    }

    pub fn system(
        &self,
        trace: &Trace,
        width: usize,
    ) -> Result<magnetar_constraint::ConstraintSystem, crate::RuntimeError> {
        self.system_with_len(trace, width).map(|(system, _)| system)
    }

    pub fn system_without_trace(
        &self,
        width: usize,
    ) -> Result<(magnetar_constraint::ConstraintSystem, usize), crate::RuntimeError> {
        let mut merged = magnetar_constraint::ConstraintSystem::new(0);
        let mut values = Vec::new();
        for shape in &self.rows {
            let instruction = magnetar_spec::Instruction {
                op: shape.op,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: shape.imm,
                shamt: 0,
            };
            let row = TraceRow {
                cycle: 0,
                pc: shape.pc,
                micro_pc: shape.pc,
                micro_op: magnetar_spec::MicroOpKind::Execute,
                next_pc: shape.pc.wrapping_add(4),
                instruction_word: 0,
                instruction_len: 4,
                instruction,
                rs1: None,
                rs2: None,
                rd: None,
                rs1_val: 0,
                rs2_val: 0,
                rd_val: 0,
                mem: shape.mem_width.map(|width| MemoryAccess {
                    addr: 0,
                    value: 0,
                    width,
                    is_write: shape.mem_write,
                }),
                extra_mem: Vec::new(),
                reservation_before: None,
                reservation_after: None,
                syscall: None,
            };
            if let Some((system, witness)) = crate::row_cpu_relation(&row, width)? {
                let offset = merged.merge(system);
                if values.len() != offset {
                    return Err(crate::RuntimeError::Proof("shape witness layout".into()));
                }
                values.extend_from_slice(witness.values());
            }
        }
        let witness = magnetar_constraint::Witness::new(values);
        let z = magnetar_proof::witness_vector(&merged, &witness)
            .map_err(|error| crate::RuntimeError::Proof(error.to_string()))?;
        Ok((merged, z.len()))
    }

    pub fn system_with_len(
        &self,
        trace: &Trace,
        width: usize,
    ) -> Result<(magnetar_constraint::ConstraintSystem, usize), crate::RuntimeError> {
        if self.rows.len() != trace.rows.len() {
            return Err(crate::RuntimeError::Proof("CPU shape length".into()));
        }
        let mut synthetic = trace.clone();
        synthetic.rows = self.synthetic_rows(trace);
        let (system, witness) = crate::merged_cpu_system(&synthetic, width)?;
        let z = magnetar_proof::witness_vector(&system, &witness)
            .map_err(|error| crate::RuntimeError::Proof(error.to_string()))?;
        Ok((system, z.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    fn config() -> MachineConfig {
        MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x100,
            stack_top: 0x1000_0080,
            max_cycles: 100,
        }
    }

    #[test]
    fn shape_reconstructs_sparse_matrices() {
        use magnetar_proof::spartan::{MatrixPart, SparseMatrix};

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
                    rd: 2,
                    rs1: 4,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::ScD,
                    rd: 5,
                    rs1: 4,
                    rs2: 2,
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
        let trace = execute(&program, config()).unwrap();
        let (real, _) = crate::merged_cpu_system(&trace, 8).unwrap();
        let shape = CpuShape::from_trace(&trace).zeroed();
        let (synthetic, _) = shape.system_with_len(&trace, 8).unwrap();
        assert_eq!(
            format!("{:?}", real.constraints),
            format!("{:?}", synthetic.constraints)
        );
        for part in [MatrixPart::A, MatrixPart::B, MatrixPart::C] {
            let a = SparseMatrix::from_system(&real, part).unwrap();
            let b = SparseMatrix::from_system(&synthetic, part).unwrap();
            let ea = a.entries();
            let eb = b.entries();
            eprintln!("part {:?} real {} synthetic {}", part, ea.len(), eb.len());
            if ea != eb {
                for i in 0..ea.len().max(eb.len()) {
                    if ea.get(i) != eb.get(i) {
                        eprintln!(
                            "first diff at {i}: real {:?} synthetic {:?}",
                            ea.get(i),
                            eb.get(i)
                        );
                        break;
                    }
                }
            }
            assert_eq!(ea, eb, "part {:?}", part);
        }
    }

    #[test]
    fn shape_reconstructs_cpu_system() {
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
        let trace = execute(&program, config()).unwrap();
        let (real, _) = crate::merged_cpu_system(&trace, 8).unwrap();
        let shape = CpuShape::from_trace(&trace);
        let synthetic = shape.system(&trace, 8).unwrap();
        assert_eq!(real.num_vars, synthetic.num_vars);
        assert_eq!(real.constraints.len(), synthetic.constraints.len());
        assert_eq!(
            format!("{:?}", real.constraints),
            format!("{:?}", synthetic.constraints)
        );
    }
}
