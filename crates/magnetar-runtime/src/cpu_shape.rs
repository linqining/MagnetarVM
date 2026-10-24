//! Value-carrying CPU shape experiment for A2.
//!
//! This is not succinct: it records the per-row values. It tests whether the CPU
//! system can be reconstructed outside the trace at all.

use magnetar_spec::{MemoryAccess, Op, Trace, TraceRow};

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct CpuShapeRow {
    pub pc: u64,
    pub op: Op,
    pub imm: i64,
    pub rs1_val: u64,
    pub rs2_val: u64,
    pub rd_val: u64,
    pub mem: Option<(u64, u64, u8, bool)>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Default)]
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
                    rs1_val: row.rs1_val,
                    rs2_val: row.rs2_val,
                    rd_val: row.rd_val,
                    mem: row.mem.map(|m| (m.addr, m.value, m.width, m.is_write)),
                })
                .collect(),
        }
    }

    fn synthetic_rows(&self, trace: &Trace) -> Vec<TraceRow> {
        self.rows
            .iter()
            .zip(trace.rows.iter())
            .map(|(shape, row)| {
                let mut synthetic = row.clone();
                synthetic.instruction.op = shape.op;
                synthetic.instruction.imm = shape.imm;
                synthetic.rs1_val = shape.rs1_val;
                synthetic.rs2_val = shape.rs2_val;
                synthetic.rd_val = shape.rd_val;
                synthetic.mem = shape
                    .mem
                    .map(|(addr, value, width, is_write)| MemoryAccess {
                        addr,
                        value,
                        width,
                        is_write,
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
        if self.rows.len() != trace.rows.len() {
            return Err(crate::RuntimeError::Proof("CPU shape length".into()));
        }
        let mut synthetic = trace.clone();
        synthetic.rows = self.synthetic_rows(trace);
        let (system, _) = crate::merged_cpu_system(&synthetic, width)?;
        Ok(system)
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
