//! Value-carrying CPU shape experiment for A2.
//!
//! This is not succinct: it records the per-row values. It tests whether the CPU
//! system can be reconstructed outside the trace at all.

use magnetar_spec::{MemoryAccess, Op, Trace, TraceRow};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CpuShapeRow {
    pub pc: u64,
    pub micro_op: magnetar_spec::MicroOpKind,
    pub op: Op,
    pub imm: i64,
    pub mem_width: Option<u8>,
    pub mem_write: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CpuShape {
    pub rows: Vec<CpuShapeRow>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ShapeWire {
    first_pc: u64,
    pc_deltas: Vec<(i64, u32)>,
    micro_ops: Vec<(magnetar_spec::MicroOpKind, u32)>,
    ops: Vec<(Op, u32)>,
    imms: Vec<i64>,
    widths: Vec<(u8, u32)>,
    flags: Vec<(u8, u32)>,
}

fn run_length<T: PartialEq + Copy>(values: &[T]) -> Vec<(T, u32)> {
    let mut runs: Vec<(T, u32)> = Vec::new();
    for value in values {
        match runs.last_mut() {
            Some((last, count)) if *last == *value => *count += 1,
            _ => runs.push((*value, 1)),
        }
    }
    runs
}

fn expand_runs<T: Copy>(runs: &[(T, u32)], len: usize) -> Option<Vec<T>> {
    let mut values = Vec::with_capacity(len);
    for (value, count) in runs {
        let count = *count as usize;
        if values.len().saturating_add(count) > len {
            return None;
        }
        values.extend(std::iter::repeat_n(*value, count));
    }
    (values.len() == len).then_some(values)
}

impl serde::Serialize for CpuShape {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use bincode::Options as _;
        let first_pc = self.rows.first().map_or(0, |row| row.pc);
        let mut wire = ShapeWire {
            first_pc,
            pc_deltas: Vec::with_capacity(self.rows.len().saturating_sub(1)),
            micro_ops: Vec::with_capacity(self.rows.len()),
            ops: Vec::with_capacity(self.rows.len()),
            imms: Vec::with_capacity(self.rows.len()),
            widths: Vec::with_capacity(self.rows.len()),
            flags: Vec::with_capacity(self.rows.len()),
        };
        let mut previous_pc = first_pc;
        let mut pc_deltas = Vec::with_capacity(self.rows.len().saturating_sub(1));
        let mut micro_ops = Vec::with_capacity(self.rows.len());
        let mut ops = Vec::with_capacity(self.rows.len());
        let mut imms = Vec::with_capacity(self.rows.len());
        let mut widths = Vec::with_capacity(self.rows.len());
        let mut flags = Vec::with_capacity(self.rows.len());
        for (index, row) in self.rows.iter().enumerate() {
            if index > 0 {
                pc_deltas.push(row.pc as i64 - previous_pc as i64);
            }
            previous_pc = row.pc;
            micro_ops.push(row.micro_op);
            ops.push(row.op);
            imms.push(row.imm);
            widths.push(row.mem_width.unwrap_or(0));
            flags.push(u8::from(row.mem_write));
        }
        wire.pc_deltas = run_length(&pc_deltas);
        wire.micro_ops = run_length(&micro_ops);
        wire.ops = run_length(&ops);
        wire.imms = imms;
        wire.widths = run_length(&widths);
        wire.flags = run_length(&flags);
        let blob = bincode::DefaultOptions::new()
            .with_varint_encoding()
            .serialize(&wire)
            .map_err(serde::ser::Error::custom)?;
        blob.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for CpuShape {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use bincode::Options as _;
        let blob = Vec::<u8>::deserialize(deserializer)?;
        let wire: ShapeWire = bincode::DefaultOptions::new()
            .with_varint_encoding()
            .deserialize(&blob)
            .map_err(serde::de::Error::custom)?;
        let count = wire.imms.len();
        let ops = expand_runs(&wire.ops, count)
            .ok_or_else(|| serde::de::Error::custom("shape op runs"))?;
        let micro_ops = expand_runs(&wire.micro_ops, count)
            .ok_or_else(|| serde::de::Error::custom("shape micro-op runs"))?;
        let widths = expand_runs(&wire.widths, count)
            .ok_or_else(|| serde::de::Error::custom("shape width runs"))?;
        let flags = expand_runs(&wire.flags, count)
            .ok_or_else(|| serde::de::Error::custom("shape flag runs"))?;
        let pc_deltas = expand_runs(&wire.pc_deltas, count.saturating_sub(1))
            .ok_or_else(|| serde::de::Error::custom("shape pc runs"))?;
        let mut rows = Vec::with_capacity(count);
        let mut pc = wire.first_pc;
        for index in 0..count {
            if index > 0 {
                pc = (pc as i64 + pc_deltas[index - 1]) as u64;
            }
            rows.push(CpuShapeRow {
                pc,
                micro_op: micro_ops[index],
                op: ops[index],
                imm: wire.imms[index],
                mem_width: (widths[index] != 0).then_some(widths[index]),
                mem_write: flags[index] != 0,
            });
        }
        Ok(Self { rows })
    }
}

impl CpuShape {
    pub fn from_trace(trace: &Trace) -> Self {
        Self::from_rows(&trace.rows)
    }

    pub fn from_rows(rows: &[TraceRow]) -> Self {
        Self {
            rows: rows
                .iter()
                .map(|row| CpuShapeRow {
                    pc: row.pc,
                    micro_op: row.micro_op,
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

    pub fn matches_rows(&self, rows: &[TraceRow]) -> bool {
        self.rows.len() == rows.len()
            && self.rows.iter().zip(rows.iter()).all(|(shape, row)| {
                shape.pc == row.pc
                    && shape.micro_op == row.micro_op
                    && shape.op == row.instruction.op
                    && shape.imm == row.instruction.imm
                    && shape.mem_width == row.mem.map(|m| m.width)
                    && shape.mem_write == row.mem.is_some_and(|m| m.is_write)
            })
    }

    pub fn matches_structure(&self, trace: &Trace) -> bool {
        self.rows.len() == trace.rows.len()
            && self.rows.iter().zip(trace.rows.iter()).all(|(shape, row)| {
                shape.pc == row.pc
                    && shape.micro_op == row.micro_op
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
                micro_op: shape.micro_op,
                next_pc: if shape.micro_op == magnetar_spec::MicroOpKind::Fetch {
                    shape.pc
                } else {
                    shape.pc.wrapping_add(4)
                },
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
