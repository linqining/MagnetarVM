//! CPU step relation.
//!
//! `check_trace` is the reference semantic checker for every RV64I/RV64M row.
//! `bit_addition_constraints` demonstrates the bit-level R1CS over `F2_128`
//! that the uniform SIMD CPU relation will use for integer addition.

use magnetar_constraint::{ConstraintSystem, Expr, VarId, Witness, F2_128};

pub mod simd;
use magnetar_spec::{
    addw, div, divu, mulh, mulhsu, mulhu, rem, remu, sllw, sraw, srlw, subw, Addr, Op, Trace,
    TraceRow, Word,
};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CpuError {
    #[error("row {row}: {op} produced rd={actual:#x}, expected {expected:#x}")]
    RdValue {
        row: usize,
        op: &'static str,
        expected: Word,
        actual: Word,
    },
    #[error("row {row}: next pc is {actual:#x}, expected {expected:#x}")]
    NextPc {
        row: usize,
        expected: Word,
        actual: Word,
    },
    #[error("row {row}: memory address is {actual:#x}, expected {expected:#x}")]
    MemAddr {
        row: usize,
        expected: Addr,
        actual: Addr,
    },
    #[error("row {row}: expected no memory access")]
    UnexpectedMemory { row: usize },
    #[error("row {row}: expected a memory access")]
    MissingMemory { row: usize },
    #[error("row {row}: store wrote rd={value:#x}, expected 0")]
    StoreRd { row: usize, value: Word },
    #[error("row {row}: memory width is {actual}, expected {expected}")]
    MemWidth {
        row: usize,
        expected: u8,
        actual: u8,
    },
    #[error("row {row}: memory value is {actual:#x}, expected {expected:#x}")]
    MemValue {
        row: usize,
        expected: Word,
        actual: Word,
    },
    #[error("row {row}: address {addr:#x} is not aligned to width {width}")]
    Misaligned { row: usize, addr: Addr, width: u8 },
    #[error("row {row}: unsupported {syscall} syscall shape")]
    SyscallShape { row: usize, syscall: &'static str },
    #[error("row {row}: reservation after is {actual:?}, expected {expected:?}")]
    Reservation {
        row: usize,
        expected: Option<Addr>,
        actual: Option<Addr>,
    },
}

/// Check every row against the RV64I step semantics.
pub fn check_trace(trace: &Trace) -> Result<(), CpuError> {
    for (index, row) in trace.rows.iter().enumerate() {
        check_row(index, row)?;
    }
    Ok(())
}

pub fn check_row(index: usize, row: &TraceRow) -> Result<(), CpuError> {
    let pc = row.pc;
    let imm = row.instruction.imm as Word;
    let rs1 = row.rs1_val;
    let rs2 = row.rs2_val;
    let next_pc_increment = pc.wrapping_add(u64::from(row.instruction_len));
    let mut expected_next_pc = next_pc_increment;
    let mut expected_reservation_after = row.reservation_before;

    match row.instruction.op {
        Op::Add => check_rd(index, row, rs1.wrapping_add(rs2))?,
        Op::Sub => check_rd(index, row, rs1.wrapping_sub(rs2))?,
        Op::Sll => check_rd(index, row, rs1.wrapping_shl((rs2 & 0x3f) as u32))?,
        Op::Slt => check_rd(index, row, u64::from((rs1 as i64) < (rs2 as i64)))?,
        Op::Sltu => check_rd(index, row, u64::from(rs1 < rs2))?,
        Op::Xor => check_rd(index, row, rs1 ^ rs2)?,
        Op::Srl => check_rd(index, row, rs1.wrapping_shr((rs2 & 0x3f) as u32))?,
        Op::Sra => check_rd(index, row, ((rs1 as i64) >> (rs2 & 0x3f)) as u64)?,
        Op::Or => check_rd(index, row, rs1 | rs2)?,
        Op::And => check_rd(index, row, rs1 & rs2)?,
        Op::Addw => check_rd(index, row, addw(rs1, rs2))?,
        Op::Subw => check_rd(index, row, subw(rs1, rs2))?,
        Op::Sllw => check_rd(index, row, sllw(rs1, rs2))?,
        Op::Srlw => check_rd(index, row, srlw(rs1, rs2))?,
        Op::Sraw => check_rd(index, row, sraw(rs1, rs2))?,
        Op::Mul => check_rd(index, row, rs1.wrapping_mul(rs2))?,
        Op::Mulh => check_rd(index, row, mulh(rs1, rs2))?,
        Op::Mulhsu => check_rd(index, row, mulhsu(rs1, rs2))?,
        Op::Mulhu => check_rd(index, row, mulhu(rs1, rs2))?,
        Op::Div => check_rd(index, row, div(rs1, rs2))?,
        Op::Divu => check_rd(index, row, divu(rs1, rs2))?,
        Op::Rem => check_rd(index, row, rem(rs1, rs2))?,
        Op::Remu => check_rd(index, row, remu(rs1, rs2))?,
        Op::Addi => check_rd(index, row, rs1.wrapping_add(imm))?,
        Op::Addiw => check_rd(index, row, addw(rs1, imm))?,
        Op::Slti => check_rd(index, row, u64::from((rs1 as i64) < row.instruction.imm))?,
        Op::Sltiu => check_rd(index, row, u64::from(rs1 < imm))?,
        Op::Xori => check_rd(index, row, rs1 ^ imm)?,
        Op::Ori => check_rd(index, row, rs1 | imm)?,
        Op::Andi => check_rd(index, row, rs1 & imm)?,
        Op::Slli => check_rd(
            index,
            row,
            rs1.wrapping_shl(u32::from(row.instruction.shamt)),
        )?,
        Op::Slliw => check_rd(index, row, sllw(rs1, u64::from(row.instruction.shamt)))?,
        Op::Srli => check_rd(
            index,
            row,
            rs1.wrapping_shr(u32::from(row.instruction.shamt)),
        )?,
        Op::Srliw => check_rd(index, row, srlw(rs1, u64::from(row.instruction.shamt)))?,
        Op::Srai => check_rd(index, row, ((rs1 as i64) >> row.instruction.shamt) as u64)?,
        Op::Sraiw => check_rd(index, row, sraw(rs1, u64::from(row.instruction.shamt)))?,
        Op::Lui => check_rd(index, row, imm)?,
        Op::Auipc => check_rd(index, row, pc.wrapping_add(imm))?,
        Op::Jal => {
            check_rd(index, row, next_pc_increment)?;
            expected_next_pc = pc.wrapping_add(imm);
        }
        Op::Jalr => {
            check_rd(index, row, next_pc_increment)?;
            expected_next_pc = rs1.wrapping_add(imm) & !1;
        }
        Op::Beq => {
            if rs1 == rs2 {
                expected_next_pc = pc.wrapping_add(imm);
            }
            check_no_rd(index, row)?;
        }
        Op::Bne => {
            if rs1 != rs2 {
                expected_next_pc = pc.wrapping_add(imm);
            }
            check_no_rd(index, row)?;
        }
        Op::Blt => {
            if (rs1 as i64) < (rs2 as i64) {
                expected_next_pc = pc.wrapping_add(imm);
            }
            check_no_rd(index, row)?;
        }
        Op::Bge => {
            if (rs1 as i64) >= (rs2 as i64) {
                expected_next_pc = pc.wrapping_add(imm);
            }
            check_no_rd(index, row)?;
        }
        Op::Bltu => {
            if rs1 < rs2 {
                expected_next_pc = pc.wrapping_add(imm);
            }
            check_no_rd(index, row)?;
        }
        Op::Bgeu => {
            if rs1 >= rs2 {
                expected_next_pc = pc.wrapping_add(imm);
            }
            check_no_rd(index, row)?;
        }
        Op::Lb | Op::Lh | Op::Lw | Op::Ld | Op::Lbu | Op::Lhu | Op::Lwu => {
            let width = match row.instruction.op {
                Op::Lb | Op::Lbu => 1,
                Op::Lh | Op::Lhu => 2,
                Op::Lw | Op::Lwu => 4,
                Op::Ld => 8,
                _ => unreachable!(),
            };
            check_memory(index, row, rs1.wrapping_add(imm), width, false)?;
        }
        Op::Sb | Op::Sh | Op::Sw | Op::Sd => {
            let width = match row.instruction.op {
                Op::Sb => 1,
                Op::Sh => 2,
                Op::Sw => 4,
                Op::Sd => 8,
                _ => unreachable!(),
            };
            check_memory(index, row, rs1.wrapping_add(imm), width, true)?;
            expected_reservation_after = None;
            if row.rd_val != 0 {
                return Err(CpuError::StoreRd {
                    row: index,
                    value: row.rd_val,
                });
            }
        }
        Op::LrW | Op::LrD => {
            let width = row.instruction.op.atomic_width().expect("LR width");
            let addr = rs1.wrapping_add(imm);
            check_memory(index, row, addr, width as u8, false)?;
            expected_reservation_after = Some(addr);
            if width == 4 && (row.rd_val as u32 as i32 as i64) as u64 != row.rd_val {
                return Err(CpuError::RdValue {
                    row: index,
                    op: row.instruction.op.name(),
                    expected: (row.rd_val as u32 as i32 as i64) as u64,
                    actual: row.rd_val,
                });
            }
        }
        Op::ScW | Op::ScD => {
            let width = row.instruction.op.atomic_width().expect("SC width");
            let addr = rs1.wrapping_add(imm);
            let mask = if width == 4 {
                (1u64 << 32) - 1
            } else {
                u64::MAX
            };
            let expected_success = row.reservation_before == Some(addr);
            if expected_success {
                let access = row.mem.ok_or(CpuError::MissingMemory { row: index })?;
                check_memory(index, row, addr, width as u8, true)?;
                if access.value != rs2 & mask {
                    return Err(CpuError::MemValue {
                        row: index,
                        expected: rs2 & mask,
                        actual: access.value,
                    });
                }
                if row.rd_val != 0 {
                    return Err(CpuError::RdValue {
                        row: index,
                        op: row.instruction.op.name(),
                        expected: 0,
                        actual: row.rd_val,
                    });
                }
            } else {
                if row.mem.is_some() {
                    return Err(CpuError::UnexpectedMemory { row: index });
                }
                if row.rd_val != 1 {
                    return Err(CpuError::RdValue {
                        row: index,
                        op: row.instruction.op.name(),
                        expected: 1,
                        actual: row.rd_val,
                    });
                }
            }
            expected_reservation_after = None;
        }
        Op::AmoswapW
        | Op::AmoswapD
        | Op::AmoaddW
        | Op::AmoaddD
        | Op::AmoxorW
        | Op::AmoxorD
        | Op::AmoandW
        | Op::AmoandD
        | Op::AmoorW
        | Op::AmoorD
        | Op::AmominW
        | Op::AmominD
        | Op::AmomaxW
        | Op::AmomaxD
        | Op::AmominuW
        | Op::AmominuD
        | Op::AmomaxuW
        | Op::AmomaxuD => {
            let width = row.instruction.op.amo_width().expect("AMO width");
            check_memory(index, row, rs1.wrapping_add(imm), width as u8, true)?;
            expected_reservation_after = None;
            if width == 4 && (row.rd_val as u32 as i32 as i64) as u64 != row.rd_val {
                return Err(CpuError::RdValue {
                    row: index,
                    op: row.instruction.op.name(),
                    expected: (row.rd_val as u32 as i32 as i64) as u64,
                    actual: row.rd_val,
                });
            }
            let expected = row.instruction.op.amo_apply(row.rd_val, rs2);
            let access = row.mem.ok_or(CpuError::MissingMemory { row: index })?;
            if access.value != expected {
                return Err(CpuError::MemValue {
                    row: index,
                    expected,
                    actual: access.value,
                });
            }
        }
        Op::Fence => {
            check_no_rd(index, row)?;
        }
        Op::Ecall => {
            let syscall = row.syscall.ok_or(CpuError::SyscallShape {
                row: index,
                syscall: "ecall",
            })?;
            if syscall.number == magnetar_spec::syscall::SYS_READ {
                let requested = syscall.args[2];
                if syscall.args[0] != 0 || row.rd != Some(10) || row.mem.is_some() {
                    return Err(CpuError::SyscallShape {
                        row: index,
                        syscall: "read",
                    });
                }
                if row.extra_mem.is_empty() {
                    if row.rd_val != 0 {
                        return Err(CpuError::RdValue {
                            row: index,
                            op: row.instruction.op.name(),
                            expected: 0,
                            actual: row.rd_val,
                        });
                    }
                } else {
                    let actual = row.rd_val;
                    if actual == 0 || actual > requested {
                        return Err(CpuError::SyscallShape {
                            row: index,
                            syscall: "read",
                        });
                    }
                    let first = syscall.args[1] & !7;
                    let lane = syscall.args[1] & 7;
                    let words = lane
                        .checked_add(actual)
                        .and_then(|value| value.checked_add(7))
                        .map(|value| value / 8)
                        .ok_or(CpuError::SyscallShape {
                            row: index,
                            syscall: "read",
                        })?;
                    if row.extra_mem.len() as u64 != words {
                        return Err(CpuError::SyscallShape {
                            row: index,
                            syscall: "read",
                        });
                    }
                    for (chunk, access) in row.extra_mem.iter().enumerate() {
                        let expected_addr =
                            first
                                .checked_add(8 * chunk as u64)
                                .ok_or(CpuError::SyscallShape {
                                    row: index,
                                    syscall: "read",
                                })?;
                        if access.addr != expected_addr || !access.is_write || access.width != 8 {
                            return Err(CpuError::SyscallShape {
                                row: index,
                                syscall: "read",
                            });
                        }
                    }
                }
                expected_next_pc = next_pc_increment;
            } else if syscall.number == magnetar_spec::syscall::SYS_WRITE {
                if !matches!(syscall.args[0], 1 | 2)
                    || row.mem.is_some()
                    || row.rd != Some(10)
                    || row.rd_val != syscall.args[2]
                    || row.next_pc != next_pc_increment
                {
                    return Err(CpuError::SyscallShape {
                        row: index,
                        syscall: "write",
                    });
                }
                expected_next_pc = next_pc_increment;
            } else if syscall.number == magnetar_spec::syscall::SYS_HINT {
                if row.mem.is_some()
                    || !row.extra_mem.is_empty()
                    || row.rd != Some(10)
                    || row.rd_val != 0
                    || row.next_pc != next_pc_increment
                {
                    return Err(CpuError::SyscallShape {
                        row: index,
                        syscall: "hint",
                    });
                }
                expected_next_pc = next_pc_increment;
            } else if syscall.number == magnetar_spec::syscall::SYS_EXIT {
                if row.mem.is_some()
                    || !row.extra_mem.is_empty()
                    || row.rd.is_some()
                    || row.rd_val != 0
                    || row.next_pc != pc
                {
                    return Err(CpuError::SyscallShape {
                        row: index,
                        syscall: "exit",
                    });
                }
                expected_next_pc = pc;
            } else if row.rd == Some(10) && row.next_pc == next_pc_increment {
                // Continuing syscall: the return value is written to a0.
            } else {
                expected_next_pc = pc;
                check_no_rd(index, row)?;
            }
        }
        Op::Ebreak => {
            expected_next_pc = pc;
            check_no_rd(index, row)?;
        }
    }

    if row.next_pc != expected_next_pc {
        return Err(CpuError::NextPc {
            row: index,
            expected: expected_next_pc,
            actual: row.next_pc,
        });
    }
    if row.reservation_after != expected_reservation_after {
        return Err(CpuError::Reservation {
            row: index,
            expected: expected_reservation_after,
            actual: row.reservation_after,
        });
    }
    Ok(())
}

fn check_rd(index: usize, row: &TraceRow, expected: Word) -> Result<(), CpuError> {
    if row.rd_val != expected {
        return Err(CpuError::RdValue {
            row: index,
            op: row.instruction.op.name(),
            expected,
            actual: row.rd_val,
        });
    }
    Ok(())
}

fn check_no_rd(index: usize, row: &TraceRow) -> Result<(), CpuError> {
    if row.rd_val != 0 {
        return Err(CpuError::RdValue {
            row: index,
            op: row.instruction.op.name(),
            expected: 0,
            actual: row.rd_val,
        });
    }
    Ok(())
}

fn check_memory(
    index: usize,
    row: &TraceRow,
    expected_addr: Addr,
    expected_width: u8,
    is_write: bool,
) -> Result<(), CpuError> {
    let access = row.mem.ok_or(CpuError::MissingMemory { row: index })?;
    if !expected_addr.is_multiple_of(u64::from(expected_width)) {
        return Err(CpuError::Misaligned {
            row: index,
            addr: expected_addr,
            width: expected_width,
        });
    }
    if access.addr != expected_addr {
        return Err(CpuError::MemAddr {
            row: index,
            expected: expected_addr,
            actual: access.addr,
        });
    }
    if access.width != expected_width {
        return Err(CpuError::MemWidth {
            row: index,
            expected: expected_width,
            actual: access.width,
        });
    }
    if access.is_write != is_write {
        return Err(CpuError::UnexpectedMemory { row: index });
    }
    Ok(())
}

/// Variable layout for a width-bit ripple-carry adder over `F2_128`.
#[derive(Clone, Debug)]
pub struct BitAdderLayout {
    pub width: usize,
    pub a: Vec<VarId>,
    pub b: Vec<VarId>,
    pub sum: Vec<VarId>,
    pub carry: Vec<VarId>,
    p1: Vec<VarId>,
    p2: Vec<VarId>,
    p3: Vec<VarId>,
    carry_in: u64,
    pub num_vars: usize,
}

impl BitAdderLayout {
    /// Build a witness for `a + b`, with LSB-first bit order.
    pub fn witness(&self, a_value: u64, b_value: u64) -> Witness {
        let mut values = vec![F2_128::from(0u64); self.num_vars];
        self.fill_witness(&mut values, a_value, b_value);
        Witness::new(values)
    }

    /// Shift every variable ID by `offset`, for merging into a larger system.
    pub fn shifted(mut self, offset: VarId) -> Self {
        for var in &mut self.a {
            *var += offset;
        }
        for var in &mut self.b {
            *var += offset;
        }
        for var in &mut self.sum {
            *var += offset;
        }
        for var in &mut self.carry {
            *var += offset;
        }
        for var in &mut self.p1 {
            *var += offset;
        }
        for var in &mut self.p2 {
            *var += offset;
        }
        for var in &mut self.p3 {
            *var += offset;
        }
        self
    }

    /// Fill the adder variables inside a larger witness buffer.
    pub fn fill_witness(&self, values: &mut [F2_128], a_value: u64, b_value: u64) {
        assert!(self.width <= 64);
        self.fill_witness_wide(values, u128::from(a_value), u128::from(b_value));
    }

    /// Fill the adder variables for widths above 64 bits.
    pub fn fill_witness_wide(&self, values: &mut [F2_128], a_value: u128, b_value: u128) {
        assert!(self.width <= 128);
        let mut carry = self.carry_in;
        for i in 0..self.width {
            let a_bit = ((a_value >> i) & 1) as u64;
            let b_bit = ((b_value >> i) & 1) as u64;
            let total = a_bit + b_bit + carry;
            let sum_bit = total & 1;
            let next_carry = total >> 1;

            values[self.a[i]] = F2_128::from(a_bit);
            values[self.b[i]] = F2_128::from(b_bit);
            values[self.sum[i]] = F2_128::from(sum_bit);
            values[self.carry[i]] = F2_128::from(carry);
            values[self.p1[i]] = F2_128::from(a_bit & b_bit);
            values[self.p2[i]] = F2_128::from(a_bit & carry);
            values[self.p3[i]] = F2_128::from(b_bit & carry);
            carry = next_carry;
        }
        values[self.carry[self.width]] = F2_128::from(carry);
    }
}

/// Encode a width-bit ripple-carry adder in the reference R1CS IR.
///
/// This is the bit-level building block for RV64 integer addition. The
/// word-level `s2` relation will batch these constraints across cycles.
pub fn bit_addition_constraints(width: usize) -> (ConstraintSystem, BitAdderLayout) {
    bit_addition_constraints_with_carry(width, 0)
}

pub fn bit_addition_constraints_with_carry(
    width: usize,
    carry_in: u64,
) -> (ConstraintSystem, BitAdderLayout) {
    assert!(width > 0);
    assert!(carry_in <= 1);
    let a: Vec<VarId> = (0..width).collect();
    let b: Vec<VarId> = (width..2 * width).collect();
    let sum: Vec<VarId> = (2 * width..3 * width).collect();
    let carry: Vec<VarId> = (3 * width..4 * width + 1).collect();
    let p1: Vec<VarId> = (4 * width + 1..5 * width + 1).collect();
    let p2: Vec<VarId> = (5 * width + 1..6 * width + 1).collect();
    let p3: Vec<VarId> = (6 * width + 1..7 * width + 1).collect();
    let num_vars = 7 * width + 1;
    let mut system = ConstraintSystem::new(num_vars);
    let one = Expr::constant(1u64);
    let zero = Expr::constant(0u64);

    system.add_constraint(Expr::var(carry[0]), one.clone(), Expr::constant(carry_in));

    for &var in a
        .iter()
        .chain(b.iter())
        .chain(sum.iter())
        .chain(carry.iter())
    {
        let x = Expr::var(var);
        system.add_constraint(x.clone(), x.add(Expr::constant(1u64)), zero.clone());
    }

    for i in 0..width {
        let ai = Expr::var(a[i]);
        let bi = Expr::var(b[i]);
        let ci = Expr::var(carry[i]);

        system.add_constraint(
            ai.clone().add(bi.clone()).add(ci.clone()),
            one.clone(),
            Expr::var(sum[i]),
        );
        system.add_constraint(ai.clone(), bi.clone(), Expr::var(p1[i]));
        system.add_constraint(ai, ci.clone(), Expr::var(p2[i]));
        system.add_constraint(bi, ci, Expr::var(p3[i]));
        system.add_constraint(
            Expr::var(p1[i]).add(Expr::var(p2[i])).add(Expr::var(p3[i])),
            one.clone(),
            Expr::var(carry[i + 1]),
        );
    }

    (
        system,
        BitAdderLayout {
            width,
            a,
            b,
            sum,
            carry,
            p1,
            p2,
            p3,
            carry_in,
            num_vars,
        },
    )
}

fn add_boolean_constraint(system: &mut ConstraintSystem, var: VarId) {
    let x = Expr::var(var);
    system.add_constraint(x.clone(), x.add(Expr::constant(1u64)), Expr::constant(0u64));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepOp {
    Add,
    Addi,
    Xor,
    Lui,
    And,
    Or,
    Slt,
    Sltu,
    Slti,
    Sltiu,
    Sub,
    Sll,
    Srl,
    Sra,
    Slli,
    Srli,
    Srai,
    Xori,
    Ori,
    Andi,
}

impl StepOp {
    pub fn index(self) -> usize {
        match self {
            StepOp::Add => 0,
            StepOp::Addi => 1,
            StepOp::Xor => 2,
            StepOp::Lui => 3,
            StepOp::And => 4,
            StepOp::Or => 5,
            StepOp::Slt => 6,
            StepOp::Sltu => 7,
            StepOp::Slti => 8,
            StepOp::Sltiu => 9,
            StepOp::Sub => 10,
            StepOp::Sll => 11,
            StepOp::Srl => 12,
            StepOp::Sra => 13,
            StepOp::Slli => 14,
            StepOp::Srli => 15,
            StepOp::Srai => 16,
            StepOp::Xori => 17,
            StepOp::Ori => 18,
            StepOp::Andi => 19,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            StepOp::Add => "add",
            StepOp::Addi => "addi",
            StepOp::Xor => "xor",
            StepOp::Lui => "lui",
            StepOp::And => "and",
            StepOp::Or => "or",
            StepOp::Slt => "slt",
            StepOp::Sltu => "sltu",
            StepOp::Slti => "slti",
            StepOp::Sltiu => "sltiu",
            StepOp::Sub => "sub",
            StepOp::Sll => "sll",
            StepOp::Srl => "srl",
            StepOp::Sra => "sra",
            StepOp::Slli => "slli",
            StepOp::Srli => "srli",
            StepOp::Srai => "srai",
            StepOp::Xori => "xori",
            StepOp::Ori => "ori",
            StepOp::Andi => "andi",
        }
    }
}

/// Selector-based uniform ALU relation for a small RV64I subset.
///
/// All supported operations share one bit-adder and one set of operand
/// variables. The one-hot selector chooses which result is written to `rd`.
#[derive(Clone, Debug)]
pub struct UniformAluLayout {
    pub width: usize,
    pub adder: BitAdderLayout,
    pub selectors: [VarId; 20],
    pub sub_adder: BitAdderLayout,
    sub_terms: Vec<VarId>,
    shamt_sel: Vec<VarId>,
    shamt_products: Vec<Vec<VarId>>,
    shift: ShiftLayout,
    pub rs2: Vec<VarId>,
    pub imm: Vec<VarId>,
    pub rd: Vec<VarId>,
    pub t: Vec<VarId>,
    pub u: Vec<VarId>,
    pub v: Vec<VarId>,
    and: Vec<VarId>,
    or: Vec<VarId>,
    w: Vec<VarId>,
    z: Vec<VarId>,
    u_imm: Vec<VarId>,
    and_imm: Vec<VarId>,
    w_imm: Vec<VarId>,
    z_imm: Vec<VarId>,
    flip_rs1: VarId,
    flip_rs2: VarId,
    flip_imm: VarId,
    pub unsigned_lt: ComparatorLayout,
    pub signed_lt: ComparatorLayout,
    pub unsigned_lt_imm: ComparatorLayout,
    pub signed_lt_imm: ComparatorLayout,
    compare_terms: [VarId; 4],
    b_add: Vec<VarId>,
    b_addi: Vec<VarId>,
    pub num_vars: usize,
}

/// Named variable groups inside a CPU row witness. These are the
/// component-layout hooks for Virtual Spartan: the runtime can translate
/// `VarId`s into merged-witness offsets and emit Register/RAM/PC claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpuVarKind {
    Rs1,
    Rs2,
    Imm,
    Rd,
    Pc,
    NextPc,
    RamAddr,
    RamValue,
    Target,
    Link,
    ShiftSource,
    ShiftAmount,
    ShiftOutput,
}

#[derive(Clone, Debug)]
pub struct CpuVarGroup {
    pub kind: CpuVarKind,
    pub vars: Vec<VarId>,
}

impl CpuVarGroup {
    /// Whether the group can be represented as one `WitnessLayout` segment.
    /// CPU rows are bit-level allocations, so several groups (e.g. shamt) are
    /// intentionally not power-of-two aligned and cannot become segments
    /// without repacking the witness.
    pub fn is_segment_aligned(&self) -> bool {
        if self.vars.is_empty() || !self.vars.len().is_power_of_two() {
            return false;
        }
        let start = self.vars[0];
        if !start.is_multiple_of(self.vars.len()) {
            return false;
        }
        self.vars.windows(2).all(|pair| pair[0] + 1 == pair[1])
    }
}

impl UniformAluLayout {
    pub fn shift_shamt_vars(&self) -> &[VarId] {
        &self.shamt_sel
    }

    pub fn shift_left_stages(&self) -> &[Vec<VarId>] {
        &self.shift.left_stages
    }

    pub fn shift_left_products(&self) -> &[Vec<VarId>] {
        &self.shift.left_products
    }

    pub fn shift_right_stages(&self) -> &[Vec<VarId>] {
        &self.shift.right_stages
    }

    pub fn shift_right_products(&self) -> &[Vec<VarId>] {
        &self.shift.right_products
    }

    pub fn shift_var_groups(&self) -> Vec<CpuVarGroup> {
        vec![
            CpuVarGroup {
                kind: CpuVarKind::ShiftSource,
                vars: self.adder.a.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::ShiftAmount,
                vars: self.shamt_sel.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::ShiftOutput,
                vars: self.rd.clone(),
            },
        ]
    }

    pub fn var_groups(&self) -> Vec<CpuVarGroup> {
        vec![
            CpuVarGroup {
                kind: CpuVarKind::Rs1,
                vars: self.adder.a.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::Rs2,
                vars: self.rs2.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::Imm,
                vars: self.imm.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::Rd,
                vars: self.rd.clone(),
            },
        ]
    }

    pub fn witness(&self, op: StepOp, rs1: u64, rs2: u64, imm: u64) -> Witness {
        let mut values = vec![F2_128::from(0u64); self.num_vars];
        self.fill_witness(&mut values, op, rs1, rs2, imm);
        Witness::new(values)
    }

    pub fn fill_witness(&self, values: &mut [F2_128], op: StepOp, rs1: u64, rs2: u64, imm: u64) {
        let mask = if self.width >= 64 {
            u64::MAX
        } else {
            (1u64 << self.width) - 1
        };
        let rs1 = rs1 & mask;
        let rs2 = rs2 & mask;
        let imm = imm & mask;
        let b_value = match op {
            StepOp::Add | StepOp::And | StepOp::Or => rs2,
            StepOp::Addi => imm,
            _ => 0,
        };

        self.adder.fill_witness(values, rs1, b_value);
        self.sub_adder.fill_witness(values, rs1, (!rs2) & mask);
        let effective_shamt = match op {
            StepOp::Sll | StepOp::Srl | StepOp::Sra => rs2,
            StepOp::Slli | StepOp::Srli | StepOp::Srai => imm,
            _ => 0,
        };
        for (stage, &selected) in self.shamt_sel.iter().enumerate() {
            values[selected] = F2_128::from((effective_shamt >> stage) & 1);
            let rs2_bit = (rs2 >> stage) & 1;
            let imm_bit = (imm >> stage) & 1;
            let candidates = [
                (op == StepOp::Sll, rs2_bit),
                (op == StepOp::Srl, rs2_bit),
                (op == StepOp::Sra, rs2_bit),
                (op == StepOp::Slli, imm_bit),
                (op == StepOp::Srli, imm_bit),
                (op == StepOp::Srai, imm_bit),
            ];
            for (index, &(active, bit)) in candidates.iter().enumerate() {
                values[self.shamt_products[stage][index]] =
                    F2_128::from(if active { bit } else { 0 });
            }
        }
        self.shift
            .fill(values, self.width, rs1, effective_shamt, op);
        values[self.selectors[op.index()]] = F2_128::from(1u64);
        fill_bits(values, &self.rs2, rs2);
        fill_bits(values, &self.imm, imm);

        let msb = 1u64 << (self.width - 1);
        let lt_unsigned = rs1 < rs2;
        let lt_signed = signed_value(rs1, self.width) < signed_value(rs2, self.width);
        let lt_imm_unsigned = rs1 < imm;
        let lt_imm_signed = signed_value(rs1, self.width) < signed_value(imm, self.width);
        values[self.flip_rs1] = F2_128::from(1u64 ^ ((rs1 >> (self.width - 1)) & 1));
        values[self.flip_rs2] = F2_128::from(1u64 ^ ((rs2 >> (self.width - 1)) & 1));
        values[self.flip_imm] = F2_128::from(1u64 ^ ((imm >> (self.width - 1)) & 1));
        self.unsigned_lt.fill(values, rs1, rs2);
        self.signed_lt.fill(values, rs1 ^ msb, rs2 ^ msb);
        self.unsigned_lt_imm.fill(values, rs1, imm);
        self.signed_lt_imm.fill(values, rs1 ^ msb, imm ^ msb);
        values[self.compare_terms[0]] = F2_128::from(u64::from(op == StepOp::Slt && lt_signed));
        values[self.compare_terms[1]] = F2_128::from(u64::from(op == StepOp::Sltu && lt_unsigned));
        values[self.compare_terms[2]] =
            F2_128::from(u64::from(op == StepOp::Slti && lt_imm_signed));
        values[self.compare_terms[3]] =
            F2_128::from(u64::from(op == StepOp::Sltiu && lt_imm_unsigned));

        let rd_value = match op {
            StepOp::Add => rs1.wrapping_add(rs2) & mask,
            StepOp::Addi => rs1.wrapping_add(imm) & mask,
            StepOp::Xor => (rs1 ^ rs2) & mask,
            StepOp::Lui => imm,
            StepOp::And => rs1 & rs2,
            StepOp::Or => rs1 | rs2,
            StepOp::Slt => u64::from(lt_signed),
            StepOp::Sltu => u64::from(lt_unsigned),
            StepOp::Slti => u64::from(lt_imm_signed),
            StepOp::Sltiu => u64::from(lt_imm_unsigned),
            StepOp::Sub => rs1.wrapping_sub(rs2) & mask,
            StepOp::Sll
            | StepOp::Srl
            | StepOp::Sra
            | StepOp::Slli
            | StepOp::Srli
            | StepOp::Srai => {
                let shamt_mask = if self.shift.stage_count == 0 {
                    0
                } else {
                    (1u64 << self.shift.stage_count) - 1
                };
                let shift_value = match op {
                    StepOp::Sll | StepOp::Srl | StepOp::Sra => rs2,
                    _ => imm,
                };
                let shamt = (shift_value & shamt_mask) as u32;
                match op {
                    StepOp::Sll | StepOp::Slli => (rs1 << shamt) & mask,
                    StepOp::Srl | StepOp::Srli => (rs1 & mask) >> shamt,
                    StepOp::Sra | StepOp::Srai => {
                        ((signed_value(rs1, self.width) >> shamt) as u64) & mask
                    }
                    _ => unreachable!(),
                }
            }
            StepOp::Xori => (rs1 ^ imm) & mask,
            StepOp::Ori => (rs1 | imm) & mask,
            StepOp::Andi => rs1 & imm,
        };
        fill_bits(values, &self.rd, rd_value);

        for i in 0..self.width {
            let a_bit = values[self.adder.a[i]].value() as u64;
            let sum_bit = values[self.adder.sum[i]].value() as u64;
            let rs2_bit = (rs2 >> i) & 1;
            let imm_bit = (imm >> i) & 1;
            let and_bit = a_bit & rs2_bit;
            let or_bit = a_bit | rs2_bit;
            let and_imm_bit = a_bit & imm_bit;
            let or_imm_bit = a_bit | imm_bit;
            values[self.t[i]] = F2_128::from(match op {
                StepOp::Add | StepOp::Addi => sum_bit,
                _ => 0,
            });
            values[self.u[i]] = F2_128::from(match op {
                StepOp::Xor => a_bit ^ rs2_bit,
                _ => 0,
            });
            values[self.v[i]] = F2_128::from(match op {
                StepOp::Lui => imm_bit,
                _ => 0,
            });
            values[self.and[i]] = F2_128::from(and_bit);
            values[self.or[i]] = F2_128::from(or_bit);
            values[self.w[i]] = F2_128::from(match op {
                StepOp::And => and_bit,
                _ => 0,
            });
            values[self.z[i]] = F2_128::from(match op {
                StepOp::Or => or_bit,
                _ => 0,
            });
            values[self.u_imm[i]] = F2_128::from(match op {
                StepOp::Xori => a_bit ^ imm_bit,
                _ => 0,
            });
            values[self.and_imm[i]] = F2_128::from(and_imm_bit);
            values[self.w_imm[i]] = F2_128::from(match op {
                StepOp::Andi => and_imm_bit,
                _ => 0,
            });
            values[self.z_imm[i]] = F2_128::from(match op {
                StepOp::Ori => or_imm_bit,
                _ => 0,
            });
            values[self.b_add[i]] = F2_128::from(match op {
                StepOp::Add | StepOp::And | StepOp::Or => rs2_bit,
                _ => 0,
            });
            values[self.b_addi[i]] = F2_128::from(match op {
                StepOp::Addi => imm_bit,
                _ => 0,
            });
            values[self.sub_terms[i]] = F2_128::from(match op {
                StepOp::Sub => values[self.sub_adder.sum[i]].value() as u64,
                _ => 0,
            });
        }
    }
}

fn fill_bits(values: &mut [F2_128], vars: &[VarId], value: u64) {
    for (index, var) in vars.iter().enumerate() {
        values[*var] = F2_128::from((value >> index) & 1);
    }
}

fn low_mask(width: usize) -> u64 {
    if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    }
}

pub fn uniform_alu_relation(width: usize) -> (ConstraintSystem, UniformAluLayout) {
    assert!(width > 0 && width <= 64);
    let (mut system, adder) = bit_addition_constraints(width);
    let (sub_system, sub_layout) = bit_addition_constraints_with_carry(width, 1);
    let sub_offset = system.merge(sub_system);
    let sub_adder = sub_layout.shifted(sub_offset);
    let selectors_vec: Vec<VarId> = system.alloc(20).collect();
    let selectors: [VarId; 20] = selectors_vec.try_into().expect("twenty selectors");
    let rs2: Vec<VarId> = system.alloc(width).collect();
    let imm: Vec<VarId> = system.alloc(width).collect();
    let rd: Vec<VarId> = system.alloc(width).collect();
    let t: Vec<VarId> = system.alloc(width).collect();
    let u: Vec<VarId> = system.alloc(width).collect();
    let v: Vec<VarId> = system.alloc(width).collect();
    let and: Vec<VarId> = system.alloc(width).collect();
    let or: Vec<VarId> = system.alloc(width).collect();
    let w: Vec<VarId> = system.alloc(width).collect();
    let z: Vec<VarId> = system.alloc(width).collect();
    let u_imm: Vec<VarId> = system.alloc(width).collect();
    let and_imm: Vec<VarId> = system.alloc(width).collect();
    let w_imm: Vec<VarId> = system.alloc(width).collect();
    let z_imm: Vec<VarId> = system.alloc(width).collect();
    let b_add: Vec<VarId> = system.alloc(width).collect();
    let b_addi: Vec<VarId> = system.alloc(width).collect();
    let flip_rs1 = system.alloc(1).start;
    let flip_rs2 = system.alloc(1).start;
    let flip_imm = system.alloc(1).start;
    let compare_terms_vec: Vec<VarId> = system.alloc(4).collect();
    let compare_terms: [VarId; 4] = compare_terms_vec.try_into().expect("four compare terms");
    let sub_terms: Vec<VarId> = system.alloc(width).collect();
    let one = Expr::constant(1u64);

    for &selector in &selectors {
        add_boolean_constraint(&mut system, selector);
    }
    for &var in rs2.iter().chain(imm.iter()).chain(rd.iter()) {
        add_boolean_constraint(&mut system, var);
    }

    let selector_sum = selectors
        .iter()
        .fold(Expr::constant(0u64), |acc, &var| acc.add(Expr::var(var)));
    system.add_constraint(selector_sum, one.clone(), one.clone());

    let s_add = Expr::var(selectors[0]);
    let s_addi = Expr::var(selectors[1]);
    let s_xor = Expr::var(selectors[2]);
    let s_lui = Expr::var(selectors[3]);
    let s_and = Expr::var(selectors[4]);
    let s_or = Expr::var(selectors[5]);
    let s_slt = Expr::var(selectors[6]);
    let s_sltu = Expr::var(selectors[7]);
    let s_slti = Expr::var(selectors[8]);
    let s_sltiu = Expr::var(selectors[9]);
    let s_sub = Expr::var(selectors[10]);
    let s_sll = Expr::var(selectors[11]);
    let s_srl = Expr::var(selectors[12]);
    let s_sra = Expr::var(selectors[13]);
    let s_slli = Expr::var(selectors[14]);
    let s_srli = Expr::var(selectors[15]);
    let s_srai = Expr::var(selectors[16]);
    let s_xori = Expr::var(selectors[17]);
    let s_ori = Expr::var(selectors[18]);
    let s_andi = Expr::var(selectors[19]);
    let use_adder = s_add.clone().add(s_addi.clone());
    let use_rs2 = s_add.clone().add(s_and.clone()).add(s_or.clone());

    system.add_constraint(
        Expr::var(adder.a[width - 1]).add(Expr::constant(1u64)),
        one.clone(),
        Expr::var(flip_rs1),
    );
    system.add_constraint(
        Expr::var(rs2[width - 1]).add(Expr::constant(1u64)),
        one.clone(),
        Expr::var(flip_rs2),
    );
    system.add_constraint(
        Expr::var(imm[width - 1]).add(Expr::constant(1u64)),
        one.clone(),
        Expr::var(flip_imm),
    );
    let mut signed_rs1 = adder.a.clone();
    let mut signed_rs2 = rs2.clone();
    let mut signed_imm = imm.clone();
    signed_rs1[width - 1] = flip_rs1;
    signed_rs2[width - 1] = flip_rs2;
    signed_imm[width - 1] = flip_imm;
    let unsigned_lt = add_unsigned_comparator(&mut system, &adder.a, &rs2, &one);
    let signed_lt = add_unsigned_comparator(&mut system, &signed_rs1, &signed_rs2, &one);
    let unsigned_lt_imm = add_unsigned_comparator(&mut system, &adder.a, &imm, &one);
    let signed_lt_imm = add_unsigned_comparator(&mut system, &signed_rs1, &signed_imm, &one);
    system.add_constraint(
        s_slt,
        Expr::var(signed_lt.less),
        Expr::var(compare_terms[0]),
    );
    system.add_constraint(
        s_sltu,
        Expr::var(unsigned_lt.less),
        Expr::var(compare_terms[1]),
    );
    system.add_constraint(
        s_slti,
        Expr::var(signed_lt_imm.less),
        Expr::var(compare_terms[2]),
    );
    system.add_constraint(
        s_sltiu,
        Expr::var(unsigned_lt_imm.less),
        Expr::var(compare_terms[3]),
    );

    let stage_count = if width <= 1 {
        0
    } else {
        (usize::BITS - (width - 1).leading_zeros()) as usize
    };
    let shamt_sel: Vec<VarId> = system.alloc(stage_count).collect();
    let mut shamt_products = Vec::with_capacity(stage_count);
    for (stage, &selected) in shamt_sel.iter().enumerate() {
        let mut sum = Expr::constant(0u64);
        let mut products = Vec::with_capacity(6);
        let candidates = [
            (s_sll.clone(), rs2[stage]),
            (s_srl.clone(), rs2[stage]),
            (s_sra.clone(), rs2[stage]),
            (s_slli.clone(), imm[stage]),
            (s_srli.clone(), imm[stage]),
            (s_srai.clone(), imm[stage]),
        ];
        for (selector, bit) in candidates {
            let product = system.alloc(1).start;
            system.add_constraint(selector, Expr::var(bit), Expr::var(product));
            sum = sum.add(Expr::var(product));
            products.push(product);
        }
        system.add_constraint(sum, one.clone(), Expr::var(selected));
        shamt_products.push(products);
    }
    let s_left = s_sll.clone().add(s_slli.clone());
    let s_right = s_srl
        .clone()
        .add(s_sra.clone())
        .add(s_srli.clone())
        .add(s_srai.clone());
    let s_arith = s_sra.clone().add(s_srai.clone());
    let shift = add_shift_layout(
        &mut system,
        width,
        &adder.a,
        &shamt_sel,
        &s_left,
        &s_right,
        &s_arith,
        &one,
    );

    for i in 0..width {
        let a_i = Expr::var(adder.a[i]);
        let sum_i = Expr::var(adder.sum[i]);
        let rs2_i = Expr::var(rs2[i]);
        let imm_i = Expr::var(imm[i]);

        system.add_constraint(use_rs2.clone(), rs2_i.clone(), Expr::var(b_add[i]));
        system.add_constraint(s_addi.clone(), imm_i.clone(), Expr::var(b_addi[i]));
        system.add_constraint(
            Expr::var(b_add[i]).add(Expr::var(b_addi[i])),
            one.clone(),
            Expr::var(adder.b[i]),
        );
        system.add_constraint(use_adder.clone(), sum_i, Expr::var(t[i]));
        system.add_constraint(
            s_xor.clone(),
            a_i.clone().add(rs2_i.clone()),
            Expr::var(u[i]),
        );
        system.add_constraint(s_lui.clone(), imm_i.clone(), Expr::var(v[i]));
        system.add_constraint(a_i.clone(), rs2_i.clone(), Expr::var(and[i]));
        system.add_constraint(
            a_i.clone().add(rs2_i).add(Expr::var(and[i])),
            one.clone(),
            Expr::var(or[i]),
        );
        system.add_constraint(s_and.clone(), Expr::var(and[i]), Expr::var(w[i]));
        system.add_constraint(s_or.clone(), Expr::var(or[i]), Expr::var(z[i]));
        system.add_constraint(
            s_xori.clone(),
            a_i.clone().add(imm_i.clone()),
            Expr::var(u_imm[i]),
        );
        system.add_constraint(a_i.clone(), imm_i.clone(), Expr::var(and_imm[i]));
        system.add_constraint(s_andi.clone(), Expr::var(and_imm[i]), Expr::var(w_imm[i]));
        system.add_constraint(
            s_ori.clone(),
            a_i.clone().add(imm_i.clone()).add(Expr::var(and_imm[i])),
            Expr::var(z_imm[i]),
        );
        system.add_constraint(
            Expr::var(sub_adder.a[i]),
            one.clone(),
            Expr::var(adder.a[i]),
        );
        system.add_constraint(
            Expr::var(sub_adder.b[i]),
            one.clone(),
            Expr::constant(1u64).add(Expr::var(rs2[i])),
        );
        system.add_constraint(
            s_sub.clone(),
            Expr::var(sub_adder.sum[i]),
            Expr::var(sub_terms[i]),
        );
        let mut result = Expr::var(t[i])
            .add(Expr::var(u[i]))
            .add(Expr::var(v[i]))
            .add(Expr::var(w[i]))
            .add(Expr::var(z[i]))
            .add(Expr::var(u_imm[i]))
            .add(Expr::var(w_imm[i]))
            .add(Expr::var(z_imm[i]))
            .add(Expr::var(sub_terms[i]))
            .add(Expr::var(shift.rd_terms[i][0]))
            .add(Expr::var(shift.rd_terms[i][1]));
        if i == 0 {
            for &term in &compare_terms {
                result = result.add(Expr::var(term));
            }
        }
        system.add_constraint(result, one.clone(), Expr::var(rd[i]));
    }

    let num_vars = system.num_vars;
    (
        system,
        UniformAluLayout {
            width,
            adder,
            selectors,
            sub_adder,
            sub_terms,
            shamt_sel,
            shamt_products,
            shift,
            rs2,
            imm,
            rd,
            t,
            u,
            v,
            and,
            or,
            w,
            z,
            u_imm,
            and_imm,
            w_imm,
            z_imm,
            flip_rs1,
            flip_rs2,
            flip_imm,
            unsigned_lt,
            signed_lt,
            unsigned_lt_imm,
            signed_lt_imm,
            compare_terms,
            b_add,
            b_addi,
            num_vars,
        },
    )
}

/// Uniform ALU plus a second bit-adder that enforces `next_pc = pc + 4`.
#[derive(Clone, Debug)]
pub struct UniformStepLayout {
    pub width: usize,
    pub alu: UniformAluLayout,
    pub pc_adder: BitAdderLayout,
    pub num_vars: usize,
}

impl UniformStepLayout {
    pub fn var_groups(&self) -> Vec<CpuVarGroup> {
        let mut groups = self.alu.var_groups();
        groups.push(CpuVarGroup {
            kind: CpuVarKind::Pc,
            vars: self.pc_adder.a.clone(),
        });
        groups.push(CpuVarGroup {
            kind: CpuVarKind::NextPc,
            vars: self.pc_adder.sum.clone(),
        });
        groups
    }

    pub fn witness(&self, op: StepOp, pc: u64, rs1: u64, rs2: u64, imm: u64) -> Witness {
        let mut values = vec![F2_128::from(0u64); self.num_vars];
        self.alu.fill_witness(&mut values, op, rs1, rs2, imm);
        self.pc_adder.fill_witness(&mut values, pc, 4);
        Witness::new(values)
    }
}

pub fn uniform_step_relation(width: usize) -> (ConstraintSystem, UniformStepLayout) {
    assert!(width > 0 && width <= 64);
    let (mut system, alu) = uniform_alu_relation(width);
    let (pc_system, pc_layout) = bit_addition_constraints(width);
    let offset = system.merge(pc_system);
    let pc_adder = pc_layout.shifted(offset);
    let one = Expr::constant(1u64);
    for index in 0..width {
        let expected = if index == 2 { 1u64 } else { 0 };
        system.add_constraint(
            Expr::var(pc_adder.b[index]),
            one.clone(),
            Expr::constant(expected),
        );
    }
    let num_vars = system.num_vars;
    (
        system,
        UniformStepLayout {
            width,
            alu,
            pc_adder,
            num_vars,
        },
    )
}

/// Unconditional jump relation: `next_pc = pc + imm`, `link = pc + 4`.
#[derive(Clone, Debug)]
pub struct UniformJalLayout {
    pub width: usize,
    pub link: BitAdderLayout,
    pub target: BitAdderLayout,
    pub link_increment: u64,
    pub next: Vec<VarId>,
    pub rd: Vec<VarId>,
    pub num_vars: usize,
}

impl UniformJalLayout {
    pub fn var_groups(&self) -> Vec<CpuVarGroup> {
        vec![
            CpuVarGroup {
                kind: CpuVarKind::Pc,
                vars: self.link.a.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::Link,
                vars: self.link.sum.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::Target,
                vars: self.target.sum.clone(),
            },
        ]
    }

    pub fn witness(&self, pc: u64, imm: u64) -> Witness {
        let mut values = vec![F2_128::from(0u64); self.num_vars];
        self.link.fill_witness(&mut values, pc, self.link_increment);
        self.target.fill_witness(&mut values, pc, imm);
        for (bit, var) in self.next.iter().enumerate() {
            values[*var] = F2_128::from((pc.wrapping_add(imm) >> bit) & 1);
        }
        for (bit, var) in self.rd.iter().enumerate() {
            values[*var] = F2_128::from((pc.wrapping_add(self.link_increment) >> bit) & 1);
        }
        Witness::new(values)
    }
}

pub fn uniform_jal_layout(
    width: usize,
    link_increment: u64,
) -> (ConstraintSystem, UniformJalLayout) {
    uniform_jal_inner(width, 0, 0, link_increment, false)
}

pub fn uniform_jal_relation(
    width: usize,
    pc: u64,
    imm: u64,
) -> (ConstraintSystem, UniformJalLayout) {
    uniform_jal_relation_with_increment(width, pc, imm, 4)
}

pub fn uniform_jal_relation_with_increment(
    width: usize,
    pc: u64,
    imm: u64,
    link_increment: u64,
) -> (ConstraintSystem, UniformJalLayout) {
    uniform_jal_inner(width, pc, imm, link_increment, true)
}

fn uniform_jal_inner(
    width: usize,
    pc: u64,
    imm: u64,
    link_increment: u64,
    pin: bool,
) -> (ConstraintSystem, UniformJalLayout) {
    assert!(width > 0 && width <= 64);
    let (mut system, link) = bit_addition_constraints(width);
    let (target_system, target_layout) = bit_addition_constraints(width);
    let offset = system.merge(target_system);
    let target = target_layout.shifted(offset);
    let one = Expr::constant(1u64);
    for index in 0..width {
        let expected = (link_increment >> index) & 1;
        system.add_constraint(
            Expr::var(link.b[index]),
            one.clone(),
            Expr::constant(expected),
        );
        if pin {
            system.add_constraint(
                Expr::var(link.a[index]),
                one.clone(),
                Expr::constant((pc >> index) & 1),
            );
            system.add_constraint(
                Expr::var(target.a[index]),
                one.clone(),
                Expr::constant((pc >> index) & 1),
            );
            system.add_constraint(
                Expr::var(target.b[index]),
                one.clone(),
                Expr::constant((imm >> index) & 1),
            );
        }
    }
    let next: Vec<VarId> = system.alloc(width).collect();
    let rd: Vec<VarId> = system.alloc(width).collect();
    for index in 0..width {
        system.add_constraint(
            Expr::var(next[index]),
            one.clone(),
            Expr::var(target.sum[index]),
        );
        system.add_constraint(
            Expr::var(rd[index]),
            one.clone(),
            Expr::var(link.sum[index]),
        );
    }
    let num_vars = system.num_vars;
    (
        system,
        UniformJalLayout {
            width,
            link,
            target,
            link_increment,
            next,
            rd,
            num_vars,
        },
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BranchOp {
    Beq,
    Bne,
    Blt,
    Bge,
    Bltu,
    Bgeu,
}

impl BranchOp {
    fn index(self) -> usize {
        match self {
            BranchOp::Beq => 0,
            BranchOp::Bne => 1,
            BranchOp::Blt => 2,
            BranchOp::Bge => 3,
            BranchOp::Bltu => 4,
            BranchOp::Bgeu => 5,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            BranchOp::Beq => "beq",
            BranchOp::Bne => "bne",
            BranchOp::Blt => "blt",
            BranchOp::Bge => "bge",
            BranchOp::Bltu => "bltu",
            BranchOp::Bgeu => "bgeu",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ComparatorLayout {
    pub prefix: Vec<VarId>,
    pub a_lt: Vec<VarId>,
    pub selected: Vec<VarId>,
    pub less: VarId,
}

impl ComparatorLayout {
    fn fill(&self, values: &mut [F2_128], a_value: u64, b_value: u64) {
        self.fill_wide(values, u128::from(a_value), u128::from(b_value));
    }

    fn fill_wide(&self, values: &mut [F2_128], a_value: u128, b_value: u128) {
        let width = self.prefix.len();
        values[self.prefix[0]] = F2_128::from(1u64);
        let mut prefix = 1u64;
        let mut less = 0u64;
        for step in 0..width {
            let bit = width - 1 - step;
            let a_bit = ((a_value >> bit) & 1) as u64;
            let b_bit = ((b_value >> bit) & 1) as u64;
            let a_less = (1 ^ a_bit) & b_bit;
            let selected = prefix & a_less;
            values[self.a_lt[step]] = F2_128::from(a_less);
            values[self.selected[step]] = F2_128::from(selected);
            less |= selected;
            if step + 1 < width {
                prefix &= 1 ^ (a_bit ^ b_bit);
                values[self.prefix[step + 1]] = F2_128::from(prefix);
            }
        }
        values[self.less] = F2_128::from(less);
    }
}

#[derive(Clone, Debug)]
struct ShiftLayout {
    stage_count: usize,
    left_stages: Vec<Vec<VarId>>,
    right_stages: Vec<Vec<VarId>>,
    left_products: Vec<Vec<VarId>>,
    right_products: Vec<Vec<VarId>>,
    fill: VarId,
    left_result: Vec<VarId>,
    right_result: Vec<VarId>,
    rd_terms: Vec<[VarId; 2]>,
}

impl ShiftLayout {
    fn fill(&self, values: &mut [F2_128], width: usize, rs1: u64, shamt: u64, op: StepOp) {
        let sign = (rs1 >> (width - 1)) & 1;
        let fill = if matches!(op, StepOp::Sra | StepOp::Srai) {
            sign
        } else {
            0
        };
        values[self.fill] = F2_128::from(fill);
        let mut left = (0..width).map(|bit| (rs1 >> bit) & 1).collect::<Vec<_>>();
        let mut right = left.clone();

        for stage in 0..self.stage_count {
            let shift = 1usize << stage;
            let shamt_bit = (shamt >> stage) & 1;
            let mut next_left = vec![0u64; width];
            let mut next_right = vec![0u64; width];
            for bit in 0..width {
                let source_left = if bit >= shift { left[bit - shift] } else { 0 };
                next_left[bit] = if shamt_bit == 1 {
                    source_left
                } else {
                    left[bit]
                };
                values[self.left_stages[stage][bit]] = F2_128::from(next_left[bit]);
                values[self.left_products[stage][bit]] = F2_128::from(if shamt_bit == 1 {
                    source_left ^ left[bit]
                } else {
                    0
                });

                let source_right = if bit + shift < width {
                    right[bit + shift]
                } else {
                    fill
                };
                next_right[bit] = if shamt_bit == 1 {
                    source_right
                } else {
                    right[bit]
                };
                values[self.right_stages[stage][bit]] = F2_128::from(next_right[bit]);
                values[self.right_products[stage][bit]] = F2_128::from(if shamt_bit == 1 {
                    source_right ^ right[bit]
                } else {
                    0
                });
            }
            left = next_left;
            right = next_right;
        }

        for bit in 0..width {
            values[self.rd_terms[bit][0]] = F2_128::from(match op {
                StepOp::Sll | StepOp::Slli => self.left_value(values, bit),
                _ => 0,
            });
            values[self.rd_terms[bit][1]] = F2_128::from(match op {
                StepOp::Srl | StepOp::Sra | StepOp::Srli | StepOp::Srai => {
                    self.right_value(values, bit)
                }
                _ => 0,
            });
        }
    }

    fn left_value(&self, values: &[F2_128], bit: usize) -> u64 {
        values[self.left_result[bit]].value() as u64 & 1
    }

    fn right_value(&self, values: &[F2_128], bit: usize) -> u64 {
        values[self.right_result[bit]].value() as u64 & 1
    }
}

#[allow(clippy::too_many_arguments)]
fn add_shift_layout(
    system: &mut ConstraintSystem,
    width: usize,
    rs1: &[VarId],
    shamt_bits: &[VarId],
    s_left: &Expr,
    s_right: &Expr,
    s_arith: &Expr,
    one: &Expr,
) -> ShiftLayout {
    let stage_count = if width <= 1 {
        0
    } else {
        (usize::BITS - (width - 1).leading_zeros()) as usize
    };
    let fill = system.alloc(1).start;
    system.add_constraint(s_arith.clone(), Expr::var(rs1[width - 1]), Expr::var(fill));

    let mut left = rs1.to_vec();
    let mut right = rs1.to_vec();
    let mut left_stages = Vec::with_capacity(stage_count);
    let mut right_stages = Vec::with_capacity(stage_count);
    let mut left_products = Vec::with_capacity(stage_count);
    let mut right_products = Vec::with_capacity(stage_count);

    for (stage, &shamt_bit) in shamt_bits.iter().enumerate().take(stage_count) {
        let shift = 1usize << stage;
        let mut next_left = Vec::with_capacity(width);
        let mut next_right = Vec::with_capacity(width);
        let mut products_left = Vec::with_capacity(width);
        let mut products_right = Vec::with_capacity(width);
        for bit in 0..width {
            let source_left = if bit >= shift {
                Expr::var(left[bit - shift])
            } else {
                Expr::constant(0u64)
            };
            let product_left = system.alloc(1).start;
            system.add_constraint(
                Expr::var(shamt_bit),
                source_left.add(Expr::var(left[bit])),
                Expr::var(product_left),
            );
            let next_left_bit = system.alloc(1).start;
            system.add_constraint(
                Expr::var(left[bit]).add(Expr::var(product_left)),
                one.clone(),
                Expr::var(next_left_bit),
            );
            products_left.push(product_left);
            next_left.push(next_left_bit);

            let source_right = if bit + shift < width {
                Expr::var(right[bit + shift])
            } else {
                Expr::var(fill)
            };
            let product_right = system.alloc(1).start;
            system.add_constraint(
                Expr::var(shamt_bit),
                source_right.add(Expr::var(right[bit])),
                Expr::var(product_right),
            );
            let next_right_bit = system.alloc(1).start;
            system.add_constraint(
                Expr::var(right[bit]).add(Expr::var(product_right)),
                one.clone(),
                Expr::var(next_right_bit),
            );
            products_right.push(product_right);
            next_right.push(next_right_bit);
        }
        left_stages.push(next_left.clone());
        right_stages.push(next_right.clone());
        left_products.push(products_left);
        right_products.push(products_right);
        left = next_left;
        right = next_right;
    }

    let left_result = left;
    let right_result = right;
    let mut rd_terms = Vec::with_capacity(width);
    for bit in 0..width {
        let left_term = system.alloc(1).start;
        system.add_constraint(
            s_left.clone(),
            Expr::var(left_result[bit]),
            Expr::var(left_term),
        );
        let right_term = system.alloc(1).start;
        system.add_constraint(
            s_right.clone(),
            Expr::var(right_result[bit]),
            Expr::var(right_term),
        );
        rd_terms.push([left_term, right_term]);
    }

    ShiftLayout {
        stage_count,
        left_stages,
        right_stages,
        left_products,
        right_products,
        fill,
        left_result,
        right_result,
        rd_terms,
    }
}

fn add_unsigned_comparator(
    system: &mut ConstraintSystem,
    a: &[VarId],
    b: &[VarId],
    one: &Expr,
) -> ComparatorLayout {
    let width = a.len();
    assert_eq!(width, b.len());
    let prefix: Vec<VarId> = system.alloc(width).collect();
    let a_lt: Vec<VarId> = system.alloc(width).collect();
    let selected: Vec<VarId> = system.alloc(width).collect();
    let less = system.alloc(1).start;

    system.add_constraint(Expr::var(prefix[0]), one.clone(), one.clone());
    for step in 0..width {
        let bit = width - 1 - step;
        system.add_constraint(
            Expr::var(b[bit]),
            Expr::constant(1u64).add(Expr::var(a[bit])),
            Expr::var(a_lt[step]),
        );
        system.add_constraint(
            Expr::var(prefix[step]),
            Expr::var(a_lt[step]),
            Expr::var(selected[step]),
        );
        if step + 1 < width {
            system.add_constraint(
                Expr::var(prefix[step]),
                Expr::constant(1u64)
                    .add(Expr::var(a[bit]))
                    .add(Expr::var(b[bit])),
                Expr::var(prefix[step + 1]),
            );
        }
    }
    let selected_sum = selected
        .iter()
        .fold(Expr::constant(0u64), |sum, &var| sum.add(Expr::var(var)));
    system.add_constraint(selected_sum, one.clone(), Expr::var(less));

    ComparatorLayout {
        prefix,
        a_lt,
        selected,
        less,
    }
}

fn add_and_tree(system: &mut ConstraintSystem, leaves: &[VarId]) -> (VarId, Vec<Vec<VarId>>) {
    let mut levels = vec![leaves.to_vec()];
    while levels.last().expect("leaf level").len() > 1 {
        let current = levels.last().expect("level").clone();
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        for pair in current.chunks(2) {
            if pair.len() == 1 {
                next.push(pair[0]);
            } else {
                let output = system.alloc(1).start;
                system.add_constraint(Expr::var(pair[0]), Expr::var(pair[1]), Expr::var(output));
                next.push(output);
            }
        }
        levels.push(next);
    }
    (
        levels
            .last()
            .expect("root")
            .first()
            .copied()
            .expect("nonempty"),
        levels,
    )
}

/// Conditional branch `beq`: `next_pc = rs1 == rs2 ? pc + imm : pc + 4`.
#[derive(Clone, Debug)]
pub struct UniformBeqLayout {
    pub width: usize,
    pub link: BitAdderLayout,
    pub target: BitAdderLayout,
    pub rs1: Vec<VarId>,
    pub rs2: Vec<VarId>,
    pub same: Vec<VarId>,
    pub next_pc: Vec<VarId>,
    eq: VarId,
    mux: Vec<VarId>,
    tree_levels: Vec<Vec<VarId>>,
    pub num_vars: usize,
}

impl UniformBeqLayout {
    pub fn witness(&self, pc: u64, rs1: u64, rs2: u64, imm: u64) -> Witness {
        let mut values = vec![F2_128::from(0u64); self.num_vars];
        self.link.fill_witness(&mut values, pc, 4);
        self.target.fill_witness(&mut values, pc, imm);
        fill_bits(&mut values, &self.rs1, rs1);
        fill_bits(&mut values, &self.rs2, rs2);
        for index in 0..self.width {
            let equal = (rs1 >> index) & 1 == (rs2 >> index) & 1;
            values[self.same[index]] = F2_128::from(u64::from(equal));
        }
        for level in 1..self.tree_levels.len() {
            let previous = &self.tree_levels[level - 1];
            for (index, output) in self.tree_levels[level].iter().enumerate() {
                let left = previous[index * 2];
                let right = if index * 2 + 1 < previous.len() {
                    previous[index * 2 + 1]
                } else {
                    left
                };
                values[*output] =
                    F2_128::from((values[left].value() & 1) & (values[right].value() & 1));
            }
        }
        let eq = (values[self.eq].value() & 1) as u64;
        for index in 0..self.width {
            let link = (values[self.link.sum[index]].value() & 1) as u64;
            let target = (values[self.target.sum[index]].value() & 1) as u64;
            let mux = eq & (target ^ link);
            values[self.mux[index]] = F2_128::from(mux);
            values[self.next_pc[index]] = F2_128::from(link ^ mux);
        }
        Witness::new(values)
    }
}

pub fn uniform_beq_relation(
    width: usize,
    pc: u64,
    imm: u64,
) -> (ConstraintSystem, UniformBeqLayout) {
    assert!(width > 0 && width <= 64);
    let (mut system, link) = bit_addition_constraints(width);
    let (target_system, target_layout) = bit_addition_constraints(width);
    let offset = system.merge(target_system);
    let target = target_layout.shifted(offset);

    let rs1: Vec<VarId> = system.alloc(width).collect();
    let rs2: Vec<VarId> = system.alloc(width).collect();
    let same: Vec<VarId> = system.alloc(width).collect();
    let mux: Vec<VarId> = system.alloc(width).collect();
    let next_pc: Vec<VarId> = system.alloc(width).collect();
    let one = Expr::constant(1u64);

    for index in 0..width {
        let expected = if index == 2 { 1u64 } else { 0 };
        system.add_constraint(
            Expr::var(link.b[index]),
            one.clone(),
            Expr::constant(expected),
        );
        system.add_constraint(
            Expr::var(link.a[index]),
            one.clone(),
            Expr::constant((pc >> index) & 1),
        );
        system.add_constraint(
            Expr::var(target.a[index]),
            one.clone(),
            Expr::constant((pc >> index) & 1),
        );
        system.add_constraint(
            Expr::var(target.b[index]),
            one.clone(),
            Expr::constant((imm >> index) & 1),
        );
        add_boolean_constraint(&mut system, rs1[index]);
        add_boolean_constraint(&mut system, rs2[index]);
        add_boolean_constraint(&mut system, same[index]);
        add_boolean_constraint(&mut system, next_pc[index]);
    }

    for index in 0..width {
        system.add_constraint(
            Expr::constant(1u64)
                .add(Expr::var(rs1[index]))
                .add(Expr::var(rs2[index])),
            one.clone(),
            Expr::var(same[index]),
        );
    }

    let (eq, tree_levels) = add_and_tree(&mut system, &same);
    for index in 0..width {
        system.add_constraint(
            Expr::var(eq),
            Expr::var(target.sum[index]).add(Expr::var(link.sum[index])),
            Expr::var(mux[index]),
        );
        system.add_constraint(
            Expr::var(link.sum[index]).add(Expr::var(mux[index])),
            one.clone(),
            Expr::var(next_pc[index]),
        );
    }
    let num_vars = system.num_vars;
    (
        system,
        UniformBeqLayout {
            width,
            link,
            target,
            rs1,
            rs2,
            same,
            next_pc,
            eq,
            mux,
            tree_levels,
            num_vars,
        },
    )
}

fn fill_and_tree(values: &mut [F2_128], levels: &[Vec<VarId>]) {
    for level in 1..levels.len() {
        let previous = &levels[level - 1];
        for (index, output) in levels[level].iter().enumerate() {
            let left = previous[index * 2];
            let right = if index * 2 + 1 < previous.len() {
                previous[index * 2 + 1]
            } else {
                left
            };
            values[*output] =
                F2_128::from((values[left].value() & 1) & (values[right].value() & 1));
        }
    }
}

fn signed_value(value: u64, width: usize) -> i64 {
    let masked = if width >= 64 {
        value
    } else {
        value & ((1u64 << width) - 1)
    };
    let shift = 64 - width;
    ((masked << shift) as i64) >> shift
}

#[derive(Clone, Debug)]
pub struct UniformBranchLayout {
    pub width: usize,
    pub link: BitAdderLayout,
    pub target: BitAdderLayout,
    pub rs1: Vec<VarId>,
    pub rs2: Vec<VarId>,
    pub same: Vec<VarId>,
    pub unsigned_lt: ComparatorLayout,
    pub signed_lt: ComparatorLayout,
    pub selectors: [VarId; 6],
    pub next_pc: Vec<VarId>,
    flip1: VarId,
    flip2: VarId,
    mux: Vec<VarId>,
    cond_terms: Vec<VarId>,
    tree_levels: Vec<Vec<VarId>>,
    pub num_vars: usize,
}

impl UniformBranchLayout {
    pub fn var_groups(&self) -> Vec<CpuVarGroup> {
        vec![
            CpuVarGroup {
                kind: CpuVarKind::Rs1,
                vars: self.rs1.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::Rs2,
                vars: self.rs2.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::Pc,
                vars: self.link.a.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::NextPc,
                vars: self.next_pc.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::Target,
                vars: self.target.sum.clone(),
            },
        ]
    }

    pub fn witness(&self, op: BranchOp, pc: u64, rs1: u64, rs2: u64, imm: u64) -> Witness {
        let mask = if self.width >= 64 {
            u64::MAX
        } else {
            (1u64 << self.width) - 1
        };
        let rs1 = rs1 & mask;
        let rs2 = rs2 & mask;
        let imm = imm & mask;
        let msb = 1u64 << (self.width - 1);

        let mut values = vec![F2_128::from(0u64); self.num_vars];
        self.link.fill_witness(&mut values, pc, 4);
        self.target.fill_witness(&mut values, pc, imm);
        fill_bits(&mut values, &self.rs1, rs1);
        fill_bits(&mut values, &self.rs2, rs2);
        values[self.flip1] = F2_128::from(1u64 ^ ((rs1 >> (self.width - 1)) & 1));
        values[self.flip2] = F2_128::from(1u64 ^ ((rs2 >> (self.width - 1)) & 1));
        for index in 0..self.width {
            let equal = (rs1 >> index) & 1 == (rs2 >> index) & 1;
            values[self.same[index]] = F2_128::from(u64::from(equal));
        }
        fill_and_tree(&mut values, &self.tree_levels);
        self.unsigned_lt.fill(&mut values, rs1, rs2);
        self.signed_lt.fill(&mut values, rs1 ^ msb, rs2 ^ msb);

        let eq = u64::from(rs1 == rs2);
        let lt_unsigned = u64::from(rs1 < rs2);
        let lt_signed = u64::from(signed_value(rs1, self.width) < signed_value(rs2, self.width));
        let condition = match op {
            BranchOp::Beq => eq,
            BranchOp::Bne => 1 ^ eq,
            BranchOp::Blt => lt_signed,
            BranchOp::Bge => 1 ^ lt_signed,
            BranchOp::Bltu => lt_unsigned,
            BranchOp::Bgeu => 1 ^ lt_unsigned,
        };
        values[self.selectors[op.index()]] = F2_128::from(1u64);
        for (index, &term) in self.cond_terms.iter().enumerate() {
            values[term] = F2_128::from(u64::from(index == op.index() && condition == 1));
        }
        for index in 0..self.width {
            let link = (values[self.link.sum[index]].value() & 1) as u64;
            let target = (values[self.target.sum[index]].value() & 1) as u64;
            let mux = condition & (target ^ link);
            values[self.mux[index]] = F2_128::from(mux);
            values[self.next_pc[index]] = F2_128::from(link ^ mux);
        }
        Witness::new(values)
    }
}

pub fn uniform_branch_layout(width: usize) -> (ConstraintSystem, UniformBranchLayout) {
    uniform_branch_inner(width, 0, 0, false)
}

pub fn uniform_branch_relation(
    width: usize,
    pc: u64,
    imm: u64,
) -> (ConstraintSystem, UniformBranchLayout) {
    uniform_branch_inner(width, pc, imm, true)
}

fn uniform_branch_inner(
    width: usize,
    pc: u64,
    imm: u64,
    pin: bool,
) -> (ConstraintSystem, UniformBranchLayout) {
    assert!(width > 0 && width <= 64);
    let (mut system, link) = bit_addition_constraints(width);
    let (target_system, target_layout) = bit_addition_constraints(width);
    let offset = system.merge(target_system);
    let target = target_layout.shifted(offset);

    let rs1: Vec<VarId> = system.alloc(width).collect();
    let rs2: Vec<VarId> = system.alloc(width).collect();
    let same: Vec<VarId> = system.alloc(width).collect();
    let selectors_vec: Vec<VarId> = system.alloc(6).collect();
    let selectors: [VarId; 6] = selectors_vec.try_into().expect("six selectors");
    let cond_terms: Vec<VarId> = system.alloc(6).collect();
    let mux: Vec<VarId> = system.alloc(width).collect();
    let next_pc: Vec<VarId> = system.alloc(width).collect();
    let one = Expr::constant(1u64);

    for index in 0..width {
        let expected = if index == 2 { 1u64 } else { 0 };
        system.add_constraint(
            Expr::var(link.b[index]),
            one.clone(),
            Expr::constant(expected),
        );
        if pin {
            system.add_constraint(
                Expr::var(link.a[index]),
                one.clone(),
                Expr::constant((pc >> index) & 1),
            );
            system.add_constraint(
                Expr::var(target.a[index]),
                one.clone(),
                Expr::constant((pc >> index) & 1),
            );
            system.add_constraint(
                Expr::var(target.b[index]),
                one.clone(),
                Expr::constant((imm >> index) & 1),
            );
        }
        add_boolean_constraint(&mut system, rs1[index]);
        add_boolean_constraint(&mut system, rs2[index]);
        add_boolean_constraint(&mut system, same[index]);
        add_boolean_constraint(&mut system, next_pc[index]);
    }
    for &selector in &selectors {
        add_boolean_constraint(&mut system, selector);
    }
    let selector_sum = selectors
        .iter()
        .fold(Expr::constant(0u64), |sum, &var| sum.add(Expr::var(var)));
    system.add_constraint(selector_sum, one.clone(), one.clone());

    for index in 0..width {
        system.add_constraint(
            Expr::constant(1u64)
                .add(Expr::var(rs1[index]))
                .add(Expr::var(rs2[index])),
            one.clone(),
            Expr::var(same[index]),
        );
    }
    let (eq, tree_levels) = add_and_tree(&mut system, &same);

    let flip1 = system.alloc(1).start;
    let flip2 = system.alloc(1).start;
    system.add_constraint(
        Expr::var(rs1[width - 1]).add(Expr::constant(1u64)),
        one.clone(),
        Expr::var(flip1),
    );
    system.add_constraint(
        Expr::var(rs2[width - 1]).add(Expr::constant(1u64)),
        one.clone(),
        Expr::var(flip2),
    );
    let mut signed1 = rs1.clone();
    let mut signed2 = rs2.clone();
    signed1[width - 1] = flip1;
    signed2[width - 1] = flip2;

    let unsigned_lt = add_unsigned_comparator(&mut system, &rs1, &rs2, &one);
    let signed_lt = add_unsigned_comparator(&mut system, &signed1, &signed2, &one);

    let s_beq = Expr::var(selectors[0]);
    let s_bne = Expr::var(selectors[1]);
    let s_blt = Expr::var(selectors[2]);
    let s_bge = Expr::var(selectors[3]);
    let s_bltu = Expr::var(selectors[4]);
    let s_bgeu = Expr::var(selectors[5]);
    let lt_unsigned = Expr::var(unsigned_lt.less);
    let lt_signed = Expr::var(signed_lt.less);

    system.add_constraint(s_beq, Expr::var(eq), Expr::var(cond_terms[0]));
    system.add_constraint(
        s_bne,
        Expr::constant(1u64).add(Expr::var(eq)),
        Expr::var(cond_terms[1]),
    );
    system.add_constraint(s_blt, lt_signed.clone(), Expr::var(cond_terms[2]));
    system.add_constraint(
        s_bge,
        Expr::constant(1u64).add(lt_signed),
        Expr::var(cond_terms[3]),
    );
    system.add_constraint(s_bltu, lt_unsigned.clone(), Expr::var(cond_terms[4]));
    system.add_constraint(
        s_bgeu,
        Expr::constant(1u64).add(lt_unsigned),
        Expr::var(cond_terms[5]),
    );
    let condition = cond_terms
        .iter()
        .fold(Expr::constant(0u64), |sum, &var| sum.add(Expr::var(var)));

    for index in 0..width {
        system.add_constraint(
            condition.clone(),
            Expr::var(target.sum[index]).add(Expr::var(link.sum[index])),
            Expr::var(mux[index]),
        );
        system.add_constraint(
            Expr::var(link.sum[index]).add(Expr::var(mux[index])),
            one.clone(),
            Expr::var(next_pc[index]),
        );
    }

    let num_vars = system.num_vars;
    (
        system,
        UniformBranchLayout {
            width,
            link,
            target,
            rs1,
            rs2,
            same,
            unsigned_lt,
            signed_lt,
            selectors,
            next_pc,
            flip1,
            flip2,
            mux,
            cond_terms,
            tree_levels,
            num_vars,
        },
    )
}

/// Load relation for a fixed statement `(addr, value)`.
///
/// Proves that `rs1 + imm = addr` and that the loaded `rd` equals `value`.
/// The caller binds `value` to a committed memory table via a PCS opening.
#[derive(Clone, Debug)]
pub struct UniformLoadLayout {
    pub width: usize,
    pub adder: BitAdderLayout,
    pub rd: Vec<VarId>,
    pub addr: u64,
    pub value: u64,
    pub num_vars: usize,
}

impl UniformLoadLayout {
    pub fn var_groups(&self) -> Vec<CpuVarGroup> {
        vec![
            CpuVarGroup {
                kind: CpuVarKind::Rs1,
                vars: self.adder.a.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::Imm,
                vars: self.adder.b.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::RamAddr,
                vars: self.adder.sum.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::Rd,
                vars: self.rd.clone(),
            },
        ]
    }

    pub fn witness(&self, rs1: u64, imm: u64) -> Witness {
        let mut values = vec![F2_128::from(0u64); self.num_vars];
        self.adder.fill_witness(&mut values, rs1, imm);
        fill_bits(&mut values, &self.rd, self.value);
        Witness::new(values)
    }
}

pub fn uniform_load_relation(
    width: usize,
    addr: u64,
    value: u64,
) -> (ConstraintSystem, UniformLoadLayout) {
    assert!(width > 0 && width <= 64);
    let (mut system, adder) = bit_addition_constraints(width);
    let rd: Vec<VarId> = system.alloc(width).collect();
    let one = Expr::constant(1u64);
    for (index, &rd_var) in rd.iter().enumerate() {
        let addr_bit = (addr >> index) & 1;
        system.add_constraint(
            Expr::var(adder.sum[index]),
            one.clone(),
            Expr::constant(addr_bit),
        );
        let value_bit = (value >> index) & 1;
        system.add_constraint(Expr::var(rd_var), one.clone(), Expr::constant(value_bit));
    }
    let num_vars = system.num_vars;
    (
        system,
        UniformLoadLayout {
            width,
            adder,
            rd,
            addr,
            value,
            num_vars,
        },
    )
}

/// Store relation for a fixed statement `(addr, new_value)`.
#[derive(Clone, Debug)]
pub struct UniformStoreLayout {
    pub width: usize,
    pub adder: BitAdderLayout,
    pub rs2: Vec<VarId>,
    pub addr: u64,
    pub new_value: u64,
    pub num_vars: usize,
}

impl UniformStoreLayout {
    pub fn var_groups(&self) -> Vec<CpuVarGroup> {
        vec![
            CpuVarGroup {
                kind: CpuVarKind::Rs1,
                vars: self.adder.a.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::Imm,
                vars: self.adder.b.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::RamAddr,
                vars: self.adder.sum.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::RamValue,
                vars: self.rs2.clone(),
            },
        ]
    }

    pub fn witness(&self, rs1: u64, imm: u64) -> Witness {
        let mut values = vec![F2_128::from(0u64); self.num_vars];
        self.adder.fill_witness(&mut values, rs1, imm);
        fill_bits(&mut values, &self.rs2, self.new_value);
        Witness::new(values)
    }
}

pub fn uniform_store_relation(
    width: usize,
    addr: u64,
    new_value: u64,
) -> (ConstraintSystem, UniformStoreLayout) {
    assert!(width > 0 && width <= 64);
    let (mut system, adder) = bit_addition_constraints(width);
    let rs2: Vec<VarId> = system.alloc(width).collect();
    let one = Expr::constant(1u64);
    for (index, &rs2_var) in rs2.iter().enumerate() {
        let addr_bit = (addr >> index) & 1;
        system.add_constraint(
            Expr::var(adder.sum[index]),
            one.clone(),
            Expr::constant(addr_bit),
        );
        let value_bit = (new_value >> index) & 1;
        system.add_constraint(Expr::var(rs2_var), one.clone(), Expr::constant(value_bit));
    }
    let num_vars = system.num_vars;
    (
        system,
        UniformStoreLayout {
            width,
            adder,
            rs2,
            addr,
            new_value,
            num_vars,
        },
    )
}

/// `auipc`: `rd = pc + imm`.
#[derive(Clone, Debug)]
pub struct UniformAuipcLayout {
    pub width: usize,
    pub adder: BitAdderLayout,
    pub pc: u64,
    pub value: u64,
    pub value_out: Vec<VarId>,
    pub num_vars: usize,
}

impl UniformAuipcLayout {
    pub fn witness(&self, imm: u64) -> Witness {
        self.witness_at(self.pc, imm)
    }

    pub fn witness_at(&self, pc: u64, imm: u64) -> Witness {
        let mut values = vec![F2_128::from(0u64); self.num_vars];
        self.adder.fill_witness(&mut values, pc, imm);
        for (bit, var) in self.value_out.iter().enumerate() {
            values[*var] = F2_128::from((pc.wrapping_add(imm) >> bit) & 1);
        }
        Witness::new(values)
    }
}

pub fn uniform_auipc_layout(width: usize) -> (ConstraintSystem, UniformAuipcLayout) {
    uniform_auipc_inner(width, 0, 0, false)
}

pub fn uniform_auipc_relation(
    width: usize,
    pc: u64,
    value: u64,
) -> (ConstraintSystem, UniformAuipcLayout) {
    uniform_auipc_inner(width, pc, value, true)
}

fn uniform_auipc_inner(
    width: usize,
    pc: u64,
    value: u64,
    pin: bool,
) -> (ConstraintSystem, UniformAuipcLayout) {
    assert!(width > 0 && width <= 64);
    let (mut system, adder) = bit_addition_constraints(width);
    let one = Expr::constant(1u64);
    for index in 0..width {
        let pc_bit = (pc >> index) & 1;
        let value_bit = (value >> index) & 1;
        if pin {
            system.add_constraint(
                Expr::var(adder.a[index]),
                one.clone(),
                Expr::constant(pc_bit),
            );
            system.add_constraint(
                Expr::var(adder.sum[index]),
                one.clone(),
                Expr::constant(value_bit),
            );
        }
    }
    let value_out: Vec<VarId> = system.alloc(width).collect();
    for (index, &var) in value_out.iter().enumerate() {
        system.add_constraint(Expr::var(var), one.clone(), Expr::var(adder.sum[index]));
    }
    let num_vars = system.num_vars;
    (
        system,
        UniformAuipcLayout {
            width,
            adder,
            pc,
            value,
            value_out,
            num_vars,
        },
    )
}

/// `jalr`: `target = (rs1 + imm) & !1`, `link = pc + 4`.
#[derive(Clone, Debug)]
pub struct UniformJalrLayout {
    pub width: usize,
    pub target_adder: BitAdderLayout,
    pub link_adder: BitAdderLayout,
    pub target: u64,
    pub link: u64,
    pub pc: u64,
    pub link_increment: u64,
    pub num_vars: usize,
}

impl UniformJalrLayout {
    pub fn var_groups(&self) -> Vec<CpuVarGroup> {
        vec![
            CpuVarGroup {
                kind: CpuVarKind::Rs1,
                vars: self.target_adder.a.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::Imm,
                vars: self.target_adder.b.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::Pc,
                vars: self.link_adder.a.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::Target,
                vars: self.target_adder.sum.clone(),
            },
            CpuVarGroup {
                kind: CpuVarKind::Link,
                vars: self.link_adder.sum.clone(),
            },
        ]
    }

    pub fn witness(&self, rs1: u64, imm: u64) -> Witness {
        let mut values = vec![F2_128::from(0u64); self.num_vars];
        self.target_adder.fill_witness(&mut values, rs1, imm);
        self.link_adder
            .fill_witness(&mut values, self.pc, self.link_increment);
        Witness::new(values)
    }
}

pub fn uniform_jalr_relation(
    width: usize,
    target: u64,
    link: u64,
    pc: u64,
) -> (ConstraintSystem, UniformJalrLayout) {
    uniform_jalr_relation_with_increment(width, target, link, pc, 4)
}

pub fn uniform_jalr_relation_with_increment(
    width: usize,
    target: u64,
    link: u64,
    pc: u64,
    link_increment: u64,
) -> (ConstraintSystem, UniformJalrLayout) {
    assert!(width > 0 && width <= 64);
    assert_eq!(target & 1, 0, "jalr target must be even");
    let (mut system, target_adder) = bit_addition_constraints(width);
    let (link_system, link_layout) = bit_addition_constraints(width);
    let offset = system.merge(link_system);
    let link_adder = link_layout.shifted(offset);
    let one = Expr::constant(1u64);
    for index in 0..width {
        let target_bit = (target >> index) & 1;
        let link_bit = (link >> index) & 1;
        let pc_bit = (pc >> index) & 1;
        if index != 0 {
            system.add_constraint(
                Expr::var(target_adder.sum[index]),
                one.clone(),
                Expr::constant(target_bit),
            );
        }
        system.add_constraint(
            Expr::var(link_adder.sum[index]),
            one.clone(),
            Expr::constant(link_bit),
        );
        system.add_constraint(
            Expr::var(link_adder.a[index]),
            one.clone(),
            Expr::constant(pc_bit),
        );
        system.add_constraint(
            Expr::var(link_adder.b[index]),
            one.clone(),
            Expr::constant((link_increment >> index) & 1),
        );
    }
    let num_vars = system.num_vars;
    (
        system,
        UniformJalrLayout {
            width,
            target_adder,
            link_adder,
            target,
            link,
            pc,
            link_increment,
            num_vars,
        },
    )
}

/// Shift-and-add multiplication over a width-bit word.
#[derive(Clone, Debug)]
pub struct UniformMulLayout {
    pub width: usize,
    pub rs1: Vec<VarId>,
    pub rs2: Vec<VarId>,
    pub partial_products: Vec<Vec<VarId>>,
    pub adders: Vec<BitAdderLayout>,
    pub rd: Vec<VarId>,
    pub num_vars: usize,
}

impl UniformMulLayout {
    pub fn witness(&self, a: u64, b: u64) -> Witness {
        let mut values = vec![F2_128::from(0u64); self.num_vars];
        self.fill_witness(&mut values, a, b);
        Witness::new(values)
    }

    fn fill_witness(&self, values: &mut [F2_128], a: u64, b: u64) {
        let mask = if self.width >= 64 {
            u64::MAX
        } else {
            (1u64 << self.width) - 1
        };
        let a = a & mask;
        let b = b & mask;
        fill_bits(values, &self.rs1, a);
        fill_bits(values, &self.rs2, b);

        let mut accumulated = 0u64;
        for (index, partial) in self.partial_products.iter().enumerate() {
            let mut product = 0u64;
            for (bit, &var) in partial.iter().enumerate() {
                let value = ((a >> bit) & 1) & ((b >> index) & 1);
                values[var] = F2_128::from(value);
                product |= value << (bit + index);
            }
            if index > 0 {
                self.adders[index - 1].fill_witness(values, accumulated, product);
            }
            accumulated = accumulated.wrapping_add(product) & mask;
        }
    }
}

pub fn uniform_mul_relation(width: usize) -> (ConstraintSystem, UniformMulLayout) {
    assert!(width > 0 && width <= 64);
    let mut system = ConstraintSystem::new(0);
    let rs1: Vec<VarId> = system.alloc(width).collect();
    let rs2: Vec<VarId> = system.alloc(width).collect();
    for &var in rs1.iter().chain(rs2.iter()) {
        add_boolean_constraint(&mut system, var);
    }

    let mut partial_products = Vec::with_capacity(width);
    for (index, &rs2_bit) in rs2.iter().enumerate() {
        let partial: Vec<VarId> = system.alloc(width - index).collect();
        for (bit, &product) in partial.iter().enumerate() {
            system.add_constraint(Expr::var(rs1[bit]), Expr::var(rs2_bit), Expr::var(product));
        }
        partial_products.push(partial);
    }

    let mut adders = Vec::with_capacity(width.saturating_sub(1));
    let mut accumulated = partial_products[0].clone();
    let one = Expr::constant(1u64);
    for index in 1..width {
        let (adder_system, adder_layout) = bit_addition_constraints(width);
        let offset = system.merge(adder_system);
        let adder = adder_layout.shifted(offset);
        for bit in 0..width {
            system.add_constraint(
                Expr::var(adder.a[bit]),
                one.clone(),
                Expr::var(accumulated[bit]),
            );
            let shifted = if bit >= index {
                Expr::var(partial_products[index][bit - index])
            } else {
                Expr::constant(0u64)
            };
            system.add_constraint(Expr::var(adder.b[bit]), one.clone(), shifted);
        }
        accumulated = adder.sum.clone();
        adders.push(adder);
    }

    let num_vars = system.num_vars;
    (
        system,
        UniformMulLayout {
            width,
            rs1,
            rs2,
            partial_products,
            adders,
            rd: accumulated,
            num_vars,
        },
    )
}

pub fn uniform_mul_row_relation(
    width: usize,
    rs1: u64,
    rs2: u64,
    rd: u64,
) -> (ConstraintSystem, UniformMulLayout) {
    let (mut system, layout) = uniform_mul_relation(width);
    let one = Expr::constant(1u64);
    for bit in 0..width {
        system.add_constraint(
            Expr::var(layout.rs1[bit]),
            one.clone(),
            Expr::constant((rs1 >> bit) & 1),
        );
        system.add_constraint(
            Expr::var(layout.rs2[bit]),
            one.clone(),
            Expr::constant((rs2 >> bit) & 1),
        );
        system.add_constraint(
            Expr::var(layout.rd[bit]),
            one.clone(),
            Expr::constant((rd >> bit) & 1),
        );
    }
    (system, layout)
}

/// Full `2w`-bit product of two `w`-bit words, used by the high-half ops.
#[derive(Clone, Debug)]
pub struct UniformFullMulLayout {
    pub width: usize,
    pub rs1: Vec<VarId>,
    pub rs2: Vec<VarId>,
    pub partial_products: Vec<Vec<VarId>>,
    pub adders: Vec<BitAdderLayout>,
    initial: Vec<VarId>,
    pub product: Vec<VarId>,
    pub num_vars: usize,
}

impl UniformFullMulLayout {
    pub fn witness(&self, a: u64, b: u64) -> Witness {
        let mut values = vec![F2_128::from(0u64); self.num_vars];
        self.fill_witness(&mut values, a, b);
        Witness::new(values)
    }

    fn fill_witness(&self, values: &mut [F2_128], a: u64, b: u64) {
        let mask = if self.width >= 64 {
            u128::from(u64::MAX)
        } else {
            (1u128 << self.width) - 1
        };
        let a = u128::from(a) & mask;
        let b = u128::from(b) & mask;
        fill_bits(values, &self.rs1, a as u64);
        fill_bits(values, &self.rs2, b as u64);
        for (bit, &var) in self.initial.iter().enumerate() {
            let value = if bit < self.width {
                ((a >> bit) & 1) & (b & 1)
            } else {
                0
            };
            values[var] = F2_128::from(value as u64);
        }

        let mut accumulated = 0u128;
        for (index, partial) in self.partial_products.iter().enumerate() {
            let mut product = 0u128;
            for (bit, &var) in partial.iter().enumerate() {
                let value = ((a >> bit) & 1) & ((b >> index) & 1);
                values[var] = F2_128::from(value as u64);
                product |= value << (bit + index);
            }
            if index > 0 {
                self.adders[index - 1].fill_witness_wide(values, accumulated, product);
            }
            accumulated = accumulated.wrapping_add(product);
        }
    }
}

pub fn uniform_full_mul_relation(width: usize) -> (ConstraintSystem, UniformFullMulLayout) {
    assert!(width > 0 && width <= 64);
    let mut system = ConstraintSystem::new(0);
    let rs1: Vec<VarId> = system.alloc(width).collect();
    let rs2: Vec<VarId> = system.alloc(width).collect();
    for &var in rs1.iter().chain(rs2.iter()) {
        add_boolean_constraint(&mut system, var);
    }

    let mut partial_products = Vec::with_capacity(width);
    for &rs2_bit in &rs2 {
        let partial: Vec<VarId> = system.alloc(width).collect();
        for (bit, &product) in partial.iter().enumerate() {
            system.add_constraint(Expr::var(rs1[bit]), Expr::var(rs2_bit), Expr::var(product));
        }
        partial_products.push(partial);
    }

    let product_bits = width * 2;
    let initial: Vec<VarId> = system.alloc(product_bits).collect();
    let one = Expr::constant(1u64);
    for (bit, &var) in initial.iter().enumerate() {
        let value = if bit < width {
            Expr::var(partial_products[0][bit])
        } else {
            Expr::constant(0u64)
        };
        system.add_constraint(Expr::var(var), one.clone(), value);
    }

    let mut adders = Vec::with_capacity(width.saturating_sub(1));
    let mut accumulated = initial.clone();
    for index in 1..width {
        let (adder_system, adder_layout) = bit_addition_constraints(product_bits);
        let offset = system.merge(adder_system);
        let adder = adder_layout.shifted(offset);
        for bit in 0..product_bits {
            system.add_constraint(
                Expr::var(adder.a[bit]),
                one.clone(),
                Expr::var(accumulated[bit]),
            );
            let shifted = if bit >= index && bit - index < width {
                Expr::var(partial_products[index][bit - index])
            } else {
                Expr::constant(0u64)
            };
            system.add_constraint(Expr::var(adder.b[bit]), one.clone(), shifted);
        }
        accumulated = adder.sum.clone();
        adders.push(adder);
    }

    let num_vars = system.num_vars;
    (
        system,
        UniformFullMulLayout {
            width,
            rs1,
            rs2,
            partial_products,
            adders,
            initial,
            product: accumulated,
            num_vars,
        },
    )
}

/// High-half multiplication: `mulhu`, `mulh`, or `mulhsu`.
#[derive(Clone, Debug)]
pub struct UniformMulHighLayout {
    pub width: usize,
    pub rs1: Vec<VarId>,
    pub rs2: Vec<VarId>,
    signed_left: bool,
    signed_right: bool,
    pub full: UniformFullMulLayout,
    corrections: Vec<Vec<VarId>>,
    subtractors: Vec<BitAdderLayout>,
    pub rd: Vec<VarId>,
    pub num_vars: usize,
}

impl UniformMulHighLayout {
    pub fn witness(&self, a: u64, b: u64) -> Witness {
        let mut values = vec![F2_128::from(0u64); self.num_vars];
        self.fill_witness(&mut values, a, b);
        Witness::new(values)
    }

    fn fill_witness(&self, values: &mut [F2_128], a: u64, b: u64) {
        self.full.fill_witness(values, a, b);
        let mask = if self.width >= 64 {
            u64::MAX
        } else {
            (1u64 << self.width) - 1
        };
        let a = a & mask;
        let b = b & mask;
        let a_sign = (a >> (self.width - 1)) & 1;
        let b_sign = (b >> (self.width - 1)) & 1;
        let mut correction_index = 0;
        if self.signed_left {
            for (bit, &var) in self.corrections[correction_index].iter().enumerate() {
                values[var] = F2_128::from(a_sign & ((b >> bit) & 1));
            }
            correction_index += 1;
        }
        if self.signed_right {
            for (bit, &var) in self.corrections[correction_index].iter().enumerate() {
                values[var] = F2_128::from(b_sign & ((a >> bit) & 1));
            }
        }

        let mut remaining = 0u64;
        for (bit, &var) in self.full.product[self.width..].iter().enumerate() {
            remaining |= (values[var].value() as u64 & 1) << bit;
        }

        let mut correction_values = Vec::with_capacity(self.corrections.len());
        for correction in &self.corrections {
            let mut value = 0u64;
            for (bit, &var) in correction.iter().enumerate() {
                let bit_value = values[var].value() as u64 & 1;
                value |= bit_value << bit;
            }
            correction_values.push(value);
        }
        for (adder, correction) in self.subtractors.iter().zip(correction_values) {
            let negated = (!correction) & mask;
            adder.fill_witness(values, remaining, negated);
            remaining = remaining.wrapping_add(negated).wrapping_add(1) & mask;
        }
    }
}

pub fn uniform_mulhu_relation(width: usize) -> (ConstraintSystem, UniformFullMulLayout) {
    uniform_full_mul_relation(width)
}

pub fn uniform_mulh_relation(
    width: usize,
    signed_left: bool,
    signed_right: bool,
) -> (ConstraintSystem, UniformMulHighLayout) {
    let (mut system, full) = uniform_full_mul_relation(width);
    let one = Expr::constant(1u64);
    let mut remaining: Vec<VarId> = full.product[width..].to_vec();
    let mut corrections = Vec::new();
    let mut subtractors = Vec::new();

    let mut correction_terms = Vec::new();
    if signed_left {
        correction_terms.push((full.rs1[width - 1], full.rs2.clone()));
    }
    if signed_right {
        correction_terms.push((full.rs2[width - 1], full.rs1.clone()));
    }
    for (sign, operand) in correction_terms {
        let correction: Vec<VarId> = system.alloc(width).collect();
        for (bit, &var) in correction.iter().enumerate() {
            system.add_constraint(Expr::var(sign), Expr::var(operand[bit]), Expr::var(var));
        }
        corrections.push(correction);
    }

    for correction in &corrections {
        let (adder_system, adder_layout) = bit_addition_constraints_with_carry(width, 1);
        let offset = system.merge(adder_system);
        let adder = adder_layout.shifted(offset);
        for bit in 0..width {
            system.add_constraint(
                Expr::var(adder.a[bit]),
                one.clone(),
                Expr::var(remaining[bit]),
            );
            system.add_constraint(
                Expr::var(adder.b[bit]),
                one.clone(),
                Expr::constant(1u64).add(Expr::var(correction[bit])),
            );
        }
        remaining = adder.sum.clone();
        subtractors.push(adder);
    }

    let num_vars = system.num_vars;
    (
        system,
        UniformMulHighLayout {
            width,
            rs1: full.rs1.clone(),
            rs2: full.rs2.clone(),
            signed_left,
            signed_right,
            full,
            corrections,
            subtractors,
            rd: remaining,
            num_vars,
        },
    )
}
pub fn uniform_mulhu_row_relation(
    width: usize,
    rs1: u64,
    rs2: u64,
    rd: u64,
) -> (ConstraintSystem, UniformFullMulLayout) {
    let (mut system, layout) = uniform_mulhu_relation(width);
    let one = Expr::constant(1u64);
    for bit in 0..width {
        system.add_constraint(
            Expr::var(layout.rs1[bit]),
            one.clone(),
            Expr::constant((rs1 >> bit) & 1),
        );
        system.add_constraint(
            Expr::var(layout.rs2[bit]),
            one.clone(),
            Expr::constant((rs2 >> bit) & 1),
        );
        system.add_constraint(
            Expr::var(layout.product[width + bit]),
            one.clone(),
            Expr::constant((rd >> bit) & 1),
        );
    }
    (system, layout)
}

pub fn uniform_mulh_row_relation(
    width: usize,
    signed_left: bool,
    signed_right: bool,
    rs1: u64,
    rs2: u64,
    rd: u64,
) -> (ConstraintSystem, UniformMulHighLayout) {
    let (mut system, layout) = uniform_mulh_relation(width, signed_left, signed_right);
    let one = Expr::constant(1u64);
    for bit in 0..width {
        system.add_constraint(
            Expr::var(layout.rs1[bit]),
            one.clone(),
            Expr::constant((rs1 >> bit) & 1),
        );
        system.add_constraint(
            Expr::var(layout.rs2[bit]),
            one.clone(),
            Expr::constant((rs2 >> bit) & 1),
        );
        system.add_constraint(
            Expr::var(layout.rd[bit]),
            one.clone(),
            Expr::constant((rd >> bit) & 1),
        );
    }
    (system, layout)
}

#[derive(Clone, Debug)]
struct DivStage {
    bit: usize,
    shifted: Vec<VarId>,
    comparator: ComparatorLayout,
    subtractor: BitAdderLayout,
    mux: Vec<VarId>,
    next_remainder: Vec<VarId>,
    quotient_bit: VarId,
}

/// Unsigned long division, producing quotient and remainder.
#[derive(Clone, Debug)]
pub struct UniformDivLayout {
    pub width: usize,
    pub dividend: Vec<VarId>,
    pub divisor: Vec<VarId>,
    pub quotient: Vec<VarId>,
    pub remainder: Vec<VarId>,
    divisor_extended: Vec<VarId>,
    stages: Vec<DivStage>,
    pub num_vars: usize,
}

impl UniformDivLayout {
    pub fn witness(&self, dividend: u64, divisor: u64) -> Witness {
        let mut values = vec![F2_128::from(0u64); self.num_vars];
        self.fill_witness(&mut values, dividend, divisor);
        Witness::new(values)
    }

    fn fill_witness(&self, values: &mut [F2_128], dividend: u64, divisor: u64) {
        let mask = if self.width >= 64 {
            u64::MAX
        } else {
            (1u64 << self.width) - 1
        };
        let extended_mask = (1u128 << (self.width + 1)) - 1;
        let dividend = dividend & mask;
        let divisor = divisor & mask;
        fill_bits(values, &self.dividend, dividend);
        fill_bits(values, &self.divisor, divisor);
        for (bit, &var) in self.divisor_extended.iter().enumerate() {
            values[var] = F2_128::from(if bit < self.width {
                (divisor >> bit) & 1
            } else {
                0
            });
        }

        let mut remainder = 0u128;
        for stage in &self.stages {
            let shifted =
                ((remainder << 1) | u128::from((dividend >> stage.bit) & 1)) & extended_mask;
            for (bit, &var) in stage.shifted.iter().enumerate() {
                values[var] = F2_128::from(((shifted >> bit) & 1) as u64);
            }
            stage
                .comparator
                .fill_wide(values, shifted, u128::from(divisor));
            let negated = (!u128::from(divisor)) & extended_mask;
            stage.subtractor.fill_witness_wide(values, shifted, negated);
            let ge = u64::from(shifted >= u128::from(divisor));
            let difference = shifted.wrapping_sub(u128::from(divisor)) & extended_mask;
            let mut next = 0u128;
            for bit in 0..=self.width {
                let shifted_bit = ((shifted >> bit) & 1) as u64;
                let difference_bit = ((difference >> bit) & 1) as u64;
                let mux = ge & (difference_bit ^ shifted_bit);
                let new_bit = shifted_bit ^ mux;
                values[stage.mux[bit]] = F2_128::from(mux);
                values[stage.next_remainder[bit]] = F2_128::from(new_bit);
                next |= u128::from(new_bit) << bit;
            }
            values[stage.quotient_bit] = F2_128::from(ge);
            remainder = next;
        }
    }
}

pub fn uniform_div_relation(width: usize) -> (ConstraintSystem, UniformDivLayout) {
    assert!(width > 0 && width <= 64);
    let mut system = ConstraintSystem::new(0);
    let dividend: Vec<VarId> = system.alloc(width).collect();
    let divisor: Vec<VarId> = system.alloc(width).collect();
    for &var in dividend.iter().chain(divisor.iter()) {
        add_boolean_constraint(&mut system, var);
    }

    let zero = system.alloc(1).start;
    let one = Expr::constant(1u64);
    system.add_constraint(Expr::var(zero), one.clone(), Expr::constant(0u64));
    let divisor_extended: Vec<VarId> = system.alloc(width + 1).collect();
    for (bit, &var) in divisor_extended.iter().enumerate() {
        let value = if bit < width {
            Expr::var(divisor[bit])
        } else {
            Expr::constant(0u64)
        };
        system.add_constraint(Expr::var(var), one.clone(), value);
    }

    let mut remainder: Vec<VarId> = vec![zero; width + 1];
    let mut quotient = vec![0; width];
    let mut stages = Vec::with_capacity(width);
    for step in 0..width {
        let bit = width - 1 - step;
        let mut shifted = Vec::with_capacity(width + 1);
        shifted.push(dividend[bit]);
        shifted.extend_from_slice(&remainder[..width]);
        let comparator = add_unsigned_comparator(&mut system, &shifted, &divisor_extended, &one);
        let ge = Expr::constant(1u64).add(Expr::var(comparator.less));

        let (subtractor_system, subtractor_layout) =
            bit_addition_constraints_with_carry(width + 1, 1);
        let offset = system.merge(subtractor_system);
        let subtractor = subtractor_layout.shifted(offset);
        for k in 0..=width {
            system.add_constraint(
                Expr::var(subtractor.a[k]),
                one.clone(),
                Expr::var(shifted[k]),
            );
            system.add_constraint(
                Expr::var(subtractor.b[k]),
                one.clone(),
                Expr::constant(1u64).add(Expr::var(divisor_extended[k])),
            );
        }

        let mux: Vec<VarId> = system.alloc(width + 1).collect();
        let next_remainder: Vec<VarId> = system.alloc(width + 1).collect();
        for k in 0..=width {
            system.add_constraint(
                ge.clone(),
                Expr::var(subtractor.sum[k]).add(Expr::var(shifted[k])),
                Expr::var(mux[k]),
            );
            system.add_constraint(
                Expr::var(shifted[k]).add(Expr::var(mux[k])),
                one.clone(),
                Expr::var(next_remainder[k]),
            );
        }
        let quotient_bit = system.alloc(1).start;
        system.add_constraint(Expr::var(quotient_bit), one.clone(), ge);
        quotient[bit] = quotient_bit;
        remainder = next_remainder.clone();
        stages.push(DivStage {
            bit,
            shifted,
            comparator,
            subtractor,
            mux,
            next_remainder,
            quotient_bit,
        });
    }
    system.add_constraint(
        Expr::var(remainder[width]),
        one.clone(),
        Expr::constant(0u64),
    );

    let num_vars = system.num_vars;
    (
        system,
        UniformDivLayout {
            width,
            dividend,
            divisor,
            quotient,
            remainder: remainder[..width].to_vec(),
            divisor_extended,
            stages,
            num_vars,
        },
    )
}

pub fn uniform_divu_row_relation(
    width: usize,
    dividend: u64,
    divisor: u64,
    quotient: u64,
) -> (ConstraintSystem, UniformDivLayout) {
    let (mut system, layout) = uniform_div_relation(width);
    let one = Expr::constant(1u64);
    for bit in 0..width {
        system.add_constraint(
            Expr::var(layout.dividend[bit]),
            one.clone(),
            Expr::constant((dividend >> bit) & 1),
        );
        system.add_constraint(
            Expr::var(layout.divisor[bit]),
            one.clone(),
            Expr::constant((divisor >> bit) & 1),
        );
        system.add_constraint(
            Expr::var(layout.quotient[bit]),
            one.clone(),
            Expr::constant((quotient >> bit) & 1),
        );
    }
    (system, layout)
}

pub fn uniform_remu_row_relation(
    width: usize,
    dividend: u64,
    divisor: u64,
    remainder: u64,
) -> (ConstraintSystem, UniformDivLayout) {
    let (mut system, layout) = uniform_div_relation(width);
    let one = Expr::constant(1u64);
    for bit in 0..width {
        system.add_constraint(
            Expr::var(layout.dividend[bit]),
            one.clone(),
            Expr::constant((dividend >> bit) & 1),
        );
        system.add_constraint(
            Expr::var(layout.divisor[bit]),
            one.clone(),
            Expr::constant((divisor >> bit) & 1),
        );
        system.add_constraint(
            Expr::var(layout.remainder[bit]),
            one.clone(),
            Expr::constant((remainder >> bit) & 1),
        );
    }
    (system, layout)
}

#[derive(Clone, Debug)]
struct NegateLayout {
    adder: BitAdderLayout,
    mux: Vec<VarId>,
    output: Vec<VarId>,
}

impl NegateLayout {
    fn fill(&self, values: &mut [F2_128], input: u64, sign: u64) {
        let width = self.output.len();
        let mask = low_mask(width);
        let input = input & mask;
        let negated = ((!input) & mask).wrapping_add(1) & mask;
        self.adder.fill_witness(values, (!input) & mask, 0);
        for bit in 0..width {
            let input_bit = (input >> bit) & 1;
            let negated_bit = (negated >> bit) & 1;
            let mux = sign & (input_bit ^ negated_bit);
            values[self.mux[bit]] = F2_128::from(mux);
            values[self.output[bit]] = F2_128::from(input_bit ^ mux);
        }
    }
}

fn add_conditional_negate(
    system: &mut ConstraintSystem,
    input: &[VarId],
    sign: VarId,
    one: &Expr,
) -> NegateLayout {
    let width = input.len();
    let (adder_system, adder_layout) = bit_addition_constraints_with_carry(width, 1);
    let offset = system.merge(adder_system);
    let adder = adder_layout.shifted(offset);
    for (bit, &input_bit) in input.iter().enumerate() {
        system.add_constraint(
            Expr::var(adder.a[bit]),
            one.clone(),
            Expr::constant(1u64).add(Expr::var(input_bit)),
        );
        system.add_constraint(Expr::var(adder.b[bit]), one.clone(), Expr::constant(0u64));
    }
    let mux: Vec<VarId> = system.alloc(width).collect();
    let output: Vec<VarId> = system.alloc(width).collect();
    for (bit, &input_bit) in input.iter().enumerate() {
        system.add_constraint(
            Expr::var(sign),
            Expr::var(input_bit).add(Expr::var(adder.sum[bit])),
            Expr::var(mux[bit]),
        );
        system.add_constraint(
            Expr::var(input_bit).add(Expr::var(mux[bit])),
            one.clone(),
            Expr::var(output[bit]),
        );
    }
    NegateLayout { adder, mux, output }
}

fn witness_value(values: &[F2_128], vars: &[VarId]) -> u64 {
    vars.iter().enumerate().fold(0u64, |value, (index, var)| {
        value | ((values[*var].value() as u64 & 1) << index)
    })
}

fn absolute_value(value: u64, width: usize) -> u64 {
    let mask = low_mask(width);
    let sign = (value >> (width - 1)) & 1;
    if sign == 1 {
        ((!value) & mask).wrapping_add(1) & mask
    } else {
        value & mask
    }
}

#[derive(Clone, Debug)]
pub struct UniformSignedDivLayout {
    pub width: usize,
    pub rs1: Vec<VarId>,
    pub rs2: Vec<VarId>,
    pub quotient: Vec<VarId>,
    pub remainder: Vec<VarId>,
    unsigned: UniformDivLayout,
    abs_dividend: NegateLayout,
    abs_divisor: NegateLayout,
    quotient_negate: NegateLayout,
    remainder_negate: NegateLayout,
    quotient_sign: VarId,
    inverted_divisor: Vec<VarId>,
    and_levels: Vec<Vec<VarId>>,
    divisor_zero: VarId,
    quotient_zero_mux: Vec<VarId>,
    remainder_zero_mux: Vec<VarId>,
    pub num_vars: usize,
}

impl UniformSignedDivLayout {
    pub fn witness(&self, dividend: u64, divisor: u64) -> Witness {
        let mut values = vec![F2_128::from(0u64); self.num_vars];
        self.fill_witness(&mut values, dividend, divisor);
        Witness::new(values)
    }

    fn fill_witness(&self, values: &mut [F2_128], dividend: u64, divisor: u64) {
        let mask = low_mask(self.width);
        let dividend = dividend & mask;
        let divisor = divisor & mask;
        fill_bits(values, &self.rs1, dividend);
        fill_bits(values, &self.rs2, divisor);
        let sign_a = (dividend >> (self.width - 1)) & 1;
        let sign_b = (divisor >> (self.width - 1)) & 1;
        let abs_dividend = absolute_value(dividend, self.width);
        let abs_divisor = absolute_value(divisor, self.width);
        self.abs_dividend.fill(values, dividend, sign_a);
        self.abs_divisor.fill(values, divisor, sign_b);
        self.unsigned
            .fill_witness(values, abs_dividend, abs_divisor);

        let quotient_abs = witness_value(values, &self.unsigned.quotient);
        let remainder_abs = witness_value(values, &self.unsigned.remainder);
        let quotient_sign = sign_a ^ sign_b;
        values[self.quotient_sign] = F2_128::from(quotient_sign);
        self.quotient_negate
            .fill(values, quotient_abs, quotient_sign);
        self.remainder_negate.fill(values, remainder_abs, sign_a);

        for (bit, &var) in self.inverted_divisor.iter().enumerate() {
            values[var] = F2_128::from(1 ^ ((divisor >> bit) & 1));
        }
        fill_and_tree(values, &self.and_levels);
        let is_zero = u64::from(divisor == 0);
        debug_assert_eq!(values[self.divisor_zero].value(), is_zero as u128);

        let quotient = witness_value(values, &self.quotient_negate.output);
        let remainder = witness_value(values, &self.remainder_negate.output);
        for bit in 0..self.width {
            let quotient_bit = (quotient >> bit) & 1;
            let mux = is_zero & (1 ^ quotient_bit);
            values[self.quotient_zero_mux[bit]] = F2_128::from(mux);
            values[self.quotient[bit]] = F2_128::from(quotient_bit ^ mux);

            let remainder_bit = (remainder >> bit) & 1;
            let dividend_bit = (dividend >> bit) & 1;
            let mux = is_zero & (remainder_bit ^ dividend_bit);
            values[self.remainder_zero_mux[bit]] = F2_128::from(mux);
            values[self.remainder[bit]] = F2_128::from(remainder_bit ^ mux);
        }
    }
}

pub fn uniform_signed_div_relation(width: usize) -> (ConstraintSystem, UniformSignedDivLayout) {
    assert!(width > 0 && width <= 64);
    let (mut system, unsigned) = uniform_div_relation(width);
    let one = Expr::constant(1u64);
    let rs1: Vec<VarId> = system.alloc(width).collect();
    let rs2: Vec<VarId> = system.alloc(width).collect();
    for &var in rs1.iter().chain(rs2.iter()) {
        add_boolean_constraint(&mut system, var);
    }
    let sign_a = rs1[width - 1];
    let sign_b = rs2[width - 1];
    let abs_dividend = add_conditional_negate(&mut system, &rs1, sign_a, &one);
    let abs_divisor = add_conditional_negate(&mut system, &rs2, sign_b, &one);
    for bit in 0..width {
        system.add_constraint(
            Expr::var(unsigned.dividend[bit]),
            one.clone(),
            Expr::var(abs_dividend.output[bit]),
        );
        system.add_constraint(
            Expr::var(unsigned.divisor[bit]),
            one.clone(),
            Expr::var(abs_divisor.output[bit]),
        );
    }

    let quotient_sign = system.alloc(1).start;
    system.add_constraint(
        Expr::var(sign_a).add(Expr::var(sign_b)),
        one.clone(),
        Expr::var(quotient_sign),
    );
    let quotient_negate =
        add_conditional_negate(&mut system, &unsigned.quotient, quotient_sign, &one);
    let remainder_negate = add_conditional_negate(&mut system, &unsigned.remainder, sign_a, &one);

    let inverted_divisor: Vec<VarId> = system.alloc(width).collect();
    for (bit, &var) in inverted_divisor.iter().enumerate() {
        system.add_constraint(
            Expr::var(rs2[bit]),
            one.clone(),
            Expr::constant(1u64).add(Expr::var(var)),
        );
    }
    let (divisor_zero, and_levels) = add_and_tree(&mut system, &inverted_divisor);

    let quotient_zero_mux: Vec<VarId> = system.alloc(width).collect();
    let quotient: Vec<VarId> = system.alloc(width).collect();
    for bit in 0..width {
        system.add_constraint(
            Expr::var(divisor_zero),
            Expr::constant(1u64).add(Expr::var(quotient_negate.output[bit])),
            Expr::var(quotient_zero_mux[bit]),
        );
        system.add_constraint(
            Expr::var(quotient_negate.output[bit]).add(Expr::var(quotient_zero_mux[bit])),
            one.clone(),
            Expr::var(quotient[bit]),
        );
    }
    let remainder_zero_mux: Vec<VarId> = system.alloc(width).collect();
    let remainder: Vec<VarId> = system.alloc(width).collect();
    for bit in 0..width {
        system.add_constraint(
            Expr::var(divisor_zero),
            Expr::var(rs1[bit]).add(Expr::var(remainder_negate.output[bit])),
            Expr::var(remainder_zero_mux[bit]),
        );
        system.add_constraint(
            Expr::var(remainder_negate.output[bit]).add(Expr::var(remainder_zero_mux[bit])),
            one.clone(),
            Expr::var(remainder[bit]),
        );
    }

    let num_vars = system.num_vars;
    (
        system,
        UniformSignedDivLayout {
            width,
            rs1,
            rs2,
            quotient,
            remainder,
            unsigned,
            abs_dividend,
            abs_divisor,
            quotient_negate,
            remainder_negate,
            quotient_sign,
            inverted_divisor,
            and_levels,
            divisor_zero,
            quotient_zero_mux,
            remainder_zero_mux,
            num_vars,
        },
    )
}

pub fn uniform_div_row_relation(
    width: usize,
    dividend: u64,
    divisor: u64,
    quotient: u64,
) -> (ConstraintSystem, UniformSignedDivLayout) {
    let (mut system, layout) = uniform_signed_div_relation(width);
    let one = Expr::constant(1u64);
    for bit in 0..width {
        system.add_constraint(
            Expr::var(layout.rs1[bit]),
            one.clone(),
            Expr::constant((dividend >> bit) & 1),
        );
        system.add_constraint(
            Expr::var(layout.rs2[bit]),
            one.clone(),
            Expr::constant((divisor >> bit) & 1),
        );
        system.add_constraint(
            Expr::var(layout.quotient[bit]),
            one.clone(),
            Expr::constant((quotient >> bit) & 1),
        );
    }
    (system, layout)
}

pub fn uniform_rem_row_relation(
    width: usize,
    dividend: u64,
    divisor: u64,
    remainder: u64,
) -> (ConstraintSystem, UniformSignedDivLayout) {
    let (mut system, layout) = uniform_signed_div_relation(width);
    let one = Expr::constant(1u64);
    for bit in 0..width {
        system.add_constraint(
            Expr::var(layout.rs1[bit]),
            one.clone(),
            Expr::constant((dividend >> bit) & 1),
        );
        system.add_constraint(
            Expr::var(layout.rs2[bit]),
            one.clone(),
            Expr::constant((divisor >> bit) & 1),
        );
        system.add_constraint(
            Expr::var(layout.remainder[bit]),
            one.clone(),
            Expr::constant((remainder >> bit) & 1),
        );
    }
    (system, layout)
}

pub fn uniform_alu_row_relation(
    width: usize,
    op: StepOp,
    rs1: u64,
    rs2: u64,
    rd: u64,
    imm: u64,
) -> (ConstraintSystem, UniformAluLayout) {
    let (mut system, layout) = uniform_alu_relation(width);
    let one = Expr::constant(1u64);
    system.add_constraint(
        Expr::var(layout.selectors[op.index()]),
        one.clone(),
        one.clone(),
    );
    for index in 0..width {
        system.add_constraint(
            Expr::var(layout.adder.a[index]),
            one.clone(),
            Expr::constant((rs1 >> index) & 1),
        );
        system.add_constraint(
            Expr::var(layout.rs2[index]),
            one.clone(),
            Expr::constant((rs2 >> index) & 1),
        );
        system.add_constraint(
            Expr::var(layout.rd[index]),
            one.clone(),
            Expr::constant((rd >> index) & 1),
        );
        system.add_constraint(
            Expr::var(layout.imm[index]),
            one.clone(),
            Expr::constant((imm >> index) & 1),
        );
    }
    (system, layout)
}

fn alloc_pinned_bits(
    system: &mut ConstraintSystem,
    values: &mut Vec<F2_128>,
    width: usize,
    value: u64,
) -> Vec<VarId> {
    let vars: Vec<VarId> = system.alloc(width).collect();
    values.resize(system.num_vars, F2_128::from(0u64));
    let one = Expr::constant(1u64);
    for (index, &var) in vars.iter().enumerate() {
        let bit = (value >> index) & 1;
        system.add_constraint(Expr::var(var), one.clone(), Expr::constant(bit));
        values[var] = F2_128::from(bit);
    }
    vars
}

/// Specialized ALU relations that allocate only the gates the operation needs.
///
/// The uniform selector relation embeds a barrel shifter and four comparators
/// in every ALU row; this path covers add/sub/logic/lui rows with a few hundred
/// variables instead. Shifts and comparisons return `None` and use the uniform
/// relation.
#[derive(Clone, Debug)]
pub struct SimpleAluLayout {
    pub rs1: Vec<VarId>,
    pub rhs: Vec<VarId>,
    pub rd: Vec<VarId>,
    pub rhs_is_imm: bool,
}

impl SimpleAluLayout {
    pub fn var_groups(&self) -> Vec<CpuVarGroup> {
        let mut groups = Vec::new();
        if !self.rs1.is_empty() {
            groups.push(CpuVarGroup {
                kind: CpuVarKind::Rs1,
                vars: self.rs1.clone(),
            });
        }
        if !self.rhs.is_empty() {
            groups.push(CpuVarGroup {
                kind: if self.rhs_is_imm {
                    CpuVarKind::Imm
                } else {
                    CpuVarKind::Rs2
                },
                vars: self.rhs.clone(),
            });
        }
        if !self.rd.is_empty() {
            groups.push(CpuVarGroup {
                kind: CpuVarKind::Rd,
                vars: self.rd.clone(),
            });
        }
        groups
    }
}

pub fn simple_alu_row_relation_with_layout(
    width: usize,
    op: StepOp,
    rs1: u64,
    rs2: u64,
    rd: u64,
    imm: u64,
) -> Option<(ConstraintSystem, Witness, SimpleAluLayout)> {
    assert!(width > 0 && width <= 64);
    let mask = if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    let rs1 = rs1 & mask;
    let rs2 = rs2 & mask;
    let rd = rd & mask;
    let imm = imm & mask;
    let one = Expr::constant(1u64);

    match op {
        StepOp::Add | StepOp::Addi | StepOp::Sub => {
            let rhs = match op {
                StepOp::Addi => imm,
                StepOp::Sub => (!rs2) & mask,
                _ => rs2,
            };
            let carry_in = u64::from(op == StepOp::Sub);
            let (mut system, layout) = bit_addition_constraints_with_carry(width, carry_in);
            for index in 0..width {
                for (var, bit) in [
                    (layout.a[index], (rs1 >> index) & 1),
                    (layout.b[index], (rhs >> index) & 1),
                    (layout.sum[index], (rd >> index) & 1),
                ] {
                    system.add_constraint(Expr::var(var), one.clone(), Expr::constant(bit));
                }
            }
            let groups = SimpleAluLayout {
                rs1: layout.a.clone(),
                rhs: if op == StepOp::Sub {
                    Vec::new()
                } else {
                    layout.b.clone()
                },
                rd: layout.sum.clone(),
                rhs_is_imm: op == StepOp::Addi,
            };
            Some((system, layout.witness(rs1, rhs), groups))
        }
        StepOp::Lui => {
            let mut system = ConstraintSystem::new(0);
            let mut values = Vec::new();
            let result = alloc_pinned_bits(&mut system, &mut values, width, rd);
            for (index, &var) in result.iter().enumerate() {
                system.add_constraint(
                    Expr::var(var),
                    one.clone(),
                    Expr::constant((imm >> index) & 1),
                );
            }
            let groups = SimpleAluLayout {
                rs1: Vec::new(),
                rhs: Vec::new(),
                rd: result,
                rhs_is_imm: false,
            };
            Some((system, Witness::new(values), groups))
        }
        StepOp::Xor | StepOp::Xori | StepOp::And | StepOp::Andi | StepOp::Or | StepOp::Ori => {
            let rhs = match op {
                StepOp::Xori | StepOp::Andi | StepOp::Ori => imm,
                _ => rs2,
            };
            let mut system = ConstraintSystem::new(0);
            let mut values = Vec::new();
            let a = alloc_pinned_bits(&mut system, &mut values, width, rs1);
            let b = alloc_pinned_bits(&mut system, &mut values, width, rhs);
            let result = alloc_pinned_bits(&mut system, &mut values, width, rd);
            for index in 0..width {
                match op {
                    StepOp::Xor | StepOp::Xori => {
                        system.add_constraint(
                            Expr::var(a[index]).add(Expr::var(b[index])),
                            one.clone(),
                            Expr::var(result[index]),
                        );
                    }
                    StepOp::And | StepOp::Andi => {
                        system.add_constraint(
                            Expr::var(a[index]),
                            Expr::var(b[index]),
                            Expr::var(result[index]),
                        );
                    }
                    StepOp::Or | StepOp::Ori => {
                        let product = system.alloc(1).start;
                        values.resize(system.num_vars, F2_128::from(0u64));
                        values[product] = F2_128::from(
                            (values[a[index]].value() as u64 & 1)
                                & (values[b[index]].value() as u64 & 1),
                        );
                        system.add_constraint(
                            Expr::var(a[index]),
                            Expr::var(b[index]),
                            Expr::var(product),
                        );
                        system.add_constraint(
                            Expr::var(a[index])
                                .add(Expr::var(b[index]))
                                .add(Expr::var(product)),
                            one.clone(),
                            Expr::var(result[index]),
                        );
                    }
                    _ => unreachable!(),
                }
            }
            let groups = SimpleAluLayout {
                rs1: a,
                rhs: b,
                rd: result,
                rhs_is_imm: matches!(op, StepOp::Xori | StepOp::Andi | StepOp::Ori),
            };
            Some((system, Witness::new(values), groups))
        }
        _ => None,
    }
}

/// Compatibility wrapper: the reference prover uses the system/witness only.
pub fn simple_alu_row_relation(
    width: usize,
    op: StepOp,
    rs1: u64,
    rs2: u64,
    rd: u64,
    imm: u64,
) -> Option<(ConstraintSystem, Witness)> {
    simple_alu_row_relation_with_layout(width, op, rs1, rs2, rd, imm)
        .map(|(system, witness, _layout)| (system, witness))
}

/// Row relation for RV64 `*W` integer operations.
///
/// The low 32 bits are constrained by the 32-bit uniform ALU relation; the
/// upper 32 bits are constrained to the sign bit of the 32-bit result.
pub fn uniform_w_row_relation(
    step_op: StepOp,
    rs1: u64,
    rs2: u64,
    rd: u64,
    imm: u64,
) -> (ConstraintSystem, Witness) {
    let (mut system, alu) = uniform_alu_row_relation(32, step_op, rs1, rs2, rd, imm);
    let sign = alu.rd[31];
    let high: Vec<VarId> = system.alloc(32).collect();
    let one = Expr::constant(1u64);
    for &var in &high {
        system.add_constraint(Expr::var(var), one.clone(), Expr::var(sign));
    }
    let mut values = alu.witness(step_op, rs1, rs2, imm).values().to_vec();
    let sign_bit = (rd >> 31) & 1;
    values.extend(std::iter::repeat_n(F2_128::from(sign_bit), 32));
    (system, Witness::new(values))
}

pub fn uniform_load_row_relation(
    width: usize,
    addr: u64,
    value: u64,
    rs1: u64,
    imm: u64,
) -> (ConstraintSystem, UniformLoadLayout) {
    let (mut system, layout) = uniform_load_relation(width, addr, value);
    let one = Expr::constant(1u64);
    for index in 0..width {
        system.add_constraint(
            Expr::var(layout.adder.a[index]),
            one.clone(),
            Expr::constant((rs1 >> index) & 1),
        );
        system.add_constraint(
            Expr::var(layout.adder.b[index]),
            one.clone(),
            Expr::constant((imm >> index) & 1),
        );
    }
    (system, layout)
}

pub fn uniform_store_row_relation(
    width: usize,
    addr: u64,
    new_value: u64,
    rs1: u64,
    imm: u64,
) -> (ConstraintSystem, UniformStoreLayout) {
    let (mut system, layout) = uniform_store_relation(width, addr, new_value);
    let one = Expr::constant(1u64);
    for index in 0..width {
        system.add_constraint(
            Expr::var(layout.adder.a[index]),
            one.clone(),
            Expr::constant((rs1 >> index) & 1),
        );
        system.add_constraint(
            Expr::var(layout.adder.b[index]),
            one.clone(),
            Expr::constant((imm >> index) & 1),
        );
    }
    (system, layout)
}

fn uniform_amo_copy_relation(
    width: usize,
    source: u64,
    new_value: u64,
) -> (ConstraintSystem, Witness) {
    let mut system = ConstraintSystem::new(0);
    let left: Vec<VarId> = system.alloc(width).collect();
    let right: Vec<VarId> = system.alloc(width).collect();
    let one = Expr::constant(1u64);
    let mut values = vec![F2_128::from(0u64); system.num_vars];
    for index in 0..width {
        let source_bit = (source >> index) & 1;
        let new_bit = (new_value >> index) & 1;
        add_boolean_constraint(&mut system, left[index]);
        add_boolean_constraint(&mut system, right[index]);
        system.add_constraint(
            Expr::var(left[index]),
            one.clone(),
            Expr::constant(source_bit),
        );
        system.add_constraint(
            Expr::var(right[index]),
            one.clone(),
            Expr::constant(new_bit),
        );
        system.add_constraint(
            Expr::var(left[index]).add(Expr::var(right[index])),
            one.clone(),
            Expr::constant(0u64),
        );
        values[left[index]] = F2_128::from(source_bit);
        values[right[index]] = F2_128::from(new_bit);
    }
    (system, Witness::new(values))
}

fn uniform_amo_minmax_relation(
    width: usize,
    signed: bool,
    min: bool,
    old: u64,
    source: u64,
    new_value: u64,
) -> (ConstraintSystem, Witness) {
    let mut system = ConstraintSystem::new(0);
    let a: Vec<VarId> = system.alloc(width).collect();
    let b: Vec<VarId> = system.alloc(width).collect();
    let rd: Vec<VarId> = system.alloc(width).collect();
    let a_cmp: Vec<VarId> = system.alloc(width).collect();
    let b_cmp: Vec<VarId> = system.alloc(width).collect();
    let products: Vec<VarId> = system.alloc(width).collect();
    let one = Expr::constant(1u64);
    let msb = width - 1;

    for index in 0..width {
        let old_bit = (old >> index) & 1;
        let source_bit = (source >> index) & 1;
        let new_bit = (new_value >> index) & 1;
        for (var, bit) in [
            (a[index], old_bit),
            (b[index], source_bit),
            (rd[index], new_bit),
        ] {
            add_boolean_constraint(&mut system, var);
            system.add_constraint(Expr::var(var), one.clone(), Expr::constant(bit));
        }
        add_boolean_constraint(&mut system, a_cmp[index]);
        add_boolean_constraint(&mut system, b_cmp[index]);
        let flip = signed && index == msb;
        system.add_constraint(
            Expr::var(a_cmp[index]).add(Expr::var(a[index])),
            one.clone(),
            Expr::constant(u64::from(flip)),
        );
        system.add_constraint(
            Expr::var(b_cmp[index]).add(Expr::var(b[index])),
            one.clone(),
            Expr::constant(u64::from(flip)),
        );
    }

    let comparator = add_unsigned_comparator(&mut system, &a_cmp, &b_cmp, &one);
    for index in 0..width {
        system.add_constraint(
            Expr::var(comparator.less),
            Expr::var(a[index]).add(Expr::var(b[index])),
            Expr::var(products[index]),
        );
        let base = if min { b[index] } else { a[index] };
        system.add_constraint(
            Expr::var(base).add(Expr::var(products[index])),
            one.clone(),
            Expr::var(rd[index]),
        );
    }

    let mut values = vec![F2_128::from(0u64); system.num_vars];
    for index in 0..width {
        let old_bit = (old >> index) & 1;
        let source_bit = (source >> index) & 1;
        let new_bit = (new_value >> index) & 1;
        let flip = u64::from(signed && index == msb);
        values[a[index]] = F2_128::from(old_bit);
        values[b[index]] = F2_128::from(source_bit);
        values[rd[index]] = F2_128::from(new_bit);
        values[a_cmp[index]] = F2_128::from(old_bit ^ flip);
        values[b_cmp[index]] = F2_128::from(source_bit ^ flip);
    }

    let flip = if signed { 1u64 << msb } else { 0 };
    let old_cmp = old ^ flip;
    let source_cmp = source ^ flip;
    comparator.fill(&mut values, old_cmp, source_cmp);
    let less = u64::from(old_cmp < source_cmp);
    for index in 0..width {
        values[products[index]] =
            F2_128::from(less & (((old >> index) & 1) ^ ((source >> index) & 1)));
    }
    (system, Witness::new(values))
}

/// Atomic RMW relation over the supported AMO subset.
///
/// The address is checked with the same 64-bit `rs1 + imm` adder used by
/// stores. `swap` is a copy relation; `add`, `xor`, `and`, and `or` reuse the
/// uniform ALU relation; `min`/`max` use a bitwise comparator and mux.
#[allow(clippy::too_many_arguments)]
pub fn uniform_amo_row_relation(
    width: usize,
    op: Op,
    addr: u64,
    old: u64,
    source: u64,
    new_value: u64,
    rs1: u64,
    imm: u64,
) -> Option<(ConstraintSystem, Witness)> {
    let amo_bits = op.amo_width()? * 8;
    let mask = if amo_bits == 64 {
        u64::MAX
    } else {
        (1u64 << amo_bits) - 1
    };
    let old = old & mask;
    let source = source & mask;
    let new_value = new_value & mask;
    let op_width = width.min(amo_bits);
    if op_width == 0 {
        return None;
    }

    let (mut system, store_layout) = uniform_store_row_relation(64, addr, new_value, rs1, imm);
    let mut values = store_layout.witness(rs1, imm).values().to_vec();
    let (op_system, op_witness) = match op {
        Op::AmoswapW | Op::AmoswapD => uniform_amo_copy_relation(op_width, source, new_value),
        Op::AmoaddW | Op::AmoaddD => {
            let (system, layout) =
                uniform_alu_row_relation(op_width, StepOp::Add, old, source, new_value, 0);
            (system, layout.witness(StepOp::Add, old, source, 0))
        }
        Op::AmoxorW | Op::AmoxorD => {
            let (system, layout) =
                uniform_alu_row_relation(op_width, StepOp::Xor, old, source, new_value, 0);
            (system, layout.witness(StepOp::Xor, old, source, 0))
        }
        Op::AmoandW | Op::AmoandD => {
            let (system, layout) =
                uniform_alu_row_relation(op_width, StepOp::And, old, source, new_value, 0);
            (system, layout.witness(StepOp::And, old, source, 0))
        }
        Op::AmoorW | Op::AmoorD => {
            let (system, layout) =
                uniform_alu_row_relation(op_width, StepOp::Or, old, source, new_value, 0);
            (system, layout.witness(StepOp::Or, old, source, 0))
        }
        Op::AmominW | Op::AmominD => {
            uniform_amo_minmax_relation(amo_bits, true, true, old, source, new_value)
        }
        Op::AmomaxW | Op::AmomaxD => {
            uniform_amo_minmax_relation(amo_bits, true, false, old, source, new_value)
        }
        Op::AmominuW | Op::AmominuD => {
            uniform_amo_minmax_relation(amo_bits, false, true, old, source, new_value)
        }
        Op::AmomaxuW | Op::AmomaxuD => {
            uniform_amo_minmax_relation(amo_bits, false, false, old, source, new_value)
        }
        _ => return None,
    };
    let offset = system.merge(op_system);
    if offset != values.len() {
        return None;
    }
    values.extend_from_slice(op_witness.values());
    Some((system, Witness::new(values)))
}

/// `jal` relation with pc, immediate, target, and link fixed by the statement.
pub fn uniform_jal_row_relation(
    width: usize,
    pc: u64,
    imm: u64,
    target: u64,
    link: u64,
) -> (ConstraintSystem, UniformJalLayout) {
    uniform_jal_row_relation_with_increment(width, pc, imm, target, link, 4)
}

pub fn uniform_jal_row_relation_with_increment(
    width: usize,
    pc: u64,
    imm: u64,
    target: u64,
    link: u64,
    link_increment: u64,
) -> (ConstraintSystem, UniformJalLayout) {
    let (mut system, layout) = uniform_jal_relation_with_increment(width, pc, imm, link_increment);
    let one = Expr::constant(1u64);
    for index in 0..width {
        system.add_constraint(
            Expr::var(layout.target.sum[index]),
            one.clone(),
            Expr::constant((target >> index) & 1),
        );
        system.add_constraint(
            Expr::var(layout.link.sum[index]),
            one.clone(),
            Expr::constant((link >> index) & 1),
        );
    }
    (system, layout)
}

/// Branch relation with opcode, operands, and both PCs fixed by the statement.
#[allow(clippy::too_many_arguments)]
pub fn uniform_branch_row_relation(
    width: usize,
    op: BranchOp,
    pc: u64,
    imm: u64,
    rs1: u64,
    rs2: u64,
    next_pc: u64,
) -> (ConstraintSystem, UniformBranchLayout) {
    let (mut system, layout) = uniform_branch_relation(width, pc, imm);
    let one = Expr::constant(1u64);
    system.add_constraint(
        Expr::var(layout.selectors[op.index()]),
        one.clone(),
        one.clone(),
    );
    for index in 0..width {
        system.add_constraint(
            Expr::var(layout.rs1[index]),
            one.clone(),
            Expr::constant((rs1 >> index) & 1),
        );
        system.add_constraint(
            Expr::var(layout.rs2[index]),
            one.clone(),
            Expr::constant((rs2 >> index) & 1),
        );
        system.add_constraint(
            Expr::var(layout.next_pc[index]),
            one.clone(),
            Expr::constant((next_pc >> index) & 1),
        );
    }
    (system, layout)
}

/// `jalr` relation with pc, source register, immediate, target, and link fixed.
pub fn uniform_jalr_row_relation(
    width: usize,
    pc: u64,
    rs1: u64,
    imm: u64,
    target: u64,
    link: u64,
) -> (ConstraintSystem, UniformJalrLayout) {
    uniform_jalr_row_relation_with_increment(width, pc, rs1, imm, target, link, 4)
}

pub fn uniform_jalr_row_relation_with_increment(
    width: usize,
    pc: u64,
    rs1: u64,
    imm: u64,
    target: u64,
    link: u64,
    link_increment: u64,
) -> (ConstraintSystem, UniformJalrLayout) {
    let (mut system, layout) =
        uniform_jalr_relation_with_increment(width, target, link, pc, link_increment);
    let one = Expr::constant(1u64);
    for index in 0..width {
        system.add_constraint(
            Expr::var(layout.target_adder.a[index]),
            one.clone(),
            Expr::constant((rs1 >> index) & 1),
        );
        system.add_constraint(
            Expr::var(layout.target_adder.b[index]),
            one.clone(),
            Expr::constant((imm >> index) & 1),
        );
    }
    (system, layout)
}

/// `auipc` relation with pc, immediate, and result fixed by the statement.
pub fn uniform_auipc_row_relation(
    width: usize,
    pc: u64,
    imm: u64,
    value: u64,
) -> (ConstraintSystem, UniformAuipcLayout) {
    let (mut system, layout) = uniform_auipc_relation(width, pc, value);
    let one = Expr::constant(1u64);
    for index in 0..width {
        system.add_constraint(
            Expr::var(layout.adder.b[index]),
            one.clone(),
            Expr::constant((imm >> index) & 1),
        );
    }
    (system, layout)
}

#[cfg(test)]
fn read_bits(witness: &Witness, vars: &[VarId]) -> u64 {
    vars.iter().enumerate().fold(0u64, |value, (index, var)| {
        value | ((witness.get(*var).expect("witness var").value() as u64 & 1) << index)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, ProgramImage};
    use proptest::prelude::*;

    fn trace() -> Trace {
        let config = MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x1000,
            stack_top: 0x1000_1000,
            max_cycles: 100,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 5,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Addi,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
                    imm: 7,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Add,
                    rd: 3,
                    rs1: 1,
                    rs2: 2,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        execute(&program, config).unwrap()
    }

    #[test]
    fn checks_reference_trace() {
        check_trace(&trace()).unwrap();
    }

    #[test]
    fn bit_adder_matches_integer_addition() {
        let width = 4;
        let (system, layout) = bit_addition_constraints(width);
        for a in 0..(1u64 << width) {
            for b in 0..(1u64 << width) {
                let witness = layout.witness(a, b);
                system.check(&witness).unwrap();
                let sum = layout
                    .sum
                    .iter()
                    .enumerate()
                    .map(|(index, var)| (witness.get(*var).unwrap().value() as u64) << index)
                    .sum::<u64>();
                assert_eq!(sum, (a + b) & ((1 << width) - 1));
                assert_eq!(
                    witness.get(layout.carry[width]).unwrap().value() as u64,
                    (a + b) >> width
                );
            }
        }
    }

    #[test]
    fn bit_adder_rejects_a_tampered_sum() {
        let (system, layout) = bit_addition_constraints(4);
        let mut witness = layout.witness(3, 5);
        let var = layout.sum[0];
        let tampered = witness.get(var).unwrap() + F2_128::from(1u64);
        witness.values_mut()[var] = tampered;
        assert!(system.check(&witness).is_err());
    }

    #[test]
    fn bit_adder_rejects_non_boolean_inputs() {
        let (system, layout) = bit_addition_constraints(4);
        let mut witness = layout.witness(0, 0);
        let var = layout.a[0];
        witness.values_mut()[var] = F2_128::from(2u64);
        assert!(system.check(&witness).is_err());
    }

    #[test]
    fn checks_rv64m_rows() {
        let instruction = |op, rd, rs1, rs2| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm: 0,
            shamt: 0,
        };
        let config = MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x1000,
            stack_top: 0x1000_1000,
            max_cycles: 100,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: -7,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Addi,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
                    imm: 2,
                    shamt: 0,
                }
                .encode(),
                instruction(Op::Mul, 3, 1, 2).encode(),
                instruction(Op::Div, 4, 1, 2).encode(),
                instruction(Op::Rem, 5, 1, 2).encode(),
                instruction(Op::Mulhu, 6, 1, 2).encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, config).unwrap();
        check_trace(&trace).unwrap();
        assert_eq!(trace.final_state.reg(3), (-14i64) as u64);
        assert_eq!(trace.final_state.reg(4), (-3i64) as u64);
        assert_eq!(trace.final_state.reg(5), (-1i64) as u64);
        assert_eq!(trace.final_state.reg(6), 1);

        let mut tampered = trace;
        tampered.rows[2].rd_val = 0;
        assert!(matches!(
            check_trace(&tampered),
            Err(CpuError::RdValue { row: 2, .. })
        ));
    }

    #[test]
    fn checks_amo_rows() {
        let instruction = |op, rd, rs1, rs2, imm| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let config = MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x1000,
            stack_top: 0x1000_1000,
            max_cycles: 100,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Lui, 4, 0, 0, 0x1000_0000).encode(),
                instruction(Op::Addi, 1, 0, 0, 10).encode(),
                instruction(Op::Sd, 0, 4, 1, 0).encode(),
                instruction(Op::Addi, 2, 0, 0, 5).encode(),
                instruction(Op::AmoaddD, 3, 4, 2, 0).encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, config).unwrap();
        check_trace(&trace).unwrap();

        let mut tampered = trace;
        let row = tampered
            .rows
            .iter_mut()
            .find(|row| row.instruction.op == Op::AmoaddD)
            .unwrap();
        row.mem.as_mut().unwrap().value = 0;
        assert!(matches!(
            check_trace(&tampered),
            Err(CpuError::MemValue { .. })
        ));
    }

    #[test]
    fn checks_lr_sc_rows() {
        let instruction = |op, rd, rs1, rs2, imm| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt: 0,
        };
        let config = MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x1000,
            stack_top: 0x1000_1000,
            max_cycles: 100,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Lui, 4, 0, 0, 0x1000_0000).encode(),
                instruction(Op::Addi, 1, 0, 0, 7).encode(),
                instruction(Op::Sd, 0, 4, 1, 0).encode(),
                instruction(Op::LrD, 2, 4, 0, 0).encode(),
                instruction(Op::ScD, 5, 4, 2, 0).encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, config).unwrap();
        check_trace(&trace).unwrap();

        let mut tampered = trace.clone();
        let row = tampered
            .rows
            .iter_mut()
            .find(|row| row.instruction.op == Op::ScD && row.mem.is_some())
            .unwrap();
        row.rd_val = 1;
        assert!(matches!(
            check_trace(&tampered),
            Err(CpuError::RdValue { .. })
        ));

        let mut bad_reservation = trace.clone();
        let row = bad_reservation
            .rows
            .iter_mut()
            .find(|row| row.instruction.op == Op::LrD)
            .unwrap();
        row.reservation_after = None;
        assert!(matches!(
            check_trace(&bad_reservation),
            Err(CpuError::Reservation { .. })
        ));

        let mut misaligned = trace;
        let row = misaligned
            .rows
            .iter_mut()
            .find(|row| row.instruction.op == Op::Sd)
            .unwrap();
        row.rs1_val += 1;
        row.mem.as_mut().unwrap().addr += 1;
        assert!(matches!(
            check_trace(&misaligned),
            Err(CpuError::Misaligned { .. })
        ));
    }

    #[test]
    fn checks_hint_and_exit_syscall_shapes() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 17,
                    rs1: 0,
                    rs2: 0,
                    imm: 1000,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
                Instruction {
                    op: Op::Addi,
                    rd: 17,
                    rs1: 0,
                    rs2: 0,
                    imm: 93,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(&program, trace().config).unwrap();
        check_trace(&trace).unwrap();

        let mut bad_hint = trace.clone();
        bad_hint.rows[1].rd_val = 1;
        assert!(matches!(
            check_trace(&bad_hint),
            Err(CpuError::SyscallShape { .. })
        ));

        let mut bad_exit = trace;
        bad_exit.rows[3].rd_val = 1;
        assert!(matches!(
            check_trace(&bad_exit),
            Err(CpuError::SyscallShape { .. })
        ));
    }

    #[test]
    fn detects_bad_alu_result() {
        let mut trace = trace();
        trace.rows[2].rd_val = 99;
        assert!(matches!(check_trace(&trace), Err(CpuError::RdValue { .. })));
    }

    #[test]
    fn simple_alu_rows_use_fewer_constraints_and_bind_results() {
        let cases = [
            (StepOp::Add, 5, 3, 7, 8),
            (StepOp::Addi, 5, 3, 7, 12),
            (StepOp::Sub, 9, 3, 0, 6),
            (StepOp::Xor, 5, 3, 0, 6),
            (StepOp::And, 5, 3, 0, 1),
            (StepOp::Or, 5, 3, 0, 7),
            (StepOp::Xori, 5, 3, 7, 2),
            (StepOp::Andi, 5, 3, 7, 5),
            (StepOp::Ori, 5, 3, 7, 7),
            (StepOp::Lui, 0, 0, 0x1234, 0x1234),
        ];
        for (op, rs1, rs2, imm, rd) in cases {
            let (system, witness) =
                simple_alu_row_relation(64, op, rs1, rs2, rd, imm).expect("specialized op");
            system.check(&witness).unwrap();
            let (uniform, _) = uniform_alu_row_relation(64, op, rs1, rs2, rd, imm);
            assert!(
                system.num_vars < uniform.num_vars / 4,
                "{}: {} vs {} variables",
                op.name(),
                system.num_vars,
                uniform.num_vars
            );
            let (bad, bad_witness) =
                simple_alu_row_relation(64, op, rs1, rs2, rd ^ 1, imm).unwrap();
            assert!(
                bad.check(&bad_witness).is_err(),
                "{} accepted a wrong rd",
                op.name()
            );
        }
        assert!(simple_alu_row_relation(64, StepOp::Sll, 1, 2, 4, 0).is_none());
        assert!(simple_alu_row_relation(64, StepOp::Slt, 1, 2, 1, 0).is_none());
    }

    #[test]
    fn uniform_alu_relation_checks_supported_ops() {
        for width in [3usize, 4] {
            let (system, layout) = uniform_alu_relation(width);
            let values: Vec<u64> = if width == 3 {
                (0..(1u64 << width)).collect()
            } else {
                vec![0, 1, 2, 7, 8, 15]
            };
            for op in [
                StepOp::Add,
                StepOp::Addi,
                StepOp::Xor,
                StepOp::Lui,
                StepOp::And,
                StepOp::Or,
                StepOp::Slt,
                StepOp::Sltu,
                StepOp::Slti,
                StepOp::Sltiu,
                StepOp::Sub,
                StepOp::Sll,
                StepOp::Srl,
                StepOp::Sra,
                StepOp::Slli,
                StepOp::Srli,
                StepOp::Srai,
                StepOp::Xori,
                StepOp::Ori,
                StepOp::Andi,
            ] {
                let stage_count = if width <= 1 {
                    0
                } else {
                    (usize::BITS - (width - 1).leading_zeros()) as usize
                };
                let shamt_mask = if stage_count == 0 {
                    0
                } else {
                    (1u64 << stage_count) - 1
                };
                let word_mask = (1u64 << width) - 1;
                for &a in &values {
                    for &b in &values {
                        let witness = layout.witness(op, a, b, b);
                        system.check(&witness).unwrap();
                        let expected = match op {
                            StepOp::Add | StepOp::Addi => (a + b) & ((1 << width) - 1),
                            StepOp::Xor => a ^ b,
                            StepOp::Lui => b,
                            StepOp::And => a & b,
                            StepOp::Or => a | b,
                            StepOp::Slt | StepOp::Slti => {
                                u64::from(signed_value(a, width) < signed_value(b, width))
                            }
                            StepOp::Sltu | StepOp::Sltiu => u64::from(a < b),
                            StepOp::Sub => a.wrapping_sub(b) & word_mask,
                            StepOp::Sll | StepOp::Slli => (a << (b & shamt_mask)) & word_mask,
                            StepOp::Srl | StepOp::Srli => (a & word_mask) >> (b & shamt_mask),
                            StepOp::Sra | StepOp::Srai => {
                                ((signed_value(a, width) >> (b & shamt_mask)) as u64) & word_mask
                            }
                            StepOp::Xori => a ^ b,
                            StepOp::Ori => a | b,
                            StepOp::Andi => a & b,
                        };
                        assert_eq!(read_bits(&witness, &layout.rd), expected, "{op:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn uniform_alu_relation_supports_64_bit_words() {
        let (system, layout) = uniform_alu_relation(64);
        let cases = [
            (0u64, 0u64),
            (1, 1),
            (u64::MAX, 1),
            (1 << 63, 1 << 63),
            (0xdead_beef_0123_4567, 0x1234_5678_9abc_def0),
        ];
        for op in [
            StepOp::Add,
            StepOp::Addi,
            StepOp::Xor,
            StepOp::Lui,
            StepOp::And,
            StepOp::Or,
            StepOp::Slt,
            StepOp::Sltu,
            StepOp::Slti,
            StepOp::Sltiu,
            StepOp::Sub,
            StepOp::Sll,
            StepOp::Srl,
            StepOp::Sra,
            StepOp::Slli,
            StepOp::Srli,
            StepOp::Srai,
            StepOp::Xori,
            StepOp::Ori,
            StepOp::Andi,
        ] {
            for &(a, b) in &cases {
                let witness = layout.witness(op, a, b, b);
                system.check(&witness).unwrap();
                let expected = match op {
                    StepOp::Add | StepOp::Addi => a.wrapping_add(b),
                    StepOp::Xor => a ^ b,
                    StepOp::Lui => b,
                    StepOp::And => a & b,
                    StepOp::Or => a | b,
                    StepOp::Slt | StepOp::Slti => {
                        u64::from(signed_value(a, 64) < signed_value(b, 64))
                    }
                    StepOp::Sltu | StepOp::Sltiu => u64::from(a < b),
                    StepOp::Sub => a.wrapping_sub(b),
                    StepOp::Sll | StepOp::Slli => a << (b & 63),
                    StepOp::Srl | StepOp::Srli => a >> (b & 63),
                    StepOp::Sra | StepOp::Srai => (signed_value(a, 64) >> (b & 63)) as u64,
                    StepOp::Xori => a ^ b,
                    StepOp::Ori => a | b,
                    StepOp::Andi => a & b,
                };
                assert_eq!(read_bits(&witness, &layout.rd), expected, "{op:?}");
            }
        }
    }

    proptest::proptest! {
        #[test]
        fn multiplication_circuits_match_u8(a in proptest::prelude::any::<u8>(), b in proptest::prelude::any::<u8>()) {
            let expected = u64::from(a) * u64::from(b);
            let (system, layout) =
                uniform_mul_row_relation(8, u64::from(a), u64::from(b), expected & 0xff);
            system.check(&layout.witness(u64::from(a), u64::from(b))).unwrap();

            let (system, layout) = uniform_full_mul_relation(8);
            let witness = layout.witness(u64::from(a), u64::from(b));
            system.check(&witness).unwrap();
            prop_assert_eq!(read_bits(&witness, &layout.product), expected);
        }

        #[test]
        fn division_circuits_match_u8(a in proptest::prelude::any::<u8>(), b in proptest::prelude::any::<u8>()) {
            let (quotient, remainder) = match a.checked_div(b) {
                Some(quotient) => (u64::from(quotient), u64::from(a % b)),
                None => (0xff, u64::from(a)),
            };
            let (system, layout) =
                uniform_divu_row_relation(8, u64::from(a), u64::from(b), quotient);
            let witness = layout.witness(u64::from(a), u64::from(b));
            system.check(&witness).unwrap();
            prop_assert_eq!(read_bits(&witness, &layout.quotient), quotient);
            prop_assert_eq!(read_bits(&witness, &layout.remainder), remainder);
        }

        #[test]
        fn signed_division_matches_i8(a in proptest::prelude::any::<i8>(), b in proptest::prelude::any::<i8>()) {
            let a_ext = i64::from(a) as u64;
            let b_ext = i64::from(b) as u64;
            let quotient = div(a_ext, b_ext) & 0xff;
            let remainder = rem(a_ext, b_ext) & 0xff;
            let (system, layout) = uniform_div_row_relation(
                8,
                u64::from(a as u8),
                u64::from(b as u8),
                quotient,
            );
            let witness = layout.witness(u64::from(a as u8), u64::from(b as u8));
            system.check(&witness).unwrap();
            prop_assert_eq!(read_bits(&witness, &layout.quotient), quotient);
            prop_assert_eq!(read_bits(&witness, &layout.remainder), remainder);
        }

        #[test]
        fn amo_rows_match_spec(
            old in proptest::prelude::any::<u64>(),
            source in proptest::prelude::any::<u64>(),
            op_index in 0usize..18,
        ) {
            let ops = [
                Op::AmoswapW, Op::AmoswapD, Op::AmoaddW, Op::AmoaddD,
                Op::AmoxorW, Op::AmoxorD, Op::AmoandW, Op::AmoandD,
                Op::AmoorW, Op::AmoorD, Op::AmominW, Op::AmominD,
                Op::AmomaxW, Op::AmomaxD, Op::AmominuW, Op::AmominuD,
                Op::AmomaxuW, Op::AmomaxuD,
            ];
            let op = ops[op_index];
            let new_value = op.amo_apply(old, source);
            let (system, witness) = uniform_amo_row_relation(
                8,
                op,
                0x1000_0010,
                old,
                source,
                new_value,
                0x1000_0000,
                0x10,
            )
            .unwrap();
            prop_assert!(system.check(&witness).is_ok());
        }
    }

    #[test]
    fn uniform_multiplication_matches_integer_product() {
        for width in [3usize, 4, 8, 16] {
            let (system, layout) = uniform_mul_relation(width);
            let mask = (1u64 << width) - 1;
            for &a in &[0u64, 1, 2, 3, mask] {
                for &b in &[0u64, 1, 2, 5, mask] {
                    let witness = layout.witness(a, b);
                    system
                        .check(&witness)
                        .unwrap_or_else(|error| panic!("width {width} {a}*{b}: {error}"));
                    assert_eq!(read_bits(&witness, &layout.rd), a.wrapping_mul(b) & mask);
                }
            }
        }
    }

    #[test]
    fn high_multiplication_matches_reference_semantics() {
        for width in [3usize, 4, 8, 16] {
            let mask = (1u64 << width) - 1;
            let sign_bit = 1u64 << (width - 1);
            for &a in &[0u64, 1, 2, mask, sign_bit] {
                for &b in &[0u64, 1, 3, mask, sign_bit] {
                    let (system, layout) = uniform_full_mul_relation(width);
                    let witness = layout.witness(a, b);
                    system.check(&witness).unwrap();
                    let full = (u128::from(a) * u128::from(b)) & ((1u128 << (2 * width)) - 1);
                    assert_eq!(read_bits(&witness, &layout.product), full as u64);

                    let expected = ((u128::from(a) * u128::from(b)) >> width) as u64 & mask;
                    let (system, layout) = uniform_mulhu_row_relation(width, a, b, expected);
                    system.check(&layout.witness(a, b)).unwrap();

                    let expected = ((i128::from(signed_value(a, width))
                        * i128::from(signed_value(b, width)))
                        >> width) as u64
                        & mask;
                    let (system, layout) =
                        uniform_mulh_row_relation(width, true, true, a, b, expected);
                    system.check(&layout.witness(a, b)).unwrap();

                    let expected = ((i128::from(signed_value(a, width)) * i128::from(b)) >> width)
                        as u64
                        & mask;
                    let (system, layout) =
                        uniform_mulh_row_relation(width, true, false, a, b, expected);
                    system.check(&layout.witness(a, b)).unwrap();
                }
            }
        }
    }

    #[test]
    fn signed_division_matches_integer_semantics() {
        for width in [1usize, 3, 4, 8] {
            let mask = (1u64 << width) - 1;
            let sign_bit = 1u64 << (width - 1);
            for &a in &[0u64, 1, 2, mask, sign_bit, sign_bit | 1] {
                for &b in &[0u64, 1, 2, mask, sign_bit] {
                    let a_signed = signed_value(a, width) as u64;
                    let b_signed = signed_value(b, width) as u64;
                    let quotient = div(a_signed, b_signed) & mask;
                    let remainder = rem(a_signed, b_signed) & mask;

                    let (system, layout) = uniform_div_row_relation(width, a, b, quotient);
                    let witness = layout.witness(a, b);
                    system.check(&witness).unwrap_or_else(|error| {
                        panic!("width {width} {a_signed}/{b_signed}: {error}")
                    });
                    assert_eq!(read_bits(&witness, &layout.quotient), quotient);
                    assert_eq!(read_bits(&witness, &layout.remainder), remainder);

                    let (system, layout) = uniform_rem_row_relation(width, a, b, remainder);
                    system.check(&layout.witness(a, b)).unwrap();
                }
            }
        }
    }

    #[test]
    fn signed_division_row_relations_bind_statement_values() {
        let (system, layout) = uniform_div_row_relation(8, (-100i64) as u64, 7, (-14i64) as u64);
        let witness = layout.witness((-100i64) as u64, 7);
        system.check(&witness).unwrap();
        assert!(system.check(&layout.witness((-100i64) as u64, 8)).is_err());

        let (system, layout) = uniform_rem_row_relation(8, (-100i64) as u64, 7, (-2i64) as u64);
        system.check(&layout.witness((-100i64) as u64, 7)).unwrap();
        let (system, layout) = uniform_rem_row_relation(8, (-100i64) as u64, 7, (-3i64) as u64);
        assert!(system.check(&layout.witness((-100i64) as u64, 7)).is_err());
    }

    #[test]
    fn unsigned_division_matches_integer_semantics() {
        for width in [1usize, 3, 4, 8] {
            let mask = (1u64 << width) - 1;
            for &a in &[0u64, 1, 2, mask] {
                for &b in &[0u64, 1, 2, 3, mask] {
                    let a_masked = a & mask;
                    let b_masked = b & mask;
                    let quotient = a_masked.checked_div(b_masked).unwrap_or(mask);
                    let remainder = a_masked.checked_rem(b_masked).unwrap_or(a_masked);

                    let (system, layout) = uniform_divu_row_relation(width, a, b, quotient);
                    let witness = layout.witness(a, b);
                    system
                        .check(&witness)
                        .unwrap_or_else(|error| panic!("width {width} {a}/{b}: {error}"));
                    assert_eq!(read_bits(&witness, &layout.quotient), quotient);
                    assert_eq!(read_bits(&witness, &layout.remainder), remainder);

                    let (system, layout) = uniform_remu_row_relation(width, a, b, remainder);
                    system.check(&layout.witness(a, b)).unwrap();
                }
            }
        }
    }

    #[test]
    fn division_supports_64_bit_words() {
        let cases = [
            (u64::MAX, 3),
            (100, 7),
            (0x8000_0000_0000_0000, u64::MAX),
            (10, 0),
            (0, u64::MAX),
        ];
        let (system, layout) = uniform_div_relation(64);
        for &(a, b) in &cases {
            let witness = layout.witness(a, b);
            system
                .check(&witness)
                .unwrap_or_else(|error| panic!("divu {a}/{b}: {error}"));
            assert_eq!(read_bits(&witness, &layout.quotient), divu(a, b));
            assert_eq!(read_bits(&witness, &layout.remainder), remu(a, b));
        }

        let (system, layout) = uniform_signed_div_relation(64);
        for &(a, b) in &cases {
            let witness = layout.witness(a, b);
            system
                .check(&witness)
                .unwrap_or_else(|error| panic!("div {a}/{b}: {error}"));
            assert_eq!(read_bits(&witness, &layout.quotient), div(a, b));
            assert_eq!(read_bits(&witness, &layout.remainder), rem(a, b));
        }
    }

    #[test]
    fn division_row_relations_bind_statement_values() {
        let (system, layout) = uniform_divu_row_relation(8, 100, 7, 14);
        let witness = layout.witness(100, 7);
        system.check(&witness).unwrap();
        assert!(system.check(&layout.witness(100, 8)).is_err());

        let (system, layout) = uniform_remu_row_relation(8, 100, 7, 2);
        system.check(&layout.witness(100, 7)).unwrap();
        let (system, layout) = uniform_remu_row_relation(8, 100, 7, 3);
        assert!(system.check(&layout.witness(100, 7)).is_err());
    }

    #[test]
    fn multiplication_supports_the_width_32_boundary() {
        let (system, layout) = uniform_full_mul_relation(32);
        let (a, b) = (0xffff_ffffu64, 2u64);
        let witness = layout.witness(a, b);
        system.check(&witness).unwrap();
        assert_eq!(
            read_bits(&witness, &layout.product),
            (u128::from(a) * u128::from(b)) as u64
        );

        let high = ((u128::from(a) * u128::from(b)) >> 32) as u64;
        let (system, layout) = uniform_mulhu_row_relation(32, a, b, high);
        system.check(&layout.witness(a, b)).unwrap();
    }

    #[test]
    fn low_multiplication_supports_64_bit_words() {
        let (system, layout) = uniform_mul_relation(64);
        for (a, b) in [
            (u64::MAX, u64::MAX),
            (0xdead_beef_0123_4567, 0x1234_5678_9abc_def0),
            (0x8000_0000_0000_0000, 2),
            (0, u64::MAX),
        ] {
            let witness = layout.witness(a, b);
            system.check(&witness).unwrap();
            assert_eq!(read_bits(&witness, &layout.rd), a.wrapping_mul(b));
        }
    }

    #[test]
    fn high_multiplication_supports_64_bit_words() {
        let cases = [
            (u64::MAX, u64::MAX),
            (0x8000_0000_0000_0000, 2),
            (0xdead_beef_0123_4567, 0x1234_5678_9abc_def0),
            (0, u64::MAX),
        ];

        let (unsigned_system, unsigned_layout) = uniform_mulh_relation(64, false, false);
        for &(a, b) in &cases {
            let witness = unsigned_layout.witness(a, b);
            unsigned_system.check(&witness).unwrap();
            assert_eq!(read_bits(&witness, &unsigned_layout.rd), mulhu(a, b));
        }

        let (signed_system, signed_layout) = uniform_mulh_relation(64, true, true);
        for &(a, b) in &cases {
            let witness = signed_layout.witness(a, b);
            signed_system.check(&witness).unwrap();
            assert_eq!(read_bits(&witness, &signed_layout.rd), mulh(a, b));
        }

        let (mixed_system, mixed_layout) = uniform_mulh_relation(64, true, false);
        for &(a, b) in &cases {
            let witness = mixed_layout.witness(a, b);
            mixed_system.check(&witness).unwrap();
            assert_eq!(read_bits(&witness, &mixed_layout.rd), mulhsu(a, b));
        }
    }

    #[test]
    fn multiplication_row_relation_binds_statement_values() {
        let (system, layout) = uniform_mul_row_relation(8, 13, 11, 143);
        let witness = layout.witness(13, 11);
        system.check(&witness).unwrap();
        assert!(system.check(&layout.witness(13, 12)).is_err());

        let (system, layout) = uniform_mul_row_relation(8, 13, 11, 142);
        assert!(system.check(&layout.witness(13, 11)).is_err());
    }

    #[test]
    fn uniform_store_relation_binds_address_and_new_value() {
        let (system, layout) = uniform_store_relation(16, 0x30, 0xbeef);
        let witness = layout.witness(0x10, 0x20);
        system.check(&witness).unwrap();
        assert_eq!(read_bits(&witness, &layout.adder.sum), 0x30);
        assert_eq!(read_bits(&witness, &layout.rs2), 0xbeef);

        let wrong = layout.witness(0x10, 0x21);
        assert!(system.check(&wrong).is_err());
    }

    #[test]
    fn row_relations_bind_statement_values() {
        let (alu_system, alu) = uniform_alu_row_relation(8, StepOp::Add, 5, 7, 12, 0);
        let alu_witness = alu.witness(StepOp::Add, 5, 7, 0);
        alu_system.check(&alu_witness).unwrap();
        assert!(alu_system
            .check(&alu.witness(StepOp::Add, 5, 8, 0))
            .is_err());

        let (load_system, load) = uniform_load_row_relation(16, 0x30, 0xbeef, 0x10, 0x20);
        let load_witness = load.witness(0x10, 0x20);
        load_system.check(&load_witness).unwrap();

        let (store_system, store) = uniform_store_row_relation(16, 0x30, 0xbeef, 0x10, 0x20);
        let store_witness = store.witness(0x10, 0x20);
        store_system.check(&store_witness).unwrap();
    }

    #[test]
    fn control_flow_row_relations_bind_statement_values() {
        let (jal_system, jal) = uniform_jal_row_relation(16, 0x1000, 0x20, 0x1020, 0x1004);
        let jal_witness = jal.witness(0x1000, 0x20);
        jal_system.check(&jal_witness).unwrap();
        assert!(jal_system.check(&jal.witness(0x1000, 0x24)).is_err());

        let (branch_system, branch) =
            uniform_branch_row_relation(16, BranchOp::Beq, 0x1000, 0x20, 7, 7, 0x1020);
        let branch_witness = branch.witness(BranchOp::Beq, 0x1000, 7, 7, 0x20);
        branch_system.check(&branch_witness).unwrap();
        assert!(branch_system
            .check(&branch.witness(BranchOp::Bne, 0x1000, 7, 7, 0x20))
            .is_err());
        assert!(branch_system
            .check(&branch.witness(BranchOp::Beq, 0x1000, 7, 7, 0x24))
            .is_err());

        let (jalr_system, jalr) =
            uniform_jalr_row_relation(16, 0x1000, 0x1000, 0x21, 0x1020, 0x1004);
        let jalr_witness = jalr.witness(0x1000, 0x21);
        jalr_system.check(&jalr_witness).unwrap();
        assert!(jalr_system.check(&jalr.witness(0x1000, 0x23)).is_err());

        let (auipc_system, auipc) = uniform_auipc_row_relation(16, 0x1000, 0x20, 0x1020);
        let auipc_witness = auipc.witness(0x20);
        auipc_system.check(&auipc_witness).unwrap();
        assert!(auipc_system.check(&auipc.witness(0x21)).is_err());
    }

    #[test]
    fn uniform_auipc_and_jalr_bind_pc_and_targets() {
        let (auipc_system, auipc) = uniform_auipc_relation(16, 0x1000, 0x1020);
        let auipc_witness = auipc.witness(0x20);
        auipc_system.check(&auipc_witness).unwrap();
        assert_eq!(read_bits(&auipc_witness, &auipc.adder.sum), 0x1020);
        assert!(auipc_system.check(&auipc.witness(0x21)).is_err());

        let (jalr_system, jalr) = uniform_jalr_relation(16, 0x1020, 0x1004, 0x1000);
        let jalr_witness = jalr.witness(0x1000, 0x21);
        jalr_system.check(&jalr_witness).unwrap();
        assert_eq!(
            read_bits(&jalr_witness, &jalr.target_adder.sum) & !1,
            0x1020
        );
        assert_eq!(read_bits(&jalr_witness, &jalr.link_adder.sum), 0x1004);
        assert!(jalr_system.check(&jalr.witness(0x1000, 0x23)).is_err());
    }

    #[test]
    fn uniform_load_relation_binds_address_and_value() {
        let (system, layout) = uniform_load_relation(16, 0x30, 0xbeef);
        let witness = layout.witness(0x10, 0x20);
        system.check(&witness).unwrap();
        assert_eq!(read_bits(&witness, &layout.adder.sum), 0x30);
        assert_eq!(read_bits(&witness, &layout.rd), 0xbeef);

        let wrong = layout.witness(0x10, 0x21);
        assert!(system.check(&wrong).is_err());
    }

    #[test]
    fn uniform_branch_relation_handles_all_conditions() {
        let pc = 0x10;
        let imm = 0x20;
        let (system, layout) = uniform_branch_relation(8, pc, imm);
        let target = 0x30;
        let fallthrough = 0x14;
        let cases = [
            (BranchOp::Beq, 7, 7, target),
            (BranchOp::Beq, 7, 8, fallthrough),
            (BranchOp::Bne, 7, 8, target),
            (BranchOp::Bne, 7, 7, fallthrough),
            (BranchOp::Blt, 0xff, 0, target),
            (BranchOp::Blt, 0, 0xff, fallthrough),
            (BranchOp::Bge, 0, 0xff, target),
            (BranchOp::Bge, 0xff, 0, fallthrough),
            (BranchOp::Bltu, 1, 0xff, target),
            (BranchOp::Bltu, 0xff, 1, fallthrough),
            (BranchOp::Bgeu, 0xff, 1, target),
            (BranchOp::Bgeu, 1, 0xff, fallthrough),
        ];
        for (op, rs1, rs2, expected) in cases {
            let witness = layout.witness(op, pc, rs1, rs2, imm);
            system
                .check(&witness)
                .unwrap_or_else(|error| panic!("{} failed: {error}", op.name()));
            assert_eq!(
                read_bits(&witness, &layout.next_pc),
                expected,
                "{}",
                op.name()
            );
        }

        let mut tampered = layout.witness(BranchOp::Beq, pc, 7, 7, imm);
        let var = layout.next_pc[0];
        let flipped = tampered.get(var).unwrap() + F2_128::from(1u64);
        tampered.values_mut()[var] = flipped;
        assert!(system.check(&tampered).is_err());
        assert!(system
            .check(&layout.witness(BranchOp::Beq, pc, 7, 7, imm + 4))
            .is_err());
    }

    #[test]
    fn uniform_beq_relation_checks_taken_and_fallthrough() {
        let (system, layout) = uniform_beq_relation(16, 0x1000, 0x20);
        let taken = layout.witness(0x1000, 7, 7, 0x20);
        system.check(&taken).unwrap();
        assert_eq!(read_bits(&taken, &layout.next_pc), 0x1020);

        let fallthrough = layout.witness(0x1000, 7, 8, 0x20);
        system.check(&fallthrough).unwrap();
        assert_eq!(read_bits(&fallthrough, &layout.next_pc), 0x1004);

        let (system8, layout8) = uniform_beq_relation(8, 0xfe, 4);
        let wrapped = layout8.witness(0xfe, 1, 1, 4);
        system8.check(&wrapped).unwrap();
        assert_eq!(read_bits(&wrapped, &layout8.next_pc), 0x02);

        let mut tampered = layout.witness(0x1000, 7, 7, 0x20);
        let var = layout.next_pc[0];
        let flipped = tampered.get(var).unwrap() + F2_128::from(1u64);
        tampered.values_mut()[var] = flipped;
        assert!(system.check(&tampered).is_err());
        assert!(system.check(&layout.witness(0x1000, 7, 7, 0x24)).is_err());
    }

    #[test]
    fn uniform_jal_relation_checks_target_and_link() {
        let (system, layout) = uniform_jal_relation(16, 0x1000, 0x20);
        let witness = layout.witness(0x1000, 0x20);
        system.check(&witness).unwrap();
        assert_eq!(read_bits(&witness, &layout.target.sum), 0x1020);
        assert_eq!(read_bits(&witness, &layout.link.sum), 0x1004);

        let (system8, layout8) = uniform_jal_relation(8, 0xfe, 4);
        let witness8 = layout8.witness(0xfe, 4);
        system8.check(&witness8).unwrap();
        assert_eq!(read_bits(&witness8, &layout8.target.sum), 0x02);
        assert_eq!(read_bits(&witness8, &layout8.link.sum), 0x02);

        let mut tampered = layout.witness(0x1000, 0x20);
        let var = layout.target.sum[0];
        let flipped = tampered.get(var).unwrap() + F2_128::from(1u64);
        tampered.values_mut()[var] = flipped;
        assert!(system.check(&tampered).is_err());
        assert!(system.check(&layout.witness(0x1000, 0x24)).is_err());
        assert!(system.check(&layout.witness(0x1004, 0x20)).is_err());
    }

    #[test]
    fn immediate_shifts_use_the_immediate_not_rs2() {
        let (system, layout) = uniform_alu_relation(16);
        let cases = [
            (StepOp::Slli, 0x00f0u64, 5u32),
            (StepOp::Srli, 0x00f0u64, 5u32),
            (StepOp::Srai, 0xff00u64, 5u32),
        ];
        for (op, value, shamt) in cases {
            let witness = layout.witness(op, value, 3, shamt as u64);
            system.check(&witness).unwrap();
            let expected = match op {
                StepOp::Slli => (value << shamt) & 0xffff,
                StepOp::Srli => value >> shamt,
                StepOp::Srai => ((signed_value(value, 16) >> shamt) as u64) & 0xffff,
                _ => unreachable!(),
            };
            assert_eq!(read_bits(&witness, &layout.rd), expected, "{op:?}");
        }
    }

    #[test]
    fn uniform_step_relation_checks_pc_increment() {
        let (system, layout) = uniform_step_relation(16);
        let witness = layout.witness(StepOp::Add, 0x1000, 5, 7, 0);
        system.check(&witness).unwrap();
        assert_eq!(read_bits(&witness, &layout.pc_adder.sum), 0x1004);

        let (system8, layout8) = uniform_step_relation(8);
        let witness8 = layout8.witness(StepOp::Xor, 0xfe, 1, 2, 0);
        system8.check(&witness8).unwrap();
        assert_eq!(read_bits(&witness8, &layout8.pc_adder.sum), 0x02);

        let mut tampered = layout.witness(StepOp::Add, 0x1000, 5, 7, 0);
        let var = layout.pc_adder.sum[0];
        let flipped = tampered.get(var).unwrap() + F2_128::from(1u64);
        tampered.values_mut()[var] = flipped;
        assert!(system.check(&tampered).is_err());
    }

    #[test]
    fn uniform_alu_relation_rejects_tampered_result() {
        let (system, layout) = uniform_alu_relation(4);
        let mut witness = layout.witness(StepOp::Add, 3, 5, 0);
        let var = layout.rd[0];
        let tampered = witness.get(var).unwrap() + F2_128::from(1u64);
        witness.values_mut()[var] = tampered;
        assert!(system.check(&witness).is_err());
    }

    #[test]
    fn amo_row_relations_cover_supported_operations() {
        let address = 0x1000_0010u64;
        let rs1 = 0x1000_0000u64;
        let imm = 0x10u64;
        let cases = [
            (0u64, 0u64),
            (1, 2),
            (10, 5),
            (u64::MAX, 1),
            (0x8000_0000, 0x7fff_ffff),
        ];

        for op in [
            Op::AmoswapW,
            Op::AmoswapD,
            Op::AmoaddW,
            Op::AmoaddD,
            Op::AmoxorW,
            Op::AmoxorD,
            Op::AmoandW,
            Op::AmoandD,
            Op::AmoorW,
            Op::AmoorD,
            Op::AmominW,
            Op::AmominD,
            Op::AmomaxW,
            Op::AmomaxD,
            Op::AmominuW,
            Op::AmominuD,
            Op::AmomaxuW,
            Op::AmomaxuD,
        ] {
            let bits = op.amo_width().unwrap() * 8;
            for &(old, source) in &cases {
                let new_value = op.amo_apply(old, source);
                let (system, witness) =
                    uniform_amo_row_relation(8, op, address, old, source, new_value, rs1, imm)
                        .unwrap();
                system
                    .check(&witness)
                    .unwrap_or_else(|error| panic!("{op:?} {old:#x} {source:#x}: {error}"));

                let (system, witness) =
                    uniform_amo_row_relation(bits, op, address, old, source, new_value, rs1, imm)
                        .unwrap();
                system.check(&witness).unwrap();
            }
        }

        assert!(uniform_amo_row_relation(8, Op::Add, address, 10, 5, 15, rs1, imm).is_none());
    }

    #[test]
    fn amo_row_relations_reject_wrong_operands_and_addresses() {
        let address = 0x1000_0010u64;
        let (rs1, imm) = (0x1000_0000u64, 0x10u64);
        let (old, source) = (10u64, 5u64);
        let new_value = Op::AmoaddD.amo_apply(old, source);

        let (system, witness) =
            uniform_amo_row_relation(8, Op::AmoaddD, address, old, source, new_value, rs1, imm)
                .unwrap();
        system.check(&witness).unwrap();

        let (system, witness) = uniform_amo_row_relation(
            8,
            Op::AmoaddD,
            address,
            old,
            source,
            new_value + 1,
            rs1,
            imm,
        )
        .unwrap();
        assert!(system.check(&witness).is_err());

        let (system, witness) = uniform_amo_row_relation(
            8,
            Op::AmoaddD,
            address + 1,
            old,
            source,
            new_value,
            rs1,
            imm,
        )
        .unwrap();
        assert!(system.check(&witness).is_err());

        let (system, witness) = uniform_amo_row_relation(
            8,
            Op::AmoaddD,
            address,
            old + 1,
            source,
            new_value,
            rs1,
            imm,
        )
        .unwrap();
        assert!(system.check(&witness).is_err());

        let (system, witness) =
            uniform_amo_row_relation(8, Op::AmoswapD, address, old, source, source + 1, rs1, imm)
                .unwrap();
        assert!(system.check(&witness).is_err());

        let min_value = Op::AmominD.amo_apply(old, source);
        let (system, witness) = uniform_amo_row_relation(
            8,
            Op::AmominD,
            address,
            old,
            source,
            min_value + 1,
            rs1,
            imm,
        )
        .unwrap();
        assert!(system.check(&witness).is_err());
    }
}

#[cfg(test)]
mod metadata_tests {
    use super::*;

    #[test]
    fn uniform_step_var_groups_match_witness_bits() {
        let (system, layout) = uniform_step_relation(8);
        let pc = 0x1000u64;
        let rs1 = 5u64;
        let rs2 = 7u64;
        let imm = 3u64;
        let witness = layout.witness(StepOp::Addi, pc, rs1, rs2, imm);
        assert_eq!(witness.values().len(), system.num_vars);
        for group in layout.var_groups() {
            let expected = match group.kind {
                CpuVarKind::Rs1 => rs1,
                CpuVarKind::Rs2 => rs2,
                CpuVarKind::Imm => imm,
                CpuVarKind::Rd => rs1.wrapping_add(imm) & 0xff,
                CpuVarKind::Pc => pc,
                CpuVarKind::NextPc => pc.wrapping_add(4),
                CpuVarKind::RamAddr
                | CpuVarKind::RamValue
                | CpuVarKind::Target
                | CpuVarKind::Link
                | CpuVarKind::ShiftSource
                | CpuVarKind::ShiftAmount
                | CpuVarKind::ShiftOutput => unreachable!(),
            };
            for (bit, var) in group.vars.iter().enumerate() {
                assert_eq!(
                    witness.values()[*var].value() as u64,
                    (expected >> bit) & 1,
                    "{:?} bit {bit}",
                    group.kind
                );
            }
        }
    }
    #[test]
    fn simple_alu_layout_exposes_operand_groups() {
        let width = 8;
        let rs1 = 5u64;
        let imm = 3u64;
        let rd = 8u64;
        let (system, witness, layout) =
            simple_alu_row_relation_with_layout(width, StepOp::Addi, rs1, 0, rd, imm)
                .expect("simple ALU");
        assert_eq!(witness.values().len(), system.num_vars);
        for group in layout.var_groups() {
            let expected = match group.kind {
                CpuVarKind::Rs1 => rs1,
                CpuVarKind::Imm => imm,
                CpuVarKind::Rd => rd,
                other => panic!("unexpected {other:?}"),
            };
            for (bit, var) in group.vars.iter().enumerate() {
                assert_eq!(witness.values()[*var].value() as u64, (expected >> bit) & 1);
            }
        }
    }
    #[test]
    fn load_and_store_layouts_expose_ram_groups() {
        let width = 8;
        let rs1 = 0x10u64;
        let imm = 0x02u64;
        let addr = rs1 + imm;
        let value = 0x34u64;

        let (system, load) = uniform_load_row_relation(width, addr, value, rs1, imm);
        let witness = load.witness(rs1, imm);
        assert_eq!(witness.values().len(), system.num_vars);
        for group in load.var_groups() {
            let expected = match group.kind {
                CpuVarKind::Rs1 => rs1,
                CpuVarKind::Imm => imm,
                CpuVarKind::RamAddr => addr,
                CpuVarKind::Rd => value,
                other => panic!("unexpected {other:?}"),
            };
            for (bit, var) in group.vars.iter().enumerate() {
                assert_eq!(witness.values()[*var].value() as u64, (expected >> bit) & 1);
            }
        }

        let (system, store) = uniform_store_row_relation(width, addr, value, rs1, imm);
        let witness = store.witness(rs1, imm);
        assert_eq!(witness.values().len(), system.num_vars);
        for group in store.var_groups() {
            let expected = match group.kind {
                CpuVarKind::Rs1 => rs1,
                CpuVarKind::Imm => imm,
                CpuVarKind::RamAddr => addr,
                CpuVarKind::RamValue => value,
                other => panic!("unexpected {other:?}"),
            };
            for (bit, var) in group.vars.iter().enumerate() {
                assert_eq!(witness.values()[*var].value() as u64, (expected >> bit) & 1);
            }
        }
    }
    #[test]
    fn branch_and_jump_layouts_expose_pc_groups() {
        let width = 8;
        let pc = 0x10u64;
        let imm = 0x02u64;
        let rs1 = 3u64;
        let rs2 = 4u64;
        let next_pc = 0x14u64;
        let (system, branch) =
            uniform_branch_row_relation(width, BranchOp::Beq, pc, imm, rs1, rs2, next_pc);
        let witness = branch.witness(BranchOp::Beq, pc, rs1, rs2, imm);
        assert_eq!(witness.values().len(), system.num_vars);
        for group in branch.var_groups() {
            let expected = match group.kind {
                CpuVarKind::Rs1 => rs1,
                CpuVarKind::Rs2 => rs2,
                CpuVarKind::Pc => pc,
                CpuVarKind::NextPc => next_pc,
                CpuVarKind::Target => pc.wrapping_add(imm),
                other => panic!("unexpected {other:?}"),
            };
            for (bit, var) in group.vars.iter().enumerate() {
                assert_eq!(
                    witness.values()[*var].value() as u64,
                    (expected >> bit) & 1,
                    "{:?} bit {bit}",
                    group.kind
                );
            }
        }

        let link = 0x14u64;
        let jal_target = 0x12u64;
        let (system, jal) = uniform_jal_row_relation(width, pc, imm, jal_target, link);
        let witness = jal.witness(pc, imm);
        assert_eq!(witness.values().len(), system.num_vars);
        for group in jal.var_groups() {
            let expected = match group.kind {
                CpuVarKind::Pc => pc,
                CpuVarKind::Target => jal_target,
                CpuVarKind::Link => link,
                other => panic!("unexpected {other:?}"),
            };
            for (bit, var) in group.vars.iter().enumerate() {
                assert_eq!(witness.values()[*var].value() as u64, (expected >> bit) & 1);
            }
        }
    }
    #[test]
    fn shift_layout_exposes_source_amount_and_output() {
        let width = 8;
        let rs1 = 0x12u64;
        let shamt = 2u64;
        let (system, layout) = uniform_alu_row_relation(width, StepOp::Sll, rs1, shamt, 0, 0);
        let witness = layout.witness(StepOp::Sll, rs1, shamt, 0);
        assert_eq!(witness.values().len(), system.num_vars);
        for group in layout.shift_var_groups() {
            let expected = match group.kind {
                CpuVarKind::ShiftSource => rs1,
                CpuVarKind::ShiftAmount => shamt,
                CpuVarKind::ShiftOutput => (rs1 << shamt) & 0xff,
                other => panic!("unexpected {other:?}"),
            };
            for (bit, var) in group.vars.iter().enumerate() {
                assert_eq!(witness.values()[*var].value() as u64, (expected >> bit) & 1);
            }
        }
    }
    #[test]
    fn shift_amount_group_needs_repacking_for_a_segment() {
        let width = 8;
        let (_system, layout) = uniform_alu_row_relation(width, StepOp::Sll, 0x12, 2, 0, 0);
        let groups = layout.shift_var_groups();
        let source = groups
            .iter()
            .find(|group| group.kind == CpuVarKind::ShiftSource)
            .unwrap();
        let amount = groups
            .iter()
            .find(|group| group.kind == CpuVarKind::ShiftAmount)
            .unwrap();
        assert!(source.is_segment_aligned());
        assert!(!amount.is_segment_aligned());
    }
}

/// Component groups for an AMO row's store-shaped part. The op-specific
/// ALU/minmax sub-relation is merged after the store layout; exposing those
/// variables requires a combined layout and is tracked separately.
pub fn uniform_amo_row_groups(addr: u64, new_value: u64, rs1: u64, imm: u64) -> Vec<CpuVarGroup> {
    let (_system, layout) = uniform_store_row_relation(64, addr, new_value, rs1, imm);
    layout.var_groups()
}
