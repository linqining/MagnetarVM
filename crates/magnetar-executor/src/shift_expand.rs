//! Reference fixed-instruction expansion for register-specified shifts.
//!
//! The expansion is branchless and uses four temporary registers (x28-x31).
//! It is only defined for programs that do not use those temporaries and do
//! not contain PC-relative control flow (branches, jal/jalr or auipc), so the
//! rewritten instruction sequence has the same semantics.

use magnetar_spec::{Instruction, Op, ProgramImage};

const T0: u8 = 28;
const T1: u8 = 29;
const T2: u8 = 30;
const T3: u8 = 31;
const TEMPS: [u8; 4] = [T0, T1, T2, T3];

fn uses_temp(instruction: &Instruction) -> bool {
    TEMPS.contains(&instruction.rd)
        || TEMPS.contains(&instruction.rs1)
        || TEMPS.contains(&instruction.rs2)
}

fn is_pc_relative(op: Op) -> bool {
    matches!(
        op,
        Op::Beq
            | Op::Bne
            | Op::Blt
            | Op::Bge
            | Op::Bltu
            | Op::Bgeu
            | Op::Jal
            | Op::Jalr
            | Op::Auipc
    )
}

fn encode(op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64) -> u32 {
    Instruction {
        op,
        rd,
        rs1,
        rs2,
        imm,
        shamt: 0,
    }
    .encode()
}

fn encode_shift(op: Op, rd: u8, rs1: u8, shamt: u8) -> u32 {
    Instruction {
        op,
        rd,
        rs1,
        rs2: 0,
        imm: 0,
        shamt,
    }
    .encode()
}

fn expand_one(instruction: &Instruction) -> Option<Vec<u32>> {
    let kind = match instruction.op {
        Op::Sll => Op::Slli,
        Op::Srl => Op::Srli,
        Op::Sra => Op::Srai,
        _ => return None,
    };
    let rd = instruction.rd;
    let rs1 = instruction.rs1;
    let rs2 = instruction.rs2;
    let mut body = vec![
        encode(Op::Andi, T0, rs2, 0, 63),
        encode(Op::Addi, T3, rs1, 0, 0),
        encode(Op::Addi, rd, T3, 0, 0),
    ];
    for bit in 0..6 {
        let mask = 1i64 << bit;
        body.push(encode(Op::Andi, T1, T0, 0, mask));
        if bit > 0 {
            body.push(encode_shift(Op::Srli, T1, T1, bit));
        }
        body.push(encode(Op::Sub, T1, 0, T1, 0));
        body.push(encode_shift(kind, T2, T3, mask as u8));
        body.push(encode(Op::Xor, T3, T3, T2, 0));
        body.push(encode(Op::And, T3, T3, T1, 0));
        body.push(encode(Op::Xor, rd, rd, T3, 0));
        body.push(encode(Op::Addi, T3, rd, 0, 0));
    }
    Some(body)
}

/// Expand register-specified shifts into branchless fixed sequences.
pub fn expand_register_shifts(program: &ProgramImage) -> Option<ProgramImage> {
    let mut changed = false;
    let mut rom = Vec::with_capacity(program.rom.len());
    for word in &program.rom {
        let instruction = magnetar_spec::decode(*word).ok()?;
        if is_pc_relative(instruction.op) || uses_temp(&instruction) {
            return None;
        }
        if let Some(body) = expand_one(&instruction) {
            rom.extend(body);
            changed = true;
        } else {
            rom.push(*word);
        }
    }
    if !changed {
        return None;
    }
    Some(ProgramImage {
        entry: program.entry,
        rom,
        data: program.data.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op};

    fn program(body: Vec<u32>) -> ProgramImage {
        ProgramImage::new(0x1000, body)
    }

    fn config() -> MachineConfig {
        MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x1000,
            stack_top: 0x1000_1000,
            max_cycles: 1000,
        }
    }

    fn assert_shift(op: Op, left: i64, amount: i64) {
        let original = program(vec![
            Instruction {
                op: Op::Addi,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: left,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Addi,
                rd: 2,
                rs1: 0,
                rs2: 0,
                imm: amount,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op,
                rd: 3,
                rs1: 1,
                rs2: 2,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction::new(Op::Ebreak).encode(),
        ]);
        let expanded = expand_register_shifts(&original).expect("expandable");
        let expected = execute(&original, config()).unwrap().final_state;
        let actual = execute(&expanded, config()).unwrap().final_state;
        assert_eq!(
            &actual.regs[..28],
            &expected.regs[..28],
            "{op:?} {left} {amount}"
        );
    }

    #[test]
    fn expansion_matches_original_shifts() {
        for op in [Op::Sll, Op::Srl, Op::Sra] {
            for left in [1i64, 0x1234_5678, -7] {
                for amount in [0i64, 1, 7, 31, 63, 70] {
                    assert_shift(op, left, amount);
                }
            }
        }
    }

    #[test]
    fn expansion_reuses_no_temporaries() {
        let program = program(vec![
            Instruction {
                op: Op::Addi,
                rd: 28,
                rs1: 0,
                rs2: 0,
                imm: 1,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Sll,
                rd: 3,
                rs1: 1,
                rs2: 2,
                imm: 0,
                shamt: 0,
            }
            .encode(),
        ]);
        assert!(expand_register_shifts(&program).is_none());
    }
}
