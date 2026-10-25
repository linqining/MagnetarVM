//! Reference fixed-instruction expansion for register-specified shifts.
//!
//! The expansion is branchless. It selects four registers that are unused by
//! the program (preferring x28-x31) and zeroes them after each expanded
//! sequence, so programs that use x28-x31 are still expandable. Static `jalr`
//! targets are resolved by constant propagation; dynamic `jalr` still falls
//! back.

use magnetar_spec::{Instruction, Op, ProgramImage};

fn choose_temps(decoded: &[Instruction]) -> Option<[u8; 4]> {
    let mut used = [false; 32];
    used[0] = true;
    for instruction in decoded {
        for register in [instruction.rd, instruction.rs1, instruction.rs2] {
            if register < 32 {
                used[register as usize] = true;
            }
        }
    }
    let mut temps = Vec::with_capacity(4);
    for register in (1u8..32).rev() {
        if !used[register as usize] {
            temps.push(register);
            if temps.len() == 4 {
                return Some([temps[0], temps[1], temps[2], temps[3]]);
            }
        }
    }
    None
}

fn is_branch(op: Op) -> bool {
    matches!(
        op,
        Op::Beq | Op::Bne | Op::Blt | Op::Bge | Op::Bltu | Op::Bgeu
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

fn shift_body(kind: Op, rd: u8, rs1: u8, rs2: u8, temps: [u8; 4]) -> Vec<u32> {
    let [t0, t1, t2, t3] = temps;
    let mut body = vec![
        encode(Op::Andi, t0, rs2, 0, 63),
        encode(Op::Addi, t3, rs1, 0, 0),
        encode(Op::Addi, rd, t3, 0, 0),
    ];
    for bit in 0..6 {
        let mask = 1i64 << bit;
        body.push(encode(Op::Andi, t1, t0, 0, mask));
        if bit > 0 {
            body.push(encode_shift(Op::Srli, t1, t1, bit));
        }
        body.push(encode(Op::Sub, t1, 0, t1, 0));
        body.push(encode_shift(kind, t2, t3, mask as u8));
        body.push(encode(Op::Xor, t3, t3, t2, 0));
        body.push(encode(Op::And, t3, t3, t1, 0));
        body.push(encode(Op::Xor, rd, rd, t3, 0));
        body.push(encode(Op::Addi, t3, rd, 0, 0));
    }
    body
}

fn static_jalr_target(
    decoded: &[Instruction],
    index: usize,
    rs1: u8,
    imm: i64,
    entry: u64,
) -> Option<usize> {
    let mut values = [None; 32];
    values[0] = Some(0u64);
    for instruction in decoded.iter().take(index) {
        if is_branch(instruction.op) || matches!(instruction.op, Op::Jal | Op::Jalr) {
            return None;
        }
        let value = match instruction.op {
            Op::Addi => values[instruction.rs1 as usize]
                .map(|value| value.wrapping_add(instruction.imm as u64)),
            Op::Lui => Some(instruction.imm as u64),
            Op::Auipc => Some(entry.wrapping_add(instruction.imm as u64)),
            _ => None,
        };
        if instruction.rd != 0 {
            values[instruction.rd as usize] = value;
        }
    }
    let target = values[rs1 as usize]?.wrapping_add(imm as u64);
    let offset = target.checked_sub(entry)?;
    if !offset.is_multiple_of(4) {
        return None;
    }
    let target = usize::try_from(offset / 4).ok()?;
    (target < decoded.len()).then_some(target)
}

fn expand_one(instruction: &Instruction, temps: [u8; 4]) -> Option<Vec<u32>> {
    let [t0, _, _, t3] = temps;
    let rd = instruction.rd;
    let rs1 = instruction.rs1;
    let rs2 = instruction.rs2;
    let body = match instruction.op {
        Op::Sll => shift_body(Op::Slli, rd, rs1, rs2, temps),
        Op::Srl => shift_body(Op::Srli, rd, rs1, rs2, temps),
        Op::Sra => shift_body(Op::Srai, rd, rs1, rs2, temps),
        Op::Sllw | Op::Srlw | Op::Sraw => {
            let mut body = vec![encode(Op::Andi, t0, rs2, 0, 31)];
            body.push(encode_shift(Op::Slli, t3, rs1, 32));
            if instruction.op == Op::Sraw {
                body.push(encode_shift(Op::Srai, t3, t3, 32));
                body.extend(shift_body(Op::Srai, rd, t3, t0, temps));
            } else {
                body.push(encode_shift(Op::Srli, t3, t3, 32));
                body.extend(shift_body(
                    if instruction.op == Op::Sllw {
                        Op::Slli
                    } else {
                        Op::Srli
                    },
                    rd,
                    t3,
                    t0,
                    temps,
                ));
            }
            body.push(encode_shift(Op::Slli, t3, rd, 32));
            body.push(encode_shift(Op::Srai, rd, t3, 32));
            body
        }
        _ => return None,
    };
    let mut body = body;
    for temp in temps {
        body.push(encode(Op::Addi, temp, 0, 0, 0));
    }
    Some(body)
}

/// Expand register-specified shifts into branchless fixed sequences.
pub fn expand_register_shifts(program: &ProgramImage) -> Option<ProgramImage> {
    let decoded = program
        .rom
        .iter()
        .map(|word| magnetar_spec::decode(*word).ok())
        .collect::<Option<Vec<_>>>()?;
    let mut jalr_targets = vec![None; decoded.len()];
    for (index, instruction) in decoded.iter().enumerate() {
        if instruction.op == Op::Jalr {
            jalr_targets[index] = Some(static_jalr_target(
                &decoded,
                index,
                instruction.rs1,
                instruction.imm,
                program.entry,
            )?);
        }
    }
    let temps = choose_temps(&decoded)?;
    let mut bodies = Vec::with_capacity(decoded.len());
    let mut changed = false;
    for instruction in &decoded {
        let body = if instruction.op == Op::Jalr {
            if instruction.rd == 0 {
                Some(vec![0])
            } else {
                Some(vec![0, 0, 0])
            }
        } else if instruction.op == Op::Auipc {
            Some(vec![instruction.encode(), 0])
        } else if instruction.op == Op::Jal && instruction.rd != 0 {
            Some(vec![0, 0, 0])
        } else {
            expand_one(instruction, temps)
        };
        changed |= body.is_some();
        bodies.push(body);
    }
    if !changed {
        return None;
    }
    let mut mapping = Vec::with_capacity(decoded.len());
    let mut rom = Vec::new();
    for body in &bodies {
        mapping.push(rom.len());
        if let Some(body) = body {
            rom.extend(body.iter().copied());
        } else {
            rom.push(0);
        }
    }
    for (index, instruction) in decoded.iter().enumerate() {
        if bodies[index].is_none() {
            rom[mapping[index]] = instruction.encode();
        }
        if instruction.op == Op::Jalr {
            let target = jalr_targets[index]?;
            let target_new = mapping[target] as i64;
            let new_index = mapping[index] as i64;
            if instruction.rd == 0 {
                let offset = (target_new - new_index) * 4;
                rom[mapping[index]] = Instruction {
                    op: Op::Jal,
                    rd: 0,
                    rs1: 0,
                    rs2: 0,
                    imm: offset,
                    shamt: 0,
                }
                .encode();
            } else {
                let old_link = (index as i64 + 1) * 4;
                let new_pc = new_index * 4;
                let delta = old_link - new_pc;
                let hi = (delta + 0x800) >> 12;
                let lo = delta - (hi << 12);
                rom[mapping[index]] = Instruction {
                    op: Op::Auipc,
                    rd: instruction.rd,
                    rs1: 0,
                    rs2: 0,
                    imm: hi << 12,
                    shamt: 0,
                }
                .encode();
                rom[mapping[index] + 1] = Instruction {
                    op: Op::Addi,
                    rd: instruction.rd,
                    rs1: instruction.rd,
                    rs2: 0,
                    imm: lo,
                    shamt: 0,
                }
                .encode();
                let offset = (target_new - (new_index + 2)) * 4;
                rom[mapping[index] + 2] = Instruction {
                    op: Op::Jal,
                    rd: 0,
                    rs1: 0,
                    rs2: 0,
                    imm: offset,
                    shamt: 0,
                }
                .encode();
            }
        }
        if instruction.op == Op::Jal && instruction.rd != 0 {
            let target = (index as i64) + instruction.imm / 4;
            if target < 0 || target as usize >= decoded.len() {
                return None;
            }
            let target_new = mapping[target as usize] as i64;
            let new_index = mapping[index] as i64;
            let old_link = (index as i64 + 1) * 4;
            let new_pc = new_index * 4;
            let delta = old_link - new_pc;
            if !(-(1i64 << 31)..(1i64 << 31)).contains(&delta) {
                return None;
            }
            let hi = (delta + 0x800) >> 12;
            let lo = delta - (hi << 12);
            rom[mapping[index]] = Instruction {
                op: Op::Auipc,
                rd: instruction.rd,
                rs1: 0,
                rs2: 0,
                imm: hi << 12,
                shamt: 0,
            }
            .encode();
            rom[mapping[index] + 1] = Instruction {
                op: Op::Addi,
                rd: instruction.rd,
                rs1: instruction.rd,
                rs2: 0,
                imm: lo,
                shamt: 0,
            }
            .encode();
            let offset = (target_new - (new_index + 2)) * 4;
            rom[mapping[index] + 2] = Instruction {
                op: Op::Jal,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: offset,
                shamt: 0,
            }
            .encode();
        }
        if instruction.op == Op::Auipc {
            let delta = (mapping[index] as i64 - index as i64) * 4;
            let correction = -delta;
            if !(-2048..=2047).contains(&correction) {
                return None;
            }
            rom[mapping[index] + 1] = Instruction {
                op: Op::Addi,
                rd: instruction.rd,
                rs1: instruction.rd,
                rs2: 0,
                imm: correction,
                shamt: 0,
            }
            .encode();
        }
        if !is_branch(instruction.op) && instruction.op != Op::Jal {
            continue;
        }
        let target = (index as i64) + instruction.imm / 4;
        if target < 0 || target as usize >= decoded.len() {
            return None;
        }
        let relocated = (mapping[target as usize] as i64 - mapping[index] as i64) * 4;
        let mut branch = *instruction;
        branch.imm = relocated;
        rom[mapping[index]] = branch.encode();
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
    fn execute_expanded_matches_direct_execution() {
        let original = program(vec![
            Instruction {
                op: Op::Addi,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 0x1234,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Addi,
                rd: 2,
                rs1: 0,
                rs2: 0,
                imm: 9,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Srl,
                rd: 3,
                rs1: 1,
                rs2: 2,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction::new(Op::Ebreak).encode(),
        ]);
        let direct = execute(&original, config()).unwrap();
        let expanded = crate::execute_expanded(&original, config()).unwrap();
        assert_eq!(
            &expanded.final_state.regs[..28],
            &direct.final_state.regs[..28]
        );
    }

    #[test]
    fn word_expansion_matches_original_shifts() {
        for op in [Op::Sllw, Op::Srlw, Op::Sraw] {
            for left in [1i64, 0x1234_5678, -7] {
                for amount in [0i64, 1, 7, 31, 32, 70] {
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
            }
        }
    }

    #[test]
    fn branch_targets_are_relocated() {
        let original = program(vec![
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
                imm: 1,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Beq,
                rd: 0,
                rs1: 1,
                rs2: 1,
                imm: 8,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Sll,
                rd: 5,
                rs1: 1,
                rs2: 2,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Addi,
                rd: 6,
                rs1: 0,
                rs2: 0,
                imm: 9,
                shamt: 0,
            }
            .encode(),
            Instruction::new(Op::Ebreak).encode(),
        ]);
        let expanded = expand_register_shifts(&original).expect("expandable");
        let direct = execute(&original, config()).unwrap().final_state;
        let actual = execute(&expanded, config()).unwrap().final_state;
        assert_eq!(direct.reg(5), 0);
        assert_eq!(direct.reg(6), 9);
        assert_eq!(&actual.regs[..28], &direct.regs[..28]);
    }

    #[test]
    fn jal_zero_link_is_relocated() {
        let original = program(vec![
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
                imm: 1,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Jal,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 8,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Sll,
                rd: 5,
                rs1: 1,
                rs2: 2,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Addi,
                rd: 6,
                rs1: 0,
                rs2: 0,
                imm: 9,
                shamt: 0,
            }
            .encode(),
            Instruction::new(Op::Ebreak).encode(),
        ]);
        let expanded = expand_register_shifts(&original).expect("expandable");
        let direct = execute(&original, config()).unwrap().final_state;
        let actual = execute(&expanded, config()).unwrap().final_state;
        assert_eq!(direct.reg(5), 0);
        assert_eq!(direct.reg(6), 9);
        assert_eq!(&actual.regs[..28], &direct.regs[..28]);
    }

    #[test]
    fn auipc_values_are_preserved() {
        let original = program(vec![
            Instruction {
                op: Op::Auipc,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Addi,
                rd: 2,
                rs1: 1,
                rs2: 0,
                imm: 16,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Addi,
                rd: 3,
                rs1: 0,
                rs2: 0,
                imm: 4,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Addi,
                rd: 4,
                rs1: 0,
                rs2: 0,
                imm: 1,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Sll,
                rd: 5,
                rs1: 3,
                rs2: 4,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction::new(Op::Ebreak).encode(),
        ]);
        let expanded = expand_register_shifts(&original).expect("expandable");
        let direct = execute(&original, config()).unwrap().final_state;
        let actual = execute(&expanded, config()).unwrap().final_state;
        assert_eq!(direct.reg(1), 0x1000);
        assert_eq!(&actual.regs[..28], &direct.regs[..28]);
    }

    #[test]
    fn jal_link_values_are_preserved() {
        let original = program(vec![
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
                imm: 1,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Jal,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 8,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Sll,
                rd: 5,
                rs1: 1,
                rs2: 2,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Addi,
                rd: 6,
                rs1: 0,
                rs2: 0,
                imm: 9,
                shamt: 0,
            }
            .encode(),
            Instruction::new(Op::Ebreak).encode(),
        ]);
        let expanded = expand_register_shifts(&original).expect("expandable");
        let direct = execute(&original, config()).unwrap().final_state;
        let actual = execute(&expanded, config()).unwrap().final_state;
        assert_eq!(direct.reg(1), 0x100c);
        assert_eq!(direct.reg(5), 0);
        assert_eq!(&actual.regs[..28], &direct.regs[..28]);
    }

    #[test]
    fn static_jalr_is_relocated() {
        let program = program(vec![
            Instruction {
                op: Op::Auipc,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Addi,
                rd: 1,
                rs1: 1,
                rs2: 0,
                imm: 16,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Jalr,
                rd: 0,
                rs1: 1,
                rs2: 0,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Addi,
                rd: 3,
                rs1: 0,
                rs2: 0,
                imm: 7,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Addi,
                rd: 4,
                rs1: 0,
                rs2: 0,
                imm: 1,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Sll,
                rd: 5,
                rs1: 3,
                rs2: 4,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction::new(Op::Ebreak).encode(),
        ]);
        let expanded = expand_register_shifts(&program).expect("expandable");
        let direct = execute(&program, config()).unwrap().final_state;
        let actual = execute(&expanded, config()).unwrap().final_state;
        assert_eq!(actual.regs, direct.regs);
    }

    #[test]
    fn dynamic_jalr_falls_back() {
        let program = program(vec![
            Instruction {
                op: Op::Lui,
                rd: 20,
                rs1: 0,
                rs2: 0,
                imm: 0x1000_0000,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Ld,
                rd: 1,
                rs1: 20,
                rs2: 0,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Jalr,
                rd: 0,
                rs1: 1,
                rs2: 0,
                imm: 0,
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
            Instruction::new(Op::Ebreak).encode(),
        ]);
        assert!(expand_register_shifts(&program).is_none());
    }

    #[test]
    fn execute_expanded_handles_static_jalr() {
        let program = program(vec![
            Instruction {
                op: Op::Auipc,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Addi,
                rd: 1,
                rs1: 1,
                rs2: 0,
                imm: 12,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Jalr,
                rd: 0,
                rs1: 1,
                rs2: 0,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Addi,
                rd: 3,
                rs1: 0,
                rs2: 0,
                imm: 7,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Addi,
                rd: 2,
                rs1: 0,
                rs2: 0,
                imm: 1,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Sll,
                rd: 4,
                rs1: 3,
                rs2: 2,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction::new(Op::Ebreak).encode(),
        ]);
        let direct = execute(&program, config()).unwrap().final_state;
        let fallback = crate::execute_expanded(&program, config())
            .unwrap()
            .final_state;
        assert_eq!(direct.regs, fallback.regs);
        assert_eq!(fallback.reg(4), 14);
    }

    #[test]
    fn backward_branch_is_relocated() {
        let original = program(vec![
            Instruction {
                op: Op::Addi,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 3,
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
            Instruction {
                op: Op::Addi,
                rd: 5,
                rs1: 0,
                rs2: 0,
                imm: 1,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Sll,
                rd: 5,
                rs1: 5,
                rs2: 2,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Addi,
                rd: 1,
                rs1: 1,
                rs2: 0,
                imm: -1,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Bne,
                rd: 0,
                rs1: 1,
                rs2: 0,
                imm: -8,
                shamt: 0,
            }
            .encode(),
            Instruction::new(Op::Ebreak).encode(),
        ]);
        let expanded = expand_register_shifts(&original).expect("expandable");
        let direct = execute(&original, config()).unwrap().final_state;
        let actual = execute(&expanded, config()).unwrap().final_state;
        assert!(direct.reg(5) > 1);
        assert_eq!(&actual.regs[..28], &direct.regs[..28]);
    }

    #[test]
    fn expansion_preserves_x28_x31_users() {
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
                op: Op::Addi,
                rd: 29,
                rs1: 0,
                rs2: 0,
                imm: 2,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Addi,
                rd: 30,
                rs1: 0,
                rs2: 0,
                imm: 3,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Addi,
                rd: 31,
                rs1: 0,
                rs2: 0,
                imm: 4,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Sll,
                rd: 3,
                rs1: 28,
                rs2: 29,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction::new(Op::Ebreak).encode(),
        ]);
        let expanded = expand_register_shifts(&program).expect("expandable");
        let direct = execute(&program, config()).unwrap().final_state;
        let actual = execute(&expanded, config()).unwrap().final_state;
        assert_eq!(actual.regs, direct.regs);
    }
}
