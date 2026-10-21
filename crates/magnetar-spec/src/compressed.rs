//! RV64C integer compressed-instruction decoder.
//!
//! The decoder expands the integer subset of the RVC extension into the
//! corresponding base `Instruction`. Floating-point compressed encodings are
//! reported as unsupported because RV64F/D are not part of the current ISA.

use crate::{Instruction, Op};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CompressedError {
    #[error("reserved compressed encoding {0:#06x}")]
    Reserved(u16),
    #[error("unsupported compressed encoding {0:#06x}")]
    Unsupported(u16),
}

fn sext(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

fn prime(inst: u16, shift: u32) -> u8 {
    8 + ((inst >> shift) & 0x7) as u8
}

fn ci_imm(inst: u16) -> i64 {
    let raw = (u64::from((inst >> 12) & 1) << 5) | u64::from((inst >> 2) & 0x1f);
    sext(raw, 6)
}

/// Decode a 16-bit RV64C instruction.
///
/// Returns `Unsupported` for compressed floating-point encodings and
/// `Reserved` for reserved code points.
pub fn decode_compressed(inst: u16) -> Result<Instruction, CompressedError> {
    if inst & 0x3 == 0x3 {
        return Err(CompressedError::Unsupported(inst));
    }
    let funct3 = (inst >> 13) & 0x7;
    let rd = ((inst >> 7) & 0x1f) as u8;
    let rs2 = ((inst >> 2) & 0x1f) as u8;
    let op = |op: Op, rd: u8, rs1: u8, rs2: u8, imm: i64, shamt: u8| Instruction {
        op,
        rd,
        rs1,
        rs2,
        imm,
        shamt,
    };
    match inst & 0x3 {
        0 => match funct3 {
            0 => {
                let nzuimm = (u64::from((inst >> 11) & 0x3) << 4)
                    | (u64::from((inst >> 7) & 0xf) << 6)
                    | (u64::from((inst >> 6) & 1) << 2)
                    | (u64::from((inst >> 5) & 1) << 3);
                if nzuimm == 0 {
                    return Err(CompressedError::Reserved(inst));
                }
                Ok(op(Op::Addi, prime(inst, 2), 2, 0, nzuimm as i64, 0))
            }
            2 => {
                let offset = (u64::from((inst >> 10) & 0x7) << 3)
                    | (u64::from((inst >> 6) & 1) << 2)
                    | (u64::from((inst >> 5) & 1) << 6);
                Ok(op(
                    Op::Lw,
                    prime(inst, 2),
                    prime(inst, 7),
                    0,
                    offset as i64,
                    0,
                ))
            }
            3 => {
                let offset = (u64::from((inst >> 10) & 0x7) << 3)
                    | (u64::from((inst >> 6) & 1) << 7)
                    | (u64::from((inst >> 5) & 1) << 6);
                Ok(op(
                    Op::Ld,
                    prime(inst, 2),
                    prime(inst, 7),
                    0,
                    offset as i64,
                    0,
                ))
            }
            6 => {
                let offset = (u64::from((inst >> 10) & 0x7) << 3)
                    | (u64::from((inst >> 6) & 1) << 2)
                    | (u64::from((inst >> 5) & 1) << 6);
                Ok(op(
                    Op::Sw,
                    0,
                    prime(inst, 7),
                    prime(inst, 2),
                    offset as i64,
                    0,
                ))
            }
            7 => {
                let offset = (u64::from((inst >> 10) & 0x7) << 3)
                    | (u64::from((inst >> 6) & 1) << 7)
                    | (u64::from((inst >> 5) & 1) << 6);
                Ok(op(
                    Op::Sd,
                    0,
                    prime(inst, 7),
                    prime(inst, 2),
                    offset as i64,
                    0,
                ))
            }
            1 | 5 => Err(CompressedError::Unsupported(inst)),
            _ => Err(CompressedError::Reserved(inst)),
        },
        1 => match funct3 {
            0 => Ok(op(Op::Addi, rd, rd, 0, ci_imm(inst), 0)),
            1 => {
                if rd == 0 {
                    return Err(CompressedError::Reserved(inst));
                }
                Ok(op(Op::Addiw, rd, rd, 0, ci_imm(inst), 0))
            }
            2 => Ok(op(Op::Addi, rd, 0, 0, ci_imm(inst), 0)),
            3 => {
                if rd == 2 {
                    let nzimm = (u64::from((inst >> 12) & 1) << 9)
                        | (u64::from((inst >> 6) & 1) << 4)
                        | (u64::from((inst >> 5) & 1) << 6)
                        | (u64::from((inst >> 4) & 0x3) << 7)
                        | (u64::from((inst >> 2) & 1) << 5);
                    if nzimm == 0 {
                        return Err(CompressedError::Reserved(inst));
                    }
                    Ok(op(Op::Addi, 2, 2, 0, sext(nzimm >> 4, 6) << 4, 0))
                } else {
                    let imm = ci_imm(inst);
                    if imm == 0 {
                        return Err(CompressedError::Reserved(inst));
                    }
                    Ok(op(Op::Lui, rd, 0, 0, imm << 12, 0))
                }
            }
            4 => {
                let funct2 = (inst >> 10) & 0x3;
                let rd_prime = prime(inst, 7);
                match funct2 {
                    0 => Ok(op(Op::Srli, rd_prime, rd_prime, 0, 0, shamt(inst))),
                    1 => Ok(op(Op::Srai, rd_prime, rd_prime, 0, 0, shamt(inst))),
                    2 => Ok(op(Op::Andi, rd_prime, rd_prime, 0, ci_imm(inst), 0)),
                    _ => {
                        let rs2_prime = prime(inst, 2);
                        if (inst >> 12) & 1 == 0 {
                            let operation = match (inst >> 5) & 0x3 {
                                0 => Op::Sub,
                                1 => Op::Xor,
                                2 => Op::Or,
                                _ => Op::And,
                            };
                            Ok(op(operation, rd_prime, rd_prime, rs2_prime, 0, 0))
                        } else {
                            match (inst >> 5) & 0x3 {
                                0 => Ok(op(Op::Subw, rd_prime, rd_prime, rs2_prime, 0, 0)),
                                1 => Ok(op(Op::Addw, rd_prime, rd_prime, rs2_prime, 0, 0)),
                                _ => Err(CompressedError::Reserved(inst)),
                            }
                        }
                    }
                }
            }
            5 => {
                let offset = (u64::from((inst >> 12) & 1) << 11)
                    | (u64::from((inst >> 11) & 1) << 4)
                    | (u64::from((inst >> 9) & 0x3) << 8)
                    | (u64::from((inst >> 8) & 1) << 10)
                    | (u64::from((inst >> 7) & 1) << 6)
                    | (u64::from((inst >> 6) & 1) << 7)
                    | (u64::from((inst >> 5) & 1) << 3)
                    | (u64::from((inst >> 3) & 0x3) << 1)
                    | (u64::from((inst >> 2) & 1) << 5);
                Ok(op(Op::Jal, 0, 0, 0, sext(offset, 12), 0))
            }
            6 | 7 => {
                let offset = (u64::from((inst >> 12) & 1) << 8)
                    | (u64::from((inst >> 10) & 0x3) << 3)
                    | (u64::from((inst >> 5) & 0x3) << 6)
                    | (u64::from((inst >> 3) & 0x3) << 1)
                    | (u64::from((inst >> 2) & 1) << 5);
                let operation = if funct3 == 6 { Op::Beq } else { Op::Bne };
                Ok(op(operation, 0, prime(inst, 7), 0, sext(offset, 9), 0))
            }
            _ => Err(CompressedError::Reserved(inst)),
        },
        2 => match funct3 {
            0 => Ok(op(Op::Slli, rd, rd, 0, 0, shamt(inst))),
            2 => {
                if rd == 0 {
                    return Err(CompressedError::Reserved(inst));
                }
                let offset = (u64::from((inst >> 4) & 0x7) << 2)
                    | (u64::from((inst >> 2) & 0x3) << 6)
                    | (u64::from((inst >> 12) & 1) << 5);
                Ok(op(Op::Lw, rd, 2, 0, offset as i64, 0))
            }
            3 => {
                if rd == 0 {
                    return Err(CompressedError::Reserved(inst));
                }
                let offset = (u64::from((inst >> 5) & 0x3) << 3)
                    | (u64::from((inst >> 2) & 0x7) << 6)
                    | (u64::from((inst >> 12) & 1) << 5);
                Ok(op(Op::Ld, rd, 2, 0, offset as i64, 0))
            }
            4 => {
                let funct4 = (inst >> 12) & 0xf;
                match funct4 {
                    0b1000 => {
                        if rs2 == 0 {
                            if rd == 0 {
                                return Err(CompressedError::Reserved(inst));
                            }
                            Ok(op(Op::Jalr, 0, rd, 0, 0, 0))
                        } else {
                            Ok(op(Op::Add, rd, 0, rs2, 0, 0))
                        }
                    }
                    0b1001 => {
                        if rs2 == 0 {
                            if rd == 0 {
                                Ok(Instruction::new(Op::Ebreak))
                            } else {
                                Ok(op(Op::Jalr, 1, rd, 0, 0, 0))
                            }
                        } else {
                            Ok(op(Op::Add, rd, rd, rs2, 0, 0))
                        }
                    }
                    _ => Err(CompressedError::Reserved(inst)),
                }
            }
            6 => {
                let offset =
                    (u64::from((inst >> 9) & 0xf) << 2) | (u64::from((inst >> 7) & 0x3) << 6);
                Ok(op(Op::Sw, 0, 2, rs2, offset as i64, 0))
            }
            7 => {
                let offset =
                    (u64::from((inst >> 10) & 0x7) << 3) | (u64::from((inst >> 7) & 0x7) << 6);
                Ok(op(Op::Sd, 0, 2, rs2, offset as i64, 0))
            }
            1 | 5 => Err(CompressedError::Unsupported(inst)),
            _ => Err(CompressedError::Reserved(inst)),
        },
        _ => Err(CompressedError::Unsupported(inst)),
    }
}

fn shamt(inst: u16) -> u8 {
    (((inst >> 12) & 1) as u8) << 5 | ((inst >> 2) & 0x1f) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_known_compressed_encodings() {
        assert_eq!(
            decode_compressed(0x0001),
            Ok(Instruction {
                op: Op::Addi,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 0,
                shamt: 0
            })
        );
        assert_eq!(
            decode_compressed(0x8082),
            Ok(Instruction {
                op: Op::Jalr,
                rd: 0,
                rs1: 1,
                rs2: 0,
                imm: 0,
                shamt: 0
            })
        );
        assert_eq!(decode_compressed(0x9002), Ok(Instruction::new(Op::Ebreak)));
    }

    #[test]
    fn decodes_integer_compressed_forms() {
        let cases = [
            (0x0800, Op::Addi, 8, 2, 0, 16),
            (0x40c0, Op::Lw, 8, 9, 0, 4),
            (0x6480, Op::Ld, 8, 9, 0, 8),
            (0xc0c0, Op::Sw, 0, 9, 8, 4),
            (0xe480, Op::Sd, 0, 9, 8, 8),
            (0x10fd, Op::Addi, 1, 1, 0, -1),
            (0x2081, Op::Addiw, 1, 1, 0, 0),
            (0x50fd, Op::Addi, 1, 0, 0, -1),
            (0x6085, Op::Lui, 1, 0, 0, 0x1000),
            (0x717d, Op::Addi, 2, 2, 0, -16),
            (0x8005, Op::Srli, 8, 8, 0, 1),
            (0x8405, Op::Srai, 8, 8, 0, 1),
            (0x8805, Op::Andi, 8, 8, 0, 1),
            (0x8c05, Op::Sub, 8, 8, 9, 0),
            (0x8c25, Op::Xor, 8, 8, 9, 0),
            (0x8c45, Op::Or, 8, 8, 9, 0),
            (0x8c65, Op::And, 8, 8, 9, 0),
            (0x9c05, Op::Subw, 8, 8, 9, 0),
            (0x9c25, Op::Addw, 8, 8, 9, 0),
            (0xa009, Op::Jal, 0, 0, 0, 2),
            (0xc009, Op::Beq, 0, 8, 0, 2),
            (0xe009, Op::Bne, 0, 8, 0, 2),
            (0x0406, Op::Slli, 8, 8, 0, 1),
            (0x4412, Op::Lw, 8, 2, 0, 4),
            (0x6422, Op::Ld, 8, 2, 0, 8),
            (0xc222, Op::Sw, 0, 2, 8, 4),
            (0xe422, Op::Sd, 0, 2, 8, 8),
            (0x808a, Op::Add, 1, 0, 2, 0),
            (0x908a, Op::Add, 1, 1, 2, 0),
            (0x9082, Op::Jalr, 1, 1, 0, 0),
        ];
        for (word, op, rd, rs1, rs2, imm) in cases {
            let decoded = decode_compressed(word).unwrap();
            assert_eq!(decoded.op, op, "{word:#06x}");
            assert_eq!(decoded.rd, rd, "{word:#06x}");
            assert_eq!(decoded.rs1, rs1, "{word:#06x}");
            assert_eq!(decoded.rs2, rs2, "{word:#06x}");
            if matches!(
                op,
                Op::Slli | Op::Srli | Op::Srai | Op::Slliw | Op::Srliw | Op::Sraiw
            ) {
                assert_eq!(decoded.shamt, imm as u8, "{word:#06x}");
            } else {
                assert_eq!(decoded.imm, imm, "{word:#06x}");
            }
        }
    }

    #[test]
    fn rejects_reserved_and_unsupported_encodings() {
        assert_eq!(
            decode_compressed(0x0000),
            Err(CompressedError::Reserved(0x0000))
        );
        assert_eq!(
            decode_compressed(0x2001),
            Err(CompressedError::Reserved(0x2001))
        );
        assert_eq!(
            decode_compressed(0x8002),
            Err(CompressedError::Reserved(0x8002))
        );
        assert_eq!(
            decode_compressed(0x2002),
            Err(CompressedError::Unsupported(0x2002))
        );
        assert_eq!(
            decode_compressed(0x2003),
            Err(CompressedError::Unsupported(0x2003))
        );
    }
}
