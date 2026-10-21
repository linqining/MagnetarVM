//! RV64F/D instruction decoding.
//!
//! This is a syntax-level decoder for the core single/double-precision
//! floating-point instructions. The reference executor does not yet execute
//! FP rows or witness them in CPU constraints.

use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FpFormat {
    Single,
    Double,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FpOp {
    Flw,
    Fsw,
    Fld,
    Fsd,
    Fadd,
    Fsub,
    Fmul,
    Fdiv,
    Fsqrt,
    Fsgnj,
    Fsgnjn,
    Fsgnjx,
    Fmin,
    Fmax,
    Feq,
    Flt,
    Fle,
    FcvtW,
    FcvtWu,
    FcvtL,
    FcvtLu,
    FcvtSw,
    FcvtSwu,
    FcvtSl,
    FcvtSlu,
    FmvToX,
    Fclass,
    FmvFromX,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FpInstruction {
    pub op: FpOp,
    pub fmt: FpFormat,
    pub rd: u8,
    pub rs1: u8,
    pub rs2: u8,
    pub rm: u8,
    pub imm: i64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FpDecodeError {
    #[error("illegal floating-point instruction 0x{0:08x}")]
    Illegal(u32),
}

fn sext(value: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    (i64::from(value) << shift) >> shift
}

pub fn decode_fp(word: u32) -> Result<FpInstruction, FpDecodeError> {
    let opcode = word & 0x7f;
    let rd = ((word >> 7) & 0x1f) as u8;
    let funct3 = (word >> 12) & 0x7;
    let rs1 = ((word >> 15) & 0x1f) as u8;
    let rs2 = ((word >> 20) & 0x1f) as u8;
    let funct7 = (word >> 25) & 0x7f;
    let rm = ((word >> 12) & 0x7) as u8;
    let instruction = |op, fmt, rd, rs1, rs2, imm| FpInstruction {
        op,
        fmt,
        rd,
        rs1,
        rs2,
        rm,
        imm,
    };
    match opcode {
        0x07 => {
            let (op, fmt) = match funct3 {
                2 => (FpOp::Flw, FpFormat::Single),
                3 => (FpOp::Fld, FpFormat::Double),
                _ => return Err(FpDecodeError::Illegal(word)),
            };
            Ok(instruction(op, fmt, rd, rs1, 0, sext(word >> 20, 12)))
        }
        0x27 => {
            let (op, fmt) = match funct3 {
                2 => (FpOp::Fsw, FpFormat::Single),
                3 => (FpOp::Fsd, FpFormat::Double),
                _ => return Err(FpDecodeError::Illegal(word)),
            };
            let imm = ((word >> 25) << 5) | ((word >> 7) & 0x1f);
            Ok(instruction(op, fmt, 0, rs1, rs2, sext(imm, 12)))
        }
        0x53 => {
            let fmt = if funct7 & 1 == 0 {
                FpFormat::Single
            } else {
                FpFormat::Double
            };
            let op = match funct7 & !1 {
                0x00 => FpOp::Fadd,
                0x04 => FpOp::Fsub,
                0x08 => FpOp::Fmul,
                0x0c => FpOp::Fdiv,
                0x2c if rs2 == 0 => FpOp::Fsqrt,
                0x10 => match funct3 {
                    0 => FpOp::Fsgnj,
                    1 => FpOp::Fsgnjn,
                    2 => FpOp::Fsgnjx,
                    _ => return Err(FpDecodeError::Illegal(word)),
                },
                0x14 => match funct3 {
                    0 => FpOp::Fmin,
                    1 => FpOp::Fmax,
                    _ => return Err(FpDecodeError::Illegal(word)),
                },
                0x50 => match funct3 {
                    0 => FpOp::Fle,
                    1 => FpOp::Flt,
                    2 => FpOp::Feq,
                    _ => return Err(FpDecodeError::Illegal(word)),
                },
                0x60 => match rs2 {
                    0 => FpOp::FcvtW,
                    1 => FpOp::FcvtWu,
                    2 => FpOp::FcvtL,
                    3 => FpOp::FcvtLu,
                    _ => return Err(FpDecodeError::Illegal(word)),
                },
                0x68 => match rs2 {
                    0 => FpOp::FcvtSw,
                    1 => FpOp::FcvtSwu,
                    2 => FpOp::FcvtSl,
                    3 => FpOp::FcvtSlu,
                    _ => return Err(FpDecodeError::Illegal(word)),
                },
                0x70 if rs2 == 0 => match funct3 {
                    0 => FpOp::FmvToX,
                    1 => FpOp::Fclass,
                    _ => return Err(FpDecodeError::Illegal(word)),
                },
                0x78 if rs2 == 0 && funct3 == 0 => FpOp::FmvFromX,
                _ => return Err(FpDecodeError::Illegal(word)),
            };
            Ok(instruction(op, fmt, rd, rs1, rs2, 0))
        }
        _ => Err(FpDecodeError::Illegal(word)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(funct7: u32, rd: u8, rs1: u8, rs2: u8, funct3: u32, opcode: u32) -> u32 {
        (funct7 << 25)
            | (u32::from(rs2) << 20)
            | (u32::from(rs1) << 15)
            | (funct3 << 12)
            | (u32::from(rd) << 7)
            | opcode
    }

    #[test]
    fn decodes_loads_and_stores() {
        let flw = decode_fp(word(0, 3, 4, 0, 2, 0x07)).unwrap();
        assert_eq!(flw.op, FpOp::Flw);
        assert_eq!(flw.fmt, FpFormat::Single);
        assert_eq!((flw.rd, flw.rs1), (3, 4));

        let fsd = decode_fp(word(0, 0, 4, 5, 3, 0x27)).unwrap();
        assert_eq!(fsd.op, FpOp::Fsd);
        assert_eq!(fsd.fmt, FpFormat::Double);
        assert_eq!((fsd.rs1, fsd.rs2), (4, 5));

        let negative = word(0x7f, 0, 4, 0x18, 2, 0x07);
        assert_eq!(decode_fp(negative).unwrap().imm, -8);
    }

    #[test]
    fn decodes_arithmetic_and_rounding_modes() {
        let fadd = decode_fp(word(0x00, 1, 2, 3, 7, 0x53)).unwrap();
        assert_eq!(
            fadd,
            FpInstruction {
                op: FpOp::Fadd,
                fmt: FpFormat::Single,
                rd: 1,
                rs1: 2,
                rs2: 3,
                rm: 7,
                imm: 0,
            }
        );
        let fdiv_d = decode_fp(word(0x0d, 1, 2, 3, 3, 0x53)).unwrap();
        assert_eq!((fdiv_d.op, fdiv_d.fmt), (FpOp::Fdiv, FpFormat::Double));
        assert_eq!(fdiv_d.rm, 3);
    }

    #[test]
    fn decodes_conversions_and_classification() {
        let fcvt = decode_fp(word(0x61, 1, 2, 0, 7, 0x53)).unwrap();
        assert_eq!((fcvt.op, fcvt.fmt), (FpOp::FcvtW, FpFormat::Double));
        let fcvt_lu = decode_fp(word(0x69, 1, 2, 3, 7, 0x53)).unwrap();
        assert_eq!((fcvt_lu.op, fcvt_lu.fmt), (FpOp::FcvtSlu, FpFormat::Double));
        let fclass = decode_fp(word(0x70, 1, 2, 0, 1, 0x53)).unwrap();
        assert_eq!(fclass.op, FpOp::Fclass);
        let fmv = decode_fp(word(0x79, 1, 2, 0, 0, 0x53)).unwrap();
        assert_eq!((fmv.op, fmv.fmt), (FpOp::FmvFromX, FpFormat::Double));
    }

    #[test]
    fn rejects_illegal_encodings() {
        assert_eq!(decode_fp(0x0000_0000), Err(FpDecodeError::Illegal(0)));
        assert_eq!(
            decode_fp(word(0x00, 1, 2, 3, 0, 0x13)),
            Err(FpDecodeError::Illegal(word(0x00, 1, 2, 3, 0, 0x13)))
        );
        assert_eq!(
            decode_fp(word(0x2d, 1, 2, 1, 7, 0x53)),
            Err(FpDecodeError::Illegal(word(0x2d, 1, 2, 1, 7, 0x53)))
        );
    }
}
