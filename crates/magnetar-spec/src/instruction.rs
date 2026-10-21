use crate::RegIdx;
use thiserror::Error;

/// RV64I base integer operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Add,
    Sub,
    Sll,
    Slt,
    Sltu,
    Xor,
    Srl,
    Sra,
    Or,
    And,
    Addi,
    Slti,
    Sltiu,
    Xori,
    Ori,
    Andi,
    Slli,
    Srli,
    Srai,
    Lui,
    Auipc,
    Jal,
    Jalr,
    Beq,
    Bne,
    Blt,
    Bge,
    Bltu,
    Bgeu,
    Lb,
    Lh,
    Lw,
    Ld,
    Lbu,
    Lhu,
    Lwu,
    Sb,
    Sh,
    Sw,
    Sd,
    Fence,
    Ecall,
    Ebreak,
}

impl Op {
    pub fn writes_rd(self) -> bool {
        !matches!(
            self,
            Op::Beq
                | Op::Bne
                | Op::Blt
                | Op::Bge
                | Op::Bltu
                | Op::Bgeu
                | Op::Sb
                | Op::Sh
                | Op::Sw
                | Op::Sd
                | Op::Fence
                | Op::Ecall
                | Op::Ebreak
        )
    }

    pub fn reads_rs1(self) -> bool {
        matches!(
            self,
            Op::Add
                | Op::Sub
                | Op::Sll
                | Op::Slt
                | Op::Sltu
                | Op::Xor
                | Op::Srl
                | Op::Sra
                | Op::Or
                | Op::And
                | Op::Addi
                | Op::Slti
                | Op::Sltiu
                | Op::Xori
                | Op::Ori
                | Op::Andi
                | Op::Slli
                | Op::Srli
                | Op::Srai
                | Op::Jalr
                | Op::Beq
                | Op::Bne
                | Op::Blt
                | Op::Bge
                | Op::Bltu
                | Op::Bgeu
                | Op::Lb
                | Op::Lh
                | Op::Lw
                | Op::Ld
                | Op::Lbu
                | Op::Lhu
                | Op::Lwu
                | Op::Sb
                | Op::Sh
                | Op::Sw
                | Op::Sd
        )
    }

    pub fn reads_rs2(self) -> bool {
        matches!(
            self,
            Op::Add
                | Op::Sub
                | Op::Sll
                | Op::Slt
                | Op::Sltu
                | Op::Xor
                | Op::Srl
                | Op::Sra
                | Op::Or
                | Op::And
                | Op::Beq
                | Op::Bne
                | Op::Blt
                | Op::Bge
                | Op::Bltu
                | Op::Bgeu
                | Op::Sb
                | Op::Sh
                | Op::Sw
                | Op::Sd
        )
    }

    pub fn is_branch(self) -> bool {
        matches!(
            self,
            Op::Beq | Op::Bne | Op::Blt | Op::Bge | Op::Bltu | Op::Bgeu
        )
    }

    pub fn is_load(self) -> bool {
        matches!(
            self,
            Op::Lb | Op::Lh | Op::Lw | Op::Ld | Op::Lbu | Op::Lhu | Op::Lwu
        )
    }

    pub fn is_store(self) -> bool {
        matches!(self, Op::Sb | Op::Sh | Op::Sw | Op::Sd)
    }

    pub fn is_jump(self) -> bool {
        matches!(self, Op::Jal | Op::Jalr)
    }

    pub fn is_halt(self) -> bool {
        matches!(self, Op::Ecall | Op::Ebreak)
    }

    pub fn name(self) -> &'static str {
        match self {
            Op::Add => "add",
            Op::Sub => "sub",
            Op::Sll => "sll",
            Op::Slt => "slt",
            Op::Sltu => "sltu",
            Op::Xor => "xor",
            Op::Srl => "srl",
            Op::Sra => "sra",
            Op::Or => "or",
            Op::And => "and",
            Op::Addi => "addi",
            Op::Slti => "slti",
            Op::Sltiu => "sltiu",
            Op::Xori => "xori",
            Op::Ori => "ori",
            Op::Andi => "andi",
            Op::Slli => "slli",
            Op::Srli => "srli",
            Op::Srai => "srai",
            Op::Lui => "lui",
            Op::Auipc => "auipc",
            Op::Jal => "jal",
            Op::Jalr => "jalr",
            Op::Beq => "beq",
            Op::Bne => "bne",
            Op::Blt => "blt",
            Op::Bge => "bge",
            Op::Bltu => "bltu",
            Op::Bgeu => "bgeu",
            Op::Lb => "lb",
            Op::Lh => "lh",
            Op::Lw => "lw",
            Op::Ld => "ld",
            Op::Lbu => "lbu",
            Op::Lhu => "lhu",
            Op::Lwu => "lwu",
            Op::Sb => "sb",
            Op::Sh => "sh",
            Op::Sw => "sw",
            Op::Sd => "sd",
            Op::Fence => "fence",
            Op::Ecall => "ecall",
            Op::Ebreak => "ebreak",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Instruction {
    pub op: Op,
    pub rd: u8,
    pub rs1: u8,
    pub rs2: u8,
    pub imm: i64,
    pub shamt: u8,
}

impl Instruction {
    pub fn new(op: Op) -> Self {
        Self {
            op,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
            shamt: 0,
        }
    }

    pub fn rd_index(&self) -> Option<RegIdx> {
        self.op.writes_rd().then_some(self.rd as RegIdx)
    }

    pub fn rs1_index(&self) -> Option<RegIdx> {
        self.op.reads_rs1().then_some(self.rs1 as RegIdx)
    }

    pub fn rs2_index(&self) -> Option<RegIdx> {
        self.op.reads_rs2().then_some(self.rs2 as RegIdx)
    }

    pub fn encode(self) -> u32 {
        let rd = u32::from(self.rd) & 0x1f;
        let rs1 = u32::from(self.rs1) & 0x1f;
        let rs2 = u32::from(self.rs2) & 0x1f;
        let shamt = u32::from(self.shamt) & 0x3f;

        let r = |funct3: u32, funct7: u32| {
            (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x33
        };
        let i = |funct3: u32, imm: i64| {
            (((imm as u32) & 0xfff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x13
        };
        let load = |funct3: u32, imm: i64| {
            (((imm as u32) & 0xfff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x03
        };
        let store = |funct3: u32, imm: i64| {
            (((imm as u32) >> 5 & 0x7f) << 25)
                | (rs2 << 20)
                | (rs1 << 15)
                | (funct3 << 12)
                | (((imm as u32) & 0x1f) << 7)
                | 0x23
        };
        let branch = |funct3: u32, imm: i64| {
            let imm = imm as u32;
            (((imm >> 12) & 1) << 31)
                | (((imm >> 5) & 0x3f) << 25)
                | (rs2 << 20)
                | (rs1 << 15)
                | (funct3 << 12)
                | (((imm >> 1) & 0xf) << 8)
                | (((imm >> 11) & 1) << 7)
                | 0x63
        };
        let u = |opcode: u32, imm: i64| ((imm as u32) & 0xffff_f000) | (rd << 7) | opcode;
        let j = |imm: i64| {
            let imm = imm as u32;
            (((imm >> 20) & 1) << 31)
                | (((imm >> 1) & 0x3ff) << 21)
                | (((imm >> 11) & 1) << 20)
                | (((imm >> 12) & 0xff) << 12)
                | (rd << 7)
                | 0x6f
        };
        let shift_imm = |funct3: u32, funct6: u32| {
            (funct6 << 26)
                | (((shamt >> 5) & 1) << 25)
                | ((shamt & 0x1f) << 20)
                | (rs1 << 15)
                | (funct3 << 12)
                | (rd << 7)
                | 0x13
        };

        match self.op {
            Op::Add => r(0, 0x00),
            Op::Sub => r(0, 0x20),
            Op::Sll => r(1, 0x00),
            Op::Slt => r(2, 0x00),
            Op::Sltu => r(3, 0x00),
            Op::Xor => r(4, 0x00),
            Op::Srl => r(5, 0x00),
            Op::Sra => r(5, 0x20),
            Op::Or => r(6, 0x00),
            Op::And => r(7, 0x00),
            Op::Addi => i(0, self.imm),
            Op::Slti => i(2, self.imm),
            Op::Sltiu => i(3, self.imm),
            Op::Xori => i(4, self.imm),
            Op::Ori => i(6, self.imm),
            Op::Andi => i(7, self.imm),
            Op::Slli => shift_imm(1, 0),
            Op::Srli => shift_imm(5, 0),
            Op::Srai => shift_imm(5, 0b010000),
            Op::Lui => u(0x37, self.imm),
            Op::Auipc => u(0x17, self.imm),
            Op::Jal => j(self.imm),
            Op::Jalr => (((self.imm as u32) & 0xfff) << 20) | (rs1 << 15) | (rd << 7) | 0x67,
            Op::Beq => branch(0, self.imm),
            Op::Bne => branch(1, self.imm),
            Op::Blt => branch(4, self.imm),
            Op::Bge => branch(5, self.imm),
            Op::Bltu => branch(6, self.imm),
            Op::Bgeu => branch(7, self.imm),
            Op::Lb => load(0, self.imm),
            Op::Lh => load(1, self.imm),
            Op::Lw => load(2, self.imm),
            Op::Ld => load(3, self.imm),
            Op::Lbu => load(4, self.imm),
            Op::Lhu => load(5, self.imm),
            Op::Lwu => load(6, self.imm),
            Op::Sb => store(0, self.imm),
            Op::Sh => store(1, self.imm),
            Op::Sw => store(2, self.imm),
            Op::Sd => store(3, self.imm),
            Op::Fence => 0x0ff0_000f,
            Op::Ecall => 0x0000_0073,
            Op::Ebreak => 0x0010_0073,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("illegal instruction 0x{0:08x}")]
    Illegal(u32),
    #[error("unsupported system instruction 0x{0:08x}")]
    UnsupportedSystem(u32),
}

pub fn decode(word: u32) -> Result<Instruction, DecodeError> {
    let opcode = word & 0x7f;
    let rd = ((word >> 7) & 0x1f) as u8;
    let funct3 = (word >> 12) & 0x7;
    let rs1 = ((word >> 15) & 0x1f) as u8;
    let rs2 = ((word >> 20) & 0x1f) as u8;
    let funct7 = (word >> 25) & 0x7f;

    let mut inst = Instruction::new(Op::Fence);
    match opcode {
        0x33 => {
            let op = match funct3 {
                0 if funct7 == 0x00 => Op::Add,
                0 if funct7 == 0x20 => Op::Sub,
                1 if funct7 == 0x00 => Op::Sll,
                2 if funct7 == 0x00 => Op::Slt,
                3 if funct7 == 0x00 => Op::Sltu,
                4 if funct7 == 0x00 => Op::Xor,
                5 if funct7 == 0x00 => Op::Srl,
                5 if funct7 == 0x20 => Op::Sra,
                6 if funct7 == 0x00 => Op::Or,
                7 if funct7 == 0x00 => Op::And,
                _ => return Err(DecodeError::Illegal(word)),
            };
            inst.op = op;
            inst.rd = rd;
            inst.rs1 = rs1;
            inst.rs2 = rs2;
        }
        0x13 => {
            let funct6 = (word >> 26) & 0x3f;
            let shamt = ((word >> 20) & 0x3f) as u8;
            let op = match funct3 {
                0 => Op::Addi,
                2 => Op::Slti,
                3 => Op::Sltiu,
                4 => Op::Xori,
                6 => Op::Ori,
                7 => Op::Andi,
                1 if funct6 == 0 => Op::Slli,
                5 if funct6 == 0 => Op::Srli,
                5 if funct6 == 0b010000 => Op::Srai,
                _ => return Err(DecodeError::Illegal(word)),
            };
            inst.op = op;
            inst.rd = rd;
            inst.rs1 = rs1;
            if matches!(op, Op::Slli | Op::Srli | Op::Srai) {
                inst.shamt = shamt;
            } else {
                inst.imm = sext(word >> 20, 12);
            }
        }
        0x03 => {
            let op = match funct3 {
                0 => Op::Lb,
                1 => Op::Lh,
                2 => Op::Lw,
                3 => Op::Ld,
                4 => Op::Lbu,
                5 => Op::Lhu,
                6 => Op::Lwu,
                _ => return Err(DecodeError::Illegal(word)),
            };
            inst.op = op;
            inst.rd = rd;
            inst.rs1 = rs1;
            inst.imm = sext(word >> 20, 12);
        }
        0x23 => {
            let op = match funct3 {
                0 => Op::Sb,
                1 => Op::Sh,
                2 => Op::Sw,
                3 => Op::Sd,
                _ => return Err(DecodeError::Illegal(word)),
            };
            inst.op = op;
            inst.rs1 = rs1;
            inst.rs2 = rs2;
            let imm = ((word >> 25) & 0x7f) << 5 | ((word >> 7) & 0x1f);
            inst.imm = sext(imm, 12);
        }
        0x63 => {
            let op = match funct3 {
                0 => Op::Beq,
                1 => Op::Bne,
                4 => Op::Blt,
                5 => Op::Bge,
                6 => Op::Bltu,
                7 => Op::Bgeu,
                _ => return Err(DecodeError::Illegal(word)),
            };
            inst.op = op;
            inst.rs1 = rs1;
            inst.rs2 = rs2;
            let imm = ((word >> 31) & 1) << 12
                | ((word >> 25) & 0x3f) << 5
                | ((word >> 8) & 0xf) << 1
                | ((word >> 7) & 1) << 11;
            inst.imm = sext(imm, 13);
        }
        0x37 => {
            inst.op = Op::Lui;
            inst.rd = rd;
            inst.imm = ((word & 0xffff_f000) as i32) as i64;
        }
        0x17 => {
            inst.op = Op::Auipc;
            inst.rd = rd;
            inst.imm = ((word & 0xffff_f000) as i32) as i64;
        }
        0x6f => {
            inst.op = Op::Jal;
            inst.rd = rd;
            let imm = ((word >> 31) & 1) << 20
                | ((word >> 21) & 0x3ff) << 1
                | ((word >> 20) & 1) << 11
                | ((word >> 12) & 0xff) << 12;
            inst.imm = sext(imm, 21);
        }
        0x67 if funct3 == 0 => {
            inst.op = Op::Jalr;
            inst.rd = rd;
            inst.rs1 = rs1;
            inst.imm = sext(word >> 20, 12);
        }
        0x0f => {
            inst.op = Op::Fence;
        }
        0x73 if funct3 == 0 && rd == 0 && rs1 == 0 => {
            let imm = word >> 20;
            inst.op = match imm {
                0 => Op::Ecall,
                1 => Op::Ebreak,
                _ => return Err(DecodeError::UnsupportedSystem(word)),
            };
        }
        _ => return Err(DecodeError::Illegal(word)),
    }
    Ok(inst)
}

fn sext(value: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    (i64::from(value) << shift) >> shift
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_base_instructions() {
        let cases = [
            Instruction {
                op: Op::Add,
                rd: 3,
                rs1: 1,
                rs2: 2,
                imm: 0,
                shamt: 0,
            },
            Instruction {
                op: Op::Addi,
                rd: 3,
                rs1: 1,
                rs2: 0,
                imm: -7,
                shamt: 0,
            },
            Instruction {
                op: Op::Srai,
                rd: 3,
                rs1: 1,
                rs2: 0,
                imm: 0,
                shamt: 33,
            },
            Instruction {
                op: Op::Lui,
                rd: 3,
                rs1: 0,
                rs2: 0,
                imm: 0x1234_5000,
                shamt: 0,
            },
            Instruction {
                op: Op::Jal,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 0x20,
                shamt: 0,
            },
            Instruction {
                op: Op::Beq,
                rd: 0,
                rs1: 1,
                rs2: 2,
                imm: -8,
                shamt: 0,
            },
            Instruction {
                op: Op::Sw,
                rd: 0,
                rs1: 1,
                rs2: 2,
                imm: -4,
                shamt: 0,
            },
            Instruction {
                op: Op::Ld,
                rd: 3,
                rs1: 1,
                rs2: 0,
                imm: 8,
                shamt: 0,
            },
        ];
        for case in cases {
            let word = case.encode();
            assert_eq!(decode(word), Ok(case), "word={word:08x}");
        }
    }

    #[test]
    fn rejects_unknown_opcode() {
        assert!(matches!(decode(0xffff_ffff), Err(DecodeError::Illegal(_))));
    }
}
