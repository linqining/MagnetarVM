use crate::{RegIdx, Word};
use thiserror::Error;

/// RV64I base integer operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    Addw,
    Subw,
    Sllw,
    Srlw,
    Sraw,
    Mul,
    Mulh,
    Mulhsu,
    Mulhu,
    Div,
    Divu,
    Rem,
    Remu,
    AmoswapW,
    AmoswapD,
    AmoaddW,
    AmoaddD,
    AmoxorW,
    AmoxorD,
    AmoandW,
    AmoandD,
    AmoorW,
    AmoorD,
    AmominW,
    AmominD,
    AmomaxW,
    AmomaxD,
    AmominuW,
    AmominuD,
    AmomaxuW,
    AmomaxuD,
    LrW,
    LrD,
    ScW,
    ScD,
    Addi,
    Addiw,
    Slti,
    Sltiu,
    Xori,
    Ori,
    Andi,
    Slli,
    Slliw,
    Srli,
    Srliw,
    Srai,
    Sraiw,
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
                | Op::Addw
                | Op::Subw
                | Op::Sllw
                | Op::Srlw
                | Op::Sraw
                | Op::Mul
                | Op::Mulh
                | Op::Mulhsu
                | Op::Mulhu
                | Op::Div
                | Op::Divu
                | Op::Rem
                | Op::Remu
                | Op::AmoswapW
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
                | Op::AmomaxuD
                | Op::LrW
                | Op::LrD
                | Op::ScW
                | Op::ScD
                | Op::Addi
                | Op::Addiw
                | Op::Slti
                | Op::Sltiu
                | Op::Xori
                | Op::Ori
                | Op::Andi
                | Op::Slli
                | Op::Slliw
                | Op::Srli
                | Op::Srliw
                | Op::Srai
                | Op::Sraiw
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
                | Op::Addw
                | Op::Subw
                | Op::Sllw
                | Op::Srlw
                | Op::Sraw
                | Op::Mul
                | Op::Mulh
                | Op::Mulhsu
                | Op::Mulhu
                | Op::Div
                | Op::Divu
                | Op::Rem
                | Op::Remu
                | Op::AmoswapW
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
                | Op::AmomaxuD
                | Op::ScW
                | Op::ScD
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

    pub fn amo_width(self) -> Option<usize> {
        match self {
            Op::AmoswapW
            | Op::AmoaddW
            | Op::AmoxorW
            | Op::AmoandW
            | Op::AmoorW
            | Op::AmominW
            | Op::AmomaxW
            | Op::AmominuW
            | Op::AmomaxuW => Some(4),
            Op::AmoswapD
            | Op::AmoaddD
            | Op::AmoxorD
            | Op::AmoandD
            | Op::AmoorD
            | Op::AmominD
            | Op::AmomaxD
            | Op::AmominuD
            | Op::AmomaxuD => Some(8),
            _ => None,
        }
    }

    pub fn atomic_width(self) -> Option<usize> {
        self.amo_width().or(match self {
            Op::LrW | Op::ScW => Some(4),
            Op::LrD | Op::ScD => Some(8),
            _ => None,
        })
    }

    /// Apply an AMO to the raw old value and source register value.
    /// `W` forms operate on the low 32 bits and return a zero-extended result.
    pub fn amo_apply(self, old: Word, source: Word) -> Word {
        let width = self.amo_width().expect("AMO op");
        let mask = if width == 4 {
            (1u64 << 32) - 1
        } else {
            u64::MAX
        };
        let old = old & mask;
        let source = source & mask;
        let signed_old = if width == 4 {
            i64::from(old as i32)
        } else {
            old as i64
        };
        let signed_source = if width == 4 {
            i64::from(source as i32)
        } else {
            source as i64
        };
        let result = match self {
            Op::AmoswapW | Op::AmoswapD => source,
            Op::AmoaddW | Op::AmoaddD => old.wrapping_add(source),
            Op::AmoxorW | Op::AmoxorD => old ^ source,
            Op::AmoandW | Op::AmoandD => old & source,
            Op::AmoorW | Op::AmoorD => old | source,
            Op::AmominW | Op::AmominD => signed_old.min(signed_source) as u64,
            Op::AmomaxW | Op::AmomaxD => signed_old.max(signed_source) as u64,
            Op::AmominuW | Op::AmominuD => old.min(source),
            Op::AmomaxuW | Op::AmomaxuD => old.max(source),
            _ => unreachable!("not an AMO"),
        };
        result & mask
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
            Op::Addw => "addw",
            Op::Subw => "subw",
            Op::Sllw => "sllw",
            Op::Srlw => "srlw",
            Op::Sraw => "sraw",
            Op::Mul => "mul",
            Op::Mulh => "mulh",
            Op::Mulhsu => "mulhsu",
            Op::Mulhu => "mulhu",
            Op::Div => "div",
            Op::Divu => "divu",
            Op::Rem => "rem",
            Op::Remu => "remu",
            Op::AmoswapW => "amoswap.w",
            Op::AmoswapD => "amoswap.d",
            Op::AmoaddW => "amoadd.w",
            Op::AmoaddD => "amoadd.d",
            Op::AmoxorW => "amoxor.w",
            Op::AmoxorD => "amoxor.d",
            Op::AmoandW => "amoand.w",
            Op::AmoandD => "amoand.d",
            Op::AmoorW => "amoor.w",
            Op::AmoorD => "amoor.d",
            Op::AmominW => "amomin.w",
            Op::AmominD => "amomin.d",
            Op::AmomaxW => "amomax.w",
            Op::AmomaxD => "amomax.d",
            Op::AmominuW => "amominu.w",
            Op::AmominuD => "amominu.d",
            Op::AmomaxuW => "amomaxu.w",
            Op::AmomaxuD => "amomaxu.d",
            Op::LrW => "lr.w",
            Op::LrD => "lr.d",
            Op::ScW => "sc.w",
            Op::ScD => "sc.d",
            Op::Addi => "addi",
            Op::Addiw => "addiw",
            Op::Slti => "slti",
            Op::Sltiu => "sltiu",
            Op::Xori => "xori",
            Op::Ori => "ori",
            Op::Andi => "andi",
            Op::Slli => "slli",
            Op::Slliw => "slliw",
            Op::Srli => "srli",
            Op::Srliw => "srliw",
            Op::Srai => "srai",
            Op::Sraiw => "sraiw",
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
        let r_w = |funct3: u32, funct7: u32| {
            (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x3b
        };
        let amo = |funct5: u32, funct3: u32| {
            (funct5 << 27) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x2f
        };
        let i = |funct3: u32, imm: i64| {
            (((imm as u32) & 0xfff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x13
        };
        let i_w = |funct3: u32, imm: i64| {
            (((imm as u32) & 0xfff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x1b
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
        let shift_imm_w = |funct3: u32, funct6: u32| {
            (funct6 << 26)
                | ((shamt & 0x1f) << 20)
                | (rs1 << 15)
                | (funct3 << 12)
                | (rd << 7)
                | 0x1b
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
            Op::Addw => r_w(0, 0x00),
            Op::Subw => r_w(0, 0x20),
            Op::Sllw => r_w(1, 0x00),
            Op::Srlw => r_w(5, 0x00),
            Op::Sraw => r_w(5, 0x20),
            Op::Mul => r(0, 0x01),
            Op::Mulh => r(1, 0x01),
            Op::Mulhsu => r(2, 0x01),
            Op::Mulhu => r(3, 0x01),
            Op::Div => r(4, 0x01),
            Op::Divu => r(5, 0x01),
            Op::Rem => r(6, 0x01),
            Op::Remu => r(7, 0x01),
            Op::AmoswapW => amo(0x01, 2),
            Op::AmoswapD => amo(0x01, 3),
            Op::AmoaddW => amo(0x00, 2),
            Op::AmoaddD => amo(0x00, 3),
            Op::AmoxorW => amo(0x04, 2),
            Op::AmoxorD => amo(0x04, 3),
            Op::AmoandW => amo(0x0c, 2),
            Op::AmoandD => amo(0x0c, 3),
            Op::AmoorW => amo(0x08, 2),
            Op::AmoorD => amo(0x08, 3),
            Op::AmominW => amo(0x10, 2),
            Op::AmominD => amo(0x10, 3),
            Op::AmomaxW => amo(0x14, 2),
            Op::AmomaxD => amo(0x14, 3),
            Op::AmominuW => amo(0x18, 2),
            Op::AmominuD => amo(0x18, 3),
            Op::AmomaxuW => amo(0x1c, 2),
            Op::AmomaxuD => amo(0x1c, 3),
            Op::LrW => amo(0x02, 2),
            Op::LrD => amo(0x02, 3),
            Op::ScW => amo(0x03, 2),
            Op::ScD => amo(0x03, 3),
            Op::Addi => i(0, self.imm),
            Op::Addiw => i_w(0, self.imm),
            Op::Slti => i(2, self.imm),
            Op::Sltiu => i(3, self.imm),
            Op::Xori => i(4, self.imm),
            Op::Ori => i(6, self.imm),
            Op::Andi => i(7, self.imm),
            Op::Slli => shift_imm(1, 0),
            Op::Slliw => shift_imm_w(1, 0),
            Op::Srli => shift_imm(5, 0),
            Op::Srliw => shift_imm_w(5, 0),
            Op::Srai => shift_imm(5, 0b010000),
            Op::Sraiw => shift_imm_w(5, 0b010000),
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
        0x2f => {
            let funct5 = (word >> 27) & 0x1f;
            let op = match (funct5, funct3) {
                (0x00, 2) => Op::AmoaddW,
                (0x00, 3) => Op::AmoaddD,
                (0x01, 2) => Op::AmoswapW,
                (0x01, 3) => Op::AmoswapD,
                (0x02, 2) => Op::LrW,
                (0x02, 3) => Op::LrD,
                (0x03, 2) => Op::ScW,
                (0x03, 3) => Op::ScD,
                (0x04, 2) => Op::AmoxorW,
                (0x04, 3) => Op::AmoxorD,
                (0x08, 2) => Op::AmoorW,
                (0x08, 3) => Op::AmoorD,
                (0x0c, 2) => Op::AmoandW,
                (0x0c, 3) => Op::AmoandD,
                (0x10, 2) => Op::AmominW,
                (0x10, 3) => Op::AmominD,
                (0x14, 2) => Op::AmomaxW,
                (0x14, 3) => Op::AmomaxD,
                (0x18, 2) => Op::AmominuW,
                (0x18, 3) => Op::AmominuD,
                (0x1c, 2) => Op::AmomaxuW,
                (0x1c, 3) => Op::AmomaxuD,
                _ => return Err(DecodeError::Illegal(word)),
            };
            inst.op = op;
            inst.rd = rd;
            inst.rs1 = rs1;
            inst.rs2 = rs2;
        }
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
                0 if funct7 == 0x01 => Op::Mul,
                1 if funct7 == 0x01 => Op::Mulh,
                2 if funct7 == 0x01 => Op::Mulhsu,
                3 if funct7 == 0x01 => Op::Mulhu,
                4 if funct7 == 0x01 => Op::Div,
                5 if funct7 == 0x01 => Op::Divu,
                6 if funct7 == 0x01 => Op::Rem,
                7 if funct7 == 0x01 => Op::Remu,
                _ => return Err(DecodeError::Illegal(word)),
            };
            inst.op = op;
            inst.rd = rd;
            inst.rs1 = rs1;
            inst.rs2 = rs2;
        }
        0x3b => {
            let op = match funct3 {
                0 if funct7 == 0x00 => Op::Addw,
                0 if funct7 == 0x20 => Op::Subw,
                1 if funct7 == 0x00 => Op::Sllw,
                5 if funct7 == 0x00 => Op::Srlw,
                5 if funct7 == 0x20 => Op::Sraw,
                _ => return Err(DecodeError::Illegal(word)),
            };
            inst.op = op;
            inst.rd = rd;
            inst.rs1 = rs1;
            inst.rs2 = rs2;
        }
        0x1b => {
            let funct6 = (word >> 26) & 0x3f;
            let shamt = ((word >> 20) & 0x1f) as u8;
            let op = match funct3 {
                0 => Op::Addiw,
                1 if funct6 == 0 => Op::Slliw,
                5 if funct6 == 0 => Op::Srliw,
                5 if funct6 == 0b010000 => Op::Sraiw,
                _ => return Err(DecodeError::Illegal(word)),
            };
            inst.op = op;
            inst.rd = rd;
            inst.rs1 = rs1;
            if matches!(op, Op::Slliw | Op::Srliw | Op::Sraiw) {
                inst.shamt = shamt;
            } else {
                inst.imm = sext(word >> 20, 12);
            }
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
    use proptest::prelude::*;

    const ALL_OPS: &[Op] = &[
        Op::Add,
        Op::Sub,
        Op::Sll,
        Op::Slt,
        Op::Sltu,
        Op::Xor,
        Op::Srl,
        Op::Sra,
        Op::Or,
        Op::And,
        Op::Addw,
        Op::Subw,
        Op::Sllw,
        Op::Srlw,
        Op::Sraw,
        Op::Mul,
        Op::Mulh,
        Op::Mulhsu,
        Op::Mulhu,
        Op::Div,
        Op::Divu,
        Op::Rem,
        Op::Remu,
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
        Op::LrW,
        Op::LrD,
        Op::ScW,
        Op::ScD,
        Op::Addi,
        Op::Addiw,
        Op::Slti,
        Op::Sltiu,
        Op::Xori,
        Op::Ori,
        Op::Andi,
        Op::Slli,
        Op::Slliw,
        Op::Srli,
        Op::Srliw,
        Op::Srai,
        Op::Sraiw,
        Op::Lui,
        Op::Auipc,
        Op::Jal,
        Op::Jalr,
        Op::Beq,
        Op::Bne,
        Op::Blt,
        Op::Bge,
        Op::Bltu,
        Op::Bgeu,
        Op::Lb,
        Op::Lh,
        Op::Lw,
        Op::Ld,
        Op::Lbu,
        Op::Lhu,
        Op::Lwu,
        Op::Sb,
        Op::Sh,
        Op::Sw,
        Op::Sd,
        Op::Fence,
        Op::Ecall,
        Op::Ebreak,
    ];

    fn sample_instruction(op: Op) -> Instruction {
        let imm = match op {
            Op::Addi
            | Op::Addiw
            | Op::Slti
            | Op::Sltiu
            | Op::Xori
            | Op::Ori
            | Op::Andi
            | Op::Jalr
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
            | Op::Sd => -4,
            Op::Beq | Op::Bne | Op::Blt | Op::Bge | Op::Bltu | Op::Bgeu => -8,
            Op::Jal => 0x20,
            Op::Lui | Op::Auipc => 0x1234_5000,
            _ => 0,
        };
        Instruction {
            op,
            rd: 3,
            rs1: 4,
            rs2: 5,
            imm,
            shamt: if matches!(op, Op::Slliw | Op::Srliw | Op::Sraiw) {
                1
            } else {
                33
            },
        }
    }

    #[test]
    fn round_trips_every_opcode() {
        for &op in ALL_OPS {
            let instruction = sample_instruction(op);
            let decoded = decode(instruction.encode())
                .unwrap_or_else(|_| panic!("failed to decode {}", op.name()));
            assert_eq!(decoded.op, op, "{}", op.name());
            if op.writes_rd() {
                assert_eq!(decoded.rd, instruction.rd, "{}", op.name());
            }
            if op.reads_rs1() {
                assert_eq!(decoded.rs1, instruction.rs1, "{}", op.name());
            }
            if op.reads_rs2() {
                assert_eq!(decoded.rs2, instruction.rs2, "{}", op.name());
            }
            if matches!(
                op,
                Op::Slli | Op::Slliw | Op::Srli | Op::Srliw | Op::Srai | Op::Sraiw
            ) {
                assert_eq!(decoded.shamt, instruction.shamt, "{}", op.name());
            } else if !matches!(op, Op::Fence | Op::Ecall | Op::Ebreak) {
                assert_eq!(decoded.imm, instruction.imm, "{}", op.name());
            }
        }
    }

    proptest! {
        #[test]
        fn addi_roundtrip(rd in 0u8..32, rs1 in 0u8..32, imm in -2048i64..2048) {
            let instruction = Instruction { op: Op::Addi, rd, rs1, rs2: 0, imm, shamt: 0 };
            let decoded = decode(instruction.encode()).unwrap();
            prop_assert_eq!(decoded.op, Op::Addi);
            prop_assert_eq!(decoded.rd, rd);
            prop_assert_eq!(decoded.rs1, rs1);
            prop_assert_eq!(decoded.imm, imm);
        }

        #[test]
        fn shift_immediate_roundtrip(shamt in 0u8..64, rd in 0u8..32, rs1 in 0u8..32) {
            let instruction = Instruction { op: Op::Srai, rd, rs1, rs2: 0, imm: 0, shamt };
            let decoded = decode(instruction.encode()).unwrap();
            prop_assert_eq!(decoded.op, Op::Srai);
            prop_assert_eq!(decoded.shamt, shamt);
            prop_assert_eq!(decoded.rd, rd);
            prop_assert_eq!(decoded.rs1, rs1);
        }
    }

    #[test]
    fn classifies_ops_and_exposes_operand_indices() {
        for &op in ALL_OPS {
            let instruction = sample_instruction(op);
            assert_eq!(
                instruction.rd_index(),
                op.writes_rd().then_some(instruction.rd as RegIdx)
            );
            assert_eq!(
                instruction.rs1_index(),
                op.reads_rs1().then_some(instruction.rs1 as RegIdx)
            );
            assert_eq!(
                instruction.rs2_index(),
                op.reads_rs2().then_some(instruction.rs2 as RegIdx)
            );
            assert_eq!(
                op.is_branch(),
                matches!(
                    op,
                    Op::Beq | Op::Bne | Op::Blt | Op::Bge | Op::Bltu | Op::Bgeu
                )
            );
            assert_eq!(
                op.is_load(),
                matches!(
                    op,
                    Op::Lb | Op::Lh | Op::Lw | Op::Ld | Op::Lbu | Op::Lhu | Op::Lwu
                )
            );
            assert_eq!(
                op.is_store(),
                matches!(op, Op::Sb | Op::Sh | Op::Sw | Op::Sd)
            );
            assert_eq!(op.is_jump(), matches!(op, Op::Jal | Op::Jalr));
            assert_eq!(op.is_halt(), matches!(op, Op::Ecall | Op::Ebreak));
            assert!(!op.name().is_empty());
        }
    }

    #[test]
    fn encoding_masks_register_and_shamt_fields() {
        let instruction = Instruction {
            op: Op::Add,
            rd: 0xff,
            rs1: 0xff,
            rs2: 0xff,
            imm: 0,
            shamt: 0,
        };
        let decoded = decode(instruction.encode()).unwrap();
        assert_eq!(decoded.rd, 31);
        assert_eq!(decoded.rs1, 31);
        assert_eq!(decoded.rs2, 31);

        let shift = Instruction {
            op: Op::Slli,
            rd: 1,
            rs1: 2,
            rs2: 0,
            imm: 0,
            shamt: 0xff,
        };
        assert_eq!(decode(shift.encode()).unwrap().shamt, 63);
    }

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
