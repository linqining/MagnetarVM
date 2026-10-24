//! Public preprocessing: program → ROM, bytecode metadata, routing tables,
//! and a trace-length-parameterized witness layout.

use magnetar_constraint::{
    LayoutError, MemoryKind, RoutingKind, Segment, SegmentKind, SegmentOwner, WitnessLayout,
};
use magnetar_routing::{
    RoutingError, RoutingTables, ShiftKind, ShiftRoute, StoreRoute, StoreWidth,
};
use magnetar_spec::{
    decode, decode_compressed, Addr, CompressedError, DecodeError, Instruction, MachineConfig, Op,
    ProgramImage, Word,
};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct RomImage {
    pub base: Addr,
    pub words: Vec<u32>,
}

impl RomImage {
    pub fn len(&self) -> usize {
        self.words.len()
    }

    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    pub fn instruction(&self, addr: Addr) -> Option<u32> {
        let offset = addr.checked_sub(self.base)?;
        if offset % 4 != 0 {
            return None;
        }
        let index = usize::try_from(offset / 4).ok()?;
        self.words.get(index).copied()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Selectors {
    pub shift: Option<ShiftRoute>,
    pub store_width: Option<StoreWidth>,
    pub is_halt: bool,
}

#[derive(Clone, Debug)]
pub struct BytecodeRow {
    pub micro_pc: Word,
    pub instruction_word: u32,
    pub instruction: Instruction,
    pub selectors: Selectors,
}

/// Kind of a scheduled micro-op. The current executor emits one `Execute`
/// micro-op per instruction; `Fetch` is reserved for instruction expansion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MicroOpKind {
    Fetch,
    Execute,
}

/// A scheduled micro-op. `rv_pc` is the architectural instruction address;
/// `micro_pc` is the row key used by the bytecode/Shout table.
#[derive(Clone, Debug)]
pub struct MicroOp {
    pub micro_pc: Word,
    pub rv_pc: Word,
    pub kind: MicroOpKind,
    pub instruction_word: u32,
    pub instruction: Instruction,
    pub selectors: Selectors,
}

/// Expand the preprocessed bytecode into scheduled micro-ops. The current
/// one-instruction/one-micro-op encoding is the identity expansion; multi-op
/// rows can be introduced here without changing the Shout table shape.
pub fn expand_bytecode(rows: &[BytecodeRow]) -> Vec<MicroOp> {
    rows.iter()
        .map(|row| MicroOp {
            micro_pc: row.micro_pc,
            rv_pc: row.micro_pc,
            kind: MicroOpKind::Execute,
            instruction_word: row.instruction_word,
            instruction: row.instruction,
            selectors: row.selectors,
        })
        .collect()
}

#[derive(Clone, Debug)]
pub struct PreprocessedProgram {
    pub config: MachineConfig,
    pub image: ProgramImage,
    pub rom: RomImage,
    pub bytecode: Vec<BytecodeRow>,
    pub micro_ops: Vec<MicroOp>,
    pub routing: RoutingTables,
}

impl PreprocessedProgram {
    pub fn bytecode_row(&self, micro_pc: Word) -> Option<&BytecodeRow> {
        self.bytecode.iter().find(|row| row.micro_pc == micro_pc)
    }

    /// Build the public segment layout for an execution of `trace_len` cycles.
    ///
    /// Every segment is padded to the next power of two and placed on an
    /// aligned subcube, matching the layout MosaicPCS expects.
    pub fn layout(&self, trace_len: usize) -> Result<WitnessLayout, LayoutError> {
        let len = trace_len.max(1).next_power_of_two();
        let specs = [
            ("pc", SegmentKind::Direct, SegmentOwner::Cpu),
            ("next_pc", SegmentKind::Direct, SegmentOwner::Cpu),
            ("instruction", SegmentKind::Direct, SegmentOwner::Cpu),
            ("rs1_idx", SegmentKind::Direct, SegmentOwner::Cpu),
            ("rs2_idx", SegmentKind::Direct, SegmentOwner::Cpu),
            ("rd_idx", SegmentKind::Direct, SegmentOwner::Cpu),
            ("rs1_val", SegmentKind::Direct, SegmentOwner::Cpu),
            ("rs2_val", SegmentKind::Direct, SegmentOwner::Cpu),
            ("rd_val", SegmentKind::Direct, SegmentOwner::Cpu),
            (
                "mem_addr",
                SegmentKind::Virtual,
                SegmentOwner::Memory(MemoryKind::Ram),
            ),
            (
                "mem_value",
                SegmentKind::Virtual,
                SegmentOwner::Memory(MemoryKind::Ram),
            ),
            (
                "shift_route",
                SegmentKind::Virtual,
                SegmentOwner::Routing(RoutingKind::Shifts),
            ),
        ];
        let segments = specs
            .into_iter()
            .enumerate()
            .map(|(index, (name, kind, owner))| Segment::new(name, index * len, len, kind, owner))
            .collect();
        WitnessLayout::new(segments)
    }
}

#[derive(Debug, Error)]
pub enum PreprocessError {
    #[error("ROM is empty")]
    EmptyRom,
    #[error("entry pc 0x{0:x} is not in ROM")]
    EntryOutOfBounds(Word),
    #[error("decode failed at pc 0x{pc:x}: {source}")]
    Decode {
        pc: Word,
        #[source]
        source: DecodeError,
    },
    #[error("compressed decode failed at pc 0x{pc:x}: {source}")]
    Compressed {
        pc: Word,
        #[source]
        source: CompressedError,
    },
    #[error(transparent)]
    Layout(#[from] LayoutError),
    #[error(transparent)]
    Routing(#[from] RoutingError),
}

pub fn preprocess(
    image: &ProgramImage,
    config: MachineConfig,
) -> Result<PreprocessedProgram, PreprocessError> {
    if image.rom.is_empty() {
        return Err(PreprocessError::EmptyRom);
    }
    let entry_in_rom = image
        .entry
        .checked_sub(config.rom_base)
        .filter(|offset| offset.is_multiple_of(2))
        .and_then(|offset| usize::try_from(offset / 4).ok())
        .is_some_and(|index| index < image.rom.len());
    if !entry_in_rom {
        return Err(PreprocessError::EntryOutOfBounds(image.entry));
    }

    let rom_base = config.rom_base;
    let mut bytecode = Vec::with_capacity(image.rom.len());
    let mut routing = RoutingTables::default();
    let halfwords = image.rom.len() * 2;
    let mut halfword = 0usize;
    while halfword < halfwords {
        let word_index = halfword / 2;
        let raw = if halfword.is_multiple_of(2) {
            image.rom[word_index] & 0xffff
        } else {
            image.rom[word_index] >> 16
        };
        let pc = rom_base + (halfword as u64) * 2;
        let (instruction_word, instruction, instruction_len) = if raw & 0x3 == 0x3 {
            let word = if halfword.is_multiple_of(2) {
                image.rom[word_index]
            } else {
                let low = image.rom[word_index] >> 16;
                let next = image.rom.get(word_index + 1).copied().unwrap_or(0);
                low | ((next & 0xffff) << 16)
            };
            let instruction =
                decode(word).map_err(|source| PreprocessError::Decode { pc, source })?;
            (word, instruction, 4)
        } else {
            let instruction = decode_compressed(raw as u16)
                .map_err(|source| PreprocessError::Compressed { pc, source })?;
            (raw, instruction, 2)
        };
        let selectors = selectors_for(instruction, &mut routing)?;
        let halt = selectors.is_halt;
        bytecode.push(BytecodeRow {
            micro_pc: pc,
            instruction_word,
            instruction,
            selectors,
        });
        halfword += instruction_len / 2;
        if halt {
            break;
        }
    }

    let micro_ops = expand_bytecode(&bytecode);
    Ok(PreprocessedProgram {
        config,
        image: image.clone(),
        rom: RomImage {
            base: rom_base,
            words: image.rom.clone(),
        },
        bytecode,
        micro_ops,
        routing,
    })
}

fn selectors_for(
    instruction: Instruction,
    routing: &mut RoutingTables,
) -> Result<Selectors, RoutingError> {
    let mut selectors = Selectors::default();
    match instruction.op {
        Op::Slli => {
            let route = ShiftRoute::new(ShiftKind::LogicalLeft, instruction.shamt);
            routing.register_shift(route);
            selectors.shift = Some(route);
        }
        Op::Srli => {
            let route = ShiftRoute::new(ShiftKind::LogicalRight, instruction.shamt);
            routing.register_shift(route);
            selectors.shift = Some(route);
        }
        Op::Srai => {
            let route = ShiftRoute::new(ShiftKind::ArithmeticRight, instruction.shamt);
            routing.register_shift(route);
            selectors.shift = Some(route);
        }
        Op::Sb | Op::Sh | Op::Sw | Op::Sd => {
            let width = match instruction.op {
                Op::Sb => StoreWidth::Byte,
                Op::Sh => StoreWidth::Half,
                Op::Sw => StoreWidth::Word,
                Op::Sd => StoreWidth::Double,
                _ => unreachable!(),
            };
            selectors.store_width = Some(width);
            let step = width.bytes();
            for offset in (0..8).step_by(step) {
                if offset + step <= 8 {
                    routing.register_store(StoreRoute::new(width, offset)?)?;
                }
            }
        }
        Op::Ecall | Op::Ebreak => {
            selectors.is_halt = true;
        }
        _ => {}
    }
    Ok(selectors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_spec::Instruction;

    fn image() -> ProgramImage {
        ProgramImage::new(
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
                    op: Op::Slli,
                    rd: 2,
                    rs1: 1,
                    rs2: 0,
                    imm: 0,
                    shamt: 4,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        )
    }

    #[test]
    fn builds_rom_and_selectors() {
        let program = preprocess(&image(), MachineConfig::default()).unwrap();
        assert_eq!(program.rom.len(), 3);
        assert_eq!(program.bytecode.len(), 3);
        assert!(program.bytecode[1].selectors.shift.is_some());
        assert!(program.bytecode[2].selectors.is_halt);
        assert_eq!(program.routing.shifts.len(), 1);
    }

    #[test]
    fn layout_is_aligned_and_ordered() {
        let program = preprocess(&image(), MachineConfig::default()).unwrap();
        let layout = program.layout(7).unwrap();
        assert_eq!(layout.segments.len(), 12);
        for segment in &layout.segments {
            assert!(segment.len.is_power_of_two());
            assert_eq!(segment.offset % segment.len, 0);
        }
        assert_eq!(layout.direct_segments().count(), 9);
        assert_eq!(layout.virtual_segments().count(), 3);
    }

    #[test]
    fn rom_lookup_and_bytecode_rows_respect_addresses() {
        let program = preprocess(&image(), MachineConfig::default()).unwrap();
        assert_eq!(program.rom.instruction(0x1000), Some(image().rom[0]));
        assert_eq!(program.rom.instruction(0x1008), Some(image().rom[2]));
        assert_eq!(program.rom.instruction(0x1002), None);
        assert_eq!(program.rom.instruction(0x0ffc), None);
        assert_eq!(program.rom.instruction(0x100c), None);
        assert_eq!(program.rom.len(), 3);
        assert!(!program.rom.is_empty());

        assert_eq!(
            program.bytecode_row(0x1004).unwrap().instruction.op,
            Op::Slli
        );
        assert!(program.bytecode_row(0x1002).is_none());
    }

    #[test]
    fn empty_trace_still_produces_an_aligned_layout() {
        let program = preprocess(&image(), MachineConfig::default()).unwrap();
        let layout = program.layout(0).unwrap();
        assert_eq!(layout.segments.len(), 12);
        for segment in &layout.segments {
            assert_eq!(segment.len, 1);
            assert_eq!(segment.offset % segment.len, 0);
        }
    }

    #[test]
    fn preprocess_rejects_empty_rom_bad_entry_and_undecodable_words() {
        let empty = ProgramImage::new(0x1000, Vec::new());
        assert!(matches!(
            preprocess(&empty, MachineConfig::default()),
            Err(PreprocessError::EmptyRom)
        ));

        let outside = ProgramImage::new(0x8000_0000, vec![Instruction::new(Op::Ecall).encode()]);
        assert!(matches!(
            preprocess(&outside, MachineConfig::default()),
            Err(PreprocessError::EntryOutOfBounds(0x8000_0000))
        ));

        let invalid = ProgramImage::new(0x1000, vec![0xffff_ffff]);
        assert!(matches!(
            preprocess(&invalid, MachineConfig::default()),
            Err(PreprocessError::Decode { pc: 0x1000, .. })
        ));
    }

    #[test]
    fn shift_and_store_selectors_register_every_route() {
        let instruction = |op, rd, rs1, rs2, imm, shamt| Instruction {
            op,
            rd,
            rs1,
            rs2,
            imm,
            shamt,
        };
        let program = ProgramImage::new(
            0x1000,
            vec![
                instruction(Op::Slli, 1, 0, 0, 0, 3).encode(),
                instruction(Op::Srli, 2, 1, 0, 0, 5).encode(),
                instruction(Op::Srai, 3, 1, 0, 0, 7).encode(),
                instruction(Op::Sb, 0, 4, 5, 0, 0).encode(),
                instruction(Op::Sh, 0, 4, 5, 0, 0).encode(),
                instruction(Op::Sw, 0, 4, 5, 0, 0).encode(),
                instruction(Op::Sd, 0, 4, 5, 0, 0).encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let preprocessed = preprocess(&program, MachineConfig::default()).unwrap();
        assert_eq!(preprocessed.routing.shifts.len(), 3);
        assert_eq!(preprocessed.routing.stores.len(), 8 + 4 + 2 + 1);
        assert_eq!(
            preprocessed.bytecode[0].selectors.shift,
            Some(ShiftRoute::new(ShiftKind::LogicalLeft, 3))
        );
        assert_eq!(
            preprocessed.bytecode[2].selectors.shift,
            Some(ShiftRoute::new(ShiftKind::ArithmeticRight, 7))
        );
        assert_eq!(
            preprocessed.bytecode[3].selectors.store_width,
            Some(StoreWidth::Byte)
        );
        assert_eq!(
            preprocessed.bytecode[6].selectors.store_width,
            Some(StoreWidth::Double)
        );
        assert!(preprocessed.bytecode[7].selectors.is_halt);
    }
}

#[cfg(test)]
mod expansion_tests {
    use super::*;

    #[test]
    fn bytecode_expands_to_execute_micro_ops() {
        let image = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: magnetar_spec::Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 7,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(magnetar_spec::Op::Ecall).encode(),
            ],
        );
        let config = MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x1000,
            stack_top: 0x1000_1000,
            max_cycles: 16,
        };
        let prepared = preprocess(&image, config).unwrap();
        assert_eq!(prepared.micro_ops.len(), prepared.bytecode.len());
        for (op, row) in prepared.micro_ops.iter().zip(&prepared.bytecode) {
            assert_eq!(op.kind, MicroOpKind::Execute);
            assert_eq!(op.micro_pc, row.micro_pc);
            assert_eq!(op.rv_pc, row.micro_pc);
        }
    }
}
