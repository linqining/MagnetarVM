//! Public preprocessing: program → ROM, bytecode metadata, routing tables,
//! and a trace-length-parameterized witness layout.

use magnetar_constraint::{
    LayoutError, MemoryKind, RoutingKind, Segment, SegmentKind, SegmentOwner, WitnessLayout,
};
use magnetar_routing::{
    RoutingError, RoutingTables, ShiftKind, ShiftRoute, StoreRoute, StoreWidth,
};
use magnetar_spec::{
    decode, Addr, DecodeError, Instruction, MachineConfig, Op, ProgramImage, Word,
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

#[derive(Clone, Debug)]
pub struct PreprocessedProgram {
    pub config: MachineConfig,
    pub image: ProgramImage,
    pub rom: RomImage,
    pub bytecode: Vec<BytecodeRow>,
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
    if config.rom_index(image.entry).is_none() {
        return Err(PreprocessError::EntryOutOfBounds(image.entry));
    }

    let rom_base = config.rom_base;
    let mut bytecode = Vec::with_capacity(image.rom.len());
    let mut routing = RoutingTables::default();

    for (index, word) in image.rom.iter().copied().enumerate() {
        let pc = config.rom_base + (index as u64) * 4;
        let instruction = decode(word).map_err(|source| PreprocessError::Decode { pc, source })?;
        let selectors = selectors_for(instruction, &mut routing)?;
        bytecode.push(BytecodeRow {
            micro_pc: pc,
            instruction_word: word,
            instruction,
            selectors,
        });
    }

    Ok(PreprocessedProgram {
        config,
        image: image.clone(),
        rom: RomImage {
            base: rom_base,
            words: image.rom.clone(),
        },
        bytecode,
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
}
