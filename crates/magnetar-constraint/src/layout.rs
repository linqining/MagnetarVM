use std::collections::HashSet;
use thiserror::Error;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum SegmentKind {
    Direct,
    Virtual,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum MemoryKind {
    Registers,
    Ram,
    Rom,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum RoutingKind {
    Shifts,
    Stores,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum SegmentOwner {
    Cpu,
    Memory(MemoryKind),
    Routing(RoutingKind),
    Pcs,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Segment {
    pub name: String,
    pub offset: usize,
    pub len: usize,
    pub kind: SegmentKind,
    pub owner: SegmentOwner,
}

impl Segment {
    pub fn new(
        name: impl Into<String>,
        offset: usize,
        len: usize,
        kind: SegmentKind,
        owner: SegmentOwner,
    ) -> Self {
        Self {
            name: name.into(),
            offset,
            len,
            kind,
            owner,
        }
    }

    pub fn end(&self) -> usize {
        self.offset + self.len
    }
}

/// Public segment layout of the witness polynomial.
///
/// Segments occupy aligned subcubes. `total_bits` is padded to the next power
/// of two so it can be committed as one multilinear polynomial.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct WitnessLayout {
    pub total_bits: usize,
    pub segments: Vec<Segment>,
}

impl WitnessLayout {
    pub fn new(mut segments: Vec<Segment>) -> Result<Self, LayoutError> {
        segments.sort_by_key(|segment| segment.offset);
        let mut names = HashSet::new();
        let mut end = 0;
        let mut previous_name = String::new();
        for segment in &segments {
            if !names.insert(segment.name.clone()) {
                return Err(LayoutError::DuplicateName(segment.name.clone()));
            }
            if segment.len == 0 {
                return Err(LayoutError::EmptySegment {
                    name: segment.name.clone(),
                });
            }
            if !segment.len.is_power_of_two() {
                return Err(LayoutError::NonPowerOfTwo {
                    name: segment.name.clone(),
                    len: segment.len,
                });
            }
            if segment.offset % segment.len != 0 {
                return Err(LayoutError::Misaligned {
                    name: segment.name.clone(),
                    offset: segment.offset,
                    len: segment.len,
                });
            }
            if segment.offset < end {
                return Err(LayoutError::Overlap {
                    left: previous_name,
                    right: segment.name.clone(),
                });
            }
            end = segment.end();
            previous_name = segment.name.clone();
        }
        let total_bits = end.next_power_of_two().max(1);
        Ok(Self {
            total_bits,
            segments,
        })
    }

    pub fn segment(&self, name: &str) -> Option<&Segment> {
        self.segments.iter().find(|segment| segment.name == name)
    }

    pub fn direct_segments(&self) -> impl Iterator<Item = &Segment> {
        self.segments
            .iter()
            .filter(|segment| segment.kind == SegmentKind::Direct)
    }

    pub fn virtual_segments(&self) -> impl Iterator<Item = &Segment> {
        self.segments
            .iter()
            .filter(|segment| segment.kind == SegmentKind::Virtual)
    }

    pub fn check_cover(&self) -> bool {
        let mut covered = vec![false; self.total_bits];
        for segment in &self.segments {
            for bit in segment.offset..segment.end() {
                if bit < covered.len() {
                    covered[bit] = true;
                }
            }
        }
        covered.into_iter().all(|value| value)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LayoutError {
    #[error("segment {name} has zero length")]
    EmptySegment { name: String },
    #[error("segment {name} length {len} is not a power of two")]
    NonPowerOfTwo { name: String, len: usize },
    #[error("segment {name} offset {offset} is not aligned to length {len}")]
    Misaligned {
        name: String,
        offset: usize,
        len: usize,
    },
    #[error("segments overlap at {left} / {right}")]
    Overlap { left: String, right: String },
    #[error("duplicate segment name {0}")]
    DuplicateName(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_requires_alignment() {
        let segments = vec![Segment::new(
            "bad",
            3,
            4,
            SegmentKind::Direct,
            SegmentOwner::Cpu,
        )];
        assert!(matches!(
            WitnessLayout::new(segments),
            Err(LayoutError::Misaligned { .. })
        ));
    }

    #[test]
    fn layout_places_segments_on_subcubes() {
        let segments = vec![
            Segment::new("pc", 0, 8, SegmentKind::Direct, SegmentOwner::Cpu),
            Segment::new(
                "mem",
                8,
                8,
                SegmentKind::Virtual,
                SegmentOwner::Memory(MemoryKind::Ram),
            ),
        ];
        let layout = WitnessLayout::new(segments).unwrap();
        assert_eq!(layout.total_bits, 16);
        assert!(layout.check_cover());
    }

    fn segment(name: &str, offset: usize, len: usize) -> Segment {
        Segment::new(name, offset, len, SegmentKind::Direct, SegmentOwner::Cpu)
    }

    #[test]
    fn layout_rejects_duplicate_empty_and_non_power_of_two_segments() {
        assert!(matches!(
            WitnessLayout::new(vec![segment("a", 0, 0)]),
            Err(LayoutError::EmptySegment { name }) if name == "a"
        ));
        assert!(matches!(
            WitnessLayout::new(vec![segment("a", 0, 3)]),
            Err(LayoutError::NonPowerOfTwo { name, len: 3 }) if name == "a"
        ));
        assert!(matches!(
            WitnessLayout::new(vec![segment("a", 0, 4), segment("a", 4, 4)]),
            Err(LayoutError::DuplicateName(name)) if name == "a"
        ));
    }

    #[test]
    fn layout_detects_overlaps_and_gaps() {
        assert!(matches!(
            WitnessLayout::new(vec![segment("a", 0, 8), segment("b", 4, 4)]),
            Err(LayoutError::Overlap { left, right }) if left == "a" && right == "b"
        ));

        let layout = WitnessLayout::new(vec![segment("pc", 0, 4), segment("mem", 4, 4)]).unwrap();
        assert_eq!(layout.segment("pc").unwrap().end(), 4);
        assert!(layout.segment("missing").is_none());
        assert_eq!(layout.direct_segments().count(), 2);
        assert_eq!(layout.virtual_segments().count(), 0);

        let gapped = WitnessLayout::new(vec![segment("late", 4, 4)]).unwrap();
        assert_eq!(gapped.total_bits, 8);
        assert!(!gapped.check_cover());
        assert_eq!(WitnessLayout::new(Vec::new()).unwrap().total_bits, 1);
    }
}
