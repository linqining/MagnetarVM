//! Recursion boundary.
//!
//! Magnetar's paper proposes chunking long executions and recursively proving
//! its own verifier, but does not ship that implementation. This crate provides
//! the chunk planner and the backend interface so the rest of the system can
//! be built against a stable boundary.

use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkRange {
    pub index: usize,
    pub start: usize,
    pub end: usize,
}

impl ChunkRange {
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkPlan {
    pub trace_len: usize,
    pub chunk_size: usize,
    pub num_chunks: usize,
}

impl ChunkPlan {
    pub fn new(trace_len: usize, chunk_size: usize) -> Result<Self, RecursionError> {
        if chunk_size == 0 {
            return Err(RecursionError::ZeroChunkSize);
        }
        let num_chunks = trace_len.div_ceil(chunk_size);
        Ok(Self {
            trace_len,
            chunk_size,
            num_chunks,
        })
    }

    pub fn ranges(&self) -> Vec<ChunkRange> {
        (0..self.num_chunks)
            .map(|index| {
                let start = index * self.chunk_size;
                let end = (start + self.chunk_size).min(self.trace_len);
                ChunkRange { index, start, end }
            })
            .collect()
    }

    pub fn is_single_chunk(&self) -> bool {
        self.num_chunks <= 1
    }
}

/// The two operations a recursion backend must provide.
pub trait RecursionBackend {
    type ChunkProof;
    type AggregatedProof;
    type Error;

    fn aggregate(&self, proofs: &[Self::ChunkProof]) -> Result<Self::AggregatedProof, Self::Error>;

    fn verify(&self, proof: &Self::AggregatedProof) -> Result<bool, Self::Error>;
}

/// Placeholder until the verifier-in-the-VM circuit and its proving workload
/// are implemented.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnimplementedRecursion;

impl RecursionBackend for UnimplementedRecursion {
    type ChunkProof = ();
    type AggregatedProof = ();
    type Error = RecursionError;

    fn aggregate(&self, _proofs: &[Self::ChunkProof]) -> Result<(), Self::Error> {
        Err(RecursionError::Unimplemented)
    }

    fn verify(&self, _proof: &Self::AggregatedProof) -> Result<bool, Self::Error> {
        Err(RecursionError::Unimplemented)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecursionError {
    #[error("chunk size must be nonzero")]
    ZeroChunkSize,
    #[error("recursive composition is not implemented")]
    Unimplemented,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_plan_covers_the_trace() {
        let plan = ChunkPlan::new(1000, 256).unwrap();
        assert_eq!(plan.num_chunks, 4);
        let ranges = plan.ranges();
        assert_eq!(ranges.first().unwrap().start, 0);
        assert_eq!(ranges.last().unwrap().end, 1000);
        assert_eq!(ranges.iter().map(ChunkRange::len).sum::<usize>(), 1000);
    }

    #[test]
    fn zero_chunk_size_is_rejected() {
        assert_eq!(ChunkPlan::new(10, 0), Err(RecursionError::ZeroChunkSize));
    }

    #[test]
    fn recursion_backend_is_explicitly_unimplemented() {
        assert_eq!(
            UnimplementedRecursion.aggregate(&[]),
            Err(RecursionError::Unimplemented)
        );
    }
}
