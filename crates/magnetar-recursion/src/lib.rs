//! Recursion boundary.
//!
//! Magnetar's paper proposes chunking long executions and recursively proving
//! its own verifier, but does not ship that implementation. This crate provides
//! the chunk planner and the backend interface so the rest of the system can
//! be built against a stable boundary.

use sha2::{Digest, Sha256};
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkProof {
    pub index: usize,
    pub trace_len: u64,
    pub state_digest: [u8; 32],
    pub proof_digest: [u8; 32],
}

impl ChunkProof {
    pub fn new(
        index: usize,
        trace_len: u64,
        state_digest: [u8; 32],
        proof_digest: [u8; 32],
    ) -> Self {
        Self {
            index,
            trace_len,
            state_digest,
            proof_digest,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregatedProof {
    pub root: [u8; 32],
    pub chunks: Vec<ChunkProof>,
    pub total_cycles: u64,
}

/// Reference aggregator: a hash chain over chunk proofs.
///
/// This is verifiable and useful for wiring the chunk pipeline, but it is not
/// a recursive zk proof. The verifier still sees every chunk proof.
#[derive(Clone, Copy, Debug, Default)]
pub struct HashChainRecursion;

impl HashChainRecursion {
    fn chain_root(chunks: &[ChunkProof]) -> [u8; 32] {
        let mut root = [0u8; 32];
        for chunk in chunks {
            let mut hasher = Sha256::new();
            hasher.update(b"magnetar-recursion-chain-v1");
            hasher.update(root);
            hasher.update((chunk.index as u64).to_le_bytes());
            hasher.update(chunk.trace_len.to_le_bytes());
            hasher.update(chunk.state_digest);
            hasher.update(chunk.proof_digest);
            root = hasher.finalize().into();
        }
        root
    }
}

impl RecursionBackend for HashChainRecursion {
    type ChunkProof = ChunkProof;
    type AggregatedProof = AggregatedProof;
    type Error = RecursionError;

    fn aggregate(&self, proofs: &[Self::ChunkProof]) -> Result<Self::AggregatedProof, Self::Error> {
        if proofs.is_empty() {
            return Err(RecursionError::EmptyProofSet);
        }
        for (expected, proof) in proofs.iter().enumerate() {
            if proof.index != expected {
                return Err(RecursionError::NonContiguousChunk {
                    expected,
                    actual: proof.index,
                });
            }
        }
        let total_cycles = proofs.iter().map(|proof| proof.trace_len).sum();
        Ok(AggregatedProof {
            root: Self::chain_root(proofs),
            chunks: proofs.to_vec(),
            total_cycles,
        })
    }

    fn verify(&self, proof: &Self::AggregatedProof) -> Result<bool, Self::Error> {
        if proof.chunks.is_empty() {
            return Err(RecursionError::EmptyProofSet);
        }
        Ok(Self::chain_root(&proof.chunks) == proof.root)
    }
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

/// A chunk that records the machine-state digest before and after execution.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChainedChunk {
    pub index: usize,
    pub trace_len: u64,
    pub state_before: [u8; 32],
    pub state_after: [u8; 32],
    pub proof_digest: [u8; 32],
}

impl ChainedChunk {
    pub fn new(
        index: usize,
        trace_len: u64,
        state_before: [u8; 32],
        state_after: [u8; 32],
        proof_digest: [u8; 32],
    ) -> Self {
        Self {
            index,
            trace_len,
            state_before,
            state_after,
            proof_digest,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChainedProof {
    pub root: [u8; 32],
    pub chunks: Vec<ChainedChunk>,
    pub total_cycles: u64,
}

/// Hash-chain aggregator that additionally enforces state continuity between
/// consecutive chunks. This is still a reference aggregator, not a recursive
/// proof, but a verifier cannot splice unrelated chunks into a valid chain.
#[derive(Clone, Copy, Debug, Default)]
pub struct ChainedRecursion;

impl ChainedRecursion {
    fn chain_root(chunks: &[ChainedChunk]) -> [u8; 32] {
        let mut root = [0u8; 32];
        for chunk in chunks {
            let mut hasher = Sha256::new();
            hasher.update(b"magnetar-recursion-state-chain-v1");
            hasher.update(root);
            hasher.update((chunk.index as u64).to_le_bytes());
            hasher.update(chunk.trace_len.to_le_bytes());
            hasher.update(chunk.state_before);
            hasher.update(chunk.state_after);
            hasher.update(chunk.proof_digest);
            root = hasher.finalize().into();
        }
        root
    }

    fn check_chain(chunks: &[ChainedChunk]) -> Result<(), RecursionError> {
        if chunks.is_empty() {
            return Err(RecursionError::EmptyProofSet);
        }
        let mut previous_state: Option<[u8; 32]> = None;
        for (expected, chunk) in chunks.iter().enumerate() {
            if chunk.index != expected {
                return Err(RecursionError::NonContiguousChunk {
                    expected,
                    actual: chunk.index,
                });
            }
            if let Some(previous) = previous_state {
                if chunk.state_before != previous {
                    return Err(RecursionError::StateMismatch { index: chunk.index });
                }
            }
            previous_state = Some(chunk.state_after);
        }
        Ok(())
    }

    pub fn aggregate(&self, chunks: &[ChainedChunk]) -> Result<ChainedProof, RecursionError> {
        Self::check_chain(chunks)?;
        Ok(ChainedProof {
            root: Self::chain_root(chunks),
            total_cycles: chunks.iter().map(|chunk| chunk.trace_len).sum(),
            chunks: chunks.to_vec(),
        })
    }

    pub fn verify(&self, proof: &ChainedProof) -> Result<bool, RecursionError> {
        Self::check_chain(&proof.chunks)?;
        Ok(Self::chain_root(&proof.chunks) == proof.root)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecursionError {
    #[error("chunk size must be nonzero")]
    ZeroChunkSize,
    #[error("proof set is empty")]
    EmptyProofSet,
    #[error("expected chunk {expected}, got {actual}")]
    NonContiguousChunk { expected: usize, actual: usize },
    #[error("chunk {index} does not start from the previous chunk's final state")]
    StateMismatch { index: usize },
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

    #[test]
    fn hash_chain_aggregates_and_verifies_chunks() {
        let chunks = vec![
            ChunkProof::new(0, 10, [1u8; 32], [2u8; 32]),
            ChunkProof::new(1, 20, [3u8; 32], [4u8; 32]),
        ];
        let aggregated = HashChainRecursion.aggregate(&chunks).unwrap();
        assert_eq!(aggregated.total_cycles, 30);
        assert!(HashChainRecursion.verify(&aggregated).unwrap());
    }

    #[test]
    fn hash_chain_rejects_tampering_and_gaps() {
        let chunks = vec![
            ChunkProof::new(0, 10, [1u8; 32], [2u8; 32]),
            ChunkProof::new(1, 20, [3u8; 32], [4u8; 32]),
        ];
        let mut aggregated = HashChainRecursion.aggregate(&chunks).unwrap();
        aggregated.chunks[1].state_digest = [9u8; 32];
        assert!(!HashChainRecursion.verify(&aggregated).unwrap());

        let gap = vec![ChunkProof::new(1, 10, [0u8; 32], [0u8; 32])];
        assert!(matches!(
            HashChainRecursion.aggregate(&gap),
            Err(RecursionError::NonContiguousChunk { .. })
        ));
    }

    #[test]
    fn chunk_plan_handles_empty_and_single_chunks() {
        let empty = ChunkPlan::new(0, 4).unwrap();
        assert_eq!(empty.num_chunks, 0);
        assert!(empty.is_single_chunk());
        assert!(empty.ranges().is_empty());

        let single = ChunkPlan::new(4, 4).unwrap();
        assert_eq!(single.num_chunks, 1);
        assert!(single.is_single_chunk());
        let range = single.ranges()[0];
        assert_eq!((range.index, range.start, range.end), (0, 0, 4));
        assert_eq!(range.len(), 4);
        assert!(!range.is_empty());
    }

    #[test]
    fn aggregator_rejects_empty_sets_and_unimplemented_verify() {
        assert_eq!(
            HashChainRecursion.aggregate(&[]),
            Err(RecursionError::EmptyProofSet)
        );
        let empty = AggregatedProof {
            root: [0u8; 32],
            chunks: Vec::new(),
            total_cycles: 0,
        };
        assert_eq!(
            HashChainRecursion.verify(&empty),
            Err(RecursionError::EmptyProofSet)
        );
        assert_eq!(
            UnimplementedRecursion.verify(&()),
            Err(RecursionError::Unimplemented)
        );
    }

    #[test]
    fn chained_recursion_enforces_state_continuity() {
        let chunks = vec![
            ChainedChunk::new(0, 10, [1u8; 32], [2u8; 32], [9u8; 32]),
            ChainedChunk::new(1, 20, [2u8; 32], [3u8; 32], [8u8; 32]),
        ];
        let proof = ChainedRecursion.aggregate(&chunks).unwrap();
        assert_eq!(proof.total_cycles, 30);
        assert!(ChainedRecursion.verify(&proof).unwrap());

        let mut spliced = chunks.clone();
        spliced[1].state_before = [7u8; 32];
        assert!(matches!(
            ChainedRecursion.aggregate(&spliced),
            Err(RecursionError::StateMismatch { index: 1 })
        ));

        let mut tampered = proof.clone();
        tampered.chunks[1].state_after = [7u8; 32];
        assert!(!ChainedRecursion.verify(&tampered).unwrap());
        assert_eq!(
            ChainedRecursion.aggregate(&[]),
            Err(RecursionError::EmptyProofSet)
        );
    }
}
