//! Hash-based commitments.
//!
//! `MerkleTree` is a real binary Merkle tree with domain-separated SHA-256.
//! `NaiveMerklePcs` is a deliberately non-succinct PCS used to exercise the
//! interface: its opening includes the whole evaluation vector. It is not a
//! replacement for Ligerito.

use magnetar_constraint::F61;
use magnetar_proof::Mle;
use magnetar_transcript::sha256;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath {
    pub index: usize,
    pub siblings: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct MerkleTree {
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    pub fn from_leaves(mut leaves: Vec<Vec<u8>>) -> Result<Self, PcsError> {
        if leaves.is_empty() {
            return Err(PcsError::Empty);
        }
        let last = leaves.last().cloned().expect("nonempty");
        while !leaves.len().is_power_of_two() {
            leaves.push(last.clone());
        }
        let mut levels = Vec::with_capacity(leaves.len().trailing_zeros() as usize + 1);
        let leaf_level: Vec<[u8; 32]> = leaves
            .iter()
            .map(|leaf| {
                let mut input = Vec::with_capacity(1 + leaf.len());
                input.push(0x00);
                input.extend_from_slice(leaf);
                sha256(&input)
            })
            .collect();
        levels.push(leaf_level);
        while levels.last().expect("nonempty").len() > 1 {
            let current = levels.last().expect("nonempty");
            let mut next = Vec::with_capacity(current.len() / 2);
            for pair in current.chunks_exact(2) {
                let mut input = Vec::with_capacity(1 + 64);
                input.push(0x01);
                input.extend_from_slice(&pair[0]);
                input.extend_from_slice(&pair[1]);
                next.push(sha256(&input));
            }
            levels.push(next);
        }
        Ok(Self { levels })
    }

    pub fn root(&self) -> [u8; 32] {
        self.levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .expect("tree always has a root")
    }

    pub fn leaves(&self) -> usize {
        self.levels.first().map(Vec::len).unwrap_or(0)
    }

    pub fn proof(&self, index: usize) -> Result<MerklePath, PcsError> {
        if index >= self.leaves() {
            return Err(PcsError::IndexOutOfRange(index));
        }
        let original = index;
        let mut cursor = index;
        let mut siblings = Vec::with_capacity(self.levels.len().saturating_sub(1));
        for level in self.levels.iter().take(self.levels.len() - 1) {
            let sibling = if cursor.is_multiple_of(2) {
                cursor + 1
            } else {
                cursor - 1
            };
            siblings.push(level[sibling]);
            cursor /= 2;
        }
        Ok(MerklePath {
            index: original,
            siblings,
        })
    }

    pub fn verify(root: [u8; 32], leaf: &[u8], path: &MerklePath) -> bool {
        let mut input = Vec::with_capacity(1 + leaf.len());
        input.push(0x00);
        input.extend_from_slice(leaf);
        let mut current = sha256(&input);
        let mut index = path.index;
        for sibling in &path.siblings {
            let mut input = Vec::with_capacity(65);
            input.push(0x01);
            if index.is_multiple_of(2) {
                input.extend_from_slice(&current);
                input.extend_from_slice(sibling);
            } else {
                input.extend_from_slice(sibling);
                input.extend_from_slice(&current);
            }
            current = sha256(&input);
            index /= 2;
        }
        current == root
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NaiveCommitment {
    pub root: [u8; 32],
    pub num_vars: usize,
    pub len: usize,
}

#[derive(Clone, Debug)]
pub struct NaiveOpening {
    pub evaluations: Vec<F61>,
}

pub trait PolynomialCommitment {
    type Commitment;
    type Opening;
    type Error;

    fn commit(&self, mle: &Mle<F61>) -> Result<Self::Commitment, Self::Error>;
    fn open(&self, mle: &Mle<F61>, point: &[F61]) -> Result<Self::Opening, Self::Error>;
    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &[F61],
        value: F61,
        opening: &Self::Opening,
    ) -> Result<bool, Self::Error>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NaiveMerklePcs;

impl PolynomialCommitment for NaiveMerklePcs {
    type Commitment = NaiveCommitment;
    type Opening = NaiveOpening;
    type Error = PcsError;

    fn commit(&self, mle: &Mle<F61>) -> Result<Self::Commitment, Self::Error> {
        let leaves = mle
            .evaluations()
            .iter()
            .map(|value| value.value().to_le_bytes().to_vec())
            .collect();
        let tree = MerkleTree::from_leaves(leaves)?;
        Ok(NaiveCommitment {
            root: tree.root(),
            num_vars: mle.num_vars(),
            len: mle.len(),
        })
    }

    fn open(&self, mle: &Mle<F61>, point: &[F61]) -> Result<Self::Opening, Self::Error> {
        mle.eval(point).map_err(|_| PcsError::PointLength {
            expected: mle.num_vars(),
            actual: point.len(),
        })?;
        Ok(NaiveOpening {
            evaluations: mle.evaluations().to_vec(),
        })
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &[F61],
        value: F61,
        opening: &Self::Opening,
    ) -> Result<bool, Self::Error> {
        if opening.evaluations.len() != commitment.len
            || commitment.len != 1usize << commitment.num_vars
        {
            return Ok(false);
        }
        let leaves = opening
            .evaluations
            .iter()
            .map(|value| value.value().to_le_bytes().to_vec())
            .collect();
        let tree = MerkleTree::from_leaves(leaves)?;
        if tree.root() != commitment.root {
            return Ok(false);
        }
        let mle = Mle::new(opening.evaluations.clone()).map_err(|_| PcsError::ShapeMismatch)?;
        Ok(mle.eval(point) == Ok(value))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PcsError {
    #[error("empty leaf set")]
    Empty,
    #[error("leaf index {0} is out of range")]
    IndexOutOfRange(usize),
    #[error("point length {actual}, expected {expected}")]
    PointLength { expected: usize, actual: usize },
    #[error("opening shape mismatch")]
    ShapeMismatch,
    #[error("evaluation mismatch")]
    EvaluationMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves() -> Vec<Vec<u8>> {
        vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()]
    }

    #[test]
    fn merkle_paths_verify() {
        let tree = MerkleTree::from_leaves(leaves()).unwrap();
        for index in 0..tree.leaves() {
            let path = tree.proof(index).unwrap();
            let leaf = &leaves()[index];
            assert!(MerkleTree::verify(tree.root(), leaf, &path));
        }
    }

    #[test]
    fn tampered_leaf_fails() {
        let tree = MerkleTree::from_leaves(leaves()).unwrap();
        let path = tree.proof(1).unwrap();
        assert!(!MerkleTree::verify(tree.root(), b"tampered", &path));
    }

    #[test]
    fn naive_pcs_round_trips() {
        let mle = Mle::new(vec![F61::from(1), F61::from(2), F61::from(3), F61::from(4)]).unwrap();
        let pcs = NaiveMerklePcs;
        let commitment = pcs.commit(&mle).unwrap();
        let point = [F61::from(1), F61::from(0)];
        let value = mle.eval(&point).unwrap();
        let opening = pcs.open(&mle, &point).unwrap();
        assert!(pcs.verify(&commitment, &point, value, &opening).unwrap());
        assert!(!pcs
            .verify(&commitment, &point, value + F61::from(1), &opening)
            .unwrap());
    }
}
