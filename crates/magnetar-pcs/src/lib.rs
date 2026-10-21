//! Hash-based commitments.
//!
//! `MerkleTree` is a real binary Merkle tree with domain-separated SHA-256.
//! `NaiveMerklePcs` is a deliberately non-succinct PCS used to exercise the
//! interface: its opening includes the whole evaluation vector. It is not a
//! replacement for Ligerito.

pub mod bn254;
pub use bn254::{
    Bn254Kzg, Bn254KzgBatchOpening, Bn254KzgCommitment, Bn254KzgError, Bn254KzgOpening,
};

use magnetar_constraint::F2_128;
use magnetar_proof::{Mle, Pcs, ProofError, SpartanProof};
use magnetar_transcript::sha256;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NaiveCommitment {
    pub root: [u8; 32],
    pub num_vars: usize,
    pub len: usize,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NaiveOpening {
    pub evaluations: Vec<F2_128>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MerkleVectorCommitment {
    pub root: [u8; 32],
    pub len: usize,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MerkleVectorOpening {
    pub indices: Vec<usize>,
    pub leaves: Vec<Vec<u8>>,
    pub paths: Vec<MerklePath>,
}

/// Merkle vector commitment with batched leaf openings.
#[derive(Clone, Copy, Debug, Default)]
pub struct MerkleVectorPcs;

impl MerkleVectorPcs {
    pub fn commit(&self, leaves: &[Vec<u8>]) -> Result<MerkleVectorCommitment, PcsError> {
        let tree = MerkleTree::from_leaves(leaves.to_vec())?;
        Ok(MerkleVectorCommitment {
            root: tree.root(),
            len: leaves.len(),
        })
    }

    pub fn open(
        &self,
        leaves: &[Vec<u8>],
        indices: &[usize],
    ) -> Result<MerkleVectorOpening, PcsError> {
        if leaves.is_empty() {
            return Err(PcsError::Empty);
        }
        let mut seen = std::collections::HashSet::with_capacity(indices.len());
        for &index in indices {
            if index >= leaves.len() {
                return Err(PcsError::IndexOutOfRange(index));
            }
            if !seen.insert(index) {
                return Err(PcsError::DuplicateIndex(index));
            }
        }
        let tree = MerkleTree::from_leaves(leaves.to_vec())?;
        let mut opened_leaves = Vec::with_capacity(indices.len());
        let mut paths = Vec::with_capacity(indices.len());
        for &index in indices {
            opened_leaves.push(leaves[index].clone());
            paths.push(tree.proof(index)?);
        }
        Ok(MerkleVectorOpening {
            indices: indices.to_vec(),
            leaves: opened_leaves,
            paths,
        })
    }

    pub fn verify(
        &self,
        commitment: &MerkleVectorCommitment,
        opening: &MerkleVectorOpening,
    ) -> Result<bool, PcsError> {
        if commitment.len == 0
            || opening.indices.len() != opening.leaves.len()
            || opening.indices.len() != opening.paths.len()
        {
            return Ok(false);
        }
        let mut seen = std::collections::HashSet::with_capacity(opening.indices.len());
        for ((&index, leaf), path) in opening
            .indices
            .iter()
            .zip(opening.leaves.iter())
            .zip(opening.paths.iter())
        {
            if index >= commitment.len || path.index != index || !seen.insert(index) {
                return Ok(false);
            }
            if !MerkleTree::verify(commitment.root, leaf, path) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

pub type NaiveSpartanProof = SpartanProof<NaiveCommitment, NaiveOpening>;

/// Canonical proof-format encoding for the reference Spartan proof.
pub fn encode_spartan(proof: &NaiveSpartanProof) -> Result<Vec<u8>, PcsError> {
    bincode::serialize(proof).map_err(|error| PcsError::Encoding(error.to_string()))
}

pub fn decode_spartan(bytes: &[u8]) -> Result<NaiveSpartanProof, PcsError> {
    bincode::deserialize(bytes).map_err(|error| PcsError::Encoding(error.to_string()))
}

pub trait PolynomialCommitment {
    type Commitment;
    type Opening;
    type Error;

    fn commit(&self, mle: &Mle<F2_128>) -> Result<Self::Commitment, Self::Error>;
    fn open(&self, mle: &Mle<F2_128>, point: &[F2_128]) -> Result<Self::Opening, Self::Error>;
    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &[F2_128],
        value: F2_128,
        opening: &Self::Opening,
    ) -> Result<bool, Self::Error>;
}

#[derive(Clone, Copy, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct NaiveMerklePcs;

impl PolynomialCommitment for NaiveMerklePcs {
    type Commitment = NaiveCommitment;
    type Opening = NaiveOpening;
    type Error = PcsError;

    fn commit(&self, mle: &Mle<F2_128>) -> Result<Self::Commitment, Self::Error> {
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

    fn open(&self, mle: &Mle<F2_128>, point: &[F2_128]) -> Result<Self::Opening, Self::Error> {
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
        point: &[F2_128],
        value: F2_128,
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

impl Pcs for NaiveMerklePcs {
    type Commitment = NaiveCommitment;
    type Opening = NaiveOpening;

    fn commit(&self, values: &[F2_128]) -> Result<Self::Commitment, ProofError> {
        let mle = Mle::new(values.to_vec())?;
        <Self as PolynomialCommitment>::commit(self, &mle)
            .map_err(|error| ProofError::Pcs(error.to_string()))
    }

    fn open(&self, values: &[F2_128], point: &[F2_128]) -> Result<Self::Opening, ProofError> {
        let mle = Mle::new(values.to_vec())?;
        <Self as PolynomialCommitment>::open(self, &mle, point)
            .map_err(|error| ProofError::Pcs(error.to_string()))
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &[F2_128],
        value: F2_128,
        opening: &Self::Opening,
    ) -> Result<bool, ProofError> {
        <Self as PolynomialCommitment>::verify(self, commitment, point, value, opening)
            .map_err(|error| ProofError::Pcs(error.to_string()))
    }

    fn commitment_bytes(&self, commitment: &Self::Commitment) -> Vec<u8> {
        commitment.root.to_vec()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PcsError {
    #[error("empty leaf set")]
    Empty,
    #[error("leaf index {0} is out of range")]
    IndexOutOfRange(usize),
    #[error("leaf index {0} appears more than once")]
    DuplicateIndex(usize),
    #[error("point length {actual}, expected {expected}")]
    PointLength { expected: usize, actual: usize },
    #[error("opening shape mismatch")]
    ShapeMismatch,
    #[error("evaluation mismatch")]
    EvaluationMismatch,
    #[error("proof encoding failed: {0}")]
    Encoding(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves() -> Vec<Vec<u8>> {
        vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()]
    }

    #[test]
    fn spartan_proof_bytes_roundtrip() {
        use magnetar_constraint::{ConstraintSystem, Expr, Witness};
        use magnetar_proof::{prove_spartan, verify_spartan};

        let a = F2_128::from(6u64);
        let b = F2_128::from(7u64);
        let mut system = ConstraintSystem::new(3);
        system.add_constraint(Expr::var(0), Expr::var(1), Expr::var(2));
        let witness = Witness::new(vec![a, b, a * b]);
        let proof = prove_spartan(&system, &witness, &NaiveMerklePcs).unwrap();
        let bytes = encode_spartan(&proof).unwrap();
        assert!(!bytes.is_empty());
        let decoded = decode_spartan(&bytes).unwrap();
        verify_spartan(&system, &decoded, &NaiveMerklePcs).unwrap();
        assert!(decode_spartan(&bytes[..bytes.len() / 2]).is_err());
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
    fn merkle_tree_pads_and_rejects_bad_indices() {
        let tree =
            MerkleTree::from_leaves(vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]).unwrap();
        assert_eq!(tree.leaves(), 4);
        let path = tree.proof(2).unwrap();
        assert!(MerkleTree::verify(tree.root(), b"c", &path));
        assert!(MerkleTree::verify(
            tree.root(),
            b"c",
            &tree.proof(3).unwrap()
        ));
        assert!(!MerkleTree::verify(tree.root(), b"d", &path));

        let mut tampered = path.clone();
        tampered.siblings[0][0] ^= 1;
        assert!(!MerkleTree::verify(tree.root(), b"c", &tampered));
        assert!(matches!(tree.proof(4), Err(PcsError::IndexOutOfRange(4))));
        assert!(matches!(
            MerkleTree::from_leaves(Vec::new()),
            Err(PcsError::Empty)
        ));

        let single = MerkleTree::from_leaves(vec![b"x".to_vec()]).unwrap();
        assert_eq!(single.leaves(), 1);
        assert!(MerkleTree::verify(
            single.root(),
            b"x",
            &single.proof(0).unwrap()
        ));
    }

    #[test]
    fn naive_pcs_rejects_wrong_shapes_and_exposes_bytes() {
        let mle = Mle::new(vec![F2_128::from(1u64), F2_128::from(2u64)]).unwrap();
        let pcs = NaiveMerklePcs;
        let commitment = <NaiveMerklePcs as PolynomialCommitment>::commit(&pcs, &mle).unwrap();
        assert_eq!(commitment.num_vars, 1);
        assert_eq!(commitment.len, 2);
        assert_eq!(
            <NaiveMerklePcs as Pcs>::commitment_bytes(&pcs, &commitment),
            commitment.root.to_vec()
        );

        let point = [F2_128::from(1u64)];
        let opening = <NaiveMerklePcs as PolynomialCommitment>::open(&pcs, &mle, &point).unwrap();
        let value = mle.eval(&point).unwrap();
        assert!(<NaiveMerklePcs as PolynomialCommitment>::verify(
            &pcs,
            &commitment,
            &point,
            value,
            &opening
        )
        .unwrap());

        assert!(matches!(
            <NaiveMerklePcs as PolynomialCommitment>::open(&pcs, &mle, &[]),
            Err(PcsError::PointLength {
                expected: 1,
                actual: 0
            })
        ));

        let mut short = opening.clone();
        short.evaluations.pop();
        assert!(!<NaiveMerklePcs as PolynomialCommitment>::verify(
            &pcs,
            &commitment,
            &point,
            value,
            &short
        )
        .unwrap());

        let wrong_commitment = NaiveCommitment {
            root: [0u8; 32],
            num_vars: 1,
            len: 2,
        };
        assert!(!<NaiveMerklePcs as PolynomialCommitment>::verify(
            &pcs,
            &wrong_commitment,
            &point,
            value,
            &opening
        )
        .unwrap());
    }

    #[test]
    fn naive_pcs_round_trips() {
        let mle = Mle::new(vec![
            F2_128::from(1u64),
            F2_128::from(2u64),
            F2_128::from(3u64),
            F2_128::from(4u64),
        ])
        .unwrap();
        let pcs = NaiveMerklePcs;
        let commitment = PolynomialCommitment::commit(&pcs, &mle).unwrap();
        let point = [F2_128::from(1u64), F2_128::from(0u64)];
        let value = mle.eval(&point).unwrap();
        let opening = PolynomialCommitment::open(&pcs, &mle, &point).unwrap();
        assert!(PolynomialCommitment::verify(&pcs, &commitment, &point, value, &opening).unwrap());
        assert!(!PolynomialCommitment::verify(
            &pcs,
            &commitment,
            &point,
            value + F2_128::from(1u64),
            &opening
        )
        .unwrap());
    }

    #[test]
    fn merkle_vector_commitment_opens_batches() {
        let leaves = vec![
            b"alpha".to_vec(),
            b"beta".to_vec(),
            b"gamma".to_vec(),
            b"delta".to_vec(),
            b"epsilon".to_vec(),
        ];
        let pcs = MerkleVectorPcs;
        let commitment = pcs.commit(&leaves).unwrap();
        let opening = pcs.open(&leaves, &[0, 2, 4]).unwrap();
        assert!(pcs.verify(&commitment, &opening).unwrap());

        let mut bad_leaf = opening.clone();
        bad_leaf.leaves[1][0] ^= 1;
        assert!(!pcs.verify(&commitment, &bad_leaf).unwrap());

        let mut bad_path = opening.clone();
        bad_path.paths[0].index = 1;
        assert!(!pcs.verify(&commitment, &bad_path).unwrap());

        let mut duplicate = opening.clone();
        duplicate.indices[1] = 0;
        assert!(!pcs.verify(&commitment, &duplicate).unwrap());

        let mut bad_root = commitment.clone();
        bad_root.root[0] ^= 1;
        assert!(!pcs.verify(&bad_root, &opening).unwrap());

        assert!(matches!(
            pcs.open(&leaves, &[5]),
            Err(PcsError::IndexOutOfRange(5))
        ));
        assert!(matches!(
            pcs.open(&leaves, &[1, 1]),
            Err(PcsError::DuplicateIndex(1))
        ));
        assert!(matches!(pcs.commit(&[]), Err(PcsError::Empty)));
    }
}
