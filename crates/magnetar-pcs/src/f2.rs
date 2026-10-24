//! Succinct F2 opening by embedding bits into the packed P3 field.
//!
//! This is not a native F2 Ligerito instance; it reuses the existing P3
//! binary-field PCS over `F2_128` and embeds each bit as `0` or `1`.

use magnetar_constraint::{Field, F2, F2_128};
use magnetar_proof::{Pcs, ProofError};

use crate::p3_pcs::{P3BinaryPcs, P3Commitment, P3Opening};

#[derive(Clone, Debug)]
pub struct F2Pcs {
    inner: P3BinaryPcs,
}

impl F2Pcs {
    pub fn new(security_level: usize) -> Self {
        Self {
            inner: P3BinaryPcs::new(security_level),
        }
    }

    pub fn commit(&self, values: &[F2]) -> Result<P3Commitment, ProofError> {
        self.inner.commit(&embed(values))
    }

    pub fn open(&self, values: &[F2], point: &[F2_128]) -> Result<P3Opening, ProofError> {
        self.inner.open(&embed(values), point)
    }

    pub fn verify(
        &self,
        commitment: &P3Commitment,
        point: &[F2_128],
        value: F2,
        opening: &P3Opening,
    ) -> Result<bool, ProofError> {
        self.inner.verify(
            commitment,
            point,
            F2_128::from(u64::from(value.value())),
            opening,
        )
    }
}

fn embed(values: &[F2]) -> Vec<F2_128> {
    values
        .iter()
        .map(|value| F2_128::from(u64::from(value.value())))
        .collect()
}

// Native F2 vector commitment: Merkle tree over bits. At an F2 point the
// multilinear evaluation is exactly one coefficient bit, so the opening is a
// Merkle path. This is a native-F2 PCS for F2 challenges; extension-field
// challenges need a different opening (sumcheck/lift), which is the next step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct F2NativeCommitment(pub [u8; 32]);

#[derive(Clone, Debug)]
pub struct F2NativeOpening {
    pub value: F2,
    pub path: Vec<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct F2NativePcs;

impl F2NativePcs {
    pub fn commit(&self, values: &[F2]) -> Result<F2NativeCommitment, ProofError> {
        if values.is_empty() {
            return Err(ProofError::Pcs("empty F2 commitment".into()));
        }
        let layers = merkle_layers(values);
        Ok(F2NativeCommitment(
            *layers
                .last()
                .and_then(|layer| layer.first())
                .ok_or_else(|| ProofError::Pcs("empty F2 Merkle tree".into()))?,
        ))
    }

    pub fn open(&self, values: &[F2], point: &[F2]) -> Result<F2NativeOpening, ProofError> {
        if values.is_empty() {
            return Err(ProofError::Pcs("empty F2 opening".into()));
        }
        let index = f2_point_index(point)?;
        if index >= values.len() {
            return Err(ProofError::Pcs("F2 opening point out of range".into()));
        }
        let layers = merkle_layers(values);
        let mut path = Vec::with_capacity(layers.len().saturating_sub(1));
        let mut position = index;
        for layer in layers.iter().take(layers.len().saturating_sub(1)) {
            path.push(layer[position ^ 1]);
            position >>= 1;
        }
        Ok(F2NativeOpening {
            value: values[index],
            path,
        })
    }

    pub fn verify(
        &self,
        commitment: &F2NativeCommitment,
        point: &[F2],
        opening: &F2NativeOpening,
    ) -> Result<bool, ProofError> {
        let index = f2_point_index(point)?;
        let mut node = leaf_hash(opening.value);
        let mut position = index;
        for sibling in &opening.path {
            node = if position & 1 == 0 {
                node_hash(&node, sibling)
            } else {
                node_hash(sibling, &node)
            };
            position >>= 1;
        }
        Ok(node == commitment.0)
    }
}

fn f2_point_index(point: &[F2]) -> Result<usize, ProofError> {
    if point.len() >= usize::BITS as usize {
        return Err(ProofError::Pcs("F2 point too long".into()));
    }
    let mut index = 0usize;
    for (bit, value) in point.iter().enumerate() {
        if value.value() == 1 {
            index |= 1usize << bit;
        }
    }
    Ok(index)
}

fn leaf_hash(value: F2) -> [u8; 32] {
    magnetar_transcript::sha256_labeled(b"f2-native-leaf", &[value.value()])
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(left);
    bytes.extend_from_slice(right);
    magnetar_transcript::sha256_labeled(b"f2-native-node", &bytes)
}

fn merkle_layers(values: &[F2]) -> Vec<Vec<[u8; 32]>> {
    let padded = values.len().next_power_of_two();
    let mut leaves = values
        .iter()
        .map(|value| leaf_hash(*value))
        .collect::<Vec<_>>();
    leaves.resize(padded, leaf_hash(F2::from_u64(0u64)));
    let mut layers = vec![leaves];
    while layers.last().map_or(0, Vec::len) > 1 {
        let previous = layers.last().expect("nonempty");
        let mut next = Vec::with_capacity(previous.len() / 2);
        for pair in previous.chunks(2) {
            next.push(node_hash(&pair[0], &pair[1]));
        }
        layers.push(next);
    }
    layers
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_constraint::Field;
    use magnetar_proof::Mle;

    #[test]
    fn native_f2_merkle_opening_round_trips() {
        let pcs = F2NativePcs;
        let values = (0..16u64)
            .map(|index| F2::from_u64(index % 2))
            .collect::<Vec<_>>();
        let point = (0..4u64)
            .map(|bit| F2::from_u64((bit * 5 + 1) % 2))
            .collect::<Vec<_>>();
        let index = point
            .iter()
            .enumerate()
            .fold(0usize, |index, (bit, value)| {
                if value.value() == 1 {
                    index | (1 << bit)
                } else {
                    index
                }
            });
        let commitment = pcs.commit(&values).unwrap();
        let opening = pcs.open(&values, &point).unwrap();
        assert_eq!(opening.value, values[index]);
        assert!(pcs.verify(&commitment, &point, &opening).unwrap());
        let mut wrong = opening.clone();
        wrong.value = F2::from_u64(u64::from(1 - wrong.value.value()));
        assert!(!pcs.verify(&commitment, &point, &wrong).unwrap());
    }

    #[test]
    fn succinct_f2_opening_round_trips() {
        let pcs = F2Pcs::new(100);
        let values = (0..64u64)
            .map(|index| F2::from_u64(index.wrapping_mul(0x9e37_79b9)))
            .collect::<Vec<_>>();
        let point = (0..6u64)
            .map(|bit| F2_128::from((bit * 7 + 3) & 1))
            .collect::<Vec<_>>();
        let embedded = embed(&values);
        let value = Mle::new(embedded.clone()).unwrap().eval(&point).unwrap();
        let commitment = pcs.commit(&values).unwrap();
        let opening = pcs.open(&values, &point).unwrap();
        assert!(pcs
            .verify(
                &commitment,
                &point,
                F2::from_u64(value.value() as u64),
                &opening
            )
            .unwrap());

        let mut wrong = point.clone();
        wrong[0] = wrong[0] + F2_128::from(1u64);
        assert!(!pcs
            .verify(
                &commitment,
                &wrong,
                F2::from_u64(value.value() as u64),
                &opening
            )
            .unwrap());
    }
}
