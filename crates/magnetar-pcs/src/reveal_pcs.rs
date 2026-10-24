//! Reference non-succinct, non-hiding point-evaluation PCS.
//!
//! The opening reveals the whole evaluation vector; the verifier recomputes the
//! hash commitment and the MLE evaluation. This is useful as a correctness and
//! size baseline for small tables, not as a succinct production PCS.

use magnetar_constraint::F2_128;
use magnetar_proof::{Mle, Pcs, ProofError};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevealCommitment(pub [u8; 32]);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevealOpening {
    pub values: Vec<F2_128>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RevealPcs;

fn digest(values: &[F2_128]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(values.len() * 16);
    for value in values {
        bytes.extend_from_slice(&value.value().to_le_bytes());
    }
    magnetar_transcript::sha256(&bytes)
}

impl Pcs for RevealPcs {
    type Commitment = RevealCommitment;
    type Opening = RevealOpening;

    fn commit(&self, values: &[F2_128]) -> Result<Self::Commitment, ProofError> {
        if values.is_empty() || !values.len().is_power_of_two() {
            return Err(ProofError::NotPowerOfTwo(values.len()));
        }
        Ok(RevealCommitment(digest(values)))
    }

    fn open(&self, values: &[F2_128], point: &[F2_128]) -> Result<Self::Opening, ProofError> {
        if values.len() != 1 << point.len() {
            return Err(ProofError::Pcs("dimensions".into()));
        }
        Ok(RevealOpening {
            values: values.to_vec(),
        })
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &[F2_128],
        value: F2_128,
        opening: &Self::Opening,
    ) -> Result<bool, ProofError> {
        if digest(&opening.values) != commitment.0 || opening.values.len() != 1 << point.len() {
            return Ok(false);
        }
        let evaluated = Mle::new(opening.values.clone())?.eval(point)?;
        Ok(evaluated == value)
    }

    fn commitment_bytes(&self, commitment: &Self::Commitment) -> Vec<u8> {
        commitment.0.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reveal_pcs_round_trips() {
        let values = (0..128).map(|i| F2_128::from(i as u64)).collect::<Vec<_>>();
        let point = (0..7)
            .map(|i| F2_128::from((i % 2) as u64))
            .collect::<Vec<_>>();
        let pcs = RevealPcs;
        let commitment = pcs.commit(&values).unwrap();
        let value = Mle::new(values.clone()).unwrap().eval(&point).unwrap();
        let opening = pcs.open(&values, &point).unwrap();
        assert!(pcs.verify(&commitment, &point, value, &opening).unwrap());
        eprintln!(
            "reveal opening {}",
            bincode::serialize(&opening).unwrap().len()
        );
    }
}
