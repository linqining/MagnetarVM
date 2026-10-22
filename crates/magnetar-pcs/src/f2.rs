//! Succinct F2 opening by embedding bits into the packed P3 field.
//!
//! This is not a native F2 Ligerito instance; it reuses the existing P3
//! binary-field PCS over `F2_128` and embeds each bit as `0` or `1`.

use magnetar_constraint::{F2, F2_128};
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

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_constraint::Field;
    use magnetar_proof::Mle;

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
