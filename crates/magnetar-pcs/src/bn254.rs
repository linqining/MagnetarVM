//! BN254 KZG polynomial commitment backend.
//!
//! This is a succinct prime-field PCS built on the mature `arkworks` curve and
//! pairing implementation. It is separate from the binary-field Spartan path,
//! which still uses the reference Merkle/naive PCS.

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use magnetar_transcript::sha256;
use rand::Rng;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bn254KzgCommitment(pub G1Affine);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bn254KzgOpening(pub G1Affine);

#[derive(Clone, Debug)]
pub struct Bn254KzgBatchOpening {
    pub point: Fr,
    pub commitments: Vec<Bn254KzgCommitment>,
    pub values: Vec<Fr>,
    pub proof: G1Affine,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Bn254KzgError {
    #[error("polynomial degree {degree} exceeds setup degree {max_degree}")]
    DegreeTooLarge { degree: usize, max_degree: usize },
    #[error("KZG setup requires a positive degree bound")]
    ZeroDegree,
}

#[derive(Clone, Debug)]
pub struct Bn254Kzg {
    g: G1Affine,
    powers: Vec<G1Affine>,
    h: G2Affine,
    tau_h: G2Affine,
}

impl Bn254Kzg {
    /// Create a reference KZG setup. The toxic waste `tau` is discarded.
    pub fn setup<R: Rng>(max_degree: usize, rng: &mut R) -> Result<Self, Bn254KzgError> {
        if max_degree == 0 {
            return Err(Bn254KzgError::ZeroDegree);
        }
        let tau = Fr::rand(rng);
        let g = G1Projective::rand(rng).into_affine();
        let h = G2Projective::rand(rng).into_affine();
        let mut powers = Vec::with_capacity(max_degree + 1);
        let mut current = G1Projective::from(g);
        for _ in 0..=max_degree {
            powers.push(current.into_affine());
            current = current.mul(tau.into_repr());
        }
        let tau_h = G2Projective::from(h).mul(tau.into_repr()).into_affine();
        Ok(Self {
            g,
            powers,
            h,
            tau_h,
        })
    }

    pub fn commit(&self, coefficients: &[Fr]) -> Result<Bn254KzgCommitment, Bn254KzgError> {
        if coefficients.len() > self.powers.len() {
            return Err(Bn254KzgError::DegreeTooLarge {
                degree: coefficients.len().saturating_sub(1),
                max_degree: self.powers.len().saturating_sub(1),
            });
        }
        let mut commitment = G1Projective::zero();
        for (coefficient, power) in coefficients.iter().zip(self.powers.iter()) {
            commitment += power.mul(coefficient.into_repr());
        }
        Ok(Bn254KzgCommitment(commitment.into_affine()))
    }

    pub fn evaluate(coefficients: &[Fr], point: Fr) -> Fr {
        let mut value = Fr::zero();
        for coefficient in coefficients.iter().rev() {
            value = value * point + coefficient;
        }
        value
    }

    pub fn open(&self, coefficients: &[Fr], point: Fr) -> Result<Bn254KzgOpening, Bn254KzgError> {
        if coefficients.len() > self.powers.len() {
            return Err(Bn254KzgError::DegreeTooLarge {
                degree: coefficients.len().saturating_sub(1),
                max_degree: self.powers.len().saturating_sub(1),
            });
        }
        let mut quotient = vec![Fr::zero(); coefficients.len().saturating_sub(1)];
        let n = coefficients.len();
        if n >= 2 {
            quotient[n - 2] = coefficients[n - 1];
            for index in (1..n - 1).rev() {
                quotient[index - 1] = coefficients[index] + point * quotient[index];
            }
        }
        let proof = self.commit(&quotient)?;
        Ok(Bn254KzgOpening(proof.0))
    }

    pub fn verify(
        &self,
        commitment: &Bn254KzgCommitment,
        point: Fr,
        value: Fr,
        opening: &Bn254KzgOpening,
    ) -> bool {
        let numerator = G1Projective::from(commitment.0) - self.g.mul(value.into_repr());
        let denominator =
            G2Projective::from(self.tau_h) - G2Projective::from(self.h).mul(point.into_repr());
        Bn254::pairing(numerator, self.h) == Bn254::pairing(opening.0, denominator)
    }

    pub fn open_batch(
        &self,
        polynomials: &[Vec<Fr>],
        point: Fr,
    ) -> Result<Bn254KzgBatchOpening, Bn254KzgError> {
        let commitments = polynomials
            .iter()
            .map(|coefficients| self.commit(coefficients))
            .collect::<Result<Vec<_>, _>>()?;
        let values = polynomials
            .iter()
            .map(|coefficients| Self::evaluate(coefficients, point))
            .collect::<Vec<_>>();
        let alpha = batch_challenge(&commitments, point, &values);
        let max_len = polynomials.iter().map(Vec::len).max().unwrap_or(0);
        let mut combined = vec![Fr::zero(); max_len];
        let mut power = Fr::from(1u64);
        for coefficients in polynomials {
            for (index, coefficient) in coefficients.iter().enumerate() {
                combined[index] += power * coefficient;
            }
            power *= alpha;
        }
        let proof = self.open(&combined, point)?.0;
        Ok(Bn254KzgBatchOpening {
            point,
            commitments,
            values,
            proof,
        })
    }

    pub fn verify_batch(&self, opening: &Bn254KzgBatchOpening) -> bool {
        if opening.commitments.len() != opening.values.len() {
            return false;
        }
        let alpha = batch_challenge(&opening.commitments, opening.point, &opening.values);
        let mut power = Fr::from(1u64);
        let mut combined_commitment = G1Projective::zero();
        let mut combined_value = Fr::zero();
        for (commitment, value) in opening.commitments.iter().zip(opening.values.iter()) {
            combined_commitment += G1Projective::from(commitment.0).mul(power.into_repr());
            combined_value += power * value;
            power *= alpha;
        }
        self.verify(
            &Bn254KzgCommitment(combined_commitment.into_affine()),
            opening.point,
            combined_value,
            &Bn254KzgOpening(opening.proof),
        )
    }
}

fn batch_challenge(commitments: &[Bn254KzgCommitment], point: Fr, values: &[Fr]) -> Fr {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"magnetar-bn254-kzg-batch-v1");
    for commitment in commitments {
        commitment
            .0
            .serialize(&mut bytes)
            .expect("canonical G1 serialization");
    }
    for limb in point.into_repr().as_ref() {
        bytes.extend_from_slice(&limb.to_le_bytes());
    }
    for value in values {
        for limb in value.into_repr().as_ref() {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
    }
    Fr::from_le_bytes_mod_order(&sha256(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::One;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn kzg_commit_open_verify_round_trip() {
        let mut rng = StdRng::seed_from_u64(7);
        let kzg = Bn254Kzg::setup(8, &mut rng).unwrap();
        let coefficients = (0..5).map(Fr::from).collect::<Vec<_>>();
        let commitment = kzg.commit(&coefficients).unwrap();
        let point = Fr::from(3u64);
        let value = Bn254Kzg::evaluate(&coefficients, point);
        let opening = kzg.open(&coefficients, point).unwrap();
        assert!(kzg.verify(&commitment, point, value, &opening));

        assert!(!kzg.verify(&commitment, point, value + Fr::one(), &opening));
        assert!(!kzg.verify(&commitment, point + Fr::one(), value, &opening));
        let mut wrong = opening;
        wrong.0 = G1Projective::rand(&mut rng).into_affine();
        assert!(!kzg.verify(&commitment, point, value, &wrong));
    }

    #[test]
    fn kzg_rejects_oversized_polynomials() {
        let mut rng = StdRng::seed_from_u64(11);
        let kzg = Bn254Kzg::setup(2, &mut rng).unwrap();
        let coefficients = vec![Fr::from(1u64); 4];
        assert!(matches!(
            kzg.commit(&coefficients),
            Err(Bn254KzgError::DegreeTooLarge { .. })
        ));
    }

    #[test]
    fn kzg_batch_openings_verify_and_reject_tampering() {
        let mut rng = StdRng::seed_from_u64(13);
        let kzg = Bn254Kzg::setup(8, &mut rng).unwrap();
        let polynomials = vec![
            (0..5).map(Fr::from).collect::<Vec<_>>(),
            (0..3).map(|value| Fr::from(value * 2 + 1)).collect(),
            vec![Fr::from(7u64)],
        ];
        let point = Fr::from(4u64);
        let opening = kzg.open_batch(&polynomials, point).unwrap();
        assert!(kzg.verify_batch(&opening));

        let mut bad_value = opening.clone();
        bad_value.values[1] += Fr::from(1u64);
        assert!(!kzg.verify_batch(&bad_value));

        let mut bad_commitment = opening.clone();
        bad_commitment.commitments[0].0 = G1Projective::rand(&mut rng).into_affine();
        assert!(!kzg.verify_batch(&bad_commitment));

        let mut bad_proof = opening;
        bad_proof.proof = G1Projective::rand(&mut rng).into_affine();
        assert!(!kzg.verify_batch(&bad_proof));
    }
}
