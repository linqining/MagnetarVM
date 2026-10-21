//! Reference Spartan reduction over the `magnetar-constraint` R1CS IR.
//!
//! The protocol follows Spartan's two sum-check reductions:
//! 1. outer: `0 = Σ_x eq(τ,x) (Az(x) Bz(x) − Cz(x))`;
//! 2. inner: reduce the three terminal claims to one witness evaluation.
//!
//! The reduction is real, but the PCS is pluggable and the bundled test PCS is
//! deliberately non-succinct. BinarySpartan/Ligerito can replace it later.

use crate::{
    eq, prove_product2, prove_product4, verify_rounds, Mle, Pcs, ProofError, SumcheckProof,
};
use magnetar_constraint::{Constraint, ConstraintError, ConstraintSystem, Expr, Witness, F2_128};
use magnetar_transcript::Sha256Transcript;
use std::cell::RefCell;
use thiserror::Error;

#[derive(Clone, Copy, Debug)]
enum MatrixPart {
    A,
    B,
    C,
}

impl MatrixPart {
    fn select(self, constraint: &Constraint) -> &Expr {
        match self {
            MatrixPart::A => &constraint.a,
            MatrixPart::B => &constraint.b,
            MatrixPart::C => &constraint.c,
        }
    }
}

#[derive(Clone, Debug)]
struct SparseMatrix {
    rows: Vec<Vec<(usize, F2_128)>>,
    cols: usize,
}

impl SparseMatrix {
    fn from_system(system: &ConstraintSystem, part: MatrixPart) -> Result<Self, SpartanError> {
        let rows_padded = system.constraints.len().next_power_of_two().max(1);
        let cols = (system.num_vars + 1).next_power_of_two().max(1);
        let mut rows = Vec::with_capacity(rows_padded);
        for (index, constraint) in system.constraints.iter().enumerate() {
            let linear = part
                .select(constraint)
                .to_linear_combination()
                .map_err(|_| SpartanError::NonLinear(index))?;
            rows.push(linear.coefficients(system.num_vars));
        }
        rows.resize(rows_padded, Vec::new());
        Ok(Self { rows, cols })
    }

    fn mul_vec(&self, z: &[F2_128]) -> Result<Vec<F2_128>, SpartanError> {
        if z.len() != self.cols {
            return Err(SpartanError::Dimensions);
        }
        Ok(self
            .rows
            .iter()
            .map(|row| {
                row.iter()
                    .fold(F2_128::from(0u64), |sum, (index, coefficient)| {
                        sum + *coefficient * z[*index]
                    })
            })
            .collect())
    }

    fn row_combination(&self, row_point: &[F2_128]) -> Result<Vec<F2_128>, SpartanError> {
        let row_bits = self.rows.len().trailing_zeros() as usize;
        if row_point.len() != row_bits {
            return Err(SpartanError::Dimensions);
        }
        let row_eq: Vec<F2_128> = (0..self.rows.len())
            .map(|index| eq(row_point, &bits(index, row_bits)))
            .collect();
        let mut result = vec![F2_128::from(0u64); self.cols];
        for (row_index, row) in self.rows.iter().enumerate() {
            for (col_index, coefficient) in row {
                result[*col_index] = result[*col_index] + *coefficient * row_eq[row_index];
            }
        }
        Ok(result)
    }

    fn eval_mle(&self, row_point: &[F2_128], col_point: &[F2_128]) -> Result<F2_128, SpartanError> {
        let row_bits = self.rows.len().trailing_zeros() as usize;
        let col_bits = self.cols.trailing_zeros() as usize;
        if row_point.len() != row_bits || col_point.len() != col_bits {
            return Err(SpartanError::Dimensions);
        }
        let row_eq: Vec<F2_128> = (0..self.rows.len())
            .map(|index| eq(row_point, &bits(index, row_bits)))
            .collect();
        let col_eq: Vec<F2_128> = (0..self.cols)
            .map(|index| eq(col_point, &bits(index, col_bits)))
            .collect();
        let mut sum = F2_128::from(0u64);
        for (row_index, row) in self.rows.iter().enumerate() {
            for (col_index, coefficient) in row {
                sum = sum + *coefficient * row_eq[row_index] * col_eq[*col_index];
            }
        }
        Ok(sum)
    }
}

fn bits(mut index: usize, count: usize) -> Vec<F2_128> {
    (0..count)
        .map(|_| {
            let bit = index & 1;
            index >>= 1;
            F2_128::from(bit as u64)
        })
        .collect()
}

fn field_bytes(value: F2_128) -> [u8; 16] {
    value.value().to_le_bytes()
}

fn absorb_field(transcript: &mut Sha256Transcript, label: &str, value: F2_128) {
    transcript.absorb(label, &field_bytes(value));
}

fn challenge_field(transcript: &mut Sha256Transcript, label: &str) -> F2_128 {
    let bytes = transcript.challenge_bytes(label, 16);
    F2_128::new(u128::from_le_bytes(bytes.try_into().expect("16 bytes")))
}

fn round_challenge(
    transcript: &RefCell<Sha256Transcript>,
    label: &str,
    round: usize,
    values: &[F2_128],
) -> F2_128 {
    let mut transcript = transcript.borrow_mut();
    transcript.absorb(label, &(round as u64).to_le_bytes());
    for value in values {
        absorb_field(&mut transcript, label, *value);
    }
    challenge_field(&mut transcript, label)
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SpartanProof<C: Clone + std::fmt::Debug, O: Clone + std::fmt::Debug> {
    pub commitment: C,
    pub v_a: F2_128,
    pub v_b: F2_128,
    pub v_c: F2_128,
    pub outer: SumcheckProof<F2_128>,
    pub inner: SumcheckProof<F2_128>,
    pub vw: F2_128,
    pub opening: O,
}

#[derive(Debug, Error)]
pub enum SpartanError {
    #[error(transparent)]
    Constraint(#[from] ConstraintError),
    #[error("constraint {0} has a nonlinear A/B expression")]
    NonLinear(usize),
    #[error(transparent)]
    Proof(#[from] ProofError),
    #[error("matrix dimensions mismatch")]
    Dimensions,
    #[error("sumcheck claim mismatch: expected {expected:?}, got {actual:?}")]
    ClaimMismatch { expected: F2_128, actual: F2_128 },
    #[error("verification failed: {0}")]
    Verification(&'static str),
}

fn witness_vector(
    system: &ConstraintSystem,
    witness: &Witness,
) -> Result<Vec<F2_128>, SpartanError> {
    if witness.len() < system.num_vars {
        return Err(SpartanError::Constraint(ConstraintError::WitnessTooShort {
            expected: system.num_vars,
            actual: witness.len(),
        }));
    }
    let cols = (system.num_vars + 1).next_power_of_two().max(1);
    let mut z = vec![F2_128::from(0u64); cols];
    z[..system.num_vars].copy_from_slice(&witness.values()[..system.num_vars]);
    z[system.num_vars] = F2_128::from(1u64);
    Ok(z)
}

pub fn prove_spartan<P: Pcs>(
    system: &ConstraintSystem,
    witness: &Witness,
    pcs: &P,
) -> Result<SpartanProof<P::Commitment, P::Opening>, SpartanError> {
    system.check(witness)?;
    let a_matrix = SparseMatrix::from_system(system, MatrixPart::A)?;
    let b_matrix = SparseMatrix::from_system(system, MatrixPart::B)?;
    let c_matrix = SparseMatrix::from_system(system, MatrixPart::C)?;
    let z = witness_vector(system, witness)?;
    let az = a_matrix.mul_vec(&z)?;
    let bz = b_matrix.mul_vec(&z)?;
    let cz = c_matrix.mul_vec(&z)?;
    let az_mle = Mle::new(az.clone())?;
    let bz_mle = Mle::new(bz.clone())?;
    let cz_mle = Mle::new(cz.clone())?;
    let z_mle = Mle::new(z.clone())?;

    let row_bits = a_matrix.rows.len().trailing_zeros() as usize;
    let commitment = pcs.commit(&z)?;
    let transcript = RefCell::new(Sha256Transcript::new("spartan-reference-v1"));
    let tau = {
        let mut transcript = transcript.borrow_mut();
        transcript.absorb("commitment", &pcs.commitment_bytes(&commitment));
        transcript.absorb("rows", &(a_matrix.rows.len() as u64).to_le_bytes());
        transcript.absorb("cols", &(a_matrix.cols as u64).to_le_bytes());
        (0..row_bits)
            .map(|_| challenge_field(&mut transcript, "tau"))
            .collect::<Vec<_>>()
    };

    let eq_values: Vec<F2_128> = (0..a_matrix.rows.len())
        .map(|index| eq(&tau, &bits(index, row_bits)))
        .collect();
    let (outer, rx, _) = prove_product4(eq_values, az, bz, cz, |round, values| {
        round_challenge(&transcript, "outer-round", round, values)
    })?;
    if outer.claimed_sum != F2_128::from(0u64) {
        return Err(SpartanError::ClaimMismatch {
            expected: F2_128::from(0u64),
            actual: outer.claimed_sum,
        });
    }

    let v_a = az_mle.eval(&rx)?;
    let v_b = bz_mle.eval(&rx)?;
    let v_c = cz_mle.eval(&rx)?;
    {
        let mut transcript = transcript.borrow_mut();
        absorb_field(&mut transcript, "va", v_a);
        absorb_field(&mut transcript, "vb", v_b);
        absorb_field(&mut transcript, "vc", v_c);
    }
    let r = {
        let mut transcript = transcript.borrow_mut();
        challenge_field(&mut transcript, "batch")
    };
    let expected_inner_claim = v_a + r * v_b + r * r * v_c;

    let a_values = a_matrix.row_combination(&rx)?;
    let b_values = b_matrix.row_combination(&rx)?;
    let c_values = c_matrix.row_combination(&rx)?;
    let left_values: Vec<F2_128> = (0..z.len())
        .map(|index| a_values[index] + r * b_values[index] + r * r * c_values[index])
        .collect();
    let (inner, ry, _) = prove_product2(left_values, z.clone(), |round, values| {
        round_challenge(&transcript, "inner-round", round, values)
    })?;
    if inner.claimed_sum != expected_inner_claim {
        return Err(SpartanError::ClaimMismatch {
            expected: expected_inner_claim,
            actual: inner.claimed_sum,
        });
    }

    let vw = z_mle.eval(&ry)?;
    let opening = pcs.open(&z, &ry)?;
    Ok(SpartanProof {
        commitment,
        v_a,
        v_b,
        v_c,
        outer,
        inner,
        vw,
        opening,
    })
}

pub fn verify_spartan<P: Pcs>(
    system: &ConstraintSystem,
    proof: &SpartanProof<P::Commitment, P::Opening>,
    pcs: &P,
) -> Result<(), SpartanError> {
    let a_matrix = SparseMatrix::from_system(system, MatrixPart::A)?;
    let b_matrix = SparseMatrix::from_system(system, MatrixPart::B)?;
    let c_matrix = SparseMatrix::from_system(system, MatrixPart::C)?;
    let row_bits = a_matrix.rows.len().trailing_zeros() as usize;
    let col_bits = a_matrix.cols.trailing_zeros() as usize;

    let transcript = RefCell::new(Sha256Transcript::new("spartan-reference-v1"));
    let tau = {
        let mut transcript = transcript.borrow_mut();
        transcript.absorb("commitment", &pcs.commitment_bytes(&proof.commitment));
        transcript.absorb("rows", &(a_matrix.rows.len() as u64).to_le_bytes());
        transcript.absorb("cols", &(a_matrix.cols as u64).to_le_bytes());
        (0..row_bits)
            .map(|_| challenge_field(&mut transcript, "tau"))
            .collect::<Vec<_>>()
    };

    if proof.outer.claimed_sum != F2_128::from(0u64) {
        return Err(SpartanError::Verification("outer claim is not zero"));
    }
    let (rx, outer_final) = verify_rounds(&proof.outer, row_bits, 3, |round, values| {
        round_challenge(&transcript, "outer-round", round, values)
    })?;
    let expected_outer = eq(&tau, &rx) * (proof.v_a * proof.v_b - proof.v_c);
    if outer_final != expected_outer {
        return Err(SpartanError::Verification("outer sumcheck mismatch"));
    }

    {
        let mut transcript = transcript.borrow_mut();
        absorb_field(&mut transcript, "va", proof.v_a);
        absorb_field(&mut transcript, "vb", proof.v_b);
        absorb_field(&mut transcript, "vc", proof.v_c);
    }
    let r = {
        let mut transcript = transcript.borrow_mut();
        challenge_field(&mut transcript, "batch")
    };
    let expected_inner_claim = proof.v_a + r * proof.v_b + r * r * proof.v_c;
    if proof.inner.claimed_sum != expected_inner_claim {
        return Err(SpartanError::Verification("inner claim mismatch"));
    }
    let (ry, inner_final) = verify_rounds(&proof.inner, col_bits, 2, |round, values| {
        round_challenge(&transcript, "inner-round", round, values)
    })?;
    let a = a_matrix.eval_mle(&rx, &ry)?;
    let b = b_matrix.eval_mle(&rx, &ry)?;
    let c = c_matrix.eval_mle(&rx, &ry)?;
    let expected_inner = (a + r * b + r * r * c) * proof.vw;
    if inner_final != expected_inner {
        return Err(SpartanError::Verification("inner sumcheck mismatch"));
    }
    if !pcs.verify(&proof.commitment, &ry, proof.vw, &proof.opening)? {
        return Err(SpartanError::Verification("PCS opening rejected"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_transcript::sha256;

    #[derive(Clone, Debug)]
    struct TestCommitment([u8; 32]);

    #[derive(Clone, Debug)]
    struct TestOpening(Vec<F2_128>);

    #[derive(Clone, Copy, Debug, Default)]
    struct TestPcs;

    impl Pcs for TestPcs {
        type Commitment = TestCommitment;
        type Opening = TestOpening;

        fn commit(&self, values: &[F2_128]) -> Result<Self::Commitment, ProofError> {
            Ok(TestCommitment(commitment_root(values)?))
        }

        fn open(&self, values: &[F2_128], point: &[F2_128]) -> Result<Self::Opening, ProofError> {
            Mle::new(values.to_vec())?.eval(point)?;
            Ok(TestOpening(values.to_vec()))
        }

        fn verify(
            &self,
            commitment: &Self::Commitment,
            point: &[F2_128],
            value: F2_128,
            opening: &Self::Opening,
        ) -> Result<bool, ProofError> {
            if commitment_root(&opening.0)? != commitment.0 {
                return Ok(false);
            }
            let mle = Mle::new(opening.0.clone())?;
            Ok(mle.eval(point)? == value)
        }

        fn commitment_bytes(&self, commitment: &Self::Commitment) -> Vec<u8> {
            commitment.0.to_vec()
        }
    }

    fn commitment_root(values: &[F2_128]) -> Result<[u8; 32], ProofError> {
        if values.is_empty() || !values.len().is_power_of_two() {
            return Err(ProofError::NotPowerOfTwo(values.len()));
        }
        let mut bytes = Vec::with_capacity(values.len() * 16);
        for value in values {
            bytes.extend_from_slice(&field_bytes(*value));
        }
        Ok(sha256(&bytes))
    }

    fn system_and_witness() -> (ConstraintSystem, Witness) {
        let a = F2_128::from(6u64);
        let b = F2_128::from(7u64);
        let product = a * b;
        let mut system = ConstraintSystem::new(3);
        system.add_constraint(Expr::var(0), Expr::var(1), Expr::var(2));
        (system, Witness::new(vec![a, b, product]))
    }

    #[test]
    fn proves_and_verifies_a_satisfied_system() {
        let (system, witness) = system_and_witness();
        let proof = prove_spartan(&system, &witness, &TestPcs).unwrap();
        verify_spartan(&system, &proof, &TestPcs).unwrap();
    }

    #[test]
    fn rejects_a_tampered_terminal_value() {
        let (system, witness) = system_and_witness();
        let mut proof = prove_spartan(&system, &witness, &TestPcs).unwrap();
        proof.v_a = proof.v_a + F2_128::from(1u64);
        assert!(verify_spartan(&system, &proof, &TestPcs).is_err());
    }

    #[test]
    fn rejects_a_tampered_opening() {
        let (system, witness) = system_and_witness();
        let mut proof = prove_spartan(&system, &witness, &TestPcs).unwrap();
        proof.opening.0[0] = proof.opening.0[0] + F2_128::from(1u64);
        assert!(verify_spartan(&system, &proof, &TestPcs).is_err());
    }

    #[test]
    fn rejects_nonlinear_a_or_b() {
        let a = F2_128::from(6u64);
        let b = F2_128::from(7u64);
        let product = a * b;
        let mut system = ConstraintSystem::new(2);
        system.add_constraint(
            Expr::var(0).mul(Expr::var(1)),
            Expr::constant(1u64),
            Expr::constant(product),
        );
        let witness = Witness::new(vec![a, b]);
        assert!(matches!(
            prove_spartan(&system, &witness, &TestPcs),
            Err(SpartanError::NonLinear(0))
        ));
    }

    #[test]
    fn rejects_short_witnesses_and_tampered_proof_components() {
        let (system, witness) = system_and_witness();
        assert!(matches!(
            prove_spartan(
                &system,
                &Witness::new(vec![F2_128::from(1u64), F2_128::from(2u64)]),
                &TestPcs
            ),
            Err(SpartanError::Constraint(
                ConstraintError::WitnessTooShort { .. }
            ))
        ));

        let proof = prove_spartan(&system, &witness, &TestPcs).unwrap();

        let mut tampered = proof.clone();
        tampered.v_b = tampered.v_b + F2_128::from(1u64);
        assert!(verify_spartan(&system, &tampered, &TestPcs).is_err());

        let mut tampered = proof.clone();
        tampered.v_c = tampered.v_c + F2_128::from(1u64);
        assert!(verify_spartan(&system, &tampered, &TestPcs).is_err());

        let mut tampered = proof.clone();
        tampered.outer.claimed_sum = tampered.outer.claimed_sum + F2_128::from(1u64);
        assert!(verify_spartan(&system, &tampered, &TestPcs).is_err());

        let mut tampered = proof.clone();
        tampered.inner.round_polys[0][0] = tampered.inner.round_polys[0][0] + F2_128::from(1u64);
        assert!(verify_spartan(&system, &tampered, &TestPcs).is_err());

        let mut tampered = proof.clone();
        tampered.inner.claimed_sum = tampered.inner.claimed_sum + F2_128::from(1u64);
        assert!(verify_spartan(&system, &tampered, &TestPcs).is_err());

        let mut tampered = proof;
        tampered.commitment.0[0] ^= 1;
        assert!(verify_spartan(&system, &tampered, &TestPcs).is_err());
    }

    #[test]
    fn proves_and_verifies_an_empty_system() {
        let system = ConstraintSystem::new(0);
        let witness = Witness::new(Vec::new());
        let proof = prove_spartan(&system, &witness, &TestPcs).unwrap();
        verify_spartan(&system, &proof, &TestPcs).unwrap();
    }
}
