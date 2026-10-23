//! Reference Spartan reduction over the `magnetar-constraint` R1CS IR.
//!
//! The protocol follows Spartan's two sum-check reductions:
//! 1. outer: `0 = Σ_x eq(τ,x) (Az(x) Bz(x) − Cz(x))`;
//! 2. inner: reduce the three terminal claims to one witness evaluation.
//!
//! The reduction is real, but the PCS is pluggable and the bundled test PCS is
//! deliberately non-succinct. BinarySpartan/Ligerito can replace it later.

use crate::virtual_spartan::{
    reconstruct_segment_claim, split_segment_claims, SegmentClaim, VirtualSpartanError,
};
use crate::{
    eq, prove_product2, prove_product4, prove_product6, verify_rounds, Mle, Pcs, ProofError,
    SumcheckProof,
};
use magnetar_constraint::{
    Constraint, ConstraintError, ConstraintSystem, Expr, Witness, WitnessLayout, F2_128,
};
use magnetar_transcript::Sha256Transcript;
use std::cell::RefCell;
use thiserror::Error;

#[derive(Clone, Copy, Debug)]
pub enum MatrixPart {
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
pub(crate) struct SparseMatrix {
    pub(crate) rows: Vec<Vec<(usize, F2_128)>>,
    pub(crate) cols: usize,
}

/// Matrix interface consumed by the Spartan reduction. `SparseMatrix` is the
/// materialized form; `SharedBlockMatrix` represents q block-diagonal
/// instances with one base matrix.
pub trait SpartanMatrix {
    fn rows(&self) -> usize;
    fn cols(&self) -> usize;
    fn mul_vec(&self, z: &[F2_128]) -> Result<Vec<F2_128>, SpartanError>;
    fn row_combination(&self, row_point: &[F2_128]) -> Result<Vec<F2_128>, SpartanError>;
    fn eval_mle(&self, row_point: &[F2_128], col_point: &[F2_128]) -> Result<F2_128, SpartanError>;
}

impl SpartanMatrix for SparseMatrix {
    fn rows(&self) -> usize {
        self.rows.len()
    }

    fn cols(&self) -> usize {
        self.cols
    }

    fn mul_vec(&self, z: &[F2_128]) -> Result<Vec<F2_128>, SpartanError> {
        SparseMatrix::mul_vec(self, z)
    }

    fn row_combination(&self, row_point: &[F2_128]) -> Result<Vec<F2_128>, SpartanError> {
        SparseMatrix::row_combination(self, row_point)
    }

    fn eval_mle(&self, row_point: &[F2_128], col_point: &[F2_128]) -> Result<F2_128, SpartanError> {
        SparseMatrix::eval_mle(self, row_point, col_point)
    }
}

impl SparseMatrix {
    pub(crate) fn from_system(
        system: &ConstraintSystem,
        part: MatrixPart,
    ) -> Result<Self, SpartanError> {
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

    pub(crate) fn mul_vec(&self, z: &[F2_128]) -> Result<Vec<F2_128>, SpartanError> {
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

    pub(crate) fn row_combination(
        &self,
        row_point: &[F2_128],
    ) -> Result<Vec<F2_128>, SpartanError> {
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

    pub(crate) fn eval_mle(
        &self,
        row_point: &[F2_128],
        col_point: &[F2_128],
    ) -> Result<F2_128, SpartanError> {
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

pub(crate) fn bits(mut index: usize, count: usize) -> Vec<F2_128> {
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
    #[error("SIMD instance count must be nonzero")]
    EmptySimd,
    #[error(transparent)]
    Virtual(#[from] VirtualSpartanError),
}

/// Build the padded Spartan witness vector `z` from a constraint witness.
pub fn witness_vector(
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
    let z_mle = Mle::new(z.clone())?;
    let az_mle = Mle::new(az.clone())?;
    let bz_mle = Mle::new(bz.clone())?;
    let cz_mle = Mle::new(cz.clone())?;

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

/// Prove a Spartan relation given matrix implementations. This is the entry
/// point used by the shared-matrix SIMD path; `z` is already padded to
/// `a.cols()`.
pub fn prove_spartan_with_matrices<P: Pcs>(
    z: &[F2_128],
    a: &dyn SpartanMatrix,
    b: &dyn SpartanMatrix,
    c: &dyn SpartanMatrix,
    pcs: &P,
) -> Result<SpartanProof<P::Commitment, P::Opening>, SpartanError> {
    if z.len() != a.cols() || b.cols() != a.cols() || c.cols() != a.cols() {
        return Err(SpartanError::Dimensions);
    }
    let az = a.mul_vec(z)?;
    let bz = b.mul_vec(z)?;
    let cz = c.mul_vec(z)?;
    let z_mle = Mle::new(z.to_vec())?;
    let az_mle = Mle::new(az.to_vec())?;
    let bz_mle = Mle::new(bz.to_vec())?;
    let cz_mle = Mle::new(cz.to_vec())?;

    let row_bits = a.rows().trailing_zeros() as usize;
    let commitment = pcs.commit(z)?;
    let transcript = RefCell::new(Sha256Transcript::new("spartan-reference-v1"));
    let tau = {
        let mut transcript = transcript.borrow_mut();
        transcript.absorb("commitment", &pcs.commitment_bytes(&commitment));
        transcript.absorb("rows", &(a.rows() as u64).to_le_bytes());
        transcript.absorb("cols", &(a.cols() as u64).to_le_bytes());
        (0..row_bits)
            .map(|_| challenge_field(&mut transcript, "tau"))
            .collect::<Vec<_>>()
    };

    let eq_values: Vec<F2_128> = (0..a.rows())
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

    let a_values = a.row_combination(&rx)?;
    let b_values = b.row_combination(&rx)?;
    let c_values = c.row_combination(&rx)?;
    let left_values: Vec<F2_128> = (0..z.len())
        .map(|index| a_values[index] + r * b_values[index] + r * r * c_values[index])
        .collect();
    let (inner, ry, _) = prove_product2(left_values, z.to_vec(), |round, values| {
        round_challenge(&transcript, "inner-round", round, values)
    })?;
    if inner.claimed_sum != expected_inner_claim {
        return Err(SpartanError::ClaimMismatch {
            expected: expected_inner_claim,
            actual: inner.claimed_sum,
        });
    }

    let vw = z_mle.eval(&ry)?;
    let opening = pcs.open(z, &ry)?;
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

/// Prove q instances of one base row relation using the shared-matrix
/// representation (no q-fold materialized matrices).
pub fn prove_shared_simd_spartan<P: Pcs>(
    base: &ConstraintSystem,
    witnesses: &[Witness],
    pcs: &P,
) -> Result<SpartanProof<P::Commitment, P::Opening>, SpartanError> {
    if witnesses.is_empty() || !witnesses.len().is_power_of_two() {
        return Err(SpartanError::EmptySimd);
    }
    let a = crate::SharedBlockMatrix::from_system(base, MatrixPart::A, witnesses.len())?;
    let b = crate::SharedBlockMatrix::from_system(base, MatrixPart::B, witnesses.len())?;
    let c = crate::SharedBlockMatrix::from_system(base, MatrixPart::C, witnesses.len())?;
    let mut z = Vec::with_capacity(a.cols());
    for witness in witnesses {
        z.extend(witness_vector(base, witness)?);
    }
    if z.len() != a.cols() {
        return Err(SpartanError::Dimensions);
    }
    prove_spartan_with_matrices(&z, &a, &b, &c, pcs)
}

pub fn verify_shared_simd_spartan<P: Pcs>(
    base: &ConstraintSystem,
    instances: usize,
    proof: &SpartanProof<P::Commitment, P::Opening>,
    pcs: &P,
) -> Result<(), SpartanError> {
    if instances == 0 || !instances.is_power_of_two() {
        return Err(SpartanError::EmptySimd);
    }
    let a = crate::SharedBlockMatrix::from_system(base, MatrixPart::A, instances)?;
    let b = crate::SharedBlockMatrix::from_system(base, MatrixPart::B, instances)?;
    let c = crate::SharedBlockMatrix::from_system(base, MatrixPart::C, instances)?;
    verify_spartan_with_matrices(&a, &b, &c, proof, pcs)
}

/// Prove `q` instances of one base constraint system with a reference
/// block-diagonal SIMD encoding. The verifier rebuilds the same system.
pub fn prove_simd_spartan<P: Pcs>(
    base: &ConstraintSystem,
    witnesses: &[Witness],
    pcs: &P,
) -> Result<SpartanProof<P::Commitment, P::Opening>, SpartanError> {
    if witnesses.is_empty() {
        return Err(SpartanError::EmptySimd);
    }
    let mut combined = ConstraintSystem::new(0);
    for _ in 0..witnesses.len() {
        combined.merge(base.clone());
    }
    let mut values = Vec::new();
    for witness in witnesses {
        values.extend_from_slice(witness.values());
    }
    prove_spartan(&combined, &Witness::new(values), pcs)
}

/// Verify a Spartan proof against matrix implementations (shared-matrix SIMD
/// path).
pub fn verify_spartan_with_matrices<P: Pcs>(
    a: &dyn SpartanMatrix,
    b: &dyn SpartanMatrix,
    c: &dyn SpartanMatrix,
    proof: &SpartanProof<P::Commitment, P::Opening>,
    pcs: &P,
) -> Result<(), SpartanError> {
    if b.cols() != a.cols() || c.cols() != a.cols() || b.rows() != a.rows() || c.rows() != a.rows()
    {
        return Err(SpartanError::Dimensions);
    }
    let row_bits = a.rows().trailing_zeros() as usize;
    let col_bits = a.cols().trailing_zeros() as usize;

    let transcript = RefCell::new(Sha256Transcript::new("spartan-reference-v1"));
    let tau = {
        let mut transcript = transcript.borrow_mut();
        transcript.absorb("commitment", &pcs.commitment_bytes(&proof.commitment));
        transcript.absorb("rows", &(a.rows() as u64).to_le_bytes());
        transcript.absorb("cols", &(a.cols() as u64).to_le_bytes());
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
    let a = a.eval_mle(&rx, &ry)?;
    let b = b.eval_mle(&rx, &ry)?;
    let c = c.eval_mle(&rx, &ry)?;
    let expected_inner = (a + r * b + r * r * c) * proof.vw;
    if inner_final != expected_inner {
        return Err(SpartanError::Verification("inner sumcheck mismatch"));
    }
    if !pcs.verify(&proof.commitment, &ry, proof.vw, &proof.opening)? {
        return Err(SpartanError::Verification("PCS opening rejected"));
    }
    Ok(())
}

pub fn verify_simd_spartan<P: Pcs>(
    base: &ConstraintSystem,
    instances: usize,
    proof: &SpartanProof<P::Commitment, P::Opening>,
    pcs: &P,
) -> Result<(), SpartanError> {
    if instances == 0 {
        return Err(SpartanError::EmptySimd);
    }
    let mut combined = ConstraintSystem::new(0);
    for _ in 0..instances {
        combined.merge(base.clone());
    }
    verify_spartan(&combined, proof, pcs)
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

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LockstepProof<C: Clone + std::fmt::Debug, O: Clone + std::fmt::Debug> {
    pub commitment: C,
    pub v_a0: F2_128,
    pub v_b0: F2_128,
    pub v_c0: F2_128,
    pub v_a1: F2_128,
    pub v_b1: F2_128,
    pub v_c1: F2_128,
    pub outer: SumcheckProof<F2_128>,
    pub inner: SumcheckProof<F2_128>,
    pub segments: Vec<SegmentClaim>,
    pub opening: O,
}

/// Lockstep proof without the PCS opening. The opening is deferred until all
/// Virtual Spartan claims exist, so one commitment/opening covers the CPU `z`
/// point and every auxiliary claim.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LockstepClaims<C: Clone + std::fmt::Debug> {
    pub commitment: C,
    pub v_a0: F2_128,
    pub v_b0: F2_128,
    pub v_c0: F2_128,
    pub v_a1: F2_128,
    pub v_b1: F2_128,
    pub v_c1: F2_128,
    pub outer: SumcheckProof<F2_128>,
    pub inner: SumcheckProof<F2_128>,
    pub segments: Vec<SegmentClaim>,
}

/// Prove two relations over one shared witness with a lockstep outer
/// sum-check and a shared inner sum-check.
pub fn prove_lockstep_claims<P: Pcs>(
    system_a: &ConstraintSystem,
    system_b: &ConstraintSystem,
    witness: &Witness,
    layout: &WitnessLayout,
    pcs: &P,
    commitment: P::Commitment,
) -> Result<(LockstepClaims<P::Commitment>, Vec<F2_128>), SpartanError> {
    system_a.check(witness)?;
    system_b.check(witness)?;
    if system_a.num_vars != system_b.num_vars {
        return Err(SpartanError::Dimensions);
    }
    let a0 = SparseMatrix::from_system(system_a, MatrixPart::A)?;
    let b0 = SparseMatrix::from_system(system_a, MatrixPart::B)?;
    let c0 = SparseMatrix::from_system(system_a, MatrixPart::C)?;
    let a1 = SparseMatrix::from_system(system_b, MatrixPart::A)?;
    let b1 = SparseMatrix::from_system(system_b, MatrixPart::B)?;
    let c1 = SparseMatrix::from_system(system_b, MatrixPart::C)?;
    if a0.rows.len() != a1.rows.len() || a0.cols != a1.cols {
        return Err(SpartanError::Dimensions);
    }
    let z = witness_vector(system_a, witness)?;
    let az0 = a0.mul_vec(&z)?;
    let bz0 = b0.mul_vec(&z)?;
    let cz0 = c0.mul_vec(&z)?;
    let az1 = a1.mul_vec(&z)?;
    let bz1 = b1.mul_vec(&z)?;
    let cz1 = c1.mul_vec(&z)?;
    let az0_mle = Mle::new(az0.clone())?;
    let bz0_mle = Mle::new(bz0.clone())?;
    let cz0_mle = Mle::new(cz0.clone())?;
    let az1_mle = Mle::new(az1.clone())?;
    let bz1_mle = Mle::new(bz1.clone())?;
    let cz1_mle = Mle::new(cz1.clone())?;
    let row_bits = a0.rows.len().trailing_zeros() as usize;
    let transcript = RefCell::new(Sha256Transcript::new("lockstep-reference-v1"));
    let tau = {
        let mut transcript = transcript.borrow_mut();
        transcript.absorb("commitment", &pcs.commitment_bytes(&commitment));
        transcript.absorb("rows", &(a0.rows.len() as u64).to_le_bytes());
        transcript.absorb("cols", &(a0.cols as u64).to_le_bytes());
        (0..row_bits)
            .map(|_| challenge_field(&mut transcript, "tau"))
            .collect::<Vec<_>>()
    };
    let eq_values = (0..a0.rows.len())
        .map(|index| eq(&tau, &bits(index, row_bits)))
        .collect::<Vec<_>>();
    let alpha = {
        let mut transcript = transcript.borrow_mut();
        challenge_field(&mut transcript, "relation-batch")
    };
    let (outer, rx, _) = prove_product6(
        eq_values,
        az0,
        bz0,
        cz0,
        az1,
        bz1,
        cz1,
        alpha,
        |round, values| round_challenge(&transcript, "outer-round", round, values),
    )?;
    if outer.claimed_sum != F2_128::from(0u64) {
        return Err(SpartanError::ClaimMismatch {
            expected: F2_128::from(0u64),
            actual: outer.claimed_sum,
        });
    }
    let va0 = az0_mle.eval(&rx)?;
    let vb0 = bz0_mle.eval(&rx)?;
    let vc0 = cz0_mle.eval(&rx)?;
    let va1 = az1_mle.eval(&rx)?;
    let vb1 = bz1_mle.eval(&rx)?;
    let vc1 = cz1_mle.eval(&rx)?;
    let (r0, r1) = {
        let mut transcript = transcript.borrow_mut();
        for value in [va0, vb0, vc0, va1, vb1, vc1] {
            absorb_field(&mut transcript, "claim", value);
        }
        (
            challenge_field(&mut transcript, "batch0"),
            challenge_field(&mut transcript, "batch1"),
        )
    };
    let expected_inner_claim =
        va0 + r0 * vb0 + r0 * r0 * vc0 + alpha * (va1 + r1 * vb1 + r1 * r1 * vc1);
    let a0_values = a0.row_combination(&rx)?;
    let b0_values = b0.row_combination(&rx)?;
    let c0_values = c0.row_combination(&rx)?;
    let a1_values = a1.row_combination(&rx)?;
    let b1_values = b1.row_combination(&rx)?;
    let c1_values = c1.row_combination(&rx)?;
    let left_values = (0..z.len())
        .map(|index| {
            a0_values[index]
                + r0 * b0_values[index]
                + r0 * r0 * c0_values[index]
                + alpha * (a1_values[index] + r1 * b1_values[index] + r1 * r1 * c1_values[index])
        })
        .collect::<Vec<_>>();
    let (inner, ry, _) = prove_product2(left_values, z.clone(), |round, values| {
        round_challenge(&transcript, "inner-round", round, values)
    })?;
    if inner.claimed_sum != expected_inner_claim {
        return Err(SpartanError::ClaimMismatch {
            expected: expected_inner_claim,
            actual: inner.claimed_sum,
        });
    }
    let segments = split_segment_claims(layout, &z, &ry)?;
    Ok((
        LockstepClaims {
            commitment,
            v_a0: va0,
            v_b0: vb0,
            v_c0: vc0,
            v_a1: va1,
            v_b1: vb1,
            v_c1: vc1,
            outer,
            inner,
            segments,
        },
        ry,
    ))
}

pub fn prove_lockstep<P: Pcs>(
    system_a: &ConstraintSystem,
    system_b: &ConstraintSystem,
    witness: &Witness,
    layout: &WitnessLayout,
    pcs: &P,
) -> Result<LockstepProof<P::Commitment, P::Opening>, SpartanError> {
    let z = witness_vector(system_a, witness)?;
    let commitment = pcs.commit(&z)?;
    let (claims, ry) =
        prove_lockstep_claims(system_a, system_b, witness, layout, pcs, commitment.clone())?;
    let opening = pcs.open(&z, &ry)?;
    Ok(LockstepProof {
        commitment: claims.commitment,
        v_a0: claims.v_a0,
        v_b0: claims.v_b0,
        v_c0: claims.v_c0,
        v_a1: claims.v_a1,
        v_b1: claims.v_b1,
        v_c1: claims.v_c1,
        outer: claims.outer,
        inner: claims.inner,
        segments: claims.segments,
        opening,
    })
}

fn verify_lockstep_internal<P: Pcs>(
    system_a: &ConstraintSystem,
    system_b: &ConstraintSystem,
    layout: &WitnessLayout,
    proof: &LockstepProof<P::Commitment, P::Opening>,
    pcs: &P,
) -> Result<(Vec<F2_128>, Vec<SegmentClaim>), SpartanError> {
    if system_a.num_vars != system_b.num_vars {
        return Err(SpartanError::Dimensions);
    }
    let a0 = SparseMatrix::from_system(system_a, MatrixPart::A)?;
    let b0 = SparseMatrix::from_system(system_a, MatrixPart::B)?;
    let c0 = SparseMatrix::from_system(system_a, MatrixPart::C)?;
    let a1 = SparseMatrix::from_system(system_b, MatrixPart::A)?;
    let b1 = SparseMatrix::from_system(system_b, MatrixPart::B)?;
    let c1 = SparseMatrix::from_system(system_b, MatrixPart::C)?;
    if a0.rows.len() != a1.rows.len() || a0.cols != a1.cols {
        return Err(SpartanError::Dimensions);
    }
    let row_bits = a0.rows.len().trailing_zeros() as usize;
    let transcript = RefCell::new(Sha256Transcript::new("lockstep-reference-v1"));
    let tau = {
        let mut transcript = transcript.borrow_mut();
        transcript.absorb("commitment", &pcs.commitment_bytes(&proof.commitment));
        transcript.absorb("rows", &(a0.rows.len() as u64).to_le_bytes());
        transcript.absorb("cols", &(a0.cols as u64).to_le_bytes());
        (0..row_bits)
            .map(|_| challenge_field(&mut transcript, "tau"))
            .collect::<Vec<_>>()
    };
    let alpha = {
        let mut transcript = transcript.borrow_mut();
        challenge_field(&mut transcript, "relation-batch")
    };
    let (rx, outer_final) = verify_rounds(&proof.outer, row_bits, 3, |round, values| {
        round_challenge(&transcript, "outer-round", round, values)
    })?;
    let expected_outer = eq(&tau, &rx)
        * (proof.v_a0 * proof.v_b0 - proof.v_c0 + alpha * (proof.v_a1 * proof.v_b1 - proof.v_c1));
    if outer_final != expected_outer {
        return Err(SpartanError::Verification("lockstep outer mismatch"));
    }
    let (r0, r1) = {
        let mut transcript = transcript.borrow_mut();
        for value in [
            proof.v_a0, proof.v_b0, proof.v_c0, proof.v_a1, proof.v_b1, proof.v_c1,
        ] {
            absorb_field(&mut transcript, "claim", value);
        }
        (
            challenge_field(&mut transcript, "batch0"),
            challenge_field(&mut transcript, "batch1"),
        )
    };
    let expected_inner_claim = proof.v_a0
        + r0 * proof.v_b0
        + r0 * r0 * proof.v_c0
        + alpha * (proof.v_a1 + r1 * proof.v_b1 + r1 * r1 * proof.v_c1);
    if proof.inner.claimed_sum != expected_inner_claim {
        return Err(SpartanError::Verification("lockstep inner claim mismatch"));
    }
    let (ry, inner_final) = verify_rounds(
        &proof.inner,
        a0.cols.trailing_zeros() as usize,
        2,
        |round, values| round_challenge(&transcript, "inner-round", round, values),
    )?;
    let vw = reconstruct_segment_claim(layout, &proof.segments, &ry)?;
    let a0_at = a0.eval_mle(&rx, &ry)?;
    let b0_at = b0.eval_mle(&rx, &ry)?;
    let c0_at = c0.eval_mle(&rx, &ry)?;
    let a1_at = a1.eval_mle(&rx, &ry)?;
    let b1_at = b1.eval_mle(&rx, &ry)?;
    let c1_at = c1.eval_mle(&rx, &ry)?;
    let expected_inner =
        (a0_at + r0 * b0_at + r0 * r0 * c0_at + alpha * (a1_at + r1 * b1_at + r1 * r1 * c1_at))
            * vw;
    if inner_final != expected_inner {
        return Err(SpartanError::Verification("lockstep inner mismatch"));
    }
    if !pcs.verify(&proof.commitment, &ry, vw, &proof.opening)? {
        return Err(SpartanError::Verification("lockstep PCS opening rejected"));
    }
    Ok((ry, proof.segments.clone()))
}

pub fn verify_lockstep_claims<P: Pcs>(
    system_a: &ConstraintSystem,
    system_b: &ConstraintSystem,
    layout: &WitnessLayout,
    claims: &LockstepClaims<P::Commitment>,
    pcs: &P,
) -> Result<(Vec<F2_128>, Vec<SegmentClaim>, F2_128), SpartanError> {
    if system_a.num_vars != system_b.num_vars {
        return Err(SpartanError::Dimensions);
    }
    let a0 = SparseMatrix::from_system(system_a, MatrixPart::A)?;
    let b0 = SparseMatrix::from_system(system_a, MatrixPart::B)?;
    let c0 = SparseMatrix::from_system(system_a, MatrixPart::C)?;
    let a1 = SparseMatrix::from_system(system_b, MatrixPart::A)?;
    let b1 = SparseMatrix::from_system(system_b, MatrixPart::B)?;
    let c1 = SparseMatrix::from_system(system_b, MatrixPart::C)?;
    if a0.rows.len() != a1.rows.len() || a0.cols != a1.cols {
        return Err(SpartanError::Dimensions);
    }
    let row_bits = a0.rows.len().trailing_zeros() as usize;
    let transcript = RefCell::new(Sha256Transcript::new("lockstep-reference-v1"));
    let tau = {
        let mut transcript = transcript.borrow_mut();
        transcript.absorb("commitment", &pcs.commitment_bytes(&claims.commitment));
        transcript.absorb("rows", &(a0.rows.len() as u64).to_le_bytes());
        transcript.absorb("cols", &(a0.cols as u64).to_le_bytes());
        (0..row_bits)
            .map(|_| challenge_field(&mut transcript, "tau"))
            .collect::<Vec<_>>()
    };
    let alpha = {
        let mut transcript = transcript.borrow_mut();
        challenge_field(&mut transcript, "relation-batch")
    };
    let (rx, outer_final) = verify_rounds(&claims.outer, row_bits, 3, |round, values| {
        round_challenge(&transcript, "outer-round", round, values)
    })?;
    let expected_outer = eq(&tau, &rx)
        * (claims.v_a0 * claims.v_b0 - claims.v_c0
            + alpha * (claims.v_a1 * claims.v_b1 - claims.v_c1));
    if outer_final != expected_outer {
        return Err(SpartanError::Verification("lockstep outer mismatch"));
    }
    let (r0, r1) = {
        let mut transcript = transcript.borrow_mut();
        for value in [
            claims.v_a0,
            claims.v_b0,
            claims.v_c0,
            claims.v_a1,
            claims.v_b1,
            claims.v_c1,
        ] {
            absorb_field(&mut transcript, "claim", value);
        }
        (
            challenge_field(&mut transcript, "batch0"),
            challenge_field(&mut transcript, "batch1"),
        )
    };
    let expected_inner_claim = claims.v_a0
        + r0 * claims.v_b0
        + r0 * r0 * claims.v_c0
        + alpha * (claims.v_a1 + r1 * claims.v_b1 + r1 * r1 * claims.v_c1);
    if claims.inner.claimed_sum != expected_inner_claim {
        return Err(SpartanError::Verification("lockstep inner claim mismatch"));
    }
    let (ry, inner_final) = verify_rounds(
        &claims.inner,
        a0.cols.trailing_zeros() as usize,
        2,
        |round, values| round_challenge(&transcript, "inner-round", round, values),
    )?;
    let vw = reconstruct_segment_claim(layout, &claims.segments, &ry)?;
    let a0_at = a0.eval_mle(&rx, &ry)?;
    let b0_at = b0.eval_mle(&rx, &ry)?;
    let c0_at = c0.eval_mle(&rx, &ry)?;
    let a1_at = a1.eval_mle(&rx, &ry)?;
    let b1_at = b1.eval_mle(&rx, &ry)?;
    let c1_at = c1.eval_mle(&rx, &ry)?;
    let expected_inner =
        (a0_at + r0 * b0_at + r0 * r0 * c0_at + alpha * (a1_at + r1 * b1_at + r1 * r1 * c1_at))
            * vw;
    if inner_final != expected_inner {
        return Err(SpartanError::Verification("lockstep inner mismatch"));
    }
    Ok((ry, claims.segments.clone(), vw))
}

pub fn verify_lockstep<P: Pcs>(
    system_a: &ConstraintSystem,
    system_b: &ConstraintSystem,
    layout: &WitnessLayout,
    proof: &LockstepProof<P::Commitment, P::Opening>,
    pcs: &P,
) -> Result<(), SpartanError> {
    verify_lockstep_internal(system_a, system_b, layout, proof, pcs).map(|_| ())
}

/// Verify a lockstep proof and expose the inner challenge plus the per-segment
/// Virtual Spartan claims. This is the routing point where CPU segment claims
/// can be handed to BinaryTwist/BinaryShout/BinaryRouter.
pub fn verify_lockstep_segments<P: Pcs>(
    system_a: &ConstraintSystem,
    system_b: &ConstraintSystem,
    layout: &WitnessLayout,
    proof: &LockstepProof<P::Commitment, P::Opening>,
    pcs: &P,
) -> Result<(Vec<F2_128>, Vec<SegmentClaim>), SpartanError> {
    verify_lockstep_internal(system_a, system_b, layout, proof, pcs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_constraint::{Segment, SegmentKind, SegmentOwner};
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
    #[test]
    fn simd_spartan_round_trips() {
        let mut base = ConstraintSystem::new(3);
        base.add_constraint(
            Expr::var(0).add(Expr::var(1)),
            Expr::constant(1u64),
            Expr::var(2),
        );
        let pcs = TestPcs;
        let witnesses = vec![
            Witness::new(vec![
                F2_128::from(1u64),
                F2_128::from(2u64),
                F2_128::from(3u64),
            ]),
            Witness::new(vec![
                F2_128::from(0u64),
                F2_128::from(0u64),
                F2_128::from(0u64),
            ]),
        ];
        let proof = prove_simd_spartan(&base, &witnesses, &pcs).unwrap();
        verify_simd_spartan(&base, witnesses.len(), &proof, &pcs).unwrap();
        assert!(verify_simd_spartan(&base, 3, &proof, &pcs).is_err());
    }
    #[test]
    fn lockstep_round_trips() {
        let mut system_a = ConstraintSystem::new(3);
        system_a.add_constraint(
            Expr::var(0).add(Expr::var(1)),
            Expr::constant(1u64),
            Expr::var(2),
        );
        let mut system_b = ConstraintSystem::new(3);
        system_b.add_constraint(
            Expr::var(0).add(Expr::var(1)),
            Expr::constant(1u64),
            Expr::var(2),
        );
        let witness = Witness::new(vec![
            F2_128::from(1u64),
            F2_128::from(2u64),
            F2_128::from(3u64),
        ]);
        let pcs = TestPcs;
        let layout = WitnessLayout::new(vec![
            Segment::new("a", 0, 2, SegmentKind::Direct, SegmentOwner::Cpu),
            Segment::new("b", 2, 2, SegmentKind::Direct, SegmentOwner::Cpu),
        ])
        .unwrap();
        let proof = prove_lockstep(&system_a, &system_b, &witness, &layout, &pcs).unwrap();
        verify_lockstep(&system_a, &system_b, &layout, &proof, &pcs).unwrap();

        let mut tampered = proof.clone();
        tampered.v_a0 = tampered.v_a0 + F2_128::from(1u64);
        assert!(verify_lockstep(&system_a, &system_b, &layout, &tampered, &pcs).is_err());

        let mut tampered = proof;
        tampered.segments[0].value = tampered.segments[0].value + F2_128::from(1u64);
        assert!(verify_lockstep(&system_a, &system_b, &layout, &tampered, &pcs).is_err());
    }
    #[test]
    fn lockstep_claims_defer_the_opening() {
        let mut system = ConstraintSystem::new(3);
        system.add_constraint(
            Expr::var(0).add(Expr::var(1)),
            Expr::constant(1u64),
            Expr::var(2),
        );
        let witness = Witness::new(vec![
            F2_128::from(1u64),
            F2_128::from(2u64),
            F2_128::from(3u64),
        ]);
        let pcs = TestPcs;
        let layout = WitnessLayout::new(vec![
            Segment::new("a", 0, 2, SegmentKind::Direct, SegmentOwner::Cpu),
            Segment::new("b", 2, 2, SegmentKind::Direct, SegmentOwner::Cpu),
        ])
        .unwrap();
        let z = witness_vector(&system, &witness).unwrap();
        let commitment = pcs.commit(&z).unwrap();
        let (claims, ry) = prove_lockstep_claims(
            &system,
            &system,
            &witness,
            &layout,
            &pcs,
            commitment.clone(),
        )
        .unwrap();
        let (verified_ry, verified_segments, verified_vw) =
            verify_lockstep_claims(&system, &system, &layout, &claims, &pcs).unwrap();
        assert_eq!(verified_ry, ry);
        assert_eq!(verified_segments, claims.segments);
        let vw = reconstruct_segment_claim(&layout, &claims.segments, &ry).unwrap();
        assert_eq!(verified_vw, vw);
        let opening = pcs.open(&z, &ry).unwrap();
        assert!(pcs.verify(&commitment, &ry, vw, &opening).unwrap());
    }
    #[test]
    fn shared_block_spartan_proves_a_two_instance_batch() {
        let base = system_and_witness().0;
        let witnesses = [
            Witness::new(vec![
                F2_128::from(1u64),
                F2_128::from(2u64),
                F2_128::from(2u64),
            ]),
            Witness::new(vec![
                F2_128::from(3u64),
                F2_128::from(4u64),
                F2_128::from(12u64),
            ]),
        ];
        let a = crate::SharedBlockMatrix::from_system(&base, MatrixPart::A, 2).unwrap();
        let b = crate::SharedBlockMatrix::from_system(&base, MatrixPart::B, 2).unwrap();
        let c = crate::SharedBlockMatrix::from_system(&base, MatrixPart::C, 2).unwrap();
        let mut z = Vec::new();
        for witness in &witnesses {
            z.extend(witness_vector(&base, witness).unwrap());
        }
        assert_eq!(z.len(), a.cols());
        let pcs = TestPcs;
        let proof = prove_spartan_with_matrices(&z, &a, &b, &c, &pcs).unwrap();
        verify_spartan_with_matrices(&a, &b, &c, &proof, &pcs).unwrap();
    }
    #[test]
    fn shared_simd_api_round_trips() {
        let base = system_and_witness().0;
        let witnesses = [
            Witness::new(vec![
                F2_128::from(1u64),
                F2_128::from(2u64),
                F2_128::from(2u64),
            ]),
            Witness::new(vec![
                F2_128::from(3u64),
                F2_128::from(4u64),
                F2_128::from(12u64),
            ]),
        ];
        let pcs = TestPcs;
        let proof = prove_shared_simd_spartan(&base, &witnesses, &pcs).unwrap();
        verify_shared_simd_spartan(&base, witnesses.len(), &proof, &pcs).unwrap();
    }
}
