//! A minimal F2 relation and its embedding into the packed F2_128 relation.
//!
//! The reference CPU still uses one packed field. This module makes the F2
//! side explicit: a sparse R1CS over bits is checked with XOR/AND semantics
//! and then embedded into a `ConstraintSystem` over `F2_128` for the lockstep
//! proof. Because the witness is bit-valued, the embedding preserves the
//! relation exactly.

use magnetar_constraint::{ConstraintSystem, Expr, VarId, Witness, F2_128};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitRow {
    pub a: Vec<VarId>,
    pub b: Vec<VarId>,
    pub c: Vec<VarId>,
}

impl BitRow {
    pub fn new(a: Vec<VarId>, b: Vec<VarId>, c: Vec<VarId>) -> Self {
        Self { a, b, c }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitRelation {
    pub num_vars: usize,
    pub rows: Vec<BitRow>,
}

impl BitRelation {
    pub fn new(num_vars: usize) -> Self {
        Self {
            num_vars,
            rows: Vec::new(),
        }
    }

    pub fn add(&mut self, row: BitRow) {
        self.rows.push(row);
    }

    fn parity(terms: &[VarId], bits: &[bool]) -> bool {
        terms.iter().filter(|term| bits[**term]).count() % 2 == 1
    }

    /// Check the relation over F2 (XOR sums and AND products).
    pub fn check(&self, bits: &[bool]) -> bool {
        if bits.len() < self.num_vars {
            return false;
        }
        self.rows.iter().all(|row| {
            let a = Self::parity(&row.a, bits);
            let b = Self::parity(&row.b, bits);
            let c = Self::parity(&row.c, bits);
            (a && b) == c
        })
    }

    /// Embed the same relation into the packed field.
    pub fn to_system(&self) -> ConstraintSystem {
        let mut system = ConstraintSystem::new(self.num_vars);
        let sum = |terms: &[VarId]| {
            terms.iter().fold(Expr::constant(0u64), |expr, term| {
                expr.add(Expr::var(*term))
            })
        };
        for row in &self.rows {
            system.add_constraint(sum(&row.a), sum(&row.b), sum(&row.c));
        }
        system
    }

    pub fn to_witness(&self, bits: &[bool]) -> Witness {
        Witness::new(
            bits.iter()
                .take(self.num_vars)
                .map(|bit| F2_128::from(u64::from(*bit)))
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{prove_lockstep, verify_lockstep, LockstepProof};
    use magnetar_constraint::{Segment, SegmentKind, SegmentOwner, WitnessLayout};
    use magnetar_transcript::sha256;

    #[derive(Clone, Debug)]
    struct TestCommitment([u8; 32]);
    #[derive(Clone, Debug)]
    struct TestOpening(Vec<F2_128>);
    #[derive(Clone, Copy, Debug, Default)]
    struct TestPcs;

    fn root(values: &[F2_128]) -> [u8; 32] {
        let mut bytes = Vec::new();
        for value in values {
            bytes.extend_from_slice(&value.value().to_le_bytes());
        }
        sha256(&bytes)
    }

    impl crate::Pcs for TestPcs {
        type Commitment = TestCommitment;
        type Opening = TestOpening;
        fn commit(&self, values: &[F2_128]) -> Result<Self::Commitment, crate::ProofError> {
            Ok(TestCommitment(root(values)))
        }
        fn open(
            &self,
            values: &[F2_128],
            point: &[F2_128],
        ) -> Result<Self::Opening, crate::ProofError> {
            crate::Mle::new(values.to_vec())?.eval(point)?;
            Ok(TestOpening(values.to_vec()))
        }
        fn verify(
            &self,
            commitment: &Self::Commitment,
            point: &[F2_128],
            value: F2_128,
            opening: &Self::Opening,
        ) -> Result<bool, crate::ProofError> {
            Ok(root(&opening.0) == commitment.0
                && crate::Mle::new(opening.0.clone())?.eval(point)? == value)
        }
        fn commitment_bytes(&self, commitment: &Self::Commitment) -> Vec<u8> {
            commitment.0.to_vec()
        }
    }

    fn relations() -> (BitRelation, BitRelation) {
        let mut and = BitRelation::new(3);
        and.add(BitRow::new(vec![0], vec![1], vec![2]));
        let mut sum = BitRelation::new(3);
        sum.add(BitRow::new(vec![0, 1, 2], vec![2], vec![0, 1, 2]));
        (and, sum)
    }

    #[test]
    fn f2_check_matches_embedded_system() {
        let (and, sum) = relations();
        for value in 0..8u64 {
            let bits = [value & 1 == 1, (value >> 1) & 1 == 1, (value >> 2) & 1 == 1];
            if !and.check(&bits) || !sum.check(&bits) {
                continue;
            }
            assert!(and.to_system().check(&and.to_witness(&bits)).is_ok());
            assert!(sum.to_system().check(&sum.to_witness(&bits)).is_ok());
        }
    }

    #[test]
    fn f2_and_packed_relations_run_lockstep() {
        let (and, sum) = relations();
        let witness = and.to_witness(&[true, true, true]);
        let pcs = TestPcs;
        let layout = WitnessLayout::new(vec![
            Segment::new("a", 0, 2, SegmentKind::Direct, SegmentOwner::Cpu),
            Segment::new("b", 2, 2, SegmentKind::Direct, SegmentOwner::Cpu),
        ])
        .unwrap();
        let proof: LockstepProof<TestCommitment, TestOpening> =
            prove_lockstep(&and.to_system(), &sum.to_system(), &witness, &layout, &pcs).unwrap();
        verify_lockstep(&and.to_system(), &sum.to_system(), &layout, &proof, &pcs).unwrap();
    }
}
