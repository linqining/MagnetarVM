//! Native F2 bit-row slice for the SIMD CPU schema.
//!
//! This is the s1 side in isolation: a sparse bit R1CS over F2 with XOR/AND
//! gates, independent of the packed F2^128 relation. It currently has a
//! reference embedding for proof (`BitRelation::to_system`) but no native F2
//! PCS/sum-check; choosing that proof backend is the next architecture
//! decision.

use magnetar_constraint::VarId;
use magnetar_proof::dual_field::{BitRelation, BitRow};
use magnetar_proof::{prove_spartan, verify_spartan, Pcs, SpartanError, SpartanProof};

/// Proof backend for the F2 bit relation. The semantic relation is native F2;
/// today's implementation embeds it into the packed F2_128 system, and a
/// native F2 backend can be swapped in later without changing the CPU schema.
pub trait BitProofBackend {
    type Proof;
    type Error;

    fn prove(&self, relation: &BitRelation, bits: &[bool]) -> Result<Self::Proof, Self::Error>;

    fn verify(&self, relation: &BitRelation, proof: &Self::Proof) -> Result<bool, Self::Error>;
}

#[derive(Clone, Copy, Debug)]
pub struct EmbeddedBitBackend<P: Pcs> {
    pub pcs: P,
}

impl<P: Pcs> BitProofBackend for EmbeddedBitBackend<P> {
    type Proof = SpartanProof<P::Commitment, P::Opening>;
    type Error = SpartanError;

    fn prove(&self, relation: &BitRelation, bits: &[bool]) -> Result<Self::Proof, Self::Error> {
        let system = relation.to_system();
        let witness = relation.to_witness(bits);
        prove_spartan(&system, &witness, &self.pcs)
    }

    fn verify(&self, relation: &BitRelation, proof: &Self::Proof) -> Result<bool, Self::Error> {
        verify_spartan(&relation.to_system(), proof, &self.pcs)?;
        Ok(true)
    }
}

#[derive(Clone, Debug)]
pub struct UniformBitAluRelation {
    pub width: usize,
    pub rs1: Vec<VarId>,
    pub rs2: Vec<VarId>,
    pub rd: Vec<VarId>,
    pub one: VarId,
    pub relation: BitRelation,
}

impl UniformBitAluRelation {
    pub fn xor(width: usize) -> Self {
        assert!(width > 0);
        let mut relation = BitRelation::new(3 * width + 1);
        let rs1 = (0..width).collect::<Vec<_>>();
        let rs2 = (width..2 * width).collect::<Vec<_>>();
        let rd = (2 * width..3 * width).collect::<Vec<_>>();
        let one = 3 * width;
        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        for bit in 0..width {
            relation.add(BitRow::new(
                vec![rs1[bit], rs2[bit]],
                vec![one],
                vec![rd[bit]],
            ));
        }
        Self {
            width,
            rs1,
            rs2,
            rd,
            one,
            relation,
        }
    }

    pub fn and(width: usize) -> Self {
        assert!(width > 0);
        let mut relation = BitRelation::new(3 * width + 1);
        let rs1 = (0..width).collect::<Vec<_>>();
        let rs2 = (width..2 * width).collect::<Vec<_>>();
        let rd = (2 * width..3 * width).collect::<Vec<_>>();
        let one = 3 * width;
        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        for bit in 0..width {
            relation.add(BitRow::new(vec![rs1[bit]], vec![rs2[bit]], vec![rd[bit]]));
        }
        Self {
            width,
            rs1,
            rs2,
            rd,
            one,
            relation,
        }
    }

    pub fn add(width: usize) -> Self {
        assert!(width > 0);
        let rs1 = (0..width).collect::<Vec<_>>();
        let rs2 = (width..2 * width).collect::<Vec<_>>();
        let rd = (2 * width..3 * width).collect::<Vec<_>>();
        let carries = (3 * width..4 * width + 1).collect::<Vec<_>>();
        let p1 = (4 * width + 1..5 * width + 1).collect::<Vec<_>>();
        let p2 = (5 * width + 1..6 * width + 1).collect::<Vec<_>>();
        let p3 = (6 * width + 1..7 * width + 1).collect::<Vec<_>>();
        let xor_ab = (7 * width + 1..8 * width + 1).collect::<Vec<_>>();
        let one = 8 * width + 1;
        let mut relation = BitRelation::new(8 * width + 2);
        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        relation.add(BitRow::new(vec![carries[0]], vec![one], Vec::new()));
        for bit in 0..width {
            relation.add(BitRow::new(vec![rs1[bit]], vec![rs2[bit]], vec![p1[bit]]));
            relation.add(BitRow::new(
                vec![rs1[bit]],
                vec![carries[bit]],
                vec![p2[bit]],
            ));
            relation.add(BitRow::new(
                vec![rs2[bit]],
                vec![carries[bit]],
                vec![p3[bit]],
            ));
            relation.add(BitRow::new(
                vec![rs1[bit], rs2[bit]],
                vec![one],
                vec![xor_ab[bit]],
            ));
            relation.add(BitRow::new(
                vec![xor_ab[bit], carries[bit]],
                vec![one],
                vec![rd[bit]],
            ));
            relation.add(BitRow::new(
                vec![p1[bit], p2[bit], p3[bit]],
                vec![one],
                vec![carries[bit + 1]],
            ));
        }
        Self {
            width,
            rs1,
            rs2,
            rd,
            one,
            relation,
        }
    }

    pub fn add_witness(&self, left: u64, right: u64) -> Vec<bool> {
        let width = self.width;
        let mut bits = vec![false; 8 * width + 2];
        bits[self.one] = true;
        let carries = 3 * width;
        for bit in 0..width {
            let a = (left >> bit) & 1 == 1;
            let b = (right >> bit) & 1 == 1;
            let carry = bits[carries + bit];
            bits[self.rs1[bit]] = a;
            bits[self.rs2[bit]] = b;
            bits[carries + bit + 1] = (a && b) || (a && carry) || (b && carry);
            bits[4 * width + 1 + bit] = a && b;
            bits[5 * width + 1 + bit] = a && carry;
            bits[6 * width + 1 + bit] = b && carry;
            bits[7 * width + 1 + bit] = a ^ b;
            bits[self.rd[bit]] = a ^ b ^ carry;
        }
        bits
    }

    pub fn witness(&self, rs1: u64, rs2: u64, xor: bool) -> Vec<bool> {
        let mut bits = vec![false; 8 * self.width + 2];
        bits[self.one] = true;
        for bit in 0..self.width {
            let a = (rs1 >> bit) & 1 == 1;
            let b = (rs2 >> bit) & 1 == 1;
            bits[self.rs1[bit]] = a;
            bits[self.rs2[bit]] = b;
            bits[self.rd[bit]] = if xor { a ^ b } else { a & b };
        }
        bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_and_relations_check_over_f2() {
        let xor = UniformBitAluRelation::xor(8);
        assert!(xor
            .relation
            .check(&xor.witness(0b1010_1010, 0b1100_1100, true)));
        assert!(!xor
            .relation
            .check(&xor.witness(0b1010_1010, 0b1100_1100, false)));

        let and = UniformBitAluRelation::and(8);
        assert!(and
            .relation
            .check(&and.witness(0b1010_1010, 0b1100_1100, false)));
        assert!(!and
            .relation
            .check(&and.witness(0b1010_1010, 0b1100_1100, true)));
    }

    #[test]
    fn xor_relation_embeds_into_the_packed_system() {
        let xor = UniformBitAluRelation::xor(8);
        let bits = xor.witness(0b1010_1010, 0b1100_1100, true);
        let system = xor.relation.to_system();
        let witness = xor.relation.to_witness(&bits);
        system.check(&witness).expect("embedded F2 relation");
    }
    #[test]
    fn embedded_bit_backend_round_trips() {
        use magnetar_pcs::P3BinaryPcs;

        let relation = UniformBitAluRelation::xor(8);
        let bits = relation.witness(0b1010_1010, 0b1100_1100, true);
        let backend = EmbeddedBitBackend {
            pcs: P3BinaryPcs::new(100),
        };
        let proof = backend.prove(&relation.relation, &bits).unwrap();
        assert!(backend.verify(&relation.relation, &proof).unwrap());
    }
    #[test]
    fn bit_adder_relation_checks_carry_chain() {
        let add = UniformBitAluRelation::add(8);
        let bits = add.add_witness(5, 3);
        assert!(add.relation.check(&bits));
        let rd = add.rd.iter().enumerate().fold(0u64, |value, (bit, var)| {
            value | (u64::from(bits[*var]) << bit)
        });
        assert_eq!(rd, 8);

        let mut broken = bits;
        broken[add.rd[0]] = !broken[add.rd[0]];
        assert!(!add.relation.check(&broken));
    }
    #[test]
    fn embedded_backend_proves_bit_addition() {
        use magnetar_pcs::P3BinaryPcs;

        let add = UniformBitAluRelation::add(8);
        let bits = add.add_witness(5, 3);
        let backend = EmbeddedBitBackend {
            pcs: P3BinaryPcs::new(100),
        };
        let proof = backend.prove(&add.relation, &bits).unwrap();
        assert!(backend.verify(&add.relation, &proof).unwrap());
    }
}
