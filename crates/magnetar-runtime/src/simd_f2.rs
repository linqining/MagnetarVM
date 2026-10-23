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
    pub signed: bool,
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
            signed: false,
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
            signed: false,
        }
    }

    pub fn add(width: usize) -> Self {
        Self::add_sub(width, false)
    }

    pub fn sub(width: usize) -> Self {
        Self::add_sub(width, true)
    }

    /// Unsigned less-than: one if `rs1 < rs2`.
    /// Unsigned less-than: one if `rs1 < rs2`.
    pub fn slt(width: usize) -> Self {
        Self::slt_mode(width, false)
    }

    /// Signed two's-complement less-than.
    pub fn slt_signed(width: usize) -> Self {
        Self::slt_mode(width, true)
    }

    fn slt_mode(width: usize, signed: bool) -> Self {
        assert!(width > 0);
        let rs1 = (0..width).collect::<Vec<_>>();
        let rs2 = (width..2 * width).collect::<Vec<_>>();
        let a_cmp = (2 * width..3 * width).collect::<Vec<_>>();
        let b_cmp = (3 * width..4 * width).collect::<Vec<_>>();
        let b_eff = (4 * width..5 * width).collect::<Vec<_>>();
        let rd = (5 * width..6 * width).collect::<Vec<_>>();
        let diff = (6 * width..7 * width).collect::<Vec<_>>();
        let carries = (7 * width..8 * width + 1).collect::<Vec<_>>();
        let p1 = (8 * width + 1..9 * width + 1).collect::<Vec<_>>();
        let p2 = (9 * width + 1..10 * width + 1).collect::<Vec<_>>();
        let p3 = (10 * width + 1..11 * width + 1).collect::<Vec<_>>();
        let xor_ab = (11 * width + 1..12 * width + 1).collect::<Vec<_>>();
        let one = 12 * width + 1;
        let lt = 12 * width + 2;
        let mut relation = BitRelation::new(12 * width + 3);
        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        relation.add(BitRow::new(vec![carries[0]], vec![one], vec![one]));
        for bit in 0..width {
            let sign = signed && bit == width - 1;
            relation.add(BitRow::new(
                if sign {
                    vec![rs1[bit], one]
                } else {
                    vec![rs1[bit]]
                },
                vec![one],
                vec![a_cmp[bit]],
            ));
            relation.add(BitRow::new(
                if sign {
                    vec![rs2[bit], one]
                } else {
                    vec![rs2[bit]]
                },
                vec![one],
                vec![b_cmp[bit]],
            ));
            relation.add(BitRow::new(
                vec![b_cmp[bit], one],
                vec![one],
                vec![b_eff[bit]],
            ));
            relation.add(BitRow::new(
                vec![a_cmp[bit]],
                vec![b_eff[bit]],
                vec![p1[bit]],
            ));
            relation.add(BitRow::new(
                vec![a_cmp[bit]],
                vec![carries[bit]],
                vec![p2[bit]],
            ));
            relation.add(BitRow::new(
                vec![b_eff[bit]],
                vec![carries[bit]],
                vec![p3[bit]],
            ));
            relation.add(BitRow::new(
                vec![a_cmp[bit], b_eff[bit]],
                vec![one],
                vec![xor_ab[bit]],
            ));
            relation.add(BitRow::new(
                vec![xor_ab[bit], carries[bit]],
                vec![one],
                vec![diff[bit]],
            ));
            relation.add(BitRow::new(
                vec![p1[bit], p2[bit], p3[bit]],
                vec![one],
                vec![carries[bit + 1]],
            ));
            if bit == 0 {
                relation.add(BitRow::new(vec![rd[bit]], vec![one], vec![lt]));
            } else {
                relation.add(BitRow::new(vec![rd[bit]], vec![one], Vec::new()));
            }
        }
        relation.add(BitRow::new(vec![carries[width], one], vec![one], vec![lt]));
        Self {
            width,
            rs1,
            rs2,
            rd,
            one,
            relation,
            signed,
        }
    }

    pub fn slt_witness(&self, left: u64, right: u64) -> Vec<bool> {
        self.slt_mode_witness(left, right)
    }

    fn slt_mode_witness(&self, left: u64, right: u64) -> Vec<bool> {
        let width = self.width;
        let mut bits = vec![false; 12 * width + 3];
        bits[self.one] = true;
        let a_cmp = 2 * width;
        let b_cmp = 3 * width;
        let b_eff = 4 * width;
        let diff = 6 * width;
        let carries = 7 * width;
        bits[carries] = true;
        for bit in 0..width {
            let sign = self.signed && bit == width - 1;
            let a = ((left >> bit) & 1 == 1) ^ sign;
            let b = ((right >> bit) & 1 == 1) ^ sign;
            let carry = bits[carries + bit];
            bits[self.rs1[bit]] = (left >> bit) & 1 == 1;
            bits[self.rs2[bit]] = (right >> bit) & 1 == 1;
            bits[a_cmp + bit] = a;
            bits[b_cmp + bit] = b;
            bits[b_eff + bit] = !b;
            bits[carries + bit + 1] = (a && !b) || (a && carry) || (!b && carry);
            bits[8 * width + 1 + bit] = a && !b;
            bits[9 * width + 1 + bit] = a && carry;
            bits[10 * width + 1 + bit] = !b && carry;
            bits[11 * width + 1 + bit] = a ^ !b;
            bits[diff + bit] = a ^ !b ^ carry;
        }
        let less = !bits[carries + width];
        bits[12 * width + 2] = less;
        bits[self.rd[0]] = less;
        bits
    }

    fn add_sub(width: usize, subtract: bool) -> Self {
        assert!(width > 0);
        let rs1 = (0..width).collect::<Vec<_>>();
        let rs2 = (width..2 * width).collect::<Vec<_>>();
        let b_eff = (2 * width..3 * width).collect::<Vec<_>>();
        let rd = (3 * width..4 * width).collect::<Vec<_>>();
        let carries = (4 * width..5 * width + 1).collect::<Vec<_>>();
        let p1 = (5 * width + 1..6 * width + 1).collect::<Vec<_>>();
        let p2 = (6 * width + 1..7 * width + 1).collect::<Vec<_>>();
        let p3 = (7 * width + 1..8 * width + 1).collect::<Vec<_>>();
        let xor_ab = (8 * width + 1..9 * width + 1).collect::<Vec<_>>();
        let one = 9 * width + 1;
        let mut relation = BitRelation::new(9 * width + 2);
        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        relation.add(BitRow::new(
            vec![carries[0]],
            vec![one],
            if subtract { vec![one] } else { Vec::new() },
        ));
        for bit in 0..width {
            relation.add(BitRow::new(
                if subtract {
                    vec![rs2[bit], one]
                } else {
                    vec![rs2[bit]]
                },
                vec![one],
                vec![b_eff[bit]],
            ));
            relation.add(BitRow::new(vec![rs1[bit]], vec![b_eff[bit]], vec![p1[bit]]));
            relation.add(BitRow::new(
                vec![rs1[bit]],
                vec![carries[bit]],
                vec![p2[bit]],
            ));
            relation.add(BitRow::new(
                vec![b_eff[bit]],
                vec![carries[bit]],
                vec![p3[bit]],
            ));
            relation.add(BitRow::new(
                vec![rs1[bit], b_eff[bit]],
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
            signed: false,
        }
    }

    pub fn add_witness(&self, left: u64, right: u64) -> Vec<bool> {
        self.add_sub_witness(left, right, false)
    }

    pub fn sub_witness(&self, left: u64, right: u64) -> Vec<bool> {
        self.add_sub_witness(left, right, true)
    }

    fn add_sub_witness(&self, left: u64, right: u64, subtract: bool) -> Vec<bool> {
        let width = self.width;
        let mut bits = vec![false; 9 * width + 2];
        bits[self.one] = true;
        let carries = 4 * width;
        bits[carries] = subtract;
        for bit in 0..width {
            let a = (left >> bit) & 1 == 1;
            let b = (right >> bit) & 1 == 1;
            let b_eff = b ^ subtract;
            let carry = bits[carries + bit];
            bits[self.rs1[bit]] = a;
            bits[self.rs2[bit]] = b;
            bits[2 * width + bit] = b_eff;
            bits[carries + bit + 1] = (a && b_eff) || (a && carry) || (b_eff && carry);
            bits[5 * width + 1 + bit] = a && b_eff;
            bits[6 * width + 1 + bit] = a && carry;
            bits[7 * width + 1 + bit] = b_eff && carry;
            bits[8 * width + 1 + bit] = a ^ b_eff;
            bits[self.rd[bit]] = a ^ b_eff ^ carry;
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
    #[test]
    fn bit_subtract_relation_uses_twos_complement_carry() {
        let sub = UniformBitAluRelation::sub(8);
        let bits = sub.sub_witness(5, 3);
        assert!(sub.relation.check(&bits));
        let rd = sub.rd.iter().enumerate().fold(0u64, |value, (bit, var)| {
            value | (u64::from(bits[*var]) << bit)
        });
        assert_eq!(rd, 2);

        let wrapped = sub.sub_witness(3, 5);
        assert!(sub.relation.check(&wrapped));
        let rd = sub.rd.iter().enumerate().fold(0u64, |value, (bit, var)| {
            value | (u64::from(wrapped[*var]) << bit)
        });
        assert_eq!(rd, 254);
    }
    #[test]
    fn bit_slt_relation_uses_borrow_out() {
        let slt = UniformBitAluRelation::slt(8);
        for (left, right, expected) in [(3u64, 5u64, 1u64), (5, 3, 0), (5, 5, 0), (255, 1, 0)] {
            let bits = slt.slt_witness(left, right);
            assert!(slt.relation.check(&bits), "{left} < {right}");
            assert_eq!(u64::from(bits[slt.rd[0]]), expected, "{left} < {right}");
            for bit in 1..8 {
                assert!(!bits[slt.rd[bit]]);
            }
        }
    }
    #[test]
    fn signed_slt_flips_the_sign_bit() {
        let slt = UniformBitAluRelation::slt_signed(8);
        for (left, right, expected) in [
            (3u64, 5u64, 1u64),
            (5, 3, 0),
            (255, 1, 1),   // -1 < 1
            (1, 255, 0),   // 1 < -1 is false
            (251, 253, 1), // -5 < -3
            (127, 128, 0), // 127 < -128 is false
            (128, 127, 1), // -128 < 127
        ] {
            let bits = slt.slt_witness(left, right);
            assert!(slt.relation.check(&bits), "{left} < {right}");
            assert_eq!(u64::from(bits[slt.rd[0]]), expected, "{left} < {right}");
        }
    }
}
