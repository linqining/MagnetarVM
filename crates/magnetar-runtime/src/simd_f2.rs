//! Native F2 bit-row slice for the SIMD CPU schema.
//!
//! This is the s1 side in isolation: a sparse bit R1CS over F2 with XOR/AND
//! gates, independent of the packed F2^128 relation. It currently has a
//! reference embedding for proof (`BitRelation::to_system`) but no native F2
//! PCS/sum-check; choosing that proof backend is the next architecture
//! decision.

use crate::RuntimeError;
use magnetar_constraint::{VarId, F2_128};
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitShiftKind {
    Sll,
    Srl,
    Sra,
}

/// Native F2 barrel shifter (SLL/SRL/SRA) over a bit relation.
#[derive(Clone, Debug)]
pub struct UniformBitShiftRelation {
    pub width: usize,
    pub stages: usize,
    pub rs1: Vec<VarId>,
    pub shamt: Vec<VarId>,
    pub rd: Vec<VarId>,
    pub kind: BitShiftKind,
    pub relation: BitRelation,
}

impl UniformBitShiftRelation {
    #[allow(clippy::needless_range_loop)]
    pub fn shift(width: usize, kind: BitShiftKind) -> Self {
        assert!(width.is_power_of_two() && width >= 2);
        let stages = width.trailing_zeros() as usize;
        let rs1 = (0..width).collect::<Vec<_>>();
        let shamt = (width..width + stages).collect::<Vec<_>>();
        let rd = (width + stages..2 * width + stages).collect::<Vec<_>>();
        let zero = 2 * width + stages;
        let one = zero + 1;
        let mut next = one + 1;
        let mut relation = BitRelation::new(0);
        let mut current = rs1.clone();
        let mut rows = Vec::new();
        rows.push(BitRow::new(vec![zero], vec![], vec![]));
        rows.push(BitRow::new(vec![one], vec![one], vec![one]));
        for stage in 0..stages {
            let shift = 1usize << stage;
            let mut diffs = Vec::with_capacity(width);
            let mut prods = Vec::with_capacity(width);
            let mut outs = Vec::with_capacity(width);
            for bit in 0..width {
                let source = match kind {
                    BitShiftKind::Sll => {
                        if bit >= shift {
                            current[bit - shift]
                        } else {
                            zero
                        }
                    }
                    BitShiftKind::Srl => {
                        if bit + shift < width {
                            current[bit + shift]
                        } else {
                            zero
                        }
                    }
                    BitShiftKind::Sra => {
                        if bit + shift < width {
                            current[bit + shift]
                        } else {
                            rs1[width - 1]
                        }
                    }
                };
                let diff = next;
                let prod = next + 1;
                let out = next + 2;
                next += 3;
                diffs.push(diff);
                prods.push(prod);
                outs.push(out);
                rows.push(BitRow::new(
                    vec![current[bit], source],
                    vec![one],
                    vec![diff],
                ));
                rows.push(BitRow::new(vec![diff], vec![shamt[stage]], vec![prod]));
                rows.push(BitRow::new(vec![current[bit], prod], vec![one], vec![out]));
            }
            current = outs;
        }
        for bit in 0..width {
            rows.push(BitRow::new(vec![rd[bit]], vec![one], vec![current[bit]]));
        }
        relation.num_vars = next;
        for row in rows {
            relation.add(row);
        }
        Self {
            width,
            stages,
            rs1,
            shamt,
            rd,
            kind,
            relation,
        }
    }

    pub fn witness(&self, left: u64, shamt: u64) -> Vec<bool> {
        let width = self.width;
        let mut bits = vec![false; self.relation.num_vars];
        let zero = 2 * width + self.stages;
        let one = zero + 1;
        bits[one] = true;
        for bit in 0..width {
            bits[self.rs1[bit]] = (left >> bit) & 1 == 1;
        }
        let mask = (1u64 << self.stages) - 1;
        let shift_amount = shamt & mask;
        for bit in 0..self.stages {
            bits[self.shamt[bit]] = (shift_amount >> bit) & 1 == 1;
        }
        let mut current = self.rs1.clone();
        let mut next = one + 1;
        for stage in 0..self.stages {
            let shift = 1u64 << stage;
            let active = (shift_amount >> stage) & 1 == 1;
            let mut outs = Vec::with_capacity(width);
            for bit in 0..width {
                let source = match self.kind {
                    BitShiftKind::Sll => {
                        if (bit as u64) >= shift {
                            bits[current[(bit as u64 - shift) as usize]]
                        } else {
                            false
                        }
                    }
                    BitShiftKind::Srl => {
                        if (bit as u64) + shift < width as u64 {
                            bits[current[(bit as u64 + shift) as usize]]
                        } else {
                            false
                        }
                    }
                    BitShiftKind::Sra => {
                        if (bit as u64) + shift < width as u64 {
                            bits[current[(bit as u64 + shift) as usize]]
                        } else {
                            bits[self.rs1[width - 1]]
                        }
                    }
                };
                let a = bits[current[bit]];
                let diff = a ^ source;
                let prod = active && diff;
                let out = a ^ prod;
                bits[next] = diff;
                bits[next + 1] = prod;
                bits[next + 2] = out;
                next += 3;
                outs.push(next - 1);
            }
            current = outs;
        }
        for bit in 0..width {
            bits[self.rd[bit]] = bits[current[bit]];
        }
        bits
    }
}

#[cfg(test)]
mod shift_tests {
    use super::*;

    #[test]
    fn barrel_shifts_match_rv64_semantics() {
        for (kind, left, shamt, expected) in [
            (BitShiftKind::Sll, 5u64, 2u64, 20u64),
            (BitShiftKind::Srl, 20, 2, 5),
            (BitShiftKind::Sra, 248, 1, 252),
            (BitShiftKind::Sll, 7, 0, 7),
        ] {
            let shift = UniformBitShiftRelation::shift(8, kind);
            let bits = shift.witness(left, shamt);
            assert!(shift.relation.check(&bits), "{kind:?} {left} {shamt}");
            let rd = shift.rd.iter().enumerate().fold(0u64, |value, (bit, var)| {
                value | (u64::from(bits[*var]) << bit)
            });
            assert_eq!(rd, expected, "{kind:?} {left} {shamt}");
        }
    }
}

/// Gated bit operation: when `gate = 0`, the output is forced to zero; when
/// `gate = 1`, it computes the requested bit op. This is the selector-gating
/// primitive for the F2 schema.
#[derive(Clone, Debug)]
pub struct GatedBitOp {
    pub width: usize,
    pub a: Vec<VarId>,
    pub b: Vec<VarId>,
    pub out: Vec<VarId>,
    pub gate: VarId,
    pub relation: BitRelation,
}

impl GatedBitOp {
    pub fn xor(width: usize) -> Self {
        let (mut relation, a, b, out, gate, one, inner) = Self::layout(width, 2 * width + 1);
        for bit in 0..width {
            relation.add(BitRow::new(
                vec![a[bit], b[bit]],
                vec![one],
                vec![inner[bit]],
            ));
            relation.add(BitRow::new(vec![inner[bit]], vec![gate], vec![out[bit]]));
        }
        Self {
            width,
            a,
            b,
            out,
            gate,
            relation,
        }
    }

    pub fn and(width: usize) -> Self {
        let (mut relation, a, b, out, gate, _one, inner) = Self::layout(width, width);
        for bit in 0..width {
            relation.add(BitRow::new(vec![a[bit]], vec![b[bit]], vec![inner[bit]]));
            relation.add(BitRow::new(vec![inner[bit]], vec![gate], vec![out[bit]]));
        }
        Self {
            width,
            a,
            b,
            out,
            gate,
            relation,
        }
    }

    #[allow(clippy::type_complexity)]
    fn layout(
        width: usize,
        inner_len: usize,
    ) -> (
        BitRelation,
        Vec<VarId>,
        Vec<VarId>,
        Vec<VarId>,
        VarId,
        VarId,
        Vec<VarId>,
    ) {
        let a = (0..width).collect::<Vec<_>>();
        let b = (width..2 * width).collect::<Vec<_>>();
        let out = (2 * width..3 * width).collect::<Vec<_>>();
        let gate = 3 * width;
        let one = 3 * width + 1;
        let inner = (3 * width + 2..3 * width + 2 + inner_len).collect::<Vec<_>>();
        let num_vars = 3 * width + 2 + inner_len;
        let mut relation = BitRelation::new(num_vars);
        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        relation.add(BitRow::new(vec![gate], vec![one], vec![gate]));
        (relation, a, b, out, gate, one, inner)
    }

    pub fn witness(&self, a: u64, b: u64, gate: bool, and: bool) -> Vec<bool> {
        let mut bits = vec![false; self.relation.num_vars];
        bits[3 * self.width + 1] = true;
        bits[self.gate] = gate;
        let inner = 3 * self.width + 2;
        for bit in 0..self.width {
            let left = (a >> bit) & 1 == 1;
            let right = (b >> bit) & 1 == 1;
            bits[self.a[bit]] = left;
            bits[self.b[bit]] = right;
            let value = if and { left & right } else { left ^ right };
            bits[inner + bit] = value;
            bits[self.out[bit]] = gate && value;
        }
        bits
    }
}

#[cfg(test)]
mod gated_tests {
    use super::*;

    #[test]
    fn gated_xor_is_zero_when_disabled() {
        let op = GatedBitOp::xor(8);
        let enabled = op.witness(0b1010_1010, 0b1100_1100, true, false);
        assert!(op.relation.check(&enabled));
        let disabled = op.witness(0b1010_1010, 0b1100_1100, false, false);
        assert!(op.relation.check(&disabled));
        for (bit, var) in op.out.iter().enumerate() {
            assert_eq!(u64::from(disabled[*var]), 0, "bit {bit}");
        }
    }

    #[test]
    fn gated_and_is_zero_when_disabled() {
        let op = GatedBitOp::and(8);
        let enabled = op.witness(0b1010_1010, 0b1100_1100, true, true);
        assert!(op.relation.check(&enabled));
        let disabled = op.witness(0b1010_1010, 0b1100_1100, false, true);
        assert!(op.relation.check(&disabled));
        for (bit, var) in op.out.iter().enumerate() {
            assert_eq!(u64::from(disabled[*var]), 0, "bit {bit}");
        }
    }
}

/// Gated ripple-carry adder over F2. `gate = 0` forces the result and the
/// carry chain to zero; `gate = 1` computes `a + b`.
#[derive(Clone, Debug)]
pub struct GatedBitAdder {
    pub width: usize,
    pub a: Vec<VarId>,
    pub b: Vec<VarId>,
    pub out: Vec<VarId>,
    pub gate: VarId,
    pub relation: BitRelation,
}

impl GatedBitAdder {
    pub fn new(width: usize) -> Self {
        let a = (0..width).collect::<Vec<_>>();
        let b = (width..2 * width).collect::<Vec<_>>();
        let out = (2 * width..3 * width).collect::<Vec<_>>();
        let gate = 3 * width;
        let one = 3 * width + 1;
        let carries = (3 * width + 2..4 * width + 3).collect::<Vec<_>>();
        let p1 = (4 * width + 3..5 * width + 3).collect::<Vec<_>>();
        let p2 = (5 * width + 3..6 * width + 3).collect::<Vec<_>>();
        let p3 = (6 * width + 3..7 * width + 3).collect::<Vec<_>>();
        let diff = (7 * width + 3..8 * width + 3).collect::<Vec<_>>();
        let xor_carry = (8 * width + 3..9 * width + 3).collect::<Vec<_>>();
        let mut relation = BitRelation::new(9 * width + 3);
        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        relation.add(BitRow::new(vec![gate], vec![one], vec![gate]));
        relation.add(BitRow::new(vec![carries[0]], vec![one], Vec::new()));
        for bit in 0..width {
            relation.add(BitRow::new(
                vec![a[bit], b[bit]],
                vec![one],
                vec![diff[bit]],
            ));
            relation.add(BitRow::new(
                vec![diff[bit], carries[bit]],
                vec![one],
                vec![xor_carry[bit]],
            ));
            relation.add(BitRow::new(
                vec![xor_carry[bit]],
                vec![gate],
                vec![out[bit]],
            ));
            relation.add(BitRow::new(vec![a[bit]], vec![b[bit]], vec![p1[bit]]));
            relation.add(BitRow::new(vec![a[bit]], vec![carries[bit]], vec![p2[bit]]));
            relation.add(BitRow::new(vec![b[bit]], vec![carries[bit]], vec![p3[bit]]));
            relation.add(BitRow::new(
                vec![p1[bit], p2[bit], p3[bit]],
                vec![one],
                vec![carries[bit + 1]],
            ));
        }
        Self {
            width,
            a,
            b,
            out,
            gate,
            relation,
        }
    }

    pub fn witness(&self, left: u64, right: u64, gate: bool) -> Vec<bool> {
        let mut bits = vec![false; self.relation.num_vars];
        bits[3 * self.width + 1] = true;
        bits[self.gate] = gate;
        let carries = 3 * self.width + 2;
        for bit in 0..self.width {
            let a = (left >> bit) & 1 == 1;
            let b = (right >> bit) & 1 == 1;
            let carry = bits[carries + bit];
            bits[self.a[bit]] = a;
            bits[self.b[bit]] = b;
            bits[carries + bit + 1] = (a && b) || (a && carry) || (b && carry);
            bits[self.out[bit]] = gate && (a ^ b ^ carry);
            bits[4 * self.width + 3 + bit] = a && b;
            bits[5 * self.width + 3 + bit] = a && carry;
            bits[6 * self.width + 3 + bit] = b && carry;
            bits[7 * self.width + 3 + bit] = a ^ b;
            bits[8 * self.width + 3 + bit] = a ^ b ^ carry;
        }
        bits
    }
}

#[cfg(test)]
mod gated_adder_tests {
    use super::*;

    #[test]
    fn gated_adder_zeroes_the_result_when_disabled() {
        let adder = GatedBitAdder::new(8);
        let enabled = adder.witness(5, 3, true);
        assert!(adder.relation.check(&enabled));
        let rd = adder
            .out
            .iter()
            .enumerate()
            .fold(0u64, |value, (bit, var)| {
                value | (u64::from(enabled[*var]) << bit)
            });
        assert_eq!(rd, 8);

        let disabled = adder.witness(5, 3, false);
        assert!(adder.relation.check(&disabled));
        for (bit, var) in adder.out.iter().enumerate() {
            assert_eq!(u64::from(disabled[*var]), 0, "bit {bit}");
        }
    }
}

/// Packed s2 companion for the XOR bit relation: one linear parity check over
/// the same F2 witness, followed by zero rows to match the bit relation's row
/// count for lockstep.
fn packed_xor_parity_system(
    relation: &UniformBitAluRelation,
    rows: usize,
) -> magnetar_constraint::ConstraintSystem {
    use magnetar_constraint::{ConstraintSystem, Expr};
    let mut system = ConstraintSystem::new(relation.relation.num_vars);
    let sum = |bits: &[VarId]| {
        bits.iter()
            .fold(Expr::constant(0u64), |expr, var| expr.add(Expr::var(*var)))
    };
    let mut left = relation.rs1.clone();
    left.extend_from_slice(&relation.rs2);
    system.add_constraint(sum(&left), Expr::constant(1u64), sum(&relation.rd));
    for _ in 1..rows {
        system.add_constraint(
            Expr::constant(0u64),
            Expr::constant(1u64),
            Expr::constant(0u64),
        );
    }
    system
}

/// Prove the F2 XOR bit relation and a packed parity relation in lockstep over
/// the same witness.
pub fn prove_xor_dual_relation(
    width: usize,
    left: u64,
    right: u64,
) -> Result<
    (
        magnetar_proof::LockstepProof<
            magnetar_pcs::P3MosaicCommitment,
            magnetar_pcs::P3MosaicOpening,
        >,
        magnetar_constraint::WitnessLayout,
    ),
    RuntimeError,
> {
    use magnetar_constraint::{Segment, SegmentKind, SegmentOwner, WitnessLayout};
    use magnetar_pcs::P3SharedPcs;
    use magnetar_proof::{prove_lockstep, witness_vector};

    let relation = UniformBitAluRelation::xor(width);
    let bits = relation.witness(left, right, true);
    let witness = relation.relation.to_witness(&bits);
    let s1 = relation.relation.to_system();
    let rows = s1.constraints.len();
    let s2 = packed_xor_parity_system(&relation, rows);
    let z =
        witness_vector(&s1, &witness).map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let total_bits = z.len().trailing_zeros() as usize;
    let half = total_bits - 1;
    let layout = WitnessLayout::new(vec![
        Segment::new("lo", 0, 1 << half, SegmentKind::Direct, SegmentOwner::Cpu),
        Segment::new(
            "hi",
            1 << half,
            1 << half,
            SegmentKind::Direct,
            SegmentOwner::Cpu,
        ),
    ])
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    let proof = prove_lockstep(&s1, &s2, &witness, &layout, &pcs)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((proof, layout))
}

#[cfg(test)]
mod lockstep_tests {
    use super::*;
    use magnetar_pcs::P3SharedPcs;
    use magnetar_proof::{verify_lockstep, witness_vector};

    #[test]
    fn f2_bit_xor_and_packed_parity_run_in_lockstep() {
        let (_proof, layout) = prove_xor_dual_relation(8, 0b1010_1010, 0b1100_1100).unwrap();
        let relation = UniformBitAluRelation::xor(8);
        let bits = relation.witness(0b1010_1010, 0b1100_1100, true);
        let witness = relation.relation.to_witness(&bits);
        let s1 = relation.relation.to_system();
        let s2 = packed_xor_parity_system(&relation, s1.constraints.len());
        let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
        let _ = witness_vector(&s1, &witness).unwrap();
        verify_lockstep(&s1, &s2, &layout, &_proof, &pcs).unwrap();
    }
}

/// Selector-gated F2 memory row: address adder and data output are both gated
/// by `is_mem`. This is the first B-scheme gadget that composes gated ALU
/// primitives into a row-level relation.
#[derive(Clone, Debug)]
pub struct GatedMemoryRow {
    pub width: usize,
    pub adder: GatedBitAdder,
    pub data_in: Vec<VarId>,
    pub data: Vec<VarId>,
    pub relation: BitRelation,
}

impl GatedMemoryRow {
    pub fn packed_system(&self) -> magnetar_constraint::ConstraintSystem {
        self.relation.to_system()
    }

    pub fn new(width: usize) -> Self {
        let adder = GatedBitAdder::new(width);
        let mut relation = adder.relation.clone();
        let data_in = (relation.num_vars..relation.num_vars + width).collect::<Vec<_>>();
        let data = (relation.num_vars + width..relation.num_vars + 2 * width).collect::<Vec<_>>();
        relation.num_vars += 2 * width;
        for bit in 0..width {
            relation.add(BitRow::new(
                vec![data_in[bit]],
                vec![adder.gate],
                vec![data[bit]],
            ));
        }
        Self {
            width,
            adder,
            data_in,
            data,
            relation,
        }
    }

    pub fn witness(&self, rs1: u64, imm: u64, value: u64, is_mem: bool) -> Vec<bool> {
        let mut bits = self.adder.witness(rs1, imm, is_mem);
        bits.resize(self.relation.num_vars, false);
        for bit in 0..self.width {
            let value_bit = (value >> bit) & 1 == 1;
            bits[self.data_in[bit]] = value_bit;
            bits[self.data[bit]] = is_mem && value_bit;
        }
        bits
    }
}

pub fn prove_gated_memory_batch(
    width: usize,
    rows: &[(u64, u64, u64, bool)],
) -> Result<
    magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
    RuntimeError,
> {
    use magnetar_proof::{prove_shared_simd_spartan, witness_vector};
    if rows.is_empty() || !rows.len().is_power_of_two() {
        return Err(RuntimeError::Proof(
            "gated memory batch must be a nonzero power of two".into(),
        ));
    }
    let row = GatedMemoryRow::new(width);
    let system = row.packed_system();
    let mut witnesses = Vec::new();
    for (rs1, imm, value, is_mem) in rows {
        let bits = row.witness(*rs1, *imm, *value, *is_mem);
        witnesses.push(row.relation.to_witness(&bits));
    }
    let _ = witness_vector(&system, &witnesses[0])
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let pcs = magnetar_pcs::P3BinaryPcs::new(100);
    prove_shared_simd_spartan(&system, &witnesses, &pcs)
        .map_err(|error| RuntimeError::Proof(error.to_string()))
}

pub fn verify_gated_memory_batch(
    width: usize,
    instances: usize,
    proof: &magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
) -> Result<(), RuntimeError> {
    use magnetar_proof::verify_shared_simd_spartan;
    let row = GatedMemoryRow::new(width);
    let system = row.packed_system();
    let pcs = magnetar_pcs::P3BinaryPcs::new(100);
    verify_shared_simd_spartan(&system, instances, proof, &pcs)
        .map_err(|error| RuntimeError::Proof(error.to_string()))
}

#[cfg(test)]
mod gated_memory_tests {
    use super::*;

    #[test]
    fn gated_memory_zeroes_address_and_data_when_inactive() {
        let row = GatedMemoryRow::new(8);
        let active = row.witness(0x10, 0x02, 0x34, true);
        assert!(row.relation.check(&active));
        let inactive = row.witness(0x10, 0x02, 0x34, false);
        assert!(row.relation.check(&inactive));
        for bit in 0..8 {
            assert!(!inactive[row.adder.out[bit]], "addr bit {bit}");
            assert!(!inactive[row.data[bit]], "data bit {bit}");
        }

        use magnetar_pcs::P3BinaryPcs;
        let backend = EmbeddedBitBackend {
            pcs: P3BinaryPcs::new(100),
        };
        let proof = backend.prove(&row.relation, &active).unwrap();
        assert!(backend.verify(&row.relation, &proof).unwrap());

        let batch =
            prove_gated_memory_batch(8, &[(0x10, 2, 0x34, true), (0x20, 4, 0x56, false)]).unwrap();
        verify_gated_memory_batch(8, 2, &batch).unwrap();
    }
}

/// Selector-gated F2 ALU operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatedAluOp {
    Xor,
    And,
    Add,
    Inactive,
}

/// Selector-gated F2 ALU row (XOR/AND/ADD). The row is inactive when all op
/// selectors are zero; output is zero in that case.
#[derive(Clone, Debug)]
pub struct GatedAluRow {
    pub width: usize,
    pub a: Vec<VarId>,
    pub b: Vec<VarId>,
    pub out: Vec<VarId>,
    pub is_alu: VarId,
    pub is_xor: VarId,
    pub is_and: VarId,
    pub is_add: VarId,
    pub one: VarId,
    pub xor_prod: Vec<VarId>,
    pub and_gated: Vec<VarId>,
    pub add_gated: Vec<VarId>,
    pub relation: BitRelation,
}

impl GatedAluRow {
    pub fn new(width: usize) -> Self {
        let a = (0..width).collect::<Vec<_>>();
        let b = (width..2 * width).collect::<Vec<_>>();
        let out = (2 * width..3 * width).collect::<Vec<_>>();
        let is_alu = 3 * width;
        let is_xor = 3 * width + 1;
        let is_and = 3 * width + 2;
        let is_add = 3 * width + 3;
        let one = 3 * width + 4;
        let xor_diff = (3 * width + 5..4 * width + 5).collect::<Vec<_>>();
        let xor_prod = (4 * width + 5..5 * width + 5).collect::<Vec<_>>();
        let and_prod = (5 * width + 5..6 * width + 5).collect::<Vec<_>>();
        let and_gated = (6 * width + 5..7 * width + 5).collect::<Vec<_>>();
        let carries = (7 * width + 5..8 * width + 6).collect::<Vec<_>>();
        let p1 = (8 * width + 6..9 * width + 6).collect::<Vec<_>>();
        let p2 = (9 * width + 6..10 * width + 6).collect::<Vec<_>>();
        let p3 = (10 * width + 6..11 * width + 6).collect::<Vec<_>>();
        let add_diff = (11 * width + 6..12 * width + 6).collect::<Vec<_>>();
        let add_xor = (12 * width + 6..13 * width + 6).collect::<Vec<_>>();
        let add_gated = (13 * width + 6..14 * width + 6).collect::<Vec<_>>();
        let mut relation = BitRelation::new(14 * width + 7);
        relation.add(BitRow::new(vec![one], vec![one], vec![one]));
        for selector in [is_alu, is_xor, is_and, is_add] {
            relation.add(BitRow::new(vec![selector], vec![selector, one], Vec::new()));
        }
        relation.add(BitRow::new(
            vec![is_xor, is_and, is_add],
            vec![one],
            vec![is_alu],
        ));
        relation.add(BitRow::new(vec![carries[0]], vec![one], Vec::new()));
        for bit in 0..width {
            relation.add(BitRow::new(
                vec![a[bit], b[bit]],
                vec![one],
                vec![xor_diff[bit]],
            ));
            relation.add(BitRow::new(
                vec![xor_diff[bit]],
                vec![is_xor],
                vec![xor_prod[bit]],
            ));
            relation.add(BitRow::new(vec![a[bit]], vec![b[bit]], vec![and_prod[bit]]));
            relation.add(BitRow::new(
                vec![and_prod[bit]],
                vec![is_and],
                vec![and_gated[bit]],
            ));
            relation.add(BitRow::new(
                vec![a[bit], b[bit]],
                vec![one],
                vec![add_diff[bit]],
            ));
            relation.add(BitRow::new(
                vec![add_diff[bit], carries[bit]],
                vec![one],
                vec![add_xor[bit]],
            ));
            relation.add(BitRow::new(
                vec![add_xor[bit]],
                vec![is_add],
                vec![add_gated[bit]],
            ));
            relation.add(BitRow::new(vec![a[bit]], vec![b[bit]], vec![p1[bit]]));
            relation.add(BitRow::new(vec![a[bit]], vec![carries[bit]], vec![p2[bit]]));
            relation.add(BitRow::new(vec![b[bit]], vec![carries[bit]], vec![p3[bit]]));
            relation.add(BitRow::new(
                vec![p1[bit], p2[bit], p3[bit]],
                vec![one],
                vec![carries[bit + 1]],
            ));
            relation.add(BitRow::new(
                vec![xor_prod[bit], and_gated[bit], add_gated[bit]],
                vec![one],
                vec![out[bit]],
            ));
        }
        Self {
            width,
            a,
            b,
            out,
            is_alu,
            is_xor,
            is_and,
            is_add,
            one,
            xor_prod,
            and_gated,
            add_gated,
            relation,
        }
    }

    pub fn witness(&self, left: u64, right: u64, op: GatedAluOp) -> Vec<bool> {
        let mut bits = vec![false; self.relation.num_vars];
        bits[3 * self.width + 4] = true;
        let (is_xor, is_and, is_add) = match op {
            GatedAluOp::Xor => (true, false, false),
            GatedAluOp::And => (false, true, false),
            GatedAluOp::Add => (false, false, true),
            GatedAluOp::Inactive => (false, false, false),
        };
        bits[self.is_alu] = is_xor || is_and || is_add;
        bits[self.is_xor] = is_xor;
        bits[self.is_and] = is_and;
        bits[self.is_add] = is_add;
        let carries = 7 * self.width + 5;
        for bit in 0..self.width {
            let a = (left >> bit) & 1 == 1;
            let b = (right >> bit) & 1 == 1;
            let carry = bits[carries + bit];
            bits[self.a[bit]] = a;
            bits[self.b[bit]] = b;
            bits[3 * self.width + 5 + bit] = a ^ b;
            bits[4 * self.width + 5 + bit] = is_xor && (a ^ b);
            bits[5 * self.width + 5 + bit] = a && b;
            bits[6 * self.width + 5 + bit] = is_and && (a && b);
            bits[11 * self.width + 6 + bit] = a ^ b;
            bits[12 * self.width + 6 + bit] = a ^ b ^ carry;
            bits[13 * self.width + 6 + bit] = is_add && (a ^ b ^ carry);
            bits[carries + bit + 1] = (a && b) || (a && carry) || (b && carry);
            bits[8 * self.width + 6 + bit] = a && b;
            bits[9 * self.width + 6 + bit] = a && carry;
            bits[10 * self.width + 6 + bit] = b && carry;
            bits[self.out[bit]] = match op {
                GatedAluOp::Xor => a ^ b,
                GatedAluOp::And => a && b,
                GatedAluOp::Add => a ^ b ^ carry,
                GatedAluOp::Inactive => false,
            };
        }
        bits
    }
}

#[cfg(test)]
mod gated_alu_tests {
    use super::*;

    #[test]
    fn gated_alu_selects_xor_and_and() {
        let row = GatedAluRow::new(8);
        let xor = row.witness(0b1010_1010, 0b1100_1100, GatedAluOp::Xor);
        assert!(row.relation.check(&xor));
        let and = row.witness(0b1010_1010, 0b1100_1100, GatedAluOp::And);
        assert!(row.relation.check(&and));
        let add = row.witness(0b0000_0101, 0b0000_0011, GatedAluOp::Add);
        assert!(row.relation.check(&add));
        let rd = row.out.iter().enumerate().fold(0u64, |value, (bit, var)| {
            value | (u64::from(add[*var]) << bit)
        });
        assert_eq!(rd, 8);
        let inactive = row.witness(0b1010_1010, 0b1100_1100, GatedAluOp::Inactive);
        assert!(row.relation.check(&inactive));
        for bit in 0..8 {
            assert!(!inactive[row.out[bit]]);
        }
        use magnetar_pcs::P3BinaryPcs;
        let backend = EmbeddedBitBackend {
            pcs: P3BinaryPcs::new(100),
        };
        let proof = backend.prove(&row.relation, &xor).unwrap();
        assert!(backend.verify(&row.relation, &proof).unwrap());
    }
}

/// Combined selector-gated ALU + memory row. ALU and memory occupy disjoint
/// variable ranges; exactly one side is active (`is_alu + is_mem = 1`).
#[derive(Clone, Debug)]
pub struct GatedCpuRow {
    pub width: usize,
    pub alu: GatedAluRow,
    pub memory: GatedMemoryRow,
    pub memory_offset: usize,
    pub pc: Vec<VarId>,
    pub next_pc: Vec<VarId>,
    pub relation: BitRelation,
}

impl GatedCpuRow {
    pub fn new(width: usize) -> Self {
        let alu = GatedAluRow::new(width);
        let memory = GatedMemoryRow::new(width);
        let memory_offset = alu.relation.num_vars;
        let mut relation = alu.relation.clone();
        relation.num_vars += memory.relation.num_vars;
        for row in &memory.relation.rows {
            let shift = |vars: &[VarId]| {
                vars.iter()
                    .map(|var| *var + memory_offset)
                    .collect::<Vec<_>>()
            };
            relation.add(BitRow::new(shift(&row.a), shift(&row.b), shift(&row.c)));
        }
        relation.add(BitRow::new(
            vec![alu.is_alu, memory_offset + memory.adder.gate],
            vec![alu.one],
            vec![alu.one],
        ));
        let pc = (relation.num_vars..relation.num_vars + width).collect::<Vec<_>>();
        let next_pc =
            (relation.num_vars + width..relation.num_vars + 2 * width).collect::<Vec<_>>();
        relation.num_vars += 2 * width;
        for bit in 0..width {
            relation.add(BitRow::new(
                vec![pc[bit]],
                vec![pc[bit], alu.one],
                Vec::new(),
            ));
            relation.add(BitRow::new(
                vec![next_pc[bit]],
                vec![next_pc[bit], alu.one],
                Vec::new(),
            ));
        }
        Self {
            width,
            alu,
            memory,
            memory_offset,
            pc,
            next_pc,
            relation,
        }
    }

    /// Packed-field view of the gated row. The selector-gated constraints are
    /// bit-level; this embeds them into the F2^128 R1CS used by the PCS/proof.
    pub fn packed_system(&self) -> magnetar_constraint::ConstraintSystem {
        self.relation.to_system()
    }

    fn finish(&self, mut bits: Vec<bool>, pc: u64) -> Vec<bool> {
        bits.resize(self.relation.num_vars, false);
        for bit in 0..self.width {
            bits[self.pc[bit]] = (pc >> bit) & 1 == 1;
            bits[self.next_pc[bit]] = ((pc + 4) >> bit) & 1 == 1;
        }
        bits
    }

    pub fn alu_witness(&self, left: u64, right: u64, op: GatedAluOp) -> Vec<bool> {
        self.alu_witness_at(0, left, right, op)
    }

    pub fn alu_witness_at(&self, pc: u64, left: u64, right: u64, op: GatedAluOp) -> Vec<bool> {
        let mut bits = self.alu.witness(left, right, op);
        let memory = self.memory.witness(0, 0, 0, false);
        bits.extend(memory);
        self.finish(bits, pc)
    }

    pub fn memory_witness(&self, rs1: u64, imm: u64, value: u64, is_mem: bool) -> Vec<bool> {
        self.memory_witness_at(0, rs1, imm, value, is_mem)
    }

    pub fn memory_witness_at(
        &self,
        pc: u64,
        rs1: u64,
        imm: u64,
        value: u64,
        is_mem: bool,
    ) -> Vec<bool> {
        let mut bits = self.alu.witness(0, 0, GatedAluOp::Inactive);
        let memory = self.memory.witness(rs1, imm, value, is_mem);
        bits.extend(memory);
        self.finish(bits, pc)
    }
}

#[cfg(test)]
mod gated_cpu_row_tests {
    use super::*;

    #[test]
    fn combined_gated_row_selects_alu_or_memory() {
        let row = GatedCpuRow::new(8);
        let alu = row.alu_witness(0b1010_1010, 0b1100_1100, GatedAluOp::Xor);
        assert!(row.relation.check(&alu));
        assert!(alu[row.alu.is_alu]);
        assert!(!alu[row.memory_offset + row.memory.adder.gate]);

        let memory = row.memory_witness(0x10, 2, 0x34, true);
        assert!(row.relation.check(&memory));
        assert!(!memory[row.alu.is_alu]);
        assert!(memory[row.memory_offset + row.memory.adder.gate]);
    }
}

#[derive(Clone, Copy, Debug)]
pub enum GatedCpuRowInput {
    Alu {
        left: u64,
        right: u64,
        op: GatedAluOp,
    },
    Memory {
        rs1: u64,
        imm: u64,
        value: u64,
        is_mem: bool,
    },
}

pub fn prove_gated_cpu_batch(
    width: usize,
    rows: &[GatedCpuRowInput],
) -> Result<
    magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
    RuntimeError,
> {
    use magnetar_proof::prove_shared_simd_spartan;

    if rows.is_empty() || !rows.len().is_power_of_two() {
        return Err(RuntimeError::Proof(
            "gated CPU batch must be a nonzero power of two".into(),
        ));
    }
    let row = GatedCpuRow::new(width);
    let system = row.packed_system();
    let mut witnesses = Vec::new();
    for input in rows {
        let bits = match input {
            GatedCpuRowInput::Alu { left, right, op } => row.alu_witness(*left, *right, *op),
            GatedCpuRowInput::Memory {
                rs1,
                imm,
                value,
                is_mem,
            } => row.memory_witness(*rs1, *imm, *value, *is_mem),
        };
        witnesses.push(row.relation.to_witness(&bits));
    }
    let pcs = magnetar_pcs::P3BinaryPcs::new(100);
    prove_shared_simd_spartan(&system, &witnesses, &pcs)
        .map_err(|error| RuntimeError::Proof(error.to_string()))
}

pub fn verify_gated_cpu_batch(
    width: usize,
    instances: usize,
    proof: &magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
) -> Result<(), RuntimeError> {
    use magnetar_proof::verify_shared_simd_spartan;

    let row = GatedCpuRow::new(width);
    let system = row.packed_system();
    let pcs = magnetar_pcs::P3BinaryPcs::new(100);
    verify_shared_simd_spartan(&system, instances, proof, &pcs)
        .map_err(|error| RuntimeError::Proof(error.to_string()))
}

#[cfg(test)]
mod gated_cpu_batch_tests {
    use super::*;

    #[test]
    fn combined_gated_row_batch_round_trips() {
        let rows = [
            GatedCpuRowInput::Alu {
                left: 0b1010_1010,
                right: 0b1100_1100,
                op: GatedAluOp::Add,
            },
            GatedCpuRowInput::Memory {
                rs1: 0x10,
                imm: 2,
                value: 0x34,
                is_mem: true,
            },
        ];
        let proof = prove_gated_cpu_batch(8, &rows).unwrap();
        verify_gated_cpu_batch(8, rows.len(), &proof).unwrap();

        let chained = [(0x1000, rows[0]), (0x1004, rows[1])];
        let proof = prove_gated_cpu_batch_pc(8, &chained).unwrap();
        verify_gated_cpu_batch_pc(8, &chained, &proof).unwrap();
    }
}

/// Gated ALU/memory batch with PC-chain rows and shared matrices.
pub fn prove_gated_cpu_batch_pc(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
) -> Result<
    magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
    RuntimeError,
> {
    use magnetar_proof::spartan::MatrixPart;
    use magnetar_proof::{prove_spartan_with_matrices, witness_vector, SharedBlockMatrix};

    if rows.is_empty() || !rows.len().is_power_of_two() {
        return Err(RuntimeError::Proof(
            "gated CPU batch must be a nonzero power of two".into(),
        ));
    }
    let row = GatedCpuRow::new(width);
    let system = row.packed_system();
    let base_cols = (row.relation.num_vars + 1).next_power_of_two();
    let mut extra_a = Vec::new();
    let mut extra_b = Vec::new();
    let mut extra_c = Vec::new();
    for instance in 0..rows.len().saturating_sub(1) {
        for bit in 0..width {
            extra_a.push(vec![(
                instance * base_cols + row.next_pc[bit],
                magnetar_constraint::F2_128::from(1u64),
            )]);
            extra_b.push(vec![(
                instance * base_cols + row.alu.one,
                magnetar_constraint::F2_128::from(1u64),
            )]);
            extra_c.push(vec![(
                (instance + 1) * base_cols + row.pc[bit],
                magnetar_constraint::F2_128::from(1u64),
            )]);
        }
    }
    let a = SharedBlockMatrix::from_system(&system, MatrixPart::A, rows.len())
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_a);
    let b = SharedBlockMatrix::from_system(&system, MatrixPart::B, rows.len())
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_b);
    let c = SharedBlockMatrix::from_system(&system, MatrixPart::C, rows.len())
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_c);
    let mut z = Vec::new();
    for (pc, input) in rows {
        let bits = match input {
            GatedCpuRowInput::Alu { left, right, op } => {
                row.alu_witness_at(*pc, *left, *right, *op)
            }
            GatedCpuRowInput::Memory {
                rs1,
                imm,
                value,
                is_mem,
            } => row.memory_witness_at(*pc, *rs1, *imm, *value, *is_mem),
        };
        z.extend(
            witness_vector(&system, &row.relation.to_witness(&bits))
                .map_err(|error| RuntimeError::Proof(error.to_string()))?,
        );
    }
    let pcs = magnetar_pcs::P3BinaryPcs::new(100);
    prove_spartan_with_matrices(&z, &a, &b, &c, &pcs)
        .map_err(|error| RuntimeError::Proof(error.to_string()))
}

pub fn verify_gated_cpu_batch_pc(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
    proof: &magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>,
) -> Result<(), RuntimeError> {
    use magnetar_proof::spartan::MatrixPart;
    use magnetar_proof::{verify_spartan_with_matrices, SharedBlockMatrix};

    let row = GatedCpuRow::new(width);
    let system = row.packed_system();
    let base_cols = (row.relation.num_vars + 1).next_power_of_two();
    let mut extra_a = Vec::new();
    let mut extra_b = Vec::new();
    let mut extra_c = Vec::new();
    for instance in 0..rows.len().saturating_sub(1) {
        for bit in 0..width {
            extra_a.push(vec![(
                instance * base_cols + row.next_pc[bit],
                magnetar_constraint::F2_128::from(1u64),
            )]);
            extra_b.push(vec![(
                instance * base_cols + row.alu.one,
                magnetar_constraint::F2_128::from(1u64),
            )]);
            extra_c.push(vec![(
                (instance + 1) * base_cols + row.pc[bit],
                magnetar_constraint::F2_128::from(1u64),
            )]);
        }
    }
    let a = SharedBlockMatrix::from_system(&system, MatrixPart::A, rows.len())
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_a);
    let b = SharedBlockMatrix::from_system(&system, MatrixPart::B, rows.len())
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_b);
    let c = SharedBlockMatrix::from_system(&system, MatrixPart::C, rows.len())
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_c);
    let pcs = magnetar_pcs::P3BinaryPcs::new(100);
    verify_spartan_with_matrices(&a, &b, &c, proof, &pcs)
        .map_err(|error| RuntimeError::Proof(error.to_string()))
}

#[cfg(test)]
mod claim_routing_tests {
    use super::*;

    #[test]
    fn gated_rows_route_register_and_ram_claims() {
        use crate::protocol::{ClaimKind, ClaimSet, ProtocolPlan, SegmentId};

        let rows = [
            GatedCpuRowInput::Alu {
                left: 5,
                right: 3,
                op: GatedAluOp::Add,
            },
            GatedCpuRowInput::Memory {
                rs1: 0x10,
                imm: 2,
                value: 0x34,
                is_mem: true,
            },
        ];
        let mut claims = ClaimSet::new();
        for (pc, input) in [(0x1000u64, rows[0]), (0x1004, rows[1])] {
            let kind = match input {
                GatedCpuRowInput::Alu { .. } => ClaimKind::Register,
                GatedCpuRowInput::Memory { .. } => ClaimKind::Ram,
            };
            claims.push(crate::protocol::Claim::new(
                kind,
                SegmentId(0),
                vec![magnetar_constraint::F2_128::from(pc)],
                magnetar_constraint::F2_128::from(1u64),
            ));
        }
        let plan = ProtocolPlan::unified();
        plan.check_virtual_claims(&claims).unwrap();
        plan.consume_virtual_claims(&mut claims).unwrap();
        assert_eq!(claims.remaining(), 0);
    }
}

/// Build a BinaryTwist RAM witness from active gated memory rows. The address
/// and data are read back from the gated row witness, so the Twist table is
/// tied to the selector-gated relation rather than to the raw inputs.
pub fn gated_memory_twist_witness(
    width: usize,
    rows: &[(u64, GatedCpuRowInput)],
) -> Result<magnetar_memory::BinaryTwistWitness, RuntimeError> {
    let row = GatedCpuRow::new(width);
    let cells = 1usize << width;
    let mut current = vec![F2_128::from(0u64); cells];
    let mut read_address = Vec::new();
    let mut write_address = Vec::new();
    let mut increment = Vec::new();
    let mut value = Vec::new();
    let mut read_value = Vec::new();
    let mut write_value = Vec::new();

    for (pc, input) in rows {
        let GatedCpuRowInput::Memory {
            rs1,
            imm,
            value: data,
            is_mem: true,
        } = input
        else {
            continue;
        };
        let bits = row.memory_witness_at(*pc, *rs1, *imm, *data, true);
        let decode = |vars: &[VarId]| {
            vars.iter().enumerate().fold(0usize, |acc, (bit, var)| {
                acc | (usize::from(bits[*var]) << bit)
            })
        };
        let address = decode(&row.memory.adder.out);
        let data = decode(&row.memory.data);
        if address >= cells {
            return Err(RuntimeError::Proof(
                "gated memory address out of range".into(),
            ));
        }
        let mut read = vec![F2_128::from(0u64); cells];
        read[address] = F2_128::from(1u64);
        let old = current[address];
        let new = F2_128::from(data as u64);
        value.push(current.clone());
        read_address.push(read.clone());
        write_address.push(read);
        increment.push(old + new);
        read_value.push(old);
        write_value.push(new);
        current[address] = new;
    }

    if read_address.is_empty() {
        return Err(RuntimeError::Proof(
            "gated memory witness has no active rows".into(),
        ));
    }
    let witness = magnetar_memory::BinaryTwistWitness {
        address_bits: width,
        cell_bits: width,
        cycles: read_address.len(),
        initial: vec![F2_128::from(0u64); cells],
        read_address,
        write_address,
        increment,
        value,
        read_value,
        write_value,
        final_value: current,
    };
    witness
        .validate()
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(witness)
}

#[cfg(test)]
mod gated_twist_tests {
    use super::*;

    #[test]
    fn gated_memory_rows_prove_through_binary_twist() {
        use crate::{prove_binary_twist_ram, verify_binary_twist_ram};

        let rows = [
            (
                0x1000,
                GatedCpuRowInput::Memory {
                    rs1: 0x10,
                    imm: 2,
                    value: 0x34,
                    is_mem: true,
                },
            ),
            (
                0x1004,
                GatedCpuRowInput::Memory {
                    rs1: 0x20,
                    imm: 4,
                    value: 0x56,
                    is_mem: true,
                },
            ),
        ];
        let witness = gated_memory_twist_witness(8, &rows).unwrap();
        let proof = prove_binary_twist_ram(&witness).unwrap();
        assert!(verify_binary_twist_ram(&witness, &proof).unwrap());
    }
}

/// Packed s2 companion for a gated ALU row: one F2^128 linear check that the
/// packed output equals the packed selected ALU products.
pub fn gated_alu_packed_system(row: &GatedAluRow) -> magnetar_constraint::ConstraintSystem {
    use magnetar_constraint::{ConstraintSystem, Expr};
    let packed = |vars: &[VarId]| {
        vars.iter()
            .enumerate()
            .fold(Expr::constant(0u64), |expr, (bit, var)| {
                expr.add(Expr::var(*var).scale(F2_128::from(1u128 << bit)))
            })
    };
    let mut system = ConstraintSystem::new(row.relation.num_vars);
    system.add_constraint(
        packed(&row.out)
            .add(packed(&row.xor_prod))
            .add(packed(&row.and_gated))
            .add(packed(&row.add_gated)),
        Expr::var(row.one),
        Expr::constant(0u64),
    );
    system
}

/// Dual proof for a gated ALU row: bit relation s1 and packed-output s2 over
/// the same witness, with the s2 zero-padded to s1's row count.
pub fn prove_gated_alu_packed(
    width: usize,
    left: u64,
    right: u64,
    op: GatedAluOp,
) -> Result<
    (
        magnetar_proof::LockstepProof<
            magnetar_pcs::P3MosaicCommitment,
            magnetar_pcs::P3MosaicOpening,
        >,
        magnetar_constraint::WitnessLayout,
    ),
    RuntimeError,
> {
    use magnetar_constraint::{Segment, SegmentKind, SegmentOwner, WitnessLayout};
    use magnetar_pcs::P3SharedPcs;
    use magnetar_proof::{prove_lockstep, witness_vector};

    let row = GatedAluRow::new(width);
    let bits = row.witness(left, right, op);
    let witness = row.relation.to_witness(&bits);
    let s1 = row.relation.to_system();
    let mut s2 = gated_alu_packed_system(&row);
    for _ in s2.constraints.len()..s1.constraints.len() {
        s2.add_constraint(
            magnetar_constraint::Expr::constant(0u64),
            magnetar_constraint::Expr::constant(1u64),
            magnetar_constraint::Expr::constant(0u64),
        );
    }
    let z =
        witness_vector(&s2, &witness).map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let total = z.len().trailing_zeros() as usize;
    let half = total - 1;
    let layout = WitnessLayout::new(vec![
        Segment::new("lo", 0, 1 << half, SegmentKind::Direct, SegmentOwner::Cpu),
        Segment::new(
            "hi",
            1 << half,
            1 << half,
            SegmentKind::Direct,
            SegmentOwner::Cpu,
        ),
    ])
    .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
    let proof = prove_lockstep(&s1, &s2, &witness, &layout, &pcs)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok((proof, layout))
}

#[cfg(test)]
mod gated_alu_packed_tests {
    use super::*;
    use magnetar_pcs::P3SharedPcs;
    use magnetar_proof::{verify_lockstep, witness_vector};

    #[test]
    fn gated_alu_packed_companion_verifies() {
        for op in [GatedAluOp::Xor, GatedAluOp::And, GatedAluOp::Add] {
            let (proof, layout) = prove_gated_alu_packed(8, 0x12, 0x34, op).unwrap();
            let row = GatedAluRow::new(8);
            let witness = row.relation.to_witness(&row.witness(0x12, 0x34, op));
            let s1 = row.relation.to_system();
            let mut s2 = gated_alu_packed_system(&row);
            for _ in s2.constraints.len()..s1.constraints.len() {
                s2.add_constraint(
                    magnetar_constraint::Expr::constant(0u64),
                    magnetar_constraint::Expr::constant(1u64),
                    magnetar_constraint::Expr::constant(0u64),
                );
            }
            let _ = witness_vector(&s2, &witness).unwrap();
            let pcs = P3SharedPcs::new(100, Vec::new(), Vec::new(), Vec::new());
            verify_lockstep(&s1, &s2, &layout, &proof, &pcs).unwrap();
        }
    }
}
