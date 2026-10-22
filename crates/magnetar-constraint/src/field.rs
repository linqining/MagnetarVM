#![allow(dead_code)]
#[cfg(test)]
use lambdaworks_math::field::fields::binary::field::TowerFieldElement;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::{Add, Mul, Neg, Sub};
use std::sync::OnceLock;

/// Minimal field interface used by the reference proof engine.
pub trait Field:
    Copy
    + Clone
    + Eq
    + fmt::Debug
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
{
    fn zero() -> Self;
    fn one() -> Self;
    fn from_u64(value: u64) -> Self;
    fn inv(self) -> Option<Self>;

    fn is_zero(self) -> bool {
        self == Self::zero()
    }

    fn pow(self, mut exponent: u64) -> Self {
        let mut base = self;
        let mut result = Self::one();
        while exponent > 0 {
            if exponent & 1 == 1 {
                result = result * base;
            }
            base = base * base;
            exponent >>= 1;
        }
        result
    }
}

/// The two-element field, used by the native F2 relation prototype.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct F2(u8);

impl F2 {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);

    pub fn new(bit: bool) -> Self {
        Self(u8::from(bit))
    }

    pub fn value(self) -> u8 {
        self.0 & 1
    }
}

impl fmt::Debug for F2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "F2({})", self.value())
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Add for F2 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Sub for F2 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        self + rhs
    }
}

impl Neg for F2 {
    type Output = Self;
    fn neg(self) -> Self {
        self
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Mul for F2 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl Field for F2 {
    fn zero() -> Self {
        Self::ZERO
    }
    fn one() -> Self {
        Self::ONE
    }
    fn from_u64(value: u64) -> Self {
        Self((value & 1) as u8)
    }
    fn inv(self) -> Option<Self> {
        (self.value() == 1).then_some(Self::ONE)
    }
}

/// `GF(2^128)` as a seven-level binary tower.
///
/// The wrapper pins every element to tower level 7. `from_u64` embeds the
/// integer's binary representation as polynomial coefficients, so `2` is the
/// basis element `x`, not `1 + 1` (which is zero in characteristic two).
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct F2_128(u128);

impl F2_128 {
    pub fn new(value: u128) -> Self {
        Self(value)
    }

    pub fn value(self) -> u128 {
        self.0
    }

    pub fn from_bits(value: u128) -> Self {
        Self(value)
    }

    #[cfg(test)]
    fn pow_u128(self, mut exponent: u128) -> Self {
        let mut base = self;
        let mut result = Self::one();
        while exponent > 0 {
            if exponent & 1 == 1 {
                result = result * base;
            }
            base = base * base;
            exponent >>= 1;
        }
        result
    }
}

impl From<u64> for F2_128 {
    fn from(value: u64) -> Self {
        Self(u128::from(value))
    }
}

impl From<u128> for F2_128 {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl From<F2_128> for u128 {
    fn from(value: F2_128) -> Self {
        value.0
    }
}

impl fmt::Debug for F2_128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "F2_128(0x{:032x})", self.0)
    }
}

impl fmt::Display for F2_128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:032x}", self.0)
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Add for F2_128 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Sub for F2_128 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Mul for F2_128 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(p3_mul(self.0, rhs.0))
    }
}

/// Multiplication in Plonky3's canonical 128-bit binary tower.
///
/// The project uses the same field representation as `p3-binary-pcs`, so
/// polynomial openings and our constraint arithmetic share one basis.
fn p3_mul(a: u128, b: u128) -> u128 {
    use p3_binary_field::{BinaryField128, TowerLevel};
    let product = BinaryField128::from_repr(a) * BinaryField128::from_repr(b);
    product.to_repr()
}

impl Neg for F2_128 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

impl Field for F2_128 {
    fn zero() -> Self {
        Self(0)
    }

    fn one() -> Self {
        Self(1)
    }

    fn from_u64(value: u64) -> Self {
        Self(u128::from(value))
    }

    fn inv(self) -> Option<Self> {
        use p3_binary_field::{BinaryField128, TowerLevel};
        use p3_field::Field as P3Field;
        if self.0 == 0 {
            None
        } else {
            let inverse = P3Field::try_inverse(&BinaryField128::from_repr(self.0))?;
            Some(Self(inverse.to_repr()))
        }
    }
}

const TOWER_LEVEL: usize = 7;
const GF8_ORDER: usize = 255;
const GF16_ORDER: usize = 65_535;

struct Gf8Tables {
    exp: [u8; GF8_ORDER],
    log: [u8; 256],
}

fn gf8_tables() -> &'static Gf8Tables {
    static TABLES: OnceLock<Gf8Tables> = OnceLock::new();
    TABLES.get_or_init(build_gf8_tables)
}

fn build_gf8_tables() -> Gf8Tables {
    let mut generator = 0u8;
    for candidate in 2u8..=255 {
        let candidate = u128::from(candidate);
        if [3u32, 5, 17]
            .iter()
            .all(|prime| pow_level_slow(candidate, GF8_ORDER as u32 / prime, 3) != 1)
        {
            generator = candidate as u8;
            break;
        }
    }
    assert!(generator != 0, "GF(2^8) generator not found");

    let mut exp = [0u8; GF8_ORDER];
    let mut log = [0u8; 256];
    let mut value = 1u128;
    for (index, slot) in exp.iter_mut().enumerate() {
        *slot = value as u8;
        log[value as usize] = index as u8;
        value = mul_level_slow(value, u128::from(generator), 3);
    }
    Gf8Tables { exp, log }
}

struct Gf16Tables {
    exp: Vec<u16>,
    log: Vec<u16>,
}

fn gf16_tables() -> &'static Gf16Tables {
    static TABLES: OnceLock<Gf16Tables> = OnceLock::new();
    TABLES.get_or_init(build_gf16_tables)
}

fn build_gf16_tables() -> Gf16Tables {
    let mut generator = 0u16;
    for candidate in 2u16..=u16::MAX {
        let candidate = u128::from(candidate);
        if [3u32, 5, 17, 257]
            .iter()
            .all(|prime| pow_level_slow(candidate, GF16_ORDER as u32 / prime, 4) != 1)
        {
            generator = candidate as u16;
            break;
        }
    }
    assert!(generator != 0, "GF(2^16) generator not found");

    let mut exp = vec![0u16; GF16_ORDER];
    let mut log = vec![0u16; 1 << 16];
    let mut value = 1u128;
    for (index, slot) in exp.iter_mut().enumerate() {
        *slot = value as u16;
        log[value as usize] = index as u16;
        value = mul_level_slow(value, u128::from(generator), 4);
    }
    Gf16Tables { exp, log }
}

fn pow_level_slow(mut base: u128, mut exponent: u32, level: usize) -> u128 {
    let mut result = 1u128;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = mul_level_slow(result, base, level);
        }
        base = mul_level_slow(base, base, level);
        exponent >>= 1;
    }
    result
}

fn half_bits(level: usize) -> usize {
    1usize << (level - 1)
}

fn split(value: u128, level: usize) -> (u128, u128) {
    let half = half_bits(level);
    let mask = if half >= 128 {
        u128::MAX
    } else {
        (1u128 << half) - 1
    };
    ((value >> half) & mask, value & mask)
}

/// Multiplication in the tower basis, with GF(2^16) and GF(2^8) log/exp tables.
fn mul_level(a: u128, b: u128, level: usize) -> u128 {
    if a == 0 || b == 0 {
        return 0;
    }
    if level == 4 {
        let tables = gf16_tables();
        let left = usize::from(tables.log[a as usize]);
        let right = usize::from(tables.log[b as usize]);
        return u128::from(tables.exp[(left + right) % GF16_ORDER]);
    }
    if level == 3 {
        let tables = gf8_tables();
        let left = usize::from(tables.log[a as usize]);
        let right = usize::from(tables.log[b as usize]);
        return u128::from(tables.exp[(left + right) % GF8_ORDER]);
    }
    if level == 0 {
        return a & b;
    }
    mul_level_recursive(a, b, level, false)
}

/// Table-free multiplication used while building the GF(2^8) tables.
fn mul_level_slow(a: u128, b: u128, level: usize) -> u128 {
    if a == 0 || b == 0 {
        return 0;
    }
    if level == 0 {
        return a & b;
    }
    mul_level_recursive(a, b, level, true)
}

fn mul_level_recursive(a: u128, b: u128, level: usize, slow: bool) -> u128 {
    let (a_hi, a_lo) = split(a, level);
    let (b_hi, b_lo) = split(b, level);
    let multiply = if slow { mul_level_slow } else { mul_level };
    let low = multiply(a_lo, b_lo, level - 1);
    let high = multiply(a_hi, b_hi, level - 1);
    let middle = multiply(a_lo ^ a_hi, b_lo ^ b_hi, level - 1) ^ low ^ high;
    let x = if level == 1 {
        1
    } else {
        1u128 << (1usize << (level - 2))
    };
    let shifted_high = multiply(high, x, level - 1);
    ((shifted_high ^ middle) << half_bits(level)) | (high ^ low)
}

fn tower_mul(a: u128, b: u128) -> u128 {
    mul_level(a, b, TOWER_LEVEL)
}

fn square_times(mut value: u128, mut count: usize) -> u128 {
    while count > 0 {
        value = tower_mul(value, value);
        count -= 1;
    }
    value
}

/// `a^(2^128 - 2)` via the Itoh–Tsujii addition chain for 127.
fn tower_inv(a: u128) -> u128 {
    debug_assert_eq!(TOWER_LEVEL, 7);
    let a1 = a;
    let a2 = tower_mul(square_times(a1, 1), a1);
    let a3 = tower_mul(square_times(a2, 1), a1);
    let a6 = tower_mul(square_times(a3, 3), a3);
    let a7 = tower_mul(square_times(a6, 1), a1);
    let a14 = tower_mul(square_times(a7, 7), a7);
    let a15 = tower_mul(square_times(a14, 1), a1);
    let a30 = tower_mul(square_times(a15, 15), a15);
    let a31 = tower_mul(square_times(a30, 1), a1);
    let a62 = tower_mul(square_times(a31, 31), a31);
    let a63 = tower_mul(square_times(a62, 1), a1);
    let a126 = tower_mul(square_times(a63, 63), a63);
    let a127 = tower_mul(square_times(a126, 1), a1);
    tower_mul(a127, a127)
}

/// The Mersenne prime field `2^61 - 1`.
///
/// Kept as a fast prime-field reference for tests and for comparing generic
/// proof-engine behavior against a characteristic-not-two field.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct F61(u64);

pub const F61_MODULUS: u64 = (1u64 << 61) - 1;

impl F61 {
    pub const fn new(value: u64) -> Self {
        Self(value % F61_MODULUS)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

impl From<u64> for F61 {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for F61 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "F61({})", self.0)
    }
}

impl fmt::Display for F61 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Add for F61 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let sum = self.0 + rhs.0;
        if sum >= F61_MODULUS {
            Self(sum - F61_MODULUS)
        } else {
            Self(sum)
        }
    }
}

impl Sub for F61 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        if self.0 >= rhs.0 {
            Self(self.0 - rhs.0)
        } else {
            Self(self.0 + F61_MODULUS - rhs.0)
        }
    }
}

impl Mul for F61 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let product = u128::from(self.0) * u128::from(rhs.0);
        Self((product % u128::from(F61_MODULUS)) as u64)
    }
}

impl Neg for F61 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        if self.0 == 0 {
            Self(0)
        } else {
            Self(F61_MODULUS - self.0)
        }
    }
}

impl Field for F61 {
    fn zero() -> Self {
        Self(0)
    }

    fn one() -> Self {
        Self(1)
    }

    fn from_u64(value: u64) -> Self {
        Self::new(value)
    }

    fn inv(self) -> Option<Self> {
        if self.0 == 0 {
            None
        } else {
            Some(self.pow(F61_MODULUS - 2))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn binary_field_has_characteristic_two() {
        let a = F2_128::new(0xdead_beef);
        assert_eq!(a + a, F2_128::zero());
        assert_eq!(a - a, F2_128::zero());
        assert_eq!(-a, a);
    }

    #[test]
    fn binary_basis_embedding_is_injective() {
        let two = F2_128::from_u64(2);
        assert_ne!(two, F2_128::zero());
        assert_ne!(two, F2_128::one());
        assert_eq!(two + two, F2_128::zero());
        assert_eq!(F2_128::from_u64(3), two + F2_128::one());
    }

    #[test]
    fn binary_inverses_exist() {
        for value in [
            1u128,
            2,
            3,
            0xdead_beef,
            0x0123_4567_89ab_cdef,
            u128::MAX - 1,
        ] {
            let element = F2_128::new(value);
            let inverse = element.inv().expect("nonzero");
            assert_eq!(element * inverse, F2_128::one());
        }
        assert!(F2_128::zero().inv().is_none());
    }

    #[test]
    fn inversion_chain_matches_fermat_exponent() {
        for value in [1u128, 2, 3, 0xdead_beef, u128::MAX - 1] {
            let element = F2_128::new(value);
            assert_eq!(
                tower_inv(value),
                element.pow_u128(u128::MAX - 1).value(),
                "value {value:#x}"
            );
        }
    }

    #[test]
    fn binary_field_helpers_and_formatting() {
        let value = F2_128::from_bits(0x1234);
        assert_eq!(u128::from(value), 0x1234);
        assert_eq!(format!("{value}"), "0x00000000000000000000000000001234");
        assert!(format!("{value:?}").starts_with("F2_128(0x"));

        assert!(F2_128::zero().is_zero());
        assert!(!F2_128::one().is_zero());
        let three = F2_128::from_u64(3);
        assert_eq!(three.pow(0), F2_128::one());
        assert_eq!(three.pow(1), three);
        assert_eq!(three.pow(2), three * three);

        let prime = F61::new(7);
        assert!(!prime.is_zero());
        assert_eq!(prime.pow(0), F61::new(1));
        assert_eq!(prime.pow(3), F61::new(343));
        assert_eq!(prime * prime.inv().unwrap(), F61::new(1));
        assert_eq!(format!("{prime}"), "7");
        assert_eq!(format!("{prime:?}"), "F61(7)");
    }

    #[test]
    fn field_identities_and_prime_reduction() {
        let a = F2_128::new(0x0123_4567_89ab_cdef);
        assert_eq!(a + F2_128::zero(), a);
        assert_eq!(a * F2_128::one(), a);
        assert_eq!(a * F2_128::zero(), F2_128::zero());
        assert_eq!(a - F2_128::one(), a + F2_128::one());
        assert_eq!(a.inv().unwrap() * a, F2_128::one());
        assert_eq!(F2_128::zero().inv(), None);
        assert_eq!(F2_128::from(5u64), F2_128::from_u64(5));
        assert_eq!(F2_128::from(9u128).value(), 9);

        assert_eq!(F61::new(F61_MODULUS + 5), F61::new(5));
        assert_eq!(F61::new(F61_MODULUS), F61::new(0));
        assert_eq!(F61::new(F61_MODULUS - 1) + F61::new(2), F61::new(1));
        assert_eq!(F61::new(1) - F61::new(2), F61::new(F61_MODULUS - 1));
        assert_eq!(
            F61::new(2) * F61::new(F61_MODULUS - 1),
            F61::new(F61_MODULUS - 2)
        );
        assert_eq!(-F61::zero(), F61::zero());
        assert_eq!(-F61::new(1), F61::new(F61_MODULUS - 1));
        assert_eq!(F61::zero().inv(), None);
        assert_eq!(F61::from_u64(3).value(), 3);
    }

    #[test]
    fn prime_field_arithmetic_holds() {
        let a = F61::new(F61_MODULUS - 1);
        let b = F61::new(2);
        assert_eq!(a + b, F61::new(1));
        assert_eq!(a * b, F61::new(F61_MODULUS - 2));
        assert_eq!(-a, F61::new(1));
        assert_eq!(F61::new(0) - F61::new(1), F61::new(F61_MODULUS - 1));
    }

    #[test]
    fn p3_multiplication_matches_the_reference_tower() {
        for index in 0..256u128 {
            let a = index.wrapping_mul(0x0123_4567_89ab_cdef);
            let b = index.wrapping_mul(0xfedc_ba98_7654_3210);
            assert_eq!(p3_mul(a, b), tower_mul(a, b), "index {index}");
        }
    }

    proptest! {
        #[test]
        fn tower_multiplication_matches_lambdaworks(a: u128, b: u128) {
            let expected =
                TowerFieldElement::new(a, 7) * TowerFieldElement::new(b, 7);
            prop_assert_eq!(tower_mul(a, b), expected.value());
        }

        #[test]
        fn binary_addition_is_commutative(a: u128, b: u128) {
            prop_assert_eq!(F2_128::new(a) + F2_128::new(b), F2_128::new(b) + F2_128::new(a));
        }

        #[test]
        fn binary_multiplication_is_commutative(a: u128, b: u128) {
            prop_assert_eq!(F2_128::new(a) * F2_128::new(b), F2_128::new(b) * F2_128::new(a));
        }

        #[test]
        fn binary_multiplication_is_associative(a: u128, b: u128, c: u128) {
            let (a, b, c) = (F2_128::new(a), F2_128::new(b), F2_128::new(c));
            prop_assert_eq!((a * b) * c, a * (b * c));
        }

        #[test]
        fn binary_multiplication_distributes(a: u128, b: u128, c: u128) {
            let (a, b, c) = (F2_128::new(a), F2_128::new(b), F2_128::new(c));
            prop_assert_eq!(a * (b + c), a * b + a * c);
        }

        #[test]
        fn binary_inverse_roundtrips(a in any::<u128>().prop_filter("nonzero", |x| *x != 0)) {
            let element = F2_128::new(a);
            prop_assert_eq!(element * element.inv().unwrap(), F2_128::one());
        }

        #[test]
        fn prime_field_addition_wraps(a: u64, b: u64) {
            let a = F61::new(a);
            let b = F61::new(b);
            prop_assert_eq!((a + b).value() as u128, (a.value() as u128 + b.value() as u128) % F61_MODULUS as u128);
        }
    }
}
