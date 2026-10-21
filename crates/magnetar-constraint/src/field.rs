use std::fmt;
use std::ops::{Add, Mul, Neg, Sub};

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

/// The Mersenne prime field `2^61 - 1`.
///
/// This is a reference field for tests of the proof engine. Magnetar itself
/// uses `F_{2^128}`; a binary-field implementation belongs behind the same
/// trait.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

    #[test]
    fn arithmetic_holds() {
        let a = F61::new(F61_MODULUS - 1);
        let b = F61::new(2);
        assert_eq!(a + b, F61::new(1));
        assert_eq!(a * b, F61::new(F61_MODULUS - 2));
        assert_eq!(-a, F61::new(1));
        assert_eq!(F61::new(0) - F61::new(1), F61::new(F61_MODULUS - 1));
    }

    #[test]
    fn inverses_exist_for_nonzero_values() {
        for value in 1..1000 {
            let field = F61::new(value);
            let inverse = field.inv().expect("nonzero");
            assert_eq!(field * inverse, F61::one());
        }
        assert!(F61::zero().inv().is_none());
    }
}
