//! RV64M multiplication/division and RV64I word-operation semantics.
//!
//! The signed operations follow the RISC-V rule that division by zero yields
//! all-ones for quotient and the dividend for remainder, and that
//! `i64::MIN / -1` overflows to `i64::MIN` with remainder zero.

use crate::Word;

pub fn mulh(a: Word, b: Word) -> Word {
    ((i128::from(a as i64) * i128::from(b as i64)) >> 64) as Word
}

pub fn mulhsu(a: Word, b: Word) -> Word {
    ((i128::from(a as i64) * i128::from(b)) >> 64) as Word
}

pub fn mulhu(a: Word, b: Word) -> Word {
    ((u128::from(a) * u128::from(b)) >> 64) as Word
}

pub fn div(a: Word, b: Word) -> Word {
    let (a, b) = (a as i64, b as i64);
    if b == 0 {
        Word::MAX
    } else if a == i64::MIN && b == -1 {
        i64::MIN as Word
    } else {
        (a / b) as Word
    }
}

pub fn divu(a: Word, b: Word) -> Word {
    a.checked_div(b).unwrap_or(Word::MAX)
}

pub fn rem(a: Word, b: Word) -> Word {
    let (a, b) = (a as i64, b as i64);
    if b == 0 {
        a as Word
    } else if a == i64::MIN && b == -1 {
        0
    } else {
        (a % b) as Word
    }
}

pub fn remu(a: Word, b: Word) -> Word {
    if b == 0 {
        a
    } else {
        a % b
    }
}

fn sext32(value: u32) -> Word {
    (value as i32 as i64) as Word
}

pub fn addw(a: Word, b: Word) -> Word {
    sext32((a as u32).wrapping_add(b as u32))
}

pub fn subw(a: Word, b: Word) -> Word {
    sext32((a as u32).wrapping_sub(b as u32))
}

pub fn sllw(a: Word, b: Word) -> Word {
    sext32((a as u32).wrapping_shl((b & 0x1f) as u32))
}

pub fn srlw(a: Word, b: Word) -> Word {
    sext32((a as u32).wrapping_shr((b & 0x1f) as u32))
}

pub fn sraw(a: Word, b: Word) -> Word {
    sext32(((a as u32 as i32) >> ((b & 0x1f) as u32)) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_multiplications_split_signed_and_unsigned() {
        assert_eq!(mulh(1 << 63, 2), Word::MAX);
        assert_eq!(mulhu(1 << 63, 2), 1);
        assert_eq!(mulhsu(1 << 63, 2), Word::MAX);
        assert_eq!(mulh(Word::MAX, Word::MAX), 0);
        assert_eq!(mulhu(Word::MAX, Word::MAX), Word::MAX - 1);
    }

    #[test]
    fn division_handles_zero_and_overflow() {
        assert_eq!(div(7, 2), 3);
        assert_eq!(div((-7i64) as Word, 2), (-3i64) as Word);
        assert_eq!(div(7, 0), Word::MAX);
        assert_eq!(div(i64::MIN as Word, (-1i64) as Word), i64::MIN as Word);

        assert_eq!(divu(Word::MAX, 2), Word::MAX / 2);
        assert_eq!(divu(7, 0), Word::MAX);
    }

    #[test]
    fn remainder_handles_zero_and_overflow() {
        assert_eq!(rem(7, 2), 1);
        assert_eq!(rem((-7i64) as Word, 2), (-1i64) as Word);
        assert_eq!(rem(7, 0), 7);
        assert_eq!(rem(i64::MIN as Word, (-1i64) as Word), 0);
        assert_eq!(remu(7, 0), 7);
        assert_eq!(remu(Word::MAX, 2), 1);
    }

    #[test]
    fn word_operations_sign_extend_low_32_bits() {
        assert_eq!(addw(0x7fff_ffff, 1), 0xffff_ffff_8000_0000);
        assert_eq!(subw(0, 1), Word::MAX);
        assert_eq!(sllw(1, 31), 0xffff_ffff_8000_0000);
        assert_eq!(srlw(0x8000_0000, 31), 1);
        assert_eq!(sraw(0x8000_0000, 31), Word::MAX);
        assert_eq!(addw(1, 2), 3);
        assert_eq!(sllw(1, 32), 1);
    }
}
