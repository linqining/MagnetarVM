//! Packed bit witness.
//!
//! The CPU witness is one bit per column per cycle (`2^29` bits at RV64
//! `2^16`). A `Vec<bool>` holds a byte each, so the witness alone was half a
//! GiB at `2^16` and would be 32 GiB at `2^22`; the packed form is eight times
//! smaller, which is what makes the paper's `2^22` memory envelope reachable
//! at all. The bit order is little-endian inside each `u64` word, so 128
//! consecutive bits map directly onto one `F2_128` element.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackedBits {
    words: Vec<u64>,
    len: usize,
}

impl PackedBits {
    pub fn zeroed(len: usize) -> Self {
        Self {
            words: vec![0u64; len.div_ceil(64)],
            len,
        }
    }

    pub fn from_bools(bits: &[bool]) -> Self {
        let mut packed = Self::zeroed(bits.len());
        for (index, bit) in bits.iter().enumerate() {
            if *bit {
                packed.set(index, true);
            }
        }
        packed
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn get(&self, index: usize) -> bool {
        debug_assert!(index < self.len);
        (self.words[index >> 6] >> (index & 63)) & 1 == 1
    }

    #[inline]
    pub fn set(&mut self, index: usize, value: bool) {
        debug_assert!(index < self.len);
        let word = &mut self.words[index >> 6];
        let mask = 1u64 << (index & 63);
        if value {
            *word |= mask;
        } else {
            *word &= !mask;
        }
    }

    pub fn words(&self) -> &[u64] {
        &self.words
    }

    /// Raw words for callers that fill disjoint, word-aligned bit ranges.
    pub fn words_mut(&mut self) -> &mut [u64] {
        &mut self.words
    }

    /// The 128 bits starting at `field * 128`, low bit first.
    #[inline]
    pub fn field_128(&self, field: usize) -> u128 {
        let low = self.words.get(field * 2).copied().unwrap_or(0);
        let high = self.words.get(field * 2 + 1).copied().unwrap_or(0);
        u128::from(low) | (u128::from(high) << 64)
    }

    /// Number of 128-bit fields the witness fills.
    pub fn fields_128(&self) -> usize {
        self.len.div_ceil(128)
    }

    pub fn iter_set(&self) -> impl Iterator<Item = usize> + '_ {
        self.words.iter().enumerate().flat_map(|(word_index, word)| {
            let mut bits = *word;
            std::iter::from_fn(move || {
                if bits == 0 {
                    return None;
                }
                let bit = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                Some(word_index * 64 + bit)
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_bits_round_trip() {
        let bools = (0..1000usize)
            .map(|index| index % 7 == 0 || index % 11 == 3)
            .collect::<Vec<_>>();
        let packed = PackedBits::from_bools(&bools);
        assert_eq!(packed.len(), bools.len());
        for (index, bit) in bools.iter().enumerate() {
            assert_eq!(packed.get(index), *bit, "index {index}");
        }
        let set = packed.iter_set().collect::<Vec<_>>();
        let expected = bools
            .iter()
            .enumerate()
            .filter_map(|(index, bit)| bit.then_some(index))
            .collect::<Vec<_>>();
        assert_eq!(set, expected);
    }

    #[test]
    fn field_128_matches_little_endian_bits() {
        let bools = (0..256usize).map(|index| index % 5 == 1).collect::<Vec<_>>();
        let packed = PackedBits::from_bools(&bools);
        for field in 0..2 {
            let expected = (0..128)
                .filter(|bit| bools[field * 128 + bit])
                .fold(0u128, |value, bit| value | (1u128 << bit));
            assert_eq!(packed.field_128(field), expected);
        }
    }
}
