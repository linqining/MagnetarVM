#![allow(dead_code)]

//! M4a table packing: production-side helpers for the bit-packed mosaic.
//!
//! The unified mosaic commits each twist address table as `2*address_bits + 2`
//! bit columns with one 16-byte field element per bit, and the Access proof
//! re-commits the same bit columns in its own batch. M4a packs those bit
//! columns 128 bits per cell and commits them once. This module owns the
//! representation change on the prover side:
//!
//! * [`pack_bit_column`] / [`unpack_bit_column`] — 128 bits per cell, lowest
//!   bit first, zero-padded to a multiple of 128 rows;
//! * [`split_and_pack`] — split a mixed table (the ROM table is 7/12 bit
//!   columns) into one packed bit table and one scalar table;
//! * [`pack_twist_tables`] — the five twist tables with the address table
//!   packed and the scalar tables untouched;
//! * [`pack_access_batch`] — the Access batch's scalar columns plus **one**
//!   packed bit table that is byte-identical to the mosaic address table's, so
//!   the bit data is committed once instead of twice;
//! * [`pack_word_pairs`] / [`unpack_word_pairs`] — the trace table's two 64-bit
//!   fields per cell.
//!
//! The module is representation-only: it does not change any proof yet. The
//! tests pin losslessness (unpack∘pack is the identity), the exact cell counts
//! the M4a projection relies on, and the dedup equality between the Access bit
//! table and the mosaic address table.

use magnetar_constraint::F2_128;
use magnetar_memory::BinaryTwistWitness;
use magnetar_pcs::P3MosaicTable;
use magnetar_proof::ProofError;

use crate::binary_twist::BatchTables;

/// Bits stored in one 16-byte cell.
pub(crate) const PACK: usize = 128;

fn is_bit_value(value: F2_128) -> bool {
    value.value() <= 1
}

pub(crate) fn is_bit_column(column: &[F2_128]) -> bool {
    column.iter().all(|value| is_bit_value(*value))
}

/// Pack one bit column 128 bits per cell (lowest bit first).
///
/// The column is zero-padded to a multiple of [`PACK`] rows. The packed length
/// is therefore `ceil(column.len() / 128)`.
pub(crate) fn pack_bit_column(column: &[F2_128]) -> Result<Vec<F2_128>, ProofError> {
    if !is_bit_column(column) {
        return Err(ProofError::Pcs("cannot pack a non-bit column".into()));
    }
    let mut packed = Vec::with_capacity(column.len().div_ceil(PACK));
    for chunk in column.chunks(PACK) {
        let mut word: u128 = 0;
        for (index, value) in chunk.iter().enumerate() {
            if value.value() & 1 == 1 {
                word |= 1u128 << index;
            }
        }
        packed.push(F2_128::from(word));
    }
    Ok(packed)
}

/// Unpack a packed bit column back to `len` 0/1 field elements.
pub(crate) fn unpack_bit_column(packed: &[F2_128], len: usize) -> Vec<F2_128> {
    let mut column = Vec::with_capacity(len);
    for value in packed {
        let word = value.value();
        for bit in 0..PACK {
            if column.len() == len {
                return column;
            }
            column.push(F2_128::from((word >> bit) & 1));
        }
    }
    column.resize(len, F2_128::from(0u64));
    column
}

/// Build one packed table from columns that are all bit-valued and equally long.
pub(crate) fn packed_bit_table(columns: &[Vec<F2_128>]) -> Result<P3MosaicTable, ProofError> {
    let rows = columns.first().map_or(0, |column| column.len());
    if rows == 0 || columns.iter().any(|column| column.len() != rows) {
        return Err(ProofError::Pcs(
            "packed bit table needs equally long, non-empty columns".into(),
        ));
    }
    let packed = columns
        .iter()
        .map(|column| pack_bit_column(column))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(P3MosaicTable { columns: packed })
}

/// Split a table into (packed bit table, scalar table) by column bit-ness.
///
/// Returns `None` for a half that has no columns. The packed half keeps the
/// column order of the bit columns, so a caller can map bit positions back.
pub(crate) fn split_and_pack(
    table: &P3MosaicTable,
) -> Result<(Option<P3MosaicTable>, Option<P3MosaicTable>, Vec<usize>), ProofError> {
    let mut bit_columns = Vec::new();
    let mut bit_indices = Vec::new();
    let mut scalar_columns = Vec::new();
    for (index, column) in table.columns.iter().enumerate() {
        if is_bit_column(column) {
            bit_columns.push(column.clone());
            bit_indices.push(index);
        } else {
            scalar_columns.push(column.clone());
        }
    }
    let bits = if bit_columns.is_empty() {
        None
    } else {
        Some(packed_bit_table(&bit_columns)?)
    };
    let scalars = if scalar_columns.is_empty() {
        None
    } else {
        Some(P3MosaicTable {
            columns: scalar_columns,
        })
    };
    Ok((bits, scalars, bit_indices))
}

/// Pack two 64-bit trace fields per cell (little-endian low field first).
///
/// The trace table holds eight 64-bit fields per row; two fit exactly in one
/// 128-bit cell, so the table halves.
pub(crate) fn pack_word_pairs(values: &[F2_128]) -> Result<Vec<F2_128>, ProofError> {
    if values.is_empty() || !values.len().is_multiple_of(2) {
        return Err(ProofError::Pcs(
            "word-pair packing needs a non-empty even number of fields".into(),
        ));
    }
    if values.iter().any(|value| value.value() >> 64 != 0) {
        return Err(ProofError::Pcs(
            "word-pair packing needs fields that fit in 64 bits".into(),
        ));
    }
    Ok(values
        .chunks(2)
        .map(|pair| {
            let low = pair[0].value();
            let high = pair[1].value();
            F2_128::from(low | (high << 64))
        })
        .collect())
}

/// Unpack two 64-bit fields per cell back to single fields.
pub(crate) fn unpack_word_pairs(packed: &[F2_128]) -> Vec<F2_128> {
    let mut values = Vec::with_capacity(packed.len() * 2);
    for value in packed {
        let word = value.value();
        values.push(F2_128::from(word & 0xFFFF_FFFF_FFFF_FFFF));
        values.push(F2_128::from(word >> 64));
    }
    values
}

/// M4a-packed twist tables: address table packed, scalar tables untouched.
pub(crate) fn pack_twist_tables(tables: &BatchTables) -> Result<Vec<P3MosaicTable>, ProofError> {
    let mut packed = Vec::with_capacity(5);
    packed.push(packed_bit_table(&tables.addr.columns)?);
    packed.push(tables.inc.clone());
    packed.push(tables.initial.clone());
    packed.push(tables.read_value.clone());
    packed.push(tables.write_value.clone());
    Ok(packed)
}

/// The Access batch after M4a: three scalar columns plus one packed bit table.
///
/// The bit table is built from the same witness bits as the mosaic address
/// table, in the Access batch's column order (`read bits, read valid, write
/// bits, write valid`), so the two consumers can share a single commitment.
pub(crate) struct PackedAccessBatch {
    pub scalars: Vec<Vec<F2_128>>,
    pub bits: P3MosaicTable,
    pub columns_before: usize,
}

pub(crate) fn pack_access_batch(
    witness: &BinaryTwistWitness,
) -> Result<PackedAccessBatch, ProofError> {
    let (read_bits, read_valid, _cycles) = crate::virtual_onehot::bit_columns_pub(witness, false);
    let (write_bits, write_valid, _cycles) = crate::virtual_onehot::bit_columns_pub(witness, true);
    let mut bit_columns = read_bits.clone();
    bit_columns.push(read_valid.clone());
    bit_columns.extend(write_bits.clone());
    bit_columns.push(write_valid.clone());
    let bits = packed_bit_table(&bit_columns)?;

    let cycles = witness.cycles.next_power_of_two().max(2);
    let mut inc = vec![F2_128::from(0u64); cycles];
    let copied = witness.cycles.min(cycles);
    inc[..copied].copy_from_slice(&witness.increment[..copied]);
    let mut read_value = witness.read_value.clone();
    read_value.resize(cycles, F2_128::from(0u64));
    let mut write_value = witness.write_value.clone();
    write_value.resize(cycles, F2_128::from(0u64));
    let scalars = vec![inc, read_value, write_value];
    let columns_before = 3 + bit_columns.len();
    Ok(PackedAccessBatch {
        scalars,
        bits,
        columns_before,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded_bits(len: usize, seed: u64) -> Vec<F2_128> {
        (0..len)
            .map(|index| {
                let mut state = (index as u64)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .wrapping_add(seed);
                state ^= state << 17;
                state ^= state >> 29;
                F2_128::from((state >> 7) & 1)
            })
            .collect()
    }

    #[test]
    fn bit_columns_round_trip_at_every_padding() {
        for len in [128usize, 256, 1000, 4096, 65536] {
            let column = seeded_bits(len, 0xABCD);
            let packed = pack_bit_column(&column).expect("pack");
            assert_eq!(packed.len(), len.div_ceil(PACK));
            let unpacked = unpack_bit_column(&packed, len);
            assert_eq!(unpacked, column, "pack must be lossless at len={len}");
        }
    }

    #[test]
    fn bit_columns_reject_non_bits() {
        let mut column = seeded_bits(256, 7);
        column[3] = F2_128::from(2u64);
        assert!(pack_bit_column(&column).is_err());
    }

    #[test]
    fn word_pairs_round_trip() {
        let values: Vec<F2_128> = (0..8)
            .map(|index| F2_128::from(0x1234_5678_9ABC_DEF0u64.wrapping_add(index as u64)))
            .collect();
        let packed = pack_word_pairs(&values).expect("pack");
        assert_eq!(packed.len(), 4);
        assert_eq!(unpack_word_pairs(&packed), values);
    }

    #[test]
    fn word_pairs_reject_wide_fields() {
        let values = vec![F2_128::from(1u128 << 64), F2_128::from(0u64)];
        assert!(pack_word_pairs(&values).is_err());
    }

    #[test]
    fn trace_word_pair_packing_is_not_evaluation_preserving() {
        use magnetar_proof::Mle;

        // A trace-shaped table: 8 rows x 8 fields, flattened into 64 values,
        // packed into 32 cells.
        let values: Vec<F2_128> = (0..64)
            .map(|index| F2_128::from(index as u64 * 3 + 1))
            .collect();
        let packed = pack_word_pairs(&values).expect("trace values fit 64 bits each");
        assert_eq!(packed.len(), 32);

        // Concatenation IS F2-linear on the bit pattern: packing a sum is the
        // sum of packings.
        let other: Vec<F2_128> = (0..64)
            .map(|index| F2_128::from(index as u64 * 5 + 7))
            .collect();
        let sum: Vec<F2_128> = values.iter().zip(&other).map(|(a, b)| *a + *b).collect();
        let packed_sum = pack_word_pairs(&sum).expect("sum stays in 64 bits");
        let packed_pair: Vec<F2_128> = pack_word_pairs(&values)
            .unwrap()
            .iter()
            .zip(pack_word_pairs(&other).unwrap())
            .map(|(a, b)| *a + b)
            .collect();
        assert_eq!(packed_sum, packed_pair, "concatenation is F2-linear");

        // But the multilinear extension does not commute with concatenation:
        // the trace claims live on log2(8C) variables, the packed table on
        // log2(4C), and no point of the packed table reproduces the trace
        // evaluation. This is why a packed trace table cannot feed the trace
        // claims without a new argument.
        let trace_point: Vec<F2_128> = (0..6)
            .map(|bit| F2_128::from(((bit * 7 + 3) % 2) as u64))
            .collect();
        let trace_claim = Mle::new(values.clone()).expect("mle").eval(&trace_point).expect("eval");
        let mut packed_point = trace_point[..5].to_vec();
        let packed_claim = Mle::new(packed.clone()).expect("mle").eval(&packed_point).expect("eval");
        assert_ne!(
            trace_claim, packed_claim,
            "packing must change the MLE; otherwise the trace claims would carry over"
        );
        // Shifting the point does not recover it either: the packed polynomial
        // has one variable fewer, so there is no relabelling that maps its
        // evaluation onto the trace's.
        for offset in [0usize, 1] {
            let shifted = trace_point[offset..offset + 5].to_vec();
            let folded = Mle::new(packed.clone()).expect("mle").eval(&shifted).expect("eval");
            assert_ne!(folded, trace_claim, "no relabelled point reproduces the trace evaluation");
        }

        // The clean way to halve the trace table is the 64-bit committed
        // alphabet (M4b): it keeps the evaluation a field-linear map (challenges
        // stay 128-bit), so the trace claims keep their meaning. Concatenating
        // two 64-bit fields per cell cannot do that, as the mismatch above
        // shows.
    }

    #[test]
    fn split_and_pack_keeps_scalars_and_packs_bits() {
        let bits = vec![seeded_bits(512, 1), seeded_bits(512, 2)];
        let scalars: Vec<F2_128> = (0..512).map(|index| F2_128::from(index as u64 * 3)).collect();
        let table = P3MosaicTable {
            columns: vec![bits[0].clone(), scalars, bits[1].clone()],
        };
        let (packed_bits, scalar_table, indices) = split_and_pack(&table).expect("split");
        assert_eq!(indices, vec![0, 2]);
        let packed_bits = packed_bits.expect("bits");
        let scalar_table = scalar_table.expect("scalars");
        assert_eq!(packed_bits.columns.len(), 2);
        assert_eq!(packed_bits.columns[0].len(), 4);
        assert_eq!(scalar_table.columns.len(), 1);
        assert_eq!(unpack_bit_column(&packed_bits.columns[0], 512), bits[0]);
        assert_eq!(unpack_bit_column(&packed_bits.columns[1], 512), bits[1]);
        assert_eq!(scalar_table.columns[0][511], F2_128::from(511u64 * 3));
    }
}
