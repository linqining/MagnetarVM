//! Packed-mosaic plan: bit-valued table columns packed 128 bits per cell.
//!
//! The mosaic commits every table column as one field element per row, so a
//! bit-valued column (the twist address tables, the ROM bit columns) spends
//! 128 bits of commitment per bit. This module builds the packed plan: each
//! table's bit-valued columns are packed 128:1 into one packed table, the
//! scalar columns stay as they are, and the plan records the mapping the
//! verifier needs to ring-switch a bit claim to a claim on the packed table.
//!
//! The plan is representation-only; wiring it into the prover/verifier is the
//! packed-mosaic redesign (the verifier must ring-switch every bit claim before
//! the mosaic opening).

use magnetar_constraint::F2_128;

use crate::P3MosaicTable;

/// Bits stored in one packed cell.
pub const PACK: usize = 128;

/// One table after packing.
pub struct PackedTable {
    /// The packed table (bit columns packed, scalar columns unchanged).
    pub table: P3MosaicTable,
    /// Original column indices that were packed, in packed-column order.
    pub bit_columns: Vec<usize>,
    /// Original row count (the packed columns have `rows.div_ceil(PACK)` cells).
    pub rows: usize,
}

/// Where one original table's columns went in the packed plan.
pub struct TableMapping {
    /// Index of the packed bit table (if the table had bit columns).
    pub packed_table: Option<usize>,
    /// Index of the scalar table (if the table had scalar columns).
    pub scalar_table: Option<usize>,
    /// Original column indices that were packed, in packed-column order.
    pub bit_columns: Vec<usize>,
    /// Original column indices kept as scalars, in scalar-column order.
    pub scalar_columns: Vec<usize>,
    /// Whether the table's single column was word-pair packed (the trace).
    pub word_pairs: bool,
}

/// The packed plan for a mosaic table set.
pub struct PackedMosaicPlan {
    pub tables: Vec<PackedTable>,
    pub mapping: Vec<TableMapping>,
    pub unpacked_cells: usize,
    pub packed_cells: usize,
}

fn is_bit_column(column: &[F2_128]) -> bool {
    column.iter().all(|value| value.value() <= 1)
}

/// Pack one bit column 128 bits per cell (lowest bit first).
pub fn pack_bit_column(column: &[F2_128]) -> Vec<F2_128> {
    column
        .chunks(PACK)
        .map(|chunk| {
            let mut word: u128 = 0;
            for (index, value) in chunk.iter().enumerate() {
                if value.value() & 1 == 1 {
                    word |= 1u128 << index;
                }
            }
            F2_128::from(word)
        })
        .collect()
}

/// Pack two 64-bit fields per cell (little-endian low field first).
pub fn pack_word_pairs(values: &[F2_128]) -> Vec<F2_128> {
    values
        .chunks(2)
        .map(|pair| {
            let low = pair[0].value();
            let high = pair.get(1).map_or(0, |value| value.value());
            F2_128::from(low | (high << 64))
        })
        .collect()
}

/// Build the packed plan for a table set, packing the trace table's word pairs.
///
/// The trace table is one column of eight 64-bit fields per cycle; two fields
/// fit in one 128-bit cell, so it halves. Other tables pack their bit-valued
/// columns 128:1 as in [`plan`].
pub fn plan_with_trace(tables: &[P3MosaicTable], trace_index: usize) -> PackedMosaicPlan {
    let mut plan = plan(tables);
    if let Some(table) = plan.tables.get_mut(trace_index) {
        if table.table.columns.len() == 1 {
            let packed = pack_word_pairs(&table.table.columns[0]);
            plan.packed_cells -= table.table.columns[0].len();
            plan.packed_cells += packed.len();
            table.table.columns = vec![packed];
            if let Some(mapping) = plan.mapping.get_mut(trace_index) {
                mapping.word_pairs = true;
            }
        }
    }
    plan
}

/// Build the packed plan for a table set.
pub fn plan(tables: &[P3MosaicTable]) -> PackedMosaicPlan {
    let mut packed_tables = Vec::with_capacity(tables.len());
    let mut mapping = Vec::with_capacity(tables.len());
    let mut unpacked_cells = 0usize;
    let mut packed_cells = 0usize;
    for table in tables {
        let rows = table.columns.first().map_or(0, |column| column.len());
        unpacked_cells += rows * table.columns.len();
        let mut bit_columns = Vec::new();
        let mut packed_columns = Vec::new();
        let mut scalar_columns = Vec::new();
        for (index, column) in table.columns.iter().enumerate() {
            if is_bit_column(column) {
                bit_columns.push(index);
                packed_columns.push(pack_bit_column(column));
            } else {
                scalar_columns.push(column.clone());
            }
        }
        // The PCS needs at least two cells per column, so tiny bit tables stay
        // unpacked.
        if !packed_columns.is_empty() && packed_columns[0].len() < 2 {
            for (index, column) in table.columns.iter().enumerate() {
                if bit_columns.contains(&index) {
                    scalar_columns.push(column.clone());
                }
            }
            bit_columns.clear();
            packed_columns.clear();
        }
        // A mosaic table needs equally long columns, so a mixed table splits
        // into a packed bit table and a scalar table.
        let mut packed_table = None;
        let mut scalar_table = None;
        let mut scalar_columns_out = Vec::new();
        if !packed_columns.is_empty() {
            packed_cells += packed_columns[0].len() * packed_columns.len();
            packed_table = Some(packed_tables.len());
            packed_tables.push(PackedTable {
                table: P3MosaicTable {
                    columns: packed_columns,
                },
                bit_columns: bit_columns.clone(),
                rows,
            });
        }
        if !scalar_columns.is_empty() {
            packed_cells += rows * scalar_columns.len();
            scalar_table = Some(packed_tables.len());
            packed_tables.push(PackedTable {
                table: P3MosaicTable {
                    columns: scalar_columns,
                },
                bit_columns: Vec::new(),
                rows,
            });
            // Recover the original scalar column indices in order.
            for (index, column) in table.columns.iter().enumerate() {
                if !bit_columns.contains(&index) {
                    scalar_columns_out.push(index);
                }
            }
        }
        mapping.push(TableMapping {
            packed_table,
            scalar_table,
            bit_columns,
            scalar_columns: scalar_columns_out,
            word_pairs: false,
        });
    }
    PackedMosaicPlan {
        tables: packed_tables,
        mapping,
        unpacked_cells,
        packed_cells,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packing_is_lossless_and_shrinks_bit_tables() {
        let rows = 256usize;
        let bits: Vec<F2_128> = (0..rows)
            .map(|index| F2_128::from(((index * 7 + 3) % 2) as u64))
            .collect();
        let scalars: Vec<F2_128> = (0..rows).map(|index| F2_128::from(index as u64)).collect();
        let table = P3MosaicTable {
            columns: vec![bits.clone(), scalars.clone()],
        };
        let plan = plan(&[table]);
        assert_eq!(plan.unpacked_cells, rows * 2);
        // 256 bits -> 2 packed cells, plus 256 scalar cells, in two tables.
        assert_eq!(plan.packed_cells, 2 + rows);
        assert_eq!(plan.tables.len(), 2);
        assert_eq!(plan.tables[0].bit_columns, vec![0]);
        assert_eq!(plan.tables[0].table.columns.len(), 1);
        assert_eq!(plan.tables[0].table.columns[0].len(), 2);
        assert_eq!(plan.tables[1].table.columns.len(), 1);
        assert_eq!(plan.tables[1].table.columns[0].len(), rows);
        let mapping = &plan.mapping[0];
        assert_eq!(mapping.packed_table, Some(0));
        assert_eq!(mapping.scalar_table, Some(1));
        assert_eq!(mapping.bit_columns, vec![0]);
        assert_eq!(mapping.scalar_columns, vec![1]);
    }
}
