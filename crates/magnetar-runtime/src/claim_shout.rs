//! M4a skeleton: committed Shout (BinaryShout-against-T, no pushforwards).
//!
//! Design: `docs/POLYLOG_CLAIM_VERIFIER.md` §C. The plan replaces the per-cycle
//! witness rebuild of the trace Logup-Shout verifier with an evaluation of a
//! committed Shout table:
//!
//! * the Shout boolean columns (`address0`/`address1` bits, `is_32`, `valid`,
//!   the 12 link columns) are appended to the claim table `T_bits` (host-side
//!   data columns), so every claim the BinaryShout sum-checks make is discharged
//!   by the existing ring-switch claim-table opening;
//! * the claim instruction word per cycle is one dense `F2_128` column committed
//!   with `P3BinaryPcs` (`T_field`), giving the reader-value binding without a
//!   2^address_bits pushforward vector (which would cost 1 MB on the synthetic
//!   2^16 benchmark);
//! * the code reuses `binary_shout`'s Boolean/read sum-checks, bound to a
//!   synthetic `P3MosaicCommitment` derived from the real claim-table
//!   commitments (the E5 binding pattern), so the transcript matches both sides.
//!
//! Status: skeleton. The proof/verify plumbing is present; the claim-table
//! relation that discharges the BinaryShout evals against `T_bits` and the
//! public-ROM word check are marked TODO(M4a) and will be completed together
//! with the first build window. The whole path is gated by
//! `MAGNETAR_COMMITTED_SHOUT=1` (default off), so the committed default path is
//! untouched.

use magnetar_constraint::F2_128;
use magnetar_pcs::{P3BinaryPcs, P3Commitment, P3MosaicCommitment, P3Opening};
use magnetar_proof::Pcs;

use crate::{claim_table, RuntimeError};

/// Domain for the synthetic BinaryShout commitment binding.
const SHOUT_BINDING_DOMAIN: &[u8] = b"magnetar-committed-shout-v1";
/// Domain for the extended (`T_bits` + `T_field`) claim-table root.
const CLAIM_TABLE_V2_DOMAIN: &[u8] = b"magnetar-claim-table-v2";

/// Is the committed-Shout path enabled? Default off (opt-in while M4a is being
/// brought up). `MAGNETAR_COMMITTED_SHOUT=1|on|true|yes` enables it.
pub fn committed_shout_enabled() -> bool {
    match std::env::var("MAGNETAR_COMMITTED_SHOUT") {
        Ok(value) => matches!(value.as_str(), "1" | "on" | "true" | "yes"),
        Err(_) => false,
    }
}

/// Should the legacy trace Logup-Shout path be used even when the committed
/// Shout proof is available? `MAGNETAR_CLASSIC_LOGUP=1` forces it, which is the
/// regression switch required for the M4a A/B.
pub fn classic_logup_enabled() -> bool {
    match std::env::var("MAGNETAR_CLASSIC_LOGUP") {
        Ok(value) => matches!(value.as_str(), "1" | "on" | "true" | "yes"),
        Err(_) => false,
    }
}

/// PCS backend for the dense claim-word column (`T_field`). One column only, so
/// the commit is trivial; rate 1/8 keeps the opening small.
pub fn claim_field_backend() -> P3BinaryPcs {
    P3BinaryPcs::with_params(100, 3, 20, 3)
}

/// Shout witness columns, as boolean bit vectors over cycles, plus the dense
/// per-cycle claim instruction word.
pub struct ShoutColumns {
    pub address_bits: usize,
    pub address0: Vec<Vec<bool>>,
    pub address1: Vec<Vec<bool>>,
    pub is_32: Vec<bool>,
    pub valid: Vec<bool>,
    /// The 12 link columns (`link_columns()` order: 4 store-width one-hot + 8
    /// shift-code bits).
    pub link: Vec<Vec<bool>>,
    pub word: Vec<F2_128>,
}

impl ShoutColumns {
    /// Number of boolean data columns appended to the claim table.
    pub fn data_column_count(&self) -> usize {
        2 * self.address_bits + 2 + 12
    }

    pub fn column(&self, index: usize) -> Result<&[bool], RuntimeError> {
        let a = self.address_bits;
        if index < a {
            return Ok(&self.address0[index]);
        }
        if index < 2 * a {
            return Ok(&self.address1[index - a]);
        }
        match index - 2 * a {
            0 => Ok(&self.is_32),
            1 => Ok(&self.valid),
            link if link - 2 < 12 => Ok(&self.link[link - 2]),
            _ => Err(RuntimeError::Proof("shout data column out of range".into())),
        }
    }
}

/// Build the host-side Shout data columns from a trace.
///
/// Word mode only (all instructions 4 bytes, the paper-path benchmark shape);
/// compressed traces keep the classic Logup-Shout path.
pub fn shout_columns(trace: &magnetar_spec::Trace) -> Result<ShoutColumns, RuntimeError> {
    if !trace.rows.iter().all(|row| row.instruction_len == 4) {
        return Err(RuntimeError::Proof(
            "M4a committed Shout requires word mode (4-byte instructions)".into(),
        ));
    }
    let witness = crate::binary_shout::BinaryShoutWitness::from_trace(trace)
        .map_err(|error| RuntimeError::Proof(format!("committed Shout witness: {error}")))?;
    let cycles = witness.cycles;
    let to_bits = |column: &[F2_128]| -> Vec<bool> {
        column.iter().map(|value| value.value() == 1).collect()
    };
    let address0 = witness
        .address0
        .iter()
        .map(|column| to_bits(column))
        .collect::<Vec<_>>();
    let address1 = witness
        .address1
        .iter()
        .map(|column| to_bits(column))
        .collect::<Vec<_>>();
    let link = witness
        .link_columns()
        .iter()
        .map(|column| to_bits(column))
        .collect::<Vec<_>>();
    if address0.len() != witness.address_bits
        || address1.len() != witness.address_bits
        || link.len() != 12
    {
        return Err(RuntimeError::Proof("committed Shout column shape".into()));
    }
    let mut word = vec![F2_128::from(0u64); cycles];
    for (cycle, row) in trace.rows.iter().enumerate() {
        word[cycle] = F2_128::from(u64::from(row.instruction_word));
    }
    Ok(ShoutColumns {
        address_bits: witness.address_bits,
        address0,
        address1,
        is_32: to_bits(&witness.is_32),
        valid: to_bits(&witness.valid),
        link,
        word,
    })
}

/// Pack `[claim schema columns | shout data columns]` into one bit table.
///
/// The slot layout is the claim-table layout for the schema slots followed by
/// the fixed Shout order `[address0, address1, is_32, valid, link]`; this order
/// is what [`data_slot`] and the verifier use.
pub fn extended_claim_bits(
    columns: &claim_table::ClaimTableColumns,
    shout: &ShoutColumns,
) -> (magnetar_proof::PackedBits, usize) {
    let slot_bits = claim_table::slot_bits_for(
        columns.columns.len() + shout.data_column_count(),
        columns.cycles,
    );
    let slots = 1usize << slot_bits;
    let total_columns = columns.columns.len() + shout.data_column_count();
    let mut values = vec![vec![false; columns.cycles]; slots];
    for (slot, column) in columns.slots.iter().enumerate() {
        values[slot].copy_from_slice(column);
    }
    for index in 0..shout.data_column_count() {
        let column = shout.column(index).expect("shout data column");
        values[columns.columns.len() + index].copy_from_slice(column);
    }
    let _ = total_columns;
    // Pack word-aligned columns directly (cycles is a power of two >= 64 in
    // practice; small traces take the per-bit path).
    let mut bits = magnetar_proof::PackedBits::zeroed(slots * columns.cycles);
    if columns.cycles % 64 == 0 {
        let words_per_column = columns.cycles / 64;
        let words = bits.words_mut();
        for (slot, value) in values.iter().enumerate() {
            let base = slot * words_per_column;
            for (word_index, word) in words[base..base + words_per_column]
                .iter_mut()
                .enumerate()
            {
                let mut packed = 0u64;
                for bit in 0..64 {
                    if value[word_index * 64 + bit] {
                        packed |= 1u64 << bit;
                    }
                }
                *word = packed;
            }
        }
    } else {
        for (slot, value) in values.iter().enumerate() {
            let base = slot * columns.cycles;
            for (row, bit) in value.iter().enumerate() {
                if *bit {
                    bits.set(base + row, true);
                }
            }
        }
    }
    (bits, slots)
}

/// Slot of the `index`-th Shout data column in the extended claim table.
pub fn data_slot(columns: &claim_table::ClaimTableColumns, index: usize) -> usize {
    columns.columns.len() + index
}

/// Commit the dense claim-word column (`T_field`).
pub fn commit_field_column(word: &[F2_128]) -> Result<P3Commitment, RuntimeError> {
    claim_field_backend()
        .commit(word)
        .map_err(|error| RuntimeError::Proof(format!("claim field commit: {error}")))
}

/// Root of the dense `T_field` commitment.
pub fn field_root(commitment: &P3Commitment) -> [u8; 32] {
    let mut bytes = CLAIM_TABLE_V2_DOMAIN.to_vec();
    bytes.extend_from_slice(b"field");
    bytes.extend_from_slice(&bincode::serialize(commitment).unwrap_or_default());
    magnetar_transcript::sha256(&bytes)
}

/// Extended claim-table root: binds the boolean table and the dense claim-word
/// column together. This is the value composed into the statement root.
pub fn extended_table_root(bits_commitment: &P3Commitment, field: &P3Commitment) -> [u8; 32] {
    let mut bytes = CLAIM_TABLE_V2_DOMAIN.to_vec();
    bytes.extend_from_slice(&bincode::serialize(bits_commitment).unwrap_or_default());
    bytes.extend_from_slice(&bincode::serialize(field).unwrap_or_default());
    magnetar_transcript::sha256(&bytes)
}

/// Synthetic mosaic commitment for the BinaryShout sum-checks, bound to the
/// real claim-table commitments (E5 pattern: the shape is derived from the
/// claimed table, the cap from the packed commitment, and `binding` hashes both
/// so neither side can swap the table).
pub fn synthetic_commitment(
    bits_commitment: &P3Commitment,
    field_commitment: &P3Commitment,
    address_bits: usize,
    cycle_bits: usize,
    table_root: &[u8; 32],
) -> P3MosaicCommitment {
    let total_columns = 2 * address_bits + 2 + 12;
    let binding = {
        let mut bytes = SHOUT_BINDING_DOMAIN.to_vec();
        bytes.extend_from_slice(table_root);
        bytes.extend_from_slice(&bincode::serialize(field_commitment).unwrap_or_default());
        magnetar_transcript::sha256(&bytes)
    };
    P3MosaicCommitment {
        cap: bits_commitment.cap.clone(),
        tables: vec![magnetar_pcs::P3MosaicTableShape {
            num_variables: cycle_bits,
            num_columns: total_columns,
        }],
        stacked_variables: cycle_bits,
        binding,
    }
}

/// The committed-Shout proof (M4a skeleton).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CommittedShoutProof {
    /// BinaryShout Boolean/read sum-checks against [`synthetic_commitment`].
    pub proof: crate::binary_shout::BinaryShoutProof,
    /// Reader point (cycles) used by the Boolean/read sum-checks; also the
    /// opening point of `T_field.word`.
    pub reader_point: Vec<F2_128>,
    /// PCS opening of the dense claim-word column at `reader_point`; the
    /// verifier checks `claimed_read` against this value and the claim table
    /// commitment.
    pub field_opening: Option<P3Opening>,
    /// Extended claim-table root bound by the statement.
    pub table_root: [u8; 32],
    /// TODO(M4a): relation proof discharging the BinaryShout evals against the
    /// committed claim-table columns, plus the position/valid/is_32 relations.
    pub table_relation: Option<claim_table::ClaimRelationProof>,
}

// Same equivalence convention as `ClaimTableProof`: the PCS opening types do
// not implement `PartialEq`, so compare the canonical bincode encoding (every
// field round-trips through serde).
impl PartialEq for CommittedShoutProof {
    fn eq(&self, other: &Self) -> bool {
        bincode::serialize(self).ok() == bincode::serialize(other).ok()
    }
}

impl Eq for CommittedShoutProof {}

impl CommittedShoutProof {
    /// Marked as a pre-M4 proof when a verifier expects committed Shout.
    pub const PRE_M4_ERROR: &'static str =
        "pre-M4 proof: committed Shout proof missing (run with MAGNETAR_CLASSIC_LOGUP=1 for legacy)";
}

/// Prover entry point (M4a skeleton).
pub fn prove_committed_shout(
    trace: &magnetar_spec::Trace,
    _selected: &crate::SelectedCpuProof,
    binding: [u8; 32],
) -> Result<CommittedShoutProof, RuntimeError> {
    let _ = (trace, binding);
    Err(RuntimeError::Proof(
        "M4a committed Shout prover not wired yet (skeleton); use MAGNETAR_CLASSIC_LOGUP=1".into(),
    ))
}

/// Verifier entry point (M4a skeleton).
pub fn verify_committed_shout(
    proof: &CommittedShoutProof,
    _statement: &crate::Statement,
    _claim_table: &claim_table::ClaimTableProof,
) -> Result<(), RuntimeError> {
    let _ = proof;
    Err(RuntimeError::Proof(
        "M4a committed Shout verifier not wired yet (skeleton)".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace() -> magnetar_spec::Trace {
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 7,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        magnetar_executor::execute(
            &program,
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 100,
            },
        )
        .unwrap()
    }

    #[test]
    fn shout_columns_match_the_trace_words() {
        let trace = trace();
        let columns = shout_columns(&trace).unwrap();
        let cycles = trace.rows.len().next_power_of_two().max(2);
        assert_eq!(columns.valid.len(), cycles);
        assert_eq!(columns.is_32.len(), cycles);
        assert_eq!(columns.link.len(), 12);
        assert_eq!(columns.address0.len(), columns.address_bits);
        assert_eq!(columns.address1.len(), columns.address_bits);
        for (cycle, row) in trace.rows.iter().enumerate() {
            assert_eq!(
                columns.word[cycle],
                F2_128::from(u64::from(row.instruction_word))
            );
            assert_eq!(columns.valid[cycle], true);
        }
        // Padded cycles are invalid and read no word.
        for cycle in trace.rows.len()..cycles {
            assert!(!columns.valid[cycle]);
            assert_eq!(columns.word[cycle], F2_128::from(0u64));
        }
        // The link column set is boolean.
        assert!(columns
            .link
            .iter()
            .all(|column| column.iter().all(|bit| *bit == false || *bit == true)));
    }

    #[test]
    fn extended_table_appends_the_shout_data_columns() {
        let trace = trace();
        let base = claim_table::claim_table_columns(&trace).unwrap();
        let shout = shout_columns(&trace).unwrap();
        let data = shout.data_column_count();
        let (bits, slots) = extended_claim_bits(&base, &shout);
        let expected_slots = 1usize
            << claim_table::slot_bits_for(base.columns.len() + data, base.cycles);
        assert_eq!(slots, expected_slots);
        assert_eq!(bits.len(), slots * base.cycles);
        // The first schema columns are preserved at their slots.
        for (slot, column) in base.slots.iter().enumerate() {
            for (row, value) in column.iter().enumerate() {
                if *value {
                    assert!(bits.get(slot * base.cycles + row));
                }
            }
        }
        // Shout data starts at the slot after the schema columns.
        let valid_slot = data_slot(&base, 2 * shout.address_bits + 1);
        for (row, value) in shout.valid.iter().enumerate() {
            assert_eq!(bits.get(valid_slot * base.cycles + row), *value);
        }
        assert_eq!(
            data_slot(&base, 0),
            base.columns.len(),
        );
    }

    #[test]
    fn committed_shout_switches_are_off_by_default() {
        // The skeleton must not change the default path.
        assert!(!committed_shout_enabled() || std::env::var_os("MAGNETAR_COMMITTED_SHOUT").is_some());
        assert!(!classic_logup_enabled() || std::env::var_os("MAGNETAR_CLASSIC_LOGUP").is_some());
    }
}
