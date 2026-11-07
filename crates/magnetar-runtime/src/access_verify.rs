//! M5b-2a: witness-free access verification (initial-RAM binding).
//!
//! Design: `docs/POLYLOG_CLAIM_VERIFIER.md` §C.12 + Lead decisions (M5b-2a/2b).
//!
//! The classic access verifier rebuilds a synthetic trace and the memory/register
//! twist witnesses from the claim rows, then compares the twist proof's
//! `initial_update_eval`/`final_eval` against those witnesses
//! (`verify_trace_access_shared`, 6.7 ms at 2^16). This module replaces the
//! witness side with the committed-claim path:
//!
//! * the twist proof is verified against the shared mosaic commitment without a
//!   witness (`verify_binary_twist_from_proof`);
//! * the initial RAM column is public statement data, rebuilt from
//!   `statement.initial_ram` in O(cells) and folded at the twist cell point `r_k`
//!   recovered by the M5b-2a read-only accessor;
//! * the final-value column is NOT public; it is committed as a separate packed
//!   bit table in M5b-2b (`T_final`, cells x 64 bits, Option A), so this module
//!   keeps an explicit gate until then. It never accepts an unbound final value.

use magnetar_constraint::F2_128;
use magnetar_pcs::{P3Commitment, P3MosaicCommitment};
use magnetar_proof::{BitPcs as _, PackedBits};

use crate::claim_shout::ShoutRelationProof;
use crate::RuntimeError;

/// Explicit gate while the committed access columns are off: the final-value
/// column is not public and is only bound once `T_final` is committed (M5b-2b).
pub const FINAL_VALUE_PENDING: &str = "M5 v4 verifier pending: M5b-2b final-value table not committed";

/// Gate after the witness-free access layer passes: the statement-only claim
/// relation / core / endpoint checks are M5c, not yet wired into the v4 path.
pub const V4_PENDING: &str =
    "M5 v4 verifier pending: statement-only claim relation and core checks not wired";

/// Slots of the final-RAM cell table: one packed bit column per value bit.
pub const FINAL_VALUE_SLOTS: usize = 64;

/// Root of the committed final-RAM cell table (domain-separated digest of the
/// packed-bit commitment).
pub fn access_final_root(commitment: &P3Commitment) -> [u8; 32] {
    let mut bytes = b"magnetar-access-final-v4".to_vec();
    bytes.extend_from_slice(&bincode::serialize(commitment).unwrap_or_default());
    magnetar_transcript::sha256(&bytes)
}

/// Padded row count of the committed final table.
///
/// The ring-switch backend packs 128 bits per field element and the P3 binary
/// PCS needs at least `2^3` fields, so the bit table must hold >= 1024 bits:
/// with 64 bit columns that means at least 16 cells. Zero-padded rows do not
/// change the MLE fold at `(cell point, 0, ..)`.
pub fn final_table_rows(cells: usize) -> usize {
    cells.next_power_of_two().max(16)
}

/// Pack the execution-derived final RAM words into `64 x rows` bit columns.
///
/// Flat bit index is `slot * rows + cell`, matching the claim table layout, so
/// the table MLE point is `(row coords, slot coords)`.
pub fn final_value_bits(final_values: &[F2_128]) -> PackedBits {
    let rows = final_table_rows(final_values.len());
    let slots = FINAL_VALUE_SLOTS;
    let mut bits = PackedBits::zeroed(slots * rows);
    for (cell, value) in final_values.iter().enumerate() {
        let raw = value.value();
        for bit in 0..FINAL_VALUE_SLOTS {
            if (raw >> bit) & 1 == 1 {
                bits.set(bit * rows + cell, true);
            }
        }
    }
    bits
}

/// Row point for the final table: the twist cell point plus the zero
/// coordinates of the zero-padded rows.
pub fn final_row_point(cell_point: &[F2_128]) -> Vec<F2_128> {
    let cells = 1usize << cell_point.len();
    let rows = final_table_rows(cells);
    let mut point = cell_point.to_vec();
    point.resize(rows.trailing_zeros() as usize, F2_128::from(0u64));
    point
}

/// Public coefficients of the final-value linear form: `2^bit`.
pub fn final_value_coeffs() -> Vec<F2_128> {
    (0..FINAL_VALUE_SLOTS)
        .map(|bit| F2_128::from(1u64 << bit))
        .collect()
}

/// M5b-2b: commit the final-RAM cell table and prove
/// `sum_bit 2^bit * fold(T_final_bit, r_k) = final_eval`.
pub fn prove_access_final(
    final_values: &[F2_128],
    cell_point: &[F2_128],
    final_eval: F2_128,
) -> Result<AccessFinalProof, RuntimeError> {
    if final_values.len() != 1usize << cell_point.len() {
        return Err(RuntimeError::Proof(
            "M5b: final-value column shape mismatch".into(),
        ));
    }
    let bits = final_value_bits(final_values);
    let commitment = crate::claim_shout::shout_backend()
        .commit(&bits)
        .map_err(|error| RuntimeError::Proof(format!("M5b final table commit: {error}")))?;
    let rows = final_table_rows(final_values.len());
    let row_point = final_row_point(cell_point);
    let relation = crate::claim_shout::prove_relation(
        &bits,
        &commitment,
        rows,
        FINAL_VALUE_SLOTS,
        &row_point,
        &final_value_coeffs(),
        final_eval,
    )?;
    Ok(AccessFinalProof {
        commitment,
        relation,
    })
}

/// The committed final-RAM table: commitment plus the linear relation binding
/// its bit folds at the twist cell point to the twist's `final_eval`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AccessFinalProof {
    pub commitment: P3Commitment,
    pub relation: ShoutRelationProof,
}

/// Rebuild the public initial-RAM column (one `F2_128` per 8-byte word).
///
/// Mirrors `BinaryTwistWitness::from_trace`: `initial[i]` is the little-endian
/// u64 of `initial_ram[8*i..8*i+8]`; missing bytes (short initial RAM) stay 0.
pub fn initial_ram_words(
    initial_ram: &[u8],
    ram_size: u64,
) -> Result<Vec<F2_128>, RuntimeError> {
    let cells = usize::try_from(ram_size / 8)
        .map_err(|_| RuntimeError::Proof("M5b: RAM size overflows usize".into()))?;
    if cells == 0 || !cells.is_power_of_two() {
        return Err(RuntimeError::Proof(
            "M5b: RAM must contain a power-of-two number of words".into(),
        ));
    }
    let mut words = vec![F2_128::from(0u64); cells];
    for (index, chunk) in initial_ram.chunks_exact(8).enumerate() {
        if index >= cells {
            break;
        }
        words[index] = F2_128::from(u64::from_le_bytes(
            chunk.try_into().expect("eight bytes"),
        ));
    }
    Ok(words)
}

/// MLE fold with the same coordinate order as `binary_twist::fold_all`.
fn fold_values(values: &[F2_128], challenges: &[F2_128]) -> Option<F2_128> {
    if values.len() != 1usize << challenges.len() {
        return None;
    }
    let mut buffer = values.to_vec();
    for &challenge in challenges {
        let half = buffer.len() / 2;
        for index in 0..half {
            let low = buffer[2 * index];
            let high = buffer[2 * index + 1];
            buffer[index] = low + challenge * (low + high);
        }
        buffer.truncate(half);
    }
    buffer.first().copied()
}

/// Witness-free access verification for the M5b v4 path (2a scope).
///
/// Verifies the RAM/register twist proofs against the shared mosaic commitment
/// and binds the twist's initial evaluation to the public initial RAM. Returns
/// the explicit M5b-2b gate for the final-value binding.
pub fn verify_access_committed(
    statement: &crate::Statement,
    proof: &crate::UnifiedTraceProof,
    commitment: &P3MosaicCommitment,
) -> Result<(), RuntimeError> {
    // 1. Proof-only twist verification (previously witness-based).
    let stage = crate::verify_profile::Stage::new("access ram twist");
    let _ram_claims = crate::binary_twist::verify_binary_twist_from_proof(
        &proof.access.ram,
        commitment,
        proof.ram_index,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?
    .ok_or_else(|| RuntimeError::Proof("M5b: RAM twist claims rejected".into()))?;
    stage.finish();
    let stage = crate::verify_profile::Stage::new("access register twist");
    let _register_claims = crate::binary_twist::verify_binary_twist_from_proof(
        &proof.access.registers,
        commitment,
        proof.register_index,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?
    .ok_or_else(|| RuntimeError::Proof("M5b: register twist claims rejected".into()))?;
    stage.finish();

    // 2. Initial RAM binding: public column folded at the twist cell point.
    let stage = crate::verify_profile::Stage::new("access initial ram");
    let evals = crate::binary_twist::binary_twist_public_evals(&proof.access.ram, commitment)
        .ok_or_else(|| RuntimeError::Proof("M5b: twist public evals unavailable".into()))?;
    if evals.address_bits != evals.cell_point.len() {
        return Err(RuntimeError::Proof(
            "M5b: twist cell point arity mismatch".into(),
        ));
    }
    let initial = initial_ram_words(&statement.initial_ram, statement.config.ram_size as u64)?;
    let initial_eval = fold_values(&initial, &evals.cell_point)
        .ok_or_else(|| RuntimeError::Proof("M5b: initial RAM fold shape mismatch".into()))?;
    if initial_eval != evals.initial_eval {
        return Err(RuntimeError::Proof(
            "M5b: initial RAM binding mismatch".into(),
        ));
    }

    stage.finish();

    // 3. Final-value binding: only possible once the access columns (and thus
    // the committed cells table) are enabled.
    if !crate::access_table::access_columns_enabled() {
        return Err(RuntimeError::Proof(FINAL_VALUE_PENDING.into()));
    }
    let final_proof = proof
        .access_final
        .as_ref()
        .ok_or_else(|| RuntimeError::Proof("M5b: final-RAM table is not committed".into()))?;

    // 3a. Statement binding: recompose the three-component v4 root from the
    // proof-carried commitments and compare it with the public statement.
    let claim_table_root = proof
        .claim_proof
        .as_ref()
        .and_then(|claims| claims.table.as_ref())
        .map(|table| crate::claim_table::claim_table_root(&table.commitment))
        .unwrap_or([0u8; 32]);
    let shout_tables_root = proof
        .committed_logup_shout
        .as_ref()
        .map(|committed| crate::logup_shout::committed_tables_root(&committed.table_commitment))
        .unwrap_or([0u8; 32]);
    let final_root = access_final_root(&final_proof.commitment);
    let expected_root = crate::claim_table::claim_shout_v4_root(
        &claim_table_root,
        &shout_tables_root,
        &final_root,
    );
    if expected_root != statement.trace_claim_root {
        return Err(RuntimeError::Proof(
            "M5b: committed access tables do not match the statement root".into(),
        ));
    }

    // 3b. `sum_bit 2^bit * fold(T_final_bit, r_k) == final_eval`.
    let stage = crate::verify_profile::Stage::new("access final relation");
    let row_point = final_row_point(&evals.cell_point);
    crate::claim_shout::verify_relation(
        &final_proof.relation,
        &final_proof.commitment,
        FINAL_VALUE_SLOTS,
        &row_point,
        &final_value_coeffs(),
        evals.final_eval,
    )?;
    stage.finish();
    Ok(())
}
