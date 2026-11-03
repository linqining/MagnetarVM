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
use magnetar_pcs::P3MosaicCommitment;

use crate::RuntimeError;

/// Explicit gate until M5b-2b commits the final-value table.
pub const FINAL_VALUE_PENDING: &str = "M5 v4 verifier pending: M5b-2b final-value table not committed";

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
    let _ram_claims = crate::binary_twist::verify_binary_twist_from_proof(
        &proof.access.ram,
        commitment,
        proof.ram_index,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?
    .ok_or_else(|| RuntimeError::Proof("M5b: RAM twist claims rejected".into()))?;
    let _register_claims = crate::binary_twist::verify_binary_twist_from_proof(
        &proof.access.registers,
        commitment,
        proof.register_index,
    )
    .map_err(|error| RuntimeError::Proof(error.to_string()))?
    .ok_or_else(|| RuntimeError::Proof("M5b: register twist claims rejected".into()))?;

    // 2. Initial RAM binding: public column folded at the twist cell point.
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

    // 3. Final-value binding needs the committed cells table (M5b-2b).
    let _ = evals.final_eval;
    Err(RuntimeError::Proof(FINAL_VALUE_PENDING.into()))
}
