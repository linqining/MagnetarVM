//! M5c: complete statement-only v4 verifier.
//!
//! The v4 statement binds the claim table commitment (no row Merkle root/blob),
//! the M4b committed Shout tables and the M5b committed final-RAM table in one
//! three-component root. This module replaces the former M5/M5b verifier gate
//! with the full statement-only check:
//!
//! 1. root binding: recompose the v4 root from the proof-carried commitments and
//!    compare it with the public statement (claim / shout / final table);
//! 2. witness-free access layer (M5b): twist proofs + public initial RAM +
//!    committed final-RAM relation, including the access statement digest;
//! 3. claim layer: the claim table relation folds the target against the
//!    committed claim columns; the resulting dynamic claim binds the selected
//!    lockstep proof (proof-only, no rows);
//! 4. Shout/ROM: the committed linear Shout (M4b) verifies the ROM against the
//!    public `statement.rom` (O(rom)); the legacy witnessed path is rejected
//!    when the linear path is enabled;
//! 5. core layer: CPU/gated/opening/aux checks (`verify_core_proof_inner`);
//! 6. endpoints/IO O(1): selected initial/final PC against the statement
//!    states, cycle count against `trace_len`, program hash against the ROM.
//!    `output`/`input`/`halted`/`exit_code` are public statement inputs in the
//!    proof-only model, matching the legacy statement-only verifier.

use crate::{RuntimeError, Statement, UnifiedTraceProof};

/// Verify a v4 (statement-only) unified proof end to end.
pub(crate) fn verify_native_unified_v4(
    statement: &Statement,
    proof: &UnifiedTraceProof,
    width: usize,
) -> Result<(), RuntimeError> {
    if proof.width != width {
        return Err(RuntimeError::Proof(
            "proof width does not match the requested width".into(),
        ));
    }
    // v4 requires the committed access columns: without them the final-RAM
    // table cannot bind the access layer witness-free.
    if !crate::access_table::access_columns_enabled() {
        return Err(RuntimeError::Proof(
            "M5 v4 verifier requires the committed access columns".into(),
        ));
    }
    let claims = proof
        .claim_proof
        .as_ref()
        .ok_or_else(|| RuntimeError::Proof("missing claim proof".into()))?;
    if !claims.is_v4_table_only() {
        return Err(RuntimeError::Proof(
            "M5 v4 mode: proof carries row claims (pre-M5 proof?)".into(),
        ));
    }
    let table = claims
        .table
        .as_ref()
        .ok_or_else(|| RuntimeError::Proof("missing claim table".into()))?;
    let selected = proof
        .selected_cpu
        .as_ref()
        .ok_or_else(|| RuntimeError::Proof("missing selected CPU proof".into()))?;

    // 1. Three-component v4 root binding.
    let claim_root = crate::claim_table::claim_table_root(&table.commitment);
    if claim_root != table.root {
        return Err(RuntimeError::Proof(
            "M5c: claim table root mismatch".into(),
        ));
    }
    let shout_root = proof
        .committed_logup_shout
        .as_ref()
        .map(|committed| {
            crate::logup_shout::committed_tables_root(&committed.table_commitment)
        })
        .unwrap_or([0u8; 32]);
    let final_root = proof
        .access_final
        .as_ref()
        .map(|final_proof| crate::access_verify::access_final_root(&final_proof.commitment))
        .unwrap_or([0u8; 32]);
    let expected_root =
        crate::claim_table::claim_shout_v4_root(&claim_root, &shout_root, &final_root);
    if expected_root != statement.trace_claim_root || proof.trace_claim_root != expected_root {
        return Err(RuntimeError::Proof(
            "M5c: committed v4 tables do not match the statement root".into(),
        ));
    }
    if proof.trace_commitment != statement.trace_commitment {
        return Err(RuntimeError::Proof(
            "M5c: trace commitment does not match the public statement".into(),
        ));
    }
    if statement.program_hash != crate::rom_hash(&statement.rom) {
        return Err(RuntimeError::Proof(
            "M5c: program hash does not match the public ROM".into(),
        ));
    }
    // The access statement digest is the O(1) derivation from the v4 claim table.
    if crate::access_table::access_statement_digest(&claim_root)
        != statement.access_statement_digest
    {
        return Err(RuntimeError::Proof(
            "M5c: access statement digest mismatch".into(),
        ));
    }

    // 2. O(1) endpoints: the selected lockstep binds the first/last PC.
    let trace_len = usize::try_from(statement.trace_len)
        .map_err(|_| RuntimeError::Proof("M5c: trace_len overflows usize".into()))?;
    let cycles = trace_len.next_power_of_two().max(2);
    if selected.cycles != cycles {
        return Err(RuntimeError::Proof(
            "M5c: selected cycle count does not match trace_len".into(),
        ));
    }
    if selected.initial_pc != statement.initial_state.pc
        || selected.final_pc != statement.final_state.pc
    {
        return Err(RuntimeError::Proof(
            "M5c: selected PC endpoints do not match the statement".into(),
        ));
    }
    if selected.width != width {
        return Err(RuntimeError::Proof(
            "M5c: selected proof width mismatch".into(),
        ));
    }

    // 3. Witness-free access layer (twist proofs, initial RAM, final table).
    crate::access_verify::verify_access_committed(statement, proof, &proof.commitment)?;

    // 4. Claim layer: target relation -> folded dynamic claim -> selected lockstep.
    let dynamic_claim = crate::claim_table::verify_claim_table_and_claim(table, selected, width)?;
    let backend = crate::protocol::selected_backend();
    crate::simd_dual::verify_dynamic_claim_binding_prepared(selected, &dynamic_claim, &backend)
        .map_err(|error| RuntimeError::Proof(format!("selected verifier: {error}")))?;

    // 5. Shout/ROM: v4 requires the committed linear Shout (M4b). The classic
    //    witnessed trace Logup-Shout proof cannot be checked without the
    //    claim-derived rows, so accepting a classic-mode v4 proof would skip the
    //    Shout argument entirely; reject it instead.
    let committed = proof.committed_logup_shout.as_ref().ok_or_else(|| {
        RuntimeError::Proof(
            "M5 v4 verifier requires the committed linear Shout (MAGNETAR_LINEAR_SHOUT=1)".into(),
        )
    })?;
    let rom_binding = crate::rom_hash(&statement.rom);
    crate::logup_shout::verify_committed_logup_shout(
        committed,
        &statement.rom,
        &rom_binding,
        statement.trace_len,
    )?;

    // 6. Core layer: CPU/gated/opening/aux (includes the classic packed Shout).
    crate::verify_core_proof_inner(proof, true)
        .map_err(|error| RuntimeError::Proof(format!("core verifier: {error}")))?;

    Ok(())
}
