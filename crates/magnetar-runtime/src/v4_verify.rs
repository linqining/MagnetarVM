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
    let stage = crate::verify_profile::Stage::new("v4 root");
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
    let mut expected_root =
        crate::claim_table::claim_shout_v4_root(&claim_root, &shout_root, &final_root);
    if crate::m4a_binding::dedup_enabled() {
        // M4a dedup: the packed address-bit commitment is bound as an extra
        // component, so the trace-free verifier recomposes the same root the
        // trace-derived statement carries.
        let bits = crate::m4a_binding::bits_root_from_proof(proof)
            .unwrap_or(crate::m4a_binding::MISSING_BITS);
        expected_root = crate::m4a_binding::bind_root(&expected_root, &bits);
    }
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
    let rom_binding = crate::rom_hash(&statement.rom);
    if statement.program_hash != rom_binding {
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

    stage.finish();

    // 2. O(1) endpoints: the selected lockstep binds the first/last PC.
    let stage = crate::verify_profile::Stage::new("v4 endpoints");
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

    stage.finish();

    // 3-6. One independent wave. The witness-free access layer, the claim
    // table relation, the selected-lockstep binding, the committed Shout and
    // the core proof each consume only the proof and the statement (the folded
    // claim below is derived from public/proof-carried data, not from a
    // verified claim table), so they can run on separate threads. They are
    // joined in the original serial order, so a failing proof still reports the
    // same first error. `MAGNETAR_VERIFY_SERIAL=1` restores the straight-line
    // order for a same-binary wall A/B.
    let serial = std::env::var_os("MAGNETAR_VERIFY_SERIAL").is_some();
    let backend = crate::protocol::selected_backend();
    let access = || {
        let stage = crate::verify_profile::Stage::new("v4 access");
        let result = crate::access_verify::verify_access_committed_with_claims(
            statement,
            proof,
            &proof.commitment,
        );
        stage.finish();
        result
    };
    let shout_check = || {
        let stage = crate::verify_profile::Stage::new("v4 committed shout");
        // v4 requires the committed linear Shout (M4b). The classic witnessed
        // trace Logup-Shout proof cannot be checked without the claim-derived
        // rows, so accepting a classic-mode v4 proof would skip the Shout
        // argument entirely; reject it instead.
        let committed = proof.committed_logup_shout.as_ref().ok_or_else(|| {
            RuntimeError::Proof(
                "M5 v4 verifier requires the committed linear Shout (MAGNETAR_LINEAR_SHOUT=1)"
                    .into(),
            )
        })?;
        let result = crate::logup_shout::verify_committed_logup_shout(
            committed,
            &statement.rom,
            &rom_binding,
            statement.trace_len,
        )
        .map(|_| ());
        stage.finish();
        result
    };
    let core_check = |access_claims| {
        let stage = crate::verify_profile::Stage::new("v4 core");
        let result = crate::verify_core_proof_inner_with_access_claims(
            proof,
            true,
            Some(access_claims),
        )
        .map_err(|error| RuntimeError::Proof(format!("core verifier: {error}")));
        stage.finish();
        result
    };

    if serial {
        // Straight-line order, identical to the pre-M6 verifier.
        let stage = crate::verify_profile::Stage::new("v4 claim inputs");
        let claim_inputs = crate::claim_table::claim_relation_inputs(selected, width)?;
        let dynamic_claim = crate::claim_table::folding_claim_from_inputs(&claim_inputs);
        stage.finish();
        let access_claims = access()?;
        let stage = crate::verify_profile::Stage::new("v4 claim table");
        let claim_result = crate::claim_table::verify_claim_table_with(table, &claim_inputs);
        stage.finish();
        claim_result?;
        let stage = crate::verify_profile::Stage::new("v4 selected binding");
        let selected_result = crate::simd_dual::verify_dynamic_claim_binding_prepared(
            selected,
            &dynamic_claim,
            &backend,
        )
        .map_err(|error| RuntimeError::Proof(format!("selected verifier: {error}")));
        stage.finish();
        selected_result?;
        shout_check()?;
        core_check(access_claims)?;
        return Ok(());
    }

    let (access_result, claim_result, selected_result, shout_result, core_result) =
        std::thread::scope(|scope| {
            // M6: the selected segment row/matrices are independent of the claim
            // table and the transcript, so build them on a worker thread while
            // the other checks run.
            let prepare = scope.spawn(|| crate::simd_dual::prepare_dynamic_segments(selected));
            // The access job hands the mosaic claims it derives to the core job:
            // the core verifier needs exactly them for the shared mosaic
            // opening, and re-deriving them would duplicate ~14 ms of CPU work.
            let (access_tx, access_rx) =
                std::sync::mpsc::channel::<(
                    crate::binary_twist::MosaicClaims,
                    crate::binary_twist::MosaicClaims,
                )>();
            let access = scope.spawn(move || {
                let stage = crate::verify_profile::Stage::new("v4 access");
                let result = crate::access_verify::verify_access_committed_with_claims(
                    statement,
                    proof,
                    &proof.commitment,
                )
                .map(|claims| {
                    let _ = access_tx.send(claims);
                });
                stage.finish();
                result
            });
            // The claim-derivation challenges are public/proof-carried; the
            // claim-table check and the selected binding are a conjunction, so
            // this job derives the folded claim once and hands it to the
            // selected job *before* its own (slow) opening check starts.
            let (claim_tx, claim_rx) =
                std::sync::mpsc::channel::<crate::simd_dual::DynamicClaim>();
            let claim_table = scope.spawn(move || {
                let stage = crate::verify_profile::Stage::new("v4 claim table");
                let inputs = crate::claim_table::claim_relation_inputs(selected, width)?;
                let dynamic_claim = crate::claim_table::folding_claim_from_inputs(&inputs);
                let _ = claim_tx.send(dynamic_claim);
                let result = crate::claim_table::verify_claim_table_with(table, &inputs);
                stage.finish();
                result
            });
            let selected_check = scope.spawn(move || {
                let stage = crate::verify_profile::Stage::new("v4 selected binding");
                let prepared = join_stage(prepare)?;
                let dynamic_claim = claim_rx.recv().map_err(|_| {
                    RuntimeError::Proof("claim derivation worker exited".into())
                })?;
                let result = crate::simd_dual::verify_prepared_dynamic_claim_binding(
                    selected,
                    &dynamic_claim,
                    &backend,
                    &prepared,
                )
                .map_err(|error| RuntimeError::Proof(format!("selected verifier: {error}")));
                stage.finish();
                result
            });
            let shout = scope.spawn(shout_check);
            let core = scope.spawn(move || {
                let claims = access_rx.recv().map_err(|_| {
                    RuntimeError::Proof("access verification did not provide claims".into())
                })?;
                core_check(claims)
            });
            (
                join_stage(access),
                join_stage(claim_table),
                join_stage(selected_check),
                join_stage(shout),
                join_stage(core),
            )
        });
    access_result?;
    claim_result?;
    selected_result?;
    shout_result?;
    core_result?;
    Ok(())
}

/// Join one spawned verifier stage, turning a panic into a proof error.
fn join_stage<T>(
    handle: std::thread::ScopedJoinHandle<'_, Result<T, RuntimeError>>,
) -> Result<T, RuntimeError> {
    handle
        .join()
        .map_err(|_| RuntimeError::Proof("verifier stage panicked".into()))?
}
