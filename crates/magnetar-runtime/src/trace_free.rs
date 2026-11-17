//! Trace-free proof architecture switch.
//!
//! The paper's verifier is statement-only: it takes the public `Statement` and
//! the proof, and never rebuilds the trace or the twist witnesses. That mode is
//! assembled from three opt-in switches (`MAGNETAR_CLAIM_V4`,
//! `MAGNETAR_ACCESS_COLUMNS`, `MAGNETAR_LINEAR_SHOUT`). `MAGNETAR_TRACE_FREE=1`
//! turns the whole stack on as one coherent mode:
//!
//! * the prover emits the v4 artifacts (committed claim table, committed
//!   selected CPU, committed linear Shout, committed final-RAM table, packed
//!   address-bit commitment when dedup is on);
//! * `verify_native_unified(statement, proof, width)` is the only verifier;
//! * the trace-carrying entry points refuse to run, so a trace-free proof can
//!   never be silently checked by the trace path (and vice versa).
//!
//! The individual switches stay available for A/B; `MAGNETAR_CLASSIC_LOGUP=1`
//! still forces the classic wire and wins over this mode.

/// True when the trace-free architecture is requested.
pub fn trace_free_enabled() -> bool {
    matches!(
        std::env::var("MAGNETAR_TRACE_FREE").ok().as_deref(),
        Some("1" | "on" | "true" | "yes")
    )
}
