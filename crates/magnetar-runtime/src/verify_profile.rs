//! Verifier-stage instrumentation for the M6 latency work.
//!
//! Every stage print is env-gated by `MAGNETAR_PROFILE_VERIFY` and carries both
//! wall time and the process-wide cumulative CPU delta, so a stage's true cost
//! can be attributed even when the host is loaded (HANDOFF §6). The CPU delta is
//! process-wide, so for a stage that spawns workers it is the sum over threads,
//! not the critical path.

use std::time::Instant;

/// Whether verifier stage prints are enabled.
pub(crate) fn enabled() -> bool {
    std::env::var_os("MAGNETAR_PROFILE_VERIFY").is_some()
}

/// One measured verifier stage. Dropping without [`Stage::finish`] prints
/// nothing, so early-error returns never swallow a completed stage's timing.
pub(crate) struct Stage {
    label: &'static str,
    started: Instant,
    cpu: f64,
    active: bool,
}

impl Stage {
    pub(crate) fn new(label: &'static str) -> Self {
        Self {
            label,
            started: Instant::now(),
            cpu: magnetar_proof::process_cpu_seconds(),
            active: enabled(),
        }
    }

    /// Print this stage's wall and CPU cost (no-op unless profiling is on).
    pub(crate) fn finish(self) {
        if self.active {
            eprintln!(
                "verify profile {}: wall={:?} cpu={:.4}s",
                self.label,
                self.started.elapsed(),
                magnetar_proof::process_cpu_seconds() - self.cpu
            );
        }
    }
}
