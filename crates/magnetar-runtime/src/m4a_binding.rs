//! M4a statement-level dedup binding.
//!
//! When the register address table is dropped from the mosaic
//! (`magnetar_addr_dedup`), the address bits exist only as the packed-bit
//! commitment carried by the v5 Access proof. This module binds that
//! commitment into the statement root, mirroring the `access_final` mechanism:
//! a domain-separated digest of the commitment is composed on top of the
//! trace-derived statement root, so a proof built from a different witness (or
//! with a substituted packed commitment) no longer matches the statement.
//!
//! The digest is deterministic in the packed columns, so the trace-derived
//! side (statement) and the proof-derived side (verifier recomposition)
//! compute the same value for an honest proof.

use magnetar_pcs::P3BatchColumnPcs;
use magnetar_proof::BatchColumnPcs;
use magnetar_spec::Trace;

use crate::UnifiedTraceProof;

const BITS_DOMAIN: &[u8] = b"m4a-dedup-bits-v1";
const ROOT_DOMAIN: &[u8] = b"m4a-dedup-root-v1";

fn digest(commitment: &magnetar_pcs::P3BatchCommitment) -> [u8; 32] {
    let mut bytes = BITS_DOMAIN.to_vec();
    bytes.extend_from_slice(&bincode::serialize(commitment).unwrap_or_default());
    magnetar_transcript::sha256(&bytes)
}

/// Packed address-bit commitment digest derived from the trace.
///
/// This is the prover/statement side: it rebuilds the register witness from the
/// trace and commits the same packed columns the Access v5 proof commits.
pub fn bits_root_from_trace(trace: &Trace) -> Option<[u8; 32]> {
    let witness = crate::register_twist::register_twist_witness(trace).ok()?;
    let packed = crate::m4a_tables::pack_access_batch(&witness).ok()?;
    let backend = P3BatchColumnPcs::new(magnetar_pcs::P3BinaryPcs::with_params(100, 2, 21, 2));
    let commitment = backend.commit_columns(&packed.bits.columns).ok()?;
    Some(digest(&commitment))
}

/// Packed address-bit commitment digest carried by the proof.
pub fn bits_root_from_proof(proof: &UnifiedTraceProof) -> Option<[u8; 32]> {
    let linear = proof.access.registers.linear_m4a.as_ref()?;
    Some(digest(&linear.m4a.bits_commitment))
}

/// Compose the dedup root: `sha256(domain || base || bits_root)`.
pub fn bind_root(base: &[u8; 32], bits: &[u8; 32]) -> [u8; 32] {
    let mut bytes = ROOT_DOMAIN.to_vec();
    bytes.extend_from_slice(base);
    bytes.extend_from_slice(bits);
    magnetar_transcript::sha256(&bytes)
}

/// True when the statement root must carry the dedup binding.
pub(crate) fn dedup_enabled() -> bool {
    crate::binary_twist::m4a_addr_dedup()
}

/// Wrap a finished proof's statement root with the dedup binding.
pub(crate) fn bind_proof_root(proof: &mut UnifiedTraceProof) {
    if !dedup_enabled() {
        return;
    }
    let bits = bits_root_from_proof(proof).unwrap_or(MISSING_BITS);
    proof.trace_claim_root = bind_root(&proof.trace_claim_root, &bits);
}

/// The zero digest used when a dedup proof lacks the packed commitment.
pub(crate) const MISSING_BITS: [u8; 32] = [0u8; 32];

