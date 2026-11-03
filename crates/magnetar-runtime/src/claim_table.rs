//! Committed claim columns and the polylog claim relation.
//!
//! The native verifier used to recompute the CPU claim sums from the
//! authenticated claim rows (`O(rows · columns)`). This module materializes the
//! same claim data as a *column-major packed bit table* (`T`), commits it with
//! the ring-switch packed-bit backend, and lets the verifier check one linear
//! relation
//!
//! ```text
//! Σ_slot  α^slot · MLE(T_slot)(z)  =  target
//! ```
//!
//! instead of summing every row. `target` is the claim target already bound to
//! the committed selected witness by the inner sum-check, and `z`/`α` are the
//! same challenges the selected verifier derives, so the relation ties the
//! committed witness to the committed claim columns without any per-row work.
//!
//! The relation is proven with a small sum-check over the slot dimension: the
//! prover folds each committed column at the row point `z` into one field
//! element `h_slot`, then proves `Σ α^slot · h_slot = target` with a degree-2
//! sum-check; the verifier's final check is a single ring-switch opening of `T`
//! at `(z, q*)`, where `q*` is the last sum-check challenge.
//!
//! The same table carries the column set the verifier needs for the Shout
//! bridge in the follow-up milestone (`position`/`word`/`link` columns); see
//! `docs/POLYLOG_CLAIM_VERIFIER.md`. M2/M3 only commit the claim schema
//! columns. Width is pinned to 64 (every proof path runs width 64); other
//! widths keep the legacy row-based verifier.

use magnetar_constraint::{Field, F2_128};
use magnetar_pcs::{P3BinaryPcs, P3Commitment, P3Opening};
use magnetar_proof::{
    prove, verify_rounds, BitPcs, PackedBits, RingSwitchOpening, RingSwitchPackedBitPcs,
    SumcheckProof,
};
use magnetar_transcript::Sha256Transcript;

use crate::{RuntimeError, SelectedCpuProof};

/// Domain for the claim-table commitment root.
const CLAIM_TABLE_DOMAIN: &[u8] = b"magnetar-claim-table-v1";
/// Domain for the composed `trace_claim_root` (legacy row root + table root).
const CLAIM_BINDING_DOMAIN: &[u8] = b"magnetar-claim-binding-v1";
/// Fiat–Shamir domain for a claim relation.
const CLAIM_REL_DOMAIN: &[u8] = b"magnetar-claim-rel-v1";

/// The polylog claim table is defined for the RV64 width only. Every proof
/// path in this workspace runs width 64 (see `docs/HANDOFF.md` §6); other
/// widths keep the legacy row-sum verifier.
pub const CLAIM_TABLE_WIDTH: usize = 64;

/// PCS backend for the claim table.
///
/// The claim table is tiny compared to the selected witness (a few MB of
/// codeword), so the proof size, not the commit cost, is what matters: a
/// rate-1/8 code cuts the opening to roughly a third of the rate-1/2 proof at
/// the same security target. Verification cost is unchanged within noise.
pub fn claim_table_backend() -> RingSwitchPackedBitPcs<P3BinaryPcs> {
    RingSwitchPackedBitPcs::new(P3BinaryPcs::with_params(100, 3, 20, 3))
}

/// One packed-bit opening plus the proof of a linear claim relation.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ClaimRelationProof {
    /// Slot-dimension sum-check: proves `Σ α^slot·h_slot = target`.
    pub sumcheck: SumcheckProof<F2_128>,
    /// Last sum-check challenge (slot point); replayed by the verifier.
    pub slot_point: Vec<F2_128>,
    /// Ring-switch opening of the claim table at `(row_point, slot_point)`.
    pub opening: RingSwitchOpening<P3Opening>,
}

/// The proof-carried claim table commitment and its claim relation.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ClaimTableProof {
    /// Ring-switch commitment to the packed claim table.
    pub commitment: P3Commitment,
    /// `claim_table_root(&commitment)`, recomputed by the verifier.
    pub root: [u8; 32],
    /// Padded slot count (power of two, includes zero padding columns).
    pub slots: usize,
    /// M2/M3 carry exactly one relation (the claim target); later milestones
    /// append the Shout bridge relations here.
    pub relations: Vec<ClaimRelationProof>,
}

// The PCS proof types (`P3Opening`, `RingSwitchOpening`) do not implement
// `PartialEq`, so equivalence is defined by the canonical bincode encoding:
// every field of these structs round-trips through serde, hence equal encodings
// imply equal values. This keeps `ClaimProof: PartialEq` (used by the claim
// proof round-trip test) without changing anything in `magnetar-pcs`.
impl PartialEq for ClaimRelationProof {
    fn eq(&self, other: &Self) -> bool {
        bincode::serialize(self).ok() == bincode::serialize(other).ok()
    }
}

impl Eq for ClaimRelationProof {}

impl PartialEq for ClaimTableProof {
    fn eq(&self, other: &Self) -> bool {
        bincode::serialize(self).ok() == bincode::serialize(other).ok()
    }
}

impl Eq for ClaimTableProof {}

/// Column-major claim data: `slots[slot][row]` is the claimed bit of the
/// `slot`-th canonical claim column.
pub struct ClaimTableColumns {
    pub mask: u8,
    pub cycles: usize,
    pub columns: Vec<usize>,
    pub slots: Vec<Vec<bool>>,
}

impl ClaimTableColumns {
    /// Number of padded slots (a power of two, at least enough for the
    /// ring-switch packing to accept the table).
    pub fn slot_count(&self) -> usize {
        1usize << slot_bits_for(self.columns.len(), self.cycles)
    }
}

/// Padding rule shared by prover and verifier: pad the slot dimension to a
/// power of two and keep the packed table large enough for both the
/// ring-switch packing (>= 256 bits) and the PCS folding factor (3): the
/// packed table needs at least `2^3 = 8` field elements, i.e. 1024 bits.
pub(crate) fn slot_bits_for(columns: usize, cycles: usize) -> usize {
    let mut slot_bits = 1usize;
    while (1usize << slot_bits) < columns {
        slot_bits += 1;
    }
    while (1usize << slot_bits).saturating_mul(cycles) < 1024 {
        slot_bits += 1;
    }
    slot_bits
}

/// Canonical claim columns for a trace, in claim-schema order.
pub fn claim_table_columns(
    trace: &magnetar_spec::Trace,
) -> Result<ClaimTableColumns, RuntimeError> {
    let (mask, cycles, columns, slots) =
        crate::simd_dual::dynamic_claim_column_bits(trace, CLAIM_TABLE_WIDTH)?;
    Ok(ClaimTableColumns {
        mask,
        cycles,
        columns,
        slots,
    })
}

/// Pack the column-major claim data into the ring-switch bit table. The flat
/// bit index is `slot * cycles + row`, so a multilinear point is
/// `(row coordinates, slot coordinates)`.
///
/// Cycles are a power of two, so for the usual `cycles >= 64` case each column
/// fills whole `u64` words and is written directly into the packed table (no
/// byte-per-bit intermediate); tiny tables fall back to per-bit writes.
pub fn claim_table_bits(columns: &ClaimTableColumns) -> PackedBits {
    let slots = columns.slot_count();
    let cycles = columns.cycles;
    let mut bits = PackedBits::zeroed(slots * cycles);
    if cycles % 64 == 0 {
        let words_per_column = cycles / 64;
        let words = bits.words_mut();
        for (slot, values) in columns.slots.iter().enumerate() {
            let base = slot * words_per_column;
            for (word_index, word) in words[base..base + words_per_column].iter_mut().enumerate() {
                let mut packed = 0u64;
                for bit in 0..64 {
                    if values[word_index * 64 + bit] {
                        packed |= 1u64 << bit;
                    }
                }
                *word = packed;
            }
        }
        return bits;
    }
    for (slot, values) in columns.slots.iter().enumerate() {
        let base = slot * cycles;
        for (row, value) in values.iter().enumerate() {
            if *value {
                bits.set(base + row, true);
            }
        }
    }
    bits
}

/// Commit the packed claim table.
pub fn commit_claim_table(bits: &PackedBits) -> Result<P3Commitment, RuntimeError> {
    claim_table_backend()
        .commit(bits)
        .map_err(|error| RuntimeError::Proof(format!("claim table commit: {error}")))
}

/// Root of the claim-table commitment (bound by the statement).
pub fn claim_table_root(commitment: &P3Commitment) -> [u8; 32] {
    let mut bytes = CLAIM_TABLE_DOMAIN.to_vec();
    bytes.extend_from_slice(&bincode::serialize(commitment).unwrap_or_default());
    magnetar_transcript::sha256(&bytes)
}

/// Legacy row-Merkle root of the claim rows.
pub fn claim_rows_root(trace: &magnetar_spec::Trace) -> [u8; 32] {
    crate::trace_claims::TraceClaimTree::build(trace).root()
}

/// Composed transition-period root: legacy row root and claim-table root.
///
/// Used by the statement constructor and the prover. M2/M3 keep the row root
/// in the binding because the claim rows are still consumed by the trace
/// Logup-Shout and access checks until those milestones replace them.
pub fn claim_binding_root_from_parts(rows_root: [u8; 32], table_root: &[u8; 32]) -> [u8; 32] {
    let mut bytes = CLAIM_BINDING_DOMAIN.to_vec();
    bytes.extend_from_slice(&rows_root);
    bytes.extend_from_slice(table_root);
    magnetar_transcript::sha256(&bytes)
}

/// Whether the committed claim table is enabled.
///
/// **Default: on.** On RV64 `2^16` measuring the same binary with the same
/// benchmark back to back: legacy claim row sums verify in 45.97 ms, the polylog
/// claim relation in 27.38 ms (-40 %) — the table replaces `O(rows)` row work
/// for +156,744 B of proof and +0.19 GiB peak. The 2^10 regression is a fixed
/// PCS cost that disappears at scale (see `docs/POLYLOG_CLAIM_VERIFIER.md` §B.5).
///
/// `MAGNETAR_CLAIM_TABLE=0|off|false` restores the legacy row path (legacy
/// statement root and wire format) for A/B; `MAGNETAR_CLAIM_ROWS=1` keeps the
/// table in the proof but verifies with the legacy per-row sums, isolating the
/// verifier change. Unit tests of this crate always exercise the enabled path.
pub fn claim_table_enabled() -> bool {
    match std::env::var("MAGNETAR_CLAIM_TABLE") {
        Ok(value) => !matches!(value.as_str(), "0" | "off" | "false"),
        Err(_) => true,
    }
}

/// Statement-side `trace_claim_root` used by `ReferencePipeline` and every
/// statement constructor: the composed claim-table binding when the claim
/// table is enabled (falling back to the legacy row root for traces the
/// dynamic claim layer cannot represent), the legacy row root otherwise.
/// Domain of the M4 v3 composed statement root.
const CLAIM_SHOUT_V3_DOMAIN: &[u8] = b"claim-shout-v3";

/// M4 v3 composed root: binds the M2/M3 claim table plus the batched committed
/// Shout tables (`T_word`, `T_pos`, `T_pf`), which share one PCS commitment.
pub fn claim_shout_v3_root(
    claim_binding_v1: &[u8; 32],
    tables_root: &[u8; 32],
) -> [u8; 32] {
    let mut bytes = CLAIM_SHOUT_V3_DOMAIN.to_vec();
    bytes.extend_from_slice(claim_binding_v1);
    bytes.extend_from_slice(tables_root);
    magnetar_transcript::sha256(&bytes)
}

pub fn statement_claim_root(trace: &magnetar_spec::Trace) -> [u8; 32] {
    if claim_table_enabled() && crate::logup_shout::linear_shout_enabled() {
        if let Ok(data) = crate::logup_shout::committed_statement_data(trace) {
            return data.statement_root;
        }
    }
    if claim_table_enabled() {
        // M4a: when the committed-Shout path is enabled the statement binds the
        // Shout/claim-word tables too (composed root); default off keeps the v1
        // root byte-identical.
        if crate::claim_shout::committed_shout_enabled() {
            if let Ok(root) = crate::claim_shout::claim_binding_root_with_shout(trace) {
                return root;
            }
        }
        claim_binding_root(trace).unwrap_or_else(|_| claim_rows_root(trace))
    } else {
        claim_rows_root(trace)
    }
}

/// Statement-side `trace_claim_root` for a trace.
pub fn claim_binding_root(trace: &magnetar_spec::Trace) -> Result<[u8; 32], RuntimeError> {
    let columns = claim_table_columns(trace)?;
    let bits = claim_table_bits(&columns);
    let commitment = commit_claim_table(&bits)?;
    let table_root = claim_table_root(&commitment);
    Ok(claim_binding_root_from_parts(
        claim_rows_root(trace),
        &table_root,
    ))
}

/// Shared challenges for the claim relation: the same row point and column
/// batching coefficient the selected verifier derives for the folded claim.
struct ClaimRelationInputs {
    matrix_cycles: usize,
    row_point: Vec<F2_128>,
    alpha: F2_128,
    gamma: F2_128,
    target: F2_128,
    selected_commitment: P3Commitment,
    schema: crate::simd_dual::DynamicClaimSchema,
    /// Public column coefficients, padded to the table's slot count:
    /// `coeffs[slot] = α^slot`, zero for padding and out-of-schema slots.
    coeffs: Vec<F2_128>,
}

fn claim_relation_inputs(
    selected: &SelectedCpuProof,
    width: usize,
) -> Result<ClaimRelationInputs, RuntimeError> {
    let binding = selected
        .claim_binding
        .as_ref()
        .ok_or_else(|| RuntimeError::Proof("claim table without a claim binding".into()))?;
    let matrix_cycles = if selected.matrix_cycles == 0 {
        selected.cycles
    } else {
        selected.matrix_cycles
    };
    let schema = crate::simd_dual::dynamic_claim_schema(selected.mask, width, matrix_cycles)?;
    if schema.root != binding.columns_root {
        return Err(RuntimeError::Proof(
            "dynamic claim column set mismatch".into(),
        ));
    }
    let target = binding.target;
    let selected_commitment = selected.proof.commitment.clone();
    let backend = crate::protocol::selected_backend();
    let commitment_bytes = backend.commitment_bytes(&selected_commitment);
    let row_bits = matrix_cycles.trailing_zeros() as usize;
    let (row_point, alpha, gamma) =
        crate::simd_dual::dynamic_claim_challenges(&commitment_bytes, &schema.root, row_bits);
    let slots = 1usize << slot_bits_for(schema.columns.len(), matrix_cycles);
    let mut coeffs = vec![F2_128::from(0u64); slots];
    let mut power = F2_128::from(1u64);
    for coeff in coeffs.iter_mut().take(schema.columns.len()) {
        *coeff = power;
        power = power * alpha;
    }
    Ok(ClaimRelationInputs {
        matrix_cycles,
        row_point,
        alpha,
        gamma,
        target,
        selected_commitment,
        schema,
        coeffs,
    })
}

/// Multilinear evaluation with the same convention as the ring-switch
/// backend: `point[b]` is the coordinate of bit `b` of the vector index.
fn eval_mle_f2(values: &[F2_128], point: &[F2_128]) -> F2_128 {
    debug_assert_eq!(values.len(), 1usize << point.len());
    let mut current = values.to_vec();
    for challenge in point {
        let half = current.len() / 2;
        for index in 0..half {
            let low = current[2 * index];
            current[index] = low + (current[2 * index + 1] - low) * *challenge;
        }
        current.truncate(half);
    }
    current[0]
}

fn rel_transcript(
    table_root: &[u8; 32],
    commitment_bytes: &[u8],
    inputs: &ClaimRelationInputs,
    target: F2_128,
) -> Sha256Transcript {
    let mut transcript = Sha256Transcript::new("magnetar-claim-table-rel");
    transcript.absorb("domain", CLAIM_REL_DOMAIN);
    transcript.absorb("table", table_root);
    transcript.absorb("commitment", commitment_bytes);
    transcript.absorb("columns", &inputs.schema.root);
    for coordinate in &inputs.row_point {
        transcript.absorb("row", &coordinate.value().to_le_bytes());
    }
    transcript.absorb("alpha", &inputs.alpha.value().to_le_bytes());
    transcript.absorb("target", &target.value().to_le_bytes());
    transcript
}

fn rel_challenge(transcript: &mut Sha256Transcript, round: usize, values: &[F2_128]) -> F2_128 {
    transcript.absorb("round", &(round as u64).to_le_bytes());
    for value in values {
        transcript.absorb("poly", &value.value().to_le_bytes());
    }
    let bytes = transcript.challenge_bytes("claim-rel", 16);
    F2_128::from_bits(u128::from_le_bytes(bytes.try_into().expect("16 bytes")))
}

/// Prover: build and commit the claim table, and prove the claim relation
/// against the selected claim target.
///
/// Returns the proof-carried table and the composed `trace_claim_root`.
pub fn prove_claim_table(
    trace: &magnetar_spec::Trace,
    width: usize,
    selected: &SelectedCpuProof,
) -> Result<(ClaimTableProof, [u8; 32]), RuntimeError> {
    if width != CLAIM_TABLE_WIDTH {
        return Err(RuntimeError::Proof("claim table requires width 64".into()));
    }
    let columns = claim_table_columns(trace)?;
    let inputs = claim_relation_inputs(selected, width)?;
    if columns.mask != selected.mask || columns.cycles != inputs.matrix_cycles {
        return Err(RuntimeError::Proof(
            "claim table shape does not match the selected CPU claims".into(),
        ));
    }
    let binding = selected
        .claim_binding
        .as_ref()
        .expect("claim relation inputs require a binding");
    let target = binding.target;
    let bits = claim_table_bits(&columns);
    let commitment = commit_claim_table(&bits)?;
    let table_root = claim_table_root(&commitment);
    let slot_bits = slot_bits_for(columns.columns.len(), columns.cycles);
    let slots = 1usize << slot_bits;
    if bits.len() != slots * columns.cycles {
        return Err(RuntimeError::Proof(
            "claim table bit length mismatch".into(),
        ));
    }
    // Fold every committed column at the row point.
    let mut h = vec![F2_128::from(0u64); slots];
    for (slot, values) in columns.slots.iter().enumerate() {
        let row_values = values
            .iter()
            .map(|bit| F2_128::from(u64::from(*bit)))
            .collect::<Vec<_>>();
        h[slot] = eval_mle_f2(&row_values, &inputs.row_point);
    }
    let claimed: F2_128 = inputs
        .coeffs
        .iter()
        .zip(&h)
        .fold(F2_128::from(0u64), |sum, (coeff, value)| {
            sum + *coeff * *value
        });
    if claimed != target {
        return Err(RuntimeError::Proof(
            "claim table relation prover target mismatch".into(),
        ));
    }
    let backend = claim_table_backend();
    let commitment_bytes =
        crate::protocol::selected_backend().commitment_bytes(&selected.proof.commitment);
    let mut transcript = rel_transcript(&table_root, &commitment_bytes, &inputs, target);
    let coeffs = inputs.coeffs.clone();
    let h_values = h.clone();
    let (sumcheck, slot_point, _final) = prove(
        |point: &[F2_128]| eval_mle_f2(&h_values, point) * eval_mle_f2(&coeffs, point),
        slot_bits,
        2,
        |round, values| rel_challenge(&mut transcript, round, values),
    )
    .map_err(|error| RuntimeError::Proof(format!("claim relation sumcheck: {error}")))?;
    if sumcheck.claimed_sum != target {
        return Err(RuntimeError::Proof(
            "claim relation claimed sum mismatch".into(),
        ));
    }
    let mut point = inputs.row_point.clone();
    point.extend_from_slice(&slot_point);
    let (value, opening) = backend
        .open_with_commitment(&bits, &point, &commitment)
        .map_err(|error| RuntimeError::Proof(format!("claim table open: {error}")))?;
    let expected = eval_mle_f2(&h, &slot_point);
    if value != expected {
        return Err(RuntimeError::Proof(
            "claim table opening disagrees with the folded columns".into(),
        ));
    }
    let binding_root = claim_binding_root_from_parts(claim_rows_root(trace), &table_root);
    Ok((
        ClaimTableProof {
            commitment,
            root: table_root,
            slots,
            relations: vec![ClaimRelationProof {
                sumcheck,
                slot_point,
                opening,
            }],
        },
        binding_root,
    ))
}

/// Verify the claim-table commitment and its relation (no folded claim).
///
/// The caller must already have bound `table.root` to the statement through
/// `claim_binding_root_from_parts(claim_proof.root, table.root)`.
pub fn verify_claim_table(
    table: &ClaimTableProof,
    selected: &SelectedCpuProof,
    width: usize,
) -> Result<(), RuntimeError> {
    let inputs = claim_relation_inputs(selected, width)?;
    verify_claim_table_with(table, &inputs)
}

/// Verifier: check the claim table and return the folded claim for the
/// selected lockstep verifier.
///
/// The target is authenticated by the claim relation against the committed
/// claim columns, so the folded claim no longer needs the claim rows.
pub(crate) fn verify_claim_table_and_claim(
    table: &ClaimTableProof,
    selected: &SelectedCpuProof,
    width: usize,
) -> Result<crate::simd_dual::DynamicClaim, RuntimeError> {
    let inputs = claim_relation_inputs(selected, width)?;
    verify_claim_table_with(table, &inputs)?;
    Ok(folding_claim_from_inputs(&inputs))
}

fn folding_claim_from_inputs(inputs: &ClaimRelationInputs) -> crate::simd_dual::DynamicClaim {
    crate::simd_dual::DynamicClaim {
        claim: crate::simd_dual::dynamic_claim_structure(
            &inputs.schema,
            &inputs.row_point,
            inputs.alpha,
            inputs.target,
        ),
        gamma: inputs.gamma,
        columns_root: inputs.schema.root,
    }
}

fn verify_claim_table_with(
    table: &ClaimTableProof,
    inputs: &ClaimRelationInputs,
) -> Result<(), RuntimeError> {
    let expected_root = claim_table_root(&table.commitment);
    if table.root != expected_root {
        return Err(RuntimeError::Proof("claim table root mismatch".into()));
    }
    let target = inputs.target;
    // `inputs.coeffs.len()` is already the padded slot count.
    if table.slots != inputs.coeffs.len() {
        return Err(RuntimeError::Proof(
            "claim table slot count mismatch".into(),
        ));
    }
    if table.slots < 2 || !table.slots.is_power_of_two() {
        return Err(RuntimeError::Proof("claim table slot count invalid".into()));
    }
    let slot_vars = table.slots.trailing_zeros() as usize;
    let bits_len = table
        .slots
        .checked_mul(inputs.matrix_cycles)
        .ok_or_else(|| RuntimeError::Proof("claim table size overflow".into()))?;
    if bits_len < 1024
        || !bits_len.is_power_of_two()
        || bits_len.trailing_zeros() as usize
            != slot_vars + inputs.matrix_cycles.trailing_zeros() as usize
    {
        return Err(RuntimeError::Proof("claim table bit length invalid".into()));
    }
    let expected_variables = bits_len.trailing_zeros() as usize - 7;
    if expected_variables < 3 {
        return Err(RuntimeError::Proof(
            "claim table packed arity too small".into(),
        ));
    }
    if table.commitment.num_variables != expected_variables {
        return Err(RuntimeError::Proof(
            "claim table commitment arity mismatch".into(),
        ));
    }
    if table.relations.len() != 1 {
        return Err(RuntimeError::Proof(
            "claim table relation count mismatch".into(),
        ));
    }
    let relation = &table.relations[0];
    if relation.sumcheck.claimed_sum != target {
        return Err(RuntimeError::Proof(
            "claim relation does not prove the claim target".into(),
        ));
    }
    let commitment_bytes =
        crate::protocol::selected_backend().commitment_bytes(&inputs.selected_commitment);
    let mut transcript = rel_transcript(&table.root, &commitment_bytes, inputs, target);
    let (slot_point, final_value) =
        verify_rounds(&relation.sumcheck, slot_vars, 2, |round, values| {
            rel_challenge(&mut transcript, round, values)
        })
        .map_err(|error| RuntimeError::Proof(format!("claim relation sumcheck: {error}")))?;
    if relation.slot_point != slot_point {
        return Err(RuntimeError::Proof(
            "claim relation slot point mismatch".into(),
        ));
    }
    let coeff_eval = eval_mle_f2(&inputs.coeffs, &slot_point);
    let inverse = coeff_eval
        .inv()
        .ok_or_else(|| RuntimeError::Proof("claim relation coefficient is zero".into()))?;
    let expected_value = final_value * inverse;
    let mut point = inputs.row_point.clone();
    point.extend_from_slice(&slot_point);
    let backend = claim_table_backend();
    let valid = backend
        .verify(&table.commitment, &point, expected_value, &relation.opening)
        .map_err(|error| RuntimeError::Proof(format!("claim table opening: {error}")))?;
    if !valid {
        return Err(RuntimeError::Proof("claim table opening rejected".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_table() -> (PackedBits, Vec<F2_128>, Vec<F2_128>, F2_128) {
        // 8 slots x 256 rows: enough for the ring-switch packing minimum and
        // the PCS folding factor (3).
        let slots = 8usize;
        let cycles = 256usize;
        let mut bits = vec![false; slots * cycles];
        for slot in 0..slots {
            for row in 0..cycles {
                bits[slot * cycles + row] = (slot * 7 + row * 5 + slot * row) % 3 == 0;
            }
        }
        let row_point = (0..(cycles.trailing_zeros() as usize))
            .map(|index| F2_128::from((index * 2 + 1) as u64))
            .collect::<Vec<_>>();
        let coeffs = (0..slots)
            .map(|slot| F2_128::from((slot + 1) as u64))
            .collect::<Vec<_>>();
        let mut h = vec![F2_128::from(0u64); slots];
        for slot in 0..slots {
            let values = bits[slot * cycles..(slot + 1) * cycles]
                .iter()
                .map(|bit| F2_128::from(u64::from(*bit)))
                .collect::<Vec<_>>();
            h[slot] = eval_mle_f2(&values, &row_point);
        }
        let target = coeffs
            .iter()
            .zip(&h)
            .fold(F2_128::from(0u64), |sum, (coeff, value)| {
                sum + *coeff * *value
            });
        (PackedBits::from_bools(&bits), coeffs, row_point, target)
    }

    #[test]
    fn multilinear_fold_matches_two_point_interpolation() {
        let values = [3u64, 5, 7, 11]
            .iter()
            .map(|value| F2_128::from(*value))
            .collect::<Vec<_>>();
        let point = [F2_128::from(2u64), F2_128::from(9u64)];
        // MLE of [v0,v1,v2,v3] at (p0,p1) = v0(1-p0)(1-p1) + v1 p0(1-p1)
        // + v2 (1-p0) p1 + v3 p0 p1.
        let one = F2_128::from(1u64);
        let (a, b) = (point[0], point[1]);
        let expected = values[0] * (one + a) * (one + b)
            + values[1] * a * (one + b)
            + values[2] * (one + a) * b
            + values[3] * a * b;
        assert_eq!(eval_mle_f2(&values, &point), expected);
    }

    #[test]
    fn claim_relation_round_trips_and_rejects_tampering() {
        let (bits, coeffs, row_point, target) = test_table();
        let backend = claim_table_backend();
        let commitment = backend.commit(&bits).expect("commit");
        let slot_bits = coeffs.len().trailing_zeros() as usize;
        let mut transcript = Sha256Transcript::new("magnetar-claim-table-rel-test");
        // The prover side runs the generic sum-check and opens the table.
        let h = {
            let slots = coeffs.len();
            let cycles = bits.len() / slots;
            let mut h = vec![F2_128::from(0u64); slots];
            for slot in 0..slots {
                let values = (0..cycles)
                    .map(|row| F2_128::from(u64::from(bits.get(slot * cycles + row))))
                    .collect::<Vec<_>>();
                h[slot] = eval_mle_f2(&values, &row_point);
            }
            h
        };
        let h_values = h.clone();
        let coeffs_clone = coeffs.clone();
        let (sumcheck, slot_point, _) = prove(
            |point: &[F2_128]| eval_mle_f2(&h_values, point) * eval_mle_f2(&coeffs_clone, point),
            slot_bits,
            2,
            |round, values| rel_challenge(&mut transcript, round, values),
        )
        .expect("sumcheck");
        assert_eq!(sumcheck.claimed_sum, target);
        let mut point = row_point.clone();
        point.extend_from_slice(&slot_point);
        let (value, opening) = backend.open(&bits, &point).expect("open");
        assert_eq!(value, eval_mle_f2(&h, &slot_point));

        let mut verifier_transcript = Sha256Transcript::new("magnetar-claim-table-rel-test");
        let (replayed_point, final_value) =
            verify_rounds(&sumcheck, slot_bits, 2, |round, values| {
                rel_challenge(&mut verifier_transcript, round, values)
            })
            .expect("verify rounds");
        assert_eq!(replayed_point, slot_point);
        let inverse = eval_mle_f2(&coeffs, &slot_point).inv().expect("nonzero");
        let expected_value = final_value * inverse;
        assert_eq!(expected_value, value);
        assert!(backend
            .verify(&commitment, &point, expected_value, &opening)
            .expect("verify"));

        // Tampered round polynomial is rejected by the verifier's replay.
        let mut tampered = sumcheck.clone();
        tampered.round_polys[0][0] = tampered.round_polys[0][0] + F2_128::from(1u64);
        let mut verifier_transcript = Sha256Transcript::new("magnetar-claim-table-rel-test");
        assert!(
            verify_rounds(&tampered, slot_bits, 2, |round, values| rel_challenge(
                &mut verifier_transcript,
                round,
                values
            ))
            .is_err()
        );

        // Tampered opening value is rejected by the PCS.
        let mut tampered_opening = opening.clone();
        tampered_opening.packed_value = tampered_opening.packed_value + F2_128::from(1u64);
        assert!(!backend
            .verify(&commitment, &point, expected_value, &tampered_opening)
            .expect("verify"));
        assert!(!backend
            .verify(
                &commitment,
                &point,
                expected_value + F2_128::from(1u64),
                &opening
            )
            .expect("verify"));
    }
}
