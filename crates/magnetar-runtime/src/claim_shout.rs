//! M4a: committed Shout (BinaryShout-against-T, no pushforwards).
//!
//! Design: `docs/POLYLOG_CLAIM_VERIFIER.md` §C. Replaces the per-cycle Shout
//! witness rebuild with committed tables:
//! * `T_shout`: BinaryShout boolean columns (address0/1 bits, is_32, valid,
//!   12 link columns) as one packed-bit ring-switch table;
//! * `T_field`: the per-cycle claim instruction word as one dense `F2_128`
//!   column, so the reader value binds to claim words without a
//!   `2^address_bits` pushforward vector;
//! * BinaryShout Boolean/read sum-checks verified against a synthetic
//!   `P3MosaicCommitment` bound to both commitments (E5 pattern);
//! * linear relations bind `T_shout` to the claim table: position = pc>>2,
//!   valid = public prefix pattern, is_32 = 0, plus the BinaryShout evals.
//!
//! Gated by `MAGNETAR_COMMITTED_SHOUT=1` (default off);
//! `MAGNETAR_CLASSIC_LOGUP=1` forces the legacy trace path (A/B switch). The
//! default path is byte-identical to the committed build.

use magnetar_constraint::{Field, F2_128};
use magnetar_pcs::{P3BinaryPcs, P3Commitment, P3MosaicCommitment, P3Opening};
use magnetar_proof::{
    verify_rounds, BitPcs, PackedBits, Pcs, RingSwitchOpening, RingSwitchPackedBitPcs,
    SumcheckProof,
};
use magnetar_transcript::Sha256Transcript;

use crate::{claim_table, RuntimeError};

const SHOUT_BINDING_DOMAIN: &[u8] = b"magnetar-committed-shout-v1";
const SHOUT_REL_DOMAIN: &[u8] = b"magnetar-claim-shout-rel-v1";
const COMPOSE_DOMAIN: &[u8] = b"magnetar-claim-shout-root-v1";

pub fn committed_shout_enabled() -> bool {
    matches!(
        std::env::var("MAGNETAR_COMMITTED_SHOUT").ok().as_deref(),
        Some("1" | "on" | "true" | "yes")
    )
}

pub fn classic_logup_enabled() -> bool {
    matches!(
        std::env::var("MAGNETAR_CLASSIC_LOGUP").ok().as_deref(),
        Some("1" | "on" | "true" | "yes")
    )
}

pub fn shout_backend() -> RingSwitchPackedBitPcs<P3BinaryPcs> {
    RingSwitchPackedBitPcs::new(P3BinaryPcs::with_params(100, 3, 20, 3))
}

pub fn claim_field_backend() -> P3BinaryPcs {
    P3BinaryPcs::with_params(100, 3, 20, 3)
}

/// Host-side Shout data columns + the dense claim word.
pub struct ShoutColumns {
    pub address_bits: usize,
    pub cycles: usize,
    pub address0: Vec<Vec<bool>>,
    pub address1: Vec<Vec<bool>>,
    pub is_32: Vec<bool>,
    pub valid: Vec<bool>,
    pub link: Vec<Vec<bool>>,
    pub word: Vec<F2_128>,
}

impl ShoutColumns {
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
            link if link >= 2 && link - 2 < 12 => Ok(&self.link[link - 2]),
            _ => Err(RuntimeError::Proof("shout data column out of range".into())),
        }
    }
}

pub fn shout_columns(trace: &magnetar_spec::Trace) -> Result<ShoutColumns, RuntimeError> {
    if !trace.rows.iter().all(|row| row.instruction_len == 4) {
        return Err(RuntimeError::Proof(
            "M4a committed Shout requires word mode (4-byte instructions)".into(),
        ));
    }
    let witness = crate::binary_shout::BinaryShoutWitness::from_trace(trace)
        .map_err(|error| RuntimeError::Proof(format!("committed Shout witness: {error}")))?;
    let to_bits = |column: &[F2_128]| -> Vec<bool> {
        column
            .iter()
            .map(|value| *value != F2_128::from(0u64))
            .collect()
    };
    let address0 = witness.address0.iter().map(|c| to_bits(c)).collect::<Vec<_>>();
    let address1 = witness.address1.iter().map(|c| to_bits(c)).collect::<Vec<_>>();
    let link = witness.link_columns().iter().map(|c| to_bits(c)).collect::<Vec<_>>();
    if address0.len() != witness.address_bits || address1.len() != witness.address_bits || link.len() != 12 {
        return Err(RuntimeError::Proof("committed Shout column shape".into()));
    }
    let mut word = vec![F2_128::from(0u64); witness.cycles];
    for (cycle, row) in trace.rows.iter().enumerate() {
        word[cycle] = F2_128::from(u64::from(row.instruction_word));
    }
    Ok(ShoutColumns {
        address_bits: witness.address_bits,
        cycles: witness.cycles,
        address0,
        address1,
        is_32: to_bits(&witness.is_32),
        valid: to_bits(&witness.valid),
        link,
        word,
    })
}

/// Packed Shout table: flat index `slot*cycles + row`, slot order
/// `[address0, address1, is_32, valid, link]`.
pub fn shout_bits(shout: &ShoutColumns) -> (PackedBits, usize) {
    let columns = shout.data_column_count();
    let slot_bits = claim_table::slot_bits_for(columns, shout.cycles);
    let slots = 1usize << slot_bits;
    let mut bits = PackedBits::zeroed(slots * shout.cycles);
    if shout.cycles % 64 == 0 {
        let words_per_column = shout.cycles / 64;
        let words = bits.words_mut();
        for index in 0..columns {
            let column = shout.column(index).expect("shout column");
            let base = index * words_per_column;
            for (word_index, word) in words[base..base + words_per_column].iter_mut().enumerate() {
                let mut packed = 0u64;
                for bit in 0..64 {
                    if column[word_index * 64 + bit] {
                        packed |= 1u64 << bit;
                    }
                }
                *word = packed;
            }
        }
    } else {
        for index in 0..columns {
            let column = shout.column(index).expect("shout column");
            let base = index * shout.cycles;
            for (row, bit) in column.iter().enumerate() {
                if *bit {
                    bits.set(base + row, true);
                }
            }
        }
    }
    (bits, slots)
}

fn hash_root(label: &[u8], commitment: &P3Commitment) -> [u8; 32] {
    let mut bytes = COMPOSE_DOMAIN.to_vec();
    bytes.extend_from_slice(label);
    bytes.extend_from_slice(&bincode::serialize(commitment).unwrap_or_default());
    magnetar_transcript::sha256(&bytes)
}

pub fn shout_root(commitment: &P3Commitment) -> [u8; 32] {
    hash_root(b"shout", commitment)
}

pub fn field_root(commitment: &P3Commitment) -> [u8; 32] {
    hash_root(b"field", commitment)
}

/// Statement-root composition for M4a: `H(v1 binding || shout root || field root)`.
pub fn compose_root(v1: &[u8; 32], shout: &[u8; 32], field: &[u8; 32]) -> [u8; 32] {
    let mut bytes = COMPOSE_DOMAIN.to_vec();
    bytes.extend_from_slice(v1);
    bytes.extend_from_slice(shout);
    bytes.extend_from_slice(field);
    magnetar_transcript::sha256(&bytes)
}


/// Composed root for a trace when the committed-Shout path is enabled.
pub fn claim_binding_root_with_shout(trace: &magnetar_spec::Trace) -> Result<[u8; 32], RuntimeError> {
    let shout = shout_columns(trace)?;
    let (bits, _) = shout_bits(&shout);
    let shout_commitment = shout_backend()
        .commit(&bits)
        .map_err(|error| RuntimeError::Proof(format!("shout commit: {error}")))?;
    let field_commitment = claim_field_backend()
        .commit(&shout.word)
        .map_err(|error| RuntimeError::Proof(format!("claim field commit: {error}")))?;
    let v1 = claim_table::claim_binding_root(trace)?;
    Ok(compose_root(
        &v1,
        &shout_root(&shout_commitment),
        &field_root(&field_commitment),
    ))
}

/// Synthetic mosaic commitment for the BinaryShout sum-checks.
pub fn synthetic_commitment(
    shout_commitment: &P3Commitment,
    field_commitment: &P3Commitment,
    address_bits: usize,
    cycle_bits: usize,
) -> P3MosaicCommitment {
    let binding = {
        let mut bytes = SHOUT_BINDING_DOMAIN.to_vec();
        bytes.extend_from_slice(&bincode::serialize(shout_commitment).unwrap_or_default());
        bytes.extend_from_slice(&bincode::serialize(field_commitment).unwrap_or_default());
        magnetar_transcript::sha256(&bytes)
    };
    P3MosaicCommitment {
        cap: shout_commitment.cap.clone(),
        tables: vec![magnetar_pcs::P3MosaicTableShape {
            num_variables: cycle_bits,
            num_columns: 2 * address_bits + 2 + 12,
        }],
        stacked_variables: cycle_bits,
        binding,
    }
}

/// One linear relation over a committed bit table: `Σ coeffs[slot]·T_slot(row_point) = value`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ShoutRelationProof {
    pub sumcheck: SumcheckProof<F2_128>,
    pub slot_point: Vec<F2_128>,
    pub opening: RingSwitchOpening<P3Opening>,
}

fn eval_mle(values: &[F2_128], point: &[F2_128]) -> F2_128 {
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

fn fold_column(bits: &PackedBits, slot: usize, cycles: usize, row_point: &[F2_128]) -> F2_128 {
    let base = slot * cycles;
    let values = (0..cycles)
        .map(|row| F2_128::from(u64::from(bits.get(base + row))))
        .collect::<Vec<_>>();
    eval_mle(&values, row_point)
}

fn relation_transcript(commitment: &P3Commitment, row_point: &[F2_128], value: F2_128) -> Sha256Transcript {
    let mut transcript = Sha256Transcript::new("magnetar-claim-shout-rel");
    transcript.absorb("domain", SHOUT_REL_DOMAIN);
    transcript.absorb("commitment", &bincode::serialize(commitment).unwrap_or_default());
    for coordinate in row_point {
        transcript.absorb("row", &coordinate.value().to_le_bytes());
    }
    transcript.absorb("value", &value.value().to_le_bytes());
    transcript
}

fn relation_challenge(transcript: &mut Sha256Transcript, round: usize, values: &[F2_128]) -> F2_128 {
    transcript.absorb("round", &(round as u64).to_le_bytes());
    for value in values {
        transcript.absorb("poly", &value.value().to_le_bytes());
    }
    let bytes = transcript.challenge_bytes("rel", 16);
    F2_128::from_bits(u128::from_le_bytes(bytes.try_into().expect("16 bytes")))
}

fn pad(values: &[F2_128], slots: usize) -> Vec<F2_128> {
    let mut padded = vec![F2_128::from(0u64); slots];
    for (slot, value) in values.iter().enumerate().take(slots) {
        padded[slot] = *value;
    }
    padded
}

pub(crate) fn prove_relation(
    bits: &PackedBits,
    commitment: &P3Commitment,
    cycles: usize,
    slots: usize,
    row_point: &[F2_128],
    coeffs: &[F2_128],
    value: F2_128,
) -> Result<ShoutRelationProof, RuntimeError> {
    use magnetar_proof::prove;
    let slot_bits = slots.trailing_zeros() as usize;
    // The ring-switch opening authenticates the evaluation of the *whole*
    // packed table at the final point, so every slot's column fold enters the
    // final check, even when its public coefficient is zero.
    let h = (0..slots)
        .map(|slot| fold_column(bits, slot, cycles, row_point))
        .collect::<Vec<_>>();
    let padded = pad(coeffs, slots);
    let mut transcript = relation_transcript(commitment, row_point, value);
    let h_values = h.clone();
    let coeff_values = padded.clone();
    let (sumcheck, slot_point, _) = prove(
        |point: &[F2_128]| eval_mle(&h_values, point) * eval_mle(&coeff_values, point),
        slot_bits,
        2,
        |round, values| relation_challenge(&mut transcript, round, values),
    )
    .map_err(|error| RuntimeError::Proof(format!("shout relation sumcheck: {error}")))?;
    if sumcheck.claimed_sum != value {
        return Err(RuntimeError::Proof("shout relation value mismatch".into()));
    }
    let mut point = row_point.to_vec();
    point.extend_from_slice(&slot_point);
    let (observed, opening) = shout_backend()
        .open(bits, &point)
        .map_err(|error| RuntimeError::Proof(format!("shout relation open: {error}")))?;
    if observed != eval_mle(&h, &slot_point) {
        return Err(RuntimeError::Proof("shout relation opening mismatch".into()));
    }
    Ok(ShoutRelationProof { sumcheck, slot_point, opening })
}

pub(crate) fn verify_relation(
    proof: &ShoutRelationProof,
    commitment: &P3Commitment,
    slots: usize,
    row_point: &[F2_128],
    coeffs: &[F2_128],
    value: F2_128,
) -> Result<(), RuntimeError> {
    let slot_bits = slots.trailing_zeros() as usize;
    if proof.sumcheck.claimed_sum != value {
        return Err(RuntimeError::Proof("shout relation value mismatch".into()));
    }
    let padded = pad(coeffs, slots);
    let mut transcript = relation_transcript(commitment, row_point, value);
    let (slot_point, final_value) = verify_rounds(&proof.sumcheck, slot_bits, 2, |round, values| {
        relation_challenge(&mut transcript, round, values)
    })
    .map_err(|error| RuntimeError::Proof(format!("shout relation sumcheck: {error}")))?;
    if proof.slot_point != slot_point {
        return Err(RuntimeError::Proof("shout relation slot point mismatch".into()));
    }
    let inverse = eval_mle(&padded, &slot_point)
        .inv()
        .ok_or_else(|| RuntimeError::Proof("shout relation coefficient is zero".into()))?;
    let expected = final_value * inverse;
    let mut point = row_point.to_vec();
    point.extend_from_slice(&slot_point);
    if !shout_backend()
        .verify(commitment, &point, expected, &proof.opening)
        .map_err(|error| RuntimeError::Proof(format!("shout relation opening: {error}")))?
    {
        return Err(RuntimeError::Proof("shout relation opening rejected".into()));
    }
    Ok(())
}

/// Deterministic data-relation coefficients, shared by prover and verifier.
struct DataRelationCoeffs {
    row_point: Vec<F2_128>,
    beta: [F2_128; 4],
    prefix: F2_128,
}

fn data_relations(
    selected: &crate::SelectedCpuProof,
    width: usize,
    table_len: u64,
    address_bits: usize,
    shout_slots: usize,
) -> Result<DataRelationCoeffs, RuntimeError> {
    let matrix_cycles = if selected.matrix_cycles == 0 { selected.cycles } else { selected.matrix_cycles };
    let schema = crate::simd_dual::dynamic_claim_schema(selected.mask, width, matrix_cycles)?;
    let backend = crate::protocol::selected_backend();
    let commitment_bytes = backend.commitment_bytes(&selected.proof.commitment);
    let row_bits = matrix_cycles.trailing_zeros() as usize;
    let (row_point, _alpha, _gamma) =
        crate::simd_dual::dynamic_claim_challenges(&commitment_bytes, &schema.root, row_bits);
    let mut transcript = Sha256Transcript::new("magnetar-claim-shout-data");
    transcript.absorb("schema", &schema.root);
    transcript.absorb("shout_slots", &(shout_slots as u64).to_le_bytes());
    transcript.absorb("address_bits", &(address_bits as u64).to_le_bytes());
    let mut beta = [F2_128::from(0u64); 4];
    for entry in beta.iter_mut() {
        let bytes = transcript.challenge_bytes("beta", 16);
        *entry = F2_128::from_bits(u128::from_le_bytes(bytes.try_into().expect("16 bytes")));
    }
    let prefix = prefix_eq(&row_point, table_len);
    Ok(DataRelationCoeffs {
        row_point,
        beta,
        prefix,
    })
}

/// `Σ_{i < len} eq(point, i)` in O(point.len()).
fn prefix_eq(point: &[F2_128], len: u64) -> F2_128 {
    prefix_rec(point, len)
}

fn prefix_rec(point: &[F2_128], len: u64) -> F2_128 {
    if len == 0 {
        return F2_128::from(0u64);
    }
    if point.is_empty() {
        // Only index 0 remains, and it is < len.
        return F2_128::from(1u64);
    }
    let k = point.len();
    let half = 1u64 << (k - 1);
    let top = point[k - 1];
    let one_plus = F2_128::from(1u64) + top;
    if len <= half {
        one_plus * prefix_rec(&point[..k - 1], len)
    } else {
        one_plus + top * prefix_rec(&point[..k - 1], len - half)
    }
}

/// The committed-Shout proof carried in `ClaimProof.committed_shout`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CommittedShoutProof {
    pub proof: crate::binary_shout::BinaryShoutProof,
    pub shout_commitment: P3Commitment,
    pub field_commitment: P3Commitment,
    pub field_opening: P3Opening,
    /// Dense claim-word MLE at `word_point` (checked against the opening).
    pub word_value: F2_128,
    /// BinaryShout `rho_j` cycle point where the reader word column is opened.
    pub word_point: Vec<F2_128>,
    pub reader_point: Vec<F2_128>,
    pub address_bits: usize,
    pub cycles: usize,
    pub shout_slots: usize,
    pub shout_relations: Vec<ShoutRelationProof>,
    pub claim_relation: Option<ShoutRelationProof>,
    /// Prover-supplied shared value of the address-sum functional (both sides).
    pub position_value: F2_128,
}

impl CommittedShoutProof {
    pub const PRE_M4_ERROR: &'static str =
        "pre-M4 proof: committed Shout proof missing (set MAGNETAR_CLASSIC_LOGUP=1 for the legacy path)";
}

impl PartialEq for CommittedShoutProof {
    fn eq(&self, other: &Self) -> bool {
        bincode::serialize(self).ok() == bincode::serialize(other).ok()
    }
}
impl Eq for CommittedShoutProof {}

fn transcript_challenge(transcript: &mut Sha256Transcript, label: &str) -> F2_128 {
    let bytes = transcript.challenge_32(label);
    let mut value = [0u8; 16];
    value.copy_from_slice(&bytes[..16]);
    F2_128::from_bits(u128::from_le_bytes(value))
}

/// Reproduce the `magnetar-binary-shout` reader transcript exactly as
/// `binary_shout` does: `rho_j` (cycle point) then `gamma0` (first column
/// batching challenge). The reader word column is committed to `T_field` and
/// opened at `rho_j`, so both sides must derive the same point.
fn binary_shout_word_binding(
    commitment: &P3MosaicCommitment,
    binding: &[u8],
    cycle_bits: usize,
) -> (Vec<F2_128>, F2_128) {
    let mut transcript = Sha256Transcript::new("magnetar-binary-shout");
    transcript.absorb("commitment", &bincode::serialize(commitment).unwrap_or_default());
    transcript.absorb("packed-binding", binding);
    let word_point = (0..cycle_bits)
        .map(|_| transcript_challenge(&mut transcript, "point"))
        .collect::<Vec<_>>();
    let gamma = transcript_challenge(&mut transcript, "column");
    (word_point, gamma)
}

pub fn prove_committed_shout(
    trace: &magnetar_spec::Trace,
    width: usize,
    selected: &crate::SelectedCpuProof,
    v1_root: &[u8; 32],
) -> Result<(CommittedShoutProof, [u8; 32]), RuntimeError> {
    let shout = shout_columns(trace)?;
    let cycles = shout.cycles;
    let (bits, slots) = shout_bits(&shout);
    let shout_commitment = shout_backend()
        .commit(&bits)
        .map_err(|error| RuntimeError::Proof(format!("shout commit: {error}")))?;
    let field_commitment = claim_field_backend()
        .commit(&shout.word)
        .map_err(|error| RuntimeError::Proof(format!("claim field commit: {error}")))?;
    let binding_root = compose_root(v1_root, &shout_root(&shout_commitment), &field_root(&field_commitment));
    // Word-only BinaryShout witness.
    let mut witness = crate::binary_shout::BinaryShoutWitness::from_trace(trace)
        .map_err(|error| RuntimeError::Proof(format!("committed Shout witness: {error}")))?;
    for row in &mut witness.rom {
        row.truncate(1);
    }
    let cycle_bits = cycles.trailing_zeros() as usize;
    let synthetic = synthetic_commitment(&shout_commitment, &field_commitment, shout.address_bits, cycle_bits);
    let (proof, _points, _values) = crate::binary_shout::prove_binary_shout_claims(
        &witness,
        &synthetic,
        0,
        SHOUT_BINDING_DOMAIN,
    )
    .map_err(|error| RuntimeError::Proof(format!("binary shout prove: {error}")))?;
    if proof.columns != 1 {
        return Err(RuntimeError::Proof("word-only Shout must have one column".into()));
    }
    let reader_point = proof
        .link_point
        .iter()
        .map(|value| F2_128::from(value.value()))
        .collect::<Vec<_>>();
    let (word_point, gamma) =
        binary_shout_word_binding(&synthetic, SHOUT_BINDING_DOMAIN, cycle_bits);
    let word_value = eval_mle(&shout.word, &word_point);
    let field_opening = claim_field_backend()
        .open(&shout.word, &word_point)
        .map_err(|error| RuntimeError::Proof(format!("claim word open: {error}")))?;
    if proof.claimed_read != gamma * word_value {
        return Err(RuntimeError::Proof("committed Shout claimed_read != claim word".into()));
    }
    // Relation [0]: BinaryShout read-side evals against T_shout at reader point.
    let mut eval_values = Vec::new();
    eval_values.extend(proof.ra0_evals.iter().copied());
    eval_values.extend(proof.ra1_evals.iter().copied());
    eval_values.push(proof.is_32_eval);
    eval_values.push(proof.valid_eval);
    eval_values.extend(proof.link_evals.iter().copied());
    let mut eval_coeffs = vec![F2_128::from(0u64); slots];
    let mut weight = F2_128::from(1u64);
    let mut eval_value = F2_128::from(0u64);
    for (index, value) in eval_values.iter().enumerate() {
        eval_coeffs[index] = weight;
        eval_value = eval_value + weight * *value;
        weight = weight * F2_128::from(7u64);
    }
    let eval_relation = prove_relation(&bits, &shout_commitment, cycles, slots, &reader_point, &eval_coeffs, eval_value)?;
    // Relation [1]: address/valid/is_32 data checks at the claim row point.
    let data = data_relations(selected, width, trace.rows.len() as u64, shout.address_bits, slots)?;
    let claim_columns = claim_table::claim_table_columns(trace)?;
    let claim_bits = claim_table::claim_table_bits(&claim_columns);
    let claim_commitment = claim_table::commit_claim_table(&claim_bits)?;
    let claim_slots = claim_columns.slot_count();
    let frame = crate::simd_dual::dynamic_claim_frame_columns(selected.mask, width, if selected.matrix_cycles == 0 { selected.cycles } else { selected.matrix_cycles })?;
    let schema = crate::simd_dual::dynamic_claim_schema(selected.mask, width, if selected.matrix_cycles == 0 { selected.cycles } else { selected.matrix_cycles })?;
    let mut shout_coeffs = vec![F2_128::from(0u64); slots];
    let mut claim_coeffs = vec![F2_128::from(0u64); claim_slots];
    let [b0, b1, bv, bi] = data.beta;
    for bit in 0..shout.address_bits {
        shout_coeffs[bit] = b0;
        shout_coeffs[shout.address_bits + bit] = b1;
        if let Some(pc_col) = frame.0.get(bit + 2) {
            if let Ok(index) = schema.columns.binary_search(pc_col) {
                claim_coeffs[index] = claim_coeffs[index] + b0 + b1;
            }
        }
    }
    shout_coeffs[2 * shout.address_bits] = bi; // is_32
    shout_coeffs[2 * shout.address_bits + 1] = bv; // valid
    // Prover-side shared position value: beta-weighted pc-shift sum at z.
    let position_value = {
        let mut value = F2_128::from(0u64);
        for bit in 0..shout.address_bits {
            if let Some(pc_col) = frame.0.get(bit + 2) {
                let pc_slot = claim_columns
                    .columns
                    .binary_search(pc_col)
                    .map_err(|_| RuntimeError::Proof("pc column outside the claim table".into()))?;
                value = value
                    + (b0 + b1)
                        * fold_column(&claim_bits, pc_slot, claim_columns.cycles, &data.row_point);
            }
        }
        value
    };
    let shout_value = position_value
        + bv * data.prefix
        + bi * F2_128::from(0u64);
    let shout_data_relation = prove_relation(&bits, &shout_commitment, cycles, slots, &data.row_point, &shout_coeffs, shout_value)?;
    let claim_relation = prove_relation(&claim_bits, &claim_commitment, claim_columns.cycles, claim_slots, &data.row_point, &claim_coeffs, position_value)?;
    let _ = width;
    Ok((
        CommittedShoutProof {
            proof,
            shout_commitment,
            field_commitment,
            field_opening,
            word_value,
            word_point,
            reader_point,
            address_bits: shout.address_bits,
            cycles,
            shout_slots: slots,
            shout_relations: vec![eval_relation, shout_data_relation],
            claim_relation: Some(claim_relation),
            position_value,
        },
        binding_root,
    ))
}

pub fn verify_committed_shout(
    committed: &CommittedShoutProof,
    statement: &crate::Statement,
    claim_table_proof: &claim_table::ClaimTableProof,
    v1_root: &[u8; 32],
    selected: &crate::SelectedCpuProof,
    width: usize,
) -> Result<(), RuntimeError> {
    if committed.shout_relations.len() != 2 || committed.claim_relation.is_none() {
        return Err(RuntimeError::Proof("committed Shout relation set missing".into()));
    }
    let expected_root = compose_root(
        v1_root,
        &shout_root(&committed.shout_commitment),
        &field_root(&committed.field_commitment),
    );
    if expected_root != statement.trace_claim_root {
        return Err(RuntimeError::Proof("committed Shout root mismatch".into()));
    }
    let cycle_bits = committed.cycles.trailing_zeros() as usize;
    let synthetic = synthetic_commitment(
        &committed.shout_commitment,
        &committed.field_commitment,
        committed.address_bits,
        cycle_bits,
    );
    crate::binary_shout::verify_binary_shout_from_proof(
        &committed.proof,
        &synthetic,
        0,
        SHOUT_BINDING_DOMAIN,
    )
    .map_err(|error| RuntimeError::Proof(format!("binary shout verify: {error}")))?
    .ok_or_else(|| RuntimeError::Proof("committed Shout claims rejected".into()))?;
    // Reader word binding.
    let reader_point = committed
        .proof
        .link_point
        .iter()
        .map(|value| F2_128::from(value.value()))
        .collect::<Vec<_>>();
    if reader_point != committed.reader_point {
        return Err(RuntimeError::Proof("committed Shout reader point mismatch".into()));
    }
    let (word_point, gamma) =
        binary_shout_word_binding(&synthetic, SHOUT_BINDING_DOMAIN, cycle_bits);
    if word_point != committed.word_point {
        return Err(RuntimeError::Proof("committed Shout word point mismatch".into()));
    }
    let field_ok = claim_field_backend()
        .verify(
            &committed.field_commitment,
            &word_point,
            committed.word_value,
            &committed.field_opening,
        )
        .map_err(|error| RuntimeError::Proof(format!("claim word opening: {error}")))?;
    if !field_ok {
        return Err(RuntimeError::Proof("claim word opening rejected".into()));
    }
    if committed.proof.claimed_read != gamma * committed.word_value {
        return Err(RuntimeError::Proof("committed Shout claimed_read != claim word".into()));
    }
    // Public ROM word column check (word mode: cells = rom.len() rounded up).
    let cells = statement.rom.len().next_power_of_two().max(2);
    if committed.proof.read_address_point.len() != committed.address_bits {
        return Err(RuntimeError::Proof("committed Shout ROM point arity".into()));
    }
    let mut rom_word = vec![F2_128::from(0u64); cells];
    for (index, word) in statement.rom.iter().enumerate() {
        rom_word[index] = F2_128::from(u64::from(*word));
    }
    let rom_claim = eval_mle(&rom_word, &committed.proof.read_address_point);
    if committed.proof.column_evals.len() != 1 || committed.proof.column_evals[0] != rom_claim {
        return Err(RuntimeError::Proof("committed Shout public ROM word mismatch".into()));
    }
    // Relation [0]: BinaryShout read-side evals against T_shout.
    let mut eval_values = Vec::new();
    eval_values.extend(committed.proof.ra0_evals.iter().copied());
    eval_values.extend(committed.proof.ra1_evals.iter().copied());
    eval_values.push(committed.proof.is_32_eval);
    eval_values.push(committed.proof.valid_eval);
    eval_values.extend(committed.proof.link_evals.iter().copied());
    let mut eval_coeffs = vec![F2_128::from(0u64); committed.shout_slots];
    let mut weight = F2_128::from(1u64);
    let mut eval_value = F2_128::from(0u64);
    for (index, value) in eval_values.iter().enumerate() {
        eval_coeffs[index] = weight;
        eval_value = eval_value + weight * *value;
        weight = weight * F2_128::from(7u64);
    }
    verify_relation(
        &committed.shout_relations[0],
        &committed.shout_commitment,
        committed.shout_slots,
        &reader_point,
        &eval_coeffs,
        eval_value,
    )?;
    // Relation [1]: address/valid/is_32 data checks against T_shout + claim table.
    let data = data_relations(
        selected,
        width,
        statement.trace_len,
        committed.address_bits,
        committed.shout_slots,
    )?;
    let matrix_cycles = if selected.matrix_cycles == 0 {
        selected.cycles
    } else {
        selected.matrix_cycles
    };
    let schema = crate::simd_dual::dynamic_claim_schema(selected.mask, width, matrix_cycles)?;
    let frame = crate::simd_dual::dynamic_claim_frame_columns(
        selected.mask,
        width,
        matrix_cycles,
    )?;
    let claim_slots = 1usize
        << claim_table::slot_bits_for(schema.columns.len(), matrix_cycles);
    let [b0, b1, bv, bi] = data.beta;
    let mut shout_coeffs = vec![F2_128::from(0u64); committed.shout_slots];
    let mut claim_coeffs = vec![F2_128::from(0u64); claim_slots];
    for bit in 0..committed.address_bits {
        shout_coeffs[bit] = b0;
        shout_coeffs[committed.address_bits + bit] = b1;
        if let Some(pc_col) = frame.0.get(bit + 2) {
            if let Ok(index) = schema.columns.binary_search(pc_col) {
                claim_coeffs[index] = claim_coeffs[index] + b0 + b1;
            }
        }
    }
    shout_coeffs[2 * committed.address_bits] = bi;
    shout_coeffs[2 * committed.address_bits + 1] = bv;
    let shout_value = committed.position_value + bv * data.prefix;
    verify_relation(
        &committed.shout_relations[1],
        &committed.shout_commitment,
        committed.shout_slots,
        &data.row_point,
        &shout_coeffs,
        shout_value,
    )?;
    let claim_relation = committed
        .claim_relation
        .as_ref()
        .ok_or_else(|| RuntimeError::Proof("claim-side relation missing".into()))?;
    verify_relation(
        claim_relation,
        &claim_table_proof.commitment,
        claim_slots,
        &data.row_point,
        &claim_coeffs,
        committed.position_value,
    )?;
    let _ = gamma;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn relation_round_trip_on_shout_table() {
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction { op: Op::Addi, rd: 1, rs1: 0, rs2: 0, imm: 7, shamt: 0 }.encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = magnetar_executor::execute(
            &program,
            MachineConfig { entry: 0x1000, rom_base: 0x1000, ram_base: 0x1000_0000, ram_size: 0x40, stack_top: 0x1000_0040, max_cycles: 100 },
        )
        .unwrap();
        let columns = shout_columns(&trace).unwrap();
        let (bits, slots) = shout_bits(&columns);
        let commitment = shout_backend().commit(&bits).unwrap();
        let row_point = (0..columns.cycles.trailing_zeros() as usize)
            .map(|index| F2_128::from((index + 1) as u64))
            .collect::<Vec<_>>();
        let mut coeffs = vec![F2_128::from(0u64); slots];
        let mut value = F2_128::from(0u64);
        for slot in 0..3 {
            let coefficient = F2_128::from((slot + 1) as u64);
            coeffs[slot] = coefficient;
            value = value + coefficient * fold_column(&bits, slot, columns.cycles, &row_point);
        }
        let relation = prove_relation(&bits, &commitment, columns.cycles, slots, &row_point, &coeffs, value).unwrap();
        verify_relation(&relation, &commitment, slots, &row_point, &coeffs, value).unwrap();
    }

    use super::*;

    #[test]
    fn prefix_eq_matches_small_cases() {
        let point = [F2_128::from(2u64), F2_128::from(3u64)];
        let one = F2_128::from(1u64);
        for len in 0..4u64 {
            let expected = (0..len).fold(F2_128::from(0u64), |sum, index| {
                let bits = [F2_128::from(index & 1), F2_128::from((index >> 1) & 1)];
                sum + (one + point[0] + bits[0]) * (one + point[1] + bits[1])
            });
            assert_eq!(prefix_eq(&point, len), expected, "len {len}");
        }
    }

    #[test]
    fn shout_columns_match_the_trace_words() {
        use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction { op: Op::Addi, rd: 1, rs1: 0, rs2: 0, imm: 7, shamt: 0 }.encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = magnetar_executor::execute(
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
        .unwrap();
        let columns = shout_columns(&trace).unwrap();
        assert_eq!(columns.cycles, trace.rows.len().next_power_of_two().max(2));
        assert_eq!(columns.link.len(), 12);
        for (cycle, row) in trace.rows.iter().enumerate() {
            assert_eq!(columns.word[cycle], F2_128::from(u64::from(row.instruction_word)));
            assert!(columns.valid[cycle]);
        }
        for cycle in trace.rows.len()..columns.cycles {
            assert!(!columns.valid[cycle]);
        }
    }
}
