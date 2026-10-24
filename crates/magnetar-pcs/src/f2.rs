//! Succinct F2 opening by embedding bits into the packed P3 field.
//!
//! This is not a native F2 Ligerito instance; it reuses the existing P3
//! binary-field PCS over `F2_128` and embeds each bit as `0` or `1`.

use magnetar_constraint::{Field, F2, F2_128};
use magnetar_proof::{BitPcs, Mle, Pcs, ProofError};

use crate::p3_pcs::{P3BinaryPcs, P3Commitment, P3Opening};

#[derive(Clone, Debug)]
pub struct F2Pcs {
    inner: P3BinaryPcs,
}

impl F2Pcs {
    pub fn new(security_level: usize) -> Self {
        Self {
            inner: P3BinaryPcs::new(security_level),
        }
    }

    pub fn commit(&self, values: &[F2]) -> Result<P3Commitment, ProofError> {
        self.inner.commit(&embed(values))
    }

    pub fn open(&self, values: &[F2], point: &[F2_128]) -> Result<P3Opening, ProofError> {
        self.inner.open(&embed(values), point)
    }

    pub fn verify(
        &self,
        commitment: &P3Commitment,
        point: &[F2_128],
        value: F2,
        opening: &P3Opening,
    ) -> Result<bool, ProofError> {
        self.inner.verify(
            commitment,
            point,
            F2_128::from(u64::from(value.value())),
            opening,
        )
    }
}

fn embed(values: &[F2]) -> Vec<F2_128> {
    values
        .iter()
        .map(|value| F2_128::from(u64::from(value.value())))
        .collect()
}

// Native F2 vector commitment: Merkle tree over bits. At an F2 point the
// multilinear evaluation is exactly one coefficient bit, so the opening is a
// Merkle path. This is a native-F2 PCS for F2 challenges; extension-field
// challenges need a different opening (sumcheck/lift), which is the next step.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct F2NativeCommitment(pub [u8; 32]);

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct F2NativeOpening {
    pub value: F2,
    pub path: Vec<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct F2NativePcs;

impl F2NativePcs {
    pub fn commit(&self, values: &[F2]) -> Result<F2NativeCommitment, ProofError> {
        if values.is_empty() {
            return Err(ProofError::Pcs("empty F2 commitment".into()));
        }
        let layers = merkle_layers(values);
        Ok(F2NativeCommitment(
            *layers
                .last()
                .and_then(|layer| layer.first())
                .ok_or_else(|| ProofError::Pcs("empty F2 Merkle tree".into()))?,
        ))
    }

    pub fn open(&self, values: &[F2], point: &[F2]) -> Result<F2NativeOpening, ProofError> {
        if values.is_empty() {
            return Err(ProofError::Pcs("empty F2 opening".into()));
        }
        let index = f2_point_index(point)?;
        if index >= values.len() {
            return Err(ProofError::Pcs("F2 opening point out of range".into()));
        }
        let layers = merkle_layers(values);
        let mut path = Vec::with_capacity(layers.len().saturating_sub(1));
        let mut position = index;
        for layer in layers.iter().take(layers.len().saturating_sub(1)) {
            path.push(layer[position ^ 1]);
            position >>= 1;
        }
        Ok(F2NativeOpening {
            value: values[index],
            path,
        })
    }

    pub fn verify(
        &self,
        commitment: &F2NativeCommitment,
        point: &[F2],
        opening: &F2NativeOpening,
    ) -> Result<bool, ProofError> {
        let index = f2_point_index(point)?;
        let mut node = leaf_hash(opening.value);
        let mut position = index;
        for sibling in &opening.path {
            node = if position & 1 == 0 {
                node_hash(&node, sibling)
            } else {
                node_hash(sibling, &node)
            };
            position >>= 1;
        }
        Ok(node == commitment.0)
    }
}

fn f2_point_index(point: &[F2]) -> Result<usize, ProofError> {
    if point.len() >= usize::BITS as usize {
        return Err(ProofError::Pcs("F2 point too long".into()));
    }
    let mut index = 0usize;
    for (bit, value) in point.iter().enumerate() {
        if value.value() == 1 {
            index |= 1usize << bit;
        }
    }
    Ok(index)
}

fn leaf_hash(value: F2) -> [u8; 32] {
    magnetar_transcript::sha256_labeled(b"f2-native-leaf", &[value.value()])
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(left);
    bytes.extend_from_slice(right);
    magnetar_transcript::sha256_labeled(b"f2-native-node", &bytes)
}

fn merkle_layers(values: &[F2]) -> Vec<Vec<[u8; 32]>> {
    let padded = values.len().next_power_of_two();
    let mut leaves = values
        .iter()
        .map(|value| leaf_hash(*value))
        .collect::<Vec<_>>();
    leaves.resize(padded, leaf_hash(F2::from_u64(0u64)));
    let mut layers = vec![leaves];
    while layers.last().map_or(0, Vec::len) > 1 {
        let previous = layers.last().expect("nonempty");
        let mut next = Vec::with_capacity(previous.len() / 2);
        for pair in previous.chunks(2) {
            next.push(node_hash(&pair[0], &pair[1]));
        }
        layers.push(next);
    }
    layers
}

/// Binary Ligero-style systematic code: `message || parity`.
///
/// This is the first milestone of the native-F2 PCS path. Parity rows are
/// derived deterministically from SHA-256 labels, so the code is reproducible
/// without storing a large matrix. The codeword is committed with
/// [`F2NativePcs`]; the remaining Ligero work is the random linear-combination
/// test that turns index openings into an extension-point evaluation.
const PARITY_DEGREE: usize = 12;

fn parity_positions(row: usize, message_columns: usize) -> Vec<usize> {
    if message_columns == 0 {
        return Vec::new();
    }
    (0..PARITY_DEGREE)
        .map(|slot| {
            let mut label = Vec::with_capacity(24);
            label.extend_from_slice(&(row as u64).to_le_bytes());
            label.extend_from_slice(&(slot as u64).to_le_bytes());
            let hash = magnetar_transcript::sha256_labeled(b"f2-ligero-parity-position", &label);
            let mut value = [0u8; 8];
            value.copy_from_slice(&hash[..8]);
            (u64::from_le_bytes(value) as usize) % message_columns
        })
        .collect()
}

#[derive(Clone, Copy, Debug)]
pub struct BinaryLigeroCode {
    pub message_bits: usize,
    pub parity_bits: usize,
}

impl BinaryLigeroCode {
    pub fn new(message_bits: usize, parity_bits: usize) -> Self {
        Self {
            message_bits,
            parity_bits,
        }
    }

    pub fn codeword_bits(&self) -> usize {
        self.message_bits + self.parity_bits
    }

    pub fn parity(&self, row: usize, message: &[F2]) -> F2 {
        let mut bit = 0u8;
        for column in parity_positions(row, message.len()) {
            bit ^= message[column].value();
        }
        F2::from_u64(u64::from(bit))
    }

    pub fn parity_ext(&self, row: usize, message: &[F2_128]) -> F2_128 {
        let mut sum = F2_128::from(0u64);
        for column in parity_positions(row, message.len()) {
            sum = sum + message[column];
        }
        sum
    }

    pub fn encode(&self, message: &[F2]) -> Result<Vec<F2>, ProofError> {
        if message.len() != self.message_bits {
            return Err(ProofError::Pcs("Ligero message length mismatch".into()));
        }
        let mut codeword = message.to_vec();
        codeword.reserve(self.parity_bits);
        for row in 0..self.parity_bits {
            codeword.push(self.parity(row, message));
        }
        Ok(codeword)
    }
}

/// One column opening for the binary Ligero linear-functional check.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BinaryLigeroColumnOpening {
    pub column: usize,
    pub values: Vec<F2>,
    pub paths: Vec<F2NativeOpening>,
}

/// Opening for `v = Σ_j (Σ_i λ_i M[i][j])`.
///
/// This is the Ligero-style linear test: the prover sends the combined column
/// vector `s = λ·M`, the verifier checks `v = Σ_j s_j`, and samples columns to
/// check that each opened `M[·][j]` reproduces `s_j`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BinaryLigeroLinearProof {
    pub rows: usize,
    pub columns: usize,
    pub combination: Vec<F2_128>,
    pub samples: Vec<BinaryLigeroColumnOpening>,
}

impl BinaryLigeroLinearProof {
    pub fn sample_columns(
        commitment: &F2NativeCommitment,
        lambda: &[F2_128],
        columns: usize,
        count: usize,
    ) -> Vec<usize> {
        if columns == 0 || count == 0 {
            return Vec::new();
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&commitment.0);
        bytes.extend_from_slice(&(columns as u64).to_le_bytes());
        for weight in lambda {
            bytes.extend_from_slice(&weight.value().to_le_bytes());
        }
        let seed = magnetar_transcript::sha256_labeled(b"f2-ligero-samples", &bytes);
        (0..count)
            .map(|index| {
                let mut block = Vec::with_capacity(40);
                block.extend_from_slice(&seed);
                block.extend_from_slice(&(index as u64).to_le_bytes());
                let hash = magnetar_transcript::sha256_labeled(b"f2-ligero-column", &block);
                let mut value = [0u8; 8];
                value.copy_from_slice(&hash[..8]);
                (u64::from_le_bytes(value) as usize) % columns
            })
            .collect()
    }

    pub fn value(&self) -> F2_128 {
        self.combination
            .iter()
            .fold(F2_128::from(0u64), |sum, value| sum + *value)
    }

    pub fn prove(
        message: &[F2],
        rows: usize,
        columns: usize,
        lambda: &[F2_128],
        samples: &[usize],
    ) -> Result<Self, ProofError> {
        if rows == 0 || columns == 0 || message.len() != rows * columns {
            return Err(ProofError::Pcs("Ligero matrix shape mismatch".into()));
        }
        if lambda.len() != rows {
            return Err(ProofError::Pcs("Ligero lambda length mismatch".into()));
        }
        let mut combination = vec![F2_128::from(0u64); columns];
        for (row, weight) in lambda.iter().enumerate() {
            for column in 0..columns {
                if message[row * columns + column].value() == 1 {
                    combination[column] = combination[column] + *weight;
                }
            }
        }
        let pcs = F2NativePcs;
        let index_bits = ligero_index_bits(message.len());
        let mut opened = Vec::with_capacity(samples.len());
        for &column in samples {
            if column >= columns {
                return Err(ProofError::Pcs("Ligero sample column out of range".into()));
            }
            let mut values = Vec::with_capacity(rows);
            let mut paths = Vec::with_capacity(rows);
            for row in 0..rows {
                let index = row * columns + column;
                let point = ligero_index_point(index, index_bits);
                values.push(message[index]);
                paths.push(pcs.open(message, &point)?);
            }
            opened.push(BinaryLigeroColumnOpening {
                column,
                values,
                paths,
            });
        }
        Ok(Self {
            rows,
            columns,
            combination,
            samples: opened,
        })
    }

    pub fn verify(
        &self,
        commitment: &F2NativeCommitment,
        lambda: &[F2_128],
        claimed: F2_128,
    ) -> Result<bool, ProofError> {
        if self.rows == 0
            || self.columns == 0
            || self.combination.len() != self.columns
            || lambda.len() != self.rows
        {
            return Ok(false);
        }
        if self.value() != claimed {
            return Ok(false);
        }
        let expected = Self::sample_columns(commitment, lambda, self.columns, self.samples.len());
        if expected.len() != self.samples.len()
            || self
                .samples
                .iter()
                .zip(&expected)
                .any(|(sample, column)| sample.column != *column)
        {
            return Ok(false);
        }
        let pcs = F2NativePcs;
        let index_bits = ligero_index_bits(self.rows * self.columns);
        for sample in &self.samples {
            if sample.column >= self.columns
                || sample.values.len() != self.rows
                || sample.paths.len() != self.rows
            {
                return Ok(false);
            }
            let mut combined = F2_128::from(0u64);
            for (row, ((value, path), weight)) in sample
                .values
                .iter()
                .zip(&sample.paths)
                .zip(lambda)
                .enumerate()
            {
                if path.value != *value {
                    return Ok(false);
                }
                let index = row * self.columns + sample.column;
                let point = ligero_index_point(index, index_bits);
                if !pcs.verify(commitment, &point, path)? {
                    return Ok(false);
                }
                if value.value() == 1 {
                    combined = combined + *weight;
                }
            }
            if combined != self.combination[sample.column] {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn ligero_index_bits(len: usize) -> usize {
    len.saturating_sub(1).next_power_of_two().trailing_zeros() as usize
}

/// Lagrange weights `eq(point, index)` for an F2^128 point.
pub fn eq_weights(point: &[F2_128]) -> Vec<F2_128> {
    let size = 1usize << point.len();
    (0..size)
        .map(|index| {
            point
                .iter()
                .enumerate()
                .fold(F2_128::from(1u64), |weight, (bit, challenge)| {
                    if (index >> bit) & 1 == 1 {
                        weight * *challenge
                    } else {
                        weight * (F2_128::from(1u64) + *challenge)
                    }
                })
        })
        .collect()
}

fn ligero_index_point(index: usize, bits: usize) -> Vec<F2> {
    (0..bits)
        .map(|bit| F2::from_u64(((index >> bit) & 1) as u64))
        .collect()
}

/// Code-based Ligero linear opening over an interleaved systematic code.
///
/// Each row of the message matrix is encoded to `codeword_columns`; the
/// commitment is over the encoded matrix. The prover sends `s = λ·W`. The
/// verifier checks that `s` is a codeword (parity equations over `F2_128`) and
/// samples columns to compare `s_j` with `λ·W[:,j]`. Code distance makes the
/// unsampled positions sound.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BinaryLigeroCodedProof {
    pub rows: usize,
    pub message_columns: usize,
    pub parity_columns: usize,
    pub codeword: Vec<F2_128>,
    pub samples: Vec<BinaryLigeroColumnOpening>,
}

impl BinaryLigeroCodedProof {
    pub fn codeword_columns(&self) -> usize {
        self.message_columns + self.parity_columns
    }

    pub fn value(&self) -> F2_128 {
        self.codeword[..self.message_columns]
            .iter()
            .fold(F2_128::from(0u64), |sum, value| sum + *value)
    }

    pub fn sample_columns(
        commitment: &F2NativeCommitment,
        lambda: &[F2_128],
        codeword_columns: usize,
        count: usize,
    ) -> Vec<usize> {
        if codeword_columns == 0 || count == 0 {
            return Vec::new();
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&commitment.0);
        bytes.extend_from_slice(&(codeword_columns as u64).to_le_bytes());
        for weight in lambda {
            bytes.extend_from_slice(&weight.value().to_le_bytes());
        }
        let seed = magnetar_transcript::sha256_labeled(b"f2-ligero-coded-samples", &bytes);
        (0..count)
            .map(|index| {
                let mut block = Vec::with_capacity(40);
                block.extend_from_slice(&seed);
                block.extend_from_slice(&(index as u64).to_le_bytes());
                let hash = magnetar_transcript::sha256_labeled(b"f2-ligero-coded-column", &block);
                let mut value = [0u8; 8];
                value.copy_from_slice(&hash[..8]);
                (u64::from_le_bytes(value) as usize) % codeword_columns
            })
            .collect()
    }

    pub fn prove(
        message: &[F2],
        rows: usize,
        message_columns: usize,
        parity_columns: usize,
        lambda: &[F2_128],
        samples: &[usize],
    ) -> Result<Self, ProofError> {
        if rows == 0 || message_columns == 0 || message.len() != rows * message_columns {
            return Err(ProofError::Pcs("coded Ligero matrix shape mismatch".into()));
        }
        if lambda.len() != rows {
            return Err(ProofError::Pcs(
                "coded Ligero lambda length mismatch".into(),
            ));
        }
        let code = BinaryLigeroCode::new(message_columns, parity_columns);
        let codeword_columns = code.codeword_bits();
        let mut encoded = Vec::with_capacity(rows * codeword_columns);
        for row in 0..rows {
            let message_row = &message[row * message_columns..(row + 1) * message_columns];
            encoded.extend(code.encode(message_row)?);
        }
        let mut codeword = vec![F2_128::from(0u64); codeword_columns];
        for row in 0..rows {
            for column in 0..codeword_columns {
                if encoded[row * codeword_columns + column].value() == 1 {
                    codeword[column] = codeword[column] + lambda[row];
                }
            }
        }
        let pcs = F2NativePcs;
        let index_bits = ligero_index_bits(encoded.len());
        let mut opened = Vec::with_capacity(samples.len());
        for &column in samples {
            if column >= codeword_columns {
                return Err(ProofError::Pcs("coded Ligero sample out of range".into()));
            }
            let mut values = Vec::with_capacity(rows);
            let mut paths = Vec::with_capacity(rows);
            for row in 0..rows {
                let index = row * codeword_columns + column;
                let point = ligero_index_point(index, index_bits);
                values.push(encoded[index]);
                paths.push(pcs.open(&encoded, &point)?);
            }
            opened.push(BinaryLigeroColumnOpening {
                column,
                values,
                paths,
            });
        }
        Ok(Self {
            rows,
            message_columns,
            parity_columns,
            codeword,
            samples: opened,
        })
    }

    pub fn mle_value(&self, low_weights: &[F2_128]) -> Result<F2_128, ProofError> {
        if low_weights.len() != self.message_columns {
            return Err(ProofError::Pcs("Ligero MLE weight length mismatch".into()));
        }
        Ok(self.codeword[..self.message_columns]
            .iter()
            .zip(low_weights)
            .fold(F2_128::from(0u64), |sum, (value, weight)| {
                sum + *value * *weight
            }))
    }

    pub fn verify(
        &self,
        commitment: &F2NativeCommitment,
        lambda: &[F2_128],
    ) -> Result<bool, ProofError> {
        let code = BinaryLigeroCode::new(self.message_columns, self.parity_columns);
        let codeword_columns = code.codeword_bits();
        if self.rows == 0
            || self.message_columns == 0
            || self.codeword.len() != codeword_columns
            || lambda.len() != self.rows
        {
            return Ok(false);
        }
        let message = self.codeword[..self.message_columns].to_vec();
        let parity = self.codeword[self.message_columns..].to_vec();
        for (row, parity_value) in parity.iter().enumerate() {
            if code.parity_ext(row, &message) != *parity_value {
                return Ok(false);
            }
        }
        let expected =
            Self::sample_columns(commitment, lambda, codeword_columns, self.samples.len());
        if expected.len() != self.samples.len()
            || self
                .samples
                .iter()
                .zip(&expected)
                .any(|(sample, column)| sample.column != *column)
        {
            return Ok(false);
        }
        let pcs = F2NativePcs;
        let index_bits = ligero_index_bits(self.rows * codeword_columns);
        for sample in &self.samples {
            if sample.column >= codeword_columns
                || sample.values.len() != self.rows
                || sample.paths.len() != self.rows
            {
                return Ok(false);
            }
            let mut combined = F2_128::from(0u64);
            for (row, ((value, path), weight)) in sample
                .values
                .iter()
                .zip(&sample.paths)
                .zip(lambda)
                .enumerate()
            {
                if path.value != *value {
                    return Ok(false);
                }
                let index = row * codeword_columns + sample.column;
                let point = ligero_index_point(index, index_bits);
                if !pcs.verify(commitment, &point, path)? {
                    return Ok(false);
                }
                if value.value() == 1 {
                    combined = combined + *weight;
                }
            }
            if combined != self.codeword[sample.column] {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Native-F2 MLE PCS built from the coded Ligero proof.
#[derive(Clone, Debug)]
pub struct NativeF2LigeroPcs {
    pub rows: usize,
    pub message_columns: usize,
    pub parity_columns: usize,
    pub samples: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NativeF2LigeroCommitment {
    pub root: F2NativeCommitment,
    pub rows: usize,
    pub message_columns: usize,
    pub parity_columns: usize,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NativeF2LigeroOpening {
    pub proof: BinaryLigeroCodedProof,
}

impl NativeF2LigeroPcs {
    pub fn new(rows: usize, message_columns: usize, parity_columns: usize, samples: usize) -> Self {
        Self {
            rows,
            message_columns,
            parity_columns,
            samples,
        }
    }

    pub fn bits(&self) -> usize {
        self.rows * self.message_columns
    }

    fn encode(&self, bits: &[F2]) -> Result<Vec<F2>, ProofError> {
        if bits.len() != self.bits() {
            return Err(ProofError::Pcs("native F2 PCS bit length mismatch".into()));
        }
        let code = BinaryLigeroCode::new(self.message_columns, self.parity_columns);
        let mut encoded = Vec::with_capacity(self.rows * code.codeword_bits());
        for row in 0..self.rows {
            let start = row * self.message_columns;
            encoded.extend(code.encode(&bits[start..start + self.message_columns])?);
        }
        Ok(encoded)
    }

    pub fn commit(&self, bits: &[F2]) -> Result<NativeF2LigeroCommitment, ProofError> {
        let encoded = self.encode(bits)?;
        Ok(NativeF2LigeroCommitment {
            root: F2NativePcs.commit(&encoded)?,
            rows: self.rows,
            message_columns: self.message_columns,
            parity_columns: self.parity_columns,
        })
    }

    pub fn open(&self, bits: &[F2], point: &[F2_128]) -> Result<NativeF2LigeroOpening, ProofError> {
        if point.len()
            != self.rows.trailing_zeros() as usize + self.message_columns.trailing_zeros() as usize
        {
            return Err(ProofError::Pcs("native F2 PCS point arity".into()));
        }
        let encoded = self.encode(bits)?;
        let commitment = F2NativePcs.commit(&encoded)?;
        let low_bits = self.message_columns.trailing_zeros() as usize;
        let lambda = eq_weights(&point[low_bits..]);
        let codeword_columns = self.message_columns + self.parity_columns;
        let samples = BinaryLigeroCodedProof::sample_columns(
            &commitment,
            &lambda,
            codeword_columns,
            self.samples,
        );
        let proof = BinaryLigeroCodedProof::prove(
            bits,
            self.rows,
            self.message_columns,
            self.parity_columns,
            &lambda,
            &samples,
        )?;
        Ok(NativeF2LigeroOpening { proof })
    }

    pub fn verify(
        &self,
        commitment: &NativeF2LigeroCommitment,
        point: &[F2_128],
        opening: &NativeF2LigeroOpening,
    ) -> Result<Option<F2_128>, ProofError> {
        if commitment.rows != self.rows
            || commitment.message_columns != self.message_columns
            || commitment.parity_columns != self.parity_columns
        {
            return Ok(None);
        }
        let low_bits = self.message_columns.trailing_zeros() as usize;
        if point.len() != self.rows.trailing_zeros() as usize + low_bits {
            return Ok(None);
        }
        let lambda = eq_weights(&point[low_bits..]);
        if !opening.proof.verify(&commitment.root, &lambda)? {
            return Ok(None);
        }
        let low = eq_weights(&point[..low_bits]);
        Ok(Some(opening.proof.mle_value(&low)?))
    }
}

/// `Pcs` adapter for bit-valued Spartan vectors. Every value must be 0 or 1;
/// the native coded Ligero PCS handles the opening at F2^128 points.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeF2BitPcs {
    pub samples: usize,
}

impl NativeF2BitPcs {
    fn params(&self, len: usize) -> NativeF2LigeroPcs {
        NativeF2LigeroPcs::new(1, len, len, self.samples.max(16))
    }

    fn bits(values: &[F2_128]) -> Result<Vec<F2>, ProofError> {
        values
            .iter()
            .map(|value| match value.value() {
                0 => Ok(F2::from_u64(0u64)),
                1 => Ok(F2::from_u64(1u64)),
                _ => Err(ProofError::Pcs("native F2 PCS expects bit values".into())),
            })
            .collect()
    }
}

impl BitPcs for NativeF2BitPcs {
    type Commitment = NativeF2LigeroCommitment;
    type Opening = NativeF2LigeroOpening;

    fn commit(&self, bits: &[bool]) -> Result<Self::Commitment, ProofError> {
        let values = bits
            .iter()
            .map(|bit| F2::from_u64(u64::from(*bit)))
            .collect::<Vec<_>>();
        self.params(values.len()).commit(&values)
    }

    fn open(&self, bits: &[bool], point: &[F2_128]) -> Result<(F2_128, Self::Opening), ProofError> {
        let values = bits
            .iter()
            .map(|bit| F2::from_u64(u64::from(*bit)))
            .collect::<Vec<_>>();
        let pcs = self.params(values.len());
        let opening = pcs.open(&values, point)?;
        let value = Mle::new(
            values
                .iter()
                .map(|value| F2_128::from(u64::from(value.value())))
                .collect(),
        )?
        .eval(point)?;
        Ok((value, opening))
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &[F2_128],
        value: F2_128,
        opening: &Self::Opening,
    ) -> Result<bool, ProofError> {
        <Self as Pcs>::verify(self, commitment, point, value, opening)
    }

    fn commitment_bytes(&self, commitment: &Self::Commitment) -> Vec<u8> {
        bincode::serialize(commitment).unwrap_or_default()
    }
}

impl Pcs for NativeF2BitPcs {
    type Commitment = NativeF2LigeroCommitment;
    type Opening = NativeF2LigeroOpening;

    fn commit(&self, values: &[F2_128]) -> Result<Self::Commitment, ProofError> {
        let bits = Self::bits(values)?;
        self.params(bits.len()).commit(&bits)
    }

    fn open(&self, values: &[F2_128], point: &[F2_128]) -> Result<Self::Opening, ProofError> {
        let bits = Self::bits(values)?;
        self.params(bits.len()).open(&bits, point)
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &[F2_128],
        value: F2_128,
        opening: &Self::Opening,
    ) -> Result<bool, ProofError> {
        let pcs = NativeF2LigeroPcs::new(
            commitment.rows,
            commitment.message_columns,
            commitment.parity_columns,
            self.samples.max(16),
        );
        Ok(matches!(pcs.verify(commitment, point, opening)?, Some(actual) if actual == value))
    }

    fn commitment_bytes(&self, commitment: &Self::Commitment) -> Vec<u8> {
        bincode::serialize(commitment).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_constraint::Field;
    use magnetar_proof::Mle;

    #[test]
    fn native_f2_bit_pcs_proves_bit_spartan() {
        use magnetar_proof::dual_field::{BitRelation, BitRow};
        use magnetar_proof::{prove_spartan, verify_spartan};
        let mut relation = BitRelation::new(4);
        relation.add(BitRow::new(vec![0], vec![1], vec![2]));
        relation.add(BitRow::new(vec![3], vec![3], vec![3]));
        let witness = vec![false, true, false, true];
        let system = relation.to_system();
        let bits = relation.to_witness(&witness);
        let pcs = NativeF2BitPcs { samples: 32 };
        let proof = prove_spartan(&system, &bits, &pcs).unwrap();
        verify_spartan(&system, &proof, &pcs).unwrap();
    }

    #[test]
    fn native_f2_ligero_pcs_round_trips() {
        use magnetar_proof::Mle;
        let pcs = NativeF2LigeroPcs::new(8, 8, 8, 24);
        let bits = (0..pcs.bits())
            .map(|index| F2::from_u64(((index * 7 + 3) % 5) as u64 % 2))
            .collect::<Vec<_>>();
        let point = (0..6u64)
            .map(|bit| F2_128::from(bit * 13 + 5))
            .collect::<Vec<_>>();
        let commitment = pcs.commit(&bits).unwrap();
        let opening = pcs.open(&bits, &point).unwrap();
        let value = pcs.verify(&commitment, &point, &opening).unwrap().unwrap();
        let dense = Mle::new(
            bits.iter()
                .map(|bit| F2_128::from(u64::from(bit.value())))
                .collect(),
        )
        .unwrap()
        .eval(&point)
        .unwrap();
        assert_eq!(value, dense);
        let mut wrong = point.clone();
        wrong[0] = wrong[0] + F2_128::from(1u64);
        let wrong_value = pcs.verify(&commitment, &wrong, &opening).unwrap().unwrap();
        assert_ne!(wrong_value, dense);
    }

    #[test]
    fn binary_ligero_extension_mle_matches_dense_eval() {
        use magnetar_proof::Mle;
        let rows = 8usize;
        let message_columns = 8usize;
        let parity_columns = 8usize;
        let message = (0..rows * message_columns)
            .map(|index| F2::from_u64(((index * 13 + 7) % 9) as u64 % 2))
            .collect::<Vec<_>>();
        let code = BinaryLigeroCode::new(message_columns, parity_columns);
        let mut encoded = Vec::new();
        for row in 0..rows {
            encoded.extend(
                code.encode(&message[row * message_columns..(row + 1) * message_columns])
                    .unwrap(),
            );
        }
        let pcs = F2NativePcs;
        let commitment = pcs.commit(&encoded).unwrap();
        let point = (0..6u64)
            .map(|bit| F2_128::from(bit * 17 + 3))
            .collect::<Vec<_>>();
        let high = &point[3..];
        let low = &point[..3];
        let lambda = eq_weights(high);
        let low_weights = eq_weights(low);
        let columns = code.codeword_bits();
        let samples = BinaryLigeroCodedProof::sample_columns(&commitment, &lambda, columns, 24);
        let proof = BinaryLigeroCodedProof::prove(
            &message,
            rows,
            message_columns,
            parity_columns,
            &lambda,
            &samples,
        )
        .unwrap();
        assert!(proof.verify(&commitment, &lambda).unwrap());
        let opened = proof.mle_value(&low_weights).unwrap();
        let embedded = message
            .iter()
            .map(|bit| F2_128::from(u64::from(bit.value())))
            .collect::<Vec<_>>();
        let dense = Mle::new(embedded).unwrap().eval(&point).unwrap();
        assert_eq!(opened, dense);
    }

    #[test]
    fn binary_ligero_coded_opening_round_trips() {
        let rows = 8usize;
        let message_columns = 8usize;
        let parity_columns = 8usize;
        let message = (0..rows * message_columns)
            .map(|index| F2::from_u64(((index * 11 + 5) % 7) as u64 % 2))
            .collect::<Vec<_>>();
        let lambda = (0..rows)
            .map(|row| F2_128::from((row as u64) * 0x9e37 + 11))
            .collect::<Vec<_>>();
        let code = BinaryLigeroCode::new(message_columns, parity_columns);
        let mut encoded = Vec::new();
        for row in 0..rows {
            encoded.extend(
                code.encode(&message[row * message_columns..(row + 1) * message_columns])
                    .unwrap(),
            );
        }
        let pcs = F2NativePcs;
        let commitment = pcs.commit(&encoded).unwrap();
        let columns = code.codeword_bits();
        let samples = BinaryLigeroCodedProof::sample_columns(&commitment, &lambda, columns, 16);
        let proof = BinaryLigeroCodedProof::prove(
            &message,
            rows,
            message_columns,
            parity_columns,
            &lambda,
            &samples,
        )
        .unwrap();
        assert!(proof.verify(&commitment, &lambda).unwrap());
        let mut bad = proof.clone();
        bad.codeword[0] = bad.codeword[0] + F2_128::from(1u64);
        assert!(!bad.verify(&commitment, &lambda).unwrap());
        let mut bad = proof.clone();
        bad.samples[0].values[0] = F2::from_u64(u64::from(1 - bad.samples[0].values[0].value()));
        assert!(!bad.verify(&commitment, &lambda).unwrap());
    }

    #[test]
    fn binary_ligero_linear_opening_round_trips() {
        let rows = 8usize;
        let columns = 8usize;
        let message = (0..rows * columns)
            .map(|index| F2::from_u64(((index * 7 + 3) % 5) as u64 % 2))
            .collect::<Vec<_>>();
        let lambda = (0..rows)
            .map(|row| F2_128::from((row as u64) * 0x9e37 + 5))
            .collect::<Vec<_>>();
        let pcs = F2NativePcs;
        let commitment = pcs.commit(&message).unwrap();
        let samples = BinaryLigeroLinearProof::sample_columns(&commitment, &lambda, columns, 3);
        let proof =
            BinaryLigeroLinearProof::prove(&message, rows, columns, &lambda, &samples).unwrap();
        assert!(proof.verify(&commitment, &lambda, proof.value()).unwrap());
        let mut bad = proof.clone();
        bad.combination[0] = bad.combination[0] + F2_128::from(1u64);
        assert!(!bad.verify(&commitment, &lambda, bad.value()).unwrap());
        let mut bad = proof.clone();
        bad.samples[0].values[0] = F2::from_u64(u64::from(1 - bad.samples[0].values[0].value()));
        assert!(!bad.verify(&commitment, &lambda, proof.value()).unwrap());
    }

    #[test]
    fn binary_ligero_code_encodes_deterministically() {
        let code = BinaryLigeroCode::new(16, 8);
        let message = (0..16u64)
            .map(|index| F2::from_u64((index * 5 + 1) % 2))
            .collect::<Vec<_>>();
        let codeword = code.encode(&message).unwrap();
        assert_eq!(codeword.len(), code.codeword_bits());
        assert_eq!(codeword[..16], message[..]);
        assert_eq!(codeword, code.encode(&message).unwrap());
        let pcs = F2NativePcs;
        let commitment = pcs.commit(&codeword).unwrap();
        let point = (0..5u64)
            .map(|bit| F2::from_u64((bit + 1) % 2))
            .collect::<Vec<_>>();
        let opening = pcs.open(&codeword, &point).unwrap();
        assert!(pcs.verify(&commitment, &point, &opening).unwrap());
    }

    #[test]
    fn native_f2_merkle_opening_round_trips() {
        let pcs = F2NativePcs;
        let values = (0..16u64)
            .map(|index| F2::from_u64(index % 2))
            .collect::<Vec<_>>();
        let point = (0..4u64)
            .map(|bit| F2::from_u64((bit * 5 + 1) % 2))
            .collect::<Vec<_>>();
        let index = point
            .iter()
            .enumerate()
            .fold(0usize, |index, (bit, value)| {
                if value.value() == 1 {
                    index | (1 << bit)
                } else {
                    index
                }
            });
        let commitment = pcs.commit(&values).unwrap();
        let opening = pcs.open(&values, &point).unwrap();
        assert_eq!(opening.value, values[index]);
        assert!(pcs.verify(&commitment, &point, &opening).unwrap());
        let mut wrong = opening.clone();
        wrong.value = F2::from_u64(u64::from(1 - wrong.value.value()));
        assert!(!pcs.verify(&commitment, &point, &wrong).unwrap());
    }

    #[test]
    fn succinct_f2_opening_round_trips() {
        let pcs = F2Pcs::new(100);
        let values = (0..64u64)
            .map(|index| F2::from_u64(index.wrapping_mul(0x9e37_79b9)))
            .collect::<Vec<_>>();
        let point = (0..6u64)
            .map(|bit| F2_128::from((bit * 7 + 3) & 1))
            .collect::<Vec<_>>();
        let embedded = embed(&values);
        let value = Mle::new(embedded.clone()).unwrap().eval(&point).unwrap();
        let commitment = pcs.commit(&values).unwrap();
        let opening = pcs.open(&values, &point).unwrap();
        assert!(pcs
            .verify(
                &commitment,
                &point,
                F2::from_u64(value.value() as u64),
                &opening
            )
            .unwrap());

        let mut wrong = point.clone();
        wrong[0] = wrong[0] + F2_128::from(1u64);
        assert!(!pcs
            .verify(
                &commitment,
                &wrong,
                F2::from_u64(value.value() as u64),
                &opening
            )
            .unwrap());
    }
}
