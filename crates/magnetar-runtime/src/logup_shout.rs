//! Sound word-mode Shout via P3's logup* indexed-lookup reduction.
//!
//! The ROM table is public. Only the reader values and the dense position
//! column are committed. The logup* reduction proves `X[i] = ROM[I[i]]`, the
//! verifier checks the output table claims directly against the public ROM, and
//! one mosaic PCS opening discharges the reader and position claims.

use magnetar_constraint::F2_128;
use magnetar_pcs::{
    P3BatchCommitment, P3BatchOpening, P3BatchPoint, P3BinaryPcs,
};
use magnetar_proof::Pcs as _;
use magnetar_transcript::Sha256Transcript;
use p3_binary_field::{BinaryChallenger, BinaryField128, TowerLevel};
use p3_challenger::HashChallenger;
use p3_field::Field as P3Field;
use p3_keccak::Keccak256Hash;
use p3_multi_stark::logup_star::transcript::{LogupStarProverTranscript, LogupStarShape};
use p3_multi_stark::logup_star::{
    LogupStarOutput, LogupStarPlan, LogupStarProof, Reader, ReaderWitness, TableLookup,
    TableWitness,
};
use p3_multilinear_util::point::Point;
use serde::{Deserialize, Serialize};

use crate::{binary_shout::BinaryShoutWitness, RuntimeError};

type B = BinaryField128;
type Challenger = BinaryChallenger<B, HashChallenger<u8, Keccak256Hash, 32>>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogupShoutProof {
    pub address_bits: usize,
    pub cycle_bits: usize,
    pub cycles: usize,
    pub columns: usize,
    pub reader_claims: Vec<F2_128>,
    pub link_claims: Vec<F2_128>,
    pub rom_claims: Vec<F2_128>,
    pub rom_point: Vec<F2_128>,
    pub link_point: Vec<F2_128>,
    pub logup: LogupStarProof<B, B>,
    pub opening: P3BatchOpening,
}

/// Shout lookup proof whose reader/position witness is reconstructed from the
/// authenticated trace or claims. No PCS opening is carried: the verifier
/// recomputes the witness columns and checks the logup* output claims.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceLogupShoutProof {
    pub address_bits: usize,
    pub cycle_bits: usize,
    pub cycles: usize,
    pub columns: usize,
    pub reader_point: Vec<F2_128>,
    pub link_claims: Vec<F2_128>,
    pub link_point: Vec<F2_128>,
    pub logup: LogupStarProof<B, B>,
}

fn public_reader_point(
    rom_binding: &[u8; 32],
    witness: &BinaryShoutWitness,
    columns: usize,
) -> Point<B> {
    let mut transcript = Sha256Transcript::new("magnetar-trace-logup-shout-reader-point");
    transcript.absorb("address_bits", &(witness.address_bits as u64).to_le_bytes());
    transcript.absorb("cycle_bits", &(witness.cycle_bits as u64).to_le_bytes());
    transcript.absorb("cycles", &(witness.cycles as u64).to_le_bytes());
    transcript.absorb("columns", &(columns as u64).to_le_bytes());
    // The ROM digest binds every value the per-element absorb used to cover,
    // in one fixed-size absorb. Hashing the ROM element by element cost 272 ms
    // at RV64 `2^16` (a `2^17`-instruction ROM) in the verifier.
    transcript.absorb("rom", rom_binding);
    Point::new(
        (0..witness.cycle_bits)
            .map(|_| {
                let bytes = transcript.challenge_bytes("reader-point", 16);
                B::from_repr(u128::from_le_bytes(bytes.try_into().expect("16 bytes")))
            })
            .collect::<Vec<_>>(),
    )
}

fn challenger() -> Challenger {
    BinaryChallenger::from_hasher(b"magnetar-logup-shout".to_vec(), Keccak256Hash)
}

fn to_f2(value: B) -> F2_128 {
    F2_128::new(value.to_repr())
}

fn to_b(value: F2_128) -> B {
    B::from_repr(value.value())
}

fn embed(position: usize) -> B {
    // Sum of the interpolation nodes of `position`'s set bits. The 4-bit
    // nibble tables make that 16 lookups and 15 additions instead of up to 64
    // `interpolation_node` calls; the per-cycle embedding of `2^16` positions
    // was the largest part of the trace Logup-Shout verifier's final stage.
    static NIBBLES: std::sync::OnceLock<Vec<[B; 16]>> = std::sync::OnceLock::new();
    let nibbles = NIBBLES.get_or_init(|| {
        (0..usize::BITS as usize / 4)
            .map(|nibble| {
                let zero = B::from_repr(0);
                let mut table = [zero; 16];
                for value in 1..16usize {
                    let bit = value.trailing_zeros() as usize;
                    table[value] = table[value ^ (1 << bit)]
                        + B::interpolation_node(1 << (4 * nibble + bit));
                }
                table
            })
            .collect()
    });
    let mut sum = B::from_repr(0);
    let mut rest = position;
    for table in nibbles {
        sum += table[rest & 0xF];
        rest >>= 4;
    }
    sum
}

/// Build the public ROM's column vectors across workers. The ROM has
/// `columns` independent columns of `2^address_bits` rows, so the gather
/// parallelizes cleanly; only the verifier's trace path uses it.
fn rom_columns_parallel(witness: &BinaryShoutWitness) -> Vec<Vec<B>> {
    let columns = witness.rom.first().map_or(0, |row| row.len());
    let workers = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .max(1);
    if workers == 1 || columns <= 1 {
        return table_columns_from_witness(witness);
    }
    let chunk = columns.div_ceil(workers);
    let mut out = Vec::with_capacity(columns);
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for first in (0..columns).step_by(chunk) {
            let last = (first + chunk).min(columns);
            let rom = &witness.rom;
            handles.push(scope.spawn(move || {
                (first..last)
                    .map(|column| rom.iter().map(|row| to_b(row[column])).collect::<Vec<_>>())
                    .collect::<Vec<_>>()
            }));
        }
        for handle in handles {
            out.extend(handle.join().expect("rom column worker"));
        }
    });
    out
}

/// Evaluate independent column folds across workers, preserving order.
fn parallel_evals(columns: &[&[B]], point: &Point<B>) -> Vec<B> {
    let workers = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .max(1);
    if workers == 1 || columns.len() <= 1 {
        return columns.iter().map(|column| eval_mle(column, point)).collect();
    }
    let chunk = columns.len().div_ceil(workers);
    let mut results = Vec::with_capacity(columns.len());
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for first in (0..columns.len()).step_by(chunk) {
            let last = (first + chunk).min(columns.len());
            let slice = &columns[first..last];
            handles.push(scope.spawn(move || {
                slice
                    .iter()
                    .map(|column| eval_mle(column, point))
                    .collect::<Vec<_>>()
            }));
        }
        for handle in handles {
            results.extend(handle.join().expect("column worker"));
        }
    });
    results
}

/// Fold a vector in place (last coordinate first, adjacent pairs). Returns
/// `None` when the length does not match the point, so callers can fall back to
/// the generic multilinear evaluation.
fn fold_in_place(buffer: &mut Vec<B>, point: &Point<B>) -> Option<B> {
    let coordinates = point.as_slice();
    if buffer.len() != 1 << coordinates.len() {
        return None;
    }
    for x in coordinates.iter().rev() {
        let half = buffer.len() / 2;
        for index in 0..half {
            let low = buffer[2 * index];
            buffer[index] = low + (buffer[2 * index + 1] - low) * *x;
        }
        buffer.truncate(half);
    }
    Some(buffer[0])
}

/// Evaluate `table_columns[c]` at `point` over the row order `positions`
/// without materialising the gathered matrix: each worker builds one column
/// straight into its fold buffer. The gathered reader columns were 25 MB at
/// RV64 `2^16` (768 MB at `2^22`) and were only ever consumed by this fold.
fn eval_gathered(table_column: &[B], positions: &[usize], point: &Point<B>) -> B {
    let mut buffer = positions
        .iter()
        .map(|position| table_column[*position])
        .collect::<Vec<_>>();
    match fold_in_place(&mut buffer, point) {
        Some(value) => value,
        None => p3_multilinear_util::poly::Poly::new(buffer).eval_ext::<B>(point),
    }
}

/// Reader claims (gathered from the public ROM at `positions`) and link claims
/// (already column-major) in one fan-out.
fn eval_reader_and_link(
    table_columns: &[&[B]],
    positions: &[usize],
    link_columns: &[&[B]],
    point: &Point<B>,
) -> (Vec<B>, Vec<B>) {
    let workers = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .max(1);
    let readers = table_columns.len();
    let total = readers + link_columns.len();
    if workers == 1 || total <= 1 {
        let claims = table_columns
            .iter()
            .map(|column| eval_gathered(column, positions, point))
            .collect::<Vec<_>>();
        let links = link_columns
            .iter()
            .map(|column| eval_mle(column, point))
            .collect::<Vec<_>>();
        return (claims, links);
    }
    let chunk = total.div_ceil(workers);
    let mut results = Vec::with_capacity(total);
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for first in (0..total).step_by(chunk) {
            let last = (first + chunk).min(total);
            handles.push(scope.spawn(move || {
                (first..last)
                    .map(|task| {
                        if task < readers {
                            eval_gathered(table_columns[task], positions, point)
                        } else {
                            eval_mle(link_columns[task - readers], point)
                        }
                    })
                    .collect::<Vec<_>>()
            }));
        }
        for handle in handles {
            results.extend(handle.join().expect("claim column worker"));
        }
    });
    let links = results.split_off(readers);
    (results, links)
}

fn eval_mle(values: &[B], point: &Point<B>) -> B {
    // `Poly::eval_ext` switches to the packed split-eq tables above ten
    // variables, which costs ~10 us per element here (40 ms at RV64 `2^12`).
    // `fold_in_place` is the same interpolation order the packed path
    // implements, in O(values.len()) additions and multiplications. Measured:
    // folding through `F2_128` instead of `B` gave no speedup (both are the same
    // tower; the stage is bound by word traffic), so fold `B` directly.
    let mut buffer = values.to_vec();
    match fold_in_place(&mut buffer, point) {
        Some(value) => value,
        None => p3_multilinear_util::poly::Poly::new(buffer).eval_ext::<B>(point),
    }
}

fn reader_point(commitment_bytes: &[u8], cycle_bits: usize) -> Point<B> {
    let mut transcript = Sha256Transcript::new("magnetar-logup-shout-reader-point");
    transcript.absorb("commitment", commitment_bytes);
    Point::new(
        (0..cycle_bits)
            .map(|_| {
                let bytes = transcript.challenge_bytes("reader-point", 16);
                B::from_repr(u128::from_le_bytes(bytes.try_into().expect("16 bytes")))
            })
            .collect::<Vec<_>>(),
    )
}

fn table_columns_from_witness(witness: &BinaryShoutWitness) -> Vec<Vec<B>> {
    (0..witness.rom.first().map_or(0, |row| row.len()))
        .map(|column| {
            witness
                .rom
                .iter()
                .map(|row| to_b(row[column]))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn positions(witness: &BinaryShoutWitness) -> Result<Vec<usize>, RuntimeError> {
    (0..witness.cycles)
        .map(|cycle| {
            if witness.valid[cycle].value() == 0 {
                return Ok(0);
            }
            let mut index = 0usize;
            for bit in 0..witness.address_bits {
                if witness.address0[bit][cycle].value() != 0 {
                    index |= 1 << bit;
                }
            }
            let position = index + usize::from(witness.is_32[cycle].value() != 0);
            if position >= witness.cells {
                return Err(RuntimeError::Proof(
                    "logup Shout position outside ROM table".into(),
                ));
            }
            Ok(position)
        })
        .collect()
}

pub fn prove_logup_shout(witness: &BinaryShoutWitness) -> Result<LogupShoutProof, RuntimeError> {
    let table_columns = table_columns_from_witness(witness);
    let position_values = positions(witness)?;
    let columns = table_columns.len();
    let pcs = P3BinaryPcs::with_params(100, 4, 24, 3);
    let reader_columns = (0..columns)
        .map(|column| {
            position_values
                .iter()
                .map(|position| table_columns[column][*position])
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let link_columns = witness
        .link_columns()
        .into_iter()
        .map(|column| column.iter().map(|value| to_b(*value)).collect::<Vec<B>>())
        .collect::<Vec<_>>();
    let mut committed_columns = reader_columns.clone();
    committed_columns.extend(link_columns.iter().cloned());
    committed_columns.push(
        position_values
            .iter()
            .map(|position| embed(*position))
            .collect(),
    );
    let columns_f2 = committed_columns
        .iter()
        .map(|column| column.iter().map(|value| to_f2(*value)).collect::<Vec<F2_128>>())
        .collect::<Vec<_>>();
    let commitment = pcs
        .commit_batch(&columns_f2)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let commitment_bytes =
        bincode::serialize(&commitment).map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let point = reader_point(&commitment_bytes, witness.cycle_bits);
    let claims = (0..columns)
        .map(|column| eval_mle(&reader_columns[column], &point))
        .collect::<Vec<_>>();
    let link_claims = (0..link_columns.len())
        .map(|column| eval_mle(&link_columns[column], &point))
        .collect::<Vec<_>>();
    let readers = [Reader {
        point: &point,
        claims: &claims,
    }];
    let lookups = [TableLookup {
        num_variables: witness.address_bits,
        readers: &readers,
    }];
    let reader_witnesses = [ReaderWitness {
        positions: &position_values,
    }];
    let column_refs = table_columns
        .iter()
        .map(|column| column.as_slice())
        .collect::<Vec<_>>();
    let table_witness = [TableWitness {
        columns: &column_refs,
        readers: &reader_witnesses,
    }];
    let mut prover_challenger = challenger();
    let (logup, output) =
        LogupStarProof::<B, B>::prove(&lookups, &table_witness, &mut prover_challenger);
    let rom_point = output
        .table_point
        .iter()
        .rev()
        .map(|coordinate| to_f2(*coordinate))
        .collect::<Vec<_>>();
    let rom_claims = table_columns
        .iter()
        .map(|column| to_f2(eval_mle(column, &Point::new(output.table_point.as_slice().to_vec()))))
        .collect::<Vec<_>>();
    let points = vec![
        P3BatchPoint {
            point: point
                .iter()
                .rev()
                .map(|coordinate| to_f2(*coordinate))
                .collect(),
            columns: (0..columns + link_claims.len()).collect(),
        },
        P3BatchPoint {
            point: output
                .position_point
                .iter()
                .rev()
                .map(|coordinate| to_f2(*coordinate))
                .collect(),
            columns: vec![columns + link_claims.len()],
        },
    ];
    let opening = pcs
        .open_batch(&columns_f2, &points)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(LogupShoutProof {
        address_bits: witness.address_bits,
        cycle_bits: witness.cycle_bits,
        cycles: witness.cycles,
        columns,
        reader_claims: claims.iter().map(|claim| to_f2(*claim)).collect(),
        link_claims: link_claims.iter().map(|claim| to_f2(*claim)).collect(),
        rom_claims,
        rom_point,
        link_point: point
            .iter()
            .rev()
            .map(|coordinate| to_f2(*coordinate))
            .collect(),
        logup,
        opening,
    })
}

pub fn verify_logup_shout(
    proof: &LogupShoutProof,
    rom: &[Vec<F2_128>],
) -> Result<(), RuntimeError> {
    verify_logup_shout_with_output(proof, rom).map(|_| ())
}

/// Verify the committed Shout proof and return the logup* output claims.
pub fn verify_logup_shout_with_output(
    proof: &LogupShoutProof,
    rom: &[Vec<F2_128>],
) -> Result<LogupStarOutput<B>, RuntimeError> {
    let mut reader_columns = proof
        .reader_claims
        .iter()
        .map(|_| Vec::<B>::new())
        .collect::<Vec<_>>();
    let _ = &mut reader_columns;
    if proof.cycles != 1usize << proof.cycle_bits
        || proof.address_bits >= usize::BITS as usize
        || rom.len() != 1usize << proof.address_bits
        || rom.iter().any(|row| row.len() != proof.columns)
        || proof.reader_claims.len() != proof.columns
        || proof.link_claims.len() != proof.columns
        || proof.rom_claims.len() != proof.columns
        || proof.link_point.len() != proof.cycle_bits
        || proof.rom_point.len() != proof.address_bits
    {
        return Err(RuntimeError::Proof(
            "logup Shout statement shape mismatch".into(),
        ));
    }
    let pcs = P3BinaryPcs::with_params(100, 4, 24, 3);
    let commitment_bytes =
        bincode::serialize(&proof.opening.commitment).map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let point = reader_point(&commitment_bytes, proof.cycle_bits);
    let claims = proof
        .reader_claims
        .iter()
        .map(|claim| to_b(*claim))
        .collect::<Vec<_>>();
    let readers = [Reader {
        point: &point,
        claims: &claims,
    }];
    let lookups = [TableLookup {
        num_variables: proof.address_bits,
        readers: &readers,
    }];
    let mut challenger = challenger();
    let output = proof
        .logup
        .verify(&lookups, &mut challenger)
        .map_err(|error| RuntimeError::Proof(format!("logup Shout reduction: {error:?}")))?;
    let table_point = output.table_point.as_slice();
    let expected_rom_point = output
        .table_point
        .iter()
        .rev()
        .map(|coordinate| to_f2(*coordinate))
        .collect::<Vec<_>>();
    if proof.rom_point != expected_rom_point {
        return Err(RuntimeError::Proof("logup Shout ROM point mismatch".into()));
    }
    let expected_link_point = point
        .iter()
        .rev()
        .map(|coordinate| to_f2(*coordinate))
        .collect::<Vec<_>>();
    if proof.link_point != expected_link_point {
        return Err(RuntimeError::Proof("logup Shout link point mismatch".into()));
    }
    for (column, claim) in output.tables[0].column_claims.iter().enumerate() {
        let values = rom
            .iter()
            .map(|row| to_b(row[column]))
            .collect::<Vec<_>>();
        let direct = eval_mle(&values, &Point::new(table_point.to_vec()));
        if direct != *claim {
            return Err(RuntimeError::Proof(format!(
                "public ROM table claim mismatch at column {column}"
            )));
        }
        if direct != to_b(proof.rom_claims[column]) {
            return Err(RuntimeError::Proof(format!(
                "logup Shout ROM claim mismatch at column {column}"
            )));
        }
    }
    let points = vec![
        P3BatchPoint {
            point: point
                .iter()
                .rev()
                .map(|coordinate| to_f2(*coordinate))
                .collect(),
            columns: (0..proof.columns * 2).collect(),
        },
        P3BatchPoint {
            point: output
                .position_point
                .iter()
                .rev()
                .map(|coordinate| to_f2(*coordinate))
                .collect(),
            columns: vec![proof.columns * 2],
        },
    ];
    let mut reader_values = claims.iter().map(|claim| to_f2(*claim)).collect::<Vec<_>>();
    reader_values.extend(proof.link_claims.iter().copied());
    let values = vec![
        reader_values,
        vec![to_f2(output.tables[0].position_claims[0])],
    ];
    if !pcs
        .verify_batch(&proof.opening, &points, &values)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
    {
        return Err(RuntimeError::Proof("logup Shout PCS opening rejected".into()));
    }
    Ok(output)
}

/// Verify a committed Shout proof and additionally bind its reader/link/
/// position claims to a supplied witness. This closes the gap between the
/// standalone Shout lookup and the authenticated trace/claim layer.
pub fn verify_logup_shout_against_witness(
    proof: &LogupShoutProof,
    witness: &BinaryShoutWitness,
) -> Result<(), RuntimeError> {
    let table_columns = table_columns_from_witness(witness);
    let position_values = positions(witness)?;
    let commitment_bytes = bincode::serialize(&proof.opening.commitment)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let point = reader_point(&commitment_bytes, witness.cycle_bits);
    let reader_columns = (0..table_columns.len())
        .map(|column| {
            position_values
                .iter()
                .map(|position| table_columns[column][*position])
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let expected_reader = reader_columns
        .iter()
        .map(|column| to_f2(eval_mle(column, &point)))
        .collect::<Vec<_>>();
    let link_columns = witness
        .link_columns()
        .into_iter()
        .map(|column| column.iter().map(|value| to_b(*value)).collect::<Vec<B>>())
        .collect::<Vec<_>>();
    let expected_link = link_columns
        .iter()
        .map(|column| to_f2(eval_mle(column, &point)))
        .collect::<Vec<_>>();
    let claims_b = expected_reader
        .iter()
        .map(|claim| to_b(*claim))
        .collect::<Vec<_>>();
    let readers = [Reader {
        point: &point,
        claims: &claims_b,
    }];
    let lookups = [TableLookup {
        num_variables: witness.address_bits,
        readers: &readers,
    }];
    let reader_witnesses = [ReaderWitness {
        positions: &position_values,
    }];
    let column_refs = table_columns
        .iter()
        .map(|column| column.as_slice())
        .collect::<Vec<_>>();
    let table_witness = [TableWitness {
        columns: &column_refs,
        readers: &reader_witnesses,
    }];
    let mut pushforward_challenger = challenger();
    let pushforwards = p3_multi_stark::logup_star::rebuild_pushforwards(
        &lookups,
        &table_witness,
        &mut pushforward_challenger,
    )
    .map_err(|error| RuntimeError::Proof(format!("committed Shout pushforwards: {error:?}")))?;
    let mut owned = proof.clone();
    owned.logup.pushforwards = pushforwards;
    let output = verify_logup_shout_with_output(&owned, &witness.rom)?;
    if proof.reader_claims != expected_reader {
        return Err(RuntimeError::Proof(
            "committed Shout reader claims do not match the witness".into(),
        ));
    }
    if proof.link_claims != expected_link {
        return Err(RuntimeError::Proof(
            "committed Shout link claims do not match the witness".into(),
        ));
    }
    let position_columns = position_values
        .iter()
        .map(|position| embed(*position))
        .collect::<Vec<_>>();
    let expected_position = eval_mle(
        &position_columns,
        &Point::new(output.position_point.as_slice().to_vec()),
    );
    if output.tables[0].position_claims[0] != expected_position {
        return Err(RuntimeError::Proof(
            "committed Shout position claim does not match the witness".into(),
        ));
    }
    Ok(())
}

pub fn prove_trace_logup_shout(
    witness: &BinaryShoutWitness,
    rom_binding: [u8; 32],
) -> Result<TraceLogupShoutProof, RuntimeError> {
    let table_columns = table_columns_from_witness(witness);
    let position_values = positions(witness)?;
    let columns = table_columns.len();
    let reader_columns = (0..columns)
        .map(|column| {
            position_values
                .iter()
                .map(|position| table_columns[column][*position])
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let point = public_reader_point(&rom_binding, witness, columns);
    let claims = (0..columns)
        .map(|column| eval_mle(&reader_columns[column], &point))
        .collect::<Vec<_>>();
    let readers = [Reader {
        point: &point,
        claims: &claims,
    }];
    let lookups = [TableLookup {
        num_variables: witness.address_bits,
        readers: &readers,
    }];
    let reader_witnesses = [ReaderWitness {
        positions: &position_values,
    }];
    let column_refs = table_columns
        .iter()
        .map(|column| column.as_slice())
        .collect::<Vec<_>>();
    let table_witness = [TableWitness {
        columns: &column_refs,
        readers: &reader_witnesses,
    }];
    let link_columns = witness
        .link_columns()
        .into_iter()
        .map(|column| column.iter().map(|value| to_b(*value)).collect::<Vec<B>>())
        .collect::<Vec<_>>();
    let link_claims = link_columns
        .iter()
        .map(|column| eval_mle(column, &point))
        .collect::<Vec<_>>();
    let mut prover_challenger = challenger();
    let (mut logup, _output) =
        LogupStarProof::<B, B>::prove(&lookups, &table_witness, &mut prover_challenger);
    logup.pushforwards.clear();
    Ok(TraceLogupShoutProof {
        address_bits: witness.address_bits,
        cycle_bits: witness.cycle_bits,
        cycles: witness.cycles,
        columns,
        reader_point: point
            .iter()
            .rev()
            .map(|coordinate| to_f2(*coordinate))
            .collect(),
        link_claims: link_claims.iter().map(|claim| to_f2(*claim)).collect(),
        link_point: point
            .iter()
            .rev()
            .map(|coordinate| to_f2(*coordinate))
            .collect(),
        logup,
    })
}

pub fn verify_trace_logup_shout(
    proof: &TraceLogupShoutProof,
    witness: &BinaryShoutWitness,
    rom_binding: &[u8; 32],
) -> Result<(), RuntimeError> {
    if proof.cycles != 1usize << proof.cycle_bits
        || proof.address_bits != witness.address_bits
        || proof.cycle_bits != witness.cycle_bits
        || proof.cycles != witness.cycles
        || proof.reader_point.len() != proof.cycle_bits
        || proof.link_claims.len() != 12
        || proof.link_point != proof.reader_point
        || witness.rom.len() != 1usize << proof.address_bits
        || witness.rom.iter().any(|row| row.len() != proof.columns)
    {
        return Err(RuntimeError::Proof(
            "trace logup Shout statement mismatch".into(),
        ));
    }
    let profile = std::env::var_os("MAGNETAR_PROFILE_VERIFY").is_some();
    let stage_started = std::time::Instant::now();
    let table_columns = rom_columns_parallel(witness);
    let position_values = positions(witness)?;
    if profile {
        eprintln!("trace logup columns+positions: {:?}", stage_started.elapsed());
    }
    if table_columns.len() != proof.columns {
        return Err(RuntimeError::Proof(
            "trace logup Shout column mismatch".into(),
        ));
    }
    let stage_started = std::time::Instant::now();
    let point = public_reader_point(rom_binding, witness, proof.columns);
    let expected_point = point
        .iter()
        .rev()
        .map(|coordinate| to_f2(*coordinate))
        .collect::<Vec<_>>();
    if proof.reader_point != expected_point {
        return Err(RuntimeError::Proof(
            "trace logup Shout reader point mismatch".into(),
        ));
    }
    // Reader and link claims fold at the same point; one fan-out over both
    // groups costs a single round of worker spawns instead of two.
    let link_columns = witness
        .link_columns()
        .into_iter()
        .map(|column| column.iter().map(|value| to_b(*value)).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    if profile {
        eprintln!("trace logup point build: {:?}", stage_started.elapsed());
    }
    let stage_started = std::time::Instant::now();
    let table_slices = table_columns
        .iter()
        .map(|column| column.as_slice())
        .collect::<Vec<_>>();
    let link_slices = link_columns
        .iter()
        .map(|column| column.as_slice())
        .collect::<Vec<_>>();
    let (claims, expected_link_claims) =
        eval_reader_and_link(&table_slices, &position_values, &link_slices, &point);
    if profile {
        eprintln!(
            "trace logup reader+link claims ({} + {} cols x {} rows): {:?}",
            proof.columns,
            link_columns.len(),
            position_values.len(),
            stage_started.elapsed()
        );
    }
    if proof
        .link_claims
        .iter()
        .zip(&expected_link_claims)
        .any(|(claim, expected)| to_b(*claim) != *expected)
    {
        return Err(RuntimeError::Proof(
            "trace logup Shout link claims mismatch".into(),
        ));
    }
    let stage_started = std::time::Instant::now();
    let readers = [Reader {
        point: &point,
        claims: &claims,
    }];
    let lookups = [TableLookup {
        num_variables: proof.address_bits,
        readers: &readers,
    }];
    let reader_witnesses = [ReaderWitness {
        positions: &position_values,
    }];
    let column_refs = table_columns
        .iter()
        .map(|column| column.as_slice())
        .collect::<Vec<_>>();
    let table_witness = [TableWitness {
        columns: &column_refs,
        readers: &reader_witnesses,
    }];
    let mut pushforward_challenger = challenger();
    let pushforwards = p3_multi_stark::logup_star::rebuild_pushforwards(
        &lookups,
        &table_witness,
        &mut pushforward_challenger,
    )
    .map_err(|error| RuntimeError::Proof(format!("trace logup Shout pushforwards: {error:?}")))?;
    if profile {
        eprintln!("trace logup pushforwards rebuild: {:?}", stage_started.elapsed());
    }
    let stage_started = std::time::Instant::now();
    let mut logup = proof.logup.clone();
    logup.pushforwards = pushforwards;
    let mut verifier_challenger = challenger();
    let output = logup
        .verify(&lookups, &mut verifier_challenger)
        .map_err(|error| RuntimeError::Proof(format!("trace logup Shout reduction: {error:?}")))?;
    if profile {
        eprintln!("trace logup reduction verify: {:?}", stage_started.elapsed());
    }
    let stage_started = std::time::Instant::now();
    let table_point = Point::new(output.table_point.as_slice().to_vec());
    // The ROM columns were already gathered for the reader side above; the
    // table claims fold the same vectors, so reuse them instead of building a
    // second copy (25 MB and 1.5 M conversions at RV64 `2^16`).
    let rom_slices = table_columns
        .iter()
        .map(|column| column.as_slice())
        .collect::<Vec<_>>();
    let direct_claims = parallel_evals(&rom_slices, &table_point);
    for (column, (direct, claim)) in direct_claims
        .iter()
        .zip(&output.tables[0].column_claims)
        .enumerate()
    {
        if direct != claim {
            return Err(RuntimeError::Proof(format!(
                "trace logup Shout table claim mismatch at column {column}"
            )));
        }
    }
    let position_values_b = position_values
        .iter()
        .map(|position| embed(*position))
        .collect::<Vec<_>>();
    let position_claim = eval_mle(&position_values_b, &Point::new(output.position_point.as_slice().to_vec()));
    if output.tables[0].position_claims[0] != position_claim {
        return Err(RuntimeError::Proof(
            "trace logup Shout position claim mismatch".into(),
        ));
    }
    if profile {
        eprintln!("trace logup final claims: {:?}", stage_started.elapsed());
    }
    Ok(())
}

pub fn trace_logup_shout_link_claims(
    proof: &TraceLogupShoutProof,
    witness: &BinaryShoutWitness,
) -> Result<(Vec<F2_128>, Vec<F2_128>, F2_128), RuntimeError> {
    let columns = witness.link_columns();
    let point = Point::new(
        proof
            .reader_point
            .iter()
            .rev()
            .map(|coordinate| to_b(*coordinate))
            .collect(),
    );
    let width = columns[..4]
        .iter()
        .map(|column| {
            let values = column.iter().map(|value| to_b(*value)).collect::<Vec<B>>();
            to_f2(eval_mle(&values, &point))
        })
        .collect::<Vec<_>>();
    let mut code = F2_128::from(0u64);
    for (bit, column) in columns[4..].iter().enumerate() {
        let values = column.iter().map(|value| to_b(*value)).collect::<Vec<B>>();
        if to_f2(eval_mle(&values, &point)).value() == 1 {
            code = code + F2_128::from(1u128 << bit);
        }
    }
    Ok((proof.reader_point.clone(), width, code))
}

pub fn logup_shout_proof_size(proof: &LogupShoutProof) -> Result<usize, RuntimeError> {
    bincode::serialize(proof)
        .map(|bytes| bytes.len())
        .map_err(|error| RuntimeError::Proof(error.to_string()))
}

// ---------------------------------------------------------------------------
// M4 v3: linear Shout with **committed pushforwards** (opt-in, default off).
//
// Same linear `logup_shout` reduction as the classic trace path. The verifier no
// longer rebuilds the Shout witness; instead ONE batched PCS commitment covers
// the three tables the check needs:
//
// * column 0, `T_word`: the reader word column (host-derived from the claim
//   rows; padding cycles read `ROM[0]`, exactly what `positions()` induces);
// * column 1, `T_pos`: the position embedding column (`embed((pc - rom_base) / 4)`,
//   padding cycles 0);
// * column 2, `T_pf`: the pushforward table (`Y[v] = sum_{i : pos_i = v} eq_r(i)`).
//
// All three are padded to the common length `2^max(cycle_bits, address_bits)` and
// committed with one `commit_batch_prepared`, then opened with ONE
// `open_batch_prepared` covering every point the check needs (reader, position,
// reduction, product). Four independent openings at 2^16 were ~127 KB each; one
// batch opening is one query set, which is what keeps the proof inside budget.
//
// Fiat-Shamir (two independent bindings):
// * the reader point is sampled from PUBLIC statement data (ROM binding,
//   `trace_len`, cycles, address bits) before any table commitment is formed,
//   so the pushforward table is fixed without a circular dependency;
// * the batched commitment is formed BEFORE `LogupStarProof::prove_committed`,
//   whose binder returns the canonical digest of that commitment. The verifier
//   recomputes the same digest from the proof's commitment, so the reduction's
//   challenges are bound to the actual table.
// The statement root then binds the same commitment again (host-derived v3 root).
//
// The three tables are host-derived at statement construction (same trust model
// as the M2/M3 claim table). Everything here is additive; the classic
// `prove_logup_shout` / `verify_logup_shout*` paths are untouched.

const COMMITTED_DOMAIN: &[u8] = b"magnetar-committed-logup-shout-v1";

/// PCS for the batched single-table commitments.
fn committed_pcs() -> P3BinaryPcs {
    P3BinaryPcs::with_params(100, 3, 20, 3)
}

fn committed_sha(label: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut buffer = COMMITTED_DOMAIN.to_vec();
    buffer.extend_from_slice(label);
    buffer.extend_from_slice(bytes);
    magnetar_transcript::sha256(&buffer)
}

/// Root/digest of the batched committed tables.
///
/// Used both as the statement-root component and as the Fiat-Shamir binding the
/// prover hands to `LogupStarProof::prove_committed`.
pub fn committed_tables_root(commitment: &P3BatchCommitment) -> [u8; 32] {
    committed_sha(
        b"tables",
        &bincode::serialize(commitment).unwrap_or_default(),
    )
}

/// Transcript binding of the batched pushforward table (absorbed instead of the
/// table-wide vector).
pub fn pushforward_binding(commitment: &P3BatchCommitment) -> [u8; 32] {
    committed_sha(
        b"pushforward-binding",
        &bincode::serialize(commitment).unwrap_or_default(),
    )
}

/// Public Fiat-Shamir reader point for the committed tables.
///
/// Derived only from statement data, before the table commitment exists, so the
/// statement builder and the prover agree on the point that fixes the
/// pushforward table.
pub fn committed_reader_point(
    rom_binding: &[u8; 32],
    trace_len: u64,
    cycle_bits: usize,
    address_bits: usize,
) -> Point<B> {
    let mut transcript = Sha256Transcript::new("magnetar-committed-logup-reader-point");
    transcript.absorb("rom", rom_binding);
    transcript.absorb("trace_len", &trace_len.to_le_bytes());
    transcript.absorb("cycle_bits", &(cycle_bits as u64).to_le_bytes());
    transcript.absorb("address_bits", &(address_bits as u64).to_le_bytes());
    Point::new(
        (0..cycle_bits)
            .map(|_| {
                let bytes = transcript.challenge_bytes("reader-point", 16);
                B::from_repr(u128::from_le_bytes(bytes.try_into().expect("16 bytes")))
            })
            .collect::<Vec<_>>(),
    )
}

/// Host-side Shout columns for the committed path (from the Shout witness):
/// `(reader word column, position embedding column)`.
pub fn committed_columns_from_witness(
    witness: &BinaryShoutWitness,
) -> Result<(Vec<F2_128>, Vec<F2_128>), RuntimeError> {
    if witness.rom.is_empty() {
        return Err(RuntimeError::Proof("committed logup Shout: empty ROM".into()));
    }
    let table_column = witness
        .rom
        .iter()
        .map(|row| row[0])
        .collect::<Vec<F2_128>>();
    let positions = positions(witness)?;
    // `positions()` maps padding cycles to 0, so the reader word column reads
    // `ROM[0]` there, matching the classic prover's `reader_columns`.
    let word = positions
        .iter()
        .map(|position| table_column[*position])
        .collect::<Vec<_>>();
    let pos = positions
        .iter()
        .map(|position| to_f2(embed(*position)))
        .collect::<Vec<_>>();
    Ok((word, pos))
}

/// Host-side Shout columns for the committed path, derived from the trace at
/// statement construction (same values [`committed_columns_from_witness`]
/// produces: real rows read `ROM[(pc - rom_base) / 4]`, padding rows read
/// `ROM[0]`; the position column is `embed((pc - rom_base) / 4)`, padding 0).
pub fn committed_columns_from_trace(
    trace: &magnetar_spec::Trace,
) -> Result<(Vec<F2_128>, Vec<F2_128>), RuntimeError> {
    if trace.rows.iter().any(|row| row.instruction_len != 4) {
        return Err(RuntimeError::Proof(
            "committed logup Shout requires word mode (4-byte instructions)".into(),
        ));
    }
    let rom_base = trace.config.rom_base;
    let cycles = trace.rows.len().next_power_of_two().max(2);
    let rom_first = trace
        .rom
        .first()
        .map(|word| F2_128::from(u64::from(*word)))
        .ok_or_else(|| RuntimeError::Proof("committed logup Shout: empty ROM".into()))?;
    let cells = trace.rom.len().next_power_of_two().max(2);
    let mut word = vec![rom_first; cycles];
    let mut pos = vec![F2_128::from(0u64); cycles];
    for (cycle, row) in trace.rows.iter().enumerate() {
        let offset = row
            .pc
            .checked_sub(rom_base)
            .ok_or_else(|| RuntimeError::Proof("row pc is below the ROM base".into()))?;
        if offset % 4 != 0 {
            return Err(RuntimeError::Proof(
                "word-mode PC is not word aligned".into(),
            ));
        }
        let position = usize::try_from(offset / 4)
            .map_err(|_| RuntimeError::Proof("ROM index overflows usize".into()))?;
        if position >= cells {
            return Err(RuntimeError::Proof(
                "row pc is outside the ROM table".into(),
            ));
        }
        word[cycle] = F2_128::from(u64::from(row.instruction_word));
        pos[cycle] = to_f2(embed(position));
    }
    Ok((word, pos))
}

/// SHA-256 of a classic (`prove_logup_shout`) proof encoding.
pub fn logup_proof_encoding_hash(proof: &LogupShoutProof) -> [u8; 32] {
    magnetar_transcript::sha256(&bincode::serialize(proof).unwrap_or_default())
}

/// Golden hash of the classic `logup_shout` proof encoding.
pub const GOLDEN_OLD_LOGUP_ENCODING: Option<[u8; 32]> = Some([
    0xf3, 0x96, 0xfd, 0x79, 0x9e, 0xc5, 0xb7, 0xe5, 0xa8, 0xfc, 0x1f, 0x92, 0x69, 0x4e, 0x9f, 0x08,
    0xce, 0x45, 0x47, 0x23, 0x31, 0x74, 0x00, 0xa7, 0xe0, 0x29, 0x30, 0xdd, 0x80, 0x40, 0x25, 0xaf,
]);

/// Rejection message when a verifier expects M4 v3 but the proof predates it.
pub const PRE_M4V3_ERROR: &str =
    "pre-M4v3 proof: committed logup-Shout proof missing (set MAGNETAR_CLASSIC_LOGUP=1 for the legacy path)";

/// M4 v3 opt-in switch: use the committed-pushforward linear Shout.
pub fn linear_shout_enabled() -> bool {
    if classic_logup_enabled() {
        return false;
    }
    crate::trace_free::trace_free_enabled()
        || matches!(
            std::env::var("MAGNETAR_LINEAR_SHOUT").ok().as_deref(),
            Some("1" | "on" | "true" | "yes")
        )
}

/// Force the classic trace Logup-Shout path (A/B regression switch).
pub fn classic_logup_enabled() -> bool {
    matches!(
        std::env::var("MAGNETAR_CLASSIC_LOGUP").ok().as_deref(),
        Some("1" | "on" | "true" | "yes")
    )
}

/// Linear Shout proof with committed pushforwards (M4 v3).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommittedLogupShoutProof {
    pub address_bits: usize,
    pub cycle_bits: usize,
    pub cycles: usize,
    pub columns: usize,
    /// Common committed table arity (`max(cycle_bits, address_bits)`).
    pub table_variables: usize,
    /// Public FS reader point (wire coordinate order, low coordinate first).
    pub reader_point: Vec<F2_128>,
    /// Reader word MLE at `reader_point`.
    pub reader_claim: F2_128,
    /// One batched commitment over the three tables.
    pub table_commitment: P3BatchCommitment,
    /// One batched opening covering every point the check needs.
    pub opening: P3BatchOpening,
    /// Pushforward values at the fraction reduction's table-block points.
    pub reduction_evals: Vec<F2_128>,
    /// Pushforward values at the product sumcheck's per-table points.
    pub product_evals: Vec<F2_128>,
    pub logup: LogupStarProof<B, B>,
}

/// What committed Shout verification hands back to the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedLogupShoutOutput {
    /// Reader word MLE at the reader point (authenticated by the opening).
    pub reader_claim: F2_128,
    /// Position-column MLE at the logup position point (authenticated by the
    /// position-column opening; the caller binds it to the claim table if it has
    /// the host-derived position column in its statement root, which it does).
    pub position_claim: F2_128,
    /// Public FS reader point (wire coordinate order).
    pub reader_point: Vec<F2_128>,
    /// Public ROM word claim at the logup table point.
    pub rom_claim: F2_128,
}

/// Common table arity for the batched commitment.
fn committed_table_bits(cycle_bits: usize, address_bits: usize) -> usize {
    cycle_bits.max(address_bits)
}

/// Pad a cycle-indexed column to `1 << table_bits` entries.
fn pad_column(values: &[F2_128], table_bits: usize) -> Vec<F2_128> {
    let mut column = vec![F2_128::from(0u64); 1usize << table_bits];
    column[..values.len()].copy_from_slice(values);
    column
}

/// Wire-order point from a p3 point over `variables` coordinates padded to
/// `table_bits` (the PCS reverses the wire slice, so the caller passes the
/// low-coordinate-first order that `P3BinaryPcs::point` reverses).
fn padded_wire_point(point: &[B], table_bits: usize) -> Vec<F2_128> {
    let mut coordinates = point
        .iter()
        .map(|coordinate| to_f2(*coordinate))
        .collect::<Vec<_>>();
    coordinates.resize(table_bits, F2_128::from(0u64));
    // `P3BinaryPcs::point` reverses its input, so hand it the reverse of the
    // intended coordinate order.
    coordinates.reverse();
    coordinates
}

/// Prover for the committed-pushforward linear Shout (word-mode reader).
///
/// Returns the proof and the table root the caller composes into the statement
/// root.
pub fn prove_committed_logup_shout(
    witness: &BinaryShoutWitness,
    rom_binding: &[u8; 32],
    trace_len: u64,
) -> Result<(CommittedLogupShoutProof, [u8; 32]), RuntimeError> {
    let cells = 1usize << witness.address_bits;
    if witness.rom.len() != cells || witness.rom.iter().any(|row| row.is_empty()) {
        return Err(RuntimeError::Proof(
            "committed logup Shout ROM shape mismatch".into(),
        ));
    }
    let (word_values, pos_values) = committed_columns_from_witness(witness)?;
    let word_b = word_values
        .iter()
        .map(|value| to_b(*value))
        .collect::<Vec<_>>();
    let point = committed_reader_point(
        rom_binding,
        trace_len,
        witness.cycle_bits,
        witness.address_bits,
    );
    let reader_claim = eval_mle(&word_b, &point);
    let table_bits = committed_table_bits(witness.cycle_bits, witness.address_bits);
    let pcs = committed_pcs();
    let readers = [Reader {
        point: &point,
        claims: &[reader_claim],
    }];
    let lookups = [TableLookup {
        num_variables: witness.address_bits,
        readers: &readers,
    }];
    let position_values = positions(witness)?;
    let reader_witnesses = [ReaderWitness {
        positions: &position_values,
    }];
    let table_column_b = witness
        .rom
        .iter()
        .map(|row| to_b(row[0]))
        .collect::<Vec<B>>();
    let column_refs = [table_column_b.as_slice()];
    let table_witness = [TableWitness {
        columns: &column_refs,
        readers: &reader_witnesses,
    }];
    // Pushforward table for the public reader point (single reader, scale 1).
    let mut pushforward = vec![B::from_repr(0); cells];
    for (row, position) in position_values.iter().enumerate() {
        let mut weight = B::from_repr(1);
        // p3's equality tables iterate the coordinates in reverse, so bit `b`
        // of the row index pairs with `point[cycle_bits - 1 - b]`.
        for (bit, coordinate) in point.as_slice().iter().rev().enumerate() {
            if (row >> bit) & 1 == 1 {
                weight *= *coordinate;
            } else {
                weight *= B::from_repr(1) + *coordinate;
            }
        }
        pushforward[*position] += weight;
    }
    let pushforward_f2 = pushforward
        .iter()
        .map(|value| to_f2(*value))
        .collect::<Vec<_>>();

    // One commitment over the three padded tables, formed BEFORE the transcript
    // binds it: the binder returns the canonical digest of that commitment so
    // the Fiat-Shamir challenges are bound to the actual table.
    let columns = [
        pad_column(&word_values, table_bits),
        pad_column(&pos_values, table_bits),
        pad_column(&pushforward_f2, table_bits),
    ];
    let prepared = pcs
        .commit_batch_prepared(&columns)
        .map_err(|error| RuntimeError::Proof(format!("committed tables commit: {error}")))?;
    let table_commitment = prepared.commitment.clone();
    let table_binding = committed_tables_root(&table_commitment);

    let mut prover_challenger = challenger();
    let (logup, output, bindings, reduction_claims, product_claims) =
        LogupStarProof::<B, B>::prove_committed(
            &lookups,
            &table_witness,
            &mut prover_challenger,
            |pushforwards: &[Vec<B>]| {
                // The pushforward table is fixed by the public reader point, so
                // it is committed before the transcript binds it. Both sides
                // derive the same digest from the batch commitment.
                let _ = pushforwards;
                vec![table_binding]
            },
        );
    let _ = bindings;

    let mut points = vec![P3BatchPoint {
        point: padded_wire_point(point.as_slice(), table_bits),
        columns: vec![0],
    }];
    let position_claim = output.tables[0].position_claims[0];
    points.push(P3BatchPoint {
        point: padded_wire_point(output.position_point.as_slice(), table_bits),
        columns: vec![1],
    });
    let _ = position_claim;
    let mut reduction_evals = Vec::with_capacity(reduction_claims.len());
    for (claim_point, value) in &reduction_claims {
        reduction_evals.push(to_f2(*value));
        points.push(P3BatchPoint {
            point: padded_wire_point(claim_point, table_bits),
            columns: vec![2],
        });
    }
    let mut product_evals = Vec::with_capacity(product_claims.len());
    for (claim_point, value) in &product_claims {
        product_evals.push(to_f2(*value));
        points.push(P3BatchPoint {
            point: padded_wire_point(claim_point, table_bits),
            columns: vec![2],
        });
    }
    let opening = pcs
        .open_batch_prepared(prepared, &points)
        .map_err(|error| RuntimeError::Proof(format!("committed tables open: {error}")))?;

    let reader_point_wire = point
        .as_slice()
        .iter()
        .rev()
        .map(|coordinate| to_f2(*coordinate))
        .collect::<Vec<_>>();
    let table_root = committed_tables_root(&table_commitment);
    let proof = CommittedLogupShoutProof {
        address_bits: witness.address_bits,
        cycle_bits: witness.cycle_bits,
        cycles: witness.cycles,
        columns: 1,
        table_variables: table_bits,
        reader_point: reader_point_wire,
        reader_claim: to_f2(reader_claim),
        table_commitment,
        opening,
        reduction_evals,
        product_evals,
        logup,
    };
    Ok((proof, table_root))
}

/// Verifier for the committed-pushforward linear Shout.
pub fn verify_committed_logup_shout(
    proof: &CommittedLogupShoutProof,
    rom: &[u32],
    rom_binding: &[u8; 32],
    trace_len: u64,
) -> Result<CommittedLogupShoutOutput, RuntimeError> {
    if proof.cycles != 1usize << proof.cycle_bits
        || proof.columns != 1
        || proof.address_bits >= usize::BITS as usize
        || proof.reader_point.len() != proof.cycle_bits
        || proof.table_variables != committed_table_bits(proof.cycle_bits, proof.address_bits)
        || rom.len() > 1usize << proof.address_bits
        || rom.len().next_power_of_two().max(2) != 1usize << proof.address_bits
    {
        return Err(RuntimeError::Proof(
            "committed logup Shout statement shape mismatch".into(),
        ));
    }
    let pcs = committed_pcs();

    // 0. The standalone commitment and the opening must describe the same table,
    //    and the transcript binding is the canonical digest of that commitment
    //    (so the Fiat-Shamir challenges bind the actual pushforward table).
    if bincode::serialize(&proof.opening.commitment).ok()
        != bincode::serialize(&proof.table_commitment).ok()
    {
        return Err(RuntimeError::Proof(
            "committed logup Shout opening commitment mismatch".into(),
        ));
    }
    let table_binding = committed_tables_root(&proof.table_commitment);

    // 1. Public FS points.
    let point = committed_reader_point(
        rom_binding,
        trace_len,
        proof.cycle_bits,
        proof.address_bits,
    );
    let reader_point_wire = point
        .as_slice()
        .iter()
        .rev()
        .map(|coordinate| to_f2(*coordinate))
        .collect::<Vec<_>>();
    if proof.reader_point != reader_point_wire {
        return Err(RuntimeError::Proof(
            "committed logup Shout reader point mismatch".into(),
        ));
    }
    let reader_claim = to_b(proof.reader_claim);

    // 2. Logup* reduction against the committed pushforwards.
    let stage = crate::verify_profile::Stage::new("shout logup reduction");
    let readers = [Reader {
        point: &point,
        claims: &[reader_claim],
    }];
    let lookups = [TableLookup {
        num_variables: proof.address_bits,
        readers: &readers,
    }];
    let reduction_evals = proof
        .reduction_evals
        .iter()
        .map(|value| to_b(*value))
        .collect::<Vec<_>>();
    let product_evals = proof
        .product_evals
        .iter()
        .map(|value| to_b(*value))
        .collect::<Vec<_>>();
    let mut verifier_challenger = challenger();
    let (output, reduction_claims, product_claims) = proof
        .logup
        .verify_committed(
            &lookups,
            &mut verifier_challenger,
            &[table_binding],
            &reduction_evals,
            &product_evals,
        )
        .map_err(|error| RuntimeError::Proof(format!("committed logup reduction: {error:?}")))?;

    stage.finish();

    // 3. ONE batched opening covering reader/position/pushforward points.
    let stage = crate::verify_profile::Stage::new("shout batch opening");
    let table_bits = proof.table_variables;
    if reduction_claims.len() != proof.reduction_evals.len()
        || product_claims.len() != proof.product_evals.len()
        || output.tables.len() != 1
        || output.tables[0].column_claims.len() != 1
    {
        return Err(RuntimeError::Proof(
            "committed logup Shout output shape mismatch".into(),
        ));
    }
    let position_claim = output.tables[0].position_claims[0];
    // The reduction/product claim values are the ones the prover sent; the
    // batched opening authenticates them against the statement-bound commitment.
    for (index, (_, value)) in reduction_claims.iter().enumerate() {
        if to_f2(*value) != proof.reduction_evals[index] {
            return Err(RuntimeError::Proof(
                "committed logup Shout reduction claim mismatch".into(),
            ));
        }
    }
    for (index, (_, value)) in product_claims.iter().enumerate() {
        if to_f2(*value) != proof.product_evals[index] {
            return Err(RuntimeError::Proof(
                "committed logup Shout product claim mismatch".into(),
            ));
        }
    }
    let mut points = vec![
        P3BatchPoint {
            point: padded_wire_point(point.as_slice(), table_bits),
            columns: vec![0],
        },
        P3BatchPoint {
            point: padded_wire_point(output.position_point.as_slice(), table_bits),
            columns: vec![1],
        },
    ];
    let mut values = vec![
        vec![proof.reader_claim],
        vec![to_f2(position_claim)],
    ];
    for (index, (claim_point, _)) in reduction_claims.iter().enumerate() {
        points.push(P3BatchPoint {
            point: padded_wire_point(claim_point, table_bits),
            columns: vec![2],
        });
        values.push(vec![proof.reduction_evals[index]]);
    }
    for (index, (claim_point, _)) in product_claims.iter().enumerate() {
        points.push(P3BatchPoint {
            point: padded_wire_point(claim_point, table_bits),
            columns: vec![2],
        });
        values.push(vec![proof.product_evals[index]]);
    }
    let opening_ok = pcs
        .verify_batch(&proof.opening, &points, &values)
        .map_err(|error| RuntimeError::Proof(format!("committed tables opening: {error}")))?;
    if !opening_ok {
        return Err(RuntimeError::Proof(
            "committed logup Shout table opening rejected".into(),
        ));
    }

    stage.finish();

    // 4. Public ROM word column: O(rom) check of the table claim.
    let stage = crate::verify_profile::Stage::new("shout rom eval");
    let cells = 1usize << proof.address_bits;
    let mut rom_words = vec![B::from_repr(0); cells];
    for (index, word) in rom.iter().enumerate() {
        rom_words[index] = to_b(F2_128::from(u64::from(*word)));
    }
    let expected = eval_mle(&rom_words, &output.table_point);
    if expected != output.tables[0].column_claims[0] {
        return Err(RuntimeError::Proof(
            "committed logup Shout public ROM word claim mismatch".into(),
        ));
    }

    // 5. The caller's statement-root check binds the same commitment on top of
    //    the transcript binding recomputed above (double binding).
    stage.finish();

    Ok(CommittedLogupShoutOutput {
        reader_claim: proof.reader_claim,
        position_claim: to_f2(position_claim),
        reader_point: proof.reader_point.clone(),
        rom_claim: to_f2(expected),
    })
}

/// Composed statement root for M4 v3:
/// `H("claim-shout-v3" || v1 claim binding || batched tables root)`.
pub fn statement_root_from_commitments(
    claim_binding_v1: &[u8; 32],
    proof: &CommittedLogupShoutProof,
) -> [u8; 32] {
    crate::claim_table::claim_shout_v3_root(
        claim_binding_v1,
        &committed_tables_root(&proof.table_commitment),
    )
}

/// Host-side statement data for M4 v3 (statement construction; same trust model
/// as the M2/M3 claim table: the statement is a public input built from the
/// trace, and its root fixes this commitment).
pub struct CommittedShoutStatementData {
    pub table_commitment: P3BatchCommitment,
    pub table_root: [u8; 32],
    pub statement_root: [u8; 32],
}

/// Derive the batched committed Shout tables at statement construction and
/// compose the v3 statement root.
///
/// The reader point comes from the ROM binding + `trace_len` (public data), so
/// the pushforward table is fixed before the commitment is formed: nothing here
/// depends on prover messages.
pub fn committed_statement_data(
    trace: &magnetar_spec::Trace,
) -> Result<CommittedShoutStatementData, RuntimeError> {
    let witness = BinaryShoutWitness::from_trace(trace)
        .map_err(|error| RuntimeError::Proof(format!("committed logup witness: {error}")))?;
    let (word_values, pos_values) = committed_columns_from_trace(trace)?;
    let (witness_word, witness_pos) = committed_columns_from_witness(&witness)?;
    if word_values != witness_word || pos_values != witness_pos {
        return Err(RuntimeError::Proof(
            "committed logup Shout host columns disagree with the witness".into(),
        ));
    }
    let rom_binding = crate::rom_hash(&trace.rom);
    let table_bits = committed_table_bits(witness.cycle_bits, witness.address_bits);
    let point = committed_reader_point(
        &rom_binding,
        trace.rows.len() as u64,
        witness.cycle_bits,
        witness.address_bits,
    );
    let positions = positions(&witness)?;
    let cells = 1usize << witness.address_bits;
    let mut pushforward = vec![B::from_repr(0); cells];
    for (row, position) in positions.iter().enumerate() {
        let mut weight = B::from_repr(1);
        for (bit, coordinate) in point.as_slice().iter().rev().enumerate() {
            if (row >> bit) & 1 == 1 {
                weight *= *coordinate;
            } else {
                weight *= B::from_repr(1) + *coordinate;
            }
        }
        pushforward[*position] += weight;
    }
    let pushforward_f2 = pushforward
        .iter()
        .map(|value| to_f2(*value))
        .collect::<Vec<_>>();
    let table_commitment = committed_pcs()
        .commit_batch(&[
            pad_column(&word_values, table_bits),
            pad_column(&pos_values, table_bits),
            pad_column(&pushforward_f2, table_bits),
        ])
        .map_err(|error| RuntimeError::Proof(format!("committed tables commit: {error}")))?;
    let table_root = committed_tables_root(&table_commitment);
    let claim_binding_v1 = crate::claim_table::claim_binding_root(trace)?;
    let statement_root =
        crate::claim_table::claim_shout_v3_root(&claim_binding_v1, &table_root);
    Ok(CommittedShoutStatementData {
        table_commitment,
        table_root,
        statement_root,
    })
}

/// Verifier-side statement binding: recompose the v3 root from the proof's
/// commitment and compare it with the statement the verifier was handed.
pub fn verify_committed_statement_binding(
    proof: &CommittedLogupShoutProof,
    claim_binding_v1: &[u8; 32],
    statement_root: &[u8; 32],
) -> Result<(), RuntimeError> {
    let expected = statement_root_from_commitments(claim_binding_v1, proof);
    if expected != *statement_root {
        return Err(RuntimeError::Proof(
            "committed logup Shout statement binding mismatch".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod committed_logup_tests {
    use super::*;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    fn trace() -> magnetar_spec::Trace {
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 7,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        magnetar_executor::execute(
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
        .unwrap()
    }

    /// A trace long enough for the P3 folding minimum of the committed path.
    fn committed_trace() -> magnetar_spec::Trace {
        let mut instructions = (0..200)
            .map(|index| {
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: index,
                    shamt: 0,
                }
                .encode()
            })
            .collect::<Vec<_>>();
        instructions.push(Instruction::new(Op::Ecall).encode());
        let program = ProgramImage::new(0x1000, instructions);
        magnetar_executor::execute(
            &program,
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 500,
            },
        )
        .unwrap()
    }

    fn prove(trace: &magnetar_spec::Trace) -> (CommittedLogupShoutProof, [u8; 32]) {
        let witness = BinaryShoutWitness::from_trace(trace).unwrap();
        let rom_binding = crate::rom_hash(&trace.rom);
        prove_committed_logup_shout(&witness, &rom_binding, trace.rows.len() as u64).unwrap()
    }

    fn verify(
        trace: &magnetar_spec::Trace,
        proof: &CommittedLogupShoutProof,
    ) -> Result<CommittedLogupShoutOutput, RuntimeError> {
        let rom_binding = crate::rom_hash(&trace.rom);
        verify_committed_logup_shout(proof, &trace.rom, &rom_binding, trace.rows.len() as u64)
    }

    #[test]
    fn committed_logup_shout_round_trips() {
        let trace = committed_trace();
        let (proof, table_root) = prove(&trace);
        let statement = committed_statement_data(&trace).unwrap();
        assert_eq!(table_root, statement.table_root);
        let output = verify(&trace, &proof).unwrap();
        assert_eq!(output.reader_claim, proof.reader_claim);
        assert_eq!(output.reader_point, proof.reader_point);
        let witness = BinaryShoutWitness::from_trace(&trace).unwrap();
        let (word, pos) = committed_columns_from_witness(&witness).unwrap();
        assert_eq!(word.len(), proof.cycles);
        assert_eq!(pos.len(), proof.cycles);
    }

    #[test]
    fn committed_logup_shout_rejects_tampering() {
        let trace = committed_trace();
        let (proof, _) = prove(&trace);

        // Public ROM tamper.
        let mut rom = trace.rom.clone();
        rom[0] ^= 1;
        let rom_binding = crate::rom_hash(&trace.rom);
        assert!(verify_committed_logup_shout(
            &proof,
            &rom,
            &rom_binding,
            trace.rows.len() as u64
        )
        .is_err());

        // Reader claim tamper.
        let mut bad = proof.clone();
        bad.reader_claim = bad.reader_claim + F2_128::from(1u64);
        assert!(verify(&trace, &bad).is_err());

        // Pushforward eval tamper.
        let mut bad = proof.clone();
        bad.reduction_evals[0] = bad.reduction_evals[0] + F2_128::from(1u64);
        assert!(verify(&trace, &bad).is_err());

        // Table commitment swap (bound by the statement, so verification itself
        // only rejects via opening/binding mismatch).
        let mut bad = proof.clone();
        bad.table_commitment = committed_pcs()
            .commit_batch(&vec![
                pad_column(
                    &committed_columns_from_trace(&trace).unwrap().0,
                    proof.table_variables,
                );
                3
            ])
            .unwrap();
        assert!(verify(&trace, &bad).is_err());

        // Standalone commitment vs opening commitment mismatch is rejected.
        // (The opening normally embeds the same batched commitment, so the
        // tamper has to install a *different* commitment to exercise the check.)
        let (word, pos) = committed_columns_from_trace(&trace).unwrap();
        let other = committed_pcs()
            .commit_batch(&[
                pad_column(&word, proof.table_variables),
                pad_column(&pos, proof.table_variables),
                pad_column(&word, proof.table_variables),
            ])
            .unwrap();
        assert_ne!(
            bincode::serialize(&other).unwrap(),
            bincode::serialize(&proof.table_commitment).unwrap()
        );
        let mut bad = proof.clone();
        bad.opening.commitment = other;
        assert!(verify(&trace, &bad).is_err());
    }

    #[test]
    fn committed_statement_binding_matches_the_proof() {
        let trace = committed_trace();
        let (proof, _) = prove(&trace);
        let statement = committed_statement_data(&trace).unwrap();
        let claim_binding_v1 = crate::claim_table::claim_binding_root(&trace).unwrap();
        // The host statement data and the prover derive the same commitment.
        assert_eq!(statement.table_root, committed_tables_root(&proof.table_commitment));
        verify_committed_statement_binding(
            &proof,
            &claim_binding_v1,
            &statement.statement_root,
        )
        .unwrap();
        let mut tampered = statement.statement_root;
        tampered[0] ^= 1;
        assert!(verify_committed_statement_binding(
            &proof,
            &claim_binding_v1,
            &tampered
        )
        .is_err());
    }

    #[test]
    fn classic_logup_encoding_matches_golden_hash() {
        let trace = trace();
        let witness = BinaryShoutWitness::from_trace(&trace).unwrap();
        let proof = prove_logup_shout(&witness).unwrap();
        let hash = logup_proof_encoding_hash(&proof);
        match GOLDEN_OLD_LOGUP_ENCODING {
            Some(expected) => assert_eq!(hash, expected),
            None => eprintln!("golden old logup proof encoding sha256 = {hash:02x?}"),
        }
    }
}
