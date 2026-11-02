//! Sound word-mode Shout via P3's logup* indexed-lookup reduction.
//!
//! The ROM table is public. Only the reader values and the dense position
//! column are committed. The logup* reduction proves `X[i] = ROM[I[i]]`, the
//! verifier checks the output table claims directly against the public ROM, and
//! one mosaic PCS opening discharges the reader and position claims.

use magnetar_constraint::F2_128;
use magnetar_pcs::{P3BatchOpening, P3BatchPoint, P3BinaryPcs, P3Commitment, P3Opening};
use magnetar_proof::Pcs as _;
use magnetar_transcript::Sha256Transcript;
use p3_binary_field::{BinaryChallenger, BinaryField128, TowerLevel};
use p3_challenger::HashChallenger;
use p3_field::Field as P3Field;
use p3_keccak::Keccak256Hash;
use p3_multi_stark::logup_star::{
    LogupStarOutput, LogupStarProof, Reader, ReaderWitness, TableLookup, TableWitness,
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
// Same linear `logup_shout` reduction as the classic trace path, but the
// verifier no longer rebuilds the Shout witness:
//
// * `T_word`: the reader word column (host-derived from the claim rows; padding
//   cycles read `ROM[0]`, exactly what `positions()` induces) is committed; its
//   opening at the Fiat-Shamir reader point is the reader claim.
// * `T_pos`: the position embedding column (`embed((pc - rom_base) / 4)`,
//   padding cycles 0) is committed; its opening at the logup position point is
//   the position claim.
// * the `2^address_bits`-wide pushforward vector is committed instead of
//   travelling: the transcript binds `H(commitment)` and the verifier checks the
//   values it needs with PCS openings.
// * the public ROM word column is checked directly (O(rom)).
//
// Both tables are host-derived at statement construction (same trust model as
// the M2/M3 claim table), and their roots are composed into the statement root.
// Everything here is additive; the classic `prove_logup_shout` /
// `verify_logup_shout*` paths are untouched.

const COMMITTED_DOMAIN: &[u8] = b"magnetar-committed-logup-shout-v1";

/// PCS for the dense single-column tables (reader word, position, pushforward).
fn committed_pcs() -> P3BinaryPcs {
    P3BinaryPcs::with_params(100, 3, 20, 3)
}

fn committed_hash(label: &[u8], commitment: &P3Commitment) -> [u8; 32] {
    let mut bytes = COMMITTED_DOMAIN.to_vec();
    bytes.extend_from_slice(label);
    bytes.extend_from_slice(&bincode::serialize(commitment).unwrap_or_default());
    magnetar_transcript::sha256(&bytes)
}

/// Root of the committed reader word column (bound by the statement root).
pub fn committed_word_root(commitment: &P3Commitment) -> [u8; 32] {
    committed_hash(b"word", commitment)
}

/// Root of the committed position-embedding column (bound by the statement root).
pub fn committed_pos_root(commitment: &P3Commitment) -> [u8; 32] {
    committed_hash(b"position", commitment)
}

/// Root of the committed pushforward table (bound by the statement root).
pub fn committed_pushforward_root(commitment: &P3Commitment) -> [u8; 32] {
    committed_hash(b"pushforward", commitment)
}

/// Transcript binding of one committed pushforward: absorbed instead of the
/// table-wide vector.
pub fn pushforward_binding(commitment: &P3Commitment) -> [u8; 32] {
    committed_hash(b"pushforward-binding", commitment)
}

/// Host-side Shout columns for the committed path (from the Shout witness):
/// `(reader word column, position embedding column)`.
///
/// The same values are derived from the trace at statement construction, so the
/// prover cannot deviate from the committed tables.
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
        let index = usize::try_from(offset / 4)
            .map_err(|_| RuntimeError::Proof("ROM index overflows usize".into()))?;
        let position = index;
        if position >= trace.rom.len().next_power_of_two().max(2) {
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
///
/// Used by the golden regression test: the M4 v3 vendor diff must not change the
/// encoding of the classic path (it only adds functions and leaves every p3
/// structure untouched).
pub fn logup_proof_encoding_hash(proof: &LogupShoutProof) -> [u8; 32] {
    magnetar_transcript::sha256(&bincode::serialize(proof).unwrap_or_default())
}

/// Golden hash of the classic `logup_shout` proof encoding.
///
/// Filled in the build window from `logup_proof_encoding_hash`; `None` here so
/// the shared tree is not blocked before the measurement window.
pub const GOLDEN_OLD_LOGUP_ENCODING: Option<[u8; 32]> = Some([
    0xf3, 0x96, 0xfd, 0x79, 0x9e, 0xc5, 0xb7, 0xe5, 0xa8, 0xfc, 0x1f, 0x92, 0x69, 0x4e, 0x9f, 0x08,
    0xce, 0x45, 0x47, 0x23, 0x31, 0x74, 0x00, 0xa7, 0xe0, 0x29, 0x30, 0xdd, 0x80, 0x40, 0x25, 0xaf,
]);

/// Linear Shout proof with committed pushforwards (M4 v3).
///
/// The reader word/position columns and the pushforward table are committed; the
/// proof carries only openings/values, never the table-wide vector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommittedLogupShoutProof {
    pub address_bits: usize,
    pub cycle_bits: usize,
    pub cycles: usize,
    pub columns: usize,
    /// Reader point in PCS coordinate order (bit `i` of a cycle index).
    pub reader_point: Vec<F2_128>,
    pub word_commitment: P3Commitment,
    pub word_opening: P3Opening,
    pub reader_claim: F2_128,
    pub pos_commitment: P3Commitment,
    /// Opening of the position column at the logup position point.
    pub pos_opening: P3Opening,
    /// One transcript binding per table (the digest of its commitment).
    pub pushforward_bindings: Vec<[u8; 32]>,
    pub pushforward_commitment: P3Commitment,
    /// Pushforward values at the fraction reduction's table-block points.
    pub reduction_evals: Vec<F2_128>,
    pub reduction_openings: Vec<P3Opening>,
    /// Pushforward values at the product sumcheck's per-table points.
    pub product_evals: Vec<F2_128>,
    pub product_openings: Vec<P3Opening>,
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
    /// Reader point in PCS coordinate order.
    pub reader_point: Vec<F2_128>,
    /// Public ROM word claim at the logup table point.
    pub rom_claim: F2_128,
}

fn open_pushforward_claims(
    pcs: &P3BinaryPcs,
    values: &[F2_128],
    claims: &[(Vec<B>, B)],
) -> Result<(Vec<F2_128>, Vec<P3Opening>), RuntimeError> {
    let mut evals = Vec::with_capacity(claims.len());
    let mut openings = Vec::with_capacity(claims.len());
    for (point, value) in claims {
        let point_f2 = point
            .iter()
            .rev()
            .map(|coordinate| to_f2(*coordinate))
            .collect::<Vec<_>>();
        let opening = pcs
            .open(values, &point_f2)
            .map_err(|error| RuntimeError::Proof(format!("pushforward open: {error}")))?;
        evals.push(to_f2(*value));
        openings.push(opening);
    }
    Ok((evals, openings))
}

/// Prover for the committed-pushforward linear Shout (word-mode reader).
///
/// Returns the proof and the three commitment roots the caller composes into the
/// statement root: `(proof, word_root, pos_root, pushforward_root)`.
pub fn prove_committed_logup_shout(
    witness: &BinaryShoutWitness,
) -> Result<(CommittedLogupShoutProof, [u8; 32], [u8; 32], [u8; 32]), RuntimeError> {
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
    let pcs = committed_pcs();

    let word_commitment = pcs
        .commit(&word_values)
        .map_err(|error| RuntimeError::Proof(format!("word commit: {error}")))?;
    let pos_commitment = pcs
        .commit(&pos_values)
        .map_err(|error| RuntimeError::Proof(format!("position commit: {error}")))?;
    let word_bytes = bincode::serialize(&word_commitment)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let point = reader_point(&word_bytes, witness.cycle_bits);
    let reader_claim = eval_mle(&word_b, &point);

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

    let mut prover_challenger = challenger();
    let mut pushforward_commitment: Option<P3Commitment> = None;
    let mut pushforward_values: Option<Vec<F2_128>> = None;
    let (logup, output, bindings, reduction_claims, product_claims) =
        LogupStarProof::<B, B>::prove_committed(
            &lookups,
            &table_witness,
            &mut prover_challenger,
            |pushforwards: &[Vec<B>]| {
                let mut out = Vec::with_capacity(pushforwards.len());
                for pushforward in pushforwards {
                    let values = pushforward.iter().map(|value| to_f2(*value)).collect::<Vec<_>>();
                    let commitment = pcs
                        .commit(&values)
                        .expect("committed pushforward table shape");
                    out.push(pushforward_binding(&commitment));
                    pushforward_commitment = Some(commitment);
                    pushforward_values = Some(values);
                }
                out
            },
        );
    let pushforward_commitment = pushforward_commitment
        .ok_or_else(|| RuntimeError::Proof("logup Shout produced no pushforward table".into()))?;
    let pushforward_values = pushforward_values
        .ok_or_else(|| RuntimeError::Proof("logup Shout stored no pushforward values".into()))?;
    let (reduction_evals, reduction_openings) =
        open_pushforward_claims(&pcs, &pushforward_values, &reduction_claims)?;
    let (product_evals, product_openings) =
        open_pushforward_claims(&pcs, &pushforward_values, &product_claims)?;

    // The PCS wire order is the reverse of the p3 point order.
    let reader_point_wire = point
        .as_slice()
        .iter()
        .rev()
        .map(|coordinate| to_f2(*coordinate))
        .collect::<Vec<_>>();
    let word_opening = pcs
        .open(&word_values, &reader_point_wire)
        .map_err(|error| RuntimeError::Proof(format!("word open: {error}")))?;
    let position_point = output
        .position_point
        .as_slice()
        .iter()
        .rev()
        .map(|coordinate| to_f2(*coordinate))
        .collect::<Vec<_>>();
    let pos_opening = pcs
        .open(&pos_values, &position_point)
        .map_err(|error| RuntimeError::Proof(format!("position open: {error}")))?;

    let proof = CommittedLogupShoutProof {
        address_bits: witness.address_bits,
        cycle_bits: witness.cycle_bits,
        cycles: witness.cycles,
        columns: 1,
        reader_point: reader_point_wire,
        word_commitment: word_commitment.clone(),
        word_opening,
        reader_claim: to_f2(reader_claim),
        pos_commitment: pos_commitment.clone(),
        pos_opening,
        pushforward_bindings: bindings,
        pushforward_commitment: pushforward_commitment.clone(),
        reduction_evals,
        reduction_openings,
        product_evals,
        product_openings,
        logup,
    };
    Ok((
        proof,
        committed_word_root(&word_commitment),
        committed_pos_root(&pos_commitment),
        committed_pushforward_root(&pushforward_commitment),
    ))
}

/// Verifier for the committed-pushforward linear Shout.
///
/// `rom` are the public instruction words; `rom_binding` binds them in the
/// transcript-free statement (already authenticated by the statement root).
pub fn verify_committed_logup_shout(
    proof: &CommittedLogupShoutProof,
    rom: &[u32],
) -> Result<CommittedLogupShoutOutput, RuntimeError> {
    if proof.cycles != 1usize << proof.cycle_bits
        || proof.columns != 1
        || proof.address_bits >= usize::BITS as usize
        || proof.reader_point.len() != proof.cycle_bits
        || rom.len() > 1usize << proof.address_bits
        || rom.len().next_power_of_two().max(2) != 1usize << proof.address_bits
        || proof.pushforward_bindings.len() != 1
    {
        return Err(RuntimeError::Proof(
            "committed logup Shout statement shape mismatch".into(),
        ));
    }
    let pcs = committed_pcs();

    // 1. Reader word column: opening at the Fiat-Shamir reader point.
    let word_bytes = bincode::serialize(&proof.word_commitment)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let point = reader_point(&word_bytes, proof.cycle_bits);
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
    let word_ok = pcs
        .verify(&proof.word_commitment, &proof.reader_point, proof.reader_claim, &proof.word_opening)
        .map_err(|error| RuntimeError::Proof(format!("word opening: {error}")))?;
    if !word_ok {
        return Err(RuntimeError::Proof("committed logup Shout word opening rejected".into()));
    }

    // 2. Pushforward table: the transcript binding must be its commitment digest.
    if proof.pushforward_bindings[0] != pushforward_binding(&proof.pushforward_commitment) {
        return Err(RuntimeError::Proof(
            "committed logup Shout pushforward binding mismatch".into(),
        ));
    }

    // 3. Logup* reduction: reader claim at the reader point, committed
    //    pushforwards binding the table side.
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
            &proof.pushforward_bindings,
            &reduction_evals,
            &product_evals,
        )
        .map_err(|error| RuntimeError::Proof(format!("committed logup reduction: {error:?}")))?;

    // 4. Open the committed pushforwards at the verifier-derived points.
    if reduction_claims.len() != proof.reduction_evals.len()
        || product_claims.len() != proof.product_evals.len()
    {
        return Err(RuntimeError::Proof(
            "committed logup Shout pushforward claim count mismatch".into(),
        ));
    }
    for (index, (claim_point, claim_value)) in reduction_claims.iter().enumerate() {
        let point_f2 = claim_point
            .iter()
            .rev()
            .map(|coordinate| to_f2(*coordinate))
            .collect::<Vec<_>>();
        if to_f2(*claim_value) != proof.reduction_evals[index] {
            return Err(RuntimeError::Proof(
                "committed logup Shout reduction claim mismatch".into(),
            ));
        }
        let ok = pcs
            .verify(
                &proof.pushforward_commitment,
                &point_f2,
                proof.reduction_evals[index],
                &proof.reduction_openings[index],
            )
            .map_err(|error| RuntimeError::Proof(format!("pushforward opening: {error}")))?;
        if !ok {
            return Err(RuntimeError::Proof(
                "committed logup Shout pushforward opening rejected".into(),
            ));
        }
    }
    for (index, (claim_point, claim_value)) in product_claims.iter().enumerate() {
        let point_f2 = claim_point
            .iter()
            .rev()
            .map(|coordinate| to_f2(*coordinate))
            .collect::<Vec<_>>();
        if to_f2(*claim_value) != proof.product_evals[index] {
            return Err(RuntimeError::Proof(
                "committed logup Shout product claim mismatch".into(),
            ));
        }
        let ok = pcs
            .verify(
                &proof.pushforward_commitment,
                &point_f2,
                proof.product_evals[index],
                &proof.product_openings[index],
            )
            .map_err(|error| RuntimeError::Proof(format!("pushforward opening: {error}")))?;
        if !ok {
            return Err(RuntimeError::Proof(
                "committed logup Shout pushforward opening rejected".into(),
            ));
        }
    }

    // 5. Position claim: opening of the committed position column at the logup
    //    position point.
    if output.tables.len() != 1 || output.tables[0].column_claims.len() != 1 {
        return Err(RuntimeError::Proof("committed logup Shout output shape mismatch".into()));
    }
    let position_claim = output.tables[0].position_claims[0];
    let position_point = output
        .position_point
        .as_slice()
        .iter()
        .rev()
        .map(|coordinate| to_f2(*coordinate))
        .collect::<Vec<_>>();
    let pos_ok = pcs
        .verify(
            &proof.pos_commitment,
            &position_point,
            to_f2(position_claim),
            &proof.pos_opening,
        )
        .map_err(|error| RuntimeError::Proof(format!("position opening: {error}")))?;
    if !pos_ok {
        return Err(RuntimeError::Proof("committed logup Shout position opening rejected".into()));
    }

    // 6. Public ROM word column: O(rom) check of the table claim at the
    //    product sumcheck's table point.
    let cells = 1usize << proof.address_bits;
    let mut rom_words = vec![B::from_repr(0); cells];
    for (index, word) in rom.iter().enumerate() {
        rom_words[index] = to_b(F2_128::from(u64::from(*word)));
    }
    let expected = eval_mle(&rom_words, &output.table_point);
    let table_claim = output.tables[0].column_claims[0];
    if expected != table_claim {
        return Err(RuntimeError::Proof(
            "committed logup Shout public ROM word claim mismatch".into(),
        ));
    }

    Ok(CommittedLogupShoutOutput {
        reader_claim: proof.reader_claim,
        position_claim: to_f2(position_claim),
        reader_point: proof.reader_point.clone(),
        rom_claim: to_f2(expected),
    })
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

    #[test]
    fn committed_logup_shout_round_trips() {
        let trace = committed_trace();
        let witness = BinaryShoutWitness::from_trace(&trace).unwrap();
        let (proof, word_root, pos_root, pushforward_root) =
            prove_committed_logup_shout(&witness).unwrap();
        assert_ne!(word_root, pos_root);
        assert_ne!(word_root, pushforward_root);
        assert_ne!(pos_root, pushforward_root);
        let output = verify_committed_logup_shout(&proof, &trace.rom).unwrap();
        assert_eq!(output.reader_claim, proof.reader_claim);
        assert_eq!(output.reader_point, proof.reader_point);
        // The word column is the host-derived claim word column.
        let (word, pos) = committed_columns_from_witness(&witness).unwrap();
        assert_eq!(word.len(), proof.cycles);
        assert_eq!(pos.len(), proof.cycles);
    }

    #[test]
    fn classic_logup_encoding_matches_golden_hash() {
        let trace = trace();
        let witness = BinaryShoutWitness::from_trace(&trace).unwrap();
        let proof = prove_logup_shout(&witness).unwrap();
        let hash = logup_proof_encoding_hash(&proof);
        // The M4 v3 vendor diff is additive: every p3 structure and every
        // classic entry point is untouched, so this encoding must not change.
        // The constant is filled in the build window when the golden value is
        // produced; until then the hash is printed for the reviewer.
        match GOLDEN_OLD_LOGUP_ENCODING {
            Some(expected) => assert_eq!(hash, expected),
            None => eprintln!("golden old logup proof encoding sha256 = {hash:02x?}"),
        }
    }

    #[test]
    fn committed_logup_shout_rejects_tampering() {
        let trace = committed_trace();
        let witness = BinaryShoutWitness::from_trace(&trace).unwrap();
        let (proof, _, _, _) = prove_committed_logup_shout(&witness).unwrap();

        // Public ROM tamper.
        let mut rom = trace.rom.clone();
        rom[0] ^= 1;
        assert!(verify_committed_logup_shout(&proof, &rom).is_err());

        // Reader claim tamper.
        let mut bad = proof.clone();
        bad.reader_claim = bad.reader_claim + F2_128::from(1u64);
        assert!(verify_committed_logup_shout(&bad, &trace.rom).is_err());

        // Pushforward eval tamper.
        let mut bad = proof.clone();
        bad.reduction_evals[0] = bad.reduction_evals[0] + F2_128::from(1u64);
        assert!(verify_committed_logup_shout(&bad, &trace.rom).is_err());

        // Pushforward binding tamper.
        let mut bad = proof.clone();
        bad.pushforward_bindings[0][0] ^= 1;
        assert!(verify_committed_logup_shout(&bad, &trace.rom).is_err());

        // Position opening tamper (swap the committed position column).
        let mut bad = proof.clone();
        bad.pos_commitment = proof.word_commitment.clone();
        assert!(verify_committed_logup_shout(&bad, &trace.rom).is_err());
    }
}
