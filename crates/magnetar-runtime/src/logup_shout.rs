//! Sound word-mode Shout via P3's logup* indexed-lookup reduction.
//!
//! The ROM table is public. Only the reader values and the dense position
//! column are committed. The logup* reduction proves `X[i] = ROM[I[i]]`, the
//! verifier checks the output table claims directly against the public ROM, and
//! one mosaic PCS opening discharges the reader and position claims.

use magnetar_constraint::F2_128;
use magnetar_pcs::{P3BatchOpening, P3BatchPoint, P3BinaryPcs};
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
