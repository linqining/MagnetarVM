//! Sound word-mode Shout via P3's logup* indexed-lookup reduction.
//!
//! The ROM table is public. Only the reader values and the dense position
//! column are committed. The logup* reduction proves `X[i] = ROM[I[i]]`, the
//! verifier checks the output table claims directly against the public ROM, and
//! one mosaic PCS opening discharges the reader and position claims.

use magnetar_constraint::F2_128;
use magnetar_pcs::{P3BinaryPcs, P3MosaicOpening, P3MosaicPoint, P3MosaicTable};
use magnetar_transcript::Sha256Transcript;
use p3_binary_field::{BinaryChallenger, BinaryField128, TowerLevel};
use p3_challenger::HashChallenger;
use p3_field::Field as P3Field;
use p3_keccak::Keccak256Hash;
use p3_multi_stark::logup_star::{
    LogupStarProof, Reader, ReaderWitness, TableLookup, TableWitness,
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
    pub logup: LogupStarProof<B, B>,
    pub opening: P3MosaicOpening,
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
    (0..usize::BITS as usize)
        .filter(|bit| (position >> bit) & 1 == 1)
        .map(|bit| B::interpolation_node(1 << bit))
        .sum()
}

fn eval_mle(values: &[B], point: &Point<B>) -> B {
    p3_multilinear_util::poly::Poly::new(values.to_vec()).eval_ext::<B>(point)
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

fn positions(witness: &BinaryShoutWitness) -> Vec<usize> {
    (0..witness.cycles)
        .map(|cycle| {
            if witness.valid[cycle].value() == 0 {
                return 0;
            }
            (0..witness.address_bits).fold(0usize, |address, bit| {
                if witness.address0[bit][cycle].value() != 0 {
                    address | (1 << bit)
                } else {
                    address
                }
            })
        })
        .collect()
}

pub fn prove_logup_shout(witness: &BinaryShoutWitness) -> Result<LogupShoutProof, RuntimeError> {
    if witness.is_32.iter().any(|bit| bit.value() != 0) {
        return Err(RuntimeError::Proof(
            "logup Shout currently supports word mode only".into(),
        ));
    }
    let table_columns = table_columns_from_witness(witness);
    let position_values = positions(witness);
    let columns = table_columns.len();
    let pcs = P3BinaryPcs::new(100);
    let mut reader_columns = (0..columns)
        .map(|column| {
            position_values
                .iter()
                .map(|position| table_columns[column][*position])
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    reader_columns.push(
        position_values
            .iter()
            .map(|position| embed(*position))
            .collect(),
    );
    let table = P3MosaicTable {
        columns: reader_columns
            .iter()
            .map(|column| column.iter().map(|value| to_f2(*value)).collect())
            .collect::<Vec<Vec<F2_128>>>(),
    };
    let commitment = pcs
        .commit_mosaic(std::slice::from_ref(&table))
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let commitment_bytes =
        bincode::serialize(&commitment).map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let point = reader_point(&commitment_bytes, witness.cycle_bits);
    let claims = (0..columns)
        .map(|column| {
            let values = &reader_columns[column];
            eval_mle(values, &point)
        })
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
    let points = vec![
        P3MosaicPoint {
            table: 0,
            point: point
                .iter()
                .rev()
                .map(|coordinate| to_f2(*coordinate))
                .collect(),
            columns: (0..columns).collect(),
            next_columns: Vec::new(),
        },
        P3MosaicPoint {
            table: 0,
            point: output
                .position_point
                .iter()
                .rev()
                .map(|coordinate| to_f2(*coordinate))
                .collect(),
            columns: vec![columns],
            next_columns: Vec::new(),
        },
    ];
    let opening = pcs
        .open_mosaic(std::slice::from_ref(&table), &points)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(LogupShoutProof {
        address_bits: witness.address_bits,
        cycle_bits: witness.cycle_bits,
        cycles: witness.cycles,
        columns,
        reader_claims: claims.iter().map(|claim| to_f2(*claim)).collect(),
        logup,
        opening,
    })
}

pub fn verify_logup_shout(
    proof: &LogupShoutProof,
    rom: &[Vec<F2_128>],
) -> Result<(), RuntimeError> {
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
    {
        return Err(RuntimeError::Proof(
            "logup Shout statement shape mismatch".into(),
        ));
    }
    let pcs = P3BinaryPcs::new(100);
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
    }
    let points = vec![
        P3MosaicPoint {
            table: 0,
            point: point
                .iter()
                .rev()
                .map(|coordinate| to_f2(*coordinate))
                .collect(),
            columns: (0..proof.columns).collect(),
            next_columns: Vec::new(),
        },
        P3MosaicPoint {
            table: 0,
            point: output
                .position_point
                .iter()
                .rev()
                .map(|coordinate| to_f2(*coordinate))
                .collect(),
            columns: vec![proof.columns],
            next_columns: Vec::new(),
        },
    ];
    let values = vec![
        claims.iter().map(|claim| to_f2(*claim)).collect::<Vec<_>>(),
        vec![to_f2(output.tables[0].position_claims[0])],
    ];
    if !pcs
        .verify_mosaic(&proof.opening, &points, &values)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
    {
        return Err(RuntimeError::Proof("logup Shout PCS opening rejected".into()));
    }
    Ok(())
}

pub fn logup_shout_proof_size(proof: &LogupShoutProof) -> Result<usize, RuntimeError> {
    bincode::serialize(proof)
        .map(|bytes| bytes.len())
        .map_err(|error| RuntimeError::Proof(error.to_string()))
}
