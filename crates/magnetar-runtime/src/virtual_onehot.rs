//! Virtual one-hot evaluation proof.
//!
//! Proves an evaluation of the dense read/write address matrix from committed
//! address bits and a validity column, without committing the dense K x T
//! one-hot table.

use magnetar_constraint::F2_128;
use magnetar_memory::BinaryTwistWitness;
use magnetar_pcs::{P3BatchPoint, P3BatchOpening};
use magnetar_proof::ProofError;
use magnetar_transcript::Sha256Transcript;

use crate::binary_twist::{eq_vector, replay_terms_derived, sample_point, sumcheck_terms};
use crate::linear_twist::{eval_mle, linear_pcs, witness_shape, LinearTwistShape};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VirtualOneHotProof {
    pub opening: P3BatchOpening,
    pub claimed: F2_128,
    pub rounds: Vec<Vec<F2_128>>,
    pub challenges: Vec<F2_128>,
    pub terminal_values: Vec<F2_128>,
}

fn bit_columns(
    witness: &BinaryTwistWitness,
    write: bool,
) -> (Vec<Vec<F2_128>>, Vec<F2_128>, usize) {
    let shape = witness_shape(witness);
    let cycles = shape.cycles;
    let mut bits = vec![vec![F2_128::from(0u64); cycles]; shape.address_bits];
    let mut valid = vec![F2_128::from(0u64); cycles];
    let source = if write {
        &witness.write_address
    } else {
        &witness.read_address
    };
    for (cycle, row) in source.iter().enumerate() {
        let Some(cell) = row.iter().position(|value| value.value() == 1) else {
            continue;
        };
        valid[cycle] = F2_128::from(1u64);
        for (bit, column) in bits.iter_mut().enumerate() {
            column[cycle] = F2_128::from(((cell >> bit) & 1) as u64);
        }
    }
    (bits, valid, cycles)
}

fn onehot_formula(
    bits: &[Vec<F2_128>],
    valid: &[F2_128],
    rk: &[F2_128],
    rj: &[F2_128],
    cycles: usize,
) -> F2_128 {
    let eq = eq_vector(rj, cycles);
    let mut total = F2_128::from(0u64);
    for cycle in 0..cycles {
        let mut weight = eq[cycle] * valid[cycle];
        for (bit, column) in bits.iter().enumerate() {
            let value = column[cycle];
            weight = weight
                * (rk[bit] * value + (F2_128::from(1u64) + rk[bit]) * (F2_128::from(1u64) + value));
        }
        total = total + weight;
    }
    total
}

pub fn prove_virtual_onehot(
    witness: &BinaryTwistWitness,
    write: bool,
    rk: &[F2_128],
    rj: &[F2_128],
) -> Result<VirtualOneHotProof, ProofError> {
    let shape = witness_shape(witness);
    let (bits, valid, cycles) = bit_columns(witness, write);
    let claimed = onehot_formula(&bits, &valid, rk, rj, cycles);
    let mut columns = bits.clone();
    columns.push(valid.clone());
    let pcs = linear_pcs(cycles);
    let commitment = pcs
        .commit_batch(&columns)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let mut transcript = Sha256Transcript::new("magnetar-virtual-onehot");
    transcript.absorb(
        "commitment",
        &bincode::serialize(&commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
    );
    transcript.absorb(
        "point",
        &bincode::serialize(&(rk.to_vec(), rj.to_vec()))
            .map_err(|error| ProofError::Pcs(error.to_string()))?,
    );
    let eq = eq_vector(rj, cycles);
    let mut factors = vec![eq, valid.clone()];
    for (bit, column) in bits.iter().enumerate() {
        factors.push(
            column
                .iter()
                .map(|value| {
                    rk[bit] * *value
                        + (F2_128::from(1u64) + rk[bit]) * (F2_128::from(1u64) + *value)
                })
                .collect(),
        );
    }
    let (rounds, challenges) = sumcheck_terms(
        &factors,
        &vec![shape.address_bits + 1; shape.cycle_bits()],
        &mut transcript,
        |folded| {
            (0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
                let mut product = folded[0][index] * folded[1][index];
                for factor in &folded[2..] {
                    product = product * factor[index];
                }
                sum + product
            })
        },
    )?;
    let points = vec![P3BatchPoint {
        point: challenges.clone(),
        columns: (0..columns.len()).collect(),
    }];
    let terminal_values = columns
        .iter()
        .map(|column| eval_mle(column, &challenges))
        .collect::<Vec<_>>();
    let values = vec![terminal_values.clone()];
    let opening = pcs
        .open_batch(&columns, &points)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let _ = pcs
        .verify_batch(&opening, &points, &values)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    Ok(VirtualOneHotProof {
        opening,
        claimed,
        rounds,
        challenges,
        terminal_values,
    })
}

pub fn verify_virtual_onehot(
    shape: LinearTwistShape,
    rk: &[F2_128],
    rj: &[F2_128],
    proof: &VirtualOneHotProof,
) -> Result<bool, ProofError> {
    let cycles = shape.cycles;
    let mut transcript = Sha256Transcript::new("magnetar-virtual-onehot");
    transcript.absorb(
        "commitment",
        &bincode::serialize(&proof.opening.commitment)
            .map_err(|error| ProofError::Pcs(error.to_string()))?,
    );
    transcript.absorb(
        "point",
        &bincode::serialize(&(rk.to_vec(), rj.to_vec()))
            .map_err(|error| ProofError::Pcs(error.to_string()))?,
    );
    let pcs = linear_pcs(cycles);
    let points = vec![P3BatchPoint {
        point: proof.challenges.clone(),
        columns: (0..proof.terminal_values.len()).collect(),
    }];
    let pcs_ok = pcs
        .verify_batch(
            &proof.opening,
            &points,
            std::slice::from_ref(&proof.terminal_values),
        )
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    if !pcs_ok {
        return Ok(false);
    }
    let Some((final_sum, challenges)) =
        replay_terms_derived(&proof.rounds, proof.claimed, &mut transcript)
    else {
        return Ok(false);
    };
    if challenges != proof.challenges {
        return Ok(false);
    }
    let mut expected = eq_vector(rj, cycles)[0];
    let _ = expected;
    let eq_eval = {
        // eq(rj, challenges) from the public point and final challenge.
        let mut value = F2_128::from(1u64);
        for (a, b) in rj.iter().zip(&challenges) {
            value = value
                * (*a * *b + (F2_128::from(1u64) + *a) * (F2_128::from(1u64) + *b));
        }
        value
    };
    let valid_eval = proof.terminal_values[shape.address_bits];
    let mut product = eq_eval * valid_eval;
    for (bit, rk_bit) in rk.iter().enumerate() {
        let bit_eval = proof.terminal_values[bit];
        product = product
            * (*rk_bit * bit_eval
                + (F2_128::from(1u64) + *rk_bit) * (F2_128::from(1u64) + bit_eval));
    }
    expected = product;
    Ok(final_sum == expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_onehot_round_trips() {
        let witness = crate::linear_twist::tests::register_witness();
        let shape = witness_shape(&witness);
        let rk = (0..shape.address_bits)
            .map(|index| F2_128::from((index * 5 + 3) as u64))
            .collect::<Vec<_>>();
        let rj = (0..shape.cycle_bits())
            .map(|index| F2_128::from((index * 7 + 1) as u64))
            .collect::<Vec<_>>();
        for write in [false, true] {
            let proof = prove_virtual_onehot(&witness, write, &rk, &rj).unwrap();
            assert!(verify_virtual_onehot(shape, &rk, &rj, &proof).unwrap());
            let bytes = bincode::serialize(&proof).unwrap().len();
            eprintln!("virtual_onehot write={write} bytes={bytes}");
        }
    }
}

/// Multi-target virtual address evaluation.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VirtualTarget {
    pub write: bool,
    pub rk: Vec<F2_128>,
    pub rj: Vec<F2_128>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VirtualAddressProof {
    pub opening: P3BatchOpening,
    pub claims: Vec<F2_128>,
    pub rounds: Vec<Vec<F2_128>>,
    pub challenges: Vec<F2_128>,
    pub terminal_values: Vec<F2_128>,
}


fn target_claim(
    witness: &BinaryTwistWitness,
    target: &VirtualTarget,
    cycles: usize,
) -> F2_128 {
    let (bits, valid, _) = bit_columns(witness, target.write);
    onehot_formula(&bits, &valid, &target.rk, &target.rj, cycles)
}

pub fn prove_virtual_address(
    witness: &BinaryTwistWitness,
    targets: &[VirtualTarget],
) -> Result<VirtualAddressProof, ProofError> {
    let shape = witness_shape(witness);
    let (read_bits, read_valid, cycles) = bit_columns(witness, false);
    let (write_bits, write_valid, _) = bit_columns(witness, true);
    let mut columns = Vec::new();
    columns.extend(read_bits.iter().cloned());
    columns.push(read_valid.clone());
    columns.extend(write_bits.iter().cloned());
    columns.push(write_valid.clone());
    let pcs = linear_pcs(cycles);
    let commitment = pcs
        .commit_batch(&columns)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let mut transcript = Sha256Transcript::new("magnetar-virtual-address");
    transcript.absorb(
        "commitment",
        &bincode::serialize(&commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
    );
    transcript.absorb(
        "targets",
        &bincode::serialize(targets).map_err(|error| ProofError::Pcs(error.to_string()))?,
    );
    let coefficients = sample_point(&mut transcript, targets.len().max(1));
    let mut claims = Vec::with_capacity(targets.len());
    let mut factors = Vec::new();
    let mut groups = Vec::with_capacity(targets.len());
    for target in targets {
        claims.push(target_claim(witness, target, cycles));
        let (bits, valid) = if target.write {
            (&write_bits, &write_valid)
        } else {
            (&read_bits, &read_valid)
        };
        let mut group = Vec::new();
        group.push(factors.len());
        factors.push(eq_vector(&target.rj, cycles));
        group.push(factors.len());
        factors.push(valid.clone());
        for (bit, column) in bits.iter().enumerate() {
            group.push(factors.len());
            factors.push(
                column
                    .iter()
                    .map(|value| {
                        target.rk[bit] * *value
                            + (F2_128::from(1u64) + target.rk[bit])
                                * (F2_128::from(1u64) + *value)
                    })
                    .collect(),
            );
        }
        groups.push(group);
    }
    let coefficients_copy = coefficients.clone();
    let groups_copy = groups.clone();
    let (rounds, challenges) = sumcheck_terms(
        &factors,
        &vec![shape.address_bits + 1; shape.cycle_bits()],
        &mut transcript,
        move |folded| {
            (0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
                let mut value = F2_128::from(0u64);
                for (group, coefficient) in groups_copy.iter().zip(&coefficients_copy) {
                    let mut product = *coefficient;
                    for factor in group {
                        product = product * folded[*factor][index];
                    }
                    value = value + product;
                }
                sum + value
            })
        },
    )?;
    let points = vec![P3BatchPoint {
        point: challenges.clone(),
        columns: (0..columns.len()).collect(),
    }];
    let terminal_values = columns
        .iter()
        .map(|column| eval_mle(column, &challenges))
        .collect::<Vec<_>>();
    let opening = pcs
        .open_batch(&columns, &points)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let _ = pcs
        .verify_batch(&opening, &points, std::slice::from_ref(&terminal_values))
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    Ok(VirtualAddressProof {
        opening,
        claims,
        rounds,
        challenges,
        terminal_values,
    })
}

pub fn verify_virtual_address(
    shape: LinearTwistShape,
    targets: &[VirtualTarget],
    proof: &VirtualAddressProof,
) -> Result<bool, ProofError> {
    let cycles = shape.cycles;
    let mut transcript = Sha256Transcript::new("magnetar-virtual-address");
    transcript.absorb(
        "commitment",
        &bincode::serialize(&proof.opening.commitment)
            .map_err(|error| ProofError::Pcs(error.to_string()))?,
    );
    transcript.absorb(
        "targets",
        &bincode::serialize(targets).map_err(|error| ProofError::Pcs(error.to_string()))?,
    );
    let coefficients = sample_point(&mut transcript, targets.len().max(1));
    let pcs = linear_pcs(cycles);
    let address_width = 2 * shape.address_bits + 2;
    let points = vec![P3BatchPoint {
        point: proof.challenges.clone(),
        columns: (0..address_width).collect(),
    }];
    if !pcs
        .verify_batch(
            &proof.opening,
            &points,
            std::slice::from_ref(&proof.terminal_values),
        )
        .map_err(|error| ProofError::Pcs(error.to_string()))?
    {
        return Ok(false);
    }
    let claimed_sum = proof
        .claims
        .iter()
        .zip(&coefficients)
        .fold(F2_128::from(0u64), |sum, (claim, coefficient)| {
            sum + *coefficient * *claim
        });
    let replay = replay_terms_derived(&proof.rounds, claimed_sum, &mut transcript);
    let Some((final_sum, challenges)) = replay else {
        return Ok(false);
    };
    if challenges != proof.challenges {
        return Ok(false);
    }
    let mut expected = F2_128::from(0u64);
    for (target, coefficient) in targets.iter().zip(&coefficients) {
        let eq_eval = {
            let mut value = F2_128::from(1u64);
            for (a, b) in target.rj.iter().zip(&challenges) {
                value = value
                    * (*a * *b + (F2_128::from(1u64) + *a) * (F2_128::from(1u64) + *b));
            }
            value
        };
        let valid_eval = if target.write {
            proof.terminal_values[2 * shape.address_bits + 1]
        } else {
            proof.terminal_values[shape.address_bits]
        };
        let mut product = eq_eval * valid_eval;
        for bit in 0..shape.address_bits {
            let bit_eval = if target.write {
                proof.terminal_values[shape.address_bits + 1 + bit]
            } else {
                proof.terminal_values[bit]
            };
            product = product
                * (target.rk[bit] * bit_eval
                    + (F2_128::from(1u64) + target.rk[bit])
                        * (F2_128::from(1u64) + bit_eval));
        }
        expected = expected + *coefficient * product;
    }
    Ok(final_sum == expected)
}

#[cfg(test)]
mod address_tests {
    use super::*;

    #[test]
    fn virtual_address_round_trips() {
        let witness = crate::linear_twist::tests::register_witness();
        let shape = witness_shape(&witness);
        let point = |salt: usize, bits: usize| {
            (0..bits)
                .map(|index| F2_128::from((index * 7 + salt) as u64))
                .collect::<Vec<_>>()
        };
        let targets = vec![
            VirtualTarget {
                write: false,
                rk: point(3, shape.address_bits),
                rj: point(1, shape.cycle_bits()),
            },
            VirtualTarget {
                write: true,
                rk: point(5, shape.address_bits),
                rj: point(2, shape.cycle_bits()),
            },
            VirtualTarget {
                write: true,
                rk: point(9, shape.address_bits),
                rj: point(4, shape.cycle_bits()),
            },
        ];
        let proof = prove_virtual_address(&witness, &targets).unwrap();
        assert!(verify_virtual_address(shape, &targets, &proof).unwrap());
        let bytes = bincode::serialize(&proof).unwrap().len();
        eprintln!("virtual_address targets={} bytes={bytes}", targets.len());
    }
}
