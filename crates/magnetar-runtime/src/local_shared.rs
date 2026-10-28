//! Local Twist proof with one shared PCS opening for values, address, and
//! endpoint tables.

use magnetar_constraint::F2_128;
use magnetar_memory::BinaryTwistWitness;
use magnetar_pcs::{P3BatchPoint, P3BatchOpening};
use magnetar_proof::ProofError;
use magnetar_transcript::Sha256Transcript;

use crate::binary_twist::{
    eq_vector, replay_terms_derived, sample_point, sumcheck_terms,
};
use crate::linear_twist::{
    eq_points_local, eval_mle, fixed_sumcheck, linear_pcs, replay_fixed,
    witness_shape, LinearTwistShape,
};
use crate::local_twist::{dense_onehot, flat, padded};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LocalSharedProof {
    pub shape: LinearTwistShape,
    pub opening: P3BatchOpening,
    pub values: Vec<Vec<F2_128>>,
    pub endpoints_opening: P3BatchOpening,
    pub endpoints: Vec<F2_128>,
    pub rw_rounds: Vec<Vec<F2_128>>,
    pub rw_challenges: Vec<F2_128>,
    pub val_claim: F2_128,
    pub val_rounds: Vec<Vec<F2_128>>,
    pub val_challenges: Vec<F2_128>,
    pub virtual_claims: Vec<F2_128>,
    pub virtual_rounds: Vec<Vec<F2_128>>,
    pub virtual_challenges: Vec<F2_128>,
    pub final_rounds: Vec<Vec<F2_128>>,
}

fn layout(shape: LinearTwistShape) -> (usize, usize, usize, usize, usize) {
    let a = shape.address_bits;
    (
        3,         // read bits start
        3 + a,     // read valid
        4 + a,     // write bits start
        4 + 2 * a, // write valid
        5 + 2 * a, // initial, final = +1
    )
}

fn build_columns(witness: &BinaryTwistWitness) -> Vec<Vec<F2_128>> {
    let shape = witness_shape(witness);
    let cycles = shape.cycles;
    let (read_bits, read_valid, _) = crate::virtual_onehot::bit_columns_pub(witness, false);
    let (write_bits, write_valid, _) = crate::virtual_onehot::bit_columns_pub(witness, true);
    let mut inc = vec![F2_128::from(0u64); cycles];
    let copied = witness.cycles.min(cycles);
    inc[..copied].copy_from_slice(&witness.increment[..copied]);
    let read_value = padded(&witness.read_value, cycles);
    let write_value = padded(&witness.write_value, cycles);
    let mut columns = vec![inc, read_value, write_value];
    columns.extend(read_bits);
    columns.push(read_valid);
    columns.extend(write_bits);
    columns.push(write_valid);
    columns
}

pub fn prove_local_shared(witness: &BinaryTwistWitness) -> Result<LocalSharedProof, ProofError> {
    let shape = witness_shape(witness);
    let cells = shape.cells();
    let cycles = shape.cycles;
    let cycle_bits = shape.cycle_bits();
    let columns = build_columns(witness);
    let read = dense_onehot(witness, false);
    let write = dense_onehot(witness, true);
    let (val_flat, _, inc) = crate::linear_twist::build_val_tables(witness);
    let write_flat = flat(&write, cycles);
    let read_flat = flat(&read, cycles);
    let mut inc_flat = vec![F2_128::from(0u64); cells * cycles];
    for cycle in 0..cycles {
        for cell in 0..cells {
            inc_flat[cell * cycles + cycle] = inc[cycle];
        }
    }
    let pcs = linear_pcs(cycles);
    let commitment = pcs
        .commit_batch(&columns)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let mut transcript = Sha256Transcript::new("magnetar-local-shared");
    transcript.absorb(
        "commitment",
        &bincode::serialize(&commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
    );
    let gamma = sample_point(&mut transcript, 1)[0];
    let cycle_point = sample_point(&mut transcript, cycle_bits);
    let eq = eq_vector(&cycle_point, cycles);
    let mut eq_flat = vec![F2_128::from(0u64); cells * cycles];
    for cycle in 0..cycles {
        for cell in 0..cells {
            eq_flat[cell * cycles + cycle] = eq[cycle];
        }
    }
    let factors = vec![eq_flat, write_flat.clone(), inc_flat.clone(), val_flat.clone(), read_flat];
    let gamma_copy = gamma;
    let (rw_rounds, rw_challenges) = sumcheck_terms(
        &factors,
        &vec![3usize; cells.trailing_zeros() as usize + cycle_bits],
        &mut transcript,
        move |folded| {
            (0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
                sum + folded[0][index]
                    * (folded[1][index] * folded[2][index]
                        + folded[1][index] * folded[3][index]
                        + gamma_copy * folded[4][index] * folded[3][index])
            })
        },
    )?;
    let rk = rw_challenges[cycle_bits..].to_vec();
    let rj = rw_challenges[..cycle_bits].to_vec();
    let val_claim = eval_mle(&val_flat, &rj.iter().chain(&rk).copied().collect::<Vec<_>>());
    let eq_rj = eq_vector(&rj, cycles);
    let mut suffix = vec![F2_128::from(0u64); cycles];
    let mut running = F2_128::from(0u64);
    for previous in (0..cycles).rev() {
        suffix[previous] = running;
        running = running + eq_rj[previous];
    }
    let mut wa_at_rk = (0..cycles)
        .map(|cycle| {
            witness
                .write_address
                .get(cycle)
                .map_or(F2_128::from(0u64), |row| eval_mle(row, &rk))
        })
        .collect::<Vec<_>>();
    wa_at_rk.resize(cycles, F2_128::from(0u64));
    let val_factors = vec![wa_at_rk, inc.clone(), suffix];
    let (val_rounds, val_challenges) = sumcheck_terms(
        &val_factors,
        &vec![3usize; cycle_bits],
        &mut transcript,
        |folded| {
            (0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
                sum + folded[0][index] * folded[1][index] * folded[2][index]
            })
        },
    )?;
    // Virtual address targets.
    let targets = vec![
        (false, rk.clone(), rj.clone()),
        (true, rk.clone(), rj.clone()),
        (true, rk.clone(), val_challenges.clone()),
    ];
    let mut virtual_claims = Vec::with_capacity(targets.len());
    let mut virtual_factors = Vec::new();
    let mut groups = Vec::with_capacity(targets.len());
    let (rb, rv) = (crate::virtual_onehot::bit_columns_pub(witness, false).0, crate::virtual_onehot::bit_columns_pub(witness, false).1);
    let (wb, wv) = (crate::virtual_onehot::bit_columns_pub(witness, true).0, crate::virtual_onehot::bit_columns_pub(witness, true).1);
    for (write_target, target_rk, target_rj) in &targets {
        let (bits, valid) = if *write_target { (&wb, &wv) } else { (&rb, &rv) };
        let dense = if *write_target { &write } else { &read };
        let dense_flat = flat(dense, cycles);
        virtual_claims.push(eval_mle(
            &dense_flat,
            &target_rj.iter().chain(target_rk).copied().collect::<Vec<_>>(),
        ));
        let mut group = Vec::new();
        group.push(virtual_factors.len());
        virtual_factors.push(eq_vector(target_rj, cycles));
        group.push(virtual_factors.len());
        virtual_factors.push(valid.clone());
        for (bit, column) in bits.iter().enumerate() {
            group.push(virtual_factors.len());
            virtual_factors.push(
                column
                    .iter()
                    .map(|value| {
                        target_rk[bit] * *value
                            + (F2_128::from(1u64) + target_rk[bit])
                                * (F2_128::from(1u64) + *value)
                    })
                    .collect(),
            );
        }
        groups.push(group);
    }
    let coefficients = sample_point(&mut transcript, targets.len());
    let coefficients_copy = coefficients.clone();
    let groups_copy = groups.clone();
    let (virtual_rounds, virtual_challenges) = sumcheck_terms(
        &virtual_factors,
        &vec![shape.address_bits + 1; cycle_bits],
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
    let (read_bits_start, read_valid_index, write_bits_start, write_valid_index, endpoint_start) = layout(shape);
    let address_columns = (0..2 * shape.address_bits + 2)
        .map(|index| read_bits_start + index)
        .collect::<Vec<_>>();
    let values_points = vec![
        P3BatchPoint {
            point: cycle_point.clone(),
            columns: vec![1, 2],
        },
        P3BatchPoint {
            point: rj.clone(),
            columns: vec![0],
        },
        P3BatchPoint {
            point: val_challenges.clone(),
            columns: vec![0],
        },
        P3BatchPoint {
            point: virtual_challenges.clone(),
            columns: address_columns,
        },
    ];
    let values = vec![
        vec![
            eval_mle(&columns[1], &cycle_point),
            eval_mle(&columns[2], &cycle_point),
        ],
        vec![eval_mle(&columns[0], &rj)],
        vec![eval_mle(&columns[0], &val_challenges)],
        (0..2 * shape.address_bits + 2)
            .map(|index| eval_mle(&columns[read_bits_start + index], &virtual_challenges))
            .collect::<Vec<_>>(),
    ];
    let opening = pcs
        .open_batch(&columns, &values_points)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let mut initial = witness.initial.clone();
    initial.resize(cells.next_power_of_two().max(2), F2_128::from(0u64));
    let mut final_value = witness.final_value.clone();
    final_value.resize(cells.next_power_of_two().max(2), F2_128::from(0u64));
    let endpoint_columns = vec![initial, final_value];
    let _endpoint_commit = pcs
        .commit_batch(&endpoint_columns)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let endpoint_points = vec![P3BatchPoint {
        point: rk.clone(),
        columns: vec![0, 1],
    }];
    let endpoints = vec![
        eval_mle(&endpoint_columns[0], &rk),
        eval_mle(&endpoint_columns[1], &rk),
    ];
    let endpoints_opening = pcs
        .open_batch(&endpoint_columns, &endpoint_points)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let _ = (read_valid_index, write_bits_start, write_valid_index, endpoint_start);
    // Final state rounds.
    let eq_cell = eq_vector(&rk, cells);
    let mut eq_cell_flat = vec![F2_128::from(0u64); cells * cycles];
    let mut inc_cell_flat = vec![F2_128::from(0u64); cells * cycles];
    for (cell, eq_value) in eq_cell.iter().enumerate() {
        for (cycle, inc_value) in inc.iter().enumerate() {
            let index = cell * cycles + cycle;
            eq_cell_flat[index] = *eq_value;
            inc_cell_flat[index] = *inc_value;
        }
    }
    let final_rounds = {
        let (rounds, _) = fixed_sumcheck(vec![eq_cell_flat, write_flat, inc_cell_flat], &rw_challenges, |folded| {
            (0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
                sum + folded[0][index] * folded[1][index] * folded[2][index]
            })
        });
        rounds
    };
    Ok(LocalSharedProof {
        shape,
        opening,
        values,
        endpoints_opening,
        endpoints,
        rw_rounds,
        rw_challenges,
        val_claim,
        val_rounds,
        val_challenges,
        virtual_claims,
        virtual_rounds,
        virtual_challenges,
        final_rounds,
    })
}

pub fn verify_local_shared(proof: &LocalSharedProof) -> Result<bool, ProofError> {
    let shape = proof.shape;
    let cells = shape.cells();
    let cycles = shape.cycles;
    let cycle_bits = shape.cycle_bits();
    let (read_bits_start, _read_valid, _write_bits_start, _write_valid, _endpoint_start) = layout(shape);
    let rk = proof.rw_challenges[cycle_bits..].to_vec();
    let rj = proof.rw_challenges[..cycle_bits].to_vec();
    let mut transcript = Sha256Transcript::new("magnetar-local-shared");
    transcript.absorb(
        "commitment",
        &bincode::serialize(&proof.opening.commitment)
            .map_err(|error| ProofError::Pcs(error.to_string()))?,
    );
    let gamma = sample_point(&mut transcript, 1)[0];
    let cycle_point = sample_point(&mut transcript, cycle_bits);
    let address_columns = (0..2 * shape.address_bits + 2)
        .map(|index| read_bits_start + index)
        .collect::<Vec<_>>();
    let points = vec![
        P3BatchPoint {
            point: cycle_point.clone(),
            columns: vec![1, 2],
        },
        P3BatchPoint {
            point: rj.clone(),
            columns: vec![0],
        },
        P3BatchPoint {
            point: proof.val_challenges.clone(),
            columns: vec![0],
        },
        P3BatchPoint {
            point: proof.virtual_challenges.clone(),
            columns: address_columns,
        },
    ];
    let pcs = linear_pcs(cycles);
    if !pcs
        .verify_batch(&proof.opening, &points, &proof.values)
        .map_err(|error| ProofError::Pcs(error.to_string()))?
    {
        return Ok(false);
    }
    let endpoint_points = vec![P3BatchPoint {
        point: rk.clone(),
        columns: vec![0, 1],
    }];
    if !pcs
        .verify_batch(
            &proof.endpoints_opening,
            &endpoint_points,
            std::slice::from_ref(&proof.endpoints),
        )
        .map_err(|error| ProofError::Pcs(error.to_string()))?
    {
        return Ok(false);
    }
    // RW.
    let claimed = proof.values[0][1] + gamma * proof.values[0][0];
    let Some((rw_final, rw_challenges)) =
        replay_terms_derived(&proof.rw_rounds, claimed, &mut transcript)
    else {
        return Ok(false);
    };
    if rw_challenges != proof.rw_challenges {
        return Ok(false);
    }
    let Some((val_final, val_challenges)) =
        replay_terms_derived(&proof.val_rounds, proof.val_claim, &mut transcript)
    else {
        return Ok(false);
    };
    if val_challenges != proof.val_challenges {
        return Ok(false);
    }
    // Virtual coefficient challenges.
    let coefficients = sample_point(&mut transcript, 3);
    let claimed_virtual = proof
        .virtual_claims
        .iter()
        .zip(&coefficients)
        .fold(F2_128::from(0u64), |sum, (claim, coefficient)| {
            sum + *coefficient * *claim
        });
    let Some((virtual_final, virtual_challenges)) =
        replay_terms_derived(&proof.virtual_rounds, claimed_virtual, &mut transcript)
    else {
        return Ok(false);
    };
    if virtual_challenges != proof.virtual_challenges {
        return Ok(false);
    }
    let terminal = &proof.values[3];
    let mut expected_virtual = F2_128::from(0u64);
    for (index, (write_target, coefficient)) in [(false, coefficients[0]), (true, coefficients[1]), (true, coefficients[2])]
        .iter()
        .enumerate()
    {
        let target_rk = &rk;
        let target_rj = if index == 2 { &proof.val_challenges } else { &rj };
        let eq_eval = {
            let mut value = F2_128::from(1u64);
            for (a, b) in target_rj.iter().zip(&virtual_challenges) {
                value = value
                    * (*a * *b + (F2_128::from(1u64) + *a) * (F2_128::from(1u64) + *b));
            }
            value
        };
        let valid_eval = if *write_target {
            terminal[2 * shape.address_bits + 1]
        } else {
            terminal[shape.address_bits]
        };
        let mut product = eq_eval * valid_eval;
        for bit in 0..shape.address_bits {
            let bit_eval = if *write_target {
                terminal[shape.address_bits + 1 + bit]
            } else {
                terminal[bit]
            };
            product = product
                * (target_rk[bit] * bit_eval
                    + (F2_128::from(1u64) + target_rk[bit])
                        * (F2_128::from(1u64) + bit_eval));
        }
        expected_virtual = expected_virtual + *coefficient * product;
    }
    if virtual_final != expected_virtual {
        return Ok(false);
    }
    let claims = &proof.virtual_claims;
    let eq_final = eq_points_local(&cycle_point, &rw_challenges[..cycle_bits]);
    let inc_rw = proof.values[1][0];
    let rw_expected = eq_final
        * (claims[1] * (inc_rw + proof.val_claim) + gamma * claims[0] * proof.val_claim);
    if rw_final != rw_expected {
        return Ok(false);
    }
    let lt_eval = crate::binary_twist::lt_mle(&val_challenges, &rj, cycles);
    let val_expected = claims[2] * proof.values[2][0] * lt_eval;
    if val_final != val_expected {
        return Ok(false);
    }
    let final_claim = proof.endpoints[1] - proof.endpoints[0];
    let Some(final_sum) = replay_fixed(&proof.final_rounds, final_claim, &proof.rw_challenges) else {
        return Ok(false);
    };
    let eq_cell = eq_points_local(&rk, &rk);
    let final_expected = eq_cell * claims[1] * inc_rw;
    let _ = cells;
    Ok(final_sum == final_expected)
}


/// Outer Access-table claims implied by the shared local proof.
pub fn local_shared_outer_claims(
    proof: &LocalSharedProof,
) -> Result<Vec<crate::linear_twist::LinearOuterClaim>, ProofError> {
    use crate::linear_twist::{LinearOuterClaim, LinearOuterTable};
    let shape = proof.shape;
    let address_bits = shape.address_bits;
    let cycle_bits = shape.cycle_bits();
    let (read_bits_start, _, _, _, _) = layout(shape);
    let mut transcript = Sha256Transcript::new("magnetar-local-shared");
    transcript.absorb(
        "commitment",
        &bincode::serialize(&proof.opening.commitment)
            .map_err(|error| ProofError::Pcs(error.to_string()))?,
    );
    let _gamma = sample_point(&mut transcript, 1)[0];
    let cycle_point = sample_point(&mut transcript, cycle_bits);
    let rk = proof.rw_challenges[cycle_bits..].to_vec();
    let mut claims = vec![LinearOuterClaim {
        table: LinearOuterTable::ReadValue,
        column: 0,
        point: cycle_point.clone(),
        value: proof.values[0][0],
    }];
    claims.push(LinearOuterClaim {
        table: LinearOuterTable::WriteValue,
        column: 0,
        point: cycle_point,
        value: proof.values[0][1],
    });
    claims.push(LinearOuterClaim {
        table: LinearOuterTable::Increment,
        column: 0,
        point: proof.rw_challenges[..cycle_bits].to_vec(),
        value: proof.values[1][0],
    });
    claims.push(LinearOuterClaim {
        table: LinearOuterTable::Increment,
        column: 0,
        point: proof.val_challenges.clone(),
        value: proof.values[2][0],
    });
    claims.push(LinearOuterClaim {
        table: LinearOuterTable::Initial,
        column: 0,
        point: rk.clone(),
        value: proof.endpoints[0],
    });
    claims.push(LinearOuterClaim {
        table: LinearOuterTable::Final,
        column: 1,
        point: rk,
        value: proof.endpoints[1],
    });
    let point = proof.virtual_challenges.clone();
    let values = &proof.values[3];
    for bit in 0..address_bits {
        claims.push(LinearOuterClaim {
            table: LinearOuterTable::Address,
            column: bit,
            point: point.clone(),
            value: values[bit],
        });
        claims.push(LinearOuterClaim {
            table: LinearOuterTable::Address,
            column: address_bits + bit,
            point: point.clone(),
            value: values[address_bits + 1 + bit],
        });
    }
    claims.push(LinearOuterClaim {
        table: LinearOuterTable::Address,
        column: 2 * address_bits,
        point: point.clone(),
        value: values[address_bits],
    });
    claims.push(LinearOuterClaim {
        table: LinearOuterTable::Address,
        column: 2 * address_bits + 1,
        point,
        value: values[2 * address_bits + 1],
    });
    let _ = read_bits_start;
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_shared_round_trips() {
        let witness = crate::linear_twist::tests::register_witness();
        let proof = prove_local_shared(&witness).unwrap();
        assert!(verify_local_shared(&proof).unwrap());
        eprintln!("local_shared bytes={}", bincode::serialize(&proof).unwrap().len());
    }
}
