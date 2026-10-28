//! Local (virtual) Twist proof: no dense RA/WA/Val commitments.

use magnetar_constraint::F2_128;
use magnetar_memory::BinaryTwistWitness;
use magnetar_pcs::{P3BatchPoint, P3BatchOpening};
use magnetar_proof::ProofError;
use magnetar_transcript::Sha256Transcript;

use crate::binary_twist::{
    eq_vector, replay_terms_derived, sample_point, sumcheck_terms,
};
use crate::linear_twist::{
    build_val_tables, eq_points_local, eval_mle, fixed_sumcheck, linear_pcs,
    replay_fixed, witness_shape, LinearTwistShape,
};
use crate::virtual_onehot::{
    prove_virtual_address, verify_virtual_address, VirtualAddressProof, VirtualTarget,
};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LocalTwistProof {
    pub shape: LinearTwistShape,
    pub values_opening: P3BatchOpening,
    pub values: Vec<Vec<F2_128>>,
    pub endpoints_opening: P3BatchOpening,
    pub endpoints: Vec<Vec<F2_128>>,
    pub virtual_address: VirtualAddressProof,
    pub rw_rounds: Vec<Vec<F2_128>>,
    pub rw_challenges: Vec<F2_128>,
    pub val_claim: F2_128,
    pub val_rounds: Vec<Vec<F2_128>>,
    pub val_challenges: Vec<F2_128>,
    pub final_rounds: Vec<Vec<F2_128>>,
}

pub(crate) fn dense_onehot(witness: &BinaryTwistWitness, write: bool) -> Vec<Vec<F2_128>> {
    let shape = witness_shape(witness);
    let cells = shape.cells();
    let cycles = shape.cycles;
    let source = if write {
        &witness.write_address
    } else {
        &witness.read_address
    };
    let mut dense = vec![vec![F2_128::from(0u64); cycles]; cells];
    for (cycle, row) in source.iter().enumerate() {
        for cell in 0..cells {
            dense[cell][cycle] = row[cell];
        }
    }
    dense
}

pub(crate) fn flat(columns: &[Vec<F2_128>], cycles: usize) -> Vec<F2_128> {
    let cells = columns.len();
    let mut result = vec![F2_128::from(0u64); cells * cycles];
    for (cell, column) in columns.iter().enumerate() {
        for cycle in 0..cycles {
            result[cell * cycles + cycle] = column[cycle];
        }
    }
    result
}

pub(crate) fn padded(values: &[F2_128], cycles: usize) -> Vec<F2_128> {
    let mut result = values.to_vec();
    result.resize(cycles, F2_128::from(0u64));
    result
}

pub fn prove_local_twist(witness: &BinaryTwistWitness) -> Result<LocalTwistProof, ProofError> {
    let shape = witness_shape(witness);
    let cells = shape.cells();
    let cycles = shape.cycles;
    let cycle_bits = shape.cycle_bits();
    let read = dense_onehot(witness, false);
    let write = dense_onehot(witness, true);
    let (val_columns, _, inc) = build_val_tables(witness);
    let val = {
        // build_val_tables returns a flattened val table; re-split by cell.
        let mut value = vec![vec![F2_128::from(0u64); cycles]; cells];
        for cell in 0..cells {
            value[cell].copy_from_slice(&val_columns[cell * cycles..(cell + 1) * cycles]);
        }
        value
    };
    let read_flat = flat(&read, cycles);
    let write_flat = flat(&write, cycles);
    let val_flat = flat(&val, cycles);
    let inc_flat = {
        let mut result = vec![F2_128::from(0u64); cells * cycles];
        for cycle in 0..cycles {
            for cell in 0..cells {
                result[cell * cycles + cycle] = inc[cycle];
            }
        }
        result
    };
    let read_value = padded(&witness.read_value, cycles);
    let write_value = padded(&witness.write_value, cycles);
    let values_columns = vec![inc.clone(), read_value.clone(), write_value.clone()];
    let mut initial = witness.initial.clone();
    initial.resize(cells.next_power_of_two().max(2), F2_128::from(0u64));
    let mut final_value = witness.final_value.clone();
    final_value.resize(cells.next_power_of_two().max(2), F2_128::from(0u64));
    let endpoint_columns = vec![initial.clone(), final_value.clone()];
    let pcs = linear_pcs(cycles);
    let values_commit = pcs
        .commit_batch(&values_columns)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let endpoints_commit = pcs
        .commit_batch(&endpoint_columns)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let mut transcript = Sha256Transcript::new("magnetar-local-twist");
    for commitment in [&values_commit, &endpoints_commit] {
        transcript.absorb(
            "commitment",
            &bincode::serialize(commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
        );
    }
    let gamma = sample_point(&mut transcript, 1)[0];
    let cycle_point = sample_point(&mut transcript, cycle_bits);
    let eq = eq_vector(&cycle_point, cycles);
    let mut eq_flat = vec![F2_128::from(0u64); cells * cycles];
    for cycle in 0..cycles {
        for cell in 0..cells {
            eq_flat[cell * cycles + cycle] = eq[cycle];
        }
    }
    let factors = vec![
        eq_flat,
        write_flat.clone(),
        inc_flat.clone(),
        val_flat.clone(),
        read_flat.clone(),
    ];
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
    let targets = vec![
        VirtualTarget {
            write: false,
            rk: rk.clone(),
            rj: rj.clone(),
        },
        VirtualTarget {
            write: true,
            rk: rk.clone(),
            rj: rj.clone(),
        },
        VirtualTarget {
            write: true,
            rk: rk.clone(),
            rj: val_challenges.clone(),
        },
    ];
    let virtual_address = prove_virtual_address(witness, &targets)?;
    let cell_point = rk.clone();
    let values_points = vec![
        P3BatchPoint {
            point: cycle_point.clone(),
            columns: vec![1, 2],
        },
        P3BatchPoint {
            point: rw_challenges[..cycle_bits].to_vec(),
            columns: vec![0],
        },
        P3BatchPoint {
            point: val_challenges.clone(),
            columns: vec![0],
        },
    ];
    let values = vec![
        vec![
            eval_mle(&values_columns[1], &cycle_point),
            eval_mle(&values_columns[2], &cycle_point),
        ],
        vec![eval_mle(&values_columns[0], &rw_challenges[..cycle_bits])],
        vec![eval_mle(&values_columns[0], &val_challenges)],
    ];
    let endpoints_points = vec![
        P3BatchPoint {
            point: rk.clone(),
            columns: vec![0],
        },
        P3BatchPoint {
            point: cell_point.clone(),
            columns: vec![0, 1],
        },
    ];
    let endpoints = vec![
        vec![eval_mle(&endpoint_columns[0], &rk)],
        vec![
            eval_mle(&endpoint_columns[0], &cell_point),
            eval_mle(&endpoint_columns[1], &cell_point),
        ],
    ];
    let values_opening = pcs
        .open_batch(&values_columns, &values_points)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let endpoints_opening = pcs
        .open_batch(&endpoint_columns, &endpoints_points)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    // Final-state fixed sumcheck.
    let eq_cell = eq_vector(&cell_point, cells);
    let mut eq_cell_flat = vec![F2_128::from(0u64); cells * cycles];
    let mut inc_cell_flat = vec![F2_128::from(0u64); cells * cycles];
    for (cell, eq_value) in eq_cell.iter().enumerate() {
        for (cycle, inc_value) in inc.iter().enumerate() {
            let index = cell * cycles + cycle;
            eq_cell_flat[index] = *eq_value;
            inc_cell_flat[index] = *inc_value;
        }
    }
    let final_factors = vec![eq_cell_flat, write_flat, inc_cell_flat];
    let final_rounds = {
        let (rounds, _) = fixed_sumcheck(final_factors, &rw_challenges, |folded| {
            (0..folded[0].len()).fold(F2_128::from(0u64), |sum, index| {
                sum + folded[0][index] * folded[1][index] * folded[2][index]
            })
        });
        rounds
    };
    Ok(LocalTwistProof {
        shape,
        values_opening,
        values,
        endpoints_opening,
        endpoints,
        virtual_address,
        rw_rounds,
        rw_challenges,
        val_claim,
        val_rounds,
        val_challenges,
        final_rounds,
    })
}

pub fn verify_local_twist(proof: &LocalTwistProof) -> Result<bool, ProofError> {
    let shape = proof.shape;
    let cycles = shape.cycles;
    let cells = shape.cells();
    let cycle_bits = shape.cycle_bits();
    let pcs = linear_pcs(cycles);
    if proof.values.len() != 3 || proof.endpoints.len() != 2 {
        return Ok(false);
    }
    // Derive RW/Val points from the transcript.
    let mut transcript = Sha256Transcript::new("magnetar-local-twist");
    for commitment in [
        &proof.values_opening.commitment,
        &proof.endpoints_opening.commitment,
    ] {
        transcript.absorb(
            "commitment",
            &bincode::serialize(commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
        );
    }
    let gamma = sample_point(&mut transcript, 1)[0];
    let cycle_point = sample_point(&mut transcript, cycle_bits);
    let rk = proof.rw_challenges[cycle_bits..].to_vec();
    let rj = proof.rw_challenges[..cycle_bits].to_vec();
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
            point: proof.val_challenges.clone(),
            columns: vec![0],
        },
    ];
    let endpoints_points = vec![
        P3BatchPoint {
            point: rk.clone(),
            columns: vec![0],
        },
        P3BatchPoint {
            point: rk.clone(),
            columns: vec![0, 1],
        },
    ];
    let values_ok = pcs
        .verify_batch(&proof.values_opening, &values_points, &proof.values)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    let endpoints_ok = pcs
        .verify_batch(&proof.endpoints_opening, &endpoints_points, &proof.endpoints)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    if !(values_ok && endpoints_ok) {
        return Ok(false);
    }
    let targets = vec![
        VirtualTarget {
            write: false,
            rk: rk.clone(),
            rj: rj.clone(),
        },
        VirtualTarget {
            write: true,
            rk: rk.clone(),
            rj: rj.clone(),
        },
        VirtualTarget {
            write: true,
            rk: rk.clone(),
            rj: proof.val_challenges.clone(),
        },
    ];
    if !verify_virtual_address(shape, &targets, &proof.virtual_address)? {
        return Ok(false);
    }
    let claims = &proof.virtual_address.claims;
    // RW replay.
    let claimed = proof.values[0][1] + gamma * proof.values[0][0];
    let mut transcript = Sha256Transcript::new("magnetar-local-twist");
    for commitment in [
        &proof.values_opening.commitment,
        &proof.endpoints_opening.commitment,
    ] {
        transcript.absorb(
            "commitment",
            &bincode::serialize(commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
        );
    }
    let _ = sample_point(&mut transcript, 1);
    let _ = sample_point(&mut transcript, cycle_bits);
    let Some((rw_final, rw_challenges)) =
        replay_terms_derived(&proof.rw_rounds, claimed, &mut transcript)
    else {
        return Ok(false);
    };
    if rw_challenges != proof.rw_challenges {
        return Ok(false);
    }
    let eq_final = eq_points_local(&cycle_point, &rw_challenges[..cycle_bits]);
    let inc_rw = proof.values[1][0];
    let rw_expected = eq_final
        * (claims[1] * (inc_rw + proof.val_claim)
            + gamma * claims[0] * proof.val_claim);
    if rw_final != rw_expected {
        return Ok(false);
    }
    // Val replay.
    let Some((val_final, val_challenges)) =
        replay_terms_derived(&proof.val_rounds, proof.val_claim, &mut transcript)
    else {
        return Ok(false);
    };
    if val_challenges != proof.val_challenges {
        return Ok(false);
    }
    let lt_eval = crate::binary_twist::lt_mle(&val_challenges, &rj, cycles);
    let val_expected = claims[2] * proof.values[2][0] * lt_eval;
    if val_final != val_expected {
        return Ok(false);
    }
    // Final-state replay.
    let final_claim = proof.endpoints[1][1] - proof.endpoints[1][0];
    let Some(final_sum) = replay_fixed(&proof.final_rounds, final_claim, &proof.rw_challenges)
    else {
        return Ok(false);
    };
    let eq_cell = eq_points_local(&rk, &rk);
    let final_expected = eq_cell * claims[1] * inc_rw;
    let _ = cells;
    Ok(final_sum == final_expected)
}


/// Outer Access-table claims implied by the local proof.
pub fn local_outer_claims(
    proof: &LocalTwistProof,
) -> Result<Vec<crate::linear_twist::LinearOuterClaim>, ProofError> {
    use crate::linear_twist::{LinearOuterClaim, LinearOuterTable};
    let shape = proof.shape;
    let address_bits = shape.address_bits;
    let cycle_bits = shape.cycle_bits();
    let mut transcript = Sha256Transcript::new("magnetar-local-twist");
    for commitment in [
        &proof.values_opening.commitment,
        &proof.endpoints_opening.commitment,
    ] {
        transcript.absorb(
            "commitment",
            &bincode::serialize(commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
        );
    }
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
        point: cycle_point.clone(),
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
        value: proof.endpoints[1][0],
    });
    claims.push(LinearOuterClaim {
        table: LinearOuterTable::Final,
        column: 1,
        point: rk,
        value: proof.endpoints[1][1],
    });
    // Virtual address terminal values at the virtual sumcheck point.
    let point = proof.virtual_address.challenges.clone();
    let values = &proof.virtual_address.terminal_values;
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
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_twist_round_trips() {
        let witness = crate::linear_twist::tests::register_witness();
        let proof = prove_local_twist(&witness).unwrap();
        assert!(verify_local_twist(&proof).unwrap());
        let bytes = bincode::serialize(&proof).unwrap().len();
        eprintln!("local_twist bytes={bytes}");
    }
}
