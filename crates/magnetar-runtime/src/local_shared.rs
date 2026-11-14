//! Local Twist proof with one shared PCS opening for values, address, and
//! endpoint tables.

use magnetar_constraint::F2_128;
use magnetar_memory::BinaryTwistWitness;
use magnetar_pcs::{P3BatchPoint, P3BatchOpening};
use magnetar_proof::ProofError;
use magnetar_transcript::Sha256Transcript;

use crate::binary_twist::{
    eq_vector, fixed_sumcheck_mixed, replay_terms_derived, sample_point, sumcheck_terms_indexed,
    sumcheck_terms_mixed, SumcheckFactor,
};
use crate::linear_twist::{
    eq_points_local, eval_mle, linear_pcs, replay_fixed, witness_shape, LinearTwistShape,
};
use crate::local_twist::padded;

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

fn build_columns(
    witness: &BinaryTwistWitness,
    read_bits: Vec<Vec<F2_128>>,
    read_valid: Vec<F2_128>,
    write_bits: Vec<Vec<F2_128>>,
    write_valid: Vec<F2_128>,
) -> Vec<Vec<F2_128>> {
    let shape = witness_shape(witness);
    let cycles = shape.cycles;
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

/// Flattens the one-hot address matrix of one side directly, cell by cell.
///
/// `flat[cell * cycles + cycle]` is the address bit of that cell. Building it
/// straight from the witness rows avoids materialising the `cells` column
/// vectors first and then copying them again.
fn flat_onehot(witness: &BinaryTwistWitness, write: bool, cycles: usize) -> Vec<F2_128> {
    let cells = 1usize << witness.address_bits;
    let source = if write {
        &witness.write_address
    } else {
        &witness.read_address
    };
    let mut flat = vec![F2_128::from(0u64); cells * cycles];
    for (cycle, row) in source.iter().enumerate() {
        for (cell, value) in row.iter().enumerate().take(cells) {
            flat[cell * cycles + cycle] = *value;
        }
    }
    flat
}

/// Repeats one cycle-indexed vector under every cell of the flattened layout.
///
/// The prover no longer builds these arrays (the sum-checks read the compact
/// [`SumcheckFactor`] form instead); the test below pins the layout it replaces.
#[cfg(test)]
fn repeated_blocks(values: &[F2_128], cells: usize, cycles: usize) -> Vec<F2_128> {
    let mut flat = vec![F2_128::from(0u64); cells * cycles];
    for cell in 0..cells {
        flat[cell * cycles..cell * cycles + cycles].copy_from_slice(&values[..cycles]);
    }
    flat
}

/// The value table and increment column without the unused write-address table.
///
/// `val[cell * cycles + cycle]` is the cell's value before that cycle's write.
fn build_val_flat(witness: &BinaryTwistWitness) -> (Vec<F2_128>, Vec<F2_128>) {
    let cells = 1usize << witness.address_bits;
    let cycles = witness.cycles.next_power_of_two().max(2);
    let mut val = vec![F2_128::from(0u64); cells * cycles];
    let mut inc = vec![F2_128::from(0u64); cycles];
    let mut current = witness.initial.clone();
    current.resize(cells, F2_128::from(0u64));
    for (cycle, target_inc) in inc.iter_mut().enumerate() {
        let increment = witness
            .increment
            .get(cycle)
            .copied()
            .unwrap_or(F2_128::from(0u64));
        let write = witness.write_address.get(cycle);
        for cell in 0..cells {
            let index = cell * cycles + cycle;
            let write_bit = write.map_or(F2_128::from(0u64), |row| row[cell]);
            val[index] = current[cell];
            current[cell] = current[cell] + write_bit * increment;
        }
        *target_inc = increment;
    }
    (val, inc)
}

/// Evaluation of a one-hot address matrix at (cell point, cycle point).
///
/// `dense[cell][cycle]` is one exactly on the addressed cell, so the
/// multilinear evaluation is a per-cycle equality weight times the address
/// weight. This is `O(cycles * address_bits)` instead of a full `cells * cycles`
/// pass over a materialised dense matrix.
fn onehot_eval(
    bits: &[Vec<F2_128>],
    valid: &[F2_128],
    cell_point: &[F2_128],
    cycle_point: &[F2_128],
    cycles: usize,
) -> F2_128 {
    let eq = eq_vector(cycle_point, cycles);
    let mut total = F2_128::from(0u64);
    for cycle in 0..cycles {
        let mut weight = eq[cycle] * valid[cycle];
        for (bit, column) in bits.iter().enumerate() {
            let value = column[cycle];
            weight = weight
                * (cell_point[bit] * value
                    + (F2_128::from(1u64) + cell_point[bit])
                        * (F2_128::from(1u64) + value));
        }
        total = total + weight;
    }
    total
}

/// Per-stage wall and process-CPU timer for the Access register-twist prover.
///
/// Under a loaded host the stage wall times move with the load; the CPU delta
/// is what tells a real work reduction apart from a scheduling artefact. The
/// process CPU counter comes from the same `getrusage` helper the proof and
/// bench crates use.
struct LocalProfile {
    enabled: bool,
    cpu_start: f64,
    cpu_last: f64,
}

impl LocalProfile {
    fn new() -> Self {
        let cpu = magnetar_proof::process_cpu_seconds();
        Self {
            enabled: std::env::var_os("MAGNETAR_PROFILE_LOCAL").is_some(),
            cpu_start: cpu,
            cpu_last: cpu,
        }
    }

    fn mark(&mut self, stage: &str, elapsed: std::time::Duration) {
        if self.enabled {
            let cpu = magnetar_proof::process_cpu_seconds();
            eprintln!("local {stage}: {elapsed:?} cpu={:.3}s", cpu - self.cpu_last);
            self.cpu_last = cpu;
        }
    }

    fn total(&self, started: std::time::Instant) {
        if self.enabled {
            eprintln!(
                "local total: {:?} cpu={:.3}s",
                started.elapsed(),
                magnetar_proof::process_cpu_seconds() - self.cpu_start
            );
        }
    }
}

pub fn prove_local_shared(witness: &BinaryTwistWitness) -> Result<LocalSharedProof, ProofError> {
    let total_started = std::time::Instant::now();
    let mut profile = LocalProfile::new();
    let shape = witness_shape(witness);
    let cells = shape.cells();
    let cycles = shape.cycles;
    let cycle_bits = shape.cycle_bits();
    let started = std::time::Instant::now();
    // One pass over the witness builds the address bit columns; every later
    // table reuses them. The former code rebuilt them six times (twice here,
    // twice for each side of the virtual-address claims).
    let (read_bits, read_valid, _) = crate::virtual_onehot::bit_columns_pub(witness, false);
    let (write_bits, write_valid, _) = crate::virtual_onehot::bit_columns_pub(witness, true);
    let columns = build_columns(
        witness,
        read_bits.clone(),
        read_valid.clone(),
        write_bits.clone(),
        write_valid.clone(),
    );
    let write_flat = flat_onehot(witness, true, cycles);
    let read_flat = flat_onehot(witness, false, cycles);
    let (val_flat, inc) = build_val_flat(witness);
    profile.mark("tables", started.elapsed());
    let started = std::time::Instant::now();
    let pcs = linear_pcs(cycles);
    // `commit_batch_prepared` retains the codeword + Merkle tree of the address
    // columns until the opening ("the prepared batch moves into the opening").
    // That retained batch is a measured peak term (+0.76 GiB footprint at
    // `2^18`), so the default now commits, drops the data and re-encodes at the
    // opening (the selected prover's pattern): the commitment bytes and the
    // proof are identical (pinned by the ignored
    // `m5_v4_tests::local_recommit_proof_bytes_match` test), and the Access
    // peak drops 8.72 -> 7.96 GiB footprint at `2^18` for +0.1 % CPU.
    // `MAGNETAR_KEEP_LOCAL_PREPARED=1` restores the retained batch for a
    // same-binary A/B.
    let keep_prepared = std::env::var_os("MAGNETAR_KEEP_LOCAL_PREPARED").is_some();
    let prepared = if keep_prepared {
        Some(
            pcs.commit_batch_prepared(&columns)
                .map_err(|error| ProofError::Pcs(error.to_string()))?,
        )
    } else {
        None
    };
    let commitment = match &prepared {
        Some(prepared) => prepared.commitment.clone(),
        None => pcs
            .commit_batch(&columns)
            .map_err(|error| ProofError::Pcs(error.to_string()))?,
    };
    let mut transcript = Sha256Transcript::new("magnetar-local-shared");
    transcript.absorb(
        "commitment",
        &bincode::serialize(&commitment).map_err(|error| ProofError::Pcs(error.to_string()))?,
    );
    let gamma = sample_point(&mut transcript, 1)[0];
    let cycle_point = sample_point(&mut transcript, cycle_bits);
    profile.mark("commit", started.elapsed());
    let started = std::time::Instant::now();
    let eq = eq_vector(&cycle_point, cycles);
    // `eq(cycle_point)` and the increment column repeat under every cell, so
    // they stay as `cycles`-long blocks instead of being expanded to
    // `cells * cycles` field elements each (the summand reads the same values,
    // so the round polynomials and the proof are unchanged).
    let mut factors = vec![
        SumcheckFactor::repeat_low(eq, cycle_bits),
        SumcheckFactor::Dense(write_flat.clone()),
        SumcheckFactor::repeat_low(inc.clone(), cycle_bits),
        SumcheckFactor::Dense(val_flat.clone()),
        SumcheckFactor::Dense(read_flat),
    ];
    profile.mark("rw factors", started.elapsed());
    if std::env::var_os("MAGNETAR_PROFILE_LOCAL").is_some() {
        let dense = factors
            .iter()
            .filter(|factor| matches!(factor, SumcheckFactor::Dense(_)))
            .count();
        eprintln!(
            "local factors: {dense} dense arrays of {} fields ({} stored compactly), {}",
            cells * cycles,
            factors.len() - dense,
            crate::memory_gib()
        );
    }
    let started = std::time::Instant::now();
    let gamma_copy = gamma;
    let (rw_rounds, rw_challenges) = sumcheck_terms_mixed(
        &mut factors,
        cells * cycles,
        &vec![3usize; cells.trailing_zeros() as usize + cycle_bits],
        &mut transcript,
        move |folded| {
            folded[0]
                * (folded[1] * folded[2]
                    + folded[1] * folded[3]
                    + gamma_copy * folded[4] * folded[3])
        },
    )?;
    profile.mark("rw sumcheck", started.elapsed());
    let started = std::time::Instant::now();
    let rk = rw_challenges[cycle_bits..].to_vec();
    let rj = rw_challenges[..cycle_bits].to_vec();
    let val_claim = eval_mle(&val_flat, &rj.iter().chain(&rk).copied().collect::<Vec<_>>());
    if std::env::var_os("MAGNETAR_PROFILE_LOCAL").is_some() {
        eprintln!("local after rw sumcheck: {}", crate::memory_gib());
    }
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
    let mut val_factors = vec![wa_at_rk, inc.clone(), suffix];
    let (val_rounds, val_challenges) = sumcheck_terms_indexed(
        &mut val_factors,
        &vec![3usize; cycle_bits],
        &mut transcript,
        |folded| folded[0] * folded[1] * folded[2],
    )?;
    profile.mark("val sumcheck", started.elapsed());
    let started = std::time::Instant::now();
    // Virtual address targets.
    let targets = vec![
        (false, rk.clone(), rj.clone()),
        (true, rk.clone(), rj.clone()),
        (true, rk.clone(), val_challenges.clone()),
    ];
    let mut virtual_claims = Vec::with_capacity(targets.len());
    let mut virtual_factors = Vec::new();
    let mut groups = Vec::with_capacity(targets.len());
    for (write_target, target_rk, target_rj) in &targets {
        let (bits, valid) = if *write_target {
            (&write_bits, &write_valid)
        } else {
            (&read_bits, &read_valid)
        };
        virtual_claims.push(onehot_eval(
            bits,
            valid,
            target_rk,
            target_rj,
            cycles,
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
    let (virtual_rounds, virtual_challenges) = sumcheck_terms_indexed(
        &mut virtual_factors,
        &vec![shape.address_bits + 1; cycle_bits],
        &mut transcript,
        move |folded| {
            let mut value = F2_128::from(0u64);
            for (group, coefficient) in groups_copy.iter().zip(&coefficients_copy) {
                let mut product = *coefficient;
                for factor in group {
                    product = product * folded[*factor];
                }
                value = value + product;
            }
            value
        },
    )?;
    profile.mark("virtual sumcheck", started.elapsed());
    let started = std::time::Instant::now();
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
    profile.mark("value claims", started.elapsed());
    let started = std::time::Instant::now();
    // The prepared batch moves into the opening: no deep copy of the codeword
    // and Merkle tree (half a gigabyte at RV64 `2^16`).
    let opening = match prepared {
        Some(prepared) => pcs.open_batch_prepared(prepared, &values_points),
        None => pcs.open_batch(&columns, &values_points),
    }
    .map_err(|error| ProofError::Pcs(error.to_string()))?;
    profile.mark("opening", started.elapsed());
    let started = std::time::Instant::now();
    let mut initial = witness.initial.clone();
    initial.resize(cells.next_power_of_two().max(2), F2_128::from(0u64));
    let mut final_value = witness.final_value.clone();
    final_value.resize(cells.next_power_of_two().max(2), F2_128::from(0u64));
    let endpoint_columns = vec![initial, final_value];
    // The endpoint tables have one row per cell (`2^address_bits` rows at most),
    // so they use the small-table profile: the cycle-table parameters would
    // spend the full 2^pow grinding on a trivially small opening.
    let endpoints_pcs = crate::linear_twist::linear_pcs(cells);
    let _endpoint_commit = endpoints_pcs
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
    let endpoints_opening = endpoints_pcs
        .open_batch(&endpoint_columns, &endpoint_points)
        .map_err(|error| ProofError::Pcs(error.to_string()))?;
    profile.mark("endpoints", started.elapsed());
    let started = std::time::Instant::now();
    let _ = (read_valid_index, write_bits_start, write_valid_index, endpoint_start);
    // Final state rounds.
    let eq_cell = eq_vector(&rk, cells);
    // Both cell-indexed factors repeat over the index space: the equality
    // vector is constant along the cycles, the increment column along the
    // cells. Storing the blocks (`cells` and `cycles` entries) instead of two
    // `cells * cycles` arrays leaves the round polynomials unchanged.
    if std::env::var_os("MAGNETAR_PROFILE_LOCAL").is_some() {
        eprintln!("local final factors ready: {}", crate::memory_gib());
    }
    let final_rounds = {
        let mut final_factors = vec![
            SumcheckFactor::repeat_high(eq_cell, cycle_bits),
            SumcheckFactor::Dense(write_flat),
            SumcheckFactor::repeat_low(inc, cycle_bits),
        ];
        let (rounds, _) = fixed_sumcheck_mixed(
            &mut final_factors,
            cells * cycles,
            &rw_challenges,
            |folded| folded[0] * folded[1] * folded[2],
        );
        rounds
    };
    profile.mark("final rounds", started.elapsed());
    profile.total(total_started);
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
    let endpoints_pcs = crate::linear_twist::linear_pcs(cells);
    if !endpoints_pcs
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

    /// The compact table builders must produce exactly the tables the former
    /// dense materialisation produced, value for value: the proof transcript
    /// depends on every one of them.
    #[test]
    fn compact_tables_match_the_dense_reference() {
        let witness = crate::linear_twist::tests::register_witness();
        let shape = witness_shape(&witness);
        let (cycles, cells) = (shape.cycles, shape.cells());
        for write in [false, true] {
            let dense = crate::local_twist::dense_onehot(&witness, write);
            let dense_flat = crate::local_twist::flat(&dense, cycles);
            assert_eq!(flat_onehot(&witness, write, cycles), dense_flat);
            let (bits, valid, _) = crate::virtual_onehot::bit_columns_pub(&witness, write);
            for seed in 0..8u64 {
                let rj = (0..shape.cycle_bits())
                    .map(|bit| F2_128::from((seed >> bit) & 1))
                    .collect::<Vec<_>>();
                let rk = (0..shape.address_bits)
                    .map(|bit| F2_128::from((seed.wrapping_mul(7) >> bit) & 1))
                    .collect::<Vec<_>>();
                let point = rj.iter().chain(rk.iter()).copied().collect::<Vec<_>>();
                assert_eq!(
                    eval_mle(&dense_flat, &point),
                    onehot_eval(&bits, &valid, &rk, &rj, cycles)
                );
            }
        }
        let (val_reference, _, inc_reference) = crate::linear_twist::build_val_tables(&witness);
        let (val, inc) = build_val_flat(&witness);
        assert_eq!(val, val_reference);
        assert_eq!(inc, inc_reference);
        let inc_flat = repeated_blocks(&inc, cells, cycles);
        for cycle in 0..cycles {
            for cell in 0..cells {
                assert_eq!(inc_flat[cell * cycles + cycle], inc[cycle]);
            }
        }
    }

    #[test]
    fn local_shared_round_trips() {
        let witness = crate::linear_twist::tests::register_witness();
        let proof = prove_local_shared(&witness).unwrap();
        assert!(verify_local_shared(&proof).unwrap());
        eprintln!("local_shared bytes={}", bincode::serialize(&proof).unwrap().len());
    }
}
