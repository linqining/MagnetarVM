# Why the paper's verifier stays ~10 ms at 2^22, and where ours grows

Snapshot 2026-11-17, branch `trace-free-arch`. Method: `MAGNETAR_PROFILE_VERIFY=1`
stage timings of the trace-free verifier (`MAGNETAR_TRACE_FREE=1`,
`verify_native_unified(statement, proof, width)`), with M4a Access + dedup on,
`paper_unified_bench`, `TRACE_SHOUT=1`, products-gated, streamed opening. Host
was loaded (load average 5-25), so wall numbers are indicative; the *scaling*
between sizes is the point.

## 1. Measured stage costs

| stage | 2^16 | 2^17 | 2^18 | scaling |
| --- | ---: | ---: | ---: | --- |
| v4 root | 0.69 ms | 1.18 ms | 2.39 ms | grows (small absolute) |
| v4 access (total) | 7.59 | 6.37 | 7.96 | flat |
| - access register twist | 6.91 | 5.97 | 7.54 | flat |
| - access final relation | 0.46 | 0.26 | 0.29 | flat |
| v4 committed shout (total) | 6.79 | 4.94 | 6.03 | flat |
| - shout batch opening | 4.93 | 2.79 | 3.09 | flat |
| - **shout rom eval** | 0.56 | 1.29 | **2.11** | **~linear in ROM/rows** |
| v4 claim table (total) | 7.77 | 5.49 | 6.63 | flat |
| - claim table opening | 5.05 | 3.58 | 4.04 | flat |
| v4 core (total) | ~5 | 4.71 | 5.45 | flat |
| - core mosaic opening | ~4 | 3.87 | 4.06 | flat |
| selected segments row/shape | 2.5 | 1.7 | 2.0 | flat |
| selected segment matrices | ~3 | 3.55 | 3.13-3.58 | flat |
| **selected lockstep bits** | ~8-9 | **12.70** | **19.0-19.4** | **grows ~1.5x per doubling** |
| **v4 selected binding (total)** | ~9-10 | **15.6** | **23.3-24.0** | grows |
| **verify wall (total)** | **11.4 ms** | **16.3-17.0 ms** | **26.6-28.7 ms** | **~1.5x per doubling** |

The 2^19 row confirms the trend: `selected lockstep bits` 31.8 ms, `v4 selected
binding` 38.1 ms, total verify 43.1-44.2 ms (proof 1,668,163 B, peak 5.93 GiB).
Extrapolating ~1.5x per doubling puts 2^22 at roughly 140-150 ms, i.e. the
selected-lockstep stage is the whole gap to the paper's ~10 ms.

Everything that is a PCS opening or a sum-check is flat (query/path dominated,
logarithmic in size): access twist, claim table opening, shout batch opening,
core mosaic opening. The growth comes from two stages:

1. **`selected lockstep bits`** — inside
   `simd_dual::verify_prepared_dynamic_segments` it calls
   `gated_shared_matrices_lazy(&prepared.row, prepared.matrix_cycles, ...)` and
   then `lockstep_bits_evaluations(&s1[..], &s2[..], &challenges)`. Both
   materialise/evaluate matrices with `O(cycles)` rows, so the stage grows with
   the trace. At 2^18 it is 19 ms of the 27 ms total.
2. **`shout rom eval`** — the verifier rebuilds the Shout ROM tables from the
   public `statement.rom` and evaluates them at the challenge point; the ROM has
   one word per instruction in this benchmark, so this is `O(program)` and grows
   with the trace (0.56 -> 1.29 -> 2.11 ms).

At 2^16 the gap to the paper's 10.8 ms is small (11.4 ms, ~6 %, mostly the
parallel-wave overhead and the v4 root stage). The real gap is the scaling: with
~1.5x per doubling, 2^22 would land around 100 ms, not ~10 ms.

## 2. Why the paper can stay at ~10 ms at 2^22

A verifier that is `O(polylog)` in the trace length cannot materialise anything
with `O(rows)` entries. The paper's architecture therefore commits every
row-indexed object and checks it by opening/sum-check at the challenge point:

* the claim table is committed and opened (we already do this: `claim table
  opening` is flat);
* the committed Shout tables are committed and opened (we do this too: `shout
  batch opening` is flat) — but the **ROM evaluation** is still rebuilt from the
  public ROM instead of being part of the committed tables;
* the selected CPU claim columns (the six lockstep matrices) are committed and
  their evaluations are checked by opening/sum-check — we instead rebuild the
  gated shared matrices from the mask and evaluate six MLEs over `O(cycles)`
  rows.

With those two stages committed, the verifier's only size-dependent work is the
PCS query verification (log) and the sum-check rounds (log), so the wall time is
essentially the 2^16 number plus a few log factors — which is exactly the
"~10 ms at 2^22" claim.

## 3. What to implement to close the gap

1. **Commit the selected CPU claim columns.** Add the six lockstep matrices
   (or their MLEs) to the selected-CPU commitment and verify
   `lockstep_bits_evaluations` by opening them at the challenge point instead of
   `gated_shared_matrices_lazy` + MLE evaluation. This removes the dominant
   `selected lockstep bits` growth.
2. **Commit the Shout ROM tables.** Fold the ROM tables into the committed
   Shout tables commitment (they are public, so the prover can commit them and
   the verifier checks the root against `statement.rom`), and evaluate them by
   opening instead of rebuilding. This removes `shout rom eval`.
3. Keep the parallel wave (access / shout / claim / selected / core run
   concurrently); after (1) and (2) the wall should be
   `max(PCS openings) + O(1) roots + join overhead`, i.e. ~10-12 ms independent
   of the trace length.
4. Re-measure the staircase with `MAGNETAR_PROFILE_VERIFY=1`; the acceptance
   criterion is that every stage stays flat from 2^16 to 2^22 (within noise).

Effort estimate: (1) is the larger change (new committed columns + verifier
opening path, ~2-4 days); (2) is smaller (~1 day) because the committed Shout
machinery already exists. Both are proof-format changes (version bump) and
should be gated behind the trace-free switch until measured.
