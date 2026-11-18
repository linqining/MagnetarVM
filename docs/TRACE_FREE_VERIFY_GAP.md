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
   Finer attribution (`MAGNETAR_PROFILE_EVAL=1`): `lockstep verify eval_mles`
   is **14.8 ms** of that 18.2 ms stage, and the six matrices all take the
   `eval_mle_fast_inner` / `eval_sum_factorized` path (no fallback prints), so
   the residual is the `O(cycles)` instance dot plus the equality-vector
   construction inside `eval_mles_parallel`. Splitting that instance dot across
   threads was tried and made it *worse* (14.8 -> 16.4-17.4 ms) because the six
   matrices are already evaluated in parallel and the nested thread spawn
   contends; the fix has to be algorithmic (below), not more threads.
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

## 2.1 First fix landed: closed-form instance dot (O(cycles) -> O(log))

The `O(cycles)` term inside `eval_sum_factorized` is a dot product of two
equality tensors over the instance bits. Summing `eq(r,i)·eq(c,i)` over the
hypercube factorises per bit (`Π_j (1 + r_j + c_j)`), and the shifted variant
(`eq(c,i+1)`) has an O(k) recursion, so the instance dot is now computed in
O(log) instead of O(cycles) (`eq_dot_full` / `eq_dot_shifted_full` in
`magnetar-proof/src/simd.rs`, with a unit test against the naive loops and an
env-gated `MAGNETAR_EVAL_CHECK` cross-check on real matrices).

Measured effect (trace-free + M4a + dedup):

| stage | 2^18 before | 2^18 after | 2^19 before | 2^19 after |
| --- | ---: | ---: | ---: | ---: |
| `lockstep verify eval_mles` | 14.8 ms | **5.85 ms** | 31.8 ms | **11.0 ms** |
| `selected lockstep bits` | 19.0 ms | **9.3 ms** | 31.8 ms | **14.4 ms** |
| `v4 selected binding` | 23.3-24.0 ms | **13.1-13.7 ms** | 38.1 ms | **20.6-21.3 ms** |
| total verify wall | 26.6-28.7 ms | ~17-18 ms (stage sum; the 38.5 ms sample was taken while the gate ran) | 43.1-44.2 ms | **26.0 ms (-40 %)** |

The remaining growth is the equality-vector construction and the base-matrix
evaluation inside `eval_mles_parallel` (still O(cycles) allocations), plus the
`shout rom eval` O(program) term. The full O(log) fix is the committed
selected-claim-columns change below.

### 2.2 Second fix: lazy shared equality vectors + O(1) v4 root

* `BlockEvalShared` no longer materialises the O(instances) row/column equality
  vectors: it keeps the instance points and builds the vectors only on the
  fallback path (`OnceLock`), and `instance_sum` is computed in O(log) with the
  same factorisation (`Π_j (1 + r_j + c_j)`).
* `v4_verify` no longer re-hashes the O(program) ROM: the statement is public
  input, so `statement.program_hash` is the ROM binding passed to the committed
  Shout check (the `v4 root` stage drops from 4.6 ms to ~0.01 ms at 2^19).

Measured totals (trace-free + M4a + dedup, `MAGNETAR_VERIFY_CPU=5`):

| size | before this round | after closed-form | after lazy shared + O(1) root |
| --- | ---: | ---: | ---: |
| 2^16 | 11.4 ms | 11.3 ms | ~11 ms |
| 2^18 | 26.6-28.7 ms | 14.7 ms | **12.2 ms** |
| 2^19 | 43.1-44.2 ms | 23.2 ms | **18.2 ms** |

Remaining growth at 2^19: `shout rom eval` 4.1 ms (O(program)), `selected
lockstep bits` 11.5 ms, `selected lockstep challenges` 3.5 ms, `selected
segments row` 2.7 ms. The ROM commitment and the remaining selected-lockstep
terms are the next targets; at ~1.5x per doubling the current 2^22 projection is
~60 ms, so those must be removed to reach the paper's ~10 ms.

### 2.3 Third fix: the ROM word column is committed

`prove_committed_logup_shout` now commits the public ROM word column as a fourth
column of the committed Shout tables batch (padded to the common table arity),
and the verifier authenticates the ROM claim with the same batched opening
instead of rebuilding the O(rom) column. The statement constructor
(`committed_statement_data`) commits the same column, so the statement root
binds it; the verifier's `rom` argument is only shape-checked (the statement is
public input and its `program_hash` is the ROM binding). The `shout rom eval`
stage disappears and `v4 committed shout` drops from 8.1 ms to ~4.0-4.5 ms at
2^19.

Totals after this fix: 2^18 12.6 ms, 2^19 18.8 ms — the total is now bounded by
`v4 selected binding` (18.6 ms at 2^19), so the next targets are its remaining
O(rows) terms: `selected segments row` (the `WitnessLayout` is built from
`cycles/64` segments, O(cycles) allocations) and `selected lockstep challenges`
(3.5 ms and growing).

### 2.4 Layout cache, and the remaining structural blocker

`segmented_dynamic_row` now builds its uniform `WitnessLayout` through a
process-wide cache keyed by `(mask, width, cycles, block_cols)`, so repeated
verifications (benchmarks, batched verification) skip the O(cycles) segment
construction; the first verification still pays it.

The remaining O(cycles) work in `v4 selected binding` is structural, not an
implementation detail:

* the selected-CPU proof carries one segment claim per `64` cycles
  (`proof.segments`, `cycles/64` entries), so both the proof size and
  `reconstruct_segment_claim` (inside `selected lockstep challenges`) are
  O(cycles/64);
* `selected lockstep bits` then evaluates the six lockstep matrices over the
  same segment structure.

At 2^22 that is 65,536 segments: ~1 MB of claims plus O(cycles) verification
work, which is why the current projection is tens of milliseconds rather than
the paper's ~10 ms. Closing it needs a selected-CPU proof-format change, in
increasing order of effort:

1. **larger segment group** (e.g. 2^10 instead of 64): 16x fewer segments, so
   the layout, the claim vector and the challenge reconstruction shrink 16x;
   the lockstep relation is unchanged (segments are power-of-two subcubes), but
   the proof format changes and the prover's segment construction must follow;
2. **commit the segment claims** and check them with an opening/sumcheck at the
   challenge point instead of carrying them in the proof (O(log) verify, O(1)
   proof growth);
3. **one segment per opcode class** (the likely paper design): the per-cycle
   structure moves entirely into the committed lockstep columns.

(1) is the cheapest experiment and should be tried first behind the trace-free
switch; (2) is the full fix.

### 2.5 Segment group 64 -> 4096 (landed)

`MAGNETAR_SEGMENT_GROUP` now controls the lockstep segment group (default
4096, power of two, clamped to the cycle count), and the cached layout is keyed
by it. The proof carries one segment claim per group, so this cuts the segment
count 64x at the default:

| size | group 64 | group 4096 |
| --- | ---: | ---: |
| 2^16 proof / verify | 1,255,173 B / ~11 ms | **1,239,045 B / 9.0 ms** |
| 2^18 proof / verify | 1,502,097 B / 23.6 ms | **1,437,585 B / 11.3 ms** |
| 2^19 proof / verify | 1,668,163 B / 18.8 ms | **1,538,691 B / 13.5 ms** |

(2^18/2^19 numbers are from the same loaded window; the 2^16 row is the cleanest.)
The 2^16 verify is now inside the paper's 8-12 ms target with margin, and the
2^22 projection improves from ~60 ms to ~20-25 ms. The remaining growth is the
lockstep evaluation/PCS and the challenge reconstruction, which the committed
segment claims (fix 2) remove.

### 2.6 The last O(cycles) term: the statement-row equality vector

`eval_sum_factorized`'s statement-row block built the full O(instances)
`col_instance_eq` vector just to read two entries (`instance = 0` and
`cycles-1`). It now evaluates `eq(point, index)` directly in O(log)
(`eq_at`), which removes the last O(cycles) term from the six lockstep matrix
evaluations:

| stage | 2^18 before | 2^18 after | 2^19 before | 2^19 after |
| --- | ---: | ---: | ---: | ---: |
| `lockstep verify eval_mles` | 4.36 ms | **0.92-0.97 ms** | 8.8-9.2 ms | **0.95-0.96 ms** |
| `selected lockstep bits` | 7.6 ms | 7.2 ms | 12.7 ms | **7.5 ms** |

`eval_mles` is now flat (O(log)) and `selected lockstep bits` is dominated by
the PCS opening check (~6.8-7.2 ms, logarithmic). Totals: 2^16 9.0 ms, 2^18
11.0-11.5 ms, 2^19 12.3-13.0 ms; the parallel wave is now bounded by the
access/claim-table/core openings (~7-8 ms each), so the 2^22 projection is
~14-16 ms — inside the "10-something ms" target.

### 2.7 2^20 measured (trace-free, statement-only)

The 2^20 row now fits the host (17.7 GiB free+inactive window; the trace-free
path needs ~10.7 GiB RSS / 12.3 GiB footprint, so the watchdog was raised to
12 GiB):

| size | proof | verify wall | verify CPU/iter | peak footprint |
| --- | ---: | ---: | ---: | ---: |
| 2^16 | 1,239,045 B | 9.0 ms | 33.3 ms | - |
| 2^18 | 1,437,585 B | 11.0-11.5 ms | 35.0 ms | - |
| 2^19 | 1,538,691 B | 12.3-13.0 ms | 37.5 ms | - |
| **2^20** | **1,638,259 B** | **14.3 ms** | 40.7 ms | **12.28 GiB** |

The growth is now ~1.1-1.2x per doubling (all remaining stages are PCS openings,
logarithmic), so the 2^22 projection is **~15-17 ms** — the "10-something ms"
target. 2^21/2^22 cannot be measured on this 36 GiB host (the 2^20 run already
needs a 17.7 GiB window and 12.3 GiB footprint; 2^21 projects to ~24 GiB
footprint).

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


## 4. Bit-packed tables (prover-side experiment, in progress)

The M4a packing helpers (`m4a_tables.rs`: `pack_bit_column`, `packed_bit_table`,
`split_and_pack`, `pack_twist_tables`, `pack_word_pairs`) are representation-only
and were not wired into the prover. This round adds an env-gated prover-side
mode (`MAGNETAR_PACK_TABLES=1`) that packs the trace table (two 64-bit fields per
cell) and the twist address tables (128 bits per cell) in the real mosaic
construction, plus `BENCH_SKIP_VERIFY=1` so the prover's peak footprint can be
measured without a verifier that understands the packed claims.

Measured projection from the existing real-table probe
(`m4a_real_table_set_projection`, `PACKED=1`): at 2^22 the committed table set
drops from **209,715,358 to 63,537,310 cells (-70 %)**, i.e. ~3.35 GiB -> ~1.02
GiB of committed table memory (~2.3 GiB saved; ~0.6 GiB at 2^20).

The prover currently rejects the packed mode with
`evaluation vector length 1 is not a nonzero power of two`: the claim
computation still uses the unpacked tables, so the packed tables must be paired
with the verifier-side ring-switch reductions (bit claims -> packed claims, and
the M4b word-pair reduction for the trace). That wiring is the remaining work;
the measured 70 % cell reduction is the payoff it unlocks.


## 5. Out-of-core message spill (first step, landed)

`MAGNETAR_OOT_PCS=1` spills the stacked message to a temp file and maps it
read-only before the streamed opening (`streamed_open` in `p3_pcs.rs`), so the
message pages are file-backed instead of anonymous. The bytes are identical, so
the proof is byte-identical and verification still passes.

Measured at 2^18 (trace-free + M4a + dedup, streamed opening, load ~6-13):
peak footprint **3.01 -> 2.83 GiB** (-6 %); the message is only ~0.2 GiB at
this size, so the win is small here. At 2^20/2^22 the message is ~0.84/3.35 GiB
and the spill matters more, but the dominant transients are the codeword and
the fold codewords (the ~6x pipeline coefficient), which still live in memory:
the next step is to spill those too (the `m4_oot_probe` demo already shows the
disk-backed encode/fold/query path and its 6.1x -> 3.2x coefficient).


## 6. Out-of-core codeword (full step, landed)

`MAGNETAR_OOT_PCS=2` encodes the base codeword once into a temp file and streams
it back for both the fold and the query pass (`CodewordFile` in the vendored
binary-pcs, wired through `fold_rounds_streaming` / `open_queries_streaming`),
so the codeword is never resident twice and the two re-encodes disappear. The
proof is byte-identical and verification still passes.

Measured at 2^20 (trace-free + M4a + dedup, streamed opening, watchdog 13 GiB):

| | peak footprint | peak RSS | verify |
| --- | ---: | ---: | ---: |
| in-memory codeword | 12.28 GiB | 10.73 GiB | 14.3 ms |
| **out-of-core codeword** | **9.93 GiB (-19 %)** | **5.55 GiB (-48 %)** | 14.8-16.7 ms |

At 2^18 the peak is dominated by the context/allocator, so the codeword spill
shows no measurable change there; the win grows with the codeword size (2^22
projects to several GiB). The remaining transients are the folded round
codewords and the context tables.


## 7. Context-table bit-packing via ring-switch dedup: measured, not a win

The next step was to pack the context tables (trace/twist/Shout) by extending the
M4a statement-level dedup to the RAM address table: drop it from the mosaic,
commit its packed bits in the RAM Access proof, ring-switch its claims, and bind
the RAM bits commitment into the statement root (the register dedup pattern).

Implemented and verified at 2^16 (proof 1,239,045 B, verify passes), but at 2^20
it is a regression:

| 2^20 (OOT codeword on) | peak footprint | peak RSS | verify |
| --- | ---: | ---: | ---: |
| register dedup only (current) | **9.93 GiB** | **5.55 GiB** | 14.8-16.7 ms |
| + RAM address dedup | 11.38 GiB | 9.28 GiB | 41.1 ms |

The second Access proof's packed-bit commitment and ring-switch transients cost
more than the ~192 MiB the dropped RAM address table saves, and the extra
ring-switch verification doubles the wall time. Reverted.

Conclusion: per-table ring-switch dedup does not pay off for the context tables.
The remaining structural option is a packed-mosaic PCS (ring-switch for every
bit-valued table in one commitment), which is a larger redesign with uncertain
payoff; the cheaper remaining wins are releasing the trace/witness after table
construction and allocator pressure relief.


## 8. Packed-mosaic measurement (2^18, real table set)

`m4a_pcs_peak` (`LOG=18`, `PACKED=0/1`) commits and streamed-opens the real
table set with the packed plan:

| 2^18 | tables | cells | stacked vars | message | peak RSS | footprint |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| unpacked | 12 | 9,175,198 | 24 | 256 MiB | 2,099 MiB | 2,091 MiB |
| **packed** | 13 | **3,184,798 (-65 %)** | 22 | **64 MiB (-75 %)** | **851 MiB (-59 %)** | **798 MiB (-62 %)** |

So the packed mosaic is a real ~60 % memory win on the PCS side. The remaining
work is the verifier wiring: every bit claim on a packed table must be
ring-switched to a claim on the packed table before the mosaic opening (the
`BatchedRingSwitch` machinery exists for the Access proof; the mosaic needs the
same reduction with the mosaic opening substituted for its own PCS opening).


## 9. Packed plan measured in the real prover (2^18)

`MAGNETAR_PACKED_MOSAIC_MEASURE=1` builds the packed plan from the real mosaic
tables and commits it (measurement only; the proof continues on the unpacked
path). At 2^18 with M4a dedup:

- tables 11, unpacked cells **6,029,470 -> packed cells 4,208,690 (-30 %)** with
  bit-column packing only;
- with the trace word-pair packing (`plan_with_trace`, two 64-bit fields per
  cell): **3,160,114 cells (-47.6 %)** — but that count kept mixed tables as one
  table with unequal column lengths, which the mosaic rejects;
- after splitting mixed tables into a packed bit table and a scalar table (the
  valid layout): **4,077,726 cells (-32.4 %)**.

The verifier claim wiring is still the remaining step; the split also means the
claim wiring must map old table indices to the new packed/scalar pair.


## 10. Packed commit switch: the exact wiring point

`MAGNETAR_PACKED_MOSAIC=1` now commits the packed plan instead of the unpacked
tables. Two findings:

- tiny bit tables (packed length < 2 cells) must stay unpacked, because the PCS
  needs at least two cells per column;
- with that fixed, the prover fails at `vector lengths do not match` in the
  opening: the mosaic claims (points/values) are still generated for the
  unpacked tables. That is exactly the claim-wiring point: every bit claim on a
  packed table must be ring-switched (`open_claims`/`verify_claims`) to a claim
  on the packed table, lifted to the mosaic point, and finished with
  `finish_claims` after the mosaic opening.


## 11. Trace word-pair packing is not evaluation-preserving

The trace table's word-pair packing (two 64-bit fields per 128-bit cell) is
F2-linear on the bit pattern, but the multilinear extension does not commute
with concatenation: the trace claims live on `log2(8C)` variables and the packed
table on `log2(4C)`, and no point of the packed table reproduces the trace
evaluation (the existing test
`trace_word_pair_packing_is_not_evaluation_preserving` pins this). So the trace
claim cannot be reduced to the packed table without a new argument (the M4b
work).

Consequence for the packed-mosaic redesign: the proof path should pack only the
bit-valued tables (twist address tables, ROM bit columns), where the bit-level
ring-switch applies, and keep the trace table unpacked. The word-pair packing
stays a memory-measurement option (`plan_with_trace`), not a proof-path
transformation.


## 12. Packed descriptor in the proof; index remapping is the next blocker

The packed plan's serializable descriptor (`PackedMosaicDescriptor`: table
shapes + per-table mapping) is now carried in the proof
(`UnifiedTraceProof.packed_mosaic`, serde-defaulted) and stored by the prover
when `MAGNETAR_PACKED_MOSAIC=1` commits the packed plan. The proof path uses
`plan` (bit tables only; the trace stays unpacked, §11).

With that, the packed prover fails at `witness has 65536 values, expected
524288`: splitting mixed tables shifts the table indices, so the context's
`trace_index`/`rom_index`/... still point at the old positions. The next step is
the index remapping (old table -> packed/scalar table) plus the claim split for
mixed tables (bit columns to the packed table, scalar columns to the scalar
table).


## 13. ROM claim split wired (prover + verifier)

The packed path now splits the ROM claim: the bit columns are ring-switched
(`open_claims` in the prover, `verify_claims` in the verifier) to the packed
table, and the scalar columns stay on the scalar table. The ring-switch proof
travels in `UnifiedTraceProof.rom_ring_switch`, and the packed descriptor in
`packed_mosaic`.

With that, the packed prover reaches verification and fails at
`core opening rejected`: the twist address-table claims are still generated for
the unpacked address tables, so they need the same ring-switch treatment (the
address tables are all-bit, so they pack into one packed table). That is the
next wiring step.


## 14. Address claims ring-switch wired (prover + verifier)

The packed path now remaps the twist claims: the RAM address table's bit claims
are grouped by point and ring-switched (`open_claims` in the prover,
`verify_claims` in the verifier) to the packed address table, the scalar tables
keep their claims on the scalar tables, and the ring-switch proof travels in
`UnifiedTraceProof.address_ring_switch`.

The packed prover now fails at `point has 5 coordinates, expected 16`: a claim
whose point is over the address dimension (5) is being checked against a table
with 16 variables (the address table). The likely culprit is the initial/final
table claims (point `rk`, length `address_bits`) or the address claim point
length; the claim remapping needs to keep those on their own tables. The normal
path is unaffected (proof 1,239,048 B, verify 10.9 ms).
