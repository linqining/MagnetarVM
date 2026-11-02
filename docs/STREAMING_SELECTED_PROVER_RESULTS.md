# Streaming selected prover: implementation and RV64 baseline

Status: implemented, RV64 `2^16` baseline recorded  
Branch: `virtual-claims-rewrite`  
Base commit: `62d135a` (handoff: [STREAMING_SELECTED_PROVER_HANDOFF.md](STREAMING_SELECTED_PROVER_HANDOFF.md))  
Chinese sibling: [streaming-selected-prover-results-zh.md](streaming-selected-prover-results-zh.md)

This note records what the streaming selected prover changed, the memory model it
targets, and the measured RV64 staircase. Start from the handoff
[HANDOFF.md](HANDOFF.md) ([中文](handoff-zh.md)) for the current state and how to run it. It supersedes the "current state"
sections of the handoff document for everything the selected stage touches.

---

## 1. Summary

| Item | Before | After |
| --- | --- | --- |
| RV64 `2^13` selected prover | killed at 20.8 GB peak RSS | 27.6 s prove, **1.25 GiB** peak |
| RV64 `2^15` selected prover | killed (OOM) | 90.0 s prove, **3.29 GiB** peak |
| RV64 `2^16` selected prover | killed (OOM) | **194.2 s** prove, **4.49 GiB** peak, verifies |
| RV64 `2^16` **full paper benchmark** | killed (OOM) | **70.4 s** prove, **29.6 ms** verify, **2.26 GiB** peak (load 26–140) |
| Proof bytes | eager format | byte-identical (asserted in test) |
| Verifier | 1.42 s (witness rebuild) | proof-only, every layer checked (§9.7); trace Logup-Shout −61 % CPU/iter at `2^16` (§7 round 9) |
| Selected PCS opening (`2^16`) | 41.6–55 s (24 grinding bits) | **5.4 s**; commit 8.7–15.2 → **2.3 s** (rate 1/2, §7) |
| Register-twist Access proof (`2^16`) | 48.2 s, 94 % of it PCS (load 80) | **1.43–1.55 s**, verify 3.7 ms (load 90, §9.10) |
| Witness bits (`2^16`) | 512 MiB (`Vec<bool>`) | **64 MiB** (`PackedBits`, 8 bits/byte, §3) |
| Selected commit vs mosaic commit | peak = sum of both transients (3.24–4.10 GiB) | **commit gate**: selected waits for mosaic, peak 2.26 GiB at `2^16`, 1.13 GiB at `2^14` |

Two rows postdate the table: the register-twist Access proof fell from 48.2 s to
**1.43–1.55 s** (§9.10), which removes ~40 s from every `2^16` prove, but the
full-benchmark row itself has not been re-measured (the host has not gone below
1-minute load 45 since the change; the stage-level measurement is direct).

The selected proof at `2^16` is 275,007 B and verifies together with the claim
binding (one sum-check, one PCS opening) and the mosaic opening; the full paper
proof at `2^16` is 861,407 B (560,943 B compressed) and verifies with the
selected lockstep proof, the claim layer and the mosaic opening all checked.
Wall-clock verify on this session's loaded host is not comparable to the
earlier `33.8 ms` (load 10): the same binary measured 19.7 ms at `2^12` and
60.9–64.4 ms steady / 206–213 ms CPU per iteration at `2^16` (load 20–52); the trace
Logup-Shout stage went from 393–450 ms to **28–31 ms** over rounds 9–11 (§7).
Sections 7 and 9 track the verifier work; §9.4 records a
verification-coverage bug found and fixed on the way (an intermediate 117.8 ms
figure had skipped the selected lockstep check).

---

## 2. What changed

### 2.1 New streaming engine — `crates/magnetar-proof/src/stream.rs`

Every large intermediate of the eager lockstep prover is derived from the bit
witness on demand:

| Eager intermediate | Size at RV64 `2^16` | Streaming replacement |
| --- | --- | --- |
| `z: Vec<F2_128>` | 8.6 GB | witness bits, read in place |
| six matvec vectors (`az0..cz1`) | 6 × 17 GB | `LockstepRows::row_values(row)` |
| six `Mle::new(az.clone())` copies | 6 × 17 GB | final fold values (§2.3) |
| `eq_values` (rows) | 17 GB | closed-form folded equality (§2.2) |
| six row-combination vectors (cols) | 6 × 8.6 GB | `ColumnRows::fill_left` |
| `left_values` (cols) | 8.6 GB | same filler, recomputed per round |
| `z.to_vec()` for the inner sum-check | 8.6 GB | `ColumnRows::fill_right` |

Three pieces do the work:

* **`LockstepRows`** — evaluates the six matrices row by row:
  block-diagonal row `(instance, local)` is the base sparse row dotted with that
  instance's witness bits; rows after `base_rows * instances` are the lazy gated
  extra rows (`LazyExtraRows::entry`, no materialized `Vec`); the rest is zero
  padding. It also rejects a materialized-extra matrix, so the prover now uses
  `LazyExtraRows::Gated` (Milestone 1 of the handoff).
* **`prove_product6_rows`** — the outer sum-check
  `eq·(a0b0 − c0 + α(a1b1 − c1))`. Rounds `0..level` are recomputed block by
  block from the witness; rounds `level..` fold the stored level array in memory.
  The folded equality never materializes: after `k` folds it is
  `C_k · f_k(t) · eq(τ[k+1..], j)` with `C_k = Π_{b<k} ((1−r_b)(1−τ_b) + r_bτ_b)`
  and `f_k(t) = tτ_k + (1−t)(1−τ_k)`, so only a `2^16`-entry low table plus a
  small high table are needed (Milestones 3–5).
* **`ColumnRows` + `prove_product2_columns`** — the inner sum-check. The left
  vector factors as `instance_weight(instance) · combined(local)` (the batched
  base row combination at `rx`) plus sparse gated-extra corrections, so a column
  chunk is filled in one multiply per column plus one pass over that chunk's
  extra rows. The right vector is the witness bit. Same leveling scheme
  (Milestone 6).

Segment claims are computed directly from the bits
(`virtual_spartan::split_segment_claims_bits`), and the `vw` terminal value is the
last folded entry of the inner right vector, so no full `z` is built (Milestone 7).

### 2.2 Folding by weighted sum, not by repeated in-place passes

Folding a `2^k` block `k` times equals one weighted sum with
`w(s) = Π_{b<k} (s_b ? r_b : 1−r_b)`. The weights are computed once per round
(`fold_weights`) and the block is accumulated into an even/odd pair. Because the
matvec values are almost always `0` or `1`, `accumulate_weighted` skips the
128-bit tower multiply in those cases. This alone took the selected prover from
`362 s` to `194 s` at `2^16` (outer sum-check `253.6 s → 74.8 s`).

### 2.3 Terminal claims come for free

The six `v_a*`, `v_b*`, `v_c*` values and `vw` are exactly the vectors' MLEs at
`rx`/`ry`, i.e. the values left after the phase-2 folds. They are read off the
final one-element arrays; no `Mle` copy and no extra scan is needed.

### 2.4 PCS: clamp the security target to the field capacity

`P3BinaryPcs` rejected RV64 `2^16` with

```
security level 100 exceeds the 99 bits the field leaves at this domain size
```

The committed witness packs to `2^22` field elements, and `p3-binary-pcs`
prices fold/sum-check error as `2·2^(n_vars+log_inv_rate)`, which caps the
reachable target at 99 bits there. `backend_with` now retries once with the cap
reported by the error. Commitment bytes and the transcript are unaffected (the
cap only changes the query count, which both sides derive from the same domain);
this is not a wire-format change.

### 2.5 Unified path: do not materialize the columns the proof discards

The dynamic proof replaces the unified CPU/gated claims and its caller drops
`cpu`, `gated`, `e5_opening`, `field_opening` and `opening`. The context still
built all of them, which dominated the whole-pipeline peak (at `2^12`: `5.30 GiB`
in `new_with_group` alone, 173.7 s, and 35-40 s per doubling). Two changes:

* `UnifiedProveContext::new_without_cpu_columns` — used by the dynamic native
  prover. It skips `merged_cpu_system`, the field-valued CPU witness `z`, the CPU
  mosaic column and the gated component/shift/active tables, and commits the
  remaining tables with `commit_mosaic` instead of the E5 path. Everything the
  proof keeps (access, routers, logup, trace claims) is unchanged; the mosaic is
  self-describing (`commitment.tables` travels in the proof), so verification
  stays consistent. Context construction at `2^12`: **173.7 s / 5.30 GiB ->
  15 ms / 0.04 GiB**.
  Net effect on the **unified** proof: it gets smaller (2^12: `372,596 B ->
  372,316 B`) because the dropped columns are no longer committed. The selected
  `LockstepProof` bytes, its commitment and the transcript are unchanged.
* `SharedBlockMatrix::with_extra_rows` counted the power-of-two padding instead
  of materializing it. `base_rows * instances` is already a large power of two at
  RV64 scale, so the old `resize` transiently allocated `next_pow2(...) - base`
  empty rows: 6.1 GiB at `2^14`, and ~100 GiB at `2^16`. The verifier's eager
  matrix build at `2^14` drops from **6.30 GiB to 0.35 GiB** (and its access walk
  from 1.8 s to 0.31 s). Row count and every evaluation are unchanged.

### 2.6 Compact claim proof round-trip (pre-existing bug found by the suite)

`magnetar-testkit --test compiled_guest` failed at the base commit `62d135a` as
well: the compact `ClaimProof` blob does not encode `rd`/`rs1`/`rs2`, it
re-derives them from the instruction word, but `TraceClaim::from_row` takes them
from the executor's row (`row.rd.unwrap_or(0)`). For the syscall row the claim
carries `rd = 10` while `decode(0x73)` yields `rd = 0`, so a
serialize/deserialize round trip changed the leaf and therefore the root, and
the decoded proof was rejected with "claim proof opening mismatch".

Fix: a `ClaimProofWire::CompactIndexed` variant that carries the rows whose
claim indices differ from the word-derived ones (empty in the common case, so
normal proofs keep the plain `Compact` form). The blob, the claim root, the
statement and the verifier are untouched; decoding applies the overrides before
building the leaves.

### 2.7 Wiring

`prove_lockstep_bits_streaming{,_with_level}` in `spartan.rs` mirrors the eager
transcript exactly; `prove_lockstep_bits_streaming_with_level` exists so tests can
pin every phase transition. `prove_dynamic_segmented_trace` builds the lazy-gated
matrices and calls the streaming prover. Nothing in the verifier changed.

---

## 3. Memory model

Measured at RV64 `2^16` (`MAGNETAR_PROFILE_UNIFIED` + `MAGNETAR_PROFILE_SELECTED`
print RSS at each stage; `rows = 2·cols`, `cols = cycles·8192`):

| Stage | RSS | What it is |
| --- | --- | --- |
| unified context | 0.45 GiB | trace, twist/shout witnesses, table columns |
| after mosaic commit | **2.15 GiB** | P3 codeword (rate 1/4 over the stacked mosaic) + Merkle tree |
| selected witness commit | **1.98 GiB** (rate 1/2) | packed witness (64 MiB) + selected PCS codeword and Merkle tree |
| **prove peak** | **2.01–2.61 GiB** (rate 1/2, load 15–43) | mosaic opening + the selected level stores |

| Buffer | RV64 `2^16` | Rule |
| --- | --- | --- |
| witness bits (`PackedBits`) | 64 MiB | `cycles · base_cols` bits, 8 per byte |
| outer level array | 400 MiB | `2^22` entries × 6 values × 16 B |
| inner level arrays (left, right) | 128 MiB | level chosen so each store is `2^22` entries |
| selected PCS packed table + codeword + Merkle | ~0.6 GiB transient | rate 1/2, 20 grinding bits; freed after the commit |
| mosaic codeword + Merkle | ~1.7 GiB | rate 1/4 over ~`2^22.1` table cells |
| per-worker chunk buffers | < 1 MiB | `2^level` rows × 6 slots |
| matrices (lazy gated metadata) | < 1 MiB | no materialized extra rows |

The automatic level is `bits − 21` (`MAGNETAR_STREAM_BUDGET_LOG`, default 22
entries ⇒ `2^22`-entry stores); `MAGNETAR_STREAM_EAGER=1` forces level 0, which
reproduces the eager scan order and is used only for the equivalence test.
Recompute passes = `level`, so memory and time trade linearly.

**Setup buffers (no measurable win).** `dynamic_segment_setup` used to allocate a witness scratch
and a block buffer per cycle (`Vec<bool>` of `num_vars` each, 65 536 times at
`2^16`); it now reuses one of each and clears only what the previous row set.
The stage RSS print (`MAGNETAR_PROFILE_SELECTED`) measured 0.43 → 1.16 GiB
across the fill loop, but RSS is process-wide and that window overlaps the
unified context build, so the attribution is approximate; the change removes
two allocations per row and the block is refilled with one `fill(false)`; the
`2^16` peak measured 2.01 GiB before and 2.61 GiB after at the same rate, i.e.
run noise, so it is kept as allocation hygiene rather than as a peak win.

**Why the level stays at budget 22.** The level store is `2^(level+1)` row slots
of six field elements and `level = row_bits − (budget−1)`, so its size depends
only on the budget: 402 MiB for the outer store and 128 MiB for the inner ones,
independent of `cycles`. Lowering the budget shrinks the stores per
point and adds recompute passes over the witness. The `2^14` sweep at load
35–40 (budgets 21/22/23) measured prove 60.7 / 77.5 / 101.5 s wall and **230.8 /
227.2 / 222.9 s CPU**, peak 1.18 / 1.35 / 1.27 GiB. CPU moves 3.4 % across
budgets whose stores differ 4×, so the recompute passes are not the binding
cost (the folded data is cache-resident and the field work dominates); the wall
differences are load noise. The stores are a fixed 0.4–0.5 GiB at every scale —
~7 % of the paper's 6.4 GiB envelope rather than a scaling term — so the budget
stays at 22 and memory work has to go at the codeword and tree, not the level
buffers.

The witness is now a `PackedBits` (`crates/magnetar-proof/src/bits.rs`): one bit
per column per cycle, 8 per byte, read in place by the streaming row/column
sources. At RV64 `2^16` that is 512 MiB → 64 MiB, and it removes the boolean
copy the eager paths used to build. The `BitPcs` trait, the ring-switch packing
and the eager prover entry points all take the packed form; ring-switch
packing is now just the little-endian word view (128 bits per field element),
so the SIMD transpose kernels are gone.

**Commit gate.** The selected witness commit allocates its own codeword and
Merkle tree (1.5 GiB at `2^16`) while the unified worker commits the mosaic
(2.15 GiB). When the two happen to overlap the peak is the *sum*: measured
3.24–4.10 GiB across interleavings, with the low end only by luck. The selected
worker now waits for the mosaic commit to finish (a one-shot channel) and
commits afterwards, overlapping the low-memory Access/Opening stages instead.
At `2^14` the peak went from 1.75 GiB (packed witness, no gate) to **1.13 GiB**,
and `2^16` now measures 2.26 GiB.

The mosaic still dominates the *steady* memory: its cost is
`cells · 2^log_inv_rate · (16 B + Merkle overhead)`. The cells are boolean
columns stored one 16-byte field element per row. Reaching `2^22` at 6.4 GiB
needs bit-packed tables (the paper's tables are `2^22 · 256` bits ≈ 128 MB
packed, against `2^30` cells here) *and* a bit-packed codeword/Merkle for the
selected PCS (its 16 B-per-field codeword is 32 GiB at `2^22`). That is the
remaining structural item.


---

## 4. RV64 staircase (selected stage)

`WIDTH=64`, `cargo run --release -p magnetar-testkit --example selected_stream_probe`,
12-core Apple Silicon, 36 GiB. `peak RSS` is sampled every 20 ms by the probe.
`rows = 2·bits`, `cols = bits`.

| ADDS | cycles | bits | prove | verify | peak RSS | selected proof |
| --- | --- | --- | --- | --- | --- | --- |
| 1023 | `2^10` | `2^23` | 6.83 s | 0.20 s | 0.83 GiB | 150,144 B |
| 4095 | `2^12` | `2^25` | 13.07 s | 0.85 s | 1.01 GiB | 186,080 B |
| 8191 | `2^13` | `2^26` | 27.61 s | 1.70 s | 1.25 GiB | 203,904 B |
| 16383 | `2^14` | `2^27` | 46.62 s | 3.55 s | 1.62 GiB | 224,808 B |
| 32767 | `2^15` | `2^28` | 89.96 s | 7.66 s | 3.29 GiB | 250,784 B |
| 65535 | `2^16` | `2^29` | 194.18 s | 4.44 s | 4.49 GiB | 279,248 B |

`2^16` breakdown (`MAGNETAR_PROFILE_SELECTED=1`):

```
selected commit          13.1 s
selected product6        74.8 s   (9 recompute passes + 21 fold rounds)
selected row-combinations 4 ms
selected product2        44.5 s   (8 recompute passes + 21 fold rounds)
selected segments         1.3 s
selected open            31.3 s
```

Both sum-checks scale linearly in `rows`/`cols`; the PCS commit/open dominate at
small sizes (`2^10`: 5.2 s of 6.8 s), the outer sum-check at large sizes.
`open` is the largest non-sum-check term at `2^16` because `RingSwitchPackedBitPcs`
packs and commits the packed table again; that path is unchanged from the handoff
(Milestone 8 was explicitly out of scope and is not the bottleneck).

The verifier numbers are wall-clock for "PCS + public matrix evaluation +
segment binding" given the trace (`verify_dynamic_segments_public` +
`verify_dynamic_segments_against_trace`); the `8 ms` verifier is a later stage and
was not attempted.

---

## 5. Correctness evidence

* `crates/magnetar-runtime/src/simd_dual.rs::tests::streaming_lockstep_proof_matches_the_eager_proof_bytes`
  builds the eager (`gated_shared_matrices` + `prove_lockstep_bits_with_point`)
  and streaming proofs for `width = 8` and `width = 64`, at levels
  `{0, 1, 2, 3, 5, 7, row_bits, usize::MAX/2}`, and asserts the bincode encodings
  are equal (commitment, terminal claims, round polynomials, segment claims,
  opening) and that the existing verifier accepts each one. This covers
  handoff acceptance items 4 and 5 and the "transcript/order unchanged" risk.
* `cargo test --release --workspace --no-fail-fast` — **39 test binaries, 642
  tests, 0 failures**. Two of them failed at the base commit `62d135a`:
  `compiled_guest` (fixed in §2.6) and `logup_shout_mixed`'s
  `native_dynamic_handles_more_compressed_programs`, whose assertion still
  expected `proof.logup_shout` although `prove_unified_trace_auto` takes the
  native dynamic path, which carries `proof.trace_logup_shout`; the assertion now
  accepts either form (the test body is unchanged otherwise).
* `cargo test --release -p magnetar-runtime --lib` — 340 passed.
* `cargo test --release -p magnetar-proof` — 41 passed.
* `cargo test --release -p magnetar-testkit --test paper_mode` — 1 passed.
* The lazy gated extras the prover now consumes are the same pattern the public
  verifier already uses (`gated_shared_matrices_lazy`), so prover and verifier
  agree on row semantics by construction.

---

## 6. Full paper benchmark (`paper_unified_bench`)

The whole pipeline runs at `2^16` and peaks at 2.26 GiB on the current build.
`peak RSS` is the whole-process maximum, so it includes the selected worker that
runs concurrently with the unified stages.

Current numbers. This session's host was shared and heavily loaded (1-minute
load 20–125 on 12 cores, against 8–20 for the earlier rows), so wall times are
not comparable across rows; `peak RSS` and `verify CPU/iter` are the stable
columns, and even CPU time inflates under memory-bandwidth saturation.

| ADDS | cycles | prove | verify | peak RSS | proof |
| --- | --- | --- | --- | --- | --- |
| 4095 | `2^12` | 33 s (load 30–60) | 30.5 ms (load 30) | — | 452,413 B |
| 16383 | `2^14` | 64 s (load 15–35) | not re-measured (earlier round: 26.5 ms at load 50) | **1.13 GiB** | 759,788 B |
| 65535 | `2^16` | **70.4 s** wall (load 70–90) | **29.6 ms** | **2.26 GiB** | 861,407 B |
| 65535 | `2^16` (earlier code, profiled) | 141–335 s wall (load 15–137) | 45–153 ms first / 34.8–84.3 ms steady, 186–228 ms CPU/iter | 2.01–4.03 GiB | 1,100,335 B |

The `2^16` row went from ~141–261 s to 70.4 s in this round. Re-runs taken
while an iOS simulator held cores are not comparable even at a low 1-minute
load: the same binary then reported 121.1 s with `product6` at 83.7 s while
using 738 CPU-seconds over 121 s (≈6 effective cores) against ≈11 in the 70.4 s
run. Quote `prove cpu / wall` alongside the load to make that visible. Two of those
seconds were real work and the rest were measurement: the
`MAGNETAR_PROFILE_SELECTED` checkpoint `setup rss after witness fill` sat
*inside* the pc-chain loop and printed one line per cycle (~65 k `eprintln!`
at `2^16`, ≈160 s). With the print moved out of the loop and the witness fill
split across cycles (word-aligned instance blocks, 64 bits per store), the
same benchmark reports `setup fill: 0.47 s` and byte-identical proofs
(861,407 B before and after). Current stage profile at `2^16`: unified
context 0.48, Commit 1.19, Access 2.56 (register twist 2.53), Opening 3.38;
selected setup 0.48, witness commit 0.95, `product6` 43.2, `product2` 23.4,
segments 1.17, open 0.92. The remaining 67 s of the 70 s is the two streaming
products, at the level-store floor described in §3.
| 131071 | `2^17` | **147.6 s** (RV64, load 67–95) | **55.8 ms** | **4.60 GiB** | 942,535 B |
| 262143 | `2^18` | **321.5 s** (RV64, load 55–80) | **161.5 ms** | **7.73 GiB** | 1,050,900 B |
| 524287 | `2^19` | **667.8 s** (RV64, load 37–118) | **318.3 ms** | **10.54 GiB** | 1,177,984 B |

Stage peaks at `2^16` (current build, `MAGNETAR_PROFILE_UNIFIED=1` +
`MAGNETAR_PROFILE_SELECTED=1`): context 0.52 GiB, mosaic Commit 1.19 GiB,
selected witness commit 2.07 GiB, Access 2.30 GiB, Opening 2.26 GiB (prove
peak). The peak is no longer the sum of the two commit transients — see the
commit gate in §3 — but RSS keeps freed pages, so the mark rises when the
register-twist Access stage allocates on top of the mosaic commit's retained
pages. At `2^18`/`2^19` the mosaic Commit (5.02/8.13 GiB) and Opening
(5.98/8.82 GiB) transients are the largest terms, and the selected witness
commit (3.70 GiB at `2^17`) adds on top of them.
The run-to-run peak range (3.15–4.03 GiB) comes from the *opening* stage: it
re-encodes the mosaic (its own codeword and Merkle tree) while the selected
prover holds its level stores, so which of the two is in flight when the other
peaks decides the number. Serializing them would bound the peak but give up the
opening/selected overlap (11–38 s at `2^16`).

**Scaling to `2^22`.** Measured staircase of the whole benchmark with the
current profile (rate-1/2 selected PCS, rate-1/4 mosaic, budget 22):

| cycles | prove peak | verify CPU/iter | verify steady |
| --- | --- | --- | --- |
| `2^16` | 2.01–2.61 GiB | 186–228 ms | 34.8–84.3 ms |
| `2^17` | 3.35 GiB | 410 ms | 181.4 ms |
| `2^18` | 5.21 GiB | 774 ms | 215.2 ms |
| `2^19` | **8.87 GiB** | 1613 ms | 478.3 ms |

**Peak memory is linear in `cycles` on the current build.** Re-measured at
RV64 width with the 16-byte digest and p3 parallelism: **2.32 / 4.74 /
7.73 / 10.54 GiB at `2^16` / `2^17` / `2^18` / `2^19`**, against prove
70.4 / 147.6 / 321.5 / 667.8 s (≈2.1× per doubling, i.e. linear in `cycles`)
and verify 29.6 / 55.8 / 161.5 / 318.3 ms. The `2^18`/`2^19` rows predate the
fused scan and the ring-switch fix. Two re-runs of `2^18` under fluctuating load
(42–324) measured 335 s and 437 s with peak RSS 5.7–7.8 GiB, i.e. the mark moves
with the allocator and the wall with the load; they stay as measured at load
37–118 and are marked pre-fusion. Peak memory adds
2.42 / 2.99 / 3.05 GiB per doubling — a fixed base plus a linear term of about
**2.8 GiB per doubling**, which projects ≈20 GiB at `2^22` and supersedes the
55–60 GiB figure inferred from the earlier 32-byte-digest staircase. The earlier 16-byte rows quoted
in this section (1.52–1.58 GiB at `2^16`, 1.69 GiB at `2^17`) are not
reproducible on the current build (they were recorded on an earlier one) and
are superseded. `RAYON_NUM_THREADS=1` versus `12` at `2^16` peaks at 2.30
versus 2.32 GiB (measured before the ring-switch fix of §9.10), so the vendored
p3 parallel paths do not inflate the peak. The high-water mark is reached at
the mosaic Opening (2.30 GiB at Access, 2.32 GiB after Opening): the selected witness commit contributes 2.07 GiB
(3.70 GiB at `2^17`) and the register-twist Access 1.43 GiB standalone, and
because freed pages are not returned to the OS the mark tracks their sum
rather than their maximum.

The measured deltas (2.42 / 2.99 / 3.05 GiB) fit a linear term: every peak
component except the level stores scales with `cycles` — witness `2^(N+10)` B,
selected codeword `2^(N+11)` B at rate 1/2, its Merkle tree `2^(N+11)` B at
16 B per node, the mosaic codeword/tree about `2^(N+10)`/`2^(N+11)` B — plus
the fixed 0.53 GiB level stores and ~0.5 GiB context. A linear fit through the
four measured points projects **≈20 GiB at `2^22`**; the 55–60 GiB figure in
earlier revisions came from the 32-byte-digest staircase and is superseded. The
memory path to 6.4 GiB remains a smaller digest plus a bit-level codeword, not
the witness (16 GiB at `2^22`) nor the levels (fixed 0.53 GiB).

The `2^16` proof is 861,407 B: 54 KB smaller than round 3 after the per-row
claim blob was removed from the selected opening (1,154,711 → 1,100,335 B),
then +16.4 KB for the local PCS profile change of §9.10.

For comparison, the first round of this work (witness rebuild in the verifier,
rate-1/16 mosaic, no streaming budget) ran `2^16` in 213 s prove / 1.59 s verify
at 8.11 GiB peak with a 788 KB proof.

The non-monotone `2^12`/`2^13` peak is **not** the selected prover: the register
Twist prover switches between its legacy and its linear-shared path at
`LINEAR_TWIST_MIN_CYCLES = 8192`. Below/around that threshold the legacy history
sum-check holds a transient 9–12 GiB working set; from `2^14` on the linear path
is used. That is a pre-existing property of `binary_twist` and the next memory
target if `2^12`/`2^13` matter.

## 7. Verification cost (three optimization rounds)

The verifier was the largest gap to the paper. At RV64 `2^16` it went from
**1.42 s** (round 0: rebuild the full witness, re-evaluate every row circuit,
bind every segment) to **175–260 ms** (round 2: streamed per-segment binding,
parallel claim Merkle) to **54.5 ms** (round 3: the proof-only claim layer,
merged into the selected lockstep inner sum-check).

Round 3 stage costs at `2^16` (paper benchmark, `MAGNETAR_PROFILE_VERIFY=1`):

| stage | time |
| --- | --- |
| claim proof (decode + leaf hash + tree) | 12.1 ms |
| claim row sums (decode rows, 12 workers) | 12.6 ms |
| lockstep rounds + segment claims + six MLEs + ring-switch PCS | 11.8 ms |
| access statement | 6.6 ms |
| core (mosaic opening verify) | 8.0 ms |
| `claims_to_trace` | 0.8 ms |
| **total** | **54.5 ms** |

Round 2 notes that still apply:

* `verify_dynamic_segments_against_rows` (trace-path reference) binds each
  segment from per-cycle row witnesses over the relation's support (~1 400 of
  8 192 columns) instead of materializing `2^29` bits; `WitnessScratch` reuses
  one buffer and clears only the bits the previous row set.
* The claim Merkle hashes each leaf once (`verify_complete_leaves`) and reduces
  the tree with one contiguous chunk per worker, keeping the canonical order.
* `MAGNETAR_VERIFY_WORKERS` pins the segment-binding worker count (round-2
  scaling at `2^14`: 208 ms with 1 worker, 58 ms with 4, 36.8 ms with 12).

Round 3 replaced circuit re-evaluation entirely: the verifier decodes the
authenticated claim rows, recomputes one batched claim target, and checks it
against the committed witness inside the *already existing* inner sum-check
(§9.5). It never rebuilds a row witness.

Rounds 4–5 cut the remaining `O(T)` work itself (54.5 → **36.8 ms**):

| change | effect at `2^16` |
| --- | --- |
| claim leaves and tree nodes hash from a stack buffer (no `Vec` per leaf/node) | claim proof 12.2 → 9.1 ms |
| claim row sums: the instruction decoder runs on 12 chunks instead of serially, and the per-row dedupe uses a row stamp instead of a reset list | row sums 13.3 → 7.7 ms |
| schema and row sums share one built row/mapping (was built twice) | claim sums total 15.1 → 10.5 ms |
| access statement, claim-derived trace and core checks moved off the critical path | −7 ms of serial time |

Rounds 6–7 remove work in the two remaining hot spots:

| change | effect at `2^16` |
| --- | --- |
| claim-tree leaves hash groups of 8 rows (one SHA-256 per group instead of one per row); the prover no longer materializes 65 536 per-row openings, and the selected bundle drops its redundant `claim_root` copy | claim proof 8.7 → 5.7 ms (leaf+tree 6.8 → ~4), prover RSS/time down |
| the six-matrix MLE evaluation shares the instance equality vectors and the `Σ eq·eq` term (`BlockEvalShared`), and builds the three `eq` tables on three threads | `eval_mles` 7.5 → 5.2 ms |
| claim schema and row sums share one built row/mapping | claim sums 15.1 → 10.5 ms |

Round 8 restructures the verifier into two waves so the four row-dependent
checks overlap instead of chaining:

* one decode of the claim blob (`ClaimProof::decode_rows`, ~1 ms);
* **wave 1**: claim leaf/tree check, the folded claim's row sums, the access
  statement and the claim-derived trace run concurrently;
* **wave 2**: the selected lockstep verify (with the prepared claim) and the
  core proof run concurrently.

The critical path drops from `decode + leaves + sums + lockstep` to
`decode + max(leaves, sums, access, trace) + max(lockstep, core)`. Per-stage
costs are unchanged; running in one wave hides the leaf check (5.7 ms) and the
access/trace checks behind the row sums.

Current split at `2^16` (load ≈10): claim proof 5.7 ms, claim sums 10.5 ms,
selected lockstep 9.1 ms (6 MLEs 5.2 + ring-switch PCS 3.6), access 6.7 ms and
core 7.5 ms (both parallel); total **≈33 ms**.

### Round 9: the trace Logup-Shout fold

Profiling the paper benchmark (`TRACE_SHOUT=1`) at `2^16` on the loaded host
(load 40–125) put **`verify_native trace_logup` at 393–450 ms — 76 % of the
515 ms CPU/iteration**; every other stage stayed in single-digit milliseconds
per wave (`claims decode` 3.5–4.7, `claims_to_trace` 0.9–1.4, `access` 10.8,
`claim sums` 18.1, `core` 15.0 at load 50). After this round's two fixes the
stage first measured **70–77 ms** and verify CPU/iteration **231 ms** (load
18–48): `columns+positions` 7.2 ms, `reader columns` 0.5 ms, `reader claims`
2.4 ms, `link claims` 5.8 ms, `reduction verify` 3.9 ms, `final claims` 21.0 ms.
After the nibble-table `embed` and the parallel ROM gather the stage measures
**39–46 ms** and CPU/iteration **200 ms** (below).

This stage is the one remaining *per-column O(cycles)* verifier step: the proof
drops its pushforwards (`logup.pushforwards.clear()`) and
`verify_trace_logup_shout` rebuilds the reader and link claims from the
claim-derived trace.

* The constant was pathological: `eval_mle` called `Poly::eval_ext`, which
  switches to the packed split-eq tables above ten variables. Evaluating the 12
  reader columns at `2^12` (49 k elements) took **40 ms**.
* Replaced with an explicit O(n) fold in the same interpolation order (last
  coordinate first, adjacent pairs), and the independent column folds now run
  one per worker (`parallel_evals`). At `2^12` `trace_logup` went **70.9 →
  20.5 ms** and total verify 46.7 → 30.5 ms (load 30–55).
* The remaining `2^16` cost was not the fold at all: `public_reader_point`
  absorbed the whole ROM into a SHA-256 transcript element by element — 786 k
  absorbs for the `2^17`-instruction ROM — at 272 ms. A single `2^16` column
  folds in 0.7 ms and a 128-bit binary multiply measures 20 ns in both `B` and
  `F2_128` (a microbenchmark, not inferred), so neither the field choice nor
  the fold shape was the problem. The reader point now absorbs the ROM digest
  (`rom_hash`, the statement's `program_hash`) once: the verifier passes
  `statement.program_hash` (O(1)), the prover hashes the ROM once. Point build
  `2^12` 15.5 ms → **9 µs**; the stage is ~2 ms and total verify CPU/iteration
  at `2^12` 68.6 → **31.8 ms** (wall 13.9 ms, steady state, load 25–60).
* The public-ROM table claims and the cycle-long position claim are independent
  columns too, so they now go through `parallel_evals` as well: `final claims`
  at `2^12` 0.66–1.4 → 0.62–0.70 ms.
* `embed()` built each cycle's position element with up to 64
  `interpolation_node` calls; a 4-bit nibble table (built once) plus 16 lookups
  replaces that, and the public ROM's column vectors are gathered one column
  per worker. At `2^16` `columns+positions` measures **3–4.5 ms** (from
  10–18 ms with the nibble table alone) and the whole stage **39–46 ms** (from
  393–450 ms before this round). Verify CPU/iteration at `2^16` is **200 ms**
  (from 231–233 ms) with a **71.8 ms** steady-state wall; the other waves —
  claim row sums 23–37 ms, access 12–14 ms, leaves 7–9 ms, core 13 ms — now
  weigh as much as this one.

* The last trace rebuild inside that stage was `BinaryShoutWitness::from_trace`
  (`2^16`: 15–18 ms, of which the per-cycle loop was 7–8 ms after this change
  and ~15–20 ms before). The loop is now split into parallel cycle chunks
  (read values, valid/is_32, ROM indices), one worker per address bit, and a
  serial ROM-row write (shared rows, identical values). What remains is mostly
  the zero-filled buffers: `address0/1` 33 MB, `read_value` 12.5 MB, `rom`
  25 MB at `2^16`. The stage total did not move outside noise on this host:
  53–60 ms and 227 ms CPU/iteration at load 48–68 (against 39–46 ms and 200 ms
  at load 22–50), so the loop win is real but the allocation floor dominates.

### Round 11: compact claim sums and an allocation-free shot witness

Two hot spots in the verifier, both working-set problems rather than arithmetic:

* **Claim row sums in slot space.** The row sums accumulated one field per
  block column (8 192 entries, 128 KB) with a dedupe stamp array of the same
  width (32 KB); both miss L1 on every one of ~600 emissions per row. The
  schema now carries `slot_of` (block column → index in the batched claim
  column set, ≤ ~350) and the workers accumulate one field per slot (5 KB) with
  stamps of 1 KB — both L1-resident, with one shared read-only `slot_of` lookup
  per emission. Columns outside the schema are skipped exactly as before, and
  the claim target is unchanged (the same `α^slot` dot product).
  `2^16` claim row sums **23–37 → 10.8–12.0 ms**; `claim sums` (decode + sums)
  23–37 → 15.6 ms. `2^12` 4.1 → 1.4 ms.
* **Shot witness without per-cycle allocations.** `BinaryShoutWitness::read_value`
  held a `Vec` per cycle, i.e. 65 536 allocations (12.5 MB of 192-byte rows) in
  the rebuild the trace Logup-Shout verifier performs. It is now
  `Vec<[F2_128; 12]>`: one inline row per cycle, written by value.
  `2^16` cycle loop **7–8 → 4.0–4.5 ms** and the whole witness build
  **15–18 → 7.1–7.6 ms** (the first calls pay the page faults on the new
  12.5 MB buffer); `2^12` loop 0.86–1.3 → 0.54–0.64 ms.

* **Tried and reverted: dedupe only set emissions.** Duplicate columns agree on
  their value (`claim_emission_stays_inside_the_schema` pins it), so a false
  emission could skip the `slot_of` lookup and stamp write. Measured at `2^16`:
  claim sums 16.5 ms against 15.6 ms without it — no change outside noise, so the
  simpler loop (stamp every emission, accumulate only set bits) stays.
* **The ROM columns are gathered once.** The verifier built them a second time
  for the table claims (12 × `2^address_bits` values, 25 MB and 1.5 M
  conversions at `2^16`); the table claims now fold the reader-side vectors.
  Time was flat (the second gather was cache-warm), but the duplicate copy is
  gone.
* **Reader and link claims fold in one fan-out.** Both fold at the same point;
  one `parallel_evals` over the 24 columns costs a single round of worker
  spawns instead of two. `2^16`: the combined fold measures 3.9–4.9 ms
  (previously ~6–8 ms split across two calls), and the stage total is
  27–28.5 ms.
* **Address columns are built at exact size.** `from_trace` zero-filled both
  address matrices (33.5 MB at `2^16`, 2 GB at `2^22`) and then overwrote every
  entry from the per-cycle `indices`; each column is now built directly from
  `indices` in its own worker, so the fill pass is gone. `2^12` witness build
  1.4–1.9 → **0.84 ms**.
* **Reader claims are gathered into the fold.** The trace verifier used to
  materialise the gathered ROM matrix (`proof.columns × cycles` values: 25 MB at
  `2^16`, 768 MB at `2^22`) and then fold it; each worker now gathers one column
  straight into its fold buffer and folds in place, so the matrix never exists.
  `2^12` timing is neutral (combined reader+link fold 0.63–0.68 ms); the change
  is a memory-scaling fix, not a speed one, and the logup tests pass.
* **Tried and reverted: fanning out `positions()`.** The scan is independent
  per cycle, but it already runs inside the verifier's wave-2 thread next to
  the mosaic-opening check; spawning 12 more workers there made
  `columns+positions` **3–4.5 → 5.7–6.0 ms** at `2^16` through contention, so
  the serial scan stays. The lesson for the remaining work: the verifier is
  thread-saturated, so the next wins have to remove work, not add parallelism.

Together: `verify_native trace_logup` at `2^16` **39–60 → 27–28.5 ms**, verify
steady wall **71.8–84.1 → 60.9–74.2 ms** and CPU/iteration 200–243 →
**198–213 ms** (load 20–137 across runs; the first verification of a fresh
process is still 2–4× slower).
Wave 2 (`core` ≈10–11 ms, trace Logup ≈29 ms) now runs as two threads instead
of one serial thread, so the mosaic opening hides under the Logup stage. The
wall did not move outside this host's noise (65.4 ms steady at load 36–83
against 60.9–64.4 ms at load 20–52; CPU/iteration 209.6 vs 206–213 ms), but the
serialization is gone and the critical path is the trace Logup stage alone.

The table dump at `2^16` (`MAGNETAR_DEBUG_TABLES=1`) shows the stacked mosaic
cells are only **0.03 GiB**: table 5/6 are `2^16 × 12`, table 11 is `2^19 × 1`.
The 2.15 GiB commit RSS is therefore the PCS codeword and Merkle tree over those
cells at rate 1/4 (16 B per field element), not the table data. At `2^22` the
cells grow 64× (≈2.4 GB), so the 16 B-per-field codeword and tree are the 2^22
blocker, not the tables alone.
* Tried and reverted: folding in `F2_128` instead of `B` gave no speedup, which
  the microbenchmark explains — both multiply at ~20 ns.

The stage is still O(cycles) in principle, so at `2^22` it would be ~64× its
`2^16` value. Making it O(polylog) means committing the Logup position column
and verifying the reader/link claims against that commitment instead of the
witness — the same structural item as §9.


**Memory: the mosaic commit, not the selected prover, set the peak.** With
`MAGNETAR_PROFILE_UNIFIED`/`MAGNETAR_PROFILE_SELECTED` RSS prints, the `2^16`
peak sat in the unified mosaic PCS: context 1.1–3.3 GiB, commit 5.9 GiB,
selected stage 0.9–1.0 GiB. The mosaic used rate 1/8 (`log_inv_rate = 3`), i.e.
an 8× codeword over the table columns. Switching the mosaic PCS to rate 1/4
(`100, 2, 21, 2` — the query count is a library function of rate and grinding,
so 100 bits hold) halves the codeword:

| `2^16` | before | after |
| --- | --- | --- |
| context RSS | 3.31 GiB | **1.11 GiB** |
| commit RSS | 5.87 GiB | **2.85 GiB** |
| prove peak RSS | **7.80 GiB** | **3.06 GiB** |
| verify peak RSS | 6.94 GiB | **2.63 GiB** |
| proof | 1,124,215 B | 1,154,711 B |
| mosaic opening | 316,049 B / 14.7 s | 346,545 B / 19.1 s |
| core (mosaic) verify | 7.5 ms (load 10) | 11.7 ms (load 111; not comparable) |
| verify CPU per iteration (25-run loop) | 139.2 ms | **138.0 ms** (load 72–95) |

At `2^14` the same change took the peak 2.58 → **1.12 GiB** and the commit
2.58 → 1.03 GiB. Per cycle this is now ~2× the paper's memory (7.8 → 3.06 GiB at
`2^16`), instead of ~5×; the remaining per-cycle cost is the table
representation (one 16-byte field element per boolean column per row) and the
`Vec<bool>` witness (1 B/bit), both of which need a packed representation to
reach `2^22` at 6.4 GiB.

**Prover: one flat non-zero list for the six base matrices.** `row_values`
used to probe six sparse rows per row of the outer sum-check; the base-matrix
nonzeros are now grouped once into a CSR list `(slot, column, coefficient)` by
local row (`LockstepRows::base_offsets/base_entries`, ~4 200 entries), so each
row iterates only its own nonzeros. The byte-equality test against the eager
prover still pins every level. At `2^12` the effect sits inside the host's
run-to-run noise (outer recompute 7.5–8.5 s at load 50–90); the change is kept
because it strictly removes per-row probes. The remaining pass cost is
field-multiply bound: the vendored `BinaryField128` multiply already uses SIMD
carry-less multiplication plus reduction, so there is no cheap factor left
there.

**Verifier coverage.** `native_claim_layer_verifies_without_trace` and the new
`native_verifier_rejects_a_tampered_compressed_claim_blob` now tamper every
field the native verifier consumes and require rejection: proof width, a missing
mosaic opening, the opening's commitment binding, the virtual claim root, the
claim data (decoded rows or the compressed register blob), `ram_index`, the
claim column-set root, the trace Logup-Shout link claims, the claim root, the
segment claims, the inner round polynomial, the ring-switch opening and the
folded claim target.

**Prover: the inner sum-check scanned the lazy extra rows per *block*.** The
streaming inner sum-check derives its left vector from the witness per block;
for every block it also walked the gated extra rows of the instances it touches
(64 entries per part). Early rounds ask for two columns at a time, so ~2^24
blocks each scanned 128 entries to find at most one. The extras only touch the
PC, next-PC and unit-constant columns (three narrow local ranges), so
`ColumnRows::fill_left` now skips any block whose window does not intersect them
(the part-2 chain rows land in the next instance's block, so both blocks are
checked). Measured at `2^12`: inner recompute **9.9 s → 2.5 s** and
`selected product2` 10.4 s → 2.6 s; the equality test that pins the streaming
proof to the eager proof byte-for-byte still passes at every level. At `2^16`
the inner recompute measured 34.7 s on a host at load 62–97 (previously 40–53 s
at lower load), so the same ratio applies.

The selected prover stages at `2^16` now measure: witness commit **9.7 s**
(never reported before), claim target 21.6 ms, product6 104.5 s (load 62–97;
55–72 s at lower load), product2 34.8 s, segments 1.3 s, opening 11.7 s.

**PCS profile: grinding, not the codeword, was the prover bottleneck.** The
selected-witness opening used rate 1/16 with 24 grinding bits, chosen earlier
for the smallest proof. Sweeping `(security, log_inv_rate, pow_bits,
log_folding)` at `2^12` shows the opening time is dominated by the query
grinding (2^pow hashes, independent of table size):

| profile | `selected open` | verify PCS | selected opening |
| --- | --- | --- | --- |
| 100, 4, 24, 3 (old) | 40.4 s | 5.05 ms | 188,623 B |
| 100, 3, 24, 3 | 10.0 s | 3.00 ms | 189,743 B |
| 100, 5, 24, 3 | 20.1 s | 3.65 ms | 191,279 B |
| 100, 3, 20, 3 (new) | **1.4 s** | 3.28 ms | 201,199 B |
| 100, 2, 16, 3 | 1.2 s | 3.58 ms | 231,727 B |

The backend derives the query count from `security_level`, so every row keeps
the 100-bit target. `(100, 3, 20, 3)` cut the opening from 41.6 s to **12.1 s**
at `2^16`, the verifier's PCS check from 5.05 to 3.28 ms at `2^12`, and grew the
selected opening by 23.6 KB (`2^16`: 274,975 → 298,559 B).

**Selected PCS rate sweep (`2^16`).** The codeword and Merkle tree scale as
`2^log_inv_rate` over the packed witness, so the rate trades proof bytes
against the commit transient and time (grinding and folding held at 20 bits and
8-way):

| `log_inv_rate`, grinding, folding | selected commit | selected open | prove peak | verify CPU/iter | selected proof | full proof |
| --- | --- | --- | --- | --- | --- | --- |
| 3, 20, 3 (previous, rate 1/8) | 8.7–15.2 s | 12.1–15.1 s | 3.15–4.03 GiB | 200–227 ms | 298,559 B | 919,759 B |
| 2, 20, 3 (rate 1/4) | 3.8 s | 12.0 s | 3.11–3.17 GiB | 243 ms | 334,111 B | 955,311 B |
| **1, 20, 3 (now, rate 1/2)** | **2.3 s** | **5.4 s** | **2.01 GiB** | **186 ms** | 479,135 B | **1,100,335 B** |

The selected profile is now **rate 1/2**, the memory-first dial, because the
target is the paper's `2^22` memory envelope: at `2^16` it measures a **2.01 GiB**
peak against 3.11–4.03 GiB for rate 1/4, the commit drops to 2.3 s and the
opening to 5.4 s, and the verifier is *faster*, not slower (34.8 ms steady,
186 ms CPU/iteration at load 15–35). The cost is proof bytes: 1,100,335 B
against 955,311 B (+15 %). None of the three rates reaches the paper's `2^22`
envelope on its own — the codeword is 16 B per field element (§3), so rate 1/2
still leaves ~8 GiB of codeword plus its tree there — but it is the closest
point on the dial and the proof-size price is explicit.

**Merkle digest: 16 bytes.** The PCS Merkle tree used `Keccak256Hash` with a
32-byte digest. It is now `Keccak256Hash16` (Keccak-256 truncated, 128-bit
collision resistance against the protocol's 100-bit target) with
`MerkleTreeMmcs<…, 2, 16>`. At `2^16` this drops the prove peak from
**2.01–2.61 → 1.52 GiB** and the proof from **1,100,335 → 845,055 B** (−23 %;
`commitment` 280 → 264 B), because the tree and every path node halve. Verify
CPU is unchanged within noise (231 vs 186–228 ms/iteration; the wall of that run
is meaningless at load 200–330). A `2^12` control confirms the shape: the proof
moves 473,405 → 471,421 B there (paths are short at that size) and the verifier
measures 43.9 ms CPU/iteration at load 257 against 31.8 ms at load 30 — load
inflation, not a regression. All 342 runtime, 43 proof and the testkit suites
pass with the new digest.

**The mosaic keeps rate 1/4.** Applying the same dial to the *mosaic* PCS was
measured at `2^16` and rejected: rate 1/2 grew the peak (2.01 → 3.07 GiB), the
proof (1,100,335 → 1,252,367 B) and the verifier (34.8 → 52.4 ms steady); only
the opening sped up (15.3 → 7.0 s). The two PCSs react differently because the
mosaic's peak sits in the opening's query paths and the twist stage, not in the
mosaic codeword alone.

**Rejected: precomputed per-kind claim emissions.** Two faster variants of the
claim row sums were implemented and reverted after the equivalence test caught
them: (a) folding each non-selected component's constant contribution into one
per-kind scalar, and (b) precomputing a deduplicated `(position, column)`
template per input kind. Both assume a row's emitted columns depend only on its
kind. That is false in two ways the test exposed: some components' emission
*length* depends on the operand values (687 vs 688 entries for the same kind),
and a column can be claimed by several components, so the per-row
first-occurrence dedupe (which keeps one value per column) cannot be replaced by
a static template or an additive constant. The per-row stamp dedupe stays; the
test `claim_emission_stays_inside_the_schema` pins the two properties that must
hold (every emitted column is claimed, duplicates agree on the value).

The mosaic change is verify-neutral in CPU terms (138.0 vs 139.2 ms per
iteration over the 25-run loop) even though the opening carries 40 queries
instead of 19: the paths are shorter and the codeword smaller.

**Steady state vs cold start.** A single verification right after proving runs
2–4x slower than the steady state (cold caches, cold worker threads): at `2^12`
the first call measured 39–46 ms while a 50-iteration loop measured **11.5–12.5
ms wall / 24.5 ms CPU**. The benchmark therefore also reports the loop numbers
(`MAGNETAR_VERIFY_CPU=N`, added this round); at `2^16` the loop measured 44.1 ms
wall / 139.2 ms CPU on a host at load 24–67, i.e. the load-10 single-shot 33.8 ms
is the comparable figure.

**Measurement caveat.** The benchmark host is shared and its load swings
between 8 and 300 (system indexing, simulator, desktop apps). The same binary
measured 33.8 ms, 40.9 ms and 59.1 ms end to end while its *stage* costs were
unchanged, so the report below uses the lowest-load run and the stage table for
cross-run comparisons. `MAGNETAR_VERIFY_CPU=N` re-runs the verifier `N` times
and prints the process CPU time per iteration, which does not depend on how the
OS schedules us; `prove cpu` does the same for the prover. Measured at `2^16`:
**128.8 ms CPU per verification** (user+sys over 25 runs, wall 50.6 ms under
load), i.e. the verifier uses ~4 cores on average — the single-threaded claim
proof and the 12-worker row sums dominate the CPU total, not the wall time.

## 8. Gap to the paper (Table 6, `erc20-mixed-block`, 2^22 cycles)

The paper runs `2^22` cycles; its per-cycle CPU row is a few hundred bits, so its
witness is `~2^22 · 256 ≈ 2^30` bits — the same order as our `2^16` run
(`2^16 · 8192 = 2^29`), which is why the `2^16` comparison below is meaningful.

| | paper `2^22` cycles | this work (measured staircase) |
| --- | --- | --- |
| witness bits | ~`2^30` (est.) | `2^29` (`2^16`) → `2^31` (`2^18`) |
| prover peak RSS | 6.4 GiB | **2.26 GiB** (`2^16`), 4.74 (`2^17`), 7.73 (`2^18`), 10.54 (`2^19`); linear fit ≈**20 GiB** at `2^22` |
| proof size | 598 KiB | 861,407 B (`2^16`), 942,535 (`2^17`), 1,050,900 (`2^18`), 1,177,984 (`2^19`) |
| verify | 11–13 ms | **29.6 ms** (`2^16`), 55.8 (`2^17`), 161.5 (`2^18`), 318.3 (`2^19`) |
| prover | 547 ms (as quoted; plausibly 547 s) | 70.4 s (`2^16`), 147.6 (`2^17`), 321.5 (`2^18`, pre-fused-scan), 667.8 (`2^19`, pre-fusion) |

What remains is quantitative and identified:

1. **Verifier: the claim layer and the trace Logup-Shout are `O(rows)`.** At
   `2^16` the trace Logup stage is 27–28.5 ms, the claim rows 15.6 ms, the
   access statement 12–14 ms and the claim leaves 7–9 ms; they are the wall at
   every size and double with the rows (410 → 774 → 1613 ms CPU/iteration from
   `2^17` to `2^19`, i.e. ≈13 s projected at `2^22` against the paper's 11–13 ms). The paper has no per-row verifier work because its CPU claims
   are committed columns opened at one point; replacing the per-row claim blob
   with committed claim columns is the structural step (results §9.8, and the
   open statement-binding question in the handoff §9.1).
2. **Memory: the codewords and Merkle trees over the committed tables
   dominate.** Per §6 the witness is `2^(N+10)` B, the level stores a fixed
   0.53 GiB, the selected codeword `2^(N+11)` B at rate 1/2 with a `2^(N+11)` B
   tree (16 B per node), and the mosaic commit/opening transient is the largest
   measured term (5.0 / 6.0 GiB at `2^18`). The linear fit puts `2^22` at
   ≈20 GiB; the remaining path to 6.4 GiB is a smaller digest and a bit-level
   codeword — not the witness (4 GiB at `2^22`) and not the level stores.
3. **Prover time is bound by the sparse per-row scan.** `2^16` runs in 84.2 s
   with `prove cpu` ≈ 800 s; `product6` (53.2 s) scans `level × rows` =
   9 × 2^30 rows and `product2` (23.6 s) 8 × 2^29 columns, each row evaluating
   its 3.7-entry sparse relation against the packed bits. The budget sweep of
   §3 puts this at the memory floor (`level = bits − 21`, a 402 MiB store);
   the remaining cost is the relation evaluation, not copies or idle workers.

## 9. Proof-only claim layer: design for the next change

The verifier is now proof-only in its *inputs* and no longer re-evaluates row
circuits, but it still has `O(rows)` work: it decodes the authenticated per-row
claim blob and accumulates the claim sums from it (§7). The paper instead binds
the CPU claims to **committed witness columns**
with one batched sum-check. This section is the concrete plan, checked against
the current code.

### 9.1 Shape of the new binding

Let `w[row, col]` be the committed CPU witness bit (`LockstepProof.commitment`)
and `v[row, col]` the claimed value of the *claim columns* — a canonical set:
`pc` bits, `next_pc` bits, the active component's operand bits, the selector
bits and the instruction-word bits. Then, for a fresh row point `z` and batching
`α`:

```
Σ_{row,col} eq(z,row)·α^col·w[row,col]  =  Σ_row eq(z,row)·(Σ_col α^col·v[row,col])
```

* The right side is computed by the verifier from the compressed columnar blob
  in `O(#runs)` — the existing `ClaimColumns` encoder already delta/run-length
  codes exactly this data (2 410 B for 65 536 rows).
* The left side is *linear* in the committed witness, so it folds into the
  existing inner sum-check the same way the matrix-combination term does: add
  `γ·eq(z,row)·α^col` to the inner `left` vector and `γ·(right side)` to the
  claimed sum. No new proof field and **no second PCS opening**: the verifier
  evaluates the coefficient at `ry` analytically (`eq(z,·)` on the row part is
  free; `α^col` is a product over column bits) and multiplies by the existing
  `vw = z(ry)`.
* Soundness: the lock-step sum-check already proves the committed witness
  satisfies the CPU relation; binding the claim columns ties that witness to the
  execution (PC chain, operands, opcode selectors), which is enough because the
  relation plus those columns determine the rest of the row.

### 9.2 Blocking finding (pre-existing, needs a decision)

`prove_unified_trace_dynamic_native_profile` sets `proof.opening = None`
(lib.rs:2952/2966), and `verify_core_statement` skips `verify_mosaic` when it is
`None`. So in the dynamic/paper path the mosaic commitment is never opened: the
access, router and trace-table claims are only checked for *internal*
consistency. A genuinely proof-only and sound verifier has to bring that opening
back:

* verifier cost: one `verify_mosaic` over the batched points (measured 8.0 ms at `2^16`);
* prover cost: the missing `open` (the PCS reveal repacks and re-commits the
  packed table; included in the 181.3 s above).

Resolved in §9.6.

### 9.3 Staged plan

1. Canonical claim columns + verifier-side functional (`O(#runs)`), as a new
   `claim_blob` payload; keep the Merkle `ClaimProof` behind a flag for
   comparison. — *not taken*: the per-row decode now costs 24.7 ms in total, so
   the `O(#runs)` blob is an optimization for later, not a blocker.
2. Fold the batched binding into the inner sum-check. — *done* (§9.5).
3. Restore the mosaic opening; make the statement bind the claim blob
   (`trace_claim_root` becomes the blob root); delete `claims_to_trace`, the
   per-row Merkle tree and `verify_dynamic_segments_against_rows`. — *mosaic
   opening restored* (§9.6); deleting `claims_to_trace`/the Merkle tree is still
   open (the trace Logup-Shout and the register-claim layer still consume the
   decoded rows).
4. Re-measure at `2^16`/`2^18` and update this document. — *`2^16` done* (§9.7).

Expected end-to-end verifier at `2^16`: **~25–40 ms** (19 ms proof-only selected
+ 1–3 ms claim functional + 5–10 ms mosaic opening), i.e. within ~2–3x of the
paper's 12 ms at a comparable witness size, with no witness reconstruction.

### 9.4 A verification-coverage bug in the first proof-only iteration

The first proof-only iteration (the "stage 2" described in the previous
revision) replaced `bind_dynamic_segments` — which called
`verify_dynamic_segments_public_point`, the *only* place that checked the
selected lockstep proof and its PCS opening — with `verify_dynamic_claim_binding`,
which checked only the claim's own sum-check and opening. `verify_native_unified`
therefore stopped verifying the selected CPU proof, and the `117.8 ms` verifier
figure measured that unsound path. The suite did not catch it because no test
tampered a proof-level field through the unified entry point.

Fixed by folding the claim into the lockstep inner sum-check (§9.5) and always
running the full lockstep/PCS verification. `native_claim_layer_verifies_without_trace`
now tampers (a) a segment claim value, (b) an inner round polynomial, (c) the
ring-switch opening and (d) the claim target, and requires all four to be
rejected.

### 9.5 Stage 2 landed: merged claim binding

Design as planned in §9.1, with one change forced by the code: the claim
coefficient is added to the inner sum-check's *left* vector (not a new field),
so a single sum-check and a single PCS opening bind both the CPU relation and
the claim.

* `ColumnRows::with_claim(claim, γ)` folds `γ·eq(z,instance)·α^slot` into the
  left vector. The claimed columns are a sorted list; each `fill_left` call
  binary-searches the window it needs, so the early sum-check rounds (two
  columns per call) stay cheap — a full scan per call made `2^16` take minutes.
* Prover: `expected_inner_claim = base + γ·target`; the commitment computed
  once in `prove_dynamic_cpu_claims` is passed in, so the prover no longer
  re-commits inside `open` (`BitPcs::open_with_commitment`).
* Verifier: `proof.inner.claimed_sum == base + γ·target` and
  `inner_final == (col_left(ry) + γ·coef(ry))·vw`, with `vw` reconstructed from
  the segment claims and `coef(ry) = claim.eval(ry[..log_block], ry[log_block..])`.
* `WitnessClaimProof`, `prove_witness_claim`/`verify_witness_claim`,
  `prove_product2_streaming` and the `claim_entries` helper are deleted; the
  binding is now `DynamicClaimBinding { target, columns_root }`.
* The claim column set is built from `claim_interface_into` (operands and
  selectors of every component + PC/next-PC/`one`/PC-correction); result
  columns are not claimed because the verified relation derives them.
* `verify_dynamic_segments_public_point` reconstructs the claim coefficient from
  the commitment and the target stated in the proof; the target itself is only
  accepted by `verify_dynamic_claim_binding`, which derives it from the
  authenticated rows.

### 9.6 The mosaic opening is restored

The dynamic path used to skip `prove_opening`, so `verify_core_statement`
skipped `verify_mosaic` and the access/router claims were never bound to the
mosaic commitment (§9.2). Both are fixed:

* the native profile prover runs the `Opening` stage, and `verify_native_unified`
  rejects a proof without a mosaic opening;
* `verify_core_statement` now also checks `opening.commitment == proof.commitment`
  (the P3 opening carries its own commitment; without the check a proof could
  pair valid claims with an unrelated opening);
* the paper path's committed-Shout ROM claim is folded into the opening before
  it is produced (`add_logup_shout_rom`), and the redundant trace-Logup-Shout
  worker is skipped when the paper Logup is used.

Known remaining gap: `proof.logup_shout` (paper path) is still only used for its
link claims; verifying the Logup-Star proof itself needs the Shout witness, so
the native verifier does not check it. The trace-Logup-Shout variant *is*
checked against the claim-derived witness.

### 9.7 Measured cost (paper benchmark, `WIDTH=64`, `MAGNETAR_PROFILE_VERIFY=1`)

`2^16` (ADDS=65 535, 65 536 rows), full verification including the selected
lockstep proof, the claim binding and the mosaic opening. The claim proof runs
on the main thread; the access statement, the claim-derived trace, the selected
branch and the core branch then run concurrently:

| stage | time | on critical path |
| --- | --- | --- |
| claim proof (decode + leaf hash + tree) | 5.7 ms | yes |
| claim row sums (12 workers) | 7.4 ms | yes (selected branch) |
| claim schema + challenges | 3.1 ms | yes (selected branch) |
| lockstep rounds + segment claims + MLEs + ring-switch PCS | 9.1 ms | yes (selected branch) |
| access statement | 6.7 ms | no (parallel) |
| core (mosaic opening + trace check) | 7.5 ms | no (parallel) |
| **total verify** | **33.8 ms** | 5.7 + 19.6 |

Prover: 154–189 s depending on machine load (peak RSS 7.8 GiB; stage RSS: context
3.3, commit 5.9, access 13.9 s, opening 14.7 s, selected stage 4.5–6.6 GiB;
selected PCS opening 12.1 s after the profile change in §7); proof 1 124 215 B
(varint 974 921, compressed 892 495): access 259 812 B, logup 245 377 B, mosaic
opening 316 049 B, selected 298 559 B.

`2^12` (ADDS=4 095): verify 12.4 ms, prove ~40 s, proof 600 269 B.

Verifier progression at `2^16`: 1.42 s (witness rebuild) → 117.8 ms (unsound,
lockstep skipped) → 54.5 ms (merged claim) → 47.2 ms (critical-path
restructure) → 36.8 ms (allocation-free claim hashing, parallel row decode,
shared row build) → **33.8 ms (8-row claim leaves, shared MLE evaluation)**.
Remaining costs: the claim layer (16.2 ms of per-row work on the critical path)
and the selected lockstep verify (9.1 ms). The paper's 8 ms figure is quoted at
8x the rows.

### 9.9 Statement binding: one vacuous check found and fixed

`claims_to_trace` copies the statement's `config`, `initial_state`,
`final_state`, `rom` and `initial_ram` into the synthetic trace, so the
"claim-derived trace matches the statement" comparison was tautological for all
of them except `trace_len`. A tamper test proved it: flipping
`statement.final_state.pc` was **accepted**. The verifier now checks the
authenticated claim endpoints directly (O(1)) —

* `claims[0].pc == statement.initial_state.pc`,
* `claims[last].next_pc == statement.final_state.pc`,

with the pc chain itself enforced by the selected lockstep and the claims bound
to the witness by the claim target. `rom` stays bound through the trace
Logup-Shout table (which is built from `statement.rom`) and `initial_ram` through
the twist witness rebuild. All four tampers (initial pc, final pc, rom,
initial_ram) are now rejected and the valid proof still verifies; the full
suites pass.

### 9.8 What a polylog trace Logup-Shout verifier needs

The trace Logup-Shout verifier is the last per-column O(cycles) stage
(§7 round 9). It recomputes three things from the claim-derived trace:

1. `reader_claims` — `ROM[column][position_i]` folded at `reader_point`, one MLE
   per ROM column (12 at RV64);
2. `link_claims` — the 12 per-cycle link columns (address bits, `is_32`, ROM
   index bits) folded at the same point;
3. `position_claim` — the per-cycle ROM position `embed(position_i)` folded at
   `output.position_point`.

The Logup* proof already carries `column_claims`, `position_claims` and the
fractional-GKR pushforwards. What is missing for a witness-free verifier is the
binding of (1)–(3) to *committed* columns: keep the pushforwards in the proof
(pushforward length is `2^address_bits`, i.e. kilobytes), open the position and
reader columns at the two points through the packed ring-switch backend used by
the selected witness / E5 path, check `column_claims` against the public ROM
(O(rom), already the case), and the stage becomes O(columns + log) per verify.

The columns are cheap to commit: 25 boolean columns of `cycles` bits are
`cycles · 25 / 8` bytes — 200 KB at `2^16`, 12.8 MB at `2^22` — before the
commitment's rate expansion, and they fit the existing `PackedMosaic` +
`RingSwitchPackedBitPcs` machinery.

**This is only sound if the committed columns are tied to the authenticated
trace.** Committing them on their own lets a prover pick any positions that
satisfy the Logup with the public ROM. The position and link columns must be
shown to equal the claim layer's per-row values (the address bits, `is_32` and
ROM index bits are claim fields), i.e. the claim table must itself be committed
and openable at a point — the same structural item as task #7. Implementing the
packed Logup columns before that would produce a fast but unsound verifier,
which is why it is not done here.

### 9.10 Register-twist Access stage: the PCS, not the sum-check

The register twist is the largest single sub-proof of the Access layer
(`2^16` rows → `2^17` cycles → `32 × 2^17 = 2^22` field elements). Adding
`MAGNETAR_PROFILE_LOCAL=1` to `prove_local_shared` produced this split at
`2^16` (load ~80):

| Stage | Before | After |
| --- | --- | --- |
| tables (`build_columns`, dense one-hot, val table) | 0.27 s | 0.09 s |
| PCS commit | 11.06 s | **0.49 s** |
| RW + Val + Virtual sum-checks | 0.62 + 0.16 + 0.52 s | 0.20 + 0.09 + 0.25 s |
| value claims | 0.02 s | 0.01 s |
| PCS opening (main table) | 23.21 s | **0.18–0.24 s** |
| endpoint commit + opening (2 × 32 rows) | 11.60 s | **0.003 s** |
| final rounds | 0.47 s | 0.10 s |
| **total** | **48.2 s (load 80)** | **1.43–1.55 s (load 90)** |

Five changes, in decreasing order of effect:

1. **Endpoint tables use the small-table PCS profile.** `linear_pcs(cells)`
   (32 rows → `P3BinaryPcs::new(100)`) instead of the cycle-table profile.
   The endpoint table is two columns of 32 rows (a 6-variable stacked
   polynomial): its domain reaches the 100-bit target with a short query
   schedule, so the 24 grinding bits of the cycle-table profile bought nothing
   and accounted for 11.6 s of the proof. The verifier derives the same profile
   from the shape, so the proof carries no extra parameters.
2. **One encode per commitment.** `open_batch` re-encodes and re-hashes the
   table to rebuild the opening (it cannot see the earlier commitment). The new
   `P3BinaryPcs::commit_batch_prepared` / `open_batch_prepared` pair keeps the
   `BinaryPcsProverData` and the post-commit challenger, so the Fiat–Shamir
   order (commit → sample points → open) still holds and the opening reuses the
   codeword and Merkle tree. Opening drops from 10.0 s (after change 3) to
   1.9 s; the commitment and transcript are identical to the old path.
3. **Local PCS profile `(100, 4, 24, 3)` → `(100, 3, 20, 3)`**, matching the
   selected PCS (rate 1/8, 20 grinding bits, 8-way folding, 100-bit security).
   Commit 11.1 → 6.3 s, opening 23.2 → 10.0 s; the local opening grows the
   proof by 16.4 KB.
4. **Vendored p3 parallelism.** `p3-binary-pcs` and `p3-merkle-tree` now carry
   their `parallel` feature (rayon is already in the tree through ligerito), so
   codeword encoding and Merkle hashing use all cores. Commit 5.4 → 3.6 s. This
   also covers the selected and mosaic `P3BinaryPcs` instances. The feature also
   turns on p3's *parallel grinding*, which returned an arbitrary passing nonce
   and made proof bytes vary run to run (and even the proof length, because a
   trivial fold can omit a root); the three byte-equality tests caught it.
   `BinaryChallenger::grind` in `vendor/plonky3/binary-field` now scans the
   candidates in fixed-size waves and returns the smallest passing candidate of
   the first wave that has one — exactly what the serial path returns, on every
   machine — while each wave is still split across the rayon pool.
5. **Fused index-wise sum-check** (`sumcheck_terms_indexed`,
   `fixed_sumcheck_indexed`). The old loop materialised `degree + 1` full copies
   of every factor per round (four threads × five 4.2 M-element factors = 1.3 GB
   of transients at the first round); the new one evaluates the summand from the
   factor pairs at each index and folds the factors in place. It is
   bit-identical to `sumcheck_terms` (asserted in `indexed_sumcheck_matches_reference`
   and `indexed_fixed_sumcheck_matches_reference`, including the folded
   factors), and cuts the register-twist peak RSS from 1.72 GiB to 1.33 GiB.
   The sum-check was never the bottleneck: 1.8 s of 48 s.

Measured A/B (`local_shared_bench`, `ROWS=65536`), same host, interleaved:

| Binary | prove | user CPU | peak RSS | load |
| --- | --- | --- | --- | --- |
| before (24-bit profile) | 41.1 s / 50.5 s | 27.8 / 28.4 s | 1.72 / 1.34 GiB | 65 / 50 |
| after sum-check fusion only | 39.2 s / 40.3 s | 28.2 / 28.1 s | 1.33 / 1.18 GiB | 62 / 70 |
| after the PCS changes (no p3 parallelism) | 9.0 s | — | — | 50 |
| final (all five, parallel + deterministic grind) | **1.43 s / 1.55 s** | 8.1 / 8.0 s | 1.43 GiB | 90 / 92 |

The host was shared and noisy throughout (1-minute load 50–767 on 12 cores), so
only the ratios are meaningful: the register-twist proof is **30× faster**,
verifies in **3.7 ms**, and the five changes remove 11.5 s of grinding, 22 s
of opening and 10.6 s of commit while cutting the peak RSS by 17 % (1.72 →
1.43 GiB; the serial path at 1.34 GiB was the fusion-only build). Proof bytes
are back to 219,208 — the same as the serial-grind build, which is the
determinism check. The full `2^16` benchmark with these changes is pending a
quiet host; the stage profile above is measured end-to-end through
`prove_local_shared`+`verify_local_shared`.

Two caveats. The parallel p3 paths also serve the selected and mosaic PCS, so
the selected commit/open and the mosaic opening should shrink on their own, but
that is unmeasured. And parallel encoding allocates per-thread buffers; the
`2^16` register-twist peak moved 1.33 → 1.43 GiB, and the `2^17`–`2^19`
staircase rows predate the feature, so their peaks and times need re-measuring
before the scale model is quoted again. The remaining prover cost is
`selected product6`/`product2` (§6 stage profile): product6 scans
`level × rows` (`9 × 2^30` at `2^16`) because the level store is capped at
`2^22` entries (402 MiB), and product2 folds the column space; both are at the
memory/budget floor chosen in §3, not at a copy or parallelisation defect.

With `MAGNETAR_PROFILE_VERIFY=1` the verifier at `2^16` now reports
**30.3 ms per verification, 31.6 ms/iter wall over 5 iterations, 188.0 ms/iter
CPU** (load 72–83), split as:

| Stage | Time |
| --- | --- |
| trace Logup-Shout (now starts with the trace, overlaps both waves) | 21.9–29.6 ms |
| — Shout witness build (`from_trace`) | 7.5–10.0 ms (contends with wave 1) |
| — reader + link claims (12 + 12 cols x 65536 rows) | 3.0 ms |
| — columns + positions / reduction / final claims | 2.5 / 2.4 / 2.5 ms |
| claim row sums (wave 1, 12 workers x 65536 rows) | 11.5–12.4 ms |
| core proof (mosaic PCS verify + eval_mles) | 7.9 ms |
| access | 6.7 ms |
| claim leaves / decode / claims-to-trace | 3.8 / 1.1 / 0.8 ms |

The trace Logup-Shout check now starts as soon as the claim-derived trace
exists and overlaps both waves; its own wall stretches to 21.9–29.6 ms when it
shares cores with the claim sums, so the wall gain is contention-limited
(34.3 → 30.3 ms with CPU 193.3 → 188.0). Every remaining term is `O(rows)` and
the structure that would make them polylog is the committed-claim-columns item
in §9.8; the wall figure is down from 60.9–84.3 ms two rounds ago.

The selected opening had the same kind of defect one level down. Under
`MAGNETAR_PROFILE_RING=1` it split as `ring pack 1.8 ms, ring eval 2.89 s,
ring product2 0.15 s, ring p3 open 0.63 s`; `ring eval` was dominated by
`eq_vector`, which built one `Vec` per table entry (4.2 M heap allocations at
`2^16`: `2^22` packed words) and by a 128-way bit test per packed word. The table now uses the
level-by-level doubling construction (same values, pinned by
`eq_vector_matches_pointwise_eq`) and the per-slot sums iterate the set bits of
each word across workers (XOR reduction, so the result is exact). `ring eval`
falls to **0.13 s**, `selected open` from 3.68 s to **0.91 s**, and the `2^16`
prove from 84.2 s to **79.2 s** with byte-identical proofs (861,407 B).

The outer sum-check's inner loop had the same shape: for every row it
materialised the six slot values and then applied the weight with two
comparisons per slot. `LockstepRows::accumulate_row_values` now folds the weight
into the sparse CSR scan — each set entry adds `weight x coefficient`, with the
`coefficient == 1` fast path — which is bit-identical by distributivity
(`w(c1 + c2) = w c1 + w c2` in the tower field, and the slot sums are XOR).
`product6` falls from 51.8 s to **43.2 s** and the `2^16` prove from 79.2 s to
**70.4 s**, with byte-identical proofs. The same fusion for the inner
(`product2`) sum-check changed the proof bytes and was reverted rather than kept
half-verified. What the bisect established: fusing only the **right** (bit) side
is byte-identical, so the divergence is on the **left** input (`fill_left`),
which also folds sparse claim deltas (`claim_columns` +
`claim_instance_weight`) into each window. A fused version replaying those deltas
separately still diverged, and a per-window self-check against `fill_left` did
not isolate the remaining difference before the attempt was abandoned. The lead
is worth about 3 s at most: an interleaved A/B of the right-side fusion at
`2^14` (the untouched `product6` stage swung 15.1–20.1 s across the same runs)
measured `product2` 7.4–8.6 s before and 8.85–8.99 s after, i.e. no gain that
this host can resolve, so it was not kept either. A quiet-host A/B is needed
before spending more time here.

Inside the full pipeline the same stage now reads `access register claims:
2.53 s` and the selected witness setup `setup fill+check: 0.48 s`. The earlier
`160.7 s` for that setup was almost entirely the pre-existing per-cycle
`eprintln!` checkpoint plus a serial fill; the fill now splits the cycles
across workers, each writing its own `base_cols`-bit word range, and packs 64
block bits per word store. `RAYON_NUM_THREADS=1` versus `12` on the `2^14`
pipeline peaks at 1.10 GiB either way, so the p3 parallel features do not
inflate the peak (`2^16` measures 2.26 GiB, inside the 2.01–2.61 GiB range
recorded in §6).

### 9.11 Width-64 tests and an E5 PCS-profile bug

The suite now runs the RV64 width on every path that exercises the pipeline:
the testkit integration tests (`e2e`, `paper_mode`, `native_trace_mode`,
`logup_shout_mixed`), the `protocol_determinism` example, and the runtime's
whole-VM proof tests (unified/paper/dynamic, chunked, trace, selected claims,
virtual CPU, claim-native, cpu-shape, gated, orchestrator). `protocol_determinism`
runs 120 concurrent prove/verify pairs at width 64 with zero byte mismatches,
which also exercises the parallel grinding determinism of §9.10.

The conversion exposed a **pre-existing completeness bug on the RV64 path**.
`UnifiedProveContext` chose its mosaic PCS profile with
`opening_pcs(&mosaic_tables)` *before* appending the gated
component/shift/active tables. When one of those later tables is the largest —
as it is at width 64 with a small trace — the prover opened the commitment with
the small-table profile (rate 1/8, 24 grinding bits) while the verifier derived
the large-table profile from the commitment (rate 1/4, 21 bits), so every
field-subset opening was rejected with `field opening rejected`. Width 8 hid
this because no table crossed the threshold. The fix moves the profile choice
after the last push, so prover and verifier derive it from the same table set.
The failure reproduces with p3 parallelism disabled, so it is independent of
§9.10's changes; instrumentation confirmed the field points and values were
identical on both sides and only the PCS profile differed.

Two further width-64 defects surfaced and are fixed. The AMO add and logic
rows computed their word mask as `(1u64 << width) - 1`; at width 64 that shift
wraps (`1u64 << 64` evaluates to 1 in release builds), the mask becomes zero,
and the batch sum-check's claimed sum disagrees with the verifier
(`sumcheck claim mismatch ... expected 0`). `pc_target_row` and
`pc_transition_row` carried the same wrap for the masked target/next value.
All four now special-case width 64 (`u64::MAX`), as `amo_minmax_row` and
`mul_row` already did.

Converting the benchmarks also exposed a pre-existing **completeness bug** in
`prove_gated_bundle_from_trace`: it derived the PC-chain target as
`last_row.pc + 4`, but `gated_rows_from_trace` appends a halt row at the final
PC, so a trace ending on a self-looping `ecall` overshot and the PC sum-check
could never vanish (it panicked at width 8, 32 and 64). The target is now the
last executed row's `next_pc`, which is right for a full trace, a halt row and
a chunk alike; `gated_trace_bundle_m4_m5_bench` proves and verifies at width 64
(M5 ring: 1.95 s prove, 165 ms verify, 255,787 B).

With those fixes every test and example that exercises the pipeline runs at
width 64 (the 16 testkit examples that still proved at width 8 — chunked,
dynamic, gated-bundle, claim-native, selected and unified with their
`WIDTH`-less defaults — were converted too; all of them compile and run at 64).
The only remaining width-8 call sites are unit tests whose *subject* is 8-bit
arithmetic (`0xff` wrap, `Sra(248, 1)`, the 8-bit split/shift relations, the
`u8`/`i8` proptests): 21 in `magnetar-cpu`, 19 dynamic-row tests in `simd_dual`,
11 shift/ALU relation tests in `simd_f2`, and 12 in the per-row modules. They
construct 8-bit words to test the arithmetic, not the prover; every test and
example that runs a proof now uses width 64. A
new `magnetar-pcs` regression test
(`mosaic_opens_a_twelve_column_table_with_repeated_points`) pins that the
mosaic opener supports the shapes the field opening produces.

## 10. Reproduction

```bash
# Selected stage only (the staircase above)
WIDTH=64 ADDS=65535 MAGNETAR_PROFILE_SELECTED=1 \
  cargo run --release --offline -p magnetar-testkit --example selected_stream_probe

# Byte-equivalence with the eager prover
cargo test --release --offline -p magnetar-runtime --lib streaming_lockstep_proof_matches

# Full pipeline (bounded by the unified CPU commit, see §6)
/usr/bin/time -l env WIDTH=64 ADDS=65535 MAGNETAR_PROFILE_UNIFIED=1 \
  cargo run --release --offline -p magnetar-testkit --example paper_unified_bench
```

## 11. RV64 `2^16` optimization round (2026-11-03)

Status: landed on top of the streaming prover above; the streaming/eager byte
equality gate stays green. Branch `virtual-claims-rewrite`.

### 11.1 Headline

| | before round (§1) | after round |
| --- | --- | --- |
| prove wall | 70.4 s | **53.8–59.3 s** (host load 14–72) |
| prove CPU (user+sys) | ≈800 s | **421.6–434.9 s** |
| verify wall | 29.6 ms | **27.4 ms** with the claim table, **46.0 ms** on the legacy row path (§11.6) |
| peak RSS | 2.26 GiB | **2.38 GiB** (claim table on; 2.19 GiB with it off) |
| proof bytes | 861,407 B | **1,018,152 B** (claim-table format, §11.6) |

The claim table is now the default: on the same `2^16` binary it replaces the
`O(rows)` claim row sums and moves verify from 46.0 to 27.4 ms for +157 KB of
proof -- the 2^10 measurement that had called it a net loss (+1.4 ms) simply
saw the fixed PCS cost at a size where the row sums are free.

Wall-clock times on this host are not comparable across sessions: the 1-minute
load moved between 13 and 150 during the round and the same binary reported a
2.4x spread. The load-robust number is the prover CPU time: the same 2^16 run
now costs **421.6–434.9 s of CPU against ≈800 s**, i.e. about **1.8x less work**
(kept honest by the stage-level A/B below, which uses the same-binary
environment switches described in §11.4).

### 11.2 Stage split (load 37–72)

| stage | before (§2) | after |
| --- | --- | --- |
| unified context | 0.48 s | **0.31 s** |
| unified Commit | 1.19 s | **0.52 s** |
| unified Access (register twist) | 2.56 s | 2.63 s |
| unified Opening | 3.38 s | **1.99 s** |
| selected setup | 0.48 s | 0.40 s (`setup fill+check`) |
| selected witness commit | 0.95 s | **0.32 s** |
| `product6` (outer scan) | 43.2 s | **24.5 s** (probe run: 24.5 s at load 74; 27.2 s inside the full pipeline) |
| `product2` (inner scan) | 23.4 s | **24.5 s** before item 8's chunked fill, which halves the stage CPU again (§11.3 item 8) |
| selected segments | 1.17 s | **0.009 s** (rewritten, §11.3 item 7) |
| selected open | 0.92 s | **0.84 s** |

The two streaming products still dominate, but the outer scan is no longer the
single biggest term. The peripheral stages also improved through a teammate's
p3 hash fix (§11.5): `Commit` and `Opening` roughly halved.

### 11.3 What changed

1. **Zero-padding rows are no longer scanned** (`LockstepRows::live_rows`,
   `prove_product6_rows`). `SharedBlockMatrix` rounds its row count up to a
   power of two; at RV64 `2^16` that padding is 49.6 % of `rows`
   (`2^29` instance rows + 4,194,368 extras pad to `2^30`). Rows past
   `instance_rows + extra_rows` evaluate to zero for all six slots, and a
   fully padded block contributes `product6_pair(0, 0, ..) = 0` for any
   equality weight, so every phase-1 pass stops at the last live block. The
   phase-2 fold carries the short (live) length: it is a prefix of the
   conceptual array and an out-of-range odd entry is zero, while the equality
   values stay at full length (the boundary element is folded with them in
   later rounds -- getting that wrong was the one bug found here, and the byte
   equality gate caught it).
   Same-binary A/B at `2^14` (`MAGNETAR_LIVE_FULL=1` disables the skip):
   product6 **12.8 s → 6.5 s**, whole prove CPU 166 s → 101 s.
2. **Branch-free set-bit accumulation** (`accumulate_row_words`). The scan is a
   sparse CSR walk over ~3.7 entries per row whose only unpredictable branch was
   `if bit { add }`. It is now one word load plus a 0/all-ones mask and a masked
   XOR, so the ~50 % mispredict disappears. Bit-identical by construction.
3. **Work-stealing round scheduling** (`parallel_chunks`). This host is 6
   performance + 6 efficiency cores, so a fixed split leaves the efficiency
   cores straggling (up to 1.3x round time); workers now claim chunks from a
   shared counter. Because field addition is XOR, the partial sums are folded
   independently of who processed what, so proof bytes do not change.
4. **Inner level budget 22 → 24** (`auto_level_inner`). The inner (column)
   sum-check recomputed `column_bits - (budget - 1)` rounds from the witness;
   two more bits of level array cost a fixed `2^24 * 16 B * 2 = 512 MiB` and
   remove two of eight full column scans at `2^16` (-25 % of the inner stage,
   -0.5 GiB difference in peak). `MAGNETAR_INNER_BUDGET_LOG` overrides.
5. **Load-robust measurement**: every gated stage print now reports cumulative
   process CPU time (`magnetar_proof::process_cpu_seconds`, `getrusage`), and
   the streaming stages have same-binary diagnostic switches
   (`MAGNETAR_STREAM_WORKERS`, `MAGNETAR_LIVE_FULL`, `MAGNETAR_P2_FUSED`,
   `MAGNETAR_INNER_BUDGET_LOG`). This is what makes the A/B above trustworthy
   on a shared machine.
6. **Memory watchdog for benchmarks** (`magnetar_testkit::install_memory_watchdog`,
   `MAGNETAR_MAX_RSS_GIB`, default 4 GiB): every example that runs a proof
   aborts before it can push the host into swap. `protocol_determinism` now
   defaults to 2 threads x 10 rounds (20 pairs) instead of 120 concurrent pairs
   -- the old default peaked at 5.75 GiB, the new default 1.99 GiB.

7. **Segment claims rewritten** (`split_segment_claims_bits`): the per-segment
   reference evaluator rebuilt an equality tensor for every segment, read the
   witness bit by bit, and ran single-threaded. A per-width shared equality
   tensor, 64-bit word scanning over the set-bit iterator (same accumulation
   order) and one thread per segment (results collected in layout order) take
   `selected segments` from 298/304 ms to 3.1/2.6 ms at `2^14` and from 1.20 s
   to **9 ms** at `2^16`. Claims are bit-identical to the reference evaluator
   (`split_bits_claims_match_the_reference_evaluator`), the streaming/eager
   proof bytes are unchanged (859,845 B at `2^14`), and the stage sits in the
   serial tail, so the ~1.19 s at `2^16` is wall-clock.
8. **Inner scan fills 512-column chunks** (`prove_product2_columns`). The
   materialise-and-accumulate block loop called `fill_left` once per sum-check
   block, and that call carries per-block bookkeeping (instance bounds, the
   claim-window binary search, the extras touch test) that costs more than the
   two columns of the first round. Filling 512 columns per call amortises it
   ~256x in round 0 while keeping the exact per-column arithmetic order, so
   proof bytes do not change (`MAGNETAR_P2_BLOCKWISE=1` restores the per-block
   fill for A/B). Interleaved same-binary A/B at `2^14`: `product2`
   12.4/17.0 s -> **5.1/5.5 s** wall and whole-run CPU 103 -> 74 s; at `2^16`
   the inner recompute drops from 226 to **108 CPU-s (-52 %)**, i.e. `product2`
   should fall from 24.5 to ~12 s on a quiet host (the 2^16 wall could not be
   re-measured: the host was giving the process ~2.8 of 12 cores during the
   run, so only CPU is comparable).

Peripheral stages (teammate track, same tree): `Keccak256Hash16` in the
vendored p3 code did not forward `hash_many`, so the Merkle trees fell back to
serial hashing; forwarding it batches the leaves and cut p3 CPU 2.1–2.7x
(selected 2.4x, mosaic 2.7x, local 2.1x). Removing the prepared-data deep
clone in `open_batch_prepared` (-0.5 GiB memcpy at `2^16`), a single table
conversion in `P3BinaryPcs::commit/open`, deduplicated register-access table
construction (Access standalone 7.6 -> 5.0 CPU-s), and skipping the
reservation-row build when the context has no CPU columns complete the set.

### 11.4 Measurement method on a shared host

- **Wall clock is unreliable here**: the same binary measured 18.5 s and 55 s
  for the same `2^14` prove depending on the load; the load average moved
  13 -> 150 within minutes. Two earlier rounds (§9.10) concluded "inner fusion
  is neutral / worth <=3 s" from wall-clock A/Bs that this round shows were
  inside the noise.
- **Use CPU time** (`cpu=` in the profiles, `getrusage`): it is stable to a few
  percent under load because it counts the work, not the waiting.
- **Use same-binary switches** for attribution: rebuilding two binaries brings
  every other in-flight tree change into the comparison.
- The byte-equality gates are the correctness check, not the timing:
  `streaming_lockstep_proof_matches_the_eager_proof_bytes` and
  `parallel_chunked_streaming_matches_sequential` are green with the new scan.

### 11.5 What did not work

- **A fused/hoisted inner block loop** (`ColumnRows::block_values`): hoisting
  `instance_weight` out of the per-column loop and fusing fill+accumulate saves
  one `F2_128` multiply per column but adds per-block claim/extras/binary-search
  overhead. Same-binary A/B at `2^14`: **9.1 CPU-s vs 6.3 CPU-s, i.e. 35 %
  slower**. Kept behind `MAGNETAR_P2_FUSED` for a host with different cache
  behaviour; the default stays on the materialise-and-accumulate loop.
- **Hoisted sum-check evaluation** in the register-twist Access stage: the
  repeated factor loads are absorbed by cache/LLVM; measured 0 % on CPU time,
  reverted.
- Work stealing is kept for robustness but its size could not be isolated on
  this host: the wall-clock spread of two identical runs is larger than the
  expected 10–30 %.

### 11.6 Proof bytes and the claim layer

The proof grew from 861,407 B to **1,018,152 B** (varint 829,741 B,
compressed 667,089 B). That is not from the prover work above: it is the
in-progress polylog claim layer (docs/POLYLOG_CLAIM_VERIFIER.md), which commits
the claim table as packed bit columns and attaches the commitment/opening to
`ClaimProof`. The claim table PCS uses rate 1/8
(`P3BinaryPcs::with_params(100, 3, 20, 3)`); at rate 1/2 the same proof was
1,136,696 B with the same verify time, so rate 1/8 is the shipped profile. The
row-based blob is still present during the transition, so both encodings are
carried (`MAGNETAR_CLAIM_TABLE=0` reverts to it); removing it is the next
structural step (M4/M5), after which the proof comes back below the old size.
The streaming/eager byte equality gate still passes, so the prover change
itself is byte-neutral.

Measured on one `2^16` binary, interleaved within a minute:

| claim table | verify | proof | peak |
| --- | --- | --- | --- |
| off (legacy row sums) | 45.97 ms | 861,408 B | 2.19 GiB |
| on, rate 1/8 (default) | **27.38 ms** | 1,018,152 B | 2.38 GiB |

### 11.7 Next

1. **Inner stage** is now the largest single term (24.5 s). The cheap levers
   left are: amortise `fill_left`'s per-block overhead by filling larger
   column chunks per block (the measured per-block cost at round 0 dominates),
   and re-check the level budget trade on a quiet host.
2. **Outer scan** (24.5 s): 3.7 entries per row stay the floor of this
   formulation; the remaining ideas are a tighter CSR layout
   (`(word, shift, slot, coefficient)` packed into 16 B) and prefetching the
   bit window.
3. **Claim layer**: finish M4/M5 so the claim table replaces the row blob
   (proof back below 861 KB and the verifier's O(rows) claim/Logup work gone).
4. Refresh the 2^17/2^18/2^19 staircase only with the memory watchdog and one
   run at a time; the host's free memory has been under 1.5 GiB during this
   round.
