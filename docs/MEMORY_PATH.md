# Memory path: RV64 `2^16` peak and the route to `2^22`

Source: code reading plus the committed measurements in
[STREAMING_SELECTED_PROVER_RESULTS.md](STREAMING_SELECTED_PROVER_RESULTS.md) §3/§6
and [HANDOFF.md](HANDOFF.md). Nothing here was measured for this note.
`2^16` means `cycles = 2^16 = 65536`, witness bits `8192·cycles = 2^29` (`64 MiB`
packed), `cols = 2^29`, `rows = 2^30`.

**Headline.** The `2^16` peak (1.94-2.01 GiB, Part 1 close) is *not* the level
stores and *not* the witness: it is two PCS codeword+Merkle transients
(selected 0.37 GiB, mosaic 0.56 GiB) plus the selected prover's level stores (≤0.8 GiB)
plus a resident context (~0.35 GiB) that overlap in the same process. At `2^22`
the same terms project to **60-90 GiB**, and a hard lower bound is **≥37 GiB**
because a rate-1/4 mosaic codeword (16 GiB) and its Merkle tree (16 GiB) are
simultaneously live inside one commit/opening. The `≈20 GiB` projection in
results §6 is an extrapolation artifact (see §3). Packing wins exist, but the
paper's 6.4 GiB envelope needs more than packing (§4-§5).

## 1. Where the `2^16` peak comes from

Two provers run in one process: the selected lockstep prover on its own thread
(witness commit, then `product6`/`product2`) and the unified main thread
(context, mosaic Commit, Access, Opening). The commit gate serializes the two
*witness commits*; Access and Opening then overlap the selected products, so the
selected level stores are live at the peak. `C` = cycles below.

| term | formula | `2^16` | scales | `2^22` |
| --- | --- | --- | --- | --- |
| packed witness (`PackedBits`) | `1024·C` B (1 KiB/cycle) | 64 MiB | linear | 4 GiB |
| mosaic table cells (resident) | `16·T`, `T ≈ 35·C` | 37 MiB (`T≈2.29 M`) | linear | 2.3 GiB (`T≈146.8 M`) |
| selected PCS commit transient | `S = 64·C` fields, `H = 2S` (rate 1/2, `protocol.rs:1655`); `32B·H` leaves+tree + `16S` layout + `16S` packed copy | 0.37 GiB (256+64+64 MiB) | linear | 24 GiB |
| mosaic PCS commit/opening transient | `P = next_pow2(35·C)`, `H = 4P` (rate 1/4, `protocol.rs:1568`); `32B·H` leaves+tree + `16·P` layout/encode buffer; opening reuses the committed batch and adds small fold commitments | 0.56 GiB (`P=2^22`, 512+64 MiB) | linear, stepwise | 36 GiB (`P=2^28`) |
| outer level store | `2^(budget-1)` entries × 96 B, budget 22 (`stream.rs:184`) | 192 MiB | **fixed** | 192 MiB |
| inner level stores (left+right) | `2·2^24` entries × 16 B, budget 24 (`stream.rs:200`) | 512 MiB | **fixed** | 512 MiB |
| context (resident) | measured 0.31-0.45 GiB; modelled 5-7 KiB/cycle (§1.1) | ~0.35 GiB | linear | 20-30 GiB |
| claim table | `slots·C` bits + ring-switch commit transient | ≲2 MiB | linear, tiny | ≲0.2 GiB |
| grind / challenger / round buffers | — | <1 MiB | fixed | <1 MiB |

The mosaic term is a *commit* peak and an *opening* peak: at commit the
encoder buffer becomes the leaf matrix, so codeword + tree + layout are live
together (0.56 GiB); at opening the committed batch stays live (0.5 GiB for
codeword + tree) while the folding rounds commit their own small codewords
(~0.07 GiB at 8-way folding), i.e. about the same 0.56 GiB.

Reconciliation at `2^16` (peak = Opening): mosaic committed data + fold
commitments 0.56 + selected outer-phase level arrays 0.33 + context 0.35 +
packed witness 0.06 ≈ 1.3 GiB live. Measured 1.94-2.01 GiB is 0.6-0.7 GiB
higher because freed pages are not returned to the OS: the selected-witness
commit transient (0.37 GiB) and the Access working set are freed before
Opening but still counted in RSS, so the high-water mark behaves like a *sum*
of consecutive transients rather than their maximum (results §3). That is also
why the peak is reached at Opening: it is the last big transient, and it lands
on the accumulated RSS of the earlier ones.

### 1.1 The context term is linear and large

Measured 0.31-0.45 GiB at `2^16`; it scales with `cycles`, not with the number
of tables. In the paper bench the RAM twist is trivial (~2 cycles, no memory
events), so the linear part is the register twist: its `BinaryTwistWitness`
holds `read_address`, `write_address` and `value` as `cycles × 32` field
elements (~1.5 KiB/cycle); `batch_tables` materialises boolean columns of
`cycles` rows (64 read-value bits, 64 write-value bits, address bits, scalar
columns — ~2.5 KiB/cycle); `mosaic_tables` then clones the 27-column register
table set into the opening tables (~0.4 KiB/cycle duplicated); trace/ROM/
router/shout witnesses add ~0.3-0.5 KiB/cycle. Sum ≈ 5-7 KiB/cycle ⇒ **20-30
GiB at `2^22`** (the upper end includes allocator slack). A real RV64 workload
adds `O(cycles)` RAM events — see §3's caveat.

## 2. What the level stores are *not*

Both stores are fixed at every scale because the auto level tracks `log(rows)`:
outer entries = `2·live/2^level` and `level = log_rows − 21`, with
`live ≈ rows/2` after the zero-padding skip, so entries = `2^21` regardless of
`cycles`; inner entries = `2·cols/2^level_inner` = `2^24` regardless of `cycles`
(`stream.rs:184`/`:200`). Note the `402 MiB` outer figure in results §3 predates
the padding skip (it used `rows`, not `live_rows`); the shipped number is
`2^21·96 B = 192 MiB`. The outer and inner stores belong to the selected
streaming prover and are used sequentially (outer phase, then inner), so the
live footprint is ≤0.8 GiB (192 MiB outer store + its 128 MiB phase-2 arrays, or
512 MiB inner stores + their shrinking fold arrays); the main thread never
allocates stream level stores. At `2^22` that is 1-2 % of the projected peak:
keeping or halving the level stores cannot move the envelope.

## 3. `2^22` projection, and why `≈20 GiB` is wrong

Bottom-up (§1 formulas, `C = 2^22`):

| term | `2^22` |
| --- | --- |
| packed witness | 4 GiB |
| mosaic table cells | 2.3 GiB |
| mosaic commit/opening transient (`P = 2^28`, `H = 2^30`) | **36 GiB** |
| selected commit transient (`S = 2^28`, `H = 2^29`) | **24 GiB** |
| level stores (selected prover) | 0.7-0.8 GiB |
| context | 20-30 GiB |
| claim table, buffers | ≲0.2 GiB |

Concurrent-live peak at Opening ≈ 36 + 0.8 + 4 + 20-30 + 2.3 ≈ **63-73 GiB**;
if the selected-commit pages are still resident, add up to 24 GiB ⇒ **70-95
GiB**. A model-free lower bound: `MerkleTree` retains the leaf matrix
(`vendor/plonky3/merkle-tree/src/merkle_tree.rs:30`) and the digest layers, so
during one mosaic commit/opening the codeword (16 GiB) and its tree (16 GiB)
are simultaneously live; with rate 1/4 and `P = 2^28` that is **≥32 GiB**, i.e.
**≥37 GiB even if context and every other transient were free**.

The `≈20 GiB` figure comes from a straight-line fit through the measured
staircase (`2^16…2^19` = 2.32/4.74/7.73/10.54 GiB, deltas 2.42/2.99/3.05 GiB
per doubling). Every large term above is proportional to `cycles`, so its
increment *doubles* per step; the near-constant measured delta is allocator
reuse of freed blocks, which cannot continue once a single simultaneously-live
object (the mosaic codeword+tree) exceeds the recycled pool. Summing the
model's doubling increments from `2^19` gives ≈60-90 GiB. The earlier 55-60 GiB
estimate was closer; results §6's `≈20 GiB` (and its `2^(N+10)`/`2^(N+11)`
shorthand for the mosaic, which understates the leaves 4× because `T/C ≈ 35`
and `P` rounds up to `2^28` at `2^22`) should be corrected.

Caveat: `T/C ≈ 35` is for the paper bench (`ram_size = 0x100`, so the RAM twist
has ~2 cycles and the tables are almost all register-twist + trace). A real
RV64 workload has `O(cycles)` RAM events and adds ~4 KiB/cycle of context
(witness + batch tables): **+17 GiB at `2^22`**.


**Reporting metric (added 2026-11-03 after the RSS/footprint finding):** every
peak must be quoted as **both** RSS (`/usr/bin/time -l`, `ps rss`, the
`peak_rss_bytes` helper) and `phys_footprint`
(`proc_pid_rusage(RUSAGE_INFO_V4)`). On macOS libmalloc's large zone frees by
`MADV_FREE_REUSABLE`, so a freed block stays in `resident_size` but drops out of
`phys_footprint`; the "freed pages are not returned" effect in results §3 is a
RSS-accounting fact, not necessarily real memory pressure. The current 2^16
figure (1.94-2.01 GiB RSS) may therefore overstate the true pressure, and the
allocator-release experiment only counts as a real win if RSS drops >=5 % while
`phys_footprint` does not rise. The >=37 GiB floor and the 60-90 GiB model are
unaffected: live codewords and Merkle trees are not reusable pages.

### 3.1 Verifying the projection before building on it

The model is falsifiable at `2^20`, not at `2^22`:

| model | predicted `2^20` peak |
| --- | --- |
| component model of §1/§3 (Opening live 17-19 GiB + retained selected-commit ~6 GiB) | **20-24 GiB** |
| straight-line extrapolation behind `≈20 GiB @2^22` (≈3 GiB per doubling from 8.87 GiB at `2^19`) | **14-15 GiB** |

One clean `2^20` run decides it: `≥17 GiB` validates §3 as written (`2^22` ≈
60-90 GiB); `≈14 GiB` means allocator reuse does more work than modelled and
the `2^22` upper range must come down (to roughly 45-60 GiB). `2^21` (~35-40
GiB of live data) must **not** be run on this 36 GiB host, even with swap; the
largest safe point is `2^20`, and `2^19` (8.87 GiB, already measured) is the
lower anchor for the refit.

Protocol for the `2^20` window:

* **Window sizing.** `2^20` prove CPU is ≈4× the `2^19` run (668 s wall at load
  37-118); reserve a 10-15 min wall window on an otherwise idle host for one
  cold-process run, ×2 for a median. All other agents stop heavy work for the
  duration: one heavy task group-wide.
* **Swap gate.** Before starting, require `free + inactive ≥ predicted peak +
  4 GiB` (≈28 GiB for `2^20`) and `vm.swapusage` free ≥8 GiB; otherwise take
  the fallback below instead of risking a thrash.
* **Bounded abort, not hope.** Set `MAGNETAR_MAX_RSS_GIB` to predicted peak +2,
  so a wrong model aborts the run instead of driving the host into swap; discard
  any run whose `maximum resident set size` lands within 1 GiB of the watchdog
  (truncated). Never run two scales concurrently.
* **Stage attribution.** Reuse the existing RSS prints (`MAGNETAR_PROFILE_UNIFIED`
  / `MAGNETAR_PROFILE_SELECTED` print `rss=` after context, Commit, selected
  commit, Access, Opening and the product stages), add the release hook's print
  at the same points, and record the stage at which the high-water mark is first
  reached; `/usr/bin/time -l`'s `maximum resident set size` is the authoritative
  peak. The goal of the run is not just the number but *which stage* owns it.
* **Fallback when the window is unavailable.** Calibrate the retention term
  instead: run the `(e)` A/B below at `2^16`/`2^17` and take
  `retention = measured peak − modelled live`. If retention is a small absolute
  term that grows with scale, extrapolate the *share*, not the absolute value.
* **`(e)` allocator-release A/B design** (no proof-byte change): env switch
  `MAGNETAR_RELEASE_TRANSIENTS=1`, default off; at each point where a big
  transient is dropped (selected commit material after Commit, Access working
  set after Access, mosaic commit/opening material after its stage) call
  `libc::malloc_zone_pressure_relief(null_mut(), 0)` on macOS (`malloc_trim(0)`
  on glibc) through one `release_unused_pages()` helper; the switch only changes
  when pages are returned, never the values. Interleaved A/B with ≥2 rounds each
  at `2^16` and `2^17` on the same binary: compare peak, per-stage RSS and prove
  CPU (must be unchanged within noise; the release call costs microseconds).
  Adopt if the peak drops ≥5 % at `2^16` and the `2^17` drop scales with the
  transient sizes; then use the hook in the `2^20` run. Failure mode: if the
  peak does not move, malloc already returns large blocks (`mmap`-backed), and
  `(e)` is closed in favour of `(d)`.

## 4. Reduction routes

| route | what changes | `2^16` peak | `2^22` peak | risk / effort | verdict |
| --- | --- | --- | --- | --- | --- |
| (a) 16 B → 8 B Merkle digests | `P3Mmcs` digest width (`p3_pcs.rs:105`); proof shrinks | −0.2 GiB | −12 GiB | 64-bit digest ⇒ ~32-bit collision (birthday) vs the 100-bit target; p3 wants digests ≥ 2×security. Also a proof-format break | **reject** on security; the security-correct direction (32 B) costs +24 GiB |
| (b) 64-bit committed alphabet (`BinaryField64` for codewords, 128-bit challenges) | PCS `F` type; halves leaves + layout, tree unchanged | ~−0.2 GiB | −18 GiB (mosaic −10, selected −8) | log_len = num_vars+log_inv_rate ≤ 64 ✓ (selected 23, mosaic 30); encoder becomes 64-bit tower; proof-format break; measure encode/verify | do after (c); best pure-PCS step |
| (c) bit-pack the mosaic commitment | commit the boolean mosaic as a packed bit witness (128 bits/field, ring-switch, like the selected witness / claim table) instead of 16 B/cell | **−0.56 GiB (28 %)** | **−32 GiB** transient, −2.3 GiB resident, −4 GiB layout | high: mosaic committed layout + opening path (`protocol.rs`), verifier, new claim layer; proof-format break; p3 boolean/mixed-trace support exists (`vendor/plonky3/binary-pcs/src/boolean.rs`) | the only route that removes the dominant term; headline |
| (d) context lifetime + dedup | (i) drop Access-only witnesses/batch tables once Access is done; (ii) `Arc`-share the register tables instead of cloning into `mosaic_tables`; (iii) reuse `trace_witness.values` for the trace table | −0.3-0.6 GiB | −10-20 GiB | medium-low: ownership/lifetime refactor of `UnifiedProveContext`; no proof-byte change | best value; do first |
| (i) streaming PCS commit on the cap-only paths (§4.6) | chunked RS encode (coset at a time) + incremental Merkle root; commit-only entry points drop the prover data anyway | **−0.41 GiB (default)**, −0.19 GiB products-gated, −0.65 GiB at the Commit stage | commit term halves; ~−1 to −2.5 GiB at `2^18` (projected, not measured) | medium; **done** — no format change, proof bytes identical; the Opening re-encode remains | **landed 2026-11-14** |
| (e) release freed pages between stages (§3.1) | `malloc_zone_pressure_relief`/`madvise(MADV_FREE)` after each big transient | −0.1-0.4 GiB | −10-30 GiB (if retention is real) | 1-day experiment; macOS malloc may already `munmap` large blocks, so measure stage RSS first | cheapest; measure before building on it |
| (f) shrink level stores | inner budget 24 → 22 | −0.5 GiB | −0.5 GiB | +7 s prove at `2^16` (+22 %); recompute passes scale with `cycles` | not a memory lever; keep for a hard cap only |
| (g) Merkle cap height / arity | top layers only | −ε | −ε | trivial | skip |
| (h) bit-pack the twist witnesses/batch tables | one-hot address matrices and boolean bit columns stored as 16 B/element; repack like `PackedBits` | ~−0.2 GiB | −15-25 GiB (part of §1.1) | medium: witness builders + `batch_tables` + Access consumers; mechanical but pervasive; combine with (d) | second structural item |

Rejected outright: caching prepared commit data into Opening — it *adds* the
selected prepared set (up to 24 GiB) and/or the mosaic prepared set (36 GiB) to
the steady peak at `2^22`; the commit gate already removes the only overlap
worth removing.

## 4.3 Where the memory work stands (2026-11-08 session, extended 2026-11-14)

Peak footprint at `2^16` native default, chronological:

| change | peak footprint | Access-prover CPU / prove CPU |
| --- | --- | --- |
| pre-route-(d) | 2.20 GiB | 30.2 s prove |
| route (d) increments 1+2 | 2.17 GiB | 30.4 s prove |
| Access-PCS lifetime (default re-encode) | 1.98 GiB | 30.3 s prove |
| compact sum-check factors (2026-11-14) | **1.89 GiB** | 22.4 -> 18.1 s / 288.1 -> 280.0 s |
| + `MAGNETAR_SERIALIZE_ACCESS=1` (memory mode) | 1.78 GiB | 31.2 s prove |
| + `MAGNETAR_SERIALIZE_PRODUCTS=1` (strongest mode) | **1.64 GiB** | 41.1 s prove (2^16, load 28) |
| + streaming PCS commit (§4.6, default schedule) | **1.49 GiB** | 295.9 s prove CPU (4-pair mean, ±8 s host drift) |
| + streaming PCS commit + `MAGNETAR_SERIALIZE_PRODUCTS=1` | **1.45 GiB** | - |
| + streamed opening (`MAGNETAR_STREAM_PCS_OPEN=1`), `2^16` | 1.47-1.54 GiB (floor: selected products) | 299 s CPU |
| + streamed opening, `2^17` products-gated | **2.10 GiB** (from 3.02) | 622 s CPU |
| + streamed opening, `2^18` products-gated | **3.60 GiB** (from 5.96) | 1285 s CPU |
| + packed twist address rows (h slice 1), `2^18` | 3.58 GiB (context 2.60 -> 1.77, Access footprint 2.72 -> 1.24) | 1294 s CPU |
| + packed twist address rows, `2^19` | **7.11 GiB** (from 7.66) | 2685 s CPU |
| + packed twist value history (h slice 2), `2^18` | **3.20 GiB** (context 1.56) | 1249 s CPU |
| + packed twist value history (h slice 2), `2^19` | **5.79 GiB** (from 7.11) | 2638 s CPU |

At `2^18` the 2026-11-08 sequence is 8.72 -> 7.96 -> 6.96 GiB footprint. The
remaining peak terms are quantified in §4.2: the mosaic Commit/Opening
codeword+Merkle transients first, then the Access PCS commit transient, then the
resident context; the dense Access factor arrays were ~12 % and the compact
sum-check factors (§4.4) removed most of that.

**Remaining routes, not attempted (multi-week design work, recorded so the next
session starts here):**
- (c) bit-pack the mosaic commitment: would shrink the resident mosaic tables
  *and* the Commit/Opening codeword+Merkle transients (the `2^18` Opening peak
  is ~5.5 GiB of transient); changes the committed format, so prover+verifier
  change together.
- (h) bit-pack the twist witnesses/batch tables: the Access inputs and the
  retained tables.
- (b) 128 -> 64-bit committed alphabet.
- streaming/virtual-one-hot Access prover: the cell-independent factors are
  now stored compactly (§4.4, -19 % Access CPU, -5 % peak at `2^16`); what is
  left of that route is virtualising the two one-hot address matrices and the
  value matrix, which needs a restructured (Jolt-style) sum-check over the
  address bits rather than a factor representation change.
- streaming PCS commit: **done** (§4.6) for the cap-only entry points, and the
  **opening half is done too** (§4.7, opt-in `MAGNETAR_STREAM_PCS_OPEN=1`):
  `-2.36 GiB` peak at `2^18`, `-0.92 GiB` at `2^17`, byte-identical proofs.
  What remains under this lever is only the cap pass it repeats (`+3-4 %` CPU),
  fixed by passing the already-computed commitment into the opening.
- `2^19` staircase: environment-blocked (needs >=13 GiB free+inactive; the host
  stayed at 10.8-14.2 GiB with swap ~9 GiB used all session, and at 4-6 GiB
  free+inactive on 2026-11-14).

**Verification tail (current tree):** `protocol_determinism` 20/20
byte-identical; `m6_verify_ab` parallel verify 10.83 ms (min 10.64) vs serial
24.87 ms; `2^16` proof 1,018,155 B and paper-path proof 1,169,603 B unchanged
by every memory change; full workspace gate **675 passed / 0 failed /
8 ignored** (39 binaries) after the compact-factor change and the
products-gated mode (`299b08b`; the extra passing test is
`compact_factors_match_the_expanded_sumcheck`, the extra ignored one the byte
equality pin for the new switch).

## 5. Recommended order and tests

Order by GiB saved per unit of work:

1. ~~**(e) + stage RSS instrumentation**~~, ~~**streaming PCS commit**~~ and
   ~~**streamed opening**~~ are done (§4.2, §4.6, §4.7): the cap-only commits
   stream (`-0.41 GiB` default-schedule peak at `2^16`) and the openings stream
   behind `MAGNETAR_STREAM_PCS_OPEN=1` (`-2.36 GiB` peak at `2^18`,
   `-0.92 GiB` at `2^17`, byte-identical). The cheap follow-up is to pass the
   cap already computed at commit into the opening so the extra leaf-hash pass
   disappears and the streamed path wins CPU as well as memory.
2. **(d) context lifetime/dedup** (2-4 days): removes 10-20 GiB at `2^22` and
   0.3-0.6 GiB at `2^16` with no proof-format change.
3. **(c)+(h) bit-packed mosaic commitment and twist witnesses** (1-2 weeks):
   removes 32 + 2.3 GiB at `2^22` and ~0.6 GiB at `2^16`; changes the proof
   format.
4. **(b) 64-bit committed alphabet** once (c) lands: another ~18 GiB.

The global peak *moves* as these land. Today it is the mosaic Opening. After
(c) the mosaic transient collapses, so the peak becomes the **selected witness
commit** (24 GiB transient + 20-30 GiB context + 4 GiB packed witness ≈ 48-58
GiB); (d)+(h) shrink the context side of that stage (down to ~5-8 GiB), and (b)
shrinks the selected transient to 16 GiB. Keep the peak-stage attribution in
the regression harness, not just the number, or the next step will chase the
wrong term.

After (c)+(d)+(h): 2^22 ≈ 0.15 (mosaic) + 16 (selected) + 5-8 (context) + 4
(witness) + 0.8 (levels) ≈ **26-30 GiB**, still ~4.5× the 6.4 GiB envelope. The
residue is RS-codeword-bound (the selected rate-1/2 codeword+tree alone is
16 GiB) and context-bound, so the envelope needs a different commitment family
(FRI/STIR-style, or an out-of-core/streaming codeword) — not more packing.

Tests for every step: (i) **peak regression** — record stage RSS at `2^16` and
`2^17` with the watchdog (`MAGNETAR_MAX_RSS_GIB`), plus `2^19` in a dedicated
window for the slope; (ii) **byte equality** — `streaming_lockstep_proof_matches`
and `protocol_determinism` for anything that touches PCS inputs; proof-format
changes need a version bump and updated golden sizes rather than the byte gate;
(iii) **verify budget** — keep `2^16` verify at ≤27 ms (24.7-27.2 ms now); a
PCS change that moves it needs an explicit trade note; (iv) **prover time** —
same-binary env-switched CPU-second A/B, never wall clock under load.

### 4.1 Route (d) implemented: Access-input lifetime + compact twist tables (2026-11-08)

All of this is memory-lifetime only; the proof bytes are unchanged.

**What changed**

1. **Dead `aux_tables` removed** from `UnifiedProveContext`: it pushed clones of
   the RAM address/increment tables, the router tables, the register
   address/increment tables and the trace table on every stage, and nothing ever
   read it (the field had no readers in the crate).
2. **Access-only inputs dropped after the Access stage**: the RAM/register
   `BinaryTwistWitness`es and their `BatchTables` are no longer kept for the rest
   of the run. `MAGNETAR_KEEP_PROVER_INPUTS=1` restores the old lifetime for a
   same-binary peak A/B.
3. **Compact twist tables on the linear path** (the shipped RV64 path,
   `cycles >= LINEAR_TWIST_MIN_CYCLES = 8192`):
   - new `binary_twist::batch_tables_committed_only` skips the per-cell bit
     tables (`read_value_bits`/`read_address_bits`, `cell_bits * cycles` field
     elements = **64 MiB** for the register twist at `2^16`) that the linear
     reduction never reads;
   - the five committed tables are **moved** into the mosaic instead of cloned
     (`TwistAccessInputs::Linear` keeps only `address_bits`/`cycle_bits`);
   - the Access stage uses the new
     `prove_binary_twist_claims_linear_shape` / `prove_trace_access_shared_linear`;
   - the quadratic reference path (small traces) is unchanged and still keeps
     its full tables.

**Deterministic live-set effect at `2^16`** (paper bench; scales with `cycles`,
so the register items are ~5 GiB at `2^22`):

| item | bytes |
| --- | --- |
| register twist witness dropped after Access | ~78 MiB |
| register committed tables moved, no duplicate | ~14 MiB |
| register `read_value_bits` never built | ~64 MiB |
| trace-table clone (was in the dead `aux_tables`) | 8 MiB |
| **total** | **~0.16 GiB** |

**Measured peak A/B, `2^16` native default** (`TRACE_SHOUT=1`,
`MAGNETAR_PROFILE_UNIFIED=1`, same binary, alternating keep/drop runs, footprint
from the watchdog, RSS from the sampler):

| window | keep (old lifetime) footprint / RSS | drop / compact footprint / RSS |
| --- | --- | --- |
| host swap 8.5/10 GiB, load 22-40 (n=4 each) | 2.21-2.22 / 1.99-2.22 GiB | 2.00-2.19 (median 2.19) / 1.64-2.19 GiB |
| load ~39, after the compact-table change (n=2 each) | 2.03-2.03 / 1.80-2.03 GiB | 2.00-2.00 / 2.00-2.01 GiB |

The absolute peak drifts by **~0.2 GiB with host memory pressure** (swap was
8.5/10 GiB used; the 2026-11-03 quiet-host figure was 1.82 GiB footprint), so
only a same-window A/B is meaningful; it measures **-0.12 GiB** footprint in the
first window and **-0.03 GiB** in the second. Prove CPU is unchanged within
noise (~-1 %), as expected for a lifetime change. Proof bytes are byte-identical
in both modes (`proof=1,018,155 B`).

**Gates:** `cargo test --workspace --release` **674 passed / 0 failed /
5 ignored** (39 binaries) after both increments (commit `3320bb0`), and
**674 passed / 0 failed / 7 ignored** after the Access-PCS lifetime and the
Access-scheduling switch (commits `3478c36`, `caa3692`; the extra ignored tests
are the byte-equality pins); the focused
legs are `magnetar-runtime --lib` 363 passed / 0 failed / 5 ignored,
`magnetar-proof` 48 passed and `magnetar-testkit` integration 21 passed /
0 failed. Smoke runs
at `2^10` (quadratic path) and `2^14` (linear path) round-trip, and the proof
bytes are identical between the old and the new lifetimes.

**Increment 2 (same day): the trace-witness duplicate.** The context kept the
whole `TraceWitness` (values + layout + point) *and* a trace table that cloned
those values, *and* pushed a second clone of the table into the mosaic — three
copies of the same `rows x 8` field-element vector. Now the values live exactly
once, inside `mosaic_tables[trace_index]`; the context keeps only the layout and
the point, and `trace_claim_points_from_parts` reads the values out of the
mosaic (the stage/finish paths do the same). That removes two retained copies:
**16 MiB at `2^16`, ~1 GiB at `2^22`** (the `Mle::new(values.to_vec())` inside
the claim-point computation is still one transient copy; it is not retained).

**`2^17` same-window A/B** (`ADDS=131071`, `TRACE_SHOUT=1`, watchdog 6 GiB, two
alternating runs per leg, host load 28-37, swap 9.4/10 GiB used):

| mode | peak footprint | peak RSS | prove CPU | proof |
| --- | --- | --- | --- | --- |
| `MAGNETAR_KEEP_PROVER_INPUTS=1` (old lifetime) | **4.51 / 4.51 GiB** | 3.97 / 4.11 GiB | 632.3 / 628.2 s | 1,110,291 B |
| new (route (d) increments 1+2) | **3.95 / 3.95 GiB** | 3.24 / 3.92 GiB | 626.0 / 625.8 s | 1,110,291 B |

**-0.56 GiB footprint (-12.4 %)**, RSS -0.2 to -0.7 GiB, prove CPU -0.7 %
(noise-level, memory-only change and the extra read-from-mosaic is trivial).
The proof bytes match the documented `2^17` baseline exactly, so the lifetime
change is byte-neutral. The `2^16` delta (0.03-0.12 GiB) sits below this host's
~0.2 GiB absolute-peak drift; `2^17` is where the route (d) win is unambiguous.

**Staircase on the route-(d) tree (2026-11-08, quiet-window sequence starting at
load 4, rising to 28-57):** native-default peaks are `2^16` **2.18 GiB RSS /
footprint**, `2^17` **4.35 / 4.35 GiB**, `2^18` **5.96 GiB RSS / 7.96 GiB
footprint** (proof 1,018,155 / 1,110,291 / 1,230,360 B, all identical to the
documented baselines). The `2^18` footprint is 2.0 GiB above RSS, so the `2^22`
extrapolation must use the footprint series. `2^19` was not run (12.3 GiB
free+inactive vs the protocol's peak+4 ≈13.5 GiB); see HANDOFF §2/§5 item 4.

**Next for route (d)/(h):** the remaining context terms are the real-RV64 RAM
witnesses/batch tables (~4 KiB/cycle, dropped after Access by increment 1) and
the uncommitted witness copies feeding the bit-packed tables; the next big step
is (h) bit-packing the twist witnesses/batch tables, then (c) the mosaic
commitment.

### 4.2 Stage-level attribution (2026-11-08): the instrumentation was blind, now it is not

`crate::resident_gib()` shelled out to `ps -o rss=`, which the sandbox blocks,
so every `MAGNETAR_PROFILE_*` stage print reported `rss=0.00 GiB` and the
attribution this document asks for was impossible. It now reads the in-process
`getrusage(RUSAGE_SELF).ru_maxrss` (peak RSS) and, next to it, the current
`phys_footprint` through `magnetar_proof::alloc_release`, so each stage print
carries both metrics (`rss_peak=... footprint=...`).

Same-binary A/B at `2^16` native default (`TRACE_SHOUT=1`,
`MAGNETAR_PROFILE_UNIFIED=1 MAGNETAR_PROFILE_SELECTED=1`), route (d) on vs
`MAGNETAR_KEEP_PROVER_INPUTS=1`:

| stage | new rss_peak / footprint | keep rss_peak / footprint |
| --- | --- | --- |
| unified context | 0.54 / 0.53 GiB | 0.54 / 0.53 GiB |
| unified Commit | 1.28 / 1.28 | 1.28 / 1.28 |
| selected witness commit | 1.78 / 1.78 | 1.77 / 1.77 |
| selected before proof | 1.83 / 1.83 | 1.82 / 1.82 |
| unified Access | 2.17 / **0.39** | 2.17 / **2.17** |
| unified Opening | 2.17 / 1.46 | **2.20 / 2.20** |
| peak (bench) | 2.17 / 2.17 | 2.20 / 2.20 |

Reading:

- The high-water mark is first reached **during the unified Access stage** at
  `2^16` (register-twist `local_shared` prover transient: after Access the new
  lifetime's live footprint is only 0.39 GiB). That is why the `2^16` peak
  barely moves with retention, while the `2^17` A/B (§4.1) -- where the Opening
  is the peak -- shows the full -0.56 GiB: **the retained Access inputs only
  become the peak term after Access**, i.e. during the mosaic Opening.
- The Opening live set is 1.46 GiB in the new tree vs 2.20 GiB with the old
  lifetime (route (d) frees 1.78 GiB of live data after Access).
- The remaining `2^16` peak is a *sum of transients*: context 0.54 -> Commit
  +0.74 -> selected witness commit +0.50 -> Access +0.34, each freed before the
  next but still counted in RSS; footprint follows the same staircase. The
  route (c)/(h) work attacks those transients/columns, not the resident tables.

`2^17` stage table (same instrumentation, one run, load 12-63; proof
1,110,291 B, peak 3.97 GiB RSS / 3.96 GiB footprint):

| stage | rss_peak / footprint |
| --- | --- |
| unified context | 1.10 / 1.10 GiB |
| unified Commit | 2.57 / 2.57 GiB |
| selected witness commit | 3.57 / 3.57 GiB |
| selected before proof | 3.58 / 3.57 GiB |
| unified Access | 3.97 / 0.75 GiB |
| unified Opening | 3.97 / 3.03 GiB |
| after selected proof | 3.97 / 1.62 GiB |

At `2^17` the peak footprint (3.96 GiB) is reached during the **mosaic
Opening** (main-thread live 0.75 GiB + the re-encode/Merkle transient + the
selected prover's product-phase live set), not at Commit: after Access the
process footprint is only 0.75 GiB, and the selected prover's product phases
hold ~2.3 GiB live (release prints: product6 end 3.04, product2 end 1.75
GiB) -- that is the packed CSR scan structure, the six lazy matrices and the
level stores, which are all needed by both products. The main-side Opening
transient (~0.9 GiB on top of 3.03) is the last increment to the peak.

**Allocator-release re-test with the new probes (`MAGNETAR_RELEASE_TRANSIENTS=1`,
`2^17`):** every release point reports `allocator returned 0.0 MiB` (selected
commit, Access, Opening, finish, product6, product2, lockstep products), and
the peak is unchanged (3.95 vs 3.96 GiB footprint; RSS 3.65 vs 3.97 is
sampling noise). macOS libmalloc already returns the large blocks, so the
allocator-release route is a confirmed no-op at `2^17` as it was at `2^16`
(HANDOFF §5 item 3), now with direct evidence instead of a peak A/B.

**Selected-prover product phase measured directly** (new prints in
`prove_lockstep_bits_streaming_inner` + `magnetar_proof::memory_gib_text()`,
`MAGNETAR_PROFILE_SELECTED=1`; footprint is process-wide):

| 2^17 | rss_peak / footprint |
| --- | --- |
| after `LockstepRows` | 3.55 / 3.55 GiB (main Access is live at this point) |
| after product6 | 3.95 / **1.02** GiB |
| after ColumnRows | 3.95 / 1.02 GiB |
| after product2 | 3.95 / 1.39 GiB |
| after the selected open | 3.95 / 1.79 GiB |

So the selected products themselves live in only **~1.0-1.8 GiB** (the
`LockstepRows` packed CSR is small: base-matrix entries only, and the level
stores are 192 MiB outer / 512 MiB inner by construction). The transient that
makes the `2^17` peak is on the **main thread's Access stage**: `selected
witness commit` prints 3.54 GiB footprint because the process is inside
`prove_access`, and `prove_local_shared` materialises dense `cells * cycles`
one-hot/eq/val arrays for the register and RAM twists (`flat_onehot`,
`repeated_blocks`, five factors of `32 * cycles` field elements: at `2^17`
that is ~134 MiB per array, ~0.8-1.0 GiB live for one twist alone at
`cycles = 2^18`). The Access stage is therefore the first place to attack at
`2^17`+; the fix is a streaming/virtual-one-hot Access prover (the
`local_twist` module has a reference virtual-one-hot path, but the shipped
Access stage still materialises the dense form), which is route (h)-adjacent
and byte-neutral by construction.

**`2^18` stage table (current tree, one run at load 6-62, proof 1,230,360 B,
peak 6.37 GiB RSS / 7.97 GiB footprint, prove 133.1 s / CPU 1240.3 s):**

| stage / milestone | rss_peak / footprint |
| --- | --- |
| unified context | 2.25 / 2.25 GiB |
| unified Commit | 4.65 / **5.18** GiB |
| selected witness commit (process-wide, main Access input live) | 5.96 / 7.18 GiB |
| local factors (5 dense arrays x 8,388,608 fields) | 6.23 / 7.56 GiB |
| local after rw sumcheck | 6.33 / 7.75 GiB |
| local final factors ready | 6.37 / **7.97** GiB (the peak) |
| unified Access (after the stage) | 6.37 / 1.38 GiB |
| unified Opening (after the stage) | 6.37 / 5.87 GiB |
| selected product6 / product2 / open | 1.46 / 2.08 / 3.71 GiB |

Reading: at `2^18` the peak is inside the **Access stage** (7.97 GiB), not at
the mosaic Opening, and it is a three-way overlap: the resident context
(2.25), the mosaic Commit transient (Commit alone reaches 5.18) / selected
witness commit transient, and the Access prover's own data -- the five dense
`cells * cycles` factor arrays (5 x 128 MiB here) plus the **retained prepared
commit batch** of the local PCS over the address columns (kept for the
opening: "the prepared batch moves into the opening"). After the Access stage
releases its inputs the live footprint is only 1.38 GiB, so the Access stage,
not the products, is the `2^17`/`2^18` peak owner. The Opening stage then
peaks around 5.87 GiB live (mosaic re-encode transient on 1.38 live), and the
products stay at ~2.1 GiB.

Consequences for the memory route:
- route (c) (bit-packed mosaic commitment) attacks the `2^18` Commit/Opening
  transients (Commit alone is +2.9 GiB over the context);
- a streaming/virtual-one-hot Access prover attacks the `2^18` peak directly
  (dense factor arrays + retained local prepared batch);
- the resident context (2.25 GiB at `2^18`) is the route (h)/(c) resident term.

`2^19` was not run: after the `2^18` run the host had 14.24 GiB
free+inactive, below the protocol's peak+4 GiB (post-route-(d) `2^19` estimate
~11.9 GiB peak => ~16 GiB). It needs a dedicated window.

**`2^16` peak decomposition -- corrected by direct measurement (2026-11-14).**
An earlier estimate in this section put ~36 % of the `2^16` peak on the Access
prover's dense factor arrays. The instrumented local profile shows that was
wrong. At `2^16` the register twist stores `cells * cycles = 2^23`... `2^21`
fields (`cells = 32`, `cycles = 2^16`): five arrays during the rw sum-check
(the `eq`/increment repeats plus the two one-hot matrices plus the value
matrix) and three during the final sum-check. That is **7 arrays x 33.5 MB =
0.23 GiB, ~12 %** of the 1.99 GiB peak, not 36 %.

The peak itself is reached at the Access prover's *final-factors* point, but
the footprint there (1.74-1.99 GiB) is far above the live data (~0.7 GiB:
context 0.55 + the arrays still held). The gap is the **commit transients**
that set the allocator high-water: the mosaic Commit reaches 1.28 GiB and the
Access PCS commit adds its codeword+Merkle tree before the arrays are built.
So the remaining peak terms, in order, are: (i) the mosaic Commit/Opening
codeword+Merkle transients (~0.74 GiB at `2^16`, route (c)), (ii) the Access
PCS commit transient, (iii) the resident context (0.55 GiB, routes (h)/(c)),
and only then (iv) the dense Access factor arrays, which the compact-factor
change below removed most of.

**Opt-in scheduling switch: `MAGNETAR_SERIALIZE_ACCESS=1`.** At `2^16`+ the

**Opt-in scheduling switch: `MAGNETAR_SERIALIZE_ACCESS=1`.** At `2^16`+ the
Access stage's dense factor arrays overlap the selected thread's commit and
product phases, and the peak is a sum of the two. The switch moves the
selected-commit gate from the mosaic Commit to the end of the Access stage, so
the two working sets no longer overlap. The proof is unchanged (ignored test
`m5_v4_tests::serialize_access_proof_bytes_match` proves the same trace both
ways and compares the serialized unified proofs).

| scale | default | `MAGNETAR_SERIALIZE_ACCESS=1` |
| --- | --- | --- |
| `2^16` | 2.17 GiB RSS / **2.17 GiB footprint** / prove 30.54 s (CPU 287.7) | 1.91 / **1.78 GiB** / prove 31.07 s (CPU 286.9) |
| `2^18` | 6.17 GiB RSS / **7.96 GiB footprint** / prove 132.90 s (CPU 1249.3) | 6.09-6.71 / **6.96-6.97 GiB** / prove 132.65-132.84 s (CPU 1247-1250) |

=> `2^16`: **-0.39 GiB footprint (-18 %)** for +1.7 % prove wall; `2^18`:
**-1.0 GiB footprint (-12.6 %)** with the wall unchanged (the later product
start is absorbed because the products then run with less contention) and at
`2^18` the peak moves from the Access stage (5.35-5.76) to the mosaic Opening
(6.39-6.86). Opt-in rather than default: at large `2^22` scale the Access
stage is much longer, so serializing it costs wall there (and the 2^19 window
will decide the default).

**Second (stronger) scheduling switch: `MAGNETAR_SERIALIZE_PRODUCTS=1`.** The
first switch removed the products/Access overlap; the remaining overlap at
`2^17`+ is the products against the **mosaic Opening**. This switch implies the
Access gate and then also holds the selected thread until the Opening stage has
finished, so during Access and Opening the selected prover has only done its
setup/commit (nothing else). Proof bytes are unchanged (ignored test
`m5_v4_tests::serialize_products_proof_bytes_match` proves one trace through the
Access-gated and the products-gated schedule and compares the serialized
unified proofs).

| scale | default (no switch) | `SERIALIZE_ACCESS=1` | `SERIALIZE_PRODUCTS=1` |
| --- | --- | --- | --- |
| `2^16` peak footprint | 2.08 GiB | 1.78-1.79 GiB | **1.64 GiB (-21 %)** |
| `2^16` prove | 40.0 s / CPU 288.7 s | 41.1 s / 285.8 s | 41.1 s / CPU 281.2 s |
| `2^17` peak footprint | 4.15 GiB | not re-measured | **3.28 GiB (-21 %)** |
| `2^17` prove | 90.8 s / CPU 600.3 s | not re-measured | 93.6 s / CPU 604.8 s |
| `2^18` peak footprint | 7.96 GiB (2026-11-08 window) | not re-measured | **6.05 GiB (-24 %)** |
| `2^18` prove | 133.1 s / CPU 1240.3 s | not re-measured | 226.6 s / CPU 1277.1 s (load 31-58) |
| proof bytes | 1,018,155 / 1,110,291 / 1,230,360 B | identical | identical |

At `2^18` the mode's peak point is the mosaic Opening (`unified Opening` footprint
5.61 GiB against 1.38 GiB live after Access), i.e. the products are fully out of
the way and what is left is the opening re-encode transient on top of the
resident context (2.24 GiB) -- again the PCS codeword, not the factors.

At both scales the strongest mode costs **~3 % prove wall and no extra CPU**
(the products start ~3-5 s later at `2^16`/`2^17` but run with less contention)
and removes a fifth of the peak. With it the `2^16` peak becomes the Access
stage alone (1.64 GiB) and `2^17` drops from 4.15 to 3.28 GiB -- the largest
single-step memory win measured so far without touching the format. It is the
recommended mode for the large staircase runs (`2^19`+), where wall is dominated
by `product6`/`product2` anyway and the products' late start is a fixed cost.

**Kept (default flipped): the Access PCS prepared batch is not retained.** The
local PCS used `commit_batch_prepared` and kept the prepared batch (codeword +
Merkle tree of the address columns) live from the commit until the opening
("the prepared batch moves into the opening"). That retained batch scales with
the address columns and is one of the Access-stage peak terms. The prover now
commits, drops the data and re-encodes at the opening -- the selected prover's
pattern -- with byte-identical commitment/proof (ignored test
`m5_v4_tests::local_recommit_is_byte_identical_to_retained_batch` proves the
same 8200-row trace both ways and compares the serialized unified proofs).

Same-window A/Bs (proof bytes identical in both legs):

| scale | retained (`MAGNETAR_KEEP_LOCAL_PREPARED=1`) | re-encode (default) |
| --- | --- | --- |
| `2^17` (3+2 runs) | 4.33 GiB footprint / 598.7, 595.0 s CPU | 4.33, 3.95 GiB / 601.6, 598.4 s CPU (inside drift) |
| `2^18` (back-to-back) | 6.51 GiB RSS / **8.72 GiB footprint** / 1248.1 s CPU | 6.17 GiB RSS / **7.96 GiB footprint** / 1249.3 s CPU |

At `2^18` that is **-0.76 GiB footprint (-8.7 %), -0.34 GiB RSS for +0.1 % CPU
(noise)**; the Access-stage peak point ("local final factors ready") drops
8.72 -> 7.96 GiB. At `2^17` the retained batch is small enough that the change
sits inside this host's ~0.4 GiB drift, which is why the 2^18 window is the one
that decides it. `MAGNETAR_KEEP_LOCAL_PREPARED=1` remains for A/B work.

**A rejected micro-optimisation, recorded so it is not retried.** The Access
prover keeps `write_flat` and `val_flat` (two of the five `cells * cycles`
factor arrays) alive across the sum-check by cloning them into the factor list.
Moving them into the factor list and rebuilding them afterwards was implemented
and A/B-ed (`MAGNETAR_KEEP_LOCAL_FLATS`): the live footprint at the factor
build drops 3.74 -> 3.65 GiB, but the final-factor point goes 3.95 -> 3.97 GiB,
the end-to-end peak is unchanged (3.95 vs 3.97 GiB) and the local prover's CPU
rises ~3 s at `2^17`. **Rejected**: the Access transient is not dominated by
those two extra arrays but by the overlap with the selected products and the
main-thread context, so the only real fix is a streaming/virtual-one-hot Access
prover (compute the cell-dimension sum-check rounds directly from the witness
instead of materialising `cells * cycles`), not an array-lifetime change.
`MAGNETAR_PROFILE_LOCAL=1` now prints the milestone memory (`local factors`,
`local after rw sumcheck`, `local final factors ready`) for that future work.

**Where the remaining memory work must go:** the `2^17` peak is split between
(a) the main thread's mosaic Opening re-encode/Merkle transient and resident
mosaic tables (route (c)/(h): bit-packing the mosaic tables shrinks both the
transient and the resident set), and (b) the selected prover's product-phase
live set (~2.3 GiB: packed CSR + matrices + level stores, scales with cycles).
(b) needs either a streaming CSR or the level-budget trade (HANDOFF §5 item 6),
and is the next thing to measure at `2^18` before touching it.

### 4.4 Access sum-check factors stored compactly (2026-11-14)

The Access prover (`local_shared::prove_local_shared`, used for both the RAM
and the register twist) ran two sum-checks over the index space
`cell * cycles + cycle`. Four of its seven factor arrays did not depend on the
full index:

* `eq(cycle_point)[cycle]` and `increment[cycle]` repeat under every cell
  (`at(i) = values[i & (cycles-1)]`),
* `eq(cell_point)[cell]` is constant along the low `cycle_bits`
  (`at(i) = values[i >> cycle_bits]`).

Each was expanded to `cells * cycles` field elements (33.5 MB at `2^16`,
134 MB at `2^18`). `SumcheckFactor` now stores the distinct block and reads it
through `at()`; the summand receives exactly the same values in the same
pair order, so the round polynomials, the challenges, the proof bytes and the
verifier are unchanged. The dense reference is kept in `evaluate_points_at` /
`sumcheck_terms_indexed` (still used by the value sum-check and the tests), and
`binary_twist::tests::compact_factors_match_the_expanded_sumcheck` pins the two
routes against each other.

Measured at `2^16` (same host, same day, `TRACE_SHOUT=1`):

| metric | before | after |
| --- | --- | --- |
| proof bytes (native / paper path) | 1,018,155 / 1,169,603 B (access 221,876 B) | identical |
| Access prover CPU (`local total`) | 22.4 s | **18.1 s (-19 %)** |
| final-round sum-check CPU | 0.78 s | 0.57 s (-27 %) |
| whole-prove CPU | 288.1 s | **280.0 s (-2.8 %)** |
| peak footprint (default) | 1.99 GiB | **1.89 GiB (-5 %)** |
| peak footprint (`MAGNETAR_SERIALIZE_ACCESS=1`) | 1.74 GiB | 1.79 GiB (inside drift) |

Live factor memory drops by two arrays at each sum-check (67 MB live at
`2^16`, 268 MB at `2^18`; four arrays' worth of allocations avoided in total,
i.e. 134 MB / 536 MB). The `2^16` peak only moves 0.10 GiB because at that point
the high-water mark is set by the commit transients (§4.2), which is why the
next target is the streaming PCS commit rather than more factor compaction.

`MAGNETAR_PROFILE_LOCAL=1` now prints which factors are compact:
`local factors: 3 dense arrays of 2097152 fields (2 stored compactly), ...`.

### 4.5 Next target: streaming PCS commit (concrete locus)

The measurement in §4.2 makes the PCS commit transient the leading peak term
(the mosaic Commit alone reaches 1.28 GiB against a 0.55 GiB context at
`2^16`). The codeword is materialised in exactly one place:

```text
magnetar-pcs/src/p3_pcs.rs   commit_batch / commit_batch_prepared
  -> P3BinaryPcs::commit                       (vendored binary-pcs/src/pcs.rs)
     -> prover.rs::commit -> PcsLayout::commit  (sumcheck/src/layout/prover/mod.rs:132)
        -> commit_borrowed_base(encoder, mmcs, folding, log_inv_rate, message)
           sumcheck/src/commit.rs:119-138
             let encoded = encoder.encode_batch_borrowed(message, log_inv_rate); // full codeword
             mmcs.commit_matrix(encoded)                                        // full leaf matrix
```

`encode_batch_borrowed` returns the whole rate-`1/8` codeword as a
`DenseMatrix`, and `Mmcs::commit_matrix` then builds the tree from that matrix,
so both the codeword and the leaf matrix are live at once.

Measured shapes at `2^16` (`MAGNETAR_PROFILE_PCS=1`):

| commit | shape | cost |
| --- | --- | --- |
| mosaic `commit_mosaic` | `cells=2293918`, `stacked_vars=22`, rate `1/4` (log_inv_rate 2), 12 tables | 414 ms, codeword ~268 MB + tree ~134 MB |
| single-column `pcs commit` (2^22-value table, used twice: commit and the opening re-encode) | `pcs_log=22`, rate `1/8` | 250 ms each, codeword ~536 MB + tree ~134 MB |

That is why the `Commit` point jumps to 1.28-1.29 GiB over a 0.54 GiB context,
and why `MAGNETAR_SERIALIZE_PRODUCTS` (§4.2) only removes 0.44 GiB of the `2^16`
peak: the rest is a single thread's own commit transient.

A streaming variant has two seams:

1. an encoder that emits codeword rows in chunks (the RS encoder works row by
   row already, it just collects into one matrix), and
2. an incremental Merkle builder that hashes leaves as they arrive and keeps
   only the tree levels (the `Mmcs` trait's `commit(Vec<M>)` contract takes the
   whole leaf set, so this needs a small `Mmcs`-adjacent builder, not a change
   to every MMCS).

The commitment root is unchanged by construction (same leaf order, same hashing
calls), so the proof bytes stay identical and a test can pin the roots. Expected
effect: the `2^16` mosaic Commit transient (~0.74 GiB) shrinks to the tree
(~0.15-0.2 GiB), i.e. roughly **-0.5 GiB at `2^16` and -2 to -3 GiB at `2^18`**,
which is the largest single remaining memory lever.

### 4.6 Streaming PCS commit implemented (2026-11-14)

The locus in §4.5 is now a streaming commit; the proof bytes are unchanged.

**What changed.** Both seams are implemented for the shipped `P3BinaryPcs`
(`crates/magnetar-pcs/src/streaming.rs`, `p3_pcs.rs`):

1. **Encoder seam.** A rate-`2^log_inv_rate` RS codeword is the concatenation of
   `2^log_inv_rate` cosets, each the message transformed on its own shifted
   subspace — the identity `PolyBasisNtt::ntt_batch_padded` already exploits.
   `streamed_codeword_root` copies the message into one message-sized scratch
   buffer per coset, applies `PolyBasisNtt::shifted_ntt_batch`, and hands the
   coset rows to the Merkle builder. The buffer the transform returns is reused
   as the next coset's copy, so one message plus one coset is live instead of
   the whole codeword.
2. **Merkle seam.** `StreamingRoot` hashes codeword rows as they arrive, builds
   one perfect subtree per `2^15`-row block (blocks hash and compress in
   parallel), and keeps a logarithmic frontier of completed subtree roots.
   `P3Mmcs` has `cap_height = 0`, so the cap is one root and no level needs to
   be retained for an opening.

The wiring is the three **cap-only** wrapper entry points, which used to build
the full codeword and tree and immediately drop both: `Pcs::commit`
(single-column), `commit_batch` (the local/shared twist and Shout tables) and
`commit_mosaic` (the unified mosaic, the `Commit` stage). The retained paths —
`commit_batch_prepared` / `open_batch_prepared` and `open` / `open_batch` /
`open_mosaic` — still materialise the codeword and tree, because their openings
need them. `MAGNETAR_LEGACY_PCS_COMMIT=1` restores the batch path in the same
binary for an A/B.

**Why the root is identical.** Same leaf order (coset `c` is codeword rows
`[c * message_rows, (c+1) * message_rows)`), same leaf hashing
(`CryptographicHasher::hash_many` over the contiguous rows of a block, which is
the tree's own leaf arm), same binary compression over the same subtree
boundaries (the block size divides every power-of-two codeword height). Three
tests pin it: `streaming_root_matches_mmcs` (root equality against
`MerkleTreeMmcs::commit_matrix` for heights `2^0..2^10`, widths 1/2/3/5/8 and
five push chunkings), `streaming_codeword_root_matches_batch_encoder`
(cap equality against `encode_batch_borrowed` + tree for heights `2^0..2^7`,
rates 0-3), and `streaming_root_matches_pcs_commit_entry_points` (each streamed
entry point against the retained path's commitment over the same tables).

**Isolated PCS probe** (`p3_stage_probe`, commit-only, same binary env-switched,
peak RSS from `getrusage`; `MAGNETAR_SERIALIZE_PRODUCTS` not involved):

| commit | shape | legacy peak | streamed peak | legacy / streamed CPU (user+sys) |
| --- | --- | --- | --- | --- |
| single column | `2^22` values, rate 1/2 | 516.7 MiB | **205.2 MiB (-60 %)** | 1.82 / 1.83 s |
| mosaic | 12 tables, `cells=2,293,918`, rate 1/4 | 843.3 MiB | **211.5 MiB (-75 %)** | 3.62 / 3.58 s |
| local twist (control) | 15 cols `x 2^16`, rate 1/8, *prepared* path | 418.5 MiB | 418.6 MiB | 178 / 179 ms |

The local-twist row is the control: it goes through `commit_batch_prepared`, so
it must not move — and does not.

**Whole prover at `2^16`** (`paper_unified_bench`, `ADDS=65535`,
`TRACE_SHOUT=1`, same binary, env-switched):

| metric | legacy commit | streamed commit |
| --- | --- | --- |
| unified `Commit` stage rss / footprint | 1.28 / 1.28 GiB | **0.63 / 0.63 GiB** |
| unified `Opening` stage rss / footprint | 1.90 / 1.46 GiB | 1.51 / 1.46 GiB |
| peak footprint, default schedule | 1.90 GiB | **1.49 GiB (-0.41 GiB, -22 %)** |
| peak footprint, `MAGNETAR_SERIALIZE_PRODUCTS=1` | 1.64 GiB | **1.45 GiB (-0.19 GiB)** |
| prove CPU (4 interleaved pairs) | 288.9 s mean (280.4-298.9) | 295.9 s mean (287.8-304.8) |
| proof / varint / compressed | 1,018,155 / 829,744 / 667,091 B | identical |

**`2^17` staircase** (`ADDS=131071`, `MAGNETAR_STREAM_BUDGET_LOG=23`,
`MAGNETAR_SERIALIZE_PRODUCTS=1`, one interleaved pair, host load 59-84 during
the leg so wall times are not comparable):

| metric | legacy commit | streamed commit |
| --- | --- | --- |
| unified `Commit` stage rss / footprint | 2.56 / 2.56 GiB | **1.28 / 1.28 GiB (-50 %)** |
| unified `Opening` stage rss / footprint | 3.13 / 3.03 GiB | 2.93 / 3.02 GiB |
| peak footprint | 3.29 GiB | **3.03 GiB (-0.26 GiB, -8 %)** |
| prove cpu | 590.2 s | 614.3 s (+4.1 %, host load 59-84) |
| proof / varint / compressed | 1,110,291 / 915,539 / 749,347 B | identical |

The commit transient halves exactly as at `2^16`; the process peak only moves
0.26 GiB because the `2^17` peak is the Opening (3.03 GiB), which is untouched.

Reading:

- The `Commit` stage drops by 0.65 GiB, matching §4.5's prediction, but the
  **peak moves to the Opening**, which still re-encodes the full codeword and
  tree for its FRI folding and query openings. That is why the products-gated
  peak only moves 0.19 GiB while the default schedule (where the commit
  transient overlapped the selected products) moves 0.41 GiB.
- Prove CPU is unchanged within this host's ±8 s whole-prove drift, and the
  isolated commit CPU is identical (the per-coset encode does the same field
  work as the batch encode; the only extra passes are the message copies, which
  are memory-bandwidth noise at this size). Verify is unchanged because the
  proof is byte-identical.
- The remaining PCS term is now the **opening-side re-encode**: chunking the
  encode is in place, so the next step is to stream the codeword *fold* and the
  query-opening pass over the same chunked encoder (the fold is a weighted row
  sum, so it can consume cosets as they are produced), then the tree only has
  to be built for the leaves the opening actually queries.

**Verification tail for §4.6.** Full workspace gate on the streaming tree:
**679 passed / 0 failed / 8 ignored** (39 binaries) — the documented 675/0/8
plus the four `streaming::*` tests. Byte equality was re-confirmed after the
hardening pass (guarded `stacked_variables` check, checked coset/height
arithmetic) at both `2^16` and `2^17`: proof / varint / compressed sizes
identical to the legacy commit in the same binary.

### 4.7 Opening-side streaming: the query half (2026-11-14, in progress)

§4.6 removed the commit half of the PCS transient. The `Opening` stage is now
the peak: at `2^16` with `MAGNETAR_SERIALIZE_PRODUCTS=1` it holds **1.45 GiB
footprint** against a 0.47 GiB unified context, and at `2^17` **3.03 GiB**
against ~1.1 GiB. That transient is the opening-side re-commit: `open` /
`open_batch` / `open_mosaic` call `BinaryPcs::open_at` with a
`BinaryPcsProverData` whose `merkle_data` owns *both* the whole codeword (the
tree's leaves) and every digest layer. The fold phase reads the base codeword
for batch 0, and the query phase opens base rows and their pruned Merkle
multiproof from the same tree. Measured base transient at the Commit stage:
0.81 GiB of work above the context at `2^16`, ~1.5 GiB at `2^17`.

**Why the code materialises it.** `fold_rounds_with` folds
`mmcs.get_matrices(&merkle_data)[0].values` (the base codeword) for the first
fold batch unless it can instead encode the message the sumcheck already bound
(`encode_bound_message`, only for `arity >= MIN_ENCODED_ARITY` with the bound
column held). `open_queries` then calls `mmcs.open_multi_batch(&base_indices,
&merkle_data)`, which needs the queried leaf rows and the digest layers for the
pruned paths.

**The streaming opening: three passes over the same stacked message.**

```text
pass 1  commit   stream encode -> incremental cap                      (done, §4.6)
pass 2  fold     stream encode -> fold each 2^a-symbol coset           (new)
                 -> round codewords (small) -> commit round codewords  (normal path)
                 -> final codeword in the clear
pass 3  query    after grind/sampling: stream encode ->               (new)
                 * keep only the queried base rows          (openings)
                 * record only the boundary digests         (pruned multiproof)
```

Neither the base codeword nor its digest layers stay live. The fold half is
already expressible with existing vendor code: `fold::fold_coset(coset_index,
values, challenges, scratch)` is exactly the per-coset engine
`fold_codeword_batch` already uses, including the global index offsets, and a
rate coset (size `2^(stacked_vars - log_inv_rate)`) is a whole number of
fold cosets (`2^arity` each) for every batch in use. The query half needs a
streaming pruned-multiproof builder; this round adds and pins one:

- `crates/magnetar-pcs/src/streaming.rs::StreamingMultiProof` plans the
  `p3_merkle_tree` pruning frontier in *index* space from the queried leaves
  (binary arity, `cap_height = 0`, one matrix, power-of-two height), then a
  single row pass keeps the queried rows and records every sent boundary digest
  into its wire slot. `finish` produces exactly the
  `Mmcs::open_multi_batch` result: same opened rows in the caller's index order,
  same `PrunedMerklePaths` sibling order.
- Tests pin byte-for-byte equality against `P3Mmcs::open_multi_batch` for
  heights `2^0..2^10`, widths 1/2/3, empty/single/all-leaves/random/duplicate
  index sets and three row chunkings (`streaming_multiproof_matches_mmcs`), and
  the multi-block frontier path at `2^16`/`2^17` (`streaming_multiproof_spans_blocks`).

**Implemented (same day).** All three seams landed:

1. `p3-commit`: `StreamingMmcs` / `StreamingOpener` — plan a streamed pruned
   multiproof over a `height x width` matrix, accept whole-row runs, return the
   same `(opened_values, MultiProof)` `Mmcs::open_multi_batch` returns.
2. `p3-merkle-tree`: `MerkleStreamingOpener` implements it for `MerkleTreeMmcs`
   on the codeword shape (one matrix, binary, `cap_height = 0`, power-of-two
   height): the frontier plan is built in index space, 2^15-row block subtrees
   hash in parallel, each reduction level runs through `compress_many`, and only
   the boundary digests are kept. Byte equality is pinned in magnetar-pcs (the
   vendored crates ship no compilable unit tests here) over heights `2^0..2^10`,
   widths 1/2/3, empty/single/first-last/all/random/duplicate index sets, three
   chunkings, and the multi-block path at `2^16`/`2^17`.
3. `p3-binary-pcs`: `fold_codeword_streamed` folds each rate coset through the
   existing `fold_coset` engine (the one `fold_codeword_batch` already uses, so
   the fold is identical by construction); `fold_rounds_streaming` and
   `open_queries_streaming` mirror the shipped fold and query phases with the
   base codeword re-derived instead of read; `BinaryPcs::open_at_streaming`
   builds the layout from the witness and assembles the same `BinaryPcsProof`.

Magnetar-pcs routes `Pcs::open`, `open_batch` and `open_mosaic` to it behind
`MAGNETAR_STREAM_PCS_OPEN=1` (opt-in for memory-bound runs). A new test,
`streamed_opening_matches_the_retained_path`, pins the serialized proof bytes
equal to the retained path at `2^8`/`2^10` rows, rates 1-2, and checks the
streamed proof verifies.

**Measured** (`paper_unified_bench`, `TRACE_SHOUT=1`,
`MAGNETAR_SERIALIZE_PRODUCTS=1`, same binary, env-switched):

| size | Opening footprint | bench peak footprint | prove CPU | proof |
| --- | --- | --- | --- | --- |
| `2^16` | 1.45 -> **0.83 GiB** | 1.49-1.50 -> 1.47-1.54 (peak floor is the selected product phase) | 287 -> 299 s (**+4.1 %**) | identical |
| `2^17` | 3.02 -> **1.65 GiB** | 3.02 -> **2.10 GiB (-0.92, -30 %)** | 597 -> 622 s (+4.3 %) | identical |
| `2^18` | 5.86 -> **2.89 GiB** | 5.96 -> **3.60 GiB (-2.36, -40 %)** | 1246 -> 1285 s (+3.1 %) | identical |
| `2^19` | 11.67 -> **6.23 GiB** | 11.93 -> **7.66 GiB (-4.27, -36 %)** | 2584 -> 2661 s (+3.0 %) | identical |

Proof bytes at those sizes: 1,018,155 / 1,110,291 / 1,230,360 B (varint and
compressed identical too). So the opening half of the PCS lever is now a
measured `-2.4 GiB` at `2^18` and the `2^18` products-gated peak drops below
4 GiB for the first time (5.96 -> 3.60 GiB).

**`2^19` staircase, 2026-11-14 quiet window** (`ADDS=524287`,
`MAGNETAR_STREAM_BUDGET_LOG=25`, `MAGNETAR_SERIALIZE_PRODUCTS=1`, watchdog
8 GiB; host had 11.8 GiB free+inactive, the first window all session above the
old >=13 GiB requirement). Streamed opening: peak footprint **7.66 GiB**, RSS
peak 6.47 GiB, Opening footprint 6.23 GiB, prove CPU 2661.4 s, proof
1,373,708 B. Retained opening in the same window: peak footprint **11.93 GiB**,
Opening footprint 11.67 GiB, CPU 2584.4 s, proof byte-identical. So:
**`-4.27 GiB` peak (-36 %) at `2^19`**, and the staircase row the previous
sessions could not run (docs `PAPER_CEILING` §2 item 5: "needs >=13 GiB
free+inactive") now fits in a 7.7 GiB envelope. A `2^20` row needs roughly
`2*7.66 - 4.0 (context)` ≈ 11.3-15 GiB and is the next staircase target.

**The remaining cost — fixed (same day).** The opening used to recompute the
cap (`streamed_codeword_root` inside `streamed_open`) even though the prover
had committed the same message earlier: one extra codeword encode and one extra
leaf-hash pass, the `+3-4 %` above. `magnetar_proof::Pcs` now has
`open_with_commitment(values, point, commitment)` (default: `open`), the
`P3BinaryPcs` open entry points take the known cap
(`open_with_cap`/`open_batch_with_cap`/`open_mosaic_with_cap`) and skip the cap
pass, `P3SharedPcs` and the `BitPcs` wrappers forward it, and the call sites
with the commitment in scope use it (unified mosaic, packed Shout/Router
trails, bound rows, trace commitment, local twist batches).

Measured on the same binary: `2^18` prove CPU 1249 -> **1225 s** (legacy
1201 s, host drift) and peak 3.60 -> **3.33 GiB**; `2^19` CPU 2638 ->
**2541 s**, peak 5.79 -> **5.74 GiB**. The streamed opening is now *cheaper*
than the retained path in CPU (2541 s vs 2584 s at `2^19`) while using
5.74 GiB against 11.93 GiB. Proofs unchanged at both sizes.

### 4.8 (h) bit-packed twist tables: assessment (not started)

The committed twist tables are 16-byte field elements holding bits or words:
`BatchTables::addr` is `2 * address_bits + 2` bit columns over `cycles` rows,
`initial`/`read_value`/`write_value` hold one 64-bit word per cycle, and `inc`
holds cycle counters. Packing them to bits/words shrinks the committed cells,
the codeword and the Merkle tree of the Access PCS by up to 16x, and it
compounds with §4.6/§4.7 because the streamed encoder works on whatever message
layout the prover writes.

It is a format change: the mosaic layout (`P3MosaicTable` columns and their
arities), the Access sum-check consumers (`address_columns()`, `increments()`,
`increments()` bit roles), the mosaic opening schedule and the verifier's
mosaic checks all move together, and the proof bytes change. A first increment
is to bit-pack only the **address** table (the one-hot bit columns,
`2*bits+2` columns) behind an env switch with proof-byte diffing and a prover
commitment A/B, then extend to the value/initial columns once the sum-check
factors are re-derived. Not started; recorded here so the next session picks up
the layout and consumer list rather than rediscovering them.

**Verification tail for §4.7.** Full workspace gate on the streamed-opening
tree: **683 passed / 0 failed / 8 ignored** (39 binaries) — the 679/0/8 of
§4.6 plus `streamed_opening_matches_the_retained_path`, the two
`streaming_multiproof_*` tests and `chunked_encoder_reproduces_the_borrowed_codeword`.
The default (opt-in off) path is byte-identical to the pre-change tree, and the
`MAGNETAR_STREAM_PCS_OPEN=1` path produces identical proof bytes at `2^16`,
`2^17` and `2^18`.

**§4.8 second slice DONE (2026-11-14): packed value history.** The witness
`value` matrix (one full cell history per cycle) is now a flat `Vec<u64>`
instead of `Vec<Vec<F2_128>>`: half the bytes and one allocation per matrix
instead of one per cycle. The linear path never reads it; the readers use
`value_row` / `value_row_into_field`. Measured: `2^18` context 1.77 -> **1.56
GiB**, peak 3.58 -> **3.20 GiB**; `2^19` peak 7.11 -> **5.79 GiB**; proofs
identical. Together the two (h) witness slices take `2^19` from **7.66 to 5.79
GiB** and `2^18` from 3.60 to 3.20 GiB (see the table below).

**§4.8 first slice DONE (2026-11-14): packed address rows.** `AddressRows` now
stores each cycle's one-hot read/write address row as one bit per slot in `u64`
words (`magnetar-memory::AddressRows`); the witness fields switch to it and
every consumer reads through `one_hot`/`bit`/`row_into_field`. Committed tables
and proof bytes are unchanged. Measured (`paper_unified_bench`, serialize
products + streamed opening): `2^18` unified context 2.60 -> **1.77 GiB** and
Access-stage footprint 2.72 -> **1.24 GiB** (peak 3.58 GiB, now the Opening;
was 3.60), `2^19` peak 7.66 -> **7.11 GiB**; proofs identical
(1,230,360 / 1,373,708 B); prove CPU unchanged within drift. The next slice is
the witness `value` matrix below.

**§4.8 addendum (2026-11-14): the concrete (h) first slice.** Reading the
witness definition fixes the target. `magnetar-memory::BinaryTwistWitness`
stores three *bit* matrices as `Vec<Vec<F2_128>>`, one 16-byte field element per
bit and one heap row per cycle:

| field | shape | bytes at `2^16` | at `2^18` |
| --- | --- | --- | --- |
| `read_address` | `cell_bits x cycles` | 64 MiB | 256 MiB |
| `write_address` | `cell_bits x cycles` | 64 MiB | 256 MiB |
| `value` | `value_bits x cycles` | 64 MiB | 256 MiB |
| `increment`/`read_value`/`write_value` | `cycles` each | 3 MiB | 12 MiB |

plus one allocator row per `(bit, cycle)` pair. A register-twist witness
therefore costs ~192 MiB at `2^16` and ~768 MiB at `2^18` *before* it is
converted into `BatchTables`, and it stays live through the Access stage.

The first slice is to store each cycle's bit row as one `u128` word
(`read_address: Vec<u128>`, bit `i` = address bit `i`; `value: Vec<u128>`
likewise), which cuts those three matrices 16x and removes the per-row
allocations — `2^16`: 192 MiB -> 12 MiB, `2^18`: 768 MiB -> 48 MiB. It is
prover-internal only: the committed `BatchTables::addr`/`initial`/values and
the Access sum-check are unchanged, so the proof bytes stay identical. The
readers are mechanical and enumerable: `batch_tables_inner`'s `one_hot_address`
(use a `u128` + `address_bits` decoder), the quadratic path's bit-table fills,
`binary_twist_address.rs`'s two slice reads, `virtual_onehot.rs`'s witness
access, `register_twist.rs`'s builder, and `protocol.rs`'s `len()` use.
Verification: the existing byte-equality tests plus the full gate; the memory
A/B reads the Access stage RSS with the same watchdog used in §4.2. A second
slice would then pack the *committed* `addr` table itself (format change,
§4.8 above), which is the part that also shrinks codewords and Merkle trees.

**§4.8 verification tail.** Full workspace gate on the packed-address-row tree:
**683 passed / 0 failed / 8 ignored** (39 binaries), including the 364-test
magnetar-runtime suite and the 14-test magnetar-memory suite. Proof bytes are
identical at `2^18` and `2^19` (`1,230,360` / `1,373,708 B`, varint and
compressed too), so the packing is witness-lifetime memory only.

**§4.8 second-slice verification tail.** Full workspace gate after the value
history packing: **683 passed / 0 failed / 8 ignored** (39 binaries), and
proof bytes are identical at `2^18`/`2^19` (`1,230,360` / `1,373,708 B`,
varint and compressed too). Cumulative effect of the two (h) witness slices
together with the streamed connection paths:

| peak footprint (products-gated, streamed opening) | `2^18` | `2^19` |
| --- | --- | --- |
| before this session's PCS work | 5.96 GiB | 11.93 GiB |
| after streamed commit + streamed opening | 3.60 GiB | 7.66 GiB |
| + packed twist address rows | 3.58 GiB | 7.11 GiB |
| + packed twist value history | **3.20 GiB** | **5.79 GiB** |
