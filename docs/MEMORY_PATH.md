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
| (e) release freed pages between stages (§3.1) | `malloc_zone_pressure_relief`/`madvise(MADV_FREE)` after each big transient | −0.1-0.4 GiB | −10-30 GiB (if retention is real) | 1-day experiment; macOS malloc may already `munmap` large blocks, so measure stage RSS first | cheapest; measure before building on it |
| (f) shrink level stores | inner budget 24 → 22 | −0.5 GiB | −0.5 GiB | +7 s prove at `2^16` (+22 %); recompute passes scale with `cycles` | not a memory lever; keep for a hard cap only |
| (g) Merkle cap height / arity | top layers only | −ε | −ε | trivial | skip |
| (h) bit-pack the twist witnesses/batch tables | one-hot address matrices and boolean bit columns stored as 16 B/element; repack like `PackedBits` | ~−0.2 GiB | −15-25 GiB (part of §1.1) | medium: witness builders + `batch_tables` + Access consumers; mechanical but pervasive; combine with (d) | second structural item |

Rejected outright: caching prepared commit data into Opening — it *adds* the
selected prepared set (up to 24 GiB) and/or the mosaic prepared set (36 GiB) to
the steady peak at `2^22`; the commit gate already removes the only overlap
worth removing.

## 5. Recommended order and tests

Order by GiB saved per unit of work:

1. **(e) + stage RSS instrumentation** (1 day, design in §3.1): per-stage peak prints already
   exist (`MAGNETAR_PROFILE_UNIFIED`/`SELECTED`); add an explicit
   release-and-measure hook, decide whether retention is real, and fix the
   `≈20 GiB` sentence in results §6 with the §3 numbers.
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
