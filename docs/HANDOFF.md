# Handoff — MagnetarVM streaming selected prover (RV64)

Status: **incremental optimization phase (Part 1 closed, Part 2 in progress)**,
branch `virtual-claims-rewrite`. Commits through `299b08b` (M6 increments 1-3:
parallel/phase-split statement-only v4 verifier + shared access claims; M4b
paper-path default flip; memory route (d) increments 1+2; stage memory
instrumentation; Access-PCS lifetime; opt-in Access scheduling switch; compact
Access sum-check factors; products-gated memory mode). Gate on the current
tree: **675 passed / 0 failed / 8 ignored** (39 binaries): `1b26b4e`
(2^16 optimization + polylog claim table), `9e805f2` (segment claims),
`a3a6e9c` (packed CSR + fast pair), `e320cf9` (M4v3 batched committed-Shout
opening + M4b paper-path replacement, opt-in), `9556746` (M5 scaffold:
table-only claim proof + v4 statement root), `d61ea71` (allocator-release hooks
+ phys_footprint instrumentation), `9e2e407` (M5b phase 1: committed access
columns + O(1) access digest). Full workspace gate on the M4v3+M5 tree:
**670 passed / 0 failed / 3 ignored**; `cargo build --workspace --examples
--release` green. The M5b phase 1 tree adds a 362-test runtime suite pass
(claim 53, access_table 4, byte equality green). **Current tree (M6 increments 1-3
+ M4b flip + memory route (d) increment 1) gate: 674 passed / 0 failed /
5 ignored**; the M4b-flip tree additionally passed the `MAGNETAR_CLASSIC_LOGUP=1`
leg (674/0/5), examples build green, and `protocol_determinism`
runs=20 identical=20 failures=0, peak 1.95 GiB.

**M4b paper default flip (2026-11-07)**: the paper path now defaults to the
committed-pushforward linear Shout; `MAGNETAR_CLASSIC_LOGUP=1` restores the
classic wire and the native `TRACE_SHOUT` path keeps M4v3 opt-in. This closes
the paper verifier's "Shout carried but not verified" gap and needs
`paper_statement_claim_root` for paper statements, plus a trace-side binding of
the committed Shout tables. Details:
[M4B_DEFAULT_FLIP.md](M4B_DEFAULT_FLIP.md),
[POLYLOG_CLAIM_VERIFIER.md](POLYLOG_CLAIM_VERIFIER.md) §C.16.

**M6 increments 1-3 (2026-11-07/08)**: the statement-only v4 verifier is one
independent five-job wave, the selected-lockstep verifier is split into
independently schedulable phases (segment row/shape on a worker, claim
derivation handed over by channel, challenge phase, then the PCS opening check
overlapped with the matrix build and MLE evaluations), and the access verifier
now hands its mosaic claims to the core verifier instead of letting it re-derive
them. A quiet-window interleaved A/B at `2^16` (`m6_verify_ab`, load 12) now
measures the statement-only v4 verify wall at **10.84 ms (min 10.50)**, inside
the paper's **8-12 ms target**, at 2.29x wall against the serial verifier and
+9 % CPU (serial CPU itself fell 49.0 -> 38.1 ms after the increment-3 dedupe).
The wall history is 42.8 -> 17.7 -> 13.4 -> **10.8 ms**; the paper-path default
(M4b flipped) verifies in 16.9 ms with a 1,169,603 B proof. Proof unchanged
(verifier-only). Details:
[POLYLOG_CLAIM_VERIFIER.md](POLYLOG_CLAIM_VERIFIER.md) §C.15, §C.17, §C.18,
§C.20. Remaining levers are optional CPU/contention work only (§5 item 1).

**Strongest memory mode (2026-11-14)**: `MAGNETAR_SERIALIZE_PRODUCTS=1` holds
the selected thread's commit/products until the mosaic Opening has finished, so
the products overlap neither Access nor Opening. Byte-identical proofs (ignored
`m5_v4_tests::serialize_products_proof_bytes_match`). Peak footprint **2^16
2.08 -> 1.64 GiB** and **2^17 4.15 -> 3.28 GiB (-21 % at both)**, for ~3 %
prove wall and no CPU increase (2^16 prove 40.0 -> 41.1 s, CPU 288.7 -> 281.2 s;
2^17 90.8 -> 93.6 s, CPU 600.3 -> 604.8 s). Recommended for the 2^19+ staircase
runs. [MEMORY_PATH.md](MEMORY_PATH.md) §4.2.

**Opt-in Access scheduling switch (2026-11-08)**: `MAGNETAR_SERIALIZE_ACCESS=1`
starts the selected commit/products after the Access stage instead of after the
mosaic Commit, so the two working sets do not overlap. Byte-identical proofs
(pinned by an ignored test). `2^16`: peak footprint **2.17 -> 1.78 GiB
(-18 %)** for +1.7 % prove wall; `2^18`: **7.96 -> 6.96 GiB (-12.6 %)** with the
wall unchanged and the peak moving from Access to the mosaic Opening
(MEMORY_PATH.md §4.2). Opt-in for memory-bound runs.

**Access PCS lifetime (2026-11-08)**: `prove_local_shared` no longer retains
the prepared codeword/Merkle batch until the opening; it re-encodes at the
opening (the selected prover's pattern), byte-identically. `2^18` same-window
A/B: peak footprint **8.72 -> 7.96 GiB (-8.7 %)**, RSS 6.51 -> 6.17 GiB,
CPU +0.1 % (noise); `MAGNETAR_KEEP_LOCAL_PREPARED=1` restores the old lifetime
for A/B (MEMORY_PATH.md §4.2).

**Memory route (d) increments 1+2 (2026-11-08)**: the unified context drops
its Access-only twist witnesses/batch tables right after the Access stage, the
dead `aux_tables` clones are gone, the linear twist path builds committed-only
batch tables (the never-read per-cell bit tables are skipped) and moves the five
committed tables into the mosaic instead of cloning them, and the trace witness
values now live exactly once (in the mosaic trace table) instead of three
times. At `2^17` a same-window A/B measures the native-default peak
**4.51 -> 3.95 GiB footprint (-0.56 GiB, -12.4 %)**, RSS -0.2 to -0.7 GiB,
prove CPU -0.7 % (noise) and **byte-identical proofs** (1,110,291 B, the
documented baseline); the `2^16` delta (0.03-0.12 GiB) sits below this host's
~0.2 GiB absolute-peak drift. Details: [MEMORY_PATH.md](MEMORY_PATH.md) §4.1;
`MAGNETAR_KEEP_PROVER_INPUTS=1` is the A/B switch.

**Compact Access sum-check factors (2026-11-14)**: the Access prover
(`local_shared`, both the RAM and the register twist) stored `eq(cycle_point)`,
`increment`, and `eq(cell_point)` expanded to `cells * cycles` field elements.
`SumcheckFactor` now keeps the distinct block (`repeat_low` / `repeat_high`) and
the mixed sum-check reads it through `at()`; values and pair order are
identical, so **proof bytes are unchanged** (native 1,018,155 B, paper path
1,169,603 B, access 221,876 B) and a new test pins the compact route against the
dense reference (`binary_twist::tests::compact_factors_match_the_expanded_sumcheck`).
At `2^16`: Access-prover CPU 22.4 -> **18.1 s (-19 %)**, whole-prove CPU
288.1 -> **280.0 s (-2.8 %)**, peak footprint 1.99 -> **1.89 GiB (-5 %)**; live
factor memory -4 arrays (134 MB at `2^16`, 536 MB at `2^18`).
[MEMORY_PATH.md](MEMORY_PATH.md) §4.4. Direct measurement also **corrected** the
earlier claim that the dense Access factors were ~36 % of the `2^16` peak: they
were ~12 %, and the peak is set by the commit transients (§4.2).

**Final verification on the current tree (2026-11-08, load 10-41):**
`protocol_determinism` 20/20 byte-identical, 0 failures, peak 1.88 GiB;
`m6_verify_ab` quiet A/B: serial 24.87 ms (CPU 38.06) vs parallel **10.83 ms
(min 10.64, CPU 40.35)** = 2.30x wall at +6 % CPU. `2^16` native default:
prove **30.34 s** / CPU 288.1 s, verify **22.18 ms**, proof 1,018,155 B, peak
**1.98 GiB footprint**; with `MAGNETAR_SERIALIZE_ACCESS=1`: prove 31.18 s,
peak **1.78 GiB footprint** (memory-bound mode). Paper-path default (M4b):
prove 30.44 s, verify **16.42 ms**, proof 1,169,603 B, peak 1.97 GiB.
Full workspace gate on this tree: **674 passed / 0 failed / 7 ignored**
(39 binaries).

**Memory attribution fixed (2026-11-08)**: the stage RSS prints now use
in-process `getrusage` + `phys_footprint` (the old `ps`-based helper returned
0.00 under the sandbox) and print `rss_peak=` next to `footprint=`;
[MEMORY_PATH.md](MEMORY_PATH.md) §4.2 has the first real stage table at `2^16`
(peak first reached during the unified Access stage; live footprint after
Access 0.39 GiB with route (d) vs 2.17 GiB with the old lifetime).

**Part 1 (2^16 optimization) is closed**: prove 70.4 -> **31.4-34.6 s** (CPU
~800 -> **274 s**, 2.9x less work), verify 29.6 -> **24.7-27.2 ms**, peak
2.26 -> **1.94-2.01 GiB**, proof unchanged by the prover work (1,018,153 B is
the claim-table format). The remaining terms are `product6` 18.2 s (a packed
CSR scan at the algebraic floor of the pair polynomial), `product2` 10.6 s,
Access ~2 s, mosaic Opening ~2.1 s. The only further product6 idea on the
table (a fused round-0 kernel) is estimated at 7-9 % of product6 (~1.5 s wall)
and would add a second code path, so it is deliberately not taken.
Chinese sibling: [handoff-zh.md](handoff-zh.md).
Measurements and per-round history: [STREAMING_SELECTED_PROVER_RESULTS.md](STREAMING_SELECTED_PROVER_RESULTS.md)
([中文](streaming-selected-prover-results-zh.md)). Background design: [STREAMING_SELECTED_PROVER_HANDOFF.md](STREAMING_SELECTED_PROVER_HANDOFF.md).

Headline at RV64 `2^16` (2026-11-03 round, host load 15–66): **prove 31.4–34.6 s
(prove CPU 274.2–274.9 s vs ≈800 s before), verify 24.7–27.2 ms, peak 1.94–2.01 GiB**.
After the M5b-era instrumentation the native default peak measures **1.41 GiB
RSS / 1.82 GiB phys_footprint** (the `drop(stored)` free); the paper-path and
opt-in rows are in §2.1. The
streaming prover is still byte-identical to the eager path; the *proof file* is
1,018,152 B because the polylog claim layer (results §11.6) now commits the
claim table and attaches it to `ClaimProof` -- with the claim table off the same
binary gives verify 46.0 ms and 861,408 B, so the table is worth +157 KB of
proof for -18.6 ms of verify. The row blob is still carried during the
transition, so the size goes back down when M4/M5 remove it. Workspace tests:
**655 passed / 0 failed**; `protocol_determinism` 20/20 byte-identical at
1.99 GiB peak.

The M5+M4b statement-only verifier (three opt-in env switches) now measures
**17.7 ms** wall at `2^16` (median of an interleaved same-process A/B; 42.8 ms
before the 2026-11-07 M6 wave) against a previous all-paths floor of
24.7-27.2 ms, while its CPU is 56.6 ms/iter (+16 %: the wave trades CPU for
latency). The paper target is 8-12 ms and needs the FRI openings merged, not
more claim work (§5 item 1).

---

## 1. Run it

**Cargo home on this checkout (2026-11-14).** The machine's `~/.cargo` is not
writable from the sandbox and the checkout ships no `target/`, so a build fails
with `failed to create directory .../.cargo/registry/cache/...`. Fetch once into
a workspace-local cargo home (git-ignored) and prefix every cargo command:

```sh
export CARGO_HOME=$PWD/.cargo-home
cargo fetch
```

```sh
cargo build --release -p magnetar-testkit --example paper_unified_bench

# Full paper benchmark at 2^16 (adds = 2^16-1), RV64
ADDS=65535 WIDTH=64 TRACE_SHOUT=1 MAGNETAR_STREAM_BUDGET_LOG=22 \
  target/release/examples/paper_unified_bench

# Stage profiles (all are env-gated prints, no behavioural change)
MAGNETAR_PROFILE_UNIFIED=1   # unified context/Commit/Access/Opening
MAGNETAR_PROFILE_SELECTED=1  # selected setup/commit/product6/product2/open
MAGNETAR_PROFILE_STREAM=1    # streaming recompute/fold rounds + CSR density
MAGNETAR_PROFILE_RING=1      # ring-switch pack/eval/product2/p3 open
MAGNETAR_PROFILE_LOCAL=1     # register twist (standalone bench below)
MAGNETAR_PROFILE_VERIFY=1 MAGNETAR_VERIFY_CPU=5   # verifier stages + CPU/iter
MAGNETAR_VERIFY_SERIAL=1     # straight-line verifier (default: parallel wave) for wall A/B

# Streaming-scan diagnostic switches (same-binary A/B; every stage print also
# carries cumulative process CPU time, which is the load-robust metric, see §6)
MAGNETAR_STREAM_WORKERS=N      # worker count (default: available_parallelism)
MAGNETAR_LIVE_FULL=1           # disable the zero-padding row skip (A/B)
MAGNETAR_P2_FUSED=1            # fused inner block loop (measured 35% slower)
MAGNETAR_INNER_BUDGET_LOG=NN   # inner sum-check level budget (default 24)
MAGNETAR_MAX_RSS_GIB=4.0       # benchmark watchdog (magnetar-testkit examples)

# Register twist alone (Access layer), 2^16 rows
ROWS=65536 MAGNETAR_PROFILE_LOCAL=1 target/release/examples/local_shared_bench

# M6 verify-latency A/B: one 2^16 proof, then serial/parallel verification
# alternated inside one process (the only load-robust wall comparison here)
ADDS=65535 MAGNETAR_CLAIM_V4=1 MAGNETAR_ACCESS_COLUMNS=1 MAGNETAR_LINEAR_SHOUT=1 \
  target/release/examples/m6_verify_ab

# Gates
cargo test --workspace --release          # 651 tests
target/release/examples/protocol_determinism   # 20 concurrent pairs by default (PROTOCOL_THREADS/ROUNDS)
```

**Host hygiene.** A 1-minute load average is not enough on this machine: an iOS
simulator holding cores made the same binary report 121 s while using only 738
CPU-seconds over 121 s (≈6 effective cores) against ≈11 in the 70.4 s run.
Always quote `prove cpu / wall` and the load together; discard runs whose
core count is low.

## 2. Where it stands

| cycles | prove | verify | peak RSS | proof |
| --- | --- | --- | --- | --- |
| `2^16` (2026-11-03, packed CSR + fast pair) | **31.4–34.6 s** | **24.7–27.2 ms** | **1.94–2.01 GiB** | 1,018,153 B† |
| `2^16` (2026-11-03, chunked inner scan only) | 38.3–38.6 s | 24.7–25.1 ms | 2.03 GiB | 1,018,153 B† |
| `2^16` (2026-11-03, before chunked inner scan) | 53.8–59.3 s | 27.3–27.4 ms | 2.04–2.38 GiB | 1,018,152 B† |
| `2^16` (2026-10-31) | 70.4 s | 29.6 ms | 2.26 GiB | 861,407 B |
| `2^17` (2026-11-07, refreshed) | **96.4 s** | 68.9 ms (CPU 249.2 ms) | 4.02 GiB | 1,110,291 B† |
| `2^18` (2026-11-07, refreshed) | **211.2 s** | 161.5 ms → 220.0 ms (CPU 503.0 ms) | **5.75 GiB RSS / 7.20 GiB footprint** | 1,230,360 B† |
| `2^19` | 667.8 s (pre-fusion) | 318.3 ms | 10.54 GiB | 1,177,984 B |

**2026-11-08 staircase refresh (route (d) tree, quiet-window sequence starting
at load 4; the load rose during the sequence, see the note).** Native default
(`TRACE_SHOUT=1`), one run per size, `MAGNETAR_MAX_RSS_GIB=8`:

| cycles | prove | prove CPU | verify (single) | peak RSS / footprint | proof |
| --- | --- | --- | --- | --- | --- |
| `2^16` | **30.3 s** | 288.1 s | **22.2 ms** | **1.98 GiB footprint** (1.78 with the memory switch) | 1,018,155 B |
| `2^17` | **62.6 s** | 595.5 s | 40.7 ms | 4.35 / 4.35 GiB* | 1,110,291 B |
| `2^18` | **133.1 s** | 1240.3 s | 109.5 ms | **6.37 / 7.97 GiB*** | 1,230,360 B |

\* `2^17`/`2^18` were measured before the Access-PCS lifetime change (which
removed a further 0.76 GiB of `2^18` footprint in a same-window A/B) and before
`MAGNETAR_SERIALIZE_ACCESS` (a further -1.0 GiB at `2^18`); the `2^16` row is the
current binary.

Proof bytes are identical to the documented baselines at all three sizes (the
route (d) lifetime change is byte-neutral); the `2^16` verify improved to
22.3 ms because the M6 verifier changes also cover the non-v4 dynamic path.
The runs started in a quiet window (load 4) and the load rose to 28-57 by the
`2^17`/`2^18` runs, so the wall columns are optimistic relative to the
2026-11-07 rows (which were measured at load ~29 but with the pre-route-(d)
tree); the CPU columns are the load-robust comparison. At `2^18` the footprint
exceeds RSS by 2.0 GiB, so both must be quoted. `2^19` was **not** run: the
host had 12.3 GiB free+inactive in the window and the MEMORY_PATH §3.1
protocol wants peak+4 GiB (≈13.5 GiB for the post-route-(d) estimate) -- it
needs a dedicated window.

† proof size is the claim-table format; the streaming proof itself is still
byte-identical to the eager path. See results §11.6. The same 2^17 row with
`MAGNETAR_CLAIM_V4=1 MAGNETAR_ACCESS_COLUMNS=1 MAGNETAR_LINEAR_SHOUT=1`
(M5+M4b) gives verify CPU 61.9 ms/iter (-75 %), peak 3.57 GiB and 1,275,305 B
(docs/POLYLOG_CLAIM_VERIFIER.md §C.14.1).
`2^18`/`2^19` predate the fused scan and the ring-switch fix; two loaded re-runs
gave 335 s and 437 s with 5.7–7.8 GiB peak and were discarded. **The ≈20 GiB
`2^22` projection below is retracted**: the constant staircase deltas were
allocator reuse, not a model. A Merkle tree lives together with its codeword, so
the mosaic commit/opening alone forces >=32 GiB live and the hard lower bound is
>=37 GiB (model 60–90 GiB); see [MEMORY_PATH.md](MEMORY_PATH.md) and results §8.

### 2.1 Opt-in paths and the M4b/M4v3 trade (2^16, `d61ea71`, load 20–90)

`verify CPU/iter` comes from `MAGNETAR_VERIFY_CPU=20` (the verifier runs two
waves, so CPU > wall); peak is RSS and phys_footprint; wall is not comparable
across rows.

| 2^16 run | proof | verify CPU/iter | footprint | RSS |
| --- | --- | --- | --- | --- |
| native default (`TRACE_SHOUT=1`) | 1,018,154 B | 158.2 ms | 1.82 GiB | 1.41 GiB |
| native `MAGNETAR_LINEAR_SHOUT=1` (M4v3) | 1,169,602 B (+151 KB) | **101.6 ms (-36 %)** | 2.06 GiB | 1.81 GiB |
| paper default | 1,199,746 B | 96.9 ms | **2.61 GiB** | 2.07 GiB |
| paper `MAGNETAR_LINEAR_SHOUT=1` (M4b) | 1,169,602 B (-30 KB) | **87.7 ms (-9.5 %)** | **1.99 GiB (-0.62)** | 1.44 GiB |

The paper M4b opt-in is better on all four metrics because it drops the classic
25-column `logup_shout` mosaic opening (the paper path's memory peak) *and*
closes the paper verifier's "Shout carried but not verified" gap; the native
M4v3 opt-in instead trades +151 KB of proof for -36 % verify CPU. **The paper
path was flipped to M4b by default on 2026-11-07** (POLYLOG_CLAIM_VERIFIER.md
§C.16, M4B_DEFAULT_FLIP.md): the "paper default" row above is now the M4b wire
(1,169,602 B) and `MAGNETAR_CLASSIC_LOGUP=1` restores the old 1,199,746 B
classic wire for A/B. M4v3 stays a measured opt-in on the native path until the
proof-size trade changes.

`2^16` stage split after the packed CSR + fast pair (load 15–65): selected
`product6` **18.18/18.36**, `product2` **10.59/10.63** (was 24.5 before results
§11.3 item 8 and 24.9 before item 9), segments **0.009**, selected open ~0.85;
unified Access ~2.0, Opening ~2.1. `product6` is still the largest term at
~55 % of prove. The earlier splits were: (load 37–72) context 0.31, Commit 0.52, Access
2.63, Opening 1.99, witness commit 0.30, `product6` 26.0, `product2` 24.9;
(load 70–90) context 0.48, Commit 1.19, Access 2.56, Opening 3.38, setup 0.48,
witness commit 0.95, `product6` 43.2, `product2` 23.4, segments 1.17, selected
open 0.92.

Verifier at `2^16` (30.3 ms wall over 5 iterations, 188 ms CPU/iter): trace
Logup-Shout 21.9–29.6 (starts as soon as the claim-derived trace exists and
overlaps both waves), claim row sums 11.5–12.4, core PCS 7.7–8.0, access 6.7,
claim leaves 3.8–4.1, claims decode 1.0, claims-to-trace 0.77.

**M6 increments 1+2 (2026-11-07) verify wall at `2^16`.** Under
`MAGNETAR_CLAIM_V4=1 MAGNETAR_ACCESS_COLUMNS=1 MAGNETAR_LINEAR_SHOUT=1` the
statement-only v4 verifier runs as a five-job wave
(access / claim table / selected binding / committed Shout / core), and the
selected job itself is phase-split: segment row/shape built on a worker thread,
folded claim handed over by channel, challenge phase, then the PCS opening
check overlapped with the matrix build and the six MLE evaluations.
Interleaved same-process A/B (`m6_verify_ab`): increment 1 gave serial
42.82 ms wall / 48.96 ms CPU vs parallel 17.70 / 56.60 (2.42x, +16 % CPU);
increment 2 gives serial 34.84 / 49.50 vs parallel **13.35 / 53.14 ms**
(2.61x, +8 % CPU; parallel min 12.84 ms). Serial drifts with host load -- quote
the ratio. The remaining critical path is the selected PCS opening check
(~6.7 ms), then the segment-matrix build (~3.3 ms) and the MLE evaluations
(~2.5-3.5 ms, parallel); see POLYLOG_CLAIM_VERIFIER.md §C.15/§C.17.
Final quiet-window A/B (2026-11-08, load 12, n=12 per mode): serial 24.80 ms
wall / 38.09 ms CPU vs parallel **10.84 ms / 10.50 min / 41.57 ms CPU** = 2.29x
wall at +9 % CPU -- inside the paper's 8-12 ms target. The paper-path default
(M4b) in the same window verifies a 1,169,603 B proof in 16.9 ms with a
1.98 GiB RSS / 1.97 GiB footprint peak. History in POLYLOG_CLAIM_VERIFIER.md
§C.20.

Increment 3 (2026-11-08) then made the access verifier return the mosaic claims
it already derives and the core verifier consume them instead of re-deriving
them (`verify_access_committed_with_claims`,
`verify_core_*_with_access_claims`, claims handed access -> core by channel):
the duplicate 4.84 ms wall / 14.42 ms CPU core stage collapses to ~0 and the
core job drops 9.91 -> 6.54 ms wall (26.97 -> 15.00 ms CPU) in profiled runs;
whole-verify parallel CPU 58.25 -> 53.14 ms/iter, parallel-vs-serial CPU premium
+14 % -> +6.5 %. The wall critical path is the selected job, so this is a
CPU/contention win; a quiet-window wall A/B is pending (host at load 40-260
during the attempt) -- last quiet reference is 13.35 ms.

## 3. Code map

| Area | File |
| --- | --- |
| Streaming lockstep prover (outer product6, inner product2) | [stream.rs:363](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/stream.rs#L363), [stream.rs:973](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/stream.rs#L973) |
| Fused weighted row scan / block scan | [stream.rs:470](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/stream.rs#L470) (`accumulate_block`), [stream.rs:410](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/stream.rs#L410) (branch-free set-bit) |
| Zero-padding skip (`live_rows`) | [stream.rs:245](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/stream.rs#L245) |
| Work-stealing round scheduler | [stream.rs:108](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/stream.rs#L108) |
| Inner level budget (`auto_level_inner`) | [stream.rs:170](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/stream.rs#L170) |
| CPU-time stage instrumentation | [lib.rs:15](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/lib.rs#L15) |
| Benchmark RSS watchdog | [testkit/src/lib.rs:89](file:///Users/mac/projects/MagnetarVM/crates/magnetar-testkit/src/lib.rs#L89) |
| Ring-switch PCS (bit → field, eq table, opening) | [bit_pcs.rs:737](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/bit_pcs.rs#L737), [bit_pcs.rs:875](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/bit_pcs.rs#L875) |
| p3 PCS wrapper: 16 B digest, prepared batches | [p3_pcs.rs:34](file:///Users/mac/projects/MagnetarVM/crates/magnetar-pcs/src/p3_pcs.rs#L34), [p3_pcs.rs:432](file:///Users/mac/projects/MagnetarVM/crates/magnetar-pcs/src/p3_pcs.rs#L432) |
| Register-twist Access proof | [local_shared.rs:66](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/local_shared.rs#L66) |
| Selected PCS params / mosaic PCS profile | [protocol.rs:1651](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/protocol.rs#L1651), [protocol.rs:1991](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/protocol.rs#L1991) |
| Two-wave verifier + overlapped trace Logup | [lib.rs:3703](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/lib.rs#L3703), [lib.rs:3847](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/lib.rs#L3847) |
| Selected witness setup (parallel fill) | [simd_dual.rs](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/simd_dual.rs) (`dynamic_segment_setup`) |
| Gated bundle PC target | [gated_bundle.rs:398](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/gated_bundle.rs#L398) |
| Deterministic parallel grind (vendored) | [challenger.rs:278](file:///Users/mac/projects/MagnetarVM/vendor/plonky3/binary-field/src/challenger.rs#L278) |
| Benchmark harness | [paper_unified_bench.rs:54](file:///Users/mac/projects/MagnetarVM/crates/magnetar-testkit/examples/paper_unified_bench.rs#L54) |
| Statement-only v4 verifier (five-job wave) | [v4_verify.rs:27](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/v4_verify.rs#L27) |
| Verifier stage instrumentation (M6) | [verify_profile.rs:18](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/verify_profile.rs#L18) |
| Lockstep-bits verifier phases + overlapped PCS | [spartan.rs:2420](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/spartan.rs#L2420) (phase API), [spartan.rs:2638](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/spartan.rs#L2638) (parallel entry) |
| Prepared selected segments (M6 phase split) | [simd_dual.rs:7491](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/simd_dual.rs#L7491) |
| M6 verify wall/CPU A/B harness | [m6_verify_ab.rs:47](file:///Users/mac/projects/MagnetarVM/crates/magnetar-testkit/examples/m6_verify_ab.rs#L47) |

## 4. What changed in this phase

1. **Register-twist PCS pipeline** — profiling (`MAGNETAR_PROFILE_LOCAL`) showed
   94 % of the stage was PCS: one encode per commitment now (`commit_batch_prepared`),
   endpoint tables on the small-table profile, local PCS at rate 1/8 with
   20 grinding bits, plus p3 `parallel`. Standalone: 48.2 s → **1.43 s**
   (verify 3.7 ms, 1.43 GiB).
2. **Deterministic parallel grinding** — p3's parallel grind returned an
   arbitrary passing nonce (proof bytes varied run to run). The vendored
   `BinaryChallenger::grind` now scans fixed-size waves and returns the smallest
   passing candidate, which equals the serial result on every machine.
3. **Fused outer sum-check scan** — `LockstepRows::accumulate_row_values` folds
   the slot weight into the sparse CSR scan; bit-identical by distributivity.
   `product6` 51.8 → **43.2 s**.
4. **Ring-switch opening** — `eq_vector` allocated one `Vec` per table entry
   (4.2 M at `2^16`: `2^22` packed words). Doubling construction plus set-bit
   accumulation across workers: `ring eval` 2.89 → **0.13 s**, selected open
   3.68 → **0.92 s**.
5. **Verifier scheduling** — the trace Logup check starts with the claim-derived
   trace and overlaps both waves: 34.3 → **30.3 ms** wall (CPU 193 → 188).
6. **Width-64 conversion** (see §6) — every test and example that runs a proof
   now uses width 64. Three real bugs fell out: the mosaic PCS profile was
   chosen before later tables were appended (E5 field opening rejected at 64),
   `(1u64 << 64) - 1` wraps to a zero mask in the AMO/PC rows, and
   `prove_gated_bundle_from_trace` used `last_row.pc + 4` as the PC-chain target
   (overshoots when the row builder appends a halt row).

### 4.1 2026-11-03 round: `2^16` optimization

Details, measurements and the rejected experiments are in results §11.

7. **Zero-padding rows are no longer scanned.** At `2^16` the matrix rounds
   `2^29` instance rows + 4.19 M extras up to `2^30`, so 49.6 % of every outer
   pass was zeros. Same-binary A/B at `2^14`: product6 12.8 → 6.5 s.
8. **Branch-free set-bit accumulation** in the CSR scan (masked XOR instead of
   an unpredictable `if bit { add }`).
9. **Work-stealing round scheduling** (`parallel_chunks`): this host has 6
   performance + 6 efficiency cores, so a fixed split straggles. Field
   addition is XOR, so the merge order does not change proof bytes.
10. **Inner level budget 22 → 24** (`auto_level_inner`): -2 of 8 column scans,
    -25 % of the inner stage, at a fixed +512 MiB of level arrays.
11. **Load-robust measurement**: every stage print carries cumulative CPU time,
    and the streaming stages have same-binary diagnostic switches. Wall-clock
    A/B is unusable on this shared host (see §6).
12. **Benchmark memory watchdog** and a smaller default `protocol_determinism`
    (20 pairs, 1.99 GiB; the old 120-pair default peaked at 5.75 GiB).
13. **Segment claims rewritten**: shared per-width equality tensors, 64-bit word
    scanning and one thread per segment take `selected segments` 1.20 s → **9 ms**
    at `2^16` (claims bit-identical, proof bytes unchanged; ~1.19 s of serial-tail
    wall).
14. **Inner scan fills 512-column chunks**: amortises `fill_left`'s per-block
    bookkeeping ~256x in round 0 with the same per-column arithmetic.
    `2^14` same-binary A/B `product2` 12.4/17.0 -> 5.1/5.5 s and whole-run CPU
    103 -> 74 s; `2^16` inner recompute 226 -> **108 CPU-s (-52 %)**, so
    `product2` should fall from 24.5 to ~12 s on a quiet host
    (`MAGNETAR_P2_BLOCKWISE=1` keeps the old path for A/B).
15. **Packed CSR + reduced pair polynomial** (results §11.3 item 9): one `u32`
    per sparse entry (asserted unit coefficients), hoisted instance/local
    cursors, `eq1 - eq0 = high` (char 2), Karatsuba p1, pre-scaled eq high
    table: 21 -> 17 multiplies per block. `2^14` phase-1 CPU 50.10 -> 37.34
    CPU-s (-25.5 %), product6 wall -23 %, whole prove wall -15.3 %; final
    `2^16` **prove 31.4-34.6 s / CPU 274 s**, `product6` 18.2-18.4 s,
    `product2` 10.6 s, peak 1.94-2.01 GiB.
14. **Register-twist Access sum-checks**: `evaluate_points_at` now returns the
    factor value directly for `r == 0` / `r == 1` and reads each factor pair once
    (the old implementation multiplied for every evaluation point, including the
    two trivial ones). Same-binary A/B on `local_shared_bench ROWS=65536`:
    Access CPU 5.31 → **4.70 s** (-11.5 %), `rw` -0.35 s and final rounds -0.17 s.
    Claims and proof bytes unchanged; `MAGNETAR_LEGACY_EVAL_POINTS=1` keeps the old
    path for A/B.
15. **M4v3 batched committed Shout opening** (`e320cf9`): the committed Shout's
    word/position/pushforward tables are padded to one arity and committed with
    one `commit_batch_prepared`, then opened with one `open_batch_prepared`; the
    pushforward is committed *before* the transcript binds it and the binder is
    the digest of that commitment (the constant-zero placeholder that shipped in
    the first draft was a soundness gap). The reader point is derived from
    public data (`rom_hash || trace_len || arity`), which breaks the circular
    "commit pushforward vs derive reader point" dependency.
    `committed_logup_shout` at `2^16`: 514,689 -> **160,897 B**. Vendored p3
    `logup_star` gained an additive committed-pushforward API only (old paths
    untouched).
16. **M4b paper-path replacement** (`e320cf9`): on the paper path the opt-in
    skips the classic `shout`/`packed_shout` stage proofs and the classic
    25-column `logup_shout` mosaic opening and attaches the committed linear
    Shout instead; the verifier rejects proofs carrying both encodings and the
    statement-free core verifier rejects committed Shout (it needs the public
    ROM). This also closes the paper verifier's "Shout carried but not verified"
    gap and measured strictly better on all four metrics (§2.1).
17. **M5 scaffold** (`9556746`): `ClaimProofWire::TableOnly` appended at the end
    of the enum (old encodings unchanged), v4 statement root
    `H("claim-shout-v4" || claim_table_root || shout_tables_root)`,
    mixed-encoding rejection in both directions, and a deliberate dependency
    gate: the v4 verifier refuses until the claim table commits the access
    columns.
18. **M5b phase 1** (`9e2e407`): the claim table gains 478 access columns (2
    memory events/cycle x 268 bits + 3 register ops/cycle x 210 bits) on top of
    512 schema slots = 1024 combined slots, a single combined packed-bit table
    commitment, and `access_statement_digest = H("magnetar-access-v4" ||
    v4_table_root)`. All default off (`MAGNETAR_ACCESS_COLUMNS=1` requires
    `MAGNETAR_CLAIM_V4=1`).
19. **M5b-2b committed final-RAM table** (2026-11-07): `T_final` is 64 bit
    columns x padded cells committed with the Shout ring-switch backend, bound
    into the v4 statement root as a third component and tied to the twist's
    `final_eval` by a linear relation `sum_b 2^b * fold(bit_b, r_k) = final_eval`.
    The access layer is now fully witness-free (initial RAM public, final RAM
    committed); the remaining gate is M5c.
20. **Memory instrumentation and the footprint metric** (`d61ea71`): default-off
    allocator-release hooks plus `phys_footprint` sampling in the testkit
    watchdog. macOS counts freed-but-reusable pages in RSS but not in the OS
    footprint, so peaks must be quoted as both. The non-gated `drop(stored)` in
    the outer product scan alone dropped the native default peak to **1.41 GiB
    RSS / 1.82 GiB footprint**.

21. **M6 increment 1** (2026-11-07): the v4 statement-only verifier became one
    independent five-job wave (access / claim table / selected binding / committed
    Shout / core) joined in the original serial order, with the folded claim
    derived from public `claim_relation_inputs` so the claim-table check and the
    selected binding run concurrently. The `magnetar-proof` lockstep-bits
    verifier was split into composable phases (identical behaviour/error order)
    and a new parallel entry point overlaps the PCS opening check with the six
    matrix MLE evaluations, without adding `Sync` bounds to the matrix trait
    objects. `MAGNETAR_VERIFY_SERIAL=1` keeps a same-binary wall A/B and
    `m6_verify_ab` measures it interleaved in one process: **verify wall
    42.8 -> 17.7 ms (2.42x) for +16 % CPU**. Increment 2 then exposed the
    lockstep phase API (`LockstepBitsChallenges` + challenge/evaluation/
    finalize/PCS functions, challenge phase takes the matrix shape), moved the
    selected segment row/shape build to a wave worker, handed the folded claim
    from the claim job to the selected job by channel, and overlapped the PCS
    check with the matrix build: **17.7 -> 13.4 ms (2.61x, +8 % CPU, min
    12.8 ms)**. Increment 3 shares the access mosaic claims with the core
    verifier (`verify_access_committed_with_claims`,
    `verify_core_*_with_access_claims`, access -> core channel) removing a
    duplicate 4.84 ms wall / 14.42 ms CPU derivation (core job 9.91 -> 6.54 ms;
    parallel CPU 58.25 -> 53.14 ms/iter; wall critical path unchanged).
    Instrumentation:
    `verify_profile.rs` + `MAGNETAR_PROFILE_VERIFY` now prints wall and
    cumulative CPU per verifier stage.

22. **M4b paper-path default flip** (2026-11-07): the paper path defaults to
    the committed-pushforward linear Shout; `MAGNETAR_CLASSIC_LOGUP=1` restores
    the classic wire; the native `TRACE_SHOUT` path keeps M4v3 opt-in and M5 v4
    keeps its explicit `MAGNETAR_LINEAR_SHOUT` gate. New
    `paper_statement_claim_root(trace, width)` builds the v3 statement root for
    paper statements (`claim_table::statement_claim_root` is unchanged for the
    73 native call sites); the trace-carrying verifier now binds the committed
    Shout tables to the host-derived tables of the trace it is given (closes a
    pre-existing forged-table gap for M4v3/M4b). Dual-mode tests, an ignored
    round-trip A/B (default vs classic vs `MAGNETAR_LINEAR_SHOUT=1` byte
    equality) and an 11-case file-level tamper matrix cover it; the paper
    proof/wire size is unchanged from the §C.13.1 opt-in measurement
    (1,169,602 B at `2^16`).

23. **Memory route (d) increment 1** (2026-11-08): Access-input lifetime +
    compact twist tables. Removed the dead `aux_tables` clones; dropped the
    RAM/register twist witnesses and batch tables after the Access stage
    (`MAGNETAR_KEEP_PROVER_INPUTS=1` A/B switch); on the linear path
    (`cycles >= 8192`) the context builds committed-only batch tables
    (`batch_tables_committed_only`, skipping the never-read per-cell bit
    tables = 64 MiB register at `2^16`), moves the five committed tables into
    the mosaic instead of cloning, and keeps only the bit widths for the Access
    stage (`TwistAccessInputs::Linear`,
    `prove_binary_twist_claims_linear_shape`,
    `prove_trace_access_shared_linear`). Increment 2 (same day) removes the
    trace-witness duplicate: the context keeps only layout/point and the values
    live once inside the mosaic trace table
    (`trace_claim_points_from_parts`), saving 16 MiB at `2^16` / ~1 GiB at
    `2^22`. At `2^17` the same-window A/B is **4.51 -> 3.95 GiB footprint
    (-0.56 GiB, -12.4 %)**, RSS -0.2 to -0.7 GiB, prove CPU -0.7 % (noise),
    byte-identical proofs (1,110,291 B). Full measurements and the
    host-pressure caveat are in [MEMORY_PATH.md](MEMORY_PATH.md) §4.1.
    Increment 3 drops the Access PCS prepared batch instead of retaining it
    until the opening (re-encode at the opening, byte-identical): `2^18`
    same-window peak footprint **8.72 -> 7.96 GiB (-8.7 %)**, CPU +0.1 %;
    `MAGNETAR_KEEP_LOCAL_PREPARED=1` is the A/B switch (§4.2).

Peripheral stages (parallel track): the vendored p3 `Keccak256Hash16` did not
forward `hash_many`, so Merkle trees hashed serially; forwarding it cut p3 CPU
2.1–2.7x and `Commit`/`Opening` roughly in half. Plus a removed prepared-data
deep clone (-0.5 GiB memcpy at `2^16`) and deduplicated Access table builds
(register twist standalone 7.6 → 5.0 CPU-s).

## 5. Open work, in priority order

1. **M6 verify wall -- TARGET MET (2026-11-08).** The statement-only v4
   verifier measures **10.84 ms (min 10.50)** wall at `2^16` in a quiet-window
   interleaved A/B, inside the paper's **8-12 ms** target (2.29x over the
   serial verifier at +9 % CPU; serial CPU fell to 38.1 ms after the §C.18
   dedupe). History: 42.8 -> 17.7 -> 13.4 -> 10.8 ms
   (POLYLOG_CLAIM_VERIFIER.md §C.15/§C.17/§C.18/§C.20); the paper-path default
   verifies in 16.9 ms. What remains is optional CPU/contention polish:
   (a) parallelize the FRI/query-path verification in the vendored binary-pcs
   (the only way to cut the ~6.7 ms selected-PCS term), (b) merge the
   committed-Shout batch opening / mosaic opening / claim-table opening so one
   FRI covers them (removes ~11 ms of CPU; they are off the critical path, so
   this is a contention win only), (c) the segment-matrix build (~3.3 ms) could
   move fully onto the prepare worker. Nothing here is needed for the wall
   target anymore.
2. **Paper-path M4b default flip -- DONE (2026-11-07).** Landed with the full
   gate on both env legs (674/0/5), the file-level tamper matrix and the
   dual-mode tests (POLYLOG_CLAIM_VERIFIER.md §C.16, M4B_DEFAULT_FLIP.md).
   Remaining follow-up: external paper-statement builders must switch to
   `paper_statement_claim_root`; the classic paper wire itself keeps its
   unverified `logup_shout` opening and is now only the A/B leg.
3. **Allocator-release hooks: no-op at `2^16` and `2^17` (direct evidence).**
   With the fixed stage probes the `MAGNETAR_RELEASE_TRANSIENTS=1` release
   points now print what the allocator actually returns: at `2^17` every point
   reports `allocator returned 0.0 MiB` (selected commit, Access, Opening,
   finish, products) and the peak is unchanged (3.95 vs 3.96 GiB footprint;
   MEMORY_PATH.md §4.2). macOS libmalloc already returns the large blocks. The
   interleaved
   base/release/base/release A/B (POLYLOG_CLAIM_VERIFIER.md §C.13.1) gave
   RSS 2.24/2.12/2.03/2.24 GiB and footprint 2.23/2.22/2.03/2.24 -- no
   consistent improvement; the env-gated hook stays default-off and is not a
   memory win. The *non-gated* `drop(stored)` free is the change that actually
   lowered the native peak (1.41 GiB RSS / 1.82 GiB footprint). Re-check only
   if a future round changes the M5 peak profile materially. Design:
   `docs/MEMORY_PATH.md` §3.1.
4. **Refresh the `2^17`-`2^19` rows** with the memory watchdog and one run at a
   time. `2^16`/`2^17`/`2^18` were re-run on the route-(d) tree on 2026-11-08
   (table in §2: 30.4/62.6/131.4 s, 22.3/40.7/112.1 ms verify, 2.18/4.35/5.96
   GiB RSS with 2^18 at 7.96 GiB footprint) and their proof bytes match the
   baselines. `2^18` was re-run on 2026-11-08 (133.1 s / CPU 1240.3 s / verify
   109.5 ms / 6.37 GiB RSS / 7.97 GiB footprint, proof 1,230,360 B) and its
   stage attribution puts the peak inside the Access stage
   (MEMORY_PATH.md §4.2). Remaining: **`2^19`** (post-route-(d) estimate
   ~11.9 GiB peak from the measured `2^17`->`2^18` footprint slope, ~10.8 GiB
   with `MAGNETAR_SERIALIZE_ACCESS`; needs a dedicated window with >=15 GiB
   free+inactive. **Blocked across the 2026-11-08 rounds**: the host stayed at
   10.8-14.2 GiB free+inactive with swap 8.9-9.4 GiB used, so every attempt was
   deferred per the MEMORY_PATH.md §3 protocol rather than risking a thrash of
   the shared machine),
   then re-fit the
   `2^22` model (MEMORY_PATH.md §3; 2^20 is the decision point, 2^21 is not
   runnable on this 36 GiB host).
5. **Memory path implementation** (`MEMORY_PATH.md`): route (d) is now
   effectively complete for the benchmark path -- increments 1+2 landed on
   2026-11-08 (Access-input lifetime + compact twist tables + trace-witness
   dedup) and the `2^17` same-window A/B measures **4.51 -> 3.95 GiB footprint
   (-12.4 %)**, RSS -0.2 to -0.7 GiB, prove CPU -0.7 % (noise), byte-identical
   proofs (§4.1). Attributed with the fixed stage probes (§4.2), the peak is
   **not** dominated by the Access prover's dense factor arrays: direct
   measurement puts them at ~12 % of the `2^16` peak (7 arrays x 33.5 MB =
   0.23 GiB of 1.99 GiB), and the high-water mark is set by the **PCS commit
   transients** -- the mosaic Commit reaches 1.28 GiB at `2^16`, plus the Access
   PCS commit's codeword+Merkle -- followed by the resident context (0.55 GiB).
   Landed so far, all byte-identical:
   - route (d) 1+2: `2^17` **4.51 -> 3.95 GiB** footprint (-12.4 %, §4.1);
   - Access-PCS lifetime (re-encode at the opening): `2^18` **8.72 -> 7.96 GiB**;
   - compact Access sum-check factors (§4.4): Access CPU **-19 %**, peak
     `2^16` **1.99 -> 1.89 GiB**, live factor memory -4 arrays;
   - opt-in `MAGNETAR_SERIALIZE_ACCESS=1`: `2^18` **6.96 GiB**, `2^16` 1.78 GiB.
   The allocator-release route is confirmed a no-op at both scales. Remaining
   order, by measured leverage: **streaming PCS commit** (mosaic + Access: encode
   in chunks and hash leaves incrementally, removing the codeword transient
   without changing the root) -> (h) bit-pack the twist witnesses/batch tables ->
   (c) bit-pack the mosaic commitment -> (b) the 128 -> 64-bit committed
   alphabet -> virtualise the two one-hot matrices and the value matrix (needs a
   restructured Jolt-style sum-check over the address bits, not a factor
   representation change) -> re-run the staircase (2^18/2^19, still
   environment-blocked) to re-fit the `2^22` model. After all of the packing
   routes the floor is still 26-30 GiB, so the paper envelope needs a different
   commitment family or streaming codewords.
6. Rejected on purpose: raising the *outer* stream budget above 22 (trades
   ~11 % of `product6` for +0.4 GiB at `2^16` and ~+25 GiB at `2^22`), caching
   scale-linear PCS data across stages (the deep clone removal was kept, the
   cache was not), the fused inner block loop (35 % slower), an 8-byte Merkle
   digest (only ~32-bit collision strength, far below the 100-bit target), and
   lowering the P3 security parameter from 100 bits for proof size.

## 6. Traps and invariants

- **Wall-clock A/B is meaningless on this host.** During the 2026-11-03 round
  the same binary reported `2^14` proves from 18.5 s to 55 s within minutes
  (1-minute load 13–150). Use the `cpu=` field that every gated profile print
  now carries (cumulative `getrusage` CPU), and A/B with same-binary env
  switches instead of rebuilding. The round's "fused inner loop" experiment is
  the cautionary tale: a wall-clock A/B had called the earlier inner fusion
  neutral when it is in fact 35 % slower.
- **Zero-padding skip keeps equality values at full length.** In
  `prove_product6_rows` the row arrays are truncated to the live prefix, but
  the equality vector is not: the boundary element of the live prefix folds
  with a *non-zero* equality value in later rounds; setting that to zero
  diverges at the first odd-length fold. The byte-equality gate found this.
- **Claim-layer transition rules.** The polylog claim table is on by default
  (`MAGNETAR_CLAIM_TABLE=0` restores the legacy row path, `MAGNETAR_CLAIM_ROWS=1`
  keeps the table in the proof but verifies with the row sums for A/B). It
  requires width 64; `ClaimProof`'s wire variants gained a `table` field, so
  proofs from an older build do not deserialize (same-version round trip is
  covered by tests). The claim-native fast path now binds the same composed
  root. Open item: at `ADDS=4095` the full benchmark was observed to peak at
  4.05–4.3 GiB (the 2^12 claim table is only ~16 MB of codeword, so it is not
  that), while `ADDS=1023` and `2^16` peak at 2.1–2.4 GiB; the benchmark
  memory watchdog caught it. Root-cause the non-monotonic transient before
  quoting small-scale peaks.
- **PoW grind cost is non-monotone across openings.** At RV64 `2^16` the
  selected opening (`pow=20`) spends 0.29 CPU-s in `grind`, the local Twist
  opening (`pow=20`, longer transcript) 0.93 CPU-s, yet the mosaic opening
  (`pow=21`, the highest difficulty) only 0.02 CPU-s. A standalone challenger
  grind scales with prefix length as expected (0.14 CPU-s at a 64 B prefix,
  2.06 s at 512 B, both 21 bits), so the mosaic opening should sit near
  0.6 CPU-s; the discrepancy is unexplained. Total grind across the three
  openings is ~1.2 CPU-s, below the optimization threshold -- understand it
  before touching `vendor/plonky3` for grind.
- **Build every target, not just tests.** `cargo test --workspace` does not build
  `magnetar-pcs` examples, which is how a broken `p3_stage_probe` slipped past a
  "655 green" run. Add `cargo build --workspace --examples --release` to the gate
  list.
- **The M4a committed-Shout skeleton is on the quadratic reference Shout.**
  `prove_binary_shout_claims` materialises `cells * cycles`-long factor vectors
  (`binary_shout.rs:666`) and `sumcheck_terms` folds `degree + 1` copies per
  round: +1.19 GiB at `ADDS=1023` (measured with `MAGNETAR_PROFILE_SHOUT` stage
  marks), abort at the 2.5 GiB watchdog at `2^14`, and `2^32` field elements at
  `2^16`. The opt-in path is therefore not scalable and stays default off; the
  M4 revision must use the linear `logup_shout` machinery and commit (or open)
  the pushforwards instead of shipping them. See
  `docs/POLYLOG_CLAIM_VERIFIER.md` §C.8.
- **M4v3/M4b are measured opt-ins with an explicit trade.** After the batched
  opening (`e320cf9`) `committed_logup_shout` is 160,897 B at `2^16`. The native
  opt-in trades +151 KB of proof for -36 % verify CPU (158.2 -> 101.6 ms/iter);
  the paper opt-in is better on all four metrics (proof -30 KB, verify CPU
  -9.5 %, footprint -0.62 GiB) and also closes the paper verifier's Shout gap.
  Neither default flips until the env-on gate and the tamper matrix pass
  (`docs/POLYLOG_CLAIM_VERIFIER.md` §C.13).
- **One heavy run at a time.** The host had <1.5 GiB free memory during this
  round. Every example installs `install_memory_watchdog` (`MAGNETAR_MAX_RSS_GIB`,
  default 4 GiB), `protocol_determinism` defaults to 20 pairs (1.99 GiB, the old
  120-pair default peaked at 5.75 GiB), and anything above ~2 GiB is serialized
  across all agents.
- **Byte equality is the gate.** `streaming_lockstep_proof_matches_the_eager_proof_bytes`
  ([simd_dual.rs:8335](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/simd_dual.rs#L8335)),
  `parallel_chunked_streaming_matches_sequential` ([lib.rs:8361](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/lib.rs#L8361))
  and `protocol_determinism` must stay green for any hot-loop change; they
  caught the nondeterministic grind and the inner-fusion divergence.
- **No prints inside per-item loops.** One `eprintln!` per cycle inside the pc
  chain turned 84 s of `2^16` prove into 261 s.
- **Allocator keeps freed pages.** Peak RSS tracks a sum of transients, not a
  max; `RAYON_NUM_THREADS=1` vs `12` measures the same peak, so the p3 parallel
  features are memory-neutral.
- **PCS profiles must be derived from the final table list** ([protocol.rs:1991](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/protocol.rs#L1991));
  deriving them earlier gives prover/verifier a different profile.
- **`1u64 << width` wraps at width 64.** Guard with `u64::MAX`.
- **Stale release artifacts**: after vendor edits, prove the binary changed
  (proof bytes or sizes) before trusting a measurement.
- **M4a committed-Shout transition (uncommitted WIP).** `ClaimProof` gains a
  `committed_shout` field (`#[serde(default)]`, `None` on the default path), so pre-M4
  unified-proof bytes differ from the current build (serde-default field only; no stored
  goldens depend on it). The opt-in path is `MAGNETAR_COMMITTED_SHOUT=1`; it commits
  `T_shout` (BinaryShout boolean columns) and `T_field` (claim word) and composes their
  roots into `trace_claim_root`. `MAGNETAR_CLASSIC_LOGUP=1` forces the legacy per-cycle
  trace Logup-Shout path. A verifier that expects the committed path rejects proofs
  without the field ("pre-M4 proof"). Opt-in path has no A/B measurement yet; do not
  enable it in the default benchmark until the unified window.

- **M4 v3 committed-pushforward linear Shout (uncommitted WIP).** `UnifiedTraceProof`
  gains a `committed_logup_shout` field (`#[serde(default)]`, `None` on the default
  path), so pre-M4v3 unified-proof bytes differ (trailing serde field only; no
  stored goldens depend on it). The v3 statement root is
  `H("claim-shout-v3" || v1 claim binding || batched tables root)` where the batch
  covers `T_word`/`T_pos`/`T_pf` (one commitment, one batch opening; reader point
  sampled from `rom_hash` + `trace_len` so the pushforward table is fixed before
  the commitment). Opt-in switch: `MAGNETAR_LINEAR_SHOUT=1`;
  `MAGNETAR_CLASSIC_LOGUP=1` forces the legacy witnessed trace Logup-Shout path.
  When enabled, a verifier that receives a proof without the field rejects it
  ("pre-M4v3 proof"). The statement root becomes
  `H("claim-shout-v3" || v1 claim binding || word root || pos root || pushforward root)`
  so the committed `T_word`/`T_pos`/pushforward tables are bound by the public
  statement (same host-derived trust model as the M2/M3 claim table). The classic
  `logup_shout` prover/verifier and every p3 structure are untouched; a golden
  hash (`GOLDEN_OLD_LOGUP_ENCODING`) pins the classic proof encoding. Opt-in path
  has no A/B measurement yet; do not enable it in the default benchmark until the
  unified window.

- **Width-8 unit tests are deliberate**: ~63 call sites in `magnetar-cpu`,
  `simd_dual`, `simd_f2` and the row modules assert 8-bit arithmetic
  (`0xff` wrap, `Sra(248,1)`, `u8`/`i8` proptests). Everything that runs a proof
  is width 64; results §9.11 has the inventory.

- **Quote peaks as RSS *and* phys_footprint.** On macOS libmalloc's large zone
  frees with `MADV_FREE_REUSABLE`: the pages leave the OS footprint immediately
  but stay in `ps`/`/usr/bin/time -l` RSS. The 1.94-2.01 GiB figure predates the
  `drop(stored)` free and the dual metric; current native default is 1.41 GiB
  RSS / 1.82 GiB footprint.
- **A committed table must be absorbed before the challenges.** The committed
  Shout binder returns the digest of the batch commitment; a constant/zero
  binding would let the prover adapt the table to the Fiat-Shamir points. The
  verifier recomputes the digest from `proof.table_commitment`, and the v3 root
  binds the same digest (double binding).
- **Opt-in tests mutate process-wide env.** The `#[ignore]` cases that flip
  `MAGNETAR_LINEAR_SHOUT` / `MAGNETAR_CLAIM_V4` race each other under the default
  test-threads; run them with `--ignored --test-threads=1`.
- **`2^22` memory: >=37 GiB hard floor, 60-90 GiB model.** The earlier ~20 GiB
  linear fit was allocator reuse. A Merkle tree lives together with its
  codeword, and the mosaic commit/opening alone forces >=32 GiB live at 2^22.
  See `docs/MEMORY_PATH.md`.

- **Stage memory prints are in-process now (`rss_peak=` + `footprint=`).** The
  former `resident_gib()` shelled out to `ps`, which the sandbox blocks, so all
  `MAGNETAR_PROFILE_*` stage prints silently reported 0.00. It now reads
  `getrusage`'s peak RSS plus the current `phys_footprint` and prints both;
  MEMORY_PATH.md §4.2 has the resulting `2^16` stage table (the peak is first
  reached during the unified Access stage at `2^16`, and the route-(d) freed
  inputs show up as a 2.17 -> 0.39 GiB footprint drop after Access, which is
  why the `2^17`/Opening A/B shows the full -0.56 GiB but the `2^16` peak
  barely moves).

- **Memory A/B on this host needs a same-window switch.** The prover's peak
  drifts by ~0.2 GiB with host memory pressure (during the 2026-11-08 round swap
  was 8.5/10 GiB used and the same binary reported 2.00-2.22 GiB footprint
  against 1.82 GiB on the 2026-11-03 quiet host). `MAGNETAR_KEEP_PROVER_INPUTS=1`
  keeps the pre-route-(d) Access-input lifetime and the full twist batch tables
  in the same binary, so A/B it with alternating runs inside one window and
  quote the window (and the load/swap state), never two separate builds. Use
  `2^17` for the headline number: the `2^16` delta (0.03-0.12 GiB) is below the
  host drift, while the `2^17` A/B is a clean 4.51 vs 3.95 GiB footprint.

- **The verifier is thread-parallel by default since M6 increment 1.** The v4
  statement-only verifier runs five independent checks (access, claim table,
  selected binding, committed Shout, core) on five threads and the selected
  lockstep spawns a sixth for its PCS opening plus six MLE-evaluation workers,
  so one verify briefly uses ~12 threads. `MAGNETAR_VERIFY_SERIAL=1` restores
  the straight-line order (both the wave and the PCS/eval overlap) for a
  same-binary A/B. Never judge a verifier latency change by "run A, then run
  B" here: host load drifts by 2x within minutes (HANDOFF §6 wall-clock
  warning). Use `target/release/examples/m6_verify_ab` -- one proof, then the
  two modes alternated in the same process -- and quote wall **and** CPU, since
  the parallel path trades ~+16 % CPU for -59 % wall.
- **Wave stage prints overlap; only their CPU deltas are additive.** With
  `MAGNETAR_PROFILE_VERIFY=1` the "v4 access/claim table/selected binding/... "
  stages run concurrently, so their `wall=` values can sum to more than one
  verify; the `cpu=` deltas are still the per-stage work. Inside the selected
  job, `lockstep verify eval_mles` and `lockstep verify pcs` now print the same
  overlapped window (their maximum is the critical path).
- **The parallel verifier must keep the serial first-error order.** The wave
  joins in the old serial order (access -> claim table -> selected -> shout ->
  core) so tamper tests that expect a specific first error still pass; if you
  add or reorder checks, re-run the file-level tamper matrix, not just the
  happy-path round trip.

- **Paper statements are path-aware since the M4b flip.** `trace_claim_root` for
  a paper proof is the v3 root `H("claim-shout-v3" || claim_binding_v1 ||
  Shout tables root)`, which `claim_table::statement_claim_root` does **not**
  produce (it keeps the native/legacy meaning for 73 call sites). Build paper
  statements with `paper_statement_claim_root(trace, width)`, which mirrors the
  prover under the same switches (`MAGNETAR_CLASSIC_LOGUP`, M5 v4, claim-table
  off). A mismatch shows up as `claim proof root mismatch` / `M5c: committed v4
  tables do not match the statement root`; a prover change that also changes the
  root must update the helper in the same commit.
- **The classic paper wire is `logup_shout` alone.** The unified dynamic prover
  hard-codes `shout_table = None`, so both wires have `shout`/`packed_shout`
  absent; on the classic leg the M4b win is dropping the 25-column
  `logup_shout` opening whose logup identity the classic verifier never checked.
  When writing dual-mode assertions, assert `committed_logup_shout` presence and
  `logup_shout` presence/absence, not the stage-proof fields.
- **M5 v4 is deliberately not flipped.** `MAGNETAR_CLAIM_V4=1` still requires
  `MAGNETAR_LINEAR_SHOUT=1` to get the committed Shout because
  `claim_table::statement_claim_root_v4` derives the v4 shout component from
  that env switch; `paper_committed_logup_enabled()` returns
  `!MAGNETAR_CLASSIC_LOGUP && (MAGNETAR_LINEAR_SHOUT || !claims_v4_enabled())`
  so the M5/M6 measured env keeps its exact behaviour. Flipping v4 needs that
  root derivation to become path-aware first.
- **The committed-Shout table binding exists on both verifier paths now.**
  Statement-only: the v3 statement root. Trace-carrying
  (`verify_unified_with_plan_impl` / `verify_unified_trace`): an explicit
  `committed_statement_data(trace).table_root` comparison
  ("committed logup Shout tables do not match the trace"). The trace path
  still cannot parse paper proofs (register-derived claim blob has no trace
  form), so that leg is exercised with a native M4v3 proof.
