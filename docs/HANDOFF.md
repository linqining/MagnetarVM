# Handoff — MagnetarVM streaming selected prover (RV64)

Status: **incremental optimization phase**, branch `virtual-claims-rewrite`,
2026-11-03 `2^16` optimization round committed (`1b26b4e` optimization +
polylog claim table, `9e805f2` segment-claim rewrite, `f310f82`/`faf3b72`/`ac8e4a4`
M4a committed-Shout skeleton/body/opt-in fixes, `bd04687` Access sum-check,
`21c38c7` chunked inner scan, `a3a6e9c` packed CSR + fast pair polynomial).
Final gate on the committed tree: **666 passed / 0 failed**,
`cargo build --workspace --examples --release` green.

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
(prove CPU 274.2–274.9 s vs ≈800 s before), verify 24.7–27.2 ms, peak 1.94–2.01 GiB**. The
streaming prover is still byte-identical to the eager path; the *proof file* is
1,018,152 B because the polylog claim layer (results §11.6) now commits the
claim table and attaches it to `ClaimProof` -- with the claim table off the same
binary gives verify 46.0 ms and 861,408 B, so the table is worth +157 KB of
proof for -18.6 ms of verify. The row blob is still carried during the
transition, so the size goes back down when M4/M5 remove it. Workspace tests:
**655 passed / 0 failed**; `protocol_determinism` 20/20 byte-identical at
1.99 GiB peak.

---

## 1. Run it

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

# Streaming-scan diagnostic switches (same-binary A/B; every stage print also
# carries cumulative process CPU time, which is the load-robust metric, see §6)
MAGNETAR_STREAM_WORKERS=N      # worker count (default: available_parallelism)
MAGNETAR_LIVE_FULL=1           # disable the zero-padding row skip (A/B)
MAGNETAR_P2_FUSED=1            # fused inner block loop (measured 35% slower)
MAGNETAR_INNER_BUDGET_LOG=NN   # inner sum-check level budget (default 24)
MAGNETAR_MAX_RSS_GIB=4.0       # benchmark watchdog (magnetar-testkit examples)

# Register twist alone (Access layer), 2^16 rows
ROWS=65536 MAGNETAR_PROFILE_LOCAL=1 target/release/examples/local_shared_bench

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
| `2^17` | **147.6 s** | 55.8 ms | 4.60 GiB | 942,535 B |
| `2^18` | 321.5 s (pre-fusion) | 161.5 ms | 7.73 GiB | 1,050,900 B |
| `2^19` | 667.8 s (pre-fusion) | 318.3 ms | 10.54 GiB | 1,177,984 B |

† proof size is the claim-table format; the streaming proof itself is still
byte-identical to the eager path. See results §11.6.
`2^18`/`2^19` predate the fused scan and the ring-switch fix; two loaded re-runs
gave 335 s and 437 s with 5.7–7.8 GiB peak and were discarded. A linear fit
through the measured points projects ≈20 GiB at `2^22` (supersedes the earlier
55–60 GiB model, which came from the 32-byte-digest build).

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

Peripheral stages (parallel track): the vendored p3 `Keccak256Hash16` did not
forward `hash_many`, so Merkle trees hashed serially; forwarding it cut p3 CPU
2.1–2.7x and `Commit`/`Opening` roughly in half. Plus a removed prepared-data
deep clone (-0.5 GiB memcpy at `2^16`) and deduplicated Access table builds
(register twist standalone 7.6 → 5.0 CPU-s).

## 5. Open work, in priority order

1. **Committed claim columns → polylog verifier** (the only route to the paper's
   8 ms). Today the verifier is `O(rows)`: claim row sums re-emit ~336 columns
   per row, and the trace Logup rebuilds the Shout witness from the claim-derived
   trace. Design sketch in results §9.8; touches the claim schema, the proof
   format, and both prover/verifier. It also needs a tamper test per layer
   through the top-level entry point.
2. **`product2` is now the largest single term** (24.5 s of 55.5 s). The fused
   block loop was measured 35 % *slower* (results §11.5) and is parked behind
   `MAGNETAR_P2_FUSED`; the next levers are amortising `fill_left`'s per-block
   overhead over larger column chunks (round 0's block is two columns) and a
   tighter CSR layout. Re-check the inner level budget on a quiet host
   (24 is the current default; 23 trades one scan for -256 MiB).
3. **Memory: bit-level / smaller codeword.** The peak is codewords and Merkle
   trees (selected witness commit 2.07 GiB, mosaic commit/opening 5.0/6.0 GiB at
   `2^18`), linear in `cycles`; ≈21 GiB projected at `2^22` against the paper's
   6.4 GiB (the 512 MiB inner level arrays are fixed, not linear).
4. **Refresh the `2^17`–`2^19` rows** with the memory watchdog and one run at a
   time; they are marked pre-fusion and the host had <1.5 GiB free during the
   round.
5. **Claim layer M4/M5**: the claim table commitment is in the tree (M2/M3),
   the row blob is still carried, so the proof is 1,136,696 B until M4/M5
   remove it (results §11.6, docs/POLYLOG_CLAIM_VERIFIER.md).
6. Rejected on purpose: raising the *outer* stream budget above 22 (trades
   ~11 % of `product6` for +0.4 GiB at `2^16` and ~+25 GiB at `2^22`), caching
   scale-linear PCS data across stages (the deep clone removal was kept, the
   cache was not), and the fused inner block loop (35 % slower).

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
  stored goldens depend on it). Opt-in switch: `MAGNETAR_LINEAR_SHOUT=1`;
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
