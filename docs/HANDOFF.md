# Handoff — MagnetarVM streaming selected prover (RV64)

Status: **incremental optimization phase**, branch `virtual-claims-rewrite`,
latest commit `386c2e8`, work since then uncommitted, 2026-10-31.
Chinese sibling: [handoff-zh.md](handoff-zh.md).
Measurements and per-round history: [STREAMING_SELECTED_PROVER_RESULTS.md](STREAMING_SELECTED_PROVER_RESULTS.md)
([中文](streaming-selected-prover-results-zh.md)). Background design: [STREAMING_SELECTED_PROVER_HANDOFF.md](STREAMING_SELECTED_PROVER_HANDOFF.md).

Headline at RV64 `2^16`: **prove 70.4 s, verify 29.6 ms, peak 2.26 GiB, proof 861,407 B**,
all proofs byte-identical to the original format. Workspace tests: **651 passed, 0 failed**.

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

# Register twist alone (Access layer), 2^16 rows
ROWS=65536 MAGNETAR_PROFILE_LOCAL=1 target/release/examples/local_shared_bench

# Gates
cargo test --workspace --release          # 651 tests
target/release/examples/protocol_determinism   # 120 concurrent prove/verify, width 64
```

**Host hygiene.** A 1-minute load average is not enough on this machine: an iOS
simulator holding cores made the same binary report 121 s while using only 738
CPU-seconds over 121 s (≈6 effective cores) against ≈11 in the 70.4 s run.
Always quote `prove cpu / wall` and the load together; discard runs whose
core count is low.

## 2. Where it stands

| cycles | prove | verify | peak RSS | proof |
| --- | --- | --- | --- | --- |
| `2^16` | **70.4 s** | **29.6 ms** | **2.26 GiB** | 861,407 B |
| `2^17` | **147.6 s** | 55.8 ms | 4.60 GiB | 942,535 B |
| `2^18` | 321.5 s (pre-fusion) | 161.5 ms | 7.73 GiB | 1,050,900 B |
| `2^19` | 667.8 s (pre-fusion) | 318.3 ms | 10.54 GiB | 1,177,984 B |

`2^18`/`2^19` predate the fused scan and the ring-switch fix; two loaded re-runs
gave 335 s and 437 s with 5.7–7.8 GiB peak and were discarded. A linear fit
through the measured points projects ≈20 GiB at `2^22` (supersedes the earlier
55–60 GiB model, which came from the 32-byte-digest build).

`2^16` stage split (load 70–90): unified context 0.48, Commit 1.19, Access 2.56
(register twist), Opening 3.38; selected setup 0.48, witness commit 0.95,
`product6` **43.2**, `product2` **23.4**, segments 1.17, selected open 0.92.
The two streaming products are 95 % of the prover.

Verifier at `2^16` (30.3 ms wall over 5 iterations, 188 ms CPU/iter): trace
Logup-Shout 21.9–29.6 (starts as soon as the claim-derived trace exists and
overlaps both waves), claim row sums 11.5–12.4, core PCS 7.7–8.0, access 6.7,
claim leaves 3.8–4.1, claims decode 1.0, claims-to-trace 0.77.

## 3. Code map

| Area | File |
| --- | --- |
| Streaming lockstep prover (outer product6, inner product2) | [stream.rs:363](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/stream.rs#L363), [stream.rs:973](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/stream.rs#L973) |
| Fused weighted row scan (`accumulate_row_values`) | [stream.rs:279](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/stream.rs#L279) |
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

## 5. Open work, in priority order

1. **Committed claim columns → polylog verifier** (the only route to the paper's
   8 ms). Today the verifier is `O(rows)`: claim row sums re-emit ~336 columns
   per row, and the trace Logup rebuilds the Shout witness from the claim-derived
   trace. Design sketch in results §9.8; touches the claim schema, the proof
   format, and both prover/verifier. It also needs a tamper test per layer
   through the top-level entry point.
2. **Memory: bit-level / smaller codeword.** The peak is codewords and Merkle
   trees (selected witness commit 2.07 GiB, mosaic commit/opening 5.0/6.0 GiB at
   `2^18`), linear in `cycles`; ≈20 GiB projected at `2^22` against the paper's
   6.4 GiB.
3. **Inner (`product2`) fusion** — the right-hand (bit) side was proven
   byte-identical but measured neutral in an interleaved `2^14` A/B (the
   untouched `product6` swung 15.1–20.1 s). Needs a quiet-host A/B before more
   effort; worth ≤3 s. Its left side (`fill_left`) also folds claim deltas
   (`claim_columns`, `claim_instance_weight`), which a fused version must replay.
4. **Refresh the `2^18`/`2^19` rows** once the host is quiet; they are marked
   pre-fusion.
5. Rejected on purpose: raising the stream budget above 22 (trades ~11 % of
   `product6` for +0.4 GiB at `2^16` and ~+25 GiB at `2^22`), and caching the
   mosaic prover data across Access (adds its transient to the peak).

## 6. Traps and invariants

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
- **Width-8 unit tests are deliberate**: ~63 call sites in `magnetar-cpu`,
  `simd_dual`, `simd_f2` and the row modules assert 8-bit arithmetic
  (`0xff` wrap, `Sra(248,1)`, `u8`/`i8` proptests). Everything that runs a proof
  is width 64; results §9.11 has the inventory.
