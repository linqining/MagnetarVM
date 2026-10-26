# Paper alignment and performance plan

Target: `papers/magnetar-2026-2423.pdf` (IACR ePrint 2026/2423).
This is a roadmap, not a claim that the implementation is aligned yet.

## Current baseline (release, width 8, single-thread, Addi loop)

`cargo run --release -p magnetar-testkit --example paper_scale_bench`
(`ROWS=16,64,256,512`):

| rows | bytes | prove | verify | cycles/s |
|---:|---:|---:|---:|---:|
| 16 | 92,528 | 0.184 s | 0.134 s | 87.2 |
| 64 | 136,472 | 1.30 s | 0.837 s | 49.3 |
| 512 | 340,920 | 3.6–6.1 s | 4.55 s | 85–141 |
| 1024 | 516,976 | 17.1–21.8 s | 10.69 s | 47–60 |

512-row split:

```text
selected_cpu 203,605 B
claim_proof   55,370 B
packed_shout  58,866 B
access        16,018 B
shape         13,320 B
```

Selected CPU is about 58% of the proof at 512 rows and 58% at 1024 rows.
At 1024 rows: selected 298,541 B, claim 110,666 B, packed_shout 62,594 B. The claim proof dropped from
202,825 B to 55,370 B by proving a complete claim set against the Merkle root
instead of carrying one sibling path per row, and the duplicated selected
segment list is no longer serialized.

Paper targets:

```text
2^16: 35 ms, 1.9 M cycles/s, 380 KiB, verify 8 ms
2^22: 547 ms, 7.7 M cycles/s, 598 KiB, verify 12 ms, peak RSS 6.4 GiB
```

Current scale is 2^9-2^10 rows; the paper target is 2^22-2^28 cycles.

## Phase 0: measurement and invariants (in progress)

- [x] deterministic proof bytes: sort table-batch selection
- [x] concurrent determinism reproducer
- [x] proof-size accounting includes `claim_proof` / `selected_cpu`
- [x] proof-only native verification works after bincode roundtrip
- [x] full runtime suite green, 310/0
- [x] make proof-size accounting exactly equal to bincode size
- [ ] add CI job for concurrent determinism and repeated full suite

Exit gate:

```text
same trace -> identical proof bytes, including under parallel proving
```

## Phase 1: proof compactness

The current proof is dominated by the selected CPU opening and per-row claim
openings.

1. [x] Use the unified `claim_proof` as the canonical claim layer and verify a
   complete claim set against the Merkle root without per-row sibling paths.
   [x] Stop serializing the duplicated selected segment list; it is rebuilt from
   the layout and proof during verification.
   [x] Serialize the selected layout as offsets/lengths/owners without per-segment
   names.
   [x] Omit the dynamic selected layout from the proof; the verifier rebuilds it
   from the trace and uses it for the lockstep opening.
   [x] Tune the selected PCS to `(security=100, log_inv_rate=4, pow_bits=16,
   folding=3)`; selected opening drops from 234,352 B to 126,936 B at 512 rows.
2. Reduce the dynamic selected witness width: a trace containing only ALU +
   halt currently pays for every component (memory/shift/mul/div/sdiv).
   Introduce an ALU+branch composite row or select the exact component set.
3. Replace per-row Merkle openings with a batched claim commitment/opening, or
   commit the claim table as a PCS table and prove only the needed claims.
4. Make `unified_proof_sizes` exact and add a size regression gate.

Interim gates:

```text
512 rows: proof < 500 KiB, selected < 300 KiB, claim < 100 KiB
(current: 340.2 KiB / 198.8 KiB / 54.1 KiB at 512 rows;
            504.7 KiB / 291.5 KiB / 108.1 KiB at 1024 rows)

At 64 rows, the selected proof splits as:

```text
commitment       48 B
outer sumcheck 1,320 B
inner sumcheck 1,032 B
segment claims 9,224 B
PCS opening   133,376 B
```

At 512 rows the selected proof is now 203,605 B: opening 126,936 B, segment
claims 73,736 B, sums 2,736 B, commitment 48 B. The Phase 1 gate is met.

At 1024 rows, proving time grows 3.9x and verification 2.2x for 2x rows, while
the proof grows only 1.48x. The prover, not proof size, is now the scaling
bottleneck.

Native-dynamic stage profile (512 rows, release):

```text
Commit           44.8 ms
Access            8.08 s
Finish           70.1 ms
PackedShout      15.24 s
SelectedCpu      11.50 s
```

So the next performance targets are packed Shout (largest), BinaryTwist access,
then the selected CPU opening. This changes the Phase 2 order: Shout/access
prover work comes before a full BinarySpartan rewrite.

Packed-Shout internal profile before parallelization (512 rows):

```text
TableCommit    26.2 ms
PackedCommit    0.7 ms
ShoutClaims    15.65 s
PackedOpen    107.1 ms
```

The Shout claim prover materializes `cells × cycles` factors and folds them for
every degree point of every round. With `cells = next_pow2(2 * ROM words)` and
`cycles = next_pow2(rows)`, this is quadratic in trace length.

The native prover now runs the selected-CPU proof and the packed-Shout proof
concurrently with the context/access work. At 1024 rows this overlaps the
selected CPU and packed Shout stages against access/shout, taking the prover
from 30.2 s to 18.0 s (4.6 s at 512 rows). Proof bytes are unchanged and the full
determinism suite still passes. Stage timings for the overlapped stages are wall
times, so they do not sum to the total.

`verify_native_unified` now authenticates claims once, then verifies the
selected-CPU proof and the orchestrator proof concurrently. The orchestrator
path skips the selected-CPU check, which the dedicated verifier already ran.
Claim-proof verification is not repeated either. Inside the selected verifier,
the lockstep proof check now runs concurrently with rebuilding the segmented
witness bits and recomputing their commitment. Verification is 4.55 s at 512
rows and 10.69 s at 1024 rows. Prover measurements still vary by 10–20%, so the
prover column is a range.

All-32-bit traces now use a word-granularity Shout table (`cells =
next_pow2(ROM words)`), halving the cell dimension. At 512 rows ShoutClaims drops
from 1.85 s to 0.85 s and the packed Shout proof from 58,866 B to 51,418 B.
Compressed/mixed traces keep the halfword table.

The degree-point evaluations are now parallelized with a bounded memory budget
(8 GiB by default; `MAGNETAR_SUMCHECK_THREADS` and
`MAGNETAR_SUMCHECK_MEMORY_GB` override it). Raising the budget to 16 GiB at
1024 rows only improved 55.11 s to 52.69 s, and 8 workers at 32 GiB was slower
(63.22 s), so the default stays conservative. ShoutClaims at
512 rows drops from 15.65 s to 1.85 s with 4 workers, and BinaryTwist access
drops from 8.08 s to 3.68 s. Full prover:

```text
512 rows: 30.67 s -> 14.27 s
1024 rows: 141.60 s -> 55.11 s
```

The next step is still a linear/sparse Shout sum-check; parallelization is only
a constant-factor improvement.

Selected CPU internals (512 rows, profile mode):

```text
commit                 40 ms
eq vector              31 ms (1.32 s before tensor construction)
matvec                106 ms
MLE                    22 ms
product6              685 ms (1.24 s before parallelization)
row combinations      822 ms (4.66 s before parallelization)
product2              407 ms
segment claims         21 ms
claims               2.50 s
open                 1.57 s
SelectedCpu stage    4.16 s

Run-to-run prover times vary by roughly 10-20% on this laptop after sustained
runs, so the table below is a point measurement, not a tight benchmark bound.

Ring-switch `a_values` now uses a scalar prefix tree plus a 16x256 byte table
for the transpose dot product when the packed table has at least 64 entries.
Proof bytes are unchanged. The Spartan row-combination/eval row selector is built by tensor doubling as
well. These cut the 16/64/512/1024-row prover to the numbers in the table above.
```
```

## Phase 2: CPU engine / BinarySpartan

1. [x] Parallelize Shout/Twist degree-point evaluations with bounded memory.
   [x] Parallelize the six lockstep row combinations (4.66 s -> 0.76 s at 512).
   [x] Parallelize product6 degree-point evaluations (1.24 s -> 0.71 s).
   [x] Build the Spartan `eq(τ, x)` table by tensor doubling; 1.32 s -> 0.03 s
   at 512 rows.
2. Replace the quadratic packed-Shout factor materialization with a linear/sparse
   sum-check (still the largest single algorithm cost).
   [x] Word-granular Shout table for all-32-bit traces (halves the cell count).
2. Pack field-valued witnesses; remove per-row witness padding.
3. Implement BinarySpartan-style packed claims instead of committing the full
   selected witness.
4. SIMD field multiplication / sumcheck fold (the packed multiply kernel exists
   but is not wired because the end-to-end fold was slower).
5. Field-valued MosaicPCS packing; single shared opening.

Interim gates:

```text
2^16 rows: prove < 2 s, proof < 2 MiB
```

## Phase 3: recursion / succintness

1. Chunked proof-only verification with chunk-boundary state commitments.
2. Recursive aggregation, verifier-in-the-VM, final low-rate proof.
3. Final proof independent of trace length.

Gate:

```text
2^22 rows: proof <= 600 KiB, verify <= 20 ms
```

## Phase 4: workloads and scale

1. SHA-256, Keccak-f1600, ERC-20 transfer/transfer-from/mixed-block,
   EVM ERC-20, LZ4 decode, varint decode, radix sort, pointer chase,
   binary search, stream copy, hot-cell increment, fibonacci, Merkle path.
2. 2^16, 2^18, 2^20, 2^22 runs with peak RSS.
3. 2^23-2^28 memory-limit runs where feasible.
4. Same-machine comparison harness for Jolt/SP1/ZisK/Lineth (external).

Gate: generate the paper's Table 2/3/6/8 shape, not a synthetic workload table.

## Phase 5: security alignment

1. Move P3 parameters from security level 100 to the paper's 120-bit target;
   document grinding/query parameters.
2. External cryptographic/protocol audit.
3. Constant-time/side-channel review.
4. Remove or explicitly scope `UnimplementedBackend`,
   `UnimplementedRecursion`, `UnimplementedZeroKnowledge`.

Gate: audited parameter spec + external report.

## Benchmark commands

```bash
ROWS=16,64,256,512 cargo run --release -p magnetar-testkit --example paper_scale_bench
cargo run --release -p magnetar-testkit --example protocol_determinism
cargo run --release -p magnetar-testkit --example workload_suite
cargo test -p magnetar-runtime --lib --offline
```

## Ordering rationale

Proof size and prover time are currently dominated by the selected CPU opening
and per-row claim openings, not by the field arithmetic. Optimizing the CPU
engine before removing those linear components would not reach the paper's
proof-size target. Phase 1 is therefore the first performance milestone.


## Rejected: P3 parallel feature

Enabling `p3-binary-pcs/parallel` (rayon) gave:

```text
512 rows:  8.76 s -> 7.46 s
1024 rows: 45.16 s -> 23.42 s
```

but it broke proof-byte determinism: the concurrent determinism stress reported
`83 / 120` mismatches, and `protocol_plan_and_orchestrator_preserve_proof_bytes`
failed. Field-level diagnostics localized the differences to `gated`,
`e5_opening`, and `packed_shout`; `selected_cpu` was not reported as differing.
The feature still has to remain off because the full proof contains those
fields. The feature was reverted. Deterministic bytes are a hard requirement for
this protocol, so the parallel P3 backend cannot be enabled until its output is
canonicalized.

A parallel product2 attempt was also reverted: at 512 rows it measured 0.48 s
versus 0.40 s sequential, so it added overhead without benefit.

After eq/product6/row-combination parallelization, the PCS grinding bits were
re-swept. At 512 rows, selected stage was 4.08 s with 8 grinding bits versus
4.16 s with 16 grinding bits, but the 8-bit proof is 11 KiB larger. The
difference is noise-level, so the smaller 16-bit-proof configuration is kept.


## Rejected: selected-only parallel P3 with serial wrapper

The next attempt wrapped the full unified prover in a one-thread rayon pool and
intended to run only the selected-CPU opening in a multi-thread pool. With
`p3-binary-pcs/parallel` enabled, the concurrent determinism stress no longer
completed within the test window (it hung/serialized for more than 120 s even
with 2x2 proofs). This is not acceptable for a proof-generation path, so the
experiment was reverted together with the feature and the rayon dependency.

The P3 parallel backend remains disabled. Any future attempt needs a proof
format with canonical output or a P3 build that is deterministic under
parallelism; wrapper-level thread-pool switching is not sufficient.


## Rejected: scalar-copy collapse of eval_rs_eq

The selected opening spends about 1.4 s in `a_values`, where each entry calls
`eval_rs_eq`. The 128-lane update is

```text
eval <- vertical * eval + horizontal * transpose(eval)
```

It is tempting to collapse `eval` to a scalar multiple of `e_0`. This is wrong:
the final `transpose128` maps a scalar multiple of `e_0` to a bit-linear
functional of the scalar, not to field multiplication. A scalar recurrence plus
a byte table did not match the vector implementation and was reverted. Any
optimization here must preserve the transpose basis map exactly.
