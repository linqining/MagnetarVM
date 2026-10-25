# Paper alignment and performance plan

Target: `papers/magnetar-2026-2423.pdf` (IACR ePrint 2026/2423).
This is a roadmap, not a claim that the implementation is aligned yet.

## Current baseline (release, width 8, single-thread, Addi loop)

`cargo run --release -p magnetar-testkit --example paper_scale_bench`
(`ROWS=16,64,256,512`):

| rows | bytes | prove | verify | cycles/s |
|---:|---:|---:|---:|---:|
| 16 | 92,528 | 0.347 s | 0.162 s | 46.2 |
| 64 | 136,472 | 1.957 s | 0.502 s | 32.7 |
| 512 | 348,368 | 30.67 s | 4.80 s | 16.7 |
| 1024 | 516,792 | 141.60 s | 13.13 s | 7.2 |

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

At 1024 rows, proving time grows 4.6x and verification 2.7x for 2x rows, while
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

Packed-Shout internal profile (512 rows):

```text
TableCommit    26.2 ms
PackedCommit    0.7 ms
ShoutClaims    15.65 s
PackedOpen    107.1 ms
```

The Shout claim prover materializes `cells × cycles` factors and folds them for
every degree point of every round. With `cells = next_pow2(2 * ROM words)` and
`cycles = next_pow2(rows)`, this is quadratic in trace length. The next concrete
optimization is a linear/sparse Shout sum-check rather than another serialization
change.
```

## Phase 2: CPU engine / BinarySpartan

1. Replace the quadratic packed-Shout factor materialization with a linear/sparse
   sum-check (largest stage: 15.65 s at 512 rows).
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
