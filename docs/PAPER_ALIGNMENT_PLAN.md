# Paper alignment and performance plan

Target: `papers/magnetar-2026-2423.pdf` (IACR ePrint 2026/2423).
This is a roadmap, not a claim that the implementation is aligned yet.

## Current baseline (release, width 8, single-thread, Addi loop)

`cargo run --release -p magnetar-testkit --example paper_scale_bench`
(`ROWS=16,64,256,512`):

| rows | bytes | prove | verify | cycles/s |
|---:|---:|---:|---:|---:|
| 16 | 124,531 | 0.271 s | 0.136 s | 59.0 |
| 64 | 240,243 | 1.754 s | 0.478 s | 36.5 |
| 256 | 582,411 | 10.03 s | 2.20 s | 25.5 |
| 512 | 971,955 | 27.98 s | 4.65 s | 18.3 |

512-row split:

```text
selected_cpu 679,737 B
claim_proof  202,825 B
packed_shout  58,866 B
access        16,018 B
shape         13,320 B
```

Selected CPU + claim openings are about 91% of the proof.

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
- [x] full runtime suite green, 309/0
- [ ] make proof-size accounting exactly equal to bincode size
- [ ] add CI job for concurrent determinism and repeated full suite

Exit gate:

```text
same trace -> identical proof bytes, including under parallel proving
```

## Phase 1: proof compactness

The current proof is dominated by the selected CPU opening and per-row claim
openings.

1. Remove duplicate selected claim root/openings from serialized data; use the
   unified `claim_proof` as the single canonical claim layer. (started)
2. Reduce the dynamic selected witness width: a trace containing only ALU +
   halt currently pays for every component (memory/shift/mul/div/sdiv).
   Introduce an ALU+branch composite row or select the exact component set.
3. Replace per-row Merkle openings with a batched claim commitment/opening, or
   commit the claim table as a PCS table and prove only the needed claims.
4. Make `unified_proof_sizes` exact and add a size regression gate.

Interim gates:

```text
512 rows: proof < 500 KiB, selected < 300 KiB, claim < 100 KiB
```

## Phase 2: CPU engine / BinarySpartan

1. Complete uniform SIMD `s1`/`s2` CPU matrices.
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
