# P1.1 Linear BinaryShout Design

Goal: remove the `cells x cycles` factor materialization from BinaryShout.
This design keeps the current selected-CPU/claim path and replaces only the
bytecode read argument.

## Statement

Let `K = 2^a` be the bytecode-table size, `T` the cycle count, and
`G(k) = sum_h gamma_h * Val_h(k)` the random linear combination of the table
columns selected by the transcript.

The read argument must prove:

```text
R(j) = G(address(j))    for every Boolean cycle j
```

where `R(j)` is the prover's claimed read value. In the native path the read
values are already authenticated by the claim proof; in the generic path they
are part of the committed bytecode table.

## Committed columns

Commit one P3 mosaic table with `T` rows and:

```text
address0 bits (a)
address1 bits (a)      // only needed for 32-bit reads
read_value columns (c)
```

No per-cell factors are committed. The table is a single P3 commitment.

For padding cycles, use address `0` and copy `Val(0)` into the read-value
columns. Padding then satisfies the same lookup equation and is harmless
because no claim row refers to it.

## Random-point identity

After the commitment, the transcript samples a cycle point `r_j`. The prover
opens the committed columns at `r_j`:

```text
raf_t = MLE(address_t)(r_j)
rv_h  = MLE(read_value_h)(r_j)
```

The verifier computes the one-hot address MLE

```text
ra(k, r_j) = product_t (1 + raf_t + k_t)
```

and checks

```text
sum_h gamma_h * rv_h
  = sum_k ra(k, r_j) * G(k)
```

The right side costs `O(K * c)` for the verifier. This is linear, not
paper-succinct; a later refinement can run the `k` sum through a sum-check with
the P3 table commitment so the verifier is polylogarithmic.

## Why one point is enough

Both sides are multilinear polynomials in the cycle variables. The committed
read-value columns define the left polynomial; the right polynomial is the
one-hot lookup. A random `r_j` catches a nonzero difference with
Schwartz-Zippel error. The address-bit columns are additionally checked by the
existing Boolean-address sum-check, so each Boolean cycle selects exactly one
table cell.

## Implementation milestones

1. Add `LinearShoutProof` and the linear prove/verify functions.
2. Reuse `AddressBooleanClaim` for address bitness.
3. Wire the proof into a native-only path first (claim proof + selected CPU +
   linear Shout + Access).
4. Benchmark 1024/2048 with proof size and peak memory.
5. Replace the paper-path `PackedShoutProof` only after the native path is
   stable; add the polylog verifier before claiming paper-scale alignment.

## Soundness caveat

The first version is linear-prover and linear-verifier in `K`. It is not the
paper's final succinct verifier and must not be described as full paper parity.


## logup* implementation found and prototyped

Relevant papers and implementations:

- Twist and Shout: <https://eprint.iacr.org/2025/105>
- Twist and Shout via logup* (hash-based adaptation): <https://powdr.org/papers/twist_shout_logup_star.pdf>
- logup*: <https://eprint.iacr.org/2025/946>
- Vendored P3 implementation: `vendor/plonky3/multi-stark/src/logup_star/`
- Jolt Twist/Shout reference: <https://github.com/a16z/jolt/tree/main/crates/jolt-claims/src/twist>

The P3 `logup_star` reduction proves `X[i] = T[I[i]]` with the
pushforward/fractional-GKR construction. A standalone Shout prototype is in
`crates/magnetar-testkit/tests/logup_star_shout.rs`: it builds the ROM table,
reader values and positions from `BinaryShoutWitness`, computes the reader
claims at a point, and runs P3 `LogupStarProof`.

Reduction-only measurements (no PCS binding):

| rows | prove | verify | proof |
|---:|---:|---:|---:|
| 1024 | 2.65 ms | 0.44 ms | 20,520 B |
| 8192 | 16.17 ms | 1.07 ms | 137,272 B |

The test now also commits the 12 table columns, 12 reader columns and the
position column with `P3BinaryPcs`, opens them at the logup* points, and checks
every claim. The reader point is drawn after all commitments. Tampering a
reader claim is rejected.

Bounds with a public ROM table and committed reader/position columns (one mosaic
commitment):

| rows | prove | verify | logup proof | mosaic opening |
|---:|---:|---:|---:|---:|
| 1024 | 15.0 ms | 31.5 ms | 20,520 B | 235,736 B |
| 8192 | 119.7 ms | 218.6 ms | 137,272 B | 373,376 B |
| 65536 | 995.7 ms | 1.72 s | 1,057,272 B | 563,304 B |

The ROM table is public, so its logup* column claims are checked directly against
the preprocessed ROM MLE instead of being committed. The mosaic opening is now
the main verifier/proof-size cost; batching the reader and position openings is
the next optimization.

The current verifier opens every committed column separately, which dominates
its time; batching those openings is the next optimization. The prover is still
far below the old quadratic Shout (1.70 s at 1024 rows, 757 s at 8192 rows).

For comparison the old quadratic Shout is 1.70 s / 337 KB at 1024 rows and
757 s / 506 KB at 8192 rows.

This is a sound reduction, but not yet a complete Shout proof: the table,
reader-value and position columns are still trusted inputs, not bound by a PCS.
The next milestone is to commit those columns and discharge the logup* output
claims through P3 openings.


## Runtime component and native field

`magnetar-runtime/src/logup_shout.rs` now exposes:

```text
LogupShoutProof
prove_logup_shout(witness)
verify_logup_shout(proof, rom)
```

The verifier derives the reader point from the committed reader/position table,
runs the logup* verification, checks the output table claims against the public
ROM, and discharges reader/position claims with one mosaic opening.

`UnifiedTraceProof.logup_shout` is optional and the native dynamic prover fills
it for word-mode traces; the verifier checks it when present.

This is still redundant: the old packed Shout proof remains, so the native
proof grew from 341 KB to 551 KB at 512 rows and from 520 KB to 770 KB at 1024
rows. The next step is to replace the packed Shout claim/link path with the
logup Shout claims instead of carrying both.


## Native integration: packed Shout removed from the dynamic path

`LogupShoutProof` now also carries:

```text
link_claims / link_point   # read metadata for shift/store routers
rom_claims / rom_point     # public ROM column claims for the router
```

`logup_shout_router_link_claims` feeds the shift/store routers from these
claims, so the dynamic native prover no longer emits `packed_shout` for
word-mode traces. The verifier accepts a logup Shout in place of packed Shout
when packed is absent.

Current native benchmark (`native_unified_bench`, width 8):

| rows | proof | prove | verify |
|---:|---:|---:|---:|
| 512 | 425,513 B | 2.76 s | 1.15 s |
| 1024 | 614,001 B | 5.54 s | 2.21 s |

Logup component: 137,921 B at 512 rows and 164,369 B at 1024 rows. Tuning the
reader/position PCS to `(100, 4, 16, 3)` cut the logup proof roughly in half.

The reader/position commitments now use one batched P3 opening instead of a
mosaic opening. At 8192 rows the logup opening drops from about 373 KB (mosaic,
testkit measurement) to 198 KB; native proof sizes at 512/1024 rows are
essentially unchanged, but the prover is slightly faster.

Updated native benchmark:

| rows | proof | prove | verify |
|---:|---:|---:|---:|
| 512 | 425,729 B | 2.31 s | 1.16 s |
| 1024 | 614,537 B | 5.42 s | 2.16 s |
| 2048 | 950,705 B | 14.57 s | 4.73 s |

The dynamic native prover uses logup Shout for word mode; the reference
fallback covers compressed/mixed traces until the selected layout supports
compressed PC rows. The remaining quadratic part is Twist.

Full runtime suite: 316 passed. Runtime clippy: clean.


## 32-bit / mixed mode

The logup Shout position is now:

```text
position = word_or_halfword_index + is_32
```

For the mixed ROM table this is the cell that holds the instruction's
metadata (`high` in `BinaryShoutWitness::from_trace`). Word mode is the special
case where `is_32 = 0`. The standalone logup Shout component supports mixed traces, and
`logup_shout_mixed` verifies a compressed trace plus a 32-bit row. The selected
dynamic CPU prover still lacks compressed PC rows, so `prove_unified_trace_auto`
falls back to the reference proof for any trace containing a 16-bit row rather
than producing a broken dynamic proof. Removing that fallback requires
compressed-PC support in the selected dynamic layout.

Full runtime suite after the change: 316 passed.


## Native scale with logup Shout

`ADDS=... native_unified_bench`:

| rows | proof | prove | verify | logup | selected | claim |
|---:|---:|---:|---:|---:|---:|---:|
| 512 | 425,513 B | 2.76 s | 1.15 s | 137,921 B | 203,550 B | 55,370 B |
| 1024 | 614,001 B | 5.54 s | 2.21 s | 164,369 B | 295,830 B | 110,666 B |
| 2048 | 951,769 B | 15.58 s | 4.87 s | 198,249 B | 461,350 B | 221,258 B |
| 4096 | 1,583,937 B | 47.75 s | 12.21 s | 245,881 B | 770,302 B | 442,442 B |

The prover is now dominated by the selected CPU proof and the O(rows) claim
layer, not by Shout. Claim-native remains faster at 4096 rows (27.5 s /
1.21 MB / 149 cycles/s), because it replaces Access/Twist with direct claim
checks.
