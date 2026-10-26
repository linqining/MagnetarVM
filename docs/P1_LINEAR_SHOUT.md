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

PCS-bound measurements:

| rows | prove | verify | logup proof |
|---:|---:|---:|---:|
| 1024 | 24.5 ms | 110.1 ms | 20,520 B |
| 8192 | 165.7 ms | 430.6 ms | 137,272 B |
| 65536 | 1.33 s | 2.87 s | 1,057,272 B |

The current verifier opens every committed column separately, which dominates
its time; batching those openings is the next optimization. The prover is still
far below the old quadratic Shout (1.70 s at 1024 rows, 757 s at 8192 rows).

For comparison the old quadratic Shout is 1.70 s / 337 KB at 1024 rows and
757 s / 506 KB at 8192 rows.

This is a sound reduction, but not yet a complete Shout proof: the table,
reader-value and position columns are still trusted inputs, not bound by a PCS.
The next milestone is to commit those columns and discharge the logup* output
claims through P3 openings.
