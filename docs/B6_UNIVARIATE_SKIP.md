# B6 univariate-skip decision note

Status: univariate skip is not a drop-in optimization for the current CPU
sum-check. Frobenius collision and the degree-point fold optimization are
implemented; this note records why the remaining protocol work is a backend
change rather than a local patch.

## What the reference sum-check does

The CPU/aux reductions are ordinary multilinear sum-checks over `F2_128`:

```text
sum_{x in {0,1}^n} f(x) = v
```

They end in a plain evaluation claim `f(r) = v_r`, which the PCS opens at an
arbitrary field point.

## What the vendored univariate_skip does

`vendor/plonky3/sumcheck/univariate_skip` implements a zerocheck/subspace
round:

- it skips `k` coordinates by treating them as an additive subspace;
- the round polynomial vanishes on the subspace, so those values are not sent;
- the residual claim is an inner product with the subspace Lagrange vector,
  not a plain multilinear evaluation;
- the caller still owes a following `k`-round reduction to a plain evaluation,
  or an opening of the bound row values.

It is parameterized over p3 tower/binary fields and a zerocheck composition.

## Mismatch

The current reference has no zerocheck composition, no additive-subspace
domain/interpolation layer over `F2_128`, and no inner-product opening
interface. Adding univariate skip would require one of:

1. a new zerocheck backend over `F2_128`, including subspace interpolation and
   the final inner-product-to-evaluation reduction; or
2. changing the CPU sum-check/PCS interface so the verifier can open bound row
   values rather than a single multilinear evaluation.

Both change the proof format and soundness argument. Copying the vendored
round without the follow-up reduction would prove a different statement.

## Prototype status

`magnetar-runtime::univariate_skip` now provides:

- an additive subspace of `F2_128` of size `2^k`;
- Lagrange weights and interpolation at an off-domain challenge;
- a `SkipRound` message that vanishes on the domain and is transmitted on a
  coset;
- `SkipRoundProof` with transcript-bound challenge/evaluation;
- `row_weights(at)`: the skip challenge as a weighted bound-row claim
  `Q(r) = Σ_i w_i(r) values_i`;
- barycentric message evaluation (O(|D|^2) instead of O(|D|^3));

with tests for distinctness, interpolation at the domain points, matching a
low-degree polynomial at a random point, domain vanishing, coset matching, and
challenge/evaluation tampering.

`univariate_skip_bench` (release):

```text
log_size=4   16 points    interpolation 56 us   skip round 71 us
log_size=8  256 points    interpolation 1.5 ms  skip round 17.2 ms
log_size=10 1024 points   interpolation 33 ms   skip round 266 ms
log_size=12 4096 points   interpolation 358 ms  skip round 4.65 s
```

Tests now also show that an all-zero domain gives a zero message and that a
nonzero domain produces a nonzero challenge evaluation. This links the skip
round to the B2 `bound_rows` interface; the remaining work is to prove the
committed domain values are the constraint composition C(f) and to wire the
result into the CPU proof. The quadratic Lagrange cost is acceptable for small skip sizes
(k=2–4); larger skips need a product-tree/interpolation optimization.

## Recommendation

For this reference, treat B6 as:

```text
Frobenius collision check       implemented
degree-point fold optimization  implemented
weighted product2 batching      implemented
univariate skip                 deferred (requires a new zerocheck backend)
```

If univariate skip becomes a hard requirement, the next concrete step is to
prototype a zerocheck backend for one reduction (for example BinaryTwist
address collision) with an explicit subspace domain and final reduction, before
touching the CPU path.


## Residual-layer finding

The current `SkipRound` proves only that the reconstructed polynomial vanishes on
the domain and matches the coset message. It does not yet prove the zerocheck
residual. The residual is subtle: the skip challenge is not the plain
multilinear evaluation `f(r)`; it is a linear combination of `f` on the Boolean
domain with Lagrange weights. Reducing that to a plain PCS opening needs a
second sum-check over the same `k` coordinates.

This was checked against the vendored p3 implementation: its skip round
explicitly documents the final claim as an inner product and states that the
caller still owes that reduction. Porting only the round would therefore change
the statement.

A full prototype must therefore include both:

1. `SkipRound` message (done here);
2. weighted inner-product sum-check ending in `f(r)` (not done here).

Until (2) exists, the skip round must not be wired into `binary_twist` or the
CPU proof.


## B2 residual opening

`magnetar-runtime::bound_rows` implements the first piece of the B2 interface:

```text
sum_i lambda_i f(i) = v
-> degree-2 product sum-check over lambda and f
-> f(r) = v_r
-> P3 opening of f at r
```

`bound_rows_bench` measures it for k=4/8/10. This is the layer a skip
challenge can target; the skip message relation itself must still be tied to
this weighted claim before it can be used in `binary_twist`/CPU.


### Skip-bound chain measurements

`prove_skip_bound` / `verify_skip_bound` compose a `SkipRoundProof` with a
`BoundRowProof` over the same committed rows. `row_weights` is O(|D|^2), so the
k=8 skip-bound chain dropped from 4.1 s to ~32 ms (prove) / ~22 ms (verify) in
this release probe:

```text
log_size=4   skip-bound proof 7,336 B   prove 0.26 ms  verify 0.20 ms
log_size=8   skip-bound proof 71,688 B  prove 31.8 ms  verify 22.2 ms
```

The chain proves `Q(r) = Σ_i w_i(r) f_i`; it still does not prove that the rows
are the constraint composition `C(f)`, which is the remaining zerocheck layer.


### Toy zero-row argument

`prove_zero_rows` / `verify_zero_rows` compose the skip message with bound rows
and require the skip evaluation to be zero. Tests accept an all-zero committed
row vector and reject a nonzero one. This validates the B2 residual chain, but
the committed rows are still an arbitrary vector; tying them to a constraint
composition `C(f)` is the remaining zerocheck layer.
