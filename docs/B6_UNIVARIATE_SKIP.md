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
