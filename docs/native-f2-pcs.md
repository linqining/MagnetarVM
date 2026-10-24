# Native F2 PCS for B3

## Goal

A polynomial commitment for multilinear polynomials with coefficients in `F2`
that can be opened at an **extension point** `r ∈ F2^128^n`, because B3's
sum-check uses extension challenges for soundness.

The existing `F2NativePcs` Merkle opening only works at `r ∈ F2^n`: at an F2
point the MLE is exactly one coefficient bit:

```text
MLE(bits, r) = bits[Σ r_i 2^i]      (r_i ∈ F2)
```

so a Merkle path suffices. At an extension point the evaluation is a dense
linear functional:

```text
MLE(bits, r) = Σ_i eq(r, i) · bits[i].
```

A Merkle path cannot prove a dense linear functional succinctly.

## Candidate: binary Ligero linear-functional PCS

Use a binary linear code `C: F2^k -> F2^n` and commit the codeword with a Merkle
tree. The code provides redundancy: if the prover commits a codeword, any
deviating codeword is far from the code, and a small number of random column
checks detects it.

### Encoding

Systematic encoding:

```text
codeword = message || parity
parity_j = Σ_i H[j][i] · message_i        over F2
```

`H` is derived deterministically from SHA-256 labels. This avoids storing a
large parity matrix and is reproducible by the verifier. The prototype lives in
`BinaryLigeroCode` in `crates/magnetar-pcs/src/f2.rs`.

### Commitment

Merkle-commit the codeword bits with `F2NativePcs`.

### Linear-functional opening

To prove

```text
v = Σ_i a_i · message_i,      a_i ∈ F2^128
```

1. The prover sends `v`.
2. The verifier samples a random linear combination of codeword positions
   (Ligero's row/column sampling) and asks for the corresponding opened symbols.
3. The prover opens those symbols plus the parity combinations needed to check
   that the opened symbols are consistent with a codeword.
4. The verifier checks the linear relation and the codeword consistency.

The exact Ligero test (number of columns, repetition, proximity gap) is the
remaining design work. The security target is 100-128 bits, matching the rest of
the workspace.

### Extension point

The MLE at `r` is the linear functional with weights `eq(r, i)`. So the Ligero
linear-functional opening directly gives the extension-point evaluation without
embedding coefficients into `F2^128`.

## Why not reuse Ligerito

The vendored Ligerito supports `BinaryElem32`/`BinaryElem128` coefficients and
is an **index-opening** PCS. It does not implement dense linear-functional
openings over F2 bits, and its coefficient field is not F2. Reusing it would
still embed each bit into a larger field.

## Milestones

1. `BinaryLigeroCode` systematic encoder + Merkle commitment (done).
2. Ligero linear-functional test (open columns, consistency, soundness).
3. Extension-point MLE wrapper using `eq(r, i)`.
4. Native F2 sum-check over the bit relation.
5. Virtual Spartan lockstep sharing with the packed `F2^128` relation.
6. CPU schema integration.

## Open choices

- Code rate and parity rows (proof size vs proximity gap).
- Number of sampled columns and repetition count for 100-bit security.
- Whether to use one Merkle tree over the codeword or column-wise trees.
- Whether the linear test is batched across many MLE claims.
