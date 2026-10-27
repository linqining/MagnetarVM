# Linear Twist port plan (option A)

## Goal

Replace the dense `cycles^2` read/write history sumcheck in
`crates/magnetar-runtime/src/binary_twist.rs` with a linear-size Twist
read/write-checking argument, following the Twist construction and Jolt's
implementation.

## Blocking fact

Current history prover materializes/streams a pair over all `(cycle, previous)`
pairs. At 2^16 that is `2^32` entries and ~85 GiB after folding. The local
Twist algorithm avoids this pair by expressing the check as two sumchecks over
one-hot address matrices and a virtual value polynomial.

## Reference implementation

Jolt (a16z) implements the local Twist prover in:

- `jolt-core/src/zkvm/registers/read_write_checking.rs`
- `jolt-core/src/zkvm/registers/val_evaluation.rs`
- `jolt-core/src/zkvm/ram/`
- `jolt-core/src/poly/ra_poly.rs`, `shared_ra_polys.rs`, `prefix_suffix.rs`

Pinned revision:
`a0dbd371c05964d6385a6995226576db0aa4a724`.

The read/write-checking relation is:

```text
sum_j eq(r_cycle, j) * (RdWriteValue(j) + gamma * ReadVals(j))
```

with

```text
RdWriteValue(j) = sum_k wa(k,j) * (inc(j) + Val(k,j))
ReadVals(j)     = sum_k ra1(k,j) * Val(k,j) + gamma * ra2(k,j) * Val(k,j)
```

and `Val(k,j)` is the value of cell `k` immediately before cycle `j`. The
`Val` polynomial is virtual; its evaluation is reduced by a separate sumcheck
from the write increments and the initial state.

## Port phases

1. **Val evaluation sumcheck**
   - Prove `Val(r_k, r_j)` from `Inc`, `WA`, and initial values.
   - Prover local: prefix/suffix over cycles and one-hot address matrices.
   - No pair-of-cycles table.

2. **Read/write checking sumcheck**
   - Prove the per-cycle relation above using one-hot `RA/WA` and the virtual
     `Val` claim from phase 1.
   - Local prover over cycle chunks; memory `O(K * T)` at worst, not `O(T^2)`.

3. **Final state check**
   - Existing final-state sumcheck can use the same virtual `Val` claim.
   - Initial state remains a table evaluation.

4. **Integrate into `prove_binary_twist_claims`**
   - Keep existing address boolean/read-initial/final claims.
   - Replace only the two dense history claims and their claimed values.
   - Verifier: accept the new linear claim type; bind the terminal
     `Val`/`RA`/`WA`/`Inc` evaluations through the existing mosaic opening.

5. **Paper 2^16 run**
   - Memory should be dominated by `K*T` and `T`, not `T^2`.
   - Re-run `paper_unified_bench` at 32768 and 65536.

## Acceptance criteria

- Full runtime suite passes.
- No `cycles^2` allocation in the prover path.
- 32768-row paper run completes well below the previous 3600 s timeout.
- Paper 2^16 attempt; report proof/prove/verify even if targets are missed.
