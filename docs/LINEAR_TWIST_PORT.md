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


## Prototype 1: linear read/write-checking sumcheck

Added `crates/magnetar-runtime/src/linear_twist.rs`. It materializes the
one-hot `RA`/`WA` matrices and a prefix `Val` table of size `K*T` (not `T^2`)
and proves the relation

```text
sum_j eq(r_cycle, j) * (WA * (Inc + Val) + gamma * RA * Val)
```

with a degree-3 sumcheck over the `K*T` boolean variables.

The prototype round-trips on a 1024-cycle register witness and rejects a
tampered claim. Verification in this prototype still recomputes the tables;
the real integration will replace those recomputations with PCS claims and a
separate Val-evaluation sumcheck.


## Negative result: first Val-evaluation prototype

A first Val-evaluation sumcheck prototype was attempted but the direct
prefix/suffix formula did not match the flat `Val` table's MLE evaluation under
the current point ordering. The prototype was reverted rather than committed
with an unverified relation. Next attempt should isolate the MLE point-order
convention in a small test before integrating it with the RW prototype.


## Val-evaluation prototype: point-order findings

A second Val-evaluation attempt confirmed the flat `Val` table point layout:
the table must be indexed `cell * cycles + cycle` and evaluated with the cycle
point first, then the address point. In a small standalone table the suffix
formula

```text
Val(rk,rj) = init(rk) + sum_p WA(rk,p) Inc(p) sum_{j>p} eq(rj,j)
```

matches the flat MLE. The full register witness still produced a mismatch, so
the prototype was reverted before committing a relation that is not verified.
The remaining discrepancy is in the full witness's table construction or
padding, not in the small-table MLE convention.
