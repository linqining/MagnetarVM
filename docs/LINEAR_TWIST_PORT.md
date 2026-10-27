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


## Full-witness Val debug: padding suspicion

The register benchmark witness used for debugging has

```text
witness.cycles = 1023
padded cycles  = 1024
```

The small-table formula matches the flat `Val` MLE, but the full witness does
not. The remaining discrepancy is therefore in the padded-cycle / table
construction path, not in the small-table point ordering. The Val prototype was
reverted again without being committed.


## Prototype 2: Val-evaluation sumcheck (fixed padded rows)

The mismatch was the padded tail of the `Val` table: cycles
`witness.cycles..T` must repeat the final register state, not stay zero, because
the MLE prefix formula includes those padded cycle coordinates.

After filling padded rows with the final current values (WA/Inc zero), the
Val-evaluation sumcheck round-trips and rejects a tampered claim. It remains a
prototype: verification still materializes the tables; PCS claims are next.

Full runtime suite: 320 passing; clippy clean.


## Prototype scaling (RW + Val sumchecks)

`ROWS=... linear_twist_bench` (release, register Twist witness):

| rows | RW prove | RW verify | Val prove | Val verify |
|---:|---:|---:|---:|---:|
| 1024 | 59 ms | 19 ms | 15 ms | 8 ms |
| 4096 | 44 ms | 20 ms | 9 ms | 5 ms |
| 16384 | 531 ms | 89 ms | 29 ms | 20 ms |
| 65536 | 986 ms | 1.38 s | 509 ms | 380 ms |

The 2^16 run completes in under 3 seconds total for both prototype sumchecks,
versus >900 s for the dense 2^14 paper run. This demonstrates the linear
algorithm removes the structural blocker; it is not yet a sound proof because
the prototype verifier recomputes the tables instead of checking PCS claims.


## Prototype 3: Val evaluation with PCS claims

`prove_val_pcs` / `verify_val_pcs` commit three PCS batches (with the default
P3 parameter set for test speed):

```text
Val, WA       (K*T)
Inc           (T)
initial       (cells)
```

The verifier obtains `Val(rk,rj)`, `WA(rk,r_i)`, `Inc(r_i)` and
`init(rk)` from checked batch openings, replays the Val sumcheck, and checks
the final product against `LT`. A tampered sumcheck round is rejected.

Full runtime suite: 321 passing. The dense prototypes are still not integrated
with `binary_twist`; dense RA/WA/Inc/Val tables are committed here independently.


## Prototype 4: RW checking with PCS openings

`prove_rw_pcs` / `verify_rw_pcs` commit two PCS batches:

```text
RA, WA, Val       (K*T)
Inc, read, write  (T)
```

Openings at the cycle point are used for the left-hand read/write value
claims; openings at the sumcheck final point supply RA/WA/Val/Inc for the
final product. The verifier replays the RW sumcheck and checks the final
`eq * (WA*(Inc+Val) + gamma*RA*Val)` term. A tampered round is rejected.

Full runtime suite: 322 passing. Still missing: one-hot/address-bit bindings,
and sharing the Val commitment between the RW and Val PCS proofs. The dense
tables are not yet integrated into `binary_twist`.


## Prototype 5: PCS-backed RW + Val at 2^16

`ROWS=65536 linear_twist_pcs_bench` with the prototype PCS parameters:

```text
rw_bytes       1,235,480 B
val_bytes      1,050,304 B
total_bytes    2,285,784 B
rw_prove          41.82 s
rw_verify         18.8 ms
val_prove         17.27 s
val_verify        12.0 ms
```

The prover is linear and the verifier is fast, but the prototype commits
dense RA/WA/Val/Inc/read/write tables independently and does not bind one-hot
addresses to the Access commitment. Proof size is therefore not comparable to
the paper target; this is a scaling demonstration only.


## PCS parameter experiment

Switching the prototype PCS to `(security=100, rate=4, pow=16, folding=3)`
reduced standalone proof size substantially:

| rows | RW+Val bytes | prove |
|---:|---:|---:|
| 1024 | 528,552 B | 4.2 s |
| 16384 | 798,080 B | 48 s |

but the 65536-row prototype did not finish within 2400 s, so the parameter
change was reverted. The default prototype parameters keep the scaling
benchmark runnable; production PCS integration remains a separate task.
