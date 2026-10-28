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


## One-hot lookup prototype (reverted)

A logup*-based identity-table prototype for proving RA/WA rows are one-hot was
started. It compiled, but no verifier/position-binding path and no shared PCS
commitment were implemented, so it was reverted rather than committed as an
unverified component. The next step is a proper one-hot verifier plus address
bit/position binding.


## Prototype 6: one-hot PCS proof

`prove_onehot_pcs` / `verify_onehot_pcs` commit the K one-hot address columns
and prove with logup* over an extended identity table:

```text
row 0       = all-zero vector (no access)
row c+1     = basis vector e_c
table width = K
```

The table has 2K entries, so the lookup uses `address_bits + 1` variables.
PCS binds the committed columns to the reader claims. A tampered reader claim
is rejected. This proves one-hotness but not yet the link between positions and
the committed address-bit columns.

Full runtime suite: 323 passing.


## Prototype 7: one-hot + address-bit binding

The one-hot PCS proof now commits two batches:

```text
RA/WA columns              (K x T)
address-bit columns + valid (a+1 x T)
```

The lookup table is indexed by `valid * K + address` so its embedding is linear
in the committed address/valid bits:

```text
index = valid*K + cell
row 0..K      = all-zero vectors
row K+c       = basis vector e_c
```

The logup* position claim is checked against the PCS-opened address/valid bits
through the embedding

```text
position = sum_b address_bit_b * embed(1<<b) + valid * embed(K)
```

A tampered reader claim is rejected. This closes one-hot and address-bit binding
for a standalone committed table. Full runtime suite: 323 passing.


## Prototype 8: combined linear Twist proof

`LinearTwistProof` bundles:

```text
RW PCS proof
Val PCS proof
read one-hot/address PCS proof
write one-hot/address PCS proof
```

`prove_linear_twist` / `verify_linear_twist` round-trip on the register
witness; tampering a one-hot reader claim is rejected. This is the integration
boundary for replacing `binary_twist` history; the sub-proofs still use separate
commitments and the outer Access commitment is not yet wired.

Full runtime suite: 324 passing.


## Prototype 9: binary_twist linear entry point

Added to `binary_twist.rs`:

```text
BinaryTwistLinearProof
prove_binary_twist_ram_linear
verify_binary_twist_ram_linear
```

They validate the witness and delegate to the combined PCS-backed linear Twist
proof. `linear_binary_twist_bench` (release):

| rows | proof bytes | prove | verify |
|---:|---:|---:|---:|
| 1024 | 1,948,712 | 0.68 s | 25 ms |
| 16384 | 3,540,776 | 10.34 s | 68 ms |
| 65536 | 4,575,944 | 41.67 s | 80 ms |

This is the first actual `binary_twist.rs` path that runs at 2^16 without the
c² history. It is standalone (its own PCS commitments) and still misses the
outer Access commitment binding and final-state check.


## Prototype 10: proof-only linear verifier

Added `LinearTwistShape` plus shape-based verifiers:

```text
verify_val_pcs_shape
verify_rw_pcs_shape
verify_onehot_pcs_shape
verify_linear_twist_proof_only
```

No witness is needed: the proof carries `address_bits`/`cycles`, and all table
values come from PCS openings. `BinaryTwistLinearProof` also has a proof-only
verifier. This is a prerequisite for the paper/verifier path, but the proof is
still standalone: it does not yet bind its PCS commitments to the outer Access
commitment or check the final-state claim.

Full runtime suite: 324 passing.


## Prototype 11: outer-table claims

`linear_outer_claims(proof)` extracts the linear proof's opening claims in a
form that can be bound to the existing Access tables:

```text
ReadValue / WriteValue  at the RW cycle point
Increment               at RW/Val final points
Initial                 at the Val initial point
Address bit+valid       at both logup position points
```

The claims and points are low-coordinate-first. The test
`linear_outer_claims_match_access_tables` evaluates the `batch_tables` Access
columns at those points and checks every claim, so the extraction is consistent
with the outer commitment data.

Full runtime suite: 326 passing. Wiring these claims into the unified verifier
(and making the linear proof's own commitments the source of truth in the paper
path) is the next step.


## Unified-routing attempt: one-hot P3 failure on RAM witnesses

An optional `linear` field and threshold branch were prototyped in
`BinaryTwistRamProof`: at >=8192 cycles it would emit the linear proof and bind
its outer claims to the Access commitment.

The 8192-row RAM witness exposed a P3 one-hot opening failure: the read
one-hot proof verifies, but the write one-hot proof's own PCS batch
`verify_batch` returns false, even though its commitment/claims/points are
produced together. The write matrix has only cell 0 nonzero, so most columns
are zero (later offset by one; still failing). The same code verifies the
register witness and the 2^16 standalone example, so this is pattern/table
dependent, not a general point issue.

The unified-routing branch and test were reverted rather than enabled with an
unverified one-hot proof. Standalone linear BinaryTwist remains available and
its 2^16 benchmark is unchanged.


## Unified integration: paper-mode linear Twist

The unified BinaryTwist claims now switch to the linear proof at
`cycles >= 8192`:

```text
BinaryTwistRamProof.linear: Option<BinaryTwistLinearProof>
prove_binary_twist_claims -> linear branch
verify_binary_twist_from_proof_inner -> proof-only linear verify
+ linear_outer_mosaic_claims bound to the Access commitment
```

Paper-mode benchmark (`paper_unified_bench`, proof-only verifier):

| rows | proof bytes | access bytes | logup | selected | claim | prove | verify |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 16384 | 3,955,231 | 3,531,060 | 203,489 | 171,302 | 47,921 | 43.6 s | 16.5 s |
| 32768 | 4,568,567 | 4,057,684 | 221,009 | 195,262 | 93,089 | 106.3 s | 30.5 s |
| 65536 | 5,233,435 | 4,583,188 | 245,377 | 219,646 | 183,599 | 200.7 s | 66.6 s |

The 2^16 paper proof now completes in about 201 s prove / 67 s verify. The
dense c² history is no longer used at these sizes.

Remaining paper-alignment gaps:

- proof is ~5.2 MB, far from the paper's ~380 KiB target, dominated by the
  linear Access proof's PCS commitments/openings;
- the linear branch does not yet check the final state;
- the selected CPU/logup/claim layers are unchanged.


## Paper-parameter experiment on the linear Access proof

Using `(security=100, rate=4, pow=16, folding=3)` for the linear PCS reduced
the 16384-row paper proof:

```text
proof 3,955,231 B -> 2,023,191 B
access 3,531,060 B -> 1,599,020 B
prove 43.6 s -> 51.1 s
```

but the 65536-row run did not complete within 2400 s, so the parameters were
reverted. The working 2^16 result remains the default-parameter 5,233,435 B
proof. Proof-size reduction for 2^16 remains open.


### Additional parameter sweep

`(security=100, rate=4, pow=8, folding=3)` at 16384 rows:

```text
proof   2,144,311 B
access  1,720,140 B
prove      50.3 s
verify     16.1 s
```

but 65536 rows again exceeded 2400 s, so the default PCS parameters remain the
only working 2^16 configuration. Proof-size reduction at 2^16 needs a different
commitment strategy, not just PCS tuning.


## Working 2^16 parameters: rate=2, pow=8, folding=3

`(security=100, rate=2, pow=8, folding=3)` completes at 2^16:

| rows | proof bytes | access | logup | selected | claim | prove | verify |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 16384 | 2,374,327 | 1,950,156 | 203,489 | 171,302 | 47,921 | 41.3 s | 16.3 s |
| 65536 | 3,028,299 | 2,378,052 | 245,377 | 219,646 | 183,599 | 202.2 s | 67.9 s |

Compared with the previous default 2^16 result, proof size drops from
5,233,435 B to 3,028,299 B; prove time is 202.2 s and verify time 67.9 s.
These are now the retained working parameters for the linear Access proof.


## Final-state check: concrete design

The linear branch still omits the final-state claim. The planned check is:

```text
commit initial and final vectors in a small PCS batch
claim = final(rk) - initial(rk)

prove claim = sum_{cell,cycle} eq(rk,cell) * WA(cell,cycle) * Inc(cycle)
```

by a degree-2 sumcheck over the `K*T` address/cycle variables. The terminal
needs `WA` and `Inc` evaluations at the sumcheck point; these should reuse the
existing RW/Val PCS openings rather than adding new commitments. A full
implementation therefore requires extending the RW/Val proof structs to expose
one extra terminal opening, plus a small committed initial/final batch. This
remains the next soundness item before paper alignment.


## Final-state check implemented

`FinalStateProof` now commits `initial`/`final`, reuses the RW final point as a
fixed-challenge sumcheck point, and proves

```text
final(rk) - initial(rk)
  = sum_{cell,cycle} eq(rk,cell) * WA(cell,cycle) * Inc(cycle)
```

The initial claim at the same cell point is also exposed as an outer Access
claim. Paper-mode results with the final-state check:

| rows | proof bytes | access | logup | selected | claim | prove | verify |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 16384 | 2,413,015 | 1,988,844 | 203,489 | 171,302 | 47,921 | 42.7 s | 16.6 s |
| 65536 | 3,067,099 | 2,416,852 | 245,377 | 219,646 | 183,599 | 246.8 s | 107.5 s |

The final check adds about 39 KiB to the proof and ~44 s prove / ~40 s verify at
2^16. The final vector itself is still committed by the linear proof, not by the
outer Access commitment.


## Combined one-hot commitment attempt (reverted)

Combining the one-hot table and address-bit batches into one PCS commitment
with two opening points reduced commitment count but the combined
`verify_batch` rejected the opening. The separate-commitment version was
restored; the combined version was not committed.


## Linear proof component sizes (16384-row class, 1024-row probe)

`linear_binary_twist_bench` now reports sub-proof sizes. At 1024 rows:

```text
RW            545,288 B
Val           445,104 B
read one-hot  473,696 B
write one-hot 473,696 B
final state    38,464 B
total       1,976,264 B
```

The two one-hot proofs are the largest single contributors; reducing/merging
them is the main remaining proof-size lever.


At 16384 rows the breakdown is:

```text
RW            521,000 B
Val           448,248 B
read one-hot  489,112 B
write one-hot 489,112 B
final state    38,688 B
total       1,986,176 B
```

The paper target (~380 KiB) would require roughly a 5x reduction. PCS
parameter tuning and one-hot batching attempts do not close that gap; it needs
a smaller commitment/opening scheme for the dense linear tables.


## Final vector in the outer Access commitment

The outer `initial` table now has two columns `[initial, final]`, so the final
vector is committed by Access without adding a new table index. The linear
proof exposes the final value at the fixed cell point as an outer claim, and the
`initial/final` columns are checked by the existing Access opening.

Latest paper-mode results:

| rows | proof bytes | access | logup | selected | claim | prove | verify |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 16384 | 2,413,039 | 1,988,844 | 203,489 | 171,302 | 47,921 | 66.3 s | 19.1 s |
| 65536 | 3,067,123 | 2,416,852 | 245,377 | 219,646 | 183,599 | 283.7 s | 77.6 s |

The final-state relation and both endpoint commitments are now bound to the
outer Access commitment. Proof size is unchanged (~3.07 MB at 2^16); the
remaining paper-alignment gap is proof size.


## Shared-commitment groundwork (option A)

Added `shared_twist.rs`: all linear tables are flattened to `K*T` columns and
committed by one PCS batch (`ra, wa, val, inc, read, write, read/write address
bits + valid, initial, final`).

At 1024 rows a single combined opening is:

```text
columns=20
commit ~0.67 s
open   ~1.29 s
verify ~5 ms
proof bytes 557,696
```

versus ~1.98 MB for the separate sub-proofs. The 16384-row 20-column batch did
not finish within 1800 s, so the next implementation step is to split the
shared commitment into three groups (K*T tables, cycle tables, cell endpoints)
rather than one wide batch.


## Option A: shared-opening findings

- Multi-point `P3BatchOpening` works (probe with two points/subsets passes).
- A single 20-column flattened shared batch opens in ~0.56 MB at 1024, but the
  16384-row version did not finish within 1800 s.
- Splitting into three broadcast groups at 16384 gives ~1.99 MB and
  commit/open ~7/14 s, i.e. no size win.
- A shared Val proof that reuses the RW table/input commitments verifies, but
  at 1024 rows it is 556,568 B versus 445,104 B for the standalone Val proof;
  the extra commitment caps/points outweigh the reuse.

Conclusion: simply sharing commitments is not sufficient; the sub-proofs must
also share *points/columns* so one opening covers RW and Val terminals. The next
step is a single shared table opening with both RW and Val points and no
duplicated commitment caps.


## Single-opening probe for RW+Val

A probe opens one shared table batch and one shared input batch at all six
RW/Val points:

```text
rows=1024 old_rw_val=990,392 B
shared_open=748,496 B
open ~0.34 s
verify ~9 ms
```

So one multi-point opening saves ~24% versus separate RW+Val proofs at small
size. The actual shared RW+Val proof still needs the circuits to consume the
same opening values; this is the next implementation step.


## Shared RW+Val proof integrated

`SharedRwValProof` now replaces the separate RW and Val proofs. It uses one
table opening and one input opening covering both reductions:

```text
rows 1024: old RW+Val 990,392 B -> shared 558,376 B
```

Paper-mode results after integration:

| rows | proof bytes | access | logup | selected | claim | prove | verify |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 16384 | **1,970,159** | 1,545,964 | 203,489 | 171,302 | 47,921 | 46.1 s | 17.5 s |
| 65536 | **2,521,411** | 1,871,140 | 245,377 | 219,646 | 183,599 | 320.5 s | 114.9 s |

At 1024 the remaining components are:

```text
rwval          558,376 B
read one-hot   473,696 B
write one-hot  473,696 B
final state     38,464 B
```

The two one-hot proofs are now the dominant remaining size target.


## Shared one-hot proof integrated

Read and write one-hot proofs now share one PCS commitment/opening and one
logup reduction with two readers. At 1024 rows:

```text
old read+write one-hot 947,392 B -> shared 381,824 B
```

Paper-mode results:

| rows | proof bytes | access | logup | selected | claim | prove | verify |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 16384 | **1,329,103** | 904,908 | 203,489 | 171,302 | 47,921 | 72.1 s | 21.1 s |
| 65536 | **1,718,763** | 1,068,492 | 245,377 | 219,646 | 183,599 | 267.9 s | 158.8 s |

Cumulative effect of option A at 2^16:

```text
3,067,123 B -> 1,718,763 B
```

Remaining linear components at 1024 are `rwval 558 KB`, `onehot 382 KB`,
`final 38 KB`.


## Parameter sweep after shared proofs

With shared RW+Val and shared one-hot, `(100, 4, 16, 3)` gives 16384-row proof
1,171,823 B (prove 68 s), but 65536 rows still exceeds 2400 s. `(100,4,8,3)`
gives 1,228,815 B at 16384 and also times out at 2^16. The working 2^16
configuration remains `(100,2,8,3)` with proof 1,718,763 B.


### Post-sharing parameter sweeps

At 16384 rows with shared proofs:

```text
rate=3,pow=8 : 1,236,159 B, prove 46.9 s
rate=2,pow=16: 1,264,111 B, prove 72.9 s
rate=2,pow=8 : 1,329,103 B, prove 72.1 s
```

Both rate=3 and pow=16 variants exceeded 2400 s at 65536 rows, so the retained
2^16 configuration remains rate=2,pow=8,folding=3 with 1,718,763 B.


## Reusing RW table commitment for one-hot claims (negative)

Probe: open the shared RW table batch `[ra,wa,val]` at one point per cell
(K points, columns `[0,1]`) to obtain all K read/write one-hot claims.

```text
reuse table opening = 381,992 B
current shared one-hot proof = 381,824 B
```

The multi-point opening alone already costs as much as the whole current
one-hot proof, before adding address openings/logup. This reuse is rejected.


## Final state merged into shared RWVal opening

The shared RWVal initial batch now commits `[initial, final]` and opens at both
the Val point and the RW final cell point. `FinalStateProof` is reduced to the
fixed-challenge sumcheck rounds (no separate PCS opening).

Paper-mode results after the merge:

| rows | proof bytes | access | logup | selected | claim | prove | verify |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 16384 | **1,299,663** | 875,468 | 203,489 | 171,302 | 47,921 | 98.1 s | 41.0 s |
| 65536 | **1,684,331** | 1,034,060 | 245,377 | 219,646 | 183,599 | 340.3 s | 216.4 s |

Timings vary strongly with machine load; proof size continues the A-direction
reduction (3,067,123 B -> 1,684,331 B at 2^16).


## A2 first component: virtual one-hot evaluation

Added `virtual_onehot.rs`:

```text
prove_virtual_onehot(witness, write, rk, rj)
verify_virtual_onehot(shape, rk, rj, proof)
```

It commits only address bits + valid, then proves a dense one-hot evaluation

```text
RA(rk,rj) = sum_cycle eq(rj,cycle) * valid(cycle) * prod_b factor(bit_b,rk_b)
```

by a cycle-variable sumcheck; the terminal opens the bit/valid columns. No dense
K x T one-hot commitment.

At 1024 rows a single virtual one-hot proof is 196,144 B. Two separate proofs
(392 KB) are not yet smaller than the current shared one-hot proof (382 KB), so
the next step is a multi-target virtual address proof sharing one commitment/
opening, then using its claims inside the local RW/Val sumchecks.


## A2 multi-target virtual address attempt (reverted)

A multi-target virtual address proof was prototyped: one address-bit commitment
and one batched cycle sumcheck for RA/WA evaluations at several points. The
prover's combined sum matched the weighted claims, but replay rejected the
round polynomials (sumcheck degree/folding mismatch). The prototype was
reverted; the committed single-target `virtual_onehot` proof remains.

Next attempt should first fix the multi-target sumcheck degree handling in a
small standalone test, then reuse the same commitment for all local Twist
terminal claims.


## A2: multi-target virtual address proof

Added `prove_virtual_address` / `verify_virtual_address`. One address-bit
commitment and one grouped sumcheck prove RA/WA evaluations at several points;
the summand is a sum of per-target products and the round degree is the address
width.

At 1024 rows, three targets (RA @ RW point, WA @ RW point, WA @ Val point):

```text
virtual address proof = 235,760 B
```

versus 382 KB for the dense shared one-hot proof and 3 x 196 KB for separate
single-target proofs. This is the component that can replace dense one-hot
commitments in the local Twist path.

Full suite: 335 passing.


## A2 local Twist proof integrated

Added `local_twist.rs`: no dense RA/WA/Val commitments. It commits only
increment/read-write values, address bits/valid, and initial/final endpoints,
and proves:

```text
RW checking with locally computed dense factors
Val evaluation from Inc/WA/initial
multi-target virtual address claims
final-state fixed sumcheck
```

Standalone local proof:

| rows | proof bytes | prove | verify |
|---:|---:|---:|---:|
| 16384 | 460,512 | 0.80 s | 6.4 ms |
| 65536 | 557,624 | 3.30 s | 8.1 ms |

Paper-mode unified results with the local proof:

| rows | proof bytes | access | logup | selected | claim | prove | verify |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 16384 | **887,375** | 463,180 | 203,489 | 171,302 | 47,921 | 87.1 s | 42.9 s |
| 65536 | **1,210,563** | 560,292 | 245,377 | 219,646 | 183,599 | 329.2 s | 102.5 s |

Cumulative: 2^16 paper proof 3,067,123 B -> 1,210,563 B (-61%). The standalone
local memory proof is 557,624 B / 8 ms verify, close to the paper's 380 KiB /
8 ms memory target; the remaining paper overhead is logup/selected/claim.


### Local proof component breakdown (2^16)

```text
values opening   243,792 B
virtual address  296,344 B
endpoints         12,816 B
rounds              ~3.9 KB
total             557,624 B
```

The two PCS openings dominate. A single shared local opening covering values,
address bits, and endpoint broadcasts is the next size lever; even then the
paper's 380 KiB total target also requires compressing logup/selected/claim,
which currently total ~648 KB at 2^16.


## A2 shared local opening: memory proof below paper target

`local_shared.rs` commits values, address bits/valid and endpoint tables with one
shared opening plus a small endpoint opening. Standalone:

| rows | proof bytes | prove | verify |
|---:|---:|---:|---:|
| 65536 | **309,848** | 2.80 s | 4.8 ms |

This is below the paper's ~380 KiB / 8 ms memory target.

Paper-mode unified results:

| rows | proof bytes | access | logup | selected | claim | prove | verify |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 16384 | **690,351** | 266,156 | 203,489 | 171,302 | 47,921 | 47.3 s | 22.6 s |
| 65536 | **962,787** | 312,516 | 245,377 | 219,646 | 183,599 | 234.1 s | 108.6 s |

Cumulative: 2^16 paper proof 3,067,123 B -> 962,787 B (-69%). The memory
component now meets the paper target; the remaining total-proof gap is
logup/selected/claim (~648 KB together) and the endpoint opening.


## Extreme local PCS parameters

Local shared proof with production-style PCS params:

| params | proof bytes | prove | verify |
|---|---:|---:|---:|
| rate2/pow8/fold3 | 309,848 | 2.80 s | 4.8 ms |
| rate4/pow16/fold3 | 277,080 | 7.41 s | 4.29 ms |
| rate4/pow24/fold3 | **257,144** | 10.60 s | 4.38 ms |
| rate4/pow28/fold3 | 240,184 | 208.06 s | 3.54 ms |

`pow24` is the retained local setting. Paper-mode 2^16 with it:

```text
proof        910,083 B
compressed   715,353 B (whole-proof DEFLATE level 6)
access       259,812 B
logup        245,377 B
selected     219,646 B
claim        183,599 B
prove        219.7 s
verify       112.6 s
```

The memory component is below the paper memory target; the remaining total-proof
gap is logup/selected/claim.


## Whole-proof compression format

Added `serialize_unified_proof_compressed` /
`deserialize_unified_proof_compressed` (bincode + DEFLATE level 6). The paper
bench verifies the decompressed proof round-trip.

2^16:

```text
raw proof        910,083 B
compressed       715,353 B
prove            208.5 s
verify            71.6 s (includes decompress + original verify)
```

At 16384 the compressed proof is 482,569 B vs 649,679 B raw.
