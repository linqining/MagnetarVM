# Paper Gap Closure Plan

This plan closes the remaining gap between the current native claim path and
the Magnetar paper. It is ordered by expected effect on the 1024/2048/4096-row
prover and by dependency.

## Phase P0: statement binding and verifier soundness

Status: completed in this round.

- The native verifier now rejects a proof whose `trace_claim_root` or
  `trace_commitment` differs from the public `Statement`.
- Remaining P0 items: reservation-chain R1CS, AMO storage rules, unaligned
  accesses, FP execution/proofs, and the third-party audit.

## Phase P1: linear/sparse BinaryShout and BinaryTwist

This is the first performance-critical rewrite.

### P1.1 BinaryShout

Replace the `cells x cycles` read sum-check with an offline-memory/log-derivative
lookup argument:

- commit the word (or halfword) table once;
- commit a read-value vector in cycle order;
- prove the read multiset is contained in the table with a random-challenge
  grand product / logUp argument;
- keep the existing address and metadata link claims;
- eliminate the quadratic factor materialization.

Expected effect: ShoutClaims becomes linear in `rows + table_cells`; the
current 1024-row 3.8 s packed-Shout CPU cost and the 4096-row memory wall should
drop by roughly an order of magnitude.

### P1.2 BinaryTwist history

Replace the `(2*rows)^2` register-history and `cells x cycles` RAM sum-checks
with a sorted access/permutation argument:

- sort `(address, cycle, read/write)` events;
- prove adjacent address equality and read/write ordering with grand products;
- discharge terminal values with the existing batched P3 opening.

Expected effect: register access (currently ~3.9 s at 1024 rows) and RAM access
become linear; 4096-row scaling is the main beneficiary.

## Phase P2: BinarySpartan and uniform SIMD CPU

- Build uniform `s1`/`s2` matrices and the Dual SIMD R1CS boundary.
- Replace the per-row CPU constraint bank with the paper's virtual Spartan
  lockstep reduction.
- Reuse the claim router/segment claims already present.
- Expected effect: large at scale, but the rewrite may temporarily regress
  until the matrix packing and PCS parameters are retuned.

## Phase P3: recursion and verifier-in-the-VM

- Implement the paper's recursive verifier circuit and chunk aggregation.
- Keep the existing hash-chain/state-continuity aggregator as a reference.
- Expected effect: smaller proofs and chunked proving; recursion adds prover
  overhead, so it should not be sold as a raw throughput win.

## Phase P4: ZK/hiding and private IO

- Blinded witness, ZK sum-check, hiding commitments, private IO.
- Expected effect: slower prover and larger proofs; do after the non-ZK path is
  performant.

## Phase P5: remaining semantics

- RV64A reservation constraints inside R1CS.
- FP execution/proofs.
- Unaligned memory accesses.
- Full syscall runtime and Sv39 integration.
- These are correctness/coverage items, not throughput items.

## Phase P6: scale benchmark and audit

- Benchmark 2^12, 2^14, 2^16, 2^18 rows with medians and peak memory.
- Compare against the paper's 2^16 and 2^22 points.
- Third-party security audit before any "secure" claim.

## Performance expectation

Completing all gaps will not automatically reach 547 ms at 2^22. The paper's
number depends on the linear BinaryShout/BinaryTwist reductions, uniform SIMD
BinarySpartan, field SIMD, and a tuned MosaicPCS/Ligerito stack. Phase P1 and P2
are the levers that can make performance better; P3 and P4 mostly trade prover
time/proof size for recursion and privacy. Small traces may regress after each
algorithmic rewrite until parameters are retuned.
