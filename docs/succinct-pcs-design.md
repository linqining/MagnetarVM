# Production-grade succinct/hiding multilinear PCS for the MagnetarVM unified proof

Status: research/design note. No production implementation is added here.

## 1. Problem and baseline

`UnifiedTraceProof` currently uses `P3BinaryPcs` (the vendored Plonky3
`p3-binary-pcs` scheme) at security level 100. Measured in this workspace:

| artifact | bytes |
|---|---:|
| Unified proof (branches, security 100) | 209,720 |
| P3 opening | 199,744 |
| P3 opening, 128 field elements | 52,712 |
| P3 opening, 512 field elements | 84,472 |
| P3 opening, 4,096 field elements | 158,752 |
| Reveal/open-free unified proof (reference only) | 9,976 |

The opening dominates. Point coalescing, one-point batched Mosaic opening, and
trace-table removal were already measured and gave ~2% or less.

Constraints for this note:

- target security >= 100 bits; do not lower it;
- multilinear point-evaluation over F2^128, not index opening;
- must eventually support the multi-table/multi-point claims used by
  `P3MosaicCommitment` and `UnifiedTraceProof`;
- hiding is desirable, but the current reference verifier is witness-checked.

## 2. Existing repo options and why they do not solve it

| option | what it is | why it fails |
|---|---|---|
| `P3BinaryPcs` / `BinaryPcs` | Plonky3 binary-field commit/fold/query PCS; real multilinear openings | works, but the hardcoded parameter schedule produces a ~200 KB opening at security 100 |
| `P3SharedPcs`, `P3MosaicOpening` | Mosaic stacking and multi-point batching over P3 | batching/stacking is not a smaller opening; measured overhead is neutral or worse for our table sizes |
| `LigeritoPcs` | binary-tower **index-opening** commitment | verifier gets values at indices, not an MLE at an arbitrary point; cannot replace a multilinear PCS |
| `RevealPcs` | hash commitment, opening reveals the whole vector | correct but non-succinct and non-hiding; useful only as a size baseline |
| `NaiveMerklePcs` | Merkle tree with full-vector opening | same non-succinct problem |
| `Bn254Kzg` | univariate KZG over BN254 Fr | prime-field univariate commitment, trusted setup, no field homomorphism from F2^128; not compatible with binary-field multilinear claims |
| M5 ring-switch `PackedBitPcs` | bit-table packing + DP24 ring switch | designed for bit-valued tables; general F2^128 multilinear vectors are not bit tables, so it is not a drop-in opening |
| Hash-chain recursion | chunk aggregation | not a PCS |

The only production-grade multilinear point-evaluation PCS in the repo is the
vendored Plonky3 `BinaryPcs`. That is why the first candidate is to tune it
rather than invent a new scheme.

## 3. Candidate A (recommended first): parameterized Plonky3 BinaryPcs

### Design

Keep the same commitment/proof family and the same `Pcs` trait, but stop
hardcoding the schedule. `P3BinaryPcs::backend` currently uses:

```rust
BinaryPcsParams {
    log_inv_rate: 2,
    pow_bits: 4,
    security_level,
}
```

and calls `BinaryPcsConfig::try_new` (folding factor 1). Plonky3 exposes:

```rust
BinaryPcsParams { log_inv_rate, pow_bits, security_level }
BinaryPcsConfig::try_new_with_folding::<F, EF>(num_variables, params, log_folding_factor)
```

Three knobs matter:

1. **`pow_bits`** — grinding budget. Total target stays `security_level`;
   increasing grinding from 4 to 16 reduces the query target from 96 to 84
   bits, hence fewer queries and a smaller proof. Cost: prover grinding
   `2^pow_bits` hashes.
2. **`log_inv_rate`** — code redundancy. Higher redundancy reduces the query
   count but makes each codeword and Merkle path longer. There is an optimum.
3. **`log_folding_factor`** — folds batched per commitment. Fewer intermediate
   commitments and query phases can reduce the `RoundProof` count in
   `BinaryPcsProof` substantially.

Candidate grid (security fixed at 100, no parameter below 100):

```text
log_inv_rate     in {2, 3, 4}
pow_bits         in {4, 8, 12, 16, 20}
log_folding      in {1, 2, 3, 4}  (<= num_variables)
security_level   = 100
```

For each point measure proof bytes, prover time, verifier time, and
`config.query_security_bits() >= security_level - pow_bits`. Also check the
total with hash-collision and sumcheck error accounting; the library's
`BinaryPcsConfig` enforces its priced model, not the entire system.

### Query-count estimate (analytic, no benchmark)

The unique-decoding query count is
`ceil((security_level + 1 - pow_bits) / -log2(1 - 2^-log_inv_rate))`.
For the relevant grid this gives approximately:

| log_inv_rate | pow_bits | queries |
|---:|---:|---:|
| 2 | 4 (current) | 144 |
| 2 | 8 | 138 |
| 2 | 16 | 126 |
| 2 | 20 | 120 |
| 3 | 16 | 103 |
| 4 | 16 | 94 |
| 4 | 20 | 89 |

So the query count can fall by ~35% (144 -> 94), but higher rate makes every
Merkle path longer and the base codeword larger. Batching folds (factor 2-4)
can remove intermediate `RoundProof` commitments and query phases; its effect
on coset width works the other way. Net proof-size gain is therefore uncertain;
a realistic guess is **15-35% plus a folding-factor gain**, not 10x.

### Proof-size estimate

Low confidence until benchmarked. The current proof is dominated by:
`RoundProof` commitments + opened cosets + multiproofs, plus base coset
openings and the final codeword. Tuning alone is unlikely to reach 10 KB;
a plausible target is 100-180 KB for the unified opening, i.e. 110-190 KB
total. This is the cheapest experiment and should be run before any new
cryptography.

### Security

- Hash: Keccak-256 in the vendored MMCS; 128-bit collision resistance.
- Algebraic/query security: 100 bits via rate, queries, grinding; increasing
  `pow_bits` does not lower the total target, it moves work to the prover.
- No trusted setup.
- Must absorb the chosen configuration/version into the transcript and proof
  statement; otherwise a verifier can be confused about the schedule.

### Integration obstacles

- `P3BinaryPcs::new(security_level)` hides params; add a `with_params`
  constructor and carry the config in the proof/verifier statement.
- `P3Commitment`/`P3Opening` types do not encode the config; `P3Proof` is the
  same generic type, so the verifier must be given the exact config.
- `P3MosaicCommitment` includes table shapes and a cap; changing only the
  opening schedule preserves the commitment type, which makes this the least
  invasive candidate.
- Existing claims (`LockstepClaims<P3MosaicCommitment>`, Shout/Router,
  gated claims) do not need type changes if the commitment type is unchanged.
- All tests and benchmarks must be rerun at 100 bits; the existing hardcoded
  4-bit grinding is not a security requirement.

### Recommendation

**Prototype this first.** It is implementable inside the current workspace
with no new cryptographic assumptions. If it reaches, say, <80 KB opening at
100-bit security, it may be sufficient for the reference and avoids a PCS
rewrite.

## 4. Candidate B: FRI/Basefold multilinear PCS over F2^128

### Design

Implement/adapt a FRI- or Basefold-style multilinear PCS over the binary tower:

1. Encode the evaluation vector with a binary-tower Reed-Solomon/NTT code
   (`p3-binary-dft` is already vendored).
2. Commit the codeword with a Merkle tree (Keccak-256).
3. Fold the codeword at Fiat-Shamir challenges derived from F2^128.
4. Query correlated cosets; verify Merkle multiproofs.
5. Bind the multilinear point through the usual tensor/eq weights, or use the
   p3 binary fold/sumcheck machinery directly.

Plonky3's `p3-binary-pcs` already contains a commit/fold/query pipeline with
`RoundProof`, `final_codeword`, `pow_witness`, and query cosets. A production
design could either:

- reuse the same pipeline with a different schedule (Candidate A), or
- fork/replace the opening protocol while keeping the MMCS and field.

A separate, purpose-built FRI over F2^128 is a fallback if the vendored
schedule cannot be tuned enough.

### Proof-size estimate

For `q` queries, `r` fold rounds, `w` coset width, and 32-byte digests:

```text
proof ~= r * (32 + w * 16 + multiproof)
       + q * (32 * log(codeword) + w * 16)
       + final_codeword
```

At rate 1/4-1/8 and 100-bit security, q is on the order of tens, so a
20-60 KB opening is plausible for our table sizes. This is an estimate, not a
benchmark.

### Security

- Proximity/query error from the FRI/Basefold regime; target 100 bits after
  grinding.
- Keccak collision 128 bits; F2^128 challenge field provides >100 bits per
  challenge.
- No trusted setup.
- Fiat-Shamir domain separation and query grinding must be specified exactly.

### Integration obstacles

- New commitment/opening types; `UnifiedTraceProof`, `ProofBundle`, claims and
  verifier all hardcode P3 types in many places.
- Multi-table/multi-point Mosaic claims need a batching adapter; a raw
  single-vector FRI proof is not enough.
- Verifier circuit for recursion would need the full FRI verifier.
- More code and more security review than Candidate A.

## 5. Candidate C: Merkle-committed row PCS with sumcheck (research)

### Design

A Spartan/Spark-style multilinear PCS:

- commit rows of the evaluation table in a Merkle tree;
- use a sumcheck to reduce the claimed point evaluation to a small number of
  row claims;
- open those rows with Merkle paths;
- batch all table/point claims with random linear coefficients.

The attraction is proof size `O(log n)` field elements/hashes plus the
sumcheck messages, potentially 5-25 KB for our sizes. The difficulty is that
the exact sumcheck/row-commitment construction and its soundness proof are not
in this repo; it is a research task, not a parameter change.

### Security

- Collision-resistant hash.
- Sumcheck soundness over F2^128; Fiat-Shamir.
- Must handle multi-point batching and successor columns.

### Integration obstacles

- New `Pcs` implementation and new commitment/proof types.
- No existing implementation to adapt; high risk of a subtly unsound
  construction.
- Recursion support would need the new verifier.

## 6. Comparison

| candidate | proof estimate | verifier work | research risk | integration |
|---|---:|---|---:|---|
| A: tuned BinaryPcs | 70-140 KB total (low confidence) | similar to P3 | low | low/medium |
| B: FRI/Basefold F2^128 | 20-60 KB opening | O(q log n) | medium/high | high |
| C: Merkle+sumcheck PCS | 5-25 KB | O(log n) hashes + sumcheck | high | high |

Only Candidate A is implementable with existing repo primitives and no new
cryptographic assumptions. B and C are research/engineering projects.

## 6.5 Hiding

None of the current repo PCS options is a hiding commitment:

- Merkle/Keccak leaves are deterministic; small-table commitments can leak
  information without masking;
- `RevealPcs` reveals the whole vector;
- the current P3 binary pipeline is used as a reference commitment, not a ZK
  commitment.

A production hiding PCS needs an explicit randomization/masking layer (for
example random codeword masks with a hiding bound, or a hiding Merkle variant),
and the security analysis must account for the masked opening. This adds proof
bytes and is orthogonal to the tuning question. Candidate A can be made hiding
only if the underlying Plonky3 configuration supports a masking mode. A quick
grep of the vendored `p3-binary-pcs` sources found no `hiding`/`mask`/`zk`
support, so it should be assumed absent until implemented.

## 7. Recommended first prototype

1. Add a **parameterized P3BinaryPcs constructor** in a branch/experiment,
   without changing the default proof format.
2. Benchmark the grid above at security 100 on:
   - single vectors of 128/512/4096 elements;
   - the unified 32-point/8-table claim shape;
   - the full gated trace.
3. Record proof bytes, prove/verify time, `num_queries`, and achieved
   `query_security_bits`.
4. Keep the best configuration only if:
   - total security is still >=100 bits including hash and sumcheck terms;
   - the config is bound into the transcript/statement;
   - all existing claims verify unchanged.
5. If the best is still >~100 KB, prototype Candidate B with the existing
   `p3-binary-dft`/MMCS primitives. Do not start Candidate C until B has a
   concrete proof-size measurement.

## 8. Honest caveats

- No benchmark for tuning or for B/C has been run in this task; the estimates
  above are analytical.
- The 9,976 B figure is the witness-checked reveal path, not a production
  succinct/hiding proof.
- The current verifier is witness-checked; a production PCS alone does not
  make the system zero-knowledge or witness-blind.
- A new PCS must also be reflected in the verifier circuit if recursion is a
  requirement.
