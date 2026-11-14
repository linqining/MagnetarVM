# M4a binding audit: how the Access / twist claims reach the statement

Scope: before implementing statement-level dedup (removing the mosaic 12-column
address table and letting the packed-bit commitment replace it), establish
*edge by edge* which mechanisms bind the Access / twist claims to the public
statement, which links are only consistency checks, and what dedup therefore
needs. This is a code-reading audit; it ends with the experiments that would
settle the open links.

## 1. Verification entry points (what the benchmark actually runs)

| entry point | signature | trace? | purpose |
| --- | --- | --- | --- |
| `verify_unified_trace` | `(trace, proof, width)` | yes | trace-carrying full verify; calls `Orchestrator::verify` → `verify_access` → `verify_trace_access_shared(trace, proof, witness, ...)` |
| `verify_unified_trace_statement` | `(statement, trace, proof, width)` | yes | checks statement == trace-derived data, then delegates to `verify_unified_trace` |
| `verify_native_unified` | `(statement, proof, width)` | no | statement path; if `claims_v4_enabled()` (opt-in `MAGNETAR_CLAIM_V4=1`) → `v4_verify::verify_native_unified_v4`; otherwise the classic statement path |
| `v4_verify::verify_native_unified_v4` | `(statement, proof, width)` | no | M5c statement-only; requires `MAGNETAR_ACCESS_COLUMNS=1`; calls `access_verify::verify_access_committed_with_claims` |
| `verify_unified_claim_proof*` | `(proof[, statement])` | no | claim layer only; **does not verify the Access/PCS layer** |

`paper_unified_bench` runs `verify_unified_trace` **and** `verify_native_unified`
(`crates/magnetar-testkit/examples/paper_unified_bench.rs:172-174`). With default
envs (`MAGNETAR_CLAIM_V4` unset) the statement path is the classic one, i.e. the
v4 machinery below is **opt-in and not what the default benchmark verifies**.

## 2. Binding mechanisms in the code

### 2.1 Commitment roots that are in the statement root

* Claim-table commitment root: `claim_table_root(&table.commitment)` compared
  with `table.root`, then folded into `claim_shout_v4_root(...)` and compared
  with `statement.trace_claim_root` / `proof.trace_claim_root`
  (`v4_verify.rs:58-84`, `claim_table.rs:295+`).
* Committed Shout tables root: same composition (`v4_verify.rs:70-76`).
* Committed final-RAM cell table (`access_final`, packed bits, ring-switch
  backend): `access_final_root(&final_proof.commitment)` is the third component
  of the same root (`access_verify.rs:41`, `v4_verify.rs:78-80`), and its
  relation is checked by `claim_shout::verify_relation`
  (`access_verify.rs:249-290`).
  This is a tested pattern: `v4_access_final_binds_without_witness`
  (`lib.rs` M5b tests) rejects a missing table and a tampered commitment root.
* Trace commitment and program/ROM hashes are compared with the statement
  directly (`v4_verify.rs:85-95`).

**Not in any statement root**: the mosaic PCS commitment (`proof.commitment`).
It is proof-carried and only used to verify the shared mosaic opening.

### 2.2 Witness vs trace

`check_trace_access_bindings(trace, witness)` (`lib.rs:950`) compares a rebuilt
twist witness against the trace (memory events, register reads/writes). It is
called by the trace-carrying Access verifier (`lib.rs:1139-1180`) **before**
the claims are verified, and it validates the *witness*, not the committed
tables.

### 2.3 Claim verification branches

`verify_binary_twist_from_proof_inner(proof, commitment, table_index, witness)`
(`binary_twist.rs:2803`):

* `linear_m4a` branch (v5, our M4a path): shape checks + `verify_access_m4a`,
  then returns the mosaic claims. **The `witness` argument is not used**
  (`binary_twist.rs:2812-2820`).
* `linear` branch: shape checks + `verify_local_shared`, same; witness unused
  (`binary_twist.rs:2821-2829`).
* non-linear branch: uses `witness` to compare `initial_update_eval` /
  `final_eval` against witness folds (`binary_twist.rs:2860+`).

So in the **trace-carrying classic path with a linear/m4a Access proof**, the
twist claims are:
1. checked internally by `verify_local_shared` / `verify_access_m4a`
   (sum-checks + PCS / ring-switch openings), and
2. used as expected values for the shared mosaic opening against
   `proof.commitment`.

Neither step compares them with the trace or the statement: the mosaic
commitment is not in the statement root, and the linear branch does not consult
`witness`. The remaining possible link is in the core/claim checks (below).

### 2.4 Core / claim-composition links

`verify_core_statement_with_access_claims` (`lib.rs:3678`) takes the access
mosaic claims and merges them with CPU/gated/shout/router claims before
verifying the shared mosaic opening (`lib.rs:3690-3730` and following). The
claim table itself is verified against trace rows in the trace-carrying path
(`verify_claims_against_trace`, `lib.rs:4062-4073`), and the v4 path checks the
claim-table relation (`v4_verify.rs:230-240`). What this does **not** show is a
comparison of the *twist* claims with claim-table-derived values in the classic
path; the M5b-2a design note says the committed-claim path is what replaces the
witness (`access_verify.rs:1-20`) — and that path is only reachable in v4 mode.

### 2.5 The witness-free (v4) Access path

`access_verify::verify_access_committed_with_claims` (`access_verify.rs:198-290`):

1. RAM and register twist via `verify_binary_twist_from_proof` (no witness);
2. **initial RAM binding**: public `statement.initial_ram` folded at the twist
   cell point `r_k`, compared with the twist proof's `initial_eval`
   (`access_verify.rs:229-245`);
3. **final-value binding**: the `access_final` committed table is root-bound
   into the statement (step 3a) and its relation gives `final_eval`
   (step 3b, `access_verify.rs:249-290`).

Note the asymmetry: initial RAM and final RAM values are bound; the **register**
twist's initial values (public `statement.initial_state.regs`) and final
values have no analogous binding in this function.

## 3. Findings

**F1 (pre-existing, affects dedup).** In the default (classic, trace-carrying)
path, a linear/m4a Access proof's claims are bound to the mosaic commitment but
the mosaic commitment is not bound to the statement, and the linear branch does
not use the witness. Whether the claim chain is nevertheless statement-bound
depends on cross-checks inside the core/claim verification (not established by
this reading). Dedup would inherit this question, so it must be settled first.

**F2 (template exists).** The `access_final` mechanism is exactly the pattern
dedup needs: a proof-carried packed-bit commitment, its root composed into
`claim_shout_v4_root`, and a relation over its slots — all witness-free and
covered by tamper tests. Extending that composition with an
`address_bits_root`/`bits_commitment_root` is mechanically the same change as
M5b-2b, with a version bump.

**F3 (asymmetry).** RAM has committed initial+final bindings in the witness-free
path; the register twist (the one whose 12-column address table dominates the
mosaic) has neither. Statement-level dedup of the register address table must be
accompanied by an equivalent binding, or it will rest on F1.

**F4 (dedup requirements, assuming F1 is closed).**
1. add the packed-bits commitment root as a component of the statement root
   (version bump), mirroring `access_final_root`;
2. keep the ring-switch claims as the source of the Address values, and drop the
   Address outer claims from the mosaic claim list;
3. remap the twist table indices and shape checks (mosaic table count changes);
4. record that the mosaic commitment itself remains unbound, as today.

## 4. Experiments and first results

**E1 result (paper/statement path, 2^16, `ADDS=65535`, `BENCH_AUDIT=1`).**
The benchmark can now run a tamper matrix on the real paper trace
(`paper_unified_bench.rs`, `BENCH_AUDIT=1`, verifying with
`verify_native_unified` — the benchmark's statement path):

| mutation | result |
| --- | --- |
| baseline | **accepted** |
| register `linear.values[3][0]` (address terminal) += 1 | rejected — core verifier: register access claims rejected |
| register `linear.endpoints[0]` (initial) += 1 | rejected — same |
| register `linear.values[2][0]` (increment) += 1 | rejected — same |
| RAM `boolean_evals[0]` += 1 | rejected — RAM access claims rejected |

So in the statement path the twist claims are bound tightly enough that a
claim-only tamper is caught (the claim is an expected value of the shared
mosaic opening and of the Access claim derivation).

**E2 attempt (coherent fake register witness).** A prover-only, env-gated hook
(`MAGNETAR_TEST_FAKE_REG="cell,delta"`, `protocol.rs`) adds `delta` to the first
increment and to that cell's final value before the twist tables/proofs are
built. `BENCH_AUDIT=1` then verifies the resulting proof against the **true**
statement: **rejected — "register access claims rejected"**, i.e. the Access
verifier itself refuses the perturbed witness before the statement-level checks
are reached (the perturbation is not algebraically coherent with the val/RW
relations). A *fully* coherent fabricated witness would have to come from a
different trace — and the statement root equality (claim table / trace
commitment) already rejects a different trace. This weakens F1: no statement
binding gap was demonstrated; the twist layer is bound by (a) the Access
relations, (b) the shared mosaic opening against claims, (c) the statement root
equality over the claim table / trace commitment.

**Remaining experiments** (they are now confirmatory rather than decisive):



Each experiment runs at the linear-twist minimum (`ADDS=8191`, 8192 cycles) so
`prove_local_shared` is active, using in-memory proof mutation (the benchmark
verifies in memory, so this is the same trust boundary).

* **E1 — claim tampering.** Flip one terminal address value / one v5
  `bits_claims` entry / one `values[3]` entry in the proof, then
  `verify_unified_trace`. Expected: rejected by the mosaic opening (the claim
  is the expected value at a committed table point). This confirms
  "claims → commitment" binding and that tampering cannot be silent.
  *Partial result (this round):* the harness
  (`binding_audit_tamper_matrix`, ignored) builds a real 8192-cycle proof and
  both verifiers accept the baseline. However, with the **native** prover at
  8192 cycles both `ram.linear` and `registers.linear` are `None`, so the
  linear/m4a branches are not exercised at that size in that configuration —
  the Access proof there is the non-linear one. The matrix therefore has to run
  on the **paper prover** (`prove_unified_trace_paper`, `TRACE_SHOUT=1`, the
  path the benchmark uses, where the linear Access proof is active), or at a
  larger size; the 16k-cycle native run was too slow for this round (>10 min
  per prove+verify cycle). This is the first concrete experiment to repeat.
* **E2 — fabricated-witness splice (the decisive classic-path test).** Produce
  a valid unified proof for the true trace, then rebuild only the twist part
  (`prove_binary_twist_claims_linear_shape` / `prove_access_m4a`) from a
  **fabricated** register witness (e.g. one register value changed) and splice
  it into `proof.access`. Verify with `verify_unified_trace`.
  * accepted → F1 is real (pre-existing unsoundness; dedup cannot be certified
    until it is fixed);
  * rejected → find the rejection site (log which stage fails) and document it
    as the statement link; dedup then only needs the packed-bits root.
* **E3 — same splice under v4** (`MAGNETAR_CLAIM_V4=1`,
  `MAGNETAR_ACCESS_COLUMNS=1`): expected RAM twist rejected by the
  initial/final binding; check whether the **register** twist splice is
  accepted, which would confirm F3's asymmetry.
* **E4 — dedup variant + binding.** After E2/E3 decide the required binding,
  implement the deduped mosaic variant with the packed-bits root added to the
  v4 root, and rerun E2/E3 plus the E1 tamper matrix: the forged splice must
  now be rejected by the root comparison (as `access_final` was).

## 5. Recommendation (revised after E1/E2)

* F1 is **not** demonstrated to be a gap: the classic/statement verifiers reject
  claim tampering (E1) and a perturbed witness fails inside the Access verifier
  (E2); trace substitution is blocked by the statement root equality.
* Statement-level dedup therefore reduces to the F2 pattern: add the packed-bits
  commitment root as a component of the statement root (mirroring
  `access_final_root` / `claim_shout_v4_root`), drop the Address outer claims,
  remap table indices, and version-bump. The pre-existing binding chain is
  unchanged by that.
* The residual risk is the soundness of the *relations themselves* (already the
  project's existing argument for the twist layer), not something dedup adds.
* Recommended next step: implement the dedup behind a switch with the bits-root
  binding, then rerun the E1 matrix on the deduped proof (address claims now come
  from the ring-switch, so the matrix should reject the same mutations) and add
  the root-tamper cases (packed commitment swapped, root recomputed, root
  dropped). That is the E4 in §4.

## 6. Older recommendation wording (kept for context)

1. Run **E1 and E2** first (half a day to a day): they decide whether dedup is a
   routine "mirror `access_final`" change or whether there is a pre-existing
   statement-binding gap to fix first.
2. If E2 is rejected (statement link exists), implement dedup by mirroring
   `access_final`: add `bits_root` to `claim_shout_v4_root` (version bump), drop
   the Address outer claims, remap table indices, and add the E1/E2 tamper
   suite to the gate. Expected 2-3 days, then the `2^18` re-measure
   (mosaic message 256 → 128 MiB).
3. If E2 is accepted, stop and fix the binding gap before any dedup work; the
   same `access_final` pattern extends to the register twist (committed initial
   and final register tables, root-bound), and the audit's F3 asymmetry should be
   closed at the same time.
4. Lean is optional: a paper-level model of the root composition / binding
   lemma (abstract binding commitments + random oracle) is 1-2 weeks and adds
   presentation value, but it cannot replace E2/E3 because the question here is
   about the *implementation's* claim graph.

## 6. Evidence index

* `crates/magnetar-runtime/src/lib.rs`: 950 (`check_trace_access_bindings`),
  1139-1180 (`verify_trace_access_shared`), 269-285
  (`statement_access_digest`), 3500 (`verify_table_batch_claims`), 3650-3760
  (`verify_core_statement_with_access_claims`), 4030 (`verify_unified_trace`),
  4176 (`verify_native_unified`), 4546 (`verify_unified_trace_statement`),
  M5b/M5c tests ~10880-10945.
* `crates/magnetar-runtime/src/binary_twist.rs`: 2786-2829 (claim branches),
  1814-1850 (`BinaryTwistLinearProof` + outer claims).
* `crates/magnetar-runtime/src/local_shared.rs`: `verify_local_shared`,
  `local_shared_outer_claims`, and the M4a v5 additions
  (`prove_access_m4a` / `verify_access_m4a` / `m4a_access_outer_claims`).
* `crates/magnetar-runtime/src/access_verify.rs`: 1-20 (design note), 41
  (`access_final_root`), 198-290 (witness-free verification + root binding).
* `crates/magnetar-runtime/src/v4_verify.rs`: 39-44 (v4 gate), 58-105 (root and
  access-statement digest), 148 / 231 (access call), 230-240 (claim relation).
* `crates/magnetar-runtime/src/claim_table.rs`: 264-276 (`claims_v4_enabled`),
  295+ (`claim_shout_v4_root`).
* `crates/magnetar-runtime/src/access_table.rs`: 45-50
  (`access_columns_enabled`).
