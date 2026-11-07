# M4b paper-path default flip (HANDOFF §5 item 2)

Status: **Phase A code complete; gate + tamper matrix results pending** (see §5/§6).
Owner: `m4b-flip` teammate. Branch `virtual-claims-rewrite`.
Related design/decision records (not edited here, the Lead consolidates):
`docs/POLYLOG_CLAIM_VERIFIER.md` §C.10 (M4b design), §C.13 (flip conditions),
§C.13.1 (quiet-host 2^16 A/B), §C.14 (M5 complete, v4 requires committed);
`docs/HANDOFF.md` §2.1, §4 items 15-19, §5 item 2, §6.

## 1. What flips

The paper path (`prove_unified_trace_paper`, no `TRACE_SHOUT`) now **defaults to
the committed-pushforward linear Shout (M4b)**:

| paper wire | default (after) | `MAGNETAR_CLASSIC_LOGUP=1` (before) |
| --- | --- | --- |
| `committed_logup_shout` | **present** | absent |
| `logup_shout` (classic 25-column mosaic opening) | absent | **present** |
| `shout` / `packed_shout` | absent | absent (vestigial: the unified dynamic prover hard-codes `shout_table = None`, so the classic paper wire is the `logup_shout` proof alone; verified empirically at 2^8, see §6) |
| statement root | v3 `H("claim-shout-v3" ‖ claim_binding_v1 ‖ Shout tables root)` | v1 claim binding |
| Shout check | full committed-Shout check (logup* reduction + one batched opening + O(rom) word check + statement-root binding) | classic stage proofs + the classic opening claims (the logup identity itself was **never checked** -- M4b closes that gap) |

The **native trace path is unchanged**: `prove_unified_trace_dynamic_native` /
`MAGNETAR_PROFILE_*` still selects M4v3 only under `MAGNETAR_LINEAR_SHOUT=1`
(measured trade: +151 KB proof for -36 % verify CPU, §C.13.1 -- still opt-in).

### Switches

| env | paper path | native trace path |
| --- | --- | --- |
| *(unset)* | M4b committed linear Shout | classic (trace Logup-Shout witness rebuild) |
| `MAGNETAR_LINEAR_SHOUT=1` | M4b (now redundant, byte-identical to the default) | M4v3 committed linear Shout (unchanged) |
| `MAGNETAR_CLASSIC_LOGUP=1` | classic wire (pre-flip bytes) | classic (forces the legacy path, unchanged) |
| `MAGNETAR_CLAIM_V4=1` | classic wire unless `MAGNETAR_LINEAR_SHOUT=1` (v4 gate unchanged) | v4 prover unchanged |

M5/M6 measured env `MAGNETAR_CLAIM_V4=1 MAGNETAR_ACCESS_COLUMNS=1
MAGNETAR_LINEAR_SHOUT=1` is **not affected** by the flip: v4 keeps its explicit
three-env gate because `claim_table::statement_claim_root_v4` derives the shout
component of the v4 root from `MAGNETAR_LINEAR_SHOUT`; flipping the paper
default inside v4 would desynchronise prover and host statement roots.

## 2. Code changes

All in `crates/magnetar-runtime/src/lib.rs` unless noted:

- `paper_committed_logup_enabled()`:
  `!MAGNETAR_CLASSIC_LOGUP && (MAGNETAR_LINEAR_SHOUT || !claims_v4_enabled())`.
  This is the paper prover's path decision: `MAGNETAR_LINEAR_SHOUT` is no longer
  required on the non-v4 path, but it is still honoured (and still required to
  get the committed Shout) inside the explicit M5 v4 mode, so the M5/M6 measured
  config keeps its behaviour.
- `prove_unified_trace_paper`: uses the new flag; classic `logup_shout` and the
  folded ROM claim are built only on the classic leg.
- `prove_unified_trace_dynamic_native_profile_inner` gained an explicit
  `linear_shout: bool` argument instead of re-reading the env, so the shared
  prover can carry two different defaults (paper: on, native: opt-in).
- `paper_statement_claim_root(trace, width)`: new public statement builder for
  paper proofs. `claim_table::statement_claim_root` is **not** changed (73
  native call sites and the native v1 root depend on it); the paper helper
  composes the v3 root from `logup_shout::committed_statement_data(trace)` and
  delegates for classic / v4 / claim-table-off / unrepresentable-trace
  fallbacks, mirroring the prover.
- `verify_unified_with_plan_impl` (**trace-carrying** verifier only): when
  `proof.committed_logup_shout` is present, the committed tables root is
  compared with the host-derived tables root of the trace given to the verifier
  ("committed logup Shout tables do not match the trace"). Before this, the
  table binding existed only through the v3 statement root, so a
  committed-Shout proof verified with the trace could carry a forged `T_pos` /
  pushforward table (pre-existing gap for the M4v3 opt-in too). No O(trace)
  work was added to `verify_native_unified` or any statement-only path.
- `verify_unified_trace_statement`: expected statement/proof roots are wrapped
  with the proof's committed tables root (v3) when present.
- Paper statement builders updated: `crates/magnetar-testkit/examples/paper_unified_bench.rs`,
  `crates/magnetar-testkit/tests/paper_mode.rs` (dual-mode wire assertions),
  `crates/magnetar-runtime/src/lib.rs` tests, plus a paper-mode test in
  `crates/magnetar-runtime/src/virtual_claims.rs` that needed a real-size trace.
- Tiny-trace note: the committed Shout PCS uses folding factor 3, so a trace
  needs `max(cycle_bits, address_bits) >= 3` (>= 8 rows). Two paper-prover tests
  with 2-instruction traces were enlarged to the 200-instruction reference
  program used by the other paper tests.

## 3. Verified behaviour (tests)

Runtime unit tests (`m4b_paper_tests`):

- `paper_default_wire_matches_the_switch` (default gate): the paper proof
  carries `committed_logup_shout` and no classic fields, the prover's
  `trace_claim_root` equals `paper_statement_claim_root`, and the proof
  round-trips through `verify_native_unified`.
- `committed_and_classic_fields_coexist_rejected` (dual-mode, default gate):
  mixing the two encodings in either direction is rejected.
- `core_verifier_rejects_committed_shout_without_statement`: the proof-only core
  verifier still rejects committed Shout (it has no public ROM).
- `paper_committed_shout_round_trips` (`#[ignore]`, run with
  `--ignored --test-threads=1`): default vs `MAGNETAR_LINEAR_SHOUT=1`
  byte-equality (the flip makes the old opt-in redundant), same-binary
  `MAGNETAR_CLASSIC_LOGUP=1` determinism + classic wire shape, proof-size /
  opening / table-batch A/B, statement ROM tamper, stripped-proof rejection.
- `paper_committed_shout_tamper_matrix` (`#[ignore]`): see §4.

Testkit: `crates/magnetar-testkit/tests/paper_mode.rs` is dual-mode (the
workspace gate is run once with the default env and once with
`MAGNETAR_CLASSIC_LOGUP=1`, so each leg pins its own wire).

## 4. Tamper matrix (committed linear Shout, M4b default)

All through the top-level verifiers (`verify_native_unified` for the statement
path, `verify_unified_trace` for the trace path); every case must return `Err`.
No current prover emits a committed proof that the trace-carrying verifier can
parse: paper proofs carry the register-derived claim blob (no `claims.verify()`
form) and the native dynamic path drops the classic Shout fields, which trips
`UnifiedVerifyContext`'s Shout-presence check (both pre-existing). The
trace-path cases therefore exercise the verifier branch directly by attaching a
committed proof to the eager unified proof (whose packed-Shout claim satisfies
the presence check) and swapping its tables.

| # | tamper | verifier | expected |
| --- | --- | --- | --- |
| 1 | whole committed proof swapped for one built on a different ROM (word/pos/pushforward tables swap) | statement | reject |
| 1b | whole committed proof swapped (eager proof + attached committed proof) | trace path | reject "committed logup Shout tables do not match the trace" |
| 2 | `table_commitment` only (opening keeps the old commitment) | statement | reject |
| 2b | table_commitment only (eager proof + attached committed proof) | trace path | reject "committed logup Shout tables do not match the trace" |
| 3 | opening `commitment` swapped | statement | reject |
| 4 | `reader_claim + 1` | statement | reject |
| 5 | `reader_point[0] + 1` | statement | reject |
| 6 | `reduction_evals[0] + 1` (pushforward at fraction-reduction points) | statement | reject |
| 7 | `product_evals[0] + 1` (pushforward at product-sumcheck points) | statement | reject |
| 8 | logup* product sumcheck `claimed_sum + 1` | statement | reject |
| 9 | claim-table commitment root bit flip | statement | reject |
| 10 | statement `trace_claim_root` bit flip | statement | reject |
| 11 | statement ROM word flip | statement | reject |
| 12 | committed node stripped from the paper proof | statement | reject (v3 root mismatch) |
| 13 | classic `logup_shout` injected next to the committed proof | statement | reject "committed and classic Shout proofs coexist" |
| 14 | trace-path baseline: eager proof + matching attached committed proof | trace path | accept (proves the binding is not a blanket rejection) |

Results: **all 14 cases pass as specified** -- the matrix lives in the ignored
test `m4b_paper_tests::paper_committed_shout_tamper_matrix`, and
`cargo test --release -p magnetar-runtime --lib -- --ignored --test-threads=1`
reports **5 passed / 0 failed / 0 ignored** (231 s) on the frozen tree; every
reject case returns `Err` and case 14 accepts, so the host binding rejects the
swapped/forged committed tables while the internally valid baseline round-trips.

## 5. Gates (run 2026-11-07, host load 60-90 during the first pass)

| command | result |
| --- | --- |
| `cargo test --workspace --release` (default env) | **39 test binaries, 674 passed / 0 failed / 5 ignored**, exit 0, wall 1098 s (includes full workspace compile from the current tree) |
| `MAGNETAR_CLASSIC_LOGUP=1 cargo test --workspace --release` | **674 passed / 0 failed / 5 ignored**, exit 0, wall 395 s (no recompile) |
| `cargo build --workspace --examples --release` | exit 0 (all examples already built by the gate build; `m6_verify_ab` and `paper_unified_bench` present) |
| `cargo test --release -p magnetar-runtime --lib -- --ignored --test-threads=1` | **5 passed / 0 failed / 0 ignored**, wall 231 s (the two M4b opt-in tests plus the three v4/M5b opt-in tests) |
| `cargo test --release -p magnetar-runtime --lib v4_ -- --include-ignored --test-threads=1` | **5 passed / 0 failed / 0 ignored**, wall 2.6 s |
| `target/release/examples/protocol_determinism` | `runs=20 identical=20 failures=0 peak_rss=1.95 GiB`, exit 0, wall 33.5 s |
| filtered `--lib m4b_paper`, default env / `MAGNETAR_CLASSIC_LOGUP=1` | 3 passed / 0 failed / 2 ignored on each leg (the two legs pin the two wire encodings) |

The default-env gate was re-run twice on the frozen tree: once after the last
test-only edits (251 s) and once after the Lead's behaviour-neutral
`magnetar-proof/spartan.rs` cleanup (which the run rebuilt): both
**674 passed / 0 failed / 5 ignored**, exit 0, wall 391.8 s. The counts above
are those runs' (identical to the first full run).

## 6. 2^16 paper A/B

Reference numbers from `docs/POLYLOG_CLAIM_VERIFIER.md` §C.13.1 (quiet host,
tree `c2abdf4`, `MAGNETAR_VERIFY_CPU=30`):

| 2^16 paper | proof | verify wall | verify CPU/iter | peak RSS/footprint |
| --- | --- | --- | --- | --- |
| classic (pre-flip default) | 1,199,746 B | 35.1 ms | 75.3 ms | 2.96 GiB |
| M4b committed | 1,169,602 B | **26.2 ms** | 78.7 ms | **2.21 GiB** |

Re-measurement of the 2^16 row was **not repeated after the flip** (the Lead
allocated no heavy-run slot; the flip is byte-identical to the already-measured
`MAGNETAR_LINEAR_SHOUT=1` paper path by the ignored round-trip test, which
asserts default vs `MAGNETAR_LINEAR_SHOUT=1` bit-equality, and §C.13.1 measured
that path). The classic code path itself is unchanged (only the default branch
selection moved) and same-binary classic re-proving is byte-identical.

Wire-size sanity probe at `ADDS=255` (2^8, `paper_unified_bench`, same binary):
classic proof **477,445 B** with `logup_shout` 91,073 B and
`committed_logup_shout` absent; M4b default proof **454,437 B** with
`committed_logup_shout` 69,969 B and `logup_shout` absent. Proof shrinks by
23,008 B at this size, consistent with the 2^14/2^16 deltas in §C.10.1/§C.13.1.

## 7. Open risks / notes

- **v4 is not flipped.** The v4 verifier still requires the committed linear
  Shout and the explicit three-env opt-in: under v4 the paper prover keeps
  honouring `MAGNETAR_LINEAR_SHOUT` and produces classic fields when it is unset,
  so the existing v4 statement-root derivation in `claim_table` is untouched.
  Flipping it would need the v4 shout-component switch to move out of
  `claim_table::statement_claim_root_v4` first.
- **`MAGNETAR_LINEAR_SHOUT=1` is now redundant on the paper path** but still
  meaningful on the native path and for v4; the strict "enabled but missing"
  rejection in the verifiers therefore remains keyed on that explicit env (an
  explicit opt-in that receives a classic proof is rejected, otherwise both wire
  encodings are accepted).
- **Statement builders must be path-aware.** Paper statements must use
  `paper_statement_claim_root`; `claim_table::statement_claim_root` keeps the
  native/legacy (v1) meaning. A paper proof verified against a v1 statement is
  rejected by the root check (fail-closed).
- **Pre-existing, not introduced here:** `verify_unified_trace` cannot verify
  paper proofs (the register-derived claim blob has no `claims.verify()` form),
  and it cannot verify native M4v3 proofs either: the dynamic prover emits no
  classic `shout`/`packed_shout` for them, so `UnifiedVerifyContext`'s
  "BinaryShout proof presence does not match the trace" check fires once
  `trace_logup_shout` is replaced by the committed proof. Native M4v3 is
  therefore verified statement-only (`verify_native_unified`, the bench/M6
  shape), which accepts it: it carries no classic Shout fields, so the
  committed/classic coexistence check does not fire. The Q2 trace-path binding
  is defence-in-depth for a future combined proof shape; its tamper test uses
  the eager-proof construction above. All unchanged by the flip.
- **Classic paper wire was never sound.** The classic paper verifier folded the
  `logup_shout` link claims into the mosaic opening but never checked the logup
  identity ("Shout carried but not verified"); the M4b default closes that gap.
