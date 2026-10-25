# Protocol proof determinism

## Symptom

`protocol_plan_and_orchestrator_preserve_proof_bytes` occasionally failed only
under the parallel test runner: two independently generated proofs for the same
trace had different bytes. The failing field was `UnifiedTraceProof::table_batches`.

## Root cause

The prover collected the tables selected for table-batched openings into a
`HashSet<usize>` and then iterated that set:

```rust
for index in selected {
    ...
    self.table_batches.push(...);
}
```

`HashSet` iteration order is not part of the proof semantics. The batch openings
themselves are deterministic, but their order in `table_batches` changed with the
set's hash seed. Under a single-threaded run the two provers usually shared a
seed; under the parallel test runner they could differ.

## Fix

The selected table indices are now sorted before iteration:

```text
HashSet only for membership
Vec + sort_unstable for proof-producing order
```

This makes `table_batches` order deterministic without changing the verifier.

## Reproducer

`crates/magnetar-testkit/examples/protocol_determinism.rs` generates direct and
Orchestrator proofs concurrently, compares serialized bytes, and on mismatch
reports which `UnifiedTraceProof` field differs.

## Verification

Before the fix, the concurrent reproducer reported `table_batches` mismatches on
every parallel run. After the fix:

```text
runs=120 failures=0
```

Full runtime suite, twice in a row:

```text
309 passed / 0 failed
309 passed / 0 failed
```
