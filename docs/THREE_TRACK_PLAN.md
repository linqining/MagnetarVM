# Authorized Three-Track Plan

User authorized all three tracks: (1) BinarySpartan/virtual claims, (2) linear
BinaryTwist, (3) compressed-PC selected CPU. This document fixes the order,
touchpoints, and acceptance tests so the work can proceed without re-scoping.

## Track 3: compressed-PC selected CPU (first)

Why first: it unblocks mixed/compressed native proofs, and it is localized to
the selected dynamic row.

Touchpoints:

- `crates/magnetar-runtime/src/simd_dual.rs`
  - `MixedAluBranchInput` carries instruction length (`len2`).
  - `DynamicMixedRow` and every `*PcRow` component use a variable PC step.
- `crates/magnetar-runtime/src/branch_row.rs`
  - `GatedBranchRow` sequential adder must use the row length, not constant 4.
- `crates/magnetar-runtime/src/simd_full.rs`
  - `gated_rows_from_trace_full` carries `row.instruction_len`.
- `crates/magnetar-runtime/src/lib.rs`
  - remove the compressed fallback from `prove_unified_trace_auto` once the
    dynamic path passes compressed tests.

Acceptance:

```text
c.li/c.addi/c.ebreak compressed program
prove_unified_trace_auto -> dynamic proof
verify_unified_trace -> ok
mixed 16/32-bit program -> ok
full runtime suite stays green
```

## Track 2: linear BinaryTwist via logup*

Why second: BinaryShout is already logup*; Twist is the remaining quadratic
memory-checking part.

Design target, following "Twist and Shout via logup*":

```text
commit ra_dense, wa_dense, Inc_val
read check + write check via logup* one-hot commitments
value-history / final-value sum-checks
```

Touchpoints:

- new `crates/magnetar-runtime/src/logup_twist.rs`
- `BinaryTwistWitness` in `magnetar-memory`
- native `TraceAccessProof` replacement after standalone proof passes
- keep old Twist until the new proof is verified on 15 workloads

Acceptance:

```text
standalone Twist round-trip on registers and RAM
tamper read/write value -> reject
native word-mode proof uses logup Twist
proof size / prove / verify improve over old Twist
```

## Track 1: BinarySpartan / virtual claims (last)

Why last: it removes the O(rows) claim layer, but it depends on both Shout and
Twist being sound and virtual.

Milestones:

1. Virtual claim root replaces row-claim root in `Statement`.
2. verifier consumes virtual claims plus selected CPU proof without
   `claims_to_trace`.
3. Remove full `ClaimProof` from the dynamic native proof.
4. Keep old path behind compatibility until all workloads pass.
5. Re-run 2^16 benchmark.

Acceptance:

```text
hello + 15 workloads
word/mixed traces
proof size no longer O(rows)
2^16 native benchmark with report
```

## Ordering

```text
Track 3 -> Track 2 -> Track 1
```

Track 3 is the smallest and gives mixed coverage. Track 2 removes the remaining
quadratic memory proof. Track 1 removes the claim layer, which is only safe
after Shout and Twist are both virtual.

## Current baseline

See `docs/P1_LINEAR_SHOUT.md`, `docs/P2_PROOF_ONLY_VERIFIER.md`, and
`docs/VIRTUAL_CLAIM_REWRITE.md`. Current runtime suite: 316 passing.

## Track 3 baseline

`logup_shout_mixed` on the tiny compressed + 32-bit program:

```text
standalone logup Shout: ok
native auto fallback proof: 117,730 B
native auto fallback prove: 8.35 s
native auto fallback verify: 96.4 ms
```

The fallback is many times slower than the dynamic word path for such a tiny
trace, which is the concrete reason to finish compressed-PC support.
