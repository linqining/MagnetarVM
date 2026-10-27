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

## Track 3 implemented (first slice)

The dynamic selected row now has a `pc_correction` bit and a raw-next/step
adder relation:

```text
raw_next = next_pc + 2 * pc_correction
```

Compressed sequential rows (ALU, memory, not-taken branch) set the bit; taken
branches and jumps do not. `mixed_alu_branch_rows_from_trace` keeps the
instruction length out of the component inputs; the prover/verifier derive the
correction from the trace row, and the claim layer exposes `instruction_len`.

`prove_unified_trace_auto` no longer falls back for compressed rows; the
compressed test now produces a dynamic proof with logup Shout.

Baseline replacement:

```text
old reference fallback: 117,730 B / 8.35 s prove / 96.4 ms verify
new dynamic native:     103,067 B / 96.8 ms prove / 49.4 ms verify
```

Compressed branch, `c.jalr`, and compressed load/store programs now also
produce dynamic native proofs and verify. The native prover keeps the
shift/store BinaryRouter proofs for traces that need them; only the old
`shout` proof is dropped in favor of logup Shout.

Full runtime suite after the change: 317 passed; clippy clean.

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


## Reprioritization evidence (round 103)

Native proof-size breakdown at 1024/4096 rows:

```text
access (Twist)   15,306 / 17,546 B
logup Shout     164,905 / 248,657 B
selected CPU    296,470 / 771,102 B
claim layer     110,666 / 442,442 B
```

BinaryTwist is now a small fraction of the native proof; the dominant costs are
the selected CPU proof and the O(rows) claim layer. Track 2 is still required
for paper semantics, but it is not the largest performance lever. The next
high-impact work is Track 1 (virtual claims / selected CPU proof), with Track 2
implemented before removing the claim compatibility path.


## Track 1 first slice: compact complete ClaimProof

`ClaimProof` now serializes a complete proof as:

```text
root + Vec<TraceClaim>
```

instead of one `TraceClaimOpening` per row (index, leaf, empty siblings).
The deserializer rebuilds leaves and indices, so `verify_complete_claims`
remains the same check. Non-complete proofs keep the old full form.

Native proof size:

| rows | before | after |
|---:|---:|---:|
| 1024 | 615,177 B | 566,028 B |
| 4096 | 1,587,513 B | 1,390,908 B |

Claim component:

| rows | before | after |
|---:|---:|---:|
| 1024 | 110,666 B | 61,517 B |
| 4096 | 442,442 B | 245,837 B |

Full runtime suite: 317 passing; clippy clean; claim-native guest still passes.


## Track 1 second slice: varint-compressed claims

For complete proofs the claim payload is now encoded with bincode varint
encoding into a single byte blob, rather than the fixed-int row vector:

```text
ClaimProof::Compact { root, blob }
```

Native proof size:

| rows | fixed claims | varint claims |
|---:|---:|---:|
| 1024 | 566,028 B | 529,657 B |
| 4096 | 1,390,908 B | 1,259,305 B |

Claim component:

| rows | fixed | varint |
|---:|---:|---:|
| 1024 | 61,517 B | 25,146 B |
| 4096 | 245,837 B | 114,234 B |

Full runtime suite: 317 passing; clippy clean; claim-native guest passes.


## Track 1 third slice: one segment per cycle

`segmented_dynamic_row` now emits one PCS segment per cycle covering the whole
row block:

```text
cycle{cycle}
```

The full segment router still binds every bit (including pc/next_pc) to the
trace-derived witness; the dedicated `verify_dynamic_pc_segments` helper is no
longer applicable to this layout.

Native proof:

| rows | before | one segment |
|---:|---:|---:|
| 1024 | 529,657 B | 397,625 B |
| 4096 | 1,259,305 B | 736,041 B |

Selected CPU component:

| rows | before | after |
|---:|---:|---:|
| 1024 | 296,470 B | 164,438 B |
| 4096 | 771,102 B | 247,838 B |

Full runtime suite: 317 passing; clippy clean.


## Track 1 fourth slice: compact selected variable mapping

The selected row mapping no longer power-of-two aligns every component/block.
All relation variables are packed sequentially, then one segment per cycle
covers the next power-of-two block. This shrinks the committed selected witness.

Native proof:

| rows | before | compact mapping |
|---:|---:|---:|
| 1024 | 397,625 B | 381,001 B |
| 4096 | 736,041 B | 720,153 B |

Selected component:

| rows | before | after |
|---:|---:|---:|
| 1024 | 164,438 B | 147,814 B |
| 4096 | 247,838 B | 231,950 B |

Full runtime suite: 317 passing; clippy clean.
