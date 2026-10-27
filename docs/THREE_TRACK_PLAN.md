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


## Negative result: link-column packing

Packing the 8-bit shift code into one field element (12 link columns -> 5)
reduced the batch PCS opening by less than 1 KB at 4096 rows; the P3 opening is
dominated by witness/security parameters rather than column count. The change
was reverted. Reducing the logup opening needs shared/aggregated PCS opening,
not fewer columns.


## Track 1 fifth slice: grouped selected segments

The selected layout groups 8 cycles into one PCS segment instead of one segment
per cycle. The full segment router now reconstructs multi-cycle blocks for each
segment; the trace-based native verifier is unchanged.

Native proof:

| rows | before | grouped segments |
|---:|---:|---:|
| 1024 | 381,001 B | 366,665 B |
| 4096 | 720,153 B | 662,809 B |

Selected component:

| rows | before | after |
|---:|---:|---:|
| 1024 | 147,814 B | 133,478 B |
| 4096 | 231,950 B | 174,606 B |

Segment claim bytes: 16,392 -> 2,056 B at 1024; 65,544 -> 8,200 B at 4096.
The grouped router is sequential and makes the P2 full-router tests slower; it
is a proof-size optimization, not a verify-time optimization.

Grouping sweep at 4096 rows (host-load dependent):

```text
group 8: proof 662,809 B / verify 21.48 s
group 4: proof 671,001 B / verify 26.59 s
group 2: proof 687,385 B / verify 22.77 s
group 1: proof 720,153 B / verify ~12-13 s (earlier, lower-load run)
```

Group 8 gives the smallest proof; the verify-time regression needs a parallel
grouped router. Full runtime suite: 317 passing; clippy clean.


## Parallel grouped router

`verify_dynamic_segments_against_trace` now builds row blocks in parallel and
checks grouped segments in parallel (up to 8 workers, thresholds 1024 cycles /
1024 segments). Proof bytes are unchanged; this restores multi-core use for the
grouped-segment layout. Full runtime suite: 317 passing; clippy clean.


## Track 1 sixth slice: columnar claim payload

The complete claim blob now uses a columnar layout:

```text
first_pc + pc deltas + next_pc deltas
instruction words/lengths/register indices
bit-packed presence flags
register values
memory rows + syscall options columns
```

instead of bincode of a row-major `Vec<TraceClaim>`.

Native proof:

| rows | before | columnar |
|---:|---:|---:|
| 1024 | 366,665 B | 360,559 B |
| 4096 | 662,809 B | 638,271 B |

Claim component:

| rows | before | after |
|---:|---:|---:|
| 1024 | 25,146 B | 19,040 B |
| 4096 | 114,234 B | 89,696 B |

Full runtime suite: 317 passing; claim-native guest passes; clippy clean.


## Logup PCS parameter: 20 grinding bits

The logup Shout reader/position PCS now uses `(security=100, rate=4, pow=20,
folding=3)` instead of pow 16. At 4096 rows this shrinks its opening from
174,064 B to 168,720 B; native logup component 248,657 -> 237,681 B and total
proof 638,271 -> 627,295 B. Prover cost rises from extra grinding; verifier
milliseconds remain low.

Full runtime suite: 317 passing; clippy clean.


## Native 8192 after size optimizations

`ADDS=8191 native_unified_bench`:

```text
proof     937,373 B
prove     1220.97 s
verify       53.29 s
access       18,666 B
logup       327,601 B
selected    197,510 B
claim       179,302 B
trace_claims    648 B
```

Before the segment/claim/formal optimizations the native 8192 proof was
2,833,745 B; the current proof is about 67% smaller. Prove/verify times are
host-load dependent and the grouped segment router remains the main verify
cost.


## Track 2 first slice: streamed register Twist history sumcheck

The history sumcheck previously materialized `(a+5) * cycles^2` field
elements for the register Twist. The prover now evaluates the first-round
polynomial directly from the base address/increment columns, folds once to
half-size factors, then runs the remaining rounds on the folded tables.

At 4096 rows the register-claims stage drops from about 91 s to 74.6 s
(the earlier run was already under host load); proof bytes are unchanged.
Full runtime suite: 317 passing; clippy clean.


## Logup PCS: 24 grinding bits

The logup Shout reader/position PCS now uses pow 24. At 4096 rows:

```text
logup       237,681 -> 231,857 B
total proof 627,295 -> 614,303 B
```

At 1024 rows the native proof is 348,975 B. Prover grinding cost rises; verify
stays low. Full runtime suite: 317 passing.


## Track 1 seventh slice: columnar CpuShape

`CpuShape` was serialized as a row-major `Vec<CpuShapeRow>` at about 26 bytes
per row. It now uses a columnar, varint-encoded blob (pc deltas, op/micro-op
columns, imm, width flags). At 4096 rows this removes about 74 KB.

Native proof:

| rows | before | compact shape |
|---:|---:|---:|
| 1024 | 348,975 B | 330,311 B |
| 4096 | 614,303 B | 540,093 B |

Full runtime suite: 317 passing; clippy clean.


## Track 2 second slice: prefix-summed Twist history claim

The prover's history claim value is now accumulated with one per-address prefix
array (O(cycles) updates), instead of the O(cycles^2) double loop. The sumcheck
proof rounds are unchanged, so proof bytes are unchanged.

At 4096 rows the register-claims stage measured 35.9 s -> 31.1 s (host-load
dependent). Full runtime suite: 317 passing; clippy clean.


## Track 1 eighth slice: derive claim instruction fields

The complete claim blob now stores only the instruction word, not the decoded
`rd/rs1/rs2` or instruction length. The decoder reconstructs them from the
canonical 32-bit/compressed encoding.

At 4096 rows the claim component drops from 89,696 B to 73,300 B and the native
proof from 540,093 B to 523,697 B. At 1024 rows the proof is 326,203 B.

Full runtime suite: 317 passing; claim-native guest passes; clippy clean.


## Track 1 ninth slice: sparse claim memory/syscall columns

The claim blob now stores memory rows and syscall options sparsely (row index +
entries) instead of one vector/option slot per row.

Native proof:

| rows | before | sparse columns |
|---:|---:|---:|
| 1024 | 326,203 B | 324,156 B |
| 4096 | 523,697 B | 515,506 B |

Claim component: 73,300 -> 65,109 B at 4096; 14,932 -> 12,885 B at 1024.
Full runtime suite: 317 passing; claim-native guest passes; clippy clean.


## Selected PCS: 20 grinding bits

Selected CPU PCS now uses pow 20 instead of 16. At 4096 rows the selected
component drops from 167,438 B to 158,206 B and the native proof from
515,506 B to 506,274 B; prover time changes little at this size.

Full runtime suite: 317 passing.


## Selected PCS: 24 grinding bits

Selected PCS pow is now 24. At 4096 rows the selected component drops from
158,206 B to 150,558 B and the native proof from 506,274 B to 498,626 B;
prover time rises from about 35.5 s to 47.0 s at this row count.

Full runtime suite: 317 passing.


## Track 1 tenth slice: RLE CPU-shape columns

The compact `CpuShape` columns now run-length encode pc deltas, micro-op, op,
memory width and flags. At 1024 rows the shape component drops from 7,968 B to
2,861 B; at 4096 rows the native proof drops from 498,626 B to 478,159 B.

Full runtime suite: 317 passing; clippy clean.


## Track 1 eleventh slice: RLE claim columns

Claim pc deltas, next-pc deltas, instruction words and presence flags are now
run-length encoded. At 4096 rows the claim component drops from 65,109 B to
56,928 B and the native proof from 478,159 B to 469,978 B; at 1024 rows the
proof is 306,388 B.

Full runtime suite: 317 passing; claim-native guest passes; clippy clean.


## Trace-backed Shout: no Shout PCS opening

The native dynamic proof now carries a `TraceLogupShoutProof`: only the logup*
reduction, the public reader point, and the 12 link claims. The verifier
reconstructs the Shout reader/position witness from the authenticated trace or
from the trace rebuilt from the claim proof, recomputes the reader claims and
checks the logup* output table/position claims and link claims. The separate
Shout PCS commitment/opening is gone.

Native proof:

| rows | before | trace-backed Shout |
|---:|---:|---:|
| 1024 | 306,388 B | 172,365 B |
| 4096 | 469,978 B | 309,755 B |

At 4096 rows the logup component drops from 231,857 B to roughly 70 KB (the
remaining pushforward/GKR proof). The old committed `LogupShoutProof` remains
for standalone tests and compatibility; the native path uses the trace-backed
variant. This moves Shout's soundness root from a committed Shout witness to
the authenticated claim/trace layer. Full runtime suite: 317 passing;
claim-native guest and logup Shout runtime tests pass; clippy clean.


## Track 2 third slice: streamed write-history sumcheck

The write-history sumcheck now uses the same first-round streaming as read
history: first-round polynomial from base columns, one fold, then remaining
rounds. The write-history claim is prefix-summed as well.

At 4096 rows the access stage measured about 31 s -> 25.6 s (host dependent).

## Trace-backed Shout soundness tests

`runtime_trace_logup_shout_round_trips` checks the trace-backed path and
rejects tampered link claims, reader point, and ROM witness. The soundness root
is the authenticated claim/trace layer: this is not a standalone succinct Shout
proof. The committed `LogupShoutProof` path remains for paper-form Shout.


## Native 8192 after trace-backed Shout

`ADDS=8191 native_unified_bench`:

```text
proof     465,107 B
prove     321.21 s
verify     27.88 s
access     18,666 B
selected  169,830 B
claim     113,766 B
trace_claims  648 B
```

This is down from 937,373 B before trace-backed Shout. The remaining large
components are selected CPU (170 KB), claim proof (114 KB), and the trace
Shout logup* reduction.


## Track 1 twelfth slice: XOR-delta instruction words

Claim instruction words are stored as XOR deltas from the previous row. At
4096 rows the claim component drops from 56,928 B to 52,836 B and the native
proof from 309,755 B to 305,663 B; at 1024 rows the proof is 171,345 B.

Full runtime suite: 317 passing; clippy clean.


## Track 1 thirteenth slice: delta/RLE shape immediates

CpuShape immediates are now stored as first value + RLE deltas. At 4096 rows
the shape component drops from 11,827 B to 52 B and the native proof from
305,663 B to 293,888 B; at 1024 rows the proof is 168,532 B.

Full runtime suite: 317 passing; clippy clean.


## Track 1 fourteenth slice: RLE source-register values

Claim `rs1_value`/`rs2_value` columns are run-length encoded. At 4096 rows the
claim component drops from 52,836 B to 44,648 B and the native proof from
293,888 B to 285,700 B; at 1024 rows the proof is 166,488 B.

Full runtime suite: 317 passing; clippy clean.


## Trace Shout: recompute pushforwards

The pushforward vector is determined by the reader positions, the statement and
the reader-batching challenge. Since the trace-backed verifier already has the
Shout witness, it now rebuilds the pushforwards itself (vendor
`logup_star::rebuild_pushforwards`) instead of reading them from the proof.

Trace Shout proof:

| rows | before | after |
|---:|---:|---:|
| 1024 | 21,089 B | 4,697 B |
| 4096 | 71,633 B | 6,089 B |

Native proof: 285,700 -> 220,156 B at 4096; 166,488 -> 150,096 B at 1024.
The prover's pushforward computation is unchanged; only serialization is
removed. Full runtime suite: 317 passing; claim-native guest and logup Shout
runtime tests pass; clippy clean.


## Track 1 fifteenth slice: delta-encode destination values

Claim `rd_value` is now stored as first value + signed deltas. At 4096 rows the
claim component drops from 44,648 B to 24,672 B and the native proof from
220,156 B to 200,180 B; at 1024 rows the proof is 148,552 B.

Full runtime suite: 317 passing; clippy clean.


## Native 8192 after trace Shout and claim deltas

`ADDS=8191 native_unified_bench`:

```text
proof     245,958 B
prove     313.48 s
verify     31.41 s
access     18,666 B
selected  169,830 B
claim      49,250 B
trace_claims   648 B
```

Components now fit in 250 KB at 8192 rows. The selected CPU PCS opening is the
dominant cost; claim and access are comparatively small. This proof is
trace/claims-backed (not a standalone PCS-bound Shout/CPU proof).


## Claim-native 2^16 after claim compression

`ROWS=65536 claim_native_bench`:

```text
proof      1,153,818 B
claim        916,013 B
selected     237,733 B
prove        377.79 s
verify       188.33 s
throughput   173.47 cycles/s
```

Before the claim/shape/selected compression work the same path was about
16.78 MB with 418 s prove and 198 s verify. The claim proof is now the dominant
component (916 KB) and the main blocker for the paper's 380 KiB 2^16 target.
This is the proof-only claim layer path, not the full trace-backed native proof.


## Native trace mode: omit complete claim proof

Added `prove_unified_trace_dynamic_native_trace`, a native mode for callers that
supply the trace. It keeps root/commitment binding and the trace-backed Shout
and selected CPU proofs, but omits the O(rows) complete claim proof.

Native trace-mode proof:

| rows | with claim | trace mode |
|---:|---:|---:|
| 1024 | 148,552 B | 142,313 B |
| 4096 | 200,180 B | 175,509 B |

At 4096 the claim component (24,672 B) is removed. At 8192 this projects to
roughly 197 KB. This is not virtual claims: the separate claim-native path and
proof-only claim verifier still carry the complete claim proof. A dedicated
test checks the trace-mode round trip.


## Virtual-claim groundwork: sparse claim openings

`ClaimProof::open_indices` now opens an arbitrary sorted subset of authenticated
row claims, with the absolute row index preserved on every opening.
`verify_indexed_claims` / `ClaimProof::verify_subset` verify those sparse
openings without requiring a dense 0..n list.

This is the first concrete building block for virtual claims: a proof-only
verifier can ask for the rows needed by CPU/Shout/Access instead of carrying the
complete claim proof. The trace-selected CPU experiment was reverted from the
working tree; committed Shout/CPU remains the paper path.

Full runtime suite: 318 passing.


## Track 1 sixteenth slice: delta-of-delta destination values

Claim destination values now use first value + first delta + RLE of delta
changes (a second-order delta). At 4096 rows the claim component drops from
24,672 B to 20,590 B and the full native proof from 200,180 B to 196,098 B; at
1024 rows the claim is 5,222 B.

The trace mode (no claim proof) is unchanged at about 175.5 KB at 4096. Full
runtime suite: 318 passing.


## Committed Shout: witness binding

Added `verify_logup_shout_against_witness`. It first verifies the committed
Shout PCS opening, then recomputes the reader/link/position MLEs from the
supplied witness and checks the proof's claims against them. This closes the
previous binding gap where a standalone committed Shout could prove a lookup
for an arbitrary witness.

The logup runtime test now also rejects tampered reader claims and a tampered
ROM witness through this binding. This is a prerequisite for using committed
Shout in the paper path while virtual claims are still under construction.


## Paper baseline: committed Shout + committed CPU + full claim proof

Added `prove_unified_trace_paper` and `verify_logup_shout_against_witness`
integration. The native verifier now binds any committed Shout proof's
reader/link/position claims to the trace-derived witness. The proof-only
`verify_native_unified` path therefore works with committed Shout, committed
selected CPU, and the complete claim proof.

Paper-mode benchmark (`paper_unified_bench`):

| rows | proof | logup | selected | claim | verify |
|---:|---:|---:|---:|---:|---:|
| 1024 | 294,746 B | 149,865 B | 116,998 B | 10,594 B | 1.74 s |
| 4096 | 446,872 B | 231,985 B | 151,262 B | 44,028 B | 8.56 s |

This is the current paper-path baseline. It is still O(rows) due to the complete
claim proof; virtual claims must replace that before the 2^16 target.


## Paper path: rebuild committed Shout pushforwards

The paper-mode prover clears the committed Shout pushforwards; the witness-bound
verifier rebuilds them from the trace-derived witness and the reader-batching
challenge before replaying logup*. This is the same deterministic-pushforward
optimization used for trace-backed Shout, now applied while keeping the Shout
PCS commitment/opening.

Paper-mode benchmark:

| rows | proof | logup | selected | claim | verify |
|---:|---:|---:|---:|---:|---:|
| 1024 | 278,354 B | 133,473 B | 116,998 B | 10,594 B | 1.78 s |
| 4096 | 381,328 B | 166,441 B | 151,262 B | 44,028 B | 10.32 s |

Full runtime suite: 318 passing; paper_mode and logup runtime tests pass;
clippy clean.


## Paper-mode 8192

`ADDS=8191 paper_unified_bench` (committed Shout + committed CPU + complete
claim proof, proof-only verifier):

```text
proof      466,410 B
access      19,378 B
logup      187,529 B
selected   169,606 B
claim       88,518 B
shape           60 B
prove      329.95 s
verify      21.83 s
```

Scaling of the paper path:

| rows | proof | prove | verify |
|---:|---:|---:|---:|
| 1024 | 278,354 B | 34.02 s | 1.78 s |
| 4096 | 381,328 B | 68.21 s | 10.32 s |
| 8192 | 466,410 B | 329.95 s | 21.83 s |

The complete claim proof grows linearly (88.5 KB at 8192) and remains the
virtual-claims blocker for the 2^16 target.


## Virtual claim root in the unified proof

`UnifiedTraceProof` now carries a canonical `virtual_claim_root` derived from
the selected CPU segment claims. The native prover sets it and the verifier
recomputes `VirtualClaimSet::from_selected` and rejects a mismatch. This is a
+32 B proof field and the first statement-visible virtual-claim commitment; it
does not yet replace the complete claim proof.

Paper mode 1024 proof: 278,386 B. Full runtime suite: 318 passing; paper-mode
root-tamper test passes.


## Selected CPU width diagnostic

Added `mixed_row_relation_vars` to measure selected witness width by component
mask. For width 8:

```text
ALU only                 433 vars
ALU + branch            1453 vars
full mixed components   3515 vars
```

The ALU-only Addi benchmark gets `mask = 3` because the final fetch/halt row
introduces the branch component, inflating the selected witness about 3.3x.
The next selected-CPU optimization should split or special-case the final
branch row rather than pay the branch component for every cycle.

The virtual claim root binding and paper-mode baseline from the previous rounds
remain in place; full runtime suite: 318 passing.


## Selected CPU: halt/ecall row uses the jump component

The dynamic row mapping now encodes the zero-condition halt/ecall row as a
`Jump` to the current PC instead of a `Fetch` branch. With width 8:

```text
ALU                    433 vars
ALU + branch          1453 vars
ALU + jump             549 vars
```

The ALU+halt trace therefore uses `mask = ALU | JUMP` and a witness about 2.6x
narrower than the old ALU+branch shape.

Paper-mode proof:

| rows | before | after |
|---:|---:|---:|
| 1024 | 278,386 B | 270,090 B |
| 4096 | 381,360 B | 367,536 B |

Selected component: 116,998 -> 108,702 B at 1024; 151,262 -> 137,438 B at
4096. The dynamic padding rows use the component family present in the mask
instead of unconditionally forcing a branch row. Full runtime suite: 318
passing; clippy clean.


## Negative result: external compression crates

Tried compressing the claim blob with `zstd`/`flate2`, but the offline Cargo
registry sandbox cannot unpack new transitive crates (`jobserver`, `crc32fast`).
The dependency change was reverted. A in-tree compression codec would be
required, which is not worth it before the virtual-claim rewrite.


## Claim proof: DEFLATE compression (vendored miniz_oxide)

The compact complete claim blob is now DEFLATE-compressed. To keep the offline
build self-contained, `miniz_oxide` and `adler2` were copied into `vendor/` and
wired as path dependencies; no registry unpack is required.

Paper mode:

| rows | before claim | after claim | before proof | after proof |
|---:|---:|---:|---:|---:|
| 1024 | 10,594 B | 3,101 B | 270,090 B | 262,597 B |
| 4096 | 44,028 B | 13,087 B | 367,536 B | 336,595 B |

Claim-native 2^16:

```text
proof      1,153,818 -> 403,315 B
claim        916,013 -> 183,598 B
selected     219,645 B
```

The 2^16 prove/verify timings were 605 s / 241 s under host load. The claim
layer is still O(rows), but the compressed payload is now small enough that the
remaining gap to the paper's 380 KiB is dominated by committed Shout/CPU
openings. Full runtime suite: 318 passing; clippy clean.


## Paper-mode 8192 after claim compression

`ADDS=8191 paper_unified_bench` (committed Shout + committed CPU + compressed
claim proof, proof-only verifier):

```text
proof      385,708 B
access      19,378 B
logup      187,529 B
selected   152,510 B
claim       24,880 B
shape           60 B
prove      597.45 s
verify      23.91 s
```

Paper scaling:

| rows | proof | verify |
|---:|---:|---:|
| 1024 | 262,597 B | ~3.0 s |
| 4096 | 336,595 B | ~25.3 s |
| 8192 | 385,708 B | ~23.9 s |

The 2^16 target remains open; selected CPU and committed Shout openings now
dominate the paper path, with claim compressed to 24.9 KB at 8192.


## Paper-mode 16384 timeout

`ADDS=16383 paper_unified_bench` did not finish within a 2400 s timeout. The
paper path is therefore not ready for a 2^16 run: at 8192 rows it already takes
about 597 s to prove, and the Access/Twist and selected-CPU stages scale
superlinearly in the current implementation. Proof-size work alone is not
enough; prover scaling must be fixed before the paper 2^16 performance target
can be measured.
