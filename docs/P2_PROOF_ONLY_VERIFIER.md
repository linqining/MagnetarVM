# P2 Proof-Only Selected-CPU Verifier

Current native verification still rebuilds a trace:

```text
ClaimProof -> claims_to_trace -> verify_dynamic_segmented_trace(trace, ...)
```

That makes Access/Shout proofs redundant for a verifier that already has the
full authenticated trace, and prevents a linear Shout from having its intended
soundness/performance role.

## Required changes

1. Carry every segment claim needed by the lockstep verifier in the selected
   proof. Today `SelectedCpuClaims::segments`, `claim_root`, and
   `claim_openings` are serde-skipped, so a deserialized proof cannot verify
   without rebuilding the trace.
2. Build the six CPU matrices from the public statement ROM/config and witness
   layout, not from `mixed_alu_branch_rows_from_trace`.
3. Verify the outer/inner lockstep claims directly against the committed
   segment claims and the PCS opening. Do not rebuild witness bits, recompute
   the commitment, or re-run `TraceClaimTree`.
4. Bind the segment claims to the statement root and to the selected proof's
   claim root.
5. Only after this verifier exists can BinaryShout/BinaryTwist become genuinely
   proof-only and can linear Shout remove the trace-rebuild dependency.

## Dependencies

- BinarySpartan virtual segment claim router (the current selected proof uses a
  trace-derived witness layout).
- A proof format for CPU segment claims that is not serde-skipped.
- A public bytecode table derived from `Statement.rom` for Shout.

## Status

Design only. This is not a constant-factor change; it changes the verifier's
trusted inputs and proof format. It should be its own workstream before P1.1.

## Concrete blocker found

Serializing `SelectedCpuClaims::segments`/`claim_root` was tried directly. It
breaks `selected_cpu_claims_round_trip`: after deserialization the compact
selected layout no longer reconstructs the same segment metadata, so
`selected_segment_claims(layout, proof)` differs from the serialized segments.
Proof-only verification therefore needs a canonical segment layout encoding,
not just removing `#[serde(skip)]`.

The experiment was reverted. This confirms P2 requires a proof-format redesign.

## Progress: serialized claim root

`SelectedCpuClaims::claim_root` is now serialized (32 B). Segment claims still
need not be serialized: they are derivable from the committed `proof.segments`
and the compact layout, and verifier comparison ignores segment names. This
keeps the selected proof within 32 bytes of its previous size
(1024 rows: 298,541 -> 298,573 B).

The remaining P2 blocker is building the six CPU matrices from public
statement/layout data instead of `synthetic` trace rows.

## Progress: public dynamic verifier

`SelectedCpuClaims` now serializes `mask` and `matrix_cycles` (and the claim
root). A new `verify_dynamic_segments_public` reconstructs the layout and the six
CPU matrices from those public fields, then verifies the lockstep proof without
calling `mixed_alu_branch_rows_from_trace` or rebuilding witness bits/
commitment. A tamper test confirms that modifying a proof segment value is
rejected. Proof growth is 9 B (mask + matrix cycles) at 512/1024 rows.

This is the matrix/layout half of P2. The remaining half is the segment-claim
router that binds `proof.segments` values to authenticated row claims.

## Progress: PC segment router

`verify_dynamic_pc_segments` calls the public verifier, obtains its `ry` point,
and compares every `pc{cycle}` proof segment against the MLE of the
authenticated claim row's `pc`/`next_pc` bits at the local segment point. A
tampered claim PC is rejected. This binds the PC/next-PC virtual segments to the
ClaimProof rows without rebuilding the witness.

Remaining router fields: instruction/selector (`mux`) and register/memory
component segments.

## Progress: full segment router

`verify_dynamic_segments_against_trace` rebuilds each cycle's component source
from `MixedAluBranchInput`, applies the segmented mapping, evaluates every
layout segment's MLE at the public verifier's `ry`, and compares it with
`proof.segments`. This covers component, PC, mux and padding segments.

`verify_dynamic_claim_bundle` then takes only a `Statement`, a `ClaimProof` and
the selected proof: it authenticates the claims, rebuilds the synthetic trace
from them, checks PC consistency, and runs the full segment router. No external
trace is required. The dynamic test rejects a tampered `rs1_val` and a tampered
proof segment.
