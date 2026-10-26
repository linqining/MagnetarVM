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
