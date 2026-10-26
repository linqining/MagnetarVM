# Claim-Native Fast Path

This is a native optimization over the authenticated claim layer. It keeps the
ClaimProof and the proof-only selected-CPU bundle and removes the Access/Shout
proofs, replacing them with linear checks over the authenticated rows.

## What it verifies

- ClaimProof root/count and statement root/trace commitment.
- Proof-only dynamic claim bundle (public matrices + full segment router).
- ROM fetch word/length at each claim PC.
- Register read/write consistency from `statement.initial_state.regs` to
  `statement.final_state.regs`.
- Little-endian RAM read/write consistency from `statement.initial_ram`.
- The final register file equals the statement final state.

## What it does not yet handle

- Syscall write/read IO binding; proofs with nonempty `statement.output`/`input`
  are rejected.
- The paper's BinaryShout/BinaryTwist semantics; this is a native claim-layer
  path, not paper parity.
- A third-party audit.

## Point measurements

1024 rows:

```text
proof   409,318 B
prove   7.18 s
verify  2.94 s
```

2048 rows:

```text
proof   680,214 B
prove   16.72 s
verify  10.87 s
```

The 2048 verifier still rebuilds per-cycle component sources in the segment
router; the access/Shout proofs are gone but the router is O(rows * columns).
