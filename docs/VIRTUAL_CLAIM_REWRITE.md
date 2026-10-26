# Virtual Claim Rewrite (Paper-Alignment Workstream)

This is the selected multi-week workstream: replace the full-trace
`ClaimProof` with BinarySpartan virtual segment claims, then add linear
BinaryShout/BinaryTwist. The full-trace claim path remains available while the
new format is built.

## Why the rewrite

Claim-native proof size is O(rows):

```text
4096 rows: total 1,214,734 B (claim 442,441 + selected 772,221)
2^16 rows: total 16.78 MB
```

The paper's 2^16 proof is 380 KiB because the CPU proof exposes virtual
segment claims, not every row. The rewrite must change the proof format and the
verifier inputs, not just the serialization.

## Milestone 0: canonical virtual claim set

Implemented in `magnetar-runtime/src/virtual_claims.rs`:

```text
VirtualClaim      { owner, value }
VirtualClaimSet   { claims, root }
```

`VirtualClaimSet::from_selected` reconstructs the selected layout from the
public mask/matrix-cycles fields, reads the lockstep segment claims, and hashes
them in a canonical order (layout order, owner tag + value). The root is
independent of trace rebuilding and is tested to be deterministic and
tamper-evident.

This is scaffolding: the proof still carries the selected opening and the old
claim path; the set is not yet the authenticated statement binding.

### Milestone 0.5: virtual CPU proof format

`VirtualCpuProof` is now implemented:

```text
width / cycles / trace_commitment
initial_pc / final_pc
VirtualClaimSet
selected CPU proof
```

`verify_virtual_cpu` checks:

- statement trace commitment and claim root
- initial/final PC
- virtual claim root and canonical claim set
- selected CPU matrices/opening via the P2 public verifier
- no `claims_to_trace`

It is still CPU-only: memory/bytecode consistency is not attached yet, and the
virtual claim set duplicates the selected proof's segment claims, so it does not
yet reduce proof size. It establishes the new verifier input shape without a
full trace.

## Milestone 1: virtual claim proof format

Replace the full `ClaimProof` in the native proof with:

```text
- statement root for the virtual claim set
- selected CPU proof (P2 public verifier)
- virtual claim set commitment
- (later) BinaryShout / BinaryTwist claims
```

The verifier must stop calling `claims_to_trace` for CPU verification. Claim
routing becomes:

```text
selected segment claim -> owner/value -> virtual claim root
```

## Milestone 2: BinarySpartan CPU claims

Move the dynamic CPU witness to the paper's uniform SIMD relations and expose
only virtual segment claims. This removes the need to rebuild row sources in the
P2 router.

## Milestone 3: linear BinaryShout

Replace `cells x cycles` read sum-check with a lookup argument over a committed
bytecode table and committed read values.

Status: blocked on the protocol design. A pointwise random-point identity was
prototyped and rejected because the MLE of a product of address-bit functions
is not the product of their MLEs; it failed `hello.elf`. The correct argument
needs logUp/multiplicity, sparse one-hot committed columns, or the paper's
table-lookup sum-check. See `docs/LINEAR_SHOUT_POSTMORTEM.md`.

## Milestone 4: linear BinaryTwist

Replace `cycles^2` register/RAM history with a sorted/permutation access
argument and terminal PCS openings.

## Milestone 5: proof-size and scale

Target:

```text
2^16: prove near paper 35 ms, proof near 380 KiB
2^22: prove near paper 547 ms, proof near 598 KiB
```

Only after milestones 1-4 should the old full-trace claim path be removed.

## Risks

- Proof-format breakage and determinism regressions.
- Soundness of the claim router and statement root change.
- P3/MosaicPCS opening canonicalization.
- Large-scale memory and parallel scheduling.
- Recursion/ZK/FP/AMO/unaligned parity remains separate.
