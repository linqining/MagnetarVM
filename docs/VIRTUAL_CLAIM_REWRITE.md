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


## Milestone 1 progress (B exploration)

`verify_virtual_cpu_layer` now verifies the selected CPU proof and its canonical
`VirtualClaimSet` root from a `UnifiedTraceProof` without the trace-claim layer:

```text
selected CPU segments verified publicly
virtual_claim_root checked against selected proof
statement trace_commitment / PC checked
```

A paper proof round-trip test (`unified_virtual_cpu_layer_round_trips`) passes;
tampering the virtual claim root is rejected. This does not yet remove ClaimProof:
the access statement digest and Shout row binding still come from the full row
claims, so proof size is unchanged. Next milestone: virtual Shout binding derived
from the virtual claim set.


## Milestone 1.5: compact claim by register reconstruction

`ClaimProof::from_trace_reg` omits the rs1/rs2 columns; `verify_reg` simulates
the initial register file over the stored PC/word/rd rows. At 2^16 the claim
proof drops from 183,599 B to 2,410 B and the proof-only trace-Shout total is
354,979 B compressed, with no verifier trace.


## Milestone 2: segment-claim binding (Virtual Spartan-style)

`verify_dynamic_segments_against_rows` now implements the first virtual-claim
binding step for the selected CPU proof:

```text
1. verify the public CPU matrices/layout/PCS from the selected proof
   (no trace-based matrix verifier),
2. rebuild the expected witness bits from claim rows,
3. compute the full witness MLE at the proof point,
4. reconstruct the witness MLE from the proof segment claims via the public
   segment layout,
5. require the two values to agree.
```

A tampered segment claim is rejected by the test
`virtual_segment_claims_bind_to_dynamic_witness`.

Measured at 2^16 trace-Shout: this path verifies in 3.09 s, slower than the
current trace-based selected verifier (2.40 s), because step 2-3 are still
O(T). It is therefore not enabled in the default verifier. The next milestone
is the actual Virtual Spartan step: replace steps 2-4 with the segment-only
linear identity and route every virtual segment claim to its auxiliary
reduction, so the verifier never reconstructs the full witness bits.


## Milestone 2.5: measured public selected verifier

`FAST_SELECTED=1` benchmark mode measures the trace-free public selected
verifier at 2^16: 646 ms. This is the lower bound before adding aux-claim
routing; it is dominated by gated-matrix construction/allocation, not PCS.
Next: lazy structured extra rows for the verifier path.


## Milestone 2.6: lazy gated matrices

Added `LazyExtraRows::Gated` to `SharedBlockMatrix`; the public selected verifier
builds the A/B/C extra rows from the PC-chain pattern instead of materializing
them. 2^16 public selected verify: 646 ms -> 53.6 ms. Full suite 339 passing.
Next: remove the O(T) witness-binding from the default verifier and route
segment claims through the auxiliary reductions.


## Milestone 3: blocked witness binding + public selected verifier by default

`eval_bits_mle` computes the expected witness MLE in blocks; the default selected
verifier now uses the lazy public matrices and this blocked binding. Full 2^16
proof-only trace-Shout verify: 3.09 s -> 1.31 s (selected public stage 53.6 ms).
Next: remove the remaining O(T) witness bits/MLE by virtual claim routing and a
single Mosaic commitment for CPU direct segments.


## Milestone 3.5: component timing and Shout size tradeoff

Fast proof-only components at 2^16: core 3.8 ms, public selected 45.6 ms,
committed Shout 11.8 ms (~61 ms total). Keeping logup pushforwards for
witness-free Shout verification makes the Shout proof 1.29 MB and total proof
1.78 MB, so the compact 380 KiB target requires a different proof-only Shout
reduction (no transmitted pushforward tables). This path is not committed as
the default verifier.


## Milestone 3.6: separability of the PC-chain pattern

The lazy gated extra-row sums factor into independent instance and bit parts for
power-of-two widths, reducing O(cycles*width) to O(cycles+width). Public selected
verify: 45.6 ms -> 11.8 ms at 2^16, 13.8 ms -> 5.1 ms at 2^14. Full suite 339
passing, clippy clean.
