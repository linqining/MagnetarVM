# CPU claim layer design

This is the architecture needed for A2 and compressed-instruction PC steps.

## Instruction length

The gated CPU row cannot choose `pc + 2` from a free witness bit: a proof-only
verifier would accept a length that disagrees with the fetched instruction.

The authenticated path is:

```text
Shout/ROM opening at pc
  -> instruction word (32 bits)
  -> len2 = (word & 3) != 3
  -> len2 feeds the CPU PC-step selector
```

The intermediate gated step uses a `step2` selector, but that selector must be
derived from the same instruction word that the Shout proof authenticates. Until
that link exists, `step2` is only safe in trace-aware reference verification.

## CPU output claims

Each selected row needs a claim record covering:

```text
pc, next_pc, instruction_word
rd, rd_value, rd_write
rs1, rs1_value, rs2, rs2_value
mem_addr, mem_value, mem_width, mem_write
```

Claims are split by owner:

```text
Cpu       pc/next_pc/rd/rs values
Memory    address/value/width
Routing   Shift/Store/Bytecode selector claims
```

The verifier checks each claim against its owning sub-proof and against the
row's selector/mux constraints. The selected witness commitment is then
well-defined without rebuilding it from a trace.

## Proof-only flow

```text
verify selected CPU witness commitment
verify per-row claims against register/read-write/memory proofs
verify claim routing
verify PC/state claims
  -> no trace.rows access
```

The trace-aware verifier remains as a reference and as the current fallback for
traces that cannot express the required claims.

## Migration stages

1. Add instruction-word/len2 Shout claim and use it only in trace-aware mode.
2. Add rd/rs1/rs2 and memory claim records to the selected proof.
3. Route claims through the existing register/access proofs.
4. Add `verify_native_proof_only` alongside `verify_native_trace`.
5. Switch grouping/chunking to the proof-only verifier.

## Current blocker

The grouped gated witness/matrix path still assumes a fixed `pc + 4`; a local
`step2` relation check passes, but the shared-matrix sumcheck rejects the grouped
proof. The instruction-length claim must be designed together with that path.


## Implemented first layer

`crates/magnetar-runtime/src/trace_claims.rs` adds a Merkle tree over per-row
claim leaves. A leaf commits to:

```text
pc, next_pc, instruction_word, instruction_len
rd, rs1, rs2 and their values
memory address/value/width
```

`TraceClaimTree::open(index)` returns an inclusion path and
`verify_opening(root, opening)` checks it. Tests cover every row, tampered
leaves and instruction-length changes. `Statement` and `UnifiedTraceProof` now carry `trace_claim_root`, and the
trace-aware verifier checks it against the trace. Inclusion openings are
implemented and tested in `TraceClaimTree`, but are not yet serialized in the
unified proof: adding every row's opening changed proof-byte equality in the
protocol round-trip test, so serialization will be added per-claim once the
proof-only verifier needs specific fields.


## Compressed-path diagnosis

The failing compressed proofs go through
`gated_bundle::prove_gated_bundle_from_trace`, which:

```text
gated_rows_from_trace(trace)
final_pc = last_pc + 4
prove_gated_dual_batch_bits_with_pc(...)
```

This path bypasses `ReservationCpuInput.step2` entirely. A step2 relation that
passes `ReservationCpuRow::relation_check` can therefore still fail in the
gated bundle's shared-matrix sumcheck. The next implementation step is to feed
the gated bundle from the reservation rows (or an equivalent step2-carrying
row view) instead of `gated_rows_from_trace`.


## Step2 experiment result

A local step2 prototype was built with:

```text
GatedCpuRow step2/add2/add4 variables
ReservationCpuInput.next_pc/step2
gated_batch_bits_with_steps
prove/verify_gated_dual_batch_bits_steps_with_pc
gated_bundle::prove_gated_bundle_from_trace using trace-derived steps
```

Result:

```text
prove_gated_bundle_from_trace(compressed trace)  passed
unified prove_cpu (reservation virtual path)     sumcheck mismatch
```

So the gated bundle itself can represent `pc + 2`; the remaining failure is in
the unified CPU stage, which builds `z` from `reservation_cpu_rows` through
`reservation_virtual_inputs` rather than from the bundle. The prototype was
reverted to keep HEAD green (295/3); the next change should target that unified
reservation/virtual input path.


## Second step2 experiment

With step2 wired into `GatedCpuRow`:

```text
compressed row relation_check                 passed
compressed reservation batch round trip       passed
compressed gated_bundle round trip            passed
unified reservation_claim_inputs matrices     ClaimMismatch
```

The remaining failure is before the proof: the shared matrices built from the
step2 relation disagree with the `z` produced from the same `ReservationCpuRow`
witness, even though every row's `relation_check` passes. This points at a
shared-matrix/link or virtual-layout variable not carrying the four new step2
variables, rather than at the PC arithmetic itself.

The prototype was reverted again to keep HEAD at 295/3. The next fix should add
a matrix-vs-z constraint probe that reports the first failing shared-matrix row
and maps its columns back to the step2 variables.


## Claim payloads and proof-only recovery

`TraceClaim` now carries the actual row fields, not just a hash:

```text
pc/next_pc/instruction_word/instruction_len
rd/rs1/rs2 values
memory addr/value/width
```

`TraceClaimOpening` carries the claim plus its Merkle path, and
`verify_opening` recomputes the leaf hash from the claim. `verify_claims(root,
openings)` verifies a contiguous opening list and returns the recovered claims.
Tests cover tampered instruction length, register value and memory records. This
is the payload the proof-only verifier will consume.


## Selected CPU claim openings

`SelectedCpuClaims` now carries `claim_root` and `claim_openings` for the dynamic
selected CPU path. `proof_dynamic_cpu_claims` fills them from
`TraceClaimTree`; `verify_dynamic_cpu_claims` checks the root and verifies all
openings against the trace. `verify_selected_claim_openings` recovers the claim
payloads without reading `trace.rows`.

The fields are `serde(skip)` for now because serializing them changed the
protocol proof-byte round-trip; proof-only serialization will be added as a
separate claim proof rather than inside the existing selected claim struct.


## Serialized ClaimProof and proof-only entry

`ClaimProof { root, openings }` is now serialized in `UnifiedTraceProof` as
`claim_proof`, and `verify_unified_claim_proof(proof)` verifies it without the
trace:

```text
root matches proof.trace_claim_root
verify_claims(root, openings)
return Vec<TraceClaim>
```

`unified_claim_proof_verifies_without_trace` checks recovery and rejects a
tampered instruction length. This is the first proof-only verifier entry point;
it authenticates claims but not yet the CPU/register/access relations.
