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
