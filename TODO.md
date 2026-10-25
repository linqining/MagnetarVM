# TODO

Detailed paper gap audit: [PAPER_GAPS.md](PAPER_GAPS.md).

## BinaryTwist

- [x] Use a linear-time `LT` MLE recurrence; `lt_mle_matches_quadratic` compares
      it with the materialized quadratic reference.
- [x] Virtualize `Val`/`Next` through the `LT` identity and keep only `ra`,
      `wa`, and compact `Inc` committed.
- [x] Address virtualization: commit bit-sliced address components and prove
      full-address evaluations with sum-checks instead of committing `K × T`
      one-hot address tables.
- [x] Add a bit-sliced `BinaryShout` ROM-read reduction (16-bit and 32-bit
      instructions) and wire its claim into `UnifiedTraceProof` through the
      shared P3 opening.
- [x] Add a `BinaryRouter` reference proof for 64-bit shifts and sub-word store
      routing, and wire its claim into `UnifiedTraceProof`.
- [x] Wire `BinaryShout` and `BinaryRouter` claims into `UnifiedTraceProof`
      without adding a second P3 opening.
- [x] Share P3 openings across claims: unified CPU/gated+RAM/Shout/Router, and
      chunked access+aux now use one commitment/opening each.

## Proof engine / PCS

- [x] MosaicPCS for the unified bit-valued tables: aligned-subcube packing,
      claim lift, batching, ring switching, and a single P3 evaluation.
      Field-valued tables (trace/RAM values) still use one shared P3 field
      opening; packing them is the remaining MosaicPCS extension.
- [ ] B6 univariate-skip/degree-reduction sum-check optimization. Frobenius
      collision and weighted product2 batch sumcheck are implemented.
- [x] Add one shared BinaryShout/BinaryRouter P3 opening to `ChunkedTraceProof`.
- [ ] Per-row `TraceProof` keeps minimal per-row P3 proofs; adding global aux
      claims per row is intentionally deferred.
- [x] Reduce the virtual-address sum-check prover cost by splitting the
      read/write reductions into `(cell, cycle)` initial/base sum-checks and
      `(cycle, previous-cycle)` history sum-checks. This removes the quadratic
      `K × T²` factor-folding blow-up.
- [ ] Reduce the quadratic LT prover work (streamed `LT` folding or the
      paper's linear-time recurrence).

## VM / ISA

- [x] PC-linkage and reservation-chain constraints inside the gated/shared proof
      (`next_pc=pc+4`/branch/jump targets; instance boundaries).
- [ ] RV64F/D execution and proofs.
- [x] Unaligned accesses inside one 8-byte word (cross-word remains rejected).
- [x] Reference syscall ABI `exit`/`hint`/`write`/`read`/`clock`, including
      `SYS_READ` write-back trace records.

## D12 shift expansion

- [x] Fixed branchless expansion for Sll/Srl/Sra/Sllw/Srlw/Sraw.
- [x] Relocate conditional branches, `jal x0`, `jal rd≠0` (link preserved), and
      `auipc` (PC correction).
- [x] Integrate into `execute_expanded`, `ReferencePipeline::run_expanded` and
      `preprocess_expanded`.
- [ ] Trace-level virtual micro-op scheduling remains open.
- [x] Programs using x28-x31 are expandable via dynamically chosen unused
      temporary registers.
- [x] Static `jalr` targets are resolved and rewritten to `jal`; only dynamic
      `jalr` falls back.

## Chunked compact mode

- [x] Default `prove_chunked_trace` uses one whole-trace CPU proof while keeping
      the chunk state chain; chunk-2 proof 646,938 -> 217,170 B.
- [x] `prove_chunked_trace_streaming` retains per-chunk CPU proofs for streaming.
