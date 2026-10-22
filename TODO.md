# TODO

## BinaryTwist

- [ ] Replace the reference `LT` reductions with the paper's linear-time
      treatment. The current implementation materializes a `T × T` `LT` table
      and builds full `(cell, cycle, previous-cycle)` factor vectors, so its
      prover cost is quadratic in the cycle count. This is correctness-first
      reference code, not the final performance path.
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
- [ ] Optimize the P3 shared opening path (currently the runtime pre-commit and
      Spartan's internal commit/open repeat the same batch commitment).

## Proof engine / PCS

- [ ] Full MosaicPCS: aligned-subcube packing, ring switching, and a single
      commitment that also covers the CPU witness in every proof variant.
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

- [ ] PC-linkage and reservation-chain constraints inside the proof.
- [ ] RV64F/D execution and proofs.
- [ ] Unaligned memory accesses.
- [ ] Broader syscall runtime beyond `exit`/`hint`/`write`/`read`.
