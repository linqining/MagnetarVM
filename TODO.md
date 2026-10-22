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
- [ ] Replace `BinaryShout`'s placeholder with a ROM read reduction.
- [ ] Optimize the P3 shared opening path (currently the runtime pre-commit and
      Spartan's internal commit/open repeat the same batch commitment).

## Proof engine / PCS

- [ ] Full MosaicPCS: aligned-subcube packing, ring switching, and a single
      commitment that also covers the CPU witness in every proof variant.
- [ ] Use the P3 mosaic opening in `ChunkedTraceProof` and per-row proofs.
- [ ] Reduce the virtual-address sum-check prover cost (currently many bit
      factors are folded per round; a specialized bit-product sum-check should
      be several times faster).
- [ ] Reduce the quadratic LT prover work (streamed `LT` folding or the
      paper's linear-time recurrence).

## VM / ISA

- [ ] PC-linkage and reservation-chain constraints inside the proof.
- [ ] RV64F/D execution and proofs.
- [ ] Unaligned memory accesses.
- [ ] Broader syscall runtime beyond `exit`/`hint`/`write`/`read`.
