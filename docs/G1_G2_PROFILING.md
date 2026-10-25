# G1/G2 profiling baseline

## Tool

`prove_unified_trace_profile` returns per-stage wall-clock timings for the
default unified plan. `crates/magnetar-testkit/examples/profile_unified.rs`
runs a straight-line ALU program and prints Commit/CPU/Access/Opening/Finish.

## First measurements (release, width 16)

```text
rows=10  proof 247,937 B  total 7.4 s
  Commit       1.0 ms
  Cpu         ~6.2 s
  Access      16.2 ms
  Opening     ~0.98 s
  Finish      17.1 ms

rows=18  proof 295,337 B  total 15.3 s
  Cpu        ~13.5 s
  Access      40.2 ms
  Opening     ~1.62 s

rows=34  proof 360,313 B  total 31.1 s
  Cpu        ~29.4 s
  Access     126.0 ms
  Opening     ~1.30 s

rows=66  proof 439,665 B  total 59.0 s
  Cpu        ~56.0 s
  Access     432.6 ms
  Opening     ~2.21 s
```

CPU is ~95% of prover time and grows ~0.85 s per trace row.

## CPU inner profile

For width 16, the combined `GatedCpuRow` has:

```text
relation.num_vars = 21,274
base_cols         = 32,768
```

The gated witness is padded to `cycles * base_cols`; even a 10-row trace
commits about `16 * 32768 = 524,288` bits (the lockstep path measured
1,048,576 bits for the padded 32-cycle layout). Inside the CPU stage:

```text
commit   ~21 ms
claims   ~3.75 s
open     ~2.25 s
```

The lockstep claims dominate: six shared-block matvecs, six row combinations,
one outer product6 sumcheck, one inner product2 sumcheck, and six MLE
evaluations.

## Attempted and rejected

Parallelizing the six independent matvecs and six row combinations with scoped
threads (12 cores available) produced no measurable improvement:

```text
serial   claims 3.75 s
threaded claims 3.79 s
```

This suggests the claims phase is dominated by serial sumcheck work and/or
memory traffic, not independent matvec CPU time alone.

## Next candidates

1. **Op-specialized gated rows**: build a row relation only from operations
   present in the trace (ALU-only loop currently includes mul/div/sdiv), reducing
   `relation.num_vars` and `base_cols`.
2. **Remove per-row padding**: use the exact row relation size where the layout
   permits it; current next-power-of-two padding inflates 21,274 -> 32,768.
3. **Reduce the number of shared-block matvecs** or cache partial products.
4. **Streaming witness/commitment** for rows beyond memory.
5. **Native F2/PCS backend** if CPU bit witness remains dominant.

The first two target the root cause (witness width), but they change the gated
virtual layout/claim routing; they should be benchmarked against the current
E5 proof size before adoption.


## Op-specialization prototype

`prove_alu_only_batch_bits` constructs only the ALU subrelation, pads rows, and
proves a batch with the same lockstep/BitPcs path. It is not yet wired into the
unified CPU layout (no PC/memory/Shifter claims), but it measures the upper
bound from removing unused subrelations.

Width 16:

```text
full GatedCpuRow  vars 21,274  nextpow2 base 32,768
ALU-only row      vars    449  nextpow2 base    512
base reduction    64x
```

ALU-only RingSwitch proof:

```text
cycles=16   bits   8,192  proof 40,424 B  prove 0.24 s  verify 3.2 ms
cycles=64   bits  32,768  proof 54,224 B  prove 1.16 s  verify 3.9 ms
cycles=256  bits 131,072  proof 75,560 B  prove 0.76 s  verify 4.8 ms
```

Same ALU rows through the **full combined gated row**:

```text
cycles=16 bits=524,288 proof=98,144 B prove=5.30 s
```

So the op-specialized relation is about **21x faster** and **2.4x smaller** at
the same 16 ALU rows, before any PC/memory/Shifter claims are added.

This confirms the witness-width bottleneck: unused mul/div/sdiv/memory/shift
subrelations currently dominate the CPU proof, not the ALU relation actually
executed. The next step is an op-specialized unified layout with claim routing.


## Parallel streaming chunks

`prove_chunked_trace_streaming` now proves per-chunk CPU proofs in parallel
with scoped threads; `prove_chunked_trace_streaming_sequential` retains the old
path, and a test asserts both produce byte-identical proofs.

16-row ALU trace, release:

```text
chunk=2 sequential 635,490 B 7.30 s   parallel 3.42 s  (2.13x)
chunk=4 sequential 414,846 B 17.35 s  parallel 7.74 s  (2.24x)
chunk=8 sequential 282,572 B 10.69 s  parallel 3.81 s  (2.80x)
```

The parallel path now overlaps the shared access/aux proof with the per-chunk
CPU proofs as well as parallelizing the chunks themselves.

Proof size and verification time are unchanged. The compact default still uses
one whole-trace CPU proof; this optimization applies to the optional streaming
mode and to memory-bounded chunked proving.
