# Op-specialized unified CPU proof: design notes

Status: scoped, first PC-linked prototype attempted and reverted.

## Motivation

`full GatedCpuRow` always includes ALU, memory, shift, branch, mul, div and
sdiv subrelations. For width 16:

```text
relation.num_vars = 21,274
base_cols         = 32,768
```

An ALU-only row is 449 vars / 512 base cols. On 16 ALU rows the full gated
batch costs 5.30 s and 98,144 B, while the ALU-only prototype costs 0.24 s and
40,424 B. Removing unused subrelations is therefore the highest-value G2 lever.

## Required pieces

1. an op mask derived from the trace;
2. a specialized row relation that keeps:
   - PC and next-PC variables,
   - sequential PC transition (pc + 4),
   - the selected op subrelation,
   - selectors/one-hot gating needed by that subrelation;
3. a matching s2 packed companion;
4. virtual segment specs/claim routing for the selected variables only;
5. a verifier path that accepts the specialized layout.

## First milestone: PC-linked ALU-only proof (done)

`AluPcRow` combines:

- a `GatedAluRow` instruction relation;
- a `GatedBitAdder` for `pc + 4 -> next_pc`;
- links `pc = adder.a`, constant 4 into `adder.b`, `next_pc = adder.out`;
- Boolean constraints for pc/next_pc and gate = 1.

The earlier failure was an encoding bug: the Boolean constraints were written
as `pc * one = 0`, forcing every PC bit to zero. They are now `pc * pc = pc`.
The row witness passes `ConstraintSystem::check`, and
`alu_pc_batch_round_trips` proves/verifies a PC-linked 16-cycle batch.

Release, width 16:

```text
full gated      524,288 bits  98,144 B  5.87 s
ALU+PC           16,384 bits  47,248 B  0.83 s
ALU-only          8,192 bits  40,424 B  0.25 s
```

The ALU+PC proof is ~7x faster and ~2.1x smaller than the full gated row while
enforcing sequential `pc + 4`.

## PC statement (done)

`prove_alu_pc_batch_bits` / `verify_alu_pc_batch_bits` now take
`(initial_pc, final_pc)` and pass them to `gated_shared_matrices`, so the
batch's first PC and final next-PC are public inputs. The test also checks that
a wrong final PC is rejected.

## Selected-op extension: shifts (done)

`ShiftPcRow` mirrors the ALU row with a `GatedShiftRow` instruction relation and
the same PC-adder/statement encoding. `prove_shift_pc_batch_bits` /
`verify_shift_pc_batch_bits` pass for a 16-cycle SLL batch. Release, width 16:

```text
cycles=64   alu+pc 57,680 B 11.0 s   shift+pc 58,192 B 12.0 s
cycles=256  alu+pc 85,880 B  2.83 s  shift+pc 84,248 B  2.81 s
```

The ALU and shift selected-op proofs are both far below the full gated row
(98,144 B / 5.9 s at 16 cycles) and demonstrate the PC/statement template is
reusable across op subrelations.

## Third selected op: multiply (done)

`MulPcRow` reuses the same PC-adder/statement template with `GatedMulRow`.
`prove_mul_pc_batch_bits` / `verify_mul_pc_batch_bits` pass for a 16-cycle
batch. The multiply subrelation is heavier than ALU/shift:

```text
cycles=64   mul+pc 98,752 B 5.84 s
cycles=256  mul+pc 125,560 B 22.6 s
```

This is expected: the multiplier carries the full product/accumulator relation.
It still avoids the memory/shift/branch/div subrelations and validates the
template across three op classes.

## Fourth selected op: memory (done)

`MemPcRow` reuses the PC-adder/statement template with `GatedMemoryRow`.
`prove_mem_pc_batch_bits` / `verify_mem_pc_batch_bits` pass for a 16-cycle batch.
Release, width 16:

```text
cycles=64   mem+pc 54,232 B 0.42 s
cycles=256  mem+pc 75,632 B 1.66 s
```

This is the cheapest selected-op row so far. It proves the address-arithmetic
and data-gating relation; the BinaryTwist address/value claims are still a
separate layer.

## Branch selected op (done)

`BranchPcRow` links the branch relation's already-selected `next` vector to the
external `next_pc`, and links the external `pc` into both `target_alu.a` and
`seq_alu.a`. This preserves the taken target-PC path without a separate adder.
`branch_pc_batch_round_trips` takes the Beq target `pc+8` on every row and
passes initial/final PC verification. Release, width 16:

```text
cycles=64   branch+pc 75,408 B 2.11 s
cycles=256  branch+pc 96,576 B 6.39 s
```

## ALU virtual specs (done)

`alu_pc_virtual_specs` emits per-cycle segments for:

```text
alu       SegmentOwner::Cpu
pc_add    SegmentOwner::Cpu
pc        SegmentOwner::Pcs
padding   SegmentOwner::Cpu
```

`alu_pc_virtual_specs_partition_the_layout` checks that the emitted source ranges
cover the padded layout exactly once, with no gaps or overlaps. This is the
first selected-op routing table; register/memory/Shifter owners are not emitted
because the ALU-only relation has no such variables.

## Next concrete step

Wire the selected-op specs into claim construction and the unified verifier,
then add the remaining selected-op spec builders.

## Non-goals for the first step

- memory/Shifter claims;
- full unified verifier;
- mixed-op traces.

The first milestone is a sound, PC-linked ALU-only CPU batch proof; mixed-op
specialization follows only after that.


## Div prototype (root cause found and fixed)

A `DivPcRow` using `GatedDivRow` and the same PC-adder template was attempted
and failed at constraint 1755. The root cause was the test input: for `width=8`,
`num=0x120` does not fit the width. `witness_requires_values_within_width`
confirms the relation is false for the overflowing value and true for `0x60`.

The row was re-added with in-range inputs and a real one-bit variable from the
div adder subrelation. `div_pc_batch_round_trips` now passes. Release width 16:

```text
cycles=64   div+pc 99,104 B 6.55 s
cycles=256  div+pc 124,216 B 24.3 s
```

The div row is heavy (it embeds a multiplier), but the PC/statement template is
confirmed across ALU, shift, mul, mem and div.

`SDivPcRow` reuses the same template with `SignedDivRow` and its exposed one
variable; `sdiv_pc_batch_round_trips` passes (16-cycle release test). It is the
heaviest selected-op row, so it is tested but not added to the timing sweep.


### Spec-to-matrix constraint

`build_padded_virtual_layout` pads each selected-op segment to the next power of
two and may move it. The current selected-op proof, however, commits the
original `cycles * base_cols` witness and its matrices use that block stride.
Feeding the per-op specs directly into the proof would therefore mismatch the
matrix column layout.

The next routing step must be a `selected_grouped_virtual_inputs` analogue:
build the padded mapping, remap the witness into the padded layout, and derive
the matrices with the padded block stride (as `reservation_grouped_virtual_inputs`
does for the full gated row). `alu_pc_virtual_specs` is the segment description;
it must not be wired into the current `segment_layout` proof without that
remapping.
