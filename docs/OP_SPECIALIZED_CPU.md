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

## Next concrete step

Extend `AluPcRow` to the selected-op relation and add PC statement claims
(initial/final PC), then virtual segment/claim routing for unified.

## Non-goals for the first step

- memory/Shifter claims;
- full unified verifier;
- mixed-op traces.

The first milestone is a sound, PC-linked ALU-only CPU batch proof; mixed-op
specialization follows only after that.
