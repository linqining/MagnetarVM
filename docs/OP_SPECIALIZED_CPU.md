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

## First prototype (reverted)

`AluPcRow` combined:

- a `GatedAluRow` instruction relation;
- a second `GatedAluRow` used as a PC adder (pc + 4 -> next_pc);
- equality links from `pc` to the adder's `a`, constants into `b`, and
  `next_pc` to the adder's `out`;
- PC/next-PC Boolean constraints.

The row witness failed its own constraint check with:

```text
constraint 453: lhs=1 rhs=0
```

so the PC-adder/link encoding is wrong or incomplete. It was reverted rather
than wired into the CPU proof. The ALU-only (no PC) prototype remains available
as a performance bound.

## Next concrete step

Replace the second ALU adder with an explicit bit-level increment relation:

```text
pc[0] = pc[1] = 0
next_pc[0] = next_pc[1] = 0
carry_2 = 1
for bit >= 2:
  next_pc[bit] = pc[bit] XOR carry
  carry_{bit+1} = pc[bit] AND carry
```

with explicit XOR/AND temporary vars, then check the row witness locally before
running any proof. Only after this passes should the specialized relation be
wired into gated matrices/layout/claims.

## Non-goals for the first step

- memory/Shifter claims;
- full unified verifier;
- mixed-op traces.

The first milestone is a sound, PC-linked ALU-only CPU batch proof; mixed-op
specialization follows only after that.
