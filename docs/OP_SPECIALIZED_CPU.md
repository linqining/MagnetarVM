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

## Selected-op virtual specs (done)

`pc_row_virtual_specs` emits per-cycle segments for the common PC-linked row
shape:

```text
instr     SegmentOwner::Cpu
pc_add    SegmentOwner::Cpu
pc        SegmentOwner::Pcs
padding   SegmentOwner::Cpu
```

Public builders exist for ALU, shift, memory, mul, div and branch selected-op
rows. `selected_pc_virtual_specs_partition_their_layouts` checks every builder's
source ranges cover the padded layout exactly once, with no gaps or overlaps.

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


## Segmented ALU proof (done)

`prove_alu_pc_segmented_batch_bits` builds a padded layout with one segment per
cycle for:

```text
instr     Cpu
pc_add    Cpu
pc        Pcs
padding   Cpu (power-of-two chunks)
```

The witness is remapped into the padded block, the relation is rebuilt on those
mapped variables, and the matrices use the padded block stride. The relation
uses `num_vars = base_cols - 1` so that the shared-matrix block size stays at
`base_cols` (the matrix builder adds one before rounding up).

Test: `alu_pc_segmented_batch_round_trips` (prove + verify, >2 segments).

Release, width 16:

```text
cycles=256  alu+pc-seg segs=1536 proof=110,328 B prove=2.31 s
```

Compared with the unsegmented ALU+PC row at 256 cycles:

```text
unsegmented 85,880 B 3.05 s
segmented  110,328 B 2.31 s
```

The segmented layout costs ~28% proof size because the tiny pc/padding segments
are rounded to powers of two, but it exposes per-op `SegmentClaim`s and is
faster at this size.


### Segmented selected-op rows

The segmented builder is generic over `GatedRowLike`. Public prove/verify pairs
now exist for ALU, shift, memory, multiply, divide and branch. Each remaps the
original witness into the padded per-op layout and rebuilds the relation on the
mapped variables.

`selected_pc_segmented_batches_round_trip` proves/verifies shift, memory and
branch segmented batches (ALU is covered by its own test). If the per-op
segments need more than the original block, the builder grows the block to the
next power of two instead of failing.


## Segment claim routing (done)

`selected_segment_claims` turns a segmented proof plus its layout into named
claims carrying `owner`:

```text
SelectedSegmentClaim { name, owner, value }
```

`selected_claim_values_by_owner` filters them by `SegmentOwner` (Cpu, Pcs,
Memory, Shifting, ...). `segmented_claims_route_by_owner` proves an ALU
segmented batch, checks the claim count matches the layout, and partitions the
claims into Cpu/Pcs groups. This is the claim-side routing table; it is not yet
consumed by the unified verifier.


## Selected claims bundle (done)

`SelectedCpuClaims` packages:

```text
op, width, cycles, initial_pc, final_pc
layout
per-segment claims
segmented LockstepProof
```

`prove_selected_cpu_claims` dispatches to the selected-op segmented provers and
extracts the owner-tagged claims. `verify_selected_cpu_claims` re-extracts the
claims, checks they match the stored bundle, and dispatches to the corresponding
segmented verifier.

`selected_cpu_claims_round_trip` proves, verifies, serializes/deserializes and
verifies again. This is the claim object intended to be embedded in the unified
proof; the unified prover/verifier integration is still pending.


## Unified proof field (plumbing done)

`UnifiedTraceProof` now has:

```text
#[serde(default)]
selected_cpu: Option<SelectedCpuProof>
```

`verify_unified_with_plan` verifies the selected claims when present.
`unified_proof_verifies_attached_selected_cpu_claims` proves a normal unified
trace, attaches a 16-cycle segmented ALU claim bundle under the E5 backend, and
verifies the unified proof.

Important: this is plumbing, not yet a witness binding. The selected claims are
not yet generated by the unified prover, and the verifier does not rebuild the
selected witness from the trace or compare its commitment. The field defaults
to `None`, so existing E5/B6 proofs are unchanged.


## Why unified trace binding needs a mixed-op row

A real trace is not homogeneous by op class: even an ALU-only program has
`Fetch` micro-op rows, and the unified CPU relation maps those through the
branch relation. A homogeneous `SelectedOp::Alu` batch therefore cannot cover
the whole trace; binding `selected_cpu` to the trace requires a selected-op
**set** (e.g. branch + ALU for an ALU-only program) in one relation.

That mixed row needs:

1. a selector per selected component;
2. a global PC/next-PC and a selector mux over each component's next-PC;
3. an inactive witness for every unselected component;
4. claim routing that only expects the selected components.

The current `SelectedCpuClaims` plumbing verifies a single-op proof but does not
yet bind it to a trace witness. This is the concrete next blocker for replacing
the full gated CPU proof.


## Mixed ALU + branch row (prototype)

`MixedAluBranchRow` combines an `AluPcRow` and a `BranchPcRow` with:

```text
global pc / next_pc
select_alu / select_branch (one-hot)
and_alu / and_branch products
next_pc = and_alu XOR and_branch
```

The component PC witnesses are both tied to the global PC, and the selected
component's next-PC drives the global transition. `alu_branch_pc_batch_round_trips`
alternates Fetch (branch, not taken) and ALU rows and passes initial/final PC
verification.

Release, width 16, 256 cycles:

```text
alu+branch mixed proof=112,368 B prove=10.49 s
```

This is the first mixed-op selected row and the prerequisite for binding a real
trace (which contains Fetch rows). It is not yet segmented/claim-routed.


## Trace-bound mixed CPU proof (done)

`prove_alu_branch_trace` / `verify_alu_branch_trace` build the mixed ALU+branch
rows directly from a trace:

```text
gated_rows_from_trace -> Alu or Branch
  -> MixedAluBranchInput
  -> pad to a power of two
  -> selected CPU proof
```

The verifier rebuilds the same witness bits and compares

```text
backend.commitment_bytes(backend.commit(bits))
  == backend.commitment_bytes(proof.commitment)
```

before verifying the proof, so the selected CPU witness is bound to the trace.
The last row is mapped to the branch component when the trace halts at the same
PC (e.g. Ecall), because the ALU row would wrongly advance `pc + 4`.

`alu_branch_trace_binds_witness` executes Addi + Ecall, proves the selected CPU
batch, and verifies it with the commitment check. This is the first sound,
trace-bound op-specialized CPU proof.

### Memory component (done)

The mixed row now also contains a `MemPcRow` with its own selector and product
term; the global next-PC mux XORs ALU, branch and memory products. Trace mapping
converts `GatedCpuRowInput::Memory` into `MixedAluBranchInput::Memory`.

`alu_branch_mem_trace_binds_witness` executes Lui + Lw + Ecall, proves, and
verifies with the commitment check.

### Shift component (done)

`ShiftPcRow` is now a fourth component with its own selector and product term.
`alu_branch_shift_trace_binds_witness` executes Lui + Slli + Ecall, proves, and
verifies with the commitment check.

### Multiply component (done)

`MulPcRow` is a fifth component. Trace mapping accepts only the low unsigned
`Mul` form; `mulh/mulhu/mulhsu` are rejected rather than mis-modelled.
`alu_branch_mul_trace_binds_witness` executes Addi/Addi/Mul/Ecall, proves, and
verifies with the commitment check.

### Divide component (done)

`DivPcRow` is a sixth component. Trace mapping accepts `Div`/`Divu` rows;
signed div/rem still maps to `SDiv` and is rejected. `alu_branch_div_trace_binds_witness`
executes Addi/Addi/Divu/Ecall and verifies the trace-bound proof.
