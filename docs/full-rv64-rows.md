# Remaining RV64 row work

Status: design only.

## Branches

A conditional branch needs two independent computations in one cycle:

1. `rs1` vs `rs2` comparison (BEQ/BNE/BLT/BGE/BLTU/BGEU);
2. `pc + imm` target and the sequential `pc + 4` value;
3. `next_pc = taken ? target : pc + 4`.

The current `GatedCpuRow` has one ALU result and one PC adder. Adding branches
therefore requires either a second ALU/comparator row or a row-level mux with
two independent datapaths. Equality needs a full OR-reduction of the XOR bits;
signed/unsigned comparisons can reuse the existing SLT subtractor.

## M extension

MUL/DIV/REM need dedicated datapaths:

- MUL: partial products / multiply-accumulate columns;
- DIV/REM: iterative or restoring division rows over multiple cycles.

These are not selector additions to the current ALU row.

## AMO

AMO needs the load value, ALU operation, store value, and reservation
semantics tied to the RAM Twist claims in the same cycle. This is a combined
CPU/memory row, not a pure ALU row.

## PCS size

The unified proof is ~173 KB, of which ~160 KB is the base P3 opening for the
current commitment shape. Point coalescing, one-point batched Mosaic opening,
and trace-table removal were all measured and gave negligible savings. A
different opening backend is required for a large size reduction.


## Execution order

Chosen order:

1. **A: branch rows** — add a second datapath for branch comparison/target.
2. **B: opening backend spike** — target the ~160 KB P3 opening, not claim routing.
3. **C: M / AMO** — deferred until A lands.
4. **D: recursive verifier** — deferred until the commitment/opening interface is stable.

A starts as an isolated `GatedBranchRow` (BEQ/BNE first), with:

- XOR/OR equality reduction;
- `pc + imm` target adder;
- `pc + 4` sequential value;
- `next_pc = taken ? target : sequential`;
- tests across 8-bit pc/imm/operands before fusing into `GatedCpuRow`.
