# C1 instruction expansion plan

## Current state

`preprocess` emits one `BytecodeRow` per instruction with `micro_pc = rv_pc`.
`preprocess::expand_bytecode` now turns rows into scheduled `MicroOp`s:

```text
MicroOpKind::Fetch
MicroOpKind::Execute
```

The current encoder is the **identity expansion**: one `Execute` micro-op per
instruction, `micro_pc == rv_pc`. The executor still produces one trace row per
instruction, so `trace_rows_fetch_the_bytecode_micro_pc` holds.

## Target

An instruction may expand to several scheduled micro-ops:

```text
Fetch (optional) -> Decode (optional) -> Execute
```

Each micro-op has a distinct `micro_pc`; `rv_pc` is the architectural PC.
The bytecode/Shout table is keyed by `micro_pc`, and `TraceRow` carries both
`rv_pc` and `micro_pc`.

## Required changes

1. **Trace row**
   - add `micro_op: MicroOpKind`, `micro_pc: Word`, `rv_pc: Word`;
   - `pc` becomes the architectural PC of the row's micro-op.

2. **Executor**
   - `step` emits one or more trace rows per fetched instruction;
   - `Fetch` rows do not change architectural state; `next_pc = pc`;
   - `Execute` rows perform the current semantics;
   - PC linkage: `next_pc(fetch) = pc(execute)` when a fetch row is emitted.

3. **CPU relation**
   - add a `fetch`/`nop` selector to `GatedCpuRow`;
   - constrain `next_pc = pc` and no register/memory writes when `fetch = 1`;
   - keep the existing sequential/branch/jump constraints for `Execute`.

4. **Bytecode table**
   - `expand_bytecode` assigns contiguous `micro_pc`s;
   - `preprocess::bytecode_row` looks up by `micro_pc`;
   - Shout reads the row selected by the trace row's `micro_pc`.

5. **Statement / shape**
   - `CpuShapeRow` gains `micro_pc` and `micro_op`;
   - `CpuShape::system_without_trace` emits the fetch/execute constraints.

## Tests

```text
expand_bytecode -> unique micro_pc per row, rv_pc preserved
trace -> every row's micro_pc has a bytecode row
fetch row -> no state change, next_pc == pc
execute row -> current semantics
gated bundle -> PC tamper still rejected
chunked/unified -> traces with fetch rows prove and verify
```

## Why this is staged

The proof layer already accepts arbitrary trace length and PC chains. The risk is
the executor/CPU relation change: adding Fetch rows doubles trace rows for every
instruction and requires a new row selector. The data model and identity
expansion are in place so this can land behind the same `MicroOp` API.
