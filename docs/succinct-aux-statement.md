# Shout/Router statement plan

## Current dependency

`BinaryShoutWitness::from_trace` reads:

```text
rom
config (entry/base/size)
row.pc, instruction_word, instruction_len
row.instruction (op/rd/rs1/rs2/imm/shamt)
row.rs2_val (shift amount)
row.mem width (store width)
```

`BinaryRouterWitness::from_trace_mode` reads:

```text
initial_ram
config.ram_base
row.instruction.op
row.mem (addr, width, is_write)
row.rs1_val / rs2_val / rd_val
row.instruction.shamt
```

Both also preprocess the ROM for selector metadata.

## Statement shape

A compact `AuxStatement` can carry:

```text
config
initial_ram
rom
rows: Vec<AuxRow>
```

where `AuxRow` has only the fields above (no PC chain, no reservation, no
syscall, no extra memory).

## Verification path

1. Build a synthetic `Trace` from `AuxStatement`.
2. Build `BinaryShoutWitness` / `BinaryRouterWitness`.
3. Verify the aux proof against the shared commitment and the table index
   already stored in `UnifiedTraceProof` (`shout_index`, etc.).
4. Return the resulting claim points/values for the opening.

## Why this is still not succinct

`BinaryShoutWitness`/`BinaryRouterWitness` verification needs the table columns
to evaluate the boolean/address claims. The statement only moves the linear data
out of `Trace`; it does not remove the linear verifier cost. A truly succinct
aux verifier needs proof-carried evaluations or a different claim system.

## Integration order

1. `AuxRow` + synthetic Trace + witness equality test.
2. Shout claims into `CoreStatement`, then `verify_core_statement`.
3. Router claims into the same statement.
4. Full opening once all aux points are available.
