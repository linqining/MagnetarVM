# Trace-free access verification plan

The CPU and gated claims already verify from `CpuStatement { width, shape }`.
Access verification still calls `BinaryTwistWitness::from_trace` and
`register_twist_witness`, so the verifier needs the full trace.

## AccessStatement

Carry the minimum data needed to rebuild the two BinaryTwist witnesses:

```text
ram_base, ram_size
initial_ram
memory_events: (cycle, addr, value, width, is_write)
initial_regs
register_ops: (rs1, rs2, rd, rd_val)
```

This is still linear in the number of accesses, but it is strictly smaller than
the full trace (no instruction decode, PCs, next PCs, CPU values unrelated to
registers).

## Verifier path

1. Build a synthetic `Trace` from the access statement (config, initial RAM,
   memory events, synthetic rows for register ops).
2. Rebuild `BinaryTwistWitness` and `register_twist_witness`.
3. Verify the BinaryTwist claims against the shared commitment.
4. Check the resulting points/values in the opening.

## Why it is not fully succinct

BinaryTwist verification currently needs the table columns to evaluate the
address/boolean claims. A truly succinct access verifier must carry those
evaluations or a commitment to the tables instead. That is the next redesign
after the statement works.

## Order

1. Add `AccessStatement` -> synthetic trace -> verify access.
2. Use it in `verify_cpu_statement` (renamed `verify_core_statement`).
3. Then add Shout/Router/opening statements.
