# B5 virtual segment protocol

## Problem

The current B5 layer routes CPU witness segment claims by owner, but the owners
do not consume them:

```text
CPU segment claim  = eval of CPU row variables at ry
Ram Twist claim    = eval of RAM table columns at a different point
Router claim       = eval of Router table columns at a different point
Shout claim        = eval of ROM table columns at a different point
```

The values and points differ, so routing metadata alone cannot make a component
consume a segment claim.

## Target protocol

Make the CPU witness a concatenation of component-owned virtual witnesses:

```text
z_cpu = z_pcs || z_ram || z_shift || z_store || z_cpu_only
```

For each owner `o`:

1. the owner commits its table/witness with its own PCS;
2. Virtual Spartan produces a claim `v_o = eval(z_o, ry)`;
3. the component opens its table at `ry` and proves the projection
   `z_o = Proj_o(table)` (or a linear relation fixed by the layout);
4. the CPU relation is checked over the reconstructed `z_cpu`.

The key missing piece is step 3: a fixed projection from each component table to
its virtual segment. Candidate projections:

- Pcs: `z_pcs` is the PC/next-PC bits; PC transition table has the same bits.
- Ram: `z_ram` is the memory row's address/value bits; RAM Twist columns expose
  the same address/value bits at the same row instance.
- Routing(Shifts/Stores): `z_shift/z_store` are the Router selector/output bits;
  Router columns expose them directly.

If a projection is not identity, it must be a **public linear map** recorded in
the layout so the verifier can check it without the trace.

## Migration

1. add `ProjectionKind` and per-owner segment metadata to the layout;
2. split the gated witness construction by owner;
3. make CPU `z` a virtual concatenation and prove the CPU relation over it;
4. open each component table at `ry` with expected values from its virtual
   segment;
5. verify `VirtualClaimRouter` and the projection equalities;
6. only then mark B5 complete.

## Current status

Owner tagging, padded virtual layout, claim routing, and consumption validation
are done. The projection and CPU-relation reconstruction are not.
