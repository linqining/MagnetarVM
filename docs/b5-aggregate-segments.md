# B5 aggregate virtual segments

## Problem

The current `reservation_virtual_specs` emits one subsegment per cycle and CPU
field, for example `memory_data0`, `memory_data1`, ...

A Virtual Spartan segment claim is the evaluation of that small segment's vector
at the low part of `ry`. A component bit column (for example one bit of
BinaryTwist `read_value`) is a vector over cycles, so its opening at `ry` is a
weighted sum over all cycles, not the single-cycle bit that the per-cycle
segment claim contains.

The two claim shapes do not match.

## Target

Aggregate each component-owned field across cycles:

```text
memory_data = concat_cycle(data_bits(cycle))
memory_addr = concat_cycle(addr_bits(cycle))
```

The segment length is `cycles * field_width` (a power of two), and the component
table column is built with the same cycle-major order. Then:

```text
segment claim at ry[..log2(len)]
= component column eval at ry[..log2(len)]
```

unconditionally, because both are the same vector.

## Source-gather layout

The aggregated vector is not contiguous in CPU z. Extend the virtual spec:

```text
VirtualSegmentSpec {
    name,
    sources: Vec<(original_offset, len)>,
    owner,
    projection,
}
```

`pad_values` concatenates all source ranges into the segment; `unpad_values`
scatters them back. The CPU-only ranges remain per-cycle segments.

## Migration

1. add `sources` to `VirtualSegmentSpec`/`VirtualSegmentMap`;
2. emit aggregated `memory_data`/`memory_addr` specs;
3. build matching component columns from full-cycle BinaryTwist;
4. replace those segment claims with component column evals at `ry`;
5. verify CPU relation over the reconstructed virtual witness.

## Why not per-cycle segments

Per-cycle owner bits cannot be replaced by a component column opening without
opening every cycle bit separately, which defeats succinctness.
