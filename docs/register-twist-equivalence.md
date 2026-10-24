# Register BinaryTwist: two-phase encoding of p=2

The paper specifies one register-file BinaryTwist instance per CPU cycle with
`p = 2` reads (`rs1`, `rs2`) and one write (`rd`).

`register_twist_witness` encodes each CPU row as two Twist sub-cycles:

```text
row t -> subcycle 2t     : read rs1, no write
         subcycle 2t + 1 : read rs2, then write rd
```

## Why this preserves the p=2 semantics

For row `t` with register state `S_t`:

1. Subcycle `2t` reads `S_t[rs1]` and does not write.
2. Subcycle `2t + 1` reads `S_t[rs2]` and does not write before the read.
3. The `rd` write is applied after both reads, producing `S_{t+1}`.

So both reads observe the same pre-row state, and the write is ordered after
both reads, exactly the p=2 read-before-write requirement. The Twist `LT`
predicate orders the three events within row `t`; the next row starts after the
write.

## What is different

The proof has `2 * rows` Twist cycles instead of `rows`, so this is an
encoding/performance gap relative to the paper's single-cycle p=2 layout. It is
not a soundness gap: the two-phase witness is a valid BinaryTwist instance and is
proved by the existing one-read/one-write reduction.

## Test evidence

`register_twist_witness_proves` checks the proof and final register value.
`register_twist_two_phase_shape` checks, for every row, that the two subcycle
read addresses/values and the odd-subcycle write match the trace.
