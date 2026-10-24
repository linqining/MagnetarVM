# Proof-carried access evaluations

## What the current verifier computes from the witness

`verify_binary_twist_claims` needs:

```text
address columns: addr[bit], valid flags
increments column
initial memory vector
read_value vector
write_value vector
```

From these it computes boolean/read-initial/read-history/write-base/write-update
terminal values and the Mosaic opening points.

## Which of these are committed

The shared Mosaic commitment has:

```text
table[table_index]     : address columns
table[table_index + 1] : increments
```

`initial`, `read_value`, and `write_value` are witness vectors and are **not**
committed by BinaryTwist today. The verifier recomputes their folded values from
the witness, so removing the witness loses the binding.

## Required change

Before the access verifier can be trace-free/succinct:

1. commit the initial memory vector (or bind it to the statement/commitment);
2. commit `read_value` and `write_value` tables;
3. store the folded evaluations for the verifier challenges in the proof;
4. add opening points for those new tables so the evaluations are bound by the
   shared opening.

Then `verify_binary_twist_claims_from_proof` can replace witness access with
proof-carried values.

## Why not just store evaluations in the proof

Storing `bit_evals`, `m0_eval`, `claimed_read`, `claimed_write` without committing
the underlying vectors would let a prover choose consistent but false values.
The evaluations must be opened from committed tables.

## Order

1. Extend `BatchTables` with initial/read/write value tables.
2. Add proof fields for their evaluations at the verifier challenges.
3. Add the corresponding Mosaic points.
4. Replace witness access in the verifier.
5. Repeat for Shout/Router value tables.
