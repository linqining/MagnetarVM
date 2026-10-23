# Packed BinaryShout design note

Status: blocked on protocol design. The existing BinaryShout proof is a working
reference over bit-sliced address tables; simply committing a packed table is
not sound and is not implemented.

## Current proof

`prove_binary_shout` commits one Mosaic table with columns:

- address0 / address1 bit-sliced ROM indices;
- is_32;
- valid;
- read_value columns.

The boolean sum-check proves the address columns are boolean/one-hot; the read
sum-check proves the ROM lookup using folded address bits and folded ROM
columns. The final claims are opened with `P3BinaryPcs::open_mosaic`.

## Why a packed commitment alone is insufficient

A `BitPcs` packed commitment of the address/valid columns can prove an MLE
evaluation at a random point. It does not prove that the committed table is the
same table used by the Shout boolean/read sum-checks, and the Shout equations
are stated over the bit-sliced address columns. Without replacing those
sum-checks (or adding a claim reduction that binds the packed evaluation to the
Shout claims), a verifier can accept an unrelated packed table.

The prototype attempted in this session was removed for that reason.

## Required design

1. Define a packed table layout:
   - 128 address/valid bits per field element;
   - keep ROM columns public;
   - define the bit-to-field basis and row ordering.
2. Replace the address fold and read fold with packed operations:
   - packed linear forms for equality weights;
   - ring-switch claims for each folded address/valid column;
   - explicit claim reduction from bit MLE to packed MLE.
3. Bind the packed commitment to the Shout boolean/read claims:
   - one commitment must be used by both the boolean and read reductions;
   - add a transcript-binding test that rejects a swapped packed table.
4. Update proof serialization and the aux bundle.
5. Bench against the current 137,381 B auxiliary proof.

## Acceptance criteria

- honest packed Shout proof verifies;
- tampered address/valid/read table is rejected;
- same ROM trace as the reference Shout;
- proof size measured against the current aux size;
- no second unpacked commitment in the final bundle.

Until steps 1-3 are designed, `packed BinaryShout` remains open.


## Update: column batching attempt

A grouped packed-table attempt (combined table + address0 + address1 + is32 +
valid) was implemented and rejected. The address columns do not enter the Shout
read check as a multilinear table over the column index: `address_value`
combines the independently folded address-bit columns as a product of
`(1 + bit + k)` factors. Packing the column index into a hypercube dimension
therefore changes the checked value. The grouped implementation produced a
different address evaluation and was reverted.

Consequence: batching packed Shout columns requires a new sum-check that
evaluates the address-bit product from packed coefficients, not a standard 2D
MLE. The per-column packed prototype remains (correct, but 48,481 B vs 17,273 B
reference on the small trace).
