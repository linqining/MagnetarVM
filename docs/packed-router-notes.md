# Packed BinaryRouter notes

Status: prototype removed; not yet packed.

## Verified Router shape

Diagnostic against the reference proof established:

```text
INPUT_BITS = 128
BIT_COLUMNS = 201
HQ_COLUMNS = 265
total columns = 266
```

Claim points and column sets:

```text
point 0: 0..201      (split 0..128 + 128..201)
point 1: 0..128
point 2: 128..131
point 3: 131..135
point 4: 265
point 5: 135..137
point 6: 137..201    (only when has_q)
point 7: 201..265    (only when has_q)
```

A diagnostic compared every `(point, column)` value with
`fold_all(table.column, point)` and found zero mismatches.

## Remaining issue

A leaf-batch prototype using these groups passed groups 0-4 but failed on
group 5 (`valid`, columns 135..136): the reference point is empty, while the
packed table evaluation used a padded zero cycle point. The leaf values are
non-zero but the padded MLE selects the wrong cycle. Empty (zero-length) Router
points therefore need a separate evaluation convention before packed Router can
be completed. The prototype was removed rather than shipping a mismatched
opening.


## Follow-up: point 5 is not empty

A direct diagnostic of `prove_binary_router_claims` shows:

```text
point 5 len 1 firstcol 135 firstval 0x6496... fold 0x6496...
```

So the valid group point has one coordinate and its reference value matches
`fold_all(table.column[135], point)`. The earlier "empty point" diagnosis was
wrong. The packed Router failure is therefore in the group 5 packed table
construction (its direct MLE is zero while the table column fold is non-zero),
not in an empty-point convention. That table construction needs a dedicated
debug pass before retrying packed Router.


## Follow-up 2: group 5 bits are correct

For `point 5` on the `slli` trace:

```text
column 135 = [1, 0]
column 136 = [0, 0]
packed group bits = [true, false, false, false]
point 5 = [0x6496...a1]
values 5 = [0x6496...a0, 0]
```

With a zero column challenge, the direct MLE equals the reference leaf. So the
group-5 bits/layout are correct; the earlier failure came from the packed
prototype's column-challenge/point construction, not from the table or an
empty point. The next Router attempt should build the point as
`[r_col, points[5].point]` and verify it against this known-good base case.
