# Linear Shout attempt: rejected prototype

Status: rejected and removed.

## What was tried

A standalone LinearShout proof committed:

```text
address0 bits + read columns
```

proved address bitness with one sum-check, and checked at a random cycle point:

```text
sum_c gamma_c * read_c(r)
  = sum_cell (sum_c gamma_c * ROM[cell][c])
      * prod_bit (1 + address_eval[bit] + cell[bit])
```

## Why it is wrong

For `a > 1`, the right-hand side is **not** the multilinear extension of
`G(address(j))`. The MLE of a product of address-bit functions is not the
product of the individual MLEs, so the random-point identity is unsound for
ROMs larger than two cells.

The Addi benchmark passed only because its address space was small; the
checked-in `hello.elf` failed the identity check. The code and benchmark were
removed rather than left as an unsound claim.

## What is needed instead

A correct linear BinaryShout needs either:

- a committed one-hot read table (linear proof size only if the PCS can commit
  sparse one-hot columns compactly), or
- a sum-check over the full cell x cycle domain with a prover that exploits the
  sparse address structure, or
- the paper's specific table-lookup argument, where table evaluation is part of
  the sum-check rather than a pointwise commitment-opening check.

The virtual claim / BinarySpartan scaffold remains; no performance claim is made
for linear Shout until the sound version lands.
