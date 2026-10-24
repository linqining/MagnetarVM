# Reservation CPU chain design

## Goal

Move the LR/SC reservation semantics from the verifier-side trace check into the
CPU relation and, eventually, into a cross-row chain constraint.

## Row fields

Each `GatedCpuRow` gets:

```text
pre_valid, pre_addr[width]
post_valid, post_addr[width]
is_lr, is_sc, is_invalidate, is_other
success
```

The row-level relation is the existing `ReservationRow` transition:

```text
LR:        post_valid = 1, post_addr = addr
SC:        success = pre_valid & (addr == pre_addr)
           post_valid = 0
store/AMO: post_valid = 0
other:     post_valid = pre_valid
```

## Cross-row chain

The hard part is that CPU rows are independent instances in the gated batch
proof. Two options:

1. **Shared column + equality constraints** — put the reservation state in a
   column shared by consecutive rows and add equality rows between row `i`'s
   post state and row `i+1`'s pre state.
2. **Separate chain sumcheck** — commit the pre/post sequence and run a sumcheck
   over the link polynomial `post_i == pre_{i+1}`.

Option 1 is preferred because it stays inside the existing gated CPU claim.

## Memory binding

The reservation address must be the same address as the LR/SC memory access,
and a successful SC must write `rs2`. This should reuse the existing memory
claims rather than adding another independent batch proof.

## Integration order

1. Add row fields and row-local transition constraints.
2. Add the chain equality for the row list.
3. Bind LR/SC address/value to memory claims.
4. Remove the standalone reservation batch once the CPU chain is verified.
