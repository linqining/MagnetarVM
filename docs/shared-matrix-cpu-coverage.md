# Shared-matrix CPU coverage

`gated_rows_from_trace` maps supported rows to `GatedCpuRowInput` and stops at
the first unsupported row, then truncates to the largest power of two below the
row count.

Supported today:

```text
ALU, memory load/store, shift, branch, mul, div, sdiv,
LUI/AUIPC/JAL/JALR (ALU mapping), and addi/addi-family via ALU
```

Not mapped:

```text
Ecall, Ebreak, Fence
AMO ops (Amoswap/Amoadd/.../Amo*)
LR.W/LR.D, SC.W/SC.D
```

Consequences:

1. A trace ending in Ecall loses the tail rows (including Ecall).
2. A trace containing LR/SC/AMO truncates before them.
3. The unified CPU proof still uses the per-row block-diagonal system, so the
   shared-matrix path is only a standalone prototype.

## To complete B

1. Add a `Nop` gated row (or map Ecall/Ebreak/Fence to a satisfiable ALU row).
2. Add LR/SC/AMO gated rows carrying the reservation fields, or prove their
   CPU facets through the reservation claim and exclude them from the shared
   matrix.
3. Pad the row batch to the next power of two with Nop rows instead of
   truncating.
4. Then replace `merged_cpu_system` in `verify_cpu` with
   `gated_claim_inputs`/shared matrices and drop the per-row CPU system.
