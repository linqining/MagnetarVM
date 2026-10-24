# Shared CPU row width

`GatedCpuRow::new(8)` currently has 7330 bit variables:

```text
alu    224
mem     91
shift  284
branch 959
mul   1271
div   1745   (contains another GatedMulRow + 2 ALUs)
sdiv  2695   (contains another GatedDivRow + 4 ALUs)
```

The nesting is the main size lever:

```text
div  = mul + 2*alu
sdiv = div + 4*alu
```

so a single row carries several copies of the multiply/add machinery.

## Options

1. Share one multiply relation and one adder relation across mul/div/sdiv,
   gating their outputs with selectors. This is the paper-style uniform row but
   changes the relation construction significantly.
2. Keep the nested rows but decrease `width` below 8. The current CPU bit width
   is already 8; going lower would break RV64 semantics.
3. Move div/sdiv to a separate per-op proof and keep the shared row free of
   those components. This reintroduces a small non-shared proof but shrinks the
   packed z table a lot.

The ring-switched gated opening is 71,577 B of the 138,640 B total, so reducing
the row width is still the largest remaining size lever.
