# Succinct PCS experiment notes

Non-compiled notes only. Nothing here is wired into Cargo or the workspace
libraries.

## Tuned BinaryPcs grid

```text
security_level = 100
log_inv_rate   = 2, 3, 4
pow_bits       = 4, 8, 12, 16, 20
log_folding    = 1, 2, 3, 4 (<= num_variables)
```

Measure for each configuration:

```text
proof bytes
prove time
verify time
config.num_queries()
config.query_security_bits()
```

Accept only if:

```text
query_security_bits + pow_bits >= 100
hash collision security >= 100
sumcheck/opening error accounted
config bound into the transcript
```

## Reference points already measured in the main workspace

```text
P3 opening 128 values:   52,712 B
P3 opening 512 values:   84,472 B
P3 opening 4096 values: 158,752 B
unified P3 opening:     199,744 B
reveal-free unified:      9,976 B  (witness-checked, not production)
```

## API sketch (not compiled)

```rust
pub struct PcsParams {
    pub log_inv_rate: usize,
    pub pow_bits: usize,
    pub security_level: usize,
    pub log_folding_factor: usize,
}

impl P3BinaryPcs {
    pub fn with_params(security_level: usize, params: PcsParams) -> Self { /* ... */ }
}
```

The verifier must receive `PcsParams` (or a hash of it) in the statement.
Changing only the opening schedule preserves `P3MosaicCommitment`'s cap/table
shape, so existing claims need no type change.

## Candidate B sketch

```text
F2^128 evaluation vector
  -> binary-tower RS codeword (p3-binary-dft)
  -> Merkle commitment (Keccak)
  -> fold at F2^128 challenges
  -> query cosets + multiproofs
  -> batch table/point claims
```

Unknowns: exact FRI/Basefold proximity accounting at 100 bits, multi-point
batching, and verifier-circuit cost.

## Candidate C sketch

```text
Merkle row commitment
  -> sumcheck reduction of f(r)
  -> open O(1) rows per table
  -> batch tables/points
```

Research only; no existing implementation in the repo.
