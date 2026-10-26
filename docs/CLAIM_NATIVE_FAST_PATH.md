# Claim-Native Fast Path

This is a native optimization over the authenticated claim layer. It keeps the
ClaimProof and the proof-only selected-CPU bundle and removes the Access/Shout
proofs, replacing them with linear checks over the authenticated rows.

## What it verifies

- ClaimProof root/count and statement root/trace commitment.
- Proof-only dynamic claim bundle (public matrices + full segment router).
- ROM fetch word/length at each claim PC.
- Register read/write consistency from `statement.initial_state.regs` to
  `statement.final_state.regs`.
- Little-endian RAM read/write consistency from `statement.initial_ram`.
- The final register file equals the statement final state.

## What it does not yet handle

- Syscall write/read/exit binding is implemented directly. The selected dynamic
  prover now uses all trace rows instead of truncating to a power-of-two prefix;
  the `Lui/Addi/Sb + SYS_WRITE + SYS_EXIT` program proves and verifies output
  `"H"`, and the checked-in `hello.elf` now round-trips through claim-native.
- The paper's BinaryShout/BinaryTwist semantics; this is a native claim-layer
  path, not paper parity.
- A third-party audit.

## Point measurements

1024 rows:

```text
proof   409,318 B
prove   7.18 s
verify  2.94 s
```

2048 rows:

```text
proof   680,214 B
prove   16.72 s
verify  10.87 s
```

The 2048 verifier still rebuilds per-cycle component sources in the segment
router; the access/Shout proofs are gone but the router is O(rows * columns).


## Selected-prover row-truncation fix

`mixed_alu_branch_rows_from_trace` used `gated_rows_from_trace`, which truncates
to the largest power-of-two prefix. That silently dropped trailing syscall rows
and caused the selected sumcheck mismatch. The dynamic path now calls
`gated_rows_from_trace_full`; all rows are covered and the IO test passes.


## Remaining blockers

- The paper-path BinaryShout/BinaryTwist linearization is still separate work.
- Third-party audit is not performed.


## Compiled-guest failure narrowed to jumps

The checked-in `hello.elf` trace starts with:

```text
Lui, Auipc, Jalr, Addi, Sd, Sd, ...
```

The dynamic selected row currently has ALU/branch/memory/shift/mul/div
components only. Its ALU component hard-codes `next_pc = pc + 4`, so a `Jalr`
(or `Jal`) target other than `pc + 4` makes the selected sumcheck unsatisfiable.
A dedicated jump component that binds both `rd = pc + len` and an arbitrary
`next_pc` is required before hello guest or compiled-guest coverage can pass.


## JumpPcRow: fixed

`hello.elf` exposed the missing jump path. `JumpPcRow` now binds:

```text
pc + 4 = link
next_pc = target
```

The inactive-row bug was that the adder gate was driven low while the component
still participated in the global PC-mux relation; inactive rows now keep the
adder gate high and set `pc` to the global row PC. `Jal`/`Jalr` map to
`MIXED_JUMP`. The checked-in `hello.elf` proves and verifies through
claim-native with `SYS_WRITE` output.
