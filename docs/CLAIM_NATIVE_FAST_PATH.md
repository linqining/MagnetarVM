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


## Workload coverage

`MODE=claim cargo run --example workload_suite` now runs all 15 representative
workloads through claim-native prove/verify, including RAM, mixed memory,
AMO, shifts, clock syscall and loops. The only failure was the `alu` workload
writing `x0`; the verifier now ignores `rd = 0` writes, matching executor
semantics.


## Scale measurements

`ROWS=N cargo run --release -p magnetar-testkit --example claim_native_bench`

| rows | proof | prove | verify | cycles/s |
|---:|---:|---:|---:|---:|
| 1024 | 409,318 B | 7.18 s | 2.94 s | 142.6 |
| 2048 | 680,214 B | 16.72 s | 10.87 s | 122.5 |
| 4096 | 1,214,734 B | 27.49 s | 10.40 s | 149.0 |
| 8192 | 2,267,398 B | 63.81 s | 23.40 s | 128.4 |
| 16384 | 4,349,654 B | 148.48 s | 53.41 s | 110.4 |

For comparison, the paper-path native prover at 4096 rows previously measured
680.6 s / 1.43 MB / 6 cycles/s. The claim-native path is roughly 24x faster
there, but it is not the paper's BinaryShout/BinaryTwist protocol and its proof
is larger.

Determinism: 120 concurrent proof runs, 0 failures.


The P2 segment router now checks cycle ranges in parallel when `cycles >= 1024`
(up to eight workers). At 8192 rows the verifier dropped from 29.8 s to 23.4 s.
A 16384-row run during sustained host load measured 228 s prove / 315 s verify
and is not representative.

Final scale points:

| rows | proof | prove | verify | cycles/s |
|---:|---:|---:|---:|---:|
| 16384 | 4,349,654 B | 148.48 s | 53.41 s | 110.4 |
| 32768 | 8,498,798 B | 203.63 s | 83.30 s | 160.9 |
| 65536 | 16,782,598 B | 418.04 s | 197.69 s | 156.8 |

At 2^16 the paper reports 35 ms / 8 ms / 1.9M cycles/s / 380 KiB. Claim-native
is therefore about 1.2e4x slower on throughput and 44x larger on proof size at
the same row count.


## Proof-size breakdown

At 4096 rows the claim-native proof splits as:

```text
total    1,214,734 B
claim      442,441 B
selected   772,221 B
```

Both parts are linear in row count. At 2^16 the total is 16.8 MB, versus the
paper's 380 KiB at the same row count. The claim proof must carry every
authenticated row claim; the selected proof carries the lockstep opening. The
paper avoids both by reducing to virtual segment claims in BinarySpartan. This
means claim-native cannot reach paper proof size without replacing the
full-trace claim layer, not by serialization tweaks.
