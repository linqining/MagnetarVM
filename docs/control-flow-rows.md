# Control-flow rows

Status: design only. LUI and AUIPC are implemented; JAL/branches/JALR are not.

## Why a simple JAL selector is not enough

The gated CPU row currently hard-codes `next_pc = pc + 4`:

- bit 0/1: `next = pc`;
- bit 2: `next = pc + 1`, carry = pc;
- higher bits: ripple carry.

A JAL row must set `next_pc = pc + imm` instead. Adding `is_jal` to the ALU
datapath alone is insufficient: the PC+4 rows still fire and reject the jump.

## Required row changes

1. Add a `sequential` bit:
   ```text
   sequential + is_jal = 1
   ```
2. Gate every PC+4 row by `sequential`:
   ```text
   sequential · (next_pc + pc) = 0        (bits 0,1)
   sequential · (next_pc + pc) = sequential (bit 2)
   sequential · (next_pc + pc + carry) = 0 (higher)
   carry = pc · previous_carry · sequential
   ```
3. Compute the target with the ADD datapath:
   ```text
   a = pc, b = imm, out = pc + imm
   is_jal · (packed(next_pc) + packed(out)) = 0
   ```
4. For branches/JALR, add a taken/select bit and mux `next_pc` between the
   sequential value and the target; branch conditions need their own ALU/compare
   rows (signed/unsigned comparisons and equality).
5. JAL/JALR write `pc+4` to `rd`; the write value must be tied to the CPU row,
   not only to the ALU target output.

The first JAL attempt only added the ALU selector and was reverted because the
PC+4 constraints and `finish()` helper still assumed sequential execution.


## Validated minimal row

`pc_row::SequentialPcRow` now passes for all 256 8-bit pc values and for free
(`sequential=0`) next-PC values. Key fixes found while isolating:

- bit PC and next-PC boolean rows must use an explicit `one` variable, not
  `sequential`;
- carry bits are unconditional ANDs `carry[bit] = pc[bit] & carry[bit-1]`;
- only the next-PC sum rows are gated by `sequential`.

These formulas are ready to be lifted into `GatedCpuRow`.


## Implemented: JAL

The validated PC row was lifted into `GatedCpuRow`:

- `sequential + is_jal = 1`;
- PC+4 sum rows gated by `sequential`;
- carry chain uses unconditional AND rows;
- `is_jal · (a + pc) = 0` and `is_jal · (next_pc + add_out) = 0`;
- `finish()` takes an explicit next PC;
- trace adapter maps `Op::Jal` to the gated ALU row.

Tests cover the ALU target, PC binding, packed companion, trace mapping, and a
two-row gated dual proof. `rd = pc + 4` for JAL is not yet constrained.
