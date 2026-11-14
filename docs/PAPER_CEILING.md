# Where MagnetarVM stands against its performance ceiling

Snapshot 2026-11-14 (branch `main`, tree through `ca3cb54`). Every number below
is measured on the RV64 benchmark (`paper_unified_bench`, `TRACE_SHOUT=1`) and
every memory change in this file is **byte-identical**: native proof
1,018,155 B (`2^16`), 1,110,291 B (`2^17`), 1,230,360 B (`2^18`); paper-path
proof 1,169,603 B. Full workspace gate on this tree: 675 passed / 0 failed /
8 ignored (39 binaries). The two "streaming PCS commit" rows and the §2 item 1
update are the 2026-11-14 follow-up described in
[MEMORY_PATH](MEMORY_PATH.md) §4.6.

## 1. Current numbers

| | `2^16` | `2^17` | `2^18` |
| --- | --- | --- | --- |
| prove wall (quiet window) | 30.3-31.2 s | 62.6-64.5 s | 133.1 s |
| prove CPU | 280-288 s | 595-604 s | 1240-1277 s |
| verify, v4 statement-only | **10.8 ms** (min 10.5) | - | - |
| verify, paper-path default | 16.4 ms | - | - |
| peak footprint, default schedule | 2.08 GiB | 4.15 GiB | 7.96 GiB |
| peak footprint, `MAGNETAR_SERIALIZE_PRODUCTS=1` | **1.64 GiB** | **3.28 GiB** | **6.05 GiB** |
| peak footprint, default schedule + streaming PCS commit | **1.49 GiB** | - | - |
| peak footprint, products-gated + streaming PCS commit | **1.45 GiB** | **3.03 GiB** | - |
| Commit-stage peak, products-gated | 1.28 GiB | 2.56 GiB | 5.17 GiB |
| Commit-stage peak, products-gated + streaming commit | **0.63 GiB** | **1.28 GiB** | - |
| proof | 1,018,155 B | 1,110,291 B | 1,230,360 B |

The paper-path default configuration (M4b committed Shout) at `2^16` in the
memory mode: proof **1,169,603 B** (unchanged), peak **1.63 GiB footprint**
against 1.97-2.06 GiB with the default schedule, prove CPU 286.4 s, verify
20.3 ms in that loaded window (16.4 ms in the quiet window). So the memory mode
applies to the paper numbers as well, not just the native default.

The paper's verify target (8-12 ms) is **met** (10.8 ms) and the `2^16` prover
is at 30 s / 280 CPU-s from 70.4 s / ~800 CPU-s. Memory is the binding ceiling
for the paper envelope: the `2^22` projection is 26-30 GiB with the current
format, against a 36 GiB host.

## 2. Remaining levers, by measured size

1. **PCS commit / opening codeword transient** — the largest term at every
   scale. Measured at `2^16` (`MAGNETAR_PROFILE_PCS=1`): mosaic commit
   `cells=2,293,918`, `stacked_vars=22`, rate 1/4, 414 ms, codeword ~268 MB +
   tree ~134 MB; a single-column `2^22`-value table at rate 1/8, 250 ms,
   codeword ~536 MB + tree ~134 MB, paid twice (commit and the opening
   re-encode). At `2^18` the Commit point is 5.17 GiB against a 2.24 GiB
   context and the Opening peaks at 5.61 GiB live.
   *Fix, HALF DONE (2026-11-14)*: the **commit-only** entry points
   (`Pcs::commit`, `commit_batch`, `commit_mosaic`) now encode one coset at a
   time and build the Merkle cap incrementally (`crates/magnetar-pcs/src/
   streaming.rs`, [MEMORY_PATH](MEMORY_PATH.md) §4.6). Measured: the `2^16`
   Commit stage **1.28 -> 0.63 GiB**, default-schedule peak **1.90 -> 1.49
   GiB (-22 %)**, products-gated peak 1.64 -> 1.45 GiB; at `2^17` the Commit
   transient 2.56 -> 1.28 GiB and the products-gated peak 3.29 -> 3.03 GiB
   (-8 %, the Opening is now the peak); proof bytes identical
   (1,018,155 / 829,744 / 667,091 B). Whole-prove CPU stayed inside the host's
   ±8 s drift over four interleaved pairs (288.9 vs 295.9 s mean) and the
   isolated commit CPU is identical, so the change is memory-only in practice.
   What is left of the same lever is the **opening-side re-encode**:
   `open`/`open_batch`/`open_mosaic` still materialise the codeword and tree for
   the FRI fold and the query openings, and that is where the `2^16` peak now
   sits (Opening footprint 1.46 GiB). Streaming the fold and the query pass
   over the chunked encoder is the next step, ~-0.3 to -0.5 GiB at `2^16` and
   the larger `2^18` share.
2. **(h) bit-pack the twist witnesses / batch tables** — the twist tables are
   committed as 16-byte field elements although they hold bits (the single
   `2^22`-value commit above is the biggest instance). Bit-packing cuts that
   table and its codeword by ~16x. Effort: days (prover + verifier relation).
   Expected: ~-0.5 GiB at `2^16` if it lands on the same table.
3. **(c) bit-pack the mosaic commitment / (b) 128 -> 64-bit alphabet** — scale
   every committed column and codeword; changes the wire format and the
   documented proof sizes. Effort: multi-day each; needs a decision on
   proof-size/security trade-offs.
4. **Streaming/virtual one-hot Access prover** — the cell-independent factors
   are already stored compactly (Access CPU -19 %, peak -5 % at `2^16`); what
   is left is virtualising the two one-hot address matrices and the value
   matrix, which needs a restructured sum-check over the address bits.
   Effort: days. Expected: the remaining ~0.23 GiB of Access arrays at `2^16`.
5. **`2^19` staircase row** — environment-blocked: needs ~13 GiB free+inactive
   (measured `2^18` peak 6.05 GiB + 4 GiB protocol headroom); the host stayed
   at 7.7-9.4 GiB free+inactive with ~21 GiB of swap used during the sessions.

## 3. What "the ceiling" looks like

* Wall: the `2^16` prover is already within ~10 % of the documented algebraic
  floor for `product6`/`product2`; the next wall win would come from the PCS
  encode/hash (streaming commit also makes the commit ~40 % cheaper in CPU).
* Verify: the 8-12 ms target is met; the remaining ~6.7 ms is the selected PCS
  opening, which needs FRI-side parallelisation in vendored `binary-pcs`
  (CPU-only win, off the critical path today).
* Memory: the routes above are the whole remaining budget. None of them
  changes the *asymptotics*; together they are the difference between the
  current 26-30 GiB `2^22` projection and a runnable paper envelope on a
  36 GiB host. The streaming commit has already removed the commit half of the
  PCS term; the opening half, (h) and (c) are what remain before a `2^22` run.

## 4. Recommended order for the next sessions

1. ~~Streaming PCS commit (largest measured term, byte-identical, no format
   change) -- start with the single-column `2^22` table, then the mosaic batch.~~ **DONE
   2026-11-14** for the commit-only paths: single column, batch and mosaic all
   stream; `-0.41 GiB` default-schedule peak at `2^16`, proof bytes identical
   ([MEMORY_PATH](MEMORY_PATH.md) §4.6). The follow-up under the same lever is
   the **opening-side** re-encode (stream the FRI fold + query pass), which is
   now the tallest remaining PCS term.
2. (h) bit-pack the twist tables (largest remaining *format* win, and it
   compounds with 1).
3. (c)/(b) format change, only after deciding the wire-format break.
4. Virtual one-hot Access prover (finishes the Access term).
5. `2^19` / `2^20` staircase rows in dedicated quiet windows, with
   `MAGNETAR_SERIALIZE_PRODUCTS=1` (still environment-blocked: free+inactive
   stayed at 4-6 GiB on 2026-11-14; a `2^17` row is the practical ceiling).
