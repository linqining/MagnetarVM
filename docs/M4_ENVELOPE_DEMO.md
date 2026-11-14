# M4 feasibility demo: 64-bit committed alphabet vs the 2^22 memory envelope

Branch `m4-envelope-demo`, snapshot 2026-11-14. Purpose: decide whether the M4
milestone from [PAPER_CEILING §4](PAPER_CEILING.md) ("(b) 64-bit committed
alphabet + a different commitment family") is worth a protocol-level
implementation, by measuring the real streamed commit + streamed opening
pipeline over both alphabets instead of estimating from table arithmetic.

Run:

```sh
cargo build --release -p magnetar-pcs --example m4_envelope_probe
CASES=scale RATE_LOG=2 target/release/examples/m4_envelope_probe   # ladder
CASES=cells RATE_LOG=2 target/release/examples/m4_envelope_probe   # equal arity
CASES=target RATE_LOG=2 target/release/examples/m4_envelope_probe  # 128-bit 2^26
CASES=target64 RATE_LOG=2 target/release/examples/m4_envelope_probe # 64-bit 2^27
```

`cases` are `small`, `scale`, `cells`, `target`, `target64`, `all`. Every case
streams the codeword (cap only, one 2^15-row subtree at a time), then runs the
production streamed opening (`BinaryPcs::open_at_streaming`) and **verifies**
the proof with `PrescribedPointPcs::verify_at`, so a case is only reported when
commit and opening agree. The root builder is a single-threaded reduced copy of
`streaming.rs`'s root (the production root itself is pinned against
`MerkleTreeMmcs` by `streaming_root_matches_mmcs`); it is used here because the
demo needs it generic over the alphabet.

## 1. Measured (single process per case, macOS, `RATE_LOG=2`, fold=2)

`cell` is the committed arity (`2^log`), `message` the message bytes,
`peak` the process high-water mark, `proof` the serialized opening.

| case | cells | message | wall | peak RSS | footprint | proof B |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 128-bit, 2^22 | 4.19 M | 64 MiB | 5.1 s | 416 MiB | 415 MiB | 249,592 |
| 64-bit, 2^22 | 4.19 M | 32 MiB | 5.7 s | 485 MiB | 484 MiB | 247,952 |
| 64-bit, 2^23 | 8.39 M | 64 MiB | 12.1 s | 766 MiB | 764 MiB | 269,784 |
| 128-bit, 2^23 | 8.39 M | 128 MiB | 10.4 s | 922 MiB | 1,025 MiB | 268,064 |
| 64-bit, 2^24 | 16.8 M | 128 MiB | 23.5 s | 1,463 MiB | 1,449 MiB | 287,320 |
| 128-bit, 2^24 | 16.8 M | 256 MiB | 21.1 s | 1,976 MiB | 1,969 MiB | 289,984 |
| 128-bit, 2^25 | 33.6 M | 512 MiB | 38.3 s | 3,124 MiB | 3,134 MiB | 312,920 |
| 64-bit, 2^25 | 33.6 M | 256 MiB | 51.7 s | 3,255 MiB | 2,599 MiB | 309,536 |

Two comparisons matter:

* **Equal committed arity** (the envelope question: same cells, different
  alphabet): at `2^25` cells, footprint 3,134 -> **2,599 MiB (-17 %)** and the
  proof 312,920 -> **309,536 B (-1.1 %)**. RSS is flat within the host's swap
  drift. So a 64-bit base shrinks the pipeline, but nowhere near the 2x the
  message bytes alone would suggest.
* **Equal message bytes**: 128-bit `2^23` (128 MiB message, 8.39 M cells) vs
  64-bit `2^24` (128 MiB message, 16.8 M cells): footprint 1,025 -> **1,449
  MiB (+41 %)**. At a fixed *message budget* the 64-bit alphabet is worse,
  because rate and leaf count are per cell, not per byte.

Wall time: the 64-bit base is **~35 % slower** in this probe (51.7 s vs 38.3 s
at `2^25` cells) on the `LchNtt` tower path; the 128-bit base runs
`PolyBasisNtt`. That is encoder work, not an inherent cost of the alphabet.

## 2. Where the bytes go (coefficients)

The streamed sequence has three passes: commit (cap), fold, query. Each
allocates roughly a message-sized scratch (and the encoder returns another
message-sized matrix), so the process peak over the whole sequence fits

```text
    peak_footprint ≈ 6.1 × message_bytes + fixed overhead
```

at `2^25` cells (3,134 MiB for a 512 MiB message; the production pipeline at
`2^20` cycles — 0.5 GiB mosaic message, measured 7.66 GiB RSS including a
4.87 GiB context — gives the same ~5.6x coefficient for its opening stage).

Why the 64-bit base only halves *part* of it: the message and one scratch are
in the base alphabet (halved), but the fold outputs live in the 128-bit
challenge field (`+0` on that term), the Merkle leaves are one digest per row
(unchanged count), and the query pass re-encodes the base message again
(halved). The measured -17 % at equal arity is that mix.

## 3. Projection to the paper envelope (2^22 cycles)

Current mosaic: 35·C cells, C = 2^22 -> 146.8 M cells -> `next_pow2` 2^28
cells. With the measured `6.1 × message` coefficient and the measured context
term (2^20: 4.87 GiB RSS at C = 2^20; ~4.6-4.9 KiB/cycle, i.e. ~19-21 GiB at
2^22):

| configuration | message | pipeline | context | total (projected) |
| --- | ---: | ---: | ---: | ---: |
| current (128-bit, 2^28 cells) | 4 GiB | ~24 GiB | ~19-21 GiB | **~43-45 GiB** |
| + (h)-committed bit packing (47 M cells -> 2^26) | 1 GiB | ~6 GiB | ~17-19 GiB | ~23-25 GiB |
| + 64-bit alphabet | 0.5 GiB | ~3-4 GiB | ~15-17 GiB | ~18-21 GiB |
| envelope target | - | - | - | **6.4 GiB** |

The first line is the same verdict the docs already carry (2^22 does not fit a
36 GiB host with the current format). The demo adds the *ordering*: bit-packing
the committed cells buys far more than the alphabet change, and even the two
together leave the envelope ~3x away. The residue is dominated by (i) the
three-pass scratch pipeline (inherent to "commit, fold, query" each needing the
message) and (ii) the context.

## 4. Verdict

* **(b) is technically feasible now.** The streamed commit + streamed opening
  path already works over a `BinaryField64` base with 128-bit challenges: every
  case above verified, and proofs are ~1 % smaller. No protocol change was
  needed for this demo because the demo commits one column without a
  claim/verifier layer.
* **(b) alone is not the M4 win.** At equal committed arity it is -17 %
  footprint (and -35 % wall in this probe, fixable with NTT work); M4 as
  "alphabet + different commitment family" should keep the commitment-family
  half, because the 6.4 GiB envelope needs the pipeline reduced from ~6x to
  ~2x message and the context by ~3x.
* **Rescope M4**:
  1. **M4a — (h)-committed/(c) cell packing first**: 146.8 M -> ~47 M cells
     shrinks message, codeword, fold outputs and resident mosaic tables
     together; this is where the 4x is, and the demo confirms message size is
     the pipeline's only large driver.
  2. **M4b — 64-bit alphabet on top**: a further -17 % at equal arity,
     -1 % proof, needs the F64 NTT path measured for wall (the probe shows the
     tower encoder is currently slower; production uses `PolyBasisNtt` for
     F128).
  3. **M4c — single-pass/out-of-core opening (the real "different commitment
     family")**: only a design that removes the three message-sized passes can
     reach the 6.4 GiB envelope with a ~2 GiB context; FRI/STIR-style codeword
     handling or an out-of-core encode is the lever, not more packing.
* **Measurement caveats**: host was swapping during the larger cases
  (`free+inactive` 6-11 GiB), so footprint is inflated on the largest runs and
  its exact value should be re-quoted in a quiet window; RSS is the more stable
  number here. The probe is single-threaded, unlike the production pipeline, so
  its wall times are not comparable to `paper_unified_bench`.

## 5. What was committed on this branch

* `crates/magnetar-pcs/examples/m4_envelope_probe.rs` — the demo and its
  measured cases.
* this document.

## 6. M4c demo: prover-side out-of-core codeword cache

The M4c direction was "remove the three message-sized passes of the streamed
opening". The demo validates the concrete variant that needs **no protocol,
proof or verifier change**: encode the codeword once, spill it to a temporary
file while hashing the Merkle cap, then stream the file back for the fold pass
and for the query pass (rows + pruned multiproof). The codeword bytes are the
same, so the proof is the same; only the prover's peak and its disk I/O change.

`crates/magnetar-pcs/examples/m4_oot_probe.rs` (one case per process; the peak
is monotonic, so two cases in one process would report retained pages):

```sh
LOG=25 CHECK=1 CHUNK_MIB=32 target/release/examples/m4_oot_probe
```

Every case checks end to end that the encode-pass cap agrees with the
file-backed multiproof (`verify_multi_batch`), and with `CHECK=1` also compares
**cap, folded codeword and pruned multiproof symbol for symbol** against an
in-memory commit of the same message; all cases reported `verified=true
in_memory=Some(true)`.

Measured (128-bit base, `RATE_LOG=2`, 32 MiB read chunks, pipeline peak sampled
before the optional in-memory check):

| cells | message | codeword file | pipeline peak RSS | encode | fold | query |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 2^20 | 16 MiB | 64 MiB | 162 MiB | 0.93 s | 0.23 s | 0.20 s |
| 2^22 | 64 MiB | 256 MiB | 309 MiB | 3.41 s | 0.89 s | 0.87 s |
| 2^23 | 128 MiB | 512 MiB | 500 MiB | 7.22 s | 1.75 s | 1.35 s |
| 2^24 | 256 MiB | 1 GiB | 888 MiB | 13.6 s | 3.93 s | 3.25 s |
| 2^25 | 512 MiB | 2 GiB | 1,659 MiB | 30.3 s | 8.94 s | 6.76 s |

Against the in-memory three-pass pipeline of §1/§2 (same cells, same rate,
`RATE_LOG=2`): `2^23` 922 -> **500 MiB (-46 %)**, `2^24` 1,976 -> **888 MiB
(-55 %)**, `2^25` 3,124 -> **1,659 MiB (-47 %)**. The asymptotic coefficient
drops from `~6.1x` to `~3.2x` message bytes: the two extra encode passes are
gone, and what remains is the encode pass itself — message plus one
message-sized coset scratch (and its NTT staging), i.e. `~2x` message plus the
read/write chunk buffers. (At `2^20` the fixed ~100 MiB process baseline
dominates and the win is only ~26 %.)

Costs:
* the codeword file is `2^rate_log x message` on disk (2 GiB at `2^25` cells,
  16 GiB for the `2^22`-cycle mosaic message at rate 1/4), written once and
  read twice — acceptable on the local SSD but a new operational constraint;
* the extra wall time is the I/O plus a serialized encode in this probe; the
  production encoder is parallel, so the incremental cost would be the file
  traffic, not the encode.

### 6.1 What this means for the envelope

Projection to `2^22` cycles (mosaic message `2^28` cells today, 4 GiB at
128-bit), adding the out-of-core factor to the table in §3:

| configuration | message | pipeline (`~3.2x`) | context | total |
| --- | ---: | ---: | ---: | ---: |
| current | 4 GiB | 12.8 GiB | ~19-21 GiB | ~32-34 GiB |
| + (h)-committed cell packing | 1 GiB | 3.2 GiB | ~17-19 GiB | ~20-22 GiB |
| + 64-bit alphabet (M4b) | 0.5 GiB | ~1.6-2 GiB | ~15-17 GiB | ~17-19 GiB |
| envelope target | - | - | - | **6.4 GiB** |

So the out-of-core cache is a real, proof-identical `-47 %` on the pipeline and
it removes the need for a *different commitment family* to get the pipeline
term down — but it does not by itself reach 6.4 GiB: after it, the envelope is
context-bound. The remaining `~3x` must come from the resident context ((c)
committed-cell packing shrinks the mosaic tables, (d) lifetime/dedup, (b)
alphabet) and from the encode-pass floor (message + one coset; only a
sub-coset streaming NTT or a writer that consumes the transform's own buffers
could push that below `2x`).

### 6.2 M4 recommendation after both demos

1. **M4a — (h)-committed/(c) cell packing**: the common multiplier for message,
   pipeline and resident mosaic tables.
2. **M4c — out-of-core codeword cache**: prover-only, proof-identical, `-47 %`
   pipeline; no format change; adopt after M4a (it pays off in proportion to
   the message that M4a leaves).
3. **M4b — 64-bit alphabet**: only if the context remains the blocker after
   M4a/M4c; it is worth ~17 % of peak at equal arity and needs the F64 NTT/verifier
   path.
4. **FRI/STIR-family change**: still the only way to shrink the *context*
   depend on the commitment design; but the pipeline half of the envelope can
   be solved without it. If the context work (M4a + (d) + (b)) lands, the
   6.4 GiB envelope may be reachable without changing the proof format at all.

Caveats: the probe is single-threaded and its wall times are not comparable to
`paper_unified_bench`; the host was swapping during some of the larger runs; the
`2^22`-cycle message is 4x the largest probe case, so the projection is a
coefficient fit, not a measurement.

## 7. M4a prototype: bit-packing the committed twist address tables

M4a is the cell-packing lever: the unified mosaic commits each twist `addr`
table as `2*address_bits + 2` bit columns with **one 16-byte field element per
bit**. At RV64 `2^16` the two 12-column address tables are 1.57 M of the
2.29 M mosaic cells (69 %), and the table is `12 x 2*cycles`, so the share is
scale-free. `crates/magnetar-pcs/examples/m4a_packed_mosaic_probe.rs` measures
both halves of the change.

### 7.1 Part A — cells and memory (streamed commit + streamed opening)

It rebuilds the `p3_stage_probe::mosaic()` replica (the same table list the PCS
benchmarks use; at `LOG=16` it reproduces the production 2,293,918 cells
exactly), commits and opens it through the real `P3BinaryPcs`, and reports the
same run with the two 12-column address tables packed 128 bits per cell:

| cycles log | variant | cells | stacked vars | message | peak RSS | commit | open | proof |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2^16 | current | 2,293,918 | 22 | 64 MiB | 534 MiB | 630 ms | 1,668 ms | 234,552 B |
| 2^16 | packed | **733,342 (-68 %)** | **20** | **16 MiB (4x)** | **148 MiB (-72 %)** | 170 ms | 436 ms | 197,584 B (-16 %) |
| 2^18 | current | 9,175,672 | 24 | 256 MiB | 2,086 MiB | 1,716 ms | 7,033 ms | 278,848 B |
| 2^18 | packed | **2,933,368 (-68 %)** | **22** | **64 MiB (4x)** | **541 MiB (-74 %)** | 671 ms | 1,982 ms | 237,912 B (-15 %) |

All four openings verify against the MLE of every opened column. The message
crosses a power of two, so the stacked-message/Codeword buffer is **4x**
smaller, the whole probe is ~-73 %, and the proof is ~15 % smaller (fewer
columns to open: 12 dense cells per packed row open as one cell instead of 12
bit cells).

### 7.2 Part B — the verifier relation exists already

A packed address table is a table of 128-bit words, not of 0/1 cells, so the
Access verifier must evaluate the *bit* vector without unpacking it. The repo
already owns that machinery: `magnetar_proof::RingSwitchPackedBitPcs` commits
256+ bits as `len/128` field elements and proves an MLE evaluation of the bit
vector with a ring-switch sum-check. Part B runs it on all 12 address columns:

| bits log | columns | packed cells | unpacked cells | commit | largest opening | wall | verified |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 2^16 | 12 | 6,144 | 786,432 (128x fewer) | 1,056 B | 54,168 B | 116 ms | yes |
| 2^20 | 12 | 98,304 | 12,582,912 (128x fewer) | 1,056 B | 97,896 B | 968 ms | yes |

Every opening verifies and the claimed value equals the MLE of the unpacked bit
column. So the soundness half of M4a needs **no new cryptography**.

### 7.3 What M4a still needs, and the projection

The remaining engineering, in order:

1. **Batch the per-column ring-switch proofs.** Part B's per-column opening is
   54 KB at `2^16` bits and 98 KB at `2^20` bits; 12 columns would add
   0.65-2.4 MB to the proof. The Access relation must be re-derived in terms of
   the eq-weighted combination the ring-switch claim provides (one claim for the
   whole packed table, like packed Shout's batched claim), or the 12 columns
   must be packed into one bit vector with the column index as extra variables.
   This is the real M4a protocol work.
2. **Shape and schedule change.** Packed rows are `2^(log-7)`, so the mosaic
   table shape (`num_variables`, `num_columns`), the mosaic opening schedule and
   the verifier's per-table checks all move; the proof format changes, so a
   version bump and new goldens replace the byte-identical gate.
3. **Applicability.** This demo packs the two dominant 12-column tables. The
   real table set also has small bit tables and the router/Shout columns; the
   production mosaic profile should be extended to print per-table cells first,
   so the packing order (and whether routers/Shout qualify) is decided from
   measurements, not the replica.

Projection to `2^22` cycles (mosaic = 2,293,918 x 64 = 146.8 M cells today):

| mosaic at 2^22 | cells | stacked message | Part-A peak coefficient | mosaic pipeline |
| --- | ---: | ---: | ---: | ---: |
| current | 146.8 M | 4 GiB | ~8.2x | ~33 GiB |
| M4a packed | **46.9 M** | **1 GiB** | ~8.4x | **~8.4 GiB** |

(The Part-A coefficient includes table construction plus commit plus open, so it
is larger than the `6.1x` opening-only coefficient of §2; it is used here as a
same-method A/B.) Adding the out-of-core cache of §6 (`~3.2x` of the message)
puts the packed mosaic at `~3.2 GiB`. The envelope then depends on the
non-mosaic context, which is what M4b/(d) must shrink; M4a is the single largest
reduction available at any scale and the only one that shrinks the *message*
itself.

## 8. M4a on the real table set: composition, dedup, and the verifier scheme

The §7 prototype packed a synthetic replica. This step profiles the **real**
unified mosaic on the paper benchmark (`MAGNETAR_PROFILE_PCS=1
MAGNETAR_PROFILE_LOCAL=1`) to decide what actually pays.

### 8.1 Measured composition (streamed opening, products-gated)

`2^16` (12 tables, 2,293,918 cells, 22 stacked variables):

| # | rows | cols | cells | bit cols |
| --- | ---: | ---: | ---: | ---: |
| 0 | 2 | 12 | 24 | 12/12 |
| 1 | 2 | 1 | 2 | 1/1 |
| 2 | 32 | 2 | 64 | 2/2 |
| 3 | 2 | 1 | 2 | 1/1 |
| 4 | 2 | 1 | 2 | 1/1 |
| 5 | 65,536 | 12 | 786,432 | **7/12** |
| 6 | 65,536 | 12 | 786,432 | **12/12** |
| 7 | 65,536 | 1 | 65,536 | 0/1 |
| 8 | 32 | 2 | 64 | 1/2 |
| 9 | 65,536 | 1 | 65,536 | 0/1 |
| 10 | 65,536 | 1 | 65,536 | 0/1 |
| 11 | 524,288 | 1 | 524,288 | 0/1 (trace) |

Access batch: `15 x 65,536 = 983,040` cells, **12 bit columns**.
`2^18` has the same shape (mosaic 9,175,198 cells, access batch 3,932,160
cells, 12/15 bit columns) — the composition is scale-free.

Three findings the replica could not show:

1. **Table 6 is the fully bit-valued 12-column table** (register-twist address
   columns): 786,432 cells at `2^16`, 3,145,728 at `2^18` — 34 % of the mosaic
   at both sizes, and packable 128:1.
2. **Table 5 has only 7 of its 12 columns bit-valued** (the remaining five are
   scalar columns), so it must be **split** before packing: the 7 bit columns
   pack, the 5 scalar columns stay.
3. **The trace table (11) is the largest single table** (524,288 at `2^16`,
   2,097,152 at `2^18`, and 33.5 M at `2^22`), and it is not bit-valued — it
   is eight 64-bit trace fields per row in 16-byte cells.
4. **The Access batch re-commits the same 12 bit columns** that table 6
   commits (`build_columns` derives them from the same witness), so the bit
   data is currently committed **twice** (786,432 + 786,432 cells at `2^16`).

### 8.2 The packed plan and the padding boundary (real table set)

`crates/magnetar-runtime/src/m4a_probe.rs` rebuilds the real table set from the
paper trace through the same private builders the prover uses (RAM-twist batch
tables, ROM table, register-twist batch tables, trace table), and it
**reproduces the production profile exactly** at `2^16` (2,293,918 mosaic
cells). Run it with:

```sh
cargo test -p magnetar-runtime --release m4a_real -- --ignored --nocapture
```

Projected committed cells and stacked-message sizes (step 1 = register address
table packed, step 2 = ROM bit columns split/packed, step 3 = Access batch
bit columns dropped): stepping 1-2 gives only **2x** at every size because the
mosaic lands just above a power of two; the trace packing (step 4) is what
crosses the boundary and delivers **4x**:

| cycles | current cells | msg | after steps 1-2 | msg | after step 4 | msg | Access batch | msg |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2^16 | 2,293,918 | 64 MiB | 1,058,462 | 32 MiB | **796,318** | **16 MiB (4x)** | 983,040 -> 196,608 | 16 -> **4 MiB** |
| 2^18 | 9,175,198 | 256 MiB | 4,233,374 | 128 MiB | **3,184,798** | **64 MiB (4x)** | 3,932,160 -> 786,432 | 64 -> **16 MiB** |
| 2^22 | 146,800,798 | 4 GiB | 67,731,614 | 2 GiB | **50,954,398** | **1 GiB (4x)** | 62,914,560 -> 12,582,912 | 1 GiB -> **256 MiB** |

Combined committed cells at `2^22` (mosaic + Access batch): **209,715,358 ->
63,537,310 (-70 %)**. The trace table (33.5 M cells at `2^22`) is the second
largest term after the two 12-column tables and is the one that decides the
padding crossing, so it must be part of M4a rather than a later optimisation.

#### 8.2.1 Measured, not projected: real table set through the PCS

`m4a_pcs_peak` in the same test module applies the packing to the real tables
and runs the shipped streamed commit + streamed opening:

```sh
LOG=18 PACKED=0 cargo test -p magnetar-runtime --release m4a_pcs_peak -- --ignored --nocapture
LOG=18 PACKED=1 cargo test -p magnetar-runtime --release m4a_pcs_peak -- --ignored --nocapture
```

| cycles | variant | tables | cells | stacked vars | message | peak RSS | footprint |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 2^16 | current | 12 | 2,293,918 | 22 | 64 MiB | 581.8 MiB | 579.5 MiB |
| 2^16 | M4a packed | 13 | 796,318 | 20 | 16 MiB | **225.2 MiB (-61 %)** | **222.7 MiB (-62 %)** |
| 2^18 | current | 12 | 9,175,198 | 24 | 256 MiB | 2,162.9 MiB | 2,186.3 MiB |
| 2^18 | M4a packed | 13 | 3,184,798 | 22 | 64 MiB | **853.4 MiB (-61 %)** | **799.5 MiB (-63 %)** |

The measured peak tracks the projected 4x message reduction (the commit+open
coefficient is ~8.5x message in both variants; the table count grows because the
ROM table is split into its bit and scalar halves). This is a memory isolation:
the openings are opaque PCS openings, so the Access claims/verifier wiring is
not yet part of the run, and only the mosaic commit+open phases are measured.

Combined committed cells at `2^22` (mosaic + Access batch): **209,715,358 ->
63,537,310 (-70 %)**. The trace table (33.5 M cells at `2^22`) is the second
largest term after the two 12-column tables and is the one that decides the
padding crossing, so it must be part of M4a rather than a later optimisation.

### 8.3 Verifier scheme decision

The Access relation needs **individual** address-bit evaluations (the summand
multiplies the bit factors; `onehot_formula` takes a product over bits), so a
single packed commitment cannot serve it with one evaluation — a packed
evaluation is a linear combination over slots, and the verifier cannot soundly
choose an isolating point. Two schemes were considered:

* **Chosen: one ring-switch claim per bit column**, all against the *single*
  packed 12-column table (the same commitment the statement binds; the Access
  batch keeps only its 3 scalar columns). `RingSwitchPackedBitPcs::open` gives
  exactly one bit column's MLE at the cycle point, and §7.2 measured the
  per-column proof sizes: 54 KB at `2^16` bits, 98 KB at `2^20` bits
  (extrapolating ~150-200 KB at `2^22` bits). For 12-19 columns that is
  **~1-3 MB extra proof** at `2^22`, to be traded against the `~25 GiB` this
  route removes; it also removes the duplicate commitment (-786 k cells at
  `2^16`).
* **Rejected: column-index-as-variables with one claim.** It proves a fixed
  eq-weighted combination of the columns, not the individual values, and the
  product over bits in the Access summand cannot consume that combination
  without a different relation.

Follow-up implementation order for M4a:

1. split mixed tables by bit-ness in `BinaryTwistWitness::batch_tables` output
   (table 5), and pack the bit tables 128:1;
2. commit the packed bit table once and route both the mosaic statement binding
   and the Access ring-switch claims through it (delete the duplicated Access
   bit columns);
3. pack the trace table 2x (two 64-bit fields per 16-byte cell; the byte layout
   and opening compatibility need their own demo);
4. re-derive the Access verifier to check 12-19 ring-switch openings plus the
   scalar-column PCS batch, and budget the proof-size increase explicitly;
5. version-bump the proof format and replace the byte-identical gate with golden
   sizes plus the ring-switch verification tests.

Profile prints added for this step: `MAGNETAR_PROFILE_PCS=1` now prints one
`pcs mosaic table <i>: rows=... cols=... cells=... bit_cols=...` line per table
plus a packing projection, and `MAGNETAR_PROFILE_LOCAL=1` prints the Access
batch shape (`local access tables: ... bit_cols=...`).

## 9. M4a step 2 prototype: the ring-switch proof/verify budget

The Access verifier needs individual evaluations of the 12 address-bit columns
(and the ROM's 7 bit columns if packed), so the pack-over-128 hits them one
column at a time. This step measures the three candidate batching schemes before
touching the protocol. All numbers come from
`crates/magnetar-pcs/examples/m4a_packed_mosaic_probe.rs`:

```sh
RUN=partB LOG=18 COLUMNS=12 target/release/examples/m4a_packed_mosaic_probe  # per-column, separate commitments
RUN=partC LOG=18 COLUMNS=12 target/release/examples/m4a_packed_mosaic_probe  # per-column, one shared commitment
RUN=partD LOG=18 COLUMNS=12 target/release/examples/m4a_packed_mosaic_probe  # one batched opening
```

### 9.1 Per-column ring-switch, separate commitments (part B)

One opening per bit column, 12 columns:

| bits log | packed cells (12 cols) | unpacked cells | one opening | 12 openings |
| --- | ---: | ---: | ---: | ---: |
| 2^16 | 6,144 | 786,432 | 54,168 B | **648,160 B** |
| 2^18 | 24,576 | 3,145,728 | 76,560 B | **918,720 B** |
| 2^20 | 98,304 | 12,582,912 | 97,597 B | **1,171,168 B** |
| 2^22 | 393,216 | 50,331,648 | ~120 KB (measured on one column) | **~1.44 MB** |

Verification (measured on the shared-commitment variant, per claim): ~20 ms for
12 claims at `2^16` and ~25 ms at `2^18`. That is on top of the current
10.8 ms statement-only verify, so the naive scheme **fails the 8-12 ms target**
by itself; it would also grow the `2^22` proof from ~1.8 MB to ~3.2 MB.

### 9.2 Per-column ring-switch, one shared commitment (part C)

Packing all 12 columns (padded to 16) into **one** bit vector and opening each
column at the basis point of its column index saves 11 commitment roots (1056 B
-> 88 B) but makes every opening pay for the whole 16-column packed vector:

| bits log | packed cells | one commitment | total openings (12) | verify (12) |
| --- | ---: | ---: | ---: | ---: |
| 2^16 | 8,192 | 88 B | **1,172,544 B** | 20.3 ms |
| 2^18 | 32,768 | 88 B | **1,445,680 B** | 24.9 ms |

Each evaluation is still correct (`verified=true`, value equals the bit column's
MLE), but the proof is *larger* than the separate-commitment scheme and the
verify cost is the same. **Rejected.**

### 9.3 Batched sumcheck + one PCS opening (part D)

The 12-19 claims share one product2 sumcheck when combined with random
coefficients (the standard batching of `sum_b lambda_b P_b(alpha) A_b(alpha)`),
so they collapse to **one evaluation point** and **one PCS batch opening** of
the 12 packed-word columns plus their 12 `a_values` columns (the latter are
derived from the sent `s_hat_v` and can also be recomputed by the verifier, so
this is the conservative shape):

| bits log | height of opened columns | proof | commit | open | verify |
| --- | ---: | ---: | ---: | ---: | ---: |
| 2^16 | 2^9 | 106,776 B | 12.9 ms | 94.9 ms | **1.74 ms** |
| 2^18 | 2^11 | 131,392 B | 23.1 ms | 136.6 ms | **2.15 ms** |
| 2^20 | 2^13 | 164,504 B | 47.5 ms | 177.9 ms | **3.34 ms** |
| 2^22 | 2^15 | **199,072 B** | 178.6 ms | 286.8 ms | **3.51 ms** |

The batched opening is both **~7x smaller and ~6x cheaper to verify** than the
naive per-column scheme, and its size grows only logarithmically.

### 9.4 Decision

* **Adopt: batched product2 sumcheck + one PCS batch opening** for all 12-19 bit
  claims. Budget at `2^22`: +~199 KB of PCS opening, +12 * 128 field elements of
  `s_hat_v` (24.6 KB; 38.9 KB for 19 claims) and the sumcheck rounds, i.e.
  **~+0.24 MB (~+13 %)** on the current ~1.8 MB proof, and **+~3.5 ms** verify
  if kept as a separate batch.
* **Fold the batch into the mosaic commitment** where possible: the packed-word
  columns have arity `L-7` (2^15 at `2^22`), which is just another table arity
  for the mosaic, so the same opening proof can cover them. Then the PCS verify
  cost is already paid and M4a's verify overhead is only the batched sumcheck
  (~0.5-1 ms), keeping the 8-12 ms target.
* Rejected: naive per-column proofs (proof +0.65-1.44 MB, verify +20-25 ms) and
  the shared-single-commitment/per-column-opening variant (larger proof, same
  verify cost).
* Remaining implementation steps are unchanged: wire the packed tables into
  `batch_tables` (split by bit-ness, dedup the Access batch), implement the
  batched sumcheck in `bit_pcs`, version-bump the proof format, then re-measure
  at `2^18` with a real proof (peak and proof size) before evaluating `2^22`.

Caveat: part D's timings are single-threaded and use the PCS directly; the
production verifier's absolute numbers must be re-measured after integration.

## 10. M4a step 1: the packed-table module (representation implemented)

`crates/magnetar-runtime/src/m4a_tables.rs` now owns the prover-side
representation change, so the protocol wiring can call one place instead of
re-implementing bit packing per consumer:

| function | what it does |
| --- | --- |
| `pack_bit_column` / `unpack_bit_column` | 128 bits per cell, lowest bit first, zero-padded to a multiple of 128 rows |
| `packed_bit_table` | one table from equally long bit columns |
| `split_and_pack` | split a mixed table (the ROM is 7/12 bit columns) into a packed bit table and a scalar table, returning the bit-column indices |
| `pack_twist_tables` | the five twist tables with the address table packed |
| `pack_access_batch` | the Access batch as three scalar columns plus **one** packed bit table, in the Access column order |
| `pack_word_pairs` / `unpack_word_pairs` | the trace table's two 64-bit fields per cell (rejects fields wider than 64 bits) |

Verified in-tree:

* unit tests: `unpack(pack(x)) == x` at lengths 128/256/1000/4096/65536 (all
  padding cases), non-bit rejection, word-pair round trip plus the 64-bit guard,
  and split-and-pack preserving the scalar half exactly;
* on the real `2^16` paper trace: mosaic cells **2,293,918 -> 796,318**
  (exactly the M4a projection), the Access batch goes from **15 columns to 3
  scalar columns plus one packed bit table** (12 columns), and every Access bit
  column is **byte-identical** to the mosaic address table's packed column, so
  the bit data is committed once instead of twice; the unpacked read-bit and
  read-valid columns match the witness columns element for element;
* the peak measurement (`m4a_pcs_peak`) now runs this production packing code
  rather than local helpers: `2^16` peak 561.8 -> **222.8 MiB** footprint.

Status: representation only. The protocol still commits the unpacked tables, the
proof format is unchanged, and the Access verifier still reads the unpacked PCS
batch. The remaining M4a work, in order:

1. batched product2 sumcheck in `magnetar-proof::bit_pcs` (the scheme chosen in
   §9), with the 12-19 individual bit evaluations as its outputs;
2. wire `m4a_tables` into `protocol.rs`/`local_shared` (packed tables, one bit
   commitment, Access claims against it), version-bump the proof format;
3. trace-table consumption demo (the byte layout of §10's word pairs has to be
   read by the trace verifier, not just measured);
4. re-measure a real proof at `2^18` (peak + proof size) and then evaluate
   `2^22`.

## 11. M4a step 2 implemented: the batched ring-switch

The budget of §9 is now a working primitive rather than a simulation.

**`magnetar-proof`:**

* `prove_product2_batched(left, right, weights, challenge)` — proves
  `sum_b weight_b * sum_x left_b(x) * right_b(x)`. Each round polynomial is the
  weighted sum of the per-pair degree-two polynomials, so the batched check is
  still degree two and verifies with the existing `verify_rounds`.
* `BatchColumnPcs` trait — commits several equally tall columns and opens them
  all at one point with a **single** proof.
* `BatchedRingSwitch` / `BatchedRingSwitchOpening` — one proof proves the MLE
  evaluation of every packed bit column at the same cycle point. The transcript
  binds the batch commitment, the point, all `s_hat_v` vectors, then samples one
  weight per column and the row-batch challenges; the packed columns are opened
  once, at the folded point.

**`magnetar-pcs`:** `P3BatchColumnPcs` implements the trait over `P3BinaryPcs`
(`commit_batch` / `open_batch_with_cap` / `verify_batch`), so the 12 packed
address columns share one cap and one opening.

**End to end** (`RUN=partE` in the M4a probe, 12 columns, claims checked against
each column's bit MLE, proof verified):

| bits log | one proof | commit | prove | verify |
| --- | ---: | ---: | ---: | ---: |
| 2^16 | 119,736 B | 11.1 ms | 60.6 ms | **1.93 ms** |
| 2^18 | 144,480 B | 20.0 ms | 200.5 ms | **2.39 ms** |
| 2^20 | 174,872 B | 29.9 ms | 87.3 ms | **2.86 ms** |
| 2^22 | 204,336 B | 81.1 ms | 156.8 ms | **3.32 ms** |

Against the §9 candidates: the implemented scheme is **~10x smaller and ~10x
cheaper to verify** than the per-column-shared-commitment variant (2^18:
144,480 B / 2.39 ms vs 1,445,680 B / 24.9 ms), and within the §9.3 simulation
budget (the ~25 KB difference is the twelve 2 KB `s_hat_v` vectors plus the
sum-check rounds). At `2^22` the addition is **~200 KB of proof and ~3.3 ms of
verify**, or about 1 ms if the packed-column batch is folded into the same
mosaic opening as planned.

Tests in the gate (not ignored): the batch proves every column's MLE, and it
refuses a tampered claim, a tampered packed value and a foreign commitment.

Status: the Access verifier can now be switched to this primitive. Remaining:

1. wire `m4a_tables` + this batched proof into `protocol.rs`/`local_shared`
   (packed tables, one bit commitment, Access claims against it) and version-bump
   the proof format;
2. trace-table consumption demo (the word-pair byte layout read by the trace
   verifier, not just measured);
3. re-measure a real proof at `2^18` (peak + proof size), then evaluate `2^22`.

## 12. M4a step 3: trace word-pair packing semantics — demo result

The §8.2 projection assumed the trace table could be halved by storing two
64-bit fields per cell (the `pack_word_pairs` helper). That was a memory-only
measurement; this step checks the semantics the verifier would need, and the
answer is **no**: concatenation packing cannot feed the trace claims.

`trace_word_pair_packing_is_not_evaluation_preserving` in
`m4a_tables.rs` shows why:

* concatenation **is** F2-linear on the bit pattern — packing a sum is the sum
  of packings (`pack(p + q) == pack(p) + pack(q)`), which is what makes it
  look promising;
* but the multilinear extension does **not** commute with it: for a trace-shaped
  column (8 rows x 8 fields, 64 values -> 32 packed cells), the trace claim
  lives on 6 variables and the packed table on 5, and neither the truncated nor
  any shifted point of the packed table reproduces the trace evaluation — so a
  verifier holding a packed opening cannot check the existing trace claims;
* this is structural: the packed value is a bit concatenation, an F2-linear but
  not F2^128-linear map, while the PCS opening is an F2^128-linear functional.
  There is no field-linear relation to exploit.

Consequence for the plan:

* `pack_word_pairs` stays a **memory-experiment helper** (it is what
  `m4a_pcs_peak` uses for the packed peak) and must **not** be wired into the
  protocol until an evaluation argument exists for it.
* The clean way to halve the trace table is the **64-bit committed alphabet**
  (M4b): the evaluation stays a field-linear map (challenges remain 128-bit), so
  the trace claims keep their meaning. That is consistent with §6's measurement
  (equal-arity peak -17 %) and with §9.4's decision to keep M4b for the context
  term.
* **Projection correction**: at `2^22` the mosaic message after M4a steps (a)-(c)
  is 2 GiB (`2^27` cells) — a 2x reduction. Reaching the 4x / 1 GiB figure
  requires the trace term to shrink too, i.e. M4b's 64-bit alphabet; without it
  the M4a-only envelope improvement is 2x on the message and the ~62 % committed
  cell reduction. The rest of §8.2 stands (the cell-count arithmetic and the
  padding boundary).

So M4a's remaining protocol work is (1) wire the packed address tables and the
batched ring-switch into `protocol.rs`/`local_shared` with a proof-format bump,
and (2) decide whether the trace table gains the 64-bit alphabet together with
M4b or waits for a separate evaluation argument.

## 13. M4a protocol wiring, first evidence: the Access bit claims are drop-in equal

Before changing the proof format, this step checks that the Access verifier can
consume the batched ring-switch output **without changing any of its checks**.

`m4a_access_bit_claims_match_the_pcs_terminal_values` runs the existing Access
prover on the real `2^16` paper witness, takes the terminal values its verifier
consumes (`proof.values[3]` — the 12 address-bit evaluations the PCS batch opens
at `virtual_challenges`), then proves the same 12 evaluations from the **packed**
bit table (built by `m4a_tables::pack_access_batch`, i.e. the deduplicated 12
columns) with one `BatchedRingSwitch` proof at the same point:

* all 12 ring-switch claims equal the PCS terminal values element by element;
* the batched proof verifies;
* the proof is **120,152 B** at `2^16` cycles and 12 columns.

So the verifier's product formula (`terminal[bit]`, `terminal[address_bits]`,
...) can be fed from the ring-switch claims unchanged. What remains is
structural, not semantic:

1. drop the 12 bit columns from the Access PCS batch (15 -> 3 scalar columns),
   so the PCS opening shrinks at every point;
2. carry the packed bit commitment + batched ring-switch opening in
   `LocalSharedProof` behind a version tag (`MAGNETAR_M4A_ACCESS` for the A/B),
   and have `verify_local_shared` take `terminal` from the ring-switch claims;
3. measure the **net** proof-size change after that wiring: the ring-switch proof
   is ~120 KB at `2^16`, while the PCS opening loses 12 columns x 4 points, so
   the two run in opposite directions and the net has to be measured (the PCS
   part grows with `cycles` while the ring-switch part grows logarithmically, so
   the balance should improve with scale);
4. then re-measure a real proof at `2^18` (peak + proof size).

The M4a pieces are now all available: the packed-table module (§10), the batched
ring-switch (§11, with its proof-size budget), the trace-packing negative result
(§12) and this Access drop-in equivalence. The next change is the gated protocol
wiring and the proof-format version bump.

## 14. M4a step 1 budget: the Access replacement costs ~+9 % of the full proof

`m4a_access_opening_size_budget` measures the actual replacement parts (no
format change yet): run the existing Access prover, then build the M4a
alternative on the same witness — a 3-column scalar batch (three point groups
instead of four) plus one batched ring-switch over the 12 packed bit columns at
the virtual point — and verify both.

| cycles | old Access opening | old Access total | scalars batch | bits commitment | bits ring-switch | new Access total | delta | on the full proof |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2^16 | 174,632 B | 219,208 B | 152,160 B | 48 B | 120,152 B | 272,360 B | **+97,728 B** | +9.6 % (of 1,018,155 B) |
| 2^18 | 206,240 B | 251,552 B | 175,544 B | 48 B | 145,408 B | 321,000 B | **+114,760 B** | +9.3 % (of 1,230,360 B) |

The surprising part: dropping twelve columns from the Access batch saves almost
nothing (206,240 -> 175,544 B at `2^18`), because a PCS batch opening is
query/path-dominated, not column-dominated — the 12 address columns ride along
on the same query paths. The batched ring-switch therefore adds nearly its full
size (~145 KB at `2^18`), and the Access component grows ~+45 %.

**Verdict: acceptable, but only because the denominator is the full proof.** On
the whole proof the change is **+9.3-9.6 %** (1.23 MB -> ~1.35 MB at `2^18`),
against M4a's **-62 % of committed cells** (`2^22` mosaic message 4 GiB -> 2 GiB,
or 1 GiB with M4b's 64-bit trace). That is the trade to record; it also says the
implementation should:

* keep the batched ring-switch opening as its own component (do not try to fold
  it into the Access batch — the heights differ: `cycles/128` vs `cycles`);
* look for a later optimisation merging the ring-switch's final PCS opening into
  the *mosaic* proof (mixed table heights are supported there), which would
  remove most of the extra ~145 KB;
* keep the old path behind the switch for A/B until the full proof is
  re-measured at `2^18` with a real serialized proof.

Remaining M4a work: implement the gated `MAGNETAR_M4A_ACCESS` wiring in
`local_shared` (new proof variant with the packed bit commitment + batched
opening, verifier reading `terminal` from the ring-switch claims), version-bump
the proof format, and re-measure a real proof at `2^18` (peak + size).

## 15. M4a Access proof v5: packed bit table wired into a real proof

The Access prover now has a second, versioned proof type that actually drops the
duplicated bit columns and proves them with the batched ring-switch:

* `M4aAccessProof` (in `local_shared.rs`, `M4A_ACCESS_VERSION = 5`) carries the
  3-column scalar batch (`increment`, `read_value`, `write_value`), the packed
  bit commitment, the `BatchedRingSwitchOpening` and its 12 claims, plus the
  unchanged sum-check/endpoint fields.
* `prove_access_m4a` builds the Access batch from
  `m4a_tables::pack_access_batch` (15 columns -> 3 scalar columns + one packed
  bit table), absorbs both commitments into the
  `magnetar-local-shared-m4a-v5` transcript, runs the same sum-checks, opens the
  scalars at three points and the packed bits with one batched ring-switch at
  the virtual point.
* `verify_access_m4a` verifies the scalar batch and the ring-switch, then feeds
  the verifier's existing product formula from the ring-switch claims instead of
  `values[3]`; the rest of the checks are unchanged.

Verified at `2^16` cycles:

* round trip: proof verifies, the version tag is 5;
* the 12 claims equal the real address-bit MLEs at the proof's virtual point
  (recomputed from the witness);
* a tampered claim or a tampered scalar value is refused;
* serialized size 316,796 B vs the old Access proof's 219,208 B
  (+97,588 B = +9.6 % of the full `2^16` proof), matching the §14 budget.

**Peak and wall** (Access prover only, one process per variant):

| cycles | variant | peak RSS | footprint | wall |
| --- | --- | ---: | ---: | ---: |
| 2^16 | old 15-column batch | 732.3 MiB | 729.9 MiB | 2,272 ms |
| 2^16 | **M4a packed** | **368.8 MiB (-50 %)** | **366.1 MiB (-50 %)** | **1,704 ms (-25 %)** |
| 2^18 | old | 2,625.5 MiB | 1,094.9 MiB | 10,484 ms |
| 2^18 | **M4a packed** | **1,442.2 MiB (-45 %)** | 1,429.1 MiB | **5,805 ms (-45 %)** |

(The `2^18` footprint columns disagree with RSS — the host was swapping and the
sampler saw different moments; RSS is the stable number there.)

So the Access component trades **+9.6 % of the full proof** for **-45…-50 % of
its peak and a large wall win**, which is exactly the M4a trade at work. The
remaining M4a step is to call `prove_access_m4a` from the unified prover behind
`MAGNETAR_M4A_ACCESS`, wire the bit commitment into the statement root, and
re-measure `paper_unified_bench` at `2^18` (full-proof peak and size).

## 16. M4a end to end: the unified prover runs the packed Access path

`MAGNETAR_M4A_ACCESS=1` now routes the unified prover's Access stage through
`prove_access_m4a`: `BinaryTwistRamProof` carries a new `linear_m4a` field
(`BinaryTwistLinearM4aProof`, version 5), the verifier prefers it and checks the
outer claims with `m4a_access_outer_claims` (bit values from the ring-switch
claims). The proof format is bumped: the field is always serialized, so the
default proof grows by exactly **+2 bytes** (one Option tag per twist proof) —
`2^16` 1,018,155 -> 1,018,157 B, `2^18` 1,230,360 -> 1,230,362 B.

End-to-end A/B (`paper_unified_bench`, `TRACE_SHOUT=1`, products-gated,
streamed opening):

| metric | default | `MAGNETAR_M4A_ACCESS=1` |
| --- | ---: | ---: |
| proof, 2^16 | 1,018,157 B | 1,115,281 B (**+9.5 %**) |
| proof, 2^18 | 1,230,362 B | 1,347,398 B (**+9.5 %**) |
| Access component, 2^18 | 254,222 B | 369,082 B |
| Access stage wall, 2^18 | 15.6 s | **8.7 s (-44 %)** |
| Access stage RSS, 2^18 | 2.93 GiB | **2.53 GiB** |
| peak footprint, 2^18 | 3.52 GiB | **3.25 GiB (-8 %)** |
| prove CPU, 2^18 | 1306.5 s | 1260.3 s (-3.5 %) |
| verify, 2^16 (2x interleaved) | 66.2 / 78.7 ms | 74.6 / 60.2 ms (noise) |

The isolated Access verification costs **+2.6 ms** (`verify_access_m4a` 6.19 ms
vs `verify_local_shared` 3.61 ms at `2^16`), and interleaved unified runs show
no verify penalty beyond host noise. The proof-size increase is exactly the
§14 budget (+9.5 % of the full proof).

So the M4a delivery is now real: an opt-in unified proof that commits the
address bits once (128:1 packed) and verifies them with one batched
ring-switch, trading +9.5 % proof for a ~44 % shorter Access stage and a smaller
peak. Remaining M4a work:

1. fold the batched ring-switch's PCS opening into the mosaic opening (the
   packed-word tables have arity `L-7`, a valid mixed-height mosaic table), which
   should recover most of the +9.5 %;
2. decide on M4b's 64-bit alphabet for the trace term (needed for the `2^22`
   1 GiB message; without it the message reduction is 2x);
3. re-check verify in a quiet window (the target is 8-12 ms) and measure the
   full `2^22` projection once the context work lands.

## 17. M4a evaluation: what it buys, and the 2^22 verdict

Measured Access prover peak/wall (one process per variant; RSS is the stable
number, the footprint columns drift with the host's swap state):

| cycles | old peak RSS | M4a peak RSS | old wall | M4a wall |
| --- | ---: | ---: | ---: | ---: |
| 2^16 | 732.3 MiB | **368.8 MiB (-50 %)** | 2,272 ms | **1,704 ms (-25 %)** |
| 2^18 | 2,625.5 MiB | **1,442.2 MiB (-45 %)** | 10,484 ms | **5,805 ms (-45 %)** |
| 2^19 | 4,172.1 MiB | **2,884.7 MiB (-31 %)** | 20,236 ms | **9,242 ms (-54 %)** |

Together with §16's unified A/B (proof +9.5 %, Access stage -44 % wall, whole
peak -8 % at `2^18`, isolated Access verify +2.6 ms), that is the M4a result:
the address bits are committed once at 128:1 in the Access batch and verified
with one batched ring-switch, instead of a 15-column PCS batch.

### 17.1 `2^22` projection (measured coefficients, not guesses)

| configuration | mosaic cells | message | pipeline (~6.1x) | context | projected peak |
| --- | ---: | ---: | ---: | ---: | ---: |
| today (default) | 146.8 M | 4 GiB | ~24 GiB | ~19-21 GiB | ~28-33 GiB |
| **+ shipped M4a Access** | 146.8 M | 4 GiB | ~24 GiB | ~19-21 GiB | **~28-33 GiB (whole peak unchanged; Access stage -31..-50 %)** |
| + full statement dedup (pack the mosaic address table, drop it from the statement) | 67.7 M | 2 GiB | ~12 GiB | ~17-19 GiB | ~20-22 GiB |
| + M4b trace alphabet | 50.9 M | **1 GiB** | ~6 GiB | ~15-17 GiB | **~17-19 GiB** |
| paper envelope | — | — | — | — | **6.4 GiB** |

Proof size at `2^22`: the current trend is 1.23 MB (`2^18`) -> 1.59 MB
(`2^20`), so ~2.0-2.2 MB; M4a's +9.5 % adds **~0.2 MB**, which matches the
measured batched-ring-switch curve (204 KB at `2^22` bits).

### 17.2 Verdict

* **The objective's M4a items are done as scoped**: packed bit tables in the
  protocol (Access batch goes 15 -> 3 columns), the deduplicated bit commitment
  proven by one batched ring-switch instead of per-column PCS openings, the
  explicit proof-size budget (+9.5 % of the full proof), the trace-packing
  semantics demo (negative result: concatenation is not evaluation-preserving;
  halving needs M4b's 64-bit alphabet), and the real-proof re-measure at `2^18`.
* **The 6.4 GiB envelope is still ~3x away.** M4a's Access half does not move
  the `2^22` whole-proof peak because that peak lives at the mosaic Opening; it
  buys a 44-54 % shorter Access stage and a much smaller Access working set.
  The remaining 3x is, in order: statement-level dedup (which is what turns the
  packed bits into a *mosaic* cell reduction), M4b's 64-bit alphabet for the
  trace term (the difference between a 2 GiB and a 1 GiB message), and the
  context term (the dominant 15-21 GiB at `2^22`, untouched by M4a).
* The proof-size cost of the packed Access (+9.5 %) can mostly be recovered by
  folding the batched ring-switch's PCS opening into the mosaic opening (the
  packed-word tables have arity `L-7`, a valid mixed-height mosaic table); that
  is the recommended next optimisation after the statement dedup.

Caveats: the `2^18`/`2^19` footprint columns are unreliable on this host (swap);
the `2^22` rows are coefficient projections, not measurements; verify must be
re-checked in a quiet window.

## 18. 2^19 unified A/B, and the statement-dedup follow-up

`2^19` cycles (`ADDS=524287`, products-gated, streamed opening):

| metric | default | `MAGNETAR_M4A_ACCESS=1` |
| --- | ---: | ---: |
| proof | 1,373,710 B | 1,507,298 B (**+9.7 %**) |
| Access component | 265,550 B | 398,994 B |
| Access stage wall | 16.5 s | **7.0 s (-57 %)** |
| prove CPU | 2597.4 s | 2504.0 s (-3.6 %) |
| peak footprint | 6.36 GiB | 6.52 GiB (host-swap noise; the stage peaks moved by <0.4 GiB in opposite directions) |
| verify | 507 ms | 326 ms (loaded window, not comparable) |

This confirms the `2^18` picture at the largest scale that fits this host: the
Access stage halves its wall and the proof grows by the budgeted ~9.7 %; the
whole-proof peak is noise-dominated at this size because the peak lives in the
mosaic Opening, which M4a's Access half does not touch.

### 18.1 What statement-level dedup would take (not shipped)

The packed bits are currently committed in the Access proof, but the **mosaic
still commits its own 12-column unpacked address table**, so the bit data is
still committed twice and the mosaic message is unchanged. Removing the mosaic
table (and dropping the Address outer claims in favour of the ring-switch
claims) would give:

| size | mosaic cells today | after dropping the address table | message today | message after |
| --- | ---: | ---: | ---: | ---: |
| 2^18 | 9.18 M | 6.03 M | 256 MiB | **128 MiB** |
| 2^19 | 36.7 M | 24.1 M | 1 GiB | **0.5 GiB** |
| 2^22 | 146.8 M | 96.5 M | 4 GiB | **2 GiB** |

It is a real protocol change, not a flag flip, because the packed commitment
must be **bound into the statement**: with the mosaic table gone, the address
values exist only as ring-switch claims against `bits_commitment`, and the
verifier must tie that commitment to the public statement. Two candidate binding
points and their caveats:

* fold a digest of `bits_commitment` into the composed claim root
  (`composed_statement_root`), which both prover and verifier already compare
  against `proof.trace_claim_root`. Cleanest, but the prover must build the
  Access proof before the statement root is fixed (it currently builds the
  statement first), and every statement producer/consumer needs the new digest.
* reuse the mosaic commitment's unused `binding: [u8; 32]` field and have the
  verifier recompute it from the Access proof. Cheap, but the mosaic commitment
  object is proof-carried, so this only helps if the verifier also proves that
  binding is statement-consistent — the claim/opening chain currently ties the
  mosaic commitment to the statement through points and claims, which needs a
  dedicated soundness argument.

Because a wrong choice here is a soundness bug rather than a performance
regression, this is left as a follow-up with its own binding analysis and a
full verifier audit, not a same-round flag.

The `2^22` envelope after that dedup is ~2 GiB message and ~20-22 GiB peak
(§17.1); the last 2x needs M4b's 64-bit alphabet for the trace table, and the
context term (15-21 GiB) still dominates.
