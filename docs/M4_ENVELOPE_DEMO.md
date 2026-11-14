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
