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
