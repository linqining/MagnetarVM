# MagnetarVM

English | [简体中文](README.zh-CN.md)

A 15-crate RV64 zkVM workspace structured after the Magnetar paper (IACR ePrint 2026/2423). The paper is available at [papers/magnetar-2026-2423.pdf](papers/magnetar-2026-2423.pdf).

## Status

This is a **compilable, testable architecture scaffold plus a P0 vertical slice**. It is not a usable zkVM, and it is not a secure implementation.

Implemented:

- RV64I base ISA (including the `*W` word operations), RV64M multiply/divide, RV64A AMO/LR/SC, RV64C integer compressed instructions (decode and execution), and an RV64F/D core decoder, interpreter, trace recording, and RV64 ELF loading via `goblin`, plus `ecall` handling for `exit`/`hint`/`write` and byte-range `read` with short-read handling in the reference executor (buffered input/output), a standalone guest ABI dispatcher, and `run_guest_elf` orchestration from ELF loading through execution and preprocessing;
- Public preprocessing: ROM, bytecode rows, selectors, and witness layout;
- Constraint IR over `GF(2^128)` (lambdaworks tower field), with `F61` as a prime-field reference;
- CPU row checks plus a bit-level ripple-carry adder R1CS over `F2_128`, with a 20-selector ALU (all RV64I register/immediate ALU ops), PC+4, Auipc, Jal, Jalr, and all six conditional branches;
- R1CS relations for all RV64M ops: `mul` (up to width 64), `mulhu`/`mulh`/`mulhsu` via a full 128-bit product plus sign corrections, and `divu`/`remu`/`div`/`rem` via unsigned long division plus absolute-value/sign handling (up to width 64), all wired into per-row trace proofs;
- R1CS relations for the supported RV64A AMO subset (`swap`/`add`/`xor`/`and`/`or`/signed and unsigned `min`/`max` in `.W` and `.D`), plus LR load and SC success/failure row relations, with 64-bit address generation, old-value read then new-value write in the access log, reservation state recorded per row, and both per-row and unified trace proofs;
- Row-bound CPU relations that pin opcode, operands, result, and both PCs to statement constants, plus a combined `TraceProof` that verifies an interleaved register/memory access log alongside per-row CPU proofs (ALU, AMO, load/store, branch, jump, Auipc);
- `UnifiedTraceProof`: every row relation is merged into one constraint system and proven once, with a statement-bound verifier and a standalone verifier that reconstructs the authenticated trace from proof rows plus the statement; `ChunkedTraceProof` has the same standalone verification path;
- A canonical SHA-256 trace commitment (`trace_digest`) over every row field, the ROM image, machine config, buffered syscall output, and consumed read input, bound into both trace-proof variants and the public `Statement`; statement-bound verification checks the program hash against the public `Statement` ROM, rejects output/input tampering, and checks write output against the RAM image at the syscall point;
- `ChunkedTraceProof`: per-row-range merged CPU proofs linked through the recursion crate's register/PC state chain, with the same access log and trace commitment;
- Lane-level sub-word load/store support in the access log (`lb/lbu/lh/lhu/lw/lwu/sb/sh/sw` within an aligned 8-byte word, with sign extension and read-modify-write checks);
- Register/RAM replay, Twist one-hot address/increment witnesses, shift/store routing witnesses, and a reference Sv39 page-table walker with permission and superpage checks;
- A reference BinaryTwist RAM reduction with bit-sliced virtual addresses and a virtual value history. The address table commits only `2a+2` cycle-length bit columns, the compact increment table commits the cycle deltas, `Val`/`Next` are reconstructed through the `LT` identity, and every terminal claim is discharged by one batched P3 opening argument;
- A multi-table P3 mosaic layer: `P3SharedPcs` stacks the unified CPU Spartan witness, the bit-sliced BinaryTwist address table, the compact increment table, the BinaryShout ROM-address table, and the BinaryRouter shift/store input table into one commitment, and opens the CPU point plus the RAM/ROM/routing claims with one P3 proof;
- The access proof keeps Merkle openings only for the 32-register file. Memory steps carry their event index and full-word values, are checked against the same BinaryTwist witness, and the initial RAM is bound by the public `Statement` instead of being serialized into the proof;
- Reference sum-check, SHA-256 and SHA3-256 transcripts, Merkle tree with batched vector openings, naive PCS, and a succinct BN254 KZG backend with single and batch openings from `arkworks`, with canonical bincode encode/decode for Spartan proofs and per-row/unified/chunked trace proofs;
- Reference Spartan reduction with Fiat–Shamir, over the existing constraint IR and Merkle PCS;
- Randomized hiding hash commitment and verifiable hash-chain/state-continuity recursion aggregators;
- Dependency boundaries across 15 crates, end-to-end integration tests, and criterion benchmarks for field arithmetic and the proof path.

Explicitly not implemented:

- Virtual Spartan and BinarySpartan; the Dual SIMD R1CS boundary and 128-bit packing exist, but the CPU is not yet converted to uniform SIMD matrices;
- The BinaryShout and BinaryRouter reference reductions are wired into `UnifiedTraceProof` and share the CPU/RAM mosaic commitment and opening; BinaryRouter covers 64-bit shift routes and sub-word store routes; the BinaryTwist `LT` prover still materializes quadratic tables;
- Full MosaicPCS ring switching and Ligerito integration with the runtime (P3 multi-table stacking, bit-sliced address virtualization, virtual `Val`/`Inc`, and a shared CPU+RAM opening are implemented);
- Recursion (only chunk planning, hash-chain and state-continuity reference aggregators, and a backend trait);
- ZK sum-check and private IO (only `NoPrivacy` and a randomized hiding hash commitment);
- RV64A reservation semantics inside R1CS (the reservation chain is recorded in the trace and checked during proof verification), RV64F/D execution and proof support (the decoder covers the core FP subset), executor/proof integration of the Sv39 walker, and a richer syscall runtime beyond `exit`/`hint`/`write`/`read`;
- Unaligned memory accesses (the executor rejects them); the proof path covers every aligned width that stays inside one 8-byte word;
- PC-linkage and reservation-chain constraints inside the proof (both are checked on the authenticated trace before proving);
- Performance optimization and third-party security audit.

> Important: `UnimplementedBackend` returns an explicit error; it never fabricates a "proof". Reference implementations exist only to validate protocol wiring and semantics.
>
> A detailed component-by-component audit against the paper is in [PAPER_GAPS.md](PAPER_GAPS.md).

## The 15 Modules

| # | Module | Crate | Current status |
|---|---|---|---|
| 1 | Protocol / ISA specification | `magnetar-spec` | RV64I base (including `*W` operations) + RV64M decode/encode/arithmetic + RV64A AMO/LR/SC decode/encode + RV64C integer decompression + core RV64F/D decoder; FP execution/proofs not implemented |
| 2 | Guest toolchain / ABI | `magnetar-guest` | ABI, syscall decoding + reference dispatcher, RV64 ELF loader, and `run_guest_elf` execution path implemented; a zig-based hello guest build script and end-to-end proof CLI are included; general compiler/toolchain integration not implemented |
| 3 | Program preprocessing / ROM | `magnetar-preprocess` | Implemented; currently one instruction = one micro-op |
| 4 | Executor / Trace | `magnetar-executor` | RV64I (including `*W`) + RV64M + RV64A (AMO and LR/SC reservations) + RV64C integer compressed instructions interpreter + trace implemented, with `ecall` handling for `exit`/`hint`/`write` and byte-range `read` including short reads, buffered input/output, and consumed-input trace binding |
| 5 | Constraint IR / Witness layout | `magnetar-constraint` | R1CS IR over `GF(2^128)`, `F61` reference field, aligned segments, and a Dual SIMD R1CS boundary with 128-bit witness packing |
| 6 | CPU constraints | `magnetar-cpu` | Row checks (including RV64M, A, and `*W` semantics), 64-bit 20-selector ALU (Add/Sub/AddI/Xor/Lui/And/Or/Slt/Sltu/Slti/Sltiu/Sll/Srl/Sra/Slli/Srli/Srai/Xori/Ori/Andi), RV64 `*W` relations, PC+4 step, Auipc, Jal, Jalr, all six conditional branches, single-step load/store relations, row-bound variants for every ALU/control relation, R1CS relations for all eight RV64M ops at full width 64, A R1CS for all AMO ops (`swap`/`add`/`xor`/`and`/`or`/`min`/`max`, signed and unsigned, W/D), and LR load / SC success-failure row relations; reservation state is trace-bound and checked during proof verification; specialized non-shift/non-compare ALU relations cut `addi`/`lui` from 4,492 variables to 449/64 |
| 7 | Memory consistency | `magnetar-memory` | Replay checks, Twist log, one-hot address/increment witness, load/store, memory/register chain, trace-order interleaved access proofs, a reference BinaryTwist RAM witness/reduction with batched P3 claims, and a reference Sv39 page-table walker |
| 8 | Routing / Bit operations | `magnetar-routing` | Shift/store routes and witnesses implemented; BinaryRouter proof wired into unified proofs for 64-bit shifts and sub-word stores |
| 9 | Proof engine | `magnetar-proof` | MLE + sum-check + reference Spartan reduction implemented; BinarySpartan not implemented |
| 10 | Commitment / PCS | `magnetar-pcs` | Merkle tree, batched Merkle vector commitment, naive polynomial PCS, `Pcs` trait, a succinct BN254 KZG backend with batch openings via `arkworks`, a vendored Ligerito 0.8.0 index-opening backend (2^16: 118,624 bytes / 99 ms / 3.1 ms), and Plonky3 `p3-binary-pcs` multilinear point PCS with single-vector, multi-column, and multi-table mosaic APIs plus a `P3SharedPcs` adapter (CPU+RAM shared opening in the unified proof) |
| 11 | Transcript / Proof format | `magnetar-transcript` | SHA-256 and SHA3-256 Fiat–Shamir transcripts implemented; canonical bincode encoding for Spartan and unified/chunked trace proofs lives in `magnetar-pcs` / `magnetar-runtime` |
| 12 | Prover / Verifier runtime | `magnetar-runtime` | Reference pipeline + Spartan backend + load/store, AMO read-modify-write, LR/SC reservation checks, syscall read write-back, memory/register chains, and trace-order interleaved access proofs; combined `TraceProof` binds CPU rows (ALU/AMO/LR/SC/load/store/branch/jump/Auipc) to the access log, including lane-level sub-word loads/stores; `UnifiedTraceProof` merges all rows into one proof and shares one mosaic P3 commitment/opening across the CPU witness, BinaryTwist RAM/register columns, BinaryShout ROM addresses, and BinaryRouter shift/store inputs, `ChunkedTraceProof` produces per-range proofs linked by state digests and carries one shared BinaryShout/BinaryRouter P3 opening, and both rely on the public `Statement` ROM and have standalone verifiers bound to a canonical trace digest and program hash; the access proof keeps no register Merkle paths; register consistency is proved by BinaryTwist and memory bindings are rechecked from the trace and BinaryTwist witness instead of being serialized, and the public `Statement` carries the initial RAM; a hiding/succinct trace commitment remains; BinaryShout and BinaryRouter claims share the unified P3 opening |
| 13 | Recursion / Aggregation | `magnetar-recursion` | Chunk plan + hash-chain and state-continuity reference aggregators implemented, wired to runtime `ChunkedTraceProof`; zk verifier-in-the-VM backend not implemented |
| 14 | Privacy layer | `magnetar-privacy` | `NoPrivacy` + randomized hiding hash commitment + trait implemented; ZK sum-check not implemented |
| 15 | Security / Performance engineering | `magnetar-testkit` | Integration tests, fixtures, and criterion benchmarks implemented; security audit not performed |

### Mapping to the Magnetar Paper

| Paper component | Current location | Next step |
|---|---|---|
| Dual SIMD R1CS over a shared witness | `magnetar-constraint` + `magnetar-cpu` | Generate uniform `s1`/`s2` and replace row-level checks |
| Virtual Spartan | `magnetar-proof` + `magnetar-runtime` | Dual-relation lockstep, per-segment claims, claim router |
| BinaryTwist / BinaryShout | `magnetar-memory` + `magnetar-runtime` | BinaryTwist has bit-sliced virtual addresses, compact increments, virtual `Val`, read/write/final-state/address sum-checks, and batched P3 claims; BinaryShout has a bit-sliced, multi-column (word + length + decoded fields + selectors) ROM-read claim wired into the shared P3 opening; next: decoded fields and performance tuning |
| BinaryRouter | `magnetar-routing` + `magnetar-preprocess` | BinaryRouter reference covers 64-bit shifts and sub-word stores, commits offset, width-selector, shift-route, and shift/store validity bits, and is wired into unified proofs (`binary_router.rs`) |
| MosaicPCS | `magnetar-pcs` | Multi-table P3 stacking and a shared CPU+RAM opening exist; next: ring switching |
| Ligerito | `magnetar-pcs` | Linear-code PCS + Merkle + query sampling |
| Recursion | `magnetar-recursion` | Verifier-in-the-VM, chunk state, aggregation |
| ZK / hiding | `magnetar-privacy` | Blinded witness, ZK sum-check, private IO |

## Dependency Direction

```text
spec
├── guest
├── executor
├── memory
├── routing ──► preprocess
└── cpu
constraint ──► cpu
constraint ──► proof ──► pcs
constraint ──► preprocess
transcript ──► pcs
transcript ──► privacy

preprocess, executor, guest, cpu, memory, routing, proof, pcs, transcript,
recursion, privacy ──► runtime
all crates ──► testkit
```

Rule: dependencies point downward only. `runtime` orchestrates; it does not push proof logic back into the VM front end.

## Running

```bash
# Offline, when dependencies are already cached locally
cargo test --workspace --offline

# End-to-end tests only
cargo test -p magnetar-testkit --test e2e --offline

# Criterion benchmarks (field arithmetic and proof path)
cargo bench -p magnetar-constraint --bench field --offline
cargo bench -p magnetar-runtime --bench proof_path --offline

# Lints and formatting
cargo clippy --workspace --all-targets --offline -- -D warnings
cargo fmt --all -- --check

# Normal networked environment
cargo test --workspace
```

At the time of writing the suite contains **298 tests across the 15 crates,
all passing**; clippy with `-D warnings` and `rustfmt --check` are clean.
The dev profile optimizes dependencies at `opt-level = 3` and workspace crates
at `opt-level = 2`, so the PCS-heavy tests stay in the second range instead of
taking tens of seconds in an unoptimized build.

## Compiling and Proving a Guest Program

`guests/hello/main.c` is a freestanding RV64 program: it writes
`Hello, MagnetarVM!` with the `write` syscall and then calls `exit(0)`.
`scripts/build_guest.sh` compiles it with zig's bundled clang/lld into
`target/guest/hello.elf`; `scripts/prove_guest.sh` then loads, executes,
proves, and verifies it:

```bash
./scripts/prove_guest.sh          # defaults to a 64-bit witness width
./scripts/prove_guest.sh 32       # optional narrower width
```

The proof CLI
(`cargo run -p magnetar-testkit --example prove_guest -- <elf> [width]`)
prints the row count, exit code, program output, and encoded proof size, then
verifies the proof against the public `Statement` only. The checked-in fixture
`crates/magnetar-testkit/tests/fixtures/hello.elf` keeps
`cargo test -p magnetar-testkit --test compiled_guest` independent of the host
toolchain; regenerate it with the build script after changing the guest source.

The build disables the RVC extension (`-mcpu=generic_rv64-c`) because the
current fetcher rejects a 32-bit instruction that starts at a 2-byte boundary.

## Mature Dependencies

- `lambdaworks-math` — binary tower field `GF(2^128)`.
- `goblin` — RV64 ELF parsing and PT_LOAD loading.
- `sha2` / `sha3` — standard hash functions for transcripts and Merkle commitments.
- `proptest` — property tests for field axioms and routing witnesses.
- `rand` — fresh blinding for hiding commitments.
- `ark-bn254` / `ark-ec` / `ark-ff` — BN254 KZG polynomial commitment backend.
- `ligerito` (vendored, MIT) — binary tower-field Ligerito PCS with SIMD/parallel backends.
- `p3-binary-pcs` / `p3-binary-field` (vendored Plonky3, MIT/Apache-2.0) — multilinear point PCS over the canonical 128-bit binary tower and CLMUL field arithmetic.
- `criterion` — micro-benchmarks for field arithmetic and the proof path.
- `serde` / `bincode` — canonical Spartan proof encoding.
- `cargo-nextest` — faster test execution.
- Xcode `llvm-cov` / `llvm-profdata` — coverage instrumentation available locally.

## Proof Path and Performance Note

The prover is a **reference implementation** built on a generic Spartan
reduction over GF(2^128). The unified CPU proof commits the Spartan witness and
the two BinaryTwist address columns and the compact increment table under **one
mosaic P3 commitment**, and opens them at the CPU point plus the RAM claims with
**one P3 opening proof**. The value history is virtual and reconstructed from
public initial RAM plus the committed write history.
Register and RAM consistency both use BinaryTwist; no register Merkle paths remain. BinarySpartan and SIMD R1CS
remain absent; BinaryShout and BinaryRouter are wired into the shared P3 opening. A
vendored Ligerito 0.8.0
backend remains available for index openings.

`F2_128` is now aligned with Plonky3's canonical 128-bit tower: multiplication
and inversion call `BinaryField128` (CLMUL/Karatsuba), so PCS values need no
basis change. Measured on the compiled 18-row hello guest in release mode
(Apple arm64, single-threaded); `./scripts/prove_guest.sh <width>` reproduces
them:

| width | CPU vars | CPU constraints | proof bytes | prove | verify |
|---|---|---|---|---|---|
| 64 | 6,991 | 11,933 | 269,455 | 0.42 s | 0.042 s |
| 32 | 4,015 | 6,813 | 231,575 | 0.36 s | 0.023 s |
| 8 | 1,783 | 2,973 | 198,687 | 0.33 s | 0.013 s |

At width 64 the proof splits into access=16,474, cpu=245,048, shout=2,330,
shift_router=1, store_router=5,570 bytes. Unified proofs no longer carry the
redundant trace rows; the verifier takes the trace alongside the proof. The changes behind these numbers:

1. **Per-op ALU relations.** `simple_alu_row_relation` allocates only the gates
   an operation needs: `addi` is 449 variables and `lui` is 64, down from 4,492
   variables/5,264 constraints per row under the uniform shifter+comparator
   circuit.
2. **One mosaic PCS for CPU and RAM.** `P3MosaicCommitment` stacks the CPU
   witness and the cycle-length address/increment tables into one polynomial; at width 64 this is 2^14, at width 32 2^13, and at width 8 2^12.
   `P3SharedPcs` plugs this batch into the Spartan proof: the CPU point and the
   BinaryTwist point claims are opened by the same P3 argument. The proof no
   longer pays for a separate CPU opening plus a separate RAM opening; the old
   separate layout was 593,508 bytes, the shared layout is 269,455 bytes.
3. **Bit-sliced virtual addresses and values.** The address table commits
   `2a+2` cycle-length bit columns (read bits, write bits, and two validity
   bits); full one-hot addresses are reconstructed by the verifier. Booleanity
   is checked by a batched sum-check over all address columns. `Inc` is a
   compact cycle-only table, and `Val` plus the successor history are virtual
   through the `LT` identity. Read, write, final-state, and address claims all
   reduce to openings of the small address/increment tables. The proof is bound
   to the trace's read/write words, and sub-word accesses update only their lane.
4. **Register-only Merkle access log.** Memory steps no longer carry a Merkle
   chain or a 131 KiB initial-memory table: each step stores its event index
   and full-word values and is checked against the BinaryTwist witness. The
   initial RAM is public input in `Statement`.
5. **No duplicated access proofs.** CPU row proofs already bind load/store
   address/value relations, so the access log does not repeat a Spartan proof
   for every register or memory access.
6. **Field arithmetic.** Plonky3's CLMUL tower brings `F2_128` multiplication to
   about **9.6 ns** and inversion to **84 ns** on this host, down from 238 ns
   and 62 µs.

`cargo run --release -p magnetar-runtime --example twist_probe -- <elf>`
prints the standalone batched BinaryTwist proof size, prove time, and verify
time for a trace; `prove_unified_trace` uses the shared mosaic path.

The reference `LT` reductions still materialize the `j × j'` table, so the
history terms remain quadratic in the cycle count; the paper's linear-time
treatment is future work. The address sum-check was split into an initial/base
part over `(cell, cycle)` and a history part over `(cycle, previous-cycle)`,
which removes the quadratic `K × T²` prover blow-up and brings prove time back
to a few hundred milliseconds. The shared P3 arity is driven by the CPU
witness; the RAM tables are cycle-length. BinaryShout and BinaryRouter now share the unified proof commitment,
and SIMD R1CS/BinarySpartan would pack many bit-lanes into one GF(2^128)
element. The verifier still reconstructs the trace and merged system before
checking the succinct CPU PCS proof, so it is not yet a fully succinct
verifier.


### Scaling probe

`cargo run --release -p magnetar-testkit --example proof_scaling` prints the
following reference measurements on the current unified proof:

| rows | proof bytes | prove ms | verify ms |
|---:|---:|---:|---:|
| 2 | 145,254 | 12.5 | 5.8 |
| 4 | 179,646 | 23.3 | 10.6 |
| 8 | 214,238 | 51.6 | 20.5 |
| 16 | 251,038 | 128.2 | 41.4 |
| 32 | 300,510 | 366.7 | 91.6 |

The proof no longer carries `rows`; the remaining growth comes from the
per-row CPU relation and PCS work. Removing that dependence is the remaining
A2/Virtual Spartan work.

## Coverage

`scripts/coverage.sh` builds instrumented tests, runs every test binary, and
writes per-binary `llvm-cov` reports to `target/coverage/reports/`.

Representative line coverage from the latest audit (each number is the highest
crate-wide ratio observed across the per-binary reports, so it is indicative
rather than one merged profile):

| Area | Line coverage |
|---|---|
| Spec instruction decode/encode, RV64C | 91% |
| Executor | 96% |
| Preprocess | 96% |
| Constraint IR / field / layout | 93% |
| CPU constraints | 93% |
| Memory / Sv39 | 93% |
| Routing | 96% |
| Proof engine (incl. Spartan) | 92% |
| PCS (incl. BN254 KZG) | 98% |
| Transcript | 93% |
| Runtime | 93% |
| Recursion | 98% |
| Privacy | 100% |
| Guest ELF loader | 93% |
| End-to-end testkit | 100% |
| **Aggregate across all crates** | **93%** |

## What the P0 Vertical Slice Does

`arith_memory_program` in `magnetar-testkit` executes:

```text
x1 = 5
x2 = 7
x3 = x1 + x2
x4 = 0x10000000
store x3 -> [x4]
x5 = load [x4]
exit(0)
```

The pipeline performs:

1. `preprocess`: decode and build ROM/bytecode/selectors/layout;
2. `execute`: interpret the program and record a `Trace`;
3. `cpu::check_trace`: check ALU, PC, memory addresses, branches, and jumps row by row;
4. `memory::check_memory`: replay the register file and RAM, checking read/write consistency;
5. `preprocess.layout`: build aligned witness segments;
6. `ChunkPlan`: plan long executions by chunk size.

This chain validates the module boundaries and semantics. It does not prove that the proof system is complete.

## Next Steps

1. **P1 (done)**: Bind the interleaved access log to row CPU relations and combine both into one `TraceProof`; extend row coverage to branches, jumps, and Auipc.
2. **P2**: Replace `NaiveMerklePcs` with a succinct Ligerito-style hash PCS and support accesses that cross an aligned word boundary. Field inversion already uses a tower addition chain with GF(2^8)/GF(2^16) lookup tables.
3. **P3**: Build a complete execution-trace proof that commits the trace itself and checks PC linkage across every row inside the proof; the merged `UnifiedTraceProof` removes per-row composition and binds a canonical digest, but a hiding/succinct trace commitment and in-proof linkage remain.
4. **P4**: Recursive zk verification, the ZK hiding layer, on-chain verifier, and security audit.
