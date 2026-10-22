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
- A canonical SHA-256 trace commitment (`trace_digest`) over every row field, the ROM image, machine config, buffered syscall output, and consumed read input, bound into both trace-proof variants and the public `Statement`; statement-bound verification checks the program hash against the proof ROM, rejects output/input tampering, and checks write output against the RAM image at the syscall point;
- `ChunkedTraceProof`: per-row-range merged CPU proofs linked through the recursion crate's register/PC state chain, with the same access log and trace commitment;
- Lane-level sub-word load/store support in the access log (`lb/lbu/lh/lhu/lw/lwu/sb/sh/sw` within an aligned 8-byte word, with sign extension and read-modify-write checks);
- Register/RAM replay, Twist one-hot address/increment witnesses, shift/store routing witnesses, and a reference Sv39 page-table walker with permission and superpage checks;
- Reference sum-check, SHA-256 and SHA3-256 transcripts, Merkle tree with batched vector openings, naive PCS, and a succinct BN254 KZG backend with single and batch openings from `arkworks`, with canonical bincode encode/decode for Spartan proofs and per-row/unified/chunked trace proofs;
- Reference Spartan reduction with Fiat–Shamir, over the existing constraint IR and Merkle PCS;
- Randomized hiding hash commitment and verifiable hash-chain/state-continuity recursion aggregators;
- Dependency boundaries across 15 crates, end-to-end integration tests, and criterion benchmarks for field arithmetic and the proof path.

Explicitly not implemented:

- Dual SIMD R1CS, Virtual Spartan, and BinarySpartan;
- Sum-check arguments for BinaryTwist, BinaryShout, and BinaryRouter;
- MosaicPCS, Ligerito, and ring switching;
- Recursion (only chunk planning, hash-chain and state-continuity reference aggregators, and a backend trait);
- ZK sum-check and private IO (only `NoPrivacy` and a randomized hiding hash commitment);
- RV64A reservation semantics inside R1CS (the reservation chain is recorded in the trace and checked during proof verification), RV64F/D execution and proof support (the decoder covers the core FP subset), executor/proof integration of the Sv39 walker, and a richer syscall runtime beyond `exit`/`hint`/`write`/`read`;
- Unaligned memory accesses (the executor rejects them); the proof path covers every aligned width that stays inside one 8-byte word;
- PC-linkage and reservation-chain constraints inside the proof (both are checked on the authenticated trace before proving);
- Performance optimization and third-party security audit.

> Important: `UnimplementedBackend` returns an explicit error; it never fabricates a "proof". Reference implementations exist only to validate protocol wiring and semantics.

## The 15 Modules

| # | Module | Crate | Current status |
|---|---|---|---|
| 1 | Protocol / ISA specification | `magnetar-spec` | RV64I base (including `*W` operations) + RV64M decode/encode/arithmetic + RV64A AMO/LR/SC decode/encode + RV64C integer decompression + core RV64F/D decoder; FP execution/proofs not implemented |
| 2 | Guest toolchain / ABI | `magnetar-guest` | ABI, syscall decoding + reference dispatcher, RV64 ELF loader, and `run_guest_elf` execution path implemented; a zig-based hello guest build script and end-to-end proof CLI are included; general compiler/toolchain integration not implemented |
| 3 | Program preprocessing / ROM | `magnetar-preprocess` | Implemented; currently one instruction = one micro-op |
| 4 | Executor / Trace | `magnetar-executor` | RV64I (including `*W`) + RV64M + RV64A (AMO and LR/SC reservations) + RV64C integer compressed instructions interpreter + trace implemented, with `ecall` handling for `exit`/`hint`/`write` and byte-range `read` including short reads, buffered input/output, and consumed-input trace binding |
| 5 | Constraint IR / Witness layout | `magnetar-constraint` | R1CS IR over `GF(2^128)`, `F61` reference field, and aligned segments implemented |
| 6 | CPU constraints | `magnetar-cpu` | Row checks (including RV64M, A, and `*W` semantics), 64-bit 20-selector ALU (Add/Sub/AddI/Xor/Lui/And/Or/Slt/Sltu/Slti/Sltiu/Sll/Srl/Sra/Slli/Srli/Srai/Xori/Ori/Andi), RV64 `*W` relations, PC+4 step, Auipc, Jal, Jalr, all six conditional branches, single-step load/store relations, row-bound variants for every ALU/control relation, R1CS relations for all eight RV64M ops at full width 64, A R1CS for all AMO ops (`swap`/`add`/`xor`/`and`/`or`/`min`/`max`, signed and unsigned, W/D), and LR load / SC success-failure row relations; reservation state is trace-bound and checked during proof verification; specialized non-shift/non-compare ALU relations cut `addi`/`lui` from 4,492 variables to 449/64 |
| 7 | Memory consistency | `magnetar-memory` | Replay checks, Twist log, one-hot address/increment witness, load/store, memory/register chain, trace-order interleaved access proofs, and a reference Sv39 page-table walker |
| 8 | Routing / Bit operations | `magnetar-routing` | Shift/store routes and witnesses implemented; BinaryRouter sum-check not implemented |
| 9 | Proof engine | `magnetar-proof` | MLE + sum-check + reference Spartan reduction implemented; BinarySpartan not implemented |
| 10 | Commitment / PCS | `magnetar-pcs` | Merkle tree, batched Merkle vector commitment, naive polynomial PCS, `Pcs` trait, a succinct BN254 KZG backend with batch openings via `arkworks`, and a vendored Ligerito 0.8.0 index-opening backend for binary fields (2^16 proof: 118,624 bytes, 99 ms prove, 3.1 ms verify); Ligerito multilinear point openings are not wired into the CPU Spartan path |
| 11 | Transcript / Proof format | `magnetar-transcript` | SHA-256 and SHA3-256 Fiat–Shamir transcripts implemented; canonical bincode encoding for Spartan and unified/chunked trace proofs lives in `magnetar-pcs` / `magnetar-runtime` |
| 12 | Prover / Verifier runtime | `magnetar-runtime` | Reference pipeline + Spartan backend + load/store, AMO read-modify-write, LR/SC reservation checks, syscall read write-back, memory/register chains, and trace-order interleaved access proofs; combined `TraceProof` binds CPU rows (ALU/AMO/LR/SC/load/store/branch/jump/Auipc) to the access log, including lane-level sub-word loads/stores, and `UnifiedTraceProof` merges all rows into one proof, `ChunkedTraceProof` produces per-range proofs linked by state digests, and both carry the ROM and have standalone verifiers bound to a canonical trace digest and program hash; memory/register tables now use Merkle-path leaf openings with single-cell root updates, and the access log no longer duplicates CPU load/store proofs; a hiding/succinct trace commitment and BinaryTwist/Shout remain |
| 13 | Recursion / Aggregation | `magnetar-recursion` | Chunk plan + hash-chain and state-continuity reference aggregators implemented, wired to runtime `ChunkedTraceProof`; zk verifier-in-the-VM backend not implemented |
| 14 | Privacy layer | `magnetar-privacy` | `NoPrivacy` + randomized hiding hash commitment + trait implemented; ZK sum-check not implemented |
| 15 | Security / Performance engineering | `magnetar-testkit` | Integration tests, fixtures, and criterion benchmarks implemented; security audit not performed |

### Mapping to the Magnetar Paper

| Paper component | Current location | Next step |
|---|---|---|
| Dual SIMD R1CS over a shared witness | `magnetar-constraint` + `magnetar-cpu` | Generate uniform `s1`/`s2` and replace row-level checks |
| Virtual Spartan | `magnetar-proof` + `magnetar-runtime` | Dual-relation lockstep, per-segment claims, claim router |
| BinaryTwist / BinaryShout | `magnetar-memory` | One-hot addresses, increments, address virtualization, sum-check |
| BinaryRouter | `magnetar-routing` + `magnetar-preprocess` | Routing identity + selector/offset claims |
| MosaicPCS | `magnetar-pcs` | Aligned-subcube lift, batching, ring switching |
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

At the time of writing the suite contains **253 tests across the 15 crates,
all passing**; clippy with `-D warnings` and `rustfmt --check` are clean.

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
- `criterion` — micro-benchmarks for field arithmetic and the proof path.
- `serde` / `bincode` — canonical Spartan proof encoding.
- `cargo-nextest` — faster test execution.
- Xcode `llvm-cov` / `llvm-profdata` — coverage instrumentation available locally.

## Proof Path and Performance Note

The prover is a **reference implementation** built on a generic Spartan
reduction over GF(2^128). The CPU witness still uses the naive Merkle PCS;
BinarySpartan, SIMD R1CS, BinaryTwist/Shout, and BinaryRouter are not on this
path. A vendored Ligerito 0.8.0 backend provides a real binary-field PCS and is
measured separately; its public API exposes indexed claims, not the multilinear
point openings the CPU Spartan reduction needs.

Measured on the compiled 18-row hello guest in release mode (Apple arm64,
single-threaded); `./scripts/prove_guest.sh <width>` reproduces them:

| width | CPU vars | CPU constraints | proof bytes | prove | verify |
|---|---|---|---|---|---|
| 64 | 6,991 | 11,933 | 278,772 | 0.335 s | 0.335 s |
| 32 | 4,015 | 6,813 | 213,108 | 0.178 s | 0.165 s |
| 16 | 2,527 | 4,253 | 213,108 | 0.186 s | 0.162 s |
| 8 | 1,783 | 2,973 | 180,212 | 0.101 s | 0.083 s |

At width 64 the proof splits into access=143,808, cpu=132,976, rows=1,860,
and rom=96 bytes. The optimization pass that produced these numbers:

1. **Per-op ALU relations.** `simple_alu_row_relation` allocates only the gates
   an operation needs: `addi` is 449 variables and `lui` is 64, down from 4,492
   variables/5,264 constraints per row under the uniform shifter+comparator
   circuit.
2. **Merkle-path table openings.** Loads and stores open one leaf with a Merkle
   path; a store proves the new root differs from the old one only on that path.
   Full RAM tables are no longer opened per access.
3. **No duplicated access proofs.** CPU row proofs already bind load/store
   address/value relations, so the access log no longer repeats a Spartan proof
   for every register or memory access.
4. **Ligerito PCS baseline.** The vendored Ligerito backend commits a 2^16
   vector of 128-bit symbols and produces a **118,624-byte** evaluation proof
   in **99 ms** (verify **3.1 ms**) on this host:
   `cargo run --release -p magnetar-pcs --example ligerito_bench`. Upstream
   reports roughly 150 KB and 50 ms for 2^20 with AVX-512.

The remaining gap is structural: BinaryTwist/Shout would remove the sequential
Merkle-path memory proof, BinaryRouter would replace the remaining shift and
compare circuits, and SIMD R1CS/BinarySpartan would pack many bit-lanes into
each GF(2^128) element. The CPU witness PCS also remains non-succinct, and the
verifier still reconstructs the trace, merged system, and final table roots, so
verification is O(trace + RAM) rather than succinct. Portable tower
multiplication is about 238 ns and inversion about 62 µs on this host, without
CLMUL/AVX packing or parallel hashing.

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
