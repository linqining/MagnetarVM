# MagnetarVM

English | [简体中文](README.zh-CN.md)

A 15-crate RV64 zkVM workspace structured after the Magnetar paper (IACR ePrint 2026/2423). The paper is available at [papers/magnetar-2026-2423.pdf](papers/magnetar-2026-2423.pdf).

## Status

This is a **compilable, testable architecture scaffold plus a P0 vertical slice**. It is not a usable zkVM, and it is not a secure implementation.

Implemented:

- RV64I base ISA decode/encode, interpreter, and trace recording;
- Public preprocessing: ROM, bytecode rows, selectors, and witness layout;
- Constraint IR (`F61` reference field), CPU row checks, and register/RAM consistency replay;
- Shift and sub-word store routing;
- Reference sum-check, SHA-256 transcript, Merkle tree, and naive PCS;
- Dependency boundaries across 15 crates and end-to-end integration tests.

Explicitly not implemented:

- Dual SIMD R1CS, Virtual Spartan, and BinarySpartan;
- Sum-check arguments for BinaryTwist, BinaryShout, and BinaryRouter;
- MosaicPCS, Ligerito, and ring switching;
- Recursion (only chunk planning and a backend trait);
- ZK hiding (only a `NoPrivacy` placeholder);
- RV64M/A/C/F/D, OS/MMU, and a real syscall runtime;
- Performance optimization and third-party security audit.

> Important: `UnimplementedBackend` returns an explicit error; it never fabricates a "proof". Reference implementations exist only to validate protocol wiring and semantics.

## The 15 Modules

| # | Module | Crate | Current status |
|---|---|---|---|
| 1 | Protocol / ISA specification | `magnetar-spec` | RV64I base implemented; M/A/C/F/D not implemented |
| 2 | Guest toolchain / ABI | `magnetar-guest` | ABI and syscall decoding implemented; compiler/runtime not wired |
| 3 | Program preprocessing / ROM | `magnetar-preprocess` | Implemented; currently one instruction = one micro-op |
| 4 | Executor / Trace | `magnetar-executor` | RV64I base interpreter + trace implemented |
| 5 | Constraint IR / Witness layout | `magnetar-constraint` | Reference R1CS IR, `F61`, and aligned segments implemented |
| 6 | CPU constraints | `magnetar-cpu` | Row-level semantic checks implemented; uniform SIMD R1CS not implemented |
| 7 | Memory consistency | `magnetar-memory` | Replay checks and Twist log implemented; Twist/Shout arguments not implemented |
| 8 | Routing / Bit operations | `magnetar-routing` | Shift/store routes implemented; BinaryRouter sum-check not implemented |
| 9 | Proof engine | `magnetar-proof` | MLE + reference sum-check implemented; Spartan/BinarySpartan not implemented |
| 10 | Commitment / PCS | `magnetar-pcs` | Merkle tree + naive PCS implemented; Ligerito not implemented |
| 11 | Transcript / Proof format | `magnetar-transcript` | SHA-256 Fiat–Shamir transcript implemented |
| 12 | Prover / Verifier runtime | `magnetar-runtime` | Reference pipeline + traits implemented; proof backend not implemented |
| 13 | Recursion / Aggregation | `magnetar-recursion` | Chunk plan + backend trait implemented; backend not implemented |
| 14 | Privacy layer | `magnetar-privacy` | `NoPrivacy` + trait implemented; ZK not implemented |
| 15 | Security / Performance engineering | `magnetar-testkit` | Integration tests and fixtures implemented; benchmarks not implemented |

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

preprocess, executor, cpu, memory, routing, proof, pcs, transcript,
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

# Normal networked environment
cargo test --workspace
```

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

1. **P1**: Replace the row-level checks in `magnetar-cpu` with uniform SIMD R1CS (`s1`/`s2`), and wire up `Virtual Spartan` claim routing.
2. **P2**: Replace `magnetar-memory` replay checks with BinaryTwist/BinaryShout sum-check reductions; add BinaryRouter.
3. **P3**: Implement MosaicPCS + Ligerito and run a real transparent SNARK proof chain.
4. **P4**: Recursive aggregation, ZK layer, on-chain verifier, benchmarks, and security audit.
