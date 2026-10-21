# MagnetarVM

[English](README.md) | 简体中文

按 Magnetar 论文（IACR ePrint 2026/2423）拆出的 15 模块 RV64 zkVM workspace。论文原文在 [papers/magnetar-2026-2423.pdf](papers/magnetar-2026-2423.pdf)。

## 当前状态

这是 **可编译、可测试的架构骨架 + P0 垂直切片**，不是可用的 zkVM，也不是安全实现。

已实现：

- RV64I base ISA 的解码/编码、解释执行、trace 记录；
- 程序预处理：ROM、bytecode row、selector、witness layout；
- 约束 IR（`F61` 参考域）、CPU 行检查、寄存器/RAM 一致性检查；
- shift / sub-word store routing；
- 参考 sum-check、SHA-256 transcript、Merkle tree、naive PCS；
- 15 个 crate 的依赖边界和端到端集成测试。

显式未实现：

- Dual SIMD R1CS、Virtual Spartan、BinarySpartan；
- BinaryTwist、BinaryShout、BinaryRouter 的 sum-check 论证；
- MosaicPCS、Ligerito、ring switching；
- recursion（只有 chunk 规划和 backend trait）；
- ZK hiding（只有 `NoPrivacy` 占位）；
- RV64M/A/C/F/D、OS/MMU、真正可用的 syscall runtime；
- 性能优化与第三方安全审计。

> 重要：`UnimplementedBackend` 会明确返回错误，不会伪造一个“proof”。参考实现只用于验证协议接线和语义。

## 15 模块

| # | 模块 | Crate | 当前状态 |
|---|---|---|---|
| 1 | 协议 / ISA 规格 | `magnetar-spec` | RV64I base 已实现；M/A/C/F/D 未实现 |
| 2 | Guest 工具链 / ABI | `magnetar-guest` | ABI 与 syscall 解码已实现；编译器/runtime 未接入 |
| 3 | 程序预处理 / ROM | `magnetar-preprocess` | 已实现；当前 1 条指令 = 1 个 micro-op |
| 4 | 执行器 / Trace | `magnetar-executor` | RV64I base 解释器 + trace 已实现 |
| 5 | 约束 IR / Witness 布局 | `magnetar-constraint` | 参考 R1CS IR、`F61`、aligned segments 已实现 |
| 6 | CPU 约束 | `magnetar-cpu` | 行级语义检查已实现；uniform SIMD R1CS 未实现 |
| 7 | 内存一致性 | `magnetar-memory` | replay 检查与 Twist log 已实现；Twist/Shout 论证未实现 |
| 8 | 路由 / 位操作 | `magnetar-routing` | shift/store route 已实现；BinaryRouter sum-check 未实现 |
| 9 | 证明引擎 | `magnetar-proof` | MLE + 参考 sum-check 已实现；Spartan/BinarySpartan 未实现 |
| 10 | 承诺 / PCS | `magnetar-pcs` | Merkle tree + naive PCS 已实现；Ligerito 未实现 |
| 11 | Transcript / 证明格式 | `magnetar-transcript` | SHA-256 Fiat–Shamir transcript 已实现 |
| 12 | Prover / Verifier 运行时 | `magnetar-runtime` | reference pipeline + trait 已实现；proof backend 未实现 |
| 13 | 递归 / 聚合 | `magnetar-recursion` | chunk plan + backend trait 已实现；backend 未实现 |
| 14 | 隐私层 | `magnetar-privacy` | `NoPrivacy` + trait 已实现；ZK 未实现 |
| 15 | 安全 / 性能工程 | `magnetar-testkit` | 集成测试与 fixtures 已实现；benchmark 未实现 |

### Magnetar 论文组件映射

| 论文组件 | 当前落点 | 后续工作 |
|---|---|---|
| Dual SIMD R1CS over shared witness | `magnetar-constraint` + `magnetar-cpu` | 生成 uniform `s1`/`s2`，替换行级检查 |
| Virtual Spartan | `magnetar-proof` + `magnetar-runtime` | 双关系 lockstep、per-segment claim、claim router |
| BinaryTwist / BinaryShout | `magnetar-memory` | one-hot 地址、increment、地址虚拟化、sum-check |
| BinaryRouter | `magnetar-routing` + `magnetar-preprocess` | routing identity + selector/offset claims |
| MosaicPCS | `magnetar-pcs` | aligned subcube lift、batch、ring switching |
| Ligerito | `magnetar-pcs` | 线性码 PCS + Merkle + query sampling |
| Recursion | `magnetar-recursion` | verifier-in-the-VM、chunk state、aggregation |
| ZK / hiding | `magnetar-privacy` | blinded witness、ZK sum-check、private IO |

## 依赖方向

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

规则：依赖只能向下；`runtime` 负责编排，不把证明逻辑塞回 VM 前端。

## 运行

```bash
# 依赖本机已有缓存时可离线跑
cargo test --workspace --offline

# 只跑端到端测试
cargo test -p magnetar-testkit --test e2e --offline

# 正常联网环境
cargo test --workspace
```

## P0 垂直切片做了什么

`magnetar-testkit` 里的 `arith_memory_program` 会执行：

```text
x1 = 5
x2 = 7
x3 = x1 + x2
x4 = 0x10000000
store x3 -> [x4]
x5 = load [x4]
exit(0)
```

流水线会依次做：

1. `preprocess`：解码并生成 ROM/bytecode/selector/layout；
2. `execute`：解释执行并记录 `Trace`；
3. `cpu::check_trace`：逐行检查 ALU、PC、内存地址、分支/跳转；
4. `memory::check_memory`：重放寄存器文件和 RAM，检查读写一致；
5. `preprocess.layout`：生成 aligned witness segments；
6. `ChunkPlan`：按 chunk size 规划长执行。

这条链路证明“模块边界和语义”是通的，不证明“证明系统已经完成”。

## 下一步

1. **P1**：把 `magnetar-cpu` 的行级检查替换成 uniform SIMD R1CS（`s1`/`s2`），补 `Virtual Spartan` 的 claim 路由。
2. **P2**：把 `magnetar-memory` 的 replay 检查替换成 BinaryTwist/BinaryShout 的 sum-check 归约；补 BinaryRouter。
3. **P3**：实现 MosaicPCS + Ligerito，跑通一条真实的透明 SNARK 证明链。
4. **P4**：递归聚合、ZK 层、链上 verifier、benchmark 与安全审计。
