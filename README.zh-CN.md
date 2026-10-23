# MagnetarVM

[English](README.md) | 简体中文

按 Magnetar 论文（IACR ePrint 2026/2423）拆出的 15 模块 RV64 zkVM workspace。论文原文在 [papers/magnetar-2026-2423.pdf](papers/magnetar-2026-2423.pdf)。

## 当前状态

这是 **可编译、可测试的架构骨架 + P0 垂直切片**，不是可用的 zkVM，也不是安全实现。

已实现：

- RV64I base ISA（含 `*W` 字操作）、RV64M 乘除法、RV64A AMO/LR/SC、RV64C 整数压缩指令（解码与执行）以及 RV64F/D 核心解码器、解释执行、trace 记录，基于 `goblin` 的 RV64 ELF loader；参考 executor 支持 `exit`/`hint`/`write` 与按字节范围 `read`（含短读）的 `ecall` 处理（输入/输出缓冲），guest ABI 另有独立 dispatcher，并提供从 ELF 加载到执行/预处理的 `run_guest_elf` 编排入口；
- 程序预处理：ROM、bytecode row、selector、witness layout；
- 约束 IR 使用 `GF(2^128)`（lambdaworks tower field），并保留 `F61` 作为素数域参考；
- CPU 行检查，以及 `F2_128` 上的位级 ripple-carry 加法 R1CS；ALU 采用 20 个 selector（覆盖全部 RV64I 寄存器/立即数 ALU 操作），并实现 PC+4、Auipc、Jal、Jalr 和全部 6 种条件分支；
- 全部 RV64M 指令的 R1CS relation：`mul`（width 最高 64）、`mulhu`/`mulh`/`mulhsu`（完整 128-bit 乘积加符号修正）、`divu`/`remu`/`div`/`rem`（无符号长除法加绝对值/符号处理，最高 width 64），均接入逐行 trace proof；
- 受支持的 RV64A AMO 子集（`.W`/`.D` 的 `swap`/`add`/`xor`/`and`/`or`/有符号与无符号 `min`/`max`）R1CS relation，以及 LR 读取和 SC 成功/失败行 relation：包含 64-bit 地址生成、access log 中先读旧值再写新值的顺序、逐行 reservation 状态记录，以及逐行与 unified 两种 trace proof；
- 行绑定 CPU relation：把 opcode、操作数、结果和两个 PC 固定到 statement 常量；组合 `TraceProof` 同时验证交错的寄存器/内存访问日志与逐行 CPU proof（ALU、AMO、load/store、branch、jump、Auipc）；
- `UnifiedTraceProof`：把所有行关系合并进单一约束系统并只生成一个 proof，提供 statement-bound verifier；另有 standalone verifier，只依赖 statement 与 proof 的 rows 重建经认证的 trace；`ChunkedTraceProof` 也支持同样的 standalone 验证；
- 规范化 SHA-256 trace commitment（`trace_digest`，覆盖每行字段、ROM 镜像、machine config、syscall 输出与已消费的 read 输入），绑定进两种 trace proof 与 public `Statement`；statement-bound verification 会用 public `Statement` 的 ROM 校验 program hash、拒绝输出/输入篡改，并在 syscall 发生点校验 write 输出与 RAM 镜像一致；
- `ChunkedTraceProof`：按行区间生成合并 CPU proof，并通过 recursion crate 的寄存器/PC 状态链连接，共享同一访问日志与 trace commitment；
- access log 支持 lane 级 sub-word load/store（`lb/lbu/lh/lhu/lw/lwu/sb/sh/sw`，限定在同一 8 字节 word 内，含符号扩展与 read-modify-write 检查）；
- 寄存器/RAM 重放、Twist one-hot 地址/increment witness、shift/store routing witness，以及带权限与 superpage 检查的参考 Sv39 page-table walker；
- 参考 BinaryTwist RAM 归约：地址采用 bit-sliced 虚拟化，value history 通过 `LT` 恒等式虚拟化。地址表只提交 `2a+2` 列 cycle-length bit，increment 表提交每 cycle 的 delta，所有终值 claim 由同一个批量 P3 opening 参数证明；
- 多表 P3 mosaic 层：`P3SharedPcs` 把 unified CPU Spartan witness、bit-sliced BinaryTwist 地址表、紧凑 increment 表、BinaryShout ROM 地址表与 BinaryRouter shift/store input 表堆进同一个 commitment，并用同一个 P3 proof 打开 CPU 点与 RAM/ROM/routing claim；
- access proof 不再为寄存器保留 Merkle opening；寄存器与内存一致性都由 BinaryTwist 证明；memory step 记录 event 索引与完整 word 值，并与同一个 BinaryTwist witness 交叉检查；初始 RAM 改由 public `Statement` 绑定，不再放入 proof；
- 参考 sum-check、SHA-256 与 SHA3-256 transcript、带批量向量 opening 的 Merkle tree、naive PCS，以及基于 `arkworks` 的简洁 BN254 KZG 后端（支持单点与批量 opening）；Spartan proof 与逐行/unified/chunked trace proof 的规范化 bincode 编解码；
- 基于现有约束 IR 与 Merkle PCS 的参考 Spartan 归约（含 Fiat–Shamir）；
- 随机 blinding 的 hiding hash commitment，以及可验证的 hash-chain/状态连续性递归聚合器；
- 15 个 crate 的依赖边界、端到端集成测试，以及域运算/证明路径的 criterion benchmark。

显式未实现：

- Virtual Spartan 与 BinarySpartan；Dual SIMD R1CS 边界与 128-bit packing 已存在，但 CPU 尚未转成统一 SIMD 矩阵；
- BinaryShout 与 BinaryRouter 参考归约已接入 `UnifiedTraceProof`，并共享 CPU/RAM mosaic commitment 与 opening；BinaryRouter 覆盖 64-bit shift 与 sub-word store routing；BinaryTwist 的 `LT` prover 仍会物化二次表；
- 完整的 MosaicPCS ring switching、与 runtime 集成的 Ligerito（P3 多表堆叠、virtual `Val`/`Inc`、地址虚拟化与 CPU+RAM 共享 opening 已实现）；
- recursion（只有 chunk 规划、hash-chain 与状态连续性参考聚合器、backend trait）；
- ZK sum-check 与 private IO（只有 `NoPrivacy` 和随机 hiding hash commitment）；
- R1CS 内部的 RV64A reservation 语义（reservation 链写入 trace，并在 proof 验证时检查）、RV64F/D 执行与 proof（当前实现核心 FP 解码子集）、Sv39 walker 的 executor/proof 集成，以及 `exit`/`hint`/`write`/`read` 之外的更完整 syscall runtime；
- 非对齐内存访问（executor 会拒绝）；proof 路径覆盖所有保持在同一 8 字节 word 内的对齐宽度；
- proof 内部的 PC 链接与 reservation 链约束（两者当前都在证明前对经认证的 trace 做检查）；
- 性能优化与第三方安全审计。

> 重要：`UnimplementedBackend` 会明确返回错误，不会伪造一个“proof”。参考实现只用于验证协议接线和语义。
>
> 逐项对照论文的实现差距见 [PAPER_GAPS.md](PAPER_GAPS.md)。

## 15 模块

| # | 模块 | Crate | 当前状态 |
|---|---|---|---|
| 1 | 协议 / ISA 规格 | `magnetar-spec` | RV64I base（含 `*W` 操作）+ RV64M 解码/编码与算术语义 + RV64A AMO/LR/SC 解码/编码 + RV64C 整数解压 + RV64F/D 核心解码器；FP 执行/proof 未实现 |
| 2 | Guest 工具链 / ABI | `magnetar-guest` | ABI、syscall 解码 + 参考 dispatcher、RV64 ELF loader 与 `run_guest_elf` 执行路径已实现；包含基于 zig 的 hello guest 构建脚本与端到端证明 CLI；通用编译器/工具链集成未实现 |
| 3 | 程序预处理 / ROM | `magnetar-preprocess` | 已实现；当前 1 条指令 = 1 个 micro-op |
| 4 | 执行器 / Trace | `magnetar-executor` | RV64I（含 `*W`）+ RV64M + RV64A（AMO 与 LR/SC 预留）+ RV64C 整数压缩指令解释器 + trace 已实现，支持 `exit`/`hint`/`write` 与按字节范围 `read`（含短读）的 `ecall`，带输入/输出缓冲与 consumed-input trace 绑定 |
| 5 | 约束 IR / Witness 布局 | `magnetar-constraint` | `GF(2^128)` 上的 R1CS IR、`F61` 参考域、aligned segments 已实现 |
| 6 | CPU 约束 | `magnetar-cpu` | 行级检查（含 RV64M、A 与 `*W` 语义）、64-bit 20-selector ALU（Add/Sub/AddI/Xor/Lui/And/Or/Slt/Sltu/Slti/Sltiu/Sll/Srl/Sra/Slli/Srli/Srai/Xori/Ori/Andi）、RV64 `*W` relation、PC+4 step、Auipc、Jal、Jalr、全部 6 种条件分支、单步 load/store relation、所有 ALU/控制 relation 的行绑定版本、全部 8 个 RV64M 指令在完整 width 64 下的 R1CS relation、全部 AMO 指令（`swap`/`add`/`xor`/`and`/`or`/`min`/`max`，有符号与无符号，W/D）的 A R1CS，以及 LR 读取 / SC 成功失败行 relation；reservation 状态由 trace 绑定并在 proof 验证时检查；非移位/非比较的专用 ALU relation 把 `addi`/`lui` 从 4,492 个变量降到 449/64 |
| 7 | 内存一致性 | `magnetar-memory` | replay、Twist log、one-hot 地址/increment witness、load/store、memory/register chain、trace 顺序交错访问 proof、带批量 P3 claim 的参考 BinaryTwist RAM 归约，以及参考 Sv39 page-table walker |
| 8 | 路由 / 位操作 | `magnetar-routing` | shift/store route 与 witness 已实现；64-bit shift 与 sub-word store BinaryRouter proof 已接入 unified proof |
| 9 | 证明引擎 | `magnetar-proof` | MLE + sum-check + 参考 Spartan 归约已实现；BinarySpartan 未实现 |
| 10 | 承诺 / PCS | `magnetar-pcs` | Merkle tree、批量 Merkle vector commitment、naive PCS、`Pcs` trait、基于 `arkworks` 的简洁 BN254 KZG 后端（支持批量 opening）、vendored Ligerito 0.8.0 索引 opening 后端（2^16：118,624 字节 / 99 ms / 3.1 ms），以及带单向量、多列/多点与多表 mosaic API 的 Plonky3 `p3-binary-pcs` 多线性点 PCS，并提供 `P3SharedPcs` 适配器（unified proof 中 CPU+RAM 共享 opening） |
| 11 | Transcript / 证明格式 | `magnetar-transcript` | SHA-256 与 SHA3-256 Fiat–Shamir transcript 已实现；Spartan 与 unified/chunked trace proof 的规范化 bincode 编解码位于 `magnetar-pcs` / `magnetar-runtime` |
| 12 | Prover / Verifier 运行时 | `magnetar-runtime` | reference pipeline + Spartan backend + load/store、AMO read-modify-write、LR/SC reservation 检查、syscall read 回写、memory/register chain、trace 顺序交错访问 proof；组合 `TraceProof` 将 CPU 行（ALU/AMO/LR/SC/load/store/branch/jump/Auipc）绑定到访问日志，并支持 lane 级 sub-word load/store；`UnifiedTraceProof` 合并所有行，并让 CPU witness、BinaryTwist RAM/register 列、BinaryShout ROM 地址与 BinaryRouter shift/store input 共享一个 mosaic P3 commitment/opening；`ChunkedTraceProof` 按区间生成并用状态链连接，并携带一个共享的 BinaryShout/BinaryRouter P3 opening，两者都依赖 public `Statement` 的 ROM，并都有绑定规范化 trace digest 与 program hash 的 standalone verifier；access proof 不再保留 register Merkle path；register 一致性由 BinaryTwist 证明，memory 绑定改为从 trace 与 BinaryTwist witness 重新检查，不再序列化 step，public `Statement` 携带初始 RAM；隐藏/简洁 trace commitment 仍待做；BinaryShout 与 BinaryRouter claim 已共享 unified P3 opening |
| 13 | 递归 / 聚合 | `magnetar-recursion` | chunk plan + hash-chain 与状态连续性参考聚合器已实现，并接入 runtime `ChunkedTraceProof`；zk verifier-in-the-VM backend 未实现 |
| 14 | 隐私层 | `magnetar-privacy` | `NoPrivacy` + 随机 hiding hash commitment + trait 已实现；ZK sum-check 未实现 |
| 15 | 安全 / 性能工程 | `magnetar-testkit` | 集成测试、fixtures 与 criterion benchmark 已实现；安全审计未做 |

### Magnetar 论文组件映射

| 论文组件 | 当前落点 | 后续工作 |
|---|---|---|
| Dual SIMD R1CS over shared witness | `magnetar-constraint` + `magnetar-cpu` | 生成 uniform `s1`/`s2`，替换行级检查 |
| Virtual Spartan | `magnetar-proof` + `magnetar-runtime` | 双关系 lockstep、per-segment claim、claim router |
| BinaryTwist / BinaryShout | `magnetar-memory` + `magnetar-runtime` | BinaryTwist 已有 bit-sliced 虚拟地址、紧凑 increment、virtual `Val`、read/write/final-state/address sum-check 与批量 P3 claim；BinaryShout 的 bit-sliced 多列（word + length + decoded fields + selectors）ROM-read claim 已接入共享 P3 opening；下一步：decoded fields 与性能优化 |
| BinaryRouter | `magnetar-routing` + `magnetar-preprocess` | 已有 64-bit shift 与 sub-word store BinaryRouter 参考实现，提交 offset、width-selector、shift-route 与 shift/store validity bits，并已接入 unified proof（`binary_router.rs`） |
| MosaicPCS | `magnetar-pcs` | 已有多表 P3 堆叠与 CPU+RAM 共享 opening；下一步：ring switching |
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

preprocess, executor, guest, cpu, memory, routing, proof, pcs, transcript,
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

# Criterion benchmark（域运算与证明路径）
cargo bench -p magnetar-constraint --bench field --offline
cargo bench -p magnetar-runtime --bench proof_path --offline

# Lint 与格式检查
cargo clippy --workspace --all-targets --offline -- -D warnings
cargo fmt --all -- --check

# 正常联网环境
cargo test --workspace
```

当前测试套件包含 **15 个 crate 的 380 个测试，全部通过**；
`clippy -D warnings` 与 `rustfmt --check` 均无问题。dev profile 将依赖设为
`opt-level = 3`、workspace crate 设为 `opt-level = 2`，避免 PCS 密集的测试
在未优化构建里跑到几十秒。

## 编译并证明一个 Guest 程序

`guests/hello/main.c` 是一个 freestanding RV64 程序：它用 `write` syscall 输出
`Hello, MagnetarVM!`，然后调用 `exit(0)`。`scripts/build_guest.sh` 调用 zig
自带的 clang/lld 将其编译为 `target/guest/hello.elf`；
`scripts/prove_guest.sh` 依次完成加载、执行、证明与验证：

```bash
./scripts/prove_guest.sh          # 默认 64 位 witness 宽度
./scripts/prove_guest.sh 32       # 可选更窄宽度
```

证明 CLI
（`cargo run -p magnetar-testkit --example prove_guest -- <elf> [width]`）
会打印行数、退出码、程序输出与编码后证明大小，并且只依赖公开的
`Statement` 验证证明。`crates/magnetar-testkit/tests/fixtures/hello.elf`
是签入的测试固件，使
`cargo test -p magnetar-testkit --test compiled_guest` 不依赖宿主工具链；
修改 guest 源码后可用构建脚本重新生成。

构建时关闭 RVC 扩展（`-mcpu=generic_rv64-c`），因为当前取指器会拒绝从
2 字节边界开始的 32 位指令。

## 成熟依赖

- `lambdaworks-math` — `GF(2^128)` binary tower field；
- `goblin` — RV64 ELF 解析与 PT_LOAD 加载；
- `sha2` / `sha3` — transcript 与 Merkle commitment 的标准哈希；
- `proptest` — 域公理与 routing witness 的属性测试；
- `rand` — hiding commitment 的随机 blinding；
- `ark-bn254` / `ark-ec` / `ark-ff` — BN254 KZG 多项式承诺后端；
- `ligerito`（vendored，MIT）— binary tower field 的 Ligerito PCS，带 SIMD/parallel 后端；
- `p3-binary-pcs` / `p3-binary-field`（vendored Plonky3，MIT/Apache-2.0）— canonical 128-bit binary tower 上的多线性点 PCS 与 CLMUL 域运算；
- `criterion` — 域运算与证明路径的微基准；
- `serde` / `bincode` — Spartan proof 的规范化编码；
- `cargo-nextest` — 更快的测试执行；
- Xcode `llvm-cov` / `llvm-profdata` — 本机可用的覆盖率工具。

## 证明路径与性能说明

当前 prover 是**参考实现**，基于 GF(2^128) 上的通用 Spartan 归约。unified CPU
proof 把 Spartan witness 与 bit-sliced BinaryTwist 地址表及紧凑 increment 表放进**同一个 mosaic P3
commitment**，并用**同一个 P3 opening proof** 打开 CPU 点和 RAM claim；value history 是虚拟的，由公开初始 RAM 与已承诺的 write history 重建。
register 与 RAM 一致性都由 BinaryTwist 证明，不再有 register Merkle path。BinarySpartan 与 SIMD R1CS 仍未实现；
BinaryShout 与 BinaryRouter 已接入共享 P3 opening。仓库内 vendored Ligerito 0.8.0 继续提供按索引 claim 的
PCS 后端。

`F2_128` 已对齐 Plonky3 的 canonical 128-bit tower：乘法和求逆调用
`BinaryField128`（CLMUL/Karatsuba），PCS 数值无需基变换。在编译后的 18 行
hello guest 上以 release 模式实测（Apple arm64，单线程）；
`./scripts/prove_guest.sh <width>` 可复现：

| 宽度 | CPU 变量 | CPU 约束 | 证明字节 | prove | verify |
|---|---|---|---|---|---|
| 64 | 6,991 | 11,933 | 261,695 | 0.59 s | 0.045 s |
| 32 | 4,015 | 6,813 | 225,191 | 0.35 s | 0.029 s |
| 8 | 1,783 | 2,973 | 228,423 | 0.35 s | 0.015 s |

width=64 时证明体积分解为 access=12,778、cpu=241,240、shout=2,298、
shift_router=1、store_router=5,346 字节。Unified proof 不再携带冗余 trace rows；verifier 与 trace 一起接收 proof。产生这些数字的改动：

1. **按操作裁剪 ALU 约束。** `simple_alu_row_relation` 只分配操作真正需要的
   gate：`addi` 449 个变量、`lui` 64 个，而统一 shifter+comparator 电路每行
   需要 4,492 个变量/5,264 条约束。
2. **CPU 与 RAM 共用一个 mosaic PCS。** `P3MosaicCommitment` 把 CPU witness
   witness 与 cycle-length 地址/increment 表堆叠；width 64 为 2^14，width 32 为 2^13，width 8 为 2^12。`P3SharedPcs` 把这个
   批量接入 Spartan proof：CPU 点与 BinaryTwist 点 claim 由同一个 P3 参数打开。
   不再同时支付独立的 CPU opening 和 RAM opening；旧的分离布局是 593,508 字节，
   共享布局是 261,695 字节。
3. **bit-sliced 虚拟地址与 value history。** 地址表只提交 `2a+2` 列
   cycle-length bit（read bits、write bits、两个 validity bit）；完整 one-hot
   地址由 verifier 重建。booleanity 由覆盖全部地址列的批量 sum-check 检查。
   `Inc` 是紧凑 cycle 表，`Val` 与后继历史通过 `LT` 恒等式虚拟化。read、write、
   final-state 与 address claim 都归约到小型地址/increment 表的 opening。proof
   与 trace 的 read/write word 绑定，sub-word 访问只更新所在 lane。
4. **register/RAM 一致性都走 BinaryTwist。** 不再保留 register Merkle path；
   memory step 不再携带 Merkle 链或 131 KiB initial-memory 表；每一步只记录
   event 索引与完整 word 值，并与 BinaryTwist witness 交叉检查。初始 RAM 作为
   public input 放入 `Statement`。
5. **去掉重复 access proof。** CPU 行证明已经绑定 load/store 的地址/值关系，
   access log 不再为每次寄存器/内存访问重复生成 Spartan proof。
6. **域运算。** Plonky3 CLMUL tower 使 `F2_128` 乘法约 **9.6 ns**、求逆约
   **84 ns**，此前为 238 ns 和 62 µs。

`cargo run --release -p magnetar-runtime --example twist_probe -- <elf>`
会打印某个 trace 的 standalone 批量 BinaryTwist proof 大小、prove 与 verify
时间；`prove_unified_trace` 使用共享 mosaic 路径。

参考 `LT` 归约仍会物化 `j × j'` 表，因此 history 部分对 cycle 数仍是二次的；
论文的线性时间处理留作后续。地址 sum-check 已拆成 `(cell, cycle)` 上的
initial/base 部分和 `(cycle, previous-cycle)` 上的 history 部分，消除了
`K × T²` 的 prover 放大，prove 时间回到几百毫秒。共享 P3 的 arity 由 CPU
witness 决定，RAM 表都是 cycle-length。BinaryShout 与 BinaryRouter 已共享 unified proof commitment；
SIMD R1CS/BinarySpartan 可把多条 bit-lane 打包进一个 GF(2^128) 元素。verifier
仍会重建 trace 与合并 system，再验证简洁 CPU PCS proof，因此还不是完整的
简洁 verifier。


### 规模探测

`cargo run --release -p magnetar-testkit --example proof_scaling` 输出当前
unified proof 的参考测量：

| rows | unified bytes | chunked bytes | prove ms | verify ms |
|---:|---:|---:|---:|---:|
| 2 | 140,222 | 201,455 | 13.9 | 6.1 |
| 4 | 175,254 | 279,911 | 31.0 | 17.2 |
| 8 | 212,086 | 444,623 | 60.4 | 21.5 |
| 16 | 249,046 | 749,319 | 146.4 | 49.4 |
| 32 | 293,686 | 1,326,655 | 424.2 | 97.1 |

unified proof 已不再携带 `rows`；剩余增长来自 per-row CPU relation 与 PCS 工作。
chunked proof 还会按 chunk 复制 CPU 证明，因此增长更快。消除该依赖是后续
A2/Virtual Spartan 的工作。

## 覆盖率

`scripts/coverage.sh` 会构建插桩测试、运行每个测试二进制，并把 per-binary
`llvm-cov` 报告写到 `target/coverage/reports/`。

最新审计的代表性行覆盖率（每个数字是该 crate 在 per-binary 报告中观察到的最高
crate 级比例，因此是参考值，不是单一合并 profile）：

| 区域 | 行覆盖率 |
|---|---|
| Spec 指令解码/编码、RV64C | 91% |
| Executor | 96% |
| Preprocess | 96% |
| Constraint IR / field / layout | 93% |
| CPU 约束 | 93% |
| Memory / Sv39 | 93% |
| Routing | 96% |
| 证明引擎（含 Spartan） | 92% |
| PCS（含 BN254 KZG） | 98% |
| Transcript | 93% |
| Runtime | 93% |
| Recursion | 98% |
| Privacy | 100% |
| Guest ELF loader | 93% |
| 端到端测试 | 100% |
| **所有 crate 的加权参考值** | **93%** |

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

1. **P1（已完成）**：把交错 access log 绑定到行级 CPU relation，并合并为单一 `TraceProof`；覆盖 branch、jump、Auipc。
2. **P2**：用 succinct 的 Ligerito-style hash PCS 替换 `NaiveMerklePcs`；支持跨 8 字节 word 边界的访问。字段求逆已采用 tower 加法链与 GF(2^8)/GF(2^16) 查表。
3. **P3**：构建完整执行 trace proof，对 trace 本身做承诺并在 proof 内逐行检查 PC 链接；合并版 `UnifiedTraceProof` 已消除逐行组合并绑定规范化 digest，但隐藏/简洁 trace commitment 与 proof 内链接仍待做。
4. **P4**：递归 zk 验证、ZK hiding 层、链上 verifier 与安全审计。
