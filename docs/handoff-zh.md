# 交接文档 — MagnetarVM streaming selected prover（RV64）

状态：**增量优化阶段**，分支 `virtual-claims-rewrite`，最新 commit `386c2e8`
加 2026-11-03 的 `2^16` 优化轮（最终闸门通过后提交），2026-11-03。
英文主文档：[HANDOFF.md](HANDOFF.md)。
实测数据与逐轮记录：[STREAMING_SELECTED_PROVER_RESULTS.md](STREAMING_SELECTED_PROVER_RESULTS.md)
（[中文](streaming-selected-prover-results-zh.md)）。早期设计：[STREAMING_SELECTED_PROVER_HANDOFF.md](STREAMING_SELECTED_PROVER_HANDOFF.md)。

RV64 `2^16` 头部数字（2026-11-03 轮，宿主 load 14–72）：**prove 55.5–59.3 s
（prove CPU 421.6–434.9 s，之前 ≈800 s）、verify 27.4 ms、峰值 2.38 GiB**。
streaming 证明器仍与 eager 路径逐字节一致；*proof 文件*是 1,018,152 B，因为 polylog
claim 层（结果文档 §11.6）把 claim 表提交并挂到 `ClaimProof` 上——同一二进制关掉
claim 表时 verify 46.0 ms、proof 861,408 B，所以表的净收益是「+157 KB proof 换
-18.6 ms verify」。过渡期行 blob 仍保留，M4/M5 去掉后 proof 会降回旧大小以下。
全 workspace 测试：**655 passed / 0 failed**；`protocol_determinism` 20/20 字节一致、
峰值 1.99 GiB。

---

## 1. 怎么跑

```sh
cargo build --release -p magnetar-testkit --example paper_unified_bench

# 2^16 完整 paper benchmark（adds = 2^16-1），RV64
ADDS=65535 WIDTH=64 TRACE_SHOUT=1 MAGNETAR_STREAM_BUDGET_LOG=22 \
  target/release/examples/paper_unified_bench

# 阶段打点（都是环境变量开关，不改变行为）
MAGNETAR_PROFILE_UNIFIED=1   # unified context/Commit/Access/Opening
MAGNETAR_PROFILE_SELECTED=1  # selected setup/commit/product6/product2/open
MAGNETAR_PROFILE_STREAM=1    # streaming 重算/折叠轮次 + CSR 密度
MAGNETAR_PROFILE_RING=1      # ring-switch pack/eval/product2/p3 open
MAGNETAR_PROFILE_LOCAL=1     # register twist（配套独立 bench，见下）
MAGNETAR_PROFILE_VERIFY=1 MAGNETAR_VERIFY_CPU=5   # 验证器阶段 + CPU/次

# streaming 扫描诊断开关（同二进制 A/B；所有阶段打印都带累计进程 CPU 时间，
# 这是负载下唯一可靠的指标，见 §6）
MAGNETAR_STREAM_WORKERS=N      # worker 数（默认 available_parallelism）
MAGNETAR_LIVE_FULL=1           # 关闭零填充行跳过（A/B）
MAGNETAR_P2_FUSED=1            # 融合内层 block 循环（实测慢 35 %）
MAGNETAR_INNER_BUDGET_LOG=NN   # 内层 sum-check level budget（默认 24）
MAGNETAR_MAX_RSS_GIB=4.0       # benchmark 内存看门狗（magnetar-testkit examples）

# 单独测 register twist（Access 层），2^16 行
ROWS=65536 MAGNETAR_PROFILE_LOCAL=1 target/release/examples/local_shared_bench

# 闸门
cargo test --workspace --release          # 651 个测试
target/release/examples/protocol_determinism   # 120 组并发 prove/verify，width 64
```

**测量纪律。** 这台机器上只看 1 分钟负载不够：iOS 模拟器占着核心时，同一二进制
报告 121 s，而 121 s 内只有 738 CPU 秒（约 6 个有效核），70.4 s 那次约 11 个。
引用数据时必须同时写 `prove cpu / wall` 与负载；有效核数明显偏低的那次直接丢弃。

## 2. 当前数据

| cycles | prove | verify | 峰值 RSS | proof |
| --- | --- | --- | --- | --- |
| `2^16`（2026-11-03，load 14–72） | **55.5–59.3 s** | **27.4 ms** | **2.38 GiB** | 1,018,152 B† |
| `2^16`（2026-10-31） | 70.4 s | 29.6 ms | 2.26 GiB | 861,407 B |
| `2^17` | **147.6 s** | 55.8 ms | 4.60 GiB | 942,535 B |
| `2^18` | 321.5 s（融合前） | 161.5 ms | 7.73 GiB | 1,050,900 B |
| `2^19` | 667.8 s（融合前） | 318.3 ms | 10.54 GiB | 1,177,984 B |

`2^18`/`2^19` 早于融合扫描与 ring-switch 修复；两次带负载重测得到 335 s 与 437 s、
峰值 5.7–7.8 GiB，均不可比、已丢弃。按已测点做线性拟合，`2^22` 约 **20 GiB**
（取代早先 32 字节摘要时代推出的 55–60 GiB）。

† proof 大小是 claim 表格式；streaming proof 本身仍与 eager 逐字节一致，见结果文档 §11.6。

`2^16` 阶段分解（2026-11-03 轮，load 37–72）：unified context 0.31、Commit 0.52、
Access 2.63（register twist）、Opening 1.99；selected setup 0.40、见证 commit 0.32、
`product6` **24.5**、`product2` **24.5**（内层 level budget 24，见结果文档 §11.3）、
segments 1.20、selected open 0.84。两个 streaming product 仍占 ≈90 %，且 `product2`
现在已是最大单项。上一轮（load 70–90）的分解：context 0.48、Commit 1.19、Access 2.56、
Opening 3.38；setup 0.48、见证 commit 0.95、`product6` 43.2、`product2` 23.4、
segments 1.17、selected open 0.92。

`2^16` 验证器（5 次迭代 wall 30.3 ms、CPU 188 ms/次）：trace Logup-Shout
21.9–29.6（claim 派生 trace 一就绪就启动，与两波重叠）、claim 行和 11.5–12.4、
core PCS 7.7–8.0、access 6.7、claim leaves 3.8–4.1、claims decode 1.0、
claims-to-trace 0.77。

## 3. 代码地图

| 模块 | 文件 |
| --- | --- |
| streaming lockstep 证明器（外层 product6、内层 product2） | [stream.rs:363](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/stream.rs#L363)、[stream.rs:973](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/stream.rs#L973) |
| 融合加权扫描 / block 扫描 | [stream.rs:470](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/stream.rs#L470)（`accumulate_block`）、[stream.rs:410](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/stream.rs#L410)（无分支 set-bit） |
| 零填充行跳过（`live_rows`） | [stream.rs:245](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/stream.rs#L245) |
| 工作窃取轮内调度 | [stream.rs:108](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/stream.rs#L108) |
| 内层 level budget（`auto_level_inner`） | [stream.rs:170](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/stream.rs#L170) |
| 阶段 CPU 计时 | [lib.rs:15](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/lib.rs#L15) |
| benchmark RSS 看门狗 | [testkit/src/lib.rs:89](file:///Users/mac/projects/MagnetarVM/crates/magnetar-testkit/src/lib.rs#L89) |
| ring-switch PCS（位→域、eq 表、打开） | [bit_pcs.rs:737](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/bit_pcs.rs#L737)、[bit_pcs.rs:875](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/bit_pcs.rs#L875) |
| p3 PCS 包装：16 字节摘要、prepared batch | [p3_pcs.rs:34](file:///Users/mac/projects/MagnetarVM/crates/magnetar-pcs/src/p3_pcs.rs#L34)、[p3_pcs.rs:432](file:///Users/mac/projects/MagnetarVM/crates/magnetar-pcs/src/p3_pcs.rs#L432) |
| register-twist Access 证明 | [local_shared.rs:66](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/local_shared.rs#L66) |
| selected PCS 参数 / mosaic PCS 档位 | [protocol.rs:1651](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/protocol.rs#L1651)、[protocol.rs:1991](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/protocol.rs#L1991) |
| 两波验证器 + 重叠的 trace Logup | [lib.rs:3703](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/lib.rs#L3703)、[lib.rs:3847](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/lib.rs#L3847) |
| selected 见证 setup（并行填充） | [simd_dual.rs](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/simd_dual.rs)（`dynamic_segment_setup`） |
| gated bundle PC 终点 | [gated_bundle.rs:398](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/gated_bundle.rs#L398) |
| 确定性并行 grinding（vendored） | [challenger.rs:278](file:///Users/mac/projects/MagnetarVM/vendor/plonky3/binary-field/src/challenger.rs#L278) |
| 基准入口 | [paper_unified_bench.rs:54](file:///Users/mac/projects/MagnetarVM/crates/magnetar-testkit/examples/paper_unified_bench.rs#L54) |

## 4. 本阶段改了什么

1. **register-twist PCS 流水线** —— `MAGNETAR_PROFILE_LOCAL` 显示该阶段 94 % 是
   PCS：每次承诺只编码一次（`commit_batch_prepared`）、endpoint 表用小表档位、
   本地 PCS 改率 1/8 + 20 位 grinding、p3 开并行。独立测量 48.2 s → **1.43 s**
   （verify 3.7 ms、1.43 GiB）。
2. **确定性并行 grinding** —— p3 的并行 grind 会返回任意满足条件的 nonce
   （proof 字节逐次变化）。vendored `BinaryChallenger::grind` 改为按固定波次扫描、
   取最小满足者，与串行结果在任意机器上一致。
3. **融合外层 sum-check 扫描** —— `LockstepRows::accumulate_row_values` 把槽权重
   并进稀疏 CSR 扫描；按分配律逐位一致。`product6` 51.8 → **43.2 s**。
4. **ring-switch 打开** —— `eq_vector` 原来给每个表项分配一个 `Vec`（`2^16` 时
   420 万次：`2^22` 个打包字）。改成逐层倍增构造 + 按 worker 拆分 set-bit 累加：`ring eval`
   2.89 → **0.13 s**，selected open 3.68 → **0.92 s**。
5. **验证器调度** —— trace Logup 在 claim 派生 trace 就绪时即启动，与两波重叠：
   34.3 → **30.3 ms** wall（CPU 193 → 188）。
6. **width-64 迁移**（见 §6）—— 所有会跑证明的测试与示例都改为 width 64，
   由此暴露并修复三个真实缺陷：mosaic PCS 档位在后加表之前就被选定（64 位下
   E5 field opening 被拒）、AMO/PC 行里 `(1u64 << 64) - 1` 回绕成零掩码、
   `prove_gated_bundle_from_trace` 用 `last_row.pc + 4` 作 PC 链终点（行构建器
   追加停机行时会越过终点）。

### 4.1 2026-11-03 轮：`2^16` 优化

细节、实测与被否掉的实验见结果文档 §11。

7. **不再扫描零填充行**。`2^16` 下矩阵把 `2^29` 个 instance 行 + 419 万 extra 行
   上取整到 `2^30`，每轮外层扫描有 49.6 % 是零。同二进制 A/B（`2^14`）：product6
   12.8 → 6.5 s。
8. **CSR 扫描去分支**：不可预测的 `if bit { add }` 改成掩码 XOR。
9. **工作窃取调度**（`parallel_chunks`）：本机 6 性能核 + 6 能效核，固定均分会
   straggler；域加法是 XOR，合并顺序不影响 proof 字节。
10. **内层 level budget 22 → 24**（`auto_level_inner`）：8 轮列扫描减 2 轮 =
    内层 stage -25 %，代价是固定 +512 MiB level 数组。
11. **负载无关的测量**：阶段打印带累计 CPU 时间 + 同二进制诊断开关；本机
    wall A/B 不可用（见 §6）。
12. **benchmark 内存看门狗**；`protocol_determinism` 默认降到 40 对（旧 120 对
    并发峰值 5.75 GiB）。

外围阶段（并行轨）：vendored p3 的 `Keccak256Hash16` 没有转发 `hash_many`，
Merkle 树退回逐条 hash；修复后 p3 CPU 降 2.1–2.7×，Commit/Opening 约减半。
另外去掉 prepared 数据 deep clone（`2^16` 下 -0.5 GiB memcpy）、Access 建表去重
（register twist 独立测量 7.6 → 5.0 CPU-s）。

## 5. 待办（按优先级）

1. **提交 claim 列 → polylog 验证器**（通往论文 8 ms 的唯一路径）。claim 表承诺
   已进树（M2/M3，见 `docs/POLYLOG_CLAIM_VERIFIER.md`），但过渡期行 blob 仍在，
   所以 proof 是 1,136,696 B；M4/M5 去掉行 blob 后回到旧大小以下，同时消除验证器
   剩余的 O(rows) claim/Logup 工作。
2. **`product2` 现在是最大单项**（24.5 s / 55.5 s）。融合 block 循环实测**慢 35 %**
   （结果文档 §11.5），已收到 `MAGNETAR_P2_FUSED` 后面；下一步是把 `fill_left` 的
   per-block 开销摊到更大的列 chunk（round 0 的 block 只有 2 列）和更紧的 CSR 布局。
   在安静宿主上重估内层 level budget（当前默认 24；23 = 少一轮扫描、-256 MiB）。
3. **内存：位级 / 更小码字。** 峰值由码字与 Merkle 树决定（selected 见证 commit
   2.07 GiB；`2^18` 的 mosaic commit/opening 5.0/6.0 GiB），随 `cycles` 线性增长；
   `2^22` 外推约 21 GiB，而论文是 6.4 GiB（512 MiB 内层 level 数组是固定项，不随规模涨）。
4. **重测 `2^17`–`2^19` 阶梯** —— 带内存看门狗、一次一个运行；本轮宿主空闲内存
   一度低于 1.5 GiB。
5. **claim 层 M4/M5**：去掉行 blob（结果文档 §11.6）。
6. 有意放弃：把*外层* stream budget 提到 22 以上（以 `2^16` +0.4 GiB、`2^22` 约
   +25 GiB 换 `product6` 约 11 %）；把 scale-linear 的 PCS 数据跨阶段缓存（只保留
   deep clone 消除）；融合内层 block 循环（慢 35 %）。

## 6. 陷阱与不变量

- **本机 wall A/B 不可用。** 2026-11-03 轮里同一二进制同一 `2^14` prove 在几分钟内
  实测 18.5 s 到 55 s（1 分钟 load 13–150）。用每个 env 门控阶段打印里新增的 `cpu=`
  （累计 `getrusage` CPU 秒），并用同二进制 env 开关做 A/B，不要重建两个二进制。
  本轮「融合内层循环」就是反例：wall A/B 曾判定早先的内层融合 neutral，实际它慢 35 %。
- **零填充行跳过的 eq 值必须保持全长。** `prove_product6_rows` 把行数组截断到 live
  前缀，但 eq 向量不截断：live 前缀的边界元素在后续轮会与一个**非零** eq 值一起折叠；
  把它当 0 会在第一次奇数长度折叠处分叉。字节等价闸门抓到了这个 bug。
- **claim 层过渡期规则。** polylog claim 表默认开启（`MAGNETAR_CLAIM_TABLE=0`
  回到 legacy 行路径；`MAGNETAR_CLAIM_ROWS=1` 保留表但验证器用逐行和，供 A/B）。
  它要求 width 64；`ClaimProof` 的 wire 变体新增 `table` 字段，所以旧 build 的
  proof 不能反序列化（同版本 round-trip 有测试覆盖）。claim-native 快速路径现在
  绑定同一个 composed root。**open item**：`ADDS=4095` 的全量 benchmark 曾被观测到
  峰值 4.05–4.3 GiB（2^12 的 claim 表码字只有 ~16 MB，可以排除），而 `ADDS=1023`
  与 `2^16` 只有 2.1–2.4 GiB；benchmark 内存看门狗抓到了它。在引用小规模峰值前
  先定位这个非单调瞬态。
- **一次只跑一个重任务。** 本轮宿主空闲内存一度低于 1.5 GiB。所有 example 都装了
  `install_memory_watchdog`（`MAGNETAR_MAX_RSS_GIB`，默认 4 GiB），
  `protocol_determinism` 默认 20 对（1.99 GiB；旧 120 对默认峰值 5.75 GiB），
  >2 GiB 的运行全组串行。
- **字节等价是闸门。** `streaming_lockstep_proof_matches_the_eager_proof_bytes`
  （[simd_dual.rs:8335](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/simd_dual.rs#L8335)）、
  `parallel_chunked_streaming_matches_sequential`（[lib.rs:8361](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/lib.rs#L8361)）
  和 `protocol_determinism` 必须在任何热循环改动后保持绿色；它们抓到了非确定性
  grinding 与内层融合的偏差。
- **不要在每个元素的循环里打印。** pc 链里每 cycle 一次 `eprintln!` 把 `2^16`
  的 84 s 量成了 261 s。
- **分配器会保留已释放页。** 峰值 RSS 更接近瞬态之和而非最大值；
  `RAYON_NUM_THREADS=1` 与 `12` 峰值相同，说明 p3 并行特性不抬峰值。
- **PCS 档位必须从最终表集合推导**（[protocol.rs:1991](file:///Users/mac/projects/MagnetarVM/crates/magnetar-runtime/src/protocol.rs#L1991)），
  提前推导会让证明端与验证端拿到不同档位。
- **`1u64 << width` 在 width 64 回绕。** 用 `u64::MAX` 特判。
- **过期 release 产物**：改过 vendor 之后，先证明二进制确实换了（proof 字节或大小）
  再相信测量。
- **width-8 的单元测试是有意保留的**：`magnetar-cpu`、`simd_dual`、`simd_f2` 与各
  row 模块里约 63 处断言 8 位算术（`0xff` 回绕、`Sra(248,1)`、`u8`/`i8` proptest）。
  所有跑证明的路径都是 width 64；清单见结果文档 §9.11。
