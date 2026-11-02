# 交接文档 — MagnetarVM streaming selected prover（RV64）

状态：**增量优化阶段**，分支 `virtual-claims-rewrite`，最新 commit `386c2e8`
（其后改动尚未提交），2026-10-31。
英文主文档：[HANDOFF.md](HANDOFF.md)。
实测数据与逐轮记录：[STREAMING_SELECTED_PROVER_RESULTS.md](STREAMING_SELECTED_PROVER_RESULTS.md)
（[中文](streaming-selected-prover-results-zh.md)）。早期设计：[STREAMING_SELECTED_PROVER_HANDOFF.md](STREAMING_SELECTED_PROVER_HANDOFF.md)。

RV64 `2^16` 头部数字：**prove 70.4 s、verify 29.6 ms、峰值 2.26 GiB、proof 861,407 B**，
proof 与原格式逐字节一致。全 workspace 测试：**651 passed / 0 failed**。

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
| `2^16` | **70.4 s** | **29.6 ms** | **2.26 GiB** | 861,407 B |
| `2^17` | **147.6 s** | 55.8 ms | 4.60 GiB | 942,535 B |
| `2^18` | 321.5 s（融合前） | 161.5 ms | 7.73 GiB | 1,050,900 B |
| `2^19` | 667.8 s（融合前） | 318.3 ms | 10.54 GiB | 1,177,984 B |

`2^18`/`2^19` 早于融合扫描与 ring-switch 修复；两次带负载重测得到 335 s 与 437 s、
峰值 5.7–7.8 GiB，均不可比、已丢弃。按已测点做线性拟合，`2^22` 约 **20 GiB**
（取代早先 32 字节摘要时代推出的 55–60 GiB）。

`2^16` 阶段分解（负载 70–90）：unified context 0.48、Commit 1.19、Access 2.56
（register twist）、Opening 3.38；selected setup 0.48、见证 commit 0.95、
`product6` **43.2**、`product2` **23.4**、segments 1.17、selected open 0.92。
两个 streaming product 占证明器 95 %。

`2^16` 验证器（5 次迭代 wall 30.3 ms、CPU 188 ms/次）：trace Logup-Shout
21.9–29.6（claim 派生 trace 一就绪就启动，与两波重叠）、claim 行和 11.5–12.4、
core PCS 7.7–8.0、access 6.7、claim leaves 3.8–4.1、claims decode 1.0、
claims-to-trace 0.77。

## 3. 代码地图

| 模块 | 文件 |
| --- | --- |
| streaming lockstep 证明器（外层 product6、内层 product2） | [stream.rs:363](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/stream.rs#L363)、[stream.rs:973](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/stream.rs#L973) |
| 融合加权逐行扫描（`accumulate_row_values`） | [stream.rs:279](file:///Users/mac/projects/MagnetarVM/crates/magnetar-proof/src/stream.rs#L279) |
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

## 5. 待办（按优先级）

1. **提交 claim 列 → polylog 验证器**（通往论文 8 ms 的唯一路径）。当前验证器是
   `O(rows)`：claim 行和每行重新发射约 336 列，trace Logup 还要从 claim 派生 trace
   重建 Shout 见证。设计草稿见结果文档 §9.8；会同时改 claim schema、proof 格式、
   证明端与验证端，且每层都要有一条从顶层入口走进来的篡改测试。
2. **内存：位级 / 更小码字。** 峰值由码字与 Merkle 树决定（selected 见证 commit
   2.07 GiB；`2^18` 的 mosaic commit/opening 5.0/6.0 GiB），随 `cycles` 线性增长；
   `2^22` 外推约 20 GiB，而论文是 6.4 GiB。
3. **内层（`product2`）融合** —— 右侧（bit）已证明逐字节等价，但在 `2^14` 的
   交错 A/B 中测不出收益（未改动的 `product6` 在同批运行里漂到 15.1–20.1 s）。
   再投入前需要安静宿主上的 A/B；上限约 3 s。左侧 `fill_left` 还会折入 claim 增量
   （`claim_columns`、`claim_instance_weight`），融合版本必须重放它们。
4. **主机安静后补测 `2^18`/`2^19`** —— 现有两行标注为融合前。
5. 有意放弃：把 stream budget 提到 22 以上（以 `2^16` +0.4 GiB、`2^22` 约 +25 GiB
   换 `product6` 约 11 %）；以及把 mosaic 证明数据跨 Access 缓存（其瞬态会叠加进峰值）。

## 6. 陷阱与不变量

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
