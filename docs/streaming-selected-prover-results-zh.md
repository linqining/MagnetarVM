# Streaming Selected Prover：实现与 RV64 基线

状态：已实现，RV64 `2^16` 基线已记录  
分支：`virtual-claims-rewrite`  
基线 commit：`62d135a`（当前交接入口：[HANDOFF.md](HANDOFF.md) / [中文](handoff-zh.md)；早期设计：[STREAMING_SELECTED_PROVER_HANDOFF.md](STREAMING_SELECTED_PROVER_HANDOFF.md)）  
英文主文档：[STREAMING_SELECTED_PROVER_RESULTS.md](STREAMING_SELECTED_PROVER_RESULTS.md)

本文记录 streaming selected prover 改了什么、内存模型、以及实测的 RV64 阶梯。凡涉及
selected 阶段的状态，以本文为准。

---

## 1. 结论

| 项目 | 改前 | 改后 |
| --- | --- | --- |
| RV64 `2^13` selected prover | 20.8 GB 峰值后被 kill | prove 27.6 s，峰值 **1.25 GiB** |
| RV64 `2^15` selected prover | OOM | prove 90.0 s，峰值 **3.29 GiB** |
| RV64 `2^16` selected prover | OOM | prove **194.2 s**，峰值 **4.49 GiB**，可验证 |
| RV64 `2^16` **完整 paper benchmark** | OOM | prove **70.4 s**、verify **29.6 ms**、峰值 **2.26 GiB**（负载 26–140） |
| proof 字节 | eager 格式 | 完全一致（有测试断言） |
| verifier | 1.42 s（重建见证） | proof-only，且每一层都真正校验（§9.7）；trace Logup-Shout 在 `2^16` 上 CPU/次 −61 %（§7 第 9 轮） |
| selected PCS opening（`2^16`） | 41.6–55 s（24 位 grinding） | **12.1 s**（20 位 grinding，+23.6 KB，§7） |
| register-twist Access 证明（`2^16`） | 48.2 s，其中 94 % 是 PCS（负载 80） | **1.43–1.55 s**，verify 3.7 ms（负载 90，§9.10） |
| 见证位（`2^16`） | 512 MiB（`Vec<bool>`） | **64 MiB**（`PackedBits`，1 字节 8 位，§3） |
| selected commit 与 mosaic commit | 峰值 = 两个瞬态之和（3.24–4.10 GiB） | **commit 闸门**：selected 等 mosaic 完成，`2^16` 峰值 2.26 GiB、`2^14` 为 1.13 GiB |

有两行是表格之后才测到的：register-twist Access 证明从 48.2 s 降到
**1.43–1.55 s**（§9.10），相当于每次 `2^16` prove 少约 40 s；但完整
benchmark 那一行本身尚未重测（改动后宿主机 1 分钟负载一直没低于 45，阶段
级数据是直接测的）。

`2^16` 的 selected proof 为 275,007 B，与 claim 绑定（一次 sum-check、一次 PCS opening）和
mosaic opening 一起验证；完整 paper proof 为 861,407 B（压缩后 560,943 B），把 selected
lockstep proof、claim 层与 mosaic opening 全部校验。本轮宿主机重载（负载 30–50），wall
verify 与更早的 33.8 ms（负载 10）不可比：同一二进制在 `2^12` 实测 30.5 ms、`2^16` 实测
`2^16` 稳态 60.9–64.4 ms、206–213 ms CPU/次（负载 20–52）；其中 trace Logup-Shout 已从 393–450 ms
降到 39–46 ms（折叠求值 + 按列并行，见 §7 第 9 轮）。
§7 与 §9 记录验证侧工作；§9.4 记录了过程中发现并修复的一个验证覆盖漏洞（中间某版
117.8 ms 其实跳过了 selected lockstep 校验）。

---

## 2. 改动内容

### 2.1 新增 streaming 引擎 `crates/magnetar-proof/src/stream.rs`

eager prover 的每个大中间量都改为按需从 bit witness 推导：

| eager 中间量 | RV64 `2^16` 规模 | streaming 替代 |
| --- | --- | --- |
| `z: Vec<F2_128>` | 8.6 GB | 直接读 witness 位 |
| 六个 matvec 向量 `az0..cz1` | 6 × 17 GB | `LockstepRows::row_values(row)` |
| 六个 `Mle::new(az.clone())` 拷贝 | 6 × 17 GB | 折叠末尾值（§2.3） |
| `eq_values`（rows） | 17 GB | 折叠等式的闭式（§2.2） |
| 六个 row-combination 向量（cols） | 6 × 8.6 GB | `ColumnRows::fill_left` |
| `left_values`（cols） | 8.6 GB | 同一个填充器，每轮重算 |
| inner 用的 `z.to_vec()` | 8.6 GB | `ColumnRows::fill_right` |

三个核心部件：

* **`LockstepRows`**：逐行求六个矩阵的值。块对角行 `(instance, local)` = 基稀疏行点乘该
  instance 的 witness 位；`base_rows * instances` 之后是 lazy gated extra 行
  （`LazyExtraRows::entry`，不再 materialize）；其余是零填充。它拒绝 materialized extra，
  因此 prover 改用 `LazyExtraRows::Gated`（交接 Milestone 1）。
* **`prove_product6_rows`**：outer sum-check `eq·(a0b0 − c0 + α(a1b1 − c1))`。前 `level`
  轮按 block 从 witness 重算，其余轮在内存里折叠 level 数组。折叠后的等式不落盘：`k`
  次折叠后为 `C_k · f_k(t) · eq(τ[k+1..], j)`，其中
  `C_k = Π_{b<k}((1−r_b)(1−τ_b)+r_bτ_b)`、`f_k(t) = tτ_k + (1−t)(1−τ_k)`，
  因此只需要一张 `2^16` 项低表加一张小高表（Milestone 3–5）。
* **`ColumnRows` + `prove_product2_columns`**：inner sum-check。left 向量分解为
  `instance_weight(instance) · combined(local)`（`rx` 处批量 base row combination）再加上
  稀疏 gated extra 修正，所以一段列只需「每列一次乘法 + 该段 extra 行一次遍历」即可填充；
  right 向量就是 witness 位。同样的 level 方案（Milestone 6）。

segment claims 直接从 bits 计算（`virtual_spartan::split_segment_claims_bits`），`vw` 取
inner right 向量最后一次折叠后的单值，都不再构造完整 `z`（Milestone 7）。

### 2.2 用加权和代替反复原地折叠

一段 `2^k` 折叠 `k` 次等于一次加权和，权 `w(s) = Π_{b<k}(s_b ? r_b : 1−r_b)`。每轮用
`fold_weights` 一次算出所有权，再把 block 累加到 even/odd 两个累加器；由于 matvec 值几乎
总是 `0/1`，`accumulate_weighted` 会跳过 128-bit tower 乘法。仅此一项就把 `2^16` 的
selected prove 从 `362 s` 降到 `194 s`（outer `253.6 s → 74.8 s`）。

### 2.3 终止 claim 免费得到

`v_a*`、`v_b*`、`v_c*` 与 `vw` 正是各向量在 `rx`/`ry` 处的 MLE，也就是 phase-2 折叠完剩下
的那个值：直接读最终单元素数组，不需要 `Mle` 拷贝，也不需要额外扫描。

### 2.4 PCS：安全目标按域容量截断

`P3BinaryPcs` 在 RV64 `2^16` 报错：

```
security level 100 exceeds the 99 bits the field leaves at this domain size
```

committed witness 打包成 `2^22` 个域元素，`p3-binary-pcs` 把 fold/sum-check 误差按
`2·2^(n_vars+log_inv_rate)` 计价，因此该域下可达上限只有 99 bit。`backend_with` 现在按错
误里给出的上限重试一次。commitment 字节与 transcript 都不受影响（上限只改变 query 数，
且 prover/verifier 从同一域大小推导同一参数），不是 wire format 变更。

### 2.5 unified 路：不再构造会被丢弃的列

dynamic proof 用 selected 证明替换了 unified 的 CPU/gated claim，调用方随后把
`cpu`、`gated`、`e5_opening`、`field_opening`、`opening` 全部置空。但 context 仍然把它们
全构造出来，成为整条流水线的内存主因（`2^12` 时仅 `new_with_group` 就要 `5.30 GiB`、
173.7 s，且每翻倍再涨 35-40 s）。两处改动：

* `UnifiedProveContext::new_without_cpu_columns`（dynamic native 使用）：跳过
  `merged_cpu_system`、域值 CPU witness `z`、CPU mosaic 列和 gated 的
  component/shift/active 表，commit 走 `commit_mosaic` 而不是 E5。proof 保留的部分
  （access、routers、logup、trace claims）完全不变；mosaic 是自描述的
  （`commitment.tables` 随 proof 一起走），验证仍然自洽。`2^12` 的 context 构造：
  **173.7 s / 5.30 GiB → 15 ms / 0.04 GiB**。
  对 **unified** proof 的净效果是它变小了（`2^12`：`372,596 B → 372,316 B`），因为被丢弃的列
  不再被提交。selected `LockstepProof` 的字节、commitment 与 transcript 都不变。
* `SharedBlockMatrix::with_extra_rows` 改为「只计数、不 materialize」补齐行。
  `base_rows * instances` 在 RV64 下本身就是一个大 2 的幂，旧实现的 `resize` 会瞬时分配
  `next_pow2(...) - base` 个空行：`2^14` 下 6.1 GiB，`2^16` 下约 100 GiB。verifier 的
  eager 矩阵构建在 `2^14` 从 **6.30 GiB 降到 0.35 GiB**，access 遍历从 1.8 s 降到 0.31 s。
  行数与所有求值结果不变。

### 2.6 compact claim proof 往返（测试套件暴露的既有 bug）

`magnetar-testkit --test compiled_guest` 在基线 commit `62d135a` 上同样失败：compact
`ClaimProof` blob 不编码 `rd`/`rs1`/`rs2`，而是从指令字重新推导；但 `TraceClaim::from_row`
取的是执行器行里的值（`row.rd.unwrap_or(0)`）。syscall 行的 claim 带 `rd = 10`，而
`decode(0x73)` 得到 `rd = 0`，于是序列化/反序列化后 leaf（进而 root）变了，解码后的 proof
被 "claim proof opening mismatch" 拒绝。

修法：新增 `ClaimProofWire::CompactIndexed` 变体，只携带「索引与指令字推导不一致」的行
（常见情况为空，普通 proof 仍走 `Compact`）。blob、claim root、statement 与 verifier 都不变；
解码时先应用覆盖再计算 leaf。

### 2.7 接线

`spartan.rs` 新增 `prove_lockstep_bits_streaming{,_with_level}`，逐字节复刻 eager 的
transcript；`_with_level` 让测试可以钉住每个 phase 切换。`prove_dynamic_segmented_trace`
改用 lazy gated 矩阵并调用 streaming prover。verifier 一行未改。

---

## 3. 内存模型

RV64 `2^16` 实测（`MAGNETAR_PROFILE_UNIFIED` + `MAGNETAR_PROFILE_SELECTED` 逐阶段打印 RSS；
`rows = 2·cols`，`cols = cycles·8192`）：

| 阶段 | RSS | 内容 |
| --- | --- | --- |
| unified context | 0.45 GiB | trace、twist/shout 见证、表列 |
| mosaic commit 之后 | **2.15 GiB** | 堆叠 mosaic 的 P3 码字（rate 1/4）+ Merkle 树 |
| selected witness commit | **1.98 GiB**（rate 1/2） | packed 见证（64 MiB）+ selected PCS 码字与 Merkle 树 |
| **prove 峰值** | **2.01–2.61 GiB**（rate 1/2，负载 15–43） | mosaic opening + selected level 数组 |

| 缓冲 | RV64 `2^16` | 规则 |
| --- | --- | --- |
| 见证位（`PackedBits`） | 64 MiB | `cycles · base_cols` 位，1 字节 8 位 |
| outer level 数组 | 400 MiB | `2^22` 项 × 6 个值 × 16 B |
| inner level 数组（left、right） | 128 MiB | level 使每个存储为 `2^22` 项 |
| selected PCS packed 表 + 码字 + Merkle | 约 1.5 GiB 瞬态 | rate 1/8、20 位 grinding；commit 后释放 |
| mosaic 码字 + Merkle | 约 1.7 GiB | rate 1/4，约 `2^22.1` 个表单元 |
| 每 worker 的块缓冲 | < 1 MiB | `2^level` 行 × 6 槽 |
| 矩阵（lazy gated 元数据） | < 1 MiB | 不物化额外行 |

自动 level 为 `bits − 21`（`MAGNETAR_STREAM_BUDGET_LOG` 默认 22 项 ⇒ `2^22` 项存储）；
`MAGNETAR_STREAM_EAGER=1` 强制 level 0，复现 eager 扫描顺序，仅用于等价性测试。
重算遍数 = `level`，内存与时间线性互换。

**setup 缓冲复用（无可测收益）。** `dynamic_segment_setup` 原先每个周期都分配一份见证 scratch 与 block 缓冲
（各为 `num_vars` 的 `Vec<bool>`，`2^16` 下即 65 536 次）；现在两者各复用一份，只清除上一行写过的位。
`MAGNETAR_PROFILE_SELECTED` 的 RSS 打点在该填充循环处测到 0.43 → 1.16 GiB，但 RSS 是进程级的，
且该窗口与 unified context 构建重叠，因此归因只是近似；改动本身去掉每行两次分配，
block 改由一次 `fill(false)` 重置；同一 rate 下 `2^16` 峰值在改动前后分别为 2.01 与 2.61 GiB，
属运行噪声，因此仅作为分配层面的清理保留，不作为峰值收益。

**为什么 level 保持 budget 22。** level 存储是 `2^(level+1)` 个「6 个域元素」的行槽，而
`level = row_bits − (budget−1)`，所以它的大小只取决于 budget：outer 402 MiB、inner 128 MiB，
与 `cycles` 无关。降低 budget 会让每个存储变小，但每次多几遍对见证的重算。`2^14` 在负载 35–40 下
（budget 21/22/23）实测：prove wall 60.7 / 77.5 / 101.5 s，**CPU 230.8 / 227.2 / 222.9 s**，
峰值 1.18 / 1.35 / 1.27 GiB。存储相差 4 倍而 CPU 只差 3.4 %，说明重算遍数不是瓶颈
（折叠数据常驻缓存，成本由域运算主导）；wall 差异是负载噪声。这些存储在
任何规模下都是固定的 0.4–0.5 GiB——相对论文 6.4 GiB 包络约 7 %，不是随规模增长的项——
所以 budget 保持 22，内存优化必须针对码字与树，而不是 level 缓冲。

见证改为 `PackedBits`（`crates/magnetar-proof/src/bits.rs`）：每列每周期 1 bit，
1 字节 8 位，streaming 行/列源原地读取。RV64 `2^16` 下从 512 MiB 降到 64 MiB，
并去掉了 eager 路径的布尔拷贝。`BitPcs` trait、ring-switch 打包和 eager 证明入口
都使用打包形式；ring-switch 打包现在就是小端字视图（128 bit 一个域元素），
原来的 SIMD 转置内核已删除。

**commit 闸门。** selected 见证 commit 自己要分配码字和 Merkle 树（`2^16` 下 1.5 GiB），
而 unified worker 同时在 commit mosaic（2.15 GiB）。两者重叠时峰值是**相加**：
不同交织下实测 3.24–4.10 GiB，低值只是运气。现在 selected worker 先等 mosaic
commit 完成（一次性 channel），再 commit，改为与低内存的 Access/Opening 阶段重叠。
`2^14` 峰值从 1.75 GiB（打包见证、无闸门）降到 **1.13 GiB**，`2^16` 实测 2.26 GiB。

稳态内存仍由 mosaic 主导：成本 = `cells · 2^log_inv_rate · (16 B + Merkle 开销)`。
这些 cell 是布尔列（每行一个 16 字节域元素）。要 `2^22` 时压进 6.4 GiB，需要表 bit 打包
（论文的表是 `2^22 · 256` bit ≈ 打包后 128 MB，而这里是 `2^30` 个 cell），**并且**
selected PCS 的码字/Merkle 也要 bit 打包（16 B/域元素的码字在 `2^22` 时是 32 GiB）。
这是剩余的结构性工作。

---

## 4. RV64 阶梯（selected 阶段）

`WIDTH=64`，`cargo run --release -p magnetar-testkit --example selected_stream_probe`，
12 核 Apple Silicon / 36 GiB。`peak RSS` 由探针每 20 ms 采样。`rows = 2·bits`，`cols = bits`。

| ADDS | cycles | bits | prove | verify | peak RSS | selected proof |
| --- | --- | --- | --- | --- | --- | --- |
| 1023 | `2^10` | `2^23` | 6.83 s | 0.20 s | 0.83 GiB | 150,144 B |
| 4095 | `2^12` | `2^25` | 13.07 s | 0.85 s | 1.01 GiB | 186,080 B |
| 8191 | `2^13` | `2^26` | 27.61 s | 1.70 s | 1.25 GiB | 203,904 B |
| 16383 | `2^14` | `2^27` | 46.62 s | 3.55 s | 1.62 GiB | 224,808 B |
| 32767 | `2^15` | `2^28` | 89.96 s | 7.66 s | 3.29 GiB | 250,784 B |
| 65535 | `2^16` | `2^29` | 194.18 s | 4.44 s | 4.49 GiB | 279,248 B |

`2^16` 分解（`MAGNETAR_PROFILE_SELECTED=1`）：

```
selected commit          13.1 s
selected product6        74.8 s   （9 遍重算 + 21 轮折叠）
selected row-combinations 4 ms
selected product2        44.5 s   （8 遍重算 + 21 轮折叠）
selected segments         1.3 s
selected open            31.3 s
```

两个 sum-check 都随 `rows`/`cols` 线性增长；小规模 PCS commit/open 占主导（`2^10` 时
6.8 s 里占 5.2 s），大规模 outer sum-check 占主导。`open` 是 `2^16` 里最大的非 sum-check
项，因为 `RingSwitchPackedBitPcs` 会再 pack 并 commit 一次 packed 表；该路径与交接文档一致
（Milestone 8 明确不在本阶段范围，也不是瓶颈）。

verify 一列是「给定 trace，验 PCS + 公开矩阵求值 + segment 绑定」的墙钟时间
（`verify_dynamic_segments_public` + `verify_dynamic_segments_against_trace`）；`8 ms`
目标属于后续阶段，本阶段未做。

---

## 5. 正确性证据

* `crates/magnetar-runtime/src/simd_dual.rs::tests::streaming_lockstep_proof_matches_the_eager_proof_bytes`
  对 `width = 8` 与 `width = 64`，在 level
  `{0, 1, 2, 3, 5, 7, row_bits, usize::MAX/2}` 上分别构造 eager
  （`gated_shared_matrices` + `prove_lockstep_bits_with_point`）与 streaming proof，断言
  bincode 编码完全相同（commitment、终止 claim、round 多项式、segment claims、opening），
  并用现有 verifier 逐个验证。这覆盖交接验收第 4、5 条以及「transcript 顺序不变」风险。
* `cargo test --release --workspace --no-fail-fast`：**39 个测试二进制、642 个测试、0 失败**。
  其中两个在基线 commit `62d135a` 上是失败的：`compiled_guest`（靠 §2.6 修复）与
  `logup_shout_mixed` 的 `native_dynamic_handles_more_compressed_programs`——它的断言仍要求
  `proof.logup_shout`，但 `prove_unified_trace_auto` 走 native dynamic 路，携带的是
  `proof.trace_logup_shout`；断言改为接受任一形式（测试其余部分不变）。
* `cargo test --release -p magnetar-runtime --lib`：340 通过。
* `cargo test --release -p magnetar-proof`：41 通过。
* `cargo test --release -p magnetar-testkit --test paper_mode`：1 通过。
* prover 现在消费的 lazy gated extra 正是公开 verifier 已在用的同一模式
  （`gated_shared_matrices_lazy`），两边行语义按构造一致。

---

## 6. 完整论文 benchmark（`paper_unified_bench`）

整条流水线可跑 `2^16`，当前构建峰值 2.26 GiB。`peak RSS` 是整进程最大值，包含与
unified 阶段并发运行的 selected worker。

当前数字。本轮宿主机被共享且重载（12 核上 1 分钟负载 20–125，更早的行是 8–20），所以 wall
数字跨行不可比；`peak RSS` 与 `verify CPU/次` 是稳定列，且 CPU 时间在内存带宽饱和时同样会膨胀。

| ADDS | cycles | prove | verify | 峰值 RSS | proof |
| --- | --- | --- | --- | --- | --- |
| 4095 | `2^12` | 33 s（负载 30–60） | 30.5 ms（负载 30） | — | 452,413 B |
| 16383 | `2^14` | 64–106 s（负载 15–40） | 未重测（更早一轮：26.5 ms，负载 50） | 0.69–1.12 GiB（噪声大） | 910,892 B |
| 65535 | `2^16` | **70.4 s**（负载 70–90） | **29.6 ms** | **2.26 GiB** | 861,407 B |
| 65535 | `2^16`（旧代码、带打点） | 141–335 s（负载 15–144） | 45–153 ms 首次 / 34.8–84.4 ms 稳态，186–228 ms CPU/次 | 1.52–1.58 GiB（16 字节摘要） | 845,055 B |

本轮 `2^16` 从约 141–261 s 降到 70.4 s（注意：当 iOS 模拟器占着核心时，
即使 1 分钟负载很低也不可比——同一二进制曾报告 121.1 s、`product6` 83.7 s，
121 s 里只有 738 CPU 秒（约 6 个有效核），而 70.4 s 那次约 11 个。引用时请把
`prove cpu / wall` 与负载一起写。另外，这一轮大部分不是计算而是测量开销：
`MAGNETAR_PROFILE_SELECTED` 的 `setup rss after witness fill` 检查点放在 pc 链
循环**内部**，每个 cycle 打印一行（`2^16` 约 6.5 万次 `eprintln!`，约 160 s）。
把打印移出循环、并把见证填充按 cycle 并行拆分（按字对齐的实例块，每次写 64 位）
后，同一 benchmark 的 `setup fill` 为 0.47 s，proof 逐字节不变（前后都是
861,407 B）。当前 `2^16` 阶段分解：unified context 0.48、Commit 1.19、Access
2.56（register twist 2.53）、Opening 3.38；selected setup 0.48、见证 commit
0.95、`product6` 43.2、`product2` 23.4、segments 1.17、open 0.92。70 s 中的
67 s 是两个 streaming product，处于 §3 所述 level store 的下限。
| 131071 | `2^17` | **147.6 s**（RV64，负载 67–95） | **55.8 ms** | **4.60 GiB** | 942,535 B |
| 262143 | `2^18` | **321.5 s**（RV64，负载 55–80） | **161.5 ms** | **7.73 GiB** | 1,050,900 B |
| 524287 | `2^19` | **667.8 s**（RV64，负载 37–118） | **318.3 ms** | **10.54 GiB** | 1,177,984 B |

`2^16` 各阶段峰值（当前构建，`MAGNETAR_PROFILE_UNIFIED=1` +
`MAGNETAR_PROFILE_SELECTED=1`）：context 0.52 GiB、mosaic Commit 1.19 GiB、
selected 见证 commit 2.07 GiB、Access 2.30 GiB、Opening 2.26 GiB（prove 峰值）。
峰值已不再是两个 commit 瞬态之和（见 §3 的 commit 闸门），但 RSS 不归还已释放
页面，所以 register-twist Access 在 mosaic commit 保留页之上分配时高水位会上升。
`2^18`/`2^19` 时最大项变成 mosaic Commit（5.02/8.13 GiB）与 Opening
（5.98/8.82 GiB）的瞬态，selected 见证 commit（`2^17` 时 3.70 GiB）再叠加其上。

**当前构建的峰值随 `cycles` 线性增长。** 在 RV64 宽度、16 字节摘要与 p3 并行下
实测：`2^16` / `2^17` / `2^18` / `2^19` 分别为 **2.32 / 4.74 / 7.73 /
10.54 GiB**，prove 70.4 / 147.6 / 321.5 / 667.8 s（每次翻倍约 2.1×，即随
`cycles` 线性），verify 29.6 / 55.8 / 161.5 / 318.3 ms。`2^18`/`2^19` 两行早于
融合扫描与 ring-switch 修复。`2^18` 在负载 42–324 波动下重测两次得到 335 s 与
437 s、峰值 5.7–7.8 GiB——wall 随负载漂、峰值随分配器漂，故仍保留负载 37–118
的实测值并标注为融合前。峰值内存每次翻倍增加
2.42 / 2.99 / 3.05 GiB——固定基数加约 **2.8 GiB/翻倍** 的线性项，外推
`2^22` 约 **20 GiB**，取代此前由 32 字节阶梯推出的 55–60 GiB。本节早先引用的 16 字节行（`2^16`
1.52–1.58 GiB、`2^17` 1.69 GiB）在当前构建上不可复现（它们来自更早的构建），
已被取代。`2^16` 下 `RAYON_NUM_THREADS=1` 与 `12` 的峰值分别是 2.30 与
2.32 GiB（该 A/B 在 §9.10 的 ring-switch 修复之前测得），说明 vendored p3 并行路径不会抬高峰值。高水位出现在 mosaic Opening
（Access 时 2.30 GiB，Opening 后 2.32 GiB）：selected 见证 commit 贡献 2.07 GiB
（`2^17` 时 3.70 GiB），register-twist Access 单独峰值为 1.43 GiB；由于释放的
页面不会归还操作系统，高水位更接近两者之和而不是最大值。32 字节阶梯行留下的
结论仍然成立：除 level 存储外的每项都随 `cycles` 线性增长，因此通往 6.4 GiB
的路径是更小的摘要加持位级码字，而不是见证或 level 存储。

proof 比第 3 轮小 54 KB（1,154,711 B → 1,100,335 B）：selected opening 不再携带逐行 claim blob，
rate 1/2 又换回一部分字节。

作为对照，本轮工作的第一版（验证器重建见证、mosaic rate 1/16、没有 streaming 预算）在 `2^16`
是 prove 213 s / verify 1.59 s、峰值 8.11 GiB、proof 788 KB。

`2^12`/`2^13` 的峰值非单调**不是** selected 证明器：register Twist 在
`LINEAR_TWIST_MIN_CYCLES = 8192` 处切换 legacy 与线性共享路径，阈值附近 legacy 历史 sum-check
会有 9–12 GiB 的瞬时工作集；`2^14` 起走线性路径。这是 `binary_twist` 的既有行为，也是若在意
`2^12`/`2^13` 时的下一个内存目标。

## 7. 验证成本（三轮优化）

验证侧曾是最大的差距。RV64 `2^16` 从 **1.42 s**（第 0 轮：重建整条见证、逐行重算电路、
逐 segment 绑定）降到 **175–260 ms**（第 2 轮：流式 segment 绑定 + 并行 claim Merkle），
再到 **54.5 ms**（第 3 轮：proof-only claim 层并入 selected lockstep 的 inner sum-check），
最新为 **47.2 ms**（把 access 与 core 校验移出关键路径）。

第 3 轮 `2^16` 各阶段（paper benchmark，`MAGNETAR_PROFILE_VERIFY=1`）：

| 阶段 | 耗时 | 关键路径 |
| --- | --- | --- |
| claim proof（解码 + leaf 哈希 + 归约） | 5.7 ms | 是 |
| claim 行和（解码行，12 线程） | 7.4 ms | 是（selected 分支） |
| claim schema + challenges | 3.1 ms | 是（selected 分支） |
| lockstep rounds + segment claims + 六次 MLE + ring-switch PCS | 9.1 ms | 是（selected 分支） |
| access statement | 6.7 ms | 否（并行） |
| core（mosaic opening + trace 校验） | 7.5 ms | 否（并行） |
| **合计** | **33.8 ms** | 5.7 + 19.6 |

第 2 轮仍适用的事实：

* trace 参考路径 `verify_dynamic_segments_against_rows` 逐 segment 绑定，只遍历 relation 的
  支撑列（8192 中的约 1400），不再物化 `2^29` 位；`WitnessScratch` 复用一块缓冲，只清上一行
  写过的位。
* claim Merkle 每个 leaf 只哈希一次（`verify_complete_leaves`），每线程连续一段归约，顺序
  与串行一致。
* `MAGNETAR_VERIFY_WORKERS` 固定 segment 绑定线程数（第 2 轮 `2^14` 伸缩：1 线程 208 ms、
  4 线程 58 ms、12 线程 36.8 ms）。

第 3 轮完全去掉了「重算电路」：验证器解码已认证的 claim 行、算出一次批量化 claim target，
并在**已有**的 inner sum-check 内把该 target 绑到已提交见证（§9.5），不再重建任何行见证。

第 4–5 轮直接削掉剩余的 `O(T)` 工作（54.5 → **36.8 ms**）：

| 改动 | `2^16` 效果 |
| --- | --- |
| claim leaf 与树节点改用栈上缓冲直接哈希（每个 leaf/节点不再分配 `Vec`） | claim proof 12.2 → 9.1 ms |
| claim 行和：指令解码按 12 段并行（原来串行），行内去重改用「行号戳」而不是清空列表 | 行和 13.3 → 7.7 ms |
| schema 与行和共用一个已构造的 row/mapping（原来构造两次） | claim sums 合计 15.1 → 10.5 ms |
| access statement、claim 推导 trace、core 校验移出关键路径 | 串行时间 −7 ms |

第 6–7 轮在两处剩余热点上继续「减少工作」：

| 改动 | `2^16` 效果 |
| --- | --- |
| claim 树的 leaf 改为每 8 行一组哈希（每组一次 SHA-256，而不是每行一次）；证明器不再构造 65,536 个逐行 opening，selected bundle 去掉冗余的 `claim_root` 副本 | claim proof 8.7 → 5.7 ms（leaf+tree 6.8 → 约 4），证明器内存/耗时下降 |
| 六矩阵 MLE 求值共享 instance 等式向量与 `Σ eq·eq` 项（`BlockEvalShared`），三个 `eq` 表并行构造 | `eval_mles` 7.5 → 5.2 ms |
| claim schema 与行和共用一个已构造的 row/mapping | claim sums 15.1 → 10.5 ms |

第 8 轮把验证器改成两波，让四个依赖 claim 行的检查互相重叠而不是串联：

* 先解码一次 claim blob（`ClaimProof::decode_rows`，约 1 ms）；
* **第 1 波**：claim leaf/树校验、折入 claim 的行和、access statement、claim 推导 trace 并发；
* **第 2 波**：selected lockstep 校验（用已算好的 claim）与 core proof 并发。

关键路径从「解码 + leaf + 行和 + lockstep」降到
「解码 + max(leaf, 行和, access, trace) + max(lockstep, core)」。各阶段成本不变，
只是把 leaf 校验（5.7 ms）与 access/trace 藏到行和后面。

`2^16` 当前拆分（负载约 10）：claim proof 5.7 ms、claim sums 10.5 ms、selected lockstep
9.1 ms（六次 MLE 5.2 + ring-switch PCS 3.6）、access 6.7 ms 与 core 7.5 ms（两者并行），
合计 **约 33 ms**。

### 第 9 轮：trace Logup-Shout 的折叠求值

在重载宿主（负载 40–125）上对 paper benchmark（`TRACE_SHOUT=1`）做 `2^16` 打点，
**`verify_native trace_logup` 占 393–450 ms，即 515 ms CPU/次的 76 %**；其余阶段都在个位数
毫秒（负载 50 时：`claims decode` 3.5–4.7、`claims_to_trace` 0.9–1.4、`access` 10.8、
`claim sums` 18.1、`core` 15.0）。

这是验证器里剩下的一处**按列 O(cycles)** 步骤：证明侧把 pushforward 丢掉
（`logup.pushforwards.clear()`），`verify_trace_logup_shout` 再从 claim 重建的 trace 里重算
reader/link claims。

* 常数异常：`eval_mle` 调用 `Poly::eval_ext`，它在变量数超过 10 时切到 packed split-eq 表。
  `2^12` 下仅 12 列 reader claims（49 k 元素）就要 **40 ms**。
* 改成显式 O(n) 折叠（同样的插值顺序：最后一维先折、相邻成对），并把相互独立的列折叠
  按 worker 分片（`parallel_evals`）。`2^12` 下 `trace_logup` **70.9 → 20.5 ms**，
  verify 总时间 46.7 → 30.5 ms（负载 30–55）。
该阶段先降到 **70–77 ms**、verify CPU/次 **231 ms**（负载 18–48）：
`columns+positions` 7.2 ms、`reader columns` 0.5 ms、`reader claims` 2.4 ms、
`link claims` 5.8 ms、`reduction verify` 3.9 ms、`final claims` 21.0 ms。

* `2^16` 剩下的开销根本不是折叠：`public_reader_point` 把整张 ROM 逐元素 absorb 进
  SHA-256 transcript——`2^17` 条指令的 ROM 要 786 k 次 absorb，耗时 272 ms。实测单列
  `2^16` 折叠只需 0.7 ms，128 位二进制乘法在 `B` 和 `F2_128` 上都是 20 ns（微基准，
  不是推断），所以既不是域选择也不是折叠形状的问题。reader point 现在只 absorb ROM 摘要
  （`rom_hash`，即 statement 的 `program_hash`）：验证器用 `statement.program_hash`（O(1)），
  证明器对 ROM 哈希一次。`2^12` 下 point 构建 15.5 ms → **9 µs**，该阶段约 2 ms，
  verify 总 CPU/次 68.6 → **31.8 ms**（wall 13.9 ms 稳态，负载 25–60）。
* 公开 ROM 的 table claims 与长度为 cycles 的 position claim 也是相互独立的列，
  一并走 `parallel_evals`：`2^12` 下 `final claims` 0.66–1.4 → 0.62–0.70 ms。
* `embed()` 原来每个周期要做最多 64 次 `interpolation_node`；改成一次性构建的 4-bit
  半字节表（16 次查表），公开 ROM 的列向量也按列分给 worker 构建。`2^16` 下
  `columns+positions` 为 **3–4.5 ms**（仅换半字节表时为 10–18 ms），整个阶段
  **39–46 ms**（本轮开始前是 393–450 ms）。verify CPU/次 **200 ms**（原 231–233 ms），
  稳态 wall **71.8 ms**；其余波次（claim 行和 23–37 ms、access 12–14 ms、
  leaves 7–9 ms、core 13 ms）现在与它同量级。

* 该阶段里最后一次 trace 重建是 `BinaryShoutWitness::from_trace`（`2^16` 下 15–18 ms；
  其中逐周期循环本轮从约 15–20 ms 降到 7–8 ms）。现在按周期分块并行（read values、
  valid/is_32、ROM index），地址位一 bit 一个 worker，只有 ROM 行写入保持串行
  （共享行、写入值相同）。剩下的主要是清零分配：`2^16` 下 `address0/1` 33 MB、
  `read_value` 12.5 MB、`rom` 25 MB。该阶段总量在这台机器上未超出噪声：
  负载 48–68 时为 53–60 ms / 227 ms CPU 次（负载 22–50 时为 39–46 ms / 200 ms），
  循环的收益是真实的，但被分配/清零的下限盖住。

### 第 11 轮：紧凑的 claim 行和 + 无逐周期分配的 shout 见证

验证侧两处热点，问题都在工作集而不是算术：

* **claim 行和改在 slot 空间累加。** 原来的行和按 block 列累加（8 192 项、128 KB），去重戳数组同宽
  （32 KB）；每行约 600 次发射几乎每次都错过 L1。schema 现在携带 `slot_of`（block 列 → 批 claim
  列集中的下标，≤ ~350），worker 按 slot 累加（5 KB）并用 1 KB 的戳数组——两者常驻 L1，每次发射只多
  一次共享只读 `slot_of` 查表。schema 之外的列照旧跳过，claim target 的 `α^slot` 点积不变。
  `2^16` 的 claim 行和 **23–37 → 10.8–12.0 ms**，`claim sums`（解码+求和）→ 15.6 ms；`2^12` 4.1 → 1.4 ms。
* **shout 见证去掉逐周期分配。** `BinaryShoutWitness::read_value` 原来是每周期一个 `Vec`——
  trace Logup-Shout 验证器重建见证时要做 65 536 次分配（12.5 MB 的 192 字节行）。现在改为
  `Vec<[F2_128; 12]>`：每周期一个内联行，按值写入。`2^16` 的逐周期循环 **7–8 → 4.0–4.5 ms**，
  整个见证构建 **15–18 → 7.1–7.6 ms**（首次调用要为新 12.5 MB 缓冲付缺页）；`2^12` 循环 0.86–1.3 → 0.54–0.64 ms。

* **试过并回退：只对置位发射做去重。** 重复列取值一致（由 `claim_emission_stays_inside_the_schema`
  钉住），因此 false 发射本可跳过 `slot_of` 查表与写戳。`2^16` 实测 claim sums 为 16.5 ms，而未改时
  15.6 ms——差异在噪声内，因此保留更简单的写法（对每条发射写戳，仅置位时累加）。
* **ROM 列只构建一次。** 验证器此前为 table claims 又构建了一遍（`2^16` 下 12 × `2^address_bits`
  个值、25 MB、150 万次转换）；现在 table claims 折叠 reader 侧的同一批向量。时间持平（第二次
  gather 命中缓存），但重复副本已消除。
* **reader 与 link claims 合并为一次并行。** 两者折叠点相同，24 列共用一次 `parallel_evals`，
  只需一轮 worker 创建。`2^16` 下合并折叠 3.9–4.9 ms（原先分两次约 6–8 ms），阶段总量
  27–28.5 ms。
* **address 列按精确尺寸直接构建。** `from_trace` 原先清零两块 address 矩阵
  （`2^16` 下 33.5 MB、`2^22` 下 2 GB），随后又用每周期 `indices` 覆盖每一项；现在每一列由
  自己的 worker 直接从 `indices` 构建，填充前的清零遍历被去掉。`2^12` 见证构建 1.4–1.9 → **0.84 ms**。
* **reader claims 改为「边收集边折叠」。** trace 验证器此前先物化 ROM 的收集矩阵
  （`proof.columns × cycles` 个值：`2^16` 下 25 MB、`2^22` 下 768 MB）再折叠；现在每个 worker
  把一列直接收集进自己的折叠缓冲并原地折叠，矩阵不再存在。`2^12` 计时持平（reader+link 合并折叠
  0.63–0.68 ms）；这是内存随规模的一项修正，不是提速项，logup 测试通过。
* **试过并回退：把 `positions()` 也并行。** 该扫描按周期独立，但它已经在验证器的第二波线程里、
  与 mosaic opening 检查并排运行；再起 12 个 worker 让 `2^16` 的 `columns+positions` 由
  **3–4.5 → 5.7–6.0 ms**（线程争用），因此保留串行。后续的经验：验证器已线程饱和，
  下一步要靠「减少工作」而不是「加并行」。

合并效果：`2^16` 的 `verify_native trace_logup` **39–60 → 27–28.5 ms**，verify 稳态 wall
**71.8–84.1 → 60.9–74.2 ms**，CPU/次 200–243 → **198–213 ms**（多次运行负载 20–137；新进程的第一次验证仍慢 2–4 倍）。
第二波（`core` 约 10–11 ms、trace Logup 约 29 ms）现在拆成两个线程而不是一个线程内串行，
mosaic opening 因此藏在 Logup 之下。wall 未超出本机噪声（负载 36–83 时稳态 65.4 ms，对比
负载 20–52 时的 60.9–64.4 ms；CPU/次 209.6 对 206–213 ms），但串行已消除，关键路径只剩
trace Logup 一段。

`2^16` 的 table dump（`MAGNETAR_DEBUG_TABLES=1`）显示堆叠 mosaic 的 cell 只有
**0.03 GiB**：表 5/6 是 `2^16 × 12`，表 11 是 `2^19 × 1`。因此 2.15 GiB 的 commit RSS
来自这些 cell 在 rate 1/4 下的 PCS 码字与 Merkle 树（每个域元素 16 B），而不是表数据。
`2^22` 时 cell 会增长 64 倍（约 2.4 GB），所以 16 B/域元素的码字与树才是 `2^22` 的瓶颈，
不只是表本身。
* 试过并回退：把列转成 `F2_128` 再折叠没有收益——微基准显示两者乘法都约 20 ns。

**9.9 statement 绑定：发现并修复一条恒真检查。** `claims_to_trace` 会把 statement 的
`config / initial_state / final_state / rom / initial_ram` 复制进合成 trace，因此「claim 派生 trace
与 statement 一致」的比较对这些字段恒真（只有 `trace_len` 有效）。篡改测试证实：翻转
`statement.final_state.pc` 修复前**会被接受**。现在验证器直接检查已认证 claim 行的端点（O(1)）：
`claims[0].pc == statement.initial_state.pc`、`claims[last].next_pc == statement.final_state.pc`；
行内 pc 链由 selected lockstep 强制，claims 与见证由 claim target 绑定。`rom` 仍经 trace Logup 表
（由 `statement.rom` 构建）绑定，`initial_ram` 经 twist 见证重建绑定。四个篡改用例（initial pc /
final pc / rom / initial_ram）现在全部被拒绝，正常证明仍通过，全量套件通过。

该阶段原则上仍是 O(cycles)，`2^22` 时会约为 `2^16` 的 64 倍。要变成 O(polylog)，需要把
Logup 的 position 列提交并对着该承诺校验 reader/link claims，而不是对着见证——与 §9 是
同一项结构性工作。英文版 §9.8 给出了完整方案与健全性前提：Logup 证明已携带
`column_claims`/`position_claims`，把 pushforward 留在证明里（长度 `2^address_bits`，KB 级），
再用 selected witness / E5 同一套 packed ring-switch 后端在两个点上打开 position 与 reader 列
（25 个布尔列 × cycles bit = `2^16` 下 200 KB、`2^22` 下 12.8 MB），阶段即降为
O(columns + log)。**前提是这些列必须与已认证的 trace 绑定**（地址位、`is_32`、ROM 索引位都是
claim 字段），即 claim 表本身要可提交并在点上打开——与本任务的 #7 是同一项工作；只提交列
而不绑定 claim 层会得到一个快但不健全的验证器，所以本次没有做。

**内存：峰值来自 mosaic commit，而不是 selected 证明器。** 用 `MAGNETAR_PROFILE_UNIFIED` /
`MAGNETAR_PROFILE_SELECTED` 的 RSS 打点看，`2^16` 的峰值落在 unified mosaic PCS 上：
context 1.1–3.3 GiB、commit 5.9 GiB、selected 阶段 0.9–1.0 GiB。mosaic 原本是 rate 1/8
（`log_inv_rate = 3`，即对表列做 8 倍码字）。改成 rate 1/4（`100, 2, 21, 2`；查询数由库按
rate 与 grinding 推导，仍满足 100 位）后码字减半：

| `2^16` | 改前 | 改后 |
| --- | --- | --- |
| context RSS | 3.31 GiB | **1.11 GiB** |
| commit RSS | 5.87 GiB | **2.85 GiB** |
| prove 峰值 RSS | **7.80 GiB** | **3.06 GiB** |
| verify 峰值 RSS | 6.94 GiB | **2.63 GiB** |
| proof | 1,124,215 B | 1,154,711 B |
| mosaic opening | 316,049 B / 14.7 s | 346,545 B / 19.1 s |
| core（mosaic）verify | 7.5 ms（负载 10） | 11.7 ms（负载 111，不可比） |
| verify 每次 CPU（25 次循环） | 139.2 ms | **138.0 ms**（负载 72–95） |

`2^14` 同样的改动把峰值从 2.58 GiB 降到 **1.12 GiB**、commit 2.58 → 1.03 GiB。按 cycle 计，
现在约是论文内存的 2 倍（`2^16` 下 7.8 → 3.06 GiB），不再是约 5 倍；剩下的每 cycle 成本来自
表表示（每个布尔列每行一个 16 字节域元素）与 `Vec<bool>` 见证（1 B/bit），要达到 `2^22`@6.4 GiB
两者都需要打包表示。

**证明器：六张基矩阵合并成一张非零表。** `row_values` 过去每行要探 6 条稀疏行；现在把基矩阵的
非零项按 local row 汇总成一张 CSR 表 `(slot, column, coefficient)`（`LockstepRows::base_offsets/
base_entries`，约 4,200 项），每行只遍历自己的非零项。与 eager 的逐字节一致性测试仍覆盖每个 level。
`2^12` 下该改动落在机器抖动内（负载 50–90 时 outer recompute 7.5–8.5 s），保留它是因为它严格减少了
每行探测；剩余成本是域乘法受限——vendored `BinaryField128` 的乘法已是 SIMD 无进位乘加约简，
这里没有便宜的可摘空间了。

**验证覆盖**：`native_claim_layer_verifies_without_trace` 与新增的
`native_verifier_rejects_a_tampered_compressed_claim_blob` 现在对 native 验证器消费的每一个字段都做
篡改并要求拒绝：proof width、缺失 mosaic opening、opening 的承诺绑定、virtual claim root、claim 数据
（解码行或压缩寄存器 blob）、`ram_index`、claim 列集合根、trace Logup-Shout 链接声明、claim root、
segment claims、inner round 多项式、ring-switch opening 与折入的 claim target。

**证明器：inner sum-check 曾按「块」扫 lazy extra 行。** 流式 inner 的左侧向量按块从见证推导；
每个块还会遍历它覆盖的实例的 gated extra 行（每个 part 64 条）。早期轮次每块只取两列，
于是约 2^24 个块各扫 128 条、最多命中 1 条。extras 只落在 PC/next-PC/单位常量这三段很窄的局部列上，
因此 `ColumnRows::fill_left` 现在会跳过与之不相交的块（part 2 的链式行落在下一个实例的块里，
所以两个块都要检查）。`2^12` 实测：inner recompute **9.9 s → 2.5 s**、`selected product2`
10.4 s → 2.6 s；把流式 proof 与 eager proof 逐字节对齐的测试在每个 level 仍通过。
`2^16` 的 inner recompute 在负载 62–97 的机器上为 34.7 s（此前较低负载下 40–53 s），比例相同。

selected 证明器在 `2^16` 的各阶段现在是：见证 commit **9.7 s**（此前未单独报告）、claim target
21.6 ms、product6 104.5 s（负载 62–97；低负载 55–72 s）、product2 34.8 s、segments 1.3 s、
opening 11.7 s。

**PCS 参数：证明器的瓶颈是 grinding，不是码长。** selected 见证的 opening 原先用 rate 1/16 + 24 位
grinding（早先按「proof 最小」选定）。在 `2^12` 扫 `(security, log_inv_rate, pow_bits, log_folding)`
发现 opening 时间由查询 grinding 主导（2^pow 次哈希，与表大小无关）：

| 参数 | `selected open` | 验证 PCS | selected opening |
| --- | --- | --- | --- |
| 100, 4, 24, 3（旧） | 40.4 s | 5.05 ms | 188,623 B |
| 100, 3, 24, 3 | 10.0 s | 3.00 ms | 189,743 B |
| 100, 5, 24, 3 | 20.1 s | 3.65 ms | 191,279 B |
| 100, 3, 20, 3（新） | **1.4 s** | 3.28 ms | 201,199 B |
| 100, 2, 16, 3 | 1.2 s | 3.58 ms | 231,727 B |

后端按 `security_level` 推导查询数，因此每行都保持 100 位目标。`(100, 3, 20, 3)` 把 `2^16` 的
opening 从 41.6 s 降到 **12.1 s**，验证侧 PCS 在 `2^12` 从 5.05 ms 降到 3.28 ms，selected opening
增加 23.6 KB（`2^16`：274,975 → 298,559 B）。

**selected PCS 的 rate 扫描（`2^16`）。** 码字与 Merkle 树按 `2^log_inv_rate` 随 packed witness 增长，
因此 rate 在「证明字节 / commit 瞬时内存与时间」之间做交换（grinding 20 位、8-way 折叠不变）：

| `log_inv_rate`、grinding、折叠 | selected commit | selected open | prove 峰值 | verify CPU/次 | selected proof | 完整 proof |
| --- | --- | --- | --- | --- | --- | --- |
| 3, 20, 3（旧，rate 1/8） | 8.7–15.2 s | 12.1–15.1 s | 3.15–4.03 GiB | 200–227 ms | 298,559 B | 919,759 B |
| 2, 20, 3（rate 1/4） | 3.8 s | 12.0 s | 3.11–3.17 GiB | 243 ms | 334,111 B | 955,311 B |
| **1, 20, 3（现在，rate 1/2）** | **2.3 s** | **5.4 s** | **2.01 GiB** | **186 ms** | 479,135 B | **1,100,335 B** |

selected 现在默认 **rate 1/2**——内存优先档，因为目标是论文的 `2^22` 内存包络：`2^16` 实测峰值
**2.01 GiB**（rate 1/4 为 3.11–4.03 GiB），commit 2.3 s、opening 5.4 s，验证反而更快（稳态 34.8 ms、
负载 15–35 下 CPU/次 186 ms）。代价是 proof 字节：1,100,335 B 对 955,311 B（+15 %）。三者单独都到不了
论文的 `2^22` 包络——码字是每域元素 16 B（§3），即使 rate 1/2 在 `2^22` 也还有约 8 GiB 码字加树——
但它是在这个可调维度上离目标最近的点，代价也写明了。

**Merkle 摘要改为 16 字节。** PCS 的 Merkle 树原用 `Keccak256Hash`（32 字节摘要），现改为
`Keccak256Hash16`（Keccak-256 截断，128 位抗碰撞，高于协议 100 位目标），
`MerkleTreeMmcs<…, 2, 16>`。`2^16` 下 prove 峰值从 **2.01–2.61 → 1.52 GiB**，proof 从
**1,100,335 → 845,055 B**（−23 %；`commitment` 280 → 264 B），因为树和每个路径节点都减半。
验证 CPU 在噪声内不变（231 对 186–228 ms/次；该次运行的 wall 在负载 200–330 下无意义）。
`2^12` 对照确认了趋势：该规模下 proof 473,405 → 471,421 B（路径本来就短），验证 CPU 在负载 257 下
43.9 ms/次、负载 30 下 31.8 ms/次——是负载膨胀而非回退。新摘要下 runtime 342、proof 43 与
testkit 测试套件全部通过。

**mosaic 保持 rate 1/4。** 把同一档位用到 *mosaic* PCS 在 `2^16` 上实测后被否决：rate 1/2 反而让峰值
（2.01 → 3.07 GiB）、proof（1,100,335 → 1,252,367 B）与验证成本（稳态 34.8 → 52.4 ms）都变差，
只有 opening 变快（15.3 → 7.0 s）。两者反应不同，因为 mosaic 的峰值来自 opening 的查询路径与
twist 阶段，而不只是 mosaic 码字。

**已否决：按 kind 预计算 claim 发射。** 为加快 claim 行和试过两种更快的写法，都在等价性测试暴露问题后回退：
(a) 把每个未选中 component 的常量贡献折叠成「每个 kind 一个标量」；(b) 按 kind 预计算去重后的
`(位置, 列)` 模板。两者都假设「一行的发射列只由 kind 决定」，但测试表明这不成立：某些 component 的
发射**长度**会随操作数取值变化（同一 kind 可为 687 或 688 项），且同一列可能被多个 component 声称，
因此「每行首次出现去重」（每列只保留一个值）无法用静态模板或可加常量替代。逐行 stamp 去重保留；
`claim_emission_stays_inside_the_schema` 固定了必须成立的两条性质（每个发射列都在 claim 集合内、
重复列的值一致）。

mosaic 改动在 CPU 口径上对验证侧是中性的（25 次循环 139.2 → 138.0 ms/次），尽管
opening 从 19 个查询涨到 40 个：路径更短、码字更小。

**稳态与冷启动**：证明刚结束时的第一次验证比稳态慢 2–4 倍（缓存与 worker 线程都冷）：
`2^12` 首次测得 39–46 ms，而 50 次循环测得 **wall 11.5–12.5 ms / CPU 24.5 ms**。
因此基准同时报告循环值（本轮新增 `MAGNETAR_VERIFY_CPU=N`）；`2^16` 的循环在负载 24–67
的机器上是 wall 44.1 ms / CPU 139.2 ms，可比的是负载 10 时的单次 33.8 ms。

**测量前提**：基准机器是共享的，负载在 8–300 间波动（系统索引、模拟器、桌面应用）。同一份
二进制在负载变化下量到 33.8 / 40.9 / 59.1 ms，而各阶段成本不变，因此下面采用最低负载的一次，
跨轮比较用阶段表。`MAGNETAR_VERIFY_CPU=N` 会重复验证 N 次并打印每次的进程 CPU 时间（与调度
无关，但仍受缓存争用影响）；`prove cpu` 对证明器做同样的事。`2^16` 实测：
**每次验证 CPU 128.8 ms**（25 次 user+sys，负载下 wall 50.6 ms），即平均约 4 核并行——
CPU 总量主要由单线程的 claim proof 与 12 线程的行和贡献，而不是 wall 时间。

## 8. 与论文的差距（Table 6，`erc20-mixed-block`，2^22 cycles）

论文跑 `2^22` cycle；它每 cycle 的 CPU 行只有几百 bit，因此总见证约 `2^30` bit，与我们 `2^16`
（`2^29` bit）同一量级，所以下面的 `2^16` 对比有意义。

| | 论文 `2^22` cycles | 本工作（实测阶梯） |
| --- | --- | --- |
| 见证 bit | ~`2^30`（估计） | `2^29`（`2^16`）→ `2^31`（`2^18`） |
| prover 峰值 RSS | 6.4 GiB | **2.26 GiB**（`2^16`）、4.74（`2^17`）、7.73（`2^18`）、10.54（`2^19`）；线性拟合 `2^22` 约 **20 GiB** |
| proof 大小 | 598 KiB | 861,407 B（`2^16`）、942,535（`2^17`）、1,050,900（`2^18`）、1,177,984（`2^19`） |
| verify | 11–13 ms | **29.6 ms**（`2^16`）、55.8（`2^17`）、161.5（`2^18`）、318.3（`2^19`） |
| prover | 547 ms（原文；更可能是 547 s） | 70.4 s（`2^16`）、147.6（`2^17`）、321.5（`2^18`，融合扫描前）、667.8（`2^19`，融合前） |

剩余差距是可量化的，且已定位：

1. **验证侧的 claim 层与 trace Logup-Shout 都是 `O(rows)`。** `2^16` 下 trace Logup 27–28.5 ms、
   claim 行 15.6 ms、access 12–14 ms、claim leaves 7–9 ms；它们在任何规模下都占据 wall，并随行数翻倍
   （`2^17` → `2^19` 的 CPU/次 410 → 774 → 1613 ms，外推 `2^22` 约 13 s，而论文是 11–13 ms）。论文没有逐行验证工作，因为它的 CPU claim 是
   「已提交列在一点上的打开」；把逐行 claim blob 换成已提交 claim 列是结构性一步
   （结果文档 §9.8，以及交接文档 §9.1 中关于 statement 绑定的未决问题）。
2. **内存由「已提交表的码字与 Merkle 树」主导。** 按 §6：见证 `2^(N+10)` B、level 固定 0.53 GiB、
   rate 1/2 的 selected 码字 `2^(N+11)` B 及其 `2^(N+11)` B 的树（16 B/节点）；实测最大项是 mosaic
   commit/opening 的瞬态（`2^18` 时 5.0 / 6.0 GiB）。按当前实测线性拟合 `2^22` 约 20 GiB，因此通往
   6.4 GiB 的路径是更小的摘要与位级码字，而不是见证（`2^22` 时 4 GiB）或 level 存储。
3. **prove 时间受稀疏逐行扫描约束。** `2^16` 为 84.2 s、`prove cpu` ≈ 800 s；`product6`
   （53.2 s）扫描 `level × rows` = 9 × 2^30 行，`product2`（23.6 s）扫描 8 × 2^29 列，
   每行对打包位求 3.7 条稀疏关系项。§3 的预算扫描把这一设计定在内存下限
   （`level = bits − 21`，402 MiB 存储）；剩余成本是关系求值，而不是拷贝或空闲 worker。

## 9. proof-only claim 层：下一步改动的设计

验证器现在在**输入**上是 proof-only，也不再重算行电路；但仍保留 `O(rows)` 的工作：
解码已认证的逐行 claim blob 并从中累加 claim 和（§7）。论文则是把 CPU claim 绑到
**已提交的见证列**上，用一次批量 sumcheck 校验。下面是逐条对照现有代码的设计。

### 9.1 新绑定的形式

令 `w[row, col]` 为已提交的 CPU 见证位（`LockstepProof.commitment`），`v[row, col]` 为
**claim 列**的声明值——列集合是规范的：`pc` 位、`next_pc` 位、当前 component 的操作数位、
selector 位、指令字位。取新的行点 `z` 与批处理 `α`：

```
Σ_{row,col} eq(z,row)·α^col·w[row,col]  =  Σ_row eq(z,row)·(Σ_col α^col·v[row,col])
```

* 右侧由验证器从压缩的列式 blob 计算，复杂度 `O(#runs)`——现有 `ClaimColumns`
  编码本来就对这类数据做差分/游程编码（65,536 行只有 2,410 B）。
* 左侧对已提交见证是**线性**的，可以像矩阵合并项一样并入现有的 inner sum-check：
  在 inner 的 `left` 向量上加 `γ·eq(z,row)·α^col`、在 claim 和上加 `γ·(右侧)`。
  **不需要新增 proof 字段，也不需要第二次 PCS opening**：验证器用解析式在 `ry` 处求
  系数（行部分是对 `z` 的 eq，免费；`α^col` 是列位上的乘积），再乘以已有的 `vw = z(ry)`。
* 可靠性：lockstep sum-check 已证明提交的见证满足 CPU 关系；绑定 claim 列把该见证与执行
  （PC 链、操作数、opcode selector）绑在一起，这已足够，因为关系加上这些列唯一确定行内其余部分。

### 9.2 阻塞性发现（既有，需要决策）

`prove_unified_trace_dynamic_native_profile` 曾把 `proof.opening` 置为 `None`，
而 `verify_core_statement` 在它是 `None` 时**跳过** `verify_mosaic`。也就是说 dynamic/paper
路径从未真正打开 mosaic 承诺：access、router 与 trace 表的 claim 只做了内部一致性检查。
（已在 §9.6 修复：opening 已恢复并强制存在，且校验 `opening.commitment == proof.commitment`。）
当时的估算：

* 验证成本：对批量点做一次 `verify_mosaic`（实测 `2^16` 为 7.7 ms）；
* 证明成本：补上缺失的 `open`（PCS reveal 会重新 pack 并重新 commit packed 表；已计入 178.3 s）。

### 9.3 分阶段计划

1. 规范 claim 列 + 验证器侧泛函（`O(#runs)`），作为新的 `claim_blob` 载荷；旧的 Merkle
   `ClaimProof` 先留开关以便对比。
2. 把批量绑定并入 inner sum-check（证明器 + 验证器；streaming 的 `ColumnRows` 增加一个线性项）。
3. 恢复 mosaic opening；让 statement 绑定 claim blob（`trace_claim_root` 改为 blob root）；
   删除 `claims_to_trace`、逐行 Merkle 树与 `verify_dynamic_segments_against_rows`。
4. 在 `2^16`/`2^18` 重新测量并更新本文。

预期 `2^16` 端到端验证：**约 25–40 ms**（19 ms proof-only selected + 1–3 ms claim 泛函 +
5–10 ms mosaic opening），即与论文在可比见证规模下的 12 ms 相差约 2–3 倍，且完全不做见证重建。

### 9.4 第一版 proof-only 的验证覆盖漏洞

第一版 proof-only（上一修订的「阶段 2」）把 `bind_dynamic_segments` 换成了
`verify_dynamic_claim_binding`。前者是**唯一**调用 `verify_dynamic_segments_public_point`
（真正的 selected lockstep + PCS 校验）的地方，后者只校验 claim 自己的 sum-check 与 opening，
于是 `verify_native_unified` 不再校验 selected CPU proof，`117.8 ms` 这个数字量到的正是这条
不健全路径。测试没发现它，是因为没有测试通过 unified 入口篡改 proof 级字段。

修复方式即 §9.5（把 claim 并入 lockstep inner sum-check）并始终执行完整
lockstep/PCS 校验。`native_claim_layer_verifies_without_trace` 现在会分别篡改
(a) segment claim 值、(b) inner round 多项式、(c) ring-switch opening、(d) claim target，
并断言四者都被拒绝。

### 9.5 第二阶段落地：claim 并入 inner sum-check

设计与 §9.1 一致，但有一处按代码实际调整：claim 系数直接加到 inner sum-check 的
**左向量**（而不是新增字段），因此一次 sum-check、一次 PCS opening 同时绑定 CPU 关系与 claim。

* `ColumnRows::with_claim(claim, γ)` 把 `γ·eq(z,instance)·α^slot` 并入左向量。声称列是排序
  列表，每次 `fill_left` 用二分查找定位所需窗口——早期 round 每次只取两列，若每次全表扫描，
  `2^16` 会从几十秒变成几分钟。
* 证明器：`expected_inner_claim = base + γ·target`；`prove_dynamic_cpu_claims` 只提交一次承诺并
  传入，`open` 里不再重复提交（`BitPcs::open_with_commitment`）。
* 验证器：检查 `proof.inner.claimed_sum == base + γ·target` 与
  `inner_final == (col_left(ry) + γ·coef(ry))·vw`，`vw` 由 segment claims 重建，
  `coef(ry) = claim.eval(ry[..log_block], ry[log_block..])`。
* 删除 `WitnessClaimProof`、`prove_witness_claim`/`verify_witness_claim`、
  `prove_product2_streaming` 与 `claim_entries`；绑定结构简化为
  `DynamicClaimBinding { target, columns_root }`。
* claim 列集合由 `claim_interface_into` 生成（各 component 的操作数与 selector + PC/next-PC/
  `one`/PC 修正）；**不再声称结果列**——已验证的关系会推出它们。
* `verify_dynamic_segments_public_point` 从承诺与 proof 内声明的 target 重建 claim 系数；
  target 本身只由 `verify_dynamic_claim_binding` 依据已认证行重算后才接受。

### 9.6 mosaic opening 已恢复

dynamic 路此前跳过 `prove_opening`，于是 `verify_core_statement` 跳过 `verify_mosaic`，
access/router claim 从未绑到 mosaic 承诺（§9.2）。两处都已修复：

* native profile prover 执行 `Opening` 阶段，`verify_native_unified` 拒绝不带 mosaic opening 的 proof；
* `verify_core_statement` 现在检查 `opening.commitment == proof.commitment`
  （P3 opening 自带承诺；不检查的话可以把合法 claim 配一个无关 opening）；
* paper 路的 committed-Shout ROM claim 在 opening 生成前折入（`add_logup_shout_rom`），
  使用 paper Logup 时不再运行冗余的 trace-Logup-Shout worker。

仍存在的缺口：`proof.logup_shout`（paper 路）目前只用到它的 link claims，Logup-Star 本身需要
Shout 见证才能校验，native 验证器没有校验它；trace-Logup-Shout 变体则确实对照由 claim 推导的
见证被校验。

### 9.7 实测成本（论文基准，`WIDTH=64`，`MAGNETAR_PROFILE_VERIFY=1`）

`2^16`（ADDS=65,535，65,536 行），完整校验（含 selected lockstep、claim 绑定、mosaic opening）：

| 阶段 | 耗时 |
| --- | --- |
| claim proof（解码 + leaf 哈希 + 归约） | 12.1 ms |
| claim 行和（12 线程） | 12.6 ms |
| lockstep rounds + segment claims + MLE + ring-switch PCS | 11.8 ms |
| access statement | 6.6 ms |
| core（mosaic opening） | 8.0 ms |
| `claims_to_trace` | 0.8 ms |
| **verify 合计** | **54.5 ms** |

证明器 154–189 s（随机器负载波动；峰值 7.8 GiB；阶段 RSS：context 3.3、commit 5.9、
access 13.9 s、opening 14.7 s、selected 阶段 4.5–6.6 GiB；selected PCS opening 在 §7 改参数后为 12.1 s）；
proof 1,124,215 B（varint 974,921，压缩 892,495）：
access 259,812 B、logup 245,377 B、mosaic opening 316,049 B、selected 275,007 B。

`2^12`（ADDS=4,095）：verify 12.4 ms、prove 约 40 s、proof 600,269 B。

`2^16` 验证侧演进：1.42 s（重建见证）→ 117.8 ms（不健全，跳过 lockstep）→
54.5 ms（claim 并入）→ 47.2 ms（access/core 移出关键路径）→
36.8 ms（claim 哈希零分配、行解码并行、row 复用）→
**33.8 ms（8 行一组 claim leaf、共享 MLE 求值），且每层都校验**。
剩余成本是 claim 层的逐行工作（关键路径 16.2 ms）与 selected lockstep 校验（9.1 ms）；
论文的 8 ms 是在 8 倍行数上给出的。

### 9.10 register-twist Access 阶段：瓶颈是 PCS，不是 sum-check

register twist 是 Access 层里最大的单个子证明（`2^16` 行 → `2^17` 周期 →
`32 × 2^17 = 2^22` 个域元素）。给 `prove_local_shared` 加上
`MAGNETAR_PROFILE_LOCAL=1` 后，`2^16`（负载约 80）的分解如下：

| 阶段 | 改前 | 改后 |
| --- | --- | --- |
| 建表（`build_columns`、dense one-hot、val 表） | 0.27 s | 0.09 s |
| PCS commit | 11.06 s | **0.49 s** |
| RW + Val + Virtual 三次 sum-check | 0.62 + 0.16 + 0.52 s | 0.20 + 0.09 + 0.25 s |
| value claims | 0.02 s | 0.01 s |
| PCS opening（主表） | 23.21 s | **0.18–0.24 s** |
| endpoint commit + opening（2 × 32 行） | 11.60 s | **0.003 s** |
| final rounds | 0.47 s | 0.10 s |
| **合计** | **48.2 s（负载 80）** | **1.43–1.55 s（负载 90）** |

五项改动，按收益排序：

1. **endpoint 表改用小表 PCS 档位**：`linear_pcs(cells)`（32 行 →
   `P3BinaryPcs::new(100)`），而不是周期表档位。endpoint 表是两列 × 32 行
   （6 变量的堆叠多项式），这个域用很短的查询序列就能达到 100 位目标，因此
   周期表档位的 24 位 grinding 一分安全性都买不到，却花掉 11.6 s。验证端按
   shape 推导出同一档位，proof 不额外携带参数。
2. **每次承诺只编码一次**：`open_batch` 为了重建 opening 会重新编码并重建
   Merkle 树（它看不到之前的承诺）。新增 `P3BinaryPcs::commit_batch_prepared`
   / `open_batch_prepared` 保留 `BinaryPcsProverData` 与 commit 后的
   challenger，Fiat–Shamir 顺序（commit → 采样点 → open）不变，opening 复
   用码字与 Merkle 树。opening 从 10.0 s（第 3 项之后）降到 1.9 s；承诺与
   transcript 与旧路径完全一致。
3. **本地 PCS 档位 `(100, 4, 24, 3)` → `(100, 3, 20, 3)`**，与 selected PCS
   一致（率 1/8、20 位 grinding、8 路折叠、100 位安全）。commit 11.1 → 6.3 s，
   opening 23.2 → 10.0 s；本地 opening 让 proof 增加 16.4 KB。
4. **打开 vendored p3 的并行特性**：`p3-binary-pcs` 与 `p3-merkle-tree` 启用
   `parallel`（rayon 已经通过 ligerito 在依赖树里），码字编码与 Merkle 哈希
   用满所有核。commit 5.4 → 3.6 s。selected 与 mosaic 的 `P3BinaryPcs`
   实例同样受益。该特性同时打开了 p3 的并行 grinding：它返回任意一个满足
   条件的 nonce，导致 proof 字节逐次变化，甚至长度也变（平凡折叠可能省略
   一个 root）；三条字节等价测试当场抓到这个回归。现在
   `vendor/plonky3/binary-field` 的 `BinaryChallenger::grind` 带剪枝地选择
   最小的满足条件的候选，与串行路径完全一致，因此在保持并行的同时 proof
   仍然逐字节一致。
5. **融合的按索引 sum-check**（`sumcheck_terms_indexed`、
   `fixed_sumcheck_indexed`）。旧实现每轮为每个因子物化 `degree + 1` 份完整
   拷贝（首轮四线程 × 五个 4.2 M 元素因子 = 1.3 GB 瞬态）；新实现按索引从
   因子对上求值，并原地折叠因子。它与 `sumcheck_terms` 逐位一致（由
   `indexed_sumcheck_matches_reference` 与
   `indexed_fixed_sumcheck_matches_reference` 断言，包含折叠后的因子），并把
   register-twist 峰值 RSS 从 1.72 GiB 降到 1.33 GiB。sum-check 从来不是瓶颈：
   48 s 里只占 1.8 s。

同机交错 A/B（`local_shared_bench`，`ROWS=65536`）：

| 二进制 | prove | user CPU | 峰值 RSS | 负载 |
| --- | --- | --- | --- | --- |
| 改前（24 位档位） | 41.1 s / 50.5 s | 27.8 / 28.4 s | 1.72 / 1.34 GiB | 65 / 50 |
| 仅融合 sum-check | 39.2 s / 40.3 s | 28.2 / 28.1 s | 1.33 / 1.18 GiB | 62 / 70 |
| PCS 改动后（未开 p3 并行） | 9.0 s | — | — | 50 |
| 最终（五项全开，含并行与确定性 grinding） | **1.43 s / 1.55 s** | 8.1 / 8.0 s | 1.43 GiB | 90 / 92 |

宿主机全程共享且噪声大（12 核上 1 分钟负载 50–767），只有比值有意义：
register-twist 证明快 **30×**、verify 3.7 ms；五项改动分别去掉 11.5 s
grinding、22 s opening、10.6 s commit，同时峰值 RSS 降 17 %（1.72 →
1.43 GiB；仅融合 sum-check 的串行版本是 1.34 GiB）。proof 字节回到
219,208——与串行 grinding 版本一致，这也是确定性检查。带这些改动的完整
`2^16` benchmark 待机器空闲后补测；上表是经
`prove_local_shared`+`verify_local_shared` 端到端测得的阶段分解。

两点保留：p3 的并行路径同样服务 selected 与 mosaic 的 PCS，selected
commit/open 与 mosaic opening 本身也应缩短，但未实测；另外并行编码会分配
每线程缓冲，`2^16` register-twist 峰值 1.33 → 1.43 GiB，而 `2^17`–`2^19`
阶梯行早于该特性，引用规模模型前需要重测。剩余证明开销是
`selected product6`/`product2`（§6 阶段分解）：product6 的扫描量是
`level × rows`（`2^16` 时 `9 × 2^30`），因为 level 存储按 §3 的预算被限制
在 `2^22` 项（402 MiB）；product2 折叠列空间；两者都处在既定的内存/预算
下限上，而不是拷贝或并行缺陷。

用 `MAGNETAR_PROFILE_VERIFY=1` 实测，`2^16` 的验证器现在是
**30.3 ms/次、5 次迭代 wall 31.6 ms、CPU 188.0 ms/次**（负载 72–83），分解如下：

| 阶段 | 时间 |
| --- | --- |
| trace Logup-Shout（现在随 trace 就绪启动，与两波重叠） | 21.9–29.6 ms |
| — Shout 见证构建（`from_trace`） | 7.5–10.0 ms（与 wave 1 争用） |
| — reader + link claims（12 + 12 列 × 65536 行） | 3.0 ms |
| — columns+positions / reduction / final claims | 2.5 / 2.4 / 2.5 ms |
| claim 行和（wave 1，12 workers × 65536 行） | 11.5–12.4 ms |
| core proof（mosaic PCS 校验 + eval_mles） | 7.9 ms |
| access | 6.7 ms |
| claim leaves / decode / claims-to-trace | 3.8 / 1.1 / 0.8 ms |

trace Logup-Shout 现在在 claim 派生出的 trace 就绪后立即开始，与两波都重叠；
与 claim 行和争用核心时它自身会拉长到 21.9–29.6 ms，所以 wall 收益受限于争用
（34.3 → 30.3 ms，CPU 193.3 → 188.0）。剩余各项都是 `O(rows)`，把它们变成
polylog 需要 §9.8 里「提交 claim 列」那一项；wall 已从两轮前的 60.9–84.3 ms 降下来。

selected opening 也有同一类缺陷。打开 `MAGNETAR_PROFILE_RING=1` 后它的分解是
`ring pack 1.8 ms、ring eval 2.89 s、ring product2 0.15 s、ring p3 open 0.63 s`；
其中 `ring eval` 主要花在 `eq_vector` 上——它给每个表项分配一个 `Vec`
（`2^16` 时 420 万次堆分配，即 `2^22` 个打包字），并且每个打包字要做 128 次位测试。现在表按层倍增
构造（数值相同，由 `eq_vector_matches_pointwise_eq` 锁定），每个槽的求和只遍历
打包字里被置位的位，并按 worker 拆分（XOR 归约，结果精确）。`ring eval` 降到
**0.13 s**，`selected open` 从 3.68 s 降到 **0.91 s**，`2^16` prove 从 84.2 s
降到 **79.2 s**，proof 逐字节不变（861,407 B）。

外层 sum-check 的内层循环也有同样的形态：每行先物化六个槽的值，再对每个槽做
两次比较后施加权重。现在 `LockstepRows::accumulate_row_values` 把权重并进稀疏
CSR 扫描——每个置位的表项加 `weight × coefficient`，`coefficient == 1` 走快路径
——按分配律与原实现逐位一致（tower 域里 `w(c1 + c2) = w c1 + w c2`，槽内求和
是 XOR）。`product6` 从 51.8 s 降到 **43.2 s**，`2^16` prove 从 79.2 s 降到
**70.4 s**，proof 逐字节不变。内层（`product2`）的同款融合会改变 proof 字节，
已回退而不是保留半验证状态。二分定位确认：只融合**右侧（bit）**可逐字节通过，
差异出在**左侧**输入 `fill_left`——它还会把稀疏的 claim 增量
（`claim_columns` + `claim_instance_weight`）折进每个窗口；单独重放这些增量的
融合版本仍然不一致，逐窗口自检未能在放弃前定位剩余差异。整条线索最多约值 3 s：对右侧融合在 `2^14` 做交错 A/B（未改动的 `product6`
在同一批运行里漂到 15.1–20.1 s），`product2` 改前 7.4–8.6 s、改后 8.85–8.99 s，
即这台机器分辨不出收益，因此也没有保留。再投入前需要安静宿主上的 A/B。

在完整流水线里，同一阶段现在是 `access register claims: 2.53 s`，selected 见证
setup 为 `setup fill+check: 0.48 s`。此前那 160.7 s 几乎全是既有的「每 cycle
一次 `eprintln!`」检查点加串行填充；现在填充按 worker 拆分 cycle，各自写自己的
`base_cols` 位字区间，并把 64 个 block 位打包成一次字写入。`2^14` 流水线上
`RAYON_NUM_THREADS=1` 与 `12` 的峰值都是 1.10 GiB，说明 p3 并行特性不会抬高
峰值（`2^16` 实测 2.26 GiB，落在 §6 记录的 2.01–2.61 GiB 区间内）。

### 9.11 width-64 测试与 E5 PCS 档位 bug

现在所有走完整流水线的测试都以 RV64 宽度运行：testkit 集成测试（`e2e`、
`paper_mode`、`native_trace_mode`、`logup_shout_mixed`）、`protocol_determinism`
示例，以及 runtime 的整机证明测试（unified/paper/dynamic、chunked、trace、
selected claims、virtual CPU、claim-native、cpu-shape、gated、orchestrator）。
`protocol_determinism` 在宽度 64 下并发跑 120 对 prove/verify，字节零不一致，
同时也覆盖了 §9.10 的并行 grinding 确定性。

这次转换暴露了一个 **RV64 路径上既有的完备性 bug**：
`UnifiedProveContext` 在追加 gated component/shift/active 三张表**之前**就用
`opening_pcs(&mosaic_tables)` 选好了 mosaic PCS 档位。当后加的表是最大的那张
（width 64 的小 trace 正是如此）时，证明端用小表档位（率 1/8、24 位 grinding）
打开承诺，而验证端从承诺推导出大表档位（率 1/4、21 位），于是每个 field 子集
opening 都被拒（`field opening rejected`）。width 8 下没有表越过阈值，所以
一直没被发现。修复把档位选择移到所有表追加之后，证明端与验证端从同一张表集合
推导。该失败在关闭 p3 并行时同样复现，与 §9.10 的改动无关；插桩确认两端的
field 点与值完全一致，差异只在 PCS 档位。

转换又暴露并修复了两个 width-64 缺陷。AMO add/logic 行把字掩码写成
`(1u64 << width) - 1`；width 64 时该移位会回绕（release 下 `1u64 << 64` 等于
1），掩码变成 0，见证里的值全被清零，于是批 sum-check 的 claimed sum 与验证
端不一致（`sumcheck claim mismatch ... expected 0`）。`pc_target_row` 与
`pc_transition_row` 对 target/next 的掩码有同样的回绕。四处现在都像
`amo_minmax_row`、`mul_row` 一样对 width 64 特判为 `u64::MAX`。

把基准示例也改成 64 时，又暴露了 `prove_gated_bundle_from_trace` 里一个既有的
**完备性 bug**：它把 PC 链终点取成 `last_row.pc + 4`，而
`gated_rows_from_trace` 会在最终 PC 上追加一条停机行，于是以自循环 `ecall`
结束的 trace 会越过终点，PC sum-check 永远无法归零（width 8、32、64 下都会
panic）。终点现在取最后一条已执行行的 `next_pc`，对完整 trace、停机行与 chunk
都成立；`gated_trace_bundle_m4_m5_bench` 在 width 64 下可证明可验证（M5 ring：
1.95 s 证明、165 ms 验证、255,787 B）。

修复后，所有走完整流水线与基准的测试和示例都以 width 64 运行（testkit 里
仍有 16 个示例沿用 width 8 证明——chunked、dynamic、gated-bundle、claim-native、
selected、unified 等——已一并改为 64；全部可编译并在 64 下跑通）。剩下的
width-8 调用都来自**被测对象就是 8 位算术**的单元测试（`0xff` 回绕、
`Sra(248, 1)`、8 位 split/shift 关系、`u8`/`i8` proptest）：`magnetar-cpu` 21 处、
`simd_dual` 的动态行测试 19 处、`simd_f2` 的移位/ALU 关系测试 11 处、各 row
模块 12 处。它们构造 8 位字是为了测算术本身，而不是证明宽度；所有会跑证明的
测试与示例都已使用 width 64。另在
`magnetar-pcs` 增加回归测试
`mosaic_opens_a_twelve_column_table_with_repeated_points`，锁定 mosaic 打开器
支持 field opening 产生的表形状。

## 10. 复现

```bash
# 只看 selected 阶段（上面的阶梯）
WIDTH=64 ADDS=65535 MAGNETAR_PROFILE_SELECTED=1 \
  cargo run --release --offline -p magnetar-testkit --example selected_stream_probe

# 与 eager prover 的字节等价性
cargo test --release --offline -p magnetar-runtime --lib streaming_lockstep_proof_matches

# 完整流水线（受 unified CPU commit 限制，见 §6）
/usr/bin/time -l env WIDTH=64 ADDS=65535 MAGNETAR_PROFILE_UNIFIED=1 \
  cargo run --release --offline -p magnetar-testkit --example paper_unified_bench
```

## 11. RV64 `2^16` 优化轮（2026-11-03）

状态：在既有 streaming 证明器之上的增量优化，streaming/eager 字节等价闸门保持绿。分支 `virtual-claims-rewrite`。

### 11.1 头部数字

| | 本轮之前（§1） | 本轮之后 |
| --- | --- | --- |
| prove wall | 70.4 s | **31.4–34.6 s**（宿主 load 15–66；item 9 前 38.3–38.6 s、chunk 前 53.8–59.3 s） |
| prove CPU（user+sys） | ≈800 s | **274.2–274.9 s**（item 9 前 321–325 s，起点 ≈800 s） |
| verify wall | 29.6 ms | **24.7–27.2 ms**（legacy 行路径 46.0 ms，§11.6） |
| 峰值 RSS | 2.26 GiB | **1.94–2.01 GiB**（item 9 前 2.03 GiB） |
| proof 字节 | 861,407 B | **1,018,152 B**（claim 表格式，见 §11.6） |

claim 表现在是默认开启：同一个 2^16 二进制上，它替掉 `O(rows)` 的 claim 行和，
verify 从 46.0 → 27.4 ms，代价是 +157 KB proof；2^10 上「表路径慢 1.4 ms」只是
小规模下 PCS 固定成本占主导。

这台机器上 wall 跨次不可比：本轮 load 在 13–150 之间波动，同一二进制同一规模的 spread 达 2.4×。真正可靠的数字是 CPU 时间：同样的 2^16 运行从 ≈800 CPU-s 降到 **421.6 CPU-s**，即工作量约 **1.9×**。下面各阶段 A/B 都在同一二进制里用 env 开关完成（§11.4），不依赖跨二进制 wall。

### 11.2 阶段分解（load 37–72）

| 阶段 | 之前（§2） | 之后 |
| --- | --- | --- |
| unified context | 0.48 s | **0.31 s** |
| unified Commit | 1.19 s | **0.52 s** |
| unified Access（register twist） | 2.56 s | 2.63 s |
| unified Opening | 3.38 s | **1.99 s** |
| selected setup | 0.48 s | 0.40 s（`setup fill+check`） |
| selected witness commit | 0.95 s | **0.32 s** |
| `product6`（外层扫描） | 43.2 s | **18.18–18.36 s**（item 9 前 24.5–25.0 s） |
| `product2`（内层扫描） | 23.4 s | 内层 budget 22 时 27.5 s；本轮把内层 budget 提到 24（§11.3 第 4 条），全链路实测 24.5 s；第 8 条的 chunk 填充再让该 stage CPU 减半 |
| selected segments | 1.17 s | **0.009 s**（已重写，§11.3 第 7 条） |
| selected open | 0.92 s | **0.84 s** |

两个 streaming product 仍占大头，但外层已不再是一枝独秀。外围阶段也因 teammate 的 p3 hash 修复（§11.5）明显下降：Commit/Opening 约减半。

### 11.3 改了什么

1. **不再扫描零填充行**（`LockstepRows::live_rows`、`prove_product6_rows`）。`SharedBlockMatrix` 把行数向上取整到 2 的幂；RV64 `2^16` 下这份 padding 占 `rows` 的 49.6 %（`2^29` 个 instance 行 + 4,194,368 个 extra 行 pad 到 `2^30`）。live 行之后的六个 slot 全为 0，且整块 padding 对任意 eq 权重都贡献 `product6_pair(0,0,..)=0`，所以每一轮 phase 1 都在最后一个 live block 停止。phase 2 折叠携带「短长度」：它是概念数组的前缀、越界的奇数项为 0；但 **eq 值必须保持全长**（边界元素在后续轮会与它一起折叠——这正是本轮唯一一个 bug，字节等价闸门抓到了它）。
   同二进制 A/B（`2^14`，`MAGNETAR_LIVE_FULL=1` 关闭该优化）：product6 **12.8 s → 6.5 s**，整次 prove CPU 166 s → 101 s。
2. **无分支 set-bit 累加**（`accumulate_row_words`）。扫描是 CSR 上每行 ~3.7 个条目，唯一不可预测的分支是 `if bit { add }`；现在改成一次 word load + 0/all-ones 掩码 + 掩码 XOR，消掉 ~50 % 的分支误预测。按构造逐位一致。
3. **工作窃取式轮内调度**（`parallel_chunks`）。这台机器是 6 性能核 + 6 能效核，固定均分会给能效核留下 straggler（轮时间最多慢 1.3×）；现在 worker 从共享计数器领 chunk。域加法是 XOR，partial sum 的合并与谁处理哪块无关，所以 proof 字节不变。
4. **内层 level budget 22 → 24**（`auto_level_inner`）。内层（列空间）sum-check 原本要重算 `column_bits-(budget-1)` 轮；多 2 bit budget = 固定 `2^24×16B×2 = 512 MiB` level 数组，换掉 8 轮里的 2 轮全列扫描（内层 stage 的 -25 %；2^16 峰值 +0.5 GiB）。`MAGNETAR_INNER_BUDGET_LOG` 可覆盖。
5. **可比的测量手段**：所有 env 门控的阶段打印现在都带累计进程 CPU 时间（`magnetar_proof::process_cpu_seconds`，`getrusage`）；streaming 阶段加了同二进制诊断开关（`MAGNETAR_STREAM_WORKERS`、`MAGNETAR_LIVE_FULL`、`MAGNETAR_P2_FUSED`、`MAGNETAR_INNER_BUDGET_LOG`）。这是本轮 A/B 在共享机器上仍然可信的原因。
6. **benchmark 内存看门狗**（`magnetar_testkit::install_memory_watchdog`，`MAGNETAR_MAX_RSS_GIB`，默认 4 GiB）：任何跑证明的 example 在把宿主推进 swap 之前直接 abort。`protocol_determinism` 默认改成 2 线程 × 10 轮（20 对，1.99 GiB），旧的 120 对并发峰值 5.75 GiB。

7. **segment claims 重写**（`split_segment_claims_bits`）：原实现每个 segment 重建 eq tensor、逐 bit 读见证、单线程；改成 per-width 共享 eq tensor + 64-bit word 扫描（set-bit 迭代、累加顺序不变）+ 每 segment 一线程（按 layout 顺序收集）。`selected segments` 在 `2^14` 从 298/304 ms 降到 3.1/2.6 ms，在 `2^16` 从 1.20 s 降到 **9 ms**；claims 与参考求值器逐位一致（`split_bits_claims_match_the_reference_evaluator`），`2^14` proof 字节不变（859,845 B）；该阶段在串行尾，2^16 省约 1.19 s 墙钟。

8. **内层扫描按 512 列 chunk 填充**（`prove_product2_columns`）。原 materialise-and-accumulate 循环每个 sum-check block 调一次 `fill_left`，而该调用带有 per-block 记账（instance 边界、claim 窗口二分、extras touch 检查），成本比 round 0 那两列本身还高。改成每次填 512 列，把记账开销摊薄 ~256×，而逐列运算顺序完全不变、proof 字节不变（`MAGNETAR_P2_BLOCKWISE=1` 可回到 per-block 版本供 A/B）。`2^14` 同二进制交错 A/B：`product2` 12.4/17.0 s → **5.1/5.5 s** wall、整次运行 CPU 103 → 74 s；`2^16` 内层重算从 226 → **108 CPU-s（-52 %）**，安静宿主上 `product2` 预期从 24.5 s 降到 ~12 s。

外围阶段（teammate 轨道，同一棵树）：vendored p3 里的 `Keccak256Hash16` 没有转发 `hash_many`，Merkle 树全走逐条 hash；转发后叶子批量哈希，p3 CPU 降 2.1–2.7×（selected 2.4×、mosaic 2.7×、local 2.1×）。另外：`open_batch_prepared` 去掉 prepared 数据的 deep clone（2^16 下 -0.5 GiB memcpy）、`P3BinaryPcs::commit/open` 单次表转换、register-access 建表去冗余（Access 独立测量 7.6 → 5.0 CPU-s）、context 无 CPU 列时跳过 reservation 行构建。

### 11.4 共享机器上的测量方法

- **wall 在这里不可靠**：同一二进制同一 `2^14` prove 在负载变化下实测 18.5 s 和 55 s；load 几分钟内从 13 到 150。§9.10 早先「内层融合 neutral / 最多 3 s」的结论正是被这种噪声误导。
- **用 CPU 时间**（profile 里的 `cpu=`，`getrusage`）：它数的是工作量而不是等待，负载下只有几个百分点的漂移。
- **归因用同二进制开关**：重建两个二进制会把树上所有其他人的改动一起带进对比。
- 正确性靠字节等价闸门，不靠计时：`streaming_lockstep_proof_matches_the_eager_proof_bytes`、`parallel_chunked_streaming_matches_sequential` 在新扫描下仍绿。

### 11.5 没成功的尝试

- **融合/外提的内层 block 循环**（`ColumnRows::block_values`）：把 `instance_weight` 提出 per-column 循环、fill+accumulate 融合，看起来每列省一次 `F2_128` 乘法，但每个 block 的 claim/extras/二分查找固定开销吃掉了收益。同二进制 A/B（`2^14`）：**9.1 CPU-s vs 6.3 CPU-s，慢 35 %**。代码留在 `MAGNETAR_P2_FUSED` 开关后面，默认走原来的 materialise-and-accumulate。
- Access 阶段的 hoisted sum-check 求值器：重复 load 被 cache/LLVM 吸收，CPU 时间 0 % 收益，已回退。
- 工作窃取保留（鲁棒性），但其单独收益在这台宿主机上无法隔离：两次相同运行的 wall 差异比预期收益还大。

### 11.6 proof 字节与 claim 层

proof 从 861,407 B 涨到 **1,018,152 B**（varint 829,741 B、压缩 667,089 B）。
这**不是**本轮 prover 改动造成的：它来自进行中的 polylog claim 层
（`docs/POLYLOG_CLAIM_VERIFIER.md`），把 claim 表按打包 bit 列提交，并把
commitment/opening 挂到 `ClaimProof` 上。claim 表 PCS 用 rate 1/8
（`P3BinaryPcs::with_params(100, 3, 20, 3)`）；rate 1/2 时同版本 proof 是
1,136,696 B 而 verify 时间一样，所以 rate 1/8 是最终参数。过渡期行 blob 仍然存在
（`MAGNETAR_CLAIM_TABLE=0` 即回到它）；去掉它是下一步结构工作（M4/M5），之后 proof
会降回旧大小以下。

同一个 2^16 二进制、一分钟内交错测得：

| claim 表 | verify | proof | peak |
| --- | --- | --- | --- |
| 关（legacy 逐行和） | 45.97 ms | 861,408 B | 2.19 GiB |
| 开，rate 1/8（默认） | **27.38 ms** | 1,018,152 B | 2.38 GiB |

### 11.7 下一步

1. **内层 stage 现在是最大单项**（24.5 s）。剩下的便宜杠杆：把 `fill_left` 的 per-block 开销摊到更大的列 chunk（实测 round 0 的 per-block 成本占比很高）；以及在安静宿主上重新评估 level budget 的取舍。
2. **外层扫描**（24.5 s）：每行 3.7 个条目是该形式的 floor；剩余想法是更紧的 CSR 布局（把 `(word, shift, slot, coefficient)` 压进 16 B）与 bit 窗口预取。
3. **claim 层**：完成 M4/M5，让 claim 表取代行 blob（proof 回到 861 KB 以下，验证器剩余的 O(rows) claim/Logup 工作消失）。
4. 2^17/2^18/2^19 阶梯只在带内存看门狗、一次一个运行的条件下重测；本轮宿主的空闲内存一度低于 1.5 GiB。
