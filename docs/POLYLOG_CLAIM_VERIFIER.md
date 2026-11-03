# 提交 claim 列 → polylog 验证器（M1 设计，待 Lead 确认）

状态：设计稿，**未改代码**。分支 `virtual-claims-rewrite`，基线 HEAD `eca3cb3`。
相关：`docs/HANDOFF.md` §5.1、`docs/STREAMING_SELECTED_PROVER_RESULTS.md` §7/§9.5/§9.8、
`docs/STREAMING_SELECTED_PROVER_HANDOFF.md` §9.1。

## 0. 结论摘要

- 现在 RV64 `2^16` 验证器 30.3 ms wall / 188 ms CPU，剩下的非 log 项（§1 表）：
  trace Logup-Shout 21.9–29.6 ms、claim 行和 11.5–12.4、claim leaves 3.8–4.1、access 6.7、
  claims decode 1.0、claims-to-trace 0.77。core PCS 7.7–8.0、selected lockstep 9.1 已是 O(log)，
  不在本任务内。
- 统一改造对象：新增 **claim 表 `T`**（host/statement 生成时从 trace 按列计算的表），
  statement 绑定其承诺摘要；proof 携带 `T` 的 ring-switch 打开。
- **核心新原语（`claim_rel`）**：对已提交的布尔列，验证任意**公开系数的线性关系**
  `Σ_slot c_slot·T_slot(z) = v`（z 为随机行点、c 公开）只需要「slot 维小 sum-check + 一次
  ring-switch 打开（在 `(z, q*)`，q* 由 sum-check 挑战给出）」，verifier 成本 O(log C + log) ≈
  1.5–2.5 ms。它同时解决：
  - **M3**：claim target 就是 `Σ_slot α^slot·T_slot(z)`，claimed sum = 已绑定到 W 的
    `binding.target`，关系成立 ⟺ target 确实由已提交 claim 列算出。**不需要改 `simd_dual.rs`
    的列系数**（原来设想的 λ 张量技巧作为备选，不需要了）。
  - **M4**：position↔pc、valid、is_32 等**线性**关系检查，以及对 logup 已提交列
    （word/code/width/position）与 `T` 数据列的随机点一致性绑定。
- M4（trace Logup-Shout）复用已有的 committed `logup_shout` proof：**保留 pushforwards**
  （prover 不再 clear）、native verifier 第一次真正校验 Logup* 本体（§9.6 已知缺口），
  reader/position/link claim 由「logup 自己的 opening + `T` 绑定」认证，不再从 claim 行
  重建 witness（删掉 7.1–7.6 ms 重建 + columns/positions/claims 重算）。
- **有序性/健全性风险（需 Lead 决策，§4.0）**：M2/M3 落地时，行 blob 仍被 trace Logup（M4）
  和 access（M5）消费，必须继续被认证。建议过渡期保留旧行 Merkle 认证（塞进同一个
  `trace_claim_root` 摘要、零 struct 改动），M5 删行时再切换语义；否则 M2–M4 之间存在
  「行未认证但被消费」的缺口。
- 预计终态：`2^16` wall ~11–15 ms；M2+M3 单独落地约省 ~9–11 ms CPU
  （wall 受 trace Logup 长杆限制，先不变）。

## 1. 每项 O(rows) 工作的替换方案

| # | 现状（2^16） | 现在做什么 | 替换为 | 里程碑（对应 Lead 编号） |
| --- | --- | --- | --- | --- |
| 1 | trace Logup-Shout 21.9–29.6 ms | 从 claim 行派生 trace → `BinaryShoutWitness::from_trace` 重建 reader/link/position 列 → 重算 pushforwards → 逐项校验 | 复用 committed `logup_shout`（pushforwards 留在 proof）：`logup.verify` 直接跑；reader 列由 logup 自己的 PCS opening 认证；position/link claim 用 `T` 的数据列做随机点绑定；`column_claims` 对**公开 ROM**（从 `statement.rom` 重建）做 O(rom) 检查；关系检查用 §0 的 `claim_rel` | M4（Lead M3） |
| 2 | claim 行和 11.5–12.4 ms | 逐行重新发射 ~336 个 claim 列、算 row sums，构造 target，与 binding 比对 | target 不变（仍由 prover 从 trace/claim 数据算，仍被 inner sum-check 绑定）；verifier 改用 `claim_rel` 校验 `Σ_slot α^slot·T_slot(z) = target`（一次 ring 打开） | M3（Lead M2 的一部分） |
| 3 | claim leaves 3.8–4.1 ms | 解码 claim 行 → 逐组哈希 → 求 Merkle 根 | statement 绑定 `T` 承诺摘要（M2 基建）；**行求根要到 M5 行消费方全部消失后才删除**（§4.0），届时 3.8–4.1 ms 才消失 | M2 → 收尾在 M5 |
| 4 | access 6.7 ms | `AccessStatement::from_claims` + 串行摘要 | `access_statement_digest` 改为 claim 承诺的域分隔派生（O(1)）；前提是 twist/shout claim 已绑定到 `T`（§9.1 的缺失连接由 M4 的 `T` 绑定补上）；`T` 需增加 memory/register 数据列 | M5（可选） |
| 5 | claims decode 1.0 / claims-to-trace 0.77 / 端点 O(1) | 解码 blob、合成 trace、端点比较 | M5 删 blob + `claims_to_trace`；端点改为 `selected.initial_pc/final_pc == statement.initial_state/final_state.pc`（O(1)，pc 链由 selected lockstep 门控强制，§9.9 已确认） | M5 |
| — | core PCS 7.7–8.0、selected lockstep 9.1 | 已是 O(log) | 不动 | — |

## 2. 数据结构与线格式变化

### 2.1 claim 表 `T`（新文件 `crates/magnetar-runtime/src/claim_table.rs`）

`T` 由 host 在构造 statement 时**从 trace 确定性计算**（与现有 `TraceClaimTree::build` 同性质，
但按列而不是按行承诺）。分两部分：

- `T_bits`（布尔列，`PackedBits` + `RingSwitchPackedBitPcs<P3BinaryPcs>` 提交）：
  - claim schema 列（现有 `DynamicClaimSchema.columns` 的顺序，≈336–350 列；每 slot =
    `cycles` 个 0/1 位）。slot 数补齐到 2 的幂（512），补零。schema 由
    `(mask, width, cycles)` 决定，host/prover/verifier 用同一 helper 重建，**slot 顺序即
    提交顺序**。
  - M4 数据列：position 位（`address_bits` 个）、`valid`、`is_32`、word 位（32）、link 位（12）
    等，按 2 的幂 slot 分组。全部 slot 数再补齐到 2 的幂（1024）。
- `T_field`（稠密字段列，`P3BinaryPcs::commit_mosaic` 提交，只在 M4 需要时引入）：
  整体值列（`position_embed`、`code`、`store_width` one-hot 等），让 verifier 能直接拿到
  **单个** claim 值，避免多列各一点的批量打开问题。列数很少（< 10），比现在 paper 路径
  25 列 logup 承诺轻。

承诺与绑定：

```
claim_table_root = H("magnetar-claim-table-v1" || bincode(T_bits_commitment) [|| bincode(T_field_commitment)])
```

`bincode(P3Commitment)` 是 PCS 的确定性序列化（cap + num_variables），由 host 计算；
statement 存 32 B 摘要。prover 重新提交同样的表（PCS 提交是确定性的）；verifier 用 proof 里
的 commitment 重算摘要并比对，再校验打开。**prover 不能自选 `T`。**

### 2.2 打开原语与线格式

```
ClaimTableOpening {                      // 放 claim_table.rs / trace_claims.rs（本任务自有文件）
    bits_commitment: P3Commitment,
    field_commitment: Option<P3MosaicCommitment>,
    relations: Vec<ClaimRelationProof>,  // §2.3 的 claim_rel，M3 1 条、M4 +2~3 条
    field_opening: Option<P3MosaicOpening>,
}

ClaimRelationProof {                     // 一条线性关系：Σ_slot c_slot·T_slot(z) = v
    rounds: Vec<Vec<F2_128>>,            // slot 维 sum-check（2^slot_bits 个变量，度 2）
    opening: RingSwitchOpening<P3Opening>, // 在 (z, q*) 的最终打开，q* 由 sum-check 挑战给出
}
```

优先把新数据塞进 `ClaimProof`（`trace_claims.rs`，本任务自有），避免改 `UnifiedTraceProof`
顶层字段：那样需要 `protocol.rs` 的 `ProofBundle::into_unified` 同步加一行（pcs-fast 所有权）。
若最终必须加顶层字段，请 Lead 安排一行修改。

### 2.3 新原语 `claim_rel`（M3/M4 共用，`claim_table.rs`）

给定已提交布尔表的列集合、行点 `z`、公开系数 `c_slot`（其余 slot 系数 0）与目标值 `v`：

- prover：对每个 slot 算 `h_slot = MLE(T_slot)(z)`（`C·cycles` 次折叠，2^16/512 slot ≈ 33 M
  次位加，~20–50 ms，可并行/一次遍历复用），跑 slot 维（`⌈log2 C⌉` 轮、度 2）sum-check 求
  `Σ c_slot h_slot = v`；
- verifier：`v` 必须已知（M3 是 `binding.target`，M4 是公开模式值/0），校验 round polys
  （O(log C) 域运算），最后得到 `h(q*) = Σ_slot eq(q*,slot)·h_slot = G_T(z,q*)`，用**一次
  ring-switch 打开**在 `(z, q*)` 校验该值。
- 健全性：标准 sum-check soundness（c 公开、h 为多线性）；最终点求值由 PCS binding/opening
  保证；`z`/`q*` 都来自 transcript（Fiat–Shamir）。
- 备选（若上述 prover 侧 `C·cycles` 太慢）：把 claim binding 的列系数改成张量权重
  `λ_slot=Π_b(slot_b?q_b:1−q_b)`，target 直接是单点求值、不需要 sum-check；代价是要改
  `simd_dual.rs` 的 3 处（约 40 行）且 prover/verifier 同步。**默认走 `claim_rel`。**

### 2.4 Statement（决策见 §4.0）

- 方案 A（推荐，零 struct 改动）：`trace_claim_root` 语义改为
  `H("magnetar-claim-binding-v1" || legacy_rows_root || claim_table_root)`，过渡期同时绑定
  旧行根与新表承诺；M5 删行后改为只含 `claim_table_root`。构造点用新 helper
  `claim_binding_root(&trace)` 替换 `TraceClaimTree::build(&trace).root()`
  （共 9 处：lib.rs×2、claim_native.rs×2、virtual_claims.rs、testkit 4 个文件）。
- 方案 B：新增 `claim_table_root: [u8; 32]`（`#[serde(default)]`），保 `trace_claim_root`
  旧语义到 M5。`Statement` struct literal 分布在 9 个文件（4 个 testkit、2 个非本任务 runtime
  文件），机械但要协调。

### 2.5 Proof 尺寸

- M2/M3：+~3–6 KB（commitment + 1 条 claim_rel 的 round polys + ring 打开）。
- M4 主要增量：`LogupStarProof.pushforwards` 保留在 proof 里（现在被清空、verifier 重建）。
  长度 ≈ `2^address_bits` 个字段元素：论文 ec20 ROM ≈ 2^11 → ~32 KB；**本仓库合成 bench
  ROM = ADDS+1 = 2^16 → ~1 MB**（proof 861 KB → ~1.9 MB）。这是 bench 构造的 artifact，
  汇报时必须分别标注两种 ROM 规模，不能混用 headline。

## 3. 各里程碑 verifier 算法

### 3.1 M2（承诺 + statement 绑定，纯使能）

1. prover：构造 `T_bits`（M2 只含 schema 列）→ 承诺 → 填 `ClaimProof.table`；
   `proof.trace_claim_root = claim_binding_root`。
2. verifier（`verify_native_unified` 开头）：重算 `claim_table_root` 与 statement 比对
   （O(1)）；校验 commitment 自洽（M2 还没有要验的关系）；**过渡期仍保留行认证**
   （旧 `verify_complete_leaves`），直到 M4/M5 移除行消费方。
   收益 ≈ 0（+0.1–0.3 ms），价值是后续里程碑的地基。
3. 顶层篡改测试：`claim_table_root`、commitment、序列化 round-trip、合法证明仍通过。

### 3.2 M3（claim 行和 → `claim_rel`，首个可测量收益）

现状：target 由 verifier 按 `Σ_row eq(z,row)·Σ_slot α^slot v[row,slot]` 逐行算，再做
inner sum-check 绑定（`DynamicClaimBinding{target, columns_root}`，§9.5）。

改动：

1. prover：target 的计算路径不变（仍从 trace/claim 数据算，仍写 `binding.target`）；
   新增一条 `claim_rel`：列集合 = schema slot 排列、系数 `c_slot = α^slot`（α 来自现有
   `dynamic_claim_challenges`，两侧一致）、行点 `z` 同上、目标值 = `binding.target`。
   注意 slot 顺序：`T` 的 slot i 对应 `schema.columns[i]`，补零 slot 的系数置 0。
2. verifier：
   - `claim_rel` 校验 `Σ α^slot·T_slot(z) = binding.target`；
   - inner sum-check 校验路径**完全不变**（`verify_dynamic_claim_binding_prepared`）；
   - 删除 `dynamic_claim_for_selected`（逐行 sums）在 native 路径的调用；
   - **不改 `simd_dual.rs`**（λ 备选方案才需要）。
3. 健全性：`T` 被 statement 绑定；关系在随机点 `z`、公开系数 `α` 下成立 ⟹（标准
   sum-check + Schwartz–Zippel）`T` 的 claim 列确实等于按行加权和；target 已被 inner
   sum-check 绑定到 `W`（§9.5 不变）⟹ claim 列 = 已提交见证列。
4. 预计：−11.5…−12.4 ms 行和，+1.5–2.5 ms（claim_rel verify + ring 打开，待测）。
5. 改动文件：新增 `claim_table.rs`；`lib.rs` verifier 接线 + 删 row-sum 分支；
   `trace_claims.rs` proof 结构；`claim_native.rs` statement 构造 helper；测试更新。
   **不碰 simd_dual.rs / protocol.rs / pcs 文件。**

### 3.3 M4（trace Logup-Shout → committed Logup + `T` 绑定）

现状：`verify_trace_logup_shout(proof, witness, program_hash)` 由 verifier 重建 witness
（`from_trace` 7.1–7.6 ms）、重算 reader/link 列（columns+positions 3–4.5、reader claims 2.4、
link claims 5.8）、重算 pushforwards，最后 O(rom) 校验 ROM 列。paper 路径的 `logup_shout`
虽然携带了承诺+打开，但**当前 native verifier 完全不验它**（§9.6 已知缺口）。

方案（首版仅 word mode，即所有指令 4 字节——paper bench 就是；compressed 继续走旧路径）：

1. prover：
   - `prove_unified_trace_paper` 不再 `logup.logup.pushforwards.clear()`；按 §2.1 构造
     `T`（含 M4 数据列）；把位置/word/link 对应的 claim 值列表写进 proof（供 verifier 绑定，
     值本身由打开认证）。
2. verifier（无 witness，复用 `logup_shout::verify_logup_shout_with_output` 的已验证逻辑）：
   - 由公开量重建 `reader_point`（cycles/address_bits/columns/`rom_binding=program_hash`）
     与 proof 内点比对；`program_hash == rom_hash(&statement.rom)`（O(rom)）；
   - `logup.verify`（pushforwards 来自 proof）：**reader 列由 logup 自己的 PCS opening
     认证**（`verify_logup_shout_with_output` 已实现）；不再重建 reader 列；
   - 公开 ROM 表：从 `statement.rom` + preprocess 重建 12 列（word 列来自公开 ROM，
     metadata 列来自公开解码；O(rom)），校验 `output.column_claims`——把「ROM 内容」
     从 claim 派生改成真正公开（当前实现其实是 claim 派生的自洽检查，这是顺带的健全性修复）；
   - **`T` 绑定**（§2.3 原语）：
     · position：`output.position_claims[0]` 必须等于 `T_field.position_embed` 在
       `position_point` 的打开值；且 `claim_rel` 校验 position 位 = pc 位右移 2（word mode，
       在 `T_bits` 的 position 位与 schema pc 位之间做随机线性组合的等式）→ position 被
       绑到 claim 层（这是 §9.8 阻塞点的核心）；
     · word：`claim_rel` 校验 `T_bits` 的 word 位组合 = logup 提交的 reader word 列在随机点
       的值（或对 `T_field.word` 打开值与 logup reader claim 做随机点等式）；
     · valid / is_32：`claim_rel` 与公开模式值（valid 前缀指示、word mode 下 is_32≡0）比较；
     · link：code/width 值对 `T` 数据列做随机点等式后，再按现有
       `logup_shout_router_link_claims` 折进 shift/store router 表 opening。
3. 预计：删 21.9–29.6 ms，新增 logup reduction verify 3.9 + 公开 ROM O(rom) 0.3–1
   （单/12 列）+ `claim_rel` 3–4 条共 4–8 + 少量 PCS 打开 0.5–1.5 → 净省 ~12–18 ms CPU；
   wall 在 trace Logup 不再是长杆后掉到 ~13–17 ms。
4. **设计风险（§4.4）**：link code/width 与 claim 选择子/内存事件之间的推导有的是
   **非线性**（如 `is_shift` 门控、store width 来自内存事件）。首版可以：位置/word/valid/is_32
   用线性关系全查（这是取指语义的关键）；link 只要求「`T` 数据列与 router 表在随机点一致」
   （`T` 是 statement 绑定数据，去掉了 prover 自选空间），把门控推导作为 M4b 可选
   （需要列乘积关系的小 sum-check，约 150–300 行）。落地前和 Lead 确认这个取舍。

### 3.4 M5（可选：access 摘要 → claim 根派生 + 删行）

- `T` 增加 memory 事件列（addr/value/width/is_write × 每行最多事件数）与 register 值/索引列；
  `statement.access_statement_digest = H("magnetar-access-claims-v1" || claim_table_root)`。
- verifier：删 `AccessStatement::from_claims` 分支；twist/shout access claims 改为对 `T`
  打开值校验。
- 删 claim blob、`verify_complete_leaves`、`decode_rows`、`claims_to_trace`、行端点检查；
  `trace_claim_root` 切换为纯 `claim_table_root`。
- 前提：§9.1 指出的「表↔statement 绑定」缺失由 M4 的 `T` 数据列 + twist claim 打开补上，
  落地前按 §9.1 的审查清单重新核对（若前提不成立，M5 不强行落地）。

## 4. 健全性论证要点与需要 Lead 决策的点

### 4.0 过渡期行认证（**决策 A**，最重要）

M2/M3 落地后，claim 行仍被 trace Logup（M4 前）和 access（M5 前）消费。若按 M2 描述立即
删掉「重新哈希所有行求根」，这些消费方的输入行就没认证，M2–M4 之间存在健全性缺口
（prover 可给假行让 trace Logup 证明假行读了公开 ROM）。**建议**：过渡期在
`trace_claim_root` 里同时绑定旧行根（方案 A），行认证保留到 M5 删行；M2 收益 0，
M3 起才有可测量收益。备选：接受 M2–M4 弱化并在最终 commit 说明（不推荐，篡改测试会进退两难）。

### 4.1 M2/M3 健全性

- `T` 承诺在 statement：`claim_table_root` 摘要 → PCS binding；打开 soundness = ring-switch + P3 verify。
- 摘要必须覆盖两个 commitment（`T_bits` + `T_field`，M4 起），否则 prover 可换其中一个。
- slot 顺序/布局是公开约定（`claim_table.rs` 唯一 helper），host/prover/verifier 同源；
  verifier 只按该约定解释打开值。
- `z`/`q*`/`α` 都从 transcript 派生；`T` 的 commitment 在 statement 里，所以 prover 不能
  事后换表来适配张量权重。
- M3 的 target 仍由 prover 计算，但 verifier 现在自己校验它 = `Σ α^slot T_slot(z)`；
  这一步不依赖 claim 行。

### 4.2 M4 健全性（对应 §9.8 的前提）

- position/word/link 数据列来自 statement 绑定的 `T`，不再是 prover 自选见证 ⇒ §9.8 的
  阻塞点消失；position 与 pc 的等式把 position 绑到 claim 层（pc 被 claim target 绑定到
  `W`，链与端点由 selected lockstep + statement 强制）。
- word ⇒ 由 Shout 证明 `word(cycle) = ROM_word(position(cycle))`；ROM 现在是真正公开的
  （从 `statement.rom` 重建），比当前实现更强。
- link claim 经 `T`/opening 认证后才折进 router 表 opening ⇒ shift/store 绑定链保留。
- 与 §9.6 的关系：修掉「paper 路径 `logup_shout` 不被验证」的已知缺口
  （`verify_native_unified` 将真正校验 Logup* 本体）。

### 4.3 需要 Lead/协调的决策

1. **决策 A**（§4.0）：过渡期保留行 Merkle（推荐）vs 立即删。
2. Statement 方案 A（改 `trace_claim_root` 派生，零 struct 改动，推荐）vs B（新增字段）。
3. M4 首版仅 word mode 是否接受（compressed 保留旧 trace-logup 路径）。
4. M4 link 门控推导：首版「`T` 数据列 + router 随机点等式」是否可接受（§3.3-4），
   还是必须同版做乘积关系检查（+150–300 行）。
5. M2/M3 是否合并为一个可回退 commit（推荐：第一个有收益的检查点）。
6. testkit 的 Statement 构造点（`paper_unified_bench.rs`、`paper_mode.rs`、`workload_suite.rs`、
   `claim_native_bench.rs`）与 `virtual_claims.rs`/`aux_statement.rs` 的机械改动授权。
7. **不需要**改 `simd_dual.rs`（`claim_rel` 方案）；若 Lead 更倾向 λ 张量方案，再要窗口。

## 5. 篡改测试矩阵（全部走顶层入口 `verify_native_unified`）

| 层 | 篡改 | 期望 |
| --- | --- | --- |
| M2 | statement 摘要 / proof `bits_commitment` / `field_commitment` | 拒 |
| M2 | 合法证明、序列化→反序列化 | 通过 |
| M2/M3 | ring opening 三处（`s_hat_v` / sumcheck round / `pcs_opening`）、claim_rel round poly | 拒 |
| M3 | `binding.target`；`claim_rel` 的 `v`；换用另一 trace 生成的 statement | 拒 |
| M3 | 改 claim schema 列序（换 mask/width） | 拒（columns_root/target 不一致） |
| M4 | logup rounds / pushforwards / reader claim / position claim / link claim | 拒 |
| M4 | statement.rom 的 word（公开表）/ program_hash | 拒 |
| M4 | `T` 的 position/word/link 数据列换值（重算 statement 摘要） | 拒（claim_rel/绑定） |
| M4 | compressed 指令 trace（走旧路径） | 合法证明通过 |
| M5 | `access_statement_digest`；`T` 的 memory 列换值 | 拒 |

另：现有用例需要重写/扩展——`native_claim_layer_verifies_without_trace`（bad_root 语义变）、
`native_verifier_rejects_a_tampered_compressed_claim_blob`（M5 后换成打开值篡改）、
`paper_mode.rs`（合法证明 + 新篡改用例）。全量 workspace 测试由 Lead 最后统一跑；
每个 milestone 至少保证 `cargo test --release -p magnetar-runtime --lib <filter>` 绿。

## 6. 成本/收益推算（2^16，待实测）

| 里程碑 | 验证器增量（估） | 删除项 | 预期净变化 |
| --- | --- | --- | --- |
| M2 | +0.1–0.3 ms | 0 | ~0（使能） |
| M3 | +1.5–2.5 ms | 行和 11.5–12.4 | **−9…−11 ms CPU**；wall 暂由 trace Logup 主导 |
| M4 | +8–11 ms（logup 3.9 + 公开 ROM 0.3–1 + claim_rel 4–8 + 打开 0.5–1.5） | trace Logup 21.9–29.6 | **−11…−18 ms CPU**；wall → ~13–17 ms |
| M5 | +0.3–1 ms | access 6.7 + leaves 3.8–4.1 + decode 1.0 + claims-to-trace 0.77 | **−10…−12 ms CPU**；wall → ~11–13 ms |

Prover/内存侧成本（M2/M3）：`T_bits` ≈ 512–1024 slots × cycles bits（2^16 ≈ 4–8 MB packed，
2^12 ≈ 0.25–0.5 MB）；P3 提交（rate 1/2）约 8–16 MB 码字、2^16 单线程 commit 约几十 ms；
host 构造 statement 也要付一次（现有 `trace_digest` 已是 O(rows)，量级可接受），
2^22 外推码字 ~0.5–1 GB —— 需要 Lead 决定 host/大规格是否可接受（可在 M2 用 2^12/2^14
实测外推）。M4 的 `T_field` 只个位数~十几列，比现在 paper 路径 25 列 logup 承诺轻。
**测量纪律**：`ADDS=4095/16383` 交错 A/B、`MAGNETAR_VERIFY_CPU=10–20`、引用 CPU 秒不用
wall；2^16 只在 Lead 窗口跑。

## 7. 风险与回退点

1. **M4 是最大不确定性**（§3.3-4、§4.3-4）：线性绑定部分风险低（原语 M3 就要做）；
   非线性门控推导若必须同版，可能 +150–300 行。建议 M2/M3 后先做 1–2 天 M4 原型
   （committed logup 无 witness 验证 + position 绑定），再定 M4 终稿。
2. **`pushforwards` 体积**：合成 bench ROM=2^16 时 proof +~1 MB；论文规模 ~32 KB。
   用「保留两条路径（原生 trace-logup 仍可选）+ 汇报两种 ROM 规模」缓解，不阻塞 M4。
3. **protocol.rs 所有权**：优先把新数据塞进 `ClaimProof`（本任务自有）避免改
   `ProofBundle`；若必须加 `UnifiedTraceProof` 顶层字段，请 Lead 安排一行修改。
4. **`simd_dual.rs` 不需要改**（默认方案）；若退到 λ 备选方案才需要 Lead 给窗口
   （该文件当前有未提交改动）。
5. **回退**：每个里程碑用 `#[serde(default)]` 的新字段 + `if let Some(...)` 分支接入，
   旧格式 proof/statement 仍能验证（旧路径保留到 M5 结束）；单个里程碑可独立 revert。
   不做 git 写操作（Lead 独占）。
6. **不承诺**：M4 的 compressed 指令模式；M4b 的乘积关系检查；M5 的完整 access 绑定
   （§9.1 前提需重审）；2^22 的 host 侧 `T` 提交成本（若不可接受，需回到本设计调整列集/分组）。

## 8. 建议的落地顺序（M2 起）

1. M2a：`claim_table.rs` + `T` 构造/承诺 + statement 绑定 + 测试（不改 verifier 行为）。
2. M2b=M3：`claim_rel` + verifier 用打开值替代行和 + 篡改用例；**第一个带测量的检查点**。
3. M4：committed logup 无 witness 验证 + position/word 绑定原型 → 正式落地 + 测量。
4. M5：access + 删行/blob/旧 Merkle + `trace_claim_root` 语义收尾。

## 附录 A：M2 实施清单（待 Lead 确认后照此执行）

新增文件 `crates/magnetar-runtime/src/claim_table.rs`（本任务自有）：

1. `claim_schema_slots(mask, width, cycles) -> (Vec<usize>, [u8; 32])`：薄封装
   `simd_dual::dynamic_claim_schema`（已 pub(crate)），返回 block 列序与 schema root。
2. `claim_table_bits(rows: &[TraceClaim], mask, width, cycles) -> PackedBits`：
   调 simd_dual 的新增 pub(crate) helper（见下）取每 slot 的位向量，按
   `slot * cycles + row` 拼成 `PackedBits`（补零 slot 到 2 的幂）；`bits.len() = slots*cycles`
   必须是 2 的幂。
3. `claim_table_backend() -> RingSwitchPackedBitPcs<P3BinaryPcs>`：固定参数（建议
   `P3BinaryPcs::with_params(100, 1, 20, 3)`，与 selected 一致；M2 实测 commit/verify 后可调）。
4. `commit_claim_table(bits) -> P3Commitment`、`claim_table_root(commitment) -> [u8;32]`
   （`H("magnetar-claim-table-v1" || bincode(commitment))`）。
5. `claim_rel` 原语（§2.3）：
   - `prove_linear_relation(bits, commitment, columns: &[(slot, F2_128 coeff)], row_point, value,
     transcript) -> ClaimRelationProof`：对每 slot 折叠 `MLE(bits[slot*cycles..])` 于 `row_point`
     得 h_slot，填 `h[slot]`；用 `magnetar_proof::prove_linear`（度 1、变量数 = slot_bits）
     跑 sum-check，challenge = 吸收 round poly + 吸收 (commitment_bytes, row_point, coeffs, value)；
     最后 `backend.open(bits, point = row_point ++ q*)` 得 ring opening。
   - `verify_linear_relation(commitment, coeffs, row_point, value, proof) -> Result`：
     用 `verify_rounds(&proof.sumcheck, slot_bits, 1, challenge)` 得到 (q*, final)，
     校验 `proof.sumcheck.claimed_sum == value`、`backend.verify(commitment, row_point++q*,
     final, &proof.opening)`。注意 transcript 吸收顺序必须与 prover 完全一致。
6. 单测：小表（如 8 slot × 16 rows）上 prover/verifier round-trip；篡改 round poly/opening/
   value/coeff 各拒绝；relation 不成立时 prover 的 claimed_sum 与 verifier 期望的 value 不等
   （由调用方拒绝）。

simd_dual.rs 的唯一改动（纯新增，无行为变化）：
`pub(crate) fn dynamic_claim_column_bits(rows: &[TraceClaim], mask, width, matrix_cycles)
-> Result<(Vec<usize>, Vec<Vec<bool>>), RuntimeError>`：复制 `dynamic_claim_sums_with` 的行循环
（相同 padding 规则、相同 `claim_emission`/`slot_of` 去重语义），但只记录每 slot 的布尔值，
不做 eq 加权。放在 `dynamic_claim_sums_with` 之后；~70 行。**等 Lead/pcs-fast 给
simd_dual.rs 窗口。**

lib.rs / trace_claims.rs / claim_native.rs 接线（M2a）：
- `ClaimProof` 增加 `#[serde(default)] table: Option<ClaimTableProof>`（`ClaimTableProof {
  commitment, bits_len, slots, relations: Vec<ClaimRelationProof> }`），旧格式解码为 None；
- `prove_*_native*` / `prove_unified_trace_paper` 里在拿到 trace 后构造并附加 `table`，
  `proof.trace_claim_root = claim_binding_root(trace)`；
- 新增 `pub fn claim_binding_root(trace: &Trace) -> [u8;32]`（内部固定 width=64 或带 width 参数）
  = `H(domain || TraceClaimTree::build(trace).root() || claim_table_root)`（过渡期方案 A）；
- `verify_native_unified` 开头：claim_proof.root 仍做旧行根检查（§4.0），新增校验
  `proof.trace_claim_root == claim_binding_root_from_parts(claim_proof.root, table_root)`，
  以及 `table_root = claim_table_root(table.commitment)`；
- 所有 Statement 构造点把 `TraceClaimTree::build(&trace).root()` 换成
  `claim_binding_root(&trace)`（9 处）。
- M2b/M3：`verify_native_unified` 里删掉 claim 行和分支，改为 `verify_linear_relation(...,
  binding.target)`；prover 在 `dynamic_claim_for_trace` 之后用同一 trace 构造 `table` 并加
  一条 relation。

M2 的测试（全部走顶层入口）：
1. `claim_table_rel_round_trips`（claim_table 内部单测）
2. `native_claim_table_binds_statement`：合法 proof 通过；篡改 statement.trace_claim_root、
   proof.table.commitment、opening、relation round poly 各拒绝；proof 序列化 round-trip 后通过。
3. 原有 `native_claim_layer_verifies_without_trace` 等测试更新断言。
4. 小规模 2^12 端到端：`ADDS=4095 WIDTH=64 target/release/examples/paper_unified_bench`
   在验证器阶段用 `MAGNETAR_PROFILE_VERIFY=1 MAGNETAR_VERIFY_CPU=20` 记录 CPU/iter；
   交错 A/B 与空跑（`NO_CLAIM` 路径或旧二进制）对比。

## 附录 B：M2+M3 实施状态（2026-11-03，未提交）

按 Lead 决策 E，M2（承诺 + statement 绑定）与 M3（claim 行和 → `claim_rel` 打开）
合并为一个可回退改动。当前实现完成、**编译已绿**（`cargo check --release -p magnetar-runtime`
exit 0），但基准测量/部分测试因宿主内存压力暂停，待窗口。

### B.1 代码落点

- 新增 `crates/magnetar-runtime/src/claim_table.rs`：
  - `claim_table_columns` / `claim_table_bits` / `commit_claim_table` / `claim_table_root`；
  - `claim_binding_root`（composed root = `H(domain ‖ 旧行根 ‖ claim 表根)`）与
    `claim_binding_root_from_parts`；
  - `prove_claim_table` / `verify_claim_table` / `verify_claim_table_and_claim`：
    一条 `claim_rel`（slot 维 degree-2 sum-check + 一次 ring-switch 打开）；
  - `ClaimTableProof { commitment, root, slots, relations }`、
    `ClaimRelationProof { sumcheck, slot_point, opening }`；
  - 3 个单元测试（MLE 折叠约定、关系 round-trip 与篡改拒绝；后者在 PCS folding
    规则修正后尚未复跑）。
- `simd_dual.rs`（**仅追加**）：`dynamic_claim_column_bits(trace, width)`，按
  `dynamic_segment_setup` 的 mask/cycles/padding 规则生成 schema 的逐列位值。
- `trace_claims.rs`：`ClaimProof` 新增 `table: Option<ClaimTableProof>`
  （wire 变体各加一个字段）；恢复 `PartialEq/Eq`（新类型用 canonical bincode
  编码手写 `PartialEq/Eq`，因为 PCS opening 类型没有 PartialEq）。
- `lib.rs`：`ReferencePipeline` 的 statement 用 composed root（表不可表示时回退旧行根）；
  native/paper prover 附加 claim 表证明并写 composed `trace_claim_root`；
  `verify_native_unified` 用 `claim_rel` 替代逐行 claim 求和（`MAGNETAR_CLAIM_ROWS=1`
  保留旧路径做同二进制 A/B）；trace 路径与 `verify_unified_trace_statement` 兼容
  composed/legacy 两种 root。
- `virtual_claims.rs`（测试 helper）与 testkit 的 `paper_mode.rs` /
  `paper_unified_bench.rs` 改用 composed root；`paper_unified_bench.rs` 的
  `TRACE_SHOUT`/`NO_CLAIM` 分支保留 claim 表 / 回退行根。
- `claim_native.rs`、`workload_suite.rs`、`claim_native_bench.rs` 保持 legacy claim-native
  语义（旧行根），未改。

### B.2 Wire 格式与兼容性（需在提交说明里记录）

- `statement` 结构体未变；`trace_claim_root` 语义变为 composed root（对能表达成 claim
  表的 trace），不支持动态 claim 表的 trace 回退旧行根（classic 路径用）。
- `ClaimProof` 的 serde wire 变体全部新增 `table: Option<ClaimTableProof>` 字段：
  **旧版本序列化的 proof 不能反序列化**（bincode 非自描述），属于计划内格式变化；
  同版本内 round-trip 正常（`claim_proof_round_trips_serde` 绿）。
- proof 尺寸增加约 4–8 KB（commitment + relation sum-check + ring 打开）。
- native/paper 验证路径现在要求 width = 64（claim schema 固定 RV64 布局）；
  `WIDTH != 64` 的 bench 路径会拒绝（已知限制，写进 HANDOFF）。

### B.3 已通过的测试（暂停前最后一次完整 claim 过滤跑）

`cargo test --release -p magnetar-runtime --lib claim`（48 passed / 1 failed；唯一失败
是 claim_table 自己的小表单元测试，原因是 PCS folding 规则要求 packed 表 ≥ 2^3 字段，
已修代码待复跑）：
`native_claim_layer_verifies_without_trace`、`native_claim_layer_handles_memory_rows`、
`native_claim_layer_verifies_compressed_trace`、`native_verifier_rejects_a_tampered_compressed_claim_blob`、
`native_claim_table_polylog_binding_rejects_tampering`（新增）、
`claim_proof_round_trips_serde`、`virtual_cpu_*`、`protocol::phase_tests::*` 均绿。

### B.4 待补（窗口恢复后）

1. 复跑 `claim_table` 单测与 `cargo test --release -p magnetar-runtime --lib claim`；
2. `cargo check --release -p magnetar-testkit --tests --examples`（testkit 未 check 过）；
3. ADDS=4095 / 16383 交错 A/B（`MAGNETAR_CLAIM_ROWS=1` vs 默认）拿 CPU/iter 与 wall，
   2^16 只在 Lead 窗口；预期 M3 净省 ~7–10 ms CPU（schema 重建 ~3 ms 仍保留，
   行和 11.5–12.4 ms 删除，新增 relation+ring ~2–4 ms）；
4. 测量 claim 表 prover/host 侧成本（2^16 单次 commit/open 估 50–150 ms）。

### B.5 默认值与 2^16 A/B 结论（2026-11-03，Lead 批准）

**最终决定：默认 ON。** 同一二进制、同一 `paper_unified_bench`、相隔 1 分钟内的
RV64 `2^16` 全量交错对比（Lead 的机器窗口）：

| 2^16 paper bench | claim 表 OFF（legacy 逐行和） | claim 表 ON（rate 1/8） |
| --- | --- | --- |
| verify | **45.97 ms** | **27.38 ms（−40 %）** |
| proof | 861,408 B | 1,018,152 B（+156,744 B） |
| peak RSS | 2.19 GiB | 2.38 GiB |
| prove | 60.1 s / 422.9 CPU | 59.3 s / 434.9 CPU（噪声内） |

即 2^16 上 claim 表替掉 `O(rows)` claim 行和后**净赚约 18.6 ms verify**，proof 代价 +157 KB；
2^10 上观察到的「表路径慢 1.4 ms」是 PCS 打开的固定成本，尺寸上去后消失。

- claim 表 PCS 参数：**rate 1/8**（`P3BinaryPcs::with_params(100, 3, 20, 3)`）。2^10 表证明从
  rate 1/2 的 160,941 B 压到 **90,189 B**，verify wall 不变；2^16 上相比 rate 1/2 也少 ~118 KB
  且 verify 持平。
- 环境开关：`MAGNETAR_CLAIM_TABLE=0|off|false` 恢复 legacy 行路径（旧 statement root/线格式，
  用于 A/B）；`MAGNETAR_CLAIM_ROWS=1` 保留表证明但 verifier 用旧逐行和（隔离 verifier 变化）。
- 测试覆盖：runtime lib 的单测（`cfg!(test)`）始终走表路径；其它 crate 的集成测试看到生产默认
  （ON）。
- open item：ADDS=4095 时 testkit memory watchdog 观测到 4.05–4.3 GiB 瞬态（ADDS=1023 正常），
  待下一个窗口定位（不是 claim 表本身：2^12 表尺寸仅 ~2.1 M bits / 码字 ~16 MB）。

## C. M4 实施计划（提交后待 Lead 确认；先不动代码）

目标：native/paper 路径的 trace Logup-Shout 从「verifier 重建 witness」改为「已提交列 + 打开」，
删掉 21.9–29.6 ms 的逐周期重建；同时把 paper 路径目前**完全不校验**的 `logup_shout`
（§9.6 已知缺口）变成真校验。M4 完成后 M5 才能删行 blob。

### C.1 方案对比（提议选 B）

**A（LogupStar slim）**：保留 p3 Logup*，reader 列从 `T_field` 打开，去掉 25 列 logup PCS
opening。问题：`LogupStarProof.pushforwards` 必须留在 proof（verifier 无 witness 可重建），
长度为 `2^address_bits` 个域元素。合成 bench 的 ROM = ADDS+1 = 2^16 words → **+1 MB proof**，
2^16 headline 无法接受；论文 ec20 ROM 小（~2^11）时才 +32 KB。受 benchmark ROM artifact 支配。

**B（BinaryShout against T，推荐）**：复用 `binary_shout.rs` 的 Boolean/read sum-check 证明
（~10–15 KB，**无 pushforwards**），把 Shout 的布尔列直接放进 claim 表 `T`，所有 claim 都通过
`T` 的批量打开认证；reader word 列用 `T_field`（1 个 dense 列）绑 claim 字，`column_evals[0]`
对公开 ROM 做 O(rom) 检查。proof 预期 **−220 KB 左右**（删 `logup_shout` 245 KB、加
BinaryShout ~10–15 KB + 额外 T 打开 ~5–8 KB），落到 ~800 KB < 旧 861 KB；verifier 增量
~5–8 ms，但替掉 native 路径 21.9–29.6 ms 的重建。

### C.2 数据面（T 扩展）

- `T_bits` 追加 shout 数据列（host 从 trace 计算）：`address0` 位（`address_bits`）、
  `address1` 位（`address_bits`）、`is_32`、`valid`、link 12 位。schema 组之外新增
  shout 组（46 列 @ a=16），slot 数 512 → 1024（2^16 时 T 从 ~4 MB packed 到 ~8 MB；
  码字 rate 1/8 约 67 MB 瞬态，可控）。
- `T_field`（新增，`P3BinaryPcs::commit_mosaic` dense 列）：**1 列 `word`**（每 cycle 的
  claim instruction word 作为域元素）。2^16 时 65 536 fields，码字 ~8 MB，成本可忽略。
  statement 绑定扩展为 `H(domain || row_root || T_bits_root || T_field_root)`。
- link/code/width 的**派生关系**（selectors→code、memory→store width 是非线性）：
  首版按决策 D 只做「T 数据列 vs router 表随机点等式」，乘积关系留 M4b。

### C.3 Prover

1. 构造/承诺扩展后的 `T_bits`、`T_field`；claim_rel 追加三条**线性**关系（都是公开系数，
   用现有 claim_rel 原语）：
   - `position = (pc − rom_base) >> 2`（word mode：`address0` 位 = schema pc 位右移 2，
     低位为 0；`address1` 在 word mode 等于 `address0`）；
   - `valid` = 公开前缀指示（MLE 在随机点可 O(log) 求值）；
   - `is_32 ≡ 0`（word mode）。
2. 调 `binary_shout::prove_binary_shout_claims` 的现有逻辑（必要时抽成对 T 数据列版本）：
   `prove_binary_shout_claims(&witness, &synthetic_commitment, 0, binding)`，其中
   `synthetic_commitment` 用 E5 模式绑定到 `T_bits` 的 shout 组 + `T_field`（cap/shapes/binding
   hash），transcript 与 verifier 一致。
3. link claims 仍按现有 `logup_shout_router_link_claims` 的格式折进 mosaic opening。
4. 删除 paper 路径的 `logup_shout`（25 列 PCS 提交 + opening），proof 字段
   `logup_shout`/`trace_logup_shout` 用新 `CommittedShoutProof` 取代（serde default，
   旧格式可拒绝）。

### C.4 Verifier（无 witness）

1. 校验 `CommittedShoutProof` 的 Boolean/read sum-checks（复用
   `verify_binary_shout_from_proof` 的检查逻辑，对 synthetic commitment）；
2. `T` 批量打开（E5 式 `MosaicBatchingProof` + ring-switch）：把 proof 返回的
   bit/link/valid/is_32 claims 转成 `T` 的 lifted 点 claim，一次打开认证；`word` 列来自
   `T_field` 在 reader 点的打开；
3. `column_evals[0]`（ROM word 列）对**公开 ROM**（`statement.rom` 重建，O(rom) 单列）比对；
   metadata 列不需要（word-only Shout）；
4. `claimed_read == MLE(T_field.word)(reader_point)`（绑定 claim 字）；
5. 三条 claim_rel 关系（C.3-1）+ 已有的 claim target relation；
6. link claims 折进 shift/store router opening（现有代码路径）。
7. compressed 指令模式保留旧 trace-logup 路径（决策 C）。

### C.5 工作量与顺序

- **M4a**（~1–1.5 天）：T 扩展 + synthetic commitment + BinaryShout prover/verifier 接线 +
  三条线性关系；先只改 **native TRACE_SHOUT 路径**，paper 路径保持不动 → 用同一 bench
  A/B 测 proof size 与 verify；验证器用 `MAGNETAR_COMMITTED_SHOUT=0` 回退。
- **M4b**（~0.5–1 天）：link 门控乘积关系（如必须）、paper 路径切到新证明、删旧
  `logup_shout` 组件与 `trace_logup_shout` 的逐周期路径；小 ROM/压缩模式 fallback 保留。
- **M5**（随后）：access digest → claim root、删行 blob/行 Merkle/decode/claims_to_trace，
  proof 再减、verify 再降（目标 ~20–25 ms，再往 8–12 ms 需要 selected/core 侧优化）。

### C.6 需要 Lead 决策

1. 采用方案 **B**（BinaryShout against T，无 pushforwards）还是 A；
2. T 扩展到 1024 slots + `T_field` 的 prover/host 成本（2^16 一次性 +~10 ms 级、+~80 MB 瞬态；
   2^22 外推 ~+0.5–1 GB 码字+字段列，可接受？）；
3. M4a 只改 native 路径、paper 路径留到 M4b 是否 OK；
4. 新增 `CommittedShoutProof` 的 proof 字段命名/兼容策略（serde default，旧 proof 拒绝）；
5. 授权范围确认：`binary_shout.rs`、`logup_shout.rs`（只删/改 M4 相关最小面）、
   `claim_table.rs`、`lib.rs`、`trace_claims.rs`；不碰 stream/spartan/bit_pcs。

### C.7 M4a 骨架状态（2026-11-03，未 build）

按 Lead 批准：方案 B；M4a 先写代码不 build，等窗口做「单测 → 字节等价 → 2^14 A/B → 2^16 全量」。

已落地（骨架，默认路径完全不受影响）：
- 新 `crates/magnetar-runtime/src/claim_shout.rs`：
  - `committed_shout_enabled()`（`MAGNETAR_COMMITTED_SHOUT=1`，默认 off）与
    `classic_logup_enabled()`（`MAGNETAR_CLASSIC_LOGUP=1`，A/B 回退开关）；
  - `ShoutColumns` + `shout_columns(trace)`：从 `BinaryShoutWitness` 取 address0/1、is_32、
    valid、12 link 列（word mode 校验），加 dense `word` 列（claim instruction word/cycle）；
  - `extended_claim_bits(base, shout)`：`[claim schema | address0 | address1 | is_32 | valid | link]`
    打包成扩展 `T_bits`（slot 数按 `ClaimTableColumns.columns + 2a+2+12` 重新补齐）；
  - `commit_field_column` / `field_root` / `extended_table_root`（`T_bits` + `T_field` 绑定 root）；
  - `synthetic_commitment(...)`：E5 式合成 `P3MosaicCommitment`（cap 取 T_bits、shape =
    (cycle_bits, 2a+2+12)、binding 同时哈希 table root + field commitment）；
  - `CommittedShoutProof`（`#[serde(default)]` 兼容策略：字段缺失时验证器报
    "pre-M4 proof"）+ `prove_committed_shout` / `verify_committed_shout` 入口
    （目前返回 "not wired yet"，待 build 窗口补全）；
  - 3 个单测：shout 列与 trace word 一致、扩展表追加列、默认开关为 off。
- `ClaimProof` 新增 `committed_shout: Option<CommittedShoutProof>`（wire 变体 + serde default）；
- `lib.rs`：native prover 在 `MAGNETAR_COMMITTED_SHOUT=1 && !MAGNETAR_CLASSIC_LOGUP` 时调用
  committed-shout 入口（当前返回 Err，即 skeleton 未启用时默认路径不变）；verifier 在
  `committed_shout` 存在时校验，enabled 但缺失时明确报 "pre-M4 proof"；
- `claim_table::slot_bits_for` 改为 `pub(crate)` 供扩展表使用。

**已补完（2026-11-03，build 窗口，check/test 绿）**：
1. `prove_committed_shout`：T_shout/T_field 提交 + word-only BinaryShout（1 列 ROM word）+
   field 列在 reader point 打开（`word_value` 显式入 proof）+ 三条关系（reader-point evals、
   data 检查、claim 侧 pc-shift）；`claimed_read == γ·word_value` 绑定 claim 字；
2. `verify_committed_shout`：组合 root → synthetic commitment → BinaryShout 全部 sumcheck →
   reader point 一致性 → field 打开（`P3BinaryPcs::verify` + `word_value`）→
   `claimed_read == γ·word_value` → 公开 ROM word 列 O(rom) 检查 → 三条 claim relation
   重算与校验（address0/address1↔pc>>2、valid=公开前缀、is_32=0、共享 position_value）；
   `prefix_eq` 修正为 O(log) 正确实现（单测对 0..4 与直接求和一致）；
3. statement root：`claim_table::statement_claim_root` 在 `MAGNETAR_COMMITTED_SHOUT=1` 时
   返回 `H(v1 ‖ shout ‖ field)`，默认 off 时与 v1 完全一致；
4. 编译：`cargo check --release -p magnetar-runtime` 绿（2 轮错误修复）；
   测试：`cargo test --release -p magnetar-runtime --lib claim` → **51 passed / 0 failed**
   （默认 env unset，包含 native/paper/claim_native/virtual_cpu/protocol 相关用例）。

**pending**：opt-in 路径的 2^14 A/B、字节等价 filter、2^16 全量（统一窗口）；此前 opt-in
路径不参与默认验收。`simd_dual.rs` 末尾仅追加 `dynamic_claim_frame_columns`（默认 env 下
零调用，仅 claim_shout 使用）。


### C.8 2026-11-03: the committed-Shout skeleton is built on a quadratic reduction

Measured with the RSS watchdog and `MAGNETAR_PROFILE_SHOUT` stage marks (temporary
instrumentation):

| stage (ADDS=1023, 2^10) | peak RSS |
| --- | --- |
| start of `prove_committed_shout` | 1.15 GiB |
| after `BinaryShoutWitness::from_trace` | 1.15 GiB |
| after `prove_binary_shout_claims` | **2.34 GiB** |

`prove_binary_shout_claims` (the reference BinaryShout in
`crates/magnetar-runtime/src/binary_shout.rs`) builds `terms = witness.cells *
cycles` field vectors per factor and `sumcheck_terms` folds `degree + 1` full
copies of every factor per round across threads. At 2^10 that is a +1.19 GiB
transient; at 2^14 the full benchmark aborts at the 2.5 GiB watchdog limit; at
2^16 `cells * cycles = 2^32` field elements (~68 GB) are simply infeasible.

Consequence: **M4a as implemented cannot scale**, so the committed-Shout path
stays opt-in and default off. The next M4 revision should reuse the *linear*
`logup_shout` prover (O(cycles log)) and commit its position/link/reader columns
(and, if the pushforwards must be checked, commit the pushforward vector and
open it at the verifier's point instead of shipping `2^address_bits` field
elements). The 1 MB pushforward that the plan tried to avoid is three orders of
magnitude cheaper than the quadratic factor materialisation it replaced.

### C.9 M4 revision sketch: linear logup_shout with committed pushforwards

The M4a skeleton (C.8) cannot scale because it reuses the quadratic reference
`binary_shout`. The revision should be built on the *linear* `logup_shout`
prover that the classic trace path already uses (O(cycles log cycles)):

1. **Columns**: keep the current `logup_shout` witness construction, but commit
   the per-cycle columns it rebuilds in the verifier (position bits, `is_32`,
   `valid`, the 12 link columns) as packed bit tables in the extended claim
   table `T`, exactly like M2/M3 commit the claim columns. The reader claims
   then come from `T` openings instead of re-deriving them from the trace.
2. **Pushforwards**: `logup_shout` proves the log-derivative identity with a
   pushforward vector of length `2^address_bits` (1 MB of F2^128 at the
   synthetic bench's ROM = 2^16, i.e. it would double the current 1.0 MB proof).
   Ship it as a *committed* table in the same PCS instead: commit, then open at
   the verifier's evaluation points (the points are derived after the commit, so
   Fiat-Shamir order still works). The opening is O(log) + queries, which is
   what keeps the proof at its current size; the alternative of serialising the
   vector is acceptable only for small ROMs (2^12 or less).
3. **Soundness binding**: the committed position/link columns must be tied to
   the authenticated claim rows (the composed `trace_claim_root` already binds
   the claim table; extend it with the shout/field roots as M4a did) and the
   public ROM is checked O(rom) against `column_evals[0]` as today.
4. **Verifier cost**: replacing the 21.9-29.6 ms `Shout` witness rebuild with
   openings should land the trace check at ~3-5 ms; combined with the M2/M3
   claim table that is the 8-12 ms path.
5. **Order**: keep M4a dead code behind `MAGNETAR_COMMITTED_SHOUT` for reference
   (or delete it), implement the logup-based path behind a new switch, and only
   flip the default after the four-metric A/B (verify wall/CPU, proof size,
   peak) passes at 2^14 and 2^16.

### C.9.1 M4 修订版实施设计（线性 logup_shout + 已提交 pushforward）

状态：设计稿，未动代码（等 Lead review）。M4a（`7c55772`）因 reference BinaryShout 的
`cells×cycles` 物化而不可扩展，冻结为 opt-in/dead code；本设计基于**线性**的
`logup_shout`（`O(cycles log cycles)` prover，`crates/magnetar-runtime/src/logup_shout.rs`）。

#### 目标与现状差距

- paper 路径的 `LogupShoutProof` 已经携带 committed reader/link/position 列（25 列 dense
  P3 batch opening，2^16 时约 245 KB），但 native verifier **完全不校验它**（§9.6）；
- native `TRACE_SHOUT` 路径用 `trace_logup_shout`：verifier 从 claim 行重建 witness
  （21.9–29.6 ms）并重算 pushforwards；
- `LogupStarProof.pushforwards` 是长度 `2^address_bits` 的向量：合成 bench ROM=2^16 时
  **1 MB**，直接塞进 proof 不可接受；不塞又无法在不重建 witness 的情况下验证 logup 恒等式。

#### 架构（三步）

1. **列进 claim 表（复用 M2/M3 的 T）**：把 logup_shout prover 构造的 per-cycle 列提交进
   扩展 claim 表 `T`：
   - `T_bits` 追加 packed 布尔列：position 位（`address_bits`）、`is_32`、`valid`、
     link 12 位（slot 布局：schema 列后按固定顺序；2^16 时 512→1024 slots）；
   - `T_field`（dense，P3BinaryPcs rate 1/8）追加 **reader word 列**（word mode 下 1 列：
     每 cycle 的 claim instruction word）；
   - statement 组合 root 扩为 v3：`H("claim-shout-v3" || v1 binding || shout root ||
     field root || pushforward root)`；`MAGNETAR_LINEAR_SHOUT=1` 时生效，默认路径零改动。
2. **pushforward 作为已提交表**：prover 在 logup prover 前先构造 pushforward 向量
   （长度 `2^address_bits`）并用 `P3BinaryPcs`（rate 1/8）提交；把**承诺绑定哈希**
   作为 transcript 消息、把 verifier 需要的**点求值**放进 proof（见下）；verifier 在
   challenge 抽完后用 PCS opening 校验这些点求值。proof 里不再出现 2^address_bits 个元素。
3. **verifier 无 witness**：
   - `reader_claims` = `T_field.word` 在 reader point 的 PCS 打开值（word-only columns=1）；
   - `position_claim` = position 位在 logup `position_point` 的**线性组合**（embed 是各位的
     线性函数：`embed(pos)=Σ_b node_b·pos_b`），用一条 claim relation（公开系数）认证；
   - `is_32/valid/link`：valid=公开前缀模式、is_32≡0（word mode）、link 若 router 表存在才
     使用（dynamic 路径没有，提交但本路径不消费）；
   - logup 恒等式校验：`LogupStarProof::verify` + committed pushforward 的点求值校验；
   - 公开 ROM：`column_evals[0]` 对 `statement.rom` 的 word 列做 O(rom) 检查（合成 bench
     ~0.3–1 ms，论文 ec20 ROM 小则更少）。

#### 需要的 vendor 改动（**需 Lead 批准**）

`vendor/plonky3/multi-stark/src/logup_star/`（仅该模块；repo 内唯一使用者是
`magnetar-runtime/logup_shout.rs`，无其它 crate 依赖）：

- `proof.rs`：`LogupStarProof { pushforwards: Vec<Vec<EF>>, .. }` →
  `pushforward_bindings: Vec<[u8;32]>`（已提交向量的绑定哈希，长度 = tables）+
  `pushforward_evals: Vec<EF>`（每个 `BlockRole::Table` block 一个点求值，顺序同
  `plan.blocks`）；
- `transcript.rs`：`pushforward(&[EF])` → `pushforward_binding(&[u8])`（吸收哈希，而不是
  整个向量）；**prover 与 verifier 同步改**，其余 transcript 消息顺序不变，因此所有已测
  证明的字节等价语义只在不含 committed-pushforward 的旧路径上保持不变（旧路径仍可保留
  原 API 或在调用处包一层：见风险）；
- `prover.rs`：新增 `prove_with_pushforward_binder(..., binder)`：在构造 `Weights` 后、
  吸收 pushforward 之前回调 `binder(&pushforwards) -> Vec<[u8;32]>`（runtime 在回调里
  P3 提交向量并返回 `H(commitment)`），然后吸收 binding、记录 evals；
- `verifier.rs`：`verify_with_pushforward_bindings(...)`：check_shape 改校验
  bindings/evals 数量；吸收 binding；`rebuild_opening` 的 Table block 用
  `pushforward_evals[k]` 替代 `Poly::eval_ext`；`LogupStarOutput` 增加
  `pushforward_claims: Vec<(Vec<EF>, EF)>`（table cube 点 + 值），供 runtime 做 PCS opening
  校验。
- 注意 `logup_star` 还有第二个使用者 **`crates/magnetar-runtime/src/linear_twist.rs`**
  （Access 层 register twist 的两处 logup）。为把爆炸半径压到最小，**保留旧 API**：
  `LogupStarProof` 增加 `#[serde(default)] pushforward_bindings/pushforward_evals` 与新入口
  `prove_with_pushforward_binder` / `verify_with_pushforward_bindings`；旧
  `prove`/`verify`（内部仍用 `pushforwards` 向量 + 现有 transcript）完全不动，
  `linear_twist` 与所有旧路径行为/字节不变。只有新的 M4 路径走 committed 版本。
- 预计 ~150–200 行 vendor diff；不改 p3 其它模块，不动 `binary_twist`/`stream`/`spartan`。
- **备选（若 vendor 改动不被批准）**：把 `logup_star` 整模块 copy 到
  `crates/magnetar-proof/src/logup_star_committed/`（~1k 行）再改，缺点是 vendored 代码
  分叉、升级成本高；不建议，除非必须零 vendor 改动。

#### 新类型 / 文件清单

| 文件 | 改动 |
| --- | --- |
| `vendor/plonky3/multi-stark/src/logup_star/{proof,transcript,prover,verifier}.rs` | committed-pushforward API（上述，需批准） |
| `crates/magnetar-runtime/src/logup_shout.rs` | 新增 `CommittedLogupShoutProof { columns: usize, address_bits, cycle_bits, cycles, reader_point, reader_claim: F2_128, link_claims, position_claim, logup: LogupStarProof, pushforward_commitment: P3Commitment, pushforward_openings: Vec<P3Opening>, field_commitment/opening..., claim_relations: Vec<ClaimRelationProof> }`；`prove_committed_logup_shout(witness)` / `verify_committed_logup_shout(proof, statement, claim_table)`；旧的 `prove_logup_shout`/`verify_logup_shout_*` 保留（legacy/参考路径） |
| `crates/magnetar-runtime/src/claim_table.rs` | T 布局扩展入口（v3 root 组合、shout 列 slot 映射、dense reader 列）——与 M2/M3 表共享 slot 布局，扩 slot 数 512→1024 |
| `crates/magnetar-runtime/src/claim_shout.rs` | 复用 M4a 已实现的 claim relation 原语（multi-point/线性关系）与 synthetic commitment 思路；删除 BinaryShout 相关路径（M4a 冻结后不再新增引用） |
| `crates/magnetar-runtime/src/lib.rs` | native/paper prover 在 `MAGNETAR_LINEAR_SHOUT=1` 时构造新证明并附加到 `ClaimProof.committed_logup_shout`；verifier 分支替换 `trace_logup_shout` 重建；statement root v3；默认路径不变 |
| `crates/magnetar-runtime/src/trace_claims.rs` | `ClaimProof` 增加 `committed_logup_shout`（serde default）；`MAGNETAR_CLASSIC_LOGUP=1` 保旧路径 |
| `crates/magnetar-runtime/src/simd_dual.rs` | 末尾纯追加（如需要）：logup reader/link/position 列所需的 claim 表 slot 映射（复用 M4a 的 frame 列已够） |
| `docs/HANDOFF.md` §6 | M4 v3 transition rules（新 wire 字段、旧 proof 拒绝策略、env 开关） |

#### 成本估计（2^16，待 A/B 验证）

- **proof**：删 25 列 logup PCS opening（~245 KB）→ 改 reader 1 列 + pushforward 承诺/打开
  （~5–15 KB）+ position 关系（~2–4 KB）≈ **净减 150–200 KB**，落在 850 KB 以下；
- **verify**：logup reduction ~3.9 ms + reader 打开 ~0.3–0.8 + position/link 关系 ~2–3 +
  pushforward 打开 ~0.3–0.8 + public ROM O(rom) ~0.3–1（2^16 合成 ROM）≈ **5–7 ms**
  （对比 native 路径 21.9–29.6 ms 重建；paper 路径则是从 0 校验→健全校验，但可同时删行 blob
  后由 M5 抵消）；
- **prover**：pushforward 提交/打开对 ROM-size 敏感（合成 bench 2^16：~2^17 输入，~10 ms 级；
  论文 ROM 更小）；logup prover 本身 O(cycles log cycles)。

#### C.9.1-R 修订（Lead 拍板后的落地版，2026-11-03）

Lead 对 §C.9.1 四个问题的拍板结果及落地调整：

**(a) vendor p3 `logup_star` 改动：批准**。落地时采用比「加 serde 字段」更强的方案：
**完全不改任何 p3 proof/output 结构体**（`LogupStarProof`/`LogupStarOutput` 字节不变），
新能力全部通过**新增函数**提供，bindings/evals 作为参数/返回值在 runtime 层携带：

- `transcript.rs`：`LogupStarShape::pattern_committed_pushforwards` /
  `domain_separator_committed`（协议名 `p3-multi-stark-logup-star-committed`，
  pushforward 步骤 = 32-byte binding message）+ prover/verifier transcript 的
  `new_committed` / `pushforward_binding`；
- `prover.rs`：`LogupStarProof::prove_committed(lookups, witness, challenger, binder)`
  → `(proof, bindings, reduction_evals, product_evals)`；proof 的
  `pushforwards` 置空，binder 在 FS 顺序中原 pushforward 位置被调用（先提交后抽 challenge）；
- `verifier.rs`：`verify_committed(lookups, challenger, bindings, reduction_evals,
  product_evals)` → `(output, pushforward_claims)`；`check_shape_committed` /
  `rebuild_opening_committed` / `final_value_committed` 用外部 evals 替代
  `Poly::eval`，并把 verifier 需要 PCS 打开的 `(point, value)` 返回给 runtime。
- 旧 `prove`/`verify`/`rebuild_pushforwards` 与全部结构体**一行未动**（vendor diff：
  664 insertions / 0 deletions），因此 `linear_twist` 及旧路径 proof **编码字节完全不变**
  （不是"语义不变"）。回归测试仍按 Lead 要求加：在 `magnetar-runtime` 里用旧入口编一份
  proof 并断言其编码 hash 与改动前一致（结构体未动 → 恒等，但保留 golden 断言防回归）。

**(b) word-only reader：批准** → M4 新路径 `columns = 1`（reader = claim word 列），
paper 路径的 12 列 reader 留 M4b。

**(c) link 列：不提交**。依据（写入验收）：
- Logup* claimed-sum 的三类项：reader claims（`product::claimed_sum` 的 reader 侧）、
  position claims（`rebuild_opening` 的 denominator 侧）、pushforward（table 侧）——
  **没有任何一项引用 link 列**；verifier 的 `position_claims` 也不含 link；
- `logup_shout` 里 link claims 只被 `logup_shout_router_link_claims` 用于 shift/store
  router 折叠；dynamic native 路径没有 router 表（`shift_router_index`/`store_router_index`
  均为 None），verifier 无消费者；
- 因此 link 列**从 T 布局与 proof 中删除**（不预留 future 占位）。同理 `valid`/`is_32`
  也不需要提交：`positions()` 对 padding cycle 取 0（即合法读取 ROM[0]），word mode
  `is_32≡0`，二者只在 prover witness 内部影响 reader claim 的值，而 reader claim 本身
  由 T_field 打开值 + logup 恒等式 + position 关系绑定，无需单独列。
- ~~修订后的 T 扩展 = 仅 `T_field`（reader word 列，dense）~~ **已被 §C.9.1-S 取代**：
  健全性复核发现表侧/位置侧需要 host-derived 的 `T_word` + `T_pos` 两列（不扩 T_bits、
  不扩 slot 布局，不做 pc 位线性关系），见下一节。

statement root v3 简化为 `H(v1 binding || field root)`；verifier 侧 PCS 校验：
`T_field` 打开（reader claim）→ logup committed 验证（bindings + pushforward PCS 打开）→
position claim 对 claim 表 pc 位的关系证明 → 公开 ROM word 列 O(rom) 检查。

#### C.9.1-S 健全性义务表（修订：保留 T_shout，两列 host-derived）

结论先行：**需要 T_shout**，但形态比 M4a 小得多——只提交 logup 论证真正消费的两列
（reader word、position embed），且它们是 **statement 构造时 host 从 trace 派生**的，
与 M2/M3 claim 表同一信任模型（statement 是公开输入，root 绑定后 prover 不能偏离）。
不提交 link/valid/is_32/pc 关系（(c) 的结论保持）。

| # | 验证器要的值 | 从哪里拿 | 被什么绑定 | 复杂度 |
|---|---|---|---|---|
| 1 | **reader claim**（word 列 MLE @ reader point） | `T_word` PCS opening @ reader point；reader point = H(field commitment) 的 FS 抽样 | `T_word` 是 host 从 claim 行 `instruction_word` 派生（padding cycle 用 ROM[0]，与 prover 的 `reader_columns` 构造一致），commitment root 进 statement v3 root | O(log) opening + O(1) absorb |
| 2 | **position claim**（embed(position) MLE @ position point） | `T_pos` PCS opening @ logup `output.position_point`，值 = `output.tables[0].position_claims[0]` | `T_pos` 是 host 用 `positions()` 同款语义派生：cycle<trace_len → (pc−rom_base)/4，padding → 0（trace_len 公开）；root 进 v3。**不需要 pc 位线性关系**（避免 `pc = rom_base + 4·pos` 的进位非线性），也避免 M4a 里 pc 位直接当 position 的隐含假设 | O(log) opening |
| 3 | **table 侧（ROM 列 claim）** | 不提交 table 列；verifier 用**公开 ROM** 现算：`expected = eval_mle(public_rom_word_column, output.table_point)`，与 `output.tables[0].column_claims[0]` 比较 | 公开 ROM 是 statement 的一部分（program hash/rom 公开）；`table_point` 来自 product sumcheck（后续被 fraction/product 校验约束） | **O(rom)=O(2^address_bits)**（word-only 单列，合成 2^16 ≈ 0.3–1 ms；论文 ec20 ROM 更小） |
| 4 | **pushforward（多重集函数）** | prover 提交 pushforward 表（P3），proof 只带 verifier 需要的点求值 + opening；transcript 吸收 `H(commitment)` | **不是"提交即正确"**：fraction reduction 把 pushforward 与 position 列绑成同一多重集（reader 侧 weights vs table 侧 `position::eval`，随机 entry challenge 下 w.h.p.），product sumcheck 再把 reader claims ↔ Σ pushforward·ROM 列绑起来（`product::claimed_sum` 来自 statement 的 reader claims）；verifier 对 pushforward 的 2–3 个 (point,value) 做 PCS opening | O(log) opening ×2–3 + O(log²) 归约校验 |
| 5 | **padding / valid** | 不需要 verifier 重算：`T_pos` 把 padding 固定为 0（=合法读 ROM[0]，与 `positions()` 语义一致），real row 的 (pc−rom_base)/4 由 host 写入；trace_len 公开且参与 statement 构造。若 prover 把 real row 标成 padding，则它用的 position 列与 `T_pos` opening 不符（PCS 拒绝）；reader 列同理被 `T_word` 钉死 | — | — |
| 6 | **paper 路径「Shout 未校验」缺口** | 由本设计的完整链闭合：reader claim ← `T_word` 打开；position ← `T_pos` 打开；ROM ← O(rom) 现算；多重集 ← fraction+product 归约。verifier 每次都会跑 logup reduction，不再有「只 carried 不消费」的 proof 字段 | — | 总计 O(rom) + O(log²)，无 O(cycles) witness 重建 |

关键正/负向理由（为何不再需要 pc→index 关系或 T_bits 扩展）：
- `pc = rom_base + 4·position` 减去常数再取位在 GF(2) 上带进位、非线性；若用 pc 位推
  position 需要提交进位列并做二次关系（CPU-relation 级复杂度），收益为零。改为 host
  直接提交 position embed（statement 信任模型与 M2/M3 完全一致），verifier 只做 PCS 打开；
- `link`/`valid`/`is_32` 在 logup verifier 侧没有消费者（C.9.1-R 已论证），不提交；
- 代价：+1 个 dense 列提交/打开（position embed），proof 约 +1–3 KB，verify 约 +0.3–0.8 ms，
  远小于放弃健全性换来的收益。

更新后的 T 扩展 = **`T_word`（reader word 列）+ `T_pos`（position embed 列）**，两列均
host-derived、root 进 statement v3 `H(v1 binding ‖ word root ‖ pos root ‖ pushforward root)`；
link/valid/is_32 不提交。其余（提交 pushforward、FS 抽点开、verifier 无 witness）按
§C.9.1-R。

#### 实施顺序与 open decisions

1. Lead 批准 vendor p3 committed-pushforward 改动（或选 fork 备选）；
2. 先做 `logup_shout` 层（新 prover/verifier + 单测，用现有 trace 路径验证字节/语义），
   默认路径不动；
3. T 扩展 + 关系（复用 `claim_shout` 的 relation 原语）+ statement root v3；
4. lib 接线 + `MAGNETAR_LINEAR_SHOUT`/`MAGNETAR_CLASSIC_LOGUP` A/B；
5. 统一窗口四项测量后，达标（2^16 verify ≤25 ms、proof ≤~820 KB、peak ≤2.6 GiB）才考虑
   切默认，否则保持 opt-in 并写进 docs。

#### C.9.2 First end-to-end A/B of M4v3 (2026-11-03)

The wiring landed (`6c956a5`): `MAGNETAR_LINEAR_SHOUT=1` builds the committed
logup proof, recomposes the statement v3 root and verifies without rebuilding the
Shout witness; default stays off. First A/B at `2^16` (the host went into heavy
swap during the run, 1-min load 480-650, so **wall is meaningless and only CPU
and proof size are quoted**):

| | default | `MAGNETAR_LINEAR_SHOUT=1` |
| --- | --- | --- |
| proof | 1,018,154 B | **1,523,394 B (+505 KB)** |
| of which `committed_logup_shout` | -- | **514,689 B** |
| verify CPU / iter | 155.3 ms (loaded) | **97.0 ms (-37 %)** |
| `verify_native` stages | -- | claim table 8.96, access 13.5, trace_logup 20.3, core 18.1 ms |

Verdict: **not ready for the default**. The verifier CPU direction is right
(-37 % on a very noisy host, needs a quiet-host confirmation), but the proof is
568 KB over the 950 KB acceptance line. The 514 KB is dominated by four
independent PCS openings (word, position, fraction-reduction pushforward,
product pushforward): each carries a full rate-1/8 query set. Next iteration:
1. batch the four openings into a single `P3BatchOpening` over one commitment
   (the `P3BatchPoint` machinery the classic logup_shout path already uses);
   target `committed_logup_shout` <= 150 KB and total proof <= 1.0 MB;
2. check why the opt-in log still reports a `verify_native trace_logup` stage
   (label reuse or a real duplicate rebuild);
3. consider trimming the logup proof itself (fraction GKR + product sumcheck).

Until then M4v3 stays opt-in. A quiet-host four-metric A/B is required before
any default flip.

### C.9.2 M4v3 修订：单次 batch opening + 公开 FS reader point（代码已写，未 build）

#### 实测问题（安静窗口需复测，以下 proof 字节数可信）

| 2^16 | 默认 trace | `MAGNETAR_LINEAR_SHOUT=1` |
| --- | --- | --- |
| proof | 1,018,154 B | 1,523,394 B（+505 KB） |
| `committed_logup_shout` | — | 514,689 B |
| verify CPU/iter | 155.3 ms（高负载，仅方向参考） | 97.0 ms |

`committed_logup_shout` 的构成（prove 侧打印，2^16）：**4 个独立 P3 opening 每个
126–127 KB**（word / pos / reduction / product）+ logup* 本体仅 **8.5 KB** +
bindings 40 B。即：proof 超标的根因是**打开次数**，不是 logup 证明本身；经典 25 列
batch opening 的 245 KB 历史数字也不适用于本路径（trace 版 logup 本体很小）。

#### 修订设计（已落地到代码）

1. **一个 batch commitment 覆盖三张表**：`T_word`、`T_pos`、`T_pf`（pushforward）都
   pad 到同一 arity `L = 2^max(cycle_bits, address_bits)`，用 `commit_batch` 一次提交。
2. **一个 `open_batch` 覆盖所有点**：reader point（列0）、logup position point（列1）、
   fraction reduction 的 Table-block 点（列2）、product point（列2），一次
   `P3BatchOpening`；`verify_batch` 一次校验全部值。目标 `committed_logup_shout`
   ≈ 一个 opening（~127 KB）+ logup 8.5 KB ≈ **140 KB**。
3. **row point 用公开 statement 数据作 FS 种子**：reader point =
   `sample(domain ‖ rom_hash ‖ trace_len ‖ cycle_bits ‖ address_bits)`（全部来自
   trace/statement 公开数据），因此 statement 构造时可以先算 reader point → 再算
   pushforward 表 → 再形成 batch commitment，**无循环依赖**；prover/verifier 用
   `rom_hash(trace.rom)` / `rom_hash(statement.rom)` 重放同一套抽样。
   **双重绑定**：batch commitment 在调 `prove_committed` **之前**形成，binder 返回
   `committed_tables_root(commitment)`（规范化编码的 sha256）作为 transcript binding，
   verifier 从 proof 的 commitment 重算同一 digest 后传给 `verify_committed`；此外
   verifier 校验 `proof.opening.commitment` 与 `proof.table_commitment` 一致。
   statement v3 root 仍为 `H("claim-shout-v3" ‖ v1 claim binding ‖ tables_root)`，把同一
   commitment 再绑一次（statement 绑定 + transcript 绑定双保险）。
4. 旧的按表 commitment/opening 字段删除；`T_word/T_pos/T_pf` 的 evals 仍逐点携带
   （每个 16 B）。pushforward 的 transcript binding 不再是常量占位：prover 在
   `prove_committed` 前 commit 三张表并把 commitment digest 交给 binder，verifier 用
   proof 的 commitment 重算；另有 `opening.commitment == table_commitment` 一致性检查。
5. statement 绑定仍在：host 侧 `committed_statement_data(trace)` 重算同一个 batch
   commitment（同 trust model），verifier 用证明里的 commitment 重组 v3 root 与
   statement 比对。

#### 验收线现实评估（重要）

- 单次 batch opening 预计 ~127 KB（查询集合共享，列只增加叶数据）→ 总 proof ≈
  `1,018,154 − 9,449(经典 trace logup) + ~140,000` ≈ **1.15 MB**，仍高于 Lead 的
  ≤1.0 MB 线。**当前 TRACE_SHOUT 路径的 proof 结构里没有可删的大 Shout 字段**，
  因此 ≤1.0 MB 只有两条现实路径：
  (a) **M4b（推荐）**：把 committed 验证接到 paper/default 路径，替换现有
      `shout`/`packed_shout`/`field_opening` 等 proof 字段（paper 2^16 proof 为
      1,018,152 B，这些字段合计预计 >100–200 KB），净增 ≤ 100 KB 才能进 1.0 MB；
  (b) 降低 P3 安全性参数（100→64 bit 查询数下降约 36%，opening ~81 KB），但属
      soundness 取舍，需 Lead 单独批准，不建议默认。
- verify 方向：2^16 trace 路径 412.7 ms（默认，含 witness 重建）→ 62.9 ms（opt-in），
  CPU 155→97 ms；但默认 paper 路径本身只有 24.7–27.2 ms，所以 opt-in 只有落到
  M4b 的 paper 路径才有机会把「默认 verify」降到 ~25 ms 以下（替换未校验的 Shout
  检查 + 复用现有 mosaic opening 的前景需 M4b 设计）。
- **本轮测量在 load 480–650 下进行，wall 数字不可信，CPU 与 proof 字节可参考**；
  安静窗口需复测。

#### 任务 2 结论：`verify_native trace_logup: X ms` 标签不是双跑

代码里该 `eprintln!` 在 committed/classic 分支之后的公共位置打印，衡量的是整个
logup stage 的耗时，不是经典重建又跑了一遍；opt-in 时 `trace_logup_shout` 为 `None`
（prover 只在 classic 分支产它），经典重建分支不可达。已修：标签改为
`verify_native logup stage`，并新增 `verify_native committed logup`（committed 分支）
与 `verify_native classic trace logup witness build`（classic 分支）。

#### 任务 3 结论：logup* 本体不需要压

2^16 实测 `logup` 字段 **8,512 B**（fraction GKR + product sumcheck），占 committed
字段 <2%；经典 25 列 245 KB 是 paper logup 的 batch opening，与此路径无关。压缩重点
只在 PCS 打开次数（已由本修订解决）。


#### C.9.2-D Lead 决策（记录在案，2026-11-03 晚）

1. batch-opening 设计+代码采纳；`trace_logup` 标签复用已确认、标签拆分认可；
   `logup*` 本体 8.5 KB 不压。
2. **不降 P3 安全参数**（100-bit 保持）：选项 (b)（降安全性换 proof）**否决**。
3. 验收线分层：
   - **M4v3 opt-in（native/TRACE_SHOUT 路径）中间验收线**：批处理后
     `committed_logup_shout ≤ 150 KB`、总 proof `≤ 1.2 MB`、2^16 verify **wall ≤18 ms**
     （安静机采集）、peak `≤2.6 GiB`。达到即算 milestone，**默认仍关**。
   - **切默认门槛**：完成 **M4b（paper/default 路径替换 `shout`/`packed_shout`/
     `field_opening` 相关字段）**且总 proof `≤1.0 MB`、verify wall `≤12 ms`
     （与论文 8–12 ms 目标一致）时才切默认。
4. 宿主危险期间**零 build/零 bench**；下一轮由 Lead 发「恢复」信号后：
   (a) 编译 batch-opening WIP（预计 1–2 轮小错）+ `cargo check -p p3-multi-stark` /
   `-p magnetar-runtime` + `cargo test --release -p magnetar-runtime --lib logup`/`claim`；
   (b) 编译绿后 commit（Lead review diff 摘要 + 测试输出），再给测量窗口
   （2^14 A/B → 2^16，只测 verify CPU/proof/peak；wall 仅在 load<20 时采集）；
   (c) 期间纯代码做 M4b 设计 → §C.10。

### C.10 M4b 设计：paper/default 路径替换经典 Shout 字段

状态：**代码已写、待编译**（纯代码阶段，零 build/零 bench；恢复窗口第一件事是
`git diff --stat` + 关键函数存在性自检，然后编译）。目标：把 M4v3 的 committed-pushforward
linear Shout 接到 **paper/default 路径**，替换该路径现有的 `shout` / `packed_shout`
字段及其 verifier 检查，使「切默认」的总 proof ≤1.0 MB、verify wall ≤12 ms（需与 M5
一起完成）。

#### C.10.1 现状（paper/default 路径）

- Prover：`UnifiedProveContext` 在 `Shout` stage 生成 `shout`（`BinaryShoutProof`）与
  `packed_shout`（`PackedShoutProof`），`finish()` 写入
  `UnifiedTraceProof.{shout, packed_shout, shout_index}`；这些证明的 aux claims 由
  `prove_opening` 折进统一 `opening`（`P3MosaicOpening`）。
- **paper 路径还额外携带经典 `logup_shout`**（`prove_unified_trace_paper` 用
  `prove_logup_shout` 的 25 列 mosaic opening，并把 `pushforwards` 清空）；该字段的
  logup 恒等式在 verifier 侧只被折 link claims、**未被校验**——M4b 用 committed 版本
  替换它，同时闭合这个 soundness 缺口。
- Verifier：statement-only 的 `verify_core_statement` 中：
  - `binary_shout::verify_binary_shout_from_proof` → aux `(point, value)` 追加到
    `points/values`，再 `pcs.verify_mosaic(opening, …)`；
  - `packed_shout::verify_packed_shout` + `shout_router_link_claims`；
  - dynamic 路径没有 shift/store router 索引，因此 router 相关 claims 实际为空。
- 已知数字（2^16，安静窗口需复测）：paper/default proof **1,018,152 B**；verify wall
  24.7–27.2 ms；M2/M3 claim table 约 157 KB 已包含其中。

#### C.10.2 替换方案

1. **Prover**（`lib.rs` + `protocol.rs`）：
   - 当 `MAGNETAR_LINEAR_SHOUT=1`：在 `Shout` stage 跳过经典 `shout`/`packed_shout`
     证明生成（新增 `UnifiedProveContext` 选项 `skip_classic_shout`，同时不把它们的
     aux claims 折进 `opening`），`finish()` 里两字段保持 `None`；
   - 用 trace 重建 `BinaryShoutWitness::from_trace(trace)`（prover 侧有 trace），调用
     `prove_committed_logup_shout(witness, &rom_hash(trace.rom), trace_len)`，附加到
     `UnifiedTraceProof.committed_logup_shout`（字段已存在，`#[serde(default)]`）；
   - statement 构造无需改动：`claim_table::statement_claim_root(trace)` 已在 env 下委托
     `logup_shout::committed_statement_data(trace)` 生成 v3 root。
2. **Verifier**（`verify_core_statement` + `verify_native_unified`）：
   - `committed_logup_shout` 存在时：跳过 `shout`/`packed_shout` 的检查与 aux claims，
     改为
     (a) `claim_proof` 的 `root`+`table.root` → v1 binding → 与 proof 的 batch commitment
         重组 v3 root，与 `statement.trace_claim_root` 比对（statement 绑定）；
     (b) `verify_committed_logup_shout(committed, &statement.rom, &rom_hash(&statement.rom),
         statement.trace_len)`（一次 batch opening + logup 归约 + O(rom) word 检查）；
   - enabled 但缺失 → `PRE_M4V3_ERROR`；committed 存在但经典字段同时存在（旧 prover）→
     拒绝（避免 opening claims 双份）。
3. **字段/wire**：`shout`/`packed_shout` 保留字段名与 serde default（旧 proof 可识别但
   在 opt-in 下拒绝）；新 proof 中二者为 None。`field_opening` 属寄存器/trace claim
   路径，M4b 不动（M5 再处理）。

#### C.10.3 proof 净减估算与验收

| 项 | 2^16 估算 | 说明 |
| --- | --- | --- |
| 当前 paper proof | 1,018,152 B | 已实测（M2/M3 后） |
| + committed_logup_shout | ≈ +148 KB | batch opening ~127 KB + logup 8.5 KB + evals |
| − `shout`（BinaryShoutProof） | −? KB | 安静窗口用 `unified_proof_sizes` 实测 |
| − `packed_shout`（PackedShoutProof） | −? KB | 同上 |
| − 经典 `logup_shout`（25 列 opening） | −? KB（历史约 245 KB 量级） | 替换对象 |
| − 折进 opening 的 aux claims | −? KB | 随 opening 字段一起变小 |
| 目标 | **≤1.0 MB** | 需要前两项 ≥~180 KB |

**待实测**：paper 模式 `UnifiedProofSizes` 的
`shout`/`packed_shout`/`logup_shout`/`opening` 精确值（安静窗口，默认 env 跑一次即可）。
替换 `logup_shout` 一项就可能带来 ~100 KB 级净减；加上两个经典 Shout 字段，≤1.0 MB
的目标比最初估计更接近。

**verify ≤12 ms 的前提**：M4b 单独只替换 Shout 检查（paper 路径 verify 变化 = −
binary_shout/packed_shout 校验 − aux opening 校验 + committed 校验 ≈ 净 ±2–4 ms），
达不到 12 ms；需 **M5**（删行 blob/行 Merkle/decode/`claims_to_trace` 的 ~10–12 ms）
同一切换窗口完成。因此切默认 = M4b + M5 联合验收。

#### C.10.4 A/B 计划（恢复后的安静窗口）

1. 先跑 paper 模式默认 env，记录 `UnifiedProofSizes` 的
   `shout`/`packed_shout`/`opening`/`field_opening` 基线（只读，不改代码）；
2. M4b 实现 + 编译绿后：paper 默认 vs `MAGNETAR_LINEAR_SHOUT=1`，2^14/2^16 各 2 次，
   报 verify CPU/iter、proof 总量与分量、peak；wall 仅在 load<20 时采；
3. 达标（≤1.0 MB、≤12 ms、peak ≤2.6 GiB）后再做 M5 联合验收并决定切默认；否则保持
   opt-in 并把数字写入 docs。

#### C.10.5 改动清单

| 文件 | 改动 |
| --- | --- |
| `crates/magnetar-runtime/src/protocol.rs` | `UnifiedProveContext` 增加 `skip_classic_shout` 选项；`finish()` 条件置 None；`Shout` stage 条件跳过 |
| `crates/magnetar-runtime/src/lib.rs` | paper prover 附加 committed proof；`verify_core_statement` 分支；statement-only 绑定；标签 |
| `crates/magnetar-runtime/src/logup_shout.rs` | 复用（batch 版），无需新类型 |
| `crates/magnetar-runtime/src/trace_claims.rs` | 无改动（字段在 `UnifiedTraceProof`） |
| 单测 | paper 路径 opt-in round-trip（需临时 env 注入）、statement 绑定 tamper、经典字段共存拒绝、opening claims 不双份 |
| docs | 本节 + HANDOFF §6 transition rules |

#### C.10.1 First M4b A/B (2^14 paper path, 2026-11-03)

Landed in `e320cf9` (batch opening unit + paper-path replacement unit, opt-in
`MAGNETAR_LINEAR_SHOUT=1`, default off). Paper path, `ADDS=16383`, two
interleaved rounds; wall was unusable (host load 40-160) so CPU/proof/peak are
the comparable numbers:

| | default | opt-in | delta |
| --- | --- | --- | --- |
| proof | 1,009,871 B | **987,023 B** | **-22.8 KB** |
| `logup_shout` component | 158,433 B | 0 | removed |
| `committed_logup_shout` | 0 | **134,849 B** | batch opening (~127 KB) + logup (~8.5 KB) |
| verify CPU | 44.7/46.5 ms/iter | 50.0/50.1 ms/iter | **+5.4 ms** |
| peak RSS | 0.88/0.94 GiB | 0.69/0.83 GiB | -0.11 GiB |
| prove CPU | 79.2/80.1 s | 67.3/68.1 s | **-12 CPU-s** |

Reading: the batch opening landed at the predicted size (135 KB), the classic
25-column `logup_shout` opening (158 KB) is gone, so the paper proof shrinks by
~23 KB and the prover saves the classic Shout stage (-12 CPU-s). Verify CPU goes
*up* 5.4 ms because the committed path now actually verifies the Shout argument
(the classic paper verifier only folded its claims into the mosaic opening and
never checked the logup identity) -- this is the soundness gap being closed, not
a regression. The `<= 12 ms` default-flip gate therefore still needs M5's
-12.3 ms (row blob/row Merkle/decode/access digest); M4b alone is not enough.

2^16 paper default (host starved the process, wall invalid): proof 1,199,746 B,
`logup_shout` 187,281 B, opening 240,561 B, verify CPU 77.8 ms/iter, peak
1.40 GiB. The 2^16 opt-in run is deferred until the host calms down.

### C.11 M5 设计全文（补回丢失稿）：删除行 blob/行 Merkle/行重建，claim 表唯一真相

状态：M5 scaffold 已作为 patch 写出（TableOnly wire + v4 root + 互斥诊断 + 依赖门控，默认关）；完整 v4
verifier 依赖 **M5b（T 的 memory/register 数据列）**。

#### C.11.1 删除对象与当前成本（2^16）

| 对象 | 现状 | 成本 | M5 替代 |
| --- | --- | --- | --- |
| claim 行 blob | inflate + bincode decode | **1.0 ms**；blob 静态估算 **≈2,412 B**（`claim` 159,156 − 表证明 156,744；2^10 交叉验证 ≈197 B） | 删除；行不再是 verifier 输入 |
| 行 Merkle 根（claim leaves） | 逐组哈希所有行 → 求根 | **3.8–4.1 ms** | statement root 直接绑定 `T` 的 PCS commitment |
| `claims_to_trace`/TraceRow 重建 | claims → synthetic Trace | **0.77 ms** + 下游派生 | trace Logup 已由 M4 删除；端点改 O(1)（selected pc vs statement pc；`cycles=2^cycle_bits`） |
| access 摘要（`AccessStatement::from_claims` + 串行 digest） | O(rows) 事件收集 | **6.7 ms** | M5b：O(1) digest 由 claim 表 root 派生 + access 校验改为对 `T` 数据列的 relation（见 §C.12） |
| claim 行和 | 已由 M2/M3 `T` 关系替换 | 已消失 | 保留 `MAGNETAR_CLAIM_ROWS=1` legacy 回退 |

#### C.11.2 statement v4

`trace_claim_root = H("claim-shout-v4" ‖ claim_table_root ‖ shout_tables_root)`（linear Shout off 时
shout 分量为 32 零字节）；`MAGNETAR_CLAIM_V4=1`、`MAGNETAR_CLASSIC_CLAIMS=1` 回退；v4 与旧 proof 互相明确
拒绝（`M5 v4 mode: proof carries row claims` / `pre-M5 verifier mode: … table-only…`）。wire 新增
`ClaimProofWire::TableOnly`（**追加在枚举末尾**，旧 variant 索引不变，旧 proof 编码兼容）。

#### C.11.3 健全性映射

行数据不再进 proof 后：claim 表值 ← statement root + PCS 打开 + `claim_rel`；执行语义 ← `claim_rel`
target + selected lockstep/gating；Shout/ROM ← M4b 的 host-derived `T_word` + O(rom) + committed
logup；端点/trace_len ← O(1)；access ← M5b 的 T 数据列 relation。伪造 rows 必须同时伪造 `T`
commitment（statement root 固定）与关系证明（`claim_rel` 拒绝）。tamper 清单：表 commitment/root、T
slot、target、旧 proof 拒绝、v4/legacy wire 混用拒绝、无 blob round-trip（paper/native）、access
digest/端点 tamper。

#### C.11.4 与 M4b 的联合验收

当前 paper 2^16 verify wall 24.7–27.2 ms；M5 删除行路径 ≈ **−12.3 ms**（leaves 3.8–4.1 + decode 1.0 +
claims-to-trace 0.77）；access 6.7 ms 由 M5b 取代（目标净省 **≥5.6 ms**，见 §C.12.6）。M4b 实测 2^14
verify CPU +5.4 ms（补上 Shout 校验缺口）、prove CPU −12 s、proof −22.8 KB。M4b+M5(+M5b) 的预算若落在
14–19 ms 仍高于 12 ms，需按 §C.12 的 M6 候选（合并 opening 校验/复核重复摘要）继续压缩。

### C.12 M5b 设计：T 增加 memory/register 数据列，access 摘要 O(1)

状态记录：M5 scaffold patch 已保存（`/tmp/m5/m5_row_blob_removal.diff`，默认关、verifier 依赖门控）；M5b 为设计稿，翻转 M5 v4 gate 的前提。

状态：设计（未动代码）。目标：让 M5 v4 verifier 在**不重建 claims/事件**的前提下校验 access 层，
删除 6.7 ms 的 `AccessStatement::from_claims` + digest；这是翻转 M5 v4 依赖门控的前提。

#### C.12.1 需要的 access/aux 事件字段（来自 `TraceClaim`/`TraceMemClaim`）

`AccessStatement` 当前由 claims 重建（`access_statement.rs`）：
- `config`、`initial_ram`、`initial_state`：来自 statement（公开，O(1) 校验，不需提交列）；
- `memory_events: Vec<MemoryEvent{cycle, access{addr, value, width, is_write}}>`：来自每个 claim 的
  `memory: Vec<TraceMemClaim{cycle, addr, value, width, is_write}>`；
- `register_ops: Vec<RegisterOp{rs1/rs2/rd 存在性与索引, rs1_val/rs2_val/rd_val}>`：每 cycle 一条。

执行器每行的 memory 事件数有上限（M 个/cycle，按 `TraceRow.memory` 上限；host 在 statement 构造时
assert）；register ops 固定 3 个/cycle（rd/rs1/rs2，各带 present/index/value）。

#### C.12.2 列清单与 slot 布局（推荐：并入现有 T_bits，不新建 commitment）

| 组 | 列（bit） | 数量/cycle |
| --- | --- | --- |
| memory 事件（M 个/cycle） | 每事件：present 1 + is_write 1 + width 2 + addr 64 + value 64 | M × 132 |
| register ops（3/cycle） | 每个：present 1 + index 5 + value 64 | 3 × 70 = 210 |
| 合计（M=2，取执行器上界） | — | **474** |

现有 T_bits：schema ≈336 + M4 数据 46 ≈382 列；扩展后 ≈856 列 → slot 数 **512 → 1024**（仍在
2 的幂内一次补齐）。这样 access 关系与现有 M2/M3 target 关系共用同一个 `T_bits` commitment 和同一次
ring-switch opening（多 group selector sum-check，见 C.12.4），**不需要第三个 commitment**。

Host 派生规则（与 M2/M3 同信任模型）：statement 构造时逐 cycle 从 trace claims 填列；padding cycle 全 0；
memory 事件数不足 M 的 cycle 用 present=0 补；register present 直接来自 claim 的 `*_present`。statement root
把 `T_bits` commitment 摘要作为唯一 claim 表根（v4）。

#### C.12.3 claim relation 数量/成本

access 校验需要两类 claim：
- RAM twist claims：`binary_twist::verify_binary_twist_from_proof(&proof.access.ram, …)` 输出的 claim 集合；
- register twist claims：同上（`proof.access.registers`）。
这两组 claim 是「事件列在 twist 求值点的多重线性函数」的线性组合：twist 的每个 bit 权重由 verifier
抽到的求值点公开决定，因此可以用**一条 claim relation**（公开系数，value = verifier 从 twist proof 读出的
claim）把「T_access 列的 MLE」与 claim 绑定。推荐做法：扩展现有 `claim_rel` 为 **multi-point/multi-group**
（与 M4a 原语相同）：
- group 0：M2/M3 claim target（现有）；
- group 1：RAM 事件列 @ twist 点；
- group 2：register 事件列 @ twist 点；
- selector 位把多组合并进**一次** slot 维 sum-check + **一次** ring opening（proof 增量主要是 sumcheck
  多项式与轮数：+~200 B；T_bits 变大带来的 opening 路径略增 ~5–15 KB）。

Prover 成本：每个 group 需按列折叠（slots_per_group × cycles 位加法）；2 个 access group × ~474 列 ×
2^16 cycles ≈ 62M bit-ops（可与 claim 表 prover 同线程），量级与 M2/M3 的 target 关系相当，预计 +0.2–0.5 s
（2^16，需实测）。Verifier：sum-check 轮数 = log2(slots)+selector_bits ≈ 11–12 轮 + 一次 ring opening
（与现有 claim_rel 同一次打开），预计 **+1–2 ms**。

#### C.12.4 access verifier 替换后的检查链

1. statement：`access_statement_digest = H("magnetar-access-v4" ‖ claim_table_root)`（O(1)，host 构造；
   verifier 重算比对；不再 `from_claims`）；
2. 验 `proof.access` 的 twist 证明：`verify_binary_twist_from_proof(ram/registers)`（现有 O(log) 检查）；
3. **新**：claim relation 的 group 1/2 把 twist claim 与 `T_access` 列的 MLE 绑定（一次 opening 内完成）；
4. 初始状态：`initial_ram`/`initial_state` 为公开 statement 数据，O(|initial_ram| + width) 校验（现有，
   非 O(rows)）；
5. 端点/长度：selected pc vs statement + `cycles`/`trace_len` O(1)；
6. 删除：`AccessStatement::from_claims`、`synthetic_trace()`、`memory_witness()`、`register_witness()` 及
   `verify_trace_access_shared` 的 witness-rebuild 部分（保留 twist 校验本体）。

#### C.12.5 proof 增量与尺寸

| 项 | 估算 |
| --- | --- |
| T_bits slots 512→1024（commitment 不变、opening 路径 +log） | **+5–15 KB** |
| access 关系（并入现有一次 ring opening；sumcheck +selector） | **+~1 KB 以内** |
| access witness 不再进 proof（本来也不在） | 0 |
| 行 blob/行根删除（M5） | −≈2.5 KB |
| **M5b 净 proof 变化** | **≈ +3–13 KB**（相对 M4b+M5；2^16 目标仍 ≤1.0 MB 量级） |

#### C.12.6 verify 时间预算（目标：真正删掉 6.7 access + 5.6 行路径）

- 删除：access 摘要 **−6.7 ms**；claim leaves −3.8…−4.1；decode −1.0；claims-to-trace −0.77；
  （行路径合计 −11.6…−12.6 ms）
- 新增：access claim relation 的 sumcheck 校验 + 与现有 claim_rel 共享的 ring opening 校验
  **+1–2 ms**（T_bits slots 翻倍让每轮 MLE 长度 ×2，sumcheck 轮数 +1）
- **净收益 ≈ −9.6…−11.6 ms**：足以把 M4b+M5 的 14–19 ms 预算压向 ~8–12 ms，支撑「切默认 ≤12 ms」
  门槛；若实测 >12 ms，按 §C.12.7 的 M6 候选继续。

#### C.12.7 tamper 测试清单（M5b）

1. `T_access` 任一列 tamper（addr/value/width/write/present）→ claim relation 拒绝；
2. RAM twist claim tamper → relation value 不符拒绝；
3. register twist claim/索引 tamper → 拒绝；
4. 列交换（addr↔value、rs1↔rs2 列分组）→ relation 系数不符拒绝；
5. padding/present tamper（把 padding cycle 标成 present 或反之）→ 关系/twist 拒绝；
6. 初始 RAM/state tamper（公开 statement）→ O(1) 检查拒绝；
7. 旧 v1/v3/v4-without-access 证明拒绝（错误文案区分）；
8. paper/native round-trip（`#[ignore]` + 进程级 env，单跑）；
9. access digest 派生 tamper（`H(...)` 输入换）→ 拒绝。

#### C.12.8 实施顺序与 open items

1. host 列派生 + T_bits slot 扩展 + v4 root（与 M5 scaffold 合并）；
2. `claim_rel` 的 multi-group 扩展（M4a 原语已有，移植到 `claim_table`）；
3. access verifier 的 witness-free 变体（twist 校验 + relation，删 from_claims）；
4. statement `access_statement_digest` O(1) 派生 + 旧 proof 拒绝；
5. 测试矩阵 + 安静窗口测量（proof/verify CPU/peak）。
Open：执行器每 cycle memory 事件上界 M 的精确值（决定列数；若 >2 需 512→2048 slots，proof 增量与
prover 成本重估）；twist claim 与 bit 列的系数是否与现有 `claim_rel` 的公开系数推导兼容（M4a 原语的
multi-point 版已覆盖该形态）。
