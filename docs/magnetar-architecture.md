# Magnetar 论文架构分析

> 依据：`papers/magnetar-2026-2423.pdf`，重点 Section 2.1（端到端流程）、Section 5.2（MosaicPCS）、Section 5.3（Virtual Spartan）、Section 5.4（BinaryRouter）、Section 5.5（完整协议）。
>
> 架构图：[magnetar-paper-architecture.png](magnetar-paper-architecture.png)（分层版）；[magnetar-architecture.png](magnetar-architecture.png)（组件/数据流版）。

## 1. 一句话概括

Magnetar 不是"CPU 表 + 操作表 + 多个 lookup/permutation"的拼接，而是：

> **一份共享 witness W，两个 SIMD R1CS 关系，Virtual Spartan 把 W 切成 direct/virtual segments 并逐段产生 evaluation claims；BinaryTwist / BinaryShout / BinaryRouter 各自消费自己负责的 virtual claim，最后所有 claim 被 MosaicPCS lift/batch/ring-switch 成对 G 的单一 evaluation claim，再由 Ligerito 证明。**

核心连接机制是 **evaluation claim on a witness segment**，不是跨表 permutation，也不是对每个组件单独承诺。

## 2. 七个层次

### 1) KeyGen / public preprocessing

输入：RV64I 程序 P、机器配置、trace 长度 T。

输出（全部 public）：

- **bytecode ROM**：把每条 RV64 指令展开成一个或多个 virtual instruction；每行由 **micro-PC** 标识。行内包含 opcode、rd/rs1/rs2、imm、shift 类型/shamt、store width 等元数据。
- **两个 SIMD R1CS 结构**：`s1 over F2` 与 `s2 over F2^128`。前者便宜地表达 bit-level 约束（XOR/加法位逻辑），后者便宜地表达 word-level packed 约束（整字选择、packed linear checks）。
- **witness layout L**：把 W 划分成 direct segments 与 virtual segments。
- **routing structures** `Rsh`, `Rst`：shift 与 sub-word store 的 public routing 描述。
- **MosaicPCS layout**：每个 polynomial 的子立方体位置/后缀。

关键点：**micro-PC expansion 是后面所有 selectors、metadata 和 recursion 的前提**。没有展开，bytecode ROM 行与 CPU cycle 不是一一对应，Shout/Router 的 selector 也无处绑定。

### 2) Execute：shared witness W

Prover 执行展开后的程序，记录 virtual cycles，形成 W。

W 被分成：

- **direct segments**：CPU 状态（pc、next pc、寄存器值、RAM 地址/值、flags 等），会被提交；
- **virtual segments**：R1CS 会读、但不直接提交的段，例如 decoded instruction fields、寄存器/RAM 读值、shift 输出、RAM increment；
- **auxiliary polynomials**：BinaryTwist 的 one-hot 地址位/valid/Inc、BinaryShout 的 fetch 地址位、BinaryRouter 的输入/selector 等；这些需要提交，供 specialized arguments 打开。

注意：**virtual segment 不提交**，这正是 Virtual Spartan 存在的原因。如果全部 W 都提交，就会为已经被 Twist/Shout/Router 证明正确的值重复付费。

### 3) Commit：唯一的 MosaicPCS commitment

Prover 把 **direct segments + auxiliary polynomials** 放到互不相交的子立方体上，拼成一个大的 multilinear polynomial `G`：

```text
G(x || s_i) = p_i(x)     // p_i 在子立方体 i 上
G(x) = 0                  // 子立方体之外
```

只发送一个承诺 `cmG = Commit(P_G)`。

这一步对应论文的 **one commitment, one evaluation argument** 目标。MosaicPCS 不是另一个 proof system，而是把很多不同大小的 polynomial 变成"对同一个 G 的 claims"的布局/适配层。

### 4) Virtual Spartan：CPU 归约枢纽

输入：`s1, s2, W, cmG`。

Virtual Spartan 做的是：

1. 对两个 SIMD R1CS 关系分别跑 Spartan 的 SIMD reduction；
2. 两个 relation 共享同一个 W，因此把两个 inner sum-check **batch 成一个**；
3. 输出 **每个 witness segment 一个 evaluation claim**（而不是整个 W 一个 claim）。

为什么必须分段：

- 一个 PCS 不能检查关于整个 W 的 claim，因为 W 的 virtual 部分没有承诺；
- Twist/Shout/Router 也只能接受"某个 segment"的 claim，不能接受整个 W。

所以 Virtual Spartan 是 **CPU 世界与 memory/bytecode/routing 世界之间的接口**：

```text
Virtual Spartan
  ├─ direct segment claims   → 留给 MosaicPCS
  └─ virtual segment claims  → 分发给 Twist / Shout / Router
```

### 5) 消费 virtual claims：specialized arguments

按论文 Step 3–6 的顺序：

#### BinaryTwist for registers

消费 register claims，输出：

- committed one-hot register address claims；
- committed increment claims；
- register index claims（留给 Step 6 的 Shout 检查）。

#### BinaryTwist for RAM

消费 RAM claims，输出：

- committed one-hot RAM address claims；
- committed increment claims；
- 一个随机点上的 `Inc(r)` evaluation claim。

这个 `Inc(r)` 有两个用途：

1. 作为 PCS claim 被 Mosaic 检查；
2. 作为 **BinaryRouter store** 的输入。

#### BinaryRouter for shifts

消费 shift output claim。它把 shift 表达成 bit routing，输出：

- 对 routing source（direct segment）的 claims；
- 对 bytecode selector 字段的 claims（留给 Step 6 Shout 检查）。

#### BinaryRouter for sub-word stores

消费 RAM 的 `Inc` claim。它把 `Inc = old XOR new` 与 byte lane 选择表达成 routing，输出：

- 对 source（direct segment）的 claims；
- 对 bytecode width selector 的 claims（留给 Shout）；
- 对低 3 位地址的 claims（direct segment）。

#### BinaryShout for bytecode

消费：

- Virtual Spartan 的 bytecode claims；
- Twist registers 的 register-index claims；
- Router 的 selector claims。

它证明这些值都是 **bytecode ROM 在对应 micro-PC 行的读值**，输出 committed one-hot fetch address claims。

这是整个架构的"闭合点"：没有 Shout，decoded fields/selectors 就只是 prover 声称的 virtual 值；有了 Shout，它们被 public ROM 认证。

### 6) MosaicPCS：lift → batch → ring switching → one evaluation

此时所有未决 claim 都是对 G 的某个 component 的 claim。

1. **Lift**：`p_i(r_i)=v_i` 变成 `G(r_i || s_i)=v_i`，只需追加 public suffix；
2. **Batch**：用随机 `α_i` 把多个 claim 变成对 G 的单一 claim `G(r_G)=v_G`；
3. **Ring switching**：把 bit-valued G 的 claim 变成 packed representation `P_G` 的 claim；
4. **PCS evaluation argument**：用 Ligerito（论文实现）证明这一个 claim。

MosaicPCS 的关键收益：**避免为每个 polynomial 单独做一次 hash-based PCS evaluation**；论文明确指出，如果每个 polynomial 单独承诺，evaluation arguments 会主导 proof length。

### 7) Verify / recursion

Verifier 主要做：

- SHA-256/SHA-3 哈希；
- F2^128 算术；
- 验证一个 Ligerito evaluation proof。

这些操作对 BinarySpartan 友好，所以可以把 verifier 本身再用同一套协议证明，做 chunked execution 的递归组合。

## 3. Claim 依赖图

```text
                    ┌────────────────────┐
                    │  Virtual Spartan   │
                    │  s1,s2 over W      │
                    └─────────┬──────────┘
        ┌──────────────┬──────┴───────┬──────────────┬─────────────┐
        ▼              ▼              ▼              ▼             ▼
   reg claim      RAM claim      shift claim    store claim   bytecode claim
        │              │              │              │             │
        ▼              ▼              ▼              ▼             │
  BinaryTwist     BinaryTwist    BinaryRouter   BinaryRouter       │
   registers          RAM           shifts         stores          │
        │              │              │              │             │
        │              └── Inc(r) ────┼──────────────┘             │
        │                             │                            │
        │                             ▼                            ▼
        │                       selector claims ───────────► BinaryShout
        │                                                        │
        └──────────────► one-hot / Inc / fetch claims ◄───────────┘
                                   │
                                   ▼
                         MosaicPCS lift + batch
                                   │
                                   ▼
                         ring switching → P_G
                                   │
                                   ▼
                         Ligerito evaluation proof
```

## 4. 设计不变量（判断实现是否"论文对齐"）

1. **只有一个 commitment**：direct segments + aux polynomials 都在同一个 G 里；不能给每个组件单独承诺。
2. **virtual segment 不承诺**：它由 R1CS 读、由 specialized argument 证明；否则 Virtual Spartan 失去意义。
3. **claim 而不是 permutation**：组件之间传的是 evaluation claims；不要引入 cross-table permutation/ grand-sum。
4. **bytecode 必须认证 selector/metadata**：Router/Twist 输出的 selector/register-index 必须最终被 Shout 消费，否则 virtual 字段可被伪造。
5. **micro-PC 是统一索引**：所有 ROM 行、selector、recursion 的指令身份都靠 micro-PC 对齐。
6. **Mosaic 只做布局/适配**：lift/batch/ring-switch 不产生新承诺；最终只有一次 PCS evaluation。
7. **verifier 是 recursion 的电路**：哈希 + 二元域算术，避免 circuit-friendly hash 假设。

## 5. 当前参考实现与论文的差距

| 论文组件 | 论文作用 | 当前参考实现 | 差距等级 |
|---|---|---|---|
| KeyGen / micro-PC expansion | 生成 public bytecode ROM、selectors、layout | 有 ROM/Statement、RVC，但按单指令/周期组织，未做多 micro-op 展开与 micro-PC ROM | 中 |
| 双 SIMD R1CS（F2 + F2^128） | 一个 W，两个 relation，锁步 | 有 lockstep，但两侧都是 F2^128；F2 只有原型 | 大 |
| Virtual Spartan | 分段 claim，连接 CPU 与 specialized args | 无；verifier 仍拿完整 trace 重建 CPU system | 大（A2） |
| BinaryTwist regs/RAM | 寄存器/RAM 一致性 | 已实现并有 proof；bit-sliced 地址、LT 物化 | 基本有，LT 待优化 |
| BinaryRouter shifts/stores | shift / sub-word store routing | 已实现 shift/store 两实例、Q/hQ；selector 尚未由 Shout 认证 | 中（D9/D10） |
| BinaryShout bytecode | 认证 ROM 行/metadata/selector | 已实现 bytecode + metadata；未消费 Router/Twist 的 selector/index claims | 中 |
| MosaicPCS | 单承诺、lift/batch/ring-switch | P3 多表共享承诺；未做 lift/batch/ring switching | 大（E4/E5） |
| Ligerito eval | 最终 PCS evaluation | 只有 index-opening wrapper；CPU 仍 P3 | 大（需 eval 接口） |
| Recursion / chunking | 大 trace 递归组合 | 有 chunked proof 参考，无递归 verifier | 大（G） |
| ZK / private IO | 隐私 | 无 | 大（F5/F6） |

### 已量化的瓶颈

- unified hello proof：**261,695 B**（width 64）。
- CPU 组件：**241,240 B**；CPU-only lockstep：**233,488 B**。
- 也就是说 **CPU P3/lockstep 是主项**，aux/trace claims 只占约 8 KB。
- 把独立 one-hot address 表接入，proof 增至 **305,103 B**；cell-column 表增至 **437,727 B**；追加到 addr 表增至 **441,887 B**。这些都被回退。

结论：**如果不先解决 CPU 证明或 PCS evaluation，继续优化 aux 的收益很小。**

## 6. 决策建议

### 如果目标是"论文架构对齐"

优先顺序建议：

1. **micro-PC expansion + public bytecode ROM/layout**（KeyGen）
2. **Virtual Spartan + witness segment layout**（A2）
3. **Shout 认证 Router/Twist 的 selector/register-index claims**（D9/D10）
4. **MosaicPCS lift/batch/ring-switching**（E5）
5. **Ligerito evaluation 接口**（PCS）
6. **recursion / chunking**

原因：Virtual Spartan 是 CPU 与 specialized args 的接口；没有它，后面的 claim routing 只能像当前实现一样手工拼，trace 也无法从 verifier 输入中移除。

### 如果目标是"proof size"

优先 **Ligerito evaluation 接口** 或 **CPU P3 替代/优化**。仅做 aux packing 不会有明显收益；CPU proof 占 90% 以上。

### 如果目标是"功能完整性"

优先 **D4 packed collision claim**（已有 `table_binding` + `PackedSharedPcs` 原型），但不要期待显著减小 total proof。

### 如果目标是"性能/大 trace"

优先 **shared-matrix SIMD CPU** 和 **chunked/parallel prover**；这两项主要改善 prover/verifier 工作量，不一定减小单 proof。

## 7. 一句话建议

> 若只能选一个方向，选 **Virtual Spartan + micro-PC/layout**：它是论文架构的"脊柱"，决定其余组件如何连接；Ligerito evaluation 是 proof size 的关键，但更偏独立研究/替换 PCS，适合作为并行第二轨。
