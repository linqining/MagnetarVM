# Magnetar 论文实现差距审计

审计对象：`papers/magnetar-2026-2423.pdf`（IACR ePrint 2026/2423）  
代码基线：`00818e8`（`feat/BinaryTwist`）  
状态说明：✅ 已实现；🟡 部分实现或采用了不同的等价/近似 instantiation；❌ 未实现。

## 一、结论摘要

当前仓库已经具备一条**可运行的参考证明链**：

- RV64I/M/A/C 执行、trace、约束 IR；
- 参考 Spartan（`F2_128` 上的通用 R1CS）；
- BinaryTwist RAM 参考归约（bit-sliced 虚拟地址、虚拟 `Val`/`Next`、紧凑 `Inc`）；
- BinaryShout ROM 读取（16/32-bit instruction）；
- BinaryRouter shift/sub-word store；
- P3 mosaic 多表 commitment 与 CPU+RAM+Shout+Router 共享 opening；
- chunked proof 的 aux claim 共享 opening；
- hash-chain / state-continuity 参考聚合器。

但距离论文的完整构造仍有**结构性差距**，最大的三项是：

1. **证明不是 trace-length succinct 的**：`UnifiedTraceProof` 仍携带全部 `rows`、`access.steps` 和 `rom`，verifier 会重建 trace；论文只发送一个 commitment 和若干 claims。
2. **没有 Dual SIMD R1CS / BinarySpartan / Virtual Spartan**：当前是单一 `F2_128` R1CS + 通用 Spartan，所有 witness 都进 `z` 并被提交；论文是两个 SIMD R1CS 共享 witness，BinarySpartan 打包 128 bit/field element，Virtual Spartan 输出 per-segment claims。
3. **没有完整的 MosaicPCS**：当前是 P3 多表/多点 opening，不是论文的 aligned-subcube packing `G` + lift + batch + ring switching + 单次 PCS evaluation。

## 进度记录

- `00818e8`：BinaryShout 支持 16/32-bit instruction。
- `4c36a8d`：BinaryRouter store 路由改为 `Inc`（old XOR new），与 BinaryTwist 的 committed `Inc` 对齐；offset-bit claims 与 `Q_st` 尚未实现。
- `d66da44`：新增 register BinaryTwist witness（`register_twist.rs`），用两相编码实现 p=2 reads + 1 write；standalone proof 已验证。
- `8665018`：把 register Twist 接入 `TraceAccessProof` 与 unified shared P3 opening。
- `443def7`：移除 register Merkle fields/steps；register Twist 成为唯一 register consistency proof。
- `6a37129`：BinaryShout 支持 `c=2` value columns（instruction word + instruction length）。
- `753b59e`：BinaryShout 扩展到 `c=7`（word、length、opcode、rd、rs1、rs2、imm）。
- `82541ba`：BinaryRouter 提交 3 个 offset bits，并用 sumcheck 与 public offset 链接。
- `2043741`：增加 4 个 one-hot width bits（`Q_st`）并与 public width 链接。
- `9b7adeb`：新增 `DualSimdR1cs`/`SimdR1cs` 边界与 128-bit binary witness packing（`constraint::simd`）。
- `6001e72`：BinaryShout 扩展到 `c=10`，加入 shift kind/shamt 与 store width selector columns。
- `b04fb23`：ROM 改为 public `Statement` 输入，三个 proof 结构移除 `rom` 字段；D13 完成。
- 本轮：BinaryShout metadata 改为来自 public `preprocess` bytecode table，扩到 `c=12`（micro-PC、is_halt）；D12 进入 🟡。

## 二、逐项差距

### A. 端到端协议与 succinctness

| # | 论文要求（§） | 当前实现 | 状态 | 剩余工作 |
|---|---|---|---|---|
| A1 | 协议只发送一个 commitment，所有 claims 由一个 PCS evaluation 证明（§5.5） | unified proof 中 CPU/RAM/Shout/Router 共享一个 P3 commitment/opening；但 chunked/per-row 仍有独立 P3 proof，register access 仍有 Merkle | 🟡 | 把 register、chunk、per-row 也并入同一 packed commitment；去掉额外 opening |
| A2 | 证明大小不随 trace 行数线性增长；verifier 不重建 trace（§2、§5.5） | `UnifiedTraceProof` 携带 `rows: Vec<TraceRow>`、`access.steps: Vec<TraceAccessStep>`、`rom`；`verify_unified_statement` 从 proof rows 重建 trace | ❌ | 这是最大差距：需要 committed trace/segment layout + Virtual Spartan claims，删除 rows/steps/rom 的传输 |
| A3 | verifier 只做 hash 和 binary-field 运算（§2.1） | P3/hash-based PCS，无 trusted setup；但 verifier 还重建约束系统/trace | 🟡 | 去掉 verifier 的 trace/系统重建；预计算 public layout |
| A4 | 透明、无 trusted setup、标准 hash、post-quantum（§1） | P3 binary-field PCS + SHA-256 transcript；默认路径无 trusted setup | ✅ | 保持；KZG 后端只是可选 |
| A5 | 一个 commitment 在 challenge 前发送（§5.5） | unified 路径满足；standalone Shout/Router/Chunked 仍各自 commit | 🟡 | 统一所有 proof 变体的 commit 顺序与 commitment 数量 |

### B. 证明系统

| # | 论文要求（§） | 当前实现 | 状态 | 剩余工作 |
|---|---|---|---|---|
| B1 | 两个 SIMD R1CS 关系共享一个 bit-valued witness：一个 over `F2`，一个 over `F2_128`（§5.1） | 新增 `constraint::simd::DualSimdR1cs` + `SimdR1cs` 边界（q 个 instance 共享同一 system、共享 witness 检查）；CPU 仍是单一 `ConstraintSystem`，尚未转成统一 SIMD 矩阵 | 🟡 | 设计两套矩阵 `A1/B1/C1`、`A2/B2/C2`；共享 witness；cross-step constraints；CPU 转换 |
| B2 | BinarySpartan：SIMD Spartan + binary witness packing（128 bits per field element）+ ring switching（§4.3） | `magnetar-proof` 的参考 Spartan；`constraint::simd::pack_binary`/`unpack_binary` 已实现 128-bit packing 与 round-trip 测试；BinarySpartan/ring switching 未实现 | 🟡 | 接入 SIMD reduction；实现 binary-witness evaluation claim、ring switching |
| B3 | Virtual Spartan：联合两个 SIMD 关系，lockstep outer sum-check，共享 inner sum-check，per-segment claims（§5.3） | 参考 Spartan 对整份 `z` 做一次 reduction；layout 有 `Virtual` 段但没有 claim router | ❌ | lockstep 两关系；per-segment `v_i`；对齐 subcube layout；claim 分发 |
| B4 | 两个 outer sum-check 共享 instance challenge，inner 只跑一次（§5.3） | 无 | ❌ | 与 B3 一起实现 |
| B5 | 直接段 claims 进 PCS；虚拟段 claims 分发给 Twist/Shout/Router（§5.3） | 所有段都在 `z` 中提交；没有虚拟段 claim 路由 | ❌ | 需要 segment layout + claim router |
| B6 | sum-check 优化：univariate skip、Frobenius one-hot check、degree reduction 等（§4.2–4.4） | 参考实现，逐轮朴素 sum-check | ❌ | 性能优化项；不影响语义 |
| B7 | 稀疏矩阵/结构矩阵 verifier 直接求值（§4.2 Remark） | 参考实现直接构造/使用矩阵 | 🟡 | 预计算 public matrices；避免 verifier 重建 |
| B8 | recursive-friendly verifier（§1、§6） | 只有 hash-chain/state-continuity 聚合器 | ❌ | 见 F 节 |

### C. CPU / ISA 约束

| # | 论文要求（§） | 当前实现 | 状态 | 剩余工作 |
|---|---|---|---|---|
| C1 | fetch-decode-execute，一个 micro-PC 对应 bytecode 表一行（§2、§5.5） | executor 支持 RV64I/M/A/C；preprocess 仍是“一 instruction = 一 micro-op” | 🟡 | bytecode table、instruction expansion、micro-PC |
| C2 | 每个 SIMD instance 覆盖若干连续 cycle，cross-step constraints 在 instance 内/间链接（§5.1） | 每行 relation 或 merged system；无 SIMD instance 概念 | ❌ | 与 B1/B3 一起实现 |
| C3 | PC linkage 在 proof 内检查（§5.5） | `check_trace_linkage` 在 verifier 重建 trace 后做；不在 R1CS 内 | ❌ | 把 PC/micro-PC 链放进 SIMD R1CS 或 Shout claim |
| C4 | reservation chain 在 proof 内检查（§5.1/§5.5） | trace 记录 reservation；verifier 检查；不在 R1CS 内 | ❌ | 加 reservation 约束/segment |
| C5 | 初始/最终 public state 绑定在 proof 内（§5.1） | `Statement` + trace digest 绑定；R1CS 不直接约束 initial/final | 🟡 | 在 R1CS 中绑定 initial/final rows |
| C6 | RV64I 核心（论文范围） | RV64I/M/A/C 已覆盖；F/D 只有 decoder | ✅/🟡 | F/D 是仓库扩展，不是论文 RV64I 核心；若要完整 RV64G 需补执行/proof |
| C7 | 任意 aligned sub-word load/store；跨 word 的 unaligned 访问 | executor 拒绝 unaligned；proof 支持 word 内所有对齐宽度 | 🟡 | 论文只要求 sub-word store 在 word 内；跨 word 是扩展 |
| C8 | 丰富 syscall/IO | `exit`/`hint`/`write`/`read`；基础 guest ABI | 🟡 | 更完整 runtime/syscall 是工程扩展 |

### D. Memory / bytecode / routing

| # | 论文要求（§） | 当前实现 | 状态 | 剩余工作 |
|---|---|---|---|---|
| D1 | BinaryTwist for RAM（p=1 read + 1 write） | `binary_twist.rs`：bit-sliced 虚拟地址、虚拟 `Val`/`Next`、紧凑 `Inc`、read/write/final/booleanity sum-check、P3 claims | ✅ | 语义已具备；性能/LT 见 D5 |
| D2 | BinaryTwist for registers（p=2 reads + 1 write） | `register_twist.rs` 把 rs1/rs2/rd 编码为两个 Twist 子 cycle；已接入 `TraceAccessProof` / unified shared P3 opening；register Merkle fields/steps 已移除，register Twist 是唯一 register consistency proof；不是论文的单周期 p=2 布局 | 🟡 | 把两相编码改成单周期 p=2（或明确说明等价编码） |
| D3 | 地址虚拟化：`d` 个 component polynomials，每个 `K^(1/d) × T`（§4.4） | bit-sliced：`a` 个地址 bit + valid，等价于 `d=a` 的 2-entry components | 🟡 | 若严格按论文，需支持任意 `d` 的 component packing；当前是合法特化但形式不同 |
| D4 | one-hot/collision polynomial，Frobenius 优化（§4.4） | 只做 booleanity；one-hot 由 bit 构造保证 | 🟡 | 论文的 collision sum-check 未实现；当前 bit-sliced 下不需要，但不是论文原样 |
| D5 | `LT` 线性时间处理（§4.4） | `LT` 物化 `T × T`，prover 二次；已记录 TODO | ❌ | 线性时间 `LT` 是研究项；当前不能扩展到大 T |
| D6 | `Inc` 紧凑表、`Val`/`Next` 虚拟 | 已实现 | ✅ | 保持 |
| D7 | BinaryShout for bytecode：公开表 `Val` 有 `c` 列，读地址 bits + 所有 value columns 一个 sum-check；bytecode 表含 micro-PC/decoded fields（§4.4、§5.5） | `binary_shout.rs`：16/32-bit ROM 读取，`c=12` columns（word、length、opcode、rd、rs1、rs2、imm、shift kind/shamt、store width、micro-PC、is_halt）；metadata 直接来自 public `preprocess` bytecode table；仍是一 instruction = 一 micro-op，无 expansion | 🟡 | instruction expansion/micro-PC 细化；把 selector columns 接到 Router 的 `Q` |
| D8 | Shout 的地址虚拟化/one-hot 检查 | bit-sliced 地址 + booleanity；valid 列 | 🟡 | 同 D3/D4；当前是 bit-sliced 特化 |
| D9 | BinaryRouter for shifts：`Y(o,j)=Σ X·Q·R`，`Q` 来自 bytecode 并由 Shout 认证；register-specified shift 展开为固定 virtual instructions（§5.4） | `binary_router.rs`：64-bit shift，按 public `ShiftRoute` 计算系数；`Q` 不存在，直接按 row 的 route 求值；register shamt 直接动态使用 | 🟡 | 引入 one-hot `Q`；由 Shout 认证 `Q`；register shift 展开；`X` 用 direct copy segment |
| D10 | BinaryRouter for stores：输出是 `Inc`（old XOR new），`R_st` 带 3 个 offset bits，`Q_st` 4 个 width selector（§5.4） | 路由 `Inc`；3 个 offset bits + 4 个 one-hot width bits 已提交，并分别通过 sumcheck 链接到 public offset/width；routing 仍用 public offset/width；未接 bytecode selector | 🟡 | 让 routing 直接使用 offset/width 的 MLE；接 bytecode width selector `Q_st` |
| D11 | 两个 BinaryRouter 实例（shift、store） | 一个通用 router claim 覆盖两类 route | 🟡 | 拆成两个实例，各自 claim/selector |
| D12 | bytecode 预处理：instruction expansion、public ROM/bytecode table（§2、§5.5） | public `preprocess` bytecode table 已存在并被 Shout 使用（含 selectors/micro-PC）；仍是一 instruction = 一 micro-op，没有 instruction expansion | 🟡 | 实现 expansion（尤其 register-shift 的固定 virtual instruction sequence）与多 micro-op 表 |
| D13 | ROM/bytecode 是 public input，不由 proof 携带 | `Statement` 现在携带 `rom`；`TraceProof`/`UnifiedTraceProof`/`ChunkedTraceProof` 已移除 `rom` 字段；verifier 从 statement 使用 ROM | ✅ | bytecode table/micro-PC 仍需按 D7/D12 完成 |

### E. PCS / MosaicPCS

| # | 论文要求（§） | 当前实现 | 状态 | 剩余工作 |
|---|---|---|---|---|
| E1 | 把所有 component 放到一个 packed polynomial `G` 的 aligned subcubes 上（§5.2） | P3 mosaic 多表 commitment；每表独立，不是单个 packed `G` | ❌ | 实现 aligned-subcube packing + `G` |
| E2 | claim lift：`G(r ‖ s_i) = p_i(r)`，verifier 追加 Boolean suffix（§5.2） | 无 | ❌ | 实现 suffix layout 与 lift |
| E3 | 多 claim batching 成一个 claim（§5.2） | P3SharedPcs 把多点 claim 放进一个 P3 opening；不是论文的 batching sum-check | 🟡 | 实现 batching sum-check 与统一 claim |
| E4 | ring switching 到 packed representation `P_G`（§5.2） | 无 | ❌ | 实现 ring switching |
| E5 | 单个 PCS evaluation argument（§5.5） | unified 一个 P3 opening；但 access register Merkle、chunked/per-row 另有 P3 | 🟡 | 全部 claim 进一个 packed commitment/opening |
| E6 | Ligerito/hash PCS 集成到 runtime（§6） | `ligerito` vendored backend 存在；runtime 默认用 P3 binary PCS | 🟡 | 把 Ligerito 接进 unified/chunked 路径并对比 |
| E7 | 多表/多点 opening API | P3 mosaic 支持 multi-table/multi-point、`next_columns` | ✅ | 可作为 MosaicPCS 的实现基础 |
| E8 | 证明大小随 trace 对数增长（§6.5） | `rows`/`steps` 线性；18 行 proof 270,713 B | ❌ | 与 A2 一起解决 |

### F. Recursion / ZK / 安全

| # | 论文要求（§） | 当前实现 | 状态 | 剩余工作 |
|---|---|---|---|---|
| F1 | chunk planning（§1、§6） | `ChunkPlan` + `ChunkedTraceProof` | ✅ | 保持 |
| F2 | 递归聚合（§1：efficient recursion） | hash-chain + state-continuity 参考聚合器；`ChunkedTraceProof` 用状态链 | 🟡 | 不是 zk proof aggregation；只是链式 digest |
| F3 | verifier-in-the-VM 递归证明（§1、§6） | 无 | ❌ | 用 BinarySpartan/bytecode 实现 verifier circuit；生成递归 proof |
| F4 | 低 rate 最终 proof / 递归链（§6） | 无 | ❌ | 需要完整递归与 PCS rate 控制 |
| F5 | ZK / private IO | `NoPrivacy` + hiding hash commitment；无 ZK sum-check | ❌ | **注意：论文核心是 transparent SNARK；ZK 是仓库扩展目标，不是论文正文必交项** |
| F6 | 安全审计、参数选择、soundness 分析 | 参考实现；无第三方审计 | ❌ | 审计、参数/安全级别文档 |
| F7 | 常数时间/侧信道 | 未处理 | ❌ | 生产化工作 |

### G. 性能 / 规模 / 评估

| # | 论文要求（§6） | 当前实现 | 状态 | 剩余工作 |
|---|---|---|---|---|
| G1 | 2^22–2^28 cycles、100 GiB 内存 | 参考实现 18 行 hello guest；未做长 trace | ❌ | 需要线性内存/流式证明、并行、优化 |
| G2 | 8–12 M cycles/s（Magnetar opt 9.5–12.8 M） | 当前 ~几十 cycles/s（18 行约 0.4 s） | ❌ | 数量级性能工程；不是算法补丁 |
| G3 | 15 个 workload（fibonacci、sha256、keccak、erc20 等） | 只有 hello guest/小型测试 | ❌ | 补 benchmark suite 与数据 |
| G4 | 与 ZisK/Lineth/Jolt 对比 | 无 | ❌ | 复现实验设置与对比 |
| G5 | optimized Magnetar（1.15–1.50×） | 无 | ❌ | 优化版本 |
| G6 | 内存/并行/多线程 | 单线程参考实现 | ❌ | 工程优化 |

## 三、按优先级排序

### P0：影响论文核心声明 / 正确性叙事

1. **A2 证明不 succinct**：proof 携带 rows/steps/rom，verifier 重建 trace。论文的“一个 commitment + claims”不成立。
2. **B1–B3 Dual SIMD / BinarySpartan / Virtual Spartan 缺失**：当前是“通用 Spartan + 全 witness 提交”，不是论文的 proof system。
3. **D2 register BinaryTwist 缺失**：register file 仍靠 Merkle，论文用 Twist p=2。
4. **E1–E4 MosaicPCS 缺失**：没有 packed `G`、lift、batch、ring switching；当前只是 P3 多表。
5. **D7/D9/D10 Shout/Router 不是论文形式**：Shout 没有 bytecode/decoded fields/多列；Router 没有 `Q`/Shout 链接、store 路由的是 new word 而非 `Inc`、没有 offset claims。
6. **C1/C3/C4 bytecode/micro-PC/PC/reservation 不在 proof 内**：仍是 trace-check。

### P1：论文组件的性能/形式补齐

7. **D5 `LT` 线性时间**：当前二次，无法扩展。
8. **D3/D4 one-hot/collision/Frobenius**：bit-sliced 是合法特化，但不是论文的 `d`-component 形式。
9. **B6 sum-check 优化**（univariate skip、degree reduction）。
10. **E6 Ligerito 集成**与 PCS 选型。

### P2：递归、ZK、工程化

11. **F3/F4 verifier-in-the-VM 递归**（论文声称 efficient recursion）。
12. **G1–G6 性能/规模/benchmark**（与论文实验差距最大，但属于工程实现）。
13. **F5 ZK/private IO**（若目标是严格 zkVM；论文正文是 transparent）。
14. **F6/F7 安全审计、侧信道**。

## 四、哪些不是论文核心缺口

- **RV64F/D 执行与 proof**：论文核心是 RV64I；仓库的解码器覆盖 F/D 子集，但这不是论文 RV64I 构造的必需项。
- **Unaligned 跨 word 访问**：论文的 sub-word store 限定在一个 64-bit RAM word 内；跨 word 是额外工程目标。
- **更丰富的 syscall/OS 运行时**：论文关注 ISA 执行证明，不规定完整 syscall 生态。
- **ZK / private IO**：论文是 transparent SNARK；如果产品目标叫“zkVM”且要求零知识，则另算扩展需求。

## 五、建议的下一阶段

1. **先做 A2**：把 trace rows/access steps 从 proof 中移除，改为 committed segments + per-segment claims；这是所有后续 succinctness 工作的前提。
2. **并行做 D2**：register BinaryTwist p=2，替换 Merkle access proof；可直接复用 RAM Twist 的地址/Inc/LT 代码。
3. **再做 B1–B3**：Dual SIMD R1CS + Virtual Spartan；这是论文 proof system 的核心，工作量最大。
4. **然后 E1–E4**：MosaicPCS packed `G` + lift + batch + ring switching；与 3 紧耦合。
5. **最后 D7/D9/D10**：把 bytecode table、`Q` selector、store `Inc` routing 接到 Shout/Router。
6. D5 线性 `LT` 作为独立研究项，不阻塞上述工程。
