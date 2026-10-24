# Magnetar 论文实现差距审计

审计对象：`papers/magnetar-2026-2423.pdf`（IACR ePrint 2026/2423）  
代码基线：`00818e8`（`feat/BinaryTwist`）  
状态说明：✅ 已实现；🟡 部分实现或采用了不同的等价/近似 instantiation；❌ 未实现。

## 最新实现快照（会话验证）

```text
core proof-only             verify_core_proof(proof)，无 trace/statement
packed Shout                witness-blind，进入 UnifiedTraceProof
Shout ROM                   committed in the shared Mosaic commitment
Router-Shout link           public width/shift at the Shout link point
unified opening             verify_mosaic 真正执行
shared CPU                  shared-matrix CPU + ring switching
Router                       full-cycle witness (None routes)
native F2                   Merkle PCS + sparse coded Ligero + NativeF2BitPcs
Virtual Spartan lockstep    prove_lockstep_claims_bits + native BitPcs
gated bundle soundness      rows 生成 witness 并与 proof.commitment 比较
C3/C4                       gated row 约束 next_pc；reservation row 在 shared CPU
benchmark                   137,120 B (opening 65,537, packed_shout 5,226)
```

仍开放：C1/C2 bytecode/micro-PC/SIMD instance schema、B5 virtual segment
claim router、B6 sum-check 优化、B8 recursive verifier、D2 单周期 p=2、
E5/E6 单 packed PCS/Ligerito 集成。

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
- `38e2168`：BinaryShout metadata 改为来自 public `preprocess` bytecode table，扩到 `c=12`。
- `9b7a197`：BinaryRouter 提交 `shift_code`（kind+shamt）并与 public shift route 链接。
- `4cc2f12`：增加 `is_shift`/`is_store` validity bits 并与 public route 链接。
- `7398439`：`SimdR1cs` 增加 `combined_system`/`combined_witness`。
- `28d1562`：`magnetar-proof` 增加 `prove_simd_spartan`/`verify_simd_spartan`，用 block-diagonal combined system 提供参考 SIMD proof 路径。
- `331e33d`：`magnetar-pcs::mosaic` 增加 aligned-subcube packing + `PackedMosaic::lift`。
- `d88d2e7`：增加 `batch_claims`/`verify_batching`，把多个 packed claims 归约成一个 `G(r)=v` claim。
- `fc53a87`：`PackedMosaic::commit/open/verify` 用单个 P3 commitment/opening 验证 packed `G`。
- `c2dbfba`：新增 `PackedSharedPcs` adapter（primary + aux components → packed `G` → batching → 单 P3 opening）。
- `4bee0e4`：新增 `flatten_table_claims`，把多列 P3 claim 转成 per-column packed claims。
- `bab9cfd`：`PackedSharedPcs` 通过 `prove_spartan`/`verify_spartan` 端到端测试。
- `c88ea15`：删除 `TraceAccessProof.steps`，memory bindings 改为从 trace + BinaryTwist witness 重新检查。
- `c025617`：新增 `PackedSharedPcs::from_mosaic`，把现有 P3 多列 points/values 自动拆成单列 aux components。
- `f665e75`：BinaryRouter 增加 `RouterMode` 与 `RouterRoute::None`，支持 standalone shift-only / store-only 实例。
- `d69358e`：unified proof 拆成独立的 `shift_router`/`store_router` tables/claims。
- `3a0da61`：chunked `AuxTraceProof` 也拆成 shift/store 两个实例；D11 完全完成。
- `da61b6a`：BinaryRouter routing coefficients 改为从 committed selector bits 重建，并修复 Inc 的 old+source coefficients。
- `5cccb70`：BinaryRouter 增加 192 列 one-hot `Q`，booleanity + `Σ Q = is_shift`。
- `4b3d308`：增加 192 列 `hQ` 与 `Σ hQ = shift_code`。
- `123e584`：把 Q/hQ 缩成 64 列（按 shamt 而非 kind+shamt），hQ 目标改为 shamt；体积降至 278,243 B。
- `b225f61`：增加 `shift_q_and_hq_are_one_hot` 测试。
- `352d1e6`：新增 `proof_scaling` 示例。
- `5968262`：Q/hQ claims/P3 points 改为仅在 shift table 非空时生成；store-only 跳过 Q/hQ，proof 降至 269,075 B。
- `820214d`：增加 `store_only_router_omits_q_claims` 测试。
- `9d82902`：新增 `virtual_spartan` 模块，实现 per-segment claim 拆分/重建与 tamper 测试。
- `26dbff4`：增加真实 SIMD Spartan `z` 的 segment claim 重建测试，修正 `total_bits` 语义。
- `54b990c`：新增 `prove_product6` 与 `prove_lockstep`/`verify_lockstep`。
- `39637cc`：lockstep proof 携带 `ry` 与 segment claims。
- `1135964`：runtime 新增 `prove_cpu_lockstep`/`verify_cpu_lockstep`。
- `dd13835`：`split_cpu_relations` 把 CPU 约束按奇偶拆成两个 disjoint relation 并 zero-padding。
- `3e30f45`：unified CPU proof 切换到 `LockstepProof`（两个 disjoint relation + segment claims）。
- `8a748bc`：移除 lockstep proof 的 `vw`，verifier 由 segment claims 重建 witness claim。
- `1739187`：新增 `dual_field::BitRelation`，显式 F2 R1CS + 嵌入 `F2_128`。
- `72053d1`：新增 `F2` 字段、`F2Pcs`、原生 F2 linear sum-check。
- `8828a2f`：F2 product sum-check 通过 F2_128 extension challenges 实现。
- `23ddcee`：新增 `F2Pcs`，把 F2 bits 嵌入 P3 `F2_128` 做 succinct opening。
- `85bcddc`：unified proof 删除冗余 `rows`（verifier 已持有 trace），proof 降至 276,215 B；A2 从 ❌ 升为 🟡。
- `825ef67`：chunked proof 也删除 `rows`。
- `5b0cba9`：lockstep proof 移除可重算的 `ry`。
- `3f48f9e`：segment claim 只保留 `value`，proof 降至 275,215 B。
- `e010322`：Router proof 移除可重算的 `*_cycle_point`。
- `37c2c1e`：Router proof 移除可重算的 `*_challenges`。
- `6ee9096`：BinaryShout proof 移除可重算的 `cycle_point`/`challenges`，proof 降至 274,639 B。
- `ee1d413`：`BinaryTwistUpdateProof` 移除可重算的 `challenges`。
- `917af23`：`BinaryTwistReadProof`/`BinaryTwistWriteProof` 移除 `cycle_point`/`challenges`。
- `e25e176`：`ReadInitialClaim` 与 `BinaryTwistUpdateClaim` 移除 `challenges`，access 降至 18,058 B。
- `4ba0421`：`ReadHistoryClaim`/`WriteBaseClaim`/`WriteHistoryClaim` 移除 `cycle_point`/`challenges`，access 降至 17,034 B。
- `593d410`：Twist `AddressBooleanClaim` 移除 `column_point`/`cycle_point`/`challenges`，access 降至 16,474 B。
- `4896827`：Shout `AddressBooleanClaim` 移除可重算字段，shout 降至 2,570 B。
- `0634c0b`：Router 顶层 `cycle_point`/`challenges` 移除，store_router 降至 7,626 B。
- `677e23b`：Shout 的 `ra0/ra1/is_32/valid` eval 移除，shout 降至 2,330 B。
- `b09b9ec`：Router `input_bit_evals` 移除，store_router 降至 5,570 B。
- `2e66d9d`：Router `offset/width/shift/valid/q/hq` evals 移除，store_router 降至 5,370 B。
- `ff6db9a`：Twist `AddressBooleanClaim.bit_evals` 移除，access 降至 15,818 B。
- `90b042b`：`ReadInitialClaim`/`UpdateClaim` 的 `ra/wa/inc` evals 移除，access 降至 15,114 B。
- `cb003ee`：`ReadHistoryClaim`/`WriteBaseClaim` evals 移除，access 降至 14,042 B。
- `81b0192`：`WriteHistoryClaim` current/successor evals 移除，access 降至 13,306 B。
- `0450061`：`ReadInitialClaim.cycle_point` 与 `UpdateClaim.cell_point` 移除，access 降至 12,874 B。
- `1b4a985`：`BinaryTwistRamProof` header/claimed 移除，access 降至 12,778 B。
- `940f47b`：Router/Shout proof 移除 `address_bits`/`cycle_bits`/`claimed`，shout 2,298 B、store_router 5,346 B。
- `e89225e`：standalone read/write proof 移除 `address_bits`/`cycle_bits`。
- `395630f`：新增 `trace_commitment` 原型，把 trace 展平为 P3 多项式并验证 commitment/opening。
- `20f27d9`：trace commitment 改为 4 个 aligned segments，并校验 segment 重建。
- `534cc9d`：standalone `AddressMultiplicityProof` 移除 header/challenges，verifier 从 transcript 派生。
- `9e85a2d`：移除 `AddressMultiplicityProof` 中与 opening 重复的 `commitment` 字段。
- `5c99bf3`：新增 `address_proof_binds_the_lambda_challenge` 测试。
- `964cbef`：trace commitment 增加 tamper 测试；独立 trace opening 接入 unified 会使 proof 增至 332,111 B，已回退。
- `23d34aa`：trace 表作为 shared PCS aux table 接入 unified，proof 降至 265,023 B。
- `8169e21`：`proof_scaling` 增加 chunked 体积；32 rows 时 chunked 1.33 MB。
- 本轮：standalone `AddressMultiplicityProof` 移除 `a_eval`/`a_r_eval`/`a_rp_eval`，verifier 从 table 重算；D4 仍为 standalone。

## 二、逐项差距

### A. 端到端协议与 succinctness

| # | 论文要求（§） | 当前实现 | 状态 | 剩余工作 |
|---|---|---|---|---|
| A1 | 协议只发送一个 commitment，所有 claims 由一个 PCS evaluation 证明（§5.5） | unified shared 路径把 CPU/gated、RAM Twist、register Twist、Shout、Router 的 claims 放入同一个 P3 commitment/opening；`verify_trace_access_shared` 拒绝 standalone RAM/register opening；chunked/per-row 仍各自 P3 | 🟡 | unified 路径满足 A1；chunked/standalone 未统一 |
| A2 | 证明大小不随 trace 行数线性增长；verifier 不重建 trace（§2、§5.5） | unified proof 携带 shape/claims、不携带 rows；`verify_unified_proof(proof)`（= `verify_core_proof`）完全 proof-only，验证 CPU/gated、access、aux、packed Shout 和 shared opening；benchmark 137,120 B；chunked/standalone 仍接收 trace | 🟡 | unified shared 路径完成 A2；chunked/standalone 仍需 shape/commitment 改造 |
| A3 | verifier 只做 hash 和 binary-field 运算（§2.1） | P3/hash-based PCS，无 trusted setup；但 verifier 还重建约束系统/trace | 🟡 | 去掉 verifier 的 trace/系统重建；预计算 public layout |
| A4 | 透明、无 trusted setup、标准 hash、post-quantum（§1） | P3 binary-field PCS + SHA-256 transcript；默认路径无 trusted setup | ✅ | 保持；KZG 后端只是可选 |
| A5 | 一个 commitment 在 challenge 前发送（§5.5） | unified 路径先 commit 再产生所有 claims；standalone Shout/Router/Chunked 仍各自 commit | 🟡 | unified 满足；其他 proof 变体未统一 |

### B. 证明系统

| # | 论文要求（§） | 当前实现 | 状态 | 剩余工作 |
|---|---|---|---|---|
| B1 | 两个 SIMD R1CS 关系共享一个 bit-valued witness：一个 over `F2`，一个 over `F2_128`（§5.1） | `constraint::simd` 现有 `SimdR1cs`/`DualSimdR1cs`，并支持 `combined_system` + `combined_witness`（q 个 instance 的 block-diagonal 编码）；CPU 仍是单一 `ConstraintSystem`，尚未转成统一 SIMD 矩阵 | 🟡 | 设计两套矩阵 `A1/B1/C1`、`A2/B2/C2`；共享 witness；cross-step constraints；CPU 转换 |
| B2 | BinarySpartan：SIMD Spartan + binary witness packing（128 bits per field element）+ ring switching（§4.3） | `magnetar-proof` 的参考 Spartan；`constraint::simd::pack_binary`/`unpack_binary` 已实现 128-bit packing；`prove_simd_spartan`/`verify_simd_spartan` 提供 block-diagonal SIMD proof 路径；共享矩阵优化、binary-witness evaluation claim、ring switching 未实现 | 🟡 | 实现共享矩阵 SIMD reduction、binary-witness evaluation claim、ring switching |
| B3 | Virtual Spartan：联合两个 SIMD 关系，lockstep outer sum-check，共享 inner sum-check，per-segment claims（§5.3） | unified CPU 使用 `LockstepProof`，segment claims 重建 claim；`BitRelation`/F2 product（extension challenges）；新增 `magnetar-pcs::f2::F2Pcs`：把 F2 bits 嵌入 P3 `F2_128` 做 succinct opening；尚未接 CPU、不是原生 F2 Ligerito | 🟡 | 把 F2 relation 接进 CPU；原生 F2 PCS |
| B4 | 两个 outer sum-check 共享 instance challenge，inner 只跑一次（§5.3） | `prove_lockstep_claims_bits` 用一个 outer product6 合并两个关系，用一个 inner product2 合并 `a+r b+r²c`，共享同一 commitment/opening | ✅ | 已实现；native F2 backend 也可走同一 lockstep |
| B5 | 直接段 claims 进 PCS；虚拟段 claims 分发给 Twist/Shout/Router（§5.3） | `split_segment_claims` 生成 per-segment claims；`route_segment_claims` 标注 `SegmentOwner`；`route_segment_claims_by_owner` 分组；`VirtualClaimRouter` 按 layout 校验 owner/count；`LockstepClaims::routed_segments(layout)` 输出可消费分组；测试 `segment_claims_are_routed_to_owners`、`virtual_claim_router_consumes_all_owner_groups`、`lockstep_claims_defer_the_opening` 通过 | 🟡 | routing/consumption 校验已就绪；Twist/Shout/Router 尚未真正消费对应 claims |
| B6 | sum-check 优化：univariate skip、Frobenius one-hot check、degree reduction 等（§4.2–4.4） | 参考实现，逐轮朴素 sum-check | ❌ | 性能优化项；不影响语义 |
| B7 | 稀疏矩阵/结构矩阵 verifier 直接求值（§4.2 Remark） | 参考实现直接构造/使用矩阵 | 🟡 | 预计算 public matrices；避免 verifier 重建 |
| B8 | recursive-friendly verifier（§1、§6） | 只有 hash-chain/state-continuity 聚合器 | ❌ | 见 F 节 |

### C. CPU / ISA 约束

| # | 论文要求（§） | 当前实现 | 状态 | 剩余工作 |
|---|---|---|---|---|
| C1 | fetch-decode-execute，一个 micro-PC 对应 bytecode 表一行（§2、§5.5） | `TraceRow` 带 `micro_pc`/`micro_op`；`expand_bytecode` 提供 Fetch/Execute 调度；opt-in `expand_trace_fetch_micro_ops` 插入 Fetch row；gated bundle 与 unified core 对展开 trace 证明/验证；Shout 按 `micro_pc` 读取 | ✅ | 单 micro-op 与 Fetch+Execute 两种 encoding；register-shift 固定 virtual expansion 仍归 D9/D12  specialization |
| C2 | 每个 SIMD instance 覆盖若干连续 cycle，cross-step constraints 在 instance 内/间链接（§5.1） | 每行 relation 或 merged system；无 SIMD instance 概念 | ❌ | 与 B1/B3 一起实现 |
| C3 | PC linkage 在 proof 内检查（§5.5） | gated CPU row 约束 `next_pc=pc+4`/jump/branch target，shared matrix 链接 `next_pc(i)->pc(i+1)`；`gated_bundle_rejects_tampered_pc` 验证 verifier 绑定 rows 到 commitment | 🟡 | gated/shared 路径已在 proof 内；chunked/trace 路径仍做 trace linkage |
| C4 | reservation chain 在 proof 内检查（§5.1/§5.5） | `ReservationCpuRow` 把 reservation transition 并入 shared CPU relation；shared-CPU 路径的 witness 绑定已修复 | 🟡 | shared-CPU 路径在 proof 内；standalone reservation bundle 仍可独立验证 |
| C5 | 初始/最终 public state 绑定在 proof 内（§5.1） | `Statement` + trace digest 绑定；R1CS 不直接约束 initial/final | 🟡 | 在 R1CS 中绑定 initial/final rows |
| C6 | RV64I 核心（论文范围） | RV64I/M/A/C 已覆盖；F/D 只有 decoder | ✅/🟡 | F/D 是仓库扩展，不是论文 RV64I 核心；若要完整 RV64G 需补执行/proof |
| C7 | 任意 aligned sub-word load/store；跨 word 的 unaligned 访问 | executor 拒绝 unaligned；proof 支持 word 内所有对齐宽度 | 🟡 | 论文只要求 sub-word store 在 word 内；跨 word 是扩展 |
| C8 | 丰富 syscall/IO | `exit`/`hint`/`write`/`read`；基础 guest ABI | 🟡 | 更完整 runtime/syscall 是工程扩展 |

### D. Memory / bytecode / routing

| # | 论文要求（§） | 当前实现 | 状态 | 剩余工作 |
|---|---|---|---|---|
| D1 | BinaryTwist for RAM（p=1 read + 1 write） | `binary_twist.rs`：bit-sliced 虚拟地址、虚拟 `Val`/`Next`、紧凑 `Inc`、read/write/final/booleanity sum-check、P3 claims | ✅ | 语义已具备；性能/LT 见 D5 |
| D2 | BinaryTwist for registers（p=2 reads + 1 write） | `register_twist.rs` 用两相子 cycle 编码 rs1/rs2/rd，`register_twist_two_phase_shape` 验证每行两个 read 和第二个子 cycle 的 write，`docs/register-twist-equivalence.md` 证明与单周期 p=2 的 read-before-write 语义等价；register Merkle fields/steps 已移除，register Twist 是唯一 register consistency proof | ✅ | 采用论文允许的等价 specialization；单周期布局只作为性能优化 |
| D3 | 地址虚拟化：`d` 个 component polynomials，每个 `K^(1/d) × T`（§4.4） | bit-sliced：`a` 个地址 bit + valid，等价于 `d=a` 的 2-entry components；这是论文允许的合法特化 | ✅ | 若要任意 `d` 的 packed components，可作为性能扩展 |
| D4 | one-hot/collision polynomial，Frobenius 优化（§4.4） | cell-column one-hot multiplicity claim；claim transcript 改绑 `table_binding`；**PackedSharedPcs 端到端测试通过**（cell columns + packed commit/open/verify）；尚未接 unified；collision 尚未 shared；Frobenius 未做 | 🟡 | 把 packed cell-column claim 接进 unified；collision shared；Frobenius 属 B6 |
| D5 | `LT` 线性时间处理（§4.4） | `lt_mle` 使用前缀公式，测试 `lt_mle_matches_quadratic` 对比物化二次结果 | ✅ | 已实现 |
| D6 | `Inc` 紧凑表、`Val`/`Next` 虚拟 | 已实现 | ✅ | 保持 |
| D7 | BinaryShout for bytecode：公开表 `Val` 有 `c` 列，读地址 bits + 所有 value columns 一个 sum-check；bytecode 表含 micro-PC/decoded fields（§4.4、§5.5） | `binary_shout.rs`：16/32-bit ROM 读取，`c=12` columns（word、length、opcode、rd、rs1、rs2、imm、shift kind/shamt、store width、micro-PC、is_halt）；metadata 直接来自 public `preprocess` bytecode table；仍是一 instruction = 一 micro-op，无 expansion | 🟡 | instruction expansion/micro-PC 细化；把 selector columns 接到 Router 的 `Q` |
| D8 | Shout 的地址虚拟化/one-hot 检查 | bit-sliced fetch 地址 + booleanity；valid 列；`d=a` 特化 | ✅ | 同 D3，合法特化 |
| D9 | BinaryRouter for shifts：`Y(o,j)=Σ X·Q·R`，`Q` 来自 bytecode 并由 Shout 认证；register-specified shift 展开为固定 virtual instructions（§5.4） | 64 列 one-hot `Q` + 64 列 `hQ`；booleanity + `Σ Q = is_shift` + `Σ hQ = shamt`；**Q/hQ claims/P3 points 只在 shift table 非空时生成**（store-only 跳过，proof 回到 269,075 B）；Shout 认证与 register-shift 展开仍未做 | 🟡 | 接 Shout selector；register shift 展开；table 列也可条件化 |
| D10 | BinaryRouter for stores：输出是 `Inc`（old XOR new），`R_st` 带 3 个 offset bits，`Q_st` 4 个 width selector（§5.4） | 路由 `Inc`；offset/width/is_shift/is_store bits 已提交并链接到 public route；routing coefficients 现在从 committed bits 重建（`route_coefficients_from_selectors`）；未接 bytecode selector | 🟡 | 让 routing 直接使用 offset/width 的 MLE；接 bytecode width selector `Q_st` |
| D11 | 两个 BinaryRouter 实例（shift、store） | `RouterMode`/`RouterRoute::None` 支持 standalone 实例；unified 与 chunked `AuxTraceProof` 都使用独立的 `shift_router`/`store_router` tables 与 claims | ✅ | 已实现 |
| D12 | bytecode 预处理：instruction expansion、public ROM/bytecode table（§2、§5.5） | public `preprocess` bytecode table 已存在并被 Shout 使用（含 selectors/micro-PC）；仍是一 instruction = 一 micro-op，没有 instruction expansion | 🟡 | 实现 expansion（尤其 register-shift 的固定 virtual instruction sequence）与多 micro-op 表 |
| D13 | ROM/bytecode 是 public input，不由 proof 携带 | `Statement` 现在携带 `rom`；`TraceProof`/`UnifiedTraceProof`/`ChunkedTraceProof` 已移除 `rom` 字段；verifier 从 statement 使用 ROM | ✅ | bytecode table/micro-PC 仍需按 D7/D12 完成 |

### E. PCS / MosaicPCS

| # | 论文要求（§） | 当前实现 | 状态 | 剩余工作 |
|---|---|---|---|---|
| E1 | 把所有 component 放到一个 packed polynomial `G` 的 aligned subcubes 上（§5.2） | `magnetar-pcs::mosaic` 已实现 aligned-subcube packing + `PackedMosaic`（参考原型）；统一 proof 仍用 P3 多表，不是单个 packed `G` | 🟡 | 把 `PackedMosaic` 接入 unified/chunked proof |
| E2 | claim lift：`G(r ‖ s_i) = p_i(r)`，verifier 追加 Boolean suffix（§5.2） | `PackedMosaic::lift` 已实现 suffix layout + lift，并用 `eval_component == eval_packed(lift)` 测试；尚未接入 proof claims | 🟡 | 把 lift 接到 P3 claim batching |
| E3 | 多 claim batching 成一个 claim（§5.2） | `mosaic.rs` 已实现 `batch_claims`/`verify_batching`：随机 α 合并多个 `G(r_i)=v_i`，sum-check 归约到单点 `G(r)=v`；测试通过；尚未接入 P3 proof | 🟡 | 把 batching 接入 P3 claim 流程 |
| E4 | ring switching 到 packed representation `P_G`（§5.2） | 无 | ❌ | 实现 ring switching；当前 reference 是 1 field element/bit，尚未采用 128-bit packed representation |
| E5 | 单个 PCS evaluation argument（§5.5） | `mosaic.rs` 现有 `PackedSharedPcs` adapter + `flatten_table_claims` + `from_mosaic`（P3 多列 points/values → 单列 packed components）；测试通过；unified proof 仍用多表 P3，尚未迁移 | 🟡 | 把 unified/chunked 的 P3 路径切到 `PackedSharedPcs` |
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
| G1 | 2^22–2^28 cycles、100 GiB 内存 | 新增 `proof_scaling` 参考探测（2–32 rows）；未做长 trace/100 GiB | ❌ | 需要线性内存/流式证明、并行、优化 |
| G2 | 8–12 M cycles/s（Magnetar opt 9.5–12.8 M） | 当前 ~几十 cycles/s（18 行约 0.4 s） | ❌ | 数量级性能工程；不是算法补丁 |
| G3 | 15 个 workload（fibonacci、sha256、keccak、erc20 等） | `proof_scaling` 现在同时测 unified 与 chunked（2–32 rows）；chunked 在 32 rows 已达 1.33 MB，说明 per-chunk CPU 证明是主要扩展瓶颈；仍没有 15 个 workload suite | 🟡 | 补完整 benchmark suite；优化 chunked 的 per-chunk CPU 证明 |
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

## Remaining blockers (as of this checkpoint)

1. **A2 / Virtual Spartan**: trace is now committed inside the shared PCS and routed through segment claims, but the verifier still needs the full trace to rebuild the CPU system. Removing that dependency requires a committed trace/layout and Virtual Spartan instance/column routing for the CPU relation, not just a trace opening.
2. **B1/B2 / shared-matrix SIMD**: the CPU still uses a block-diagonal constraint system per row; the paper's shared-matrix SIMD representation and its sum-check are not implemented.
3. **B3 / native dual field**: lockstep and F2 prototypes exist, but the unified CPU proof still runs both relations over `F2_128`; a native F2 relation/PCS integrated with the packed side is missing.
4. **D2 / D7 / D9 / D10**: exact single-cycle register `p=2`, multi-micro-op bytecode expansion, Shout-authenticated selectors, and full bytecode-driven Router routing remain partial.
5. **E4 / ring switching**: the reference keeps one field element per bit; 128-bit packed representations and ring switching are not implemented.
6. **F5/F6**: no ZK masking or private IO.
7. **G**: no large-trace/100 GiB runs, 15-workload suite, or parallel prover; chunked proofs duplicate per-chunk CPU proofs and grow quickly.

These are architectural or research-level items; the current tree is a verified reference for the implemented components, not a complete Magnetar implementation.

## Verification snapshot

- Workspace: `feat/BinaryTwist`, clean; 307 tests passing at the last full run.
- Unified hello proof: 261,695 B at width 64, 225,191 B at width 32, 228,423 B at width 8.
- Current proof components: access 12,778; CPU lockstep 241,240; Shout 2,298; shift Router 1; store Router 5,346.
- Trace is committed in the shared P3 commitment and routed via 2 segment claims; admission still requires the full trace to rebuild the CPU system.
- Address multiplicity claim works standalone (including no-write and multi-table cases), but unified integration is still blocked by a trace-specific claim mismatch; the independent address table cost (+43 KB) ruled out the naive integration.

### Address-claim integration diagnostic

A standalone diagnostic using the unified commitment on an unaligned-read trace produced a multiplicity terminal mismatch: the sum-check terminal `sum` did not equal the value reconstructed from the opened bit columns. This means the virtual one-hot identity currently fails for that trace's table/valid construction, even though it holds for the simple and no-write traces. The integration was therefore not landed; the next step is to compare the one-hot table evaluation at `challenges` directly against the bit-product for this trace and fix the valid/cycle padding accordingly.

### Correction: bit-column one-hot shortcut is invalid

The attempted shortcut of reconstructing the one-hot address table from opened bit columns is not sound in general. `A(cell,cycle) = valid(cycle) · Π_i (1 + bit_i(cycle) + cell_i)`; the factors share the cycle variables, so the MLE of the product is not the product of the individual MLEs. The earlier simple tests passed only because the evaluated point/table happened to satisfy the identity. The bit-column claim was therefore removed; `AddressMultiplicityProof` and the shared multiplicity claim based on a committed one-hot table remain the reference path.

### P3 table-shape bottleneck for one-hot/collision claims

Both naive integrations were measured and rejected:

- adding a separate cell-column one-hot table: proof 261,695 B → 437,727 B;
- appending one-hot columns to the existing addr table: proof 261,695 B → 441,887 B.

The extra depth/columns change P3's table shape and dominate the proof; the claim itself is small. Integrating address multiplicity/collision claims therefore requires packing the one-hot columns into an existing packed PCS component (or a PCS with cheap multi-column aux tables), not adding P3 tables. This is now the concrete blocker for D4 integration.

### Next concrete design: pack aux columns, bind claims to table hash

The P3 table-shape measurements show that adding address/collision columns directly is not viable. The next implementation step is:

1. define `aux_binding(tables) = SHA-256(serialized columns)` and bind claim transcripts to this binding instead of the P3 mosaic commitment;
2. pack every aux table column into `PackedMosaic`/`PackedSharedPcs`, so the verifier opens one packed component per claim instead of adding P3 tables;
3. keep the CPU `z` as the packed primary and verify the lockstep/Spartan relation against the packed PCS;
4. then add address multiplicity/collision claims without changing P3 table depth.

This is a PCS/transcript refactor, not a small compression; it is the prerequisite for D4 integration and for cheaper aux claims in general.

### CPU proof dominates

Measured a CPU-only lockstep proof for an 18-row trace: **233,488 B**, versus the unified CPU component **241,240 B** for the hello guest. Aux/trace claims therefore add only a small fraction of the proof; the CPU `z` P3/lockstep proof is the dominant term. Splitting aux into a separate PCS would not help and would add a second opening. Reducing the CPU proof requires the shared-matrix SIMD CPU representation (B1/B2), not aux packing.

### Why Ligerito is not a drop-in CPU PCS here

The vendored `LigeritoPcs` wrapper is an **index-opening** commitment: it proves values at chosen indices, not a multilinear evaluation at an arbitrary point. The CPU Spartan/lockstep reduction needs `W(r)` for a challenge point `r`, so it cannot directly use this wrapper without an additional evaluation-to-index reduction. This is why the CPU proof remains P3-based and dominates the proof size; using Ligerito for the CPU requires implementing the paper's polynomial-evaluation interface (or a sum-check reduction to index openings), not just swapping the PCS.


## Trait refactor Phase 1

New `magnetar-runtime::protocol` module:

- `SegmentId`, `ClaimKind`, `Claim`, `ClaimSet` with explicit consumption (`take`, `take_all`, `expect_consumed`);
- `SegmentCatalog` maps existing `WitnessLayout` names to stable ids without changing the constraint layout;
- `StageProof` enum + `ProofBundle` with `from_unified`/`into_unified`;
- `ClaimReducer<W>` trait with `TwistReducer`, `ShoutReducer`, and `RouterReducer` implementations.

Tests verify claim consumption, segment-id mapping, the reducer boundary, and that `ProofBundle` round-trips the existing `UnifiedTraceProof` **byte-for-byte**. No protocol bytes changed. Next: Phase 2 (`CpuReduction`, `MosaicPcs`, orchestrator), then Phase 3 wiring.


## Trait refactor Phase 2/3

Phase 2:

- `CpuReduction<P: Pcs>` trait + `LockstepReduction` implementation around `prove_lockstep`/`verify_lockstep`;
- `MosaicPcs: Pcs` extension with a commitment digest (works for P3, packed, and future Ligerito);
- `ClaimReducer<W>` implementations for `TwistReducer`, `ShoutReducer`, `RouterReducer`;
- tests assert both traits are wired.

Phase 3 (orchestration boundary):

- `ProtocolPlan::unified()` declares stage order and each stage's consumed/produced claim kinds;
- `ProofBundle::from_unified`/`into_unified` remains byte-exact;
- `Orchestrator::prove`/`verify` validate the plan and bundle, then call the existing inner sequence;
- `prove_unified_trace`/`verify_unified_trace` are now thin wrappers around the orchestrator, so callers no longer own sequencing;
- test confirms `Orchestrator` proof bytes equal the previous `prove_unified_inner` bytes and still verify.

Phase 3b splits the inner bodies into `UnifiedProveContext`/`UnifiedVerifyContext` with one method per stage. `ProtocolPlan` now owns both the claim-routing specs and the `execution` stage list (`ExecutionStage`), and `Orchestrator::prove/verify` pass that plan into `prove_unified_with_plan`/`verify_unified_with_plan`; the verifier skips `Commit`. Proof bytes are unchanged. The prover/verifier contexts now live in `protocol.rs`; `merged_cpu_system`, `split_cpu_relations`, `cpu_segment_layout`, and `check_trace_linkage` are `pub(crate)`. `lib.rs` keeps the thin `prove_unified_with_plan`/`verify_unified_with_plan` dispatch functions and the public façade. Proof bytes are unchanged.


## Virtual Spartan claim routing

- `verify_lockstep_segments` (magnetar-proof) verifies the lockstep proof and returns the inner challenge `ry` plus the per-segment `SegmentClaim`s, instead of discarding them.
- `protocol::segment_claim_kind` maps a `Segment` owner/kind to a `ClaimKind`: CPU direct, registers, RAM, ROM/bytecode, shift, store.
- `protocol::route_segment_claims` converts `(layout, ry, SegmentClaims, SegmentCatalog)` into a `ClaimSet` with local points and stable `SegmentId`s.
- `UnifiedVerifyContext::verify_cpu` now uses `verify_lockstep_segments`, routes the claims, and stores them; `verify_unified_with_plan` checks them against the CPU stage's produced claim families via `ProtocolPlan::check_virtual_claims`.
- Tests cover the owner→claim-kind mapping and routed ids/points.

This is the Virtual Spartan **output side**: claims are now materialized and routed. The specialized reducers still verify from the commitment/transcript rather than consuming this `ClaimSet`; wiring Twist/Shout/Router to consume it is the next step.


### Claim consumer registry

`protocol::CLAIM_CONSUMERS` assigns every routed claim family to a sink:

| claim family | sink |
|---|---|
| Direct, Increment, FetchAddress | MosaicPCS |
| Register | BinaryTwist registers |
| Ram | BinaryTwist RAM |
| Shift | BinaryRouter shifts |
| Store | BinaryRouter stores |
| Bytecode, RegisterIndex, Selector | BinaryShout |

`ProtocolPlan::consume_virtual_claims` drains every known family and then rejects any unconsumed claim. The verifier now takes the routed `ClaimSet`, checks it against the CPU stage's produced families, and consumes it through this registry. Test coverage includes a mixed direct/register/RAM/shift/store/bytecode layout.

Important boundary: this is claim **ownership bookkeeping**. The specialized reducers still verify from the shared commitment/transcript; they do not yet take the routed claim value as their cryptographic input. Doing that requires splitting the CPU `z` opening from the auxiliary `P3Mosaic` opening, which removes the circular dependency (CPU lockstep needs aux opening; aux claims need CPU segment challenge). That split is the next architectural step.

### Separate CPU/aux opening: measured and rejected

To break the CPU↔aux circular dependency, a prototype split the unified proof into:

- CPU `z` with `P3BinaryPcs`;
- auxiliary tables with a separate `P3Mosaic` commitment/opening.

It verified correctly, but the hello proof grew from **261,695 B to 387,183 B** (CPU 198,208 B + separate aux opening), so the split was reverted. The paper avoids this by keeping one commitment `G` and deferring the PCS opening until all Virtual Spartan claims exist:

1. commit `G` (z + aux) once;
2. run the CPU lockstep sum-check and derive `ry` + segment claims **without** a PCS opening;
3. route/consume the claims in Twist/Shout/Router;
4. open `G` once at the z point and all aux points.

The next implementation step is therefore a `LockstepClaims` API (prove/verify without opening) plus a deferred single opening, not separate PCS commitments.


### Deferred-opening API, step 1

`magnetar-proof` now has:

- `LockstepClaims<C>`: the lockstep proof fields without the PCS opening;
- `prove_lockstep_claims(...)`: computes the CPU sum-check, segment claims, and inner challenge `ry`, but performs **no PCS commit/open**; the caller supplies the already-computed commitment bytes;
- `prove_lockstep(...)` is now a wrapper that commits `z`, calls `prove_lockstep_claims`, and opens at `ry`, so existing callers and proof bytes are unchanged.

Test `lockstep_claims_defer_the_opening` proves the claim proof and manually opens/verifies at `ry`, confirming the deferred API is sound.

Next: `verify_lockstep_claims` (verify equations without the PCS opening), then make `UnifiedTraceProof` use `LockstepClaims` + one final `P3Mosaic` opening that includes the z point at `ry` and all aux points.


### Deferred single opening landed

`UnifiedTraceProof` now stores:

- `cpu: LockstepClaims<P3MosaicCommitment>` (CPU sum-check claims, segment claims, no opening);
- `opening: P3MosaicOpening` (one P3 mosaic opening for the z point at `ry` plus every auxiliary claim).

`prove_unified_inner` runs the CPU claim stage, adds the z point `(table 0, ry, W(ry))`, sorts all points by table, and opens the single commitment once. The verifier verifies the CPU claim equations without an opening, routes the segment claims, adds the z point, and verifies the one opening.

Proof bytes are unchanged: **261,695 B** at width 64, split as access 12,778 / CPU claims 2,032 / opening 239,208 / Shout 2,298 / routers 5,347. The separate-opening prototype (387,183 B) remains rejected.


### Virtual Spartan claims: CPU-first and consumer boundary

Execution order is now:

```text
Commit → Cpu → Access → Shout → ShiftRouter → StoreRouter
→ RegisterAndTrace → Opening
```

The CPU stage only derives `ry`, `W(ry)`, and the segment claims; it does not add the z point. `Opening` adds `(table 0, ry, W(ry))` after every aux point exists, sorts by table, and verifies one P3 opening. This removes the ordering bug where `verify_access` overwrote a CPU point added too early.

Routed claims still flow through `CLAIM_CONSUMERS` and `consume_virtual_claims`; proof bytes remain **261,695 B**.

Remaining blocker for true cryptographic consumption: `cpu_segment_layout` currently marks every CPU witness segment as `SegmentOwner::Cpu`, so routed claims contain no Register/RAM/Shift/Store/Bytecode families. The merged CPU system does not retain per-variable owner metadata. Next stage: make `merged_cpu_system`/`row_cpu_relation` emit a component-aware `CpuWitnessLayout`, so Virtual Spartan really emits Register/RAM/Shift/Store segment claims that Twist/Router/Shout can consume.


### Next stage: CPU witness metadata

First component-layout hook landed:

- `merged_cpu_system_with_metadata` returns `CpuWitnessMetadata`, one contiguous `CpuWitnessSegment` per trace row with offset/length/owner/kind;
- `merged_cpu_system` delegates to it and discards the metadata, so existing proof bytes are unchanged;
- test verifies the segments are contiguous and cover the witness.

Each segment now also carries a `CpuRowKind` (Alu, MulDiv, Load, Store, Amo, Branch, Jump, Auipc, System) derived from the trace opcode. Segments are still `SegmentOwner::Cpu`/`Direct`; the next increment is to tag semantic variable ranges inside each row relation (register index/value, RAM address/value, shift source/output, bytecode fields) so `cpu_segment_layout` can emit real Register/RAM/Shift/Store claims for Virtual Spartan consumption.


### CPU variable groups

First variable-level metadata landed in `magnetar-cpu`:

- `CpuVarKind`: `Rs1`, `Rs2`, `Imm`, `Rd`, `Pc`, `NextPc`;
- `CpuVarGroup { kind, vars: Vec<VarId> }`;
- `UniformAluLayout::var_groups()` returns rs1/rs2/imm/rd groups;
- `UniformStepLayout::var_groups()` adds PC and next-PC groups from the PC adder.

Test `uniform_step_var_groups_match_witness_bits` checks every variable against the corresponding bit of the witness. The runtime metadata still uses row-level `CpuRowKind`; connecting these groups to merged offsets requires `row_cpu_relation` to return the layout/var groups, which is the next increment.


### Runtime var-group hook

`CpuWitnessSegment` now carries optional `vars: Vec<CpuVarGroup>` translated into merged offsets. `merged_cpu_system_with_metadata` fills them for rows that take the uniform ALU relation path; rows handled by `simple_alu_row_relation` have no layout object and therefore no groups yet. Test coverage verifies segment coverage; the ALU var-group test in `magnetar-cpu` verifies the variable semantics independently. Extending groups to simple ALU/load/store/RAM is the remaining metadata work.


### simple ALU layout

`simple_alu_row_relation_with_layout` now returns a `SimpleAluLayout` alongside the system/witness:

- `rs1`, `rhs`, `rd` variable groups;
- `rhs_is_imm` distinguishes immediate from register rhs;
- `simple_alu_row_relation` remains as a compatibility wrapper returning only system/witness.

The runtime `row_cpu_var_groups` uses the layout-returning function, so simple ALU rows (Add/Addi/Sub/Lui/Xor/Xori/And/Andi/Or/Ori) now contribute `CpuVarGroup`s to `CpuWitnessMetadata`. Tests verify `Addi` groups match the witness bits. This confirms the two directions are independent: simple row gadgets keep their smaller circuits while still exposing component metadata.


### Load/store RAM groups

`CpuVarKind` now includes `RamAddr` and `RamValue`:

- `UniformLoadLayout::var_groups()`: Rs1, Imm, RamAddr (adder sum), Rd (loaded value);
- `UniformStoreLayout::var_groups()`: Rs1, Imm, RamAddr, RamValue (rs2);
- runtime `row_cpu_var_groups` reconstructs these layouts for load/store/SC rows and attaches the groups to `CpuWitnessMetadata`;
- tests verify every group's variables against the load/store witness bits.

AMO is still skipped in metadata because its circuit merges store layout with an op-specific sub-relation. Next: AMO, branch/jump PC groups, and shift routing groups.


### Branch/jump groups

`CpuVarKind` now carries `Target` and `Link`. Shapes:

- `UniformBranchLayout`: Rs1, Rs2, Pc (link adder a), NextPc, Target (target adder sum);
- `UniformJalLayout`: Pc (link adder a), Link (link adder sum), Target (target adder sum);
- `UniformJalrLayout`: Rs1/Imm (target adder a/b), Pc (link adder a), Target, Link.

The runtime metadata reconstructs these layouts for branch/Jal/Jalr rows. Tests verify each group against the branch and Jal witness bits; AMO/shift/bytecode groups remain.


### CPU metadata: AMO, shift, bytecode, alignment

- `CpuVarKind` adds ShiftSource/ShiftAmount/ShiftOutput and Target/Link;
- `UniformAluLayout::shift_var_groups()` exposes source (rs1), shamt, output (rd);
- runtime uses these for Sll/Srl/Sra/Slli/Srli/Srai rows;
- `uniform_amo_row_groups` exposes the store-shaped part of AMO rows (Rs1/Imm/RamAddr/RamValue); op-specific AMO sub-relation variables are not yet exposed;
- `CpuWitnessSegment` now carries `fetch_pc` and `rom_word` from the trace/ROM.

Attempting to switch `cpu_segment_layout` exposed a hard alignment constraint: many CPU var groups are not one power-of-two aligned segment. `CpuVarGroup::is_segment_aligned` tests this; e.g. shift source is aligned but shamt (3 bits) is not. A component-aware `WitnessLayout` therefore requires repacking/aligning the CPU witness (or padding each component to an aligned segment), not just translating VarIds. The current 2-segment layout remains until that repacking is designed.


## Pivot: uniform SIMD CPU row schema

Starting point landed in `magnetar-cpu::simd`:

- `UniformCpuRowLayout { width, step: UniformStepLayout, num_vars }`;
- `uniform_cpu_row_layout(width)` builds one relation/layout shared by every ALU/PC instance;
- `UniformCpuRowWitness` carries op/pc/rs1/rs2/imm plus the fixed-column witness;
- test constructs Add/Xor/Addi instances against the same system and checks all satisfy it.

This is the first SIMD schema slice (ALU + PC). It deliberately reuses `uniform_step_relation` rather than `simple_alu`: fixed columns and selectors, one system, multiple instances. Legacy per-row `simple_alu` remains only as a reference path. Next: batch instances into SIMD witness/matrix, then add load/store and the native F2 relation.

Per-row witness repacking is frozen; metadata work remains as legacy/reference support.


### Uniform SIMD row batch

`magnetar-cpu::simd` now has:

- `UniformCpuBatchLayout { row, cycles }` with cycle-major witness layout;
- `batch_witness` checks cycle count and per-row width, concatenates instances;
- `row_values` slices one instance;
- `validate_pc_chain` enforces `pc_{i+1} = pc_i + 4` for the ALU/PC slice;
- selector test checks exactly one operation selector is active per row.

Tests cover batch layout, out-of-range cycles, selector activation, and PC-chain acceptance/rejection. This is still a batched-instance schema (not yet the shared-matrix SIMD relation).

Blocking decision for the next step: choose between

1. **block-diagonal batched runtime baseline** (fast to wire, validates claims/proof metrics), or
2. **true shared-matrix SIMD relation** (paper target; larger upfront rewrite, needs memory columns and dual-field design).


### Batched row system with PC constraints

`UniformCpuBatchLayout::batch_system(rows)` now builds:

- q block-diagonal copies of the uniform row system;
- cross-cycle constraints `next_pc_i == pc_{i+1}` on every bit;
- a concatenated witness.

Tests verify a contiguous PC chain satisfies the batch system and a broken chain is rejected. This is the block-diagonal baseline, not yet the paper's shared-matrix SIMD relation; it gives a runnable comparison point and exercises selector/PC semantics.


### Shared-matrix representation

`magnetar-proof::simd::SharedBlockMatrix` is the first true shared-matrix piece:

- stores one base `SparseMatrix` plus an instance count;
- `mul_vec` applies the base matrix to each instance block;
- `row_combination` / `eval_mle` compute block-diagonal results from the base matrix plus `eq(instance, point)` factors, without materializing q copies;
- test compares it against an explicitly assembled two-instance block matrix for `mul_vec`, `row_combination`, and `eval_mle`.

This is the matrix representation target for scheme B. Spartan still constructs `SparseMatrix` from a `ConstraintSystem`; the next step is genericizing the sum-check over a matrix trait so `SharedBlockMatrix` can be proved directly, then wiring the uniform CPU batch.


### Shared-matrix Spartan proof

`SpartanMatrix` is now a trait implemented by both `SparseMatrix` and `SharedBlockMatrix`. New entry points:

- `prove_spartan_with_matrices(z, a, b, c, pcs)`;
- `verify_spartan_with_matrices(a, b, c, proof, pcs)`;
- `prove_shared_simd_spartan(base, witnesses, pcs)`;
- `verify_shared_simd_spartan(base, instances, proof, pcs)`.

The shared SIMD entry builds q `SharedBlockMatrix` views over one base system, assembles a block-padded `z`, and runs the same sum-check. Tests prove and verify a two-instance batch without materializing q matrices, and the direct matrix API round-trips. This is a true shared-matrix proof prototype (local rows only; cross-cycle PC constraints still need to be added as extra rows).


### Shared-matrix CPU batch with PC chain

`SharedBlockMatrix::with_extra_rows` appends sparse rows after the block-diagonal instances (padding to the next power of two). `row_combination`/`eval_mle` account for the extra row-index bits and the non-block rows.

Runtime test `uniform_cpu_batch_enforces_pc_chain_with_shared_matrices`:

- base = `uniform_cpu_row_layout(16).system`;
- two Add/Xor instances;
- A/B/C shared matrices with extra chain rows encoding `next_pc_i * 1 = pc_{i+1}`;
- block-padded z;
- `prove_spartan_with_matrices` / `verify_spartan_with_matrices` pass on P3.

This is the first end-to-end shared-matrix CPU proof: no q-fold materialized matrices, local ALU rows plus cross-cycle PC constraints.


### Runtime SIMD CPU slice

New `magnetar-runtime::simd_cpu`:

- `SimdCpuProof { width, cycles, proof }`;
- `prove_simd_cpu_rows(width, rows)` builds the uniform layout, shared A/B/C matrices with PC-chain rows, block-padded z, and one shared-matrix Spartan proof;
- `verify_simd_cpu_rows(proof)` rebuilds the same shared matrices;
- `simd_cpu_rows_from_trace(trace, width)` converts a power-of-two prefix of supported ALU rows into `UniformCpuRowWitness` (memory/AMO/control/W rows are rejected).

Tests prove/verify a two-row Add/Xor batch, tamper detection, and a trace prefix ending at ecall. This is the first runtime wiring of scheme B; it is a standalone CPU slice, not yet merged into `UnifiedTraceProof`. Next: load/store columns, native F2, and unified integration.


### Uniform memory row schema

`magnetar-cpu::simd::UniformMemoryRowLayout` adds fixed load/store columns:

- address adder (rs1 + imm -> addr);
- data bits (load result / store value);
- PC adder;
- one-hot `is_load` / `is_store` selectors;
- `var_groups`: Rs1, Imm, RamAddr, RamValue, Pc, NextPc.

`magnetar-runtime::simd_memory` proves a q-row load/store batch with shared matrices and PC-chain rows, using the same `SharedBlockMatrix` path as the ALU slice. Test `simd_memory_rows_round_trip` proves/verifies one load and one store.

The schema currently enforces the CPU-side address/data columns and selectors only; RAM consistency remains BinaryTwist's job. The next step is to add the load/store relation to the CPU schema (not a separate relation), then wire Twist claims.


### Single ALU + memory CPU schema

`magnetar-cpu::simd::UniformCpuFullLayout` merges the ALU/PC schema and the load/store schema into one fixed system:

- both sub-relations are always active;
- ALU rows use a default load-shaped memory witness (data 0);
- memory rows use `Addi` on the ALU side (`rd = rs1 + imm`) so both sides are satisfied;
- equality constraints tie the duplicated PC/rs1/imm columns;
- `alu_witness` / `memory_witness` produce combined witnesses.

`magnetar-runtime::simd_full` proves a two-row batch (ALU + load) with shared matrices and PC-chain rows. Tests cover the combined relation and proof.

This is a single-schema stepping stone, not yet selector-gated: inactive sub-relations are still enforced by default witnesses, which costs variables/constraints. Next: gate ALU/memory constraints by row selector, then connect the memory columns to BinaryTwist claims.


### Memory selector gating (first step)

`UniformMemoryRowLayout` now has an `is_mem` selector and the constraint

```text
is_load + is_store = is_mem
```

instead of forcing one of them to 1. `inactive_witness` produces an ALU-side default with `is_mem = is_load = is_store = 0` and zero data. The combined schema uses this default for ALU rows, so memory operation selectors are genuinely off on ALU rows. The address/data sub-relations are still active; full gating of those constraints requires intermediate selector products or a dedicated gated gadget, which is the next step.


### Native F2 bit slice (s1)

`magnetar-runtime::simd_f2` adds a standalone bit-level CPU relation:

- `UniformBitAluRelation::xor(width)` and `::and(width)`;
- variables for rs1/rs2/rd bits plus a constant-one bit;
- XOR rows `(a + b) * 1 = c`, AND rows `a * b = c`;
- `check` over F2 and `to_system`/`to_witness` embedding.

Tests cover XOR/AND check and embedding into the packed system. This is the semantic s1 slice; it does **not** yet have a native F2 proof backend.

Architecture decision needed: (A) prove s1 by embedding the bit relation into the packed F2^128 system (current BitRelation path), (B) implement a native F2 R1CS/PCS/sum-check backend, or (C) keep the bit relation as the semantic source and initially embed, then swap in a native F2 backend behind the same interface.


### Bit proof backend boundary

Chosen intermediate path: keep the F2 bit relation as the semantic s1 source and isolate the proof backend behind `BitProofBackend`.

- `EmbeddedBitBackend<P: Pcs>` embeds the bit relation into the packed F2^128 system and proves it with Spartan;
- `prove`/`verify` are generic over the PCS;
- test proves/verifies the XOR relation with P3;
- a native F2 backend can later implement the same trait without changing the CPU schema or claim layout.

This avoids blocking the uniform schema on the native F2 proof decision.


### Mixed ALU/memory trace slice

`simd_full_rows_from_trace` now converts a trace prefix of supported ALU and load/store rows into combined-schema witnesses:

- ALU rows use `alu_witness`;
- load rows use `memory_witness(..., is_load=true)`;
- store rows use `memory_witness(..., is_load=false)`;
- unsupported rows (branch/AMO/W) end the slice;
- the slice must be a nonzero power of two.

Test `mixed_trace_slice_round_trips` executes `lui; sw; lw; add; ecall`, takes the four supported rows, and proves/verifies them with shared matrices. This validates the combined schema on a real trace, not just hand-built witnesses.


### F2 bit adder

`UniformBitAluRelation::add(width)` adds a native F2 ripple-carry adder relation:

- rs1/rs2/rd bits;
- carry chain;
- p1=a*b, p2=a*carry, p3=b*carry;
- xor_ab=(a+b)*1;
- sum=(xor_ab+carry)*1;
- carry_next=(p1+p2+p3)*1;
- carry0=0.

Tests check 5+3=8, reject a tampered result bit, and prove/verify the relation through `EmbeddedBitBackend` + P3. This extends the s1 bit slice beyond XOR/AND while the native F2 proof backend remains a trait boundary.


### F2 bit subtraction

`UniformBitAluRelation::sub(width)` shares the ripple-carry layout with `add`:

- `b_eff = rs2 XOR subtract`;
- `carry0 = subtract` (1 for subtraction);
- same sum/majority rows;
- `sub_witness(left, right)` computes two's-complement subtraction.

Tests check 5 - 3 = 2 and 3 - 5 = 254 (8-bit wraparound). `add` remains the same public API with `subtract = false`. The relation still proves through `EmbeddedBitBackend`.


### F2 unsigned SLT

`UniformBitAluRelation::slt(width)` computes `rs1 < rs2` from a two's-complement subtraction borrow:

- `b_eff = ~rs2`, carry-in 1;
- same carry/majority chain as `sub`;
- final carry 1 means `rs1 >= rs2`, so `lt = 1 XOR carry`;
- `rd[0] = lt`, all higher rd bits forced to 0.

Tests cover 3<5, 5<3, 5==5, and 255<1; all check over F2. Signed SLT can be obtained by flipping the sign bit of both operands (next).


### Signed SLT

`UniformBitAluRelation::slt_signed(width)` shares the comparator layout with `slt`, but flips the sign bit of both operands before the unsigned borrow comparison:

- `a_cmp = rs1` for bits below the sign, `rs1 ^ 1` at the sign;
- `b_cmp` analogously;
- `b_eff = ~b_cmp`, carry-in 1;
- borrow-out gives `lt`.

Tests cover 3<5, 5<3, -1<1, 1<-1, -5<-3, 127<-128, -128<127. Both signed and unsigned comparator relations check over F2.


### F2 barrel shifts

`UniformBitShiftRelation::shift(width, kind)` implements SLL/SRL/SRA over F2:

- stage count `log2(width)`;
- each stage uses shamt bits;
- multiplexer rows `diff = a XOR b`, `prod = diff AND shamt`, `out = a XOR prod`;
- SLL fills zero, SRL fills zero, SRA fills the sign bit;
- final stage wires into rd.

Tests cover 5<<2=20, 20>>2=5, -8>>1=-4 (8-bit), and shift-by-zero. This completes the basic F2 ALU op set (XOR/AND/ADD/SUB/SLT/SLL/SRL/SRA) at the semantic level.


### Gated bit ops

`GatedBitOp` is the F2 selector-gating primitive:

- XOR path: `diff = a XOR b`, `out = diff * gate`;
- AND path: `prod = a * b`, `out = prod * gate`;
- `gate = 0` forces every output bit to zero;
- `gate = 1` computes the operation.

Tests cover enabled and disabled XOR/AND. This is the gadget needed to gate ALU/memory sub-relations without turning the R1CS degree above two; applying it across the full CPU schema is the next step.


### Row-kind selector in the combined schema

`UniformCpuFullLayout` now allocates `is_alu` and ties it to the memory side's `is_mem`:

```text
is_alu + is_mem = 1
```

`alu_witness` sets `is_alu=1`/memory inactive; `memory_witness` sets `is_alu=0`/memory active. Tests assert the selector values and that both row kinds satisfy the same system. This gives the CPU schema an explicit row-kind selector for future claim routing and gated constraint blocks, without yet gating the always-active address/data sub-relations.


### Gated F2 adder

`GatedBitAdder` gates a ripple-carry adder:

- full adder diff/xor rows;
- `out = gate * xor_carry`;
- carry chain itself remains ungated (so `gate=0` zeroes the result, not the internal carry);
- test checks 5+3=8 with gate=1 and all-zero output with gate=0.

This gives a gated ADD primitive for row-selector composition. Fully gating the carry chain would require a gated carry product per bit; that is the next refinement if inactive rows must not compute carries.


### F2 s1 + packed s2 lockstep

First dual-relation lockstep landed:

- s1: F2 XOR bit relation (`(a_i + b_i) * 1 = c_i`) over the bit witness;
- s2: one packed parity constraint `Σa + Σb = Σc` over the same variables, padded with zero rows to match s1's row count;
- both use the same `Witness` and a two-segment `WitnessLayout`;
- one `LockstepProof` with `P3SharedPcs` proves both relations jointly;
- test proves and verifies the pair.

This is a real dual-relation lockstep over one witness, not yet the paper's full F2 / F2^128 CPU relations. It establishes the wiring: bit relation + packed companion + shared witness + one lockstep proof.


### F2 s1 + packed CPU s2 lockstep

`magnetar-runtime::simd_dual` proves the F2 bit XOR relation and the packed CPU ALU system in lockstep over **one witness**:

- s1: bit XOR rows over the packed row's rs1/rs2/rd variable groups, using the row's XOR selector as the constant-one bit;
- s2: the full `uniform_cpu_row_layout` packed ALU system;
- s1 is padded with zero rows to the packed row's constraint count;
- one `LockstepProof` with `P3SharedPcs`;
- test proves/verifies the pair.

This is a genuine dual-relation lockstep over one CPU row witness. Next: extend s1 to ADD/SUB/shift and combine with the shared-matrix CPU batch.


### Dual lockstep for ADD

`simd_dual` now generalizes `prove/verify_dual_cpu(width, op, ...)`:

- XOR: s1 rows `(rs1_i + rs2_i) * 1 = rd_i`;
- ADD: s1 rows `(a_i + b_i + carry_i) * 1 = sum_i` over the packed ALU adder variables;
- s2 is still the full packed CPU ALU system;
- zero rows pad s1 to the packed constraint count.

Tests cover XOR and ADD lockstep over one witness. Next: SUB/shift s1 rows and the shared-matrix batch version.


### Dual lockstep for SUB

`simd_dual` adds `StepOp::Sub` s1 rows over the packed ALU's public `sub_adder` variables:

```text
(sub_a_i + sub_b_i + sub_carry_i) * 1 = sub_sum_i
```

The full packed ALU system is still s2. Test covers an 8-bit subtraction lockstep. `UniformAluLayout::sub_adder` is now public for this relation. Next: shared-matrix batching of the dual lockstep.


### Matrix-based lockstep API

`magnetar-proof` now exposes:

- `prove_lockstep_claims_with_matrices(z, a0..c1, layout, pcs, commitment)`;
- `prove_lockstep_with_matrices(z, a0..c1, layout, pcs)`;
- `verify_lockstep_with_matrices(a0..c1, layout, proof, pcs)`.

All three take `SpartanMatrix` trait objects, so `SharedBlockMatrix` can drive a lockstep proof without materializing q copies. Test `shared_block_lockstep_round_trips` proves/verifies a two-instance shared-block lockstep.

This is the API prerequisite for the dual shared-matrix batch (F2 s1 + packed s2 over q rows).


### Dual shared-matrix batch

`simd_dual::prove_dual_batch(width, op, cycles)` builds:

- s1: F2 bit relation (XOR/ADD/SUB) as `SharedBlockMatrix`, padded with zero rows;
- s2: packed CPU system as `SharedBlockMatrix`, with PC-chain extra rows;
- one block-padded z over q cycles;
- one `prove_lockstep_with_matrices` proof.

`verify_dual_batch` rebuilds the same shared matrices and verifies the lockstep. Test covers XOR/ADD/SUB with q=2, all with PC-chain constraints. This is the first q-instance dual shared-matrix CPU proof.


### Dual batch shift coverage

The dual batch includes SLL/SRL/SRA (and immediate forms). `UniformAluLayout` now exposes the packed shift shamt/stage/product variables, and s1 enforces the barrel mux rows:

```text
(source + current) * shamt_bit = product
(current + product) * selector = next
```

SLL/SRL/SRA all use the real packed stage variables, so the shift dual relation is no longer only booleanity.


### Dual batch scaling (q = 2/4/8)

`cargo run --release -p magnetar-testkit --example simd_dual_scaling` measures the dual shared-matrix ADD batch:

| cycles | proof bytes | prove | verify |
|---:|---:|---:|---:|
| 2 | 133,128 | 17.5 ms | 10.1 ms |
| 4 | 159,776 | 31.8 ms | 15.4 ms |
| 8 | 199,128 | 68.9 ms | 26.6 ms |

Proof size grows sublinearly (roughly +20% per doubling), while prover time grows roughly linearly with q. This is the first scaling evidence for the dual shared-matrix path.


### Scheme B: gated memory row

First B-scheme row-level gadget landed:

- `GatedMemoryRow` composes `GatedBitAdder` with gated data bits;
- address output and data output are zero when `is_mem = 0`;
- data input bits are always present and explicitly gated;
- test checks active address/data and all-zero inactive outputs.

This is still an F2 bit-level gadget, not the packed CPU schema. It establishes the row-level composition pattern (gated adder + gated columns) that the packed rebuild will follow.

`prove_gated_memory_batch` / `verify_gated_memory_batch` batch q gated memory rows through `prove_shared_simd_spartan`; test proves two rows (active + inactive) with P3.


### Scheme B: gated ALU row

`GatedAluRow` composes XOR/AND/ADD under selectors:

- `is_xor`, `is_and`, `is_alu` one-hot/boolean selectors;
- `xor_diff = a XOR b`, `xor_prod = xor_diff * is_xor`;
- `and_prod = a AND b`, `and_gated = and_prod * is_and`;
- ADD carries use the shared a/b bits, with `add_gated = add_xor * is_add`;
- `out = xor_prod XOR and_gated XOR add_gated`;
- all selectors zero => all output bits zero.

Test checks XOR, AND, ADD (5+3=8), and inactive-zero rows; the XOR row also proves through `EmbeddedBitBackend` + P3. This is a row-level gated ALU gadget for the B rebuild.


### Scheme B: combined gated CPU row

`GatedCpuRow` merges `GatedAluRow` and `GatedMemoryRow` into one F2 schema:

- disjoint ALU/memory variable ranges;
- `is_alu + is_mem = 1` across the two sub-rows;
- ALU rows: `GatedAluOp::{Xor,And,Add,Inactive}`, memory side inactive;
- memory rows: gated address/data, ALU side inactive;
- inactive sub-row outputs are zero.

`prove_gated_cpu_batch` / `verify_gated_cpu_batch` batch q combined rows through `prove_shared_simd_spartan`. Test proves an ADD row and a memory row together.


### Packed view of gated rows

`GatedCpuRow::packed_system()` and `GatedMemoryRow::packed_system()` expose the F2^128 R1CS embedding of the selector-gated bit relations. The combined batch proof already runs on these systems with P3:

- selector-gated ALU/memory constraints;
- inactive outputs zero;
- one-hot ALU/memory row selection;
- prove/verify through `prove_shared_simd_spartan`.

This is selector gating proven in the packed field. It is not yet word-packed (64 bits per field element); the remaining B decision is whether the packed schema should stop at F2^128 embedding of bit rows or introduce true word-packed columns with packed selectors.


### Gated CPU row with PC chain

`GatedCpuRow` now carries `pc`/`next_pc` bits (boolean-constrained) and offers `alu_witness_at` / `memory_witness_at`.

`prove_gated_cpu_batch_pc` / `verify_gated_cpu_batch_pc`:

- q combined gated ALU/memory rows;
- shared matrices;
- extra PC-chain rows (`next_pc_i * 1 = pc_{i+1}`);
- one shared-matrix Spartan proof.

Test batches an ADD row and a memory row at PCs 0x1000/0x1004 and verifies the chain. This is a selector-gated CPU row with cross-cycle continuity in the packed field.


### Gated dual batch and claim routing

`simd_dual::prove_gated_dual_batch` / `verify_gated_dual_batch` connect `GatedCpuRow` to the dual lockstep path:

- s1: gated bit relation (`relation.to_system`);
- s2: packed F2^128 gated system;
- shared matrices for q rows;
- PC-chain extra rows;
- one `LockstepProof`.

`simd_gated_dual_compare` (release, single run) compares q=2 ADD:

| path | proof | prove | verify |
|---|---:|---:|---:|
| always-active dual | 133,128 B | 30.7 ms | 10.6 ms |
| gated dual | 86,136 B | 4.8 ms | 2.8 ms |
| gated dual mixed ALU/memory | 86,232 B | — | — |

The gated row is ~35% smaller and ~6x faster to prove in this run. These are illustrative single-run numbers, not a statistically stable benchmark.

`gated_rows_route_register_and_ram_claims` builds `ClaimKind::Register` / `ClaimKind::Ram` claims from gated ALU/memory rows and verifies they pass `ProtocolPlan::unified()` claim production and consumption (`TwistRegisters`/`TwistRam` sinks). This is protocol-level routing, not yet a BinaryTwist proof over gated memory rows.


### Gated dual scaling q = 2/4/8

`cargo run --release -p magnetar-testkit --example simd_gated_dual_scaling` (mixed ALU/memory rows):

| cycles | proof bytes | prove | verify |
|---:|---:|---:|---:|
| 2 | 84,984 | 5.8 ms | 2.8 ms |
| 4 | 107,248 | 8.1 ms | 4.9 ms |
| 8 | 131,208 | 23.5 ms | 7.6 ms |

The gated dual path scales sublinearly in proof size; prover time grows with q. Test `gated_dual_batch_scales_to_eight_cycles` verifies q=8.

### Gated memory rows prove through BinaryTwist

`gated_memory_twist_witness(width, rows)`:

- filters active gated memory rows;
- reads address/data back from the gated row witness;
- builds a one-read/one-write `BinaryTwistWitness`;
- validates it.

Test `gated_memory_rows_prove_through_binary_twist` proves/verifies the resulting RAM witness with `prove_binary_twist_ram`. This is a real BinaryTwist proof over gated memory rows, not just claim routing.

### Packed XOR/select microbenchmark

`cargo run --release -p magnetar-testkit --example packed_xor_select_bench`:

| case | vars | rows | proof | prove | verify |
|---|---:|---:|---:|---:|---:|
| bit XOR 64 | 193 | 65 | 67,944 B | 2.30 ms | 1.14 ms |
| packed XOR 64 | 4 | 2 | 3,176 B | 0.25 ms | 0.10 ms |
| packed select 64 | 7 | 5 | 3,320 B | 0.12 ms | 0.09 ms |

Packed linear rows are ~21x smaller and ~9x faster to prove in this microbenchmark. This is the strongest B-scheme evidence so far, but it only covers linear/select; AND/ADD/carry still need bit-level or lookup gadgets.

### Decision data

- A (F2^128 embedding) is already proving gated rows end-to-end and connecting to BinaryTwist; q=8 proof 131 KB.
- B (word-packed) gives large wins on linear/select/XOR, but no direct win on AND/ADD/SUB/SLT/shift carry chains.
- Recommended: keep A as the CPU correctness path; prototype packed linear/select columns for commitment compression and row gating; only extend to packed ADD/AND if profiling shows they dominate.


### Milestone 1: packed s2 select over one bit witness

`magnetar-runtime::packed_select::PackedSelectLayout` implements the paper's word-wide selection example:

- s1 over F2: `c * x_i = y_i` for every bit;
- s2 over F2^128: `c * (Σ β_i x_i) = Σ β_i y_i`, one packed constraint plus `c*c=c`;
- both read the same bit-valued witness;
- `prove_packed_select` / `verify_packed_select` run one `LockstepProof` with one commitment.

`lockstep_packed_system()` keeps the semantic s2 at 2 constraints and pads only for the lockstep matrix dimensions.

Benchmark (`packed_select_bench`, release, 64 bits):

| path | proof | prove | verify |
|---|---:|---:|---:|
| s1 bit select | 67,648 B | 1.59 ms | 1.03 ms |
| s2 packed select (2 rows) | 67,096 B | 0.90 ms | 0.88 ms |
| dual same-W lockstep | 67,720 B | 1.14 ms | 1.25 ms |

Key finding: packing reduces s2 rows from 64 to 2, but proof size stays PCS/variable-bound because the witness is still one F2^128 cell per bit. Row reduction improves prover work modestly; large proof-size gains require the BinarySpartan 128-bits-per-field commitment packing and ring switching (Milestone 5), not s2 row packing alone.


### Milestone 2: packed companion for gated ALU

`gated_alu_packed_system(row)` builds the s2 linear check:

```text
Σ β_i out_i = Σ β_i xor_prod_i + Σ β_i and_gated_i + Σ β_i add_gated_i
```

over the same bit witness as the gated ALU s1 relation. `prove_gated_alu_packed` runs the s1 bit relation and this packed s2 companion in one lockstep proof (s2 zero-padded to s1's row count).

Test covers XOR/AND/ADD. This is a real packed linear check over the gated CPU row, but proof size is still variable-bound because the commitment remains one F2^128 cell per bit.


### Milestone 2b: packed companion is now the gated dual s2

`GatedCpuRow::packed_companion_system()` contains two real packed checks over the same bit witness:

- ALU: `Σ β out = Σ β xor_prod + Σ β and_gated + Σ β add_gated`;
- memory: `is_mem * Σ β data_in = Σ β data`.

`prove_gated_dual_batch` / `verify_gated_dual_batch` now use this companion as s2 instead of the s1 embedding, zero-padded to the bit relation's row count.

This is the first gated dual batch with a genuinely different s2: s1 is the full bit relation, s2 is the packed linear/select companion, both over one witness.

Release q=2/4/8 (`simd_gated_dual_scaling`, mixed ALU/memory):

| cycles | proof | prove | verify |
|---:|---:|---:|---:|
| 2 | 85,752 B | 5.1 ms | 2.9 ms |
| 4 | 105,392 B | 7.8 ms | 4.1 ms |
| 8 | 132,200 B | 15.2 ms | 7.2 ms |

Proof size is still variable/commitment-bound, so the s2 row reduction does not change it materially. Test `gated_alu_packed_companion_verifies` covers XOR/AND/ADD; `gated_memory_packed_select_verifies` covers active/inactive memory data.


### Milestone 3: PC increment cross-step

`GatedCpuRow` now enforces `next_pc = pc + 4` inside every row:

- bits 0/1 unchanged;
- bit 2 flips and produces carry `carry_2 = pc_2`;
- bits >= 3 use `next_i = pc_i XOR carry_{i-1}`, `carry_i = pc_i AND carry_{i-1}`.

The gated dual batch's extra PC-chain rows then tie `next_pc_j = pc_{j+1}`. Test checks a placed PC (0x1004), rejects a tampered `next_pc` bit, and q=8 still proves/verifies.

Release q=2/4/8 after PC+4:

| cycles | proof | prove | verify |
|---:|---:|---:|---:|
| 2 | 85,560 B | 5.5 ms | 2.8 ms |
| 4 | 107,056 B | 8.4 ms | 4.8 ms |
| 8 | 133,512 B | 15.7 ms | 7.7 ms |


### Milestone 4: gated end-to-end bundle

`magnetar-runtime::gated_bundle` ties the gated CPU path to memory checking:

- gated dual CPU proof (`prove_gated_dual_batch`);
- BinaryTwist RAM proof from `gated_memory_twist_witness`;
- `Register`/`Ram` claims routed through `ProtocolPlan::unified()`;
- `verify_gated_bundle` checks CPU, RAM, claim production and consumption.

Test `gated_bundle_covers_alu_memory_and_twist` covers an ALU ADD row and a memory row.

`gated_bundle_bench` (release, one ALU + one memory row):

| component | bytes |
|---|---:|
| CPU lockstep | 85,880 |
| BinaryTwist RAM | 41,041 |
| claims | 100 |
| total | 127,021 |

prove 7.3 ms, verify 3.5 ms in this run. This is the first end-to-end gated CPU + Twist bundle; it still uses the 1-bit/cell commitment, so M5 remains the proof-size gap.


### BitPcs abstraction

`magnetar-proof::BitPcs` is the bit-witness commitment backend:

- `commit(bits)`;
- `open(bits, point) -> (value, opening)`;
- `verify(commitment, point, value, opening)`;
- `commitment_bytes`.

`DirectBitPcs<P: Pcs>` implements the current one-F2^128-cell-per-bit encoding. `prove_spartan_bits` / `verify_spartan_bits` run the Spartan reduction over bit witnesses and delegate commitment/opening to a `BitPcs`; the CPU/matrix code is unchanged.

Tests:

- `direct_bit_pcs_opens_bit_mle` checks commit/open/verify;
- `bit_pcs_drives_spartan_without_changing_matrices` proves a bit R1CS through `DirectBitPcs<TestPcs>`.

A future `PackedBitPcs` can implement 128-bits-per-field commitment + ring switching behind the same trait without touching the CPU schema. The lockstep/gated-dual path is not yet generic over `BitPcs`; that is the next integration step.


### M4/M5 BitPcs backends and shared tests

`BitPcs` now has two implementations:

- `DirectBitPcs<P>`: one F2^128 cell per bit (M4);
- `PackedBitPcs<P>`: packs up to 128 bits into one field element (M5). `PackedOpening` stores the packed opening and `verify` recovers the bit-MLE value from the packed value's basis bits.

Shared CPU/gated/dual tests:

- `both_bit_pcs_backends_run_the_same_lockstep_test` runs the same matrices/layout with Direct and Packed;
- `gated_dual_backends_share_the_same_test` runs the gated s1/s2 matrices through both backends.

M5 currently supports at most 128 witness bits per commitment (`PackedBitPcs` returns an explicit error above that). Multi-field packing needs the full ring-switching reduction and is not implemented.

M4 vs M5 benchmark (`bit_pcs_m4_m5_bench`, 63-bit packed select, P3, release):

| backend | proof | prove | verify |
|---|---:|---:|---:|
| M4 DirectBitPcs | 53,648 B | 1.31 ms | 0.73 ms |
| M5 PackedBitPcs | 1,488 B | 0.20 ms | 0.22 ms |

This is the first measurable M5 proof-size result: ~36x smaller and ~6x faster to prove in this microbenchmark. It is a 128-bit-witness prototype, not yet a full multi-field ring-switching backend.


### M4/M5 scaling: 64 / 96 / 128 witness bits

`bit_pcs_scaling_bench` (P3, release; booleanity R1CS, padded witness):

| bits | M4 proof | M4 prove | M5 proof | M5 prove |
|---:|---:|---:|---:|---:|
| 64 | 53,712 B | 1.16 ms | 1,488 B | 0.20 ms |
| 96 | 53,784 B | 0.86 ms | 1,560 B | 0.28 ms |
| 128 | 67,848 B | 1.28 ms | unsupported | unsupported |

M5 is ~34-36x smaller at 64/96 bits. 128 logical bits need a 256-cell padded Spartan witness in this system (`num_vars + 1`), which crosses the current single-field M5 limit; multi-field ring switching is still required. The benchmark prints the unsupported boundary instead of panicking.


### Multi-field fallback: RevealingPackedBitPcs

`RevealingPackedBitPcs<P>` supports arbitrary bit lengths by packing all 128-bit chunks and revealing the packed table in the opening. The verifier recomputes the deterministic commitment and evaluates the bit MLE from the packed table.

This is **not** ring switching and **not succinct**: proof size grows as `len/128` field elements. It is a correctness fallback used to run the same CPU/gated/dual tests above 128 bits; test `gated_dual_revealing_backend_handles_width8` proves a width-8 gated dual relation with it.

Scaling (`bit_pcs_scaling_bench`, P3, release):

| bits | M4 proof | M5 single-field | M5 reveal |
|---:|---:|---:|---:|
| 64 | 53,712 B | 1,488 B | 1,048 B |
| 96 | 53,784 B | 1,560 B | 1,120 B |
| 128 | 67,848 B | unsupported | 1,176 B |
| 256 | 84,576 B | unsupported | 1,336 B |
| 512 | 106,104 B | unsupported | 1,528 B |

The reveal backend's small proofs come from revealing O(len/128) packed elements; they are not comparable to M5 single-field succinct openings. True multi-field M5 still needs ring switching.


### DP24 ring switching (multi-field M5)

`RingSwitchPackedBitPcs` implements the DP24/Binius ring-switch reduction:

- pack 128 bits per field element;
- prover computes and sends `s_hat_v` (128 field elements) by folding the packed table against the evaluation-point suffix;
- verifier checks `evaluate(s_hat_v, prefix) == claim`;
- derive row-batching challenges, basis-transpose `s_hat_v` to `s_hat_u`, and compute `sumcheck_claim = <s_hat_u, eq(r'')>`;
- build the ring-switch indicator `A` with the Binius `eval_rs_eq` formula (tensor algebra: vertical/horizontal scaling, basis transpose, vertical fold);
- run `prove_product2` / `verify_rounds` for `Σ P(x)·A(x)`;
- open the packed table at the sumcheck point and check `P(r*)·A(r*)`.

Tests:

- `ring_switch_matches_direct_for_multi_field` (256 bits) matches `DirectBitPcs`, and rejects a tampered `s_hat_v`;
- `gated_dual_ring_switch_handles_width8` runs the width-8 gated dual relation through the ring-switch backend.

Scaling (`bit_pcs_scaling_bench`, P3, release):

| bits | M4 | M5 single-field | M5 ring |
|---:|---:|---:|---:|
| 64 | 53,712 B | 1,488 B | — |
| 96 | 53,784 B | 1,560 B | — |
| 128 | 67,848 B | unsupported | — |
| 256 | 84,576 B | unsupported | 4,600 B |
| 512 | 106,104 B | unsupported | 6,408 B |

Ring-switch proof overhead is about 2 KB for `s_hat_v` plus the sum-check and PCS opening; it is still 16-18x smaller than M4 in this benchmark.


### Ring-switch M5 on gated dual q=2/4/8

`prove_gated_dual_batch_bits` / `verify_gated_dual_batch_bits` are generic over `BitPcs`, so the same gated s1/s2 matrices run with Direct (M4) and RingSwitch (M5).

`gated_dual_m4_m5_bench` (P3, release, mixed ALU/memory):

| cycles | M4 proof | M5 ring proof | M4 prove | M5 ring prove |
|---:|---:|---:|---:|---:|
| 2 | 84,696 B | 4,816 B | 6.3 ms | 4.3 ms |
| 4 | 106,352 B | 6,624 B | 9.8 ms | 7.5 ms |
| 8 | 130,888 B | 10,736 B | 16.7 ms | 14.2 ms |

At q=8 the ring-switch M5 proof is ~12x smaller, with comparable prover/verifier time. Test `gated_dual_batch_runs_with_both_backends_on_q8` verifies both backends on q=8.


### Generic gated bundle with M5 ring CPU proof

`GatedBundle<C, O>` and `prove/verify_gated_bundle_with_backend` are generic over `BitPcs`; `P3GatedBundle` is the Direct/P3 alias. The same bundle test runs with `DirectBitPcs` and `RingSwitchPackedBitPcs`.

`gated_bundle_m4_m5_bench` (one ALU + one memory row):

| backend | CPU | RAM | claims | total | prove | verify |
|---|---:|---:|---:|---:|---:|---:|
| M4 direct | 85,816 B | 41,041 B | 100 B | 126,957 B | 7.8 ms | 4.7 ms |
| M5 ring | 4,816 B | 41,041 B | 100 B | 45,957 B | 5.1 ms | 3.8 ms |

The CPU proof is ~18x smaller; total bundle is ~2.8x smaller because BinaryTwist RAM (41 KB) now dominates. Next: packed Twist or larger q to amortize the ring-switch overhead.


### Mixed backend bundle: CPU/ALU M4, memory rows M5

`MixedGatedBundle` splits rows by kind:

- ALU rows: `DirectBitPcs` (M4);
- memory rows: `RingSwitchPackedBitPcs` (M5);
- RAM consistency: BinaryTwist (unchanged, not packed).

`prove_mixed_gated_bundle` / `verify_mixed_gated_bundle` prove both CPU batches, the BinaryTwist RAM witness, and the claim routing.

`gated_bundle_mixed_bench` (one ALU + one memory row):

| component | bytes |
|---|---:|
| ALU CPU M4 | 67,928 |
| memory CPU M5 | 3,896 |
| BinaryTwist RAM | 41,041 |
| claims | 100 |
| total | 112,965 |

This is a simple per-component backend split. It does not yet pack the BinaryTwist RAM tables; RAM is still the memory-checking proof.


### Deferred: packed BinaryTwist

Status: **not implemented**. Current RAM consistency still uses the existing BinaryTwist proof over one-hot address/value/increment tables; "M5 memory" only covers the gated memory CPU row.

Planned scope:

- pack BinaryTwist address / value / increment tables at 128 bits per F2^128 element;
- run read/write/update sum-checks over the packed representation;
- apply the same DP24 ring-switch reduction used by `RingSwitchPackedBitPcs` to the BinaryTwist evaluation claims;
- keep one commitment/opening across the packed tables where possible;
- add tamper tests for packed address, value, increment, and final memory state;
- benchmark packed vs current BinaryTwist on the same RAM trace.

Acceptance criteria:

- same RAM witness as the current BinaryTwist path;
- verify accepts honest packed proof and rejects tampered tables;
- proof size/RAM cost measured against the 41,041 B current reference;
- no separate unpacked witness commitment in the final bundle.

This is the main remaining component-level gap for RAM proof size.


### P0 progress: fuller packed s2

`GatedAluRow` now exposes `xor_diff`, `and_prod`, and `add_xor`, and `packed_companion_system` adds the selector-gated packed products:

```text
is_xor * Σ β xor_diff = Σ β xor_prod
is_and * Σ β and_prod = Σ β and_gated
is_add * Σ β add_xor  = Σ β add_gated
```

plus the packed ALU output linear check and the packed memory data select. The q=8 Direct/RingSwitch tests still pass, so the dual relation has a more complete packed s2 while remaining one witness.


### P0 progress: trace adapter for gated rows

`gated_rows_from_trace(trace, width)` maps a supported trace prefix into `GatedCpuRowInput`:

- ALU XOR/AND/ADD rows;
- load/store rows;
- unsupported op / branch / AMO / W-op ends the slice;
- slice truncated to the largest power-of-two length.

Test `supported_trace_prefix_proves_through_gated_dual` executes a small RV64 program (`add`, `add`, `xor`, `and`, `ecall`), converts the four supported rows, and proves/verifies them through the gated dual batch with `DirectBitPcs`.

This is a real trace-to-gated adapter for the supported subset, not yet full RV64 op coverage.


### P0 progress: register-file Twist from gated events/trace

`gated_register_twist_witness(events, initial)` builds the p=2 register-file BinaryTwist witness:

- two sub-cycles per ALU event: read rs1, then read rs2 and write rd;
- one-hot read/write addresses, value snapshots, increments, final register state;
- validates the witness and proves it with `prove_binary_twist_ram`.

`gated_register_events_from_trace(trace)` extracts register events from a supported ALU prefix (ADD/XOR/AND) using the actual trace rs1/rs2/rd values and initial registers.

Tests:

- `gated_register_events_prove_through_binary_twist`;
- `trace_events_prove_through_register_twist` (4 events from a real RV64 trace).

This closes the register-proof component; bundle-level Register claim replacement is still pending.


### P0 progress: register Twist in the gated bundle

`GatedBundle` now optionally carries:

- `register: Option<BinaryTwistRamProof>`;
- `register_events`;
- `register_initial`.

`prove_gated_bundle_with_registers` attaches a p=2 register-file BinaryTwist proof to the same CPU/RAM bundle; verification rebuilds the register witness from the stored events and initial state and checks it.

Test `gated_bundle_attaches_register_twist` proves/verifies an ALU + memory bundle with a register proof attached. Register claims are now backed by an actual BinaryTwist proof in the bundle, not only claim routing.


### P0 progress: SUB in the gated ALU row

`GatedAluRow` now supports XOR/AND/ADD/SUB:

- SUB uses `b_eff = ~b` and carry-in 1;
- shared a/b bits, separate carry chain and majority products;
- output mux includes `sub_gated`;
- packed s2 adds `is_sub * Σ β sub_xor = Σ β sub_gated`, and the packed output check includes `sub_gated`.

Tests cover 5-3=2 and 3-5=254 (8-bit wrap). The q=8 Direct/RingSwitch test now mixes ADD and SUB, and the trace adapter/register-event extractor accept `StepOp::Sub`.


### P0 progress: unsigned SLT in the gated ALU row

`GatedAluOp::Sltu` reuses the SUB carry chain:

- `lt = 1 XOR sub_carry[width]`;
- `slt_gated[0] = lt * is_slt`;
- higher output bits forced to zero;
- output mux includes `slt_gated`;
- packed s2 output check includes `slt_gated`.

Tests cover 3<5=1 and 5<3=0. The q=8 Direct/RingSwitch test mixes ADD/SUB/SLTU; trace adapter and register-event extraction accept `StepOp::Sltu`.


### P0 progress: signed SLT in the gated ALU row

`GatedAluOp::Slt` shares the SLTU path but flips both sign bits before the subtraction comparator:

- `a_s = a XOR is_slts` at the sign bit, `b_s` likewise;
- the SUB borrow chain runs over `a_s` / `b_s`;
- `lt` is selected by `slt_mode = is_slt + is_slts`;
- only bit 0 of the output is the comparison result.

Tests cover -1<1, 1<-1, and -5<-3 in 8-bit two's complement. The q=8 Direct/RingSwitch test mixes ADD/SUB/SLTU/SLT; the trace adapter and register-event extractor accept `StepOp::Slt`.


### P0 progress: shift proof component

`gated_shift` wraps the native F2 barrel-shift relation as a standalone proof component:

- `prove_gated_shift_row(width, event)` / `verify_gated_shift_row`;
- SLL/SRL/SRA;
- `gated_shift_events_from_trace(trace)` extracts shift rows from a supported trace prefix.

Tests cover 5<<2=20, 20>>2=5, -8>>1=-4 (8-bit), and a trace with `slli`.

This is a separate shift component, not yet fused into `GatedAluRow`; it closes the shift proof gap while leaving work fusion/selector integration for later.


### P0 progress: shift and auxiliary Shout/Router proofs

`gated_shift` proves SLL/SRL/SRA rows independently with the native F2 barrel-shift relation and extracts shift events from a trace.

`gated_aux` builds the bytecode/shift/store auxiliary proofs for a trace:

- `BinaryShoutWitness` + `prove_binary_shout`;
- `BinaryRouterWitness` in Shift and Store modes, when the trace has the corresponding rows;
- verify rebuilds each witness and checks each proof.

Test `gated_aux_proves_shout_and_shift` covers a trace with `slli` and `ecall`. Store mode is wired but not exercised in that test.

These are component proofs; they are not yet fused into the gated CPU row or the bundle's claim routing.


### P0 progress: gated bundle from a real trace

`GatedBundle` now carries an optional `GatedAuxProof` (BinaryShout + shift/store BinaryRouter).

`prove_gated_bundle_from_trace(trace, width, backend)`:

- converts the supported trace prefix to gated rows;
- proves the gated dual CPU batch;
- attaches register-file BinaryTwist when ALU register events exist;
- attaches BinaryTwist RAM when memory rows exist;
- attaches Shout/shift/store auxiliary proofs.

`verify_gated_bundle_from_trace` rebuilds the rows/events/aux witnesses and verifies every component.

Test `trace_bundle_includes_aux_and_register` uses a real trace (`add`, `slli`, `ecall`): CPU, register Twist, Shout, and shift Router all verify.


### P0 progress: store Router and shift proofs in the trace bundle

- `gated_aux_proves_store_router` now covers a real `Lui/Slli/Sw` trace, including BinaryRouter store mode.
- `gated_shift_events_from_trace` now skips non-shift rows and collects shift rows across the trace instead of stopping at the first non-shift ALU row.
- `GatedBundle` carries `shift_events` and per-row shift proofs; `prove_gated_bundle_from_trace` attaches them, and `verify_gated_bundle_from_trace` verifies each.
- The trace bundle test asserts CPU, register, aux, and shift proofs are all present.

This closes the store-Router test gap and puts SLL/SRL/SRA proofs into the traced bundle, while shift is still a separate component rather than fused into `GatedAluRow`.


### P0 progress: auxiliary claim routing

`gated_aux_claims(trace)` builds Shift/Store/Bytecode claims from the trace and checks them against `ProtocolPlan::unified()`; `verify_gated_aux_claims` also runs the standard claim consumers.

Test `aux_claims_route_through_protocol` uses a shift + ecall trace and verifies the Shift/Bytecode claims are accepted and consumed. This connects the auxiliary proofs to the claim graph; it is still separate from proof-object claim extraction.


### P0 progress: fused shift row

`GatedShiftRow` combines SLL/SRL/SRA under one row relation:

- three native barrel-shift relations in disjoint variable ranges;
- `is_sll / is_srl / is_sra / is_shift` selectors;
- one predicate row `is_sll + is_srl + is_sra = is_shift`;
- a single witness can select one shift kind while all three relations are present.

Test `fused_shift_row_selects_kind` checks 5<<2=20, 20>>2=5, -8>>1=-4 in one row. This is the row-level fusion needed for the CPU schema; wiring it into `GatedCpuRow` (and its one-hot ALU/memory/shift selector) is the remaining integration step.


### P0 progress: shift fused into GatedCpuRow

`GatedCpuRow` now unions ALU, memory, and the fused `GatedShiftRow`:

```text
is_alu + is_mem + is_shift = 1
```

- `GatedCpuRowInput::Shift { left, shamt, kind }`;
- `shift_witness_at` fills ALU/memory inactive and the selected shift relation;
- ALU/memory witnesses fill the shift relation inactive;
- trace adapter maps SLL/SRL/SRA rows to `Shift`;
- q=8 Direct/RingSwitch test mixes ALU, SUB, SLTU, SLT, and shift rows;
- bundle claim mapping uses `ClaimKind::Shift`.

The shift relation is fused at row level, but packed s2 still only checks ALU/memory (shift rows make the ALU/memory packed checks zero). A packed shift companion is a remaining s2 item.


### P0 progress: packed gate for shift rows

`packed_companion_system` now adds a packed shift gate:

```text
is_shift * Σ β (rd_sll + rd_srl + rd_sra) = Σ β (rd_sll + rd_srl + rd_sra)
```

so a shift-inactive row forces the packed shift result to zero, while an active row leaves the selected result unchanged. `GatedShiftRow::result_vars(kind)` exposes the three shifted result ranges for this check.

The ALU/memory packed checks still hold on shift rows (their gated outputs are zero). Test `combined_gated_row_selects_alu_or_memory` checks the shift companion, and q=8 Direct/RingSwitch still pass with mixed shift rows.


### P0 progress: public initial/final PC statement

`prove/verify_gated_dual_batch_bits_with_pc` adds public PC binding to the gated dual batch:

- first instance `pc` is constrained to the public initial PC;
- last instance `next_pc` is constrained to the public final PC;
- the rows are added to the s2 matrices and mirrored by zero rows on s1 so lockstep dimensions match.

Test `gated_dual_binds_public_pc_statement` proves `pc=0x1000 -> next_pc=0x1008` and rejects a wrong final PC. This is the first public statement bound directly into the gated CPU proof, not just stored in the bundle.


### P0 progress: gated dual over the Mosaic PCS adapter

`test gated_dual_uses_mosaic_pcs_adapter` runs the gated dual batch with:

```text
DirectBitPcs<PackedSharedPcs>
```

`PackedSharedPcs` builds a single packed `G`, lifts the primary/aux claims, batches them into one sumcheck point, and opens with one P3 proof. With no auxiliary tables, this exercises the single-commitment/single-evaluation adapter on the gated CPU proof.

This is still the reference one-field-per-bit layer; it does not yet implement the paper's MosaicPCS + ring-switch + 128-bit commitment packing composition. It does show the gated dual can run against the Mosaic adapter without changing the CPU matrices.


### P0 progress: ring switch composed with Mosaic adapter

`gated_dual_combines_ring_switch_and_mosaic` runs the gated dual batch with:

```text
RingSwitchPackedBitPcs<PackedSharedPcs>
```

Composition:

- RingSwitch packs 128 witness bits per field element and performs the DP24 reduction;
- `PackedSharedPcs` receives the packed table, builds one Mosaic `G`, batches claims, and opens with one P3 proof;
- the gated CPU matrices are unchanged.

This composes the two key proof-system layers (ring switching + single-commitment Mosaic adapter) on a real gated CPU batch. It is still not full Virtual Spartan claim reduction across auxiliary components.


### P1 progress: trace bundle benchmark and shift-proof deduplication

Because shift rows are now fused into `GatedCpuRow`, the trace bundle no longer attaches per-row standalone shift proofs. `shift_proofs` remains in the wire type but is empty on the fused path; the test now asserts that.

`gated_trace_bundle_m4_m5_bench` (add, xor, slli, ecall; register + aux included):

| backend | CPU | register | aux | claims | total | prove |
|---|---:|---:|---:|---:|---:|---:|
| M4 direct | 107,880 | 42,257 | 19,561 | 54 | 169,760 | 14.9 ms |
| M5 ring | 6,552 | 42,257 | 19,561 | 54 | 68,432 | 11.3 ms |

M5 CPU drops to 6.5 KB; register Twist and auxiliary Shout/Router now dominate the bundle. The aux byte count is a debug-format estimate because `GatedAuxProof` is not serialized yet.


### P1 progress: serialized auxiliary proofs and real bundle split

`GatedAuxProof` now derives serde Serialize/Deserialize, so the trace bundle benchmark can measure its actual wire size instead of a debug-string estimate.

`gated_trace_bundle_m4_m5_bench` (add, xor, slli, ecall):

| backend | CPU | register | aux | total | prove |
|---|---:|---:|---:|---:|---:|
| M4 direct | 107,880 | 42,257 | 137,381 | 287,580 | 13.2 ms |
| M5 ring | 6,552 | 42,257 | 137,381 | 186,252 | 11.0 ms |

The real dominant cost is the unpacked Shout/Router auxiliary proof (137 KB), not the CPU. This makes packed BinaryShout/BinaryRouter and packed register Twist the next meaningful size work; CPU M5 optimization has already taken its component to 6.5 KB.


### P0 progress: trace bundle binds public PCs

`GatedBundle` now records `initial_pc` / `final_pc` when built from a trace. `prove_gated_bundle_from_trace` re-proves the CPU batch with `prove_gated_dual_batch_bits_with_pc`, and `verify_gated_bundle_with_backend` dispatches to the PC-bound verifier when those fields are present.

Test `trace_bundle_includes_aux_and_register` now verifies CPU, register, aux, and public PC binding from a real trace.


### P1 progress: gated chunk pipeline over the recursion boundary

`gated_recursion` adds:

- `prove_gated_chunks(trace, width, chunk_size)`;
- `GatedChunkedProof { chunk_size, chunks, aggregated }`;
- `verify_gated_chunks`.

Each chunk with supported gated rows is proved by `prove_gated_bundle_from_trace`; empty/unsupported chunks are skipped. Chunk digests are aggregated with the existing `HashChainRecursion` reference backend.

Test `gated_chunks_aggregate` proves two chunks and verifies the hash-chain aggregate.

This is the chunk planner + aggregation wiring, not a recursive zk verifier.


### A: packed BinaryShout prototype

`packed_shout` implements a packed Shout final-evaluation path:

- Shout boolean/read sum-checks still run over the bit witness;
- table columns are packed at 128 bits/field and committed before the Shout challenges;
- the claim transcript absorbs the bit table commitment plus all packed column commitments (new `packed-binding` absorb in `binary_shout` claims);
- each packed column evaluation is proved with `RingSwitchPackedBitPcs`;
- the verifier recomputes the Shout claims and checks each packed opening against the expected column value.

Tests: `packed_shout_round_trips`; reference `binary_shout_round_trips` still passes with the empty binding.

Benchmark (`packed_shout_bench`, small 3-row trace):

| proof | bytes | prove |
|---|---:|---:|
| reference BinaryShout | 17,273 | 4.4 ms |
| packed Shout prototype | 48,481 | 11.4 ms |

The prototype is correct but **larger** than the reference because it opens each column separately (two points × many columns), so the next step is batching all packed columns into one Mosaic/ring-switch claim instead of per-column openings.


### A: packed BinaryShout leaf batching

`packed_shout` now uses one packed address/valid table and a row-batch challenge:

- the bit table commitment is unchanged;
- the packed table is committed before the Shout challenges;
- the read-point folded columns are sent as leaves;
- `r_col` is sampled after the leaf values;
- verifier checks:
  ```text
  Σ_col eq(r_col, col) · leaf_col = MLE(packed_table)(r_col, r_j)
  ```
  with one ring-switch opening;
- leaves are checked against the read-point Shout claims; tampering either
  leaves or the packed value is rejected.

Benchmark (`packed_shout_bench`, small trace):

| proof | bytes | prove |
|---|---:|---:|
| reference BinaryShout | 17,385 | 0.89 ms |
| packed Shout (leaf batch) | **4,193** | **0.45 ms** |

This is a 4.1x reduction and now smaller than the reference. The Shout verifier
still receives the witness in this reference architecture; replacing the
witness-derived column checks with the packed leaves for a witness-blind
verifier is the remaining integration step.


### Packed Shout integrated into the auxiliary bundle

`GatedAuxProof` now carries `packed_shout: Option<PackedShoutProof>` and keeps
the reference `shout` field as an optional fallback. `prove_gated_aux` emits the
packed proof; `verify_gated_aux` dispatches to it.

The gated trace row truncation was also fixed to use the largest power of two
not exceeding the supported-row count (`add, xor, slli` now keeps two rows
instead of one), with public-PC binding skipped for a single-row batch.

Trace bundle (`add, xor, slli, ecall`) after integration:

| backend | CPU | register | aux | total |
|---|---:|---:|---:|---:|
| M4 | 131,144 | 42,257 | 124,303 | 297,812 |
| M5 | 10,736 | 42,257 | 124,303 | 177,404 |

Aux dropped by ~13 KB (the Shout difference); the remaining 124 KB is dominated
by the unpacked shift/store Router proofs.


### Packed BinaryRouter merged and integrated

`PackedRouterProof` now merges every Router group in one proof:

- boolean groups and q use packed bit tables with ring-switch leaf batches;
- `shift_code` and `hq` are field-valued and use P3 field-table batches;
- all group commitments are fixed before the Router challenges (binding threaded through `prove/verify_binary_router_claims`).

Benchmark (`packed_router_bench`, shift router, small trace):

| proof | bytes | prove |
|---|---:|---:|
| reference BinaryRouter | 119,433 | 4.5 ms |
| packed Router | **87,201** | **3.4 ms** |

`GatedAuxProof` now carries `packed_shifts` / `packed_stores` and falls back to the reference Router proofs only when packed proofs are absent.

Trace bundle after integration:

| backend | CPU | register | aux | total |
|---|---:|---:|---:|---:|
| M4 | 131,144 | 42,257 | 91,401 | 264,910 |
| M5 | 10,736 | 42,257 | 91,401 | **144,502** |

Aux dropped from 124,303 to 91,401 B; M5 bundle dropped from 177,404 to 144,502 B.


Packed Router size breakdown (small shift trace):

```text
claims      6,129 B
bit groups 26,432 B
field groups 54,568 B
total      87,201 B
```

The two field-valued groups (`shift_code`, `hq`) dominate because each uses a
full P3 field-table opening. Batching both into one Mosaic/PackedSharedPcs
opening is the next Router optimization.


### Negative result: batching Router field groups

Batching `shift_code` and `hq` into one `PackedSharedPcs` opening was
implemented and measured at **68,400 B**, larger than the two independent field
openings (**54,568 B**). The Mosaic batching/lift overhead for one small code
table plus a 64-column hq table outweighs the saved opening. The prototype was
reverted; field groups remain independent.


### Negative result: PackedSharedPcs for BinaryTwist opening

Register BinaryTwist proof breakdown on a small trace:

```text
boolean    536 B
read     1,208 B
write    1,240 B
update     560 B
opening 38,713 B
total   42,257 B
```

The opening dominates. Replacing it with a `PackedSharedPcs::from_mosaic` opening
over the same Twist points produced **67,248 B**, larger than the original
38,713 B opening. The prototype was reverted. Packing the register opening needs
a different claim-batching/ring-switch construction, not `PackedSharedPcs`.


### P0 progress: LUI in the gated ALU row

`GatedAluOp::Lui` is now part of `GatedAluRow`:

- `is_lui` selector and `lui_gated` bits;
- output mux `out = Σ gated ops + lui_gated`;
- packed s2 gate `is_lui · packed(b) = packed(lui_gated)`;
- trace adapter maps `StepOp::Lui` to the gated ALU row.

Test `gated_alu_selects_xor_and_and` includes `LUI 0x1234` in an 8-bit row and
checks the truncated output `0x34`.


### P0 progress: AUIPC in the gated CPU row

`GatedAluOp::Auipc` is now supported:

- AUIPC reuses the ADD datapath with `left = pc`, `right = imm`;
- `is_auipc` is a boolean sub-selector of `is_add`;
- `GatedCpuRow` constrains `is_auipc · (packed(a) + packed(pc)) = 0`;
- packed s2 adds the same PC binding;
- trace adapter maps `Op::Auipc` to `GatedAluOp::Auipc`.

Tests cover the ALU output, the CPU packed companion, and the trace adapter mapping.


### P0 progress: JAL control flow

`GatedCpuRow` now supports JAL:

- PC+4 is conditional on `sequential`; JAL clears it;
- target is the ADD datapath `pc + imm` and is bound to `next_pc`;
- ALU `a` is bound to `pc`;
- packed s2 checks both bindings;
- trace adapter maps `Op::Jal`.

A two-row JAL trace (`jal x1, +4` then `addi`) proves/verifies through the gated
dual backend. JAL's `rd = pc + 4` write value is still not constrained.


### P0 progress: JALR control flow

`GatedAluOp::Jalr` is supported:

- target = rs1 + imm via the ADD datapath;
- next_pc bound to the ALU output;
- PC+4 disabled by `sequential = 1 + is_jal + is_jalr`;
- packed s2 binds next_pc to the ALU output;
- trace adapter maps `Op::Jalr`.

Remaining JALR items: force target bit 0 to zero, bind rs1 to the register file,
and constrain `rd = pc + 4`.


JALR now clears target bit 0: `next_pc[0]` is constrained to zero and only bits
1.. are bound to `rs1 + imm`. The odd-target test yields the aligned PC. The
destination write (`rd = pc + 4`) and rs1/register-file binding remain open.


### A: unified gated proof object

`unified_gated` combines two proofs over the same trace commitment:

- `UnifiedTraceProof`: the legacy shared-commitment proof whose CPU, register
  Twist, RAM Twist, Shout, and Router claims share one commitment/opening;
- `P3GatedBundle`: the gated SIMD CPU proof with public PC binding.

`prove_unified_gated` / `verify_unified_gated` verify both against the same trace
digest. This is one proof object and closes the reference-model binding gap
transitively through the shared trace, but it is still two proof systems: the
gated CPU claims are not yet merged into the legacy Virtual Spartan commitment.
Merging those claims is the remaining A work.


### A: gated claims against a shared Mosaic commitment

`gated_claim_inputs` exposes the gated CPU z, matrices, and segment layout.
Test `gated_claims_use_shared_commitment` commits gated z as a Mosaic table and
calls `prove_lockstep_claims_bits` with `DirectBitPcs<P3SharedPcs>` and that
commitment. The resulting `LockstepClaims` carry the shared `P3MosaicCommitment`
and non-empty segments.

This is the proof-generation ingredient needed to merge gated CPU claims into
`UnifiedTraceProof`; verification/opening integration is the next step.


### A: verifying gated claims against shared matrices

Added `verify_lockstep_claims_with_matrices` so gated claims whose matrices
include PC-chain extra rows can be verified without rebuilding plain systems.
`gated_claims_use_shared_commitment` now:

- commits gated z as a Mosaic table;
- generates `LockstepClaims` with `prove_lockstep_claims_bits`;
- verifies them with the new matrix-based verifier and the shared commitment;
- checks non-empty segments.

This supplies both proof-generation and verification ingredients for merging
gated claims into `UnifiedTraceProof`.


### A: gated CPU claims merged into UnifiedTraceProof

`UnifiedTraceProof` now carries `gated: Option<GatedCpuClaims>`:

- the gated z vector is committed as an extra Mosaic table in the same
  `P3MosaicCommitment` as the legacy CPU/register/RAM/Shout/Router tables;
- gated claims are generated with `prove_lockstep_claims_bits` against that
  shared commitment;
- verification uses `verify_lockstep_claims_with_matrices`;
- the gated `ry` evaluation is added to the single shared P3 opening.

Test `unified_trace_merges_gated_cpu_claims` proves/verifies a two-row gated
trace through `prove_unified_trace`/`verify_unified_trace` and checks the extra
committed table.

Also fixed the shift packed gate for widths above 42: the three shift result
vectors are packed separately instead of concatenating into a >128-bit vector.
`compiled_guest_elf_runs_and_proves` (width 64) passes again.


### A: single unified proof object

`UnifiedGatedProof` now contains only `UnifiedTraceProof`; the duplicate
`P3GatedBundle` was removed. Since `UnifiedTraceProof` already carries the gated
claims and shares the opening, the old wrapper's second proof/opening is gone.

`unified_gated_bench` (two gated rows) measures:

```text
UnifiedTraceProof: 173,439 B
gated claims present: true
```

This replaces the previous two-proof wrapper (legacy unified plus a separate
gated bundle).


Unified proof size breakdown (two gated rows):

```text
total   173,439 B
opening 163,592 B
access    5,546 B
gated     1,857 B
cpu       1,264 B
shout     1,146 B
```

The shared P3 opening is 94% of the proof. Packed aux/claims are now small; the
next size work must target the opening itself (fewer claim points or a batched
Mosaic opening), not the component witnesses.


The unified opening has 32 points over 8 tables. A coalescing pass over
identical `(table, point, next_columns)` claims found no duplicates, so point
merging alone cannot reduce the 163 KB opening. Reducing it requires a batched
Mosaic opening (one final point) or fewer claim families, which is a PCS-level
change rather than claim routing.


### Negative result: batched Mosaic opening

A one-point batched Mosaic opening (`PackedMosaic` + `batch_claims` + one P3
opening) was prototyped over the unified tables/points. Result:

```text
old P3MosaicOpening 163,592 B
batched opening     159,936 B
```

Only a ~2% reduction. The packed G polynomial is as large as the sum of all
table columns, so the final one-point P3 opening plus batching sumcheck nearly
cancels the point-count savings. The prototype was reverted.


Unified commitment table shapes (two gated rows):

```text
table 0: 1 column,  7 vars
table 1: 8 columns, 1 var
table 2: 1 column,  1 var
table 3: 8 columns, 2 vars
table 4: 12 columns,3 vars
table 5: 1 column,  3 vars
table 6: 1 column,  5 vars
table 7: 1 column, 11 vars  (trace table, 2048 elements)
```

The trace table alone is ~87% of the committed field elements. The opening is
therefore dominated by the trace table, not the CPU/aux tables. Replacing the
full trace table claim with a smaller segment commitment (or binding trace rows
through the already-public trace digest) is the next size lever.


### Negative result: removing the trace table

Removing the full trace table from the shared commitment reduced the unified
proof only from 173,439 to 170,287 B and the opening from 163,592 to 160,472 B.
The next largest table is the register increment table (1 column, 11 vars,
2048 elements), and the base P3 opening remains ~160 KB. The trace claims were
restored because a 3 KB saving does not justify dropping the trace-table
binding.

The opening is therefore dominated by the base P3 proof for this commitment
shape, not by the number of points or the trace table alone.


### A: isolated BEQ/BNE branch row

`branch_row::GatedBranchRow` prototypes a branch row with:

- two independent ADD datapaths (`pc + imm`, `pc + 4`);
- XOR/OR equality reduction over `rs1`/`rs2`;
- BEQ/BNE selectors and a `taken` bit;
- `next_pc = taken ? target : sequential` mux.

Test `branch_row_selects_equal_and_not_equal` covers BEQ taken/not-taken and BNE
taken on 8-bit values. The row is not yet fused into `GatedCpuRow` or the trace
adapter; that is the next A step.


### A: BEQ/BNE fused into GatedCpuRow

`GatedCpuRow` now includes `GatedBranchRow` as a fourth row kind:

```text
is_alu + is_mem + is_shift + is_branch = 1
```

- branch target/sequential ALU inputs are gated to `pc`;
- `next_pc` is bound to the branch mux output;
- `sequential + is_jal + is_jalr + is_branch = 1`;
- branch trace rows map to `GatedCpuRowInput::Branch`.

Test `branch_trace_proves_through_gated_dual` executes `beq x0,x0,+8`
(taken), then a normal Add, and proves/verifies through the gated dual backend.

Still missing: BLT/BGE/BLTU/BGEU and branch `rd`/register binding.


BEQ/BNE branch row extended to all six RV64 branches:

- BEQ/BNE use the XOR/OR equality reduction;
- BLT/BGE use a signed SLT comparator;
- BLTU/BGEU use an unsigned SLTU comparator;
- all six selectors are one-hot and feed the same `next_pc` mux.

`branch_row_selects_all_kinds` covers taken/not-taken cases for all six.


### Branch cost and B opening spike

Adding all six branch kinds to `GatedCpuRow` increased the unified proof:

```text
before branches 173,439 B
after branches  209,719 B  (opening 199,744 B)
```

The branch row adds four ALU datapaths per row, so the gated witness table grows.

B spike results:

- `P3BinaryPcs` security 64: unified 148,119 B (opening 138,144 B);
- `P3BinaryPcs` security 40: unified 107,207 B (opening 97,232 B);
- `LigeritoPcs` is an index-opening PCS, not a multilinear point-evaluation
  opening, so it cannot replace the unified opening.

Lowering security to 64/40 is not acceptable as the default. A new
point-evaluation PCS backend is required for B; one is not present in the repo.


### B: revealing point-evaluation backend

Added `RevealPcs`, a non-succinct, non-hiding point-evaluation PCS:

- commitment = SHA-256 of the evaluation vector;
- opening = whole vector;
- verifier recomputes the hash and MLE value.

Measured:

```text
P3 opening, 128 values:      52,712 B
Reveal opening, 128 values:   2,056 B
```

The unified proof now supports `opening: None` and
`prove_unified_revealed`. In that mode the verifier rebuilds the mosaic tables
from the trace, checks the reconstructed commitment, and evaluates every claim
point directly.

Small gated trace:

```text
P3 unified proof:       209,720 B
revealed unified proof:   9,976 B
```

Tampering the reconstructed commitment is rejected.

This is a real size reduction but not a production PCS: it reveals the tables
and relies on the verifier having the trace. It is the first working B backend
and a baseline for a future succinct/hiding replacement.


The 9,976 B unified proof contains only the claims/commitment; it does **not**
carry the table vectors. The verifier rebuilds the tables from the trace, checks
the reconstructed P3 commitment, and evaluates the claim points. So this is a
witness-checked, opening-free backend: proof size is small, but verification
work is non-succinct and there is no zero-knowledge/hiding guarantee. A
production succinct/hiding opening remains future work.


### C: MUL row

`mul_row::GatedMulRow` implements a schoolbook shift-add multiplier:

- `width^2` partial products;
- `width` shift-add rounds over a `2*width` accumulator;
- full adders with explicit OR-majority carry;
- output = low/high `width` bits.

Test `mul_row_multiplies` covers `5*3=15`, `255*255=65025`, `0*7`, `17*13`.

`GatedCpuRow` now has a fifth row kind:

```text
is_alu + is_mem + is_shift + is_branch + is_mul = 1
```

`mul_trace_proves_through_gated_dual` executes `lui x1,5; mul x2,x1,x1`
and proves/verifies through the gated dual backend.


### C: MUL output binding and MULHU

`GatedCpuRow` now ties the multiplier product to a row output:

- `mul_high` selects low vs high product bits;
- `mul_out = mul_high ? product[width..] : product[..width]`;
- trace adapter supplies `rd_val` as `mul_out`.

`MUL` and `MULHU` both work end-to-end. `mulhu_trace_proves_through_gated_dual`
executes `lui x1,255; mulhu x2,x1,x1` and verifies the high product.

MULH/MULHSU still need signed correction and are the next C item.


### C: MULH and MULHSU

The multiplier now computes a signed high correction:

```text
signed_high = high_unsigned - sign_a·b - sign_b·a  (mod 2^w)
```

Two-w's-complement subtractors are built from full adders; tests cover
`-5 * 3` high `0xff`. The CPU selects the signed high when either operand is
signed, and the trace adapter maps MULH/MULHSU.

`mulh_trace_proves_through_gated_dual` executes LUI/MULH/MULHSU and verifies.
The width-64 `compiled_guest_elf_runs_and_proves` also passes again; the witness
high bits are read from the committed product instead of a 64-bit host multiply.


### C: isolated DIV/REM row

`div_row::GatedDivRow` proves unsigned division as a multiplication check:

```text
num = q*den + rem
rem < den
```

It reuses `GatedMulRow` for `q*den`, an ADD ALU for `product_low + rem`, and a
SUB ALU for `rem - den`. Tests cover `17/5`, `255/7`, `100/10`, `1/3` with the
expected quotient and remainder. Integration into `GatedCpuRow` (DIVU/REMU
selectors and trace adapter) is next.


### C: DIVU/REMU fused into GatedCpuRow

`GatedDivRow` is now part of the CPU row:

- `is_alu + is_mem + is_shift + is_branch + is_mul + is_div = 1`;
- `div_rem` selects quotient vs remainder;
- trace adapter maps DIVU/REMU with `rd_val` as the selected output.

`divu_trace_proves_through_gated_dual` runs LUI/SRLI/DIVU/REMU and proves the
quotient/remainder. Width-64 `compiled_guest_elf_runs_and_proves` still passes;
the product fold now takes only the low width bits.


### C: signed DIV/REM row

`signed_div_row::SignedDivRow` wraps unsigned division:

1. take absolute values with `0 - x` ALUs;
2. run unsigned `GatedDivRow` on the magnitudes;
3. negate quotient when signs differ;
4. negate remainder when the dividend is negative.

Tests cover `-5/5`, `5/-5`, `-5/-5`, `1/3`. The INT_MIN/-1 wrap path is handled
by two's-complement negation. Integration into the CPU row and DIVW/REMW remain.


Attempting to fuse `SignedDivRow` into `GatedCpuRow` produced a lockstep
sumcheck mismatch on an 8-row signed DIV/REM trace even though the isolated row
passes. The CPU integration was reverted; `SignedDivRow` remains an isolated,
tested component until the row offsets/top-selector interaction is debugged.


### C: signed DIV/REM fused into GatedCpuRow

The earlier lockstep mismatch was a test-vector problem, not a row problem:
a width-8 trace derived `0xfb` with SRLI, so the 64-bit executor saw +251
while the width-8 row saw -5. Sign-extending with SRAI makes the trace and row
agree, and the signed DIV/REM trace now proves/verifies.

`GatedCpuRow` has `is_sdiv`, `sdiv_rem`, and `sdiv_out`; DIV/REM map to
`SignedDivRow`.


### B: parameter-tuned P3 backend

`P3BinaryPcs` now carries `log_inv_rate`, `pow_bits`, and `log_folding_factor`
and uses `BinaryPcsConfig::try_new_with_folding`. The unified proof uses
`(rate=4, pow=16, folding=3)`.

Measured unified proof:

```text
default (rate2, pow4, fold1): 209,720 B total, 199,745 B opening
tuned   (rate4, pow16, fold3): 156,088 B total, 145,857 B opening
```

That is a 26% total reduction at the same 100-bit setting. The standalone
12-variable sweep (`p3_param_sweep`) ranges from 162,080 B at the default to
97,328 B at `(rate3, pow16, fold2)`; the unified layout favors `(4,16,3)`.

This reduces P3 overhead but does not provide hiding or the 10x reduction of a
new succinct backend.


### C: 32-bit word DIV row

`word_div_row::WordDivRow` runs 32-bit signed and unsigned division on the low
halves and sign-extends the 32-bit result to 64 bits. Tests cover `100/7` for
both signedness and the `0x8000_0000 / 0xffff_ffff` overflow/magnitude cases.
CPU fusion for DIVW/REMW/DIVUW/REMUW is the next step.


### C: isolated AMOADD row

`amo_add_row::AmoAddRow` constrains `new = old + operand` by binding a single
`GatedAluRow` ADD to old/operand/new. Tests cover `5+3`, `255+1`, `0+7`,
`17+13` at width 8. Memory read/write binding and the other AMO operations are
the next step.


`AmoAddRow` now carries two memory rows: a read of `old` and a write of `new`
at the same address, with the address adder inputs bound together and the
memory gate forced high. The isolated relation checks read-modify-write
consistency for AMOADD.


### C: AMO logic operations

`amo_logic_row::AmoLogicRow` covers AMOXOR, AMOAND, AMOOR, and AMOSWAP with the
same two-memory-row read-modify-write binding as AMOADD. Tests cover
`0b1100`/`0b1010` for each operation.


### C: AMO min/max rows

`amo_minmax_row::AmoMinMaxRow` covers AMOMIN, AMOMAX, AMOMINU, AMOMAXU with
the same read-modify-write memory binding. It uses one SLT/SLTU ALU and a
select mux; tests cover `-5`/`3` for signed and unsigned orderings.


### C: isolated LR/SC rows

`lr_row::LrRow` loads `old` from the address and exposes a reservation flag.
`sc_row::ScRow` reads `old`, writes `operand` only when `success`, and sets
`rd = !success`. Tests cover both SC outcomes and LR load/reserve. Reservation
validity is not yet chained across CPU rows.


### C: reservation transition row

`reservation_row::ReservationRow` models LR/SC state:

- LR sets the reservation and its address;
- SC succeeds only when the previous reservation is valid and addresses match;
- stores/AMOs clear the reservation;
- other events preserve it.

Tests cover LR, matching SC, mismatching SC, and invalidation.


AMO row batches now have standalone proofs:

```text
prove_amo_add_batch / verify_amo_add_batch
prove_amo_logic_batch / verify_amo_logic_batch
prove_amo_minmax_batch / verify_amo_minmax_batch
```

Each batch uses `prove_shared_simd_spartan` over the row's packed system with
4 instances in tests. These are standalone proofs, not yet part of the unified
trace proof.


### C: AMO bundle proof from a trace

`amo_bundle::AmoBundleProof` collects AMO events from `TraceRow.mem` and
`rd_val`/`rs2_val`, groups them by operation, pads each group to a power of two,
and proves each group with its standalone AMO batch prover. Tests execute a
trace containing AMOADD/AMOSWAP/AMOXOR/AMOMAX and verify the bundle. This is not
yet wired into `UnifiedTraceProof` or CPU/memory claims.


### C: AMO bundle in UnifiedTraceProof

`UnifiedTraceProof.amo` now carries the AMO bundle when the trace contains AMO
events. `ProveContext::finish` generates it, `ProofBundle` preserves it, and
`verify_unified_with_plan` checks both presence and each batch proof. The
`unified_amo_bundle_round_trips` test executes AMOADD.D and verifies the unified
proof. AMO events are not yet bound to CPU/memory claims or the reservation
chain.


`verify_amo_bundle` now recomputes each AMO row's new value and requires a
matching write in `trace.memory_events` at the same address. Executor traces do
not emit a separate read event for AMO, so the old value is bound through the
trace commitment and `rd_val` rather than a read event.


Attempting to emit an AMO read event in the executor broke the unified
BinaryTwist memory proof (`memory write does not match BinaryTwist`): the
current witness/claim construction assumes one memory access per row. The
executor change was reverted. Binding the AMO old value as a first-class memory
read requires extending BinaryTwist to handle a read+write pair per row.


Without adding an executor read event, `verify_amo_bundle` now binds the AMO
old value to memory history: it finds the latest prior write at the same address
(or the initial RAM value) before the row cycle, masks to the AMO width, and
requires it to equal `rd_val`. This avoids changing BinaryTwist while still
tying the read side to memory state.


LR and SC now have standalone batch provers:

```text
prove_lr_batch / verify_lr_batch
prove_sc_batch / verify_sc_batch
```

Tests prove four instances each. They are not yet part of `AmoBundleProof` or
`UnifiedTraceProof`.


`AmoBundleProof` now includes LR and SC batches. LR rows use `rd_val`/`mem.addr`;
SC rows use the prior memory value as `old`, `rs2_val` as the new value, and
`rd_val == 0` as success. The bundle test executes AMOADD/AMOSWAP/AMOXOR/AMOMAX
followed by LR/SC and verifies all batches. Reservation state is still not
chained in the CPU.


`verify_amo_bundle` now checks the trace's reservation chain:

- `reservation_before` must equal the previous `reservation_after`;
- LR sets the reservation to its address;
- a successful SC requires `reservation_before == addr` and clears it;
- stores/AMOs clear it.

A tampered LR `reservation_after` is rejected. This is still verifier-side trace
checking, not a CPU-row chained constraint.


`unified_lr_sc_bundle_round_trips` executes LUI/ADDI/SD/LR.D/ADDI/SC.D and
verifies the unified proof with both LR and SC batches present.


`AmoBundleProof.reservation` now proves one `ReservationRow` per trace row and
verifies it. The witness uses the width-masked address for the match bit, which
fixed a false mismatch when a 64-bit address was truncated. This binds the
reservation transition fields cryptographically per row, while the cross-row
chain check remains verifier-side.


`check_lr_sc_memory` now binds LR/SC to memory history: LR's `rd_val` must be
the latest prior value, and a successful SC's write must appear in
`memory_events`. Targeted tests: `cargo test -p magnetar-runtime amo_bundle`.


A tamper test mutates LR `rd_val` and confirms `check_lr_sc_memory` rejects it.


Reservation batches are now only generated when the trace has AMO/LR/SC
events. A plain trace keeps `proof.amo == None`, avoiding reservation overhead
on every unified proof; `unified_trace_proof_merges_row_constraints` asserts it.


`unified_amo_lr_sc_bundle_round_trips` executes SD/AMOADD.D/LR.D/SC.D together
and checks that AMO, LR, SC, and reservation batches are all present in one
unified proof.


The reservation batch now contains only rows where `reservation_before !=
reservation_after`, instead of every trace row. Non-changing rows are covered by
the verifier-side chain check, so this avoids proving trivial transitions on
long traces.


### C: PC transition row

`pc_transition_row::PcTransitionRow` proves

```text
next = sequential ? pc + 4 : target
```

with an ADD ALU and a select mux. It has a batch prover/verifier
(`prove_pc_transition_batch`, `verify_pc_transition_batch`). Tests cover
sequential and branch-target transitions. It is not yet part of the unified
proof.


`UnifiedTraceProof.pc` now carries a `PcBatchProof` over all trace rows:

```text
next = (next_pc == pc+4) ? pc+4 : next_pc
```

This proves the per-row PC transition. The branch target value is still bound by
the gated CPU row and the public PC statement, not by the PC batch itself.


### C: PC target binding

`pc_target_row::PcTargetRow` proves `target = base + imm`, with an optional
JALR low-bit clear. `PcBatchProof.targets` proves every trace row whose
`next_pc != pc+4`, using `pc` as base for branches/JAL and `rs1_val` for JALR.
A test executes a taken BEQ and verifies the target batch.


### PC batch size regression

Adding `PcBatchProof` as a separate unified sub-proof raised the small gated
trace from 156,089 B to 348,731 B: two extra P3 proofs cost ~192 KB, more than
the entire opening. The field was removed from `UnifiedTraceProof`; PC rows and
batches remain standalone. PC constraints must be folded into the CPU/gated
claims rather than proved as another P3 batch.


### Soundness fix: bind AMO/LR/SC/reservation batches to trace rows

The batch verifiers previously checked only that a valid Spartan proof existed
for the row system; they did not bind it to the rows recomputed from the trace.
A proof for different witnesses with the same instance count would verify.

`verify_shared_simd_spartan_with_witnesses` now rebuilds `z` from the supplied
rows, commits it, and compares the commitment to `proof.commitment` before the
Spartan verification. All AMO/LR/SC/reservation bundle verifiers use this bound
path. A tampered AMOADD `rd_val` is rejected by `verify_amo_bundle`.


PC batch verification is now witness-bound: `verify_pc_batch` rebuilds the
transition and target witnesses from the trace and compares their PCS
commitment with the proof. A tampered `next_pc` is rejected. The batch remains
standalone; it is not in the unified proof because of the measured size
regression.


`ProofBundle` now preserves `gated: Option<GatedCpuClaims>`. Previously a
from_unified/into_unified roundtrip dropped gated claims, and verification
failed with "gated CPU claims presence does not match the trace". The combined
AMO/LR/SC test now roundtrips the bundle and verifies the restored proof.


`verify_gated_memory_batch_bound` rebuilds the memory-row witnesses from the
supplied rows and compares their PCS commitment to the proof. A tampered value
is rejected. This closes the same witness-binding gap for the standalone memory
batch.


### C: reservation combined with CPU row

`reservation_cpu_row::ReservationCpuRow` concatenates a `GatedCpuRow` relation
with a `ReservationRow` relation, using the CPU witness builder and a
row-local reservation transition. It has a batch prover whose verifier rebuilds
both witnesses and compares the PCS commitment (`verify_*_with_witnesses`).
Tests cover an LR transition and a successful SC transition. The cross-row
chain is still not part of this row.


### C: reservation CPU link

`ReservationCpuRow` now carries `next_pre_valid`/`next_pre_addr` and enforces:

```text
post_valid == next_pre_valid
post_addr  == next_pre_addr   when post_valid
next_pre_addr == 0            when !next_pre_valid
```

The address equality is gated by `post_valid`. A four-instance batch is chained
(LR -> SC -> LR -> SC) and verifies. This is still a standalone row batch, not
yet the unified CPU row list.


### C: reservation rows from a trace

`reservation_cpu_rows_from_trace` maps the gated CPU rows and uses the trace's
`reservation_before` fields for the chain:

```text
addr, res_addr, pre_valid
is_lr, is_sc
next_pre from row[i+1].reservation_before
```

A real LUI/LR.D/SC.D/ADD trace produces four linked instances and the batch
proves/verifies. This is still a standalone batch, not yet the unified CPU
claim list.


### C: ADDI gated trace support

`gated_rows_from_trace` now maps ADDI to an ALU ADD with the immediate as the
right operand. This makes simple LUI/ADDI/LR/SC traces fully gated; the unified
table-count assertion now includes the gated claims table.


A tamper test flips a reservation `pre_valid` in the trace-derived CPU chain and
confirms the witness-bound verifier rejects it.


### C: reservation constraints in unified gated claims

`gated_shared_matrices` now accepts any `GatedRowLike`; `ReservationCpuRow`
implements it. Unified proving/verification builds reservation CPU rows from the
trace and uses `reservation_claim_inputs`, so reservation transitions and their
chain are inside the existing gated claims, not a separate P3 proof.

Small gated trace size:

```text
before: 156,089 B
after:  157,433 B  (+1.3 KB)
```

Targeted tests: `unified_trace_proof_merges`, `unified_lr_sc`,
`unified_amo_lr_sc`.


### C: remove duplicate reservation batch

Reservation transitions are now in the unified gated claims, so the standalone
`AmoBundleProof.reservation` batch was removed. AMO/LR/SC bundles now contain
only their operation proofs; reservation presence is checked through the gated
claims.


### C: bind reservation address to CPU memory claims

`ReservationCpuRow` now constrains its reservation address bits to the CPU
memory adder output. For LR/SC rows this is the memory access address; for
non-memory rows both are zero. This ties the reservation chain to the same
memory claim used by the CPU/gated proof, not only to trace fields.

Targeted tests: `reservation_cpu_row`, `unified_lr_sc`, `unified_amo_lr_sc`.


### C: bind LR/SC value to CPU memory data

`ReservationCpuRow` now carries `value`/`has_value` and constrains, when
`has_value = 1`:

```text
value == cpu.memory.data_in
```

The trace builder sets it to `rd_val` for LR and to the memory write value for
SC. This binds the LR read / SC write data to the same CPU memory claim as the
address. The small gated benchmark is 155,833 B after the change.


`reservation_cpu_rows_from_trace` now marks `Sd` (and the other store widths) as
`is_invalidate`, so a store clears the reservation in the gated chain instead
of preserving it. Unified LR/SC tests still pass.


### C: AMO clears reservation in the gated chain

`reservation_cpu_rows_from_trace` now marks AMO rows as `is_invalidate`. A new
`amo_chain_rows_check` test builds LUI/ADDI/SD/ADDI/AMOADD.D/ADD/ADD/ADD rows and
checks every combined CPU+reservation relation. `unified_amo_lr_sc` also still
passes.


### A2: carry the gated opening value in the proof

`GatedCpuClaims` now stores `value: F2_128`, the evaluation of the gated witness
at the verification point. The verifier uses this value directly instead of
rebuilding the gated `z` and evaluating it. Prover still needs `z`; this removes
one witness dependency from verification.


### A2: gated verification no longer builds gated z

`reservation_claim_matrices` builds the gated matrices/layout from width and row
count only; the verifier constructs `GatedProveInput` with an empty `z`. Combined
with the proof-carried gated value, gated claim verification no longer depends
on gated witness values.


### A2 shape finding

A `CpuShape` with only `pc/op/imm/mem presence` reconstructs the CPU system for
simple Addi/Xor traces but not for LR/SC traces: those row constraints embed
memory address/value-derived structure. Adding the per-row values (rs1/rs2/rd,
memory addr/value/width/flag) reproduces the exact CPU constraint system, but
this shape is not succinct; it is effectively a compact trace.

Therefore A2 needs either a fixed CPU circuit that treats all such values as
variables (A2a), or a shape that carries the values and is not succinct (A2b).


### A2a: fixed ALU and memory CPU systems

The CPU row relation no longer pins ALU operands/results to constants:

```text
uniform_alu_row_relation(...)  -> uniform_alu_relation(width) + layout.witness(...)
```

Loads/stores now use the fixed `uniform_memory_row_layout(64)` with data as a
variable, instead of `uniform_load_row_relation`/`uniform_store_row_relation`
with address/value constants. `unified_lr_sc`, `unified_trace_proof_merges`, and
`unified_amo_lr_sc` pass; the gated benchmark is ~156 KB.

Branch/MUL/DIV/JAL rows still pin values and must be converted next.


### A2a: fixed branch CPU system

Added `uniform_branch_layout(width)` (no pc/imm pinning) and used it for branch
rows with `layout.witness(branch_op, pc, rs1, rs2, imm)`. `uniform_branch_relation`
keeps the pinned variant for existing callers. New
`unified_branch_round_trips` proves a taken BEQ. ALU, memory, and branch CPU
systems are now value-independent; MUL/DIV/JAL/JALR/AUIPC still pin values.


### A2a: fixed MUL/DIV CPU systems

MUL now uses `uniform_mul_relation(width)` + `layout.witness`; MULH/MULHSU/MULHU
use `uniform_mulh_relation(width, signed_a, signed_b)`; DIVU/REMU use
`uniform_div_relation(width)`; DIV/REM use `uniform_signed_div_relation(width)`.
The row systems no longer pin operands/results. New `unified_mul_div_round_trips`
proves MUL and DIVU traces.


### A2a: fixed JAL CPU system

`UniformJalLayout` now exposes `next`/`rd` output variables constrained to the
target/link sums. `uniform_jal_layout(width, increment)` builds the unpinned
system; runtime JAL uses it with `layout.witness(pc, imm)`. New
`unified_jal_round_trips` passes. JALR/AUIPC still pin values.


### A2a: fixed AUIPC CPU system

`UniformAuipcLayout` now has `value_out` variables constrained to the adder sum;
`uniform_auipc_layout(width)` leaves pc/imm as variables and `witness_at(pc,
imm)` fills the row. New `unified_auipc_round_trips` passes. JALR remains pinned.


### A2a: JALR fixed and zero-value shape check

`UniformJalrLayout` now exposes `pc_in`, `target_out`, `link_out`;
`uniform_jalr_layout(width, increment)` leaves values as variables and
`witness_at(pc, rs1, imm)` fills them. `unified_jalr_round_trips` passes.

With ALU/memory/branch/MUL/DIV/JAL/JALR/AUIPC systems fixed, zeroing every
value in `CpuShape` still reconstructs the same CPU constraint system for an
LR/SC trace (exact debug equality). AMO rows still pin values.


### A2a: zeroing shape values preserves the CPU system

The shape test now zeroes each value class independently (rs1/rs2/rd, memory
address, memory value) and compares the exact constraint debug for an LR/SC
trace. All variants match. This shows the CPU system can be reconstructed from a
value-free shape; the earlier value-free struct experiment was an implementation
bug, not a constraint dependency.


A first attempt to put the zeroed shape into `UnifiedTraceProof` and rebuild the
verifier CPU system failed with a lockstep mismatch on the LUI/ADDI/SD/LR/SC
trace. The field was reverted. The shape test still shows zeroed reconstruction
for the LR/SC/Add trace, so the remaining difference is specific to one of the
extra rows (likely ADDI/SD layout details) and needs isolated debugging.


The zeroed shape test was extended to the exact LUI/ADDI/SD/LR/SC/ADDI/SC
program and still reproduces the CPU constraint system and z length. A second
attempt to use it in `UnifiedTraceProof` nevertheless failed with a lockstep
inner mismatch, so the proof field was reverted again. The remaining difference
is not system constraints or z length; it must be in the claim/layout wiring.


### A2a: isolated shape claim test fails

A direct test generated CPU lockstep claims from the real trace system and then
verified them with the zeroed-shape system. The system debug, `num_vars`, z
length, and layout length all match, yet verification returns "lockstep inner
mismatch". This rules out shape/system reconstruction as the cause and points at
how `verify_lockstep_claims` consumes the system matrices or layout in this
path. The failing test was removed from the committed suite; the shape-system
equality test remains.


### A2a milestone: proof-carried value-free CPU shape

The root cause of the lockstep mismatch was the SC row: `row_cpu_relation` still
used `uniform_store_row_relation`, which pins address/value. Switching SC to the
fixed memory layout made the zeroed-shape system and the real system produce
identical SparseMatrix entries.

`UnifiedTraceProof.shape` now carries the zeroed `CpuShape`; the verifier rebuilds
the CPU system and witness length from it, with an AMO trace fallback. Proofs for
branch, MUL/DIV, JAL, AUIPC, JALR, and LR/SC all pass. The gated benchmark is
156,184 B (+95 B vs before the shape field).


### A2a: CPU-only verifier without a trace

`CpuShape::system_without_trace(width)` builds a synthetic `TraceRow` per shape
row and reconstructs the merged CPU system/witness length with no `Trace` input.
`CpuStatement { width, shape }` plus `verify_cpu_statement` verifies the CPU
lockstep claims against that system. The new
`cpu_statement_verifies_without_trace` test calls it successfully; this is the
first real succinct-verifier API (CPU claims only, no access/aux yet).


### A2a: gated claims in the trace-free CPU verifier

`GatedCpuClaims` now stores `cycles`; `GatedProveInput` carries it. The
trace-free `verify_cpu_statement` rebuilds the gated matrices from
`(width, cycles)` and verifies the gated claims with
`verify_lockstep_claims_with_matrices`. The test program asserts `gated` is
present and passes without a trace.


### A2a: LR/SC gated claims without a trace

`lr_sc_cpu_statement_verifies_without_trace` proves a LUI/LR.D/SC.D/ADD trace
and then verifies CPU + gated claims using only `CpuStatement { width, shape }`.
The gated reservation chain is included in those claims. Access/aux/opening are
still outside this API.


### A2a: CoreStatement verifies CPU + gated + access without a trace

Added `AccessStatement` (config, initial RAM/registers, memory events, compact
register ops) and `verify_access`, which builds synthetic witnesses and checks
the BinaryTwist access claims against the shared commitment. `CoreStatement`
combines it with `CpuStatement`; `verify_core_statement` verifies CPU, gated, and
access claims without passing a `Trace`. The new
`core_statement_verifies_without_trace` test proves a LUI/ADDI/SD/LD trace and
verifies with the statement. Shout/Router/opening remain outside.


### A2a: CoreStatement (CPU + gated + access)

`AccessStatement` rebuilds both BinaryTwist witnesses from a compact access
record. `verify_access_claims` returns RAM and register claims, and
`verify_core_statement` combines them with `cpu_statement_claims` (CPU + gated)
and, when no Shout/Router proof is present, checks the shared opening. The
`core_statement_verifies_without_trace` test passes without a `Trace`; opening is
skipped when Shout/Router tables are present because those claims are not yet in
the statement.


The core-statement test now tampers a shape PC and a memory-event value; both
`verify_core_statement` calls are rejected.


`UnifiedTraceProof` now records `shout_index`, `shift_router_index`, and
`store_router_index`, and `ProofBundle` preserves them. This is groundwork for
moving Shout/Router claims into the trace-free statement; no verification
behavior changes yet.


### A2a: AuxStatement for Shout/Router claims

`AuxStatement` carries config/rom/initial RAM/initial PC and compact `AuxRow`s.
Its synthetic trace rebuilds `BinaryShoutWitness` and `BinaryRouterWitness`
exactly (test compares debug). `verify_shout` / `verify_router` return the aux
claim points from the statement. `CoreStatement` optionally includes the aux
statement and verifies those claims.

Adding aux points back into the opening did not verify ("core opening
rejected"), so the core statement currently verifies the opening only when
`aux` is absent. The aux claim points or table indexes still have a mismatch to
debug.


### A2a milestone: full core opening without a Trace argument

`CoreStatement` now also carries the trace witness table. `verify_core_statement`
adds its segment points at `proof.trace_index`, includes aux Shout/Router points,
and verifies the shared Mosaic opening. `core_statement_verifies_without_trace`
passes with CPU + gated + RAM/register + Shout + Router + trace tables, without
passing a `Trace` to the verifier.

This is a statement-based verifier, not a succinct proof: the statement still
contains the trace witness, access records, and aux rows. But the verifier API
no longer needs the execution trace itself.


### A2a: trace claims move into the proof

`UnifiedTraceProof.trace_claims` now carries the trace table points/values
(generated from the trace witness at prove time). `CoreStatement` no longer
contains the full `TraceWitness`; `verify_core_statement` uses the proof-carried
claims. The gated benchmark is 156,515 B (+331 B) while the statement shrinks.


`CoreStatement` is serde-able again now that the trace witness was removed; the
core test serializes/deserializes it and verifies the decoded statement.


### A2a: commit initial/read/write Twist tables

`BatchTables` now includes `initial`, `read_value`, and `write_value` tables
(padded to powers of two, minimum 2). The unified Mosaic commitment adds these
three tables for both RAM and registers; auxiliary/gated/trace table indexes are
shifted accordingly. `unified_lr_sc`, `core_statement`, `aux_statement`, and
`unified_amo_lr_sc` pass. The benchmark is 156,771 B (+256 B).

This is the commitment prerequisite for proof-carried access evaluations. The
verifier still reads these vectors from the witness until the new eval fields
and points are added.


An attempt to add initial/read/write eval points directly to
`prove_binary_twist_claims` and `verify_binary_twist_claims` caused the shared P3
opening to reject. The prover and verifier point multisets did not match
(duplicate/missing register and RAM value-table points), so the experiment was
reverted to the committed table-extension state. The next attempt should derive
the points once in a shared helper used by both sides instead of editing each
side independently.


### A2a: shared Twist value-eval points

Added `TwistValueEvals`/`push_twist_value_points` and call it from both
`prove_binary_twist_claims` and `verify_binary_twist_claims`. The helper emits
three initial-table points, one read-value point, and one write-value point, so
the prover and verifier point multisets match. The benchmark is 159,203 B
(+2.4 KB). The eval values are still computed from the witness; the points are
the prerequisite for using proof-carried values.


### A2a: verifier uses proof-carried Twist value evals

`BinaryTwistRamProof` now stores `read_value_eval`, `write_value_eval`,
`initial_read_eval`, `initial_write_eval`, and `initial_update_eval`.
`verify_binary_twist_claims` uses those values instead of folding
witness.read_value/write_value/initial; the shared point helper binds them to the
opening. Benchmark: 159,363 B (+160 B). Address/increment/final tables and
`read_value`/`write_value` addresses still come from the witness.


### A2a milestone: witness-free BinaryTwist verification

`BinaryTwistRamProof` now carries every table evaluation the verifier needs
(boolean address bits, read-initial/history, write-base/history, final values,
initial/read/write value evals, cycle/address bits).
`verify_binary_twist_from_proof` derives its dimensions from the proof and does
not use a witness at all; `verify_binary_twist_claims` is a compatibility wrapper.
`access_claims_from_proof` verifies RAM and register claims from the proof, and
`CoreStatement` no longer contains `AccessStatement`. Benchmark: 161,187 B
(+1.8 KB). Aux Shout/Router statements are still linear.


### A2a: proof-only BinaryShout verification

`BinaryShoutProof` now carries dimensions, claimed read fold, address/is_32/valid
evals, and ROM column evals. `verify_binary_shout_claims` takes the witness only
for API compatibility and uses proof values for every check; the witness argument
is unused. Benchmark: 161,579 B (+392 B).


### A2a milestone: proof-only core verifier

`UnifiedTraceProof` now carries `width` and all aux table evals. BinaryTwist,
BinaryShout, and BinaryRouter verifiers are proof-only (witness arguments are
compatibility wrappers); `CoreStatement` is reduced to `{ width, shape }`, and
`verify_core_proof(proof)` verifies CPU, gated, RAM/register, Shout, shift/store
Router, trace claims, and the shared Mosaic opening with **no trace and no
caller-provided statement**.

The CPU shape is still carried per row in the proof, so proof size remains linear
in cycles; committing/compressing the shape is the remaining succinctness gap.
Benchmark: 161,523 B.


### A2a: value-free CpuShape in the proof

`CpuShapeRow` is now only `{ pc, op, imm, mem_width, mem_write }`; all register
and memory values were removed. This is possible because the SC row was fixed
earlier. The proof shape is therefore value-free (though still one row per
cycle). All targeted tests pass; benchmark 161,454 B.


### Packed Shout is now witness-blind

`verify_packed_shout(proof)` no longer takes a `BinaryShoutWitness`; it calls
`verify_binary_shout_from_proof` and checks the packed leaves/table opening
directly. `gated_aux` dispatches to it without a witness. Tests:
`packed_shout_round_trips`, `gated_aux` (3) pass. This closes the remaining
witness-derived column check noted for packed Shout.


### Packed Shout in the unified proof

`UnifiedTraceProof` now carries `packed_shout: Option<PackedShoutProof>`. The
prover no longer commits a reference Shout table and `shout` is `None`; the
verifier checks the packed proof (witness-blind) instead of the reference Shout
claims. Table indexes shift down by one and the reference shout check is skipped
when a packed proof is present. All targeted tests pass; benchmark 161,343 B
(slightly smaller than the reference-Shout build).


### D2: two-phase register encoding documented and tested

Added `docs/register-twist-equivalence.md`: each CPU row maps to two Twist
subcycles (read rs1; read rs2 then write rd), so both reads observe the pre-row
state and the write is ordered after both. This is an encoding/performance gap
versus the paper's single-cycle p=2 layout, not a soundness gap.
`register_twist_two_phase_shape` checks every row's read addresses/values and
odd-subcycle write. Standalone `prove/verify_binary_twist_ram` now commits/checks
all five tables and sorts points by table. Tamper test now mutates the proof eval
(not the witness), matching the proof-only verifier.


### Current P0 status after A2/D2/packed Shout

```text
A2  core verifier proof-only, value-free shape
    verify_core_proof(proof), no trace/statement
    remaining: shape still one row per cycle

D2  two-phase register encoding documented/tested
    single-cycle p=2 layout still not implemented

D7  packed Shout witness-blind and used by UnifiedTraceProof
    reference Shout table removed

E1  PackedMosaic aligned subcubes implemented
E2  lift implemented and tested
E3  batch_claims implemented and tested
E4  RingSwitchPackedBitPcs implemented and tested as a backend
    none of E1-E4 is yet the default unified opening
    a one-point batched opening prototype was only ~2% smaller

B1-B3 shared-matrix SIMD / native F2 dual relation still absent
D9/D10 bytecode/Shout-authenticated selectors, Router Q/Inc routing still partial
C1/C3/C4 bytecode/micro-PC/PC/reservation still trace/statement checked
```


### P1 D5: linear-time LT

Replaced the quadratic `lt_mle` double loop with the bitwise prefix formula

```text
LT(a,b) = sum_i (prod_{j>i} (1 + a_j + b_j)) * (1 + a_i) * b_i
```

for bits MSB to LSB. `lt_mle_matches_quadratic` checks bits 1..=5 against the
quadratic definition. All BinaryTwist/unified tests still pass; benchmark
161,343 B unchanged.


### D10 soundness gap: proof-carried public route evals

After making the Router verifier proof-only, `offset_public_evals`,
`width_public_evals`, `shift_public_eval`, and `valid_public_evals` are sent in
`BinaryRouterProof` and compared against the committed selector-column evals.
They are not bound to a committed public route table or to bytecode/Shout.

So the current Router proof proves consistency between two proof-chosen values,
not that the route matches the program. Fixing this needs committed public
route columns (offset/width/shift/is_shift/is_store) opened at the same points,
or a Shout/bytecode selector binding. Do not claim D10 complete before that.


### D10: commit and open the public route columns

The Router table now appends 10 committed public-route columns:

```text
offset_bits[3], width_one_hot[4], shift_code, is_shift, is_store
```

The prover/verifier add opening points for these columns at the offset, width,
shift, and valid challenge points, using the selector evals as expected values.
The proof-carried `offset_public_evals`/`width_public_evals`/`shift_public_eval`/
`valid_public_evals` fields were removed. The offset/width/shift/valid sumchecks
now reduce to `sum == 0`, which forces selector evals to equal the committed
public-route columns.

This closes the internal "proof-chosen public eval" gap. The route is still not
authenticated by bytecode/Shout, so D10 remains partial.


### B1: standalone shared-matrix CPU claim test

`shared_matrix_cpu_claims_verify` builds four ALU `GatedCpuRowInput` rows,
calls `gated_claim_inputs` (the shared block-matrix path), proves and verifies
the lockstep claims with `prove/verify_lockstep_claims_with_matrices`. No
per-row `merged_cpu_system` is used. This is the first direct B1 evidence.

Unified CPU integration is still blocked by coverage: `gated_rows_from_trace`
breaks/truncates at unsupported rows (Ecall, AMO, LR/SC), so the shared matrix
cannot yet replace the full per-row CPU system.


### B: Ecall/Nop coverage fallback

`gated_rows_from_trace` now maps unsupported ALU/AMO fallbacks to a zero ALU row
instead of breaking, and `gated_rows_from_trace_padded` pads the batch to the
next power of two with zero ALU rows. `padded_trace_covers_ecall` checks that an
Ecall tail is represented.

The padded batch does **not** yet prove successfully through
`prove_gated_dual_batch_bits` (sumcheck claim mismatch), so this is coverage-only;
the shared-matrix relation needs a real Nop selector or consistent PC/next-PC
witness before unified CPU integration.


### B: padded full-row gated batch now proves

`gated_rows_from_trace_impl(..., truncate)` now separates the legacy truncated
view from the full row list. `gated_rows_from_trace_padded` uses the full list
and pads with zero ALU rows to the next power of two.
`padded_alu_rows_prove` proves/verifies a 5-row trace (4 ALU + Ecall) padded to
8 rows through the shared-matrix dual backend. Ecall maps to a satisfiable zero
ALU row.

AMO/LR/SC still map to a zero ALU fallback rather than a semantic row, so their
CPU facets are not yet in the shared matrix.


### B: full CPU+reservation shared batch proves

`reservation_cpu_rows_from_trace_full` maps every trace row (padded to a power of
two) to `ReservationCpuInput`; unknown padding rows get zero reservation fields.
`full_reservation_rows_prove_shared` proves/verifies a 5-row (4 ALU + Ecall)
trace padded to 8 rows through `reservation_claim_inputs` and
`verify_lockstep_claims_with_matrices`.

Switching the unified gated input to these full rows succeeded functionally but
raised the benchmark to 180,247 B because the per-row CPU proof/table is still
present. Removing that duplicate requires making `cpu` optional and moving the
shared commitment onto `UnifiedTraceProof`; the CPU table index shift is the
remaining work. The protocol change was reverted for this commit.


### B groundwork: commitment on UnifiedTraceProof

`UnifiedTraceProof`/`ProofBundle` now carry `commitment: P3MosaicCommitment`
separately, and all access/aux/opening code reads `proof.commitment` instead of
`proof.cpu.commitment`. The CPU proof is still present, so the benchmark grows
to 161,607 B (+264 B) from the duplicated commitment. This is preparation for
making `cpu` optional and removing the per-row CPU table.


### B groundwork: Cpu stage is optional in protocol plan

`ProtocolPlan::unified` marks the Cpu stage optional, and
`check_virtual_claims` falls back to the union of all stage outputs when the Cpu
stage is absent. This removes the "missing stage Cpu" bundle check that blocked
making `UnifiedTraceProof.cpu` optional. The proof still emits the CPU claims,
so behavior and size are unchanged.


### B: cpu claims are optional in the proof type

`UnifiedTraceProof.cpu` is now `Option<LockstepClaims<P3MosaicCommitment>>`.
`ProofBundle` only emits a Cpu stage when present; `cpu_statement_claims`,
`verify_cpu`, and `verify_core_statement` skip the CPU lockstep/opening point
when it is absent. The prover still emits CPU claims, so existing tests and size
are unchanged; this makes the skip path compile and testable.


### B milestone: unified CPU uses the shared-matrix gated batch

`prove_cpu` now proves the gated shared-matrix claims when a full gated input is
present and sets `cpu = None`; the verifier skips the per-row CPU lockstep and
table-0 point. The unified gated input uses
`reservation_cpu_rows_from_trace_full` (all rows padded to a power of two with
Nop rows). `verify_core_proof`/`core_statement`, `unified_lr_sc`, and
`unified_amo_lr_sc` pass without CPU claims.

Benchmark: 176,128 B, larger than 161,343 B because the full gated z table and
reservation columns are bigger than the removed CPU proof/table points. This is
the architectural B switch, not a size win yet; removing the now-unused CPU
table 0 and shifting indexes is the next step.


### B: CPU table removed from the shared commitment

When the full gated batch is present, the prover no longer commits the per-row
CPU z table; the RAM table moves to index 0. `UnifiedTraceProof.ram_index`
records this, and access proving/verification use it instead of hard-coded 1.
Table-0 opening points are omitted. All targeted unified tests pass with no CPU
lockstep claims. Benchmark: 176,952 B (still larger than the per-row build
because the full gated z/reservation table dominates).


### B size diagnosis

The benchmark prints `gated table 11 cycles 4`. Table 11 has 1 column and
15 variables (32768 bits) for 4 padded rows, so the gated/reservation z table is
the new dominant committed object (~8192 bits per row) and explains the
176,952 B result. The per-row CPU table was only 7 variables. Shrinking the
reservation row's bit width (or not padding from 3 to 4 rows) is the size lever.


### B/E4 milestone: ring-switched packed CPU witness

The shared CPU claims now use `RingSwitchPackedBitPcs` instead of
`DirectBitPcs` for the gated batch. The bit witness is packed 128 bits per field
element; the gated claims carry a `RingSwitchOpening`. The separate gated Mosaic
table and its opening point are removed, and `GatedCpuClaims` stores
`proof: LockstepProof<..., RingSwitchOpening<...>>`.

All targeted unified/core/AMO tests pass. Benchmark:

```text
before ring switch: 176,952 B
after ring switch:  138,640 B
gated component:     71,577 B
```

This is below the old per-row CPU build (161,343 B). The remaining cost is the
ring-switch gated opening; shrinking div/sdiv row widths is now the next lever.


### Negative result: global P3SharedPcs parameter tuning

Changing `P3SharedPcs` to always use `with_params(90, 4, 16, 3)` makes every
unified test fail with "folding factor log 3 must be in 1..=1" on small tables.
The tuned parameters are only valid for large polynomials. An adaptive choice
would need the verifier to recover the parameter set from the commitment shape,
because verify() does not receive the values. The attempt was reverted; the
benchmark is still 138,640 B.


### Negative result: adaptive P3 params by table size

Tried selecting `(4,16,3)` only when `values.len().trailing_zeros() >= 4`.
Commit/open used the primary value length, verify used
`commitment.tables[0].num_variables`, and the existing shared-PCS test rejected
the opening, so the table shape does not recover the same choice reliably. The
attempt was reverted. P3 parameter tuning remains blocked on carrying the
parameter choice explicitly with the commitment/opening.


### P3 parameter tuning unblocked

`P3SharedPcs` now selects `P3BinaryPcs::with_params(100, 4, 16, 3)` when the
largest table has at least 4 variables, otherwise `P3BinaryPcs::new(100)`.
Commit/open use the max over all tables; verify uses the max committed table
`num_variables`, so the choice is recoverable from the commitment. The
shared-PCS tests and all unified tests pass.

Benchmark:

```text
before tuning: 138,640 B (gated 71,577)
after tuning:  123,928 B (gated 56,865)
```


### Negative result: merging Twist value tables

Tried merging the initial/read/write value tables of each Twist into one
three-column table padded to `max(cells, cycles)`. All functional tests passed
after padding the point vectors, but the benchmark grew from 123,928 B to
136,408 B (opening 54,337 -> 66,881) because the merged table has more variables
and the multi-column point openings cost more than the saved tables. Reverted.


### Negative result: separate Shout ROM commitment

Tried giving `PackedShoutProof` a separate P3 commitment/opening for the 12 ROM
metadata columns. It is sound for the metadata but adds a full P3 opening; the
packed Shout component grew from 4,586 B to 57,474 B and the total from 123,928
to 176,816 B. Reverted. Shout ROM metadata must share an existing P3 opening (or
be packed into the Shout bit table) rather than get its own.

Also fixed `packed_router::groups`: the q/hq group point indices were not updated
after the Router public-route values were appended; they are now 10/11 and
gated_aux passes again.


### Negative result: appending per-cycle Shout metadata columns

Tried appending the 12 per-cycle `read_value` metadata columns to
`BinaryShoutWitness::table()` and extending the read-point values/leaves. The
packed Shout leaf batch disagreed with the packed table value
(leaves=18, col_bits=5) because the packed bit layout pads the column dimension
to a power of two and the row/column point layout is derived from that padded
shape, so the simple column append does not preserve the packed-point layout.
Reverted. A correct integration must pack the metadata region with the same
column padding used by `table_bits`, or use a region suffix in the row point.


Follow-up debug: after appending 12 metadata columns the Shout table has 18
columns, `col_bits=5` (32 padded columns), leaves=18, and packed bits are padded
from 128 to 256 entries. The leaf batch still disagrees, so the mismatch is in
how the padded row/column point is formed for the packed table, not in the
metadata values themselves. A region suffix in the point (or a packed layout
helper shared by prove/verify) is still required.


Further instrumentation: after appending metadata, every leaf equals the
corresponding table column MLE at the read point, and every table bit equals the
packed bit at `cycle * 2^col_bits + column`. The disagreement is therefore only
in the evaluation point padding used by the packed opening, not in the data or
columns. The next fix must derive the padded row/column point from the same
helper that builds `packed_bits`, including the padded row bits.


A small probe confirmed `Mle::eval` treats `point[0]` as the least-significant
index bit (values[1] is selected by point [1,0]). So the packed Shout layout is
LSB-first; the remaining metadata mismatch is not due to point bit order.


### D10: committed bit-sliced Shout link columns

Raw Shout metadata fields are field-valued, so appending them to the bit-packed
table was invalid (packed bits only represent booleans). Instead
`BinaryShoutWitness::link_columns()` derives 12 boolean columns:

```text
store-width one-hot[4]
shift code bits[8] = (kind-1)*64 + shamt
```

These are appended to the Shout table, included in the read-point leaves, and
stored as `BinaryShoutProof.link_evals`. Packed Shout now round-trips with them.
Benchmark: 124,528 B (packed_shout 5,186 B, +600 B).

The remaining D10 step is to open the Router public-route columns at the Shout
read point and compare them with `link_evals`; this requires proving packed Shout
before the shared opening so the extra Router point can be added to the same
Mosaic opening.


### D10 domain mismatch: Router cycles are filtered, Shout cycles are full

Attempting to open the Router public columns at the Shout read point failed
because the domains differ: `BinaryRouterWitness::from_trace_mode` emits one
route row per **matching** shift/store row, so its `cycles` is the number of
routes padded to a power of two. Shout's `cycles` is the full trace row count
padded. In the core test the Shout link point had length 3 while the store Router
table had 1 variable. The opening was rejected.

To finish D10 the Router witness must either:

1. be full-cycle, pushing `RouterRoute::None` for every non-matching trace row;
2. or carry the original cycle index per route and link through a sparse/lookup
   sum.

Option 1 is the SIMD-consistent layout. The link columns and helper work is
otherwise ready.


### D10: Router is now full-cycle

`BinaryRouterWitness::from_trace_mode` now pushes exactly one route per trace row
(`RouterRoute::None` for non-matching rows), pads the route vector to the cycle
power of two, and keeps RAM updates for store rows. This makes Router `cycles`
match Shout `cycles` and fixes the earlier point-length mismatch (Shout len 3 vs
Router vars 1).

All binary_router, gated_aux, unified, and core tests pass; benchmark unchanged
at 124,528 B.

Remaining D10 step: comparing Shout `link_evals` with Router evals at two
different random points is not sound (equal evaluations at different points do
not imply equal vectors). The link still needs a **common-point bridge** or a
sumcheck equality, now possible because the cycle domains align.


### D10: Router-Shout link at the Shout read point

With Router now full-cycle, the common point is the Shout read point. The
prover generates packed Shout before the opening, then adds Router public points
at the Shout read point:

```text
shift Router:  shift_code column  <- Σ 2^i Shout link[4+i]
store Router:  width one-hot[4]   <- Shout link[0..4]
```

Both points go into the same shared Mosaic opening. The core statement and the
unified context append the same points before verifying the opening. This makes
the opening the equality proof (same table, same point, same columns).

Also fixed: `verify_unified_trace` now actually verifies the shared Mosaic
opening; previously the context only accumulated points.

All targeted unified/AMO/aux/gated/Router tests pass. Benchmark: 124,568 B
(+40 B).


### Shout ROM shared commitment and Router link

The full 12-column ROM table is now committed in the **same shared Mosaic
commitment** (no separate P3 opening). The Shout read/ROM claim is added at the
ROM point with `column_evals`, so the previously proof-carried Shout metadata is
now bound by the opening.

The Router-Shout link is also part of the same opening: at the Shout link point,
the store Router width one-hot and shift Router shift code are opened with
expected values taken from `BinaryShoutProof.link_evals`. The unified context now
verifies the shared Mosaic opening (previously it only accumulated points), and
both core and unified paths add the same link/ROM points before verification.

All targeted tests pass. Benchmark: 138,064 B (from 124,568 B); the +13.5 KB is
the cost of committing/opening the ROM table. Packed Shout component 5,226 B.


Added tamper tests for the committed Shout metadata: flipping a Shout
`link_evals` entry (Router-Shout link) and flipping a `column_evals` entry (ROM
claim) are both rejected by `verify_core_proof`.


### Negative result: per-table opening batching

Prototype `table_claim_batching_reconstructs_packed_value` works: per-table
PackedMosaic layout + batch_claims + a final P3 opening of all columns at the
batched row point. Integrated into the unified opening it reduced the opening
from 67,809 to 65,825 B, but the stored per-table claims and batching proofs add
about 19 KB and prove time rose from ~2 s to 11-17 s on the small benchmark.
Total grew to 154,976 B. Reverted; the prototype test stays in magnetar-pcs.


### Negative result: selective per-table batching

Batching only tables with at least 4 points reduced the opening from 67,809 to
65,249 B, but stored claims/batch proofs raised the total to 148,464 B. Raising
the threshold to 8 points gave 148,352 B (opening 66,241). In both cases the
claim storage outweighs the saved opening points; reverted.


### Compact batched opening

Verifier-side claims are now rebuilt from the existing claim points instead of
being stored in `TableBatchProof`. Points are ordered by a deterministic
`(table, columns, point-bytes)` key so prover and verifier build the same claim
list. Only tables with at least 6 points and at most 3 row bits are batched.

Benchmark: 138,064 -> 137,120 B; opening 67,809 -> 65,537 B. The size win is
real. Debug test time rose to ~10-26 s, but the release benchmark binary runs the
whole prove+verify in ~1.1 s; the extra cost is batching sumcheck plus an
all-column opening point per selected table.


### B3 first step: native F2 Merkle PCS

Added `F2NativePcs` in `magnetar-pcs/src/f2.rs`. It commits bits in a SHA-256
Merkle tree. At an **F2 point** the multilinear evaluation is exactly one
coefficient bit (for `r_i=0` only index bit 0 contributes, for `r_i=1` only bit 1),
so the opening is a Merkle path and the claimed value is the selected bit.

This is a genuine native-F2 opening (not the F2^128 embedding) for F2
challenges. Extension-field sumcheck challenges still need a lift/sumcheck layer;
that is the next B3 step. The prototype is tested for round-trip and tamper.


The vendored Ligerito implementation only supports `BinaryElem32`/`BinaryElem128`
coefficient and challenge fields and is an index-opening PCS, not an MLE
point-evaluation PCS. It cannot directly open the native F2 Merkle commitment at
an F2^128 sumcheck point. B3's extension-point opening therefore needs a new
native-F2 PCS (FRI/Ligerito over F2) or a different challenge strategy.


### B3 Step 2 started: binary Ligero code

Added `BinaryLigeroCode` (systematic `message || parity`, SHA-256-derived parity
rows) and `docs/native-f2-pcs.md` describing the native-F2 linear-functional PCS
plan. The code is committed with `F2NativePcs`; the Ligero random-column linear
test is the next milestone.


### B3 Step 2 prototype: Ligero linear-functional opening

`BinaryLigeroLinearProof` proves `v = Σ_j (Σ_i λ_i M[i][j])` over a bit matrix
committed by `F2NativePcs`. The prover sends the combined column vector `s`, the
verifier checks `v = Σ s_j`, and Fiat-Shamir-derived columns are opened (Merkle
paths for each row bit) and checked against `s_j`. Round-trip and tamper tests
pass. This direct-column variant is not yet the succinct parity-code Ligero
test: proof size is `O(columns + samples·rows·log k)`.


### B3 Step 2/3: coded Ligero extension-point opening

`BinaryLigeroCodedProof` interpolates each message row with the systematic
`BinaryLigeroCode`, commits the encoded matrix, and sends `s = λ·W`. The
verifier checks the parity equations over `F2_128`, checks `v = Σ s_j`, and
samples Fiat-Shamir columns to compare `s_j` with `λ·W[:,j]`; code distance makes
unsampled positions sound. Because `eq(r,index)` factorises as
`eq(r_low,col)·eq(r_high,row)`, setting `λ = eq(r_high)` and weighting the
message columns by `eq(r_low)` gives a native-F2 extension-point MLE opening.
The test compares it against a dense `Mle::eval` and passes.


### B3 Step 3: NativeF2LigeroPcs interface

`NativeF2LigeroPcs` wraps the coded Ligero projection into a PCS-shaped API:
`commit(bits)`, `open(bits, point ∈ F2^128^n)`, and
`verify(commitment, point, opening) -> Option<F2_128>`. The test compares the
opened value against a dense `Mle::eval` and checks that changing the low
coordinates changes the returned value. This is the interface a native F2
sum-check can call.


### B3 Step 4: native F2 bit-relation proof backend

`NativeF2BitPcs` implements the generic `Pcs` trait for bit-valued vectors: it
rejects non-0/1 values, commits them with `NativeF2LigeroPcs`, and opens at
`F2^128` points. `NativeBitBackend` (in `simd_f2.rs`) then proves a `BitRelation`
with the existing `prove_spartan`/`verify_spartan` reduction, but with native-F2
commitments/openings instead of the `F2^128` embedding. The XOR relation test
passes. Remaining B3 work: shared Virtual Spartan lockstep/inner sum-check with
the packed relation and CPU integration.


### Virtual Spartan lockstep with the native F2 backend

`NativeF2BitPcs` now implements `BitPcs`, so the existing lockstep reduction
(`prove_lockstep_claims_bits`: shared outer product over both relations, one
shared inner sum-check, one commitment/opening) runs with a native-F2 witness
commitment instead of the packed `F2^128` backend. The gated CPU bundle proves
and verifies with `NativeF2BitPcs` (test marked ignored because the prototype
Ligero opening takes ~205 s in debug). This is the lockstep integration point;
the unified CPU path still uses `RingSwitchPackedBitPcs`.


### Native F2 Ligero speedup: sparse parity

The dense parity matrix made encoding O(k²): the native gated-bundle test took
~205 s. Replacing each parity row with the XOR of 12 SHA-256-derived message
positions makes encoding linear and the same test runs in ~1.1 s. The test is no
longer ignored. The distance/proximity gap of this sparse code still needs
analysis; the dense construction is the fallback reference.


### Native F2 lockstep vs ring-switch size

With the sparse code, the native F2 gated-bundle test runs in ~1.1 s, but the CPU
lockstep proof is 534,656 B versus 49,056 B for `RingSwitchPackedBitPcs` on the
same 8-bit two-row bundle (about 11x). The native path is therefore kept as the
B3 reference backend, not the default unified CPU backend. Reducing this needs a
smaller codeword/sampling strategy or a native Ligero-like PCS with succinct
linear tests.


### C3/C4 soundness: gated batch verifier now binds rows

`verify_gated_dual_batch_bits` and `_with_pc` previously rebuilt the shared
matrices from `rows` but did not bind the witness to those rows. They now
recompute `gated_batch_bits`, commit them with the same backend, and compare the
commitment bytes with the proof before running the lockstep verifier. A test
that changes the PC of a row is now rejected (`gated_bundle_rejects_tampered_pc`).

The gated CPU row already constrains `next_pc` (sequential PC+4, jump/branch
targets) and the shared matrices chain `next_pc(instance)` to
`pc(instance+1)`, so PC linkage is inside the proof for this path. The
reservation relation is included in `ReservationCpuRow` on the shared-CPU path.


### Fix: chunked aux Shout point after link columns

Adding the 12 Shout link columns changed `total_columns` from `2a+2` to
`2a+2+12`, but the auxiliary Shout boolean point still opened all
`total_columns` while its value vector has only `2a+2` entries. The opening then
failed (`chunked aux opening rejected`). The boolean point now opens exactly
`2a+2` columns; the read point still opens all columns. All three chunked tests
pass again.

The chunked verifier also now rebuilds the chunk witness, commits it, and
compares the commitment bytes with `ChunkCpuProof.cpu.commitment` before
verification, binding chunk proofs to the supplied rows.


### C1 expansion plan

`preprocess::expand_bytecode` and `MicroOp { micro_pc, rv_pc, kind }` are in
place (identity expansion today). The executor/CPU-relation migration is
documented in `docs/c1-instruction-expansion.md`: trace rows need `micro_pc` and
`MicroOpKind`, the gated row needs a fetch selector with `next_pc = pc`, and
Shout must read by `micro_pc`. This is the next C1 step.


### A2 chunked: per-chunk CPU shape

`ChunkCpuProof` now carries a value-free `CpuShape`. The verifier rebuilds the
chunk CPU system from the shape (`system_without_trace`) instead of from the
trace rows, while still checking that the shape matches the supplied trace and
that the chunk witness commitment matches `ChunkCpuProof.cpu.commitment`.
Tampering a chunk shape is rejected.


### B5: CPU segment owners

`CpuWitnessSegment.owner` is now derived from the row kind:

```text
Load/Amo        -> Memory(Ram)
Store           -> Routing(Stores)
Branch/Jump     -> Pcs
Shift           -> Routing(Shifts)
other           -> Cpu
```

`cpu_segments_are_tagged_with_their_owner` covers the mapping. Merged row
system lengths are not powers of two (observed 511), so `padded_virtual_layout`
now pads each row segment to the next power of two, aligns it, and returns a
mapping back to the merged witness; `pad_values` places the witness in the
virtual layout. The metadata test builds this layout, splits claims, routes them
to owners, and verifies the `VirtualClaimRouter`.


### B5: owner-tagged gated layout and verifier routing

`reservation_claim_inputs` now builds a per-instance gated `WitnessLayout` with
owners: Memory(Ram), Routing(Stores/Shifts), Pcs, or Cpu. `GatedCpuClaims`
carries this layout, and the unified CPU verifier routes the lockstep segment
claims with `route_segment_claims_by_owner` and validates them with
`VirtualClaimRouter` before accepting the gated proof. This is integrated
routing/consumption validation; Twist/Shout/Router still need to consume the
routed values themselves.


### B5 semantic protocol design

The remaining B5 work is a schema change, not wiring: CPU segment claims are
evaluations of CPU row variables, while Ram/Router/Shout claims are evaluations
of separate tables at different points. `docs/b5-virtual-segments.md` describes
the target: split the CPU witness into component-owned virtual witnesses and
prove a public projection from each component table to its virtual segment
before reconstructing the CPU witness. Owner metadata, padded layouts, routing,
and consumption validation are already implemented.


### B5: projection metadata

Added `ProjectionKind { Identity, PcBits, RamBits, RouterBits }` and
`SegmentOwner::projection()`:

```text
Cpu       -> Identity
Memory    -> RamBits
Routing   -> RouterBits
Pcs       -> PcBits
```

`segment_owners_expose_their_projection` covers the mapping. This is the layout
metadata the shared segment protocol needs before reconstructing CPU z from
component tables.


### B5: generic padded virtual segment specs

`VirtualSegmentSpec` (offset/len/owner/projection) + `build_padded_virtual_layout`
build a power-of-two aligned virtual layout for arbitrary row subsegments;
`PaddedVirtualLayout::unpad_values` scatters a virtual witness back to the
merged original order. The CPU metadata test now round-trips
`pad_values`/`unpad_values` and still routes claims through
`VirtualClaimRouter`. This is the layout substrate for splitting a CPU row into
PC/RAM/Router subsegments.


### B5: variable-group virtual specs

`reservation_virtual_specs` splits each gated instance into contiguous
variable-group subsegments with owners/projections: alu, memory (Ram), shift
(Routing(Shifts)), branch (Pcs), mul/div/sdiv, pc (Pcs), tail/reservation, and
padding. The test `reservation_specs_cover_each_gated_instance` checks that the
segments cover every gated instance exactly and include Memory/Routing/Pcs
owners. This is the subsegment schema needed before reconstructing CPU z from
component claims.


### B5: PcBits projection verified

`pc_component_witness_matches_gated_pc_subsegment` builds a trace, extracts the
gated `ReservationCpuRow` PC subsegment, and compares it bit-for-bit with the
`PcTransitionRow` component witness. The PC projection is identity over the PC
bit range. RamBits/RouterBits projections remain.


### B5: RamBits data projection verified

`ram_data_bits_match_twist_read_value` builds a load trace, extracts the gated
memory `data` subsegment (accounting for `memory_offset`), and compares it
bit-for-bit with the BinaryTwist `read_value` low bits. The memory data bits are
the RAM value bits; the RAM address affine projection is also checked: gated address = `ram_base + 8 * word_index`, where `word_index` is the BinaryTwist one-hot read address.


### B5: RouterBits projection verified

`router_shift_bits_match_gated_shift_subsegment` compares the gated shift
subsegment with the Router witness for a shift trace: `is_shift` matches for
every cycle, and the gated shamt bits match the Router `shift_q` one-hot column.
Together with PcBits and RamBits data, each owner now has a verified projection
prototype.


### B5: virtual subsegments reconstruct CPU z

`reservation_specs_cover_each_gated_instance` now also fills a virtual witness
from the gated z subsegments, pads it through `build_padded_virtual_layout`, and
scatters it back with `unpad_values`; the result equals the original z. This
verifies the segment-to-CPU reconstruction mapping. The PC subsegments are now filled from the `PcTransitionRow` component witness
(not from z), padded, and unpad-rounded back to z; the reconstruction still
equals z. Other owners are still copied from z.


### B5: PC and RAM subsegments are component-filled

`reservation_specs_cover_each_gated_instance` fills the PC subsegment from the
`PcTransitionRow` component witness; `memory_subsegment_is_filled_from_twist`
fills the gated memory `data` and `adder.out` bits from the BinaryTwist
`read_value`/`read_address` (affine `ram_base + 8*word`). Both then pad the
virtual witness and unpad back to the original CPU z; the reconstruction equals
z. `shift_subsegment_is_filled_from_router` fills the gated `is_shift` and shamt bits from the Router `is_shift`/`shift_q` columns. PC, RAM and Router owners now all have component-driven virtual segment fill that reconstructs CPU z.


### B5: full-cycle RAM Twist witness

`BinaryTwistWitness::from_trace_full_cycles` emits one Twist cycle per trace row,
using an idle read at word 0 for non-memory rows. The test verifies one cycle per
row, `validate()`, and that memory-row `read_value`/`write_value` match the
event-indexed witness. This aligns the RAM domain with the gated/ Router cycle
domain for component claims.


`full_cycle_ram_twist_proves_and_verifies` proves and verifies a
`from_trace_full_cycles` witness with the existing BinaryTwist RAM prover,
confirming the full-cycle tables are valid proof inputs.


The full-cycle witness pads to the trace-cycle power of two and selects the idle
read cell as a zero, unwritten RAM word (error if none exists). With that sentinel,
`ram_read_value_eval_matches_gated_data_subsegment` confirms that the
BinaryTwist `read_value` column and the gated memory `data` subsegment evaluate
identically at the same cycle point. Idle rows no longer inject a nonzero cell 0.


### B5: memory owner split into addr/data subsegments

`reservation_virtual_specs` now emits `memory_addr` and `memory_data` as
Memory(Ram) segments containing exactly the gated adder-out and data bits, with
the remaining memory relation variables tagged Cpu. `memory_subsegment_is_filled_from_twist`
fills these subsegments from BinaryTwist `read_address`/`read_value` and still
reconstructs the original CPU z after pad/unpad.


### B5 aggregate segments design

Per-cycle owner subsegments have a different claim shape from component bit
columns over cycles. `docs/b5-aggregate-segments.md` describes the aggregate
virtual segment (`sources` gather, cycle-major field vectors) that makes
segment claims and component column evals identical at the same local point.
This is the next B5 schema step.


### B5: aggregate virtual segments

`VirtualSegmentSpec` now carries `sources: Vec<(offset, len)>`; `build_padded_virtual_layout`
concatenates them, `pad_values` gathers and `unpad_values` scatters. Memory owner
segments are aggregated across cycles (`memory_addr`, `memory_data`), while CPU
ranges remain per-cycle. The PC/RAM/shift fill tests and metadata round-trip pass
with the gather layout.


### B5: aggregate RAM claim from component bit columns

`batch_tables` now also exposes `read_value_bits` and `read_address_bits`
(per-bit columns over cycles). `aggregate_ram_claim_matches_component_bit_columns`
checks the aggregate `memory_data` segment evaluation against the weighted sum of
component bit-column evaluations at the cycle point; they match. This is the
claim-replacement equation for RAM data. `aggregate_ram_address_claim_matches_component_bit_columns`
does the same for `memory_addr`; the full-cycle witness records its `idle_word`
and `read_address_bits` zero the idle address, so the gated idle-zero address
projection matches.


### B5: bit-column P3 round-trip

`ram_bit_columns_commit_and_open` packs all `read_value_bits` and
`read_address_bits` columns into one P3 mosaic table, commits, opens at a cycle
point, and verifies the opening against computed column evaluations. This shows
the component bit columns are PCS-ready; the remaining step is to add their
proof-carried evaluations to the CPU claim reconstruction.


### B5: lockstep segment replacement API

Added `verify_lockstep_bits_with_replacements`: the verifier can override
individual layout segment claims (for example with component bit-column
evaluations) before reconstructing the full witness claim and checking the
lockstep inner product/PCS opening. The existing verifier calls it with no
replacements; a tampered replacement is rejected in the DirectBitPcs test.


`GatedCpuClaims` now carries `component_claims: Vec<Option<F2_128>>`, and the
unified CPU verifier calls `verify_lockstep_bits_with_replacements` with them.
The vector is currently all `None`; the next step is to fill memory_addr /
memory_data overrides from verified component bit-column openings.


### B5 proof integration boundary

The lockstep verifier checks CPU matrices at the same `ry` used to reconstruct
the committed witness. Component aggregate claims live in a **virtual layout**
(padded/gathered); replacing segment claims only works if `z` itself is ordered
by that virtual layout. Otherwise `reconstruct_segment_claim` reconstructs a
different vector than the matrix evaluation uses. Completing B5 therefore
requires making the virtual layout the primary gated witness and conjugating the
CPU matrices by the gather permutation (or building the matrices directly over
virtual segments). The current layout/replacement API is a prerequisite, not
sufficient by itself.


### B5: virtual witness is now the gated witness

Added `ScatterMatrix`: it maps virtual columns to original columns, reconstructs
the original witness for `mul_vec`, scatters `row_combination`, and evaluates the
permuted matrix MLE. `reservation_virtual_inputs` now returns the padded/gathered
`z`, virtual layout and mapping; `GatedProveInput` carries the mapping. The gated
prover and both verifier paths wrap the CPU matrices with `ScatterMatrix` and
prove/verify over the virtual witness. `core_statement`, `unified_lr_sc`, gated
bundle and chunked tests pass. This removes the B5 witness-ordering blocker;
component claim replacement is the remaining step.


### B5 virtual witness size

After making the virtual layout the gated witness, removing the redundant
`layout` field from `GatedCpuClaims` (the verifier recomputes it from width and
cycles) reduces the benchmark from 152,912 to 150,902 B; the gated component is
70,635 B. The remaining growth over the 137,120 B baseline is the per-owner
segment split and its claims.


### B5: component claims fill the virtual segments

`prove_cpu` keeps the gated `ry` (via `prove_lockstep_bits_with_point`) and
builds the aggregate RAM data/address vectors from the full-cycle BinaryTwist
witness. For each `memory_data`/`memory_addr` virtual segment it evaluates the
component vector at the segment's local point and writes
`component_claims[index]`. The verifier's
`verify_lockstep_bits_with_replacements` uses these values in the CPU claim
reconstruction. A load-only unified trace asserts that at least one replacement
is filled and that the proof verifies; the replacement equals the original
segment claim. Store rows currently skip the data replacement because gated data
holds the stored value while RAM `read_value` holds the old word.


### B5: component openings verify the replacements

`GatedCpuClaims` now carries a component P3 commitment/opening over the aggregate
`memory_data`/`memory_addr` columns. `prove_cpu` keeps `gated_ry` and commits the
component table; the verifier obtains `ry` from
`verify_lockstep_bits_with_replacements_point`, rebuilds the same local points
from the virtual layout, and verifies the component opening against the
replacement values. A tampered replacement is rejected. Load-only traces use
both columns; store traces still skip `memory_data` (gated store data is the
source value, not RAM `read_value`).

The component proof is a separate P3 opening, so the benchmark grows to
188,616 B. Moving the component table into the shared Mosaic commitment is the
next step to avoid the extra opening.


### B5 opening integration attempts (negative)

Two follow-up attempts were reverted:

1. Moving the component table into the shared Mosaic commitment and adding the
   component point at `gated_ry` made `core opening rejected`, even though the
   prover/verifier component columns and values matched. The P3 shared-opening
   interaction needs isolation (likely point/column ordering or table indexing).
2. Projecting store frames into the aggregate `memory_data` column (using
   `access.value`) still mismatched the gated `memory.data` segment claim, so
   store replacement remains disabled.

The stable state remains the separate component P3 opening (188,616 B) with
load-only data/address replacement.


### B5 shared opening isolation

`p3_component_table_multi_column_point` shows P3 handles a component table with
two columns opened at one point, even alongside a second table. Therefore the
shared-commitment failure is not a P3 multi-column limitation; it is in the
integration point list or table indexing.


`p3_component_point_with_many_tables` also passes: 12 single-column tables plus
the two-column component table, all opened in one P3 mosaic proof. The shared
integration failure is therefore in the unified point/batch wiring, not P3 table
count or multi-column support.


### B5: component table in the shared commitment

The earlier shared-opening failure was a point-lifetime bug: component points were
pushed during `prove_cpu`, but the later Access stage overwrites `self.points`.
The points are now appended at the end of `prove_register_and_trace` (after
Access/Shout/Routers) using the stored gated `ry`; the verifier appends the same
points in `verify_opening` (context) and in `verify_core_statement` (core).
`GatedCpuClaims` carries `component_columns`/`component_index`; the separate
component P3 commitment/opening is gone.

Benchmark: 188,616 -> 151,415 B; gated 108,349 -> 70,716 B. Load-only RAM
data/address replacements are covered by the shared opening and the tamper test
still rejects altered replacements. Store data replacement remains skipped.


### B5: store data and byte addresses

`gated_component_columns` now derives the component columns directly from the
gated row inputs: data = `access.value` for stores and `row.rd_val` for loads,
address = `access.addr` (byte address, lane included), zero on non-memory rows.
This matches the gated `memory.data`/`adder.out` bits exactly for both loads and
stores, so `memory_data` replacement is no longer skipped. The column is a
committed gated-memory component table (for stores it represents the store
source, not RAM `read_value`); routing that value to the register component is a
later paper-fidelity step.


### B5: PC aggregate replacement and shared component columns

`reservation_virtual_specs` now has an aggregate `pc_bits` segment (one source per
cycle) owned by Pcs. The shared component table gains a third PC column, built
from the gated row PCs. `gated_component_columns` now derives data/address/PC
from the gated inputs themselves (Memory value and rs1+imm; row PC), so loads,
stores and padding rows match the gated virtual segments exactly. Component
claims include `memory_data`, `memory_addr` and `pc_bits`; all are covered by the
shared opening. Benchmark: 151,415 -> 151,124 B; gated 70,185 B.


### B5: Router shift aggregate replacements

The per-cycle shift relation is split into per-kind non-shamt ranges plus
aggregate `shift_sll`/`shift_srl`/`shift_sra` segments (one shamt slice per
cycle). A second component table holds the three shamt columns padded to a power
of two; `gated_shift_claims` evaluates them at the virtual segment points and the
prover/verifier add the shift table point to the shared Mosaic opening. The
`is_shift`/selector bits stay per-cycle (shift_sel). Benchmark: 151,124 ->
152,098 B; gated 70,999 B. The shift split adds four claim segments and a small
third table.


### B5: shift-active replacement

`shift_sel` is split into `shift_sel_lo`/`shift_one`, and an aggregate
`shift_active` segment (one `is_shift` source per cycle) is backed by a
one-column component table. The point is added to the shared opening. Benchmark:
152,098 -> 152,556 B; gated 71,521 B. Together with memory/PC/shift shamt, the
gated virtual segments for the main architectural components are now covered by
committed component claims; the remaining per-cycle CPU/branch segments stay in
the CPU relation.


### C7: unaligned within a word

`magnetar-executor` and `magnetar-cpu` no longer require natural alignment. They
accept any access whose `lane + width <= 8` (the BinaryTwist lane model), and
still reject accesses that cross an 8-byte word. `allows_unaligned_within_word_
loads_and_stores` covers execution; `unaligned_within_word_trace_proves` proves
and verifies a `Lw` at `ram_base + 2` through the unified path. Cross-word
unaligned accesses remain an extension.

### B5 branch replacement (negative)

Aggregating the whole branch relation into a component table works in `core`,
but adds ~46 KB to the opening (152,556 -> 198,832 B), so it was reverted. The
branch segment remains a CPU/Pcs claim; memory/PC/Router components stay on the
shared component tables.


### D10/B5 fallback: standalone shift Router opening

A shift-heavy unified trace exposed a P3 shared-opening failure: including the
276-column shift Router table and its 13 claim points in the shared Mosaic
opening made even `open_mosaic`/`verify_mosaic` on the same inputs return false
(`prover self verify Ok(false)`); the same table verifies standalone. The shift
Router is therefore committed/opened standalone inside `BinaryRouterProof`
(`prove_binary_router`), the shared commitment keeps a 2-cell placeholder table
to preserve indexes, and the verifier checks the standalone opening in both core
and trace paths. `shift_program_unified_proof_round_trips` covers a Slli/Srli/Xor
program. The Shout-to-shift-Router link is skipped while the shift router is
standalone; store Router and all shared component openings are unchanged. The
shift proof is ~216 KB at width 8 versus 152 KB for the no-shift benchmark.


### G3: incremental workload suite

`magnetar-testkit/examples/workload_suite.rs` runs four representative
workloads through the unified path (width 16):

| workload | rows | bytes | prove ms | verify ms |
| --- | ---: | ---: | ---: | ---: |
| fibonacci | 10 | 113,383 | 8,257 | 1,940 |
| memory | 5 | 126,312 | 7,212 | 976 |
| shifts | 5 | 217,168 | 3,990 | 975 |
| alu | 25 | 127,775 | 17,306 | 3,902 |

The shifts row exercises the standalone shift-Router fallback. This is a
stepping stone toward the paper's 15-workload suite, not a replacement.


### P3 shift-Router shared opening: isolation status

`router_shape_plus_large_table_round_trips` reproduces the shift Router table
shape (3 vars x 276 columns), two distinct row points, 12 opening batches and a
second 9-var table. P3 opens and verifies this synthetic schedule. The real
failure therefore depends on additional unified tables/schedule state, not just
the router table shape or multi-point batches; the standalone shift-Router
fallback stays in place until the exact combined schedule is minimized.


### G3: branch workload

The suite now also runs a branchy program (Beq/Bne loops, 19 rows, 115,367 B
at width 16). All five workloads prove and verify. A backward-branch Fibonacci
variant was dropped from the probe because its hand-written immediate pointed at
the wrong byte offset (cycle limit), not because of a proof failure.


The suite now includes a backward-branch countdown loop (8 rows, 97,639 B at
width 16) and a branchy Beq/Bne workload (19 rows, 115,367 B). All six
workloads prove and verify.


### Shift Router shared opening fixed

Root cause was two indexing bugs, not P3:

1. `next_table` was initialized to 6 and incremented manually. When the Shout ROM
   table was also pushed, the shift/store Router indexes no longer matched their
   positions in `mosaic_tables`; shift Router points were applied to the wrong
   table.
2. `shout_router_link_claims` used column `total - 3` for the shift code, but the
   Router table appends shift_code followed by three offset and four width
   columns. The link must use `total - 8`.

Both are fixed; indexes now come from `mosaic_tables.len()`. The shift Router is
back in the shared Mosaic opening, its Shout link is restored, and the standalone
fallback/placeholder is removed. The shift workload drops from 217,168 to
128,600 B (width 16) and `shift_program_unified_proof_round_trips` passes.


### C2: intra-instance cross-step constraints

`grouped_gated_system` builds one SIMD instance over `group` consecutive cycles:
the per-row relation is replicated block-diagonally (tight block stride), and
cross-step rows enforce `next_pc(row i) == pc(row i+1)` with the per-row
constant-one variable. `grouped_gated_system_links_consecutive_cycles` checks
that the grouped witness satisfies the combined system and that flipping the
next row's PC is rejected. Boundary links between instances, PCS/witness layout
integration, and the runtime grouping policy remain open.


### C2: grouped lockstep proof

`grouped_simd_lockstep_proves` builds a four-cycle trace with two grouped SIMD
instances (two cycles each), adds `next_pc -> pc` boundary rows between the
instances as extra shared-matrix rows, and runs a full lockstep proof over the
grouped witness. Verification passes; flipping the first PC of the second
instance makes proving fail. This exercises the multi-cycle base relation,
intra-instance cross-step rows, and inter-instance boundary rows together.
Runtime layout/PCS grouping and the virtual claim layout are still open.


`reservation_grouped_lockstep` packages the grouped witness, the two grouped
shared-matrix relations (inter-instance boundary rows included), and a
per-instance `WitnessLayout`. `grouped_lockstep_layout_round_trips` commits that
layout and runs `prove_lockstep_bits`/`verify_lockstep_bits` end to end. The
grouping is not yet selected by the unified runtime path.


`grouped_lockstep_supports_four_cycles_per_instance` runs the same grouped
lockstep path with group=4 over an eight-cycle trace, checking the helper is not
specific to pair grouping.


`group_virtual_specs` maps the cycle-major virtual segment sources into grouped
instance order (dropping per-row padding and adding a group-padding segment).
`grouped_virtual_layout_round_trips` checks the gather/scatter round trip, and
`grouped_virtual_lockstep_proves` wraps the grouped matrices in `ScatterMatrix`
against that layout, proves/verifies, and rejects a tampered second-instance PC.
C2 now has a grouped virtual-layout lockstep path; the unified gated path still
uses group=1 because grouped component claims are not yet reordered.


`grouped_component_claims_match_virtual_segments` evaluates the existing
cycle-major component columns at the grouped virtual layout's local points and
checks every filled replacement equals the corresponding grouped segment claim.
This shows the B5 component tables remain valid under C2 grouping; the unified
gated path still needs to select the grouped matrices/layout.


### C2: grouped path enabled in the unified gated prover

The gated prover now selects `group=2` when the padded cycle count is at least
four and even; otherwise it keeps `group=1`. `reservation_grouped_virtual_inputs`
builds the grouped witness/matrices and the grouped owner-segment virtual layout;
the core and trace verifiers rebuild the same grouped view (a dummy-row view is
used when no rows are available) and wrap the matrices with `ScatterMatrix`.
`GatedCpuClaims` carries the group size. Grouped component claims were checked
against the grouped segment values, and the workload suite passes with the
grouped path. The no-shift benchmark is 152,687 B (group field/layout overhead
about 131 B); workload prover times drop noticeably (e.g. fibonacci 8.2s -> 5.8s,
branchy 17.1s -> 11.7s, loop 3.9s -> 2.9s).


### C2: configurable SIMD group

`prove_unified_trace_group` / `Orchestrator::prove_group` select a group size
explicitly; `GatedCpuClaims.group` drives both core and trace verification.
The default remains `choose_group = 2` for at least four even cycles and 1
otherwise. `group_four_unified_proof_round_trips` proves/verifies group=4
through both verifier entry points. A 32-cycle width-8 comparison
(`group_compare`) gives group=2: 127,327 B / 6.0 s and group=4: 128,031 B /
6.0 s, so group=2 stays the default.
