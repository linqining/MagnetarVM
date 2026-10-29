# Streaming Selected Prover / PCS 重写交接文档

状态：待实现  
分支：`virtual-claims-rewrite`  
基线 commit：`62d135a`  
适用目标：RV64（`WIDTH=64`）proof-only verifier 8 ms 级验证  
当前阻塞：RV64 selected prover 内存爆炸，2^15/2^16 无法运行

---

## 1. 背景与验收前提

项目最终目标是通用程序 zkVM，必须是 RV64：

```text
width = 64
```

`width` 是 CPU/PC/ALU 变量的 bit width，不是字节数：

- `width=8`：只约束低 8 bit，是 8-bit 截断机器，不是 RV64；
- `width=64`：完整 RV64 变量宽度。

之前记录的所有 `735 ms / 354,979 B / selected 11.8 ms` 都是 `width=8` 的结果，**不能用于 RV64 验收**。

论文 Magnetar（ePrint 2026/2423）自身在 2^22 规模下 prover peak RSS 约 **6.4 GiB**（§6.4 / Table 6）；100 GiB 主要是评测 Jolt 等系统的内存预算（§6.5），不是 Magnetar 的要求。

---

## 2. 当前实测状态

### 2.1 RV64 可运行的小规模

```text
WIDTH=64, ADDS=4095 (2^12)
prove  ~151 s
verify ~316 ms
proof  372,596 B
```

### 2.2 RV64 内存测量

```text
WIDTH=64, ADDS=1023 (2^10)
bits = 8,388,608
rows = 16,777,216
cols = 8,388,608
rows = 2 * cols
```

```text
WIDTH=64, ADDS=8191 (2^13)
selected prover peak RSS = 20,887,732,224 B ≈ 20.8 GB
随后被 OS kill
```

selected 阶段耗时（2^13）：

```text
selected commit            1.67 s
selected matvec            7.71 s
selected mle               5.33 s
selected product6         53.99 s
selected row-combinations  1.97 s
selected product2         13.80 s
selected claims          101.74 s
selected open             12.64 s
```

### 2.3 RV64 2^15 / 2^16

```text
ADDS=32767: killed
ADDS=65535: killed
```

按当前线性维度外推 2^16：

```text
bits ≈ 5.37e8
rows ≈ 1.07e9
cols ≈ 5.37e8
```

---

## 3. 当前实现的数据流

入口：

- `crates/magnetar-runtime/src/simd_dual.rs`
  - `prove_dynamic_segmented_trace`（约 5653 行）
  - 构造 `bits: Vec<bool>`、`segmented_dynamic_row`、`gated_shared_matrices`
  - 调用 `prove_lockstep_bits`
- `crates/magnetar-runtime/src/protocol.rs`
  - `selected_backend()`（1631 行）
  - 返回 `RingSwitchPackedBitPcs<P3BinaryPcs>`
- `crates/magnetar-proof/src/spartan.rs`
  - `prove_lockstep_bits_with_point`（1480 行）
  - `prove_lockstep_claims_bits`（1150 行）
- `crates/magnetar-proof/src/simd.rs`
  - `SharedBlockMatrix`：base sparse matrix + instances + extra rows
  - `LazyExtraRows::Gated`：verifier-only lazy extra rows
- `crates/magnetar-proof/src/bit_pcs.rs`
  - `BitPcs` trait（13 行）
  - `RingSwitchPackedBitPcs`（577 行）
  - `pack`/`pack_scalar`/`pack_neon`/`pack_avx2`

当前关键路径：

```text
bits (Vec<bool>)
  -> z: Vec<F2_128>                       (完整复制)
  -> az0,bz0,cz0,az1,bz1,cz1              (六个完整 matvec 向量)
  -> 六个 Mle::new(az.clone())            (每个再复制一份)
  -> eq_values: Vec<F2_128>               (rows 长度)
  -> prove_product6(...)
  -> row_combinations_parallel            (六个 cols 长度向量)
  -> left_values: Vec<F2_128>             (cols 长度)
  -> prove_product2(left_values, z.to_vec())
  -> split_segment_claims(layout, z, ry)
```

---

## 4. 内存为什么爆炸

用 2^16 RV64 估算：

```text
bits = 5.37e8
rows = 2 * bits ≈ 1.07e9
cols = bits ≈ 5.37e8
```

F2_128 每个 16 B：

```text
z                        bits * 16 ≈ 8.6 GB
六个 matvec 向量          rows * 16 * 6 ≈ 102 GB
六个 MLE 拷贝            另 ≈ 102 GB
eq_values                 rows * 16 ≈ 17 GB
六个 row-combination      cols * 16 * 6 ≈ 51 GB
left_values              cols * 16 ≈ 8.6 GB
bits                      ≈ 0.5 GB（Vec<bool>）
```

即使部分临时向量被释放，峰值也会在 **150–200 GB 以上**。

当前实现还存在两个放大因素：

1. `prove_lockstep_claims_bits` 里 `Mle::new(az0.clone())` 会让每个 matvec 向量在内存中同时存在两份；
2. `SharedBlockMatrix` 的 extra rows 在 prover 路径仍然是 materialized `Vec<Vec<(usize, F2)>>`，2^16 下额外占大量内存。

---

## 5. 重写目标

### 5.1 硬目标

```text
RV64 WIDTH=64
2^16 可实际运行
peak RSS 目标：
  硬上限 < 100 GiB
  推荐 < 20 GiB
```

### 5.2 必须保持不变

```text
1. LockstepProof wire format 不变
2. commitment 字节不变
3. transcript 顺序/domain separation 不变
4. 现有 verifier 可以验证新 prover 产生的 proof
5. proof 语义、soundness 不变
```

### 5.3 可接受的变化

```text
prove 时间可以变慢
CPU 利用率可以变化
内部函数/模块可以新增，但不要改 proof format
```

---

## 6. 推荐实现路线

### Milestone 1：prover 使用 lazy extra rows

当前：

```rust
gated_shared_matrices(...) -> Vec<Vec<(usize, F2_128)>>
```

prover 路径仍会 materialize 每个 extra row。

建议：

```text
1. 复用 LazyExtraRows::Gated 描述
2. 为 SharedBlockMatrix 实现 prover 所需的 streaming 接口：
   - matvec_bits
   - row_combination_chunk
3. mul_vec / row_combination 不能再要求完整 extra Vec
4. 保留 eager 路径作为 fallback/测试对照
```

验收：

```text
width=64, 2^12/2^13 下 peak RSS 明显下降
proof 与旧实现一致（同输入下）
```

### Milestone 2：bit-addressable witness（去掉完整 F2 z）

当前：

```rust
let z = bits.iter().map(|bit| F2_128::from(...)).collect::<Vec<_>>();
```

建议：

```text
1. 新增 BitWitness（Vec<u64> 或 &[bool] 包装）
2. 提供按 chunk 生成 F2 的接口：
   - for_each_f2_chunk
   - get_f2(index)（尽量少用）
3. matvec 直接用 bits，不再要求 z: &[F2_128]
```

注意：

```text
不要一次性构造完整 z
```

### Milestone 3：streaming matvec

把：

```text
az0 = a0.mul_vec(z)
...
```

改为：

```text
matvec_chunk(matrix, bits, start, end) -> Vec<F2_128>
```

或者：

```text
for_each_matvec_row(matrix, bits, |row, value| ...)
```

要求：

```text
- 不保存六个完整向量
- 支持按行 chunk 重新计算
- SharedBlockMatrix 的 lazy extra rows 直接参与计算
```

### Milestone 4：streaming sumcheck

当前 `prove_product6(eq_values, az0..cz1)` 和
`prove_product2(left_values, z)` 都要求完整向量。

推荐方案（实现者可二选一）：

#### 方案 A：每轮从 bits/matrices 重算（简单，慢）

```text
for round in 0..row_bits:
  for fixed univariate evaluation t:
    sum over rows in chunks:
      compute Az/Bz/... from bits and matrix chunk
      multiply by eq(tau, row)
  derive round polynomial
```

优点：

```text
实现直接，内存 O(chunk)
```

缺点：

```text
matvec 重复 log(rows) 次，prove 时间上升
```

#### 方案 B：multi-pass blocked sumcheck（推荐）

```text
1. 把 rows 切成能放内存的 block
2. 每轮对所有 block 做 folding/统计
3. 只保留 round polynomial 和当前挑战
4. 不保留完整 folded vectors
```

需要新增：

```text
prove_product6_streaming
prove_product2_streaming
folded_chunk 状态
```

验收：

```text
proof/transcript 与旧实现一致
```

### Milestone 5：terminal claims

当前：

```text
az0_mle.eval(rx)
```

不要保留六个完整 `Mle`。

改为：

```text
az_mle(rx) = Σ_row eq(rx, row) * Az(row)
```

按 row chunk 流式计算。

### Milestone 6：inner sumcheck / row combination

当前：

```text
row_combinations_parallel(...) -> 六个 cols 向量
left_values: Vec<F2_128>
```

改为：

```text
row_combination_chunk(matrix, rx, start, end)
left_values_chunk(...)
```

然后对 chunk 做 streaming fold。

### Milestone 7：segment claims

当前：

```text
split_segment_claims(layout, z, ry)
```

改为逐 segment 计算：

```text
for segment in layout.segments:
  compute segment MLE at segment local point from bits chunk
```

不要构造完整 z。

### Milestone 8：PCS

当前 `RingSwitchPackedBitPcs` 的 `pack` 产物大小是 `bits/8` 量级，
2^16 下约 64–70 MB，**不是主要瓶颈**。

建议先保留 PCS 的完整 packed 向量，只确认：

```text
1. pack 不额外保存多份 bits
2. open 不保存不必要的完整 F2 向量
3. commit/open 的临时 codeword 峰值可接受
```

如果 PCS 本身成为瓶颈，再扩展 `BitPcs`：

```rust
trait StreamingBitPcs {
    fn commit_chunks(...);
    fn open_chunks(...);
}
```

---

## 7. 内存预算建议

### 2^16 RV64 目标

```text
bits (packed)               ~67 MB
PCS packed                  ~67 MB
PCS codeword/temp           < 2 GB
chunk field vectors         < 1 GB
matrices lazy metadata      < 1 GB
其他                        < 2 GB
------------------------------------
推荐 peak RSS               < 10 GB
硬上限                      < 100 GiB
```

---

## 8. 测试与验收

### 8.1 正确性

```text
1. cargo test -p magnetar-runtime --lib
2. paper_mode integration test
3. width=8 小规模 proof 与旧实现字节一致
4. width=64 2^12 proof 用现有 verifier 验证通过
```

### 8.2 内存

```bash
/usr/bin/time -l env WIDTH=64 ADDS=65535 \
  cargo run --release --offline -p magnetar-testkit \
  --example paper_unified_bench
```

记录：

```text
peak RSS
prove time
verify time
proof bytes
```

### 8.3 RV64 规模阶梯

```text
2^12  ADDS=4095
2^13  ADDS=8191
2^14  ADDS=16383
2^15  ADDS=32767
2^16  ADDS=65535
```

每级必须：

```text
1. 不 OOM
2. proof 可验证
3. 记录 peak RSS
```

---

## 9. 风险与开放问题

1. `prove_product6/product2` 的 transcript 顺序必须保持完全一致；
2. 流式 matvec 与矩阵 row ordering 必须一致；
3. `SharedBlockMatrix` 的 lazy extra rows 目前 verifier-only，prover 侧需要补 mul_vec/row_combination chunk；
4. P3/Ligerito commit/open 是否会在内部 materialize 大向量，需要实测；
5. RV64 2^16 的 prove 时间可能显著上升，先保内存，再优化速度；
6. 完成 streaming 之后，才继续 Virtual Spartan / virtual claim routing / 8 ms verifier。

---

## 10. 关键文件清单

```text
crates/magnetar-runtime/src/simd_dual.rs
  - prove_dynamic_segmented_trace
  - gated_shared_matrices(_lazy)
  - segmented_dynamic_row
crates/magnetar-runtime/src/protocol.rs
  - selected_backend
crates/magnetar-proof/src/spartan.rs
  - prove_lockstep_bits_with_point
  - prove_lockstep_claims_bits
  - prove_product6 / prove_product2
  - row_combinations_parallel
crates/magnetar-proof/src/simd.rs
  - SharedBlockMatrix
  - LazyExtraRows
  - mul_vec / row_combination / eval_mle
crates/magnetar-proof/src/bit_pcs.rs
  - BitPcs
  - RingSwitchPackedBitPcs
crates/magnetar-testkit/examples/paper_unified_bench.rs
```

---

## 11. 交接状态

```text
branch: virtual-claims-rewrite
base commit: 62d135a

已验证：
  RV64 width=64 2^12 可运行
  RV64 width=64 2^13 peak 20.8 GB 后被 kill
  RV64 width=64 2^15/2^16 OOM

未完成：
  memory-efficient selected prover
  RV64 2^16 baseline
  Virtual Spartan / virtual claim routing
  verifier 8 ms
```

## 12. 本阶段非目标

```text
1. 不改 verifier 逻辑
2. 不改 LockstepProof wire format
3. 不改 commitment/transcript
4. 不实现 Virtual Spartan
5. 不实现 8 ms verifier
6. 不追求 prove time 最小化
```

本阶段只解决：

```text
RV64 width=64 selected prover/PCS 内存可运行
并建立 2^16 RV64 baseline
```

## 13. 完成标准

```text
1. RV64 2^16 (WIDTH=64, ADDS=65535) 不再 OOM
2. peak RSS 记录并低于 100 GiB（目标 <20 GiB）
3. proof 可被现有 verifier 验证
4. width=8 小规模 proof 与旧实现字节一致
5. 现有测试套件通过
6. 2^12/2^13/2^14/2^15/2^16 阶梯结果写入 docs
```

本文件是 streaming selected prover/PCS 重写的交接说明；实现应从 Milestone 1 开始，先消除 eager extra rows 和完整 `Vec<F2_128>` 中间向量，再建立 RV64 2^16 基线。
