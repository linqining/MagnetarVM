# Magnetar：基于标准哈希的高速后量子 RV64 zkVM

**中文译稿**

> 原文：Srinath Setty, *Magnetar: High-speed post-quantum RV64 zkVM from standard hashes*, IACR ePrint 2026/2423，2026 年 10 月。
>
> 译者说明：
> 1. 本文按论文章节顺序翻译，保留定理、引理、构造、公式和关键表格；为可读性，部分长证明按原文结构作“译述”，并标注“证明要点”。
> 2. 公式使用 LaTeX 记号；`F2` 表示二元域，`F2^128` 表示其 128 次扩域。
> 3. 参考文献保留英文原貌；正文中的引用编号与原文一致。
> 4. 表格中的实验数据按原文抄录；部分重复性表格作了合并/摘要，并注明。

---

## 目录

- [摘要](#摘要)
- [1 引言](#1-引言)
  - [1.1 zkVM 的设计空间](#11-zkvm-的设计空间)
  - [1.2 我们的工作：Magnetar](#12-我们的工作magnetar)
  - [1.3 密切相关工作](#13-密切相关工作)
- [2 Magnetar 技术概览](#2-magnetar-技术概览)
  - [2.1 端到端协议](#21-端到端协议)
  - [2.2 Magnetar 的核心思想](#22-magnetar-的核心思想)
- [3 预备知识](#3-预备知识)
- [4 Magnetar 的证明系统构建模块](#4-magnetar-的证明系统构建模块)
- [5 Magnetar 构造](#5-magnetar-构造)
- [6 实现与评估](#6-实现与评估)
- [附录 A 符号表](#附录-a-符号表)
- [附录 B 术语表](#附录-b-术语表)
- [参考文献](#参考文献)

---

## 摘要

本文描述 **Magnetar** 的设计、实现与实验评估：这是一个针对 **RV64I 程序执行**的透明证明系统，也就是一个 zkVM。Magnetar 是首个同时满足以下三个性质的 zkVM：

1. **通用证明**：Magnetar 证明编译到通用 **RV64I** ISA 的程序。用 Rust 或 Go 写的 EVM 实现因此可以跑在 Magnetar 里，从而为现有 EVM 智能合约生成 zkEVM 证明。
2. **基于哈希、后量子安全**：密码学安全性只依赖标准哈希函数（如 SHA-256 或 SHA-3），不依赖椭圆曲线、格、Poseidon/Poseidon2 之类电路友好哈希，也不依赖对 Reed–Solomon 码邻近性间隙的猜想。
3. **高效递归**：验证 proof 的工作主要是计算标准哈希；Magnetar 的证明引擎 BinarySpartan 很适合这类 bit-oriented 计算，因此“验证一个 proof”本身就是一个高效的 proving workload。

与已有通用 zkVM 不同，Magnetar 不依赖电路友好的代数哈希、椭圆曲线或格假设，也不依赖猜想的 Reed–Solomon 邻近性间隙。即使是被普遍称为“hash-based”的 zkVM，也常在核心证明机制中依赖椭圆曲线或格假设，或者只有约 100 bit 安全性，或者依赖猜想性 soundness；有些系统同时占了两项以上。

我们在 Rust 中实现了 Magnetar，并做了实验评估。在 **120 bit 可证明安全性**、M4 Max MacBook Pro 的 **12 个性能核**上，Magnetar 证明 **2^22 cycle** 执行时达到 **7.2–8.7 million cycles/s**，proof 约 **600 KiB**，验证时间 **11–13 ms**。在 15 个应用 workload 上，Magnetar 的 proving throughput 是 SP1 Hypercube 的 **24–66×**、Jolt-Dory 的 **12–37×**、Jolt-Akita 的 **6–20×**；几何平均约为 **39×、18×、9.6×**。优化版 Magnetar（Magnetar opt）证明 2^22 cycle 达到 **9.5–12.8 million cycles/s**，把上述几何平均加速比分别提高到约 **52×、24×、12.7×**。Magnetar 的 proof 比 SP1 Hypercube 小约 **4.6×**；Jolt 的 proof 小于 100 KiB，但它依赖椭圆曲线或格假设。

---

## 1 引言

零知识虚拟机（zkVM）是面向程序执行的通用证明系统。给定程序和输入，prover 在指定机器（如 RISC-V）上运行程序，并生成一个简洁 proof，证明执行得到了声称的输出；program 还可以从 prover 那里取得私有的、非确定性输入。Verifier 不需要重复执行，就能验证 proof。

zkVM 的主要优势是**通用证明**：证明系统最终需要计算的算术描述，可以针对固定应用设计并优化电路，但增加或修改功能就要换电路；zkVM 则一次性算术化处理器，然后把每个应用作为机器码输入。开发者可以用 Rust、Go 或 C 写程序，用现有工具链编译；同一个处理器算术化可以证明所有这些程序。

面向 RV64 这类通用 ISA 的 zkVM 还能直接通向 zkEVM：用 Rust 或 Go 写的 EVM 实现可以编译到 RV64，在 zkVM 里运行，从而为现有 EVM 智能合约生成 proof，而不需要为专用 ISA 重写合约。对以太坊而言，这就是用“复制的验证”替代“复制的执行”。

不过，通用证明的收益取决于被算术化的机器。标准 ISA（如 RISC-V）让开发者可以使用现有编译器、语言和库；受限 ISA（如 Cairo、leanVM 的 leanISA）更容易构建端到端 prover，但应用必须目标该 ISA、使用专用工具链，并接受机器限制（例如 write-once memory）。

通用执行并不是唯一目标。底层证明系统还决定了 zkVM 是否后量子、依赖什么密码学假设、是否需要可信设置、是否支持递归 proof 组合。递归组合让 prover 能处理单机内存放不下的超长执行，也让持续演进的计算在任何时刻都能保持一个简洁 proof；简洁区块链就是递归组合的典型应用。

本文要问的是：能否同时实现这些目标，并且比现有 zkVM 更快？

### 1.1 zkVM 的设计空间

我们用三个性质比较 zkVM。多数 zkVM 只提供 VM 执行的 succinct argument；zero-knowledge 是额外属性。

1. **通用证明**：应用用高级语言编写，编译到标准 ISA（如 RV64）；程序员不需要构造电路，也不需要目标受限机器。
2. **基于哈希、后量子安全**：计算安全性只依赖 SHA-256/SHA-3 等标准哈希，而不是椭圆曲线、格或 Poseidon 等代数哈希。这个要求覆盖整个证明机制，而不只是承诺方案：一个用 Merkle tree 承诺、但在证明机制里用椭圆曲线或格哈希的 zkVM 不算合格。此外，系统不需要可信设置，也不依赖底层纠错码的猜想性 proximity gap。
3. **高效递归**：验证 proof 本身是 zkVM 的高效 workload，因此长执行可以递归组合，而不必构造一个巨大的 monolithic proof。

现有 zkVM 大致分为四类：

- **椭圆曲线型**：短 proof，支持高效递归，但不是后量子。Jolt-Dory 属于此类。
- **格型**：后量子，但依赖格假设；Jolt-Akita 属于此类，且当时尚未展示完整 zkVM proof 的端到端递归组合。
- **Hash-and-more 型**：通常用 Merkle tree 承诺，但安全性还依赖代数哈希，甚至椭圆曲线或格；SP1 Hypercube、RISC Zero、ZisK 属于此类。它们多数在小素域上算术化，用 Reed–Solomon 编码 + Merkle tree，并用 FRI 类 STARK 或 sum-check proof；跨表 lookup/permutation 还会带来与表大小线性相关的 soundness loss。
- **纯 hash-based 型**：安全性只依赖标准哈希。leanVM 是代表：Spartan-based、binary field、BLAKE2s，但它当前的 leanISA 是专用小机器，不能支持任意 RV64 程序。

结论：现有系统没有同时具备三项性质。Magnetar 试图占据这个空缺。

### 1.2 我们的工作：Magnetar

Magnetar 证明编译到 **RV64I** 的程序。核心证明系统是 **BinarySpartan**，即 Spartan 在二元域上的实例化。类似地，我们把 Twist 和 Shout 实例化到二元域，得到 **BinaryTwist** 和 **BinaryShout**，并对 one-hotness 检查做了细化。我们还提出 **BinaryRouter**，一类用于“可表达为 bit routing 的计算”的 sum-check 参数，并实例化到 shift 和 sub-word store。最后，**MosaicPCS** 把 prover 承诺的所有东西打包成一个 multlinear polynomial，使每个 proof 只有一个 commitment 和一个 evaluation argument。

整个证明栈都在二元域上：

- 计算安全性基于 SHA-256/SHA-3 等标准哈希；
- 不需要可信设置，因此是透明的；
- 不依赖椭圆曲线、配对、格、Poseidon 或猜想性 Reed–Solomon proximity gap；
- verifier 做 Merkle path 检查、transcript 哈希和二元扩域算术；
- 验证 proof 是 BinarySpartan 擅长的工作，因此递归不需要电路友好哈希。

我们在 Rust 中实现 Magnetar。在 120 bit 可证明安全性、12 个性能核的 M4 Max MacBook Pro 上：

- 2^22 cycle 执行，proving 7.2–8.7 million cycles/s；
- proof 约 600 KiB；
- 验证 11–13 ms；
- 在 15 个 workload 上，proving throughput 相对 SP1 Hypercube/Jolt-Dory/Jolt-Akita 的几何平均加速约为 39×/18×/9.6×；
- 端到端吞吐（含 guest 执行和 trace 构造）约为 Jolt-Akita 的 8.7×；
- Magnetar opt 达到 9.5–12.8 million cycles/s，几何平均比 Magnetar 快 1.32×，prover 内存少 36–40%。

Magnetar 的 proof 比 SP1 Hypercube 小约 4.6×；Jolt 的 proof 更小，但依赖曲线/格假设。我们预计递归组合后这个差距会缩小：递归链的最终 proof 只覆盖前一个 proof 的 verifier，计算很小，可以用更低 code rate 生成更小 proof，而额外 prover 工作不大。

### 1.3 密切相关工作

**Hash-and-more zkVM。** 包括 RISC Zero、SP1、ZisK 等。它们通常把执行组织成多张表：CPU 表 + 操作表，用 lookup/permutation 连接，用 AIR 约束每张表。传统实现用 FRI-based STARK；较新实现用 multilinear sum-check，但保留 CPU/操作表、跨表 lookup/permutation。内存一致性多用 offline memory checking 的跨表 permutation，而不是 Twist/Shout 这样的 memory argument。Permutation/grand-sum 的 soundness loss 与表大小线性相关（约 ℓ/|F|），所以 2^20 行表在约 124-bit 扩域上会损失 20 bit 以上安全性，和它们 96–100 bit 的安全目标一致。为了递归，它们用 Poseidon2 等电路友好哈希；SP1 Hypercube 的内存一致性还用椭圆曲线 multiset hash，ZisK 的分布式 challenge 派生用格 multiset hash，所以安全性都不只依赖标准哈希。

**Jolt。** Jolt 用“一张大 lookup 表”的架构，把指令语义归约为查表。对两个 64-bit 输入的操作，概念表至少有 2^128 项；prover/verifier 都不物化它，verifier 在随机点求其 MLE，lookup argument 证明执行访问了正确项。Jolt 用 Spartan 连接 lookup，用 Lasso（最新版用 Twist/Shout）做 lookup；支持 Dory（椭圆曲线）和 Akita（格）后端。Jolt-Akita 是后量子的，但依赖格假设，且当时未展示完整递归组合。

**Magnetar 与它们的关系。** Magnetar 同样基于 Spartan、Twist、Shout，但做了二元域实例化；与 Jolt 的关键区别是 CPU 算术化方式：Magnetar 用“电路 + BinaryRouter”证明指令语义，而不是查一张 2^128 的大表。两个 SIMD R1CS 关系构成 CPU 核心；BinaryRouter 处理 shift 和 sub-word store；BinaryShout 只服务 bytecode。在二元域上，这比把相同语义做成 2^128 结构化 lookup 更快。

Magnetar 与 Jolt 的扩展方式也不同。Jolt 的 streaming prover 通过跨 sum-check 轮流式处理 trace 来降低空间，不做递归；Magnetar 则提出按 chunk 证明、递归组合，但论文明确说这两条 scaling path 都还没有实现。由于 Magnetar 的 verifier 主要是标准哈希和二元域运算，递归 verifier 很适合这个证明系统。

---

## 2 Magnetar 技术概览

先给出端到端协议，再解释设计思想。

### 2.1 端到端协议

Magnetar 证明 **RV64I** 机器在 Harvard 架构下的 fetch-decode-execute 循环：

- instruction memory：public、read-only；
- data memory：separate、mutable。

概括地说：

1. 把每个 cycle 的状态转移写成 **F2 上的 R1CS** 和 **F2^128 上的 R1CS**；
2. 用 **BinarySpartan** 一次性证明所有 cycle 的两个 **SIMD R1CS** 关系；
3. 把不属于 local transition 的部分（寄存器/RAM 一致性、instruction fetch、shift、sub-word store）交给基于 sum-check 的 argument，它们与两个关系共享同一个 witness；
4. 用 **BinaryTwist** / **BinaryShout** 做 memory checking；
5. 用 **BinaryRouter** 处理 shift 和 sub-word store；
6. 用 **MosaicPCS** 把所有 commitment 打包成一个 multilinear polynomial，因此只有一个 commitment 和一个 evaluation argument。

一个直接的做法是：承诺完整 witness，然后依次运行各协议，用 commitment 连接 claim。Magnetar 不是这样做的。它把 witness 分成：

- **direct segments**：需要提交；
- **virtual segments**：R1CS 会读，但不提交，由其他 argument 证明其正确性。

协议之间通过 **virtual segment 上的 evaluation claim** 连接，而不是通过 commitment。这正是 Spartan 避免承诺 `Az, Bz, Cz` 的机制：outer sum-check 末尾对这些量的 claim，由 inner sum-check 检查，而不是对 commitment 检查；类似 GKR 把一层电路的 claim 归约到下一层。Jolt 也用类似方式连接 Spartan 与 Twist/Shout。

Magnetar 把这种“每个 witness segment 输出一个 evaluation claim”的 BinarySpartan 变体称为 **Virtual Spartan**。

预处理阶段，verifier 确定性地把 public RV64I 程序的每条指令展开成一个或多个 **virtual instruction**，组成 public bytecode table；每行由 **micro-PC** 标识。Proving 阶段，CPU circuit 用从该表取出的 decoded instruction 执行每个 cycle 的 transition，并把剩余一致性检查委托出去：

- BinaryTwist for registers / RAM：访问一致性；
- 两个 BinaryRouter 实例：shift 和 sub-word store；
- BinaryShout for bytecode：认证取出的行及其 metadata。

在线阶段分五步：

1. **Execute**：prover 运行展开后的程序，记录 virtual cycles 作为一条 trace。该 trace 是 CPU circuit 的逻辑 witness，由两个 SIMD R1CS 关系共享。它被分成 direct segments 和 virtual segments（bytecode、registers、RAM、shifts）；prover 还构造 BinaryTwist/BinaryShout/BinaryRouter 检查 virtual segments 所需的 auxiliary vectors（例如 one-hot address bits、RAM increments）。
2. **Commit**：prover 把 direct CPU segments 和 auxiliary vectors 打包进一个 MosaicPCS polynomial，在任何 verifier challenge 之前发送协议唯一的 commitment。
3. **Reduce CPU claims with Virtual Spartan**：Virtual Spartan 联合两个 SIMD R1CS 关系、针对共享 witness，归约为每个 witness segment 一个 evaluation claim。Direct segment 的 claim 留给 MosaicPCS batching；virtual segment 的 claim 传给下一阶段的专用 argument。
4. **Reduce virtual claims**：BinaryTwist for registers/RAM 归约两个 access claim；BinaryRouter 实例归约 shift-output claim 和来自 BinaryTwist RAM 的 increment claim；BinaryShout for bytecode 认证所有与 bytecode 关联的 claim。它们把 virtual segment claim 变成对第二步所承诺向量的 evaluation claim。
5. **Prove committed evaluations**：此时所有剩余 claim 都指向 MosaicPCS polynomial 的某个 component。MosaicPCS 做 lift 和 batch，ring switching 把它们归约成 packed polynomial 上的一个 claim，prover 用一次 PCS evaluation argument 证明它。

验证时，verifier 计算标准哈希（SHA-256/SHA-3）并做二元扩域算术；BinarySpartan 高效支持这两类操作，所以递归不需要电路友好哈希。

### 2.2 Magnetar 的核心思想

#### （1）一个共享 witness 上的双 SIMD R1CS

BinarySpartan 证明二元域上的 R1CS。最直接的 CPU 算术化是 **F2 上的一个 SIMD R1CS**：每个 wire 是 bit，每个约束是 bit 的 linear combination 的乘积。Bit-level 检查（如 64-bit adder 的 XOR 和 majority logic）在这种表示下最便宜，但 word-level 操作不是：在条件 bit 下选择两个 64-bit word 需要 64 个 product constraints，而 CPU 每个 cycle 要做好几次这种选择。

另一个极端是全部用 **F2^128**：word-wide selection 变成一个约束（把每个 word pack 成一个 field element，再乘条件 bit），但每个 bit-level product 都变成完整的 128-bit field multiplication。

Magnetar 两者都用：

- `s1`：F2 上的 SIMD R1CS，用于 bit constraints；
- `s2`：F2^128 上的 SIMD R1CS，用于 packed products 和 packed linear checks；
- 两者读**同一个 bit-valued witness W**。

每个 SIMD instance 覆盖若干连续 cycle；跨 step 的约束把相邻 instance 连起来，因此两个关系也强制 CPU 状态（如 micro-PC）在 cycle 间连续。

Prover 拿到两个关系，可能想用两个不同 witness 分别满足它们。Magnetar 用两点排除：

1. 两个关系产生的 evaluation claim 都针对同一个 commitment（direct segments）或同一个 auxiliary argument（virtual segments），所以两个关系必须对每个 witness 值一致；
2. Virtual Spartan 用**一个 inner sum-check** 同时归约两个关系，确保 prover 只需证明 witness polynomial 在一个点上的 evaluation。

#### （2）Virtual Spartan：让 R1CS 读取未承诺的 segment

在 Spartan 中，prover 在第一个 challenge 之前承诺整个 R1CS witness；两个 sum-check 把可满足性归约成对该 committed polynomial 的一个 evaluation claim。

如果直接套到 CPU circuit，prover 要承诺整个 W，包括那些已经由 BinaryTwist/BinaryShout/BinaryRouter 证明正确的值：寄存器/RAM 读值、decoded instruction fields、shift outputs 等。承诺这些 segment 是多余工作，除非另一个 argument 需要它被承诺。

Magnetar 让 R1CS **读取**这些 segment，但不承诺它们；这些叫 **virtual segments**，其余叫 **direct segments**。

但 Spartan 不能直接这样做：它的 inner sum-check 末尾只产生一个针对整个 witness polynomial 的 evaluation claim，而 PCS 只能检查整个 polynomial 都被承诺的 claim。

Virtual Spartan 把这个 claim 替换成**每个 segment 一个 claim**。为了便宜地做到这一点，W 的布局满足：

- 每个 segment 占据 Boolean hypercube 的一个**对齐 subcube**；
- 每个 segment 大小是 2 的幂，起始位置是其大小的整数倍。

于是 W 上的 claim 是每个 segment claim 的固定线性组合；prover 发送 per-segment values，verifier 用少量 field 运算检查组合，不需要额外 sum-check。

Direct claims 留给 PCS。Virtual claims 转发给拥有它的 argument：

- register accesses → BinaryTwist for register file；
- RAM accesses → BinaryTwist for RAM；
- shift outputs → BinaryRouter for shifts；
- micro-PC 和 decoded fields → BinaryShout for bytecode。

每个 argument 再通过 sum-check 把 claim 归约到已承诺 polynomial 的 evaluation（如 one-hot address bits、RAM increments）。

关键：**每个 claim 都来自同一个 witness 上的同一个 sum-check**，不存在第二条 trace 需要对账；因此 Magnetar 不需要 permutation 或 grand-product argument。后者除了成本，还有与 instance size 线性相关的 soundness loss：ℓ 个元素的 grand-product/grand-sum soundness error 约 ℓ/|F|，在 128-bit field 上，ℓ=2^20 会损失 20 bit 安全性。Magnetar 的 sum-check 只损失与 log(instance size) 相关的 bit：ℓ=2^20 有 20 轮，degree-d 每轮 soundness error 约 20d/|F|，d=3 时只损失约 6 bit。

#### （3）BinaryRouter：处理 bit routing

有两个 RV64 操作不适合 Magnetar 的双 SIMD R1CS：

- **shift**：把 word 的每个 bit 移到由 shift amount 决定的位置；
- **sub-word store**：替换 64-bit RAM word 的某些 byte lane，保留其余部分。

有两种自然做法：

1. 直接用 R1CS 编码；
2. 按 Jolt 的思路，把操作当作按操作数索引的结构化表 lookup。

两者都可行，但都比为这两个操作实例化 BinaryRouter 更贵。

Magnetar 的观察是：这两个操作都是 **bit routing**：

- 每个输出 bit 要么是 0，要么是某个输入 bit 的拷贝；
- 哪个输入 bit 由指令决定（store 还由低 3 位地址决定），而不是由被移动的值决定；
- 例外是“shift amount 来自寄存器”的 shift：它被展开成一小段固定的 virtual instructions，每段都是 static routing。

Routing 恒等式：

```text
Y(o) = Σ_{u,h} X(u) · Q(h) · R(o, u, h)
```

其中：

- `X`：候选 source bits；
- `Q`：当前 routing 的 one-hot selector；
- `R`：public tensor，记录每种 routing 下哪个 source 喂给哪个 output。

Virtual Spartan 给出输出 `Y` 的 evaluation claim；对上述恒等式跑 sum-check，把它归约成 `X` 的 evaluation 和 `Q` 的 evaluation。`R` 是 public、sparse 的（任一 routing 下，每个输出 bit 最多由两个 source bit 喂入），verifier 可以自己求其 MLE；prover 的 sum-check 工作量与 trace length 线性。

`X` 是 W 的 direct segments，所以其 evaluation 交给 PCS。`Q` 是 bytecode row 的一个 field，所以用 BinaryShout 通过一次额外 bytecode 查询来认证。

对 store，使用同一恒等式：

- source：old RAM word 和 store-source word；
- output：BinaryTwist 承诺的 `Inc`（old XOR new）。

新 word 是两个 source 的 routing，因此每个 increment bit 要么是 0，要么是 old bit 与 store-source bit 的 XOR；`R` 通过让该输出 bit 同时由两个 source bit 喂入来表达 XOR。

两个 source 都是 W 的 virtual segments，所以 W 还包含一个 direct segment，持有两个 word 的拷贝；R1CS 把拷贝绑定到原始值，BinaryRouter 读这个拷贝。

store routing 还依赖低 3 位地址，所以 `R` 把它们作为额外参数；归约也输出这些 bit 的 evaluation claim，它们位于 W 的 direct segment。

#### （4）MosaicPCS：为所有东西只做一次承诺

上述归约结束时，verifier 手里有几十个不同大小、bit-valued polynomial 的 evaluation claim：

- direct witness segments；
- 两个 BinaryTwist 实例和一个 BinaryShout 实例的 one-hot address components；
- register/RAM increments。

朴素做法是每个 polynomial 单独承诺、单独 evaluation argument；对 hash-based PCS，每个 evaluation argument 都带自己的 Merkle authentication path。

MosaicPCS 避免这个成本。它是一层 PCS packing：

- 每个 component 大小是 2 的幂；
- 把它们放在一个更大的 Boolean hypercube 的互不相交、对齐 subcube 上；
- 定义一个大的 polynomial `G`：在每个 component 的 subcube 上等于该 component，在并集之外为 0；
- 只承诺一次 `G`。

坚持“对齐 subcube”的原因是：claim `p_i(r)=v` 可以**精确地** lift 成 `G(r || s_i)=v`，其中 `s_i` 是选择子立方体的固定 Boolean suffix。Verifier 只需把 `s_i` 追加到 point 后面，不需要额外 sum-check。

Lift 后的 claim 被 batch；ring switching 把结果归约成 `G` 的 packed representation 的一次 evaluation，由一次 PCS argument 对唯一 commitment 证明。Proving throughput 基本不受影响，因为 prover 承诺的 bit 数几乎不变。

**Remark 1（与 Spark/JaggedPCS 的关系）。** MosaicPCS 与已有的 sparse multilinear polynomial evaluation 技术相关。Spark 支持一般 sparse multilinear polynomial；JaggedPCS 专门处理任意高度的 stacked polynomial families。用 JaggedPCS 时，sparse component 的 claim 要先通过一个额外的 adapter sum-check 归约到 committed dense polynomial；MosaicPCS 因为对齐 subcube，不需要 adapter：追加固定 Boolean selector 坐标即可 lift。

---

## 3 预备知识

我们在二元域 `B = F2` 及其 128 次扩域 `K = F2^128` 上工作。`K` 有 `2^128` 个元素，`B` 通过 canonical embedding 嵌入 `K`。Bit-level witness 和约束系数可以在 `B`，但所有 verifier challenge 和 multilinear evaluation claim 都在 `K`。

对正整数 `ℓ`，把 `[2^ℓ]` 中的索引与 `{0,1}^ℓ` 的小端二进制表示等同。

### 3.1 多重线性扩展（MLE）

给定 `v ∈ K^{2^ℓ}`，按 `b ∈ {0,1}^ℓ` 索引。其 MLE 是唯一在 Boolean hypercube 上与 `v` 一致的多重线性多项式：

```text
ṽ(x) = Σ_{b∈{0,1}^ℓ} v[b] · eq(x, b)
eq(x, b) = Π_{i=1}^ℓ ( x_i·b_i + (1-x_i)·(1-b_i) )
```

对矩阵/张量，固定 Boolean 索引坐标的顺序后使用同一约定。

### 3.2 Sum-check 协议

设 `g` 是 `K` 上的 `m` 元多项式，每个变量次数至多 `d`。Sum-check 协议是一个 public-coin reduction of knowledge（定义 2），从关系

```text
S = Σ_{b∈{0,1}^m} g(b)
```

归约到 polynomial-evaluation 关系 `y = g(r), r ∈ K^m`。

`g` 在第一个 sum-check challenge 之前被绑定；在本文所有使用中，它由 public data、之前的 transcript 消息、以及已承诺或由已承诺值定义的 witness polynomial 决定。

协议有 `m` 个 public-coin 轮，完美完备，通信 `O(md)` 个 field elements，soundness error 至多 `md/|K|`。

### 3.3 Preprocessing SNARK

**定义 1（Preprocessing SNARK）**：关系 `R` 定义在 `(pp, s, x, w)` 上。一个 preprocessing SNARK 包含：

- `Setup(1^λ) → pp`：生成 public parameters；
- `KeyGen(pp, s) → (pk, vk)`：预处理 structure；
- `Prove(pk, x, w) → π`：证明 `(pp,s,x,w) ∈ R`；
- `Verify(vk, x, π) → {0,1}`：验证 proof。

要求：

- **完美完备性**：诚实生成的 proof 总被接受；
- **知识可靠性（knowledge soundness）**：对任意 expected polynomial-time adversary `A` 和 prover `P*`，存在 expected polynomial-time extractor `E`，使得 extractor 成功提取 witness 的概率至少是 `P*` 让 verifier 接受的概率减去 `negl(λ)`。

如果 proof length 和 verifier time 是 structure/witness size 的 polylog，则称其 **succinct**；如果 setup 和 key generation 不需要 secret trapdoor，则称其 **transparent**。

### 3.4 Reductions of knowledge

回忆 Kothapalli–Parno 的 reduction-of-knowledge 框架。一个 reduction of knowledge 推广 argument of knowledge：verifier 交互地把“知道 `R1` 中 witness”归约成“知道 `R2` 中 witness”。Prover 和 verifier 输入 instance `u1`，prover 额外输入 `w1`；交互后双方输出 `u2`，prover 额外输出 `w2`。

**定义 2（Preprocessed reduction of knowledge）**：从 `R1` 到 `R2` 的 reduction 包含 setup、确定性 key generation、交互 prover/verifier：

- `Setup(1^λ) → pp`；
- `KeyGen(pp, s1) → (pk, vk, s2)`；
- `P(pk, u1, w1) → (u2, w2)`；
- `V(vk, u1) → u2`。

要求：

- **完备性**：诚实交互后 `(pp, s2, u2, w2) ∈ R2`；
- **知识可靠性**：对任意 adversary/prover，存在 extractor `E`，其提取 `R1` witness 的概率不低于 prover 让 verifier 输出 `R2` 实例的概率减去 `negl(λ)`；
- **Public reducibility**：存在确定性多项式时间函数 `φ`，对每个 transcript 计算 `u2`。

Reduction 可以顺序组合、并行组合；本文所有 reduction 都是 public-coin、publicly reducible；Fiat–Shamir 后可变成 random-oracle 模型下的非交互 argument。

### 3.5 R1CS 与 SIMD R1CS

**定义 3（R1CS）**：固定域 `F` 和大小上界 `m,n,ℓ`，`m > ℓ`。R1CS structure 是 `s = (A,B,C)`，其中 `A,B,C ∈ F^{m×m}`，每个矩阵至多 `n` 个非零元。Instance `x ∈ F^ℓ` 包含 public inputs/outputs。Witness `w ∈ F^{m-ℓ-1}` 满足

```text
(Az) ∘ (Bz) = Cz,   z = (w, 1, x)
```

其中 `∘` 是 Hadamard product。记 `(s,x,w) ∈ R_R1CS`。

**定义 4（SIMD R1CS）**：设 `q` 是 2 的幂。SIMD R1CS 把同一个 structure `s` 应用到 `q` 个 instance-witness 对 `(x_i,w_i)`。若对每个 `i`，

```text
(Az_i) ∘ (Bz_i) = Cz_i,   z_i = (w_i,1,x_i)
```

则满足。等价地，它是块对角约束系统 `I_q ⊗ A, I_q ⊗ B, I_q ⊗ C` 作用在 `z_i` 的拼接上。记 `(s,(x_i),(w_i)) ∈ R_SIMD-R1CS`。

`R_BSIMD-R1CS` 是限制所有 witness entry 在 `B` 的版本；约束可在 canonical embedding `B → K` 后于 `K` 上求值。

### 3.6 多项式承诺

**定义 5（Virtual evaluation relation）**：virtual evaluation claim 表示一个 multilinear polynomial 的 evaluation，但暂不把该 polynomial 绑定到 commitment。对域 `F`：

```text
R_veval[F] = { ((r,y), v) | v ∈ F^{2^ℓ}, r ∈ F^ℓ, y ∈ F, ṽ(r) = y }
```

简写 `R_veval = R_veval[K]`。`R*_veval` 表示这些关系的有限乘积；`R_Bveval` 是 `v` 为 bit-valued、其 MLE 在 `K` 上求值的限制。

**定义 6（Multilinear polynomial commitment scheme）**：一个 multilinear PCS 是对 `v ∈ K^{2^ℓ}` 的承诺方案，通过其 MLE 看待，并带一个 knowledge argument：

```text
R_ceval = { (pp,(cm,r,y),(v,ρ)) |
  v ∈ K^{2^ℓ}, r ∈ K^ℓ, y ∈ K,
  ṽ(r)=y, cm=Commit(pp,v;ρ) }
```

`R_ceval` 的实例称为 **committed evaluation claim**。

本文把 PCS 当黑盒。Witness 是 bit-valued，但 PCS 承诺 `K` 上的向量，因此使用 **ring switching**：把 binary vector 上的 virtual evaluation claim 归约成对应 packed polynomial（128 bit / field element）上的 claim。

---

## 4 Magnetar 的证明系统构建模块

本节描述 Magnetar 组合的三个构建模块：

- **BinarySpartan**：核心证明引擎；
- **BinaryTwist** 和 **BinaryShout**：memory checking。

每个都表示为 reduction of knowledge（RoK）：从其原生关系（R1CS 或 memory-checking relation）归约到 bit-valued polynomial 的 virtual evaluation claim，因为第 5 节正是以这种形式组合它们。本节借用已有工作 [50,51,55]；这里把 Spartan 看作 RoK，和常见的 argument-of-knowledge / polynomial-IOP 表述不同。

### 4.1 Spartan

不失一般性，设 `m` 是 2 的幂，且 `|w| = 1 + |x| = m/2`；不满足时 padding。令 `z=(w,1,x) ∈ F^m`。对 `y ∈ F^{log m}`，记 `y[0]` 为第一个坐标，`y[1..]` 为其余坐标。则

```text
z̃(y) = (1 - y[0]) · w̃(y[1..]) + y[0] · (1,x)̃(y[1..])   (1)
```

右边是与 `z` 在 Boolean hypercube 上一致的多重线性多项式，因此就是 `z` 的唯一 MLE。Verifier 可以从 witness 的一次 evaluation 和 public input 重构 `z̃` 的 evaluation。

Spartan 用两个 sum-check 把 R1CS 可满足性归约成 witness polynomial 上的一个 virtual evaluation claim。Prover 在 reduction 开始前（任何 verifier challenge 之前）承诺 `w`；最后用 PCS evaluation argument 对 commitment 证明 claim。

**Outer sum-check** 把证明 `(Az)∘(Bz)=Cz` 归约成在一个随机点求 `Az,Bz,Cz` 的 MLE：

```text
0 = Σ_{x∈{0,1}^{log m}} eq(τ,x) · ( Ãz(x)·B̃z(x) - C̃z(x) )   (2)
```

其中 `τ ∈ F^{log m}` 是 verifier 在 prover 承诺 `w` 后随机选的。如果 `z` 满足 R1CS，该等式对所有 `τ` 成立；否则随机 `τ` 使其成立的概率至多 `log m / |F|`（Schwartz–Zippel）。

Outer sum-check 把 `x` 绑定到随机 `r_x ∈ F^{log m}`。末尾 prover 发送 `v_A,v_B,v_C`，声称等于 `Ãz(r_x), B̃z(r_x), C̃z(r_x)`；verifier 检查

```text
e = eq(τ, r_x) · (v_A·v_B - v_C)
```

其中 `e` 是 sum-check 最后一轮留下的 claim。接下来要检查三个值的正确性，这是 inner sum-check 的任务。

为了一次 sum-check 检查三个 claim，verifier 采样 `r ∈ F`，令

```text
c = v_A + r·v_B + r^2·v_C
```

并检查

```text
c = Σ_{y∈{0,1}^{log m}} ( Ã(r_x,y) + r·B̃(r_x,y) + r^2·C̃(r_x,y) ) · z̃(y)   (3)
```

由于 `v_A,v_B,v_C` 在采样 `r` 前已固定，错误三元组通过 batching 的概率至多 `2/|F|`。

Inner sum-check 把 `y` 绑定到随机 `r_y ∈ F^{log m}`。Prover 提供 `v_w = w̃(r_y[1..])`。Verifier 自己求 public matrix polynomial，并用式 (1) 从 `v_w` 和 `(1,x)̃(r_y[1..])` 重构 `z̃(r_y)`。剩余 claim 就是 witness polynomial 上的单个 evaluation claim：

```text
w̃(r_y[1..]) = v_w
```

Reduction 把它作为 virtual evaluation claim 输出（定义 5），暂不绑定到 `w` 的 commitment；PCS evaluation argument 之后再绑定。

**Remark 2**：由于 `w` 的 commitment 在 reduction 开始前已发送，Spartan reduction 也可以输出 committed evaluation claim（定义 6）。这里保持 commitment-free，是因为 Magnetar 之后会按 segment 拆分 claim，只把其中一部分绑定到 commitment（第 5.3 节）。

**Construction 1（Spartan reduction）**：输入 `s=(A,B,C)`。KeyGen 把矩阵、维度、padding 约定存入 prover/verifier key，并输出长度为 `m/2` 的向量的目标 evaluation structure。Reduction 本身不发送 commitment；假设外层协议已在第一步前发送 `w` 的 commitment。输入 `(x,w)`，`z=(w,1,x)`，在线步骤：

1. `V → P`：`τ ← F^{log m}`。
2. 双方对 claim `Σ_{x∈{0,1}^{log m}} g(x)=0` 运行 sum-check，其中

```text
g(x) = eq(τ,x) · ( Ãz(x)·B̃z(x) - C̃z(x) )
```

每个变量次数为 3。经过 `log m` 轮，verifier 每轮采样 `r_x` 的一个坐标，最后得到 claim `e=g(r_x)`。

3. `P → V`：`v_A,v_B,v_C ∈ F`，声称等于 `Ãz(r_x),B̃z(r_x),C̃z(r_x)`。Verifier 检查 `e=eq(τ,r_x)·(v_A·v_B-v_C)`，否则中止。
4. `V → P`：`r ← F`。双方令 `c=v_A+r·v_B+r^2·v_C`。
5. 双方对 claim `Σ_{y∈{0,1}^{log m}} h(y)=c` 运行 sum-check，其中

```text
h(y) = ( Ã(r_x,y) + r·B̃(r_x,y) + r^2·C̃(r_x,y) ) · z̃(y)
```

每个变量次数为 2。Verifier 每轮采样 `r_y` 的一个坐标，最后得到 `e'=h(r_y)`。

6. `P → V`：`v_w ∈ F`，声称等于 `w̃(r_y[1..])`。Verifier 用式 (1) 计算 `v_z=(1-r_y[0])·v_w+r_y[0]·(1,x)̃(r_y[1..])`，自己求 `Ã(r_x,r_y),B̃(r_x,r_y),C̃(r_x,r_y)`，并检查

```text
e' = ( Ã(r_x,r_y) + r·B̃(r_x,r_y) + r^2·C̃(r_x,r_y) ) · v_z
```

否则中止。

7. 双方输出 `R_veval[F]` 实例 `(r_y[1..],v_w)`；prover 额外输出 witness `w`。

**Remark 3**：在 Construction 1 中，verifier 自己求 `A,B,C` 的 MLE，时间与其非零元数线性。Spartan 还提供 preprocessing 变体：KeyGen 用 sparse PCS 承诺三个矩阵，verifier 只保留 succinct commitment，prover 之后证明所需 evaluation，从而使非结构化 R1CS 的在线 verifier 也 succinct。本文不考虑这个通用变体：Magnetar 使用结构化 R1CS（SIMD R1CS + 小固定 base structure），verifier 直接求值已经很便宜。

### 4.2 SIMD R1CS 的 Spartan

Phalanx [60] 把 Spartan reduction 扩展到 SIMD R1CS（定义 4）。考虑同一个 `m×m` structure `s=(A,B,C)` 的 `q=2^s` 个 instance-witness 对。SIMD 关系可以看成：

- `q` 份 base R1CS，每份对应一个 pair；或
- 一个 R1CS，矩阵为 `I_q⊗A, I_q⊗B, I_q⊗C`。

Prover 把 `q` 个 witness 排成 `q×m/2` 矩阵 `W` 的行，用一个 multilinear polynomial `W̃(u,y)` 表示全部，其中 `u∈{0,1}^{log q}` 索引 instance，`y` 是列。

Outer sum-check 直接适用于块对角 R1CS。块对角 R1CS 的行索引由 `s` 个 instance 坐标和 `log m` 个 base R1CS 行坐标组成。Verifier 在 sum-check 过程中逐坐标选择 `r_x=(r_inst,r_row)`。

Inner sum-check 中共享结构起作用。对 `M∈{A,B,C}`，块对角性给出

```text
(I_q⊗M)̃((r_inst,r_row),(u,y)) = eq(r_inst,u) · M̃(r_row,y)
```

因此对 `u` 的求和把 `q` 个 `z_i` 在 `r_inst` 处折叠，prover/verifier 只需在 base R1CS 的列 `y` 上跑一次 inner sum-check。注意 inner sum-check 不是孤立检查某个 SIMD instance，而是检查所有 `q` 个实例的随机折叠（随机线性组合），这对 soundness 足够。Reduction 最后得到联合定义的 witness polynomial 的一个 virtual evaluation。

只有 outer sum-check 增加 `log q` 轮；inner sum-check 和三个矩阵 evaluation 保持 base R1CS 的维度。本文 base R1CS 固定且小（固定数量的连续 CPU transition），所以 verifier 直接求矩阵，而不用 Spartan 的 sparse-matrix evaluation argument（Remark 3）。

**Lemma 1（R1CS 与 SIMD R1CS 的 Spartan reduction [50,60]）**：对 `m×m` R1CS structure `s=(A,B,C)`，Construction 1 及其 SIMD 扩展满足：

1. Base reduction 是 public-coin RoK

```text
R_R1CS → R_veval[F]
```

有 `O(log m)` 个 public-coin 轮，通信 `O(log m)` 个 field elements，knowledge error `O(log m)/|F|`。Prover 做 `O(nnz(A,B,C)+m)` 次 field 运算；verifier 直接求三个 public matrix polynomial 时做 `O(nnz(A,B,C)+|x|+log m)` 次 field 运算。

2. 对同一结构的 `q` 个 instance-witness 对，SIMD reduction 是 public-coin RoK

```text
R_SIMD-R1CS → R_veval[F]
```

有 `O(log q+log m)` 轮，通信 `O(log q+log m)` 个 field elements，knowledge error `O(log(qm))/|F|`。Prover 做 `O(q·nnz(A,B,C)+qm)` 次 field 运算；verifier 直接求三个 base matrix polynomial 时做 `O(nnz(A,B,C)+Σ_i|x_i|+log q+log m)` 次 field 运算。

注意 SIMD reduction 的 verifier 成本基本等于单个实例：只多 `log q` 轮 sum-check（加上读取 public inputs，而 public inputs 不必随 `q` 增长）。Prover 工作量与 `q` 线性，和逐个证明相同。

### 4.3 BinarySpartan

BinarySpartan [51] 把 Phalanx SIMD 构造中的 witness 限制在 `B`。它包含标准 Spartan 优化，包括对 sum-check 的改进 [60,53,22,12,3]。这里把它的 R1CS-to-evaluation 阶段称为 **BinarySpartan reduction**；独立的 BinarySpartan SNARK 用一次 commitment、ring switching 和一次 PCS evaluation argument 包住该 reduction。

BinarySpartan 分三步，把定义 6 的 multilinear PCS 当黑盒：

1. **承诺 binary witness**：若把 witness 表示成 `K` 上向量，每个 bit 要一个 field element。对长度 `2^ℓ` 的 witness，把条目看成表

```text
w : {0,1}^7 × {0,1}^{ℓ-7} → B
```

令 `u_0,...,u_127` 枚举 `{0,1}^7`，`β_0,...,β_127` 是 `K` 的 `B`-基。定义 packed table

```text
P(v) = Σ_{j=0}^{127} β_j · w(u_j, v)
```

每个 `P` 条目包含 128 个 witness bit。Prover 用 PCS 承诺 `P`。

2. **对 binary witness 做 SIMD R1CS reduction**：发送 commitment 后，双方跑 SIMD Spartan reduction。Binary restriction 只限制 witness，不限制协议算术：两个 sum-check 仍在 `K` 上跑。SIMD Spartan reduction 输出 claim `w̃(r)=v_w`，所以目标是 `R_Bveval` 而不是 `R_veval`。

3. **证明 binary-witness evaluation**：Ring switching [13] 把 binary-witness virtual evaluation claim 归约成 `P̃` 的 virtual evaluation claim；PCS evaluation argument 对第一步的 commitment 证明最终 committed evaluation claim。

**Corollary 1（BinarySpartan [51]）**：Lemma 1 的 SIMD reduction 限制到 bit-valued witness、在 `K` 上运行，是 public-coin RoK

```text
Π_BSp : R_BSIMD-R1CS → R_Bveval
```

设 `Π_RS` 是 ring-switching reduction，`Π_PCS` 是透明、succinct、完美完备且 knowledge sound 的 PCS evaluation argument。若 public matrix polynomial 对 verifier 可高效求值，则“在 `Π_BSp` 前承诺一次 `P`，然后跑 `Π_RS` 和 `Π_PCS`”的协议，是 binary witness 上 SIMD R1CS 的透明 preprocessing SNARK。

### 4.4 BinaryTwist 与 BinaryShout

BinarySpartan 证明每个 cycle 的 local constraint 成立，但还没有把 CPU circuit 读到的寄存器值、RAM word、decoded instruction 与一致的 register file / memory / bytecode 绑定起来。Magnetar 用 BinaryShout 和 BinaryTwist 建立一致性。

回忆：

- **Shout** 证明从 public read-only table 的读取；
- **Twist** 证明每个 cycle 先做 `p` 次读、再做一次写，针对可变内存。

Magnetar 用：

- 一个 BinaryShout 实例：bytecode；
- 两个 BinaryTwist 实例：register file（`p=2`）和 RAM（`p=1`）。

与 Spartan 一样，下面的 reduction 不发送 commitment：prover 预先承诺它们用到的每个 component polynomial（在 Magnetar 中作为唯一 MosaicPCS commitment `cm_G` 的一部分）；每个 reduction 输出这些 component 的 virtual evaluation claim；最后的 PCS evaluation argument 证明对应的 committed claim。

Twist/Shout 最初为素域和同态承诺提出，但它们很适合二元域 + hash-based commitment：它们承诺的数据（one-hot address、increment）是 bit vector，地址还是 sparse 的，pack 进 binary-field element 后承诺很便宜。

两个协议共享地址编码和 one-hot 检查，先描述这些，再总结各自协议与保证。

#### 共享地址表示

设内存单元数 `K=2^a`，cycle 数 `T=2^n`。选 `d | a`。对每个地址序列（每 cycle 一个地址），prover 承诺 `d` 个 bit-valued component polynomial：

```text
ra_i : {0,1}^{a/d} × {0,1}^n → B,  i∈[d]
```

若 `k=(k^(1),...,k^(d))` 是内存地址的对应划分，则 virtual full-address polynomial 在 Boolean cycle `j` 上满足

```text
ra(k,j) = Π_{i=1}^d ra_i(k^(i), j)
```

Prover 只承诺 `d` 个 component `ra_1,...,ra_d`，它们比 `ra` 短得多：完整地址有 `K·T` 项，每个 component 有 `K^{1/d}·T` 项，所以每 cycle 承诺 `d·K^{1/d}` bit，而不是 `K` bit。

完整地址 `ra`、普通 address bits、读/写值都是 virtual：prover 从不承诺它们。只要 verifier 需要这些 virtual polynomial 的 evaluation（如 `ra(r_address,r_cycle)`），就用定义它们的恒等式跑 sum-check，把 evaluation 归约到已承诺 component `ra_i` 的 evaluation。这一步称为 **address virtualization**。

#### 二元域上的 one-hotness

在 `F2` 上，检查 bit vector 元素之和为 1 只能说明 Hamming weight 为奇数；BinaryTwist/BinaryShout 必须另外证明每个地址 component 的每一行 `ra_i(·,j)` 的 Hamming weight 至多 1。

固定一个 component，记其 Boolean table 为 `A:{0,1}^{a/d}×{0,1}^n→B`，MLE 为 `Ã`。Twist/Shout 用 **collision polynomial**：

```text
Δ(j;r,s) = Ã(r,j)·Ã(s,j) - Σ_{u∈{0,1}^{a/d}} A(u,j)·eq(r,u)·eq(s,u)
```

对 bit-valued 行 `A(·,j)`，`Δ` 在 `(r,s)` 上为零多项式，当且仅当该行 Hamming weight 至多 1。（展开乘积可见，`Δ` 是所有“两个位置都为 1”的 `eq(r,k)·eq(s,k')` 之和，`k≠k'`。）

对 cycle 变量在随机 `r,s,ρ` 上跑 sum-check，检查

```text
Σ_j eq(ρ,j)·Δ(j;r,s) = 0
```

最后留下 `Ã` 的三个 evaluation：`r`、`s`、以及 diagonal term 产生的第三点。

Magnetar 的细化：不独立采样 `s`，而是令 `s_h = r_h^2`。由于 `A` 的条目是 bit，Frobenius 映射给出 `Ã(s,j)=Ã(r,j)^2`，所以 `Δ` 的第一项不需要单独 evaluation。对 diagonal term，verifier 计算

```text
c_h = 1 + r_h + r_h^2
r'_h = r_h^3 / c_h
C(r) = Π_h c_h
```

若某个 `c_h=0` 则重采样 `r`。于是对每个 Boolean `u`，`eq(r,u)^3 = C(r)·eq(r',u)`，collision polynomial 化简为

```text
Δ*(j;r) = Ã(r,j)^3 + C(r)·Ã(r',j)
```

Verifier 采样 `ρ∈K^n`，对 cycle 变量跑 sum-check 证明

```text
0 = Σ_{j∈{0,1}^n} eq(ρ,j)·Δ*(j;r)
```

只剩 `Ã` 的两个 evaluation，而不是三个。若某个 Boolean cycle 有 collision，`Δ*(·;r)` 是非零多项式，随机 `r,ρ` 会以 Schwartz–Zippel 误差检测到。

#### BinaryShout

BinaryShout 证明从 public read-only table `Val : {0,1}^a → K^c`（`c` 列）的读取。在 Boolean cycle `j` 上，读取返回的值和地址 bit 是 virtual polynomial：

```text
rv_h(j) = Σ_k ra(k,j)·Val_h(k)
raf_t(j) = Σ_k k_t·ra(k,j)
```

给定这些 polynomial 在 cycle 点 `r_cycle` 的 claimed evaluation，用一个 sum-check 检查所有 claim。Verifier 采样非零 `α_0`、地址系数 `α_1,...,α_a`、值系数 `γ_1,...,γ_c`。双方定义

```text
Φ(k) = α_0 + Σ_{t=1}^a α_t·k_t + Σ_{h=1}^c γ_h·Val_h(k)
```

Prover 证明

```text
α_0 + Σ_t α_t·raf_t(r_cycle) + Σ_h γ_h·rv_h(r_cycle)
  = Σ_{k∈{0,1}^a} ra(k,r_cycle)·Φ(k)
```

因为 `Φ` 是地址 bit 与表列的随机线性组合，这一个恒等式同时检查所有地址 bit 和值 claim。`α_0` 还做一件事：左边贡献 `α_0`，右边贡献 `α_0·Σ_k ra(k,r_cycle)`，所以恒等式也强制 `Σ_k ra(k,·)=1`；结合 collision check，地址 Hamming weight 恰好为 1。因此 BinaryShout 不需要单独的 non-emptiness check。

最后，用 address virtualization sum-check 把 full address `ra` 的剩余 evaluation 归约成 `d` 个 component evaluation。

#### BinaryTwist

BinaryTwist 证明：一个有 `K` 个 cell、每个 cell `L=2^ℓ` bit、初始状态为 public `M_0` 的可变内存，在每个 cycle 做 `p` 次读后跟一次写时，访问是一致的。

除了 `p` 次读和写的地址 component，prover 还承诺一个 polynomial：write increment

```text
Inc : {0,1}^ℓ × {0,1}^n → B
```

`Inc(·,j)` 是 cycle `j` 写入 cell 的 old/new 内容的 XOR。其他都是 virtual。特别是完整内存历史 `Val(k,o,j)`（cell `k` 的 bit `o` 在 cycle `j` 开始时的值）有 `K·L·T` 项，从不物化，更不承诺。

在 Boolean 点上，increment 决定 `Val`，`Val` 又决定读写值：

```text
Val̃(k,o,j) = M̃_0(k,o) + Σ_{j'} LT(j',j)·wa(k,j')·Inc(o,j')
rv_s(o,j) = Σ_k ra_s(k,j)·Val̃(k,o,j)
wv(o,j) = Σ_k wa(k,j)·( Val̃(k,o,j) + Inc(o,j) )
```

其中 `LT(j',j)=1` 当且仅当 `j'<j`。

- 第一式：从初始值和之前 cycle 写入的 increment 重构 cell；
- 第二式：选出读 cell 在当前写之前的内容；
- 第三式：给出写后 cell 的内容。

给定 `rv_s` 和 `wv` 在 cycle 点、value 点的 claimed evaluation，对每个恒等式跑一次 sum-check：

- 第二、三式把读写值归约到 address polynomial、`Val̃`、`Inc` 的 evaluation；
- 第一式把 `Val̃` 的 evaluation 进一步归约到 `wa` 和 `Inc`，verifier 自己求 `M̃_0` 和 `LT`；
- 普通 address bits 按 BinaryShout 处理；
- address virtualization 把每个 full-address evaluation 归约到 component。

此时每个剩余 claim 都是 committed polynomial 的 evaluation。

注意：与 BinaryShout 不同，上面三个恒等式对 address polynomial 是齐次的，全零地址会平凡满足。因此 BinaryTwist 用单独的 sum-check 证明每个 address component 的每一行之和为 1；结合 collision check，得到 Hamming weight 恰好 1。

**定义 7（Memory-checking relations）**：

- `R_BinaryShout` 实例包含 public table `Val`、`raf_t (t∈[a])` 和 `rv_h (h∈[c])` 在常数个 cycle 点的 claimed evaluation，以及每个 cycle 点 `r_cycle` 的 claim `Σ_k ra(k,r_cycle)=1`。Witness 是 component `ra_1,...,ra_d`。成立条件：每个 `ra_i(·,j)` 行 Hamming weight 至多 1，且所有 claim 正确。
- `R_BinaryTwist` 实例包含 `K,L,T,p,d`、初始内存 `M_0`、每个读和写的地址 bit 的 claimed evaluation（定义同 BinaryShout）、`rv_s (s∈[p])`、`wv` 在公共 cycle/value 点的 evaluation；还可以请求 `Inc` 在另一个点的 evaluation。Witness 是 `p` 个读和写的 address component，以及 `Inc`。成立条件：每个 address component 的每行 Hamming weight 恰好 1，且所有 claim 正确；`Val̃,rv_s,wv` 由上面恒等式给出。

**Lemma 2（BinaryShout/BinaryTwist reduction [55]）**：假设所有 address component 宽度相同（即 `d|a`）：

1. BinaryShout 是 public-coin RoK

```text
R_BinaryShout → (R_Bveval)^{3d}
```

使用 `O(log T + log K)` 轮，通信 `O(d·log T + log K)` 个 field elements，knowledge error `O(d·(log T+log K))/|K|`。

2. BinaryTwist 是 public-coin RoK

```text
R_BinaryTwist → (R_Bveval)^{4(p+1)d + 1_{d=1} + 2 + 1_inc}
```

其中 `1_inc` 表示是否请求单独的 increment evaluation；`1_{d=1}` 来自单个地址 component：此时 `p+2` 个 full-address claim（每个读一个、写地址两个）已经是 component evaluation，不需要 address virtualization；`d>1` 时两个写地址 claim 共享一个 product term，virtualization 产生 `(p+1)d` 个 component evaluation。

使用 `O(log T+log K)` 轮，通信 `O(d·log T+log K+(p+1)d)` 个 field elements，knowledge error `O(d·log T+(p+1)·log K+log L)/|K|`。

对每 cycle 常数次读，每个 reduction 只跑对数轮、通信 `O(d·log T+log K)`、每个 address component 留下常数个 evaluation claim；prover 成本与 `T` 线性。


---

## 5 Magnetar 构造

本节描述 Magnetar：一个针对 RV64I 执行的 SNARK，由第 4 节的 reduction 组合而成。概括：

1. 把每个 cycle 的 transition 算术化成两个 SIMD R1CS 关系，二者共享一个 bit-valued witness；
2. 用 Virtual Spartan 把它们归约成每个 witness segment 一个 evaluation claim；
3. 用 BinaryTwist、BinaryShout、BinaryRouter 处理 virtual segment claim 和 sub-word store；
4. 用 MosaicPCS 把所有剩余 claim batch 成一次 committed evaluation。

5.5 节把这些组件拼成完整协议并证明安全性。

**定义 8（Magnetar execution）**：设 `P` 是 RV64I 程序。对 public input `inp`、private auxiliary input `w`、public output `out`，关系 `R_P` 包含 `((inp,out),w)`，当且仅当 `P(inp,w)=out`。

如第 2 节所述，Magnetar 在 public preprocessing 中把 `P` 的每条指令展开成一个或多个 virtual instruction，并用 **micro-PC** 标识每个 virtual instruction。展开结果组成 public bytecode table `ROM`，按 micro-PC 索引。Prover 证明的执行是一串 virtual cycle，每个 cycle 执行一条 virtual instruction。

### 5.1 用两个 SIMD R1CS 关系算术化 CPU 语义

可以只用 `B` 上的一个 SIMD R1CS 关系来强制所有 CPU 检查，但有些 word-wide 操作在 `K` 上 packed 后便宜得多。

考虑 word-wide selection：对 bit `c,x_i,y_i∈B`，`0≤i<b≤128`，要求 `y_i = c·x_i`。

- 在 `B` 上，每个 bit 一个 product constraint；
- 在 `K` 上，取 `B`-基 `β_0,...,β_127`，同样的 `b` 个约束等价于一个 field constraint：

```text
c · ( Σ_{i=0}^{b-1} β_i·x_i ) = Σ_{i=0}^{b-1} β_i·y_i
```

因此 Magnetar 使用：

- `K` 上的 SIMD R1CS：处理这类 packed product families 和 packed linear checks；
- `B` 上的 SIMD R1CS：处理剩余 bit constraints（如 datapath 的 bitwise logic）。

二者共同强制 fetch-decode-execute 语义。每个 SIMD instance 覆盖固定数量的连续 cycle，所以 instance 内跨 cycle 的状态（如 micro-PC）由普通约束链起来。Instance 边界处，binary relation 还包含 cross-step constraints，把 instance `j` 的状态与 `j-1` 关联；Spartan 通过标准 next MLE [53] 支持这些约束，public initial/final state 在首/末 instance 绑定。两个关系把 memory-checking claim 和 shift/sub-word store 的 routing identity 留给后续 reduction。

形式化地，两个关系共享一个 witness。对 SIMD instance `j`，令 `w_j` 为其 witness，`x_j` 为其 public inputs/outputs，`W` 是第 `j` 行为 `w_j` 的 bit-valued 矩阵。令 `z_j=(w_j,1,x_j)`，要求对每个 `j`：

```text
(A_1 z_j) ∘ (B_1 z_j) = C_1 z_j    over B
(A_2 z_j) ∘ (B_2 z_j) = C_2 z_j    over K
```

`A_1,B_1,C_1` 的元素在 `B`，`A_2,B_2,C_2` 的元素在 `K`；这使第二个关系的一行可以像上面例子那样 pack 一个 word-wide check。两个关系约束同一个 `W`，所以 prover 不能拿两个不同 witness 分别满足它们。5.3 节说明 Virtual Spartan 如何以“额外一次 outer sum-check + 对 `W` 的一次 inner sum-check”的代价归约两个关系。

**Remark 4**：为简化描述，这里省略 cross-step constraints 和 public initial/final state 的绑定。Virtual Spartan 用 next MLE 和对 instance 坐标的一次额外 sum-check 强制它们；Lemma 3 仍然成立。

### 5.2 MosaicPCS

本节每个 reduction 都以 bit-valued polynomial 的 evaluation claim 结束：R1CS witness 的 direct segments，以及 auxiliary reduction 承诺的 polynomial（如 one-hot address components、RAM increments）。这些 polynomial 数量多、大小不同。如果逐个承诺，每个都要自己的 PCS evaluation argument；对 hash-based PCS，这些 evaluation argument 会主导 proof length。

MosaicPCS 的做法：

- 把所有 polynomial 放在一个更大 polynomial 的互不相交 subcube 上；
- 只承诺这个大 polynomial 一次；
- 用一次 PCS evaluation argument 证明所有 evaluation claim。

具体地，设 `p_1,...,p_N` 是上述 polynomial（direct segments + auxiliary），`p_i:{0,1}^{ℓ_i}→B`。选 `ℓ≥max_iℓ_i` 和 Boolean suffix `s_i∈{0,1}^{ℓ-ℓ_i}`，使得 subcube

```text
{ x || s_i : x∈{0,1}^{ℓ_i} }
```

两两不相交。定义 `G:{0,1}^ℓ→B`：

```text
G(x || s_i) = p_i(x)   for x∈{0,1}^{ℓ_i}
G(x) = 0               outside all subcubes
```

Prover 只承诺 `G` 的 packed representation `P_G`，发送 `cm_G = Commit(P_G)`。

这个布局的关键：任何 `p_i` 的 claim 都能免费 lift 到 `G`。把 `G̃` 的 suffix 变量固定到 Boolean 点 `s_i`，`G` 就限制到第 `i` 个 subcube，等于 `p_i`。因此对每个 `r∈K^{ℓ_i}`：

```text
G̃(r || s_i) = p̃_i(r)   (4)
```

也就是说，要把 `p̃_i(r_i)=v_i` 变成 `G̃(r_i || s_i)=v_i`，verifier 只需把 public suffix `s_i` 追加到 point。所有 claim 都变成对 `G` 的 claim 后，还剩两个标准步骤：

- **Batching**：现在有多个对不同点的 claim `G̃(r_i||s_i)=v_i`，归约成单点 `r_G∈K^ℓ` 的一个 claim `G̃(r_G)=v_G`。Verifier 对每个 claim 采样 `α_i←K`，双方对

```text
Σ_i α_i·v_i = Σ_{x∈{0,1}^ℓ} ( Σ_i α_i·eq(r_i||s_i,x) )·G(x)
```

跑 sum-check；summand 每个变量次数为 2；`r_G` 是轮中选出的点，`v_G` 是 prover 声称的 `G̃(r_G)`。这一步是 public-coin RoK，knowledge error `O(ℓ)/|K|`，不发送 commitment。

- **Ring switching**：`G̃` 是 bit-valued 向量的 MLE，而 PCS 承诺的是 `G` 在 `K` 元素中的 packing `P_G`。Ring switching [13] 是 public-coin RoK，把 `G̃(r_G)=v_G` 归约成 `P̃_G(r*)=v*`，同样不发送 commitment。

把 lift 和这两步合起来记为 `Π_MosRS`。它是从 `(R_Bveval)*` 到 `R_veval` 的 RoK，knowledge error 是两步误差之和。Verifier 把输出 `(r*,v*)` 与 `cm_G` 配对成 committed evaluation claim `(cm_G,r*,v*)`，prover 用一次 PCS evaluation argument 证明它。

### 5.3 Virtual Spartan

第 5.1 节的两个 SIMD R1CS 关系共享 witness `W`，而只想承诺其中一部分。如果分别对两个关系跑 SIMD Spartan reduction，会得到两个针对整个 `W` 的 evaluation claim，二者都无法被单独消解：

- PCS 不能检查整个 `W` 的 claim，因为 `W` 没有全部被承诺；
- auxiliary argument 也不能，因为每个只接受单个 segment 的 claim，而不是整个 `W`。

Virtual Spartan 解决这个问题。固定一个 public layout，把 `W` 分成 `W_1,...,W_N`：

- 一部分 segment 放进 MosaicPCS polynomial `G`，称为 **direct**；
- 其余是 **virtual**：R1CS 读它们，但没有 commitment 包含它们。

Virtual Spartan 先把两个 SIMD R1CS 关系联合归约成共享 witness 上的一个 evaluation claim `W̃(r)=v_W`；然后 prover 对每个 segment 发送一个 claim `W̃_i(r_i)=v_i`，verifier 检查这些 claim 与 `W` 的 claim 一致。因为每个 segment 占据 `W` 的一个对齐 subcube，这个一致性检查是 `v_i` 的固定线性恒等式。

之后：

- direct segment claim 交给 MosaicPCS，由最终 PCS evaluation argument 证明；
- 每个 virtual segment claim 交给拥有该 segment 的 auxiliary reduction。

**Construction 2（Virtual Spartan）**：假设两个 SIMD R1CS 关系有相同的 padded SIMD 维度 `q`、相同 size bound `m`，`z` 的条目索引相同，共享 bit-valued witness `W`。固定其 public segment layout。Reduction 如下：

1. 对 binary relation 跑 BinarySpartan outer sum-check，对 `K`-coefficient relation 跑 SIMD Spartan outer sum-check。两个 sum-check **锁步**运行：
   - 绑定 SIMD instance 变量的轮中，verifier 发送一个 challenge，两个 sum-check 共用，因此都结束在同一个 instance point `r_inst`；
   - 绑定 constraint row 变量的轮中，每个 sum-check 各自收到 challenge，分别结束在 `r_row,t`，`t∈{bin,fld}`。
2. 每个 outer argument 以三个 terminal value 结束。把六个值记为 `v_{t,M}`，`t∈{bin,fld}`，`M∈{A,B,C}`。
3. 六个值固定后，verifier 采样独立系数 `α_{t,M}←K`，令

```text
v* = Σ_{t,M} α_{t,M}·v_{t,M}
```

4. 对下式跑**一次** inner sum-check：

```text
v* = Σ_y ( Σ_{t,M} α_{t,M}·M̃_t(r_row,t,y) )·z̃(r_inst,y)
```

其中 `M_t` 是对应的 public base matrix，`z̃(r_inst,·)` 是共享向量 `z` 在公共 SIMD instance point 上折叠后的结果。Verifier 在 sum-check 过程中逐坐标选择 `r_y`，令 `r_col=r_y[1..]`。Prover 提供 `v_W=W̃(r_inst,r_col)`，verifier 用式 (1) 检查最终恒等式。

5. Layout 把 segment `W_i` 放在 column space 的对齐 subcube 上：其列是二进制索引以固定 Boolean suffix `b_i` 结尾的那些列，剩余索引 bit 是 segment 的 local coordinates。把 column point 相应拆成 `r_col=(r_i,q_i)`，其中 `r_i` 是 `W_i` 的 local coordinates，`q_i` 是其 suffix 的坐标。因为 `W` 在该 subcube 上与 `W_i` 一致，且 subcube 划分所有列：

```text
W̃(r_inst,r_col) = Σ_i eq(q_i,b_i)·W̃_i(r_inst,r_i)
```

6. `P → V`：对每个 segment 发送 `v_i`，声称等于 `W̃_i(r_inst,r_i)`。Padding segment 恒为零，所以 `v_i=0`。
7. `V` 检查 `v_W = Σ_i eq(q_i,b_i)·v_i`，否则中止。
8. 双方对每个非 padding segment `W_i` 输出 `R_Bveval` 实例 `(r_inst || r_i, v_i)`；prover 额外输出 `W_i`。

**Lemma 3（Virtual Spartan reduction）**：设 `R_dual` 的 instance 是 public inputs `(x_j)_{j∈[q]}`，witness 是 bit-valued 矩阵 `W`，使得第 5.1 节两个 SIMD R1CS 关系都以 `W` 的行为 witness 成立。Construction 2 是 public-coin RoK

```text
R_dual → Π_i R_Bveval
```

乘积遍历非 padding segment，第 `i` 个因子的 instance 是 `(r_inst||r_i,v_i)`，witness 是 `W_i`。Knowledge error 为 `O(log q+log m)/|K|`。

**证明要点**：完备性来自两个 outer 恒等式、batched inner 恒等式和 Step 5 的 subcube 恒等式。Knowledge soundness 反向看：

- Step 5 是精确恒等式，所以满足输出 claim 的 segment polynomial `W_i` 按 public layout 拼接成 `W`，且 `W̃(r_inst,r_col)=v_W`；
- inner sum-check 把这个 evaluation 绑定到 batched terminal claim；由于 `α_{t,M}` 在六个 terminal value 固定后才采样，错误 terminal 值通过 batch 的概率至多 `1/|K|`；
- 剩下的是两个关系的 SIMD Spartan reduction（Lemma 1），只是两个 inner sum-check 被 batch 成一个。其 extractor 作用于该 `W`，得到两个关系的 witness，即 `R_dual` 的 witness；
- knowledge error 是两次 Spartan reduction 误差与 batching 误差之和。

Virtual Spartan 的每个输出 claim 由知道如何检查它的 argument 消解。Direct claim 针对已承诺 polynomial，等待 MosaicPCS；每个 virtual claim 针对 auxiliary argument 定义的 polynomial，该 argument 把 claim 替换成对它承诺的 polynomial 的 claim。5.5 节给出 argument 顺序和它们之间链接的 claim。

### 5.4 BinaryRouter

有两个 RV64 操作没有紧凑的 R1CS 编码：

- **shift**：把 source word 的每个 bit 移到新位置；
- **sub-word store**：替换 64-bit RAM word 的某些 byte lane，保留其余。

Magnetar 观察到二者都是 **bit routing**：每个输出 bit 要么是 0，要么是某个输入 bit 的拷贝；哪个输入 bit 由指令决定（store 还由低地址位决定），而不是由被移动的值决定。Magnetar 为这种结构设计了一族 sum-check argument，称为 **BinaryRouter**。

Routing 是如下恒等式：

```text
Y(o,j) = Σ_{u,h} X(u,j)·Q(h,j)·R(o,u,h)
```

其中：

- `Y`：输出表；
- `X`：候选 source bits；
- `Q(·,j)`：cycle `j` 使用的 routing 的 one-hot selector（或零）；
- `R`：public、sparse 的 routing structure，在 preprocessing 中固定，类似 R1CS 矩阵。

BinaryRouter 用一次 sum-check（对 cycle、source、routing 索引）把输出 `Y` 的 evaluation claim 归约成输入 `X` 与 `Q` 的 evaluation claim（store 还包括低地址位）。Verifier 自己求 `R`，因为 `R` 是 public、sparse 的；reduction 不承诺额外 polynomial。

**Lemma 4（BinaryRouter reduction）**：固定 public routing structure `R`。BinaryRouter 是 public-coin RoK，把 `Y` 的 evaluation claim（witness 为满足 routing 恒等式的 `X,Q`）归约成 `X,Q` 上常数个 `R_Bveval` 实例。若 `R` 还接受 per-cycle byte offset `a(j)`（store 情形），witness 还包含 offset bits，输出也包含每个 offset bit 一个实例。对固定 word/routing/address 宽度，轮数为 `O(log T)`，knowledge error 为 `O(log T)/|K|`。

**证明要点**：把 routing 恒等式代入 `Ỹ(r)`，claim 变成对 Boolean `(u,h,j)` 的 `X,Q,R̃,eq` 乘积之和。Sum-check 把和归约成随机点上 `X` 和 `Q` 的 evaluation；verifier 自己求 `R̃` 和 `eq`。若 `R` 接受 `a(j)`，summand 中的 `R̃` 最后三个参数是 offset bits 的 MLE；prover 发送它们在随机 cycle 点的值，verifier 用这些值求 `R̃`，这些值成为 offset bits 的 claim。Summand 每个变量次数为常数，所以 knowledge error 为 `O(log T)/|K|`。

Magnetar 中 BinaryRouter 有两个实例：

#### （1）shift

Shift 把 source word 的 bit 移到新位置，剩余位置填 0；算术右移填符号位。哪个 bit 去哪里由 bytecode row 固定（shift kind，以及 immediate shift 的 amount）。

用 routing 记号：

- `X(u,j)`：cycle `j` 的候选 source bits，包括一个固定为 0 的 source；
- `Y(o,j)`：shift output 的第 `o` 个 bit；
- `h`：可能的 routing；
- `Q_sh(h,j)`：cycle `j` 所用 routing 为 1，否则 0；无 shift 的 cycle 恒为 0；
- `R_sh(o,u,h)`：routing `h` 把 source `u` 映射到 output `o` 时为 1。

Shift witness 必须满足

```text
Y(o,j) = Σ_{u,h} X(u,j)·Q_sh(h,j)·R_sh(o,u,h)   (5)
```

selector one-hot 时，右边返回输出 `o` 规定的 source；selector 为零时，恒等式强制 `Y(o,j)=0`。

Routing 有几百种，所以 `Q_sh` 不存成一个宽 one-hot field，而是把 routing index 存成两个较短的 one-hot field：

```text
Q_sh(h,j) = Q_lo(h_lo,j)·Q_hi(h_hi,j),  h=(h_lo,h_hi)
```

这使 sum-check 在每个 cycle 变量上的次数增加 1；其余不变。

Shift output `Y` 是双 R1CS witness `W` 的 virtual segment，所以它的 evaluation claim 来自 Virtual Spartan，reduction 把 claim 消解成输入上的 claim。候选 source bits 在 `W` 的 direct segments，MosaicPCS 会和其余东西一起证明它们的 evaluation。

`Q_sh` 的两个因子是每 cycle fetch 的 bytecode row 的字段，所以 BinaryShout 用 public table `ROM` 把它们归约成 committed fetch address 的 claim（5.5 节）。

Shift amount 来自寄存器的 shift 没有 static routing，所以展开成一段短的固定 virtual instruction 序列，每条都是 static routing。

#### （2）sub-word store

Byte/halfword/word store 替换 64-bit RAM word 的一部分，保留其余；doubleword store 替换全部。

BinaryTwist for RAM 承诺 `Inc`（old/new RAM word 的 bitwise XOR），并证明 RAM 通过这些 increment 演化；但它不证明每个 increment 执行了 bytecode row 要求的 store。BinaryRouter 证明这一点。

Store 的新 word 是 old RAM word 与 store-source word 的 routing；把 `Inc` 作为输出，应用 routing 恒等式：

- 被写入的 byte 之外，increment 为 0；
- 被写入的 byte 内，新 bit 是 store-source bit，所以 increment bit 是 old RAM bit 与 store-source bit 的 XOR；
- routing structure 让该输出 bit 同时由两个 source bit 喂入；二者在 `B` 上的和就是 XOR。

哪些位置在内部只取决于：

- store width：bytecode row 固定；
- byte offset：低 3 位地址，每 cycle 变化。

因此取 old RAM word 和 store-source word 作为 source `X`，取 bytecode row 的四种 width 的 one-hot selector `Q_st`，以及一个接受 byte offset `a∈B^3` 的 routing structure `R_st(o,u,h,a)`。`R_st` 保持 public，尽管 offset 每 cycle 变化。令 `a(j)` 为 cycle `j` 的 offset，store witness 必须满足

```text
Inc(o,j) = Σ_{u,h} X(u,j)·Q_st(h,j)·R_st(o,u,h,a(j))   (6)
```

两个 word 都是 `W` 的 virtual segments（old word 由 BinaryTwist RAM 拥有，store-source 由 BinaryTwist registers 拥有），所以给 `W` 增加一个 direct segment，持有两个 word 的拷贝；R1CS 在每个 cycle 把拷贝绑定到原始值。`X` 是这个拷贝，所以和 shift 一样，MosaicPCS 证明它的 evaluation。

因为 `R_st` 通过 `a(j)` 依赖 cycle，sum-check 的 summand 包含因子 `R̃_st(r_o,u,h,ã(j))`，其中 `r_o` 是 claim 的输出点，`ã` 收集三个 offset bit 的 MLE。Sum-check 末尾，prover 发送 `ã` 在 cycle 点的值；verifier 在 argument 过程中逐坐标选择该点，并自己求 `R̃_st`。Offset bits 是 store address 的低位，R1CS 在 `W` 的 direct segment 中计算它们，所以这三个值成为 MosaicPCS 证明的 evaluation claim。

与 shift 不同，store 的输出 claim 不来自 Virtual Spartan。`Inc` 是 committed 的，因为 BinaryTwist RAM 用它证明 RAM 历史；所以这个实例的起始 claim 是 verifier 随机选点上的 `Inc` evaluation，PCS 对 commitment 检查它。其余与 shift 类似。

### 5.5 完整协议

**Construction 3（Magnetar）**：对 trace length `T`，KeyGen 从程序 `P` 导出：

- bytecode table `ROM`；
- 两个 SIMD R1CS 结构 `s_1`（`B` 上）和 `s_2`（`K` 上）；
- witness layout `L`；
- routing structures `R_sh,R_st`；
- MosaicPCS layout。

在线阶段：

1. Prover 形成共享 witness `W`，用 MosaicPCS 承诺 direct segments 与 memory-checking argument 的 auxiliary polynomial，发送唯一 commitment `cm_G`。
2. Prover/verifier 跑 Virtual Spartan（Construction 2），把 `s_1,s_2` 在 `W` 上的满足性归约成每个 witness segment 一个 evaluation claim。
3. 对 Step 2 的 virtual register claim 跑 BinaryTwist for registers。它把 claim 归约成 committed one-hot register address/increment 的 evaluation claim，以及 register index claim；后者在 Step 6 由 bytecode 检查。
4. 对 Step 2 的 virtual RAM claim 跑 BinaryTwist for RAM。它把 claim 归约成 committed one-hot RAM address/increment 的 evaluation claim。此外，verifier 选随机点，prover 发送 `Inc` 在该点的 evaluation；这个 claim 既是本步输出（PCS 对 commitment 检查），又是 Step 5 sub-word store Router 的输入。
5. 对 Virtual Spartan 的 shift output claim 跑 BinaryRouter for shifts；对 Step 4 的 increment claim 跑 BinaryRouter for sub-word stores。每个都把 claim 归约成对 routing source（`W` 的 direct segment）和 bytecode selector field 的 evaluation claim；selector 在 Step 6 检查。Store 实例还输出低 3 位地址的 evaluation claim，它们位于 `W` 的 direct segment。Verifier 自己求 public routing structure `R_sh,R_st`。
6. 对 bytecode 跑 BinaryShout with `Val=ROM`，消费 Step 2 的 virtual bytecode claim、Step 3 的 register-index claim、Step 5 的 selector claim。它们都是 bytecode lookup 的 read value；reduction 把它们变成 committed one-hot fetch address 的 evaluation claim。
7. 此时所有未决 claim（Step 2 的 direct claim，以及 Step 3–6 输出且未被 Step 6 消费的 claim）都是 `G` 的某个 component 的 evaluation claim。Prover/verifier 把每个 claim lift 到 `G`，batch，并做 ring switching，得到 packed `P_G` 上的一个 evaluation claim。Prover 用一次 PCS evaluation argument 对 `cm_G` 证明它；verifier 当且仅当该 argument 通过时接受。

**Lemma 5（Execution arithmetization）**：设 `P` 是程序，`T` 是 trace length，`ROM,s_1,s_2,R_sh,R_st` 是 KeyGen 的输出。对 public input `inp`、output `out`，存在 witness `W` 和 auxiliary polynomial 满足 Step 2–6 的两个 SIMD R1CS 及 BinaryTwist/BinaryRouter/BinaryShout 关系，当且仅当存在 auxiliary input `w`，使得 `P(inp,w)=out` 在 `T` cycle 内完成。

**证明**：

- 若 `P(inp,w)=out` 在 `T` cycle 内完成，执行 trace（padding 到 `T` cycle）和 memory-checking bookkeeping 定义所有 witness。
- 反过来，假设所有关系成立：
  - BinaryShout 确保每个 cycle fetch 的正是 micro-PC 对应的 `ROM` 行；
  - 两个 SIMD R1CS 在每个 cycle 强制该行规定的状态转移，除了它们延迟的检查；
  - BinaryTwist registers/RAM 确保每次读返回最近写入的值；
  - 两个 BinaryRouter 实例强制 shift/store 语义。
- 对 cycle 归纳，trace 就是 `P` 在 `inp` 和 `W` 中记录的 private input `w` 上的执行；R1CS 把 `inp,out` 绑定到初始/最终状态。

**Theorem 1**：假设 PCS 透明、succinct，且其 evaluation argument 完美完备、public-coin、knowledge error 为 `ε_PCS`。设 `ε_stat` 是 Step 2–7 各 reduction knowledge error 之和，每个都是 `O(log T)/|K|`（机器宽度固定）。则 Construction 3 是 `R_P` 的透明 preprocessing SNARK，限制在执行至多 `T` cycle，knowledge error 至多 `ε_stat+ε_PCS`。

**证明**：完美完备性来自底层 RoK 的完美完备性和 PCS evaluation argument 的完美完备性。Knowledge soundness：`cm_G` 发送后，Step 2–7 是 public-coin reduction of knowledge 的顺序组合：

- Virtual Spartan（Lemma 3）；
- BinaryTwist/BinaryRouter/BinaryShout（Lemma 2、4）；
- MosaicPCS 的 batching + ring-switching；
- 终止的 PCS evaluation argument。

Direct claim 原样传递、component claim lift 到 `G` 都是精确的，不增加误差。由 RoK 组合定理，协议是 Lemma 5 关系的 argument of knowledge，knowledge error 至多 `ε_stat+ε_PCS`；Lemma 5 把提取的 witness 变成 auxiliary input `w`。机器宽度固定时，proof 由常数个 succinct component 组成，因此 succinct。Setup 不用 secret trapdoor，所以 transparent。所有步骤 public-coin，Fiat–Shamir 后在 random oracle 模型下得到非交互 succinct argument of knowledge。

---

## 6 实现与评估

我们在 Rust 中基于 BinarySpartan [51] 实现 Magnetar；PCS 使用 Ligerito [44]。

### 6.1 实验设置

实验环境：

- M4 Max MacBook Pro，12 个性能核，128 GiB 内存；
- 一次只跑一个 prover 进程；
- 每个系统先 warm-up 一次，再取三次运行的中位数；
- Magnetar 报告两个指标：
  - **Proving time**：只含 proof generation；
  - **End-to-end time**：还含 guest 执行和 trace construction。

安全性配置为 **120 bit 可证明安全性**：协议每轮 soundness error 至多 `2^-120`；该界只使用 Reed–Solomon 码在 unique-decoding radius 内的已证明 proximity gap [5]。6.6 节评估 Magnetar opt；其余结果都是 Magnetar。

**Workloads**：15 个应用 workload，覆盖算术、内存访问、数据处理、密码 kernel、智能合约执行。ERC-20 workload 只执行 token logic，不验证签名，也不检查 Keccak Merkle path。

**Table 1：实验 workload**

| # | 简称 | 说明 |
|---:|---|---|
| 1 | fibonacci | 带 64-bit wrapping addition 的 Fibonacci 循环 |
| 2 | hot-cell-increment | 循环递增同一个 64-bit counter |
| 3 | stream-copy | 拷贝 16-word buffer |
| 4 | pointer-chase | 沿 64-node pointer chain 追逐 |
| 5 | binary-search | 在 64 项有序表中二分查找 |
| 6 | radix-sort-u64 | 对 16 个 unsigned 64-bit key 做 radix sort |
| 7 | lz4-decode | 把 17-byte LZ4 block 解压为 32 byte |
| 8 | varint-decode | 解码 10 个 LEB128 值，每个 1–10 byte |
| 9 | sha256 | 软件循环执行 SHA-256 compression |
| 10 | keccak-f1600 | 软件执行 Keccak-f1600 |
| 11 | sha256-merkle-path | 软件计算 8 层 SHA-256 Merkle path |
| 12 | erc20-transfer | 在两个余额之间转移 256-bit amount |
| 13 | erc20-transfer-from | 带 allowance 检查的 transfer |
| 14 | erc20-mixed-block | 多账户间 transfer，每 16 次失败一次 |
| 15 | evm-erc20-transfer | 在小 EVM 解释器中执行 balance transfer |


**Baselines**：在同一台机器上运行 Jolt-Dory、Jolt-Akita [11]、SP1 Hypercube、ZisK、Lineth：

- Jolt commit `7a052796e373`；
- SP1 Hypercube v6.8.0 crates（source revision `58c4aeadbc50`）；
- ZisK commit `b08d856c0f72`；
- Lineth commit `b75b5ca955d8`。

Baseline 的安全级别不同，按发布版本比较：

- SP1 Hypercube 目标 100 bit；
- Jolt-Dory 用 BN254 pairing group，约 100 bit；
- Jolt-Akita 的 Module-SIS commitment 目标 128 bit，但其 128-bit field 上的 sum-check 使整体约 122 bit；
- ZisK 声称 128 bit；
- Lineth 用 Vortex 承诺，其哈希基于 Ring-SIS 格假设；代码声明 128 bit，但本文未验证实际级别。

因此 Magnetar 的 120 bit 高于 SP1 Hypercube/Jolt-Dory 的目标，与 Jolt-Akita 整体相当，低于 ZisK 声称的目标。

不同系统 cycle 计数不同（Magnetar 执行 RV64I，Jolt 执行 RV64IMAC，SP1 Hypercube 又不同），所以 cycle 数不可直接比较。本文对每个系统、每个 workload 固定其自身 cycle budget，取能放下的最大整数个 application-level operation，再比较每秒完成的操作数；每个 baseline 至少填满 98.8% budget。校准例子：一次 Fibonacci step 在 Magnetar 是 6 个 virtual cycle，在 Jolt 是 5 个 cycle，在 SP1 约 6 条指令。

Jolt 的 prover time 不含 tracing；SP1 Hypercube 的 prover time 覆盖 core prove phase，不含 setup 或递归压缩；二者与 Magnetar 的 proving time 可比。

### 6.2 核心 zkVM 速度

**Prover speed**：在 2^22 cycle，Magnetar 在 15 个 workload 上证明 **7.2–8.7 million cycles/s**（Table 3）。Per-workload proving speedup：

- 相对 Jolt-Dory：**12–37×**；
- 相对 Jolt-Akita：**6–20×**；
- 相对 SP1 Hypercube：**24–66×**；
- 几何平均：约 **18×、9.6×、39×**。

即使 Magnetar 的 end-to-end throughput（含 guest 执行）在 15 个 workload 上的几何平均也约为 Jolt-Akita proving throughput 的 **8.7×**。在 `erc20-mixed-block` 上，Magnetar proving rate 随 trace length 增长：从 2^16 的 1.9 million cycles/s 升到 2^22 的 7.7 million（6.4 节）。

Speedup 随 workload 变化，因为它是两个比值的乘积：

1. Magnetar proving rate / baseline proving rate（Magnetar 稳定在 7.2–8.7M cycles/s，变化不大）；
2. baseline cycles per operation / Magnetar cycles per operation（取决于各 ISA 如何处理 workload）。

例如 Jolt 的 trace 在每次 SHA-256 上约是 Magnetar 的 1.4 倍 cycle，但在每个 sorted key 上只有 0.8 倍；所以 Magnetar 相对 Jolt-Akita 在 SHA-256 上约 15×，在 radix-sort-u64 上约 6×。

**Table 2（2^22 cycle 的 application-level throughput；单位见 workload）**

| workload | 单位 | Magnetar proving | Magnetar end-to-end | Jolt-Dory | Jolt-Akita | SP1 Hypercube |
|---|---|---:|---:|---:|---:|---:|
| fibonacci | steps/s | 1,454,419 | 1,326,305 | 97,189 | 149,936 | 33,701 |
| hot-cell-increment | updates/s | 1,386,435 | 1,242,999 | 119,034 | 221,880 | 38,056 |
| stream-copy | words/s | 1,212,866 | 1,109,764 | 66,836 | 111,308 | 28,404 |
| pointer-chase | chases/s | 2,183,642 | 1,951,046 | 94,095 | 153,723 | 33,023 |
| binary-search | searches/s | 102,997 | 93,019 | 5,274 | 11,562 | 2,203 |
| radix-sort-u64 | keys/s | 13,172 | 11,968 | 997 | 2,282 | 468 |
| lz4-decode | bytes/s | 550,207 | 499,288 | 14,883 | 28,040 | 11,934 |
| varint-decode | values/s | 96,491 | 88,168 | 5,981 | 11,838 | 4,041 |
| sha256 | hashes/s | 1,356 | 1,249 | 51 | 91 | 32 |
| keccak-f1600 | permutations/s | 888 | 807 | 53 | 82 | 27 |
| sha256-merkle-path | nodes/s | 530 | 486 | 24 | 44 | 16 |
| erc20-transfer | tx/s | 111,236 | 101,016 | 8,262 | 16,834 | 3,193 |
| erc20-transfer-from | tx/s | 79,357 | 72,144 | 4,741 | 9,707 | 1,855 |
| erc20-mixed-block | tx/s | 94,416 | 86,009 | 7,240 | 15,027 | 2,707 |
| evm-erc20-transfer | tx/s | 21,665 | 19,418 | 966 | 2,057 | 446 |

Proof size / verifier time / peak RSS 的最大值：

| 指标 | Magnetar | Jolt-Dory | Jolt-Akita | SP1 Hypercube |
|---|---:|---:|---:|---:|
| proof size（KiB） | 599 | 89 | 91 | 2,766 |
| verifier time（ms） | 13 | 61 | 8 | 63 |
| peak RSS（GiB） | 6 | 2 | 2 | 26 |


**Memory**：Magnetar prover 还有空间优化余地，但已比 SP1 Hypercube、ZisK、Lineth 省内存：2^22 cycle 时约为 SP1 Hypercube peak RSS 的四分之一，显著低于 ZisK/Lineth（6.3 节）。Magnetar opt 比 Magnetar 少 36–40% 内存（6.6 节）。

**Proof size / verifier time**：2^22 cycle 时，Magnetar proof 约 **600 KiB**，验证 **11–13 ms**。对比：

- Jolt-Dory：89 KiB，约 60 ms；
- Jolt-Akita：91 KiB，<9 ms；
- SP1 Hypercube：core proof（递归压缩前）约 2.7 MiB，约 63 ms；
- Magnetar opt：8–11 ms。

Jolt 的 proof 更小，因为曲线/格承诺用对数个 group/ring element 证明 evaluation，而 hash-based 承诺需要很多查询的 Merkle authentication path。本文预计递归组合后差距会缩小：递归链的最终 proof 只覆盖前一个 proof 的 verifier，计算很小，可以用更低 code rate 生成更小 proof；低 rate 意味着更少查询、更小 proof，额外 prover 工作不大。Magnetar 的递归因此可以“应用用高 rate 证明以保速度，最终 proof 用低 rate 证明以保大小”，不影响端到端 proving 速度。

从 2^16 到 2^22（64 倍 trace length），Magnetar proof 增加 218 KiB，验证时间增加约 3.7 ms（6.4 节）。

**Trace length**：选 2^22 cycle，是因为预计 Magnetar 会把更长执行拆成 2^22–2^24 cycle 的 chunk，并递归组合 chunk proof。Jolt 则把执行证明成一个 monolithic proof，所以 6.5 节也比较了超过 2^22 的 trace。即使 Jolt 跑到 2^28 cycle（本机内存能放下的最长），Magnetar 仍更快。

### 6.3 与 ZisK、Lineth 的比较

ZisK 和 Lineth 在本机生成 proof 需要数分钟，且未必针对笔记本优化，所以只在 `erc20-transfer` 上运行。

**ZisK**：按其他 baseline 校准，71,078 transfers 填满其 2^22-step budget 的约 100%。2^22 cycle 时，Magnetar prover 比 ZisK 本地 CPU prover 快约 **330×**（Table 4），尽管 ZisK 可能未针对 MacBook 优化。ZisK 的 main-machine/ROM/memory/binary-operation 表固定为 2^22 行，所以 trace 更短时 proving time 不下降：17,761 transfers（填满其 2^20-step budget 的约 100%）时 ZisK 需 212 s，Magnetar 在 2^20 的加速比升到约 **1,100×**。

**Lineth**：15,360 transfers 时 Lineth prover 已达 94 GiB；其他系统在 2^22 cycle 能证明 3.8–4.6 倍的 transfers。所以本文在 15,360 transfers 上运行 Lineth，并与 2^20 cycle 的 Magnetar 比较（Magnetar 的 14,528-transfer 输入最接近，Table 5）。由于 Magnetar throughput 随 trace length 增长，这个比较给出的加速比小于 2^22 时会得到的值。Magnetar prover 比 Lineth 快约 **2,500×**，proof 更小、验证更快。

### 6.4 扩展与内存

Table 6 给出 `erc20-mixed-block` 在四种 trace length 下的结果，peak RSS 按整个进程测量：

| trace length | proving (ms) | cycles/s | peak RSS | proof | verify (ms) |
|---:|---:|---:|---:|---:|---:|
| 2^16 | 35 | 1.9M | 0.2 GiB | 380 KiB | 8 |
| 2^18 | 59 | 4.5M | 0.4 GiB | 462 KiB | 9 |
| 2^20 | 157 | 6.7M | 1.6 GiB | 529 KiB | 10 |
| 2^22 | 547 | 7.7M | 6.4 GiB | 598 KiB | 12 |

吞吐随 trace length 增长，2^22 比 2^20 高 14%。trace length 增加 64 倍，peak RSS 从 0.2 GiB 增到 6.4 GiB；proof 和验证时间增长慢得多：proof 增加 218 KiB，验证时间增加约 3.7 ms。

### 6.5 更大 trace

Jolt 的 throughput 随 trace length 增长：其 PCS evaluation argument 成本只随 trace length 的平方根增长，所以在更长 trace 上占比更小。因此本文也比较超过 2^22 cycle 的 trace。

所测 Jolt 版本尚未实现 streaming prover [39]；如果实现，会给 throughput 增加开销。实验从 2^23 cycle 开始，只要“当前长度下最大 peak RSS 的两倍”仍在 96 GiB 内，就把 trace length 翻倍。Magnetar 跑全部 15 个 workload；Jolt-Dory/Jolt-Akita 跑三个：

- `sha256`：Jolt-Akita 已发表结果使用；
- `erc20-transfer`；
- `radix-sort-u64`：Magnetar 相对 Jolt-Akita 在 2^22 领先最小。

Table 7 给出这三个 workload：

| workload | system | 2^22 | 2^23 | 2^24 | 2^25 | 2^26 | 2^27 | 2^28 | lead |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| sha256 (hashes/s) | Magnetar | 1,356 | 1,381 | 1,313 | — | — | — | — | |
| | Jolt-Dory | 51 | 64 | 69 | 71 | 81 | 90 | 97 | 14.2× |
| | Jolt-Akita | 91 | 94 | 91 | 120 | 130 | 160 | 134 | 8.6× |
| erc20-transfer (tx/s) | Magnetar | 111,236 | 111,963 | 106,093 | — | — | — | — | |
| | Jolt-Dory | 8,262 | 9,618 | 10,155 | 11,368 | 13,589 | 13,997 | 15,411 | 7.3× |
| | Jolt-Akita | 16,834 | 18,269 | 18,079 | 21,198 | 21,911 | 26,758 | 23,436 | 4.2× |
| radix-sort-u64 (keys/s) | Magnetar | 13,172 | 13,663 | 13,066 | — | — | — | — | |
| | Jolt-Dory | 997 | 1,214 | 1,280 | 1,578 | 1,859 | 1,955 | 2,135 | 6.4× |
| | Jolt-Akita | 2,282 | 2,450 | 2,398 | 2,918 | 3,041 | 3,785 | 3,261 | 3.6× |

Peak RSS（三个 workload 最大值，GiB）：

| system | 2^22 | 2^23 | 2^24 | 2^25 | 2^26 | 2^27 | 2^28 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Magnetar | 6 | 13 | 25 | — | — | — | — |
| Jolt-Dory | 2 | 4 | 7 | 16 | 25 | 46 | 82 |
| Jolt-Akita | 2 | 3 | 7 | 13 | 21 | 37 | 67 |

Magnetar 只打算跑至多 2^24 cycle 的 trace，更长执行按 chunk 证明（6.2 节）。在这些长度上，Magnetar prover 每 cycle 约用 1.6 KiB 内存；本文尚未进一步优化空间。Jolt 每 cycle 用更少内存：2^22 约 0.5 KiB，2^28 约 0.3 KiB。

从 2^22 到各自最佳长度：

- Jolt-Dory throughput 约翻倍（最佳 2^28）；
- Jolt-Akita 增长 1.6–1.8×（最佳 2^27），但 2^28 时在三个 workload 上都下降；
- Jolt-Akita 在本机的 throughput 与作者报告一致。

按各自最佳长度比较，Magnetar 在三个 workload 上领先 Jolt-Dory **6.4–14.2×**，领先 Jolt-Akita **3.6–8.6×**。与 6.2 节一样，差距主要反映 cycles per operation，而不是 proving rate：仅看 cycles/s，Magnetar 在其最佳长度上比 Jolt-Akita 的最佳长度快 **4.7–6.3×**。

### 6.6 优化版 Magnetar

Magnetar opt 在 Magnetar 基础上增加优化；用相同机器、相同设置、相同操作数/cycle 数、120 bit 安全性重复所有实验，且每个计时的 proof 都验证通过。

Table 8 比较 2^22 cycle：

| workload | Magnetar (M cycles/s) | Magnetar opt | gain |
|---|---:|---:|---:|
| fibonacci | 8.73 | 12.78 | 1.46 |
| hot-cell-increment | 8.32 | 10.08 | 1.21 |
| stream-copy | 7.51 | 10.15 | 1.35 |
| pointer-chase | 8.74 | 10.01 | 1.15 |
| binary-search | 8.06 | 10.40 | 1.29 |
| radix-sort-u64 | 7.19 | 9.98 | 1.39 |
| lz4-decode | 7.62 | 9.89 | 1.30 |
| varint-decode | 7.68 | 10.06 | 1.31 |
| sha256 | 7.55 | 11.08 | 1.47 |
| keccak-f1600 | 7.33 | 10.94 | 1.49 |
| sha256-merkle-path | 7.31 | 11.00 | 1.50 |
| erc20-transfer | 8.01 | 9.63 | 1.20 |
| erc20-transfer-from | 7.70 | 9.76 | 1.27 |
| erc20-mixed-block | 7.66 | 9.53 | 1.24 |
| evm-erc20-transfer | 7.80 | 9.56 | 1.23 |
| **几何平均** | | | **1.32** |
| verifier time (ms) | 12.7 | 10.7 | |
| peak RSS (GiB) | 6.4 | 4.0 | |

Magnetar opt 证明 9.5–12.8 million cycles/s，是 Magnetar 的 1.15–1.50×，几何平均 1.32×。相对 Jolt-Dory/Jolt-Akita/SP1 Hypercube 的几何平均加速因此约为 **24×/12.7×/52×**（Magnetar 为 18×/9.6×/39×）。

从 2^20 到 2^24 cycle，增益随 trace length 增长：15 个 workload 几何平均，Magnetar opt 在 2^20/2^22/2^23/2^24 分别是 Magnetar 的 1.30×/1.32×/1.36×/1.44×。按各自最佳长度比较（Table 7 的三个 workload），Magnetar opt 领先 Jolt-Dory **9.2–21.6×**，领先 Jolt-Akita **5.3–13.1×**（Magnetar 为 6.4–14.2× 和 3.6–8.6×）。

2^22 cycle 时，Magnetar opt prover 比 Magnetar 少 36–40% 内存，最大 peak RSS 为 4.0 GiB，不到 SP1 Hypercube 的六分之一。2^22 到 2^24 时，每 cycle 约 1.0 KiB 内存（Magnetar 为 1.6 KiB）。

---

## 附录 A 符号表

| 符号 | 含义 |
|---|---|
| `B` | `F2` |
| `K` | `F2^128` |
| `ṽ` / `ṽ` | 向量 `v` 的多重线性扩展 |
| `eq(x,b)` | equality polynomial `Π_i (x_i b_i + (1-x_i)(1-b_i))` |
| `R1CS` | rank-1 constraint system |
| `SIMD R1CS` | 同一结构作用于多个 instance-witness 对 |
| `RoK` | reduction of knowledge |
| `PCS` | polynomial commitment scheme |
| `MLE` | multilinear extension |
| `micro-PC` | 展开后 virtual instruction 的程序计数器 |
| `direct segment` | 被承诺的 witness segment |
| `virtual segment` | 被 R1CS 读取但不承诺的 witness segment |
| `one-hot` | 地址/select 的 one-hot 表示 |
| `Twist` | 可变内存一致性 argument |
| `Shout` | public read-only table lookup argument |
| `Router` | bit routing sum-check argument |
| `MosaicPCS` | 多 polynomial packing + 单 commitment/evaluation |
| `Virtual Spartan` | 按 segment 输出 evaluation claim 的 Spartan 变体 |

## 附录 B 术语表

- **succinct**：proof length 和 verifier time 是 structure/witness size 的 polylog。
- **transparent**：setup/KeyGen 不需要 secret trapdoor。
- **knowledge soundness**：成功 prover 必须“知道” witness，存在 extractor。
- **reduction of knowledge**：把一个关系的 witness 检查归约成另一个关系。
- **Fiat–Shamir**：用哈希把 public-coin 交互协议变成非交互 proof。
- **ring switching**：把 binary vector 上的 evaluation claim 归约成 packed field element 表示上的 claim。
- **one-hot address**：地址用一个长度为 `K` 的 bit vector 表示，只有被选中的 cell 为 1。
- **increment**：`Inc = old XOR new`，用于 BinaryTwist 表达 RAM 更新。
- **collision polynomial**：检测 one-hot 行中是否有两个位置同时为 1 的多项式。
- **bit routing**：每个输出 bit 是 0 或某个输入 bit 的拷贝；shift/store 都属于此类。
- **micro-PC**：指令展开后每个 virtual instruction 的公共索引；用于 ROM、selector、recursion 对齐。

---

## 参考文献

参考文献保留英文原貌，编号与原文一致。由于篇幅较长，此处不逐条重排；请参见原文 `papers/magnetar-2026-2423.pdf` 的 References。正文中引用的关键工作包括：

- Spartan [50]、BinarySpartan [51]；
- Twist and Shout [55]；
- Ligerito [44]；
- Jolt [1,25]、Jolt-Akita [11]；
- SP1 Hypercube [56,57,58,59]；
- ZisK [45,62]；
- Lineth [35]；
- Reed–Solomon proximity gaps [5]；
- ring switching [13]；
- JaggedPCS [23]、Spark [50]。

---

*译稿完。*
