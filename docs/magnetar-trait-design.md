# Magnetar 组件 trait 化设计分析

> 结论：**可以 trait 化，但不建议"七层各一个 trait"**。应按"可替换的协议行为"切 4 组 seam trait，加上 3 个协议数据模型；其余保持具体类型/枚举。这样新增 Virtual Spartan、Shout selector 认证、packed Mosaic、Ligerito eval 时，不需要改其他组件。

## 1. 先区分"层"和"可替换行为"

七层里并不是每层都是一个行为组件：

| 层 | 性质 | 是否 trait 化 |
|---|---|---|
| 1 KeyGen / preprocessing | 行为（ISA 展开、ROM/layout 生成） | 是：`Preprocessor` |
| 2 Witness / segments | 数据布局 | 部分：`WitnessLayout` 数据 schema；`Witness` 本身不做 trait |
| 3 Commit | PCS 行为 | 是：`MosaicPcs` / `Pcs` |
| 4 Virtual Spartan | 归约行为 | 是：`CpuReduction` |
| 5 Twist/Shout/Router | 归约行为 | 是：`SegmentReducer`（一个 trait，多实现） |
| 6 Mosaic lift/batch/ring-switch | PCS 适配行为 | 是：`ClaimBatchPcs`（可由 `MosaicPcs` 提供） |
| 7 Verify / recursion | 验证行为 | 是：`ProtocolVerifier`；递归单独 `RecursiveVerifier` |

关键：**第 4、5 层之间的接口不是"函数调用"，而是 typed claim 的传递**。因此核心抽象应该是 `Claim`/`SegmentId`/`ClaimSet`，而不是给每个 stage 一个泛型 `prove/verify`。

## 2. 推荐的四组 seam traits

### 2.1 `Preprocessor`：public KeyGen

```rust
pub trait Preprocessor {
    type Layout: WitnessLayout;
    type Error;

    fn expand(
        &self,
        program: &ProgramImage,
        config: &MachineConfig,
    ) -> Result<ExpandedProgram, Self::Error>;

    fn layout(
        &self,
        expanded: &ExpandedProgram,
        max_cycles: usize,
    ) -> Result<Self::Layout, Self::Error>;
}
```

`ExpandedProgram` 是具体数据：public bytecode ROM、`s1/s2` 结构引用、`Rsh/Rst`、micro-PC 表。trait 只负责"如何从程序生成这些数据"，不把 ROM 本身变成 trait。

### 2.2 `CpuReduction`：Virtual Spartan

```rust
pub trait CpuReduction<W> {
    type Proof;
    type Error;

    fn prove(
        &self,
        ctx: &ProtocolContext,
        witness: &W,
        transcript: &mut dyn Transcript,
    ) -> Result<(Self::Proof, SegmentClaims), Self::Error>;

    fn verify(
        &self,
        ctx: &ProtocolContext,
        commitment: &MosaicCommitment,
        proof: &Self::Proof,
        transcript: &mut dyn Transcript,
    ) -> Result<SegmentClaims, Self::Error>;
}
```

`SegmentClaims` 是 `Vec<(SegmentId, Claim)>`，direct/virtual 用 `ClaimKind` 标记。当前 `prove_lockstep`/`verify_lockstep` 可以直接包成一个实现；未来 Virtual Spartan 是另一个实现，Twist/Shout/Router 完全不用改。

### 2.3 `SegmentReducer`：Twist / Shout / Router

```rust
pub trait SegmentReducer<W> {
    type Proof;
    type Input;    // e.g. RegisterClaim, RamClaim, ShiftClaim, StoreClaim, BytecodeClaim
    type Output;   // must convert into ClaimSet
    type Error;

    fn prove(
        &self,
        ctx: &ProtocolContext,
        witness: &W,
        input: &Self::Input,
        transcript: &mut dyn Transcript,
    ) -> Result<(Self::Proof, Self::Output), Self::Error>;

    fn verify(
        &self,
        ctx: &ProtocolContext,
        commitment: &MosaicCommitment,
        input: &Self::Input,
        proof: &Self::Proof,
        transcript: &mut dyn Transcript,
    ) -> Result<Self::Output, Self::Error>;
}
```

实现：

- `TwistRegisters`：`Input = RegisterClaim`，`Output = TwistOutput`；
- `TwistRam`：`Input = RamClaim`，`Output = RamOutput { inc_claim, ... }`；
- `RouterShift`：`Input = ShiftClaim`，`Output = RouterOutput { source_claims, selector_claims }`；
- `RouterStore`：`Input = StoreClaim`（含 RAM 的 `Inc`），`Output = RouterOutput`；
- `Shout`：`Input = BytecodeClaimSet`（bytecode + register-index + selector），`Output = FetchClaimSet`。

这一组是"补缺口不影响别人"的关键：新增一个 reducer 只需实现 trait，并在 `ProtocolPlan` 里注册，不改已有实现。

### 2.4 `ClaimBatchPcs` / `MosaicPcs`：最终 PCS

```rust
pub trait MosaicPcs {
    type Commitment;
    type Proof;
    type Error;

    fn commit(&self, components: &[Component]) -> Result<Self::Commitment, Self::Error>;

    fn prove_claims(
        &self,
        components: &[Component],
        claims: &[Claim],
        transcript: &mut dyn Transcript,
    ) -> Result<Self::Proof, Self::Error>;

    fn verify_claims(
        &self,
        commitment: &Self::Commitment,
        claims: &[Claim],
        proof: &Self::Proof,
        transcript: &mut dyn Transcript,
    ) -> Result<(), Self::Error>;
}
```

`P3SharedPcs` 先实现；未来 `PackedSharedPcs` / Ligerito 实现同一 trait。`lift/batch/ring-switch` 属于这个实现内部，不需要暴露给 stage。

### 2.5 `Transcript` / `ProtocolVerifier`

```rust
pub trait Transcript {
    fn absorb(&mut self, label: &str, bytes: &[u8]);
    fn challenge(&mut self, label: &str) -> F2_128;
    fn fork(&self, label: &str) -> Self where Self: Sized;
}
```

`ProtocolVerifier` 只负责按 `ProtocolPlan` 调度 stage 和 claim bus；递归 verifier 用另一个 trait，因为它是电路约束，不是 native 验证。

## 3. 三个数据模型（比 trait 更重要）

### 3.1 `SegmentId` + `WitnessLayout`

```rust
#[derive(Clone, Copy, Eq, Hash, Serialize, Deserialize)]
pub struct SegmentId(pub u16);

pub trait WitnessLayout {
    fn segments(&self) -> &[SegmentSpec];
    fn segment(&self, id: SegmentId) -> Option<&SegmentSpec>;
}

pub struct SegmentSpec {
    pub id: SegmentId,
    pub kind: SegmentKind,     // Direct | Virtual(ComponentKind)
    pub offset: usize,
    pub len: usize,
    pub suffix: Vec<F2_128>,   // MosaicPcs subcube suffix
}
```

`Witness` 本身是 `Vec<F2_128>`/`WitnessValues`，不是 trait。把 witness 做成 trait 会让所有 PCS/电路代码泛型化，收益低。

### 3.2 `Claim` + `ClaimSet`

```rust
pub enum Claim {
    Direct { segment: SegmentId, point: Vec<F2_128>, value: F2_128 },
    Register { segment: SegmentId, point: Vec<F2_128>, value: F2_128 },
    Ram { ... },
    Shift { ... },
    Store { ... },
    Bytecode { ... },
}

pub struct ClaimSet { claims: Vec<Claim> }
```

`Claim` 是 wire format；`ClaimSet` 有 `take(kind)`、`expect_consumed()`，防止某个 claim 被静默漏掉。论文的 Shout 必须消费 register-index/selector claims；这个约束应该在 `ClaimSet` 层强制，而不是靠调用顺序。

### 3.3 `ProofBundle` 用 enum，不用 `dyn Proof`

```rust
pub enum StageProof {
    Cpu(CpuProof),
    Registers(BinaryTwistProof),
    Ram(BinaryTwistProof),
    Shift(BinaryRouterProof),
    Store(BinaryRouterProof),
    Shout(BinaryShoutProof),
    Final(MosaicProof),
}

pub struct ProofBundle {
    pub commitment: MosaicCommitment,
    pub stages: Vec<(StageId, StageProof)>,
}
```

trait 用于算法；enum 用于序列化/协议边界。不要 `Box<dyn Proof>`，否则 bincode/递归/电路都不好处理。

## 4. 为什么不能只做一个 `Stage` trait

一个泛型 `Stage`：

```rust
trait Stage { type Input; type Output; fn prove(...); fn verify(...); }
```

看起来统一，但会导致：

1. **异构 pipeline 无法放进 Vec**：每个 stage 的 `Input/Output/Proof` 不同，只能靠 enum 包起来；
2. **claim 依赖是 DAG，不是线性链**：Twist RAM 的输出同时给 PCS 和 Router store；Router 的输出给 Shout 和 PCS；一个 `Input/Output` 很难表达 fan-out；
3. **安全顺序**：Shout 必须在 Router selector 之后、最终 PCS 之前；泛型 stage 不会强制这一点；
4. **`dyn` 对象安全**：associated types + `Pcs` 泛型让 `dyn Stage` 不可行；monomorphize 又会二进制膨胀。

所以：**stage 是 `ProtocolPlan` 的数据，不是 trait 对象**。trait 只负责每个 reducer 的算法边界。

## 5. 建议的 crate/module 结构

```text
magnetar-protocol/          // 新：协议层，不依赖具体 CPU/PCS
  claim.rs                  // SegmentId, Claim, ClaimSet, SegmentKind
  layout.rs                 // WitnessLayout, SegmentSpec
  plan.rs                   // ProtocolPlan, StageSpec, claim edges/DAG
  traits.rs                 // Preprocessor, CpuReduction, SegmentReducer, MosaicPcs, Transcript
  proof.rs                  // StageProof enum, ProofBundle
  orchestrator.rs           // prove/verify 按 plan 调度

magnetar-machine/           // RV64I 具体实现
  preprocess.rs             // micro-PC expansion, ROM, Rsh/Rst, s1/s2
  witness.rs                // WitnessValues, layout construction
  cpu/                      // row systems, lockstep, virtual spartan impl

magnetar-components/        // 各自 reducer
  twist_registers.rs
  twist_ram.rs
  router_shift.rs
  router_store.rs
  shout.rs

magnetar-pcs/               // 已有
  p3.rs, mosaic.rs, packed.rs, ligerito.rs
```

现有 `magnetar-runtime` 保留为 façade：`prove_unified_trace` 变成 `Orchestrator` 的 thin wrapper，旧 API 不破坏。

## 6. 迁移顺序（低风险）

### Phase 1：只抽数据模型，不改协议

- 新增 `SegmentId`/`Claim`/`SegmentClaims`；
- 把 `UnifiedTraceProof` 里的组件 proof 包成 `StageProof` enum；
- 现有 `prove_*`/`verify_*` 签名不变，内部构造 `ClaimSet`；
- golden test：proof bytes 完全不变。

这一步就能让后续组件独立测试。

### Phase 2：把现有 reducer 包成 trait 实现

- `TwistRegisters`、`TwistRam`、`RouterShift`、`RouterStore`、`Shout` 各实现 `SegmentReducer`；
- `prove_lockstep` 实现 `CpuReduction`；
- `P3SharedPcs` 实现 `MosaicPcs`；
- 用 fake claim bus 做单元测试，不跑完整 unified。

### Phase 3：引入 `ProtocolPlan` 和 `Orchestrator`

- 把 `prove_unified_trace` 的硬编码顺序改成 plan；
- `ClaimSet` 强制每个 claim 被消费；
- 旧 `UnifiedTraceProof` 由 `ProofBundle` 生成，保持 wire compatibility 或加版本号。

### Phase 4：补论文缺口

- 新 `VirtualSpartan` 作为 `CpuReduction`；
- Router 输出 `selector_claims`，Shout 消费；
- `PackedSharedPcs` 作为 `MosaicPcs`；
- Ligerito eval 作为 `MosaicPcs` 的另一个实现；
- 递归 verifier 单独 trait。

## 7. 风险与约束

1. **不要过度 trait 化 witness/field**：`Witness`、`F2_128` 先保持具体类型；字段泛型化会把整个代码库拖入 const generics/associated-type 地狱。
2. **`Pcs` 已经存在**：用 `magnetar-proof::Pcs`，不要重复造；Mosaic 是 adapter，不是第二套 Pcs。
3. **对象安全**：`MosaicPcs`/`Preprocessor` 用泛型 monomorphize；只对 `Transcript`/`ProtocolVerifier` 用 `dyn`。
4. **序列化**：proof 边界用 enum + version；不要序列化 trait object。
5. **安全顺序**：`ProtocolPlan` 必须显式声明 `consumes/produces`，并验证 DAG；不能只靠 Vec 顺序。
6. **trait 粒度**：一个 `SegmentReducer` 足够；不要给 `BinaryTwist` 内部再拆 address/read/write/update 四个 trait，否则补缺口会变成改 20 个 impl。
7. **测试策略**：每个 reducer 用固定 witness + fake claim 做 standalone test；orchestrator 用 golden proof bytes/negative tests；避免只靠 unified 端到端测试。

## 8. 结论

- **可以 trait 化，而且值得做**，但应按 **claim 边界** 切，不是按七层切。
- 最小可行集合：`Preprocessor`、`CpuReduction`、`SegmentReducer`、`MosaicPcs` + `Transcript`，外加 `SegmentId`/`Claim`/`ProofBundle` 三个数据模型。
- 这样：
  - 新增 Virtual Spartan 不动 Twist/Shout/Router；
  - 新增 Shout selector 认证只改 Router 的 `Output` 和 Shout 的 `Input`；
  - P3 → packed → Ligerito 只改 `MosaicPcs` 实现；
  - 补缺口不再牵动 `lib.rs` 的 6000 行编排。

建议先做 **Phase 1（数据模型 + ProofBundle，不改 proof bytes）**，这是收益最高、风险最低的一步。
