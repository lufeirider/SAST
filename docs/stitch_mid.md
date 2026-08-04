# stitch_mid：反射中间点与双向拼接

本文用白话说明 **stitch_mid** 是什么、为什么要有、怎么拼，以及和「上万条链」数字怎么区分。  
实现见 `analyze/reflective.py`、`analyze/dynamic_cha_chains.py`；算法总览见 [`call_chain_stitch.md`](call_chain_stitch.md)。

> 命名：曾叫 hub（枢纽）。为避免和旧版硬编码 mid catalog 混淆，现统一为 **stitch_mid**（拼接用的中间点）。也可称 reflect_mid，含义相同。

---

## 1. stitch_mid 是什么

**stitch_mid** = 项目里调用了反射派发 API 的方法，例如：

| 方法 | 反射 API |
|------|----------|
| `InvokerTransformer#transform` | `Method#invoke` |
| `InstantiateTransformer#transform` | `Constructor#newInstance` |

在调用图上它像**中转站**：左边很多 `readObject` 路径汇到这里，右边再经反射接到危险目标 / sink。查链时在这里做 **A/B/C 双向拼接**，而不是从入口一次正向猜出所有反射目标。

---

## 2. 为什么要用 stitch_mid（是因为太多吗？）

**对，主要是因为「太多」+「推不出具体类型」。**

以 `InstantiateTransformer#transform` 为例：

```java
Constructor con = ((Class) input).getConstructor(iParamTypes);
return con.newInstance(iArgs);
```

- `input` 运行时要求是 **`Class`**（攻击者可控）
- `iParamTypes` / `iArgs` 也是对象字段，gadget 场景下也可控
- 源码里通常**没有** `forName("…TrAXFilter")` 常量 → 静态**推不出**一定是哪个类

若分析器按「可能 new 任意类」去连 classpath **全部构造器**（CC_FULL 约 1.7 万），单点扇出极大，路径爆炸。

因此：

1. **不能**在 mid 上开放「全世界构造器」  
2. **改用**两边夹逼：左边搜到 mid，右边只保留「能到当前 sink 的危险构造器」，在 mid 上接上  

stitch_mid 不是多一层概念好玩，而是：**反射缺口太大时，用有界拼接代替无界扇出。**

---

## 3. 怎么拼接：CC3 例子

### 设定

- **Entry**：`AnnotationInvocationHandler#readObject`
- **stitch_mid**：`InstantiateTransformer#transform`（`Constructor#newInstance`）
- **Sink**：`TemplatesImpl#defineTransletClasses`

### A — 正向：entry → stitch_mid

只走 `CALLS` + 按需 CHA + 常量反射（**关闭**开放构造器扇出）：

```text
AnnotationInvocationHandler#readObject
→ LazyMap#get
→ ChainedTransformer#transform
→ InstantiateTransformer#transform    ← 前缀 P（停在 stitch_mid）
```

此时链上还没有 `TrAXFilter`。

### B — 反向：sink ← 危险目标

从 sink 做反向 BFS（含逆 CHA，例如调用了接口 `Templates#newTransformer` 的也能挂到 `TemplatesImpl#newTransformer`）：

```text
defineTransletClasses
← getTransletInstance
← TemplatesImpl#newTransformer
← TrAXFilter#TrAXFilter(Templates)    ← 危险构造器
```

得到后缀 S：

```text
TrAXFilter#TrAXFilter(Templates)
→ TemplatesImpl#newTransformer
→ getTransletInstance
→ defineTransletClasses
```

### C — 在 stitch_mid 处拼

mid 调了 `Constructor#newInstance` → 规则：

```text
完整链 = 前缀 P + 危险构造器路径 S
```

拼完：

```text
AnnotationInvocationHandler#readObject
→ LazyMap#get
→ ChainedTransformer#transform
→ InstantiateTransformer#transform          ← stitch_mid
→ TrAXFilter#TrAXFilter(Templates)          ← 拼上去的反射目标
→ TemplatesImpl#newTransformer
→ getTransletInstance
→ defineTransletClasses                     ← sink
```

**刻意不让** `InstantiateTransformer` **直连** `defineTransletClasses`，否则链上会丢掉 `TrAXFilter`，和真实利用形态不一致。

对 `Method#invoke` 类 mid（如 InvokerTransformer），开放目标通常直接是**当前 sink 集合**（再加常量 `getMethod` 边）：`entry→stitch_mid→sink`。

---

## 4. 为什么能把 TrAXFilter 构造器拼上去？

### 运行时（利用语义）

入参是 `Object`，但会当成 **`Class`** 用：攻击者可令 `input = TrAXFilter.class`，`iArgs` 带 `Templates`，于是进入 `TrAXFilter#TrAXFilter(Templates)`。  
「任意」的是 **要 new 哪个 Class**，不是任意实例上乱调方法（那是 Invoker 那条线）。

### 分析时（我们为什么敢拼）

**不是**类型推断出了 `TrAXFilter`，而是过近似：

1. 看见 mid 调了 `Constructor#newInstance` → 认为可能 new 外部给定的类  
2. 从 sink 反向得到「能到 sink 的构造器」集合（含 `TrAXFilter#…`）  
3. 把该集合挂到 mid 后面  

即：**「任意 Class 都可能」→ 只拼「能通向当前 sink 的构造器」**，不是拼全世界。

---

## 5. 和「14401 条 InstantateTransformer」别混

查链时若把 `InstantiateTransformer#transform` **自己也列为 sink**，会出现大量：

```text
readObject → … → InstantiateTransformer#transform   （到此结束）
```

例如经典 6 入口 + `CHA_MAX=100` 时，曾统计到约 **14401** 条终点为 IT 的链。  
这些主要是：**很多路能走到这个 mid/sink**（CHA、多入口、路径全保留），**不是**「任意类全连了一遍」。

经 stitch_mid **再拼出去**到 `TemplatesImpl` 的链，终点记在 TemplatesImpl 上（例如数百条 `defineTransletClasses`），和那 14401 不是同一桶。

| 数字含义（示例） | 实际在说什么 |
|------------------|--------------|
| 上万条 → IT | 能到反射跳板 / 把 IT 当 sink 的路径很多 |
| 数百条 → TemplatesImpl | 穿过 mid 拼到字节码加载类 sink 的路径 |

**路径条数 ≠ 独立可利用 gadget 条数**；答案键（CC1–CC7）才是经典形态对照。

---

## 6. 速度怎么样？

| 阶段 | 相对快慢 | 说明 |
|------|----------|------|
| B 反向危险构造器 | 较快 | sink 少，有界 |
| C 拼接 | 看数量 | 前缀 × 危险 ctor；全保留时条数会多 |
| A entry→mid | **最贵** | CHA、大量 `readObject`、visit budget |

经验：

- stitch_mid 比「全世界构造器」**快得多、也可控得多**  
- 相对「只做精确 CALLS」仍多 B+C；**全量入口时瓶颈多半在 A（CHA），不在拼接几行代码**  
- 经典少数入口：约分钟内可出结果；全量数百 entry + 大 `CHA_MAX_CALLEES` 会很慢

---

## 7. 和旧「mid catalog」的区别

| | 旧 mid catalog | 现 stitch_mid |
|--|----------------|---------------|
| 是什么 | 硬编码中间 gadget 名单，靠名单串链 | 图上真实的 `invoke`/`newInstance` 调用方 |
| 策略 | Entry 留、Mid 目录删 | 无名单；sink 反向 + 拼接 |
| 目的 | 人工点名中间类 | 有界补全反射缺口 |

不要把 stitch_mid 理解成「又把 mid 目录加回来了」。

---

## 8. 相关配置与文件

- `CHA_MAX_CALLEES`（`parse/config.py`）：每个虚调用 CHA 最多保留 N 个 override（截断，不是找全）——影响的是 A 的扇出，不是「全世界构造器」  
- `max_paths_per_stitch_mid`：每个 mid 的 entry→mid 前缀条数；默认 `0` = 不截断（只去环、去精确重复）  
- 发现 mid：`ReflectiveEdgeIndex.stitch_mids`  
- 拼接：`DynamicChaChainFinder` 的 A/B/C（`_stitch_at_mids`）

更完整的边类型、逆 CHA、旋钮说明见 [`call_chain_stitch.md`](call_chain_stitch.md)。
