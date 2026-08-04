# 调用链查找：动态 CHA + stitch_mid 双向拼接

本文沉淀 gadget / 确认 sink 上的 **call-chain** 策略（实现：`analyze/dynamic_cha_chains.py`、`analyze/reflective.py`）。  
标准 CC 答案键见 [`rules/cc_gadget_answer_chains.md`](../rules/cc_gadget_answer_chains.md)。  
**动态 CHA（含 CC 例子）**见 [`dynamic_cha.md`](dynamic_cha.md)。  
**stitch_mid 概念与 CC3 拼接例子（白话）**见 [`stitch_mid.md`](stitch_mid.md)。  
**CHA / Object 扇出热点与 cha_mid 夹逼**见 [`cha_virtual_mid.md`](cha_virtual_mid.md)。

---

## 1. 总览

```
Entry (readObject / readExternal)
        │
        │  A  forward：CALLS + 按需 CHA + 常量反射
        ▼
   stitch_mid              （Method#invoke / Constructor#newInstance 的调用方）
        │
        │  C  stitch：stitch_mid → 反射目标
        ▼
   Dangerous target        （危险构造器 / sink 方法）
        │
        │  B  已由 sink 反向算出 target→sink
        ▼
      Sink
```

同时保留 **不经 stitch_mid** 的直达路径：`entry ──CALLS/CHA──► sink`（如已确认的 `InvokerTransformer#transform`）。

---

## 2. 入口与边类型

| 要素 | 规则 |
|------|------|
| Entry | 仅 `readObject` / `readExternal`（`analyze/neo4j_store.py`） |
| 精确边 | Neo4j `CALLS`（parse 落库，虚调用只存解析目标，如 `Map#get`） |
| CHA | **查询时按需**展开子类型 override（不物化全图 `CHA_CALLS`） |
| **`CHA_MAX_CALLEES`** | **默认 100：每个虚调用点最多只留 100 个 CHA 目标（排序后截断，不是找全）** |
| `Object#toString` 等 | 按方法名对齐可序列化 / focus 类型上的同名方法（同样受上项上限） |
| 常量反射 | 同一方法（含 `<clinit>`）内 `forName`/`getMethod` 字符串字面量 → 具体 Method QN |

### `CHA_MAX_CALLEES = 100`（务必记住）

配置在 `parse/config.py`。含义：

```text
虚调用解析目标（如 Map.Entry#setValue）
  → CHA 枚举子类型/实现类上的同名方法（可能几十～上百）
  → 按 focus / 可序列化等排序
  → 只保留前 CHA_MAX_CALLEES 个进入 BFS
```

**不是**「会覆盖全部 CHA 相关类」，**是**「每个调用点最多跟 N 个 override」（当前 N=100）。

曾用 24 时的后果（CC1-1）：

- `Map.Entry#setValue` 在 CC_FULL 约有 50+ 个 `*#setValue`
- top-24 里可能没有 `AbstractInputCheckedMapDecorator.MapEntry#setValue`
- 于是走不到 `checkSetValue`；调到 100 后该 override 可进入候选

调参：再增大可继续提高召回；扇出与链数会变大。`Collection#add` 等仍可能超过 100 被截断。

---

## 3. 为什么需要 stitch_mid 拼接

`InstantiateTransformer#transform` 形如：

```java
Constructor con = ((Class) input).getConstructor(iParamTypes);
return con.newInstance(iArgs);
```

- `Class` / `iParamTypes` / `iArgs` 在 gadget 场景下均可视为**外部可控**（参数或可序列化字段）
- 源码里**没有** `forName("…TrAXFilter")`，常量反射推不出目标
- 若把 `Constructor#newInstance` 连到 classpath **全部**构造器（CC_FULL 约 1.7 万），单点扇出约 500×，路径会爆炸

因此采用 **有界过近似**：反射目标 =「能到达当前分析 sink 的危险构造器 / sink 方法」，在 stitch_mid 处拼接，而不是全世界。

---

## 4. 三阶段（A / B / C）

### A — `entry ──forward──► stitch_mid`

- 边：`CALLS` + 按需 CHA + **常量**反射边
- **关闭**开放反射扇出（不在 BFS 里 `stitch_mid → 全部 sink/构造器`）
- 命中 stitch_mid 时记录 `entry→…→stitch_mid` 路径（`max_paths_per_stitch_mid`，默认不截断）
- 命中 sink 时直接记链（无需反射）

**stitch_mid 定义**：项目内 `CALLS` 到

- `java.lang.reflect.Method#invoke…`，或
- `java.lang.reflect.Constructor#newInstance…`

的方法（例如 `InvokerTransformer#transform`、`InstantiateTransformer#transform`）。

### B — `sink ◄──backward── 危险目标`

从当前查询的 sink 集合做 **反向 BFS**（`CALLS` 逆边）：

1. 精确前驱：谁 `CALLS` 当前方法
2. **逆 CHA**：当前方法若是某超类型槽位的 override，则同时取「调用了超类型同名方法」的前驱  
   - 例：`TemplatesImpl#newTransformer` ←（逆 CHA）← 调用了 `Templates#newTransformer` 的 `TrAXFilter#<init>`
3. 落在前驱集合中的 **构造器**（方法名 = 简单类名）视为 **dangerous ctors**
4. 为每个 dangerous ctor 保留一条最短 `ctor→…→sink` 路径
5. 条数 / 深度有上限；focus 类型构造器若反向未命中，可用短正向补强

`Method#invoke` 的开放目标直接取 **当前 sink 集合**（外加该 stitch_mid 上的常量反射边）。

### C — 在 stitch_mid 处拼接

| stitch_mid 类型 | 拼接形态 |
|----------|----------|
| `Constructor#newInstance` | `entry→stitch_mid` + `ctor` + `ctor→sink`（**禁止** `stitch_mid` 直连 sink，避免丢掉 `TrAXFilter`） |
| `Method#invoke` | `entry→stitch_mid` + `sink`（或常量目标再短正向到 sink） |

整条链长度上限约为 `max_depth + backward_depth`，避免后缀被裁掉。

---

## 5. 与「全世界 / 仅 focus」的对比

| 策略 | 扇出 | 问题 |
|------|------|------|
| 全世界构造器 | ~10⁴ / 点 | 路径爆炸、噪声极大 |
| 仅 focus 构造器 | 小 | 依赖人工 focus；易漏 |
| **Sink 反向危险构造器 + stitch_mid 拼接** | 随 sink 走，通常几十～上百 | 需逆 CHA；实现复杂度中等 |

安全语义仍是「外部可控的 Class → 匹配构造器」，搜索空间由 **sink 可达性**界定。

---

## 6. CC3 对照例（验证形态）

```
AnnotationInvocationHandler#readObject
→ LazyMap#get
→ ChainedTransformer#transform
→ InstantiateTransformer#transform          ← stitch_mid (newInstance)
→ TrAXFilter#TrAXFilter(Templates)        ← B 挖出的危险构造器
→ TemplatesImpl#newTransformer
→ TemplatesImpl#getTransletInstance
→ TemplatesImpl#defineTransletClasses       ← sink
```

- A：走到 `InstantiateTransformer#transform`
- B：从 `defineTransletClasses` 反向（含 `Templates#newTransformer` 槽）得到 `TrAXFilter` 构造器
- C：拼接出上链（链上保留 `TrAXFilter`，而非 `IT → TemplatesImpl` 捷径）

---

## 7. 关键文件与旋钮

| 文件 | 职责 |
|------|------|
| `analyze/reflective.py` | stitch_mid 发现、常量 `getMethod`/`forName`、开放目标接口 |
| `analyze/dynamic_cha_chains.py` | 按需 CHA、A/B/C、`find_chains` |
| `analyze/neo4j_store.py` | Entry 列举、调用 `DynamicChaChainFinder` |

`find_chains` 常用参数：

- `max_depth`：A 正向深度
- `backward_depth`：B 反向深度（默认 5）
- `max_dangerous_ctors`：危险构造器上限（默认 80）
- `max_paths_per_stitch_mid`：每个 stitch_mid 的 entry→stitch_mid 路径数；**默认 0 = 不截断**（只去环、去精确重复），与 sink 路径策略一致

---

## 8. 局限（已知）

- 逆 CHA 是「同名超类型槽」近似，不是完整反向虚调用解析
- 开放 `invoke → 全部当前 sink` 仍可能产生捷径噪声，需报告侧去重 / 人工看
- 过程内污点、字段约束未证明「可利用」；流水线 **C1**（`analyze/chain_taint.py`）仅做跳边污点连续性初筛（见 [`taint.md`](taint.md)），call chain ≠ gadget 证明
- Entry 很多时 A 仍可能慢；可对 stitch_mid / entry 结果做缓存（未默认开启）

---

## 9. 演进备忘

曾考虑但未采用：classpath 全量构造器扇出。  
可选增强：按 `iParamTypes` arity / 字段图类型收窄 dangerous ctors；stitch_mid 路径按 project 缓存；报告里标注 `stitch=new|invoke`。
