# 简单污点分析（过程内）

实现：`analyze/taint.py`  
CLI：`run_analyze.py --mode vuln|gadget`  
Sink 规则：`rules/sinks.json`（Tabby 对齐）

本文说明 **gadget 模式**下的 source / 传播 / 报到 sink 的规则；并对照 **vuln** 模式。

---

## 1. 两种模式对照

| | **gadget**（找利用链） | **vuln**（找漏洞） |
|--|------------------------|-------------------|
| 目标 | 反序列化 / 反射 gadget | 普通入口漏洞 |
| Source | **类字段** + **方法参数** | 仅 **方法参数** |
| 字段默认 | 视为攻击者可控 | 不默认污染 |
| 入口 | `readObject` / `readExternal` 视为反序列化入口 | 无此特殊入口 |

默认模式见 `analyze/config.py` 的 `TAINT_MODE`。

---

## 2. Gadget：Source

在 **gadget** 模式下，对当前正在分析的方法，污点集合初始为：

1. **类属性（字段）**  
   - 当前类型 `TypeInfo.fields` 里每个字段名  
   - 语义：反序列化后字段可被攻击者拼装，默认可控  

2. **函数参数**  
   - 当前方法形参名  
   - 语义：调用方传入的参数也视为可控（含 `readObject(ObjectInputStream s)` 的流参数等）  

实现要点（`_seed_sources`，gadget）：

- **字段**：当前类型全部字段名加入污点集  
- **参数**：当前方法全部形参名加入污点集  

标识符抽取：从表达式里取名字；`this.field` 会收成 `field`。

---

## 3. 传播（赋值）

**只沿赋值边传播，过程内、迭代不动点（最多 32 轮）。**

规则：

```text
x1 = <右侧任意表达式>
```

若右侧表达式里出现**任意已污染标识符**，则左侧 `x1` 被污染。

也就是说：

```text
x1 = xxx + x2
```

只要 `xxx` 或 `x2`（或右侧其它标识符）已在污点集中，**整次赋值把污点传到 `x1`**——不要求「整段 RHS 都是污点」，也**不做**算数/字符串运算的精细语义，只看标识符是否出现在 RHS。

更多例子：

| 赋值 | 若已污染 | 结果 |
|------|----------|------|
| `a = field` | `field` | `a` 污染 |
| `a = xxx + x2` | `x2` | `a` 污染 |
| `a = foo(x2, 1)` | `x2` | `a` 污染（RHS 含 `x2`） |
| `a = "const"` | — | 不传播 |
| `this.x = y` | `y` | `x` 污染（去掉 `this.` 前缀） |

**不做**：

- 跨方法 / 过程间传播  
- 字段写后读的堆模型（除通过赋值里的名字）  
- 控制流敏感（分支、循环按收集到的赋值列表迭代）  

---

## 4. Sink 与「污点命中」

Sink 来自 `rules/sinks.json`（按类 + 方法，优先 `CallSite.resolved_qn`）。

对每个 sink 调用点：

1. 按 Tabby 规则的 `polluted` 下标检查 **receiver / 参数** 是否含已污染标识符  
2. gadget 下若下标未命中，会放宽：receiver 或任一参数表达式里出现污点名也算命中  
3. gadget 下对 `readObject` 等 SERIALIZE 类调用另有宽松处理（入口语义）

命中则产出 `TaintFinding`（含 `tainted_vars`、`evidence` 赋值链摘要等）。

gadget 下还会给 `readObject` / `readExternal` **方法入口**本身记一条 SERIALIZE finding（表示「字段可控的反序列化入口」）。

---

## 5. 在分析流水线中的位置

```text
A  找 sink 调用方（gadget 下含 readObject/readExternal）
B  过程内污点 → 确认方法（本文）
C  调用链 Entry → sink（动态 CHA + stitch_mid，见 call_chain_stitch.md）
C1 链路跳边污点连续性初筛（analyze/chain_taint.py）
C2 字段对象图 MAY_REF
D  对链上其它方法再跑一轮过程内污点
```

### C1：链路跳边初筛（去误报）

对每条 `call_chain` 的每一跳 `caller → callee`：

1. 在 caller 里找到可能派发到 callee 的 call site（精确 `resolved_qn` 或 CHA hub）
2. 要求过程内污点能到达该次调用的 **receiver / 参数**
3. 额外规则：`equals(<字面量>)` 且后续仍走 `TiedMapEntry#equals → LazyMap/getValue` → **丢弃**  
   （`instanceof Map.Entry` 失败，`getValue` 不会执行；典型 FP：`DefaultTreeSelectionModel#readObject`）

CHA 枢纽（`Object#equals` 等）、反射 stitch（`invoke` / `newInstance` → 构造器）、以及「有调用点但对不上下一跳」的缺口 **放行**（保召回，例如 `InstantiateTransformer → TrAXFilter`）；缺 IR 时也 **放行**。

**Call chain ≠ 完整 gadget 证明。**  
C1 只做跳边数据流初筛；完整利用仍要靠字段拼装与人工确认。

---

## 6. 与调用链文档的关系

| 文档 | 内容 |
|------|------|
| **本文** `docs/taint.md` | Source / 赋值传播 / sink 命中 |
| [`call_chain_stitch.md`](call_chain_stitch.md) | Entry→sink 调链、stitch_mid |
| [`dynamic_cha.md`](dynamic_cha.md) | 动态 CHA |
| [`cha_virtual_mid.md`](cha_virtual_mid.md) | 虚调用过宽与过滤 |

---

## 7. 一句话（gadget）

> **类字段 + 方法参数是 source；`x1 = …` 只要右侧出现污点标识符，就污染 `x1`；污点进到 Tabby sink 的 receiver/参数则报警。过程内、赋值传播、故意保持简单。**
