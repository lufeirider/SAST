# CHA / Object 类型不明：耗时热点与 stitch_mid 类方案

反射缺口已用 [`stitch_mid.md`](stitch_mid.md) 解决。本文专门谈 **虚调用 CHA** 与 **Object 等过宽类型** 造成的计算爆炸，以及「路径去重 + 二次 source」思路。

---

## 1. 哪些地方会爆

正向 BFS 里，每次遇到虚调用都会 `cha_expand_callee`，候选再被过滤 / `CHA_MAX_CALLEES`（现 100）截断。  
**CC_FULL 现状**（classic sinks + focus，`sink_reaching≈43039`，2026-08 实测）：

| 虚调用槽 | raw | ∩reach | +桥过滤 | 最终 | 说明 |
|----------|-----|--------|---------|------|------|
| `Collection#add` | 195 | 82 | — | **82** | 无桥过滤；仍贵 |
| `Comparable#compareTo` | 127 | 16 | — | **16** | reach 已砍很多 |
| `Map#get` | 96 | 47 | — | **47**（二次再 cap→24） | AIH/LazyMap 必经 |
| `Map.Entry#setValue` | 52 | 15 | — | **15** | 含 InputChecked |
| `Object#toString` | 738 | 201 | **18** | **18** | ser 池 + 须 CALL get/getValue… |
| `Object#hashCode` | 464 | 104 | **18** | **18** | 同上 |
| `Object#equals` | 558 | 193 | **66** | **66**（二次→24） | 桥过滤后仍偏多 |
| `Comparator#compare` | 63 | 21 | — | **21** | CC2/CC4 |
| `Transformer#transform` | 13 | 10 | — | **10** | 小，不贵 |

> 二次 source：frontier 成员若 >24，再优先 focus/commons 截到 24。  
> 合计约 `24+15+18+18+24+21 ≈ 120` 个二次 source —— 仍是 classic 扫不动的主因。

> **结论**：贵的是「**重写/声明了同名方法的类太多**」，不是「空壳继承」。CHA 候选都是自己有 `HAS_METHOD` 的类型。

另外：多个 `readObject` 会反复对同一 `Map#get` 扇出 → 与入口数相乘。

---

## 2. 链路去重：先构造 get / compare / toString，再 CHA

核心做法（已实现）：

```text
① 提前构造（并去重）到达虚槽的路径
   readObject₁ ──► … ──► Map#get
   readObject₂ ──► … ──► Map#get     ← 同一槽只留每条 entry 的最短前缀
   readObject₃ ──► … ──► Object#toString
   PriorityQueue ─► … ──► Comparator#compare

② 对每个虚槽做一次 CHA：看落到哪些「类的方法」
   Map#get ──CHA──► LazyMap#get
                 ├─ Hashtable#get
                 └─ …

③ 每个具体类方法当二次 source，只往 sink 搜一次
   LazyMap#get ──► … ──► InvokerTransformer#transform

④ 拼链
   entry→槽  +  类方法→sink
```

Frontier 槽（`_CHA_FRONTIER_SLOTS`，只认这些接收者，避免 `ByteBuffer#get` 等也进 frontier）：

| 槽 | 用途 |
|----|------|
| `Map#get` | CC1 / CC3 / CC5 / CC6… |
| `Comparator#compare` | CC2 / CC4 |
| `Object#toString` | CC5 |
| `Map.Entry#setValue` | CC1-1 |
| `Object#hashCode` / `equals` | HashMap / Hashtable 侧 |

`Transformer#transform`（~13）不进 frontier，照常跟。

和「大节点」是同一件事：虚槽 = 去重汇聚点；CHA 成员 = 二次 source。

---

## 3. 和 stitch_mid / cha_mid 的关系

| 机制 | 解决什么 |
|------|----------|
| **frontier 去重** | 同一 get/compare/toString 不按 entry 重复扇出 |
| **Object 虚方法桥过滤** | `toString`/`hashCode`/`equals` 必须 CALL `get`/`getValue`/… 才当二次 source |
| **stitch_mid** | 反射 `newInstance` / `invoke` 两边夹 |

---

## 4. 实现状态

- `DynamicChaChainFinder.is_cha_frontier`：Phase A 停在虚槽，记录 `entry→slot`
- `_expand_cha_hubs`：对每个槽 `cha_expand` 一次 → 类方法；类方法全局只 BFS 一次
- `_apply_sink_reaching_filter`：CHA 候选 ∩ sink_reaching

相关：[`dynamic_cha.md`](dynamic_cha.md)、[`stitch_mid.md`](stitch_mid.md)、[`call_chain_stitch.md`](call_chain_stitch.md)。
