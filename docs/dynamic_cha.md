# 动态 CHA（Dynamic Class Hierarchy Analysis）

本文说明本仓库里 **动态 CHA** 是什么、和物化 CHA 的差别，并用 CommonsCollections（CC）链举例。  
实现：`analyze/dynamic_cha_chains.py`（`cha_expand_callee` / `successors`）。  
相关：[`call_chain_stitch.md`](call_chain_stitch.md)、[`stitch_mid.md`](stitch_mid.md)、[`cha_virtual_mid.md`](cha_virtual_mid.md)。

---

## 1. 一句话

**动态 CHA = 查链 BFS 时现算「这个接口/父类调用可能落到哪些子类型上的同名方法」**，而不是 import 时在 Neo4j 里预先铺好大量 `CHA_CALLS` 边。

---

## 2. 为什么需要

Java 源码里经常是**接口接收者**：

```java
Map memberValues = ...;
memberValues.get(key);   // 解析目标多为 Map#get
```

图里精确 `CALLS` 往往是：

```text
AnnotationInvocationHandler#readObject  --CALLS-->  java.util.Map#get
```

真实 gadget 却要走到：

```text
… → LazyMap#get → Transformer#transform → …
```

若不做 CHA，链在 `Map#get` 处对不上实现类；若把所有 `Map` 实现的 `get` 都在 import 时写成边，图会极度膨胀。

动态 CHA 的折中：**搜索走到虚调用时再展开**，并可加上限 / sink-reaching 过滤。

---

## 3. 动态 vs 物化

| | 物化 CHA（旧思路） | **动态 CHA（现在）** |
|--|-------------------|----------------------|
| 时机 | import / 分析前批量建边 | BFS 碰到虚调用再算 |
| 图中内容 | `CALLS` + 大量 `CHA_CALLS` | 基本只有精确 `CALLS`（如 → `Map#get`） |
| 好处 | 查链只需扫边 | 图小；可按本次查询裁剪 |
| 代价 | 导入慢、边爆炸 | 每次展开要查继承与同名方法 |

配置相关：

- `CHA_MAX_CALLEES`：每个虚调用点最多保留多少个 override（截断，不是找全）
- `CHA_NO_EXPAND_TYPES`：`Object` / `Serializable` 等**禁止**按 `<:T` 全图扇出
- `Object#toString` / `hashCode` / `equals`：改为「可序列化或相关类型上的同名方法」再截断
- sink-reaching（cha_mid）：优先只保留反向能到 sink 的 override，见 [`cha_virtual_mid.md`](cha_virtual_mid.md)

---

## 4. 在搜索里怎么接上

`successors(当前方法)` 大致：

```text
1. 取精确 CALLS 后继（如 Map#get）
2. 对每个后继做 cha_expand_callee
   - 普通类型：子类型上同名方法（EXTENDS/IMPLEMENTS）
   - Object 等：按方法名在可序列化/相关类型上找（不走 <:Object）
3. 精确边 ∪ CHA 结果 = 本步可走的后继
4. 若后继是 stitch_mid（invoke/newInstance 调用方），另走反射拼接（不是 CHA）
```

实现细节：CHA 得到的 override 是挂在**当前调用方**的后继集合里，与接口方法**并列**，并不一定先物化 `Map#get → LazyMap#get` 再走一步。报告里的 call chain 仍可看成「逻辑上经过了该实现方法」。

```text
精确 CALLS（落库）              动态 CHA（搜索时现算）
─────────────────              ────────────────────
AIH#readObject                 AIH 的后继里可同时有：
  └─► Map#get                    ├─ Map#get        （精确）
                                 ├─ LazyMap#get    （CHA）
                                 ├─ HashMap#get    （CHA）
                                 └─ …（上限内）
```

---

## 5. CC 例子

### 5.1 CC1-2：`Map#get` → `LazyMap#get`

答案键形态：

```text
AnnotationInvocationHandler#readObject
→ … → LazyMap#get
→ ChainedTransformer#transform
→ InvokerTransformer#transform
```

**无动态 CHA**

```text
AIH#readObject → Map#get → （难以接到 LazyMap#get）
```

**有动态 CHA**

```text
AIH#readObject
  ├─(CALLS)→ Map#get
  └─(CHA)──→ LazyMap#get
               → ChainedTransformer#transform
               → InvokerTransformer#transform
```

CC1-2 能出，主要靠对 **`Map#get` 的动态 CHA**，不是反射 stitch_mid。

---

### 5.2 CC1-1：`Map.Entry#setValue` → `checkSetValue`

```text
AIH#readObject
→ Map.Entry#setValue                                      （精确）
→ AbstractInputCheckedMapDecorator.MapEntry#setValue    （CHA）
→ TransformedMap#checkSetValue
→ … → InvokerTransformer#transform
```

`Map.Entry#setValue` 的 CHA 候选可有几十个 `*#setValue`。  
若截断过狠（例如旧 `CHA_MAX_CALLEES=24`）且排不到 `InputChecked.MapEntry`，CC1-1 会断。  
加大上限、sink-reaching 或 focus 保该类，都是在**动态展开结果**上调整，不是改精确 `CALLS`。

---

### 5.3 CC5：`Object#toString` → `TiedMapEntry#toString`

```text
BadAttributeValueExpException#readObject
→ … →（Object#toString 或经 Hashtable#toString 等）
→ TiedMapEntry#toString                 （Object 虚方法按名动态展开）
→ TiedMapEntry#getValue
→ LazyMap#get
→ … → InvokerTransformer#transform
```

对 `Object` **不能**做「所有子类」CHA。动态阶段只在可序列化等范围内按 `toString` 名收集候选并截断；其中需要能进到 `TiedMapEntry#toString`。

---

### 5.4 CC2 / CC4：`Comparator#compare`

```text
PriorityQueue#readObject
→ heapify / siftDownUsingComparator
→ TransformingComparator#compare          （对 Comparator#compare 的 CHA，或精确到该类）
→ InvokerTransformer / InstantiateTransformer#transform
```

队列反序列化路径上对比较器的虚调用，同样依赖层次展开才能落到 CC 的 `TransformingComparator`。

---

### 5.5 和 stitch_mid 的分工（CC3）

```text
AIH → LazyMap#get → … → InstantiateTransformer#transform
                         → TrAXFilter#… → TemplatesImpl#…
```

| 段 | 机制 |
|----|------|
| `Map#get` → `LazyMap#get` | **动态 CHA**（接收者是哪个 Map） |
| `InstantiateTransformer` → `TrAXFilter` 构造器 | **stitch_mid**（反射要 new 哪个 Class） |

都是「静态目标不明」，但一个是**虚调用接收者**，一个是**反射实例化目标**。细节见 [`stitch_mid.md`](stitch_mid.md)。

---

## 6. 查一条链时的顺序（概念）

```text
1. 从 readObject / readExternal 开始 BFS
2. 取 CALLS 后继
3. 虚调用目标 → 动态 CHA 追加 override
4. stitch_mid（invoke / newInstance）→ 反射拼接
5. 碰到确认 sink → 记录 call chain
```

耗时上：宽槽（`Map#get`、`Collection#add`、`Object#toString`）的动态 CHA 往往比反射 mid 更贵，见 [`cha_virtual_mid.md`](cha_virtual_mid.md)。

---

## 7. 和「作弊 / focus」的关系

动态 CHA 本身是通用算法（按继承与方法名展开）。  
`focus`、加大 `CHA_MAX_CALLEES`、sink-reaching 是**工程上的召回/刹车**，会改变「留下哪些 override」，不改变「CHA = 子类型同名方法」这一语义。  
focus 含义见分析代码中的 `focus_type_qns`：本轮更相关的类型，展开时优先保留。
