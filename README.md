# SAST Pipeline

静态分析流水线：`reverse` → `parse`（调用链入 Neo4j）→ `analyze`（sink + 污点检测）。

```
sast/
├── reverse/                 # 逆向：下载源码 / 反编译
├── parse/                   # JavaParseIr → parse_ir → Neo4j 调用图
├── analyze/                 # 分析检测：sink 识别 + 简单污点
├── target/                  # 默认输入 JAR
├── tmpwork/                 # 纯源码输出
└── docker-compose.yml       # 不起服务；Neo4j 用本机已有容器
```

## Neo4j（本机已有，项目直接连）

项目**不会**再起 Neo4j，只连 `bolt://127.0.0.1:7687`（免密）。搭建命令：

```bash
docker run -d \
    --name sast-neo4j \
    --publish=7474:7474 \
    --publish=7687:7687 \
    -m 6G \
    -e NEO4J_server_memory_heap_initial__size=512m \
    -e NEO4J_server_memory_heap_max__size=2G \
    -e NEO4J_server_memory_pagecache_size=1G \
    -e NEO4J_server_memory_transaction_total__max=2G \
    -e NEO4J_server_config_strict__validation_enabled=false \
    -e NEO4J_ACCEPT_LICENSE_AGREEMENT=yes \
    -e NEO4J_PLUGINS='["apoc"]' \
    -e NEO4J_AUTH=none \
    neo4j:2026.05.0-enterprise
```

> Docker Desktop 内存约 8G 时不要用 heap 4G + pagecache 4G（会直接起不来）。
容器停了用 `docker start <容器名>` 恢复即可。Browser: http://localhost:7474

## 快速开始

```bash
# 1. 确认本机 Neo4j 已在跑（见上一节），不要为本项目再起容器

# 2. 安装依赖
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 3. reverse：默认读 target/，结果写到 tmpwork/
# 胖 JAR 拆 BOOT-INF/lib → 优先下源码，失败则 CFR；业务 class 始终 CFR
# 源码缓存默认：tmpwork/source_cache/（按 GAV，避免重复下载）
python run_reverse.py

# 依赖源码失败时跳过 CFR（更快，但缺源码）
python run_reverse.py --no-decompile-libs

# 指定输入 / 仅当前层
python run_reverse.py -i /path/to/app.jar
python run_reverse.py -i /path/to/libs --no-recursive

# 4. parse：JavaParseIr 产出 parse_ir.json → Python objects → Neo4j
# 首次需 JDK 17+：
bash parse/tools/build_java_parse_ir.sh
python run_parse.py -p JavaTarget
# 可选：保留中间 IR
# python run_parse.py -p JavaTarget --no-import \
#   --dump-parse-ir tmpwork/ir/parse_ir.json \
#   --dump-json tmpwork/ir/parse_ir_objects.json

# 5. analyze：两种污点模式
# vuln  = 找漏洞（source=方法参数）
python run_analyze.py -p JavaTarget --mode vuln --dump-json tmpwork/analyze_vuln.json --report
# gadget = 找 gadget（source=类字段 + readObject 入口）
python run_analyze.py -p JavaTarget --mode gadget --dump-json tmpwork/analyze_report.json --report
open tmpwork/analyze_report.html
```

## 模块说明

| 模块 | 职责 |
|------|------|
| `reverse` | JAR 中心拿源码 / CFR；输出纯源码树 `app/` + `lib/` |
| `parse` | `JavaParseIr` → `parse_ir` objects → Neo4j 调用链 |
| `analyze` | sink 检测 + 简单污点（参数/字段经赋值传播到 `exec`/`readObject`） |

### reverse：源码怎么来（不是解析项目 Maven 依赖）

对 **Spring Boot / 胖 JAR** 输出纯源码树（不含 jar/class）：

```
tmpwork/<app>/
  app/                 # 业务 .java（包路径）
  resources/           # 配置等
  lib/<dependency>/    # 依赖源码（下载或反编译）
```

1. 解包到 `tmpwork/.unpack/`（完成后删除）
2. 依赖并行拉源码 → `lib/<name>/`
3. 业务 class CFR → `app/`
4. 下载失败的依赖再 CFR（`--no-decompile-libs` 可关）

对每个普通 JAR，识别顺序：

1. 同目录旁路 `foo-1.0-sources.jar`
2. **`META-INF/MANIFEST.MF`**（Implementation-* / Bundle-*）
3. `META-INF/maven/**/pom.properties`
4. JAR SHA1 / 文件名搜索 Maven Central
5. `*-SNAPSHOT` 跳过远程下载；都没有再 CFR

目录输入默认 `--recursive`。

### Neo4j 图模型与调用相关概念

#### 哪些名称是业界通用的？

| 概念 | 是否通用 | 说明 |
|------|----------|------|
| **Call site** | ✅ 通用 | 调用发生的位置（那一行 `.foo(...)` / `new Foo()`） |
| **Caller / Callee** | ✅ 通用 | 调用方方法 / 被调方方法 |
| **Call graph / call edge** | ✅ 通用 | 方法→方法的调用关系（概念） |
| **关系类型 `CALLS`** | ⚠️ 常见约定 | Method→Method 的 call edge；也有人写 `INVOKES` |
| **`CallSite` 节点** | ✅ 常见 | 把 call site 建成独立节点 |
| **`HAS_CALL_SITE` / `RESOLVED_TO`** | ❌ 本项目命名 | 刻意避开和 `CALLS` 撞名：拥有调用点 / 解析到目标方法 |

一句话：**Call site / call graph 是通用术语；`CALLS`（方法→方法）、`HAS_CALL_SITE`（方法→调用点）、`RESOLVED_TO`（调用点→方法）是本仓库关系名。**

#### 同一行源码如何建模？

例如在 `GadgetVulController#upper` 里：

```java
new TestUpVul().test(vul);  // 第 50 行
```

```
upper(Method) --HAS_CALL_SITE--> CallSite(line=50, receiver=new TestUpVul(),
                                          callee_name=test, arguments=[vul],
                                          caller_qn=...#upper, resolved_qn=...#test)
                    |                         |
                    |                         +--RESOLVED_TO--> test(Method)
                    |
                    +--CALLS--> test(Method)   // 方法→方法简图，便于走链
```

| 关系 | 从 → 到 | 干什么 |
|------|---------|--------|
| **`HAS_CALL_SITE`** | Method → **CallSite** | 这个方法里有一次调用记录（细节） |
| **`RESOLVED_TO`** | CallSite → Method | 这次调用解析到哪个方法 |
| **`CALLS`** | Method → Method | 调用图简边（不经 CallSite，方便 `CALLS*1..n`） |

三者描述同一调用的不同侧面，不是互相矛盾的两套数据。

#### CallSite 主要属性

| 属性 | 含义 |
|------|------|
| `caller_qn` | 所在方法（谁发起的调用） |
| `callee_name` | 语法上的被调名（如 `test`） |
| `receiver` | `.` 左边（如 `new TestUpVul()` / `vul`） |
| `arguments` | 实参文本列表 |
| `line` | 源码行号 |
| `resolved_qn` | SymbolSolver 解析出的目标方法全名 |
| `target_qn` | 导入时选中的主目标（通常同 `resolved_qn`） |
| `is_constructor` | 是否 `new Xxx(...)` |
| `is_sink` | Method：反序列化入口；CallSite：是否命中 Tabby sink |

#### 结构总览

```
(:Project)-[:HAS_FILE]->(:File)-[:DECLARES]->(:Type)
(:Type)-[:HAS_METHOD]->(:Method)-[:HAS_PARAM]->(:Parameter)
(:Type)-[:HAS_FIELD]->(:Field)
(:Type)-[:EXTENDS|IMPLEMENTS]->(:Type)          # 继承 / 实现（已落库）
(:Field)-[:DECLARED_TYPE]->(:Type)              # 字段声明类型
(:Field)-[:POINTS_TO]->(:Type)                  # 声明类型 + CHA 子类型
(:Type)-[:MAY_REF {field, serializable_write}]->(:Type)  # 对象图快捷边
(:Method)-[:CALLS]->(:Method)
(:Method)-[:HAS_CALL_SITE]->(:CallSite)-[:RESOLVED_TO]->(:Method)
(:Finding)-[:IN_METHOD]->(:Method)
```

```cypher
# 方法级调用链（走 CALLS）
MATCH (a:Method)-[:CALLS*1..5]->(b:Method)
WHERE a.project = 'JavaTarget'
RETURN a.qualified_name, b.qualified_name LIMIT 50

# 某方法里的调用点（走 HAS_CALL_SITE → CallSite）
MATCH (m:Method {name:'upper'})-[:HAS_CALL_SITE]->(cs:CallSite)
RETURN cs.caller_qn, cs.line, cs.receiver, cs.callee_name, cs.resolved_qn
ORDER BY cs.line

# 对象图：字段可能指向（MAY_REF）
MATCH (a:Type)-[r:MAY_REF]->(b:Type)
WHERE a.project = 'CC_JDK8' AND a.name = 'LazyMap'
RETURN a.name, r.field, b.name, r.serializable_write LIMIT 30

# 污点发现
MATCH (f:Finding {project:'JavaTarget'})
RETURN f.sink_name, f.method_qn, f.sink_line, f.sink_arg, f.source_kind
```

### analyze 污点规则（简单，分模式）

完整说明（gadget source / 赋值传播）：→ **[`docs/taint.md`](docs/taint.md)**

| 模式 | CLI | Source | 额外规则 |
|------|-----|--------|----------|
| **vuln**（找漏洞） | `--mode vuln` | 方法**参数** | 不把类字段默认当污点；`readObject()` 调用仅当 receiver 已被参数污染才报 |
| **gadget**（找 gadget） | `--mode gadget` | **类字段** + **方法参数** | `readObject`/`readExternal` 为反序列化入口；字段默认攻击者可控 |

- **Sink**：对齐 [Tabby `rules/sinks.json`](https://github.com/tabby-sec/tabby/tree/master/rules)（本地 `rules/sinks.json`）；按 **类 + 方法** 匹配，优先 `CallSite.resolved_qn`
- **传播**：赋值 RHS 出现污点标识符即污染 LHS（如 `x1 = xxx + x2`）
- **分析流程（调用关系串起来）**：
  1. **A** 找调用了 Tabby sink 的方法（gadget 下 `readObject`/`readExternal` 入口也算）
  2. **B** 对这些方法做过程内污点 → 得到**确认可利用**的方法
  3. **C** 只对确认方法查调用链：Entry → sink（动态 CHA + stitch_mid 双向拼接，见下节文档）
  4. **C2** 查字段对象图路径（`MAY_REF`，见下方 FAQ）
  5. **D** 对链上额外方法再做一轮污点（仍过程内）
- 默认模式见 `analyze/config.py` 的 `TAINT_MODE`（当前 `vuln`）
- `--no-import` 时只做 A+B，没有调用链 / 对象图

调用链算法说明（动态 CHA、stitch_mid、为何不做「全世界构造器」）：

→ **[`docs/taint.md`](docs/taint.md)**（过程内污点）  
→ **[`docs/dynamic_cha.md`](docs/dynamic_cha.md)**（动态 CHA 是什么，含 CC 例子）  
→ **[`docs/call_chain_stitch.md`](docs/call_chain_stitch.md)**（总览）  
→ **[`docs/stitch_mid.md`](docs/stitch_mid.md)**（反射 stitch_mid）  
→ **[`docs/cha_virtual_mid.md`](docs/cha_virtual_mid.md)**（CHA / Object 过宽与 sink-reaching 夹逼）

### CommonsCollections + JDK8 联跑（gadget 挖掘）

**全量布局**（推荐挖新链）：CC3 + CC4 + 全量 JDK8 都进 `app/` 并写入 Neo4j。

```bash
# 重建全量源码树（~1.2 万+ .java）
python3 tmpwork/cc_full/rebuild_full_layout.py
#   app/  = JDK8 + CC3 + CC4（全部 emit）
#   lib/  = 空（不再把 JDK 藏成 solver-only）

# 首次解析会分片并行 JavaParseIr，并缓存到 tmpwork/cc_full/.cache/parse_ir.json
# 之后默认走缓存；改源码或 --force-reparse 才重解析
python3 run_analyze.py \
  -i tmpwork/cc_full -p CC_FULL --mode gadget \
  --app-root tmpwork/cc_full/app \
  --dump-json tmpwork/cc_full_analyze_report.json \
  --report tmpwork/cc_full_analyze_report.html

# 强制重解析
python3 run_analyze.py -i tmpwork/cc_full -p CC_FULL --mode gadget --force-reparse ...
```

**速度**：`PARSE_SHARD_WORKERS` / `JAVA_PARSE_XMX` / `BATCH_SIZE` 在 `parse/config.py`；
分析阶段 CHA **按需**展开，链查询见 [`docs/call_chain_stitch.md`](docs/call_chain_stitch.md)。

**`CHA_MAX_CALLEES = 100`（强烈注意）**：每个虚调用点做 CHA 时，**最多只保留 100 个**子类型/实现类上的同名方法（排序后截断）。  
不是找全所有 CHA 类；候选多于 100 时后面的 override 仍会被裁掉。详见链文档第 2 节。

**CHA / 反射策略**：
- **import**：只存精确边——`CALLS`→解析目标（如 `Map#get`），`MAY_REF`→声明类型；**不**做 Map→所有实现类扇出，**不**物化全图 `CHA_CALLS`
- **analyze 查链**：`CALLS` + 按需子类型 CHA（受 `CHA_MAX_CALLEES` 截断）；`Method#invoke` / `Constructor#newInstance` 在 **stitch_mid 上 A/B/C 拼接**（危险构造器由 sink 反向 + 逆 CHA 得到），避免「全世界构造器」爆炸
- 配置 `parse/config.py`；实现 `analyze/dynamic_cha_chains.py`、`analyze/reflective.py`、`analyze/cha_expand.py`；JavaParseIr 默认 `-Xmx6g`（分片）

较小联跑（仅 AIH 片段 + CC3）：`tmpwork/cc_jdk8/`。

报告 Tab：`Call Chains` / `Object Graph` / `Sinks` / `Findings`。

### CommonsCollections 标准答案链

文本答案键（对照分析用）：[`rules/cc_gadget_answer_chains.md`](rules/cc_gadget_answer_chains.md)  
来源：[Squirt1e — CC利用链总结](https://squirt1e.top/2021/12/25/cc-li-yong-lian-zong-jie/)

查链算法（Entry→stitch_mid→危险目标→Sink）：[`docs/call_chain_stitch.md`](docs/call_chain_stitch.md)  
动态 CHA 说明与 CC 例子：[`docs/dynamic_cha.md`](docs/dynamic_cha.md)  
stitch_mid 白话说明与例子：[`docs/stitch_mid.md`](docs/stitch_mid.md)

### FAQ（设计问答摘要）

#### Sinks 和 Findings 有什么区别？

| | **Sinks** | **Findings** |
|--|-----------|--------------|
| 是什么 | 危险 API **目录**（按 vul + owner + name 聚合） | 污点分析后的 **逐条确认** |
| 关注点 | 有哪些危险点、谁在用（callers） | 哪次调用、哪行、哪个参数、证据 |
| 例子 | `ObjectInputStream#readObject` 被 28 个方法调到 | `InvokerTransformer#transform` L125，`invoke` 参数被污染 |

一个 Sink 可对应多条 Finding。

#### 有 Call Chain 为什么还不算找到完整 gadget？

**Call chain ≠ gadget chain。**

- 当前 `CALLS` 链回答：谁调用了谁，最终落到确认的 sink 方法  
- 经典 gadget（如 CC1）还要证明：反序列化入口 + **字段拼装** 能把控制流/数据配到 `Method.invoke`

常见缺口：

1. **缺 JDK 入口**（只扫 CC 库时没有 `AnnotationInvocationHandler`）→ 合成 `cc_jdk8` 项目可补  
2. **污点是过程内的**（当前刻意保持简单，靠人工审查降误报）  
3. **接口/`Object` 虚调**：不是“猜一个类”，而是 **CHA** 展开所有子类型（边会变多，再按能否到 sink 筛）

#### CHA 是什么？在哪做的？

**CHA = Class Hierarchy Analysis（类层次分析）**。

遇到接口/父类上的虚调用或字段声明类型时，按 `EXTENDS` / `IMPLEMENTS` 把工程内子类/实现类当成候选目标。

- **import**：一般**不**把 CHA 扇出写进 `CALLS`（只存精确解析边）
- **analyze 查链**：在 BFS 时**按需**展开 override（动态 CHA，见 [`docs/dynamic_cha.md`](docs/dynamic_cha.md)）  
  - **`CHA_MAX_CALLEES = 100`**：每个虚调用点最多只跟 **100** 个 CHA 目标（排序截断，不是找全）
- **反射**：`invoke` / `newInstance` 用 **stitch_mid 双向拼接**；详见 [`docs/call_chain_stitch.md`](docs/call_chain_stitch.md)

#### 继承关系有没有保存？和 Serializable 有什么关系？

**有。** import 写入：

- `(子)-[:EXTENDS]->(父)`
- `(类)-[:IMPLEMENTS]->(接口)`

没有继承/实现边，就无法可靠判断「是否 `implements Serializable`、能否被反序列化写入」。  
当前还会：对可序列化类型打 `Type.is_serializable`；字段非 static/transient 时标 `serializable_write`（另有 `readObject` 等启发式）。

#### MAY_REF 是什么？怎么实现的？

**MAY_REF**：类型 A 的某个字段**可能引用**类型 B（对象图快捷边）。

```
(AnnotationInvocationHandler)-[:MAY_REF {field:'memberValues'}]->(LazyMap)
(LazyMap)-[:MAY_REF {field:'factory'}]->(InvokerTransformer)
```

| 边 | 含义 |
|----|------|
| `HAS_FIELD` | 类上有这个字段 |
| `DECLARED_TYPE` / `POINTS_TO` | 挂在 Field 节点上的类型边 |
| **`MAY_REF`** | Type→Type 快捷边（带字段名），方便查对象链 |
| `CALLS` | 方法调用方法 |

实现（目前）：**字段声明类型 + CHA**，不是精确指针分析。

- 做了：擦除泛型/数组、跳过 `Object`/`String`、声明类型 ∪ 子类型（有上限）、标 `serializable_write`  
- **没做**：不看 `new Xxx` 赋值、不做 points-to / 堆抽象  

所以是 **MAY**（可能），不是 MUST。

#### 目前可以用来找 gadget 吗？

**可以挖候选 + 人工确认，不能当自动“证明可利用”引擎。**

已具备：Sink / 过程内污点、`CALLS` 链、字段对象图（MAY_REF+CHA）、Serializable 继承、HTML 报告。  
对 CC1 能同时给出例如：

- 调用：`AnnotationInvocationHandler.invoke → LazyMap.get → InvokerTransformer.transform`  
- 字段：`AIH.memberValues → LazyMap.factory → InvokerTransformer`（及 Chained 变体）

仍缺：字段值约束（数组里具体 Constant+Invoker）、触发条件细节、跨方法精确污点 / 利用可行性证明。

### 配置（测试环境硬编码）

- Neo4j: `bolt://127.0.0.1:7687`，免密（与上节 `NEO4J_AUTH=none` 一致）
- parse / analyze 默认读 `tmpwork/` 下 reverse 的 `app/` 源码
