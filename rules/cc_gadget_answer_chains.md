# CommonsCollections 标准答案链（文本）

来源：[Squirt1e — CC利用链总结](https://squirt1e.top/2021/12/25/cc-li-yong-lian-zong-jie/)  
用途：对照本仓库 gadget 分析结果的答案键（answer key）。

---

## CC1-1

**限制**：jdk≤8u71；CommonsCollections 3.1–3.2.1、4.0

```
AnnotationInvocationHandler#readObject
→ AbstractInputCheckedMapDecorator.MapEntry#setValue
→ TransformedMap#checkSetValue
→ ChainedTransformer#transform
→ InvokerTransformer#transform
```

---

## CC1-2

**限制**：jdk≤8u71；CommonsCollections 3.1–3.2.1、4.0  
（常见 ysoserial CommonsCollections1）

```
AnnotationInvocationHandler#readObject
→ Proxy(AnnotationInvocationHandler).xxx
→ AnnotationInvocationHandler#invoke
→ LazyMap#get
→ ChainedTransformer#transform
→ InvokerTransformer#transform
```

---

## CC2

**限制**：CommonsCollections 4.0

```
PriorityQueue#readObject
→ TransformingComparator#compare
→ InvokerTransformer#transform
→ TemplatesImpl#newTransformer
→ defineClass
→ newInstance
```

---

## CC3

**限制**：CommonsCollections 3.1–3.2.1；jdk≤8u71

```
AnnotationInvocationHandler#readObject
→ Proxy(AnnotationInvocationHandler).xxx
→ AnnotationInvocationHandler#invoke
→ LazyMap#get
→ ChainedTransformer#transform
→ InstantiateTransformer#transform
→ TrAXFilter#<init>
→ TemplatesImpl#newTransformer
→ defineClass
→ newInstance
```

---

## CC4

**限制**：CommonsCollections 4.0

```
PriorityQueue#readObject
→ TransformingComparator#compare
→ ChainedTransformer#transform
→ InstantiateTransformer#transform
→ TrAXFilter#<init>
→ TemplatesImpl#newTransformer
→ defineClass
→ newInstance
```

---

## CC5

**限制**：CommonsCollections 3.1–3.2.1（可绕高版本 AIH 限制）

```
BadAttributeValueExpException#readObject
→ TiedMapEntry#toString
→ LazyMap#get
→ ChainedTransformer#transform
→ InvokerTransformer#transform
```

---

## CC6

**限制**：CommonsCollections 3.1–3.2.1  
（博文简写；`TiedMapEntry#getValue` 之后实际还会进 `LazyMap#get`）

```
HashMap#readObject
→ HashMap#hash
→ TiedMapEntry#getValue
→ LazyMap#get
→ ChainedTransformer#transform
→ InvokerTransformer#transform
```

---

## CC7

**限制**：CommonsCollections 3.1–3.2.1

```
Hashtable#readObject
→ Hashtable#reconstitutionPut
→ AbstractMap#equals
→ LazyMap#get
→ ChainedTransformer#transform
→ InvokerTransformer#transform
```

---

## CC6+CC3

**限制**：CommonsCollections 3.1–3.2.1（CC6 前半绕高版本 + CC3 后半绕 Invoker 黑名单）

```
HashMap#readObject
→ HashMap#hash
→ TiedMapEntry#getValue
→ LazyMap#get
→ ChainedTransformer#transform
→ InstantiateTransformer#transform
→ TrAXFilter#<init>
→ TemplatesImpl#newTransformer
→ defineClass
→ newInstance
```
