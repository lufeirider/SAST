"""Compress / dedupe call chains for reporting.

Also: skeleton extraction + known (answer-key) vs novel classification.
"""

from __future__ import annotations

from typing import Any, Iterable

# --- Answer-key patterns (rules/cc_gadget_answer_chains.md) ---
CC_ANSWER_PATTERNS: list[tuple[str, list[str]]] = [
    ("CC1-1", ["AnnotationInvocationHandler#readObject", "checkSetValue", "InvokerTransformer"]),
    ("CC1-2", ["AnnotationInvocationHandler", "LazyMap#get", "InvokerTransformer"]),
    ("CC2", ["PriorityQueue", "TransformingComparator", "InvokerTransformer"]),
    ("CC3", ["AnnotationInvocationHandler", "LazyMap", "InstantiateTransformer", "TrAXFilter"]),
    ("CC4", ["PriorityQueue", "TransformingComparator", "InstantiateTransformer"]),
    ("CC5", ["BadAttributeValueExpException", "TiedMapEntry", "InvokerTransformer"]),
    ("CC6", ["TiedMapEntry", "LazyMap", "InvokerTransformer"]),
    ("CC7", ["Hashtable", "InvokerTransformer"]),
    ("CC6+CC3", ["HashMap#readObject", "TiedMapEntry", "InstantiateTransformer"]),
]

# Nodes kept in a→b→c skeletons (needle substring → short label).
_SKELETON_BRIDGES: tuple[tuple[str, str], ...] = (
    ("TiedMapEntry", "TiedMapEntry"),
    ("LazyMap", "LazyMap"),
    ("TransformingComparator", "TransformingComparator"),
    ("checkSetValue", "checkSetValue"),
    ("TransformedMap", "TransformedMap"),
    ("AbstractInputCheckedMapDecorator", "AbstractInputChecked"),
    ("TrAXFilter", "TrAXFilter"),
    ("ChainedTransformer", "ChainedTransformer"),
    ("InstantiateTransformer", "InstantiateTransformer"),
    ("InvokerTransformer", "InvokerTransformer"),
    ("TemplatesImpl", "TemplatesImpl"),
    ("Object#toString", "Object#toString"),
    ("Object#hashCode", "Object#hashCode"),
    ("Object#equals", "Object#equals"),
    ("java.util.Map#get", "Map#get"),
    ("Comparator#compare", "Comparator#compare"),
    ("Map.Entry#setValue", "Entry#setValue"),
    ("reconstitutionPut", "reconstitutionPut"),
    ("HashMap#hash", "HashMap#hash"),
)

# Real gadget bridges (not bare CHA slots). Missing these → noise.
_REAL_BRIDGES = frozenset(
    {
        "TiedMapEntry",
        "LazyMap",
        "TransformingComparator",
        "checkSetValue",
        "TransformedMap",
        "AbstractInputChecked",
        "TrAXFilter",
        "ChainedTransformer",
    }
)

_JDK_NOISE = (
    "HookGetFields",
    "IIOPInputStream",
    "PKCS11Exception",
    "InputStreamHook",
    "com.sun.corba",
    "org.omg.CORBA",
)

# OIS → IIOP/CORBA via stream CHA (not field-substitutable receivers).
_STREAM_HIJACK_MARKERS = (
    "IIOPInputStream",
    "com.sun.corba",
    "org.omg.CORBA",
    "InputStreamHook",
)


def _chain(c: dict[str, Any]) -> tuple[str, ...]:
    return tuple(c.get("call_chain") or [])


def _sink_key(c: dict[str, Any]) -> tuple:
    return (c.get("sink"), c.get("sink_method"), c.get("sink_line"))


def _same_target(a: dict[str, Any], b: dict[str, Any]) -> bool:
    if _sink_key(a) == _sink_key(b):
        return True
    return bool(a.get("sink_method") and a.get("sink_method") == b.get("sink_method"))


def _entry_score(qn: str) -> int:
    """Prefer web/controller and deserialization entry method names (no class allowlist)."""
    score = 0
    if "Controller" in qn or "Servlet" in qn or "Resource" in qn:
        score += 50
    if "#readObject" in qn or "#readExternal" in qn:
        score += 40
    if "#invoke(" in qn:
        score += 20
    if "#upper(" in qn or "#exec(" in qn or "#exec1(" in qn or "#exec2(" in qn:
        score += 30
    if "#do_exec" in qn or "#do_exec1" in qn or "#do_exec2" in qn:
        score -= 20
    return score


def _rank(c: dict[str, Any]) -> tuple:
    """Higher priority first: entry quality, then longer paths (all kept; sort only)."""
    ch = c["call_chain"]
    score = _entry_score(ch[0] if ch else "")
    return (-score, -len(ch))


def short_method_label(qn: str) -> str:
    """pkg.Class#method(args) → Class#method."""
    if "#" not in (qn or ""):
        return (qn or "").rsplit(".", 1)[-1]
    cls, rest = qn.split("#", 1)
    return cls.rsplit(".", 1)[-1] + "#" + rest.split("(", 1)[0]


def chain_skeleton(path: list[str]) -> tuple[str, ...]:
    """Collapse a full call_chain to entry → bridges → sink labels."""
    if not path:
        return ()
    nodes = [short_method_label(path[0])]
    seen = set(nodes)
    mid = path[1:-1] if len(path) > 2 else []
    for step in mid:
        for needle, label in _SKELETON_BRIDGES:
            if needle in step and label not in seen:
                nodes.append(label)
                seen.add(label)
                break
    if len(path) >= 2:
        sink = short_method_label(path[-1])
        # Prefer canonical sink labels from bridge table when applicable.
        for needle, label in _SKELETON_BRIDGES:
            if needle in path[-1]:
                sink = label
                break
        if sink not in seen:
            nodes.append(sink)
    return tuple(nodes)


def skeleton_label(path: list[str]) -> str:
    return " → ".join(chain_skeleton(path))


def _body(path: Iterable[str]) -> str:
    return " | ".join(path)


def match_known_pattern(path: list[str]) -> str | None:
    """Return answer-key name if path matches, else None."""
    body = _body(path)
    sk = " → ".join(chain_skeleton(path))
    for name, keys in CC_ANSWER_PATTERNS:
        if all(k in body or k in sk for k in keys):
            return name
    return None


def has_real_bridge(path: list[str]) -> bool:
    sk = chain_skeleton(path)
    return bool(set(sk) & _REAL_BRIDGES)


def has_jdk_noise(path: list[str]) -> bool:
    body = _body(path)
    return any(n in body for n in _JDK_NOISE)


def has_stream_hijack(path: list[str]) -> bool:
    """True if path went through CORBA/IIOP stream machinery (OIS CHA FP)."""
    body = _body(path)
    return any(n in body for n in _STREAM_HIJACK_MARKERS)


def classify_chain(path: list[str]) -> dict[str, Any]:
    """Classify one path: known | novel | noise."""
    sk = chain_skeleton(path)
    known = match_known_pattern(path)
    stream_hijack = has_stream_hijack(path)
    if known:
        kind = "known"
    elif stream_hijack or not has_real_bridge(path):
        kind = "noise"
    else:
        kind = "novel"
    return {
        "skeleton": " → ".join(sk),
        "skeleton_nodes": list(sk),
        "kind": kind,
        "known_as": known,
        "jdk_noise": has_jdk_noise(path),
        "stream_hijack": stream_hijack,
    }


def _novel_rank(item: dict[str, Any]) -> tuple:
    """Prefer distinctive bridges; demote TiedMap→Instantiate-only floods."""
    sk = item.get("skeleton") or ""
    nodes = set(item.get("skeleton_nodes") or sk.split(" → "))
    score = 0
    if "LazyMap" in nodes:
        score += 30
    if "TransformingComparator" in nodes:
        score += 30
    if "checkSetValue" in nodes or "AbstractInputChecked" in nodes:
        score += 40
    if "TrAXFilter" in nodes or "TemplatesImpl" in nodes:
        score += 20
    if "TiedMapEntry" in nodes and "LazyMap" not in nodes:
        score -= 15  # common over-approx
    if item.get("jdk_noise"):
        score -= 10
    # fewer raw variants first among equals; then shorter skeleton
    return (-score, item.get("count", 0), len(nodes), sk)


def summarize_gadget_skeletons(
    chains: list[dict[str, Any]],
    *,
    min_hops: int = 2,
) -> dict[str, Any]:
    """Skeleton-dedupe and split known / novel / noise.

    Returns:
      {
        raw, unique,
        known: [...], novel: [...], noise: [...],
        counts: {known, novel, noise}
      }
      each skeleton item: skeleton, kind, known_as, count, jdk_noise, witness
    """
    buckets: dict[tuple[str, ...], dict[str, Any]] = {}
    raw = 0
    for c in chains:
        ch = list(c.get("call_chain") or [])
        if len(ch) < min_hops or len(ch) != len(set(ch)):
            continue
        raw += 1
        info = classify_chain(ch)
        key = tuple(info["skeleton_nodes"])
        slot = buckets.get(key)
        if slot is None:
            buckets[key] = {
                **info,
                "count": 1,
                "witness": ch,
                "sink_method": c.get("sink_method") or (ch[-1] if ch else ""),
            }
        else:
            slot["count"] += 1
            if len(ch) < len(slot["witness"]):
                slot["witness"] = ch
                slot["sink_method"] = c.get("sink_method") or ch[-1]

    known, novel, noise = [], [], []
    for item in buckets.values():
        wit = item["witness"]
        item["witness_short"] = " → ".join(short_method_label(x) for x in wit)
        kind = item["kind"]
        if kind == "known":
            known.append(item)
        elif kind == "novel":
            novel.append(item)
        else:
            noise.append(item)

    known.sort(key=lambda x: (x.get("known_as") or "", -x["count"]))
    novel.sort(key=_novel_rank)
    noise.sort(key=lambda x: (-x["count"], x["skeleton"]))

    return {
        "raw": raw,
        "unique": len(buckets),
        "counts": {
            "known": len(known),
            "novel": len(novel),
            "noise": len(noise),
        },
        "known": known,
        "novel": novel,
        "noise": noise,
    }


def annotate_chains_with_skeleton(
    chains: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Attach skeleton / kind / known_as on each chain dict."""
    out: list[dict[str, Any]] = []
    for c in chains:
        ch = list(c.get("call_chain") or [])
        if len(ch) < 2:
            out.append(c)
            continue
        info = classify_chain(ch)
        out.append({**c, **info})
    return out


def compress_call_chains(
    chains: list[dict[str, Any]],
    *,
    min_hops: int = 2,
    max_chains: int = 0,
) -> list[dict[str, Any]]:
    """
    Keep all acyclic unique paths (caller already filters cycles).

    Only drops exact duplicate call_chain tuples. max_chains<=0 means no cap.
    Ordering prefers longer spines first for display.
    """
    items: list[dict[str, Any]] = []
    for c in chains:
        ch = list(c.get("call_chain") or [])
        if len(ch) < min_hops:
            continue
        if len(ch) != len(set(ch)):
            continue
        items.append({**c, "call_chain": ch})

    items.sort(key=_rank)

    kept: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for c in items:
        t = _chain(c)
        if t in seen:
            continue
        seen.add(t)
        kept.append(c)
        if max_chains > 0 and len(kept) >= max_chains:
            break

    kept.sort(key=_rank)
    return kept
