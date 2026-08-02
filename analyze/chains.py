"""Compress / dedupe call chains for reporting."""

from __future__ import annotations

from typing import Any


def _chain(c: dict[str, Any]) -> tuple[str, ...]:
    return tuple(c.get("call_chain") or [])


def _sink_key(c: dict[str, Any]) -> tuple:
    return (c.get("sink"), c.get("sink_method"), c.get("sink_line"))


def _is_contiguous_subpath(short: tuple[str, ...], long: tuple[str, ...]) -> bool:
    if not short or len(short) >= len(long):
        return False
    n = len(short)
    for i in range(len(long) - n + 1):
        if long[i : i + n] == short:
            return True
    return False


def _is_subsequence(short: tuple[str, ...], long: tuple[str, ...]) -> bool:
    """True if all nodes of short appear in order inside long (not necessarily contiguous)."""
    if not short or len(short) >= len(long):
        return False
    it = iter(long)
    return all(node in it for node in short)


def _same_target(a: dict[str, Any], b: dict[str, Any]) -> bool:
    if _sink_key(a) == _sink_key(b):
        return True
    return bool(a.get("sink_method") and a.get("sink_method") == b.get("sink_method"))


def _entry_score(qn: str) -> int:
    """Prefer HTTP/controller / deserialization / classic gadget entries."""
    score = 0
    if "Controller" in qn or "Servlet" in qn or "Resource" in qn:
        score += 50
    if "#readObject" in qn or "#readExternal" in qn:
        score += 40
    if "#upper(" in qn or "#exec(" in qn or "#exec1(" in qn or "#exec2(" in qn:
        score += 30
    # CommonsCollections-style entries (AIH.invoke is the CC1 trigger)
    if "AnnotationInvocationHandler#invoke" in qn:
        score += 110
    elif "AnnotationInvocationHandler" in qn:
        score += 90
    if "LazyMap#get" in qn:
        score += 60
    if "TiedMapEntry" in qn:
        score += 45
    if "ChainedTransformer#transform" in qn:
        score += 35
    if "#do_exec" in qn or "#do_exec1" in qn or "#do_exec2" in qn:
        score -= 20
    if "InvokerTransformer#transform" in qn:
        score -= 15
    if "BeanMap#" in qn:
        score -= 40  # CHA noise often routes through BeanMap
    return score


def _rank(c: dict[str, Any]) -> tuple:
    ch = c["call_chain"]
    end = ch[-1] if ch else ""
    body = " ".join(ch)
    score = _entry_score(ch[0])
    if (
        "AnnotationInvocationHandler" in body
        and "LazyMap" in body
        and "InvokerTransformer" in body
    ):
        score += 50
    # prefer direct AIH → LazyMap → Invoker over CHA detours
    if (
        len(ch) == 3
        and "AnnotationInvocationHandler" in ch[0]
        and "LazyMap#get" in ch[1]
        and "InvokerTransformer#transform" in ch[2]
    ):
        score += 40
    if "BeanMap" in end:
        score -= 30
    # higher score first, then shorter chains
    return (-score, len(ch))


def compress_call_chains(
    chains: list[dict[str, Any]],
    *,
    min_hops: int = 2,
    max_chains: int = 40,
) -> list[dict[str, Any]]:
    """
    Drop duplicate / dominated paths for the same sink target.

    Prefer shorter gadget paths: if A→C is already kept, drop A→B→C;
    if A→B→C is kept and A→C arrives, replace with A→C.
    """
    items: list[dict[str, Any]] = []
    for c in chains:
        ch = list(c.get("call_chain") or [])
        if len(ch) < min_hops:
            continue
        items.append({**c, "call_chain": ch})

    items.sort(key=_rank)

    kept: list[dict[str, Any]] = []
    for c in items:
        t = _chain(c)
        dominated = False
        for k in list(kept):
            if not _same_target(k, c):
                continue
            kt = _chain(k)
            if t == kt:
                dominated = True
                break
            # current shorter than kept → replace kept
            if _is_contiguous_subpath(t, kt) or _is_subsequence(t, kt):
                kept = [x for x in kept if _chain(x) != kt]
                continue
            # kept already shorter → drop current
            if _is_contiguous_subpath(kt, t) or _is_subsequence(kt, t):
                dominated = True
                break
        if dominated:
            continue
        kept.append(c)
        if len(kept) >= max_chains:
            break

    kept.sort(key=_rank)
    return kept
