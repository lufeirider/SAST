"""Preliminary call-chain filter via intra-proc taint continuity.

For each hop caller → callee on a path:
  1) Find call sites in caller that can dispatch to callee (precise or CHA hub).
  2) Require gadget/vuln taint to reach that site's receiver or arguments.
  3) Kill equals(<literal>) hops that continue into TiedMapEntry#equals → LazyMap
     (Map.Entry branch never taken — e.g. DefaultTreeSelectionModel#readObject).

CHA hubs / reflective stitch edges without a local call site are fail-open.
Missing IR for a method is fail-open (keep chain).

Docs: docs/taint.md
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Iterable

from analyze.taint import TaintMode, _idents, propagate_taint
from parse.models import CallSite, MethodInfo, TypeInfo

logger = logging.getLogger(__name__)

# Virtual slots / interfaces: hop to override is CHA-synthesized, no body call.
_CHA_HUB_OWNERS = frozenset(
    {
        "java.lang.Object",
        "java.util.Map",
        "java.util.Map.Entry",
        "java.util.Comparator",
        "java.lang.Comparable",
        "java.util.Collection",
        "java.util.List",
        "java.util.Set",
        "org.apache.commons.collections.Transformer",
        "org.apache.commons.collections.Factory",
    }
)

_STITCH_NAME_MARKERS = frozenset({"invoke", "newInstance"})

_LITERAL_ARG = re.compile(
    r"^\s*(?:"
    r"null|true|false|"
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"-?\d+[lLfFdD]?"
    r")\s*$"
)


@dataclass
class HopVerdict:
    ok: bool
    reason: str
    caller: str
    callee: str


@dataclass
class ChainTaintResult:
    ok: bool
    reason: str
    hops: list[HopVerdict]


def _owner(qn: str) -> str:
    return (qn or "").split("#", 1)[0]


def _method_name(qn: str) -> str:
    if "#" not in (qn or ""):
        return qn or ""
    return qn.split("#", 1)[1].split("(", 1)[0]


def _is_literal(expr: str) -> bool:
    return bool(expr) and bool(_LITERAL_ARG.match(expr))


def build_method_index(
    types: Iterable[TypeInfo],
) -> dict[str, tuple[TypeInfo, MethodInfo]]:
    out: dict[str, tuple[TypeInfo, MethodInfo]] = {}
    for t in types:
        for m in t.methods:
            if m.qualified_name:
                out[m.qualified_name] = (t, m)
    return out


def _is_cha_hub(method_qn: str) -> bool:
    return _owner(method_qn) in _CHA_HUB_OWNERS


def _is_stitch_mid(method_qn: str) -> bool:
    return _method_name(method_qn) in _STITCH_NAME_MARKERS


def _is_ctor_qn(qn: str) -> bool:
    name = _method_name(qn)
    owner_simple = _owner(qn).rsplit(".", 1)[-1]
    return name in {"<init>", owner_simple} or "#<init>" in (qn or "")


def _has_reflective_dispatch(method: MethodInfo) -> bool:
    for cs in method.call_sites:
        n = cs.callee_name or ""
        rq = cs.resolved_qn or ""
        if n in _STITCH_NAME_MARKERS or "newInstance" in rq or "#invoke(" in rq:
            return True
        if n == "getConstructor" or "getConstructor" in rq:
            return True
    return False


def _call_can_dispatch(cs: CallSite, callee_qn: str) -> bool:
    """True if this call site may resolve / CHA-expand to callee_qn."""
    cname = _method_name(callee_qn)
    if not cname:
        return False
    simple = cs.callee_name or ""
    resolved = cs.resolved_qn or ""

    if resolved == callee_qn:
        return True

    if cs.is_constructor:
        # callee like pkg.Foo#<init>(…) or resolved ctor QN
        if "<init>" in callee_qn or "<init>" in resolved:
            owner_simple = _owner(callee_qn).rsplit(".", 1)[-1]
            if simple in {owner_simple, "<init>"} or owner_simple in simple:
                if not resolved or _is_cha_hub(resolved) or _owner(resolved) != _owner(
                    callee_qn
                ):
                    return True
                return _owner(resolved) == _owner(callee_qn)
        return False

    if simple != cname and _method_name(resolved) != cname:
        return False
    if not resolved:
        return True
    if _method_name(resolved) != cname:
        return False
    # Precise resolve to hub / different owner → CHA may pick callee
    if _is_cha_hub(resolved) or _owner(resolved) != _owner(callee_qn):
        return True
    return _owner(resolved) == _owner(callee_qn)


def _site_polluted(cs: CallSite, tainted: set[str], *, mode: TaintMode) -> bool:
    if _idents(cs.receiver or "") & tainted:
        return True
    for arg in cs.arguments:
        if _idents(arg) & tainted:
            return True
    # gadget: implicit this — fields are sources
    if mode == "gadget" and not (cs.receiver or "").strip():
        return True
    return False


def _rest_needs_tiedmap_equals_bridge(rest: list[str]) -> bool:
    """rest includes callee … sink; TiedMapEntry#equals then LazyMap/getValue."""
    has_tme_eq = any("TiedMapEntry#equals" in (x or "") for x in rest)
    has_bridge = any(
        ("LazyMap#get" in (x or ""))
        or ("#getValue" in (x or "") and "TiedMapEntry" in (x or ""))
        for x in rest
    )
    return has_tme_eq and has_bridge


def check_hop(
    caller_qn: str,
    callee_qn: str,
    rest: list[str],
    index: dict[str, tuple[TypeInfo, MethodInfo]],
    *,
    mode: TaintMode,
) -> HopVerdict:
    if _is_cha_hub(caller_qn) or _is_stitch_mid(caller_qn):
        return HopVerdict(True, "cha_or_stitch", caller_qn, callee_qn)

    hit = index.get(caller_qn)
    if hit is None:
        return HopVerdict(True, "no_ir", caller_qn, callee_qn)

    type_info, method = hit
    tainted, _, _ = propagate_taint(type_info, method, mode=mode)

    sites = [cs for cs in method.call_sites if _call_can_dispatch(cs, callee_qn)]
    if not sites:
        # Concrete method but no matching site — CHA / reflective stitch gap.
        # Fail-open: preliminary filter must not drop answer-key stitch edges
        # (e.g. InstantiateTransformer#transform → TrAXFilter#<init>).
        if not method.call_sites:
            return HopVerdict(True, "empty_body", caller_qn, callee_qn)
        if _is_ctor_qn(callee_qn) and _has_reflective_dispatch(method):
            return HopVerdict(True, "reflective_stitch", caller_qn, callee_qn)
        return HopVerdict(True, "no_call_site_open", caller_qn, callee_qn)

    live = [cs for cs in sites if _site_polluted(cs, tainted, mode=mode)]
    if not live:
        return HopVerdict(False, "untainted_call", caller_qn, callee_qn)

    if _method_name(callee_qn) == "equals" and _rest_needs_tiedmap_equals_bridge(
        rest
    ):
        if all(
            len(cs.arguments) >= 1 and _is_literal(cs.arguments[0]) for cs in live
        ):
            return HopVerdict(False, "equals_literal_arg", caller_qn, callee_qn)

    return HopVerdict(True, "ok", caller_qn, callee_qn)


def check_chain(
    path: list[str],
    index: dict[str, tuple[TypeInfo, MethodInfo]],
    *,
    mode: TaintMode = "gadget",
) -> ChainTaintResult:
    if len(path) < 2:
        return ChainTaintResult(True, "short", [])
    hops: list[HopVerdict] = []
    for i in range(len(path) - 1):
        rest = path[i + 1 :]
        v = check_hop(path[i], path[i + 1], rest, index, mode=mode)
        hops.append(v)
        if not v.ok:
            return ChainTaintResult(False, v.reason, hops)
    return ChainTaintResult(True, "ok", hops)


def filter_chains_by_taint(
    chains: list[dict],
    types: list[TypeInfo] | Iterable[TypeInfo],
    *,
    mode: TaintMode = "gadget",
) -> tuple[list[dict], dict[str, int]]:
    """Drop chains that fail hop taint continuity. Annotate keepers with taint_ok.

    Returns (kept_chains, stats).
    """
    index = build_method_index(types)
    kept: list[dict] = []
    stats: dict[str, int] = {"input": 0, "kept": 0, "dropped": 0}
    drop_reasons: dict[str, int] = {}

    for c in chains:
        stats["input"] += 1
        path = list(c.get("call_chain") or [])
        result = check_chain(path, index, mode=mode)
        if result.ok:
            stats["kept"] += 1
            kept.append({**c, "taint_ok": True, "taint_reason": result.reason})
        else:
            stats["dropped"] += 1
            drop_reasons[result.reason] = drop_reasons.get(result.reason, 0) + 1

    stats.update({f"drop_{k}": v for k, v in sorted(drop_reasons.items())})
    logger.info(
        "Chain taint filter: in=%d kept=%d dropped=%d reasons=%s",
        stats["input"],
        stats["kept"],
        stats["dropped"],
        drop_reasons,
    )
    return kept, stats
