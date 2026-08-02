"""
Load and match Tabby-style sink rules (rules/sinks.json).

Source: https://github.com/tabby-sec/tabby/tree/master/rules

Matching preference:
  1) CallSite.resolved_qn  →  owner#method(...)
  2) constructor rules (function blank) via is_constructor + simple class name
  3) fallback: callee simple name when it uniquely maps / is high-signal
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Optional

RULES_DIR = Path(__file__).resolve().parent
SINKS_JSON = RULES_DIR / "sinks.json"

# When resolved_qn is missing, only these simple names are trusted alone
# (avoids treating every write/execute/query as a sink).
# Unresolved CallSites: only these simple names may match without owner
# (lookup/load/get/newInstance etc. require resolved_qn to avoid FP).
_NAME_ONLY_OK = frozenset(
    {
        "exec",
        "readObject",
        "readExternal",
        "invoke",
        "invoke0",
        "forName",
        "defineClass",
    }
)


@dataclass(frozen=True)
class SinkRule:
    owner: str
    function: str  # "" = constructor
    vul: str
    polluted: tuple[tuple[int, ...], ...] = ()


@dataclass(frozen=True)
class SinkMatch:
    rule: SinkRule
    via: str  # resolved | name | constructor


def _normalize_function(raw: str) -> str:
    fn = (raw or "").strip()
    if not fn:
        return ""
    # Tabby typo / mangled: "java.lang.ObjectreadObject()"
    if "readObject" in fn and not fn.startswith("readObject"):
        return "readObject"
    if fn.endswith("()"):
        fn = fn[:-2]
        if "." in fn:
            fn = fn.rsplit(".", 1)[-1]
    return fn


@lru_cache(maxsize=1)
def load_sink_rules() -> tuple[SinkRule, ...]:
    data = json.loads(SINKS_JSON.read_text(encoding="utf-8"))
    out: list[SinkRule] = []
    for entry in data:
        owner = (entry.get("name") or "").strip()
        if not owner:
            continue
        for r in entry.get("rules") or []:
            if (r.get("type") or "sink") != "sink":
                continue
            fn = _normalize_function(r.get("function") or "")
            vul = (r.get("vul") or "OTHER").strip() or "OTHER"
            polluted_raw = r.get("polluted") or []
            polluted: list[tuple[int, ...]] = []
            for item in polluted_raw:
                if isinstance(item, list):
                    polluted.append(tuple(int(x) for x in item))
            out.append(
                SinkRule(
                    owner=owner,
                    function=fn,
                    vul=vul,
                    polluted=tuple(polluted),
                )
            )
    return tuple(out)


@lru_cache(maxsize=1)
def sink_function_names() -> frozenset[str]:
    """All non-constructor sink method simple names (for coarse filters / Neo4j)."""
    names = {r.function for r in load_sink_rules() if r.function}
    # keep historical aliases
    names.update({"exec", "readObject", "readobject"})
    return frozenset(names)


@lru_cache(maxsize=1)
def _rules_by_owner() -> dict[str, list[SinkRule]]:
    m: dict[str, list[SinkRule]] = {}
    for r in load_sink_rules():
        m.setdefault(r.owner, []).append(r)
    return m


@lru_cache(maxsize=1)
def _rules_by_function() -> dict[str, list[SinkRule]]:
    m: dict[str, list[SinkRule]] = {}
    for r in load_sink_rules():
        if r.function:
            m.setdefault(r.function, []).append(r)
    return m


_RE_QN = re.compile(r"^(?P<owner>[\w.$]+)#(?P<method>[\w$]+)\(")


def _parse_resolved(resolved_qn: str) -> tuple[str, str] | None:
    m = _RE_QN.match(resolved_qn or "")
    if not m:
        return None
    return m.group("owner"), m.group("method")


def match_sink_call(
    *,
    callee_name: str,
    resolved_qn: str = "",
    is_constructor: bool = False,
) -> Optional[SinkMatch]:
    """Return the best Tabby sink match for one call site."""
    owner_method = _parse_resolved(resolved_qn)
    if owner_method:
        owner, method = owner_method
        for rule in _rules_by_owner().get(owner, []):
            if rule.function == "":
                simple = owner.rsplit(".", 1)[-1]
                if is_constructor or method == simple:
                    return SinkMatch(rule, "constructor")
            elif method == rule.function:
                return SinkMatch(rule, "resolved")
        # resolved owner may be a subtype / different packaging — try by method+suffix
        for rule in _rules_by_function().get(method, []):
            if owner == rule.owner or owner.endswith("." + rule.owner.split(".")[-1]):
                if owner.endswith(rule.owner) or rule.owner.endswith(owner.split(".")[-1]):
                    # stricter: owner equal OR resolved owner ends with full rule owner
                    if owner == rule.owner or owner.endswith(rule.owner):
                        return SinkMatch(rule, "resolved")

    # constructor without useful resolved qn
    if is_constructor and callee_name:
        for owner, rules in _rules_by_owner().items():
            simple = owner.rsplit(".", 1)[-1]
            if callee_name != simple:
                continue
            for rule in rules:
                if rule.function == "":
                    return SinkMatch(rule, "constructor")

    # name-only fallback: only high-signal names (never bare get/write/execute)
    name = callee_name or ""
    if name not in _NAME_ONLY_OK:
        return None
    cands = _rules_by_function().get(name) or []
    if not cands:
        return None
    cands_sorted = sorted(
        cands,
        key=lambda r: (
            0 if r.owner.startswith("java.") else 1,
            r.owner,
        ),
    )
    return SinkMatch(cands_sorted[0], "name")


def is_gadget_entry_method(method_name: str) -> bool:
    """Deserialization / externalizable entry methods (gadget mode)."""
    return method_name in {"readObject", "readExternal"}


def match_any_sink(
    calls: Iterable[tuple[str, str, bool]],
) -> bool:
    """calls: iterable of (callee_name, resolved_qn, is_constructor)."""
    for callee_name, resolved_qn, is_ctor in calls:
        if match_sink_call(
            callee_name=callee_name,
            resolved_qn=resolved_qn,
            is_constructor=is_ctor,
        ):
            return True
    return False
