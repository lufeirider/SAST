"""Resolve reflective call targets without gadget-specific hardcoding.

Mechanisms:
1. Constant Class.forName / classOrNull + Class.getMethod(name) in the same
   callable (incl. <clinit>) → concrete Method QNs. Wired to every method on
   that declaring type that calls Method#invoke / Constructor#newInstance.
2. Open reflection stitch_mids: methods that call Method#invoke or
   Constructor#newInstance. Chain finding stitches entry→stitch_mid and
   dangerous-target→sink at these stitch_mids (see dynamic_cha_chains), instead of
   spraying every constructor in the classpath.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Any, Iterable

logger = logging.getLogger(__name__)

_STR_LIT = re.compile(r'^"((?:\\.|[^"\\])*)"$')
_GET_METHOD_NAMES = frozenset({"getMethod", "getDeclaredMethod"})
_CLASS_NAME_APIS = frozenset({"forName", "classOrNull"})
_INVOKE_HINTS = (
    "java.lang.reflect.Method#invoke",
    "java.lang.reflect.Constructor#newInstance",
)


def _string_literal(expr: str | None) -> str | None:
    if not expr:
        return None
    text = str(expr).strip()
    m = _STR_LIT.match(text)
    if not m:
        return None
    return bytes(m.group(1), "utf-8").decode("unicode_escape")


def _is_reflective_dispatch(qn: str) -> bool:
    return any(h in (qn or "") for h in _INVOKE_HINTS)


def is_ctor_qn(qn: str) -> bool:
    """True when method name equals the simple declaring-type name."""
    if "#" not in (qn or ""):
        return False
    owner, rest = qn.split("#", 1)
    name = rest.split("(", 1)[0]
    simple = owner.rsplit(".", 1)[-1]
    return bool(name) and name == simple


class ReflectiveEdgeIndex:
    """Project-scoped reflective edges + stitch_mid discovery."""

    def __init__(self) -> None:
        self.edges: dict[str, list[str]] = defaultdict(list)
        # stitch_mid_qn → {"invoke": bool, "new": bool}
        self.stitch_mids: dict[str, dict[str, bool]] = {}
        self._loaded = False

    def load_from_neo4j(self, session: Any, project: str) -> None:
        if self._loaded:
            return
        rows = session.run(
            """
            MATCH (cs:CallSite {project:$p})
            WHERE cs.callee_name IN $names
               OR cs.resolved_qn CONTAINS 'Class#getMethod'
               OR cs.resolved_qn CONTAINS 'Class#getDeclaredMethod'
               OR cs.resolved_qn CONTAINS 'Class#forName'
               OR cs.callee_name IN $classApis
            RETURN cs.caller_qn AS caller,
                   cs.callee_name AS name,
                   cs.resolved_qn AS resolved,
                   cs.arguments AS args
            """,
            p=project,
            names=list(_GET_METHOD_NAMES),
            classApis=list(_CLASS_NAME_APIS),
        ).data()

        by_caller: dict[str, list[dict]] = defaultdict(list)
        for r in rows:
            caller = r.get("caller") or ""
            if caller:
                by_caller[caller].append(r)

        # owner type → reflected method QNs from constant getMethod bindings
        type_targets: dict[str, set[str]] = defaultdict(set)
        pending: list[tuple[str, str, str]] = []  # owner, class_name, method_name

        for caller, sites in by_caller.items():
            owner = caller.split("#", 1)[0]
            class_names: list[str] = []
            method_names: list[str] = []
            for s in sites:
                name = s.get("name") or ""
                resolved = s.get("resolved") or ""
                args = list(s.get("args") or [])
                lit0 = _string_literal(args[0]) if args else None
                if name in _CLASS_NAME_APIS or "Class#forName" in resolved:
                    if lit0:
                        class_names.append(lit0)
                if name in _GET_METHOD_NAMES or "Class#getMethod" in resolved or (
                    "Class#getDeclaredMethod" in resolved
                ):
                    if lit0:
                        method_names.append(lit0)
            for cn in class_names:
                for mn in method_names:
                    pending.append((owner, cn, mn))

        # Resolve (class, methodName) → Method nodes
        if pending:
            class_names = sorted({cn for _, cn, _ in pending})
            method_rows = session.run(
                """
                MATCH (m:Method {project:$p})
                WHERE split(m.qualified_name, '#')[0] IN $classes
                RETURN m.qualified_name AS qn, m.name AS name,
                       split(m.qualified_name, '#')[0] AS owner
                """,
                p=project,
                classes=class_names,
            ).data()
            by_owner_name: dict[tuple[str, str], list[str]] = defaultdict(list)
            for r in method_rows:
                by_owner_name[(r["owner"], r["name"])].append(r["qn"])

            for owner, cn, mn in pending:
                for qn in by_owner_name.get((cn, mn), []):
                    type_targets[owner].add(qn)

        # Wire: methods on owner that call Method.invoke / Constructor.newInstance
        # (callee may be a cross-project JDK stub — do not require same project)
        if type_targets:
            owners = sorted(type_targets)
            invoke_callers = session.run(
                """
                MATCH (a:Method {project:$p})-[:CALLS]->(b:Method)
                WHERE split(a.qualified_name, '#')[0] IN $owners
                  AND (
                    b.qualified_name STARTS WITH 'java.lang.reflect.Method#invoke'
                    OR b.qualified_name STARTS WITH 'java.lang.reflect.Constructor#newInstance'
                  )
                RETURN DISTINCT a.qualified_name AS qn,
                       split(a.qualified_name, '#')[0] AS owner
                """,
                p=project,
                owners=owners,
            ).data()
            for r in invoke_callers:
                owner = r["owner"]
                for tgt in sorted(type_targets.get(owner, ())):
                    self._add(r["qn"], tgt)

        self._load_stitch_mids(session, project)
        self._loaded = True
        n_edges = sum(len(v) for v in self.edges.values())
        logger.info(
            "Reflective: constant edges=%d callers; stitch_mids=%d (invoke=%d new=%d)",
            n_edges,
            len(self.stitch_mids),
            sum(1 for h in self.stitch_mids.values() if h.get("invoke")),
            sum(1 for h in self.stitch_mids.values() if h.get("new")),
        )

    def _load_stitch_mids(self, session: Any, project: str) -> None:
        rows = session.run(
            """
            MATCH (a:Method {project:$p})-[:CALLS]->(b:Method)
            WHERE b.qualified_name STARTS WITH 'java.lang.reflect.Method#invoke'
               OR b.qualified_name STARTS WITH 'java.lang.reflect.Constructor#newInstance'
            RETURN DISTINCT a.qualified_name AS qn, collect(DISTINCT b.qualified_name) AS bs
            """,
            p=project,
        ).data()
        stitch_mids: dict[str, dict[str, bool]] = {}
        for r in rows:
            qn = r.get("qn") or ""
            if not qn:
                continue
            bs = r.get("bs") or []
            stitch_mids[qn] = {
                "invoke": any("Method#invoke" in (b or "") for b in bs),
                "new": any("Constructor#newInstance" in (b or "") for b in bs),
            }
        self.stitch_mids = stitch_mids

    def _add(self, caller: str, callee: str) -> None:
        bucket = self.edges[caller]
        if callee not in bucket:
            bucket.append(callee)

    def targets_for(
        self,
        method_qn: str,
        *,
        calls: Iterable[str] | None = None,
        open_sinks: Iterable[str] | None = None,
        dangerous_ctors: Iterable[str] | None = None,
        focus_ctors: Iterable[str] | None = None,
        open_invoke: bool = True,
        open_new: bool = False,
    ) -> list[str]:
        """Return reflective callees.

        Constant getMethod bindings always apply. Open Method.invoke → sinks
        only when open_invoke. Open Constructor.newInstance → dangerous/focus
        ctors when open_new (never sprays all classpath ctors; never direct
        sink spray — stitch layer adds ctor→sink).
        """
        out: list[str] = []
        seen: set[str] = set()
        for t in self.edges.get(method_qn, []):
            if t not in seen:
                seen.add(t)
                out.append(t)
        # Precise constant bindings: do not also open-spray.
        if out:
            return out
        call_list = list(calls or [])
        opens_invoke = _is_reflective_dispatch(method_qn) or any(
            _is_reflective_dispatch(c) for c in call_list
        )
        opens_new = any(
            "Constructor#newInstance" in (c or "") for c in call_list
        ) or ("Constructor#newInstance" in (method_qn or ""))
        if open_invoke and opens_invoke:
            for t in open_sinks or ():
                if t and t not in seen and t != method_qn:
                    seen.add(t)
                    out.append(t)
        if open_new and opens_new:
            for t in list(dangerous_ctors or ()) + list(focus_ctors or ()):
                if t and t not in seen and t != method_qn:
                    seen.add(t)
                    out.append(t)
        return out
