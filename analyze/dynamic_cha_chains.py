"""On-demand CHA while stitching call chains (no CHA_CALLS materialization).

Import stores precise CALLS only. BFS walks CALLS + subtype CHA.

Reflective stitch_mids (Method#invoke / Constructor#newInstance callers) use
meet-in-the-middle:
  A) entry ──forward──► stitch_mid   (CALLS + CHA + constant reflect only)
  B) sink  ◄─backward── dangerous targets (ctors / methods that reach sinks)
  C) stitch entry→stitch_mid→(reflect target)→sink

Wide CHA frontier (get / compare / toString / setValue):
  1) Forward until the virtual slot; dedupe entry→slot paths
  2) CHA the slot once → concrete class methods (secondary sources)
  3) From each concrete method, search to sink once; stitch with prefixes
  See docs/cha_virtual_mid.md.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from typing import Any, Iterable

from parse.config import (
    CHA_MAX_CALLEES,
    is_cha_no_expand,
)
from analyze.reflective import ReflectiveEdgeIndex, is_ctor_qn

logger = logging.getLogger(__name__)

_OBJECT_VIRTUAL_NAMES = frozenset({"toString", "hashCode", "equals"})

# Object#toString/hashCode/equals is only a gadget bridge if it CALLS into
# something like get/getValue (TiedMapEntry), not just StringBuilder/Object.
_OBJECT_VIRTUAL_BRIDGE_CALLEE_NAMES = frozenset(
    {
        "get",
        "getValue",
        "getKey",
        "put",
        "setValue",
        "entrySet",
        "keySet",
        "values",
        "transform",
        "compare",
        "checkSetValue",
    }
)

# Path-dedupe frontiers: only these wide receivers (not every method named get).
# Phase A stops here; CHA once → concrete class methods as secondary sources.
_CHA_FRONTIER_SLOTS = frozenset(
    {
        ("java.util.Map", "get"),
        ("java.util.Comparator", "compare"),
        ("java.lang.Object", "toString"),
        ("java.lang.Object", "hashCode"),
        ("java.lang.Object", "equals"),
        ("java.util.Map.Entry", "setValue"),
    }
)
_CHA_FRONTIER_NAMES = frozenset(n for _, n in _CHA_FRONTIER_SLOTS)

# Reverse BFS: full reverse-CHA (supertype slots) only near sinks. Deeper levels
# use precise CALLS only — otherwise ~20k Neo4j slot queries dominate Phase B.
_REV_CHA_MAX_DEPTH = 2


def _prefer_score(qn: str) -> int:
    """Stable ordering only — no class-name allowlist."""
    return -len(qn or "")


def _owner_name(qn: str) -> tuple[str, str]:
    if "#" not in qn:
        return qn, ""
    owner, rest = qn.split("#", 1)
    return owner, rest.split("(", 1)[0]


def _chunk(xs: list[str], n: int) -> list[list[str]]:
    return [xs[i : i + n] for i in range(0, len(xs), n)]


class DynamicChaChainFinder:
    """BFS over CALLS + on-demand CHA; reflective stitch_mids via A/B/C stitch."""

    def __init__(
        self,
        session: Any,
        project: str,
        *,
        focus_type_qns: Iterable[str] | None = None,
        max_per_site: int = CHA_MAX_CALLEES,
    ):
        self.session = session
        self.project = project
        self.focus_types = set(focus_type_qns or [])
        self.max_per_site = max(1, int(max_per_site))
        self._calls: dict[str, list[str]] = {}
        self._rev_calls: dict[str, list[str]] = {}
        self._declared_slots: dict[str, list[str]] = {}
        self._overrides: dict[tuple[str, str], list[str]] = {}
        # raw override lists (pre filter/cap) for hub detection
        self._raw_override_n: dict[tuple[str, str], int] = {}
        self._hub_cache: dict[str, bool] = {}
        self._reflective = ReflectiveEdgeIndex()
        self._open_sinks: list[str] = []
        self._dangerous_ctors: list[str] = []
        self._focus_ctors: list[str] = []
        # Methods that can reach current sinks (reverse BFS). When set, CHA /
        # Object#virtual expand prefers intersection with this set (cha_mid).
        self._sink_reaching: set[str] | None = None
        # Phase-A forward: constant reflect only (no open spray).
        self._open_invoke = False
        self._open_new = False
        # When False, successors() does not CHA-expand hub callees (big-node mode).
        self._expand_hubs = True
        self._reflective.load_from_neo4j(session, project)
        if self.focus_types:
            self._load_focus_ctors()

    def _load_focus_ctors(self) -> None:
        rows = self.session.run(
            """
            MATCH (m:Method {project:$p})
            WHERE split(m.qualified_name, '#')[0] IN $types
              AND m.name = split(split(m.qualified_name, '#')[0], '.')[-1]
            RETURN m.qualified_name AS qn
            LIMIT 200
            """,
            p=self.project,
            types=sorted(self.focus_types),
        ).data()
        self._focus_ctors = [r["qn"] for r in rows if r.get("qn")]

    def _load_calls(self, qns: list[str]) -> None:
        missing = [q for q in qns if q not in self._calls]
        if not missing:
            return
        for batch in _chunk(missing, 400):
            rows = self.session.run(
                """
                MATCH (a:Method {project:$p})-[:CALLS]->(b:Method)
                WHERE a.qualified_name IN $qns
                RETURN a.qualified_name AS a, collect(DISTINCT b.qualified_name) AS bs
                """,
                p=self.project,
                qns=batch,
            ).data()
            found = {r["a"]: list(r["bs"] or []) for r in rows}
            for q in batch:
                self._calls[q] = found.get(q, [])

    def _prefetch_queue_calls(self, q: deque[str], n: int = 200) -> None:
        """Batch-load CALLS for the next n BFS queue nodes (skip Neo4j round-trips)."""
        if not q:
            return
        batch: list[str] = []
        for i, x in enumerate(q):
            if i >= n:
                break
            batch.append(x)
        self._load_calls(batch)

    def _load_rev_calls(self, qns: list[str]) -> None:
        """Callers of qns (project callers → possibly cross-project callee)."""
        missing = [q for q in qns if q not in self._rev_calls]
        if not missing:
            return
        for batch in _chunk(missing, 400):
            rows = self.session.run(
                """
                MATCH (a:Method {project:$p})-[:CALLS]->(b:Method)
                WHERE b.qualified_name IN $qns
                RETURN b.qualified_name AS b, collect(DISTINCT a.qualified_name) AS as
                """,
                p=self.project,
                qns=batch,
            ).data()
            found = {r["b"]: list(r["as"] or []) for r in rows}
            for q in batch:
                self._rev_calls[q] = found.get(q, [])

    def _supertype_slot_qns(self, method_qn: str) -> list[str]:
        """Declared methods on supertypes with the same name (reverse-CHA slots)."""
        if method_qn in self._declared_slots:
            return self._declared_slots[method_qn]
        owner, mname = _owner_name(method_qn)
        if not owner or not mname:
            self._declared_slots[method_qn] = []
            return []
        rows = self.session.run(
            """
            MATCH (sub:Type {project:$p})
            WHERE sub.qualified_name = $owner OR sub.name = $owner
            WITH sub LIMIT 1
            MATCH (sub)-[:EXTENDS|IMPLEMENTS*0..6]->(sup:Type {project:$p})
            MATCH (sup)-[:HAS_METHOD]->(m:Method {project:$p})
            WHERE m.name = $mname
              AND m.qualified_name <> $own
            RETURN DISTINCT m.qualified_name AS qn
            LIMIT 80
            """,
            p=self.project,
            owner=owner,
            mname=mname,
            own=method_qn,
        ).data()
        out = [r["qn"] for r in rows if r.get("qn")]
        self._declared_slots[method_qn] = out
        return out

    def _reverse_predecessors(self, method_qn: str) -> list[str]:
        """Callers of method_qn, plus callers of supertype same-name slots (rev CHA)."""
        slots = [method_qn] + self._supertype_slot_qns(method_qn)
        self._load_rev_calls(slots)
        out: list[str] = []
        seen: set[str] = set()
        for slot in slots:
            for pred in self._rev_calls.get(slot, []):
                if pred and pred not in seen:
                    seen.add(pred)
                    out.append(pred)
        return out

    def _subtype_overrides(self, owner: str, mname: str) -> list[str]:
        key = (owner, mname)
        if key in self._overrides:
            return self._truncate_cha(
                self._apply_sink_reaching_filter(list(self._overrides[key]))
            )

        rows = self.session.run(
            """
            MATCH (ownerType:Type {project:$p})
            WHERE ownerType.qualified_name = $owner OR ownerType.name = $owner
            WITH ownerType LIMIT 1
            MATCH (sub:Type {project:$p})-[:EXTENDS|IMPLEMENTS*0..6]->(ownerType)
            MATCH (sub)-[:HAS_METHOD]->(override:Method {project:$p})
            WHERE override.name = $mname
              AND NOT override.qualified_name STARTS WITH ($owner + '#')
            RETURN DISTINCT override.qualified_name AS qn,
                   sub.qualified_name AS sub_qn,
                   coalesce(sub.is_serializable, false) AS ser
            LIMIT 5000
            """,
            p=self.project,
            owner=owner,
            mname=mname,
        ).data()

        ranked = sorted(
            rows,
            key=lambda r: (
                0 if r["sub_qn"] in self.focus_types else 1,
                0 if r["ser"] else 1,
                -_prefer_score(r["qn"] or ""),
                r["qn"] or "",
            ),
        )
        out: list[str] = []
        seen: set[str] = set()
        for r in ranked:
            qn = r["qn"]
            if not qn or qn in seen:
                continue
            if is_cha_no_expand(_owner_name(qn)[0]):
                continue
            seen.add(qn)
            out.append(qn)
        # Cache full ranked list; sink-reaching filter then CHA_MAX truncate.
        self._overrides[key] = out
        self._raw_override_n[key] = len(out)
        return self._truncate_cha(self._apply_sink_reaching_filter(out))

    def _universal_name_targets(self, mname: str) -> list[str]:
        """Object#m → same-name methods on serializable / focus types (no hierarchy)."""
        key = ("java.lang.Object", mname)
        if key in self._overrides:
            filtered = self._apply_sink_reaching_filter(list(self._overrides[key]))
            filtered = self._filter_object_virtual_gadget_bridges(filtered)
            return self._truncate_cha(filtered)

        focus = sorted(self.focus_types)
        rows = self.session.run(
            """
            MATCH (t:Type {project:$p})-[:HAS_METHOD]->(m:Method {project:$p})
            WHERE m.name = $mname
              AND NOT m.qualified_name STARTS WITH 'java.lang.Object#'
              AND (
                coalesce(t.is_serializable, false)
                OR t.qualified_name IN $focus
              )
            RETURN DISTINCT m.qualified_name AS qn,
                   t.qualified_name AS type_qn,
                   coalesce(t.is_serializable, false) AS ser
            LIMIT 3000
            """,
            p=self.project,
            mname=mname,
            focus=focus,
        ).data()

        ranked = sorted(
            rows,
            key=lambda r: (
                0 if r["type_qn"] in self.focus_types else 1,
                0 if r["ser"] else 1,
                0
                if not (r["qn"] or "").startswith(("java.", "javax.", "sun.", "com.sun."))
                else 1,
                r["qn"] or "",
            ),
        )
        out: list[str] = []
        seen: set[str] = set()
        for r in ranked:
            qn = r["qn"]
            if not qn or qn in seen:
                continue
            seen.add(qn)
            out.append(qn)
        self._overrides[key] = out
        self._raw_override_n[key] = len(out)
        # Gadget bridge: toString/hashCode/equals must CALL a bridge method
        # (get / getValue / …). Leaf or StringBuilder-only overrides are noise.
        filtered = self._apply_sink_reaching_filter(out)
        filtered = self._filter_object_virtual_gadget_bridges(filtered)
        return self._truncate_cha(filtered)

    def _filter_methods_with_callees(self, qns: list[str]) -> list[str]:
        """Keep only methods that CALL at least one other method."""
        if not qns:
            return qns
        self._load_calls(list(qns))
        return [q for q in qns if self._calls.get(q)]

    def _filter_object_virtual_gadget_bridges(self, qns: list[str]) -> list[str]:
        """Keep Object-virtual overrides that call get/getValue/… (gadget-shaped)."""
        if not qns:
            return qns
        self._load_calls(list(qns))
        kept: list[str] = []
        for q in qns:
            callees = self._calls.get(q) or []
            if not callees:
                continue
            if any(
                _owner_name(c)[1] in _OBJECT_VIRTUAL_BRIDGE_CALLEE_NAMES for c in callees
            ):
                kept.append(q)
        return kept

    def _truncate_cha(self, qns: list[str]) -> list[str]:
        """Hard cap after sink-reaching filter (CHA_MAX_CALLEES)."""
        if len(qns) <= self.max_per_site:
            return qns
        return qns[: self.max_per_site]

    def _apply_sink_reaching_filter(self, qns: list[str]) -> list[str]:
        """Prefer CHA targets that reverse-reach a sink (cha_mid style).

        If intersection is empty, fall back to the unfiltered list so shallow
        reverse BFS cannot wipe recall. Focus-type owners always kept when present.
        """
        reaching = self._sink_reaching
        if not reaching:
            return qns
        out: list[str] = []
        seen: set[str] = set()
        for q in qns:
            if not q or q in seen:
                continue
            owner = _owner_name(q)[0]
            if q in reaching or owner in self.focus_types:
                seen.add(q)
                out.append(q)
        return out if out else qns

    def _override_key(self, callee_qn: str) -> tuple[str, str] | None:
        owner, mname = _owner_name(callee_qn)
        if not owner or not mname:
            return None
        if is_cha_no_expand(owner):
            if mname in _OBJECT_VIRTUAL_NAMES:
                return ("java.lang.Object", mname)
            return None
        return (owner, mname)

    def _ensure_raw_overrides(self, callee_qn: str) -> int:
        """Populate override cache; return raw (pre-cap) candidate count."""
        key = self._override_key(callee_qn)
        if key is None:
            return 0
        if key in self._raw_override_n:
            return self._raw_override_n[key]
        # Trigger cache fill via cha_expand_callee.
        self.cha_expand_callee(callee_qn)
        return self._raw_override_n.get(key, 0)

    def is_cha_frontier(self, callee_qn: str) -> bool:
        """True if callee is Map#get / Comparator#compare / Object#toString / …"""
        if callee_qn in self._hub_cache:
            return self._hub_cache[callee_qn]
        key = self._override_key(callee_qn)
        if key is None:
            self._hub_cache[callee_qn] = False
            return False
        owner, mname = key
        # Object virtuals normalize to java.lang.Object via _override_key.
        is_f = (owner, mname) in _CHA_FRONTIER_SLOTS
        self._hub_cache[callee_qn] = is_f
        return is_f

    def _frontier_slot_qn(self, callee_qn: str) -> str:
        """Canonical slot QN for path dedupe (Object virtuals → java.lang.Object#…)."""
        key = self._override_key(callee_qn)
        if key is None:
            return callee_qn
        owner, mname = key
        # Keep original signature when possible; Object/CharSequence → Object#mname()
        if owner == "java.lang.Object" and mname in _OBJECT_VIRTUAL_NAMES:
            if mname == "equals":
                return "java.lang.Object#equals(Object)"
            if mname == "hashCode":
                return "java.lang.Object#hashCode()"
            if mname == "toString":
                return "java.lang.Object#toString()"
        return callee_qn

    def hub_members(self, hub_qn: str) -> list[str]:
        """Concrete class methods from CHA on a frontier slot."""
        return self.cha_expand_callee(hub_qn)

    def cha_expand_callee(self, callee_qn: str) -> list[str]:
        owner, mname = _owner_name(callee_qn)
        if not owner or not mname:
            return []
        if is_cha_no_expand(owner):
            if mname in _OBJECT_VIRTUAL_NAMES:
                return self._universal_name_targets(mname)
            return []
        return self._subtype_overrides(owner, mname)

    def successors(self, method_qn: str) -> list[str]:
        self._load_calls([method_qn])
        callees = list(self._calls.get(method_qn, []))
        callees.extend(
            self._reflective.targets_for(
                method_qn,
                calls=callees,
                open_sinks=self._open_sinks,
                dangerous_ctors=self._dangerous_ctors,
                focus_ctors=self._focus_ctors,
                open_invoke=self._open_invoke,
                open_new=self._open_new,
            )
        )
        out: list[str] = []
        seen: set[str] = set()
        for c in callees:
            if c and c not in seen:
                seen.add(c)
                out.append(c)
            # Big-node mode: keep the hub edge, do not fan out overrides here.
            if not self._expand_hubs and self.is_cha_frontier(c):
                continue
            for o in self.cha_expand_callee(c):
                if o and o not in seen and o != method_qn:
                    seen.add(o)
                    out.append(o)
        out.sort(key=lambda q: (-_prefer_score(q), q))
        return out

    def find_chains(
        self,
        entries: Iterable[str],
        sinks: Iterable[str],
        *,
        max_depth: int = 7,
        max_paths_per_sink: int = 0,
        max_visit: int = 80000,
        backward_depth: int = 5,
        max_dangerous_ctors: int = 80,
        max_paths_per_stitch_mid: int = 0,
    ) -> list[dict]:
        """Meet-in-the-middle: A entry→mid, B sink←ctors, C pure connect.

        Reflective new/invoke: no graph search in C — only A prefixes × B targets.
        CHA frontiers use secondary sources (A2). Path dedupe is O(1) via set.
        """
        entry_list = [e for e in entries if e]
        sink_set = {s for s in sinks if s}
        if not entry_list or not sink_set:
            return []

        stitch_mids = self._reflective.stitch_mids
        self._open_sinks = sorted(sink_set)

        # --- B: sink ◄── dangerous targets + sink-reaching set for CHA ---
        ctor_to_sink_paths, dangerous_ctors, sink_reaching = self._backward_from_sinks(
            sink_set,
            max_depth=backward_depth,
            max_ctors=max_dangerous_ctors,
        )
        # Fall back / supplement: focus ctors that reach sinks via short forward.
        for ctor in self._focus_ctors:
            if ctor in ctor_to_sink_paths:
                continue
            suffix = self._forward_path_to_sink(
                ctor, sink_set, max_depth=backward_depth, max_visit=800
            )
            if suffix:
                ctor_to_sink_paths.setdefault(ctor, []).append(suffix)
                if ctor not in dangerous_ctors:
                    dangerous_ctors.append(ctor)
                sink_reaching.add(ctor)
                sink_reaching.update(suffix)
        self._dangerous_ctors = dangerous_ctors
        self._sink_reaching = sink_reaching
        # CHA caches must not reuse pre-filter expand results.
        self._overrides.clear()
        self._raw_override_n.clear()
        self._hub_cache.clear()

        logger.info(
            "Reflective/CHA stitch B: dangerous_ctors=%d sink_reaching=%d "
            "(backward_depth=%d frontiers=%s)",
            len(dangerous_ctors),
            len(sink_reaching),
            backward_depth,
            ",".join(f"{o}#{n}" for o, n in sorted(_CHA_FRONTIER_SLOTS)),
        )

        paths_for: dict[str, list[list[str]]] = defaultdict(list)
        path_seen: dict[str, set[tuple[str, ...]]] = defaultdict(set)
        # stitch_mid → entry→stitch_mid paths (A only; C just connects)
        stitch_mid_paths: dict[str, list[list[str]]] = defaultdict(list)
        # CHA frontier → entry→slot paths
        hub_paths: dict[str, list[list[str]]] = defaultdict(list)

        # --- A: entry ──► stitch_mid / sink / CHA frontier (no side BFS) ---
        self._open_invoke = False
        self._open_new = False
        self._expand_hubs = False
        total_visited = 0
        visit_budget = max(12000, max_visit // max(1, min(6, len(entry_list))))

        for entry in entry_list:
            parent: dict[str, str | None] = {entry: None}
            depth: dict[str, int] = {entry: 0}
            q: deque[str] = deque([entry])
            visited = 0
            while q and visited < visit_budget:
                if visited % 64 == 0:
                    self._prefetch_queue_calls(q)
                u = q.popleft()
                visited += 1
                total_visited += 1
                du = depth[u]
                if du >= max_depth:
                    continue
                for v in self.successors(u):
                    if v in sink_set:
                        path = self._reconstruct(parent, u) + [v]
                        self._add_path(
                            paths_for, path_seen, v, path, max_paths_per_sink
                        )
                        # Reflective mid that is also a sink (e.g. InstantiateTransformer):
                        # record for C connect, but do not treat every sink as mid.
                        if v in stitch_mids:
                            self._add_stitch_mid_path(
                                stitch_mid_paths,
                                v,
                                path,
                                max_paths_per_stitch_mid,
                            )
                        if v not in parent and du + 1 < max_depth:
                            parent[v] = u
                            depth[v] = du + 1
                            q.append(v)
                        continue
                    if self.is_cha_frontier(v):
                        path = self._reconstruct(parent, u) + [v]
                        slot = self._frontier_slot_qn(v)
                        self._add_hub_path(hub_paths, slot, path[:-1] + [slot], entry)
                        continue
                    if v in stitch_mids and v not in parent:
                        path = self._reconstruct(parent, u) + [v]
                        self._add_stitch_mid_path(
                            stitch_mid_paths,
                            v,
                            path,
                            max_paths_per_stitch_mid,
                        )
                    if v in parent:
                        continue
                    parent[v] = u
                    depth[v] = du + 1
                    if depth[v] < max_depth:
                        q.append(v)

        # --- A2: CHA frontier → class methods as secondary sources ---
        hub_stitched = self._expand_cha_hubs(
            hub_paths,
            sink_set,
            stitch_mids,
            paths_for,
            path_seen,
            stitch_mid_paths,
            max_depth=max_depth,
            max_paths_per_sink=max_paths_per_sink,
            max_paths_per_stitch_mid=max_paths_per_stitch_mid,
            # Secondary BFS is short for CC gadgets; large budgets mostly burn CHA queries.
            max_visit_per_hub=max(300, min(600, visit_budget // 20)),
        )

        # --- C: pure connect A prefixes × B targets (no extra graph search) ---
        self._expand_hubs = True
        stitched = self._stitch_at_mids(
            stitch_mid_paths,
            stitch_mids,
            sink_set,
            ctor_to_sink_paths,
            paths_for,
            path_seen,
            max_len=max_depth + backward_depth + 1,
            max_paths_per_sink=max_paths_per_sink,
        )

        out: list[dict] = []
        for sink, paths in paths_for.items():
            for path in paths:
                out.append(
                    {
                        "sink_method": sink,
                        "call_chain": path,
                        "hops": len(path),
                        "prio": 0,
                    }
                )
        logger.info(
            "Dynamic CHA A/B/C: entries=%d visited=%d hubs=%d hub_expand=%d "
            "stitch_mids_hit=%d stitched=%d overrides=%d chains=%d sinks_hit=%d",
            len(entry_list),
            total_visited,
            len(hub_paths),
            hub_stitched,
            len(stitch_mid_paths),
            stitched,
            len(self._overrides),
            len(out),
            len(paths_for),
        )
        return out

    @classmethod
    def _add_hub_path(
        cls,
        hub_paths: dict[str, list[list[str]]],
        hub: str,
        path: list[str],
        entry: str,
    ) -> None:
        """Keep shortest path per (entry, hub); avoids one entry flooding the hub."""
        if len(path) < 2 or path[-1] != hub or len(path) != len(set(path)):
            return
        bucket = hub_paths[hub]
        best_i = None
        for i, existing in enumerate(bucket):
            if existing and existing[0] == entry:
                best_i = i
                break
        if best_i is None:
            bucket.append(path)
            return
        if len(path) < len(bucket[best_i]):
            bucket[best_i] = path

    def _expand_cha_hubs(
        self,
        hub_paths: dict[str, list[list[str]]],
        sink_set: set[str],
        stitch_mids: dict[str, dict[str, bool]],
        paths_for: dict[str, list[list[str]]],
        path_seen: dict[str, set[tuple[str, ...]]],
        stitch_mid_paths: dict[str, list[list[str]]],
        *,
        max_depth: int,
        max_paths_per_sink: int,
        max_paths_per_stitch_mid: int,
        max_visit_per_hub: int,
    ) -> int:
        """Dedupe frontier: CHA each get/compare/toString once, then secondary BFS.

        For each unique virtual slot:
          CHA → concrete class methods (LazyMap#get, TiedMapEntry#toString, …)
        Each concrete method is a secondary source searched once; results are
        stitched onto all deduped entry→slot prefixes.
        """
        if not hub_paths:
            return 0
        saved = self._expand_hubs
        self._expand_hubs = True  # secondary search expands normally
        found = 0
        # Global cache: concrete method → shortest path to sink / stitch_mid
        member_to_sink: dict[str, dict[str, list[str]]] = {}
        member_to_stitch: dict[str, dict[str, list[str]]] = {}
        expanded_members: set[str] = set()

        def bfs_from_member(start: str) -> None:
            if start in expanded_members:
                return
            expanded_members.add(start)
            parent: dict[str, str | None] = {start: None}
            depth = {start: 0}
            q: deque[str] = deque([start])
            visited = 0
            sinks_hit: dict[str, list[str]] = {}
            stitches_hit: dict[str, list[str]] = {}
            while q and visited < max_visit_per_hub:
                if visited % 64 == 0:
                    self._prefetch_queue_calls(q)
                u = q.popleft()
                visited += 1
                du = depth[u]
                if du >= max_depth:
                    continue
                for v in self.successors(u):
                    if v in sink_set:
                        suffix = self._reconstruct(parent, u) + [v]
                        prev = sinks_hit.get(v)
                        if prev is None or len(suffix) < len(prev):
                            sinks_hit[v] = suffix
                        if v in stitch_mids:
                            prev_s = stitches_hit.get(v)
                            if prev_s is None or len(suffix) < len(prev_s):
                                stitches_hit[v] = suffix
                        if v not in parent and du + 1 < max_depth:
                            parent[v] = u
                            depth[v] = du + 1
                            q.append(v)
                        continue
                    if v in stitch_mids:
                        suffix = self._reconstruct(parent, u) + [v]
                        prev = stitches_hit.get(v)
                        if prev is None or len(suffix) < len(prev):
                            stitches_hit[v] = suffix
                    if v in parent:
                        continue
                    parent[v] = u
                    depth[v] = du + 1
                    if depth[v] < max_depth:
                        q.append(v)
            member_to_sink[start] = sinks_hit
            member_to_stitch[start] = stitches_hit
            if start in sink_set:
                member_to_sink.setdefault(start, {})
                member_to_sink[start].setdefault(start, [start])
            if start in stitch_mids:
                member_to_stitch.setdefault(start, {})
                member_to_stitch[start].setdefault(start, [start])

        try:
            for hub, prefixes in hub_paths.items():
                if not prefixes:
                    continue
                # CHA: which class methods does this virtual slot resolve to?
                members = self.hub_members(hub)
                # Prefer members that reverse-reach a sink; for Object pool do not
                # fall back to the full CHA_MAX spray (that re-explodes secondary BFS).
                reaching = self._sink_reaching
                if reaching and members:
                    focused = [
                        m
                        for m in members
                        if m in reaching or _owner_name(m)[0] in self.focus_types
                    ]
                    if focused:
                        members = focused
                    elif hub.startswith("java.lang.Object#"):
                        members = [
                            m
                            for m in members
                            if _owner_name(m)[0] in self.focus_types
                        ] or members[:8]
                # Cap secondary fan-out: prefer focus / commons-collections owners.
                if len(members) > 24:
                    prefer = [
                        m
                        for m in members
                        if _owner_name(m)[0] in self.focus_types
                        or "commons.collections" in m
                    ]
                    if prefer:
                        members = prefer
                    members = members[:24]
                logger.info(
                    "CHA frontier %s → %d class methods (prefixes=%d)",
                    hub,
                    len(members),
                    len(prefixes),
                )
                for member in members:
                    bfs_from_member(member)
                    for sink, suffix in member_to_sink.get(member, {}).items():
                        for prefix in prefixes:
                            full = self._stitch_hub_path(prefix, hub, suffix)
                            if self._add_path(
                                paths_for, path_seen, sink, full, max_paths_per_sink
                            ):
                                found += 1
                    for stitch_mid, suffix in member_to_stitch.get(member, {}).items():
                        for prefix in prefixes:
                            full = self._stitch_hub_path(prefix, hub, suffix)
                            if self._add_stitch_mid_path(
                                stitch_mid_paths,
                                stitch_mid,
                                full,
                                max_paths_per_stitch_mid,
                            ):
                                found += 1
            logger.info(
                "CHA frontier secondary sources: unique_members=%d",
                len(expanded_members),
            )
        finally:
            self._expand_hubs = saved
        return found

    @staticmethod
    def _stitch_hub_path(prefix: list[str], hub: str, suffix: list[str]) -> list[str]:
        """entry→…→hub + ClassMethod→…→sink (no duplicate hub node)."""
        if not prefix:
            return list(suffix)
        if not suffix:
            return list(prefix)
        if prefix[-1] == hub:
            if suffix[0] == hub:
                return prefix + suffix[1:]
            return prefix + suffix
        if prefix[-1] == suffix[0]:
            return prefix + suffix[1:]
        return prefix + suffix

    def _backward_from_sinks(
        self,
        sink_set: set[str],
        *,
        max_depth: int,
        max_ctors: int,
    ) -> tuple[dict[str, list[list[str]]], list[str], set[str]]:
        """Reverse CALLS BFS from sinks (level-batched).

        Near sinks (depth ≤ `_REV_CHA_MAX_DEPTH`) also walks callers of
        supertype same-name slots (reverse CHA). Deeper levels use precise
        CALLS only, with batched Neo4j loads per frontier.

        Returns:
          ctor→sink paths, ranked dangerous ctors, and all sink-reaching methods
          (for CHA / Object virtual filtering — cha_mid).
        """
        if not sink_set or max_depth < 1:
            return {}, [], set(sink_set)

        parent: dict[str, str | None] = {s: None for s in sink_set}
        depth: dict[str, int] = {s: 0 for s in sink_set}
        frontier: list[str] = sorted(sink_set)
        ctor_paths: dict[str, list[list[str]]] = defaultdict(list)
        ctor_dist: dict[str, int] = {}

        visited = 0
        max_visit = 50000
        cha_depth = min(_REV_CHA_MAX_DEPTH, max_depth)

        for _ in range(max_depth + 1):
            if not frontier or visited >= max_visit:
                break
            use_cha = depth.get(frontier[0], 0) <= cha_depth
            if use_cha:
                slots: list[str] = []
                for u in frontier:
                    slots.append(u)
                    slots.extend(self._supertype_slot_qns(u))
                # Dedupe while preserving order for stable Neo4j batches.
                self._load_rev_calls(list(dict.fromkeys(slots)))
            else:
                self._load_rev_calls(frontier)

            nxt: list[str] = []
            for u in frontier:
                visited += 1
                du = depth[u]
                if is_ctor_qn(u) and u not in sink_set:
                    path = self._reconstruct_forward(parent, u)
                    if path and path[-1] in sink_set:
                        sink = path[-1]
                        existing = ctor_paths[u]
                        if not any(p[-1] == sink for p in existing):
                            ctor_paths[u].append(path)
                            ctor_dist[u] = min(ctor_dist.get(u, 999), du)
                if du >= max_depth:
                    continue
                if use_cha:
                    preds = self._reverse_predecessors(u)
                else:
                    preds = self._rev_calls.get(u, [])
                for pred in preds:
                    if pred in parent:
                        continue
                    parent[pred] = u
                    depth[pred] = du + 1
                    nxt.append(pred)
            frontier = nxt

        ranked = sorted(
            ctor_paths.keys(),
            key=lambda c: (
                ctor_dist.get(c, 999),
                0 if _owner_name(c)[0] in self.focus_types else 1,
                c,
            ),
        )
        if max_ctors > 0:
            ranked = ranked[:max_ctors]
        selected = {c: ctor_paths[c] for c in ranked}
        sink_reaching = set(parent.keys())
        return selected, ranked, sink_reaching

    def _backward_dangerous_ctors(
        self,
        sink_set: set[str],
        *,
        max_depth: int,
        max_ctors: int,
    ) -> tuple[dict[str, list[list[str]]], list[str]]:
        """Compat wrapper around _backward_from_sinks (ctors only)."""
        paths, ctors, _ = self._backward_from_sinks(
            sink_set, max_depth=max_depth, max_ctors=max_ctors
        )
        return paths, ctors

    def _forward_path_to_sink(
        self,
        start: str,
        sink_set: set[str],
        *,
        max_depth: int,
        max_visit: int,
    ) -> list[str]:
        parent: dict[str, str | None] = {start: None}
        depth = {start: 0}
        q: deque[str] = deque([start])
        visited = 0
        # temporary: allow following CALLS only
        saved_oi, saved_on = self._open_invoke, self._open_new
        self._open_invoke = False
        self._open_new = False
        try:
            while q and visited < max_visit:
                u = q.popleft()
                visited += 1
                du = depth[u]
                if du >= max_depth:
                    continue
                for v in self.successors(u):
                    if v in sink_set:
                        return self._reconstruct(parent, u) + [v]
                    if v in parent:
                        continue
                    parent[v] = u
                    depth[v] = du + 1
                    if depth[v] < max_depth:
                        q.append(v)
        finally:
            self._open_invoke = saved_oi
            self._open_new = saved_on
        return []

    def _stitch_at_mids(
        self,
        stitch_mid_paths: dict[str, list[list[str]]],
        stitch_mids: dict[str, dict[str, bool]],
        sink_set: set[str],
        ctor_to_sink_paths: dict[str, list[list[str]]],
        paths_for: dict[str, list[list[str]]],
        path_seen: dict[str, set[tuple[str, ...]]],
        *,
        max_len: int,
        max_paths_per_sink: int,
    ) -> int:
        """C: pure connect — A prefixes × B targets. No extra graph search.

        newInstance mid:  prefix + ctor + (B's ctor→sink suffix)
        invoke mid:       prefix + sink   (or const reflective target if it is a sink)
        """
        stitched = 0
        n_pref = sum(len(v) for v in stitch_mid_paths.values())
        logger.info(
            "Reflective stitch C (pure connect): mids=%d prefixes=%d ctors=%d",
            len(stitch_mid_paths),
            n_pref,
            len(self._dangerous_ctors),
        )
        for stitch_mid, prefixes in stitch_mid_paths.items():
            kind = stitch_mids.get(stitch_mid) or {}
            self._load_calls([stitch_mid])
            const_tgts = list(self._reflective.edges.get(stitch_mid, []))
            calls = self._calls.get(stitch_mid) or []
            is_new = bool(kind.get("new")) or any(
                "Constructor#newInstance" in c or "Class#newInstance" in c
                for c in calls
            )
            is_invoke = bool(kind.get("invoke")) or any(
                "Method#invoke" in c for c in calls
            )

            if is_new:
                # B already computed ctor→sink; only connect those (plus const edges
                # that B also covered). No on-the-fly forward BFS.
                targets = list(dict.fromkeys(const_tgts + self._dangerous_ctors))
                for c in self._focus_ctors:
                    if c in ctor_to_sink_paths and c not in targets:
                        targets.append(c)
                for prefix in prefixes:
                    if not prefix or prefix[-1] != stitch_mid:
                        continue
                    for ctor in targets:
                        if ctor == stitch_mid:
                            continue
                        suffixes = list(ctor_to_sink_paths.get(ctor) or [])
                        if not suffixes and ctor in sink_set:
                            suffixes = [[ctor]]
                        # No suffix from B → skip (do not search the graph here).
                        for suffix in suffixes:
                            if not suffix:
                                continue
                            if suffix[0] == ctor:
                                full = prefix + suffix
                            else:
                                full = prefix + [ctor] + suffix
                            if len(full) > max_len:
                                continue
                            sink = full[-1]
                            if sink not in sink_set:
                                continue
                            if self._add_path(
                                paths_for, path_seen, sink, full, max_paths_per_sink
                            ):
                                stitched += 1

            if is_invoke:
                # Connect only to sinks (open invoke) or const edges that are sinks.
                invoke_tgts = list(dict.fromkeys(
                    [t for t in const_tgts if t in sink_set] + sorted(sink_set)
                ))
                for prefix in prefixes:
                    if not prefix or prefix[-1] != stitch_mid:
                        continue
                    for tgt in invoke_tgts:
                        if tgt == stitch_mid or tgt not in sink_set:
                            continue
                        full = prefix + [tgt]
                        if len(full) > max_len:
                            continue
                        if self._add_path(
                            paths_for, path_seen, tgt, full, max_paths_per_sink
                        ):
                            stitched += 1
        return stitched

    # Per (entry, stitch_mid): keep several prefixes so short LazyMap→mid and
    # longer TiedMap→LazyMap→mid both survive for Phase C (CC6+CC3).
    _STITCH_PREFIXES_PER_ENTRY = 6
    # Prefer prefixes that carry classic gadget bridges over shorter noise.
    _STITCH_BRIDGE_MARKERS = (
        "TiedMapEntry",
        "TransformingComparator",
        "checkSetValue",
        "TransformedMap",
        "BadAttributeValueExpException",
    )

    @classmethod
    def _stitch_prefix_rank(cls, path: list[str]) -> tuple:
        """Lower is better to keep: more bridges first, then shorter."""
        bridges = sum(
            1 for m in cls._STITCH_BRIDGE_MARKERS if any(m in n for n in path)
        )
        return (-bridges, len(path))

    @classmethod
    def _add_stitch_mid_path(
        cls,
        stitch_mid_paths: dict[str, list[list[str]]],
        stitch_mid: str,
        path: list[str],
        max_paths: int,
    ) -> bool:
        """Record entry→stitch_mid prefixes (top-k per entry).

        Short LazyMap→mid and longer TiedMap→LazyMap→mid both count as answers;
        bridge-bearing prefixes are preferred over shorter noise when the
        per-entry budget is full.
        """
        if len(path) < 1 or len(path) != len(set(path)):
            return False
        if path[-1] != stitch_mid:
            return False
        entry = path[0]
        bucket = stitch_mid_paths[stitch_mid]
        if any(existing == path for existing in bucket):
            return False
        same_idx = [
            i for i, existing in enumerate(bucket) if existing and existing[0] == entry
        ]
        if not same_idx:
            if max_paths > 0 and len(bucket) >= max_paths:
                return False
            bucket.append(path)
            return True
        if len(same_idx) < cls._STITCH_PREFIXES_PER_ENTRY:
            if max_paths > 0 and len(bucket) >= max_paths:
                return False
            bucket.append(path)
            return True
        # Full: replace worst-ranked prefix if the new one ranks better
        # (e.g. TiedMap path beats a short LazyMap-only noise prefix).
        worst_i = max(same_idx, key=lambda i: cls._stitch_prefix_rank(bucket[i]))
        if cls._stitch_prefix_rank(path) < cls._stitch_prefix_rank(bucket[worst_i]):
            bucket[worst_i] = path
            return True
        return False

    @classmethod
    def _add_path(
        cls,
        paths_for: dict[str, list[list[str]]],
        path_seen: dict[str, set[tuple[str, ...]]],
        sink: str,
        path: list[str],
        max_paths: int,
    ) -> bool:
        """Acyclic + O(1) exact-dedupe via set of tuples. max_paths<=0 unlimited."""
        if len(path) < 2 or len(path) != len(set(path)):
            return False
        key = tuple(path)
        seen = path_seen[sink]
        if key in seen:
            return False
        bucket = paths_for[sink]
        if max_paths > 0 and len(bucket) >= max_paths:
            return False
        seen.add(key)
        bucket.append(path)
        return True

    @staticmethod
    def _reconstruct(parent: dict[str, str | None], node: str) -> list[str]:
        path: list[str] = []
        cur: str | None = node
        seen: set[str] = set()
        while cur is not None:
            if cur in seen:
                return []
            seen.add(cur)
            path.append(cur)
            cur = parent.get(cur)
        path.reverse()
        return path

    @staticmethod
    def _reconstruct_forward(parent: dict[str, str | None], start: str) -> list[str]:
        """Follow reverse-BFS parent pointers start→…→sink."""
        path: list[str] = []
        cur: str | None = start
        seen: set[str] = set()
        while cur is not None:
            if cur in seen:
                return []
            seen.add(cur)
            path.append(cur)
            cur = parent.get(cur)
        return path
