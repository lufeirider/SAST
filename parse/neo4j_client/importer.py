"""Import ParseResult into Neo4j with call-chain edges."""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Optional

from neo4j import Driver, GraphDatabase

from parse.config import (
    BATCH_SIZE,
    CHA_MAX_CALLEES,
    CHA_PREFER_SUBSTRINGS,
    NEO4J_AUTH,
    NEO4J_DATABASE,
    NEO4J_PASSWORD,
    NEO4J_URI,
    NEO4J_USER,
    is_cha_no_expand,
)
from parse.models import MethodInfo, ParseResult, TypeInfo
from parse.neo4j_client.schema import CONSTRAINTS, INDEXES
from parse.object_graph import build_serializable_set, iter_field_point_rows
from rules.sinks import match_sink_call, sink_function_names

logger = logging.getLogger(__name__)

# Coarse name set; precise matching uses match_sink_call (Tabby rules)
SINK_NAMES = set(sink_function_names())

_RE_NEW = re.compile(r"new\s+([\w.]+)\s*(?:<[^>]*>)?\s*\(")
_RE_CAST = re.compile(r"\(\s*([\w.]+)\s*\)")
_RE_IDENT = re.compile(r"^[A-Za-z_][\w]*$")


class Neo4jImporter:
    def __init__(
        self,
        uri: str = NEO4J_URI,
        user: str = NEO4J_USER,
        password: str = NEO4J_PASSWORD,
        database: str = NEO4J_DATABASE,
        batch_size: int = BATCH_SIZE,
    ):
        self.uri = uri
        self.user = user
        self.password = password
        self.database = database
        self.batch_size = batch_size
        self._driver: Optional[Driver] = None

    def connect(self) -> None:
        auth = NEO4J_AUTH
        if auth is not None and self.user:
            auth = (self.user, self.password)
        self._driver = GraphDatabase.driver(self.uri, auth=auth)
        self._driver.verify_connectivity()
        logger.info("Connected to Neo4j at %s (auth=%s)", self.uri, "none" if auth is None else "user")

    def close(self) -> None:
        if self._driver:
            self._driver.close()
            self._driver = None

    def __enter__(self) -> "Neo4jImporter":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @property
    def driver(self) -> Driver:
        if self._driver is None:
            raise RuntimeError("Not connected.")
        return self._driver

    def ensure_schema(self) -> None:
        with self.driver.session(database=self.database) as session:
            for cypher in CONSTRAINTS + INDEXES:
                session.run(cypher)
        logger.info("Neo4j schema ensured")

    def clear_project(self, project: str) -> None:
        with self.driver.session(database=self.database) as session:
            session.run(
                "MATCH (n {project: $project}) DETACH DELETE n",
                project=project,
            )
            session.run(
                "MATCH (p:Project {name: $project}) DETACH DELETE p",
                project=project,
            )
        logger.info("Cleared project=%s", project)

    def import_result(self, result: ParseResult, clear: bool = True) -> None:
        if clear:
            self.clear_project(result.project)
        self.ensure_schema()
        self._import_project(result.project)
        self._import_files(result)
        self._import_types(result)
        self._import_methods_fields_params(result)
        self._import_inheritance(result)
        self._import_object_graph(result)
        self._import_calls_and_sites(result)
        logger.info(
            "Imported project=%s files=%d types=%d methods=%d call_sites=%d",
            result.project,
            len(result.files),
            result.type_count,
            result.method_count,
            result.call_site_count,
        )

    def _run_batches(self, cypher: str, rows: list[dict], key: str = "rows") -> None:
        if not rows:
            return
        with self.driver.session(database=self.database) as session:
            for i in range(0, len(rows), self.batch_size):
                session.run(cypher, **{key: rows[i : i + self.batch_size]})

    def _import_project(self, project: str) -> None:
        with self.driver.session(database=self.database) as session:
            session.run(
                "MERGE (p:Project {name: $project}) SET p.project = $project",
                project=project,
            )

    def _import_files(self, result: ParseResult) -> None:
        rows = [
            {
                "path": f.path,
                "language": f.language,
                "package": f.package,
                "imports": f.imports,
                "project": result.project,
            }
            for f in result.files
        ]
        cypher = """
        UNWIND $rows AS row
        MATCH (p:Project {name: row.project})
        MERGE (f:File {path: row.path})
        SET f.language = row.language,
            f.package = row.package,
            f.imports = row.imports,
            f.project = row.project
        MERGE (p)-[:HAS_FILE]->(f)
        """
        self._run_batches(cypher, rows)

    def _import_types(self, result: ParseResult) -> None:
        all_types = [t for f in result.files for t in f.types]
        serializable = build_serializable_set(all_types)
        rows = []
        for f in result.files:
            for t in f.types:
                rows.append(
                    {
                        "qn": t.qualified_name,
                        "name": t.name,
                        "kind": t.kind,
                        "package": t.package,
                        "file_path": f.path,
                        "start_line": t.start_line,
                        "end_line": t.end_line,
                        "is_serializable": t.qualified_name in serializable,
                        "project": result.project,
                    }
                )
        cypher = """
        UNWIND $rows AS row
        MATCH (f:File {path: row.file_path})
        MERGE (t:Type {qualified_name: row.qn})
        SET t.name = row.name,
            t.kind = row.kind,
            t.package = row.package,
            t.file_path = row.file_path,
            t.start_line = row.start_line,
            t.end_line = row.end_line,
            t.is_serializable = row.is_serializable,
            t.project = row.project
        MERGE (f)-[:DECLARES]->(t)
        """
        self._run_batches(cypher, rows)

    def _import_methods_fields_params(self, result: ParseResult) -> None:
        method_rows = []
        field_rows = []
        param_rows = []
        serializable = build_serializable_set(
            [t for f in result.files for t in f.types]
        )
        for f in result.files:
            for t in f.types:
                field_names = [fld.name for fld in t.fields]
                for m in t.methods:
                    calls_sink = any(
                        match_sink_call(
                            callee_name=cs.callee_name,
                            resolved_qn=cs.resolved_qn,
                            is_constructor=cs.is_constructor,
                        )
                        for cs in m.call_sites
                    )
                    is_entry_sink = m.name in {"readObject", "readExternal"}
                    method_rows.append(
                        {
                            "type_qn": t.qualified_name,
                            "qn": m.qualified_name,
                            "name": m.name,
                            "return_type": m.return_type,
                            "parameters": [f"{p.type_name} {p.name}" for p in m.parameters],
                            "param_names": [p.name for p in m.parameters],
                            "field_names": field_names,
                            "start_line": m.start_line,
                            "end_line": m.end_line,
                            "calls": m.calls,
                            # Neo4j props cannot be maps — store as strings
                            "assignments": [
                                f"{a.lhs}={a.rhs}@{a.line}" for a in m.assignments
                            ],
                            "is_sink": is_entry_sink,
                            "calls_sink": calls_sink,
                            "project": result.project,
                        }
                    )
                    for p in m.parameters:
                        param_rows.append(
                            {
                                "method_qn": m.qualified_name,
                                "key": f"{m.qualified_name}::{p.index}:{p.name}",
                                "name": p.name,
                                "type_name": p.type_name,
                                "index": p.index,
                                "project": result.project,
                            }
                        )
                owner_ser = t.qualified_name in serializable
                for fld in t.fields:
                    ser_write = (
                        (not fld.is_static)
                        and (not fld.is_transient)
                        and owner_ser
                        and t.kind in {"class", "enum"}
                    )
                    field_rows.append(
                        {
                            "type_qn": t.qualified_name,
                            "name": fld.name,
                            "type_name": fld.type_name,
                            "resolved_type": fld.resolved_type,
                            "is_static": fld.is_static,
                            "is_transient": fld.is_transient,
                            "is_final": fld.is_final,
                            "serializable_write": ser_write,
                            "start_line": fld.start_line,
                            "key": f"{t.qualified_name}#{fld.name}",
                            "project": result.project,
                        }
                    )

        method_cypher = """
        UNWIND $rows AS row
        MATCH (t:Type {qualified_name: row.type_qn})
        MERGE (m:Method {qualified_name: row.qn})
        SET m.name = row.name,
            m.return_type = row.return_type,
            m.parameters = row.parameters,
            m.param_names = row.param_names,
            m.field_names = row.field_names,
            m.start_line = row.start_line,
            m.end_line = row.end_line,
            m.calls = row.calls,
            m.assignments = row.assignments,
            m.is_sink = row.is_sink,
            m.calls_sink = row.calls_sink,
            m.project = row.project
        MERGE (t)-[:HAS_METHOD]->(m)
        """
        field_cypher = """
        UNWIND $rows AS row
        MATCH (t:Type {qualified_name: row.type_qn})
        MERGE (f:Field {key: row.key})
        SET f.name = row.name,
            f.type_name = row.type_name,
            f.resolved_type = row.resolved_type,
            f.is_static = row.is_static,
            f.is_transient = row.is_transient,
            f.is_final = row.is_final,
            f.serializable_write = row.serializable_write,
            f.start_line = row.start_line,
            f.project = row.project
        MERGE (t)-[:HAS_FIELD]->(f)
        """
        param_cypher = """
        UNWIND $rows AS row
        MATCH (m:Method {qualified_name: row.method_qn})
        MERGE (p:Parameter {key: row.key})
        SET p.name = row.name,
            p.type_name = row.type_name,
            p.index = row.index,
            p.project = row.project
        MERGE (m)-[:HAS_PARAM]->(p)
        """
        self._run_batches(method_cypher, method_rows)
        self._run_batches(field_cypher, field_rows)
        self._run_batches(param_cypher, param_rows)

    def _import_object_graph(self, result: ParseResult) -> None:
        """Field declared/points-to types + Type-MAY_REF-Type object aliases (CHA)."""
        points_rows, alias_rows, stats = iter_field_point_rows(result)

        declared = [r for r in points_rows if r["kind"] == "declared"]
        points = [r for r in points_rows if r["kind"] == "points"]

        declared_cypher = """
        UNWIND $rows AS row
        MATCH (f:Field {key: row.field_key})
        MATCH (t:Type {qualified_name: row.target_qn})
        WHERE f.project = row.project AND t.project = row.project
        MERGE (f)-[:DECLARED_TYPE]->(t)
        """
        points_cypher = """
        UNWIND $rows AS row
        MATCH (f:Field {key: row.field_key})
        MATCH (t:Type {qualified_name: row.target_qn})
        WHERE f.project = row.project AND t.project = row.project
        MERGE (f)-[:POINTS_TO]->(t)
        """
        # Deduplicate MAY_REF rows
        seen: set[tuple] = set()
        uniq_alias: list[dict] = []
        for r in alias_rows:
            key = (r["owner_qn"], r["target_qn"], r["field_key"])
            if key in seen:
                continue
            seen.add(key)
            uniq_alias.append(r)

        alias_cypher = """
        UNWIND $rows AS row
        MATCH (owner:Type {qualified_name: row.owner_qn, project: row.project})
        MATCH (target:Type {qualified_name: row.target_qn, project: row.project})
        MERGE (owner)-[r:MAY_REF {field_key: row.field_key}]->(target)
        SET r.field = row.field,
            r.field_type = row.field_type,
            r.is_array = row.is_array,
            r.serializable_write = row.serializable_write,
            r.project = row.project
        """
        self._run_batches(declared_cypher, declared)
        self._run_batches(points_cypher, points)
        self._run_batches(alias_cypher, uniq_alias)
        logger.info(
            "Object graph: fields=%d with_points=%d DECLARED_TYPE=%d "
            "POINTS_TO=%d MAY_REF=%d serializable_types=%d",
            stats["fields_total"],
            stats["fields_with_points"],
            stats["declared_edges"],
            stats["points_edges"],
            len(uniq_alias),
            stats["serializable_types"],
        )

    def _import_inheritance(self, result: ParseResult) -> None:
        rows = []
        for f in result.files:
            for t in f.types:
                for parent in t.extends:
                    rows.append(
                        {
                            "child": t.qualified_name,
                            "parent_name": parent,
                            "rel": "EXTENDS",
                            "project": result.project,
                        }
                    )
                for iface in t.implements:
                    rows.append(
                        {
                            "child": t.qualified_name,
                            "parent_name": iface,
                            "rel": "IMPLEMENTS",
                            "project": result.project,
                        }
                    )
        cypher = """
        UNWIND $rows AS row
        MATCH (child:Type {qualified_name: row.child})
        OPTIONAL MATCH (parent:Type {project: row.project})
        WHERE parent.name = row.parent_name
           OR parent.qualified_name = row.parent_name
           OR parent.qualified_name ENDS WITH ('.' + row.parent_name)
        WITH child, row, collect(parent)[0] AS resolved
        FOREACH (_ IN CASE WHEN resolved IS NULL THEN [1] ELSE [] END |
            MERGE (stub:Type {
                qualified_name: row.project + '::stub::' + row.parent_name
            })
            SET stub.name = row.parent_name, stub.kind = 'stub', stub.project = row.project
            FOREACH (__ IN CASE WHEN row.rel = 'EXTENDS' THEN [1] ELSE [] END |
                MERGE (child)-[:EXTENDS]->(stub)
            )
            FOREACH (__ IN CASE WHEN row.rel = 'IMPLEMENTS' THEN [1] ELSE [] END |
                MERGE (child)-[:IMPLEMENTS]->(stub)
            )
        )
        FOREACH (_ IN CASE WHEN resolved IS NOT NULL THEN [1] ELSE [] END |
            FOREACH (__ IN CASE WHEN row.rel = 'EXTENDS' THEN [1] ELSE [] END |
                MERGE (child)-[:EXTENDS]->(resolved)
            )
            FOREACH (__ IN CASE WHEN row.rel = 'IMPLEMENTS' THEN [1] ELSE [] END |
                MERGE (child)-[:IMPLEMENTS]->(resolved)
            )
        )
        """
        self._run_batches(cypher, rows)

    def _import_calls_and_sites(self, result: ParseResult) -> None:
        """Resolve CALLS using receiver / local types (not same-package name alone)."""
        by_type_methods: dict[str, list[str]] = defaultdict(list)  # typeQn -> methodQn
        simple_to_types: dict[str, list[str]] = defaultdict(list)  # SubVul -> [pkg.SubVul]
        types_by_qn: dict[str, TypeInfo] = {}
        # parent_simple/qn -> child type qns (for virtual calls)
        subtypes: dict[str, list[str]] = defaultdict(list)

        for f in result.files:
            for t in f.types:
                types_by_qn[t.qualified_name] = t
                simple_to_types[t.name].append(t.qualified_name)
                if "." in t.qualified_name:
                    simple_to_types[t.qualified_name].append(t.qualified_name)
                for m in t.methods:
                    by_type_methods[t.qualified_name].append(m.qualified_name)

        for t in types_by_qn.values():
            for parent in t.extends + t.implements:
                parent_qns = self._lookup_type_qns(parent, simple_to_types)
                for pq in parent_qns:
                    subtypes[pq].append(t.qualified_name)
                # also index by simple parent name
                subtypes[parent.split(".")[-1]].append(t.qualified_name)

        call_rows = []
        site_rows = []
        site_id = 0

        for f in result.files:
            for t in f.types:
                field_types = {fld.name: fld.type_name for fld in t.fields}
                for m in t.methods:
                    local_types = self._local_types(m, field_types)
                    for cs in m.call_sites:
                        targets: list[str] = []
                        # Import: precise edges only (no CHA fan-out).
                        # CHA subtype expansion is materialized at analyze time
                        # as :CHA_CALLS (see analyze/cha_expand.py).
                        if cs.resolved_qn:
                            owner = (
                                cs.resolved_qn.split("#", 1)[0]
                                if "#" in cs.resolved_qn
                                else ""
                            )
                            # Object / Serializable / … = any type → no CALLS edge
                            if is_cha_no_expand(owner):
                                targets = []
                            else:
                                targets = [cs.resolved_qn]
                        elif not cs.is_constructor:
                            # Heuristic fallback: same-type / inferred receiver only,
                            # still no subtype fan-out (include_subtypes=False).
                            targets = self._resolve_callees(
                                cs.callee_name,
                                receiver=cs.receiver,
                                caller_type=t.qualified_name,
                                local_types=local_types,
                                field_types=field_types,
                                by_type_methods=by_type_methods,
                                simple_to_types=simple_to_types,
                                subtypes=subtypes,
                            )
                        for target in targets:
                            if target == m.qualified_name:
                                continue
                            call_rows.append(
                                {
                                    "caller_qn": m.qualified_name,
                                    "callee_qn": target,
                                    "project": result.project,
                                }
                            )
                        site_id += 1
                        primary = ""
                        if len(targets) == 1:
                            primary = targets[0]
                        elif targets:
                            # prefer exact receiver type over subtype expansions
                            primary = targets[0]
                        sink_hit = match_sink_call(
                            callee_name=cs.callee_name,
                            resolved_qn=cs.resolved_qn,
                            is_constructor=cs.is_constructor,
                        )
                        site_rows.append(
                            {
                                "id": f"{result.project}::cs::{site_id}",
                                "caller_qn": m.qualified_name,
                                "callee_name": cs.callee_name,
                                "receiver": cs.receiver,
                                "arguments": cs.arguments,
                                "line": cs.line,
                                "is_constructor": cs.is_constructor,
                                "is_sink": sink_hit is not None,
                                "sink_vul": sink_hit.rule.vul if sink_hit else "",
                                "sink_owner": sink_hit.rule.owner if sink_hit else "",
                                "resolved_qn": cs.resolved_qn or "",
                                "target_qn": primary or (cs.resolved_qn or ""),
                                "project": result.project,
                            }
                        )

        seen = set()
        uniq_calls = []
        for row in call_rows:
            key = (row["caller_qn"], row["callee_qn"])
            if key in seen:
                continue
            seen.add(key)
            uniq_calls.append(row)

        call_cypher = """
        UNWIND $rows AS row
        MATCH (caller:Method {qualified_name: row.caller_qn})
        MATCH (callee:Method {qualified_name: row.callee_qn})
        MERGE (caller)-[:CALLS]->(callee)
        """
        site_cypher = """
        UNWIND $rows AS row
        MATCH (caller:Method {qualified_name: row.caller_qn})
        MERGE (cs:CallSite {id: row.id})
        SET cs.caller_qn = row.caller_qn,
            cs.callee_name = row.callee_name,
            cs.receiver = row.receiver,
            cs.arguments = row.arguments,
            cs.line = row.line,
            cs.is_constructor = row.is_constructor,
            cs.is_sink = row.is_sink,
            cs.sink_vul = row.sink_vul,
            cs.sink_owner = row.sink_owner,
            cs.resolved_qn = row.resolved_qn,
            cs.target_qn = row.target_qn,
            cs.project = row.project
        MERGE (caller)-[:HAS_CALL_SITE]->(cs)
        WITH cs, row
        WHERE row.target_qn <> ''
        MATCH (callee:Method {qualified_name: row.target_qn})
        MERGE (cs)-[:RESOLVED_TO]->(callee)
        """
        self._run_batches(call_cypher, uniq_calls)
        self._run_batches(site_cypher, site_rows)
        logger.info(
            "CALLS edges=%d CallSites=%d", len(uniq_calls), len(site_rows)
        )

    @staticmethod
    def _method_base_name(qn: str) -> str:
        if "#" not in qn:
            return qn
        return qn.split("#", 1)[1].split("(", 1)[0]

    @staticmethod
    def _simple_type(name: str) -> str:
        name = (name or "").strip()
        name = name.split("<", 1)[0].strip()
        return name.split(".")[-1] if name else ""

    @classmethod
    def _lookup_type_qns(
        cls, type_name: str, simple_to_types: dict[str, list[str]]
    ) -> list[str]:
        if not type_name:
            return []
        if type_name in simple_to_types:
            return list(dict.fromkeys(simple_to_types[type_name]))
        simple = cls._simple_type(type_name)
        return list(dict.fromkeys(simple_to_types.get(simple, [])))

    @classmethod
    def _local_types(
        cls, method: MethodInfo, field_types: dict[str, str]
    ) -> dict[str, str]:
        """var/param name → declared or inferred type simple/qn string."""
        out: dict[str, str] = {}
        for p in method.parameters:
            if p.name and p.type_name:
                out[p.name] = p.type_name
        for a in method.assignments:
            lhs = (a.lhs or "").strip()
            if not lhs or " " in lhs:
                continue
            m = _RE_NEW.search(a.rhs or "")
            if m:
                out[lhs] = m.group(1)
            cast = _RE_CAST.search(a.rhs or "")
            if cast and lhs not in out:
                out[lhs] = cast.group(1)
        out.update({k: v for k, v in field_types.items() if k not in out})
        return out

    @classmethod
    def _infer_receiver_types(
        cls,
        receiver: str,
        *,
        caller_type: str,
        local_types: dict[str, str],
        field_types: dict[str, str],
        simple_to_types: dict[str, list[str]],
    ) -> list[str]:
        r = (receiver or "").strip()
        if not r or r == "this":
            return [caller_type]

        m = _RE_NEW.search(r)
        if m:
            return cls._lookup_type_qns(m.group(1), simple_to_types)

        cast = _RE_CAST.search(r)
        if cast:
            return cls._lookup_type_qns(cast.group(1), simple_to_types)

        if r.startswith("this."):
            fname = r[5:]
            tname = field_types.get(fname) or local_types.get(fname)
            if tname:
                return cls._lookup_type_qns(tname, simple_to_types)
            return []

        if _RE_IDENT.match(r):
            tname = local_types.get(r) or field_types.get(r)
            if tname:
                return cls._lookup_type_qns(tname, simple_to_types)
            # static-looking TypeName.method
            found = cls._lookup_type_qns(r, simple_to_types)
            if found:
                return found
            return []

        # nested: foo.bar — take outermost identifier if known
        if "." in r and not r.startswith("("):
            head = r.split(".", 1)[0]
            if _RE_IDENT.match(head):
                tname = local_types.get(head) or field_types.get(head)
                if tname:
                    return cls._lookup_type_qns(tname, simple_to_types)
        return []

    @classmethod
    def _rank_cha_target(cls, mqn: str) -> tuple:
        """Prefer gadget-relevant callees when CHA fan-out is capped."""
        score = 0
        for i, hint in enumerate(CHA_PREFER_SUBSTRINGS):
            if hint in mqn:
                score += 100 - i
        return (-score, len(mqn), mqn)

    @classmethod
    def _cap_cha(cls, mqns: list[str], limit: int | None = None) -> list[str]:
        lim = CHA_MAX_CALLEES if limit is None else limit
        if len(mqns) <= lim:
            return mqns
        ranked = sorted(mqns, key=cls._rank_cha_target)
        return ranked[:lim]

    @classmethod
    def _methods_named_on_types(
        cls,
        name: str,
        type_qns: list[str],
        by_type_methods: dict[str, list[str]],
        subtypes: dict[str, list[str]],
        *,
        include_subtypes: bool = True,
    ) -> list[str]:
        """Methods named `name` on type and (optionally) overriding subtypes."""
        out: list[str] = []
        seen: set[str] = set()
        stack = list(type_qns)
        visited: set[str] = set()
        while stack:
            tqn = stack.pop(0)
            if not tqn or tqn in visited:
                continue
            visited.add(tqn)
            for mqn in by_type_methods.get(tqn, []):
                if cls._method_base_name(mqn) == name and mqn not in seen:
                    seen.add(mqn)
                    out.append(mqn)
            if include_subtypes:
                for child in subtypes.get(tqn, []):
                    stack.append(child)
                simple = tqn.rsplit(".", 1)[-1]
                for child in subtypes.get(simple, []):
                    stack.append(child)
        return cls._cap_cha(out)

    @classmethod
    def _resolve_callees(
        cls,
        name: str,
        *,
        receiver: str,
        caller_type: str,
        local_types: dict[str, str],
        field_types: dict[str, str],
        by_type_methods: dict[str, list[str]],
        simple_to_types: dict[str, list[str]],
        subtypes: dict[str, list[str]],
    ) -> list[str]:
        recv_types = cls._infer_receiver_types(
            receiver,
            caller_type=caller_type,
            local_types=local_types,
            field_types=field_types,
            simple_to_types=simple_to_types,
        )
        # Drop universal receivers — "any type", no CALLS edges
        recv_types = [t for t in recv_types if not is_cha_no_expand(t)]
        if recv_types:
            # Import-time: resolved receiver type only (no subtype CHA).
            found = cls._methods_named_on_types(
                name, recv_types, by_type_methods, subtypes, include_subtypes=False
            )
            if found:
                return found

        # No usable receiver type: only resolve unqualified calls on same type
        # (implicit this). Never same-package-by-name (false ClassInheritController#test).
        if not (receiver or "").strip() or (receiver or "").strip() == "this":
            if is_cha_no_expand(caller_type):
                return []
            return cls._methods_named_on_types(
                name,
                [caller_type],
                by_type_methods,
                subtypes,
                include_subtypes=False,
            )
        return []
