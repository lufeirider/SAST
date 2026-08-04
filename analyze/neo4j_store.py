"""Write analysis findings into Neo4j + query call chains to confirmed methods."""

from __future__ import annotations

import hashlib
import logging
from typing import Iterable, Optional

from neo4j import Driver, GraphDatabase

from analyze.config import (
    NEO4J_AUTH,
    NEO4J_DATABASE,
    NEO4J_PASSWORD,
    NEO4J_URI,
    NEO4J_USER,
)
from analyze.chains import (
    annotate_chains_with_skeleton,
    compress_call_chains,
    summarize_gadget_skeletons,
)
from analyze.dynamic_cha_chains import DynamicChaChainFinder
from analyze.taint import TaintFinding

logger = logging.getLogger(__name__)


class FindingStore:
    def __init__(
        self,
        uri: str = NEO4J_URI,
        user: str = NEO4J_USER,
        password: str = NEO4J_PASSWORD,
        database: str = NEO4J_DATABASE,
    ):
        self.uri = uri
        self.user = user
        self.password = password
        self.database = database
        self._driver: Optional[Driver] = None

    def connect(self) -> None:
        auth = NEO4J_AUTH
        if auth is not None and self.user:
            auth = (self.user, self.password)
        self._driver = GraphDatabase.driver(self.uri, auth=auth)
        self._driver.verify_connectivity()

    def close(self) -> None:
        if self._driver:
            self._driver.close()
            self._driver = None

    def __enter__(self) -> "FindingStore":
        self.connect()
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def clear_findings(self, project: str) -> None:
        assert self._driver
        with self._driver.session(database=self.database) as session:
            session.run(
                "MATCH (f:Finding {project: $project}) DETACH DELETE f",
                project=project,
            )

    def save_findings(self, project: str, findings: list[TaintFinding]) -> int:
        assert self._driver
        rows = []
        for f in findings:
            fid = hashlib.sha1(
                f"{project}|{f.method_qn}|{f.sink_name}|{f.sink_line}|{f.sink_arg}".encode()
            ).hexdigest()[:16]
            rows.append(
                {
                    "id": fid,
                    "project": project,
                    "method_qn": f.method_qn,
                    "method_name": f.method_name,
                    "type_qn": f.type_qn,
                    "sink_name": f.sink_name,
                    "sink_owner": f.sink_owner,
                    "vul": f.vul,
                    "sink_line": f.sink_line,
                    "sink_arg": f.sink_arg,
                    "tainted_vars": f.tainted_vars,
                    "source_kind": f.source_kind,
                    "evidence": f.evidence,
                    "rule": "tabby-sink+simple-taint",
                }
            )

        cypher = """
        UNWIND $rows AS row
        MERGE (f:Finding {id: row.id})
        SET f.project = row.project,
            f.method_qn = row.method_qn,
            f.method_name = row.method_name,
            f.type_qn = row.type_qn,
            f.sink_name = row.sink_name,
            f.sink_owner = row.sink_owner,
            f.vul = row.vul,
            f.sink_line = row.sink_line,
            f.sink_arg = row.sink_arg,
            f.tainted_vars = row.tainted_vars,
            f.source_kind = row.source_kind,
            f.evidence = row.evidence,
            f.rule = row.rule
        WITH f, row
        OPTIONAL MATCH (m:Method {qualified_name: row.method_qn})
        FOREACH (_ IN CASE WHEN m IS NULL THEN [] ELSE [1] END |
            MERGE (f)-[:IN_METHOD]->(m)
        )
        """
        with self._driver.session(database=self.database) as session:
            session.run(cypher, rows=rows)
        logger.info("Saved %d findings for project=%s", len(rows), project)
        return len(rows)

    def _entry_qns(self, session, project: str) -> list[str]:
        """Deserialization entries only: readObject / readExternal → sinks."""
        rows = session.run(
            """
            MATCH (t:Type {project:$p})-[:HAS_METHOD]->(m:Method {project:$p})
            WHERE m.name IN ['readObject', 'readExternal']
            RETURN DISTINCT m.qualified_name AS qn
            ORDER BY m.qualified_name
            """,
            p=project,
        ).data()
        return [r["qn"] for r in rows if r.get("qn")]

    def query_call_chains_to_methods(
        self,
        project: str,
        method_qns: Iterable[str],
        *,
        max_depth: int = 7,
        batch_size: int = 25,
        per_batch_limit: int = 400,
        focus_type_qns: Iterable[str] | None = None,
    ) -> list[dict]:
        """
        Find CALLS paths from entry methods → confirmed sinks with on-demand CHA.

        Reflective Method#invoke / Constructor#newInstance use meet-in-the-middle
        stitch at stitch_mids (entry→stitch_mid + dangerous-target→sink).
        """
        assert self._driver
        qns = sorted({q for q in method_qns if q})
        if not qns:
            return []

        depth = max(1, min(int(max_depth), 8))
        _ = batch_size, per_batch_limit  # kept for API compat

        with self._driver.session(database=self.database) as session:
            path_entries = self._entry_qns(session, project)
            # Drop entries that are themselves the queried sinks
            sink_set = set(qns)
            path_entries = [e for e in path_entries if e not in sink_set]
            from analyze.chains import _entry_score

            path_entries.sort(key=lambda q: (-_entry_score(q), q))
            logger.info(
                "Chain query (dynamic CHA): %d sinks, %d entries, depth=%d",
                len(qns),
                len(path_entries),
                depth,
            )
            finder = DynamicChaChainFinder(
                session,
                project,
                focus_type_qns=focus_type_qns,
            )
            raw = finder.find_chains(
                path_entries,
                qns,
                max_depth=depth,
                max_paths_per_sink=0,
            )

        cleaned: list[dict] = []
        for row in raw:
            ch = list(row.get("call_chain") or [])
            if len(ch) < 2 or len(ch) != len(set(ch)):
                continue
            cleaned.append(
                {
                    **row,
                    "call_chain": ch,
                    "sink": row.get("sink") or "",
                    "sink_line": row.get("sink_line") or 0,
                    "sink_vul": row.get("sink_vul") or "",
                    "sink_owner": row.get("sink_owner") or "",
                }
            )

        by_target: dict[str, list[dict]] = {}
        for row in cleaned:
            by_target.setdefault(str(row.get("sink_method") or ""), []).append(row)

        out: list[dict] = []
        for target, rows in by_target.items():
            if not target:
                continue
            out.extend(compress_call_chains(rows, min_hops=2, max_chains=0))
        out = annotate_chains_with_skeleton(out)
        summary = summarize_gadget_skeletons(out)
        logger.info(
            "Call chains to %d confirmed methods: %d raw → %d acyclic → %d compressed",
            len(qns),
            len(raw),
            len(cleaned),
            len(out),
        )
        logger.info(
            "Gadget skeletons: unique=%d known=%d novel=%d noise=%d (from %d chains)",
            summary["unique"],
            summary["counts"]["known"],
            summary["counts"]["novel"],
            summary["counts"]["noise"],
            summary["raw"],
        )
        return out
