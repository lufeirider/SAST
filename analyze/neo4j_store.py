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
from analyze.chains import compress_call_chains
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

    def query_call_chains_to_methods(
        self,
        project: str,
        method_qns: Iterable[str],
        *,
        max_depth: int = 5,
        batch_size: int = 25,
        per_batch_limit: int = 400,
    ) -> list[dict]:
        """
        For confirmed exploitable methods, find CALLS paths that reach them.

        Only these targets are queried (not every Tabby CallSite) — cheaper and
        matches: sink → taint-confirmed → then stitch callers.
        """
        assert self._driver
        qns = sorted({q for q in method_qns if q})
        if not qns:
            return []

        # depth baked into query string (neo4j param not allowed in *range*)
        depth = max(1, min(int(max_depth), 8))
        # Per-target query: a shared LIMIT across many sinks lets BeanMap CHA
        # noise starve classic AIH→LazyMap→Invoker (3 hops).
        cypher = f"""
        MATCH (sink:Method {{project: $project, qualified_name: $qn}})
        MATCH path = (entry:Method {{project: $project}})-[:CALLS|CHA_CALLS*1..{depth}]->(sink)
        WITH sink, [n IN nodes(path) | n.qualified_name] AS call_chain
        WITH sink, call_chain, size(call_chain) AS hops,
          CASE
            WHEN any(x IN call_chain WHERE x CONTAINS 'AnnotationInvocationHandler')
             AND any(x IN call_chain WHERE x CONTAINS 'LazyMap')
             AND any(x IN call_chain WHERE x CONTAINS 'InvokerTransformer') THEN 0
            WHEN any(x IN call_chain WHERE x CONTAINS 'AnnotationInvocationHandler')
             AND any(x IN call_chain WHERE x CONTAINS 'LazyMap') THEN 1
            WHEN any(x IN call_chain WHERE x CONTAINS 'AnnotationInvocationHandler') THEN 2
            WHEN any(x IN call_chain WHERE x CONTAINS 'TiedMapEntry')
             AND any(x IN call_chain WHERE x CONTAINS 'LazyMap') THEN 3
            WHEN any(x IN call_chain WHERE x CONTAINS 'LazyMap') THEN 4
            WHEN any(x IN call_chain WHERE x CONTAINS 'ChainedTransformer') THEN 5
            WHEN any(x IN call_chain WHERE x CONTAINS 'BeanMap') THEN 20
            ELSE 10
          END AS prio
        RETURN DISTINCT
          sink.qualified_name AS sink_method,
          call_chain AS call_chain,
          hops,
          prio
        ORDER BY prio ASC, hops ASC
        LIMIT $limit
        """

        per_target_limit = max(40, min(120, per_batch_limit))
        raw: list[dict] = []
        with self._driver.session(database=self.database) as session:
            for qn in qns:
                try:
                    rows = session.run(
                        cypher,
                        project=project,
                        qn=qn,
                        limit=per_target_limit,
                    ).data()
                    raw.extend(rows)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Call-chain query failed for %s: %s", qn, exc)

        # drop cycles + attach placeholder fields
        cleaned: list[dict] = []
        for row in raw:
            ch = list(row.get("call_chain") or [])
            if len(ch) < 2 or len(ch) != len(set(ch)):
                continue
            row = {
                **row,
                "call_chain": ch,
                "sink": row.get("sink") or "",
                "sink_line": row.get("sink_line") or 0,
                "sink_vul": row.get("sink_vul") or "",
                "sink_owner": row.get("sink_owner") or "",
            }
            cleaned.append(row)

        # Compress per target method so noisy sinks don't starve others
        by_target: dict[str, list[dict]] = {}
        for row in cleaned:
            by_target.setdefault(str(row.get("sink_method") or ""), []).append(row)

        out: list[dict] = []
        per_target = 12
        for target, rows in by_target.items():
            if not target:
                continue
            out.extend(
                compress_call_chains(rows, min_hops=2, max_chains=per_target)
            )
        logger.info(
            "Call chains to %d confirmed methods: %d raw → %d acyclic → %d compressed",
            len(qns),
            len(raw),
            len(cleaned),
            len(out),
        )
        return out
