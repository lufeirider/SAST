"""Analysis-time CHA helpers.

Import stores only precise edges (CALLS → resolved target, MAY_REF → declared type).
Call-chain CHA defaults to on-demand expansion in analyze/dynamic_cha_chains.py
(no CHA_CALLS in Neo4j). This module still materializes scoped CHA_REF for
object-graph field paths, and can optionally materialize CHA_CALLS (legacy).
"""

from __future__ import annotations

import logging
from typing import Any, Iterable

from parse.config import (
    CHA_MAX_CALLEES,
    CHA_UNIVERSAL_VIRTUAL_METHODS,
    is_cha_no_expand,
)

logger = logging.getLogger(__name__)

# Method names commonly on gadget / deserialization call surfaces (not class names).
_CALLER_NAME_ALLOW = (
    "readObject",
    "readExternal",
    "invoke",
    "hash",
    "hashCode",
    "equals",
    "compare",
    "get",
    "getValue",
    "toString",
    "setValue",
    "checkSetValue",
    "transform",
    "heapify",
    "siftDown",
    "siftDownUsingComparator",
    "reconstitutionPut",
    "newTransformer",
    "defineTransletClasses",
)


def _prefer_score(qn: str) -> int:
    """No class-name prefer list — length only for stable ordering."""
    return -len(qn or "")


def _chunk(xs: list[str], n: int) -> list[list[str]]:
    return [xs[i : i + n] for i in range(0, len(xs), n)]


def materialize_cha_for_analysis(
    store: Any,
    project: str,
    *,
    focus_type_qns: Iterable[str] | None = None,
    focus_method_qns: Iterable[str] | None = None,
    max_per_site: int = CHA_MAX_CALLEES,
    expand_calls: bool = False,
) -> dict[str, int]:
    """
    Create analysis-only edges (cleared/rebuilt each run):

      (Method)-[:CHA_CALLS]->(Method)   # optional; prefer dynamic CHA in chain BFS
      (Type)-[:CHA_REF]->(Type)

    By default expand_calls=False: call-chain CHA is done on demand in
    analyze/dynamic_cha_chains.py so Neo4j does not store CHA_CALLS.
    """
    assert store._driver
    focus = sorted({q for q in (focus_type_qns or []) if q})
    focus_set = set(focus)
    focus_methods = sorted({q for q in (focus_method_qns or []) if q})
    virtuals = sorted(CHA_UNIVERSAL_VIRTUAL_METHODS)
    cha_call_rows: list[dict] = []
    cha_ref_rows: list[dict] = []
    callers: list[str] = []

    with store._driver.session(database=store.database) as session:
        session.run(
            """
            MATCH (a:Method {project:$p})-[r:CHA_CALLS]->(:Method {project:$p})
            DELETE r
            """,
            p=project,
        )
        session.run(
            """
            MATCH (a:Type {project:$p})-[r:CHA_REF]->(:Type {project:$p})
            DELETE r
            """,
            p=project,
        )

        if expand_calls:
            # Legacy path: materialize scoped CHA_CALLS (can OOM on full JDK).
            caller_rows = session.run(
                """
                MATCH (caller:Method {project:$p})-[:CALLS]->(:Method {project:$p})
                WHERE caller.qualified_name IN $focus_methods
                   OR caller.name IN $names
                RETURN DISTINCT caller.qualified_name AS qn
                """,
                p=project,
                focus_methods=focus_methods,
                names=list(_CALLER_NAME_ALLOW),
            ).data()
            callers = [r["qn"] for r in caller_rows if r.get("qn")]
            logger.info(
                "CHA scoped callers: %d (focus_methods=%d)",
                len(callers),
                len(focus_methods),
            )

            by_site: dict[tuple[str, str], list[dict]] = {}
            for batch in _chunk(callers, 200):
                rows = session.run(
                    """
                    MATCH (caller:Method {project:$p})-[:CALLS]->(callee:Method {project:$p})
                    WHERE caller.qualified_name IN $callers
                    WITH caller, callee,
                         split(callee.qualified_name, '#')[0] AS owner,
                         callee.name AS mname
                    WHERE NOT owner IN ['java.lang.Object', 'Object']
                    MATCH (sub:Type {project:$p})-[:EXTENDS|IMPLEMENTS*0..6]->(ownerType:Type {project:$p})
                    WHERE ownerType.qualified_name = owner OR ownerType.name = owner
                    MATCH (sub)-[:HAS_METHOD]->(override:Method {project:$p})
                    WHERE override.name = mname
                      AND override.qualified_name <> callee.qualified_name
                    RETURN DISTINCT
                      caller.qualified_name AS caller_qn,
                      callee.qualified_name AS callee_qn,
                      override.qualified_name AS override_qn,
                      sub.qualified_name AS sub_qn,
                      owner AS owner,
                      mname AS mname,
                      coalesce(sub.is_serializable, false) AS ser
                    LIMIT 50000
                    """,
                    p=project,
                    callers=batch,
                ).data()
                for row in rows:
                    owner = (row["override_qn"] or "").split("#", 1)[0]
                    if is_cha_no_expand(owner):
                        continue
                    by_site.setdefault((row["caller_qn"], row["callee_qn"]), []).append(row)

            for batch in _chunk(callers, 200):
                obj_rows = session.run(
                    """
                    MATCH (caller:Method {project:$p})-[:CALLS]->(callee:Method {project:$p})
                    WHERE caller.qualified_name IN $callers
                      AND callee.qualified_name STARTS WITH 'java.lang.Object#'
                      AND callee.name IN $virtuals
                    MATCH (sub:Type {project:$p})-[:HAS_METHOD]->(override:Method {project:$p})
                    WHERE override.name = callee.name
                      AND override.qualified_name <> callee.qualified_name
                      AND (
                        sub.qualified_name IN $focus
                        OR coalesce(sub.is_serializable, false)
                      )
                    RETURN DISTINCT
                      caller.qualified_name AS caller_qn,
                      callee.qualified_name AS callee_qn,
                      override.qualified_name AS override_qn,
                      sub.qualified_name AS sub_qn,
                      'java.lang.Object' AS owner,
                      callee.name AS mname,
                      coalesce(sub.is_serializable, false) AS ser
                    LIMIT 20000
                    """,
                    p=project,
                    callers=batch,
                    virtuals=virtuals,
                    focus=focus,
                ).data()
                for row in obj_rows:
                    oqn = row["override_qn"] or ""
                    if not (
                        row["sub_qn"] in focus_set or row.get("ser")
                    ):
                        continue
                    by_site.setdefault((row["caller_qn"], row["callee_qn"]), []).append(row)

            for (caller_qn, callee_qn), cands in by_site.items():
                ranked = sorted(
                    cands,
                    key=lambda r: (
                        0 if r["sub_qn"] in focus_set else 1,
                        0 if r["ser"] else 1,
                        -_prefer_score(r["override_qn"]),
                        r["override_qn"],
                    ),
                )
                seen: set[str] = set()
                for r in ranked:
                    oqn = r["override_qn"]
                    if oqn in seen or oqn == caller_qn:
                        continue
                    seen.add(oqn)
                    cha_call_rows.append(
                        {
                            "caller_qn": caller_qn,
                            "override_qn": oqn,
                            "project": project,
                        }
                    )
                    if len(seen) >= max_per_site:
                        break

            if cha_call_rows:
                for batch_rows in _chunk(
                    [f"{r['caller_qn']}\t{r['override_qn']}" for r in cha_call_rows], 2000
                ):
                    rows = [
                        {
                            "caller_qn": x.split("\t", 1)[0],
                            "override_qn": x.split("\t", 1)[1],
                            "project": project,
                        }
                        for x in batch_rows
                    ]
                    session.run(
                        """
                        UNWIND $rows AS row
                        MATCH (a:Method {project: row.project, qualified_name: row.caller_qn})
                        MATCH (b:Method {project: row.project, qualified_name: row.override_qn})
                        MERGE (a)-[:CHA_CALLS]->(b)
                        """,
                        rows=rows,
                    )
        else:
            logger.info(
                "Skipping CHA_CALLS materialization (dynamic CHA during chain BFS)"
            )

        # Field CHA_REF — only focus owner types
        focus_types = focus or []
        if focus_types:
            frows = session.run(
                """
                MATCH (owner:Type {project:$p})-[:HAS_FIELD]->(f:Field {project:$p})
                      -[:DECLARED_TYPE]->(decl:Type {project:$p})
                WHERE owner.qualified_name IN $focus
                  AND NOT decl.name IN ['Object', 'Serializable', 'Externalizable',
                                        'Cloneable', 'Comparable', 'CharSequence', 'Iterable']
                MATCH (sub:Type {project:$p})-[:EXTENDS|IMPLEMENTS*0..6]->(decl)
                RETURN DISTINCT
                  owner.qualified_name AS owner_qn,
                  sub.qualified_name AS sub_qn,
                  f.name AS field,
                  f.key AS field_key,
                  f.type_name AS field_type,
                  coalesce(f.serializable_write, false) AS ser_write,
                  coalesce(sub.is_serializable, false) AS sub_ser
                LIMIT 100000
                """,
                p=project,
                focus=focus_types,
            ).data()
            by_field: dict[str, list[dict]] = {}
            for row in frows:
                if is_cha_no_expand(row["sub_qn"]):
                    continue
                by_field.setdefault(row["field_key"], []).append(row)
            for _fkey, cands in by_field.items():
                ranked = sorted(
                    cands,
                    key=lambda r: (
                        0 if r["sub_qn"] in focus_set else 1,
                        0 if r["sub_ser"] or r["ser_write"] else 1,
                        -_prefer_score(r["sub_qn"]),
                        r["sub_qn"],
                    ),
                )
                seen = set()
                for r in ranked:
                    if r["sub_qn"] in seen:
                        continue
                    seen.add(r["sub_qn"])
                    cha_ref_rows.append(
                        {
                            "owner_qn": r["owner_qn"],
                            "sub_qn": r["sub_qn"],
                            "field": r["field"],
                            "field_key": r["field_key"],
                            "field_type": r["field_type"],
                            "serializable_write": r["ser_write"],
                            "project": project,
                        }
                    )
                    if len(seen) >= max_per_site:
                        break
            if cha_ref_rows:
                for i in range(0, len(cha_ref_rows), 2000):
                    session.run(
                        """
                        UNWIND $rows AS row
                        MATCH (owner:Type {project: row.project, qualified_name: row.owner_qn})
                        MATCH (sub:Type {project: row.project, qualified_name: row.sub_qn})
                        MERGE (owner)-[r:CHA_REF {field_key: row.field_key}]->(sub)
                        SET r.field = row.field,
                            r.field_type = row.field_type,
                            r.serializable_write = row.serializable_write,
                            r.project = row.project
                        """,
                        rows=cha_ref_rows[i : i + 2000],
                    )

    stats = {
        "cha_calls": len(cha_call_rows),
        "cha_refs": len(cha_ref_rows),
        "focus_types": len(focus),
        "scoped_callers": len(callers),
    }
    logger.info(
        "Analysis CHA: CHA_CALLS=%d CHA_REF=%d focus_types=%d callers=%d expand_calls=%s",
        stats["cha_calls"],
        stats["cha_refs"],
        stats["focus_types"],
        stats["scoped_callers"],
        expand_calls,
    )
    return stats
