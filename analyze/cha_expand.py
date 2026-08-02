"""Analysis-time CHA expansion.

Import stores only precise edges (CALLS → resolved target, MAY_REF → declared type).
Inheritance EXTENDS/IMPLEMENTS is always in the graph. When analyzing vulns/gadgets,
materialize scoped CHA fan-out as CHA_CALLS / CHA_REF so chain queries can use them.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable

from parse.config import CHA_MAX_CALLEES, CHA_PREFER_SUBSTRINGS, is_cha_no_expand

logger = logging.getLogger(__name__)


def _prefer_score(qn: str) -> int:
    score = 0
    for i, hint in enumerate(CHA_PREFER_SUBSTRINGS):
        if hint in qn:
            score += 100 - i
    return score


def materialize_cha_for_analysis(
    store: Any,
    project: str,
    *,
    focus_type_qns: Iterable[str] | None = None,
    max_per_site: int = CHA_MAX_CALLEES,
) -> dict[str, int]:
    """
    Create analysis-only edges (cleared/rebuilt each run):

      (Method)-[:CHA_CALLS]->(Method)   virtual overrides of CALLS targets
      (Type)-[:CHA_REF {field,...}]->(Type)   field declared type → subtypes

    Scope: skip Object/Serializable; prefer focus types + gadget-ish names;
    cap fan-out per site with max_per_site.
    """
    assert store._driver
    focus = sorted({q for q in (focus_type_qns or []) if q})

    with store._driver.session(database=store.database) as session:
        # Drop previous analysis CHA edges for this project
        session.run(
            """
            MATCH (a:Method {project:$p})-[r:CHA_CALLS]->(b:Method {project:$p})
            DELETE r
            """,
            p=project,
        )
        session.run(
            """
            MATCH (a:Type {project:$p})-[r:CHA_REF]->(b:Type {project:$p})
            DELETE r
            """,
            p=project,
        )

        # --- CALLS → CHA_CALLS (subtype overrides of the resolved callee) ---
        # Pull candidate expansions into Python for ranking/cap (Neo4j alone
        # can't easily apply our prefer list + focus filter).
        rows = session.run(
            """
            MATCH (caller:Method {project:$p})-[:CALLS]->(callee:Method {project:$p})
            WITH caller, callee,
                 split(callee.qualified_name, '#')[0] AS owner,
                 callee.name AS mname
            WHERE NOT owner IN ['java.lang.Object', 'Object']
            MATCH (sub:Type {project:$p})-[:EXTENDS|IMPLEMENTS*0..8]->(ownerType:Type {project:$p})
            WHERE ownerType.qualified_name = owner
               OR ownerType.name = owner
            MATCH (sub)-[:HAS_METHOD]->(override:Method {project:$p})
            WHERE override.name = mname
              AND override.qualified_name <> callee.qualified_name
            RETURN DISTINCT
              caller.qualified_name AS caller_qn,
              callee.qualified_name AS callee_qn,
              override.qualified_name AS override_qn,
              sub.qualified_name AS sub_qn,
              coalesce(sub.is_serializable, false) AS ser
            """,
            p=project,
        ).data()

        # group by (caller, callee)
        by_site: dict[tuple[str, str], list[dict]] = {}
        for row in rows:
            owner = (row["override_qn"] or "").split("#", 1)[0]
            if is_cha_no_expand(owner):
                continue
            by_site.setdefault((row["caller_qn"], row["callee_qn"]), []).append(row)

        focus_set = set(focus)
        cha_call_rows: list[dict] = []
        for (caller_qn, _callee_qn), cands in by_site.items():
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
                if oqn in seen:
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
            session.run(
                """
                UNWIND $rows AS row
                MATCH (a:Method {project: row.project, qualified_name: row.caller_qn})
                MATCH (b:Method {project: row.project, qualified_name: row.override_qn})
                MERGE (a)-[:CHA_CALLS]->(b)
                """,
                rows=cha_call_rows,
            )

        # --- Field DECLARED_TYPE → CHA_REF to subtypes (declared itself via *0) ---
        frows = session.run(
            """
            MATCH (owner:Type {project:$p})-[:HAS_FIELD]->(f:Field {project:$p})
                  -[:DECLARED_TYPE]->(decl:Type {project:$p})
            WHERE NOT decl.name IN ['Object', 'Serializable', 'Externalizable',
                                    'Cloneable', 'Comparable', 'CharSequence', 'Iterable']
              AND NOT decl.qualified_name STARTS WITH 'java.lang.Object'
            MATCH (sub:Type {project:$p})-[:EXTENDS|IMPLEMENTS*0..8]->(decl)
            RETURN DISTINCT
              owner.qualified_name AS owner_qn,
              sub.qualified_name AS sub_qn,
              f.name AS field,
              f.key AS field_key,
              f.type_name AS field_type,
              coalesce(f.serializable_write, false) AS ser_write,
              coalesce(sub.is_serializable, false) AS sub_ser
            """,
            p=project,
        ).data()

        by_field: dict[str, list[dict]] = {}
        for row in frows:
            if is_cha_no_expand(row["sub_qn"]):
                continue
            by_field.setdefault(row["field_key"], []).append(row)

        cha_ref_rows: list[dict] = []
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
                # skip self-loop unless useful? keep declared→declared for MAY_REF parity
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
                rows=cha_ref_rows,
            )

    stats = {
        "cha_calls": len(cha_call_rows),
        "cha_refs": len(cha_ref_rows),
        "focus_types": len(focus),
    }
    logger.info(
        "Analysis CHA materialized: CHA_CALLS=%d CHA_REF=%d focus_types=%d",
        stats["cha_calls"],
        stats["cha_refs"],
        stats["focus_types"],
    )
    return stats
