"""Query field / object-graph paths (MAY_REF) for gadget reporting."""

from __future__ import annotations

import logging
from typing import Any, Iterable

logger = logging.getLogger(__name__)

# High-value gadget types to prefer in object-graph paths
_ENTRY_HINTS = (
    "AnnotationInvocationHandler",
    "TiedMapEntry",
    "LazyMap",
    "HashMap",
)
_SINK_OWNER_HINTS = (
    "InvokerTransformer",
    "InstantiateTransformer",
    "ChainedTransformer",
    "ConstantTransformer",
)


def _score_field_path(types: list[str], fields: list[str]) -> int:
    body = " ".join(types)
    score = 0
    if "AnnotationInvocationHandler" in body:
        score += 80
    if "LazyMap" in body:
        score += 50
    if "ChainedTransformer" in body:
        score += 40
    if "InvokerTransformer" in body:
        score += 40
    if "TiedMapEntry" in body:
        score += 30
    if any(f in {"memberValues", "factory", "iTransformers", "iTransformer"} for f in fields):
        score += 35
    # prefer serializable-write-heavy short paths — length penalty
    score -= max(0, len(types) - 2) * 3
    return score


def query_field_paths(
    store: Any,
    project: str,
    *,
    entry_type_qns: Iterable[str] | None = None,
    sink_type_qns: Iterable[str] | None = None,
    max_depth: int = 4,
    limit: int = 80,
    serializable_only: bool = True,
) -> list[dict[str, Any]]:
    """
    Find Type -MAY_REF*-> Type paths.

    Default: prefer paths that touch classic gadget types; optionally restrict
    to serializable_write edges (fields attacker can set via deserialization).
    """
    assert store._driver
    depth = max(1, min(int(max_depth), 6))
    entries = sorted({q for q in (entry_type_qns or []) if q})
    sinks = sorted({q for q in (sink_type_qns or []) if q})

    # Where clause fragments
    ser = "AND ALL(r IN relationships(path) WHERE r.serializable_write = true)" if serializable_only else ""

    rows: list[dict] = []
    with store._driver.session(database=store.database) as session:
        if entries and sinks:
            cypher = f"""
            UNWIND $entries AS eq
            UNWIND $sinks AS sq
            MATCH (entry:Type {{project: $project, qualified_name: eq}})
            MATCH (sink:Type {{project: $project, qualified_name: sq}})
            MATCH path = (entry)-[:MAY_REF|CHA_REF*1..{depth}]->(sink)
            WHERE entry <> sink
            {ser}
            WITH entry, sink, path,
                 [n IN nodes(path) | n.qualified_name] AS type_chain,
                 [r IN relationships(path) | r.field] AS field_chain,
                 [r IN relationships(path) | r.field_key] AS field_keys,
                 [r IN relationships(path) | r.serializable_write] AS ser_flags
            RETURN DISTINCT type_chain, field_chain, field_keys, ser_flags,
                   entry.qualified_name AS entry_type,
                   sink.qualified_name AS sink_type,
                   size(type_chain) AS hops
            ORDER BY hops ASC
            LIMIT $limit
            """
            try:
                rows = session.run(
                    cypher,
                    project=project,
                    entries=entries,
                    sinks=sinks,
                    limit=limit,
                ).data()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Field-path query (seeded) failed: %s", exc)
        else:
            # Heuristic: any path whose nodes mention classic names
            cypher = f"""
            MATCH (entry:Type {{project: $project}})
            WHERE any(h IN $entry_hints WHERE entry.qualified_name CONTAINS h)
               OR entry.is_serializable = true
            MATCH path = (entry)-[:MAY_REF|CHA_REF*1..{depth}]->(sink:Type {{project: $project}})
            WHERE entry <> sink
              AND (
                any(h IN $sink_hints WHERE sink.qualified_name CONTAINS h)
                OR sink.is_serializable = true
              )
            {ser}
            WITH entry, sink, path,
                 [n IN nodes(path) | n.qualified_name] AS type_chain,
                 [r IN relationships(path) | r.field] AS field_chain,
                 [r IN relationships(path) | r.field_key] AS field_keys,
                 [r IN relationships(path) | r.serializable_write] AS ser_flags
            WHERE any(h IN $entry_hints WHERE any(t IN type_chain WHERE t CONTAINS h))
              AND any(h IN $sink_hints WHERE any(t IN type_chain WHERE t CONTAINS h))
            RETURN DISTINCT type_chain, field_chain, field_keys, ser_flags,
                   entry.qualified_name AS entry_type,
                   sink.qualified_name AS sink_type,
                   size(type_chain) AS hops
            ORDER BY hops ASC
            LIMIT $limit
            """
            try:
                rows = session.run(
                    cypher,
                    project=project,
                    entry_hints=list(_ENTRY_HINTS),
                    sink_hints=list(_SINK_OWNER_HINTS),
                    limit=limit,
                ).data()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Field-path query (heuristic) failed: %s", exc)

    out: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    for row in rows:
        types = list(row.get("type_chain") or [])
        fields = list(row.get("field_chain") or [])
        key = (tuple(types), tuple(fields))
        if key in seen or len(types) < 2:
            continue
        seen.add(key)
        label_parts = []
        for i, tqn in enumerate(types):
            simple = tqn.rsplit(".", 1)[-1]
            label_parts.append(simple)
            if i < len(fields):
                label_parts.append(f".{fields[i]}→")
        out.append(
            {
                "entry_type": row.get("entry_type") or types[0],
                "sink_type": row.get("sink_type") or types[-1],
                "type_chain": types,
                "field_chain": fields,
                "field_keys": list(row.get("field_keys") or []),
                "serializable_write": list(row.get("ser_flags") or []),
                "path_label": "".join(label_parts),
                "hops": len(types),
                "score": _score_field_path(types, fields),
            }
        )

    out.sort(key=lambda c: (-c["score"], c["hops"]))
    logger.info("Object-graph field paths: %d", len(out))
    return out[:limit]


def seed_types_from_methods(method_qns: Iterable[str]) -> list[str]:
    """Method QN → owning type QN."""
    out: list[str] = []
    for mq in method_qns:
        if "#" in mq:
            out.append(mq.split("#", 1)[0])
    return list(dict.fromkeys(out))
