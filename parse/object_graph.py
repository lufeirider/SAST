"""Field / object-graph helpers: declared types → CHA POINTS_TO targets."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable

from parse.config import is_cha_no_expand
from parse.models import FieldInfo, ParseResult, TypeInfo

# Skip exploding these as field targets (too broad / not useful for gadgets)
_SKIP_SIMPLE = {
    "Object",
    "String",
    "Class",
    "Boolean",
    "Byte",
    "Character",
    "Short",
    "Integer",
    "Long",
    "Float",
    "Double",
    "Number",
    "Void",
    "Enum",
    "Throwable",
    "Exception",
    "RuntimeException",
    "Cloneable",
    "Comparable",
    "CharSequence",
    "Serializable",  # marker only
    "Externalizable",
}

_PRIMITIVES = {
    "void",
    "boolean",
    "byte",
    "char",
    "short",
    "int",
    "long",
    "float",
    "double",
}

_RE_ARRAY = re.compile(r"^(.+?)(\[\])+$")
_RE_GENERIC = re.compile(r"^([^<]+)<.*>$")


def erase_type_name(type_name: str) -> tuple[str, bool]:
    """
    Return (erased type name, is_array).
    Map<String,Object>[] → (Map, True); Transformer[] → (Transformer, True)
    """
    raw = (type_name or "").strip()
    if not raw:
        return "", False
    is_array = False
    m = _RE_ARRAY.match(raw)
    if m:
        raw = m.group(1).strip()
        is_array = True
    g = _RE_GENERIC.match(raw)
    if g:
        raw = g.group(1).strip()
    # varargs style Type...
    if raw.endswith("..."):
        raw = raw[:-3].strip()
        is_array = True
    return raw, is_array


def should_skip_target(type_name: str) -> bool:
    erased, _ = erase_type_name(type_name)
    if not erased:
        return True
    simple = erased.rsplit(".", 1)[-1]
    if erased in _PRIMITIVES or simple in _PRIMITIVES:
        return True
    # Object / Serializable / … → "any type", no POINTS_TO / MAY_REF fan-out
    if is_cha_no_expand(erased):
        return True
    if simple in _SKIP_SIMPLE:
        return True
    if erased.startswith("java.lang.") and simple in _SKIP_SIMPLE:
        return True
    return False


def field_type_hint(fld: FieldInfo) -> str:
    """Prefer SymbolSolver FQCN, fall back to source type_name."""
    return (fld.resolved_type or fld.type_name or "").strip()


def type_is_serializable(t: TypeInfo, serializable_qns: set[str]) -> bool:
    if t.qualified_name in serializable_qns:
        return True
    for p in t.implements + t.extends:
        simple = p.rsplit(".", 1)[-1]
        if p in serializable_qns or simple == "Serializable" or p.endswith(".Serializable"):
            return True
        if simple == "Externalizable" or p.endswith(".Externalizable"):
            return True
    # gadget entry markers
    for m in t.methods:
        if m.name in {"readObject", "readExternal", "readResolve"}:
            return True
    return False


def build_serializable_set(types: Iterable[TypeInfo]) -> set[str]:
    """Closure: types that implement Serializable/Externalizable (by name or known parents)."""
    by_qn = {t.qualified_name: t for t in types}
    simple_to: dict[str, list[str]] = defaultdict(list)
    for t in types:
        simple_to[t.name].append(t.qualified_name)

    seeds = {"java.io.Serializable", "java.io.Externalizable", "Serializable", "Externalizable"}
    known = set(seeds)
    # fixed-point over implements/extends
    changed = True
    while changed:
        changed = False
        for t in types:
            if t.qualified_name in known:
                continue
            for p in t.implements + t.extends:
                pq = p if p in by_qn else None
                if p in known or p.rsplit(".", 1)[-1] in {"Serializable", "Externalizable"}:
                    known.add(t.qualified_name)
                    changed = True
                    break
                if pq and pq in known:
                    known.add(t.qualified_name)
                    changed = True
                    break
                # parent may be simple name resolved in project
                for cand in simple_to.get(p.rsplit(".", 1)[-1], []):
                    if cand in known:
                        known.add(t.qualified_name)
                        changed = True
                        break
    return known


def collect_subtypes(
    types: Iterable[TypeInfo],
) -> tuple[dict[str, list[str]], dict[str, list[str]], dict[str, TypeInfo]]:
    """parent_qn/simple → child qns; simple→qns; qn→TypeInfo."""
    types_by_qn: dict[str, TypeInfo] = {}
    simple_to: dict[str, list[str]] = defaultdict(list)
    subtypes: dict[str, list[str]] = defaultdict(list)

    for t in types:
        types_by_qn[t.qualified_name] = t
        simple_to[t.name].append(t.qualified_name)
        if "." in t.qualified_name:
            simple_to[t.qualified_name].append(t.qualified_name)

    def lookup(name: str) -> list[str]:
        if not name:
            return []
        if name in simple_to:
            return list(dict.fromkeys(simple_to[name]))
        simple = name.rsplit(".", 1)[-1]
        return list(dict.fromkeys(simple_to.get(simple, [])))

    for t in types_by_qn.values():
        for parent in t.extends + t.implements:
            for pq in lookup(parent):
                subtypes[pq].append(t.qualified_name)
            subtypes[parent.rsplit(".", 1)[-1]].append(t.qualified_name)

    # unique
    for k, v in list(subtypes.items()):
        subtypes[k] = list(dict.fromkeys(v))
    return subtypes, simple_to, types_by_qn


def cha_targets_for_field(
    type_hint: str,
    *,
    subtypes: dict[str, list[str]],
    simple_to: dict[str, list[str]],
    types_by_qn: dict[str, TypeInfo],
    max_targets: int = 32,
) -> tuple[list[str], str, bool]:
    """
    Import-time targets: declared type only (no CHA subtype fan-out).

    Subtype expansion is done at analyze time as :CHA_REF
    (see analyze/cha_expand.py). `subtypes` / `max_targets` kept for API compat.
    """
    del subtypes, max_targets  # unused at import
    erased, is_array = erase_type_name(type_hint)
    if should_skip_target(erased):
        return [], "", is_array

    declared_qns: list[str] = []
    if erased in types_by_qn:
        declared_qns = [erased]
    else:
        declared_qns = list(
            dict.fromkeys(
                simple_to.get(erased, [])
                or simple_to.get(erased.rsplit(".", 1)[-1], [])
            )
        )

    declared = declared_qns[0] if declared_qns else ""
    # MAY_REF / POINTS_TO at import: declared type only
    targets = list(declared_qns[:1]) if declared else []
    return targets, declared, is_array


def iter_field_point_rows(
    result: ParseResult, *, max_targets_per_field: int = 48
) -> tuple[list[dict], list[dict], dict]:
    """
    Build Neo4j row payloads:
      points_rows: Field -POINTS_TO-> Type (+ DECLARED_TYPE)
      alias_rows:  Type -MAY_REF-> Type (via field)
    Also returns stats dict.
    """
    types = [t for f in result.files for t in f.types]
    subtypes, simple_to, types_by_qn = collect_subtypes(types)
    serializable = build_serializable_set(types)

    points_rows: list[dict] = []
    alias_rows: list[dict] = []
    fields_total = 0
    fields_with_points = 0

    for t in types:
        owner_ser = type_is_serializable(t, serializable)
        for fld in t.fields:
            fields_total += 1
            hint = field_type_hint(fld)
            targets, declared, is_array = cha_targets_for_field(
                hint,
                subtypes=subtypes,
                simple_to=simple_to,
                types_by_qn=types_by_qn,
                max_targets=max_targets_per_field,
            )
            key = f"{t.qualified_name}#{fld.name}"
            ser_write = (
                (not fld.is_static)
                and (not fld.is_transient)
                and owner_ser
                and t.kind in {"class", "enum"}
            )
            if declared:
                points_rows.append(
                    {
                        "field_key": key,
                        "target_qn": declared,
                        "kind": "declared",
                        "project": result.project,
                    }
                )
            for tgt in targets:
                points_rows.append(
                    {
                        "field_key": key,
                        "target_qn": tgt,
                        "kind": "points",
                        "project": result.project,
                    }
                )
                alias_rows.append(
                    {
                        "owner_qn": t.qualified_name,
                        "target_qn": tgt,
                        "field": fld.name,
                        "field_key": key,
                        "field_type": hint,
                        "is_array": is_array,
                        "serializable_write": ser_write,
                        "project": result.project,
                    }
                )
            if targets:
                fields_with_points += 1

    stats = {
        "fields_total": fields_total,
        "fields_with_points": fields_with_points,
        "points_edges": sum(1 for r in points_rows if r["kind"] == "points"),
        "declared_edges": sum(1 for r in points_rows if r["kind"] == "declared"),
        "may_ref_edges": len(alias_rows),
        "serializable_types": len(serializable),
    }
    return points_rows, alias_rows, stats
