"""
Simple intra-procedural taint analysis.

Modes (see analyze.config.TAINT_MODE):
  - vuln:   找漏洞 — source = 方法参数；不把类字段默认当污点
  - gadget: 找 gadget — source = 类字段 + 方法参数

Propagation: assignment only — if any tainted ident appears on the RHS
  (e.g. x1 = xxx + x2), the LHS becomes tainted.

Docs: docs/taint.md
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Literal

from parse.models import CallSite, MethodInfo, TypeInfo
from rules.sinks import (
    SinkMatch,
    is_gadget_entry_method,
    match_sink_call,
    sink_function_names,
)

TaintMode = Literal["vuln", "gadget"]

# backward-compatible alias (simple names from Tabby rules)
SINK_CALLEES = sink_function_names()


@dataclass
class TaintFinding:
    method_qn: str
    method_name: str
    type_qn: str
    sink_name: str
    sink_line: int
    sink_arg: str
    tainted_vars: list[str]
    source_kind: str  # param | field | mixed
    evidence: list[str] = field(default_factory=list)
    mode: str = "vuln"
    vul: str = ""  # Tabby vul category: EXEC / REFLECTION / ...
    sink_owner: str = ""


_IDENT = re.compile(r"\b([A-Za-z_][\w]*)\b")


def _idents(expr: str) -> set[str]:
    """Identifiers in expr, ignoring this. / common keywords."""
    skip = {
        "this",
        "super",
        "null",
        "true",
        "false",
        "new",
        "return",
        "if",
        "else",
        "for",
        "while",
        "class",
        "String",
        "int",
        "long",
        "boolean",
        "void",
        "public",
        "private",
        "protected",
        "static",
    }
    found: set[str] = set()
    for m in _IDENT.finditer(expr):
        name = m.group(1)
        if name not in skip:
            found.add(name)
    for m in re.finditer(r"this\.([A-Za-z_][\w]*)", expr):
        found.add(m.group(1))
    return found


def method_calls_sink(method: MethodInfo) -> bool:
    """True if the method body invokes a Tabby sink."""
    return any(
        match_sink_call(
            callee_name=cs.callee_name,
            resolved_qn=cs.resolved_qn,
            is_constructor=cs.is_constructor,
        )
        for cs in method.call_sites
    )


def is_sink_taint_candidate(method: MethodInfo, mode: TaintMode) -> bool:
    """Phase-1: methods that call sinks (+ gadget deserialization entry)."""
    if method_calls_sink(method):
        return True
    if mode == "gadget" and is_gadget_entry_method(method.name):
        return True
    return False


def sink_candidate_qns(types: list[TypeInfo], mode: TaintMode) -> set[str]:
    return {
        m.qualified_name
        for t in types
        for m in t.methods
        if is_sink_taint_candidate(m, mode)
    }


def method_qns_from_call_chains(call_chains: Iterable[dict]) -> set[str]:
    """Collect all Method qualified_names appearing on call chains."""
    qns: set[str] = set()
    for row in call_chains:
        sink_m = row.get("sink_method")
        if sink_m:
            qns.add(str(sink_m))
        for qn in row.get("call_chain") or []:
            if qn:
                qns.add(str(qn))
    return qns


def _seed_sources(
    type_info: TypeInfo, method: MethodInfo, mode: TaintMode
) -> tuple[set[str], dict[str, str]]:
    """Return (tainted_names, source_kind_by_name) for the analysis mode."""
    param_names = {p.name for p in method.parameters}
    tainted: set[str] = set()
    source_of: dict[str, str] = {}

    if mode == "vuln":
        for p in param_names:
            tainted.add(p)
            source_of[p] = "param"
    else:
        # gadget: class fields + method parameters are both sources
        for f in type_info.fields:
            tainted.add(f.name)
            source_of[f.name] = "field"
        for p in param_names:
            tainted.add(p)
            source_of[p] = "param"

    return tainted, source_of


def _polluted_hits(
    cs: CallSite,
    match: SinkMatch,
    tainted: set[str],
    *,
    mode: TaintMode,
) -> list[str]:
    """Return argument/receiver expressions that are tainted per Tabby polluted indexes."""
    hits: list[str] = []
    groups = match.rule.polluted
    if not groups:
        for arg in cs.arguments:
            if _idents(arg) & tainted:
                hits.append(arg)
        if not hits and match.rule.vul in {"SERIALIZE", "REFLECTION"}:
            recv = cs.receiver or ""
            if _idents(recv) & tainted or (
                mode == "gadget" and match.rule.function in {"readObject", "invoke"}
            ):
                hits.append(recv or "<this>")
        return hits

    for group in groups:
        for idx in group:
            if idx < 0:
                recv = cs.receiver or ""
                if _idents(recv) & tainted:
                    label = recv or "<this>"
                    if label not in hits:
                        hits.append(label)
            elif idx < len(cs.arguments):
                arg = cs.arguments[idx]
                if _idents(arg) & tainted and arg not in hits:
                    hits.append(arg)

    # gadget: field names often appear in args beyond Tabby's polluted index
    # (e.g. Method.invoke(input, iArgs) with field-sourced Method name)
    if not hits and mode == "gadget":
        blob_parts = [cs.receiver or "", *cs.arguments]
        blob = " ".join(blob_parts)
        if _idents(blob) & tainted:
            hits.append(next((p for p in blob_parts if _idents(p) & tainted), blob[:120]))
    return hits


def propagate_taint(
    type_info: TypeInfo,
    method: MethodInfo,
    *,
    mode: TaintMode = "vuln",
) -> tuple[set[str], dict[str, str], list[str]]:
    """Assignment-only intra-proc taint. Returns (tainted, source_of, evidence)."""
    tainted, source_of = _seed_sources(type_info, method, mode)
    evidence: list[str] = []

    changed = True
    rounds = 0
    while changed and rounds < 32:
        changed = False
        rounds += 1
        for a in method.assignments:
            rhs_ids = _idents(a.rhs)
            if not rhs_ids & tainted:
                continue
            lhs = a.lhs
            if lhs.startswith("this."):
                lhs = lhs[5:]
            if lhs not in tainted:
                tainted.add(lhs)
                kinds = {source_of[i] for i in rhs_ids if i in source_of}
                source_of[lhs] = (
                    "mixed"
                    if len(kinds) > 1
                    else (next(iter(kinds)) if kinds else "param")
                )
                evidence.append(f"L{a.line}: {a.lhs} = {a.rhs}")
                changed = True
    return tainted, source_of, evidence


def analyze_method(
    type_info: TypeInfo,
    method: MethodInfo,
    *,
    mode: TaintMode = "vuln",
) -> list[TaintFinding]:
    """Run simple assignment-based taint on one method; report sink hits."""
    field_names = {f.name for f in type_info.fields}
    param_names = {p.name for p in method.parameters}

    tainted, source_of, evidence = propagate_taint(type_info, method, mode=mode)

    findings: list[TaintFinding] = []

    for cs in method.call_sites:
        matched = match_sink_call(
            callee_name=cs.callee_name,
            resolved_qn=cs.resolved_qn,
            is_constructor=cs.is_constructor,
        )
        if not matched:
            continue

        hit_args = _polluted_hits(cs, matched, tainted, mode=mode)

        # SERIALIZE readObject: gadget mode keeps prior loose behavior
        if (
            not hit_args
            and matched.rule.function == "readObject"
            and mode == "gadget"
        ):
            hit_args = [cs.receiver or "<input-stream>"]

        if not hit_args:
            continue

        kinds = {source_of.get(i, "param") for arg in hit_args for i in _idents(arg)}
        if mode == "gadget" and matched.rule.vul in {"SERIALIZE", "REFLECTION"}:
            kinds.add("field")
        kind = "mixed" if len(kinds) > 1 else (next(iter(kinds)) if kinds else "field")

        findings.append(
            TaintFinding(
                method_qn=method.qualified_name,
                method_name=method.name,
                type_qn=type_info.qualified_name,
                sink_name=cs.callee_name or matched.rule.function or "<ctor>",
                sink_line=cs.line,
                sink_arg="; ".join(hit_args),
                tainted_vars=sorted(tainted),
                source_kind=kind,
                evidence=evidence[-8:],
                mode=mode,
                vul=matched.rule.vul,
                sink_owner=matched.rule.owner,
            )
        )

    if mode == "gadget" and is_gadget_entry_method(method.name):
        findings.append(
            TaintFinding(
                method_qn=method.qualified_name,
                method_name=method.name,
                type_qn=type_info.qualified_name,
                sink_name=method.name,
                sink_line=method.start_line,
                sink_arg="<method-entry; fields attacker-controlled>",
                tainted_vars=sorted(set(field_names) | set(param_names)),
                source_kind="field" if field_names else "param",
                evidence=[f"{method.name} entry in {type_info.qualified_name}"]
                + evidence[-6:],
                mode=mode,
                vul="SERIALIZE",
                sink_owner=type_info.qualified_name,
            )
        )

    return findings


def _dedupe_findings(findings: list[TaintFinding]) -> list[TaintFinding]:
    seen: set[tuple] = set()
    out: list[TaintFinding] = []
    for f in findings:
        key = (f.method_qn, f.sink_name, f.sink_line, f.sink_arg, f.mode, f.vul)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def analyze_types(
    types: list[TypeInfo],
    *,
    mode: TaintMode = "vuln",
    only_method_qns: set[str] | None = None,
) -> list[TaintFinding]:
    """
    Run taint on selected methods.

    If only_method_qns is None: phase-1 default (sink callers / gadget entry).
    If provided: only those qualified names (phase-1 ∪ call-chain methods).
    """
    if only_method_qns is None:
        only_method_qns = sink_candidate_qns(types, mode)

    out: list[TaintFinding] = []
    for t in types:
        for m in t.methods:
            if m.qualified_name not in only_method_qns:
                continue
            out.extend(analyze_method(t, m, mode=mode))
    return _dedupe_findings(out)


def methods_using_sinks(types: list[TypeInfo]) -> list[dict]:
    """List methods that call Tabby sinks or are deserialization entries."""
    rows = []
    for t in types:
        for m in t.methods:
            sinks = []
            for cs in m.call_sites:
                matched = match_sink_call(
                    callee_name=cs.callee_name,
                    resolved_qn=cs.resolved_qn,
                    is_constructor=cs.is_constructor,
                )
                if not matched:
                    continue
                sinks.append(
                    {
                        "name": cs.callee_name,
                        "owner": matched.rule.owner,
                        "vul": matched.rule.vul,
                        "line": cs.line,
                        "args": cs.arguments,
                        "receiver": cs.receiver,
                        "resolved_qn": cs.resolved_qn,
                    }
                )
            if is_gadget_entry_method(m.name):
                sinks.append(
                    {
                        "name": m.name,
                        "owner": t.qualified_name,
                        "vul": "SERIALIZE",
                        "line": m.start_line,
                        "args": ["<method-entry>"],
                        "receiver": "",
                        "resolved_qn": "",
                    }
                )
            if not sinks:
                continue
            rows.append(
                {
                    "type": t.qualified_name,
                    "method": m.qualified_name,
                    "sinks": sinks,
                }
            )
    return rows
