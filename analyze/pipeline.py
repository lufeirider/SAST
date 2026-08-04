"""Analysis pipeline: sink → taint-confirm → call-chain stitch."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from analyze.cha_expand import materialize_cha_for_analysis
from analyze.chain_taint import filter_chains_by_taint
from analyze.config import TAINT_MODE
from analyze.neo4j_store import FindingStore
from analyze.object_graph import query_field_paths, seed_types_from_methods
from analyze.taint import (
    TaintMode,
    analyze_types,
    method_qns_from_call_chains,
    methods_using_sinks,
    sink_candidate_qns,
)
from parse.config import DEFAULT_INPUT
from parse.pipeline import ParsePipeline

logger = logging.getLogger(__name__)


def _attach_chains_to_findings(
    findings_payload: list[dict], call_chains: list[dict]
) -> None:
    """Annotate each finding with call chains that end at its method."""
    by_sink: dict[str, list[dict]] = {}
    for c in call_chains:
        sm = c.get("sink_method") or ""
        if not sm:
            continue
        by_sink.setdefault(sm, []).append(
            {
                "call_chain": c.get("call_chain") or [],
                "sink": c.get("sink") or "",
                "sink_vul": c.get("sink_vul") or "",
            }
        )
    for f in findings_payload:
        f["call_chains"] = by_sink.get(f["method"], [])


class AnalyzePipeline:
    def __init__(self, project: str = "default", mode: TaintMode | None = None):
        self.project = project
        self.mode: TaintMode = mode or TAINT_MODE  # type: ignore[assignment]

    def run(
        self,
        input_dir: Path | None = None,
        *,
        parse_first: bool = True,
        import_graph: bool = True,
        dump_json: Optional[Path] = None,
        mode: TaintMode | None = None,
        reuse_parse_ir: bool | Path = True,
    ) -> dict:
        """
        Core flow (user-requested):
          1) Parse (+ import CALLS graph)
          2) Find methods that call Tabby sinks
          3) Taint those methods → keep only exploitable findings
          4) For confirmed methods, stitch Neo4j CALLS call chains
          5) (optional) taint extra methods that appear on those chains
        """
        taint_mode: TaintMode = mode or self.mode
        parse_pipe = ParsePipeline(project=self.project)
        if parse_first:
            if import_graph:
                result = parse_pipe.parse_and_import(
                    input_dir or DEFAULT_INPUT,
                    reuse_parse_ir=reuse_parse_ir,
                )
            else:
                result = parse_pipe.parse(
                    input_dir or DEFAULT_INPUT,
                    reuse_parse_ir=reuse_parse_ir,
                )
        else:
            result = parse_pipe.parse(
                input_dir or DEFAULT_INPUT,
                reuse_parse_ir=reuse_parse_ir,
            )
        types = [t for f in result.files for t in f.types]
        known = {m.qualified_name for t in types for m in t.methods}

        # --- Step A: locate sink callers ---
        sink_users = methods_using_sinks(types)
        sink_caller_qns = sink_candidate_qns(types, taint_mode)
        logger.info(
            "Step A — sink callers: %d methods (sink_user rows=%d)",
            len(sink_caller_qns),
            len(sink_users),
        )

        # --- Step B: taint → confirmed exploitable methods ---
        findings = analyze_types(
            types, mode=taint_mode, only_method_qns=sink_caller_qns
        )
        confirmed_qns = {f.method_qn for f in findings}
        logger.info(
            "Step B — taint-confirmed exploitable methods: %d (findings=%d)",
            len(confirmed_qns),
            len(findings),
        )

        # --- Step C: call chains only to confirmed methods ---
        call_chains: list[dict] = []
        field_paths: list[dict] = []
        chain_extra_qns: set[str] = set()
        chain_taint_stats: dict = {}
        if import_graph and confirmed_qns:
            with FindingStore() as store:
                # Step C0: analysis-time CHA (import stored precise edges only)
                focus_types = seed_types_from_methods(sink_caller_qns | confirmed_qns)
                try:
                    # CHA_CALLS not materialized — chain BFS expands on demand.
                    # Still write CHA_REF for field/object-graph paths.
                    cha_stats = materialize_cha_for_analysis(
                        store,
                        self.project,
                        focus_type_qns=focus_types,
                        focus_method_qns=sink_caller_qns | confirmed_qns,
                        expand_calls=False,
                    )
                    logger.info(
                        "Step C0 — CHA_REF=%s (CHA_CALLS deferred to dynamic BFS)",
                        cha_stats.get("cha_refs"),
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Analysis CHA expand failed: %s", exc)

                # On large graphs, keep reflection/exec confirmed sinks + common API sinks.
                chain_targets = confirmed_qns
                if len(confirmed_qns) > 200:
                    api_preferred = {
                        q
                        for q in confirmed_qns
                        if any(
                            h in q
                            for h in (
                                "Method#invoke",
                                "Constructor#newInstance",
                                "defineClass",
                                "defineTransletClasses",
                                "newInstance",
                                "Runtime#exec",
                                "ProcessBuilder",
                                "getOutputProperties",
                                "newTransformer",
                            )
                        )
                    }
                    reflection_confirmed = {
                        f.method_qn
                        for f in findings
                        if f.vul in {"REFLECTION", "EXEC", "JNDI"}
                        and f.method_qn in confirmed_qns
                    }
                    preferred = api_preferred | reflection_confirmed
                    if preferred:
                        chain_targets = preferred
                        logger.info(
                            "Chain query scoped sinks: %d / %d confirmed",
                            len(chain_targets),
                            len(confirmed_qns),
                        )

                try:
                    call_chains = store.query_call_chains_to_methods(
                        self.project,
                        chain_targets,
                        focus_type_qns=focus_types,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Call-chain query failed: %s", exc)

                # Step C1: preliminary hop taint filter (dataflow continuity)
                if call_chains:
                    before = len(call_chains)
                    call_chains, chain_taint_stats = filter_chains_by_taint(
                        call_chains, types, mode=taint_mode
                    )
                    logger.info(
                        "Step C1 — chain taint filter: %d → %d (%s)",
                        before,
                        len(call_chains),
                        chain_taint_stats,
                    )

                chain_extra_qns = method_qns_from_call_chains(call_chains) - confirmed_qns
                chain_extra_qns &= known
                logger.info(
                    "Step C — call chains: %d (extra methods on chains: %d)",
                    len(call_chains),
                    len(chain_extra_qns),
                )

                # Step C2: object-graph field paths (MAY_REF|CHA_REF)
                try:
                    entry_types = seed_types_from_methods(
                        q
                        for q in (sink_caller_qns | confirmed_qns)
                        if "#readObject" in q or "#readExternal" in q or "#invoke(" in q
                    )[:80]
                    sink_types = seed_types_from_methods(chain_targets)[:80]
                    field_paths = query_field_paths(
                        store,
                        self.project,
                        entry_type_qns=entry_types,
                        sink_type_qns=sink_types,
                        max_depth=3,
                        limit=80,
                        serializable_only=True,
                    )
                    if not field_paths:
                        field_paths = query_field_paths(
                            store,
                            self.project,
                            entry_type_qns=entry_types[:40],
                            sink_type_qns=sink_types[:40],
                            max_depth=3,
                            limit=80,
                            serializable_only=False,
                        )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Object-graph query failed: %s", exc)
                logger.info("Step C2 — field/object-graph paths: %d", len(field_paths))

                # Step D (light): taint methods that only appear on chains
                if chain_extra_qns:
                    more = analyze_types(
                        types, mode=taint_mode, only_method_qns=chain_extra_qns
                    )
                    if more:
                        logger.info(
                            "Step D — chain-method taint added %d findings",
                            len(more),
                        )
                        findings = findings + more
                        # de-dupe by identity fields
                        seen: set[tuple] = set()
                        uniq = []
                        for f in findings:
                            key = (
                                f.method_qn,
                                f.sink_name,
                                f.sink_line,
                                f.sink_arg,
                                f.vul,
                            )
                            if key in seen:
                                continue
                            seen.add(key)
                            uniq.append(f)
                        findings = uniq
                        confirmed_qns = {f.method_qn for f in findings}

                store.clear_findings(self.project)
                store.save_findings(self.project, findings)
        elif import_graph:
            with FindingStore() as store:
                store.clear_findings(self.project)
                store.save_findings(self.project, findings)

        findings_payload = [
            {
                "method": f.method_qn,
                "type": f.type_qn,
                "sink": f.sink_name,
                "sink_owner": f.sink_owner,
                "vul": f.vul,
                "line": f.sink_line,
                "arg": f.sink_arg,
                "source_kind": f.source_kind,
                "tainted_vars": f.tainted_vars,
                "evidence": f.evidence,
                "mode": f.mode,
            }
            for f in findings
        ]
        _attach_chains_to_findings(findings_payload, call_chains)

        report = {
            "project": self.project,
            "mode": taint_mode,
            "files": len(result.files),
            "types": result.type_count,
            "methods": result.method_count,
            "call_sites": result.call_site_count,
            "flow": [
                "A: find sink callers",
                "B: taint-confirm exploitable",
                "C0: CHA_REF only; call CHA on-demand in chain BFS",
                "C: dynamic CALLS+CHA BFS to confirmed",
                "C1: chain hop taint continuity filter",
                "C2: field/object-graph MAY_REF|CHA_REF paths",
                "D: taint extra methods on those chains",
            ],
            "taint_scope": {
                "sink_callers": sorted(sink_caller_qns),
                "confirmed_exploitable": sorted(confirmed_qns),
                "chain_extra_methods": sorted(chain_extra_qns),
                "analyzed_count": len(sink_caller_qns | chain_extra_qns),
            },
            "chain_taint_filter": chain_taint_stats,
            "sink_users": sink_users,
            "findings": findings_payload,
            "call_chains_to_sinks": call_chains,
            "field_paths": field_paths,
        }

        if dump_json:
            path = Path(dump_json)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            logger.info("Wrote analysis report -> %s", path)

        logger.info(
            "Analysis done: mode=%s sink_callers=%d confirmed=%d "
            "findings=%d chains=%d field_paths=%d",
            taint_mode,
            len(sink_caller_qns),
            len(confirmed_qns),
            len(findings),
            len(call_chains),
            len(field_paths),
        )
        return report
