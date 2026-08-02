"""CLI for SAST analysis (sinks + taint)."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from analyze.config import TAINT_MODE
from analyze.pipeline import AnalyzePipeline
from parse.config import DEFAULT_INPUT


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analyze",
        description=(
            "Detect vulns/gadgets: parse call graph → sinks → "
            "simple taint (mode=vuln|gadget)."
        ),
    )
    p.add_argument("-i", "--input", type=Path, default=DEFAULT_INPUT)
    p.add_argument("-p", "--project", default="JavaTarget")
    p.add_argument(
        "--mode",
        choices=("vuln", "gadget"),
        default=TAINT_MODE,
        help="污点模式: vuln=找漏洞(参数 source); gadget=找gadget(字段+readObject)",
    )
    p.add_argument(
        "--no-import",
        action="store_true",
        help="Parse+taint only; do not write graph/findings to Neo4j",
    )
    p.add_argument(
        "--dump-json",
        type=Path,
        default=None,
        help="Write analysis report JSON",
    )
    p.add_argument(
        "--report",
        type=Path,
        nargs="?",
        const=Path("tmpwork/analyze_report.html"),
        default=None,
        help="Write HTML report with code snippets + call chains "
        "(default: tmpwork/analyze_report.html)",
    )
    p.add_argument(
        "--app-root",
        type=Path,
        default=None,
        help="Source root for snippets (default: tmpwork/*/app)",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    pipe = AnalyzePipeline(project=args.project, mode=args.mode)
    try:
        report = pipe.run(
            input_dir=args.input,
            parse_first=True,
            import_graph=not args.no_import,
            dump_json=args.dump_json,
            mode=args.mode,
        )
    except Exception as exc:  # noqa: BLE001
        logging.error("%s", exc)
        return 1

    scope = report.get("taint_scope") or {}
    print(
        f"OK project={report['project']} mode={report.get('mode')} "
        f"sink_callers={len(scope.get('sink_callers') or [])} "
        f"confirmed={len(scope.get('confirmed_exploitable') or [])} "
        f"findings={len(report['findings'])} "
        f"chains={len(report['call_chains_to_sinks'])}"
    )
    for f in report["findings"][:20]:
        vul = f.get("vul") or "?"
        print(
            f"  [{vul}/{f['sink']}] {f['method']}:{f['line']} "
            f"arg={f['arg']!r} src={f['source_kind']}"
        )

    if args.report is not None:
        from analyze.report import enrich_report, write_html

        enriched = enrich_report(report, args.app_root)
        out = write_html(enriched, args.report)
        print(f"HTML report: {out.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
