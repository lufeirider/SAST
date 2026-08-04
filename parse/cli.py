"""CLI entry for parse module."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from parse.config import DEFAULT_INPUT
from parse.pipeline import ParsePipeline


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="parse",
        description="Emit parse IR (JavaParseIr) and import into Neo4j.",
    )
    p.add_argument(
        "--input",
        "-i",
        type=Path,
        default=DEFAULT_INPUT,
        help=f"Source directory (default: {DEFAULT_INPUT})",
    )
    p.add_argument(
        "--project",
        "-p",
        default="default",
        help="Project name stored on Neo4j nodes",
    )
    p.add_argument(
        "--no-import",
        action="store_true",
        help="Only parse; do not write to Neo4j",
    )
    p.add_argument(
        "--no-clear",
        action="store_true",
        help="Do not delete existing project nodes before import",
    )
    p.add_argument(
        "--dump-json",
        type=Path,
        default=None,
        help="Write parse_ir objects re-serialized as JSON",
    )
    p.add_argument(
        "--dump-parse-ir",
        type=Path,
        default=None,
        help="Keep parse_ir.json from JavaParseIr (before Python load)",
    )
    p.add_argument(
        "--force-reparse",
        action="store_true",
        help="Ignore parse IR cache and re-run JavaParseIr",
    )
    p.add_argument(
        "--parse-ir",
        type=Path,
        default=None,
        help="Load this parse_ir.json instead of parsing sources",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Debug logging",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.parse_ir is not None:
        reuse: bool | Path = args.parse_ir
    elif args.force_reparse:
        reuse = False
    else:
        reuse = True

    pipeline = ParsePipeline(project=args.project)
    try:
        if args.no_import:
            result = pipeline.parse(
                args.input,
                keep_parse_ir_json=args.dump_parse_ir,
                reuse_parse_ir=reuse,
            )
            if args.dump_json:
                pipeline.dump_json(result, args.dump_json)
        else:
            result = pipeline.parse_and_import(
                input_dir=args.input,
                clear=not args.no_clear,
                dump_json=args.dump_json,
                keep_parse_ir_json=args.dump_parse_ir,
                reuse_parse_ir=reuse,
            )
    except Exception as exc:  # noqa: BLE001
        logging.error("%s", exc)
        return 1

    print(
        f"OK project={result.project} "
        f"files={len(result.files)} "
        f"types={result.type_count} "
        f"methods={result.method_count} "
        f"call_sites={result.call_site_count}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
