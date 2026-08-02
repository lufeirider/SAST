"""CLI entry for reverse module."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from reverse.config import (
    DEFAULT_INPUT,
    DEFAULT_OUTPUT,
    DECOMPILE_MISSING_LIBS,
    SOURCE_CACHE_DIR,
)
from reverse.pipeline import ReversePipeline


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reverse",
        description=(
            "Unpack fat jars, download dependency sources via MANIFEST/pom, "
            "CFR app classes. Supports directories with recursion."
        ),
    )
    p.add_argument(
        "--input",
        "-i",
        type=Path,
        default=DEFAULT_INPUT,
        help=f"JAR / CLASS / WAR / EAR, or a directory (default: {DEFAULT_INPUT})",
    )
    p.add_argument(
        "--output",
        "-o",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output directory (default: {DEFAULT_OUTPUT})",
    )
    p.add_argument(
        "--no-source-download",
        action="store_true",
        help="Skip JAR source resolve; always decompile with CFR",
    )
    p.add_argument(
        "--recursive",
        "-r",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="When input is a directory, recurse into subdirs",
    )
    p.add_argument(
        "--decompile-libs",
        action=argparse.BooleanOptionalAction,
        default=DECOMPILE_MISSING_LIBS,
        help="CFR nested jars when sources download fails (default: on)",
    )
    p.add_argument(
        "--cache-dir",
        type=Path,
        default=SOURCE_CACHE_DIR,
        help=f"Sources download cache (default: {SOURCE_CACHE_DIR})",
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

    pipeline = ReversePipeline(
        output_dir=args.output,
        prefer_source=not args.no_source_download,
        recursive=args.recursive,
        decompile_missing_libs=args.decompile_libs,
        cache_dir=args.cache_dir,
    )
    try:
        result = pipeline.process(args.input)
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        logging.error("%s", exc)
        return 1

    print(f"OK -> {result}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
