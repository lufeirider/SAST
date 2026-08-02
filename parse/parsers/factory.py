"""Parser factory and directory walker."""

from __future__ import annotations

import logging
from pathlib import Path

from parse.config import LANGUAGE_EXTENSIONS, PREFER_APP_SOURCES, SKIP_DIR_NAMES
from parse.models import FileInfo, ParseResult
from parse.parsers.parse_ir import ParseIrLoader

logger = logging.getLogger(__name__)


def _should_skip_dir(path: Path) -> bool:
    return path.name in SKIP_DIR_NAMES


def _iter_source_files(root: Path) -> list[Path]:
    root = Path(root).resolve()
    files: list[Path] = []

    # reverse layout: tmpwork/<proj>/app/**/*.java
    if PREFER_APP_SOURCES:
        app_dirs = sorted(p for p in root.rglob("app") if p.is_dir() and p.name == "app")
        preferred: list[Path] = []
        for app in app_dirs:
            parent = app.parent
            if (parent / ".sast_meta").exists() or (parent / "lib").is_dir():
                preferred.append(app)
        if preferred:
            for app in preferred:
                for path in sorted(app.rglob("*")):
                    if path.is_file() and path.suffix.lower() in LANGUAGE_EXTENSIONS:
                        files.append(path)
            if files:
                logger.info("Using reverse app/ sources: %d files under %s", len(files), root)
                return files

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(_should_skip_dir(p) for p in path.parents):
            continue
        if path.suffix.lower() in LANGUAGE_EXTENSIONS:
            files.append(path)
    return files


def _discover_java_roots(java_files: list[Path], fallback_root: Path) -> list[Path]:
    """Source roots for SymbolSolver (directories that contain package trees)."""
    roots: set[Path] = set()
    for f in java_files:
        app = next((p for p in f.parents if p.name == "app"), None)
        if app is not None:
            roots.add(app.resolve())
        else:
            roots.add(f.parent.resolve())
    if not roots and fallback_root.is_dir():
        roots.add(fallback_root.resolve())
    return sorted(roots)


def parse_directory(
    root: Path,
    project: str = "default",
    *,
    keep_parse_ir_json: Path | None = None,
) -> ParseResult:
    root = Path(root).resolve()
    if not root.exists():
        raise FileNotFoundError(root)

    source_files = _iter_source_files(root)
    java_files = [p for p in source_files if p.suffix.lower() == ".java"]
    other = [p for p in source_files if p.suffix.lower() != ".java"]
    if other:
        logger.warning("Skipping non-Java sources (no parser): %d files", len(other))

    files: list[FileInfo] = []
    if java_files:
        roots = _discover_java_roots(java_files, root)
        # Dependency sources under reverse lib/ — SymbolSolver only, not emitted
        solver_roots: list[Path] = []
        for app in roots:
            lib = app.parent / "lib"
            if lib.is_dir():
                for child in sorted(p for p in lib.iterdir() if p.is_dir()):
                    solver_roots.append(child)
                solver_roots.append(lib)
        try:
            files.extend(
                ParseIrLoader().parse_roots(
                    roots,
                    solver_roots=solver_roots,
                    keep_parse_ir_json=keep_parse_ir_json,
                )
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("ParseIrLoader failed: %s", exc)
            raise

    result = ParseResult(project=project, files=files)
    logger.info(
        "Parsed project=%s files=%d types=%d methods=%d call_sites=%d (parse_ir)",
        project,
        len(result.files),
        result.type_count,
        result.method_count,
        result.call_site_count,
    )
    return result
