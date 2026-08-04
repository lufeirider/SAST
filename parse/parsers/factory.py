"""Parser factory and directory walker."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from parse.config import LANGUAGE_EXTENSIONS, PREFER_APP_SOURCES, SKIP_DIR_NAMES
from parse.models import FileInfo, ParseResult
from parse.parsers.parse_ir import ParseIrLoader, fingerprint_java_tree

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


def _cache_paths(project_root: Path) -> tuple[Path, Path]:
    cache_dir = project_root / ".cache"
    return cache_dir / "parse_ir.json", cache_dir / "parse_ir.meta.json"


def parse_directory(
    root: Path,
    project: str = "default",
    *,
    keep_parse_ir_json: Path | None = None,
    reuse_parse_ir: bool | Path = True,
) -> ParseResult:
    """
    Parse Java sources under root.

    reuse_parse_ir:
      True  — use <project>/.cache/parse_ir.json when fingerprint matches
      Path  — load that IR file directly (skip JavaParseIr)
      False — always re-parse
    """
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
        solver_roots: list[Path] = []
        for app in roots:
            lib = app.parent / "lib"
            if lib.is_dir():
                for child in sorted(p for p in lib.iterdir() if p.is_dir()):
                    solver_roots.append(child)
                solver_roots.append(lib)

        loader = ParseIrLoader()

        # Direct IR path
        if isinstance(reuse_parse_ir, Path):
            ir_path = Path(reuse_parse_ir)
            if not ir_path.is_file():
                raise FileNotFoundError(ir_path)
            logger.info("Loading parse IR from %s", ir_path)
            files.extend(loader.load_parse_ir_json(ir_path))
        else:
            # Auto cache beside reverse project (tmpwork/cc_full/.cache/)
            cache_hit = False
            cache_ir: Path | None = None
            cache_meta: Path | None = None
            if len(roots) == 1:
                proj = roots[0].parent
                cache_ir, cache_meta = _cache_paths(proj)
                fp = fingerprint_java_tree(roots[0])
                if (
                    reuse_parse_ir
                    and cache_ir.is_file()
                    and cache_meta.is_file()
                ):
                    try:
                        meta = json.loads(cache_meta.read_text(encoding="utf-8"))
                        if meta.get("fingerprint") == fp:
                            logger.info(
                                "Parse IR cache hit (%s files) -> %s",
                                meta.get("files"),
                                cache_ir,
                            )
                            files.extend(loader.load_parse_ir_json(cache_ir))
                            cache_hit = True
                    except (OSError, json.JSONDecodeError) as exc:
                        logger.warning("Parse IR cache unreadable: %s", exc)

            if not cache_hit:
                keep = keep_parse_ir_json
                if keep is None and cache_ir is not None:
                    keep = cache_ir
                files.extend(
                    loader.parse_roots(
                        roots,
                        solver_roots=solver_roots,
                        keep_parse_ir_json=keep,
                    )
                )
                if cache_ir is not None and cache_meta is not None and keep == cache_ir:
                    cache_meta.parent.mkdir(parents=True, exist_ok=True)
                    cache_meta.write_text(
                        json.dumps(
                            {
                                "fingerprint": fingerprint_java_tree(roots[0]),
                                "files": len(files),
                            },
                            indent=2,
                        ),
                        encoding="utf-8",
                    )
                    logger.info("Wrote parse IR cache meta -> %s", cache_meta)

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
