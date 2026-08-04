"""Load parse_ir.json into Python parse.models objects."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable

from parse.config import (
    JAVA_PARSE_XMX,
    PARSE_SHARD_MIN_FILES,
    PARSE_SHARD_WORKERS,
)
from parse.models import (
    AssignmentInfo,
    CallSite,
    FieldInfo,
    FileInfo,
    MethodInfo,
    ParameterInfo,
    TypeInfo,
)

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent.parent
PARSE_IR_JAR = ROOT / "parse" / "tools" / "java-parse-ir.jar"
LIBS_DIR = ROOT / "parse" / "tools" / "jp-libs"


def fingerprint_java_tree(root: Path) -> str:
    """Stable fingerprint of a Java source tree (paths + size + mtime)."""
    root = Path(root).resolve()
    h = hashlib.sha1()
    for path in sorted(root.rglob("*.java")):
        try:
            st = path.stat()
        except OSError:
            continue
        rel = path.relative_to(root).as_posix().encode()
        h.update(rel)
        h.update(str(st.st_size).encode())
        h.update(str(int(st.st_mtime_ns)).encode())
    return h.hexdigest()


class ParseIrLoader:
    """Run JavaParseIr to emit parse_ir.json, then load into FileInfo trees."""

    language_key = "java"

    def __init__(self, java_bin: str = "java", xmx: str | None = None):
        self.java_bin = java_bin
        self.xmx = xmx or JAVA_PARSE_XMX
        if not PARSE_IR_JAR.is_file():
            raise FileNotFoundError(
                f"Missing {PARSE_IR_JAR}. Build with: "
                "bash parse/tools/build_java_parse_ir.sh"
            )
        if not LIBS_DIR.is_dir():
            raise FileNotFoundError(f"Missing JavaParser libs at {LIBS_DIR}")

    def _classpath(self) -> str:
        jars = [str(PARSE_IR_JAR), *sorted(str(p) for p in LIBS_DIR.glob("*.jar"))]
        return ":".join(jars)

    def load_parse_ir_json(self, path: Path) -> list[FileInfo]:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return [self._to_file_info(f) for f in payload.get("files") or []]

    def parse_roots(
        self,
        roots: Iterable[Path],
        solver_roots: Iterable[Path] | None = None,
        *,
        keep_parse_ir_json: Path | None = None,
        shard: bool = True,
    ) -> list[FileInfo]:
        root_list = [Path(r).resolve() for r in roots if Path(r).is_dir()]
        solver_list = [
            Path(r).resolve()
            for r in (solver_roots or [])
            if Path(r).is_dir() and Path(r).resolve() not in root_list
        ]
        if not root_list:
            return []

        # Auto-shard large single roots (full JDK mining)
        if shard and len(root_list) == 1:
            only = root_list[0]
            n_files = sum(1 for _ in only.rglob("*.java"))
            children = sorted(
                p for p in only.iterdir() if p.is_dir() and not p.name.startswith(".")
            )
            if n_files >= PARSE_SHARD_MIN_FILES and len(children) >= 2:
                return self._parse_sharded(
                    only,
                    children,
                    solver_list,
                    keep_parse_ir_json=keep_parse_ir_json,
                )

        return self._parse_once(
            root_list, solver_list, keep_parse_ir_json=keep_parse_ir_json
        )

    def _parse_sharded(
        self,
        full_root: Path,
        children: list[Path],
        extra_solver: list[Path],
        *,
        keep_parse_ir_json: Path | None,
    ) -> list[FileInfo]:
        # Solver sees the whole tree; each shard only emits one top-level package dir.
        solver = [full_root, *extra_solver]
        workers = max(1, min(PARSE_SHARD_WORKERS, len(children)))
        logger.info(
            "JavaParseIr sharded: %d package dirs, workers=%d xmx=%s root=%s",
            len(children),
            workers,
            self.xmx,
            full_root,
        )

        merged: list[FileInfo] = []
        shard_payloads: list[dict] = []

        def _one(child: Path) -> tuple[Path, list[FileInfo], dict]:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                out = Path(tmp.name)
            files = self._parse_once(
                [child], solver, keep_parse_ir_json=out, xmx=self.xmx
            )
            payload = json.loads(out.read_text(encoding="utf-8"))
            out.unlink(missing_ok=True)
            return child, files, payload

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(_one, c) for c in children]
            for fut in as_completed(futs):
                child, files, payload = fut.result()
                logger.info("  shard %s -> %d files", child.name, len(files))
                merged.extend(files)
                shard_payloads.append(payload)

        if keep_parse_ir_json is not None:
            out_path = Path(keep_parse_ir_json)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            all_files: list[dict] = []
            for p in shard_payloads:
                all_files.extend(p.get("files") or [])
            out_path.write_text(
                json.dumps({"files": all_files}, ensure_ascii=False),
                encoding="utf-8",
            )
            logger.info("Kept merged parse_ir.json -> %s (%d files)", out_path, len(all_files))

        return merged

    def _parse_once(
        self,
        root_list: list[Path],
        solver_list: list[Path],
        *,
        keep_parse_ir_json: Path | None = None,
        xmx: str | None = None,
    ) -> list[FileInfo]:
        if keep_parse_ir_json is not None:
            out_path = Path(keep_parse_ir_json)
            out_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                out_path = Path(tmp.name)

        heap = xmx or self.xmx
        if not str(heap).startswith("-Xmx"):
            heap_arg = f"-Xmx{heap}"
        else:
            heap_arg = str(heap)
        cmd = [
            self.java_bin,
            heap_arg,
            "-cp",
            self._classpath(),
            "sast.parse.JavaParseIr",
        ]

        for r in root_list:
            cmd.extend(["--root", str(r)])
        for r in solver_list:
            cmd.extend(["--solver-root", str(r)])
        cmd.extend(["--out", str(out_path)])

        logger.info(
            "JavaParseIr roots=%s solver_roots=%s %s",
            [str(r) for r in root_list],
            [str(r) for r in solver_list],
            heap_arg,
        )
        env = os.environ.copy()
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"JavaParseIr failed ({proc.returncode}): {proc.stderr[-2000:]}"
            )
        if proc.stderr.strip():
            for line in proc.stderr.strip().splitlines()[:20]:
                logger.warning("%s", line)

        payload = json.loads(out_path.read_text(encoding="utf-8"))
        # When caller passed keep_parse_ir_json for shard merge, leave file;
        # for normal single-shot with keep=None, delete temp.
        if keep_parse_ir_json is None:
            out_path.unlink(missing_ok=True)
        elif keep_parse_ir_json is not None and Path(keep_parse_ir_json) == out_path:
            logger.info("Kept parse_ir.json -> %s", out_path)
        return [self._to_file_info(f) for f in payload.get("files") or []]

    def parse_path(self, path: Path) -> FileInfo:
        """Single-file entry (uses parent package root heuristics)."""
        path = Path(path).resolve()
        root = self._guess_source_root(path)
        files = self.parse_roots([root], shard=False)
        for f in files:
            if Path(f.path).resolve() == path:
                return f
        raise FileNotFoundError(f"ParseIr did not return {path}")

    @staticmethod
    def _guess_source_root(java_file: Path) -> Path:
        for parent in java_file.parents:
            if parent.name == "app":
                return parent
        return java_file.parent

    @classmethod
    def _to_file_info(cls, raw: dict) -> FileInfo:
        types = [cls._to_type(t) for t in raw.get("types") or []]
        return FileInfo(
            path=raw.get("path") or "",
            language=raw.get("language") or "java",
            package=raw.get("package") or "",
            imports=list(raw.get("imports") or []),
            types=types,
        )

    @classmethod
    def _to_type(cls, raw: dict) -> TypeInfo:
        methods = [cls._to_method(m) for m in raw.get("methods") or []]
        fields = [
            FieldInfo(
                name=f.get("name") or "",
                type_name=f.get("type_name") or "",
                resolved_type=f.get("resolved_type") or "",
                is_static=bool(f.get("is_static")),
                is_transient=bool(f.get("is_transient")),
                is_final=bool(f.get("is_final")),
                start_line=int(f.get("start_line") or 0),
            )
            for f in raw.get("fields") or []
        ]
        return TypeInfo(
            name=raw.get("name") or "",
            qualified_name=raw.get("qualified_name") or "",
            kind=raw.get("kind") or "class",
            package=raw.get("package") or "",
            file_path=raw.get("file_path") or "",
            extends=list(raw.get("extends") or []),
            implements=list(raw.get("implements") or []),
            methods=methods,
            fields=fields,
            start_line=int(raw.get("start_line") or 0),
            end_line=int(raw.get("end_line") or 0),
        )

    @classmethod
    def _to_method(cls, raw: dict) -> MethodInfo:
        params = [
            ParameterInfo(
                name=p.get("name") or "",
                type_name=p.get("type_name") or "",
                index=int(p.get("index") or 0),
            )
            for p in raw.get("parameters") or []
        ]
        call_sites = [
            CallSite(
                callee_name=cs.get("callee_name") or "",
                receiver=cs.get("receiver") or "",
                arguments=list(cs.get("arguments") or []),
                line=int(cs.get("line") or 0),
                is_constructor=bool(cs.get("is_constructor")),
                resolved_qn=cs.get("resolved_qn") or "",
            )
            for cs in raw.get("call_sites") or []
        ]
        assignments = [
            AssignmentInfo(
                lhs=a.get("lhs") or "",
                rhs=a.get("rhs") or "",
                line=int(a.get("line") or 0),
            )
            for a in raw.get("assignments") or []
        ]
        return MethodInfo(
            name=raw.get("name") or "",
            qualified_name=raw.get("qualified_name") or "",
            return_type=raw.get("return_type") or "",
            parameters=params,
            start_line=int(raw.get("start_line") or 0),
            end_line=int(raw.get("end_line") or 0),
            calls=list(raw.get("calls") or []),
            call_sites=call_sites,
            assignments=assignments,
        )
