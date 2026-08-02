"""Load parse_ir.json into Python parse.models objects."""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable

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


class ParseIrLoader:
    """Run JavaParseIr to emit parse_ir.json, then load into FileInfo trees."""

    language_key = "java"

    def __init__(self, java_bin: str = "java"):
        self.java_bin = java_bin
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

    def parse_roots(
        self,
        roots: Iterable[Path],
        solver_roots: Iterable[Path] | None = None,
        *,
        keep_parse_ir_json: Path | None = None,
    ) -> list[FileInfo]:
        root_list = [Path(r).resolve() for r in roots if Path(r).is_dir()]
        solver_list = [
            Path(r).resolve()
            for r in (solver_roots or [])
            if Path(r).is_dir() and Path(r).resolve() not in root_list
        ]
        if not root_list:
            return []

        if keep_parse_ir_json is not None:
            out_path = Path(keep_parse_ir_json)
            out_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                out_path = Path(tmp.name)

        cmd = [
            self.java_bin,
            "-Xmx8g",
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
            "JavaParseIr roots=%s solver_roots=%s",
            [str(r) for r in root_list],
            [str(r) for r in solver_list],
        )
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"JavaParseIr failed ({proc.returncode}): {proc.stderr[-2000:]}"
            )
        if proc.stderr.strip():
            for line in proc.stderr.strip().splitlines()[:20]:
                logger.warning("%s", line)

        payload = json.loads(out_path.read_text(encoding="utf-8"))
        if keep_parse_ir_json is None:
            out_path.unlink(missing_ok=True)
        else:
            logger.info("Kept parse_ir.json -> %s", out_path)
        return [self._to_file_info(f) for f in payload.get("files") or []]

    def parse_path(self, path: Path) -> FileInfo:
        """Single-file entry (uses parent package root heuristics)."""
        path = Path(path).resolve()
        root = self._guess_source_root(path)
        files = self.parse_roots([root])
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
