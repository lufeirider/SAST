"""Parse sources and optionally import into Neo4j."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from parse.config import DEFAULT_INPUT
from parse.models import ParseResult
from parse.neo4j_client.importer import Neo4jImporter
from parse.parsers.factory import parse_directory

logger = logging.getLogger(__name__)


class ParsePipeline:
    def __init__(self, project: str = "default"):
        self.project = project

    def parse(
        self,
        input_dir: Path | None = None,
        *,
        keep_parse_ir_json: Path | None = None,
        reuse_parse_ir: bool | Path = True,
    ) -> ParseResult:
        root = Path(input_dir or DEFAULT_INPUT)
        return parse_directory(
            root,
            project=self.project,
            keep_parse_ir_json=keep_parse_ir_json,
            reuse_parse_ir=reuse_parse_ir,
        )

    def parse_and_import(
        self,
        input_dir: Path | None = None,
        clear: bool = True,
        dump_json: Optional[Path] = None,
        keep_parse_ir_json: Optional[Path] = None,
        reuse_parse_ir: bool | Path = True,
    ) -> ParseResult:
        result = self.parse(
            input_dir,
            keep_parse_ir_json=keep_parse_ir_json,
            reuse_parse_ir=reuse_parse_ir,
        )

        if dump_json:
            self.dump_json(result, dump_json)

        with Neo4jImporter() as importer:
            importer.import_result(result, clear=clear)

        return result

    @staticmethod
    def dump_json(result: ParseResult, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "project": result.project,
            "files": [
                {
                    "path": f.path,
                    "language": f.language,
                    "package": f.package,
                    "imports": f.imports,
                    "types": [
                        {
                            "name": t.name,
                            "qualified_name": t.qualified_name,
                            "kind": t.kind,
                            "extends": t.extends,
                            "implements": t.implements,
                            "fields": [
                                {
                                    "name": fld.name,
                                    "type_name": fld.type_name,
                                    "resolved_type": fld.resolved_type,
                                    "is_static": fld.is_static,
                                    "is_transient": fld.is_transient,
                                    "is_final": fld.is_final,
                                    "start_line": fld.start_line,
                                }
                                for fld in t.fields
                            ],
                            "methods": [
                                {
                                    "name": m.name,
                                    "qualified_name": m.qualified_name,
                                    "return_type": m.return_type,
                                    "parameters": [
                                        {
                                            "name": p.name,
                                            "type_name": p.type_name,
                                            "index": p.index,
                                        }
                                        for p in m.parameters
                                    ],
                                    "calls": m.calls,
                                    "call_sites": [
                                        {
                                            "callee_name": cs.callee_name,
                                            "receiver": cs.receiver,
                                            "arguments": cs.arguments,
                                            "line": cs.line,
                                            "is_constructor": cs.is_constructor,
                                            "resolved_qn": cs.resolved_qn,
                                        }
                                        for cs in m.call_sites
                                    ],
                                    "assignments": [
                                        {
                                            "lhs": a.lhs,
                                            "rhs": a.rhs,
                                            "line": a.line,
                                        }
                                        for a in m.assignments
                                    ],
                                    "start_line": m.start_line,
                                    "end_line": m.end_line,
                                }
                                for m in t.methods
                            ],
                        }
                        for t in f.types
                    ],
                }
                for f in result.files
            ],
        }
        path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        logger.info("Wrote parse dump -> %s", path)
