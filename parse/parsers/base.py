"""Base Tree-sitter parser."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from tree_sitter import Language, Parser

from parse.models import FileInfo


class BaseParser(ABC):
    language_key: str = "unknown"

    def __init__(self):
        self._language = self._load_language()
        self._parser = Parser(self._language)

    @abstractmethod
    def _load_language(self) -> Language:
        ...

    @abstractmethod
    def parse_file(self, path: Path, source: bytes | None = None) -> FileInfo:
        ...

    def parse_path(self, path: Path) -> FileInfo:
        source = path.read_bytes()
        return self.parse_file(path, source)

    def _node_text(self, node, source: bytes) -> str:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def _child_by_field(self, node, field: str):
        return node.child_by_field_name(field)

    def _walk(self, node):
        yield node
        for child in node.children:
            yield from self._walk(child)
