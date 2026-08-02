"""Base decompiler interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path


class BaseDecompiler(ABC):
    """Language-agnostic decompiler contract."""

    language: str = "unknown"

    @abstractmethod
    def decompile(self, input_path: Path, output_dir: Path) -> Path:
        """Decompile binary/resources into source under output_dir."""

    @abstractmethod
    def supports(self, path: Path) -> bool:
        """Whether this decompiler can handle the given path."""
