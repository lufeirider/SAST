"""C# decompiler placeholder (ilspycmd / dnSpy later)."""

from __future__ import annotations

from pathlib import Path

from reverse.decompilers.base import BaseDecompiler


class CSharpDecompiler(BaseDecompiler):
    """Not implemented yet — reserved for .dll / .exe via ilspycmd."""

    language = "csharp"

    def supports(self, path: Path) -> bool:
        return path.is_file() and path.suffix.lower() in {".dll", ".exe"}

    def decompile(self, input_path: Path, output_dir: Path) -> Path:
        raise NotImplementedError(
            "C# decompilation is planned. "
            "Suggested tool: ilspycmd (ICSharpCode.Decompiler)."
        )
