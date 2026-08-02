"""Java decompiler backed by CFR — parallel, class-dir aware."""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

from reverse.config import CFR_JAR_NAME, CFR_URL, DECOMPILE_WORKERS, TOOLS_DIR
from reverse.decompilers.base import BaseDecompiler

logger = logging.getLogger(__name__)

JAVA_SUFFIXES = {".jar", ".class", ".war", ".ear"}


class JavaDecompiler(BaseDecompiler):
    language = "java"

    def __init__(self, java_bin: str = "java", workers: int = DECOMPILE_WORKERS):
        self.java_bin = java_bin
        self.cfr_jar = TOOLS_DIR / CFR_JAR_NAME
        self.workers = workers

    def supports(self, path: Path) -> bool:
        path = Path(path)
        if path.is_file():
            return path.suffix.lower() in JAVA_SUFFIXES
        if path.is_dir():
            # class directory or contains binaries
            if any(path.rglob("*.class")):
                return True
            return any(self._iter_binaries(path, recursive=True))
        return False

    def ensure_cfr(self) -> Path:
        if self.cfr_jar.exists():
            return self.cfr_jar

        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        logger.info("Downloading CFR from %s", CFR_URL)
        resp = requests.get(CFR_URL, timeout=120)
        resp.raise_for_status()
        self.cfr_jar.write_bytes(resp.content)
        logger.info("CFR saved to %s", self.cfr_jar)
        return self.cfr_jar

    def decompile(
        self,
        input_path: Path,
        output_dir: Path,
        *,
        recursive: bool = True,
    ) -> Path:
        input_path = Path(input_path)
        if input_path.is_dir():
            if any(input_path.rglob("*.class")):
                out = output_dir / f"{input_path.name}_decompiled"
                return self.decompile_to(input_path, out)
            return self.decompile_directory(
                input_path, output_dir, recursive=recursive
            )
        return self.decompile_to(
            input_path, output_dir / f"{input_path.stem}_decompiled"
        )

    def decompile_to(self, input_path: Path, out: Path) -> Path:
        """Decompile into an exact output directory (e.g. src/main/java)."""
        input_path = Path(input_path)
        # CFR cannot take a bare classes directory — pack to a temp jar first
        if input_path.is_dir() and any(input_path.rglob("*.class")):
            with tempfile.TemporaryDirectory(prefix="sast-cfr-") as tmp:
                jar_path = Path(tmp) / f"{input_path.name}.jar"
                self._pack_classes_jar(input_path, jar_path)
                return self._decompile_one(jar_path, Path(out))
        return self._decompile_one(input_path, Path(out))

    @staticmethod
    def _pack_classes_jar(classes_dir: Path, jar_path: Path) -> Path:
        """Zip a classes root into a jar so CFR can consume it."""
        jar_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(jar_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for path in classes_dir.rglob("*"):
                if path.is_file():
                    zf.write(path, path.relative_to(classes_dir).as_posix())
        logger.debug("Packed classes dir %s -> %s", classes_dir, jar_path)
        return jar_path

    def decompile_many(
        self, binaries: list[Path], output_dir: Path
    ) -> dict[Path, Path | None]:
        """Parallel CFR; each jar -> output_dir/<stem>_decompiled."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        mapping = {b: output_dir / f"{b.stem}_decompiled" for b in binaries}
        return self.decompile_many_to(mapping)

    def decompile_many_to(
        self, mapping: dict[Path, Path]
    ) -> dict[Path, Path | None]:
        """Parallel CFR with explicit per-jar output paths."""
        results: dict[Path, Path | None] = {}
        if not mapping:
            return results

        self.ensure_cfr()
        items = list(mapping.items())
        workers = min(self.workers, max(1, len(items)))
        logger.info("CFR decompile %d items (workers=%d)", len(items), workers)

        def _one(src: Path, out: Path) -> tuple[Path, Path | None]:
            try:
                return src, self.decompile_to(src, out)
            except Exception as exc:  # noqa: BLE001
                logger.error("CFR failed %s: %s", src.name, exc)
                return src, None

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(_one, src, out) for src, out in items]
            for fut in as_completed(futs):
                src, path = fut.result()
                results[src] = path
        return results

    def decompile_directory(
        self,
        directory: Path,
        output_dir: Path,
        *,
        recursive: bool = True,
    ) -> Path:
        directory = Path(directory).resolve()
        binaries = list(self._iter_binaries(directory, recursive=recursive))
        if not binaries:
            raise ValueError(
                f"No .jar/.class/.war/.ear under {directory} "
                f"(recursive={recursive})"
            )

        dest_root = output_dir / f"{directory.name}_decompiled"
        dest_root.mkdir(parents=True, exist_ok=True)
        mapping = {b: dest_root / b.relative_to(directory).parent for b in binaries}

        def _one(binary: Path) -> None:
            out = mapping[binary] / f"{binary.stem}_decompiled"
            try:
                self._decompile_one(binary, out)
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed %s: %s", binary, exc)

        workers = min(self.workers, max(1, len(binaries)))
        logger.info(
            "Decompiling %d binaries under %s (workers=%d)",
            len(binaries),
            directory,
            workers,
        )
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(_one, binaries))

        (dest_root / ".sast_meta").write_text(
            f"source=decompile:cfr\ninput={directory}\nrecursive={recursive}\n",
            encoding="utf-8",
        )
        return dest_root

    def _decompile_one(self, input_path: Path, out: Path) -> Path:
        if not shutil.which(self.java_bin):
            raise RuntimeError(
                f"Java runtime not found (`{self.java_bin}`). "
                "Install JDK to decompile."
            )

        cfr = self.ensure_cfr()
        # Skip if already decompiled (has java files)
        if out.exists() and any(out.rglob("*.java")):
            logger.info("Skip CFR (cached): %s", out)
            return out

        out.mkdir(parents=True, exist_ok=True)

        # Speed-oriented CFR flags (less pretty-print work)
        cmd = [
            self.java_bin,
            "-Xss4m",
            "-jar",
            str(cfr),
            str(input_path),
            "--outputdir",
            str(out),
            "--silent",
            "true",
            "--comments",
            "false",
            "--showversion",
            "false",
            "--analyseas",
            "JAR" if input_path.is_file() else "DETECT",
        ]
        logger.info("Running CFR: %s", input_path.name)
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(
                f"CFR failed on {input_path.name} ({proc.returncode}): "
                f"{proc.stderr or proc.stdout}"
            )

        logger.info("Decompiled %s -> %s", input_path.name, out)
        return out

    @staticmethod
    def _iter_binaries(directory: Path, *, recursive: bool):
        pattern_iter = directory.rglob if recursive else directory.glob
        for path in sorted(pattern_iter("*")):
            if path.is_file() and path.suffix.lower() in JAVA_SUFFIXES:
                yield path
