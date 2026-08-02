"""Orchestrate fat-jar unpack + source download + pure source tree output."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Optional

from reverse.config import (
    DEFAULT_OUTPUT,
    DECOMPILE_MISSING_LIBS,
    PREFER_SOURCE_DOWNLOAD,
    SKIP_NESTED_NAME_SUBSTRINGS,
    SOURCE_CACHE_DIR,
)
from reverse.decompilers.java import JAVA_SUFFIXES, JavaDecompiler
from reverse.downloaders.jar_source import JarSourceResolver
from reverse.project_layout import (
    copy_resources,
    ensure_source_project,
    install_sources,
    scrub_binaries,
    write_readme,
)
from reverse.unpack.fatjar import inspect_archive, unpack_archive

logger = logging.getLogger(__name__)


class ReversePipeline:
    """
    Recover sources into a pure source tree (no jar/class in the project):

      <project>/
        app/                 # application .java
        resources/
        lib/<dep>/           # dependency sources
    """

    def __init__(
        self,
        output_dir: Optional[Path] = None,
        prefer_source: bool = PREFER_SOURCE_DOWNLOAD,
        recursive: bool = True,
        decompile_missing_libs: bool = DECOMPILE_MISSING_LIBS,
        cache_dir: Optional[Path] = None,
    ):
        self.output_dir = Path(output_dir or DEFAULT_OUTPUT)
        self.prefer_source = prefer_source
        self.recursive = recursive
        self.decompile_missing_libs = decompile_missing_libs
        self.cache_dir = Path(cache_dir or SOURCE_CACHE_DIR)
        self.jar_sources = JarSourceResolver(cache_dir=self.cache_dir)
        self.java = JavaDecompiler()

    def process(self, input_path: Path) -> Path:
        input_path = Path(input_path).resolve()
        if not input_path.exists():
            raise FileNotFoundError(input_path)

        self.output_dir.mkdir(parents=True, exist_ok=True)

        if input_path.is_dir():
            return self._process_directory(input_path)

        if input_path.suffix.lower() == ".java":
            return self._copy_sources(input_path)

        if input_path.suffix.lower() in JAVA_SUFFIXES:
            return self._process_java_binary(input_path)

        raise ValueError(
            f"Unsupported input: {input_path}. "
            "Supported: .jar / .class / .war / .ear / directory (recursive)."
        )

    def _unpack_dir(self, stem: str) -> Path:
        """Intermediate unpack lives outside the project tree."""
        work = self.output_dir / ".unpack" / stem
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(parents=True, exist_ok=True)
        return work

    def _cleanup_unpack(self, work: Path) -> None:
        try:
            if work.exists():
                shutil.rmtree(work)
            parent = work.parent
            if parent.name == ".unpack" and parent.exists() and not any(parent.iterdir()):
                parent.rmdir()
        except OSError as exc:
            logger.warning("Failed to cleanup unpack dir %s: %s", work, exc)

    def _process_java_binary(self, path: Path) -> Path:
        if path.suffix.lower() in {".jar", ".war", ".ear"}:
            layout = inspect_archive(path)
            if layout.is_fat:
                return self._process_fat_jar(path)

        root = self.output_dir / path.stem
        if root.exists():
            shutil.rmtree(root)
        dirs = ensure_source_project(root)

        if self.prefer_source and path.suffix.lower() in {".jar", ".war", ".ear"}:
            tree = self.jar_sources.resolve_source_tree(path)
            if tree is not None:
                # single library jar → sources under app/
                if dirs["app"].exists():
                    shutil.rmtree(dirs["app"])
                install_sources(tree, dirs["app"])
                scrub_binaries(root)
                write_readme(root, path.stem)
                self._write_meta(root, f"source=jar-sources\nfrom={path.name}\nlayout=source\n")
                return root

        if dirs["app"].exists():
            shutil.rmtree(dirs["app"])
        self.java.decompile_to(path, dirs["app"])
        scrub_binaries(root)
        write_readme(root, path.stem)
        self._write_meta(root, f"source=decompile:cfr\nfrom={path.name}\nlayout=source\n")
        return root

    def _process_fat_jar(self, path: Path) -> Path:
        """
        Spring Boot / WAR → pure source tree:

          app/           business java
          resources/     configs
          lib/<dep>/     dependency java sources only
        """
        root = self.output_dir / path.stem
        if root.exists():
            shutil.rmtree(root)

        dirs = ensure_source_project(root)
        work = self._unpack_dir(path.stem)
        layout = unpack_archive(path, work)

        nested = [
            j
            for j in layout.nested_jar_paths
            if not any(s in j.name for s in SKIP_NESTED_NAME_SUBSTRINGS)
        ]
        logger.info(
            "Fat jar %s: nested_libs=%d app_classes=%s",
            path.name,
            len(nested),
            bool(layout.app_classes_dir),
        )

        got_sources: dict[Path, Path] = {}
        need_decompile: list[Path] = []

        if self.prefer_source and nested:
            resolved = self.jar_sources.try_get_sources_many(nested)
            for jar, tree in resolved.items():
                if tree is not None:
                    got_sources[jar] = tree
                    install_sources(tree, dirs["lib"] / jar.stem)
                else:
                    need_decompile.append(jar)
        else:
            need_decompile = list(nested)

        # App classes → app/ (pure java packages)
        if layout.app_classes_dir and any(layout.app_classes_dir.rglob("*.class")):
            logger.info("Decompiling app classes -> app/")
            if dirs["app"].exists():
                shutil.rmtree(dirs["app"])
            self.java.decompile_to(layout.app_classes_dir, dirs["app"])
            n_res = copy_resources(layout.app_classes_dir, dirs["resources"])
            logger.info("Copied %d resource files -> resources/", n_res)

        decompiled_libs = 0
        if need_decompile:
            if self.decompile_missing_libs:
                logger.info(
                    "CFR fallback for %d/%d nested jars -> lib/*/",
                    len(need_decompile),
                    len(nested),
                )
                mapping = {jar: dirs["lib"] / jar.stem for jar in need_decompile}
                self.java.decompile_many_to(mapping)
                decompiled_libs = len(need_decompile)
            else:
                miss_list = root / "libs_missing_sources.txt"
                miss_list.write_text(
                    "\n".join(p.name for p in need_decompile) + "\n",
                    encoding="utf-8",
                )
                logger.info(
                    "Skip CFR for %d libs without sources "
                    "(use --decompile-libs to force). Listed in %s",
                    len(need_decompile),
                    miss_list,
                )

        # Drop unpack intermediates (jars/classes) — final tree is sources only
        self._cleanup_unpack(work)
        scrub_binaries(root)

        write_readme(root, path.stem)
        self._write_meta(
            root,
            (
                f"source=fat-jar\nfrom={path.name}\n"
                f"layout=source\n"
                f"nested={len(nested)}\n"
                f"sources_ok={len(got_sources)}\n"
                f"sources_miss={len(need_decompile)}\n"
                f"decompiled_libs={decompiled_libs}\n"
                f"manifest_main={layout.manifest.get('Start-Class', layout.manifest.get('Main-Class', ''))}\n"
            ),
        )
        logger.info(
            "Fat jar done: sources=%d miss=%d decompiled_libs=%d -> %s",
            len(got_sources),
            len(need_decompile),
            decompiled_libs,
            root,
        )
        return root

    def _process_directory(self, directory: Path) -> Path:
        binaries = list(self._iter_binaries(directory))
        java_files = list(self._iter_java(directory))

        if binaries:
            logger.info(
                "Directory %s: %d binaries (recursive=%s)",
                directory,
                len(binaries),
                self.recursive,
            )
            if len(binaries) == 1:
                return self._process_java_binary(binaries[0])

            summary = self.output_dir / directory.name
            summary.mkdir(parents=True, exist_ok=True)
            for binary in binaries:
                ReversePipeline(
                    output_dir=summary,
                    prefer_source=self.prefer_source,
                    recursive=self.recursive,
                    decompile_missing_libs=self.decompile_missing_libs,
                    cache_dir=self.cache_dir,
                )._process_java_binary(binary)

            self._write_meta(
                summary,
                f"source=mixed\ninput={directory}\nbinaries={len(binaries)}\n",
            )
            return summary

        if java_files:
            dest = self.output_dir / directory.name
            if dest.resolve() != directory.resolve():
                if dest.exists():
                    shutil.rmtree(dest)
                shutil.copytree(directory, dest)
            else:
                dest = directory
            scrub_binaries(dest)
            self._write_meta(dest, "source=local\nlayout=source\n")
            logger.info("Copied existing sources -> %s", dest)
            return dest

        raise FileNotFoundError(
            f"No .jar/.class/.war/.ear or .java under {directory} "
            f"(recursive={self.recursive}). "
            f"Put a JAR into target/ (default input) or pass -i /path/to/app.jar"
        )

    def _iter_binaries(self, directory: Path):
        it = directory.rglob if self.recursive else directory.glob
        for path in sorted(it("*")):
            if path.is_file() and path.suffix.lower() in JAVA_SUFFIXES:
                yield path

    def _iter_java(self, directory: Path):
        it = directory.rglob if self.recursive else directory.glob
        yield from sorted(p for p in it("*.java") if p.is_file())

    def _copy_sources(self, java_file: Path) -> Path:
        root = self.output_dir / java_file.stem
        if root.exists():
            shutil.rmtree(root)
        dirs = ensure_source_project(root)
        shutil.copy2(java_file, dirs["app"] / java_file.name)
        write_readme(root, java_file.stem)
        self._write_meta(dirs["root"], "source=local\nlayout=source\n")
        return root

    @staticmethod
    def _write_meta(path: Path, text: str) -> None:
        path.mkdir(parents=True, exist_ok=True)
        (path / ".sast_meta").write_text(text, encoding="utf-8")
