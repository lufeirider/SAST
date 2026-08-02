"""Detect and unpack fat / Spring Boot / WAR archives."""

from __future__ import annotations

import logging
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

NESTED_LIB_PREFIXES = (
    "BOOT-INF/lib/",
    "WEB-INF/lib/",
    "lib/",
)
APP_CLASS_PREFIXES = (
    "BOOT-INF/classes/",
    "WEB-INF/classes/",
)


@dataclass
class FatJarLayout:
    archive: Path
    is_fat: bool
    manifest: dict[str, str] = field(default_factory=dict)
    nested_jars: list[str] = field(default_factory=list)  # zip entry names
    app_class_prefix: str | None = None  # e.g. BOOT-INF/classes/
    extract_root: Path | None = None
    nested_jar_paths: list[Path] = field(default_factory=list)
    app_classes_dir: Path | None = None


def read_manifest(jar_path: Path) -> dict[str, str]:
    """Parse META-INF/MANIFEST.MF into a flat dict (handles continuation lines)."""
    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            try:
                raw = zf.read("META-INF/MANIFEST.MF").decode("utf-8", errors="ignore")
            except KeyError:
                return {}
    except (zipfile.BadZipFile, OSError):
        return {}

    manifest: dict[str, str] = {}
    key = None
    for line in raw.splitlines():
        if not line:
            key = None
            continue
        if line.startswith(" ") and key:
            manifest[key] += line[1:]
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            key = k.strip()
            manifest[key] = v.strip()
    return manifest


def inspect_archive(jar_path: Path) -> FatJarLayout:
    jar_path = Path(jar_path)
    manifest = read_manifest(jar_path)
    nested: list[str] = []
    app_prefix = None

    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError) as exc:
        logger.warning("Cannot inspect %s: %s", jar_path, exc)
        return FatJarLayout(archive=jar_path, is_fat=False, manifest=manifest)

    for name in names:
        if name.endswith(".jar") and any(name.startswith(p) for p in NESTED_LIB_PREFIXES):
            nested.append(name)

    # Prefer MANIFEST Spring-Boot-Classes
    sb_classes = manifest.get("Spring-Boot-Classes", "").strip()
    if sb_classes:
        app_prefix = sb_classes if sb_classes.endswith("/") else sb_classes + "/"
    else:
        for prefix in APP_CLASS_PREFIXES:
            if any(n.startswith(prefix) and n.endswith(".class") for n in names):
                app_prefix = prefix
                break

    is_fat = bool(nested) or bool(app_prefix) or "Spring-Boot-Version" in manifest
    return FatJarLayout(
        archive=jar_path,
        is_fat=is_fat,
        manifest=manifest,
        nested_jars=sorted(nested),
        app_class_prefix=app_prefix,
    )


def unpack_archive(jar_path: Path, output_dir: Path) -> FatJarLayout:
    """
    Unpack nested lib jars + app classes from a fat/Spring Boot/WAR archive.

    Layout:
      output_dir/
        libs/          extracted nested jars
        classes/       BOOT-INF/classes (or WEB-INF/classes) contents
        MANIFEST.MF
    """
    layout = inspect_archive(jar_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    layout.extract_root = output_dir

    libs_dir = output_dir / "libs"
    classes_dir = output_dir / "classes"
    libs_dir.mkdir(exist_ok=True)

    with zipfile.ZipFile(jar_path, "r") as zf:
        # save manifest text
        if "META-INF/MANIFEST.MF" in zf.namelist():
            (output_dir / "MANIFEST.MF").write_bytes(zf.read("META-INF/MANIFEST.MF"))

        for entry in layout.nested_jars:
            dest = libs_dir / Path(entry).name
            if not dest.exists():
                dest.write_bytes(zf.read(entry))
            layout.nested_jar_paths.append(dest)

        if layout.app_class_prefix:
            classes_dir.mkdir(exist_ok=True)
            prefix = layout.app_class_prefix
            for name in zf.namelist():
                if not name.startswith(prefix) or name.endswith("/"):
                    continue
                rel = name[len(prefix) :]
                if not rel:
                    continue
                out = classes_dir / rel
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(zf.read(name))
            layout.app_classes_dir = classes_dir

    logger.info(
        "Unpacked fat jar %s -> libs=%d classes=%s",
        jar_path.name,
        len(layout.nested_jar_paths),
        layout.app_classes_dir,
    )
    return layout
