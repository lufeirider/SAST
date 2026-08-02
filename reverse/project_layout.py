"""Arrange recovered sources into a pure source tree (no jar/class leftovers)."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

# Binary leftovers that must not appear in the final source tree
BINARY_SUFFIXES = {".jar", ".class", ".war", ".ear", ".dll", ".so", ".dylib"}


def link_or_copy(src: Path, dest: Path) -> Path:
    """Point dest at src via symlink, or copytree if symlink fails."""
    src = Path(src).resolve()
    dest = Path(dest)
    if dest.exists() or dest.is_symlink():
        if dest.is_symlink() and dest.resolve() == src:
            return dest
        if dest.is_dir() and not dest.is_symlink() and any(dest.rglob("*.java")):
            return dest
        if dest.is_symlink() or dest.is_file():
            dest.unlink()
        else:
            shutil.rmtree(dest)

    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        dest.symlink_to(src, target_is_directory=True)
    except OSError:
        shutil.copytree(src, dest)
    return dest


def install_sources(source_tree: Path, dest_dir: Path) -> Path:
    """
    Install a source tree (package roots at top: com/, org/, ...) into dest_dir.
    Pure source mode — no src/main/java wrapper.
    """
    dest_dir = Path(dest_dir)
    link_or_copy(source_tree, dest_dir)
    return dest_dir


def ensure_source_project(project_root: Path) -> dict[str, Path]:
    """
    Pure source layout:

      app/           application .java (package dirs)
      resources/     non-java resources
      lib/<dep>/     dependency sources (package dirs)
    """
    root = Path(project_root)
    root.mkdir(parents=True, exist_ok=True)
    paths = {
        "root": root,
        "app": root / "app",
        "resources": root / "resources",
        "lib": root / "lib",
    }
    for key in ("app", "resources", "lib"):
        paths[key].mkdir(parents=True, exist_ok=True)
    return paths


def copy_resources(classes_dir: Path, resources_dir: Path) -> int:
    """Copy non-class/non-jar files from unpacked classes into resources/."""
    classes_dir = Path(classes_dir)
    resources_dir = Path(resources_dir)
    count = 0
    if not classes_dir.is_dir():
        return 0
    for path in classes_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in BINARY_SUFFIXES:
            continue
        rel = path.relative_to(classes_dir)
        dest = resources_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
        count += 1
    return count


def scrub_binaries(root: Path) -> int:
    """Remove any jar/class (etc.) that slipped into the source tree."""
    removed = 0
    root = Path(root)
    if not root.exists():
        return 0
    for path in sorted(root.rglob("*"), reverse=True):
        if not path.is_file():
            continue
        # follow_symlinks=False — don't delete through cache symlinks' targets wrongly;
        # only remove binary files that are real files inside the project.
        if path.is_symlink():
            continue
        if path.suffix.lower() in BINARY_SUFFIXES:
            path.unlink(missing_ok=True)
            removed += 1
    if removed:
        logger.info("Scrubbed %d binary files from %s", removed, root)
    return removed


def write_readme(project_root: Path, title: str) -> None:
    text = f"""# {title}

纯源码输出（sast/reverse）：

```
app/                 # 业务 Java 源码（包路径）
resources/           # 配置等资源
lib/<dependency>/    # 依赖源码（下载或反编译）
```

不含 .jar / .class。
"""
    (Path(project_root) / "README.md").write_text(text, encoding="utf-8")
