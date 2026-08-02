"""
Resolve & fetch Java sources for a given binary JAR.

JAR-centric identify order:
  1) Local sibling *-sources.jar
  2) Embedded META-INF/maven/*/pom.properties
  3) MANIFEST.MF + filename → probe Maven Central by likely groupIds (HEAD)
  4) Maven Central search API (ranked)
  5) JAR SHA1 (last resort, short timeout)

SNAPSHOT versions skip remote download.
"""

from __future__ import annotations

import hashlib
import logging
import re
import shutil
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional
from urllib.parse import quote

import requests

from reverse.config import (
    DOWNLOAD_WORKERS,
    MAVEN_CENTRAL_REPO,
    MAVEN_CENTRAL_SEARCH,
    SOURCE_CACHE_DIR,
)
from reverse.unpack.fatjar import read_manifest

logger = logging.getLogger(__name__)

# Fast path: guess groupId from well-known artifact name prefixes
GROUP_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^spring-boot"), "org.springframework.boot"),
    (re.compile(r"^spring-"), "org.springframework"),
    (re.compile(r"^tomcat-embed-"), "org.apache.tomcat.embed"),
    (re.compile(r"^tomcat-"), "org.apache.tomcat"),
    (re.compile(r"^jackson-databind$"), "com.fasterxml.jackson.core"),
    (re.compile(r"^jackson-core$"), "com.fasterxml.jackson.core"),
    (re.compile(r"^jackson-annotations$"), "com.fasterxml.jackson.core"),
    (re.compile(r"^jackson-datatype-"), "com.fasterxml.jackson.datatype"),
    (re.compile(r"^jackson-module-"), "com.fasterxml.jackson.module"),
    (re.compile(r"^logback-"), "ch.qos.logback"),
    (re.compile(r"^log4j-"), "org.apache.logging.log4j"),
    (re.compile(r"^slf4j-"), "org.slf4j"),
    (re.compile(r"^jul-to-slf4j$"), "org.slf4j"),
    (re.compile(r"^snakeyaml$"), "org.yaml"),
    (re.compile(r"^jakarta\.annotation-api$"), "jakarta.annotation"),
]


class JarSourceResolver:
    """Given a JAR path, try to obtain its original sources."""

    def __init__(
        self,
        timeout: int = 15,
        search_timeout: int = 8,
        workers: int = DOWNLOAD_WORKERS,
        cache_dir: Path | None = None,
    ):
        self.timeout = timeout
        self.search_timeout = search_timeout
        self.workers = workers
        self.cache_dir = Path(cache_dir or SOURCE_CACHE_DIR)
        self._headers = {"User-Agent": "sast-reverse/0.1"}
        self._cache_lock = threading.Lock()
        # in-process memo: GAV -> extracted cache path | None (known miss)
        self._mem: dict[tuple[str, str, str], Optional[Path]] = {}

    def _get(self, url: str, timeout: int | None = None, **kwargs):
        kwargs.setdefault("headers", self._headers)
        return requests.get(url, timeout=timeout or self.timeout, **kwargs)

    def _head(self, url: str, timeout: int | None = None, **kwargs):
        kwargs.setdefault("headers", self._headers)
        kwargs.setdefault("allow_redirects", True)
        return requests.head(url, timeout=timeout or self.timeout, **kwargs)

    def try_get_sources(self, jar_path: Path, output_dir: Path | None = None) -> Optional[Path]:
        """
        Resolve sources for jar.

        Returns extracted source tree path (usually under source_cache).
        If output_dir is set, also materialize a copy/symlink there.
        """
        jar_path = Path(jar_path)
        tree = self.resolve_source_tree(jar_path)
        if tree is None:
            return None
        if output_dir is not None:
            safe = f"{jar_path.stem}-sources"
            return self._materialize(tree, Path(output_dir) / safe)
        return tree

    def resolve_source_tree(self, jar_path: Path) -> Optional[Path]:
        """Return cached/extracted source root for this jar (no project layout)."""
        jar_path = Path(jar_path)
        # local sibling sources jar → extract into cache-like staging under cache_dir/_local
        local_jar = self._find_local_sources_jar(jar_path)
        if local_jar is not None:
            dest = self.cache_dir / "_local" / jar_path.stem / "content"
            if not (dest.exists() and any(dest.rglob("*.java"))):
                self._extract_sources_jar(local_jar, dest, meta_extra="source=local-sibling\n")
            return dest

        identity = self._identify_jar(jar_path)
        if not identity:
            logger.info("Cannot identify JAR %s; skip source download", jar_path.name)
            return None

        group_id, artifact_id, version = identity
        if self._is_snapshot(version):
            logger.info(
                "Skip remote sources for SNAPSHOT %s (%s:%s:%s)",
                jar_path.name,
                group_id,
                artifact_id,
                version,
            )
            return None

        return self._download_to_cache(group_id, artifact_id, version, jar_path.name)

    def try_get_sources_many(
        self, jars: list[Path], output_dir: Path | None = None
    ) -> dict[Path, Optional[Path]]:
        """Parallel resolve; values are source-tree paths (cache), not project dirs."""
        results: dict[Path, Optional[Path]] = {}
        if not jars:
            return results

        def _one(jar: Path) -> tuple[Path, Optional[Path]]:
            try:
                tree = self.resolve_source_tree(jar)
                if tree is not None and output_dir is not None:
                    tree = self._materialize(
                        tree, Path(output_dir) / jar.stem / f"{jar.stem}-sources"
                    )
                return jar, tree
            except Exception as exc:  # noqa: BLE001
                logger.warning("Source resolve failed for %s: %s", jar.name, exc)
                return jar, None

        workers = min(self.workers, max(1, len(jars)))
        logger.info("Resolving sources for %d jars (workers=%d)", len(jars), workers)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(_one, j) for j in jars]
            for fut in as_completed(futs):
                jar, path = fut.result()
                results[jar] = path
                logger.info("  [%s] %s", "OK" if path else "miss", jar.name)
        return results

    def _find_local_sources_jar(self, jar_path: Path) -> Optional[Path]:
        candidates = [
            jar_path.with_name(f"{jar_path.stem}-sources.jar"),
            jar_path.with_name(jar_path.name.replace(".jar", "-sources.jar")),
        ]
        for candidate in candidates:
            if candidate.is_file() and candidate.resolve() != jar_path.resolve():
                logger.info("Found local sources jar: %s", candidate)
                return candidate
        return None

    def _identify_jar(self, jar_path: Path) -> Optional[tuple[str, str, str]]:
        # 1) embedded pom — most reliable for nested libs
        from_pom = self._identity_from_embedded_pom(jar_path)
        if from_pom:
            logger.info(
                "Identified %s via pom.properties: %s:%s:%s", jar_path.name, *from_pom
            )
            return from_pom

        parsed = guess_artifact_from_filename(jar_path.name)
        mf = read_manifest(jar_path)
        artifact = None
        version = None
        if parsed:
            artifact, version = parsed
        if mf:
            version = version or mf.get("Implementation-Version") or mf.get(
                "Bundle-Version"
            )
            if version:
                version = version.strip()
            title = (
                mf.get("Implementation-Title")
                or mf.get("Automatic-Module-Name")
                or ""
            ).strip()
            if not artifact and title and re.match(r"^[\w.\-]+$", title):
                artifact = title

        # 2) filename/MANIFEST → probe Central with group hints (no search API)
        if artifact and version:
            probed = self._probe_groups(jar_path, artifact, version, mf)
            if probed:
                logger.info(
                    "Identified %s via MANIFEST/filename probe: %s:%s:%s",
                    jar_path.name,
                    *probed,
                )
                return probed

        # 3) Maven search API (ranked)
        if artifact and version:
            searched = self._resolve_group(artifact, version)
            if searched:
                logger.info(
                    "Identified %s via Maven search: %s:%s:%s",
                    jar_path.name,
                    *searched,
                )
                return searched

        # 4) SHA1 last
        from_sha1 = self._identity_from_sha1(jar_path)
        if from_sha1:
            logger.info(
                "Identified %s via JAR SHA1: %s:%s:%s", jar_path.name, *from_sha1
            )
            return from_sha1

        return None

    def _probe_groups(
        self,
        jar_path: Path,
        artifact: str,
        version: str,
        mf: dict[str, str],
    ) -> Optional[tuple[str, str, str]]:
        candidates: list[str] = []

        for pattern, group in GROUP_HINTS:
            if pattern.search(artifact):
                candidates.append(group)

        vendor = (mf.get("Implementation-Vendor-Id") or "").strip()
        if vendor and re.match(r"^[\w.]+$", vendor):
            candidates.append(vendor)

        bsn = (mf.get("Bundle-SymbolicName") or "").split(";")[0].strip()
        if bsn and "." in bsn:
            parts = bsn.split(".")
            if len(parts) >= 2:
                candidates.append(".".join(parts[:-1]))

        # dedupe preserve order
        seen: set[str] = set()
        groups: list[str] = []
        for g in candidates:
            if g not in seen:
                seen.add(g)
                groups.append(g)

        for group in groups:
            url = self._sources_url(group, artifact, version)
            try:
                resp = self._head(url, timeout=5)
                if resp.status_code == 200:
                    return group, artifact, version
            except requests.RequestException:
                continue
        return None

    def _identity_from_embedded_pom(
        self, jar_path: Path
    ) -> Optional[tuple[str, str, str]]:
        try:
            with zipfile.ZipFile(jar_path, "r") as zf:
                pom_names = [
                    n
                    for n in zf.namelist()
                    if n.startswith("META-INF/maven/")
                    and n.endswith("/pom.properties")
                ]
                if not pom_names:
                    return None
                chosen = pom_names[0]
                stem = jar_path.stem.lower()
                for name in pom_names:
                    if any(part.lower() in stem for part in Path(name).parts):
                        chosen = name
                        break

                text = zf.read(chosen).decode("utf-8", errors="ignore")
                props = {}
                for line in text.splitlines():
                    if "=" in line and not line.strip().startswith("#"):
                        k, v = line.split("=", 1)
                        props[k.strip()] = v.strip()
                group = props.get("groupId")
                artifact = props.get("artifactId")
                version = props.get("version")
                if group and artifact and version:
                    return group, artifact, version
        except (zipfile.BadZipFile, KeyError, OSError) as exc:
            logger.debug("Embedded pom parse failed for %s: %s", jar_path, exc)
        return None

    def _identity_from_sha1(self, jar_path: Path) -> Optional[tuple[str, str, str]]:
        sha1 = hashlib.sha1(jar_path.read_bytes()).hexdigest()
        params = {"q": f"1:{sha1}", "rows": 1, "wt": "json"}
        try:
            resp = self._get(
                MAVEN_CENTRAL_SEARCH, params=params, timeout=self.search_timeout
            )
            resp.raise_for_status()
            docs = resp.json().get("response", {}).get("docs", [])
            if not docs:
                return None
            doc = docs[0]
            return doc["g"], doc["a"], doc["v"]
        except (requests.RequestException, KeyError, ValueError) as exc:
            logger.debug("SHA1 search failed: %s", exc)
            return None

    def _resolve_group(
        self, artifact_id: str, version: str
    ) -> Optional[tuple[str, str, str]]:
        params = {
            "q": f'a:"{artifact_id}" AND v:"{version}"',
            "rows": 20,
            "wt": "json",
        }
        try:
            resp = self._get(
                MAVEN_CENTRAL_SEARCH, params=params, timeout=self.search_timeout
            )
            resp.raise_for_status()
            docs = resp.json().get("response", {}).get("docs", [])
            if not docs:
                return None
            doc = self._pick_best_doc(docs, artifact_id, version)
            if not doc:
                return None
            return doc["g"], doc["a"], doc["v"]
        except (requests.RequestException, KeyError, ValueError) as exc:
            logger.debug("Group resolve failed: %s", exc)
            return None

    @staticmethod
    def _pick_best_doc(
        docs: list[dict], artifact_id: str, version: str
    ) -> Optional[dict]:
        exact = [
            d for d in docs if d.get("a") == artifact_id and d.get("v") == version
        ] or list(docs)

        def score(d: dict) -> int:
            g = d.get("g", "")
            s = 0
            for pattern, group in GROUP_HINTS:
                if pattern.search(artifact_id) and g == group:
                    s += 100
            if g.startswith("org.") or g.startswith("com.") or g.startswith("jakarta."):
                s += 10
            if any(x in g for x in ("xdob", "example", "test", "fork")):
                s -= 80
            # prefer shorter, conventional coordinates
            s -= g.count(".") 
            return s

        return max(exact, key=score)

    def _cache_gav_dir(self, group_id: str, artifact_id: str, version: str) -> Path:
        """tmpwork/source_cache/<group.path>/<artifact>/<version>/"""
        return (
            self.cache_dir
            / group_id.replace(".", "/")
            / artifact_id
            / version
        )

    def _download_to_cache(
        self,
        group_id: str,
        artifact_id: str,
        version: str,
        jar_name: str,
    ) -> Optional[Path]:
        """Download/extract into source_cache; return content dir or None."""
        key = (group_id, artifact_id, version)
        safe_name = f"{artifact_id}-{version}-sources"

        with self._cache_lock:
            if key in self._mem:
                return self._mem[key]

        gav_dir = self._cache_gav_dir(group_id, artifact_id, version)
        content_dir = gav_dir / "content"
        missing_marker = gav_dir / ".missing"
        sources_jar = gav_dir / f"{safe_name}.jar"

        if missing_marker.exists():
            logger.info("Cache miss-marker for %s (skip download)", jar_name)
            with self._cache_lock:
                self._mem[key] = None
            return None

        if content_dir.exists() and any(content_dir.rglob("*.java")):
            logger.info("Cache hit %s -> %s", jar_name, content_dir)
            with self._cache_lock:
                self._mem[key] = content_dir
            return content_dir

        if sources_jar.exists() and sources_jar.stat().st_size > 0:
            logger.info("Cache hit (jar) %s -> extract", jar_name)
            self._extract_sources_jar(
                sources_jar,
                content_dir,
                meta_extra=f"gav={group_id}:{artifact_id}:{version}\ncache=1\n",
            )
            with self._cache_lock:
                self._mem[key] = content_dir
            return content_dir

        sources_url = self._sources_url(group_id, artifact_id, version)
        logger.info("Downloading sources for JAR %s <- %s", jar_name, sources_url)

        try:
            head = self._head(sources_url, timeout=5)
            if head.status_code == 404:
                logger.info("Sources not published for %s (404)", jar_name)
                self._mark_missing(gav_dir, missing_marker)
                with self._cache_lock:
                    self._mem[key] = None
                return None
            resp = self._get(sources_url)
            if resp.status_code != 200:
                logger.info(
                    "Sources not published for %s (%s)", jar_name, resp.status_code
                )
                if resp.status_code == 404:
                    self._mark_missing(gav_dir, missing_marker)
                    with self._cache_lock:
                        self._mem[key] = None
                return None
        except requests.RequestException as exc:
            logger.warning("Source download failed for %s: %s", jar_name, exc)
            return None

        gav_dir.mkdir(parents=True, exist_ok=True)
        sources_jar.write_bytes(resp.content)
        self._extract_sources_jar(
            sources_jar,
            content_dir,
            meta_extra=f"gav={group_id}:{artifact_id}:{version}\ncache=1\n",
        )
        with self._cache_lock:
            self._mem[key] = content_dir
        logger.info(
            "Cached sources %s:%s:%s -> %s", group_id, artifact_id, version, content_dir
        )
        return content_dir

    @staticmethod
    def _mark_missing(gav_dir: Path, marker: Path) -> None:
        gav_dir.mkdir(parents=True, exist_ok=True)
        marker.write_text("404\n", encoding="utf-8")

    def _materialize(self, cache_content: Path, dest: Path) -> Path:
        """
        Place cached sources into the per-run output dir.
        Prefer symlink to avoid copying; fall back to copytree.
        """
        dest = Path(dest)
        if dest.exists():
            if dest.is_symlink() or dest.resolve() == cache_content.resolve():
                return dest
            # already populated
            if any(dest.rglob("*.java")):
                return dest

        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            if dest.exists() or dest.is_symlink():
                if dest.is_dir() and not dest.is_symlink():
                    shutil.rmtree(dest)
                else:
                    dest.unlink()
            dest.symlink_to(cache_content.resolve(), target_is_directory=True)
            return dest
        except OSError:
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(cache_content, dest)
            return dest

    @staticmethod
    def _extract_sources_jar(
        sources_jar: Path,
        extract_dir: Path,
        meta_extra: str = "",
    ) -> Path:
        extract_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(sources_jar, "r") as zf:
            zf.extractall(extract_dir)
        logger.info("Extracted sources -> %s", extract_dir)
        (extract_dir / ".sast_meta").write_text(
            f"source=jar-sources\nfrom={sources_jar.name}\n{meta_extra}",
            encoding="utf-8",
        )
        return extract_dir

    @staticmethod
    def _sources_url(group_id: str, artifact_id: str, version: str) -> str:
        group_path = group_id.replace(".", "/")
        return (
            f"{MAVEN_CENTRAL_REPO}/{group_path}/{quote(artifact_id)}/"
            f"{quote(version)}/{quote(artifact_id)}-{quote(version)}-sources.jar"
        )

    @staticmethod
    def _is_snapshot(version: str) -> bool:
        return version.upper().endswith("-SNAPSHOT") or "-SNAPSHOT-" in version.upper()


def guess_artifact_from_filename(name: str) -> Optional[tuple[str, str]]:
    m = re.match(r"^(.+?)-(\d[\w.\-]*)\.jar$", name, re.IGNORECASE)
    if not m:
        return None
    return m.group(1), m.group(2)


MavenSourceDownloader = JarSourceResolver
