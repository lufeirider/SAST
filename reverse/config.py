"""Hardcoded test-env config for reverse module."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = ROOT / "target"
DEFAULT_OUTPUT = ROOT / "tmpwork"
# Persistent Maven sources cache (survives per-jar clean under tmpwork/<name>/)
SOURCE_CACHE_DIR = DEFAULT_OUTPUT / "source_cache"
TOOLS_DIR = Path(__file__).resolve().parent / "tools"

# CFR decompiler (downloaded on first use)
CFR_VERSION = "0.152"
CFR_JAR_NAME = f"cfr-{CFR_VERSION}.jar"
CFR_URL = f"https://repo1.maven.org/maven2/org/benf/cfr/{CFR_VERSION}/{CFR_JAR_NAME}"

# Maven Central
MAVEN_CENTRAL_SEARCH = "https://search.maven.org/solrsearch/select"
MAVEN_CENTRAL_REPO = "https://repo1.maven.org/maven2"

# Prefer sources over decompilation when possible
PREFER_SOURCE_DOWNLOAD = True

# Parallelism (test env)
DOWNLOAD_WORKERS = 8
DECOMPILE_WORKERS = 4

# Nested dependency jars: download sources first; fall back to CFR when miss
# (app BOOT-INF/classes is always decompiled — that is the target code)
DECOMPILE_MISSING_LIBS = True

# Skip nested jars that look like Spring Boot loader tooling
SKIP_NESTED_NAME_SUBSTRINGS = (
    "spring-boot-jarmode-layertools",
)
