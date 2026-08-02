"""Hardcoded test-env config for parse module."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = ROOT / "tmpwork"

# Prefer reverse layout: only business sources under */app/
# (skip lib/ and source_cache/ to keep call graph focused)
PREFER_APP_SOURCES = True
SKIP_DIR_NAMES = {
    "source_cache",
    ".unpack",
    ".git",
    "__pycache__",
    "lib",  # dependency sources — optional; skip by default for app call graph
    "resources",
}

# Neo4j — 本机已有实例（docker run … NEO4J_AUTH=none，见 README）
NEO4J_URI = "bolt://127.0.0.1:7687"
NEO4J_USER = ""
NEO4J_PASSWORD = ""
NEO4J_AUTH = None  # NEO4J_AUTH=none
NEO4J_DATABASE = "neo4j"

LANGUAGE_EXTENSIONS = {
    ".java": "java",
}

# Larger batches cut Neo4j round-trips on full-JDK imports (~10k+ files).
BATCH_SIZE = 2000

# Universal / meaningless static receivers: treat as "could be any type",
# so CHA must NOT materialize CALLS/POINTS_TO edges to every subtype.
CHA_NO_EXPAND_TYPES = frozenset(
    {
        "Object",
        "java.lang.Object",
        # marker / too broad for call fan-out
        "Serializable",
        "java.io.Serializable",
        "Externalizable",
        "java.io.Externalizable",
        "Cloneable",
        "java.lang.Cloneable",
        "Comparable",
        "java.lang.Comparable",
        "CharSequence",
        "java.lang.CharSequence",
        "Iterable",
        "java.lang.Iterable",
    }
)

# Safety cap when CHA still expands (e.g. Map.get → many Map impls)
CHA_MAX_CALLEES = 32
# Prefer these packages when truncating CHA targets
CHA_PREFER_SUBSTRINGS = (
    "commons.collections",
    "AnnotationInvocationHandler",
    "TiedMapEntry",
    "LazyMap",
    "BadAttributeValueExpException",
    "TemplatesImpl",
    "TrAXFilter",
    "InvokerTransformer",
    "InstantiateTransformer",
    "ChainedTransformer",
    "TransformedMap",
    "TransformingComparator",
    "PriorityQueue",
    "Hashtable",
    "HashMap",
    "HashSet",
)


def is_cha_no_expand(type_name: str) -> bool:
    """True if type is universal — do not CHA-expand to subtypes / draw fan-out edges."""
    raw = (type_name or "").strip()
    if not raw:
        return False
    # strip generics / arrays
    raw = raw.split("<", 1)[0].strip()
    while raw.endswith("[]"):
        raw = raw[:-2].strip()
    if raw in CHA_NO_EXPAND_TYPES:
        return True
    simple = raw.rsplit(".", 1)[-1]
    return simple in CHA_NO_EXPAND_TYPES
