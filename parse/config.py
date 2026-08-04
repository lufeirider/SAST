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
BATCH_SIZE = 4000

# JavaParseIr heap + parallel shards (full JDK mining)
JAVA_PARSE_XMX = "6g"
# Shard when emit root has at least this many .java files
PARSE_SHARD_MIN_FILES = 1500
# Parallel JavaParseIr processes (each gets JAVA_PARSE_XMX)
PARSE_SHARD_WORKERS = 4

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
        # Framework stream passed into readObject(s) — attacker does not
        # substitute IIOPInputStream for a normal ObjectInputStream.
        # CHA to CORBA overrides (IIOP#readInt → …) is a major FP source.
        "ObjectInputStream",
        "java.io.ObjectInputStream",
        "InputStreamHook",
        "com.sun.corba.se.impl.io.InputStreamHook",
    }
)

# ---------------------------------------------------------------------------
# CHA_MAX_CALLEES（强烈注意）
# 每个虚调用点做 CHA 时，最多只保留 N 个「子类型/实现类上的同名方法」。
# 不是「找到全部 CHA 类」，而是「CHA 候选排序后截断到前 N 个」（当前默认 100）。
# 例：Map.Entry#setValue 在 CC_FULL 可有 ~50+ 个 override；只留 24 时，
# AbstractInputCheckedMapDecorator.MapEntry#setValue 可能被裁掉 → CC1-1 断链。
# 当前 100：setValue 全收；Map#get(~96) 也基本全收；Collection#add(~195) 仍截断。
# 再调大可提高召回，但单点扇出与链数会明显上升。
# ---------------------------------------------------------------------------
CHA_MAX_CALLEES = 100
# Optional prefer substrings when truncating CHA (empty = no class allowlist)
CHA_PREFER_SUBSTRINGS: tuple[str, ...] = ()

# Object / interface methods that MUST keep CALLS edges so analyze-time CHA
# can specialize Object#toString / hashCode / equals onto overrides.
CHA_UNIVERSAL_VIRTUAL_METHODS = frozenset(
    {
        "toString",
        "hashCode",
        "equals",
        "setValue",
        "getValue",
        "compare",
    }
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


def is_universal_virtual_call(resolved_qn: str) -> bool:
    """True if CALLS to this resolved target should be kept despite CHA_NO_EXPAND owner.

    Object#toString / hashCode / equals are recorded so analyze-time CHA can
    specialize them onto overrides without exploding every Object call.
    """
    if not resolved_qn or "#" not in resolved_qn:
        return False
    owner, rest = resolved_qn.split("#", 1)
    if not is_cha_no_expand(owner):
        return False
    name = rest.split("(", 1)[0]
    return name in CHA_UNIVERSAL_VIRTUAL_METHODS
