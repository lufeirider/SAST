"""Hardcoded test-env config for the analyze module."""

from pathlib import Path

from rules.sinks import sink_function_names

ROOT = Path(__file__).resolve().parent.parent

# Neo4j — 本机已有实例（docker run … NEO4J_AUTH=none，见 README）
NEO4J_URI = "bolt://127.0.0.1:7687"
NEO4J_USER = ""
NEO4J_PASSWORD = ""
NEO4J_AUTH = None  # NEO4J_AUTH=none
NEO4J_DATABASE = "neo4j"

# Sink method simple names from Tabby rules/sinks.json
# Full class+method matching lives in rules.sinks.match_sink_call
SINK_NAMES = set(sink_function_names())

# 污点分析模式（可用 CLI --mode 覆盖）
# - vuln:   找漏洞 — source = 方法参数
# - gadget: 找 gadget — source = 类字段 + readObject/readExternal 入口
TAINT_MODE = "vuln"

# Source kinds
# - param: method formal parameters
# - field: class attributes (this.xxx / field name)
SOURCE_KINDS = ("param", "field")
