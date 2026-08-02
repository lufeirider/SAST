"""Shared analysis rules (Tabby-compatible sinks, etc.)."""

from rules.sinks import (
    SinkMatch,
    SinkRule,
    is_gadget_entry_method,
    load_sink_rules,
    match_sink_call,
    sink_function_names,
)

__all__ = [
    "SinkMatch",
    "SinkRule",
    "is_gadget_entry_method",
    "load_sink_rules",
    "match_sink_call",
    "sink_function_names",
]
