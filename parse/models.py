"""Graph-oriented intermediate models extracted from AST."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ParameterInfo:
    name: str
    type_name: str = ""
    index: int = 0


@dataclass
class CallSite:
    """One method_invocation / object creation inside a method."""

    callee_name: str
    receiver: str = ""  # e.g. this, Runtime, ois, ""
    arguments: list[str] = field(default_factory=list)  # raw expr texts
    line: int = 0
    is_constructor: bool = False
    # Filled by JavaParseIr / SymbolSolver when available, e.g. pkg.Type#method(String)
    resolved_qn: str = ""


@dataclass
class AssignmentInfo:
    """Simple assignment / declarator: lhs = rhs (for taint)."""

    lhs: str
    rhs: str
    line: int = 0


@dataclass
class MethodInfo:
    name: str
    qualified_name: str
    return_type: str = ""
    parameters: list[ParameterInfo] = field(default_factory=list)
    start_line: int = 0
    end_line: int = 0
    calls: list[str] = field(default_factory=list)  # unique callee names
    call_sites: list[CallSite] = field(default_factory=list)
    assignments: list[AssignmentInfo] = field(default_factory=list)


@dataclass
class FieldInfo:
    name: str
    type_name: str = ""
    resolved_type: str = ""  # FQCN from SymbolSolver when available
    is_static: bool = False
    is_transient: bool = False
    is_final: bool = False
    start_line: int = 0


@dataclass
class TypeInfo:
    name: str
    qualified_name: str
    kind: str  # class | interface | enum | record
    package: str = ""
    file_path: str = ""
    extends: list[str] = field(default_factory=list)
    implements: list[str] = field(default_factory=list)
    methods: list[MethodInfo] = field(default_factory=list)
    fields: list[FieldInfo] = field(default_factory=list)
    start_line: int = 0
    end_line: int = 0


@dataclass
class FileInfo:
    path: str
    language: str
    package: str = ""
    imports: list[str] = field(default_factory=list)
    types: list[TypeInfo] = field(default_factory=list)


@dataclass
class ParseResult:
    project: str
    files: list[FileInfo] = field(default_factory=list)

    @property
    def type_count(self) -> int:
        return sum(len(f.types) for f in self.files)

    @property
    def method_count(self) -> int:
        return sum(len(t.methods) for f in self.files for t in f.types)

    @property
    def call_site_count(self) -> int:
        return sum(
            len(m.call_sites) for f in self.files for t in f.types for m in t.methods
        )
