"""Neo4j schema for code graph + findings."""

CONSTRAINTS = [
    """
    CREATE CONSTRAINT project_name IF NOT EXISTS
    FOR (p:Project) REQUIRE p.name IS UNIQUE
    """,
    """
    CREATE CONSTRAINT file_path IF NOT EXISTS
    FOR (f:File) REQUIRE f.path IS UNIQUE
    """,
    """
    CREATE CONSTRAINT type_qn IF NOT EXISTS
    FOR (t:Type) REQUIRE t.qualified_name IS UNIQUE
    """,
    """
    CREATE CONSTRAINT method_qn IF NOT EXISTS
    FOR (m:Method) REQUIRE m.qualified_name IS UNIQUE
    """,
    """
    CREATE CONSTRAINT finding_id IF NOT EXISTS
    FOR (f:Finding) REQUIRE f.id IS UNIQUE
    """,
    """
    CREATE CONSTRAINT field_key IF NOT EXISTS
    FOR (f:Field) REQUIRE f.key IS UNIQUE
    """,
    """
    CREATE CONSTRAINT call_site_id IF NOT EXISTS
    FOR (c:CallSite) REQUIRE c.id IS UNIQUE
    """,
]

INDEXES = [
    """
    CREATE INDEX type_name IF NOT EXISTS
    FOR (t:Type) ON (t.name)
    """,
    """
    CREATE INDEX method_name IF NOT EXISTS
    FOR (m:Method) ON (m.name)
    """,
    """
    CREATE INDEX type_project IF NOT EXISTS
    FOR (t:Type) ON (t.project)
    """,
    """
    CREATE INDEX method_project IF NOT EXISTS
    FOR (m:Method) ON (m.project)
    """,
    """
    CREATE INDEX method_sink IF NOT EXISTS
    FOR (m:Method) ON (m.is_sink)
    """,
    """
    CREATE INDEX field_project IF NOT EXISTS
    FOR (f:Field) ON (f.project)
    """,
    """
    CREATE INDEX call_site_project IF NOT EXISTS
    FOR (c:CallSite) ON (c.project)
    """,
]

# Graph model:
# (:Project)-[:HAS_FILE]->(:File)-[:DECLARES]->(:Type)
# (:Type)-[:HAS_METHOD]->(:Method)
# (:Type)-[:HAS_FIELD]->(:Field)
# (:Type)-[:EXTENDS|IMPLEMENTS]->(:Type)
# (:Field)-[:DECLARED_TYPE]->(:Type)          # erased declared type (import)
# (:Field)-[:POINTS_TO]->(:Type)              # import: declared only
# (:Type)-[:MAY_REF {field, serializable_write}]->(:Type)  # import: declared only
# Method.parameters / Method.param_names stored as props (no Parameter nodes)
# (:Method)-[:CALLS]->(:Method)               # import: resolved target only (no CHA)
# (:Method)-[:CHA_CALLS]->(:Method)           # analyze-time CHA fan-out
# (:Type)-[:CHA_REF {field,...}]->(:Type)     # analyze-time field CHA fan-out
# (:Method)-[:HAS_CALL_SITE]->(:CallSite)-[:RESOLVED_TO]->(:Method)
# (:Finding)-[:IN_METHOD]->(:Method)
# (:Finding)-[:SINKS_TO]->(:Method)
