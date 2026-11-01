"""Evidence store: schema, models, migrations and stores (```` §2.4).

S1 delivers the schema (nine tables, Alembic-versioned), the engine/session helpers, and
the SQL audit sink. Query/repository helpers and the report-facing reads arrive with the
orchestration and report stages.
"""

from __future__ import annotations

from arachne.data.audit_sink import SqlAuditSink
from arachne.data.db import create_db_engine, create_session_factory, session_scope
from arachne.data.models import (
    AnalysisLog,
    Asset,
    AuditLog,
    Base,
    Check,
    Evidence,
    Finding,
    Scan,
    ScanDiff,
    Target,
)
from arachne.data.schema import LATEST_SCHEMA_REVISION, TABLE_NAMES

__all__ = [
    "LATEST_SCHEMA_REVISION",
    "TABLE_NAMES",
    "AnalysisLog",
    "Asset",
    "AuditLog",
    "Base",
    "Check",
    "Evidence",
    "Finding",
    "Scan",
    "ScanDiff",
    "SqlAuditSink",
    "Target",
    "create_db_engine",
    "create_session_factory",
    "session_scope",
]
