"""Durable storage for website scan results.

Falls back to raw sqlite3 when SQLAlchemy is not installed so that the local
demo continues to work with the api+dev extras only. When the enterprise extra
is installed, SQLAlchemy is used automatically, which also unlocks PostgreSQL.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Any

try:
    from sqlalchemy import (
        Column, String, Integer, Text, Index, delete, func,
    )
    from sqlalchemy.orm import declarative_base, sessionmaker
    from sqlalchemy import create_engine as _create_engine
    _SA_AVAILABLE = True
except ImportError:  # pragma: no cover
    _SA_AVAILABLE = False

from .website_models import WebsiteScanResult


# ── SQLAlchemy ORM model (only defined when SA is available) ─────────────────
if _SA_AVAILABLE:
    _Base = declarative_base()

    class _WebsiteScanRecord(_Base):  # type: ignore[valid-type]
        __tablename__ = "website_scans"

        scan_id = Column(String, primary_key=True)
        target_origin = Column(String, nullable=False)
        final_url = Column(String, nullable=False)
        posture_classification = Column(String, nullable=False)
        score = Column(Integer, nullable=False)
        findings_count = Column(Integer, nullable=False)
        passed_count = Column(Integer, nullable=False)
        failed_count = Column(Integer, nullable=False)
        warning_count = Column(Integer, nullable=False)
        unknown_count = Column(Integer, nullable=False)
        rule_pack_version = Column(String, nullable=False)
        scan_timestamp = Column(String, nullable=False)
        limitations = Column(Text)
        findings_json = Column(Text, nullable=False)
        created_at = Column(String, nullable=False)

        __table_args__ = (
            Index("idx_target_origin", "target_origin"),
            Index("idx_scan_timestamp", "scan_timestamp"),
        )


# ── Shared helper ────────────────────────────────────────────────────────────

def _findings_to_json(result: WebsiteScanResult) -> str:
    return json.dumps([
        {
            "finding_id": f.finding_id,
            "rule_id": f.rule_id,
            "title": f.title,
            "status": f.status.value,
            "severity": f.severity.value,
            "evidence": {
                "check_type": f.evidence.check_type,
                "observed_value": f.evidence.observed_value,
                "expected_value": f.evidence.expected_value,
            },
            "rationale": f.rationale,
            "remediation": f.remediation,
            "observed_at": f.observed_at.isoformat(),
            "rule_version": f.rule_version,
            "limitations": f.limitations,
        }
        for f in result.findings
    ])


# ── SQLite fallback (no dependency) ─────────────────────────────────────────

class _SqliteStorage:
    """Raw sqlite3 implementation, used when SQLAlchemy is not installed."""

    def __init__(self, db_path: str) -> None:
        import sqlite3 as _sqlite3
        self._sqlite3 = _sqlite3
        if db_path.startswith("sqlite:///"):
            db_path = db_path[10:]
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _init_schema(self) -> None:
        with self._sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS website_scans (
                    scan_id TEXT PRIMARY KEY,
                    target_origin TEXT NOT NULL,
                    final_url TEXT NOT NULL,
                    posture_classification TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    findings_count INTEGER NOT NULL,
                    passed_count INTEGER NOT NULL,
                    failed_count INTEGER NOT NULL,
                    warning_count INTEGER NOT NULL,
                    unknown_count INTEGER NOT NULL,
                    rule_pack_version TEXT NOT NULL,
                    scan_timestamp TEXT NOT NULL,
                    limitations TEXT,
                    findings_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_target_origin ON website_scans(target_origin)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_timestamp  ON website_scans(scan_timestamp)")
            conn.commit()

    def save_scan(self, result: WebsiteScanResult) -> None:
        with self._sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO website_scans
                (scan_id, target_origin, final_url, posture_classification, score,
                 findings_count, passed_count, failed_count, warning_count, unknown_count,
                 rule_pack_version, scan_timestamp, limitations, findings_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result.scan_id,
                result.target_origin,
                result.final_url,
                result.posture_classification.value,
                result.score,
                len(result.findings),
                result.passed_count,
                result.failed_count,
                result.warning_count,
                result.unknown_count,
                result.rule_pack_version,
                result.scan_timestamp.isoformat(),
                result.limitations,
                _findings_to_json(result),
                datetime.now(timezone.utc).isoformat(),
            ))
            conn.commit()

    def get_scan(self, scan_id: str) -> Optional[dict[str, Any]]:
        with self._sqlite3.connect(self.db_path) as conn:
            conn.row_factory = self._sqlite3.Row
            row = conn.execute("SELECT * FROM website_scans WHERE scan_id = ?", (scan_id,)).fetchone()
            return dict(row) if row else None

    def get_scans_by_target(self, target_origin: str, limit: int = 10) -> list[dict[str, Any]]:
        with self._sqlite3.connect(self.db_path) as conn:
            conn.row_factory = self._sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM website_scans WHERE target_origin = ? ORDER BY scan_timestamp DESC LIMIT ?",
                (target_origin, limit),
            ).fetchall()
            return [dict(r) for r in rows]

    def delete_scan(self, scan_id: str) -> bool:
        with self._sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("DELETE FROM website_scans WHERE scan_id = ?", (scan_id,))
            conn.commit()
            return cur.rowcount > 0

    def cleanup_old_scans(self, days: int = 30) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("DELETE FROM website_scans WHERE scan_timestamp < ?", (cutoff,))
            conn.commit()
            return cur.rowcount

    def get_statistics(self) -> dict[str, Any]:
        with self._sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM website_scans").fetchone()[0]
            unique = conn.execute("SELECT COUNT(DISTINCT target_origin) FROM website_scans").fetchone()[0]
            avg = conn.execute("SELECT AVG(score) FROM website_scans").fetchone()[0] or 0
            return {"total_scans": total, "unique_targets": unique, "average_score": round(avg, 2)}


# ── SQLAlchemy backend ───────────────────────────────────────────────────────

class _SqlAlchemyStorage:
    """SQLAlchemy-backed storage; supports SQLite and PostgreSQL."""

    def __init__(self, db_url: str) -> None:
        self.engine = _create_engine(db_url, pool_pre_ping=True)
        _Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def save_scan(self, result: WebsiteScanResult) -> None:
        with self.Session() as session:
            record = session.query(_WebsiteScanRecord).filter_by(scan_id=result.scan_id).first()
            if not record:
                record = _WebsiteScanRecord(scan_id=result.scan_id)
                session.add(record)
            record.target_origin = result.target_origin
            record.final_url = result.final_url
            record.posture_classification = result.posture_classification.value
            record.score = result.score
            record.findings_count = len(result.findings)
            record.passed_count = result.passed_count
            record.failed_count = result.failed_count
            record.warning_count = result.warning_count
            record.unknown_count = result.unknown_count
            record.rule_pack_version = result.rule_pack_version
            record.scan_timestamp = result.scan_timestamp.isoformat()
            record.limitations = result.limitations
            record.findings_json = _findings_to_json(result)
            record.created_at = datetime.now(timezone.utc).isoformat()
            session.commit()

    def get_scan(self, scan_id: str) -> Optional[dict[str, Any]]:
        with self.Session() as session:
            r = session.query(_WebsiteScanRecord).filter_by(scan_id=scan_id).first()
            return self._to_dict(r) if r else None

    def get_scans_by_target(self, target_origin: str, limit: int = 10) -> list[dict[str, Any]]:
        with self.Session() as session:
            rows = (
                session.query(_WebsiteScanRecord)
                .filter_by(target_origin=target_origin)
                .order_by(_WebsiteScanRecord.scan_timestamp.desc())
                .limit(limit)
                .all()
            )
            return [self._to_dict(r) for r in rows]

    def delete_scan(self, scan_id: str) -> bool:
        with self.Session() as session:
            result = session.execute(delete(_WebsiteScanRecord).where(_WebsiteScanRecord.scan_id == scan_id))
            session.commit()
            return result.rowcount > 0

    def cleanup_old_scans(self, days: int = 30) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self.Session() as session:
            result = session.execute(delete(_WebsiteScanRecord).where(_WebsiteScanRecord.scan_timestamp < cutoff))
            session.commit()
            return result.rowcount

    def get_statistics(self) -> dict[str, Any]:
        with self.Session() as session:
            total = session.query(func.count(_WebsiteScanRecord.scan_id)).scalar() or 0
            unique = session.query(func.count(func.distinct(_WebsiteScanRecord.target_origin))).scalar() or 0
            avg = session.query(func.avg(_WebsiteScanRecord.score)).scalar() or 0
            return {"total_scans": total, "unique_targets": unique, "average_score": round(avg, 2)}

    @staticmethod
    def _to_dict(r: _WebsiteScanRecord) -> dict[str, Any]:  # type: ignore[valid-type]
        return {
            "scan_id": r.scan_id,
            "target_origin": r.target_origin,
            "final_url": r.final_url,
            "posture_classification": r.posture_classification,
            "score": r.score,
            "findings_count": r.findings_count,
            "passed_count": r.passed_count,
            "failed_count": r.failed_count,
            "warning_count": r.warning_count,
            "unknown_count": r.unknown_count,
            "rule_pack_version": r.rule_pack_version,
            "scan_timestamp": r.scan_timestamp,
            "limitations": r.limitations,
            "findings_json": r.findings_json,
            "created_at": r.created_at,
        }


# ── Public facade ────────────────────────────────────────────────────────────

class WebsiteScanStorage:
    """Storage facade: uses SQLAlchemy when available, raw sqlite3 otherwise.

    The CONFIGSENTINEL_DATABASE_URL environment variable controls the backend:
    - SQLite (default):    sqlite:///./.configsentinel/configsentinel.db
    - PostgreSQL:          postgresql://user:pass@host/dbname
    """

    def __init__(self, db_path: str = "sqlite:///./.configsentinel/configsentinel.db") -> None:
        if _SA_AVAILABLE:
            # Normalise plain path → sqlite:// URI for SQLAlchemy
            url = db_path if "://" in db_path else f"sqlite:///{db_path}"
            self._impl: _SqliteStorage | _SqlAlchemyStorage = _SqlAlchemyStorage(url)
        else:
            self._impl = _SqliteStorage(db_path)

    def save_scan(self, result: WebsiteScanResult) -> None:
        self._impl.save_scan(result)

    def get_scan(self, scan_id: str) -> Optional[dict[str, Any]]:
        return self._impl.get_scan(scan_id)

    def get_scans_by_target(self, target_origin: str, limit: int = 10) -> list[dict[str, Any]]:
        return self._impl.get_scans_by_target(target_origin, limit)

    def delete_scan(self, scan_id: str) -> bool:
        return self._impl.delete_scan(scan_id)

    def cleanup_old_scans(self, days: int = 30) -> int:
        return self._impl.cleanup_old_scans(days)

    def get_statistics(self) -> dict[str, Any]:
        return self._impl.get_statistics()
