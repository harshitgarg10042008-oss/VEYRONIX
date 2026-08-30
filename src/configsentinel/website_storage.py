"""Durable storage for website scan results using SQLite.

This module provides SQLite-based storage for website security scan results
with proper schema and retention management.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional, Any

from .website_models import WebsiteScanResult, WebsiteFinding


class WebsiteScanStorage:
    """SQLite storage for website scan results."""
    
    def __init__(self, db_path: str = "sqlite:///./.configsentinel/website_scans.db") -> None:
        """Initialize storage with database path.
        
        Args:
            db_path: SQLite database path (sqlite:/// prefix for file-based)
        """
        if db_path.startswith("sqlite:///"):
            db_path = db_path[10:]  # Remove sqlite:/// prefix
        
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()
    
    def _initialize_schema(self) -> None:
        """Create database schema if it doesn't exist."""
        with sqlite3.connect(self.db_path) as conn:
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
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_target_origin 
                ON website_scans(target_origin)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_timestamp 
                ON website_scans(scan_timestamp)
            """)
            
            conn.commit()
    
    def save_scan(self, result: WebsiteScanResult) -> None:
        """Save a website scan result.
        
        Args:
            result: The WebsiteScanResult to save
        """
        findings_json = json.dumps([
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
        
        with sqlite3.connect(self.db_path) as conn:
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
                findings_json,
                datetime.utcnow().isoformat(),
            ))
            conn.commit()
    
    def get_scan(self, scan_id: str) -> Optional[dict[str, Any]]:
        """Retrieve a scan result by ID.
        
        Args:
            scan_id: The scan ID to retrieve
            
        Returns:
            Dictionary with scan data or None if not found
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM website_scans WHERE scan_id = ?",
                (scan_id,)
            )
            row = cursor.fetchone()
            
            if row is None:
                return None
            
            return dict(row)
    
    def get_scans_by_target(
        self,
        target_origin: str,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Get recent scans for a specific target.
        
        Args:
            target_origin: The target origin
            limit: Maximum number of scans to return
            
        Returns:
            List of scan dictionaries
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT * FROM website_scans 
                WHERE target_origin = ?
                ORDER BY scan_timestamp DESC
                LIMIT ?
                """,
                (target_origin, limit)
            )
            return [dict(row) for row in cursor.fetchall()]
    
    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan result.
        
        Args:
            scan_id: The scan ID to delete
            
        Returns:
            True if deleted, False if not found
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM website_scans WHERE scan_id = ?",
                (scan_id,)
            )
            conn.commit()
            return cursor.rowcount > 0
    
    def cleanup_old_scans(self, days: int = 30) -> int:
        """Delete scans older than specified days.
        
        Args:
            days: Number of days to retain
            
        Returns:
            Number of scans deleted
        """
        cutoff_date = datetime.utcnow().replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        from datetime import timedelta
        cutoff_date = cutoff_date - timedelta(days=days)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM website_scans WHERE scan_timestamp < ?",
                (cutoff_date.isoformat(),)
            )
            conn.commit()
            return cursor.rowcount
    
    def get_statistics(self) -> dict[str, Any]:
        """Get storage statistics.
        
        Returns:
            Dictionary with statistics
        """
        with sqlite3.connect(self.db_path) as conn:
            total_scans = conn.execute("SELECT COUNT(*) FROM website_scans").fetchone()[0]
            unique_targets = conn.execute(
                "SELECT COUNT(DISTINCT target_origin) FROM website_scans"
            ).fetchone()[0]
            
            avg_score = conn.execute(
                "SELECT AVG(score) FROM website_scans"
            ).fetchone()[0] or 0
            
            return {
                "total_scans": total_scans,
                "unique_targets": unique_targets,
                "average_score": round(avg_score, 2),
            }
