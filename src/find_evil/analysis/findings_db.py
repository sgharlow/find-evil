"""SQLite-backed findings database with provenance chain.

Stores findings, their confidence scores, and the UUID links back to
the tool invocations that produced them. Used by the report generator
to produce the final IR report.

SQLite is chosen for zero-dependency local deployment — no separate
database server needed on the SIFT Workstation.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    evidence_dir TEXT NOT NULL,
    file_count INTEGER NOT NULL,
    sealed_at TEXT NOT NULL,
    halted_at TEXT,
    halt_reason TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    description TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    confidence REAL NOT NULL,
    evidence_strength REAL NOT NULL,
    corroboration REAL NOT NULL,
    mitre_technique TEXT DEFAULT '',
    action_required INTEGER DEFAULT 0,
    status TEXT DEFAULT 'accepted',
    created_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS finding_provenance (
    finding_id TEXT NOT NULL,
    invocation_id TEXT NOT NULL,
    relationship TEXT DEFAULT 'supports',
    PRIMARY KEY (finding_id, invocation_id),
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
);

CREATE TABLE IF NOT EXISTS self_corrections (
    correction_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    original_description TEXT NOT NULL,
    original_confidence REAL NOT NULL,
    reason TEXT NOT NULL,
    new_approach TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);
"""


class FindingsDB:
    """SQLite database for findings with provenance chain."""

    def __init__(self, path: str = "findings.db") -> None:
        self._path = Path(path)
        self._conn = sqlite3.connect(str(self._path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(CREATE_TABLES_SQL)

    async def close(self) -> None:
        self._conn.close()

    def record_session(
        self,
        session_id: str,
        evidence_dir: str,
        file_count: int,
        sealed_at: str,
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO sessions VALUES (?, ?, ?, ?, NULL, NULL)",
            (session_id, evidence_dir, file_count, sealed_at),
        )
        self._conn.commit()

    def halt_session(self, session_id: str, reason: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "UPDATE sessions SET halted_at = ?, halt_reason = ? WHERE session_id = ?",
            (now, reason, session_id),
        )
        self._conn.commit()

    def add_finding(
        self,
        session_id: str,
        description: str,
        artifact_type: str,
        confidence: float,
        evidence_strength: float,
        corroboration: float,
        source_invocations: list[str],
        mitre_technique: str = "",
        action_required: bool = False,
    ) -> str:
        finding_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        self._conn.execute(
            "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'accepted', ?)",
            (
                finding_id,
                session_id,
                description,
                artifact_type,
                confidence,
                evidence_strength,
                corroboration,
                mitre_technique,
                1 if action_required else 0,
                now,
            ),
        )

        for inv_id in source_invocations:
            self._conn.execute(
                "INSERT INTO finding_provenance VALUES (?, ?, 'supports')",
                (finding_id, inv_id),
            )

        self._conn.commit()
        return finding_id

    def add_self_correction(
        self,
        session_id: str,
        original_description: str,
        original_confidence: float,
        reason: str,
        new_approach: str,
    ) -> str:
        correction_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        self._conn.execute(
            "INSERT INTO self_corrections VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                correction_id,
                session_id,
                original_description,
                original_confidence,
                reason,
                new_approach,
                now,
            ),
        )
        self._conn.commit()
        return correction_id

    def get_findings(self, session_id: str) -> list[dict[str, Any]]:
        cursor = self._conn.execute(
            "SELECT * FROM findings WHERE session_id = ? ORDER BY created_at",
            (session_id,),
        )
        findings = []
        for row in cursor.fetchall():
            finding = dict(row)
            # Attach provenance chain
            prov_cursor = self._conn.execute(
                "SELECT invocation_id, relationship FROM finding_provenance "
                "WHERE finding_id = ?",
                (finding["finding_id"],),
            )
            finding["provenance"] = [
                {"invocation_id": p["invocation_id"], "relationship": p["relationship"]}
                for p in prov_cursor.fetchall()
            ]
            findings.append(finding)
        return findings

    def get_self_corrections(self, session_id: str) -> list[dict[str, Any]]:
        cursor = self._conn.execute(
            "SELECT * FROM self_corrections WHERE session_id = ? ORDER BY created_at",
            (session_id,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_session_summary(self, session_id: str) -> dict[str, Any]:
        findings = self.get_findings(session_id)
        corrections = self.get_self_corrections(session_id)

        high_confidence = [f for f in findings if f["confidence"] >= 0.75]
        low_confidence = [f for f in findings if f["confidence"] < 0.75]

        return {
            "session_id": session_id,
            "total_findings": len(findings),
            "high_confidence_findings": len(high_confidence),
            "low_confidence_findings": len(low_confidence),
            "self_corrections": len(corrections),
            "artifact_types": list({f["artifact_type"] for f in findings}),
            "action_required_count": sum(
                1 for f in findings if f["action_required"]
            ),
        }
