"""Pydantic models for evidence session state."""

from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field


class HashRecord(BaseModel):
    """SHA-256 hash of a single evidence file."""

    filepath: str
    sha256: str
    size_bytes: int
    sealed_at: str


class IntegrityResult(BaseModel):
    """Result of an evidence integrity verification check."""

    passed: bool
    files_checked: int = 0
    failures: list[dict] = Field(default_factory=list)
    checked_at: str = ""

    @property
    def summary(self) -> str:
        if self.passed:
            return f"OK — {self.files_checked} files verified"
        return (
            f"VIOLATION — {len(self.failures)} file(s) tampered, "
            f"{self.files_checked} checked"
        )


class SessionInfo(BaseModel):
    """Metadata about an active evidence session."""

    session_id: str
    evidence_dir: str
    file_count: int
    sealed_at: str
    manifest: dict[str, str] = Field(default_factory=dict)
