"""Shared test fixtures for the find-evil test suite."""

import os
import tempfile
from pathlib import Path

import pytest

from find_evil.session.manager import EvidenceSession
from find_evil.session.hash_daemon import HashDaemon
from find_evil.audit.logger import AuditLogger


@pytest.fixture
def evidence_dir(tmp_path: Path) -> Path:
    """Create a temporary directory with mock evidence files."""
    # Create fake evidence files with known content
    (tmp_path / "memory.raw").write_bytes(b"FAKE_MEMORY_DUMP_CONTENT_12345")
    (tmp_path / "disk.img").write_bytes(b"FAKE_DISK_IMAGE_CONTENT_67890")
    (tmp_path / "network.pcap").write_bytes(b"FAKE_PCAP_CONTENT_ABCDE")
    (tmp_path / "Security.evtx").write_bytes(b"FAKE_EVTX_CONTENT_FGHIJ")
    # Non-evidence file — should be ignored
    (tmp_path / "notes.txt").write_text("analyst notes — not evidence")
    return tmp_path


@pytest.fixture
def session() -> EvidenceSession:
    """Create a fresh EvidenceSession instance."""
    return EvidenceSession()


@pytest.fixture
def sealed_session(session: EvidenceSession, evidence_dir: Path) -> EvidenceSession:
    """Create an EvidenceSession with evidence already sealed."""
    session.initialize(str(evidence_dir))
    return session


@pytest.fixture
def audit_logger(tmp_path: Path) -> AuditLogger:
    """Create an AuditLogger writing to a temp file."""
    return AuditLogger(path=str(tmp_path / "test_audit.jsonl"))


@pytest.fixture
def daemon(sealed_session: EvidenceSession) -> HashDaemon:
    """Create a HashDaemon (not started) for a sealed session."""
    return HashDaemon(sealed_session, interval=1)  # 1s for fast tests
