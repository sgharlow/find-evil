"""Tests for the JSONL audit trail."""

import json
from pathlib import Path

import pytest

from find_evil.audit.logger import AuditLogger, hash_output


class TestAuditLogger:

    def test_creates_log_file(self, tmp_path):
        path = str(tmp_path / "audit.jsonl")
        audit = AuditLogger(path=path)
        audit.log_invocation_start("vol_pslist", {"image": "test.raw"})
        assert Path(path).exists()

    def test_log_entries_are_valid_jsonl(self, tmp_path):
        path = str(tmp_path / "audit.jsonl")
        audit = AuditLogger(path=path)

        inv_id = audit.log_invocation_start("vol_pslist", {"image": "test.raw"})
        audit.log_invocation_complete(inv_id, output_hash="abc123", summary="89 procs")
        audit.log_integrity_check({"passed": True, "files_checked": 3})

        with open(path) as f:
            lines = f.readlines()

        assert len(lines) == 3
        for line in lines:
            record = json.loads(line)
            assert "timestamp" in record
            assert "event" in record

    def test_invocation_start_returns_uuid(self, audit_logger):
        inv_id = audit_logger.log_invocation_start("test_tool", {})
        assert len(inv_id) == 36  # UUID format

    def test_finding_log_has_provenance(self, tmp_path):
        path = str(tmp_path / "audit.jsonl")
        audit = AuditLogger(path=path)

        inv1 = audit.log_invocation_start("vol_pslist", {})
        inv2 = audit.log_invocation_start("vol_netscan", {})
        finding_id = audit.log_finding(
            {"description": "C2 beacon", "confidence": 0.88},
            source_calls=[inv1, inv2],
        )

        with open(path) as f:
            lines = f.readlines()

        finding_record = json.loads(lines[-1])
        assert finding_record["event"] == "finding_committed"
        assert finding_record["finding_id"] == finding_id
        assert len(finding_record["provenance"]) == 2

    def test_self_correction_logged(self, tmp_path):
        path = str(tmp_path / "audit.jsonl")
        audit = AuditLogger(path=path)

        audit.log_self_correction(
            original_finding={"description": "svchost suspicious", "confidence": 0.61},
            reason="DRS gate: below threshold",
            new_approach="Check parent process chain",
        )

        with open(path) as f:
            record = json.loads(f.readline())

        assert record["event"] == "self_correction"
        assert record["original"]["confidence"] == 0.61

    def test_session_id_attached(self, tmp_path):
        path = str(tmp_path / "audit.jsonl")
        audit = AuditLogger(path=path)
        audit.set_session_id("test-session-123")

        audit.log_invocation_start("test_tool", {})

        with open(path) as f:
            record = json.loads(f.readline())

        assert record["session_id"] == "test-session-123"

    def test_integrity_violation_logged(self, tmp_path):
        path = str(tmp_path / "audit.jsonl")
        audit = AuditLogger(path=path)

        audit.log_session_halt("Hash mismatch on 1 file(s)")

        with open(path) as f:
            record = json.loads(f.readline())

        assert record["event"] == "session_halt"
        assert "chain of custody" in record["message"].lower()


class TestHashOutput:

    def test_produces_hex_string(self):
        result = hash_output("test data")
        assert len(result) == 16  # truncated SHA-256
        assert all(c in "0123456789abcdef" for c in result)

    def test_different_inputs_different_hashes(self):
        h1 = hash_output("data A")
        h2 = hash_output("data B")
        assert h1 != h2

    def test_same_input_same_hash(self):
        h1 = hash_output("consistent data")
        h2 = hash_output("consistent data")
        assert h1 == h2
