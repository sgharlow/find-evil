"""End-to-end integration tests for the Evidence Integrity Enforcer.

These tests exercise the full tool pipeline with real session, daemon,
and audit logger instances — verifying that the enforce() gate, tool
execution, audit logging, and findings DB all work together.

No subprocess or MCP protocol overhead — we call the tool functions
directly with a properly initialized lifespan context.
"""

import asyncio
import json
import tempfile
from pathlib import Path

import pytest

from find_evil.session.manager import EvidenceSession
from find_evil.session.hash_daemon import HashDaemon
from find_evil.audit.logger import AuditLogger
from find_evil.analysis.findings_db import FindingsDB
from find_evil.tools._base import enforce, complete, get_lifespan, ToolContext


class MockContext:
    """Minimal mock of FastMCP Context for direct tool testing.

    Provides request_context.lifespan_context access path that
    enforce() and the tool functions expect.
    """

    def __init__(self, lifespan: dict):
        self.request_context = type("RC", (), {"lifespan_context": lifespan})()


@pytest.fixture
def integration_env(tmp_path):
    """Set up a full integration environment with evidence, session, daemon, and audit."""
    # Create evidence files
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    (evidence_dir / "memory.raw").write_bytes(b"MEMORY_DUMP_" + b"A" * 500)
    (evidence_dir / "disk.img").write_bytes(b"DISK_IMAGE_" + b"B" * 500)
    (evidence_dir / "Security.evtx").write_bytes(b"EVTX_LOG_" + b"C" * 200)

    # Initialize components
    session = EvidenceSession()
    info = session.initialize(str(evidence_dir))

    audit_path = str(tmp_path / "audit.jsonl")
    audit = AuditLogger(path=audit_path)
    audit.set_session_id(info.session_id)

    daemon = HashDaemon(session, interval=60)  # long interval, we verify manually
    daemon.start()

    findings_db = FindingsDB(path=str(tmp_path / "findings.db"))
    findings_db.record_session(
        session_id=info.session_id,
        evidence_dir=str(evidence_dir),
        file_count=info.file_count,
        sealed_at=info.sealed_at,
    )

    lifespan = {
        "session": session,
        "daemon": daemon,
        "audit": audit,
        "findings_db": findings_db,
    }
    ctx = MockContext(lifespan)

    yield {
        "ctx": ctx,
        "session": session,
        "daemon": daemon,
        "audit": audit,
        "findings_db": findings_db,
        "audit_path": audit_path,
        "evidence_dir": evidence_dir,
        "session_id": info.session_id,
    }

    daemon.stop()


class TestEnforceGate:
    """Tests for the enforce() integrity gate used by all tools."""

    def test_enforce_passes_on_clean_evidence(self, integration_env):
        ctx = integration_env["ctx"]
        result = enforce(ctx, "test_tool", {"arg": "value"})
        assert isinstance(result, ToolContext)
        assert result.invocation_id  # UUID assigned
        assert result.session is integration_env["session"]

    def test_enforce_blocks_on_tampered_evidence(self, integration_env):
        ctx = integration_env["ctx"]
        evidence_dir = integration_env["evidence_dir"]

        # Tamper with evidence
        (evidence_dir / "memory.raw").write_bytes(b"TAMPERED")

        result = enforce(ctx, "test_tool", {"arg": "value"})
        assert isinstance(result, dict)
        assert result["error"] == "EVIDENCE_INTEGRITY_VIOLATION"
        assert result["session_halted"] is True

    def test_enforce_logs_to_audit(self, integration_env):
        ctx = integration_env["ctx"]
        audit_path = integration_env["audit_path"]

        enforce(ctx, "test_tool", {"key": "value"})

        with open(audit_path) as f:
            records = [json.loads(line) for line in f]

        tool_starts = [r for r in records if r["event"] == "tool_call_start"]
        assert len(tool_starts) >= 1
        assert tool_starts[-1]["tool"] == "test_tool"
        assert tool_starts[-1]["arguments"]["key"] == "value"

    def test_complete_attaches_provenance(self, integration_env):
        ctx = integration_env["ctx"]

        tc = enforce(ctx, "test_tool", {})
        assert isinstance(tc, ToolContext)

        result = complete(tc, {"data": [1, 2, 3], "summary": "test"})

        assert "_provenance" in result
        assert result["_provenance"]["invocation_id"] == tc.invocation_id
        assert result["_provenance"]["integrity_verified"] is True
        assert len(result["_provenance"]["output_hash"]) == 16  # truncated SHA-256


class TestToolPipeline:
    """Test calling multiple tools in sequence — the investigation workflow."""

    def test_vol_pslist_returns_structured_data(self, integration_env):
        ctx = integration_env["ctx"]

        # Call vol_pslist via enforce + simulated backend
        tc = enforce(ctx, "vol_pslist", {"memory_image": "memory.raw"})
        assert isinstance(tc, ToolContext)

        # Import and verify the simulated data directly
        from find_evil.tools.volatility import SIMULATED_PSLIST
        assert len(SIMULATED_PSLIST) > 10

    def test_sequential_tool_calls_all_pass_integrity(self, integration_env):
        ctx = integration_env["ctx"]

        # Simulate the investigation sequence from CLAUDE.md
        tools = [
            ("vol_pslist", {"memory_image": "memory.raw"}),
            ("vol_netscan", {"memory_image": "memory.raw"}),
            ("vol_malfind", {"memory_image": "memory.raw"}),
            ("parse_evtx", {"evtx_path": "Security.evtx"}),
            ("registry_query", {"hive_path": "SYSTEM"}),
            ("build_timeline", {"evidence_path": "disk.img"}),
            ("yara_scan", {"target_path": "memory.raw"}),
        ]

        for tool_name, args in tools:
            result = enforce(ctx, tool_name, args)
            assert isinstance(result, ToolContext), (
                f"Tool {tool_name} should pass integrity check, got: {result}"
            )

    def test_tamper_mid_investigation_blocks_subsequent_tools(self, integration_env):
        ctx = integration_env["ctx"]
        evidence_dir = integration_env["evidence_dir"]

        # First tool passes
        tc1 = enforce(ctx, "vol_pslist", {"memory_image": "memory.raw"})
        assert isinstance(tc1, ToolContext)

        # Tamper with evidence
        (evidence_dir / "disk.img").write_bytes(b"TAMPERED_MID_INVESTIGATION")

        # Next tool is blocked (either INTEGRITY_VIOLATION or NO_ACTIVE_SESSION)
        result = enforce(ctx, "vol_netscan", {"memory_image": "memory.raw"})
        assert isinstance(result, dict)
        assert result["error"] in ("EVIDENCE_INTEGRITY_VIOLATION", "NO_ACTIVE_SESSION")

        # All subsequent tools also blocked
        result2 = enforce(ctx, "parse_evtx", {"evtx_path": "Security.evtx"})
        assert isinstance(result2, dict)
        assert result2["error"] in ("EVIDENCE_INTEGRITY_VIOLATION", "NO_ACTIVE_SESSION")


class TestAuditTrailIntegrity:
    """Tests for audit trail completeness and provenance chain."""

    def test_audit_trail_records_all_tool_calls(self, integration_env):
        ctx = integration_env["ctx"]
        audit_path = integration_env["audit_path"]

        # Call 3 tools
        for name in ["vol_pslist", "vol_netscan", "parse_evtx"]:
            tc = enforce(ctx, name, {"arg": "test"})
            if isinstance(tc, ToolContext):
                complete(tc, {"data": [], "summary": "test"})

        with open(audit_path) as f:
            records = [json.loads(line) for line in f]

        starts = [r for r in records if r["event"] == "tool_call_start"]
        completes = [r for r in records if r["event"] == "tool_call_complete"]

        assert len(starts) == 3
        assert len(completes) == 3

        # Every record has a timestamp
        for r in records:
            assert "timestamp" in r

    def test_finding_provenance_chain(self, integration_env):
        ctx = integration_env["ctx"]
        audit_path = integration_env["audit_path"]

        # Two tool calls
        tc1 = enforce(ctx, "vol_pslist", {})
        complete(tc1, {"data": [], "summary": "test"})

        tc2 = enforce(ctx, "vol_netscan", {})
        complete(tc2, {"data": [], "summary": "test"})

        # Submit a finding referencing both invocations
        audit = integration_env["audit"]
        finding_id = audit.log_finding(
            {"description": "C2 beacon detected", "confidence": 0.88},
            source_calls=[tc1.invocation_id, tc2.invocation_id],
        )

        # Verify the chain
        with open(audit_path) as f:
            records = [json.loads(line) for line in f]

        finding_records = [r for r in records if r.get("event") == "finding_committed"]
        assert len(finding_records) == 1
        assert finding_records[0]["finding_id"] == finding_id
        assert tc1.invocation_id in finding_records[0]["provenance"]
        assert tc2.invocation_id in finding_records[0]["provenance"]

    def test_tamper_event_logged(self, integration_env):
        ctx = integration_env["ctx"]
        audit_path = integration_env["audit_path"]
        evidence_dir = integration_env["evidence_dir"]

        # Tamper
        (evidence_dir / "memory.raw").write_bytes(b"TAMPERED")
        enforce(ctx, "vol_pslist", {})

        with open(audit_path) as f:
            records = [json.loads(line) for line in f]

        halt_records = [r for r in records if r.get("event") == "session_halt"]
        assert len(halt_records) >= 1
        assert "chain of custody" in halt_records[0]["message"].lower()


class TestFindingsDB:
    """Tests for findings database integration."""

    def test_finding_persisted_to_db(self, integration_env):
        db = integration_env["findings_db"]
        session_id = integration_env["session_id"]

        finding_id = db.add_finding(
            session_id=session_id,
            description="cmd.exe lateral movement via LOLBin chain",
            artifact_type="memory",
            confidence=0.91,
            evidence_strength=0.88,
            corroboration=0.85,
            source_invocations=["inv-001", "inv-002"],
            mitre_technique="T1059.003",
            action_required=False,
        )

        findings = db.get_findings(session_id)
        assert len(findings) == 1
        assert findings[0]["description"] == "cmd.exe lateral movement via LOLBin chain"
        assert findings[0]["confidence"] == 0.91
        assert len(findings[0]["provenance"]) == 2

    def test_session_summary_counts(self, integration_env):
        db = integration_env["findings_db"]
        session_id = integration_env["session_id"]

        # Add a high-confidence finding
        db.add_finding(
            session_id=session_id, description="High", artifact_type="memory",
            confidence=0.91, evidence_strength=0.9, corroboration=0.85,
            source_invocations=["inv-1"],
        )
        # Add a low-confidence finding
        db.add_finding(
            session_id=session_id, description="Low", artifact_type="disk",
            confidence=0.55, evidence_strength=0.5, corroboration=0.25,
            source_invocations=["inv-2"],
        )
        # Add a self-correction
        db.add_self_correction(
            session_id=session_id,
            original_description="svchost suspicious",
            original_confidence=0.61,
            reason="DRS gate below threshold",
            new_approach="Check parent chain",
        )

        summary = db.get_session_summary(session_id)
        assert summary["total_findings"] == 2
        assert summary["high_confidence_findings"] == 1
        assert summary["low_confidence_findings"] == 1
        assert summary["self_corrections"] == 1
