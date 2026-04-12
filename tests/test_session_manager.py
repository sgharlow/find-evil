"""Tests for the Evidence Session Manager — the most critical component.

These tests verify:
1. Evidence files are discovered and sealed correctly
2. SHA-256 hashes detect content changes (not just metadata)
3. Session halts when evidence is tampered
4. Deleted files are detected as tampering
5. Non-evidence files are ignored
"""

from pathlib import Path

import pytest

from find_evil.session.manager import EvidenceSession, EvidenceIntegrityError


class TestEvidenceDiscovery:
    """Tests for evidence file discovery."""

    def test_discovers_evidence_by_extension(self, session, evidence_dir):
        info = session.initialize(str(evidence_dir))
        assert info.file_count == 4  # .raw, .img, .pcap, .evtx
        assert "notes.txt" not in str(info.manifest)

    def test_rejects_empty_directory(self, session, tmp_path):
        with pytest.raises(ValueError, match="No evidence files found"):
            session.initialize(str(tmp_path))

    def test_rejects_nonexistent_directory(self, session):
        with pytest.raises(ValueError, match="does not exist"):
            session.initialize("/nonexistent/path")


class TestHashSealing:
    """Tests for SHA-256 hash sealing."""

    def test_seal_creates_session_id(self, session, evidence_dir):
        info = session.initialize(str(evidence_dir))
        assert info.session_id is not None
        assert len(info.session_id) == 36  # UUID format

    def test_seal_records_all_files(self, session, evidence_dir):
        info = session.initialize(str(evidence_dir))
        assert info.file_count == 4
        assert len(info.manifest) == 4

    def test_verify_passes_on_clean_evidence(self, sealed_session):
        result = sealed_session.verify_all()
        assert result.passed is True
        assert result.files_checked == 4
        assert result.failures == []

    def test_session_is_active_after_seal(self, sealed_session):
        assert sealed_session.is_active is True


class TestTamperDetection:
    """Tests for evidence integrity verification — the core differentiator."""

    def test_detects_content_modification(self, sealed_session, evidence_dir):
        """Modify file content → hash mismatch → session halted."""
        # Append bytes to evidence file (NOT just touch — SHA-256 checks content)
        evidence_file = evidence_dir / "memory.raw"
        with open(evidence_file, "ab") as f:
            f.write(b"\x00TAMPERED")

        result = sealed_session.verify_all()
        assert result.passed is False
        assert len(result.failures) == 1
        assert "memory.raw" in result.failures[0]["file"]

    def test_detects_file_deletion(self, sealed_session, evidence_dir):
        """Delete an evidence file → treated as tampered."""
        (evidence_dir / "network.pcap").unlink()

        result = sealed_session.verify_all()
        assert result.passed is False
        assert len(result.failures) == 1

    def test_detects_content_replacement(self, sealed_session, evidence_dir):
        """Replace file with different content of same size → detected."""
        evidence_file = evidence_dir / "disk.img"
        original_size = evidence_file.stat().st_size
        # Write different content of same length
        evidence_file.write_bytes(b"X" * original_size)

        result = sealed_session.verify_all()
        assert result.passed is False

    def test_session_halts_on_violation(self, sealed_session, evidence_dir):
        """After tamper detection, session must be inactive."""
        (evidence_dir / "memory.raw").write_bytes(b"TAMPERED")

        sealed_session.verify_all()

        assert sealed_session.is_active is False

    def test_require_active_raises_after_halt(self, sealed_session, evidence_dir):
        """require_active() must raise after integrity violation."""
        (evidence_dir / "memory.raw").write_bytes(b"TAMPERED")
        sealed_session.verify_all()

        with pytest.raises(EvidenceIntegrityError, match="Session halted"):
            sealed_session.require_active()

    def test_touch_does_not_trigger_detection(self, sealed_session, evidence_dir):
        """IMPORTANT: touch only changes mtime, not content. SHA-256 should NOT trigger.

        This test documents a spec bug: the original spec used `touch` for the
        tamper demo, but SHA-256 hashes file content, not metadata.
        """
        import os
        evidence_file = evidence_dir / "memory.raw"
        # touch — change mtime without changing content
        os.utime(evidence_file, (0, 0))

        result = sealed_session.verify_all()
        assert result.passed is True  # touch does NOT change content hash


class TestReseal:
    """Tests for evidence re-sealing after intervention."""

    def test_reseal_creates_new_session(self, sealed_session, evidence_dir):
        old_id = sealed_session.session_id
        # Tamper and halt
        (evidence_dir / "memory.raw").write_bytes(b"TAMPERED")
        sealed_session.verify_all()
        assert sealed_session.is_active is False

        # Re-seal
        info = sealed_session.reseal()
        assert info.session_id != old_id
        assert sealed_session.is_active is True

    def test_reseal_without_init_raises(self, session):
        with pytest.raises(ValueError, match="No evidence directory set"):
            session.reseal()
