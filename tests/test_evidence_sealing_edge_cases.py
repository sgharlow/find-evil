"""Evidence sealing edge case tests.

Covers scenarios not tested in test_session_manager.py or test_security_bypass.py:
1. Empty evidence directory (no matching extensions)
2. Large file hashing correctness
3. Concurrent verification resilience
4. Hash verification timing
5. Multiple reseal cycles
6. Evidence with unusual extensions
7. Deeply nested evidence files
8. Read-only evidence files
9. Evidence file with zero bytes
10. Rapid successive verifications
"""

from __future__ import annotations

import hashlib
import os
import time
import threading
from pathlib import Path

import pytest

from find_evil.session.manager import (
    EvidenceSession,
    EvidenceIntegrityError,
    EVIDENCE_EXTENSIONS,
)
from find_evil.session.hash_daemon import HashDaemon


# ---------------------------------------------------------------------------
# 1. Empty and degenerate evidence directories
# ---------------------------------------------------------------------------

class TestEmptyEvidenceHandling:
    """Edge cases for directories with no or minimal evidence files."""

    def test_directory_with_only_non_evidence_files(self, tmp_path):
        """Directory with files but no evidence extensions should be rejected."""
        (tmp_path / "readme.txt").write_text("Just a note")
        (tmp_path / "config.json").write_text('{"key": "value"}')
        (tmp_path / "data.csv").write_text("a,b,c\n1,2,3")

        session = EvidenceSession()
        with pytest.raises(ValueError, match="No evidence files found"):
            session.initialize(str(tmp_path))

    def test_directory_with_single_evidence_file(self, tmp_path):
        """Directory with exactly one evidence file should work."""
        (tmp_path / "single.raw").write_bytes(b"MINIMAL_EVIDENCE")

        session = EvidenceSession()
        info = session.initialize(str(tmp_path))
        assert info.file_count == 1

    def test_zero_byte_evidence_file(self, tmp_path):
        """Zero-byte evidence file should be sealed (it has a valid SHA-256)."""
        (tmp_path / "empty.raw").write_bytes(b"")

        session = EvidenceSession()
        info = session.initialize(str(tmp_path))
        assert info.file_count == 1

        # Verify passes on untouched empty file
        result = session.verify_all()
        assert result.passed is True

    def test_zero_byte_file_tamper_detected(self, tmp_path):
        """Adding content to a zero-byte file should be detected."""
        evidence = tmp_path / "empty.raw"
        evidence.write_bytes(b"")

        session = EvidenceSession()
        session.initialize(str(tmp_path))

        # Add content to the empty file
        evidence.write_bytes(b"NOW_HAS_CONTENT")

        result = session.verify_all()
        assert result.passed is False


# ---------------------------------------------------------------------------
# 2. Evidence extension coverage
# ---------------------------------------------------------------------------

class TestEvidenceExtensionHandling:
    """Verify all declared evidence extensions are actually recognized."""

    @pytest.mark.parametrize("ext", sorted(EVIDENCE_EXTENSIONS))
    def test_extension_is_recognized(self, tmp_path, ext):
        """Each declared evidence extension should be discovered by the session."""
        (tmp_path / f"test{ext}").write_bytes(b"EVIDENCE_DATA_FOR_" + ext.encode())

        session = EvidenceSession()
        info = session.initialize(str(tmp_path))
        assert info.file_count == 1, f"Extension {ext} was not recognized"

    def test_case_insensitive_extension(self, tmp_path):
        """Extensions should be matched case-insensitively."""
        (tmp_path / "test.RAW").write_bytes(b"UPPER_CASE_EXTENSION")

        session = EvidenceSession()
        info = session.initialize(str(tmp_path))
        assert info.file_count == 1

    def test_mixed_case_extension(self, tmp_path):
        """Mixed case extensions should be recognized."""
        (tmp_path / "test.EvTx").write_bytes(b"MIXED_CASE")

        session = EvidenceSession()
        info = session.initialize(str(tmp_path))
        assert info.file_count == 1


# ---------------------------------------------------------------------------
# 3. Deeply nested evidence files
# ---------------------------------------------------------------------------

class TestNestedEvidenceDiscovery:
    """Verify evidence files in subdirectories are discovered."""

    def test_discovers_files_in_subdirectory(self, tmp_path):
        """Evidence in a subdirectory should be found by rglob."""
        sub = tmp_path / "case1" / "memory"
        sub.mkdir(parents=True)
        (sub / "memory.raw").write_bytes(b"NESTED_EVIDENCE")
        # Also add a top-level file
        (tmp_path / "disk.img").write_bytes(b"TOP_LEVEL")

        session = EvidenceSession()
        info = session.initialize(str(tmp_path))
        assert info.file_count == 2

    def test_discovers_files_three_levels_deep(self, tmp_path):
        """Evidence 3 levels deep should still be found."""
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        (deep / "deep.pcap").write_bytes(b"DEEP_NESTED")

        session = EvidenceSession()
        info = session.initialize(str(tmp_path))
        assert info.file_count == 1


# ---------------------------------------------------------------------------
# 4. Large file handling
# ---------------------------------------------------------------------------

class TestLargeFileHandling:
    """Verify hashing works correctly on larger files."""

    def test_file_larger_than_chunk_size(self, tmp_path):
        """Files larger than 64KB (the chunk size) should hash correctly."""
        large_data = b"A" * (65536 * 3 + 7)  # ~192 KB + 7 bytes
        (tmp_path / "large.raw").write_bytes(large_data)

        session = EvidenceSession()
        session.initialize(str(tmp_path))

        result = session.verify_all()
        assert result.passed is True

    def test_large_file_tamper_detected(self, tmp_path):
        """Modifying a byte in a large file should be detected."""
        large_data = bytearray(b"B" * (65536 * 2))
        evidence = tmp_path / "large.raw"
        evidence.write_bytes(bytes(large_data))

        session = EvidenceSession()
        session.initialize(str(tmp_path))

        # Modify a byte in the middle (second chunk)
        large_data[65537] = (large_data[65537] + 1) % 256
        evidence.write_bytes(bytes(large_data))

        result = session.verify_all()
        assert result.passed is False

    def test_hash_matches_python_hashlib(self, tmp_path):
        """Session hash should match a direct hashlib computation."""
        data = b"VERIFICATION_DATA_" + os.urandom(1024)
        evidence = tmp_path / "verify.raw"
        evidence.write_bytes(data)

        session = EvidenceSession()
        session.initialize(str(tmp_path))

        # Compute expected hash
        expected = hashlib.sha256(data).hexdigest()

        # Get actual hash from manifest
        manifest = session._hash_manifest
        actual_hash = list(manifest.values())[0].sha256
        assert actual_hash == expected


# ---------------------------------------------------------------------------
# 5. Multiple reseal cycles
# ---------------------------------------------------------------------------

class TestMultipleResealCycles:
    """Verify the system handles multiple reseal operations correctly."""

    def test_three_reseal_cycles(self, tmp_path):
        """Three consecutive reseal cycles should each create a new session."""
        (tmp_path / "test.raw").write_bytes(b"ORIGINAL")

        session = EvidenceSession()
        info1 = session.initialize(str(tmp_path))
        id1 = info1.session_id

        # First reseal
        info2 = session.reseal()
        id2 = info2.session_id
        assert id2 != id1
        assert session.is_active

        # Tamper and verify fails
        (tmp_path / "test.raw").write_bytes(b"MODIFIED")
        result = session.verify_all()
        assert result.passed is False
        assert not session.is_active

        # Second reseal after tamper
        info3 = session.reseal()
        id3 = info3.session_id
        assert id3 != id2
        assert session.is_active

        # Verify passes with new content
        result = session.verify_all()
        assert result.passed is True

    def test_reseal_updates_file_count(self, tmp_path):
        """If files are added between reseals, the new count is correct."""
        (tmp_path / "first.raw").write_bytes(b"FILE_ONE")

        session = EvidenceSession()
        info1 = session.initialize(str(tmp_path))
        assert info1.file_count == 1

        # Add another evidence file
        (tmp_path / "second.img").write_bytes(b"FILE_TWO")

        # Reseal picks up the new file
        info2 = session.reseal()
        assert info2.file_count == 2


# ---------------------------------------------------------------------------
# 6. Concurrent access scenarios
# ---------------------------------------------------------------------------

class TestConcurrentVerification:
    """Verify that concurrent verify_all calls are safe."""

    def test_concurrent_verifications_all_pass(self, tmp_path):
        """Multiple threads calling verify_all concurrently should all pass."""
        (tmp_path / "test.raw").write_bytes(b"CONCURRENT_TEST_DATA")

        session = EvidenceSession()
        session.initialize(str(tmp_path))

        results = []
        errors = []

        def verify():
            try:
                result = session.verify_all()
                results.append(result.passed)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=verify) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not errors, f"Errors during concurrent verification: {errors}"
        assert all(results), "Some concurrent verifications failed"

    def test_daemon_and_manual_verify_coexist(self, tmp_path):
        """Hash daemon and manual verify_now should not conflict."""
        (tmp_path / "test.raw").write_bytes(b"DAEMON_COEXIST_TEST")

        session = EvidenceSession()
        session.initialize(str(tmp_path))

        daemon = HashDaemon(session, interval=1)
        daemon.start()

        try:
            # Manual verifications while daemon is running
            for _ in range(3):
                result = daemon.verify_now()
                assert result.passed is True
                time.sleep(0.3)
        finally:
            daemon.stop()


# ---------------------------------------------------------------------------
# 7. Verification timing
# ---------------------------------------------------------------------------

class TestVerificationTiming:
    """Verify hash checks complete in reasonable time."""

    def test_single_file_verify_under_100ms(self, tmp_path):
        """Verifying a single small file should complete quickly."""
        (tmp_path / "small.raw").write_bytes(b"SMALL_FILE")

        session = EvidenceSession()
        session.initialize(str(tmp_path))

        start = time.perf_counter()
        result = session.verify_all()
        elapsed = time.perf_counter() - start

        assert result.passed is True
        assert elapsed < 0.1, f"Verification took {elapsed:.4f}s (> 100ms)"

    def test_multiple_files_verify_under_500ms(self, tmp_path):
        """Verifying 10 evidence files should complete in < 500ms."""
        for i in range(10):
            ext = list(EVIDENCE_EXTENSIONS)[i % len(EVIDENCE_EXTENSIONS)]
            (tmp_path / f"file_{i}{ext}").write_bytes(
                b"DATA_" + str(i).encode() * 1024
            )

        session = EvidenceSession()
        session.initialize(str(tmp_path))
        assert session.file_count == 10

        start = time.perf_counter()
        result = session.verify_all()
        elapsed = time.perf_counter() - start

        assert result.passed is True
        assert elapsed < 0.5, f"Verification of 10 files took {elapsed:.4f}s (> 500ms)"

    def test_rapid_successive_verifications(self, tmp_path):
        """50 rapid verify_all calls should all pass without degradation."""
        (tmp_path / "test.raw").write_bytes(b"RAPID_VERIFY_DATA")

        session = EvidenceSession()
        session.initialize(str(tmp_path))

        start = time.perf_counter()
        for _ in range(50):
            result = session.verify_all()
            assert result.passed is True
        elapsed = time.perf_counter() - start

        assert elapsed < 2.0, (
            f"50 verifications took {elapsed:.2f}s (> 2s)"
        )


# ---------------------------------------------------------------------------
# 8. Manifest state
# ---------------------------------------------------------------------------

class TestManifestState:
    """Verify manifest metadata is correct and complete."""

    def test_manifest_contains_all_files(self, tmp_path):
        """get_manifest() should return entries for all sealed files."""
        (tmp_path / "a.raw").write_bytes(b"FILE_A")
        (tmp_path / "b.img").write_bytes(b"FILE_B")
        (tmp_path / "c.pcap").write_bytes(b"FILE_C")

        session = EvidenceSession()
        session.initialize(str(tmp_path))

        manifest = session.get_manifest()
        assert len(manifest) == 3

    def test_manifest_hashes_are_truncated(self, tmp_path):
        """Manifest hashes should be truncated (16 chars + '...')."""
        (tmp_path / "test.raw").write_bytes(b"TRUNCATION_TEST")

        session = EvidenceSession()
        session.initialize(str(tmp_path))

        manifest = session.get_manifest()
        for _path, hash_str in manifest.items():
            assert hash_str.endswith("..."), "Manifest hash should end with '...'"
            assert len(hash_str) == 19, f"Expected 16+3 chars, got {len(hash_str)}"

    def test_is_sealed_file_returns_true_for_sealed(self, tmp_path):
        """is_sealed_file should return True for sealed evidence files."""
        evidence = tmp_path / "sealed.raw"
        evidence.write_bytes(b"SEALED_DATA")

        session = EvidenceSession()
        session.initialize(str(tmp_path))

        assert session.is_sealed_file(str(evidence))

    def test_is_sealed_file_returns_false_for_non_evidence(self, tmp_path):
        """is_sealed_file should return False for non-evidence files."""
        (tmp_path / "evidence.raw").write_bytes(b"EVIDENCE")
        non_evidence = tmp_path / "notes.txt"
        non_evidence.write_text("Not evidence")

        session = EvidenceSession()
        session.initialize(str(tmp_path))

        assert not session.is_sealed_file(str(non_evidence))

    def test_session_properties_after_init(self, tmp_path):
        """Session properties should be correctly set after initialization."""
        (tmp_path / "test.raw").write_bytes(b"PROPERTY_CHECK")

        session = EvidenceSession()
        info = session.initialize(str(tmp_path))

        assert session.session_id is not None
        assert len(session.session_id) == 36  # UUID
        assert session.evidence_dir is not None
        assert session.sealed_at is not None
        assert session.is_active is True
        assert session.file_count == 1


# ---------------------------------------------------------------------------
# 9. Hash record detail
# ---------------------------------------------------------------------------

class TestHashRecordIntegrity:
    """Verify hash records store correct information."""

    def test_hash_record_has_correct_sha256(self, tmp_path):
        """Internal hash record should match hashlib computation."""
        data = b"HASH_RECORD_VERIFICATION_DATA"
        (tmp_path / "verify.raw").write_bytes(data)

        session = EvidenceSession()
        session.initialize(str(tmp_path))

        expected = hashlib.sha256(data).hexdigest()
        record = list(session._hash_manifest.values())[0]
        assert record.sha256 == expected

    def test_hash_record_has_correct_size(self, tmp_path):
        """Internal hash record should have correct file size."""
        data = b"SIZE_CHECK_DATA_1234567890"
        (tmp_path / "size.raw").write_bytes(data)

        session = EvidenceSession()
        session.initialize(str(tmp_path))

        record = list(session._hash_manifest.values())[0]
        assert record.size_bytes == len(data)

    def test_hash_record_has_sealed_at_timestamp(self, tmp_path):
        """Internal hash record should have a sealed_at timestamp."""
        (tmp_path / "time.raw").write_bytes(b"TIMESTAMP_CHECK")

        session = EvidenceSession()
        session.initialize(str(tmp_path))

        record = list(session._hash_manifest.values())[0]
        assert record.sealed_at is not None
        assert len(record.sealed_at) > 0


# ---------------------------------------------------------------------------
# 10. Integrity result details
# ---------------------------------------------------------------------------

class TestIntegrityResultDetails:
    """Verify IntegrityResult contains proper failure details."""

    def test_failure_includes_file_path(self, tmp_path):
        """Integrity failure should identify which file was tampered."""
        evidence = tmp_path / "tracked.raw"
        evidence.write_bytes(b"ORIGINAL")

        session = EvidenceSession()
        session.initialize(str(tmp_path))

        evidence.write_bytes(b"TAMPERED")
        result = session.verify_all()

        assert result.passed is False
        assert len(result.failures) == 1
        assert "tracked.raw" in result.failures[0]["file"]

    def test_failure_includes_expected_hash(self, tmp_path):
        """Integrity failure should include the expected hash prefix."""
        evidence = tmp_path / "hash_detail.raw"
        evidence.write_bytes(b"EXPECTED_CONTENT")

        session = EvidenceSession()
        session.initialize(str(tmp_path))

        evidence.write_bytes(b"UNEXPECTED_CONTENT")
        result = session.verify_all()

        assert "expected" in result.failures[0]
        assert "actual" in result.failures[0]
        assert result.failures[0]["expected"] != result.failures[0]["actual"]

    def test_failure_includes_timestamp(self, tmp_path):
        """Integrity failure should include detection timestamp."""
        evidence = tmp_path / "timed.raw"
        evidence.write_bytes(b"BEFORE")

        session = EvidenceSession()
        session.initialize(str(tmp_path))

        evidence.write_bytes(b"AFTER_CHANGE")
        result = session.verify_all()

        assert "detected_at" in result.failures[0]

    def test_multiple_tampered_files_all_reported(self, tmp_path):
        """If multiple files are tampered, all should be in failures."""
        (tmp_path / "a.raw").write_bytes(b"FILE_A")
        (tmp_path / "b.img").write_bytes(b"FILE_B")
        (tmp_path / "c.pcap").write_bytes(b"FILE_C")

        session = EvidenceSession()
        session.initialize(str(tmp_path))

        # Tamper with all three
        (tmp_path / "a.raw").write_bytes(b"TAMPERED_A")
        (tmp_path / "b.img").write_bytes(b"TAMPERED_B")
        (tmp_path / "c.pcap").write_bytes(b"TAMPERED_C")

        result = session.verify_all()
        assert result.passed is False
        assert len(result.failures) == 3
        assert result.files_checked == 3
