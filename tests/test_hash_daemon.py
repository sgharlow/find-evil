"""Tests for the Hash Verification Daemon."""

import time
from pathlib import Path

import pytest

from find_evil.session.hash_daemon import HashDaemon


class TestHashDaemon:
    """Tests for background integrity monitoring."""

    def test_daemon_starts_and_stops(self, daemon):
        daemon.start()
        assert daemon.is_running is True
        daemon.stop()
        assert daemon.is_running is False

    def test_daemon_performs_checks(self, daemon):
        daemon.start()
        time.sleep(1.5)  # 1s interval, should get at least 1 check
        daemon.stop()
        assert daemon.check_count >= 1

    def test_verify_now_returns_result(self, daemon):
        result = daemon.verify_now()
        assert result.passed is True
        assert result.files_checked == 4

    def test_daemon_detects_tamper(self, daemon, evidence_dir):
        daemon.start()
        time.sleep(0.5)

        # Tamper with evidence
        (evidence_dir / "memory.raw").write_bytes(b"TAMPERED_BY_ADVERSARY")

        # Wait for daemon to detect
        time.sleep(1.5)
        daemon.stop()

        # Daemon should have detected the violation and stopped
        last = daemon.last_result
        assert last is not None
        assert last.passed is False

    def test_verify_now_detects_tamper_immediately(self, daemon, evidence_dir):
        """On-demand check catches tampering without waiting for daemon cycle."""
        (evidence_dir / "disk.img").write_bytes(b"TAMPERED")

        result = daemon.verify_now()
        assert result.passed is False
        assert len(result.failures) == 1


class TestDaemonIdempotent:
    """Daemon should handle edge cases gracefully."""

    def test_double_start_is_safe(self, daemon):
        daemon.start()
        daemon.start()  # should not raise or create second thread
        assert daemon.is_running is True
        daemon.stop()

    def test_stop_without_start_is_safe(self, daemon):
        daemon.stop()  # should not raise
