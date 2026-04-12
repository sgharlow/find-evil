"""Hash Verification Daemon — continuous background integrity monitoring.

Runs as a daemon thread that re-verifies evidence file hashes every 30 seconds.
Any mismatch immediately halts the analysis session and voids all findings.

Uses threading (not asyncio) because the daemon must run independently of the
MCP server's async request loop. The daemon thread is marked as a daemon so it
dies automatically when the server process exits.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone

from .manager import EvidenceSession
from .models import IntegrityResult

logger = logging.getLogger("find_evil.hash_daemon")

DEFAULT_INTERVAL_SECONDS = 30


class HashDaemon:
    """Background thread verifying evidence integrity on a fixed interval.

    Usage:
        daemon = HashDaemon(session, interval=30)
        daemon.start()
        ...
        result = daemon.verify_now()  # synchronous on-demand check
        ...
        daemon.stop()
    """

    def __init__(
        self,
        session: EvidenceSession,
        interval: int = DEFAULT_INTERVAL_SECONDS,
    ) -> None:
        self._session = session
        self._interval = interval
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._last_result: IntegrityResult | None = None
        self._lock = threading.Lock()
        self._check_count = 0
        self._violation_detected = False

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def check_count(self) -> int:
        return self._check_count

    @property
    def last_result(self) -> IntegrityResult | None:
        with self._lock:
            return self._last_result

    def start(self) -> None:
        """Start the background verification thread."""
        if self.is_running:
            return
        self._stop_event.clear()
        self._violation_detected = False
        self._thread = threading.Thread(
            target=self._run,
            name="hash-daemon",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "Hash daemon started — %ds verification cycle", self._interval
        )

    def stop(self) -> None:
        """Signal the daemon to stop and wait for it to finish."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("Hash daemon stopped after %d checks", self._check_count)

    def verify_now(self) -> IntegrityResult:
        """Synchronous on-demand verification.

        Called by the @forensic_tool decorator before every tool execution.
        This is in addition to the periodic background checks.
        """
        result = self._session.verify_all()
        with self._lock:
            self._last_result = result
            self._check_count += 1
        if not result.passed:
            self._violation_detected = True
            logger.error(
                "INTEGRITY VIOLATION detected (on-demand check): %s",
                result.summary,
            )
        return result

    def _run(self) -> None:
        """Background loop: verify → sleep → verify → ..."""
        while not self._stop_event.is_set():
            result = self._session.verify_all()

            with self._lock:
                self._last_result = result
                self._check_count += 1

            if not result.passed:
                self._violation_detected = True
                logger.error(
                    "INTEGRITY VIOLATION detected by hash daemon: %s",
                    result.summary,
                )
                # Session is now halted (verify_all sets _active=False).
                # Stop the daemon — no point continuing checks.
                break

            logger.debug(
                "Integrity check #%d passed — %d files verified",
                self._check_count,
                result.files_checked,
            )

            # Wait for the interval or until stop is requested
            self._stop_event.wait(self._interval)
