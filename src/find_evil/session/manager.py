"""Evidence Session Manager — SHA-256 hash sealing and integrity verification.

This is the most critical component. It cryptographically seals evidence files
at session start and provides continuous integrity verification. Any modification
to a sealed evidence file is detected and halts the analysis session.

Translates the check-contracts.sh pattern from ai-control-framework to
forensic evidence integrity enforcement.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .models import HashRecord, IntegrityResult, SessionInfo

# Evidence file extensions recognized by the session manager.
EVIDENCE_EXTENSIONS = frozenset({
    ".e01", ".ex01", ".aff4",          # EnCase / AFF4 images
    ".img", ".raw", ".dd", ".iso",     # Raw disk images
    ".vmdk", ".vhd", ".vhdx",         # Virtual disk images
    ".mem", ".dmp", ".lime",           # Memory dumps
    ".pcap", ".pcapng",               # Network captures
    ".evtx", ".evt",                  # Windows Event Logs
    ".hive", ".reg",                  # Registry hives
    ".pf",                            # Prefetch files
    ".lnk",                           # LNK shortcut files
})


class EvidenceIntegrityError(Exception):
    """Raised when evidence integrity cannot be guaranteed."""


class EvidenceSession:
    """Manages evidence lifecycle: mount, hash-seal, verify, halt.

    Usage:
        session = EvidenceSession()
        info = session.initialize("/path/to/case-data")
        result = session.verify_all()  # IntegrityResult
        session.require_active()       # raises if halted
    """

    def __init__(self) -> None:
        self.session_id: str | None = None
        self.evidence_dir: str | None = None
        self.sealed_at: datetime | None = None
        self._hash_manifest: dict[str, HashRecord] = {}
        self._active: bool = False
        self._halt_reason: str | None = None

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def file_count(self) -> int:
        return len(self._hash_manifest)

    def initialize(self, evidence_dir: str) -> SessionInfo:
        """Hash-seal all evidence files in the given directory.

        Recursively discovers evidence files by extension, computes SHA-256
        for each, and stores the manifest. The session is now sealed — any
        subsequent modification to these files will be detected by verify_all().
        """
        path = Path(evidence_dir)
        if not path.is_dir():
            raise ValueError(f"Evidence directory does not exist: {evidence_dir}")

        self.session_id = str(uuid.uuid4())
        self.evidence_dir = str(path.resolve())
        self._hash_manifest = {}

        for filepath in self._discover_evidence_files(path):
            record = self._seal_file(filepath)
            self._hash_manifest[str(filepath)] = record

        if not self._hash_manifest:
            raise ValueError(
                f"No evidence files found in {evidence_dir}. "
                f"Recognized extensions: {sorted(EVIDENCE_EXTENSIONS)}"
            )

        self.sealed_at = datetime.now(timezone.utc)
        self._active = True
        self._halt_reason = None

        manifest = {
            str(fp): rec.sha256[:16] + "..."
            for fp, rec in self._hash_manifest.items()
        }

        return SessionInfo(
            session_id=self.session_id,
            evidence_dir=self.evidence_dir,
            file_count=len(self._hash_manifest),
            sealed_at=self.sealed_at.isoformat(),
            manifest=manifest,
        )

    def verify_all(self) -> IntegrityResult:
        """Re-hash all sealed evidence files and compare to manifest.

        If any file hash has changed, the session is immediately halted
        and all findings are voided. Called by the hash daemon every 30s
        AND synchronously before every tool call.
        """
        if not self._hash_manifest:
            return IntegrityResult(
                passed=False,
                files_checked=0,
                failures=[{"error": "No session initialized"}],
                checked_at=datetime.now(timezone.utc).isoformat(),
            )

        failures = []
        for filepath, record in self._hash_manifest.items():
            current_hash = self._compute_sha256(Path(filepath))
            if current_hash != record.sha256:
                failures.append({
                    "file": filepath,
                    "expected": record.sha256[:16] + "...",
                    "actual": current_hash[:16] + "...",
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                })

        now = datetime.now(timezone.utc).isoformat()

        if failures:
            self._active = False
            self._halt_reason = (
                f"Hash mismatch on {len(failures)} file(s). "
                "Chain of custody broken."
            )
            return IntegrityResult(
                passed=False,
                files_checked=len(self._hash_manifest),
                failures=failures,
                checked_at=now,
            )

        return IntegrityResult(
            passed=True,
            files_checked=len(self._hash_manifest),
            failures=[],
            checked_at=now,
        )

    def require_active(self) -> None:
        """Gate called before every tool execution. Raises if session halted."""
        if not self._active:
            raise EvidenceIntegrityError(
                f"Session halted: {self._halt_reason} "
                "Evidence integrity cannot be guaranteed. "
                "Re-seal evidence to start a new session."
            )

    def reseal(self) -> SessionInfo:
        """Re-seal evidence files after a tamper event or manual intervention.

        Creates a new session with fresh hashes. The old session is abandoned.
        """
        if self.evidence_dir is None:
            raise ValueError("No evidence directory set. Call initialize() first.")
        return self.initialize(self.evidence_dir)

    def get_manifest(self) -> dict[str, str]:
        """Return the current hash manifest (filepath → truncated SHA-256)."""
        return {
            fp: rec.sha256[:16] + "..."
            for fp, rec in self._hash_manifest.items()
        }

    def is_sealed_file(self, filepath: str) -> bool:
        """Check if a file is part of the sealed evidence set."""
        resolved = str(Path(filepath).resolve())
        return resolved in self._hash_manifest or filepath in self._hash_manifest

    def _discover_evidence_files(self, root: Path) -> list[Path]:
        """Recursively find evidence files by extension."""
        files = []
        for entry in root.rglob("*"):
            if entry.is_file() and entry.suffix.lower() in EVIDENCE_EXTENSIONS:
                files.append(entry.resolve())
        return sorted(files)

    def _seal_file(self, filepath: Path) -> HashRecord:
        """Compute SHA-256 hash and create a HashRecord."""
        sha256 = self._compute_sha256(filepath)
        size = filepath.stat().st_size
        return HashRecord(
            filepath=str(filepath),
            sha256=sha256,
            size_bytes=size,
            sealed_at=datetime.now(timezone.utc).isoformat(),
        )

    @staticmethod
    def _compute_sha256(filepath: Path) -> str:
        """Compute SHA-256 hash of file contents (not metadata).

        Reads in 64KB chunks to handle large evidence images efficiently.
        """
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256.update(chunk)
        except (OSError, PermissionError) as e:
            # File deleted or inaccessible — treat as tampered
            return f"ERROR:{e}"
        return sha256.hexdigest()
