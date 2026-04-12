#!/usr/bin/env python3
"""Tamper Detection Demo — the submission's signature moment.

This script demonstrates the evidence integrity enforcement system:
1. Creates mock evidence files
2. Seals them with SHA-256 hashes
3. Starts the hash daemon
4. Tampers with an evidence file (BYTE-LEVEL modification, not touch)
5. Verifies the daemon detects the tamper and halts the session

IMPORTANT: The original spec used `touch` to demonstrate tampering.
`touch` only changes mtime/atime metadata — SHA-256 hashes file CONTENT.
`touch` would NOT trigger detection. This demo correctly modifies bytes.

Usage:
    python demo/tamper_demo.py
"""

import sys
import time
import tempfile
from pathlib import Path

# Add project to path for standalone execution
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from find_evil.session.manager import EvidenceSession
from find_evil.session.hash_daemon import HashDaemon
from find_evil.audit.logger import AuditLogger


def main():
    print("=" * 70)
    print("  EVIDENCE INTEGRITY ENFORCER — Tamper Detection Demo")
    print("=" * 70)
    print()

    # 1. Create mock evidence files
    with tempfile.TemporaryDirectory() as tmpdir:
        evidence_dir = Path(tmpdir)
        files = {
            "victim-hdd.img": b"DISK_IMAGE_CONTENT_" + b"x" * 1000,
            "memory.raw": b"MEMORY_DUMP_CONTENT_" + b"y" * 500,
            "network.pcap": b"PCAP_CAPTURE_DATA_" + b"z" * 300,
        }
        for name, content in files.items():
            (evidence_dir / name).write_bytes(content)

        print(f"[SETUP] Created {len(files)} mock evidence files in {evidence_dir}")
        print()

        # 2. Seal evidence
        session = EvidenceSession()
        audit = AuditLogger(path=str(evidence_dir / "demo_audit.jsonl"))

        print("[STEP 1] Sealing evidence files with SHA-256 hashes...")
        info = session.initialize(str(evidence_dir))
        audit.set_session_id(info.session_id)
        audit.log_session_start(info.model_dump())

        print(f"  Session ID: {info.session_id}")
        print(f"  Files sealed: {info.file_count}")
        for filepath, hash_prefix in info.manifest.items():
            name = Path(filepath).name
            print(f"    {name:20s}  sha256: {hash_prefix}  SEALED")
        print()

        # 3. Start hash daemon
        daemon = HashDaemon(session, interval=2)  # 2s for fast demo
        daemon.start()
        print("[STEP 2] Hash daemon started (2-second verification cycle)")
        print()

        # 4. Verify integrity passes
        print("[STEP 3] Verifying integrity (should pass)...")
        result = daemon.verify_now()
        print(f"  Status: {'OK' if result.passed else 'VIOLATION'}")
        print(f"  Files verified: {result.files_checked}")
        assert result.passed, "Integrity should pass before tamper"
        print()

        # 5. Tamper with evidence (BYTE modification, NOT touch)
        target = evidence_dir / "victim-hdd.img"
        print(f"[STEP 4] TAMPERING with evidence: {target.name}")
        print("  (Appending bytes — SHA-256 detects content changes, not metadata)")
        with open(target, "ab") as f:
            f.write(b"\x00\x00TAMPERED_BY_ADVERSARY\x00\x00")
        print("  Evidence file modified.")
        print()

        # 6. Verify integrity fails
        print("[STEP 5] Verifying integrity (should FAIL)...")
        result = daemon.verify_now()
        audit.log_integrity_check(result.model_dump())

        if not result.passed:
            print()
            print("  " + "!" * 60)
            print("  ! EVIDENCE INTEGRITY VIOLATION DETECTED                    !")
            print("  " + "!" * 60)
            print()
            for violation in result.failures:
                name = Path(violation["file"]).name
                print(f"  File:     {name}")
                print(f"  Expected: {violation['expected']}")
                print(f"  Actual:   {violation['actual']}")
            print()
            print("  ANALYSIS HALTED — chain of custody broken.")
            print("  All findings voided. Session suspended.")
            audit.log_session_halt("Tamper detected during demo")
        else:
            print("  ERROR: Tamper was NOT detected. This should not happen.")
            daemon.stop()
            sys.exit(1)

        print()

        # 7. Verify session is halted
        print("[STEP 6] Confirming session is halted...")
        print(f"  Session active: {session.is_active}")
        assert not session.is_active, "Session should be halted after tamper"
        print()

        # 8. Re-seal and resume
        print("[STEP 7] Re-sealing evidence (new session)...")
        new_info = session.reseal()
        daemon.stop()
        daemon = HashDaemon(session, interval=2)
        daemon.start()

        print(f"  New session ID: {new_info.session_id}")
        print(f"  Files sealed: {new_info.file_count}")
        print(f"  Session active: {session.is_active}")
        assert session.is_active, "Session should be active after reseal"
        print()

        # Cleanup
        daemon.stop()

        print("=" * 70)
        print("  Demo complete. Evidence integrity enforcement verified.")
        print()
        print("  Key takeaway: SHA-256 hashes file CONTENT, not metadata.")
        print("  `touch` would NOT trigger detection — byte modification does.")
        print("  The agent cannot bypass this — destructive functions don't exist.")
        print("=" * 70)


if __name__ == "__main__":
    main()
