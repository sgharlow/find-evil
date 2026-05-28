#!/usr/bin/env python3
"""Live tamper detection on the REAL committed evidence.

Seals writable copies of the actual evidence files (Application_small.evtx +
SYSTEM/SOFTWARE registry hives) with real SHA-256, confirms integrity, then
modifies one byte and shows the daemon halt the session and void findings.
Everything here is real: real files, real hashing, real detection, real halt.

    python demo/live_tamper.py            # auto-tamper (smooth, deterministic; for recording)
    python demo/live_tamper.py --manual   # PAUSE so you tamper a sealed file in another terminal
"""
import argparse
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# The daemon logs an ERROR when it detects the (intended) tamper; silence it so
# only this script's formatted banner shows on camera.
import logging
logging.getLogger("find_evil.hash_daemon").setLevel(logging.CRITICAL)

from find_evil.session.manager import EvidenceSession
from find_evil.session.hash_daemon import HashDaemon
from find_evil.audit.logger import AuditLogger

REPO = Path(__file__).parent.parent
REAL_FILES = ["Application_small.evtx", "SYSTEM", "SOFTWARE"]
BANG = "!" * 60


def main():
    ap = argparse.ArgumentParser(description="Live tamper detection on real evidence")
    ap.add_argument("--manual", action="store_true",
                    help="pause so YOU tamper a sealed file in another terminal (most dramatic on camera)")
    args = ap.parse_args()

    print("=" * 70)
    print("  EVIDENCE INTEGRITY ENFORCER - Live Tamper Detection (REAL evidence)")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as td:
        ev = Path(td)
        for name in REAL_FILES:
            shutil.copy2(REPO / "evidence" / name, ev / name)

        session = EvidenceSession()
        audit = AuditLogger(path=str(ev / "_audit.jsonl"))

        # SEAL (real SHA-256 over the real evidence copies)
        info = session.initialize(str(ev))
        audit.set_session_id(info.session_id)
        audit.log_session_start(info.model_dump())
        print(f"\n[SEAL] {info.file_count} REAL evidence files sealed with SHA-256:")
        for fp, h in info.manifest.items():
            print(f"    {Path(fp).name:24s} {h}")

        # Daemon verifies every 30s AND the enforce() gate verifies before every
        # tool call; here we trigger the synchronous check explicitly.
        daemon = HashDaemon(session, interval=30)
        daemon.start()
        r = daemon.verify_now()
        print(f"\n[VERIFY] integrity: {'VERIFIED - all files intact' if r.passed else 'VIOLATION'} "
              f"({r.files_checked} files checked)")

        target = ev / "Application_small.evtx"
        if args.manual:
            print(f"\n[TAMPER] In ANOTHER terminal, modify the sealed evidence, then press Enter here:")
            print(f'    echo TAMPERED >> "{target}"')
            try:
                input()
            except EOFError:
                pass
        else:
            print(f"\n[TAMPER] modifying one byte of the sealed evidence:")
            print(f"    $ echo 'TAMPERED' >> {target.name}")
            with open(target, "ab") as f:
                f.write(b"\x00TAMPERED\x00")

        time.sleep(0.3)

        # VERIFY again -> real content-hash mismatch
        r = daemon.verify_now()
        audit.log_integrity_check(r.model_dump())
        print()
        if r.passed:
            print("  ERROR: tamper was NOT detected (unexpected).")
            daemon.stop()
            sys.exit(1)
        print("  " + BANG)
        print("  ! EVIDENCE INTEGRITY VIOLATION DETECTED                     !")
        print("  " + BANG)
        for v in r.failures:
            print(f"  File:     {Path(v['file']).name}")
            print(f"  Expected: {v['expected']}")
            print(f"  Actual:   {v['actual']}   <-- CONTENT HASH MISMATCH")
        print("\n  ANALYSIS HALTED - chain of custody broken. All findings voided.")
        audit.log_session_halt("Live tamper detected on real evidence")

        print(f"\n[HALT] session active: {session.is_active}")

        # RECOVER
        new = session.reseal()
        daemon.stop()
        print(f"[RECOVER] evidence re-sealed -> new session {new.session_id[:8]}... "
              f"(active: {session.is_active})")

        print("\n" + "=" * 70)
        print("  Real SHA-256 detection on a real Windows EVTX. Not a prompt rule the")
        print("  agent can argue with - a cryptographic halt enforced by the server.")
        print("=" * 70)


if __name__ == "__main__":
    main()
