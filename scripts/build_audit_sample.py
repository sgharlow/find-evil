"""Curate a small, redacted, judge-friendly audit-trail excerpt.

Reads output/audit_trail.jsonl (produced by demo/run_investigation.py) and
writes demo/audit_trail_sample.jsonl with one entry per major event type.
Appends a representative session_halt entry via the real AuditLogger so all
six DEVPOST deliverable #8 event types are present.

Usage:
    python scripts/build_audit_sample.py
"""
from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

from find_evil.audit.logger import AuditLogger

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "output" / "audit_trail.jsonl"
DST = ROOT / "demo" / "audit_trail_sample.jsonl"

WANTED_ORDER = [
    "session_start",
    "integrity_check",
    "tool_call_start",
    "tool_call_complete",
    "finding_committed",
    "self_correction",
]


def redact(obj):
    if isinstance(obj, dict):
        return {k: redact(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    if isinstance(obj, str):
        s = obj
        s = re.sub(r"[Cc]:\\Users\\[^\\\"\s]+", r"<HOME>", s)
        s = re.sub(r"/Users/[^/\"\s]+", r"/Users/<HOME>", s)
        s = re.sub(r"sgharlow", "<USER>", s, flags=re.IGNORECASE)
        s = re.sub(r"WIN-[A-Z0-9]+", "<HOSTNAME>", s)
        return s
    return obj


def main() -> int:
    events = [json.loads(line) for line in SRC.read_text(encoding="utf-8").splitlines() if line.strip()]
    sample: list[dict] = []
    for kind in WANTED_ORDER:
        match = next((e for e in events if e.get("event") == kind), None)
        if match is None:
            print(f"WARN: no {kind} found in {SRC}")
            continue
        sample.append(redact(match))

    # Generate a real session_halt event via AuditLogger.
    # Uses a tempdir so we don't pollute output/ — we just want one well-formed line.
    with tempfile.TemporaryDirectory() as td:
        tmp_log = Path(td) / "halt.jsonl"
        logger = AuditLogger(path=str(tmp_log))
        logger.log_session_halt(
            "DEMONSTRATIVE: integrity violation simulated for judge inspection. "
            "See test_security_bypass.py and demo/tamper_demo.py for live triggers."
        )
        halt_line = tmp_log.read_text(encoding="utf-8").splitlines()[-1]
        sample.append(redact(json.loads(halt_line)))

    DST.parent.mkdir(parents=True, exist_ok=True)
    with DST.open("w", encoding="utf-8") as f:
        for e in sample:
            f.write(json.dumps(e) + "\n")

    kinds = [e.get("event") for e in sample]
    print(f"Wrote {DST.relative_to(ROOT)} with {len(sample)} entries: {kinds}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
