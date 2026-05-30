#!/usr/bin/env python
"""Scrub a real capture hostname from a shared EVTX demo fixture.

`evidence/Application_small.evtx` was captured on a real workstation and ships
in a *public* repo, where `parse_evtx` reads it live. This replaces an embedded
host FQDN with a benign, equal-length placeholder via in-place UTF-16LE byte
substitution (EVTX stores strings as UTF-16LE).

The host to scrub is supplied at runtime (argument or `SCRUB_OLD_HOST`) and is
deliberately NOT hardcoded here, so the original hostname never lands in this
public source file.

Why equal-length: the hostname lives inside binary-XML template instances whose
length prefixes and surrounding offsets must stay byte-for-byte stable. The
script refuses any replacement of a different character length.

Why CRCs are not recomputed: the only consumer is python-evtx, which does not
validate chunk CRC32s on read, and evidence integrity here is a *live* SHA-256
over the current bytes at session-seal time, not the on-disk EVTX checksum.

NOTE: this rewrites the working file only. The original bytes remain in git
history; purging those requires a history rewrite + force-push (owner decision).

Usage:
    SCRUB_OLD_HOST="<real-host>" python scripts/scrub_evtx_hostname.py
    python scripts/scrub_evtx_hostname.py <file.evtx> <old-host> [new-host]
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

DEFAULT_TARGET = Path("evidence/Application_small.evtx")
DEFAULT_NEW_HOST = "DESKTOP-VICTUS.forensics.example.io"


def scrub_bytes(raw: bytes, old: str, new: str) -> tuple[bytes, int]:
    """Replace every UTF-16LE occurrence of `old` with `new`.

    Returns the scrubbed bytes and the number of occurrences replaced. Raises
    ValueError if the replacement is not the same character length (which would
    shift EVTX binary-XML offsets and corrupt the file).
    """
    if len(old) != len(new):
        raise ValueError(
            f"replacement length mismatch: {len(old)} vs {len(new)} chars "
            "(EVTX offsets require an equal-length substitution)"
        )
    old_b = old.encode("utf-16-le")
    new_b = new.encode("utf-16-le")
    count = raw.count(old_b)
    return raw.replace(old_b, new_b), count


def main(argv: list[str]) -> int:
    target = Path(argv[1]) if len(argv) > 1 else DEFAULT_TARGET
    old_host = argv[2] if len(argv) > 2 else os.environ.get("SCRUB_OLD_HOST", "")
    new_host = argv[3] if len(argv) > 3 else os.environ.get("SCRUB_NEW_HOST", DEFAULT_NEW_HOST)

    if not old_host:
        print(
            "ERROR: supply the host to scrub via argv[2] or SCRUB_OLD_HOST "
            "(not hardcoded, to keep it out of this public file).",
            file=sys.stderr,
        )
        return 2
    if not target.exists():
        print(f"ERROR: {target} not found", file=sys.stderr)
        return 2

    raw = target.read_bytes()
    scrubbed, count = scrub_bytes(raw, old_host, new_host)
    if count == 0:
        print(f"No occurrences of the supplied host in {target} — nothing to do.")
        return 0

    # Back up OFF-repo (temp dir) so the recovery copy never re-introduces the
    # leak into the public tree.
    backup = Path(tempfile.gettempdir()) / (target.name + ".prescrub.bak")
    backup.write_bytes(raw)

    target.write_bytes(scrubbed)
    print(
        f"Scrubbed {count} occurrence(s) -> {new_host!r} in {target}.\n"
        f"Off-repo backup: {backup}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
