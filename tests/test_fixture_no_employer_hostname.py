"""Guard: the shared EVTX demo fixture must only ever name a benign host.

`evidence/Application_small.evtx` was captured on a real workstation and ships
in a *public* repo, where it is parsed live by `parse_evtx`. The host embedded
in its bytes must be the benign placeholder installed by
`scripts/scrub_evtx_hostname.py` — never a real/employer hostname.

This guard uses an ALLOWLIST (assert the only host is the benign one) rather
than blocklisting the real hostname, so the sensitive string never appears in
this public test file. If any other host re-enters the fixture, the allowlist
assertion fails.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE = REPO_ROOT / "evidence" / "Application_small.evtx"
SCRUB_SCRIPT = REPO_ROOT / "scripts" / "scrub_evtx_hostname.py"

# The benign, equal-length host the scrub installs — the ONLY host permitted in
# the fixture.
BENIGN_HOST = "DESKTOP-VICTUS.forensics.example.io"


def _load_scrub_module():
    spec = importlib.util.spec_from_file_location("scrub_evtx_hostname", SCRUB_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fixture_bytes_contain_the_benign_host():
    raw = FIXTURE.read_bytes()
    assert BENIGN_HOST.encode("utf-16-le") in raw


def test_fixture_parses_with_only_the_benign_host(monkeypatch):
    pytest.importorskip("Evtx")
    import find_evil.tools.evtx as evtx_mod

    # Force raw values regardless of ambient env so we assert on the bytes,
    # not the runtime redaction map.
    monkeypatch.setattr(evtx_mod, "_COMPUTER_REDACT_MAP", {})
    events = evtx_mod._parse_real_evtx(str(FIXTURE))

    assert len(events) == 10
    # Allowlist: the benign host is the only Computer value present.
    assert {e.get("Computer", "") for e in events} == {BENIGN_HOST}


def test_scrub_bytes_requires_equal_length():
    mod = _load_scrub_module()
    with pytest.raises(ValueError):
        mod.scrub_bytes(b"anything", "short", "a-much-longer-replacement")


def test_scrub_bytes_replaces_and_counts():
    mod = _load_scrub_module()
    old, new = "AB", "XY"  # equal length, no sensitive content
    raw = ("x" + old + "y" + old + "z").encode("utf-16-le")
    scrubbed, count = mod.scrub_bytes(raw, old, new)
    assert count == 2
    assert old.encode("utf-16-le") not in scrubbed
    assert scrubbed == ("x" + new + "y" + new + "z").encode("utf-16-le")
