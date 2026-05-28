# Try It Out — Judge Walkthrough

**See it first (2 min):** demo video at **https://youtu.be/7VTVS9E6cX8**.

Every step below is copy-paste with the **expected output** shown. Two ways to run:
the **manual walkthrough** (this doc) or the **one-command orchestrator**
(`python demo/record_demo.py` — runs the demo acts in sequence with pacing).

Prereqs: **Python 3.11+** (Docker optional, only for the full SIFT live environment).

---

## 1. Clone + install

```bash
git clone https://github.com/sgharlow/find-evil.git
cd find-evil
pip install -e ".[dev]"        # installs mcp>=1.27 (required for the live agent)
```

## 2. Run the test suite

```bash
pytest tests/ -q
```
**Expect:** `550 passed, 1 skipped` (the 1 skip is a Windows-admin-only symlink test; it runs on Linux/SIFT).

## 3. Run the automated proof

```bash
python demo/validate_submission.py
```
**Expect:** a pass/fail checklist ending in `Total checks: 49 / Passed: 49 / Failed: 0 — ALL CHECKS PASSED`. This script *is* the proof — every claim is verified live.

## 4. Run a simulated investigation (any laptop)

```bash
python demo/run_investigation.py
```
**Expect:** the 7-phase investigation, `6 accepted, 4 self-corrected`, and a ~149-entry audit trail. Writes `output/audit_trail.jsonl` + `output/ir_report.md` (`mode: simulated`).

## 5. Run against REAL evidence (live backends)

```bash
python demo/run_live_investigation.py
```
**Expect:** seals 3 real files (SHA-256), then **live** `python-evtx` (10 real events), `python-registry` (3 services incl. `WinUpdateHelper`), and `yara-python` (9 matches incl. Cobalt Strike / Mimikatz / C2). The DRS gate **self-corrects** every single-source finding (it will not accept an uncorroborated claim — the anti-hallucination control). Writes `output/live_audit_trail.jsonl` (`mode: live`). *Drop a `.raw`/`.vmem` memory image into `evidence/` to add live Volatility3 and corroborated ACCEPTs.*

## 6. Tamper detection (the integrity guarantee)

```bash
python demo/video_demo.py        # or: python demo/tamper_demo.py
```
**Expect:** seal → investigate → a red `EVIDENCE INTEGRITY VIOLATION DETECTED` banner when a sealed file is modified → `ANALYSIS HALTED, all findings voided` → re-seal/recovery → IR report. Byte-content change is detected; a `touch` (mtime only) is not.

## 7. Connect Claude Code (the live autonomous agent)

**Simplest (pip, no Docker):**
```bash
claude mcp add find-evil -- python -m find_evil
claude mcp list                  # expect: find-evil ... ✓ Connected
claude                           # then ask it to investigate /evidence (or the repo's evidence/)
```

**Full SIFT environment (real Volatility3/Plaso backends in Docker):**
```bash
docker compose -f docker-compose.sift.yml build      # one-time: builds find-evil-sift:latest
claude mcp add find-evil -- docker run --rm -i -v "$PWD/evidence:/evidence:ro" -v "$PWD/output:/output" find-evil-sift:latest
```
Then in a Claude session: *"Investigate the sealed evidence following your CLAUDE.md protocol; report findings with provenance."* Claude autonomously calls `session_init → verify_integrity → parse_evtx / registry_query / yara_scan …`, and every call is logged to `output/audit_trail.jsonl`.

> Requires `mcp>=1.27` (pinned in `pyproject.toml`); earlier versions had a Context-injection regression.

## 8. Verify the security boundary (constraint implementation)

```bash
python -c "from find_evil.server import mcp; n={t.name for t in mcp._tool_manager.list_tools()}; assert not (n & {'execute_shell_cmd','write_file','rm','dd','shell','bash'}); print(f'{len(n)} tools, zero destructive - PASS')"
```
**Expect:** `15 tools, zero destructive - PASS`. The destructive functions were never implemented — attack surface is zero by construction.

## 9. Trace provenance (audit trail)

```bash
cat output/ir_report.md          # findings cite invocation UUIDs
cat output/audit_trail.jsonl     # one JSON event per line; match the UUIDs
```
Every finding → `invocation_ids[]` → `tool_call_*` records → the verified evidence state at that moment.

---

## One-command orchestrator (used for the demo recording)

```bash
python demo/record_demo.py                 # ACT 1 validate -> 3 real evidence -> 4 tamper, paced
python demo/record_demo.py --with-agent    # also runs the REAL Claude agent (claude -p) as ACT 2
python demo/record_demo.py --pause 0       # no pauses (fast)
```
See [`../demo/VIDEO_SCRIPT.md`](../demo/VIDEO_SCRIPT.md) for the narration that maps onto these acts.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: find_evil` | `pip install -e .` from the repo root |
| Live agent tools fail / `ctx` errors | Upgrade mcp: `pip install -U "mcp[cli]"` (need >=1.27) |
| `claude mcp list` shows not connected | For the pip form, ensure `pip install -e ".[dev]"` ran; for Docker, build the image first |
| `yara_scan` parsing skipped | Install the optional `yara-python` (`pip install -e ".[sift]"`) |
| Tests: 1 skipped | Expected — Windows-admin-only symlink test; runs on Linux/SIFT |
