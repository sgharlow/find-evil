# Submission Readiness — 2026-04-24

> One-page green-light sheet for the SANS FIND EVIL! Devpost submission
> (`devpost.com/submit-to/29127-find-evil/manage/submissions/995757`).
> Submission window: Apr 15 – Jun 15, 2026.

## Pre-submit verification — all green

| # | Check | Command / source | Result |
|---|---|---|---|
| 1 | Documentation drift guard | `pytest tests/test_docs_consistency.py` | **PASS** (53/53) |
| 2 | Test-count consistency in `DEVPOST_SUBMISSION.md` | manual diff vs `SUBMISSION.md` | **PASS** — three stale lines (129, 155, 383) fixed in this session to read 543 / 1 / 544 |
| 3 | Full pytest suite with SIFT optional deps installed | `pytest tests/` | **PASS** — **543 passed, 1 skipped, 0 failed** — exact match to the canonical claim in `SUBMISSION.md`/`README.md`. The single skip is the Windows-admin-only symlink test in `test_security_bypass.py`. |
| 4 | `validate_submission.py` | `python demo/validate_submission.py` | **PASS** — 49 of 49 automated judging-criteria checks (re-run after SIFT install confirmed below) |
| 5 | Investigation demo runnable end-to-end | `python demo/run_investigation.py` | **PASS** — 118 audit entries, 6 findings accepted, 4 self-corrections, IR report + STIX bundle produced |
| 6 | Demo artifacts present + non-empty | `ls -lh output/audit_trail.jsonl output/ir_report.md` | **PASS** — 58K + 4.3K |
| 7 | Audit-trail excerpt for judges | `demo/audit_trail_sample.jsonl` | **PASS** — 7 entries, all 6 required event types (`session_start`, `integrity_check`, `tool_call_start`, `tool_call_complete`, `finding_committed`, `self_correction`, `session_halt`); regenerable via `python scripts/build_audit_sample.py` |
| 8 | Anonymity / employer scrub | `grep -inE "opus.?inspection\|virginia\b\|\b189\b\|\b191\b\|\b198\b" SUBMISSION.md DEVPOST_SUBMISSION.md README.md docs/sans-submission-answers.md docs/dataset_documentation.md docs/accuracy_report.md` | **PASS** — zero hits across all 6 submission docs |
| 9 | Demo video URL | `https://youtu.be/7VTVS9E6cX8` | **PASS** — referenced in `SUBMISSION.md` and `DEVPOST_SUBMISSION.md` |
| 10 | GitHub URL | `https://github.com/sgharlow/find-evil` | **PASS** — referenced in `SUBMISSION.md` and `DEVPOST_SUBMISSION.md` |

## Local environment now matches the docs claim

Installed the full SIFT optional-deps group via `pip install -e ".[sift]"` during this session — pulled in `volatility3 2.27.0`, `python-evtx 0.8.1`, `yara-python 4.5.4`, `python-registry 1.3.1`, `regipy 6.2.1`. Docker Desktop daemon is running locally (`29.4.0`) so the Docker smoke tests collect normally.

Result: local pytest now reports **543 passed, 1 skipped** — exact match to `SUBMISSION.md`. No further action needed on the test-count drift.

## Files changed in this session

```
M  DEVPOST_SUBMISSION.md          # 3 stale test-count lines + audit-sample link + try-it-out link
?  demo/audit_trail_sample.jsonl  # 7-entry redacted excerpt for Devpost deliverable #8
?  scripts/build_audit_sample.py  # regenerator for the excerpt
?  docs/submission-readiness-2026-04-24.md  # this file
```

No tests were modified. No production code was modified.

## What still needs Steve before clicking Submit

These are USER-only — Claude cannot do them.

1. **Devpost thumbnail** (`demo/thumbnail.png`, 3:2, ≤5 MB) — DEVPOST page 1 requires it.
2. **Architecture diagram as PNG/PDF** — currently only ASCII in README. Devpost wants the Custom-MCP-Server pattern + prompt-vs-architectural callout visible.
3. **Click through Devpost submission flow** — DEVPOST_SUBMISSION.md is structured page-by-page; copy-paste each block, then tick T&Cs on page 4.
4. *(Optional, non-blocking)* Test Docker SIFT live mode (`docker compose -f docker-compose.sift.yml up`) — deferred from Apr 18 per memory `project_findevil_docker_deferred.md`. Pip path is sufficient for submission.

## Lead time

Devpost requires the demo video uploaded ≥48 hr before deadline → **submit by ~Jun 13** to be safe. 50 days of slack remains as of today.
