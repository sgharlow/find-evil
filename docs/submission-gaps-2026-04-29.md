# Find Evil — SUBMISSION.md Gap Audit (2026-04-29)

**Auditor:** Claude (executed via `/execute-session` Story 2 from `session-prd-2026-04-29-b.md`)
**Scope:** Verify SUBMISSION.md against the SANS hackathon 8-deliverable checklist and the 15-tool inventory claim.
**Source of truth for tools:** `@mcp.tool()` decorators in `src/find_evil/**/*.py`.

## TL;DR

SUBMISSION.md is **submission-ready** — all 8 SANS deliverables are linked, GitHub + demo video URLs resolve, license is present. **One gap:** the document delegates the 15-tool list to `README.md` rather than enumerating the tools inline with one-line descriptions. Fix is optional (judges will follow the link), but inlining makes the doc self-contained.

## Status (2026-05-08 update)

| Gap | Priority | Status |
|-----|----------|--------|
| G1 — Tool list not inline | LOW | ✅ CLOSED 2026-05-08 — inline 15-tool table added to `SUBMISSION.md` after the "15 forensic tools" sentence; Deliverable #3 row updated to point at it |
| G2 — `docs/sans-submission-answers.md` presence | MEDIUM | ✅ CLOSED 2026-05-01 — file present (19,530 bytes), both refs resolve |
| G3 — Test count claim "544" | MEDIUM | ✅ CLOSED 2026-05-01 — pytest verifies 544 (543 passed, 1 skipped); all docs consistent |
| G4 — Hackathon header dates | LOW | ✅ CLOSED 2026-05-08 — header reads "Apr 15 – Jun 15, 2026"; dates internally consistent across `SUBMISSION.md`, `README.md`, `status.md`, `MEMORY.md` row 17. Submission deadline 2026-06-15 confirmed in MEMORY. No formatting issue. |

All four gaps resolved. SUBMISSION.md is judging-ready against the 8-deliverable checklist.

## 15-Tool Inventory — Verified Present in Source

Counted `@mcp.tool()` decorators across the codebase:

| #  | Tool                   | File                                | Phase            | One-line description                                                              |
|----|------------------------|-------------------------------------|------------------|-----------------------------------------------------------------------------------|
| 1  | `session_init`         | `src/find_evil/server.py`           | 0 SEAL           | Initialize an evidence session and seal all files with SHA-256 hashes             |
| 2  | `verify_integrity`     | `src/find_evil/server.py`           | 0 SEAL           | Verify hashes of all sealed evidence files match originals                        |
| 3  | `list_sealed_evidence` | `src/find_evil/server.py`           | 0 SEAL           | List sealed evidence files and their hash fingerprints                            |
| 4  | `reseal_evidence`      | `src/find_evil/server.py`           | 0 SEAL           | Re-seal evidence after a tamper event or manual intervention                      |
| 5  | `vol_pslist`           | `src/find_evil/tools/volatility.py` | 1 TRIAGE         | List running processes from a Windows memory image (Volatility3)                  |
| 6  | `vol_netscan`          | `src/find_evil/tools/volatility.py` | 1 TRIAGE         | List network connections from a Windows memory image (Volatility3)                |
| 7  | `vol_malfind`          | `src/find_evil/tools/volatility.py` | 2 DEEP MEMORY    | Detect injected code in process memory (Volatility3 malfind)                      |
| 8  | `vol_cmdline`          | `src/find_evil/tools/volatility.py` | 2 DEEP MEMORY    | Get command-line arguments for processes from a memory image                      |
| 9  | `parse_evtx`           | `src/find_evil/tools/evtx.py`       | 3 LOGS           | Parse Windows EVTX files filtering by Event ID                                    |
| 10 | `registry_query`       | `src/find_evil/tools/registry.py`   | 4 PERSISTENCE    | Query a Windows registry hive for persistence indicators                          |
| 11 | `build_timeline`       | `src/find_evil/tools/timeline.py`   | 5 TIMELINE       | Generate a super-timeline from disk + memory + log evidence                       |
| 12 | `yara_scan`            | `src/find_evil/tools/yara_scan.py`  | 6 IOC SCAN       | Scan files or memory with YARA rules for malware/IOC matches                      |
| 13 | `submit_finding`       | `src/find_evil/tools/findings.py`   | 7 SYNTHESIS      | Submit a finding through the DRS confidence gate for inclusion in the report      |
| 14 | `generate_report`      | `src/find_evil/tools/findings.py`   | 7 SYNTHESIS      | Generate a structured incident response report from accepted findings             |
| 15 | `export_stix`          | `src/find_evil/tools/findings.py`   | 7 SYNTHESIS      | Export findings and IOCs as a STIX 2.1 bundle for threat-intel interop            |

**Count: 15 ✓** (matches the SUBMISSION.md / README claim).

## SANS 8-Deliverable Checklist (against current SUBMISSION.md)

| #  | Deliverable                            | Linked in SUBMISSION.md? | Notes                                                          |
|----|----------------------------------------|--------------------------|----------------------------------------------------------------|
| 1  | Project description + value prop       | ✅ Yes                   | Top-of-file paragraph + README pointer                         |
| 2  | Architecture diagram                   | ✅ Yes                   | Points to README ASCII diagram (lines 23-100)                  |
| 3  | Tool inventory                         | ⚠️ Indirect              | Delegated to README; not enumerated in SUBMISSION.md itself    |
| 4  | Test strategy + results                | ✅ Yes                   | "544 tests" called out (verify against latest pytest, see #G3) |
| 5  | Demo video + scripts                   | ✅ Yes                   | YouTube URL + demo/ directory                                  |
| 6  | STIX 2.1 export format                 | ✅ Yes                   | README pointer to sample indicator                             |
| 7  | Try-it-out guide                       | ✅ Yes                   | docs/try_it_out.md                                             |
| 8  | Accuracy / DRS methodology             | ✅ Yes                   | docs/accuracy_report.md                                        |

## Open Gaps

### G1 — Tool list not inline (LOW)
**Observation:** SUBMISSION.md says "15 forensic tools" but does not enumerate them. Judges must navigate to README.md for the inventory.
**Recommendation:** Optional — paste the 15-row table from this doc directly into SUBMISSION.md (after line 16 "the server ships with 15 forensic tools"). Self-contained submission docs are a courtesy.
**Priority:** LOW — passing on its own.
**Resolution (2026-05-08):** ✅ CLOSED. Inline 15-tool table added to `SUBMISSION.md` directly after the "15 forensic tools" sentence. Deliverable #3 row updated to "Inline table above (15 Forensic Tools); MITRE mapping in README.md". Submission doc is now self-contained for tool inventory.

### G2 — `docs/sans-submission-answers.md` not verified to exist
**Observation:** SUBMISSION.md references this file twice. I did not verify file presence in this audit.
**Recommendation:** `ls -1 find-evil/docs/sans-submission-answers.md` before final submission.
**Priority:** MEDIUM — broken-link risk.
**Resolution (2026-05-01):** ✅ CLOSED. File exists (`docs/sans-submission-answers.md`, 19,530 bytes). Both inline references in SUBMISSION.md (lines 10 and 22) resolve to the present file. No broken-link risk.

### G3 — Test count claim "544" needs re-verification
**Observation:** SUBMISSION.md says 544 (543 passing, 1 skipped). MEMORY.md and CLAUDE.md say 541. Numbers should match before submission.
**Recommendation:** Run `pytest --collect-only -q | tail -3` and reconcile across SUBMISSION.md, README.md, and MEMORY.md.
**Priority:** MEDIUM — minor credibility hit if numbers diverge.
**Resolution (2026-05-01):** ✅ CLOSED. `pytest --collect-only -q` reports **544 tests collected**; `pytest -q` reports **543 passed, 1 skipped in 11.49s**. SUBMISSION.md (lines 25, 46), README.md (lines 116, 157), and MEMORY.md row 17 are all consistent at 544 (543 passing, 1 skipped). The audit's "541" reference was based on a pre-rebaseline snapshot — no divergence remains.

### G4 — Hackathon window dates static
**Observation:** Header says "Apr 15 – Jun 15, 2026". Submission deadline is Jun 15. No dynamic deadline reminder needed for judges, but worth confirming dates match the official Devpost listing.
**Priority:** LOW — formatting only.
**Resolution (2026-05-08):** ✅ CLOSED. Dates "Apr 15 – Jun 15, 2026" are internally consistent across `SUBMISSION.md` (line 3), `README.md`, `status.md`, and `MEMORY.md` row 17. Submission deadline of 2026-06-15 confirmed in MEMORY index. Header format is plain prose, no static-date hazard for judges. No edit needed beyond consistency check.

## Files referenced (no edits made by this audit)

- `src/find_evil/server.py:97,138,176,200`
- `src/find_evil/tools/volatility.py:154,204,253,299`
- `src/find_evil/tools/evtx.py:98`
- `src/find_evil/tools/registry.py:177`
- `src/find_evil/tools/timeline.py:97`
- `src/find_evil/tools/yara_scan.py:309`
- `src/find_evil/tools/findings.py:77,201,463`
- `SUBMISSION.md` (0 edits — read-only audit)
