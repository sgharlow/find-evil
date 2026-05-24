# Find-Evil — Submission Readiness Status

> **OWNER ACTION REQUIRED (2026-05-24):** Devpost form submission is NOT confirmed by any in-repo artifact.
> The PAGE 4 checklist in `DEVPOST_SUBMISSION.md` remains unchecked.
> MEMORY.md says "SUBMITTED early May" but no in-repo evidence (confirmation screenshot,
> submission ID, or checked checklist) corroborates that claim.
> **Action:** Log into `devpost.com/submit-to/29127-find-evil/manage/submissions/995757`,
> confirm whether the form was actually submitted, and capture a confirmation screenshot.
> SANS deadline 2026-06-15 — 48-hr-buffer target is **2026-06-13**.
> Also confirm `https://youtu.be/7VTVS9E6cX8` is set to **Public** (not Unlisted/Private)
> — Devpost requires a publicly accessible video URL.
> See **REMAINING TODO** below for the full owner checklist.

**Last reviewed:** 2026-04-26 (media assets added); banner added 2026-05-24 (no code/docs changed)
**Hackathon:** SANS (Apr 15 – Jun 15, 2026)
**Deadline:** 2026-06-15
**Followup reminder:** **2026-06-01** — confirm Devpost form submission completed and YouTube link is public; final dry-run of `python demo/run_investigation.py` and verify YouTube link still live.

## Overall: 98% READY — GREEN LIGHT (Devpost form submission status unconfirmed)

Repo clean (last commit `f86c4a4`, Apr 24). Tests 543 passing / 1 skipped (544 collected). CI green on Python 3.11 + 3.12. All technical deliverables complete; remaining items are user-only Devpost presentation tasks.

## DONE

- `SUBMISSION.md` — full SANS index, 8 deliverables mapped, no placeholders
- `docs/sans-submission-answers.md` — Q1–Q8 answered (DRS methodology, evidence integrity layers, architecture)
- `README.md` — 238 lines, ASCII architecture, judging-criteria map, MITRE coverage (15 techniques / 11 tactics), STIX format spec
- 15 MCP tools verified real (4 session, 4 volatility, evtx, registry, timeline, yara, 3 findings/STIX)
- STIX 2.1 export — `src/find_evil/tools/findings.py:464–512`, sample at `output/bundle.stix.json`
- Demo video — `assets/Evidence_Integrity_Enforcer.mp4` (32 MB) + YouTube https://youtu.be/7VTVS9E6cX8 (uploaded Apr 18) — **NOTE: public visibility unverified as of 2026-05-24; Devpost requires the URL to be publicly accessible (not Unlisted or Private)**
- Demo artifacts committed in `output/` — audit_trail.jsonl, ir_report.md, bundle.stix.json, findings.db
- 13 screenshot frames + walkthrough.mp4 in `screenshots/`
- **Devpost media assets generated** in `screenshots/` (2026-04-26):
  - `find-evil-thumbnail.png` (+ `-mid` variant) — Devpost form page-1 thumbnail (3:2)
  - `find-evil-architecture.png` (+ `-mid` variant) — rendered architecture diagram (replaces ASCII for Devpost)
  - `find-evil-title.png` (+ `-mid` variant) — title card / video cover frame
- LICENSE (MIT)
- GitHub Actions CI passing on Python 3.11 / 3.12
- Install paths: pip + Docker (`docker-compose.sift.yml`) + Claude Code MCP integration
- `.gitignore` clean, no secrets leaked

## PARTIAL

- `DEVPOST_SUBMISSION.md` is copy-paste-structured but not a standalone PDF deck (acceptable — Devpost form takes pasted text)
- README still references ASCII architecture (lines 24–86); rendered PNG now in `screenshots/find-evil-architecture.png` — *optional:* embed PNG into README

## REMAINING TODO — User Tasks Only

> **Status as of 2026-05-24:** No in-repo artifact confirms the Devpost form was submitted.
> MEMORY.md records "SUBMITTED early May" but the PAGE 4 checklist in `DEVPOST_SUBMISSION.md`
> is still unchecked and no confirmation screenshot is committed. Owner must verify.

1. **Confirm or complete Devpost form submission** at `devpost.com/submit-to/29127-find-evil/manage/submissions/995757`:
   - If already submitted: capture a confirmation screenshot and note the submission ID here.
   - If not yet submitted, complete the form:
     - Upload `screenshots/find-evil-thumbnail.png` as the cover/thumbnail
     - Upload `screenshots/find-evil-architecture.png` in the gallery / project images section
     - Optionally upload `screenshots/find-evil-title.png` as an additional gallery image
     - Paste each section from `DEVPOST_SUBMISSION.md` into the matching form field
     - Verify YouTube link `https://youtu.be/7VTVS9E6cX8` is set as the demo video URL and the video is **set to Public** on YouTube
     - Confirm GitHub repo URL, license (MIT), and team info
     - Submit and capture the confirmation screenshot
2. **Confirm YouTube video public visibility** — open `https://youtu.be/7VTVS9E6cX8` in a private/incognito browser tab (no login). If it plays, it is Public. Devpost will reject or penalize a non-public link.
3. **Commit the new media assets** — `git add screenshots/find-evil-*.png && git commit -m "docs: add Devpost media assets"` (currently uncommitted)
4. *Optional:* Embed `screenshots/find-evil-architecture.png` into `README.md` above the ASCII diagram for richer GitHub presentation
5. *Optional:* Docker SIFT live-mode end-to-end test (pip path already sufficient for judges)

## Timeline

| Milestone | Date | Status |
|-----------|------|--------|
| Demo video uploaded | 2026-04-18 | Done |
| G2 + G3 gaps closed (docs/submission-gaps-2026-04-29.md) | 2026-05-01 | Done |
| G1 + G4 gaps closed (docs/submission-gaps-2026-04-29.md) | 2026-05-08 | Done |
| Devpost media assets added (`screenshots/find-evil-*.png`) | 2026-04-26 | Done (uncommitted) |
| **Followup checkpoint — confirm Devpost submission + YouTube public** | **2026-06-01** | **OWNER ACTION — review this file and verify** |
| Recommended submission target (48-hr buffer) | 2026-06-13 | Pending |
| SANS deadline | 2026-06-15 | — |

## Judges' Evaluation Path

1. Read `SUBMISSION.md` → index to 8 deliverables
2. Clone repo → `pip install -e ".[dev]" && pytest tests/` → 543 passed / 1 skipped
3. Run demo → `python demo/run_investigation.py` (5 min) → audit trail + IR report + STIX bundle
4. Verify security → `src/find_evil/server.py:238–243` + `try_it_out.md` check script → no destructive tools exist
5. Trace finding provenance → UUID in `ir_report.md` → `audit_trail.jsonl`
6. Check MITRE coverage → `README.md:171–193` → 15 techniques / 11 tactics
