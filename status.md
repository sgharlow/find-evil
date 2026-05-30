# Find-Evil — Submission Readiness Status

> **OWNER ACTIONS REMAINING (as of 2026-05-26):**
> 1. **Re-record the demo video** (~4–5 min, ≤5 min cap) per `demo/VIDEO_SCRIPT.md`:
>    live terminal + audio narration, **a visible DRS self-correction**, the
>    **tamper-detection HALT + recovery**, against real evidence. Upload **Public**
>    to YouTube ≥48 h before the deadline. (The prior cut is ~2:00 and predates the
>    current 5-min requirement.)
> 2. **Fill + submit the Devpost form** from `DEVPOST_SUBMISSION.md` (field-by-field),
>    upload `screenshots/find-evil-architecture.png` (now carries the pattern +
>    guardrail call-outs) + thumbnail + title images, set the video URL, tick T&Cs,
>    **Submit**, and capture a confirmation screenshot. *No in-repo artifact yet
>    confirms the form was submitted — treat as NOT submitted until you see the
>    confirmation.*
> 3. **Confirm the YouTube video is Public** (open `https://youtu.be/7VTVS9E6cX8`
>    in an incognito tab) — oembed shows it is not private, but public-vs-unlisted
>    is unverified; Devpost wants public.
> 4. **(Optional, high-value) Drop in a memory image** — place a `.raw`/`.vmem`/`.mem`
>    in `evidence/` or set `EVIDENCE_MEMORY`, then run `python demo/run_live_investigation.py`
>    to light up live `vol_pslist/netscan/malfind` and produce corroborated ACCEPTs.
>    The memory phase is fully wired; only the image is missing.

**Hackathon:** SANS (Apr 15 – Jun 15, 2026) · **Deadline:** 2026-06-15
**Submission target:** **2026-06-02** (next Tue; ~11 days inside the 48-h buffer of 2026-06-13)

## Overall: technical deliverables COMPLETE; remaining work is video + form (owner) + optional memory image

Latest commit `2a6cd8e` (+ this sprint's follow-ups). Tests **554 passing / 1 skipped (551 collected)**.
`python demo/validate_submission.py` → **49/49 checks pass**. CI green on Python 3.11 + 3.12.

## DONE (8 SANS deliverables)

- **1 Code repo** — `https://github.com/sgharlow/find-evil` (public, MIT `LICENSE`, `README.md` with setup).
- **2 Demo video** — script ready (`demo/VIDEO_SCRIPT.md`, 5-min). *Re-record pending (owner).*
- **3 Architecture diagram** — `assets/find-evil-architecture.html` source → `screenshots/find-evil-architecture.png` (+ `-mid`). Now **names the pattern (Custom MCP Server)** and **contrasts architectural vs prompt-based guardrails** (Devpost requirement #3). Badge: 555 tests · MITRE 15/11.
- **4 Written description** — `DEVPOST_SUBMISSION.md` (Devpost story format, paste-ready).
- **5 Dataset documentation** — `docs/dataset_documentation.md` + `evidence/README.md` (real EVTX + registry hives + IOC binary; simulated scenario; planned live images).
- **6 Accuracy report** — `docs/accuracy_report.md` + `docs/evidence_integrity_approach.md` (FP/missed/hallucination + bypass-attempt table).
- **7 Try-it-out** — `docs/try_it_out.md` (pip + Docker + `claude mcp add` + security one-liner).
- **8 Agent execution logs** — `output/audit_trail.jsonl` (tool side, real UUID/timestamp/hash) + **`docs/agent_execution_logs.md`** (token-usage profile + `/cost` capture for the LLM side). Sample: `demo/audit_trail_sample.jsonl`.

## This sprint (2026-05-26 — real-data hardening)

- **Live-mode demo** `demo/run_live_investigation.py` — seals the **real** evidence dir and runs genuine live backends (python-evtx: 10 real events; python-registry: 3 real services incl. `WinUpdateHelper`; yara-python: 9 real matches incl. Cobalt Strike/Mimikatz/C2). Produces `output/live_audit_trail.jsonl` (27 real events) + `output/live_ir_report.md` (`Analysis Mode: live`). Memory phase wired to real Volatility3 (`vol`); activates on image drop-in.
- **Core fix** — `EvidenceSession` now seals extensionless registry hives (`SYSTEM`/`SOFTWARE`/`SAM`/`NTUSER.DAT`). +7 unit tests (TDD).
- **Architecture diagram** rebuilt with the required call-outs (above).
- **`docs/agent_execution_logs.md`** added (deliverable #8 token usage).
- **Docs reconciled** — test count → 551/550 across 8 docs; validate-script count → 49; video length → ≤5 min; `submission-needs.pdf` gitignored.

## REMAINING (owner)

| # | Item | Owner |
|---|------|-------|
| 1 | Re-record ~5-min video (self-correction + tamper + real data), upload Public | Steve |
| 2 | Fill + submit Devpost form; capture confirmation screenshot | Steve |
| 3 | Confirm YouTube video is Public | Steve |
| 4 | *(Optional)* Drop in a memory image → re-run live demo for corroborated ACCEPTs | Steve |

## Judges' Evaluation Path

1. `SUBMISSION.md` → index to deliverables.
2. Clone → `pip install -e ".[dev]" && pytest tests/` → 554 passed / 1 skipped.
3. `python demo/run_investigation.py` (simulated, any laptop) **or** `python demo/run_live_investigation.py` (real evidence) → audit trail + IR report + STIX.
4. `python demo/validate_submission.py` → 49/49 checks.
5. Verify security boundary → `src/find_evil/server.py` + the one-liner in `DEVPOST_SUBMISSION.md`.
6. Trace provenance → finding UUID → `audit_trail.jsonl`.
7. MITRE coverage → `README.md` (15 techniques / 11 tactics).
