# 

| Hackathon | Project   | Deadline   | Days Left | Code Done       | Repo Public?         | Demo Recordable Today?                  |
| --------- | --------- | ---------- | --------- | --------------- | -------------------- | --------------------------------------- |
| SANS DFIR | Find Evil | 2026-06-15 | 58        | YES (544 tests) | Private (flip later) | YES — local Python demo runs end-to-end |

---



## 2. FIND EVIL — SANS DFIR

### 2A. Submission Metadata (paste-ready)

| Field    | Value                                                           |
| -------- | --------------------------------------------------------------- |
| Name     | Evidence Integrity Enforcer                                     |
| Repo     | https://github.com/sgharlow/find-evil (currently PRIVATE)       |
| Demo URL | None hosted — distributed via `pip install` or `docker compose` |
| License  | MIT                                                             |
| Team     | Steve Harlow (solo)                                             |

**Tagline:** *MCP server making forensic evidence tampering architecturally impossible: 15 read-only tools, SHA-256 sealing, DRS confidence gate, UUID audit trail. Not a prompt rule — a function registry.*

**Description (~150 words):**

> Evidence Integrity Enforcer is a custom MCP server that wraps the SIFT Workstation forensic stack (Volatility3, python-evtx, python-registry, YARA, Plaso) as exactly 15 typed, read-only functions. An autonomous Claude Code agent investigates evidence through those functions and only those functions. Four architectural controls make tampering impossible: (1) destructive functions like `execute_shell`, `write_file`, `rm`, `dd` simply do not exist in the registry — zero attack surface by construction; (2) SHA-256 content sealing with a 30-second background daemon and synchronous re-verification before every tool call; (3) a DRS confidence gate that forces self-correction below 0.75 confidence; (4) a UUID-linked JSONL audit trail tracing every finding back to the verified evidence state at the moment of analysis. Output is a court-quality IR report plus a STIX 2.1 bundle for MISP/OpenCTI/ThreatConnect ingestion.

**Tech stack:** Python 3.11+, FastMCP, MCP stdio transport, Pydantic, Volatility3, python-evtx, python-registry, regipy, yara-python, Plaso, SHA-256, SQLite, Docker, docker-compose, pytest (544), JSONL audit, STIX 2.1, MITRE ATT&CK. SIFT Workstation host. Claude Code agent.

**Judging-criteria alignment** (`README.md:139-146`):

- *Constraint Implementation (HIGH):* destructive tools don't exist
- *Audit Trail Quality (HIGH):* UUID provenance: finding → tool call → verified evidence
- *IR Accuracy (HIGH):* typed JSON, not raw text
- *Autonomous Execution (TIEBREAKER):* DRS gate self-correction
- *Breadth/Depth (MED):* 15 tools, 15 MITRE techniques across 11 tactics
- *Usability (MED):* `pip install -e .` + one command, OR `docker compose up`

**Pre-existing source-of-truth files:** `DEVPOST_SUBMISSION.md` (25 KB) and `docs/sans-submission-answers.md` (19 KB).

### 2B. Branding Brief

**Visual identity:** Deep forensic indigo `#1a1f3a`, alert crimson `#d93636`, integrity-seal cyan `#00b4d8`, court-document cream `#f5f1e8`. Mood: methodical, immutable, evidentiary — locked steel evidence locker, not a hacker terminal. Metaphor: a wax seal stamped with SHA-256 that breaks visibly when tampered with; a chain of custody links forming a circular UUID.

**Logo prompt:**

> A minimalist square logo for "Evidence Integrity Enforcer," a digital forensics tool. Centered: a hexagonal wax seal in deep indigo (#1a1f3a) with a stylized SHA-256 hash pattern engraved across its face, broken by a single thin crimson (#d93636) crack only on the left half — symbolizing tamper detection. Surround the seal with a thin cyan (#00b4d8) chain of six interlinked UUID-style hexagonal links forming a complete ring. The negative space inside the seal subtly forms the silhouette of a magnifying glass. Flat vector style, no gradients, no shadows, no text. Cream (#f5f1e8) background. Court-document aesthetic, clinical, evidentiary. Square 1:1.

**Architecture diagram prompt:**

> A horizontal architecture diagram showing the data flow of an autonomous DFIR system. Left side: a Claude Code agent icon (small robot silhouette with a SIFT Workstation Ubuntu badge). Center: a large rounded-rectangle labeled "Evidence Integrity MCP Server" containing seven stacked components in deep indigo (#1a1f3a) tiles — (1) Evidence Session Manager with SHA-256 seal icon, (2) Hash Daemon (clock at 30s), (3) enforce() Gate (vault door), (4) Typed Tool Registry showing 15 tool chips grouped into SESSION/MEMORY/LOGS/REGISTRY/ANALYSIS/IOC/STIX, (5) JSONL Audit Logger (chain links with UUIDs), (6) DRS Confidence Gate (0.75 threshold meter), (7) Findings DB (SQLite cylinder). Right side: outputs branching to "IR Report.md", "audit_trail.jsonl", and "STIX 2.1 bundle" feeding into MISP/OpenCTI logos. Bottom strip: "SIFT Tool Layer" — Volatility3, Plaso, RegRipper, python-evtx, YARA, Sleuth Kit. Clean isometric or flat-vector style, indigo + cyan + crimson alert color, cream background, technical-blueprint aesthetic, no photorealism. Wide 16:9.

### 2C. NotebookLM Video Script Source (~420 words)

> **Evidence Integrity Enforcer: Architectural Guardrails for AI-Assisted Digital Forensics**
> 
> **The problem.** Digital forensics has a chain-of-custody problem nobody is talking about in the AI era. Today's AI-assisted DFIR tools rely on prompt-based guardrails — a system prompt that politely asks the model "please don't modify evidence." That's a blocklist enforced on the client side, and anyone who has spent five minutes with a capable language model knows how prompt injection, hallucination, or model drift can route around polite instructions. In a forensic context this isn't a bug, it's a chain-of-custody failure: one silent write voids the investigation and destroys courtroom admissibility. Threat hunters need autonomous AI agents that can rip through memory dumps, event logs, and registry hives in minutes — but they cannot trade speed for the ability to get evidence thrown out at trial.
> 
> **The solution.** Evidence Integrity Enforcer is a custom MCP server that flips the model. Instead of asking the AI to behave, we make misbehavior architecturally impossible. The server exposes exactly fifteen typed, read-only forensic tools to a Claude Code agent. Functions like execute shell, write file, remove, and modify evidence simply do not exist. There is no "deny" rule because there is no function to deny. Attack surface is zero by construction.
> 
> **How it works.** Every evidence file is SHA-256 sealed at session start. A background daemon re-verifies hashes every thirty seconds, AND a synchronous gate re-verifies before every single tool call. Any modification halts the session and voids all findings. Every tool invocation writes a UUID-stamped JSONL audit record with the input arguments, the timestamp, and the output hash. Every finding in the final report links back through that UUID chain to the exact tool call and the verified evidence state at that moment. A DRS confidence gate scores every finding — evidence strength times sixty percent plus corroboration times forty percent — and below 0.75 the agent must self-correct using a different tool.
> 
> **Demo highlights.** The investigation demo walks through a full seven-phase attack: brute force, encoded PowerShell, service install persistence, process injection, lateral movement via PsExec and RDP, and command-and-control beaconing. Fifteen MITRE ATT&CK techniques across eleven tactics, all detected with cross-tool corroboration. Output: a court-quality IR report and a STIX 2.1 bundle ready for MISP, OpenCTI, or ThreatConnect.
> 
> **Why SANS judges should care.** This is the first DFIR MCP server we know of that enforces integrity through function-registry design rather than prompt instruction. Five hundred forty-four automated tests, including twenty-one dedicated security-bypass tests, prove the architecture holds. Allowlists beat blocklists. Server-side enforcement beats client-side instruction. Architecture beats vibes.

### 2D. Demo Recording Infrastructure (verified)

**Status:** Primary 5-min demo runs end-to-end on this laptop with zero new setup beyond a Windows console UTF-8 fix. STIX 2.1 export now baked into `video_demo.py` directly (committed today).

| Component                            | Status                | Notes                                                                                                                                                                    |
| ------------------------------------ | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Python MCP install                   | READY                 | `pip install -e ".[dev]"` works on Python 3.13.13                                                                                                                        |
| Sample evidence (5 files)            | COMMITTED             | `evidence/Application_small.evtx` (real EVTX, 69 KB), `SYSTEM`, `SOFTWARE`, `evidence_iocs.bin`, `find_evil_rules.yar`                                                   |
| Manufactured 7-phase scenario        | COHERENT              | PID 4200 (svchost) appears in vol_pslist + vol_malfind (MZ header) + parents PID 4344 (rundll32) which beacons to `185.220.101.34:8443` (Tor exit, public training data) |
| `demo/validate_submission.py`        | 49/49 PASS in ~13 s   | Cold-open proof                                                                                                                                                          |
| `demo/video_demo.py`                 | RUNS (verified today) | Now includes STIX 2.1 export scene as Act 6 — writes `output/bundle.stix.json`                                                                                           |
| `demo/run_investigation.py`          | RUNS                  | Full 7-phase, emits audit_trail.jsonl + ir_report.md + findings.db                                                                                                       |
| `demo/tamper_demo.py`                | RUNS                  | Byte-level tamper, daemon halts session, reseal recovers                                                                                                                 |
| STIX 2.1 export                      | REAL                  | `bundle--<uuid>` with `report` + `indicator` + `relationship` objects, `spec_version: "2.1"`, validated in test today                                                    |
| `find-evil-sift:latest` Docker image | BUILT TODAY           | 729 MB; pre-built for live-mode bonus scene; `docker compose -f docker-compose.sift.yml run --rm mcp-server <cmd>`                                                       |
| Test suite                           | 543 pass + 1 skipped  | Unchanged after today's refactor                                                                                                                                         |

**Live mode coverage (SIFT Docker):** real EVTX (python-evtx), real YARA (yara-python), real registry (python-registry). Volatility3 wrapper requires a real `.raw` memory image you don't have — keep memory tools in simulated mode. Plaso/log2timeline NOT in `[sift]` extras — `build_timeline` runs simulated regardless.

### 2E. Recommended 10-12 min Recording Sequence

| t    | Action                           | Script                                                                                                                                                                                          | Narration anchor                                                                             |
| ---- | -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| 0:00 | Hook (camera only)               | —                                                                                                                                                                                               | "CrowdStrike 7-min breakout" (`VIDEO_SCRIPT.md:18-22`)                                       |
| 0:30 | Cold-open proof                  | `python demo/validate_submission.py`                                                                                                                                                            | "49 of 49 checks pass — every claim verified"                                                |
| 1:00 | Start main demo                  | `rm output/audit_trail.jsonl output/findings.db output/bundle.stix.json && python demo/video_demo.py`                                                                                           | Phase 0 SEAL — point at SHA-256 hashes                                                       |
| 1:30 | Available/NOT-available          | (auto in script)                                                                                                                                                                                | "These functions were never implemented"                                                     |
| 2:00 | Phases 1-6                       | (auto, runs ~30s)                                                                                                                                                                               | Read `VIDEO_SCRIPT.md:60-77`                                                                 |
| 3:00 | DRS gate                         | (auto Phase 7)                                                                                                                                                                                  | Tiebreaker criterion (`VIDEO_SCRIPT.md:96-100`)                                              |
| 3:30 | Tamper banner                    | (auto, the wow moment)                                                                                                                                                                          | Pause 3 seconds (`VIDEO_SCRIPT.md:118`)                                                      |
| 4:30 | Recovery + report                | (auto)                                                                                                                                                                                          | Open `output/ir_report.md` + `audit_trail.jsonl` in side editor — show UUID provenance chain |
| 5:30 | **STIX 2.1 export** (NEW — auto) | (auto Act 6)                                                                                                                                                                                    | "MISP/OpenCTI/ThreatConnect ingestion — court to threat-intel handoff in one tool call"      |
| 6:30 | Live-mode bonus (optional)       | `docker compose -f docker-compose.sift.yml run --rm --entrypoint python mcp-server -c "from find_evil.tools.evtx import _parse_real_evtx; print(len(_parse_real_evtx('/evidence/Application_small.evtx')))"` | "Same MCP server, real python-evtx — not simulated" (expected output: `10`)                                          |
| 7:30 | Close                            | —                                                                                                                                                                                               | `VIDEO_SCRIPT.md:158-163`                                                                    |

### 2F. Recording Pre-flight Checklist

- [ ] Terminal: dark bg, 18–20pt monospace, ~100 cols (per `demo/VIDEO_SCRIPT.md:5-9`)
- [ ] `set PYTHONIOENCODING=utf-8` (Windows console — em-dashes render as `�` otherwise)
- [ ] `rm -f output/audit_trail.jsonl output/findings.db output/bundle.stix.json` between takes (audit log is append-only)
- [ ] Side editor open on `output/audit_trail.jsonl` + `output/ir_report.md` for the provenance reveal at 4:00
- [ ] (Optional) Pre-pull Docker images: `docker compose -f docker-compose.sift.yml pull` to avoid mid-demo network delays
- [ ] (Optional) Smoke test: `bash scripts/docker-smoke-test.sh`
- [ ] Disable IDE notifications, screen recorder armed (OBS / Loom / Win+G)

### 2G. Risks to Mitigate (Find Evil)

- **Audit log is append-only** — `output/audit_trail.jsonl` accumulates across runs; always delete before recording (`video_demo.py` does this on line 117–120 but verify)
- **STIX export needs findings in DB** — already handled: `video_demo.py` populates `findings_db` then calls `build_stix_bundle()` against it in the new Act 6
- **Docker first-run pulls** — already mitigated: `find-evil-sift:latest` is built locally as of today
- **Volatility CLI subprocess** (`src/find_evil/tools/volatility.py:52`) will fail without `vol` on PATH — only run vol_* in simulated mode unless you provide a real `.raw` and verify `vol -h` works
- **EVTX em-dash on Windows** — already mitigated by `set PYTHONIOENCODING=utf-8`

---

## 3. Security Posture (both repos)



### 3B. Find Evil — VERDICT: GO for public exposure (after flip)

| Check                                | Result                                                                |
| ------------------------------------ | --------------------------------------------------------------------- |
| `.env*` in `.gitignore`              | YES + `*.pem`/`*.key` added today                                     |
| `.env*` ever committed               | Only `.env.example` (empty values, intentional)                       |
| Hardcoded secrets / API keys         | 0 matches                                                             |
| VirusTotal/Shodan/AbuseIPDB API keys | 0 matches                                                             |
| Sample IOC sensitivity               | `185.220.101.34` is well-known Tor exit (public training data) — safe |
| Sample evidence                      | Synthetic, documented in `evidence/README.md:8-21`                    |
| PCAP / E01 / DMP files               | NONE                                                                  |
| Customer/employer references         | NONE                                                                  |
| Test count drift                     | Fixed today (497/541 → 544 across 9 docs)                             |
| Stray `evidence;C/` typoed dir       | Removed today                                                         |

**Remaining task:** flip GitHub repo `sgharlow/find-evil` private → public when ready to record.

---



---

## 5. User Action Items (Claude can't do these)

| #   | Action                                                                      | Project   | Priority                 | Est. Time |
| --- | --------------------------------------------------------------------------- | --------- | ------------------------ | --------- |
|     |                                                                             |           |                          |           |
|     |                                                                             |           |                          |           |
| 3   | Record demo video (script: `demo/VIDEO_SCRIPT.md`, now ends at STIX export) | find-evil | MED (Jun 15)             | 1–2 hr    |
| 4   | Flip GitHub repo `sgharlow/find-evil` private → public                      | find-evil | HIGH (before submission) | 1 min     |
| 5   | Generate logos via image model (prompts in §§ 1B + 2B)                      | both      | MED                      | 30 min    |
| 6   | Generate architecture diagrams via image model (prompts in §§ 1B + 2B)      | both      | MED                      | 30 min    |
| 7   | Generate NotebookLM Audio/Video Overviews (scripts in §§ 1C + 2C)           | both      | MED                      | 15 min    |
| 9   | Submit on SANS portal                                                       | find-evil | MED (Jun 15)             | 30 min    |

---

## Appendix A — Key file paths

### 

### Find Evil

- `find-evil/README.md` — overview, MITRE coverage, judging criteria map
- `find-evil/SUBMISSION.md` — root SANS deliverables index
- `find-evil/DEVPOST_SUBMISSION.md` — 25 KB pre-written Devpost packet
- `find-evil/docs/sans-submission-answers.md` — 19 KB SANS 8-question answers
- `find-evil/docs/accuracy_report.md` — DRS methodology + per-category test breakdown
- `find-evil/docs/try_it_out.md` — judge quick-start
- `find-evil/docs/evidence_integrity_approach.md` — architectural rationale
- `find-evil/docs/guides/docker-sift-setup.md` — SIFT Docker setup
- `find-evil/demo/VIDEO_SCRIPT.md` — narration source
- `find-evil/demo/video_demo.py` — primary recording script (now ends with STIX export)
- `find-evil/demo/validate_submission.py` — 49-check cold-open proof
- `find-evil/demo/run_investigation.py` — full 7-phase investigation
- `find-evil/demo/tamper_demo.py` — tamper detection demo
- `find-evil/src/find_evil/tools/findings.py:393-449` — `build_stix_bundle()` pure function (refactored today)
- `find-evil/src/find_evil/tools/findings.py:451-491` — `export_stix` MCP tool wrapper
- `find-evil/src/find_evil/tools/_base.py:96-108` — integrity violation gate
- `find-evil/src/find_evil/tools/volatility.py:76-108` — manufactured scenario data
- `find-evil/Dockerfile.sift` — SIFT live-mode container (built today as `find-evil-sift:latest`)
- `find-evil/docker-compose.sift.yml` — compose definition for live-mode bonus

---

## Appendix B — Live verification commands (re-run before recording)

### Find Evil end-to-end demo (clean run)

```bash
cd C:/Users/Steve.Harlow/CascadeProjects/find-evil
rm -f output/audit_trail.jsonl output/findings.db output/bundle.stix.json
PYTHONIOENCODING=utf-8 python demo/video_demo.py
```

### Find Evil validate_submission cold-open

```bash
cd C:/Users/Steve.Harlow/CascadeProjects/find-evil
PYTHONIOENCODING=utf-8 python demo/validate_submission.py
```

### Find Evil SIFT live-mode bonus shot

```bash
cd C:/Users/Steve.Harlow/CascadeProjects/find-evil
# NOTE: --entrypoint python is required because Dockerfile.sift sets ENTRYPOINT=["python","-m","find_evil"]
# without the override, the `python -c` args are swallowed by the MCP server entrypoint.
docker compose -f docker-compose.sift.yml run --rm --entrypoint python mcp-server -c "from find_evil.tools.evtx import _parse_real_evtx; print(len(_parse_real_evtx('/evidence/Application_small.evtx')))"
# Expected output: 10
```

### Find Evil full test suite (regression check)

```bash
cd C:/Users/Steve.Harlow/CascadeProjects/find-evil
PYTHONIOENCODING=utf-8 python -m pytest tests/ -q
# Expected: 543 passed, 1 skipped in ~13s
```

### Find Evil STIX bundle structure validation

```bash
cd C:/Users/Steve.Harlow/CascadeProjects/find-evil
python -c "import json; b = json.load(open('output/bundle.stix.json', encoding='utf-8')); print('id:', b['id']); print('objects:', len(b['objects'])); print('types:', sorted(set(o['type'] for o in b['objects']))); print('spec_version:', b['objects'][0].get('spec_version'))"
# Expected: type bundle, 3+ objects, types include indicator/report/relationship, spec_version 2.1
```
