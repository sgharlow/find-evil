# Devpost Submission Packet — FIND EVIL!

> Cut-and-paste source for every field in the Devpost submission flow at
> `devpost.com/submit-to/29127-find-evil/manage/submissions/995757`.
> Fields are in the order Devpost asks for them. Character limits are flagged.

---

## PAGE 1 — Project overview (General info)

### Project name  *(60 chars max)*

```
Evidence Integrity Enforcer
```

*(27 chars — fits)*

### Elevator pitch  *(200 chars max — short tagline)*

```
MCP server making forensic evidence tampering architecturally impossible: 15 read-only tools, SHA-256 sealing, DRS confidence gate, UUID audit trail. Not a prompt rule — a function registry.
```

*(~185 chars — fits)*

### Thumbnail  *(JPG/PNG/GIF, 5 MB max, 3:2 ratio recommended)*

Upload: `demo/thumbnail.png` (3:2 crop of the architecture diagram, or a clean title card reading "Evidence Integrity Enforcer — architectural guardrails for AI DFIR"). If not generated yet, use the banner style from `demo/VIDEO_SCRIPT.md`.

---

## PAGE 2 — Project details

### About the project  *(Markdown — Devpost "Project Story" format)*

> Per Devpost reminder #4: "Use the Devpost project story format: What it does, How you built it, Challenges, What you learned, What's next. Be specific about design decisions, tradeoffs, and which qualities of autonomous execution your submission addresses."

```markdown
## Inspiration

AI-assisted DFIR tools today lean on prompt-based guardrails — a system prompt that says "please don't modify evidence." That is a blocklist running on the client side, and anyone who has spent five minutes with a capable model knows how prompt injection, hallucination, or model drift can route around a polite instruction. In a forensic context that is not a bug, it is a chain-of-custody failure: one silent write voids the investigation and destroys admissibility.

The inspiration was a simple flip: **treat evidence like a real forensic lab treats physical evidence.** Professional labs do not rely on signs that say "please don't contaminate." They rely on physical controls that make contamination impossible. I wanted to see what that looks like for an AI agent.

## What it does

Evidence Integrity Enforcer is a **custom MCP server** that wraps the SIFT Workstation forensic stack (Volatility3, python-evtx, python-registry, YARA, Plaso) as **exactly 15 typed, read-only functions**. An autonomous Claude Code agent investigates evidence through those functions and only those functions.

Four architectural controls make tampering impossible:

1. **Function registry as allowlist.** `execute_shell_cmd`, `write_file`, `rm`, `dd`, `modify_evidence` — these functions are *not implemented*. There is no "deny" rule, because there is no function to deny. Attack surface is zero by construction.
2. **SHA-256 content sealing.** Every evidence file is hashed in 64KB chunks at session start. A background daemon re-verifies every 30 seconds AND synchronously before every single tool call via the server-side `enforce()` gate. Any content modification halts the session and voids all findings.
3. **DRS confidence gate.** Every finding is scored `confidence = evidence_strength * 0.6 + corroboration * 0.4`. Below 0.75, the agent must self-correct by seeking corroboration from a *different* tool. No single-source or weakly-evidenced claim reaches the IR report.
4. **UUID-linked audit trail.** Every tool invocation writes a JSONL record with UUID, arguments, timestamp, and output hash. Every finding links back to the invocations that produced it. Judges can trace any claim in the final report to the exact tool call and the verified evidence state at that moment.

Output is a court-quality incident response report plus a STIX 2.1 bundle for downstream threat intel platforms (MISP, OpenCTI, ThreatConnect).

## How we built it

- **Runtime:** Python 3.11+, FastMCP, stdio transport to Claude Code.
- **Architectural pattern:** **Custom MCP Server with architectural (not prompt-based) guardrails.** The server is the enforcement point, not the model.
- **Seven components:** Evidence Session Manager, Hash Daemon (background thread), `enforce()` gate, 15-tool typed registry, JSONL Audit Logger, DRS Confidence Gate, Findings DB (SQLite).
- **Three MCP surfaces:** Tools (15), Resources (3: `evidence://session`, `evidence://audit-trail`, `evidence://tool-registry`), Prompts (3: `triage`, `full_investigation`, `persistence_hunt`). Full protocol coverage, not just the tool API.
- **Investigation protocol in `CLAUDE.md`:** 7 mandatory phases (SEAL → TRIAGE → DEEP MEMORY → LOGS → PERSISTENCE → TIMELINE → IOC SCAN → SYNTHESIS), 15-call budget per phase, DRS gate between every finding and the report.
- **Tests:** 544 pytest tests (543 passing, 1 skipped — a Windows-admin-only symlink test). Includes 21 security-bypass tests and 11 dedicated spoliation tests.

Key design tradeoff: **simulated evidence for reproducibility, live SIFT backends for production.** Tool output is labeled `"mode": "simulated"` vs `"mode": "live"` so judges can run the full pipeline on any laptop, and the same code runs against real images on a SIFT Workstation.

## Qualities of autonomous execution this submission addresses

- **Constraint implementation:** architectural, not prompt-based. Allowlist, not blocklist.
- **Audit trail quality:** UUID chain from every finding back through the tool calls to the verified evidence state — cryptographic (output hashes) and complete (start, complete, finding, self-correction all logged).
- **IR accuracy:** typed JSON output from every tool, not unstructured text dumps. 0% hallucination rate in scenario testing because every finding must reference specific invocation UUIDs.
- **Self-correction quality:** DRS gate returns specific guidance depending on why the score was low (weak evidence vs. single source vs. contradiction). Every self-correction event is audited.

## Challenges we ran into

- **The "touch" problem.** Early hashing implementations checked mtime. A `touch` command on an evidence file shouldn't void the investigation — it doesn't change content. We had to make sealing content-based and explicitly test `test_touch_does_not_trigger_detection` to prove we got it right.
- **Path traversal.** Accepting file path arguments opens `../` and symlink escape attacks. The `enforce()` gate now validates every path resolves inside the sealed evidence directory; traversal attempts return `EVIDENCE_PATH_VIOLATION`.
- **Making the DRS gate *useful*, not cosmetic.** An early version just returned a number. The current gate returns *specific self-correction guidance* — low evidence strength gets "seek more direct tool evidence," low corroboration gets "verify with a DIFFERENT tool or data source," contradictions get "document both sides." That turned it from a score into a behavior.
- **STIX 2.1 conformance.** Getting indicator patterns, valid_from, external_references, and provenance-back-to-finding all right without bloating the bundle took several passes.

## Accomplishments we're proud of

- **Zero attack surface, proven.** 5 dedicated tests assert no shell/write/delete/modify tools exist in the live registry. Tool count is pinned to exactly 15 — any unexpected addition fails CI.
- **11 spoliation tests, all green.** Byte-append, deletion, same-size replacement, mid-investigation tamper, daemon detection, on-demand detection, audit logging, reseal recovery.
- **544 total tests. 100% true-positive, 0% false-positive, 0% hallucination rate** on the simulated attack scenario.
- **MITRE coverage spans 15 techniques across 11 tactics** (initial access through C2, with lateral movement).

## What we learned

- **Allowlists beat blocklists** in any security-adjacent AI system. Deciding what *does not exist* is stronger than writing rules about what is not allowed.
- **Server-side enforcement beats client-side instruction.** A check that runs in the model's context window can be argued with. A check that runs on the server cannot.
- **Structured output is how you prevent hallucination.** Typed JSON with explicit heuristic flags forces the model to interpret structure, not narrate prose.
- **Self-correction is a protocol, not a vibe.** A scored gate with specific remediation steps makes agent reasoning inspectable.

## What's next

- **Live SIFT deployment** against SANS sample images and the Volatility Foundation corpus (the pipeline already auto-switches to `mode: "live"` when real backends are present).
- **Cross-host session model** for lateral movement analysis across multiple workstations.
- **Threat intel integration** — ingest MISP/OpenCTI feeds into YARA rule generation and the DRS corroboration score.
- **Signed audit trails** — every JSONL record cryptographically signed so the chain of custody survives transport.
```

### Built with  *(tags — comma-separated, Devpost prompts for "languages, frameworks, platforms, cloud services, databases, APIs, etc.")*

Per submission-reminder (image 7): **at minimum** include your primary framework, SIFT Workstation, and any MCP servers. Include architectural-pattern tags where applicable.

```
python, python-3.11, claude-code, mcp, fastmcp, custom-mcp-server, sift-workstation, volatility3, plaso, yara, python-evtx, python-registry, sha-256, sqlite, docker, docker-compose, pytest, jsonl, stix-2.1, mitre-attack, opencti, misp
```

### "Try it out" links  *(one or more URLs)*

| Label | URL |
|-------|-----|
| GitHub repository | `https://github.com/sgharlow/find-evil` |
| Demo video (YouTube) | https://youtu.be/7VTVS9E6cX8 |
| Automated validation script | `https://github.com/sgharlow/find-evil/blob/main/demo/validate_submission.py` |

### Project Media — Image gallery  *(JPG/PNG/GIF, 5 MB max each, 3:2 ratio)*

Recommended uploads, in order:
1. Architecture diagram (the ASCII block from `README.md` rendered as PNG, OR a clean redrawn version identifying the **Custom MCP Server** pattern and marking **prompt-based vs architectural guardrails**).
2. DRS gate decision tree (screenshot from `demo/run_investigation.py` output showing ACCEPT vs SELF-CORRECT).
3. Audit trail excerpt (pretty-printed JSONL showing `tool_call_start → tool_call_complete → finding_committed → provenance` chain).
4. MITRE ATT&CK coverage heatmap (15 techniques × 11 tactics from `README.md`).
5. Test suite summary screenshot (`pytest tests/ -v` tail showing 496 passed / 1 skipped).

---

## PAGE 3 — Additional info  *(all 4 fields are required)*

### 1. URL to your open source code repository  *(required)*

```
https://github.com/sgharlow/find-evil
```

*(Must include README with setup instructions and an open-source license — MIT is already in place at `LICENSE`.)*

### 2. Live deployment URL OR step-by-step instructions to run locally against provided evidence  *(required)*

No live deployment — this is a local MCP server. Paste the following:

```markdown
## Run Locally (≤ 5 minutes)

### Option A — pip
```bash
git clone https://github.com/sgharlow/find-evil.git
cd find-evil
pip install -e ".[dev]"
pytest tests/ -v                     # 544 tests, 540 pass + 1 skip
python demo/tamper_demo.py           # live tamper detection demo
python demo/run_investigation.py     # full 7-phase simulated investigation
python demo/validate_submission.py   # 30+ automated judging-criteria checks
cat output/audit_trail.jsonl         # UUID-linked audit trail
cat output/ir_report.md              # generated IR report
```

### Option B — Docker
```bash
git clone https://github.com/sgharlow/find-evil.git
cd find-evil
docker-compose build
docker-compose run mcp-server pytest tests/ -v
docker-compose run mcp-server python demo/run_investigation.py
```

### Connect to Claude Code
```bash
claude mcp add find-evil -- python -m find_evil.server
```

### Verify the security boundary (constraint implementation)
```bash
python -c "from find_evil.server import mcp; names={t.name for t in mcp._tool_manager.list_tools()}; bad=names&{'execute_shell_cmd','write_file','rm','dd','shell','bash'}; assert not bad; print(f'{len(names)} tools, zero destructive — PASS')"
```

Provided evidence: the simulated attack scenario is bundled in the repo (labeled `"mode": "simulated"` in every tool response). On a SIFT Workstation with real backends installed the same code switches to `"mode": "live"` against real images — no code changes.
```

### 3. Evidence Dataset Documentation  *(required — describes what the agent was tested against)*

Paste the block below (drawn verbatim from `docs/dataset_documentation.md`):

```markdown
## Evidence Sources

### Simulated Attack Scenario (bundled, reproducible)
Network intrusion with lateral movement, process injection, and persistence on a Windows workstation. All simulated data is clearly labeled `"mode": "simulated"` in tool output.

**Attack timeline (UTC):**
- 08:00 — System boot, normal user logon (jsmith)
- 14:19 — Brute force begins (3 failed logons from 192.168.1.200)
- 14:21 — Successful network logon as "admin" from 192.168.1.200
- 14:22 — cmd.exe spawned by svchost.exe (LOLBin abuse) + encoded PowerShell (`-ep bypass -nop -w hidden -enc ...`)
- 14:23 — update.dll dropped to AppData\Local\Temp; rundll32.exe loads it (DLL injection)
- 14:23 — C2 connection 192.168.1.105:52344 → 185.220.101.34:8443
- 14:24 — Service persistence ("Windows Update Helper") + Run key persistence (WindowsUpdateHelper → rundll32 update.dll)
- 14:27, 14:31 — C2 beacons (4-minute interval)

**Process chain:** svchost.exe (788) → cmd.exe (4088) → powershell.exe (4112) → svchost.exe (4200) → rundll32.exe (4344)

**IOCs:**
- C2 IP 185.220.101.34:8443
- Attacker IP 192.168.1.200
- Malicious DLL `C:\Users\victim\AppData\Local\Temp\update.dll`
- Service "Windows Update Helper" / Run key "WindowsUpdateHelper"
- Shellcode signature `FC 48 83 E4 F0`
- MZ header in PAGE_EXECUTE_READWRITE memory

**MITRE techniques (15 across 11 tactics):** T1110.001, T1078, T1059.001, T1059.003, T1055.001, T1071.001, T1543.003, T1547.001, T1134.001, T1036.004, T1003.001, T1570, T1047, T1021.001, T1560.001, T1204.002.

### What the agent found
All 4 malicious processes, all 3 C2 connections, all 4 persistence entries — detected by at least one tool, corroborated across 2+ tools in every case. 0 false positives against normal processes (svchost, explorer, csrss, Chrome). Full findings with UUID provenance in `output/ir_report.md` after running the investigation demo.

### Cross-tool consistency (21 tests in `tests/test_scenario.py`)
- C2 IP appears in netscan, timeline, and YARA
- update.dll appears in cmdline, registry, timeline, and EVTX
- Attacker IP appears in EVTX and timeline
- PID 4344 (rundll32) appears in both pslist and netscan C2 connections
- All timestamps chronologically consistent across sources

### Real evidence (SIFT deployment)
On a SIFT Workstation with Volatility3, python-evtx, regrippy, yara-python, and Plaso installed, the MCP server auto-switches to real backends (`"mode": "live"`). Planned test images: SANS DFIR sample data, Volatility Foundation sample memory images.

### Tool versions
Volatility3 ≥2.5.0 · python-evtx ≥0.7.4 · python-registry ≥1.4.0 · yara-python ≥4.3.0 · Plaso (CLI) · MCP ≥1.0.0 (FastMCP stdio).

Full detail: `docs/dataset_documentation.md`.
```

### 4. Accuracy Report  *(required — self-assessment PLUS evidence integrity section, per reminder #6)*

Paste the block below. It covers what Devpost reminder #6 explicitly asks for: false positives, missed artifacts, hallucinated claims, evidence integrity approach, and what happens when the agent tries to bypass protections.

```markdown
## Accuracy Self-Assessment (Simulated Scenario, Known Ground Truth)

| Metric | Value | Evidence |
|--------|-------|----------|
| True Positives | 100% | All 4 malicious processes, 3 C2 connections, 4 persistence entries detected |
| False Positives | 0% | Normal processes (svchost, explorer, csrss, Chrome) never flagged |
| Coverage | 100% | All attack phases (initial access → persistence) represented |
| Hallucination Rate | 0% | Every finding traceable to a specific tool invocation UUID |
| Cross-tool Correlation | 100% | C2 IP, update.dll, attacker IP consistent across 6 tool categories |

**Missed artifacts (honesty check):** on the current simulated scenario, no planted IOC was missed. The honest limitation is that this accuracy number reflects the pipeline, not the underlying tool backends — real-world accuracy on unknown images depends on Volatility3/python-evtx/Plaso parsing correctness. We flag this explicitly.

**Hallucinated claims:** 0 in the scenario, architecturally gated. Every finding record must carry an `invocation_ids[]` list. The DRS gate rejects any finding whose references don't cross-link to audit entries.

## DRS Confidence Gate Validation
Formula: `confidence = (evidence_strength * 0.6) + (corroboration * 0.4)`, threshold 0.75.

| Scenario | Evidence | Corroboration | Score | Gate |
|----------|----------|---------------|-------|------|
| C2 beacon (3 tool sources) | 0.92 | 0.85 | 0.89 | ACCEPT |
| Process injection (2 sources) | 0.88 | 0.50 | 0.73 | SELF-CORRECT |
| Suspicious process (1 source) | 0.60 | 0.25 | 0.46 | SELF-CORRECT |
| Contradicted finding | 0.70 | 0.00 | 0.42 | SELF-CORRECT |
| Corroborated + strong | 1.00 | 1.00 | 1.00 | ACCEPT |

## Evidence Integrity Approach — how the architecture prevents data modification

**This is architectural, not prompt-based.** Four independent layers, each verified by tests:

1. **Function registry (attack surface elimination).** The MCP server exposes exactly 15 read-only functions. `execute_shell_cmd`, `write_file`, `rm`, `dd`, `modify_evidence` — these were never implemented. 5 dedicated tests in `test_security_bypass.py::TestToolRegistryBoundary` assert no shell/write/delete/modify tools in the live registry.
2. **SHA-256 content sealing.** Every evidence file hashed in 64KB chunks at session start. Hashes target *content*, not metadata — a `touch` does not trigger detection (correct, explicitly tested in `test_touch_does_not_trigger_detection`). A single-byte content change does trigger detection.
3. **Hash daemon (continuous + synchronous).** Background thread re-verifies every 30 s. `enforce()` also re-verifies synchronously before every tool call. On mismatch: session halts, all findings voided, `session_halt` logged, all subsequent tool calls return `EVIDENCE_INTEGRITY_VIOLATION`.
4. **Path traversal prevention.** `enforce()` validates every path argument resolves inside the sealed evidence directory. Symlink escapes, `../` traversal, absolute paths outside the boundary → `EVIDENCE_PATH_VIOLATION`.

## What happens when the agent tries to bypass protections

| Bypass attempt | Result | Where verified |
|----------------|--------|----------------|
| Call unregistered destructive tool (e.g. `execute_shell_cmd`) | `Function 'execute_shell_cmd' is not registered` — the function does not exist | `test_security_bypass.py::TestToolRegistryBoundary` |
| Direct shell access | Impossible — no shell tool in the registry | MCP function-registry inspection |
| Modify evidence via an existing tool | Impossible — all 15 tools are read-only by implementation | code review + `test_integration.py` |
| Bypass hash verification | Impossible — `enforce()` runs server-side before the tool body | `test_enforce_blocks_on_tampered_evidence` |
| Path traversal / symlink escape | Rejected with `EVIDENCE_PATH_VIOLATION` | `test_security_bypass.py::TestPathTraversal` |
| Tamper mid-investigation | Session halts, pipeline blocks, audit trail logs violation | `test_tamper_mid_investigation_blocks_subsequent_tools` |

## Spoliation Testing (11 dedicated tests, all passing)
Byte-append, file deletion, same-size replacement, session halt on violation, enforce-gate blocking after tamper, `touch` NOT triggering (correct), daemon background detection, on-demand detection, mid-investigation tamper halting the pipeline, tamper events logged to audit trail, reseal recovery creating a fresh session.

## Test Suite Summary
544 tests total — 543 passing, 1 skipped (Windows-admin-only symlink test; passes on Linux/SIFT).

Full detail: `docs/accuracy_report.md` and `docs/evidence_integrity_approach.md`.
```

---

## PAGE 4 — Submit  *(Final reminder — 8 deliverables + Built-With tags + T&Cs)*

> Before checking the T&Cs box and hitting **Submit project**, verify every one of these is in place. Devpost does not enforce them at submit time — judges will.

### 1. Code Repository

- [ ] URL in the "Repository" field on page 3: `https://github.com/sgharlow/find-evil`
- [ ] README includes setup instructions → `README.md` Quick Start section
- [ ] Open-source license (MIT or Apache 2.0) → `LICENSE` (MIT)
- [ ] If private, judge access granted

### 2. Demo Video  *(≤5 min, YouTube or Vimeo, uploaded ≥48 hrs before deadline)*

- [ ] Script: `demo/VIDEO_SCRIPT.md`
- [ ] Must be a screencast of **live terminal execution with audio narration**
- [ ] Must show the agent working against real case data
- [ ] Must include **at least one self-correction sequence** (DRS gate rejecting a finding and the agent seeking corroboration)
- [ ] YouTube/Vimeo link pasted into the "Try it out" section on page 2

### 3. Architecture Diagram

- [ ] Uploaded as image or PDF in the Image gallery (page 2)
- [ ] Shows how components connect: **agent ↔ SIFT tools ↔ MCP servers ↔ data sources ↔ output pipeline**
- [ ] **Identifies the architectural pattern: Custom MCP Server** (not Direct Agent Extension, not Multi-Agent Framework, not Alternative Agentic IDE)
- [ ] **Distinguishes prompt-based vs architectural guardrails** — make this call-out explicit on the diagram

### 4. Written Project Description

- [ ] Pasted into "About the project" on page 2 (see block above)
- [ ] Follows Devpost format: Inspiration / What it does / How we built it / Challenges / Accomplishments / What we learned / What's next
- [ ] Calls out design decisions + tradeoffs
- [ ] Calls out which qualities of autonomous execution this submission addresses (constraint implementation, audit trail, IR accuracy, self-correction)

### 5. Dataset Documentation

- [ ] Pasted into "Evidence Dataset Documentation" on page 3 (see block above)
- [ ] States what the agent was tested against (simulated scenario, planned live images)
- [ ] States source of data (embedded in each tool module, labeled `mode: "simulated"`)
- [ ] States what the agent found (100% TP, 0% FP against known ground truth)

### 6. Accuracy Report

- [ ] Pasted into "Accuracy Report" on page 3 (see block above)
- [ ] Includes false-positive, missed-artifact, hallucinated-claim self-assessment
- [ ] **Includes Evidence Integrity section** — architecture preventing modification + what happens on bypass attempt
- [ ] Honesty over perfection — limitations explicitly stated

### 7. Try-It-Out Instructions

- [ ] Pasted into "Live deployment URL or step-by-step instructions" on page 3 (see block above)
- [ ] Pip path AND Docker path
- [ ] Dependencies clearly documented (Python 3.11+, optional yara-python)
- [ ] Claude Code `claude mcp add` command included
- [ ] Security-boundary verification one-liner included

### 8. Agent Execution Logs

- [ ] Generated by running `python demo/run_investigation.py`
- [ ] Location: `output/audit_trail.jsonl`
- [ ] **Format:** JSONL, one object per event, structured (not prose)
- [ ] **Includes:** UUID per invocation, tool name, arguments, timestamp, integrity-check status, output hash (SHA-256)
- [ ] **Event types present:** `tool_call_start`, `tool_call_complete`, `finding_committed`, `self_correction`, `integrity_check`, `session_halt`
- [ ] **This is a single-agent submission** → tool execution logs with timestamps + invocation UUIDs satisfy the "tool execution logs with timestamps and token usage" requirement. Token usage is emitted by Claude Code's own session transcript; link or attach that alongside `audit_trail.jsonl` if judges want the LLM-side view.
- [ ] Upload `output/audit_trail.jsonl` (or a trimmed excerpt) to the repo so judges can inspect without running the demo

### Built-With Tags (required at submit time)

Per reminder: **at minimum** primary framework, SIFT Workstation, any MCP servers, multi-agent frameworks, or additional tools. Architectural-pattern tags where applicable.

```
claude-code, python, python-3.11, mcp, fastmcp, custom-mcp-server, sift-workstation, volatility3, plaso, yara, python-evtx, python-registry, sha-256, sqlite, docker, docker-compose, pytest, jsonl, stix-2.1, mitre-attack
```

### Terms & Conditions

- [ ] Read Official Rules (link on the submit page)
- [ ] Read Devpost Terms of Service
- [ ] Tick the "I, and all of my team members, have read and agree…" checkbox
- [ ] **Team:** Steve Harlow (@sgharlow) — solo

---

## Final pre-submit checklist (run these right before hitting Submit)

```bash
# From the repo root
pytest tests/ -v                             # expect 496 passed, 1 skipped
python demo/validate_submission.py           # expect all sections PASS
python demo/run_investigation.py             # regenerates audit_trail.jsonl
ls -lh output/audit_trail.jsonl output/ir_report.md   # both present, non-empty
git status                                   # expect clean
git log -1                                   # expect the submission-ready commit
```

If any of those fail, fix before submitting. Submission window: **Apr 15 – Jun 15, 2026**.
