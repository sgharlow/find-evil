# Video Script: Evidence Integrity Enforcer (5 minutes)

## Setup Before Recording

- Terminal: dark background, 18-20pt monospace font, ~100 columns
- Two terminals side by side (left: main demo, right: will show tamper)
- `cd` into the `find-evil` project directory
- Clear any previous output: `rm -f output/audit_trail.jsonl output/findings.db`
- Test run once to verify: `python demo/video_demo.py`

---

## ⭐ Real-agent segment (Claude Code driving the MCP server) — RECORD THIS FIRST

This is the strongest scene and the one judges weight most (autonomous execution):
the **actual** agent, not a script. **Verified working** via the SIFT Docker server —
an MCP client listed all **15 tools**, sealed `/evidence`, and ran `parse_evtx` in
`mode: live` against the real EVTX (hostname redacted to `VICTUS`).

**Setup (one-time, off-camera)** — full guide: `docs/guides/live-demo-setup.md`
```bash
docker compose -f docker-compose.sift.yml build        # builds find-evil-sift:latest
claude mcp add find-evil -- docker run --rm -i \
  -e FIND_EVIL_COMPUTER_REDACT_MAP=<your-host>=VICTUS \
  -v "$PWD/evidence:/evidence:ro" -v "$PWD/output:/output" find-evil-sift:latest
claude mcp list                                         # confirm: find-evil ... ✓ Connected
```
> Either path works now: **Docker** (above — full real-backend SIFT environment) or
> **pip** (`claude mcp add find-evil -- python -m find_evil`, needs mcp ≥ 1.27).

**On camera**
```text
$ claude
> Investigate the sealed evidence at /evidence following your CLAUDE.md protocol.
  Seal and verify integrity first, then triage and parse the event log. Report
  findings with their tool-call provenance.
```
> Interactive `claude` will prompt to approve each find-evil tool — approve them
> (all read-only), or launch `claude --allowedTools mcp__find-evil` for an
> uninterrupted take. `python demo/record_demo.py --with-agent` pre-authorizes them.

**Narrate as Claude works autonomously:**
- It calls `session_init` → `verify_integrity` (real SHA-256 seal of `/evidence`).
- It calls `parse_evtx` / `registry_query` / `yara_scan` — **real backends, `mode: live`**.
- Every call lands in `output/audit_trail.jsonl` with a UUID (show the file).
- The DRS gate makes it **self-correct** low-corroboration findings.
- Say it plainly: *"This is Claude Code autonomously driving the MCP server — real
  tool calls against real evidence, not a script."*

Then cut to `python demo/video_demo.py` for the **tamper wow-moment** (Act 3 below).

---

## Recommended recording sequence — the 4-beat arc (≤5 min)

**One command runs the whole arc, paced for narration:**
```bash
python demo/record_demo.py                 # BEAT1 hook -> BEAT2 live agent -> BEAT3 live tamper -> BEAT4 proof
python demo/record_demo.py --no-agent      # BEAT2 = scripted run_investigation.py (no Claude)
python demo/record_demo.py --manual-tamper # BEAT3 = you tamper a sealed file in another terminal
python demo/record_demo.py --pause 4       # longer narration gaps
```

The four beats (run individually if you prefer; the timecoded narration below maps onto them):

1. **HOOK (~20s):** the problem — AI-DFIR leans on "please don't modify evidence" prompts; one silent write voids chain of custody. This makes tampering *architecturally* impossible.
2. **★ REAL AGENT (~2 min) — the centerpiece:** interactive `claude` driving the MCP server (see the segment at the top). On the committed real evidence it surfaces genuine persistence — the **SYSTEM service `WinUpdateHelper`** *and* the **SOFTWARE Run key `WindowsUpdateHelper`**, both pointing to `...\Temp\update.dll` — plus YARA IOC hits (Mimikatz / Cobalt Strike / C2). The DRS gate then **HOLDS every finding at single-source confidence (0.61 → SELF-CORRECT)**: two registry artifacts agree, but both come from one tool, so the gate refuses to accept any claim until a *different* tool confirms it. That withholding **is** the story — an AI agent that won't over-claim on real evidence. *(Drop a memory image into `evidence/` → `vol_netscan`+`vol_malfind` corroborate the C2/Cobalt YARA hit from a second tool → a genuine ACCEPT at conf 0.77. That's where 0.77 comes from — memory-corroborated C2, not registry-only persistence.)*
3. **LIVE TAMPER (~60s):** `python demo/live_tamper.py` — seals the **real** EVTX, then a one-byte change triggers a real SHA-256 `VIOLATION` → `ANALYSIS HALTED, findings voided` → re-seal. Real detection on real evidence (not a scripted banner). Use `--manual` to tamper it yourself in a second terminal on camera.
4. **PROOF + PROVENANCE (~30s):** `python demo/validate_submission.py` (49/49) + trace a finding's UUID into `output/audit_trail.jsonl`. *"Every claim traces to the exact tool call and verified evidence state."*

Total ~4–4.5 min — keep under 5:00, upload **Public** to YouTube.

> The timecoded sections below are the original `video_demo.py` walkthrough narration. They remain a good narration reference, and `video_demo.py` is still a valid polished all-in-one alternative for BEATS 2–4 if you don't want the live agent.

---

## [0:00 - 0:20] THE HOOK

**Run**: nothing yet — just you talking to camera or voiceover

**Say**:
> "CrowdStrike's fastest observed adversary breakout time: seven minutes.
> A defender has to be faster. But here's the problem with AI-assisted
> forensics: every other tool relies on prompt-based guardrails — 'please
> don't modify evidence.' This submission makes evidence modification
> architecturally impossible. Let me show you."

**Judging criterion**: Sets up the Constraint Implementation angle.

---

## [0:20 - 1:00] EVIDENCE SEALING

**Run**: `python demo/video_demo.py`

**What viewers see**: Phase 0 — evidence files sealed with SHA-256 hashes.

**Say** (while output scrolls):
> "Before a single tool runs, every evidence file is sealed with a
> SHA-256 hash. The hash daemon starts — it will re-verify every
> 30 seconds and before every tool call."

**Point out on screen**:
- The 5 evidence files being sealed with hash prefixes
- "Available functions" — the 15 read-only tools
- "NOT available" — shell, write, rm, dd in red

> "Notice what's NOT available. Shell commands, file writes, delete
> operations — they don't exist in the MCP server. This is not a
> blocklist. These functions were never implemented. The attack surface
> is zero."

**Judging criterion**: Constraint Implementation (HIGH).

---

## [1:00 - 2:30] AUTONOMOUS INVESTIGATION

**What viewers see**: Phases 1-6 rolling through with tool calls and results.

**Say** (as each phase runs):

Phase 1 (Triage):
> "The agent starts with memory triage. Process list finds 3 suspicious
> processes — cmd.exe spawned by svchost, that's a LOLBin chain.
> Netscan finds 3 connections to 185.220.101.34 on port 8443 — C2 beacon."

Phase 2 (Deep Memory):
> "Malfind detects injected code — an MZ header in read-write-execute
> memory. That's a PE injected into a process. Cmdline reveals
> encoded PowerShell with execution policy bypass."

Phase 3 (Logs):
> "Event logs show 3 failed logon attempts from 192.168.1.200, then a
> successful network logon — brute force followed by compromise."

Phase 4-6 (briefly):
> "Registry shows persistence — a service and a Run key both pointing
> to update.dll in the Temp directory. The timeline puts it all on
> one axis. YARA catches the shellcode pattern and the C2 IP."

**Judging criteria**: IR Accuracy (HIGH), Breadth and Depth (MEDIUM).

---

## [2:30 - 3:10] DRS GATE SELF-CORRECTION

**What viewers see**: Phase 7 — findings scored through confidence gate.

**Say**:
> "Now the DRS confidence gate. Every finding is scored on evidence
> strength and corroboration. C2 beacon — three independent tools
> confirm it — confidence 0.91, accepted."

**Point out**:
- Green [+] findings being accepted
- Then the yellow [~] self-corrections appearing

> "But watch — 'brute force from 192.168.1.200' only has two sources.
> Confidence 0.74, just below the 0.75 threshold. The agent flags it
> for self-correction — it needs to find another tool that confirms
> this before committing. This is the tiebreaker criterion in action."

**Judging criterion**: Autonomous Execution Quality (TIEBREAKER).

---

## [3:10 - 4:00] THE WOW MOMENT — TAMPER DETECTION

**What viewers see**: "TAMPER DETECTION DEMO" banner appears.

**Say**:
> "Now watch what happens when someone touches an evidence file
> mid-analysis."

**On screen**: the simulated tamper command appears, then:
- Red violation banner
- Hash mismatch with expected vs actual
- "ANALYSIS HALTED — chain of custody broken"
- "All findings voided"

**Pause here — let it breathe. This is the signature moment.**

> "The hash daemon detected the modification instantly. Not a prompt
> restriction the agent can talk itself out of — a cryptographic hash
> mismatch that halts the session and voids all findings. This is
> how a professional forensic lab works."

**Then the recovery**:
> "Evidence re-sealed. New session. Clean chain of custody. Analysis
> can resume."

**Judging criterion**: Constraint Implementation (HIGH) — this is THE moment.

---

## [4:00 - 4:40] INCIDENT REPORT

**What viewers see**: Final report with findings, IOCs, provenance UUIDs.

**Say**:
> "Four high-confidence findings. Every one links back to specific
> tool invocations by UUID. Judges can trace any finding in this
> report back through the audit trail to the exact tool call that
> produced it."

**Point out on screen**:
- Finding descriptions with confidence scores
- `tool_calls: [uuid, uuid, uuid]` — the provenance chain
- IOC summary table
- Self-correction log
- "Defender clock: 0:34 | Adversary breakout: 7:00"

> "Thirty-four seconds. The adversary had seven minutes."

**Judging criterion**: Audit Trail Quality (HIGH).

---

## [4:40 - 5:00] CLOSE

**Say**:
> "This is open source under MIT. Fifteen typed functions. Zero
> destructive. A hash daemon that catches tampering in seconds.
> A confidence gate that forces the agent to self-correct.
> And a UUID audit trail that makes every finding forensically
> defensible. Thank you."

---

## Post-Recording Checklist

After recording, verify these are visible in the video:

- [ ] Evidence files sealed with SHA-256 hashes (Phase 0)
- [ ] "NOT available" list shown in red (shell, write, rm, dd)
- [ ] At least 3 tool phases visible with structured results
- [ ] Suspicious items flagged in yellow
- [ ] DRS gate: at least 1 ACCEPTED finding and 1 SELF-CORRECT finding
- [ ] Tamper detection: red violation banner, hash mismatch
- [ ] "ANALYSIS HALTED" message
- [ ] Recovery: re-seal, new session
- [ ] Final report with confidence scores and UUID provenance
- [ ] IOC table visible
- [ ] Race clock visible (defender vs adversary)
- [ ] Total video under 5:00

## Alternative: Validation-First Approach

If you want to lead with proof instead of narrative, run the validation
script first as a cold open:

```bash
python demo/validate_submission.py
```

This shows 49/49 checks passing in ~10 seconds. Then transition to the
full demo. This proves claims before demonstrating them.
