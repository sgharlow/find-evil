# Video Script: Evidence Integrity Enforcer (5 minutes)

## Setup Before Recording

- Terminal: dark background, 18-20pt monospace font, ~100 columns
- Two terminals side by side (left: main demo, right: will show tamper)
- `cd` into the `find-evil` project directory
- Clear any previous output: `rm -f output/audit_trail.jsonl output/findings.db`
- Test run once to verify: `python demo/video_demo.py`

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

This shows 45/45 checks passing in ~10 seconds. Then transition to the
full demo. This proves claims before demonstrating them.
