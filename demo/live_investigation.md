# Live Investigation — Prompt for Claude Code

This is the prompt you paste into a Claude Code session once the `find-evil`
MCP server is attached. The agent will drive the 15 read-only forensic tools
against the sealed evidence directory, honor the DRS confidence gate, emit a
UUID-linked audit trail, and (optionally) export a STIX 2.1 bundle.

The prompt is deliberately open-ended. The tools, the integrity enforcement,
the DRS gate, and the STIX export are all real — what Claude says about each
finding is genuinely derived from tool output. Each recording run will differ
slightly in wording and investigation order; that variance is the point.

---

## Prerequisites (one-time, see docs/guides/live-demo-setup.md)

1. Docker image built: `docker compose -f docker-compose.sift.yml build`
2. Claude Code attached: see setup guide for the exact `claude mcp add` command
3. (Optional) Hostname redaction env var set so the evidence fixture's host
   FQDN is replaced with a generic name in parsed EVTX output
4. Output directory empty: `rm -f output/audit_trail.jsonl output/findings.db output/bundle.stix.json`

---

## The prompt (paste into Claude Code)

> You are operating as the autonomous DFIR analyst defined in `CLAUDE.md`.
> The `find-evil` MCP server is attached with 15 read-only forensic tools.
>
> Investigate the evidence directory `/evidence` using whatever tools apply.
> The evidence contains a Windows Application event log, SYSTEM and SOFTWARE
> registry hives, a binary with embedded indicators, and a YARA rules file.
> Memory forensics tools (`vol_*`) will fail because there is no `.raw`
> memory image present — that is expected; skip them.
>
> Follow the investigation protocol in `CLAUDE.md` (SEAL → TRIAGE → LOGS →
> PERSISTENCE → IOC SCAN → SYNTHESIS). Do not fabricate findings that your
> tool calls did not directly produce. Every finding you submit must reference
> the invocation ID(s) that produced it. Respect the DRS gate — below 0.75
> confidence, seek corroboration from a different tool.
>
> When analysis is complete:
> 1. Call `generate_report` to produce the incident response report
> 2. Call `export_stix` to produce a STIX 2.1 bundle for threat-intel handoff
> 3. Tell me the location of the audit trail, findings DB, and STIX bundle
>
> Narrate your reasoning as you go — which tool you are calling, what the
> output tells you, and why a finding is worth submitting. This is being
> recorded.

---

## What to expect during the run

- **Total wall-clock time**: 4–8 minutes depending on how aggressive Claude
  is with tool calls. Expect 15–25 tool calls total. Each call is 200 ms–2 s.
- **Silent thinking**: Claude pauses for a few seconds between tool calls
  while it decides what to do next. That's fine for recording — edit in post
  or narrate over it.
- **Variance run-to-run**: Wording will differ. Confidence scores may flip a
  finding from ACCEPTED to SELF-CORRECTED. This is authentic agent behavior,
  not a bug.
- **Findings will look different from `video_demo.py`**: That script is a
  manufactured scenario (brute force → process injection → persistence → C2).
  The real evidence contains Windows SPP events, registry persistence keys,
  and a YARA match set — which is what the agent will actually report.

---

## Failure modes and recovery

| Symptom | Likely cause | Recovery |
|---|---|---|
| `claude mcp list` shows `find-evil: disconnected` | Docker not running | `docker ps` to confirm; restart Docker Desktop; retry |
| `parse_evtx` returns simulated data | `[sift]` extras not in image | Rebuild with `docker compose -f docker-compose.sift.yml build` |
| `Computer` field still shows FQDN | Env var not passed to container | Verify `FIND_EVIL_COMPUTER_REDACT_MAP` is in the `claude mcp add` command, not just the shell env |
| Claude keeps retrying a failing `vol_*` call | No memory image present | Tell Claude to skip memory tools and continue |
| Rate limit mid-demo | Claude API throttled | Pause 60 s, ask Claude to resume |
| Investigation completes too fast | Claude skipped phases | Ask explicitly: "Walk through the LOGS and PERSISTENCE phases before you stop" |

---

## After the recording

- `output/ir_report.md` — Claude's generated report with real findings
- `output/audit_trail.jsonl` — one line per tool call, UUID-linked
- `output/findings.db` — SQLite; `sqlite3 output/findings.db "SELECT * FROM findings"` to inspect
- `output/bundle.stix.json` — STIX 2.1 bundle

Reset before next take:

```bash
rm -f output/audit_trail.jsonl output/findings.db output/bundle.stix.json
```
