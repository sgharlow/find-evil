# Agent Execution Logs

> SANS submission deliverable #8. **Single-agent submission** — one Claude Code
> agent drives the `find-evil` MCP server through the 7-phase protocol in
> `CLAUDE.md`. Per the requirement, this means *"tool execution logs with
> timestamps and token usage."* Those are two distinct layers, documented below.

## Two log layers

| Layer | What it records | Where | Status |
|-------|-----------------|-------|--------|
| **MCP audit trail** (tool side) | every tool invocation — UUID, tool name, arguments, timestamp, integrity-check status, SHA-256 output hash, elapsed_ms | `output/audit_trail.jsonl` (simulated demo) · `output/live_audit_trail.jsonl` (live demo) | **Captured automatically** by the server's `enforce()`/`complete()` gate — nothing optional |
| **LLM session** (token side) | input/output **token usage**, cache hits, model, cost | Claude Code's own session transcript (`claude` → `/cost`) | **Owner attaches** one real session (instructions below); the profile below is the representative estimate |

The audit trail is the forensically-meaningful log (it is what links a finding to
the exact tool call and verified evidence state). Token usage is the LLM-side
operational metric the requirement also asks for.

## Tool-side audit trail (real, structured)

One JSON object per event, append-only. Event types present in a full run:
`session_start`, `integrity_check`, `tool_call_start`, `tool_call_complete`,
`finding_committed`, `self_correction`, `session_halt`.

A clean live run (`python demo/run_live_investigation.py`, no memory image) emits
**27 events** — 1 session_start, 3 tool_call_start / 3 tool_call_complete (live
EVTX + registry + YARA), 10 finding_committed, 10 self_correction. Every record
carries a timestamp and `session_id`; tool_call_complete records carry
`elapsed_ms` and the SHA-256 `output_hash`. Trimmed sample:
[`demo/audit_trail_sample.jsonl`](../demo/audit_trail_sample.jsonl).

## Token usage (LLM side)

Token cost has two components. The **tool-output** component is measured directly
from real tool outputs (these become input tokens to the model on the next turn);
the **reasoning/output** component is session-dependent and captured exactly via
`/cost`.

### Measured tool-output sizes (real)

`tokens ≈ bytes / 4`. Measured from actual tool output on the bundled evidence /
scenario:

| Tool | Output bytes | ~Tokens | Rows |
|------|-------------:|--------:|-----:|
| `parse_evtx` (real Application log) | 1,826 | ~456 | 10 |
| `registry_query` (real SYSTEM services) | 804 | ~201 | 3 |
| `yara_scan` (real IOC binary, 9 matches) | 3,971 | ~993 | 9 |
| `vol_pslist` (typical scenario) | 3,452 | ~863 | 17 |
| `vol_netscan` (typical scenario) | 1,895 | ~474 | 9 |
| `vol_malfind` (typical scenario) | 704 | ~176 | 2 |
| `vol_cmdline` (typical scenario) | 1,287 | ~322 | 9 |

The `CLAUDE.md` system/protocol prompt is **~1,240 tokens**, loaded once and
prompt-cached across turns.

### Representative per-phase profile (estimate)

A full 7-phase investigation, single agent. Input = protocol + accumulated
history + the turn's tool output; output = the agent's reasoning + next tool call.
These are **representative estimates** for planning — the exact figures for a
given run come from `/cost` (see below).

| Phase | Tools called | ~Input tok (this turn) | ~Output tok |
|-------|--------------|----------------------:|------------:|
| 0 SEAL | session_init, verify_integrity | ~1,400 | ~300 |
| 1 TRIAGE | vol_pslist, vol_netscan | ~2,600 | ~700 |
| 2 DEEP MEMORY | vol_malfind, vol_cmdline | ~2,400 | ~500 |
| 3 LOGS | parse_evtx | ~2,300 | ~400 |
| 4 PERSISTENCE | registry_query | ~2,200 | ~350 |
| 5 TIMELINE | build_timeline | ~2,600 | ~400 |
| 6 IOC SCAN | yara_scan | ~2,900 | ~450 |
| 7 SYNTHESIS | submit_finding ×N, generate_report, export_stix | ~3,200 | ~1,600 |
| **Total** | **15-tool budget/phase** | **~19,600 in** | **~4,700 out** |

Order of magnitude: **~20–25K input / ~5K output tokens** for a complete
investigation (history re-sends inflate input on later turns; prompt caching
offsets the static protocol). A focused single-phase triage is ~3–4K tokens.

### Capturing the exact figures (owner, one real session)

```bash
claude mcp add find-evil -- python -m find_evil.server
claude            # run the 7-phase protocol against the bundled evidence
/cost             # prints exact input/output/cache tokens + USD for the session
```

Attach the `/cost` output (and, if desired, the exported transcript) alongside
`output/audit_trail.jsonl` in the Devpost "Agent Execution Logs" field. The
transcript is the authoritative token-usage record; the table above is the
planning estimate.

## Correlating the two layers

Each finding in the IR report cites the `invocation_ids[]` that produced it →
those UUIDs are the `tool_call_*` records in the audit trail → the LLM turns that
issued and consumed those calls are the corresponding entries in the `/cost`
transcript. Tool side and token side reconcile through the invocation UUID.
