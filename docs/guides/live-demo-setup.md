# Live Demo Setup — Claude Code + find-evil MCP

One-pager for wiring Claude Code to the find-evil MCP server so you can
record a real autonomous investigation instead of the theatrical
`video_demo.py` run. This is Option B from the recording-readiness audit.

## Prerequisites

- Docker Desktop running
- Claude Code CLI (`claude` on PATH, `claude --version` ≥ 2.x)
- An Anthropic API key in your environment (`ANTHROPIC_API_KEY`)
- This repo checked out at a stable absolute path (the `claude mcp add` line
  below bakes the path into the MCP server registration — moving the repo
  later requires re-adding)

## One-time setup

### 1. Build the Docker image

```bash
docker compose -f docker-compose.sift.yml build
```

This produces `find-evil-mcp-server:latest`. Tag it as the stable alias
`find-evil-sift:latest`:

```bash
docker tag find-evil-mcp-server:latest find-evil-sift:latest
```

### 2. Register the MCP server with Claude Code

**On Windows (Git Bash)** the plain `claude mcp add -- ...` form gets
mangled by MSYS path conversion (the `:` in Docker volume args gets
replaced with `;` and Windows paths get substituted). Use the JSON form
instead — it passes the args through unmodified:

```bash
REPO_WIN=$(python -c "print(r'$(pwd -W)')")
# => C:/Users/sghar/CascadeProjects/find-evil

claude mcp add-json find-evil "{\"type\":\"stdio\",\"command\":\"docker\",\"args\":[\"run\",\"--rm\",\"-i\",\"-e\",\"FIND_EVIL_COMPUTER_REDACT_MAP=TDC-5690-SH.Opus.OpusInspection.com=VICTUS\",\"-v\",\"${REPO_WIN}/evidence:/evidence:ro\",\"-v\",\"${REPO_WIN}/output:/output\",\"find-evil-sift:latest\"]}"
```

**On Linux / macOS** the simpler form works:

```bash
REPO=$(pwd)
claude mcp add find-evil -- docker run --rm -i \
  -e FIND_EVIL_COMPUTER_REDACT_MAP="TDC-5690-SH.Opus.OpusInspection.com=VICTUS" \
  -v "$REPO/evidence:/evidence:ro" \
  -v "$REPO/output:/output" \
  find-evil-sift:latest
```

Key points:

- `--rm -i` — ephemeral container with stdio open (required for MCP stdio)
- `-e FIND_EVIL_COMPUTER_REDACT_MAP=...` — remaps the hostname in the
  fixture's EVTX events to a generic value. Remove or change as needed.
- `evidence:ro` — read-only mount; integrity enforcement sees tamper as
  an attack, which is exactly what we want
- `output` is writable so the audit trail, findings DB, and STIX bundle
  land on the host

Verify:

```bash
claude mcp list
# Expected: find-evil — Connected (or similar OK status)

claude mcp get find-evil
# Expected: 15 tools listed
```

### 3. Smoke-test from the shell (no Claude session)

```bash
bash scripts/test-live-mcp.sh
```

This runs `initialize` + `tools/list` + one real `parse_evtx` call through
the Docker stdio transport and checks that:

1. The server hands back all 15 tools
2. `parse_evtx` returns live-mode output (not simulated)
3. The `Computer` field is redacted to the expected value

## Recording the live investigation

### Before each take

```bash
rm -f output/audit_trail.jsonl output/findings.db output/bundle.stix.json
```

### During the take

1. Open a terminal. Run `claude`.
2. Paste the prompt from `demo/live_investigation.md`.
3. Let the agent work — 4–8 minutes of real tool calls.
4. When Claude stops, ask it to walk through the generated report.

### After the take

- Preserve the `output/` artifacts (rename to `output/takeN/` or similar)
- Audit trail has a UUID per tool call; findings link back to those UUIDs
- STIX bundle is valid 2.1 JSON — show it in the recording if you want the
  threat-intel-handoff moment

## Recovering from a broken take

If Claude hangs, picks up a bad path, or emits a rate-limit mid-stream:

```bash
# In the Claude session
/clear                    # wipes context but keeps MCP attached

# Back to the shell
rm -f output/*.jsonl output/findings.db output/bundle.stix.json

# Resume from the top
claude
```

If the MCP server shows disconnected:

```bash
claude mcp remove find-evil
# Re-run step 2
```

## Why this is genuinely real

Every claim made by the `find-evil` architecture is exercised at runtime:

| Claim | Mechanism during live investigation |
|---|---|
| 15 typed read-only tools, no destructive ones | Claude can ONLY call what's in the tool registry — try asking it to delete a file, it has no such tool |
| SHA-256 evidence sealing at session start | `session_init` hashes every file; the manifest is visible via `list_sealed_evidence` |
| Synchronous integrity gate before every tool call | Editing any file in `./evidence/` between tool calls halts the session; Claude sees the violation and cannot continue |
| 30-second hash daemon | Runs inside the container for the entire investigation |
| UUID-linked audit trail | Every `tools/call` writes a line to `output/audit_trail.jsonl` with a fresh UUID; findings cite those UUIDs |
| DRS confidence gate (0.75 threshold) | `submit_finding` computes the score and returns ACCEPTED / SELF-CORRECT; Claude actually receives this and reacts |
| STIX 2.1 export | `export_stix` produces a valid bundle from whatever IOCs the agent extracted |

What differs from `video_demo.py`:

- The specific findings depend on what's really in the evidence (SPP events,
  registry Run keys, YARA matches). They will look less dramatic than the
  manufactured 7-phase attack scenario, but they will be real.
- Memory tools (`vol_*`) will error because there is no `.raw` memory image.
  This is acceptable — tell the agent to skip them.

## Cleanup (after all recordings are done)

```bash
claude mcp remove find-evil
docker rmi find-evil-sift:latest
```
