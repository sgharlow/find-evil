# Docker SIFT Live Mode — Setup Guide

**Audience:** Steve setting up local Docker environment for SANS hackathon testing and video recording.

**Time required:** ~15 minutes (mostly Docker build time)

**Prerequisites:** Docker Desktop installed and running on Windows

---

## What This Does

The MCP server has two modes:

| Mode | What happens | When |
|------|-------------|------|
| **Simulated** | Tools return hardcoded forensic data matching our attack scenario | SIFT tools not installed (current dev setup) |
| **Live** | Tools parse real `.evtx` files, registry hives, memory dumps, and run real YARA scans | SIFT tools installed (Docker SIFT image) |

The Docker SIFT image installs `python-evtx`, `yara-python`, `python-registry`, and `volatility3` inside the container. Your Windows system is untouched — everything runs in an isolated Linux container.

---

## Step 1: Build the SIFT Docker Image

Open a terminal in the `find-evil` project directory:

```bash
cd C:/Users/sghar/CascadeProjects/find-evil

# Build the image (~2-3 min first time, cached after)
docker build -f Dockerfile.sift -t find-evil-sift .
```

You should see `All SIFT tools verified` near the end of the build output.

---

## Step 2: Copy Sample Evidence

Copy our test fixtures into the evidence directory so the tools have real files to parse:

```bash
# Copy test evidence into the evidence/ directory
cp tests/fixtures/Application_small.evtx evidence/
cp tests/fixtures/SYSTEM_test.dat evidence/SYSTEM
cp tests/fixtures/SOFTWARE_test.dat evidence/SOFTWARE
cp tests/fixtures/evidence_iocs.bin evidence/
```

---

## Step 3: Run All Tests in Live Mode

This is the moment of truth — tests that were skipped locally should now pass:

```bash
# Run full test suite inside the SIFT container
docker-compose -f docker-compose.sift.yml run --rm mcp-server pytest tests/ -v --tb=short
```

**Expected result:** 544 tests, most passing (the 89 previously-skipped tests should now run). Some may still skip if they need specific evidence files not present.

---

## Step 4: Run the Investigation Demo

This produces the audit trail and IR report that judges need:

```bash
# Run the full 7-phase investigation
docker-compose -f docker-compose.sift.yml run --rm mcp-server python demo/run_investigation.py
```

Output files appear in `output/`:
- `output/audit_trail.jsonl` — Agent execution logs with timestamps (hackathon deliverable)
- `output/ir_report.md` — Generated incident response report

---

## Step 5: Connect Claude Code to the Containerized Server

This is how judges (and you) interact with the MCP server through Claude:

```bash
# Start the container in the background
docker-compose -f docker-compose.sift.yml up -d

# Add the MCP server to Claude Code
claude mcp add find-evil -- docker-compose -f docker-compose.sift.yml exec mcp-server python -m find_evil
```

Now when you open Claude Code, you can say:
> "Initialize evidence at /evidence and investigate for signs of compromise"

Claude will call the MCP tools (session_init, vol_pslist, parse_evtx, etc.) and they'll run against real evidence in live mode.

When done:
```bash
docker-compose -f docker-compose.sift.yml down
```

---

## Step 6: Record the Demo Video

The hackathon requires a **video under 5 minutes** showing live terminal execution with audio narration. Here's a recording workflow:

1. **Start the container:**
   ```bash
   docker-compose -f docker-compose.sift.yml up -d
   ```

2. **Open Claude Code** with the MCP server connected (Step 5 above)

3. **Start screen recording** (OBS, Windows Game Bar `Win+G`, or Loom)

4. **Walk through the investigation protocol:**
   - "Initialize evidence at /evidence" → shows session_init + hash sealing
   - "Run triage — show me running processes and network connections" → vol_pslist + vol_netscan
   - "Parse the security event log for failed logons" → parse_evtx (LIVE mode)
   - "Scan evidence for YARA IOCs" → yara_scan (LIVE mode — real pattern matching)
   - "Check registry for persistence mechanisms" → registry_query (LIVE mode)
   - "Build a timeline of the attack" → build_timeline
   - "Generate the incident response report" → report generation

5. **Narrate key points:**
   - "Notice the tool says LIVE mode, not simulated — it's parsing real evidence"
   - "Every finding has a confidence score from the DRS gate"
   - "The audit trail logs every tool call with a UUID"
   - Show the self-correction: if a finding has low confidence, Claude seeks corroboration

6. **Stop recording,** trim to under 5 minutes

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `docker build` fails on yara-python | Ensure `libyara-dev` is in the Dockerfile apt-get line |
| Tests still show "skipped" | Some tests require specific evidence fixtures — check the skip reason |
| `vol_pslist` returns simulated data | Volatility3 needs a real memory dump (`.raw`/`.vmem`) — sample evidence doesn't include one |
| "Permission denied" on evidence/ | Docker mounts are read-only by design; output goes to `output/` |
| Container exits immediately | MCP uses stdio transport — use `docker-compose run` not `up` for one-shot commands |

## Getting Real Evidence for Volatility (Memory Analysis)

Our simulated memory analysis (vol_pslist, vol_netscan, vol_malfind) works without a real memory dump. For the video demo, the simulated output is fine — judges understand that acquiring memory dumps requires a running compromised system.

If you want to test with a real memory dump:
1. Download a sample from [Digital Corpora](https://digitalcorpora.org/) or [Volatility samples](https://github.com/volatilityfoundation/volatility3/wiki/Sample-Memory-Dumps)
2. Place the `.raw` or `.vmem` file in `evidence/`
3. The MCP server will automatically detect and use Volatility3 in live mode
