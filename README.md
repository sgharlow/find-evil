# Evidence Integrity Enforcer

**FIND EVIL! SANS Hackathon** (April 15 - June 15, 2026)

A purpose-built MCP server that wraps SIFT Workstation forensic tools as typed,
read-only functions — with cryptographic evidence integrity enforcement that is
**architecturally impossible to bypass**.

## The Core Insight

Most AI-assisted DFIR tools rely on prompt-based guardrails ("please don't
modify evidence files"). This submission enforces integrity the same way a
professional forensic lab does — through physical controls that make tampering
impossible by design, not by instruction.

- Destructive functions (`shell`, `write`, `rm`, `dd`) **do not exist** in the MCP server
- Evidence files are SHA-256 sealed before any tool runs
- A background daemon re-verifies hashes every 30 seconds AND before every tool call
- Any modification halts the session and voids all findings
- Full UUID-linked audit trail traces every finding back to its source tool call

## Architecture

```
Claude Code Agent          Evidence Integrity MCP Server
 (autonomous DFIR)    ──►   (Python, FastMCP, stdio)
                              │
                              ├─ Evidence Session Manager
                              │   SHA-256 seal ─► verify ─► halt on mismatch
                              │
                              ├─ Hash Daemon (30s background thread)
                              │
                              ├─ Typed Tool Registry (read-only only)
                              │   vol_pslist │ vol_netscan │ vol_malfind
                              │   parse_evtx │ registry_query │ yara_scan
                              │   build_timeline │ vol_cmdline │ ...
                              │
                              │   NOT AVAILABLE:
                              │   ✗ execute_shell_cmd  ✗ write_file
                              │   ✗ rm / dd / mkfs     ✗ modify_evidence
                              │
                              ├─ Audit Logger (JSONL + UUID provenance)
                              │
                              └─ DRS Confidence Gate (self-correction < 0.75)
                                    │
                              SIFT Workstation Tool Layer
                              Volatility3 │ Plaso │ RegRipper
                              python-evtx │ YARA │ Sleuth Kit
```

## Quick Start

```bash
# Install
pip install -e .

# Connect to Claude Code
claude mcp add find-evil -- python -m find_evil.server

# Or run with auto-sealed evidence
EVIDENCE_DIR=/path/to/case-data claude mcp add find-evil -- python -m find_evil.server
```

## Status

Under active development. See `PLAN.md` for implementation roadmap.
