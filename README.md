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
- DRS confidence gate forces self-correction on low-confidence findings

## Architecture

```
+------------------------------------------------------------------+
|                    SIFT Workstation (Ubuntu)                      |
|                                                                  |
|  +------------------+    +------------------------------------+  |
|  | Claude Code      |    | Evidence Integrity MCP Server      |  |
|  | Agent            |--->| (Python 3.11+ / FastMCP / stdio)   |  |
|  |                  |<---|                                    |  |
|  | - Follows        |    |  [1] Evidence Session Manager      |  |
|  |   CLAUDE.md      |    |      SHA-256 seal at session start |  |
|  | - 7-phase        |    |      verify_all() on every call    |  |
|  |   investigation  |    |      halt + void on mismatch       |  |
|  | - DRS gate       |    |                                    |  |
|  |   self-correct   |    |  [2] Hash Daemon (30s thread)      |  |
|  | - Max-iter cap   |    |      Background re-verification    |  |
|  +------------------+    |      Stops on first violation      |  |
|                          |                                    |  |
|                          |  [3] enforce() Gate                |  |
|                          |      EVERY tool call goes through: |  |
|                          |      verify -> log -> execute ->   |  |
|                          |      hash output -> log complete   |  |
|                          |                                    |  |
|                          |  [4] Typed Tool Registry           |  |
|                          |      14 read-only functions:       |  |
|                          |                                    |  |
|                          |    SESSION   vol_pslist             |  |
|                          |    session_init   vol_netscan       |  |
|                          |    verify_integrity  vol_malfind    |  |
|                          |    list_sealed    vol_cmdline       |  |
|                          |    reseal_evidence  parse_evtx     |  |
|                          |                  registry_query    |  |
|                          |    ANALYSIS      build_timeline    |  |
|                          |    submit_finding  yara_scan       |  |
|                          |    generate_report                 |  |
|                          |                                    |  |
|                          |    NOT AVAILABLE:                  |  |
|                          |    X execute_shell_cmd             |  |
|                          |    X write_file / rm / dd          |  |
|                          |    X modify_evidence               |  |
|                          |                                    |  |
|                          |  [5] Audit Logger (JSONL)          |  |
|                          |      UUID per invocation           |  |
|                          |      Finding -> invocation chain   |  |
|                          |                                    |  |
|                          |  [6] DRS Confidence Gate           |  |
|                          |      confidence = evidence*0.6     |  |
|                          |                  + corroboration*0.4|  |
|                          |      < 0.75: SELF-CORRECT          |  |
|                          |      >= 0.75: ACCEPT               |  |
|                          |                                    |  |
|                          |  [7] Findings DB (SQLite)          |  |
|                          |      Provenance chain              |  |
|                          |      Self-correction log           |  |
|                          +------------------------------------+  |
|                                        |                         |
|                          +-------------v----------------------+  |
|                          | SIFT Tool Layer                    |  |
|                          | Volatility3 | Plaso | RegRipper    |  |
|                          | python-evtx | YARA  | Sleuth Kit   |  |
|                          +------------------------------------+  |
+------------------------------------------------------------------+
```

**Data flow for every tool call:**

```
Agent calls tool
  -> enforce() verifies evidence integrity (SHA-256)
    -> audit logger records invocation start (UUID)
      -> SIFT tool executes (read-only)
        -> parser structures output (JSON)
          -> audit logger records completion (output hash)
            -> provenance metadata attached to result
              -> result returned to agent
```

## Quick Start

```bash
# Install
git clone https://github.com/sgharlow/find-evil.git
cd find-evil
pip install -e ".[dev]"

# Run tests (334 total: 333 passing, 1 skipped)
pytest tests/ -v

# Run the tamper detection demo
python demo/tamper_demo.py

# Run a full simulated investigation
python demo/run_investigation.py

# Inspect outputs
cat output/audit_trail.jsonl   # JSONL audit trail with UUID provenance
cat output/ir_report.md        # Generated incident response report
```

### Connect to Claude Code

```bash
claude mcp add find-evil -- python -m find_evil.server
```

### Docker

```bash
docker-compose build
docker-compose run mcp-server pytest tests/ -v
docker-compose run mcp-server python demo/run_investigation.py
```

## Judging Criteria Map

| Criterion | Weight | How This Submission Wins |
|-----------|--------|------------------------|
| **Constraint Implementation** | High | Destructive functions don't exist. Zero attack surface. Not a blocklist. |
| **Audit Trail Quality** | High | UUID provenance chain: finding -> tool call -> verified evidence |
| **IR Accuracy** | High | Structured JSON from typed tools, not raw text dumps to LLM |
| **Autonomous Execution** | Tiebreaker | DRS gate forces self-correction below 0.75 confidence |
| **Breadth/Depth** | Medium | 15 tools across memory, disk, logs, registry, network, IOCs, STIX export |
| **Usability** | Medium | `pip install -e .` + one command. Docker for reproducibility. |

## Test Suite

334 tests (333 passing, 1 skipped), organized by component:

| Category | Tests | What They Verify |
|----------|-------|-----------------|
| Session integrity | 15 | SHA-256 sealing, tamper detection, halt, reseal |
| Hash daemon | 7 | Background verification, on-demand checks, idempotency |
| DRS confidence gate | 13 | Scoring formula, threshold, self-correction guidance |
| Audit logger | 10 | JSONL format, UUID provenance, finding chain |
| Volatility tools | 18 | Process, connection, cmdline anomaly detection |
| EVTX tools | 9 | Event log parsing, suspicious event flagging |
| Registry tools | 12 | Persistence detection, query filtering |
| Timeline tools | 7 | Chronological ordering, source coverage, attack window |
| YARA tools | 11 | Rule matching, severity, MITRE mapping |
| Security bypass | 21 | Registry boundary, path traversal, state attacks, tamper bypass |
| Integration | 12 | enforce() gate, tool pipeline, audit trail completeness |
| Scenario | 21 | Full 7-phase attack narrative, cross-tool correlation |

## MITRE ATT&CK Coverage

The investigation demo detects techniques across the full attack lifecycle:

| Tactic | Technique | ID | Detection Source |
|--------|-----------|-----|-----------------|
| Initial Access | Brute Force | T1110.001 | EVTX (4625→4624 sequence) |
| Execution | Command-Line Interface | T1059.001 | vol_cmdline (encoded PowerShell) |
| Execution | LOLBin Chain | T1059.003 | vol_pslist (parent-child anomaly) |
| Persistence | Service Install | T1543.003 | registry_query + EVTX (7045) |
| Persistence | Registry Run Key | T1547.001 | registry_query (Temp path) |
| Privilege Escalation | Token Manipulation | T1134.001 | EVTX (4672 SeDebugPrivilege) |
| Defense Evasion | Process Injection | T1055.001 | vol_malfind (MZ in RWX) |
| Defense Evasion | Masquerading | T1036.004 | vol_pslist (svchost under powershell) |
| Credential Access | LSASS Dump | T1003.001 | yara_scan (mimikatz pattern) |
| Lateral Movement | PsExec | T1570 | EVTX (PSEXESVC install) |
| Lateral Movement | WMI | T1047 | EVTX (WmiPrvSE→cmd) |
| Lateral Movement | RDP | T1021.001 | EVTX (Type 10 logon) |
| Collection | Archive Data | T1560.001 | yara_scan (compression header) |
| Command & Control | Web Protocols | T1071.001 | vol_netscan (185.220.101.34:8443) |
| User Execution | Malicious File | T1204.002 | yara_scan (update.dll) |

**15 techniques across 11 tactics** — covering initial access through C2 with cross-tool corroboration.

## Submission Deliverables

| # | Deliverable | Location |
|---|------------|----------|
| 1 | Code Repository | This repo (MIT license) |
| 2 | Demo Video | `demo/video_demo.py` (script), `demo/VIDEO_SCRIPT.md` |
| 3 | Architecture Diagram | This README (above) |
| 4 | Project Description | This README + Devpost |
| 5 | Dataset Documentation | `docs/dataset_documentation.md` |
| 6 | Accuracy Report | `docs/accuracy_report.md` |
| 7 | Try-It-Out Instructions | `docs/try_it_out.md` |
| 8 | Agent Execution Logs | `output/audit_trail.jsonl` (generated by demo) |

## License

MIT
