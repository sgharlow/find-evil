# Try It Out — Judge Setup Instructions

**Want to see it first?** The 2-minute demo video is at **https://youtu.be/7VTVS9E6cX8** — live autonomous investigation with DRS self-correction, YARA matches, and STIX export.

Get the Evidence Integrity Enforcer running in under 5 minutes.

## Option A: Local Install (Fastest)

### Prerequisites
- Python 3.11+
- pip

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/sgharlow/find-evil.git
cd find-evil

# 2. Install
pip install -e ".[dev]"

# 3. Run the test suite (544 total: 543 passing, 1 skipped)
pytest tests/ -v

# 4. Run the tamper detection demo
python demo/tamper_demo.py

# 5. Run a full simulated investigation
python demo/run_investigation.py

# 6. Inspect the outputs
cat output/audit_trail.jsonl | head -10   # JSONL audit trail
cat output/ir_report.md                    # Generated IR report
```

### Connect to Claude Code

```bash
# Register the MCP server
claude mcp add find-evil -- python -m find_evil

# Now Claude Code can use all 15 forensic tools
# Start a conversation and ask it to investigate evidence
```

## Option B: Docker (Reproducible)

### Prerequisites
- Docker
- Docker Compose

### Steps

```bash
# 1. Clone and build
git clone https://github.com/sgharlow/find-evil.git
cd find-evil
docker-compose build

# 2. Run tests in container
docker-compose run mcp-server pytest tests/ -v

# 3. Run the tamper demo
docker-compose run mcp-server python demo/tamper_demo.py

# 4. Run the full investigation
docker-compose run mcp-server python demo/run_investigation.py

# 5. Connect Claude Code to the container
claude mcp add find-evil -- docker-compose exec mcp-server python -m find_evil
```

## What to Inspect

### 1. Security Boundary (Constraint Implementation)

Verify that no destructive tools exist:

```bash
python -c "
from find_evil.server import mcp
tools = mcp._tool_manager.list_tools()
names = {t.name for t in tools}
print(f'{len(tools)} tools registered:')
for t in tools: print(f'  {t.name}')
bad = names & {'execute_shell_cmd','write_file','rm','dd','shell','bash'}
assert not bad, f'VIOLATION: {bad}'
print('Security check: PASSED')
"
```

### 2. Tamper Detection (Evidence Integrity)

```bash
python demo/tamper_demo.py
```

Watch for: SHA-256 sealing, byte-level tamper detection (not `touch`),
session halt, all findings voided, re-seal recovery.

### 3. Audit Trail (Provenance Chain)

After running the investigation:

```bash
# Each entry is one JSON object per line
cat output/audit_trail.jsonl

# Trace a finding back to its source tool calls:
# finding_committed -> provenance[] -> invocation_ids -> tool_call_start
```

### 4. DRS Self-Correction (Autonomous Execution Quality)

In the investigation output, look for findings that score below the 0.75
threshold and are flagged for self-correction. The agent must seek
additional corroborating evidence before these findings are accepted.

### 5. Generated IR Report

```bash
cat output/ir_report.md
```

Contains: executive summary, findings with confidence scores and provenance
UUIDs, self-correction log, IOC summary table, evidence integrity statement.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: find_evil` | Run `pip install -e .` from the repo root |
| Tests fail with import errors | Ensure Python 3.11+ (`python --version`) |
| Docker build fails | Ensure Docker daemon is running |
| `yara_scan` test skipped | Expected — yara-python not installed (optional dependency) |
