# Evidence Directory

Place forensic evidence files here for live analysis.

This directory is mounted **read-only** into the Docker container at `/evidence`.
The MCP server cannot modify anything in this directory — that's by design.

## Included sample evidence

These files are committed so the Docker SIFT container can run in **live mode**
(real parsing via python-evtx, yara-python, python-registry) out of the box,
without needing to source external evidence.

| File | Size | Type | Tool | Description |
|------|------|------|------|-------------|
| `Application_small.evtx` | 69 KB | Windows Event Log | `parse_evtx` | Real EVTX from `tests/fixtures/` — contains parseable Application log events |
| `SYSTEM` | 8 KB | Registry hive | `registry_query` | Synthetic regf-format hive with 3 services (Dhcp, WinDefend, WinUpdateHelper) |
| `SOFTWARE` | 8 KB | Registry hive | `registry_query` | Synthetic regf-format hive with Run key entries (SecurityHealth, WindowsDefender, WindowsUpdateHelper) |
| `evidence_iocs.bin` | 7 KB | Binary evidence | `yara_scan` | Contains 10 embedded IOC patterns (PowerShell, Mimikatz, Cobalt Strike, C2 IP, etc.) |
| `find_evil_rules.yar` | 8 KB | YARA rules | `yara_scan` | 12 custom YARA rules organized by MITRE ATT&CK tactic |

### Quick verification inside the Docker container

```bash
# Parse the EVTX file (live mode — real python-evtx parsing)
python -c "
from find_evil.tools.evtx import _parse_real_evtx
events = _parse_real_evtx('/evidence/Application_small.evtx')
print(f'{len(events)} events parsed')
"

# Scan IOC binary with custom YARA rules (live mode — real yara-python)
python -c "
from find_evil.tools.yara_scan import _run_real_yara
matches = _run_real_yara('/evidence/evidence_iocs.bin', '/evidence/find_evil_rules.yar')
print(f'{len(matches)} YARA matches')
for m in matches:
    print(f'  [{m[\"severity\"]}] {m[\"rule\"]}')
"

# Query registry hive (live mode — real python-registry)
python -c "
from find_evil.tools.registry import _query_real_registry
result = _query_real_registry('/evidence/SYSTEM', 'ControlSet001\\\\Services')
print(result)
"
```

## Supported evidence types

| Type | Extensions | Tool |
|------|-----------|------|
| Windows Event Logs | `.evtx` | `parse_evtx` (python-evtx) |
| Registry hives | `SYSTEM`, `SOFTWARE`, `NTUSER.DAT`, `SAM` | `registry_query` (python-registry) |
| Memory dumps | `.raw`, `.vmem`, `.dmp` | `vol_pslist`, `vol_netscan`, etc. (volatility3) |
| Any binary file | `*` | `yara_scan` (yara-python) |
| Disk images | `.E01`, `.dd`, `.raw` | `build_timeline` (plaso/log2timeline) |

## Populating evidence (automated)

Run the populate script to regenerate all sample evidence from test fixtures:

```bash
python evidence/populate_samples.py
```

This copies fixtures from `tests/fixtures/` and generates fresh registry hives.
The script is idempotent — safe to run multiple times.

## Adding real evidence for deeper demos

### Windows Event Logs (.evtx)

Real `.evtx` files provide the richest live-mode demo. Sources:

1. **Your own machine** (Windows):
   - `C:\Windows\System32\winevt\Logs\Security.evtx`
   - `C:\Windows\System32\winevt\Logs\System.evtx`
   - Copy and place them here (they may be large — 50MB+)

2. **SANS DFIR samples**: https://www.sans.org/blog/sans-dfir-challenge/

3. **EVTX-ATTACK-SAMPLES** (GitHub):
   ```bash
   git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git /tmp/evtx-samples
   cp /tmp/evtx-samples/Credential\ Access/*.evtx evidence/
   ```

### Memory dumps (.raw, .vmem)

Memory dumps enable volatility3 tools (`vol_pslist`, `vol_netscan`, `vol_malfind`).
These are large (1-8 GB) and **gitignored** — do not commit them.

- Digital Corpora: https://digitalcorpora.org/
- NIST CFReDS: https://cfreds.nist.gov/
- Volatility Foundation samples: https://github.com/volatilityfoundation/volatility3/wiki/Sample-Memory-Images

### Disk images (.E01, .dd)

Disk images enable `build_timeline` (plaso/log2timeline). Also large and gitignored.

- Digital Corpora: https://digitalcorpora.org/
- SANS DFIR challenges: https://www.sans.org/blog/sans-dfir-challenge/

### Custom YARA rules

Place additional `.yar` files here and reference them via the `rules_path` parameter:

```python
yara_scan(target_path="/evidence/suspect_file.bin",
          rules_path="/evidence/my_custom_rules.yar")
```

The included `find_evil_rules.yar` covers 12 rules across 8 MITRE ATT&CK tactics.
To add rules, either edit that file or create a new `.yar` alongside it.

## Note on EVTX generation

The EVTX binary format (Microsoft BinXML) is proprietary and cannot be reliably
generated from Python alone. The `Application_small.evtx` file was sourced as a
real Windows Event Log fixture. To generate custom EVTX files with specific
Event IDs (4624, 4688, 7045, etc.), use a Windows machine:

```powershell
# On Windows, write custom events then export
Write-EventLog -LogName Application -Source "TestSource" -EventId 1000 -Message "Test event"
wevtutil epl Application evidence\custom.evtx
```

Or use the `evtxgen` tool from the SIFT workstation if available.
