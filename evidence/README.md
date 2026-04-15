# Evidence Directory

Place forensic evidence files here for live analysis.

This directory is mounted **read-only** into the Docker container at `/evidence`.
The MCP server cannot modify anything in this directory — that's by design.

## Supported evidence types

| Type | Extensions | Tool |
|------|-----------|------|
| Windows Event Logs | `.evtx` | `parse_evtx` (python-evtx) |
| Registry hives | `SYSTEM`, `SOFTWARE`, `NTUSER.DAT`, `SAM` | `registry_query` (python-registry) |
| Memory dumps | `.raw`, `.vmem`, `.dmp` | `vol_pslist`, `vol_netscan`, etc. (volatility3) |
| Any binary file | `*` | `yara_scan` (yara-python) |
| Disk images | `.E01`, `.dd`, `.raw` | `build_timeline` (plaso/log2timeline) |

## Quick start with sample evidence

Copy the test fixtures into this directory for a quick demo:

```bash
cp tests/fixtures/Application_small.evtx evidence/
cp tests/fixtures/SYSTEM_test.dat evidence/
cp tests/fixtures/SOFTWARE_test.dat evidence/
cp tests/fixtures/evidence_iocs.bin evidence/
```

## Using real evidence

For the SANS hackathon, download sample evidence from:
- SANS DFIR challenges: https://www.sans.org/blog/sans-dfir-challenge/
- Digital Corpora: https://digitalcorpora.org/
- NIST CFReDS: https://cfreds.nist.gov/
