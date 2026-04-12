# Dataset Documentation

## Evidence Sources

### Simulated Attack Scenario (Development and Testing)

For development and testing without a SIFT Workstation, the MCP server includes
a comprehensive simulated attack scenario embedded in each tool module. All
simulated data is clearly labeled with `"mode": "simulated"` in tool output.

**Scenario**: A network intrusion with lateral movement, process injection,
and persistence installation on a Windows workstation.

**Attack Timeline**:

| Time (UTC) | Event | Source |
|------------|-------|--------|
| 08:00 | System boot, normal user logon (jsmith) | EVTX, Timeline |
| 09:14 | Chrome browser session | Process list, Timeline |
| 14:19 | Brute force begins: 3 failed logons from 192.168.1.200 | EVTX, Timeline |
| 14:21 | Successful network logon as "admin" from 192.168.1.200 | EVTX, Timeline |
| 14:22 | cmd.exe spawned by svchost.exe (LOLBin abuse) | Process list, EVTX, Cmdline, Prefetch, Timeline |
| 14:22 | Encoded PowerShell: `-ep bypass -nop -w hidden -enc ...` | Cmdline, EVTX, YARA |
| 14:23 | update.dll dropped to AppData\Local\Temp | MFT Timeline, YARA |
| 14:23 | rundll32.exe loads update.dll (process injection) | Process list, EVTX, Malfind, Timeline |
| 14:23 | C2 connection: 192.168.1.105:52344 → 185.220.101.34:8443 | Netscan, Timeline, YARA |
| 14:24 | Service persistence: "Windows Update Helper" (update.dll) | EVTX, Registry, Timeline |
| 14:24 | Run key persistence: WindowsUpdateHelper → rundll32 update.dll | Registry, Timeline |
| 14:27 | C2 beacon (4-minute interval) | Netscan, Timeline |
| 14:31 | C2 beacon (4-minute interval) | Netscan, Timeline |

**Process Chain** (parent → child):
```
svchost.exe (PID 788) → cmd.exe (PID 4088) → powershell.exe (PID 4112) → svchost.exe (PID 4200) → rundll32.exe (PID 4344)
```

**IOCs (Indicators of Compromise)**:
- C2 IP: 185.220.101.34 (port 8443, 4-minute beacon interval)
- Attacker source: 192.168.1.200
- Malicious DLL: C:\Users\victim\AppData\Local\Temp\update.dll
- Persistence service: "Windows Update Helper"
- Persistence Run key: "WindowsUpdateHelper"
- Encoded PowerShell with `-ep bypass -nop -w hidden`
- Shellcode pattern: `FC 48 83 E4 F0` (CLD + stack alignment)
- MZ header in PAGE_EXECUTE_READWRITE memory (process injection)

**MITRE ATT&CK Techniques**:
- T1110.001 — Brute Force: Password Guessing
- T1078 — Valid Accounts (network logon after brute force)
- T1059.001 — PowerShell (encoded command)
- T1059.003 — Windows Command Shell (cmd.exe LOLBin)
- T1055.001 — Process Injection: DLL Injection
- T1071.001 — Application Layer Protocol: Web Protocols (C2 over HTTPS)
- T1543.003 — Create or Modify System Process: Windows Service
- T1547.001 — Boot or Logon Autostart: Registry Run Keys

### Cross-Tool Consistency

All 7 tool types return data from the same scenario. This is verified by
21 automated tests in `tests/test_scenario.py`:

- C2 IP (185.220.101.34) appears in netscan, timeline, and YARA matches
- Malicious DLL (update.dll) appears in cmdline, registry, timeline, and EVTX
- Attacker IP (192.168.1.200) appears in EVTX and timeline
- PID 4344 (rundll32.exe) appears in both pslist and netscan C2 connections
- Attack timestamps are chronologically consistent across all sources

### Real Evidence (SIFT Workstation Deployment)

When deployed on a SIFT Workstation with real forensic tools installed
(Volatility3, python-evtx, regrippy, yara-python, Plaso), the MCP server
automatically uses the real tool backends instead of simulated data.

Planned test evidence sources:
- SANS DFIR sample data (downloadable from sans.org/tools/sift-workstation)
- Volatility Foundation sample memory images
- Custom test image with planted known artifacts

Tool output is labeled `"mode": "live"` when using real backends.

## Tool Versions

| Tool | Package | Version | Backend |
|------|---------|---------|---------|
| Volatility3 | volatility3 | >=2.5.0 | Python API (direct) |
| Event Logs | python-evtx | >=0.7.4 | Python library |
| Registry | python-registry | >=1.4.0 | Python library |
| YARA | yara-python | >=4.3.0 | Python library |
| Timeline | Plaso (log2timeline) | CLI | subprocess |
| MCP Server | mcp | >=1.0.0 | FastMCP (stdio transport) |
