"""Super-timeline generation tool.

Wraps Plaso (log2timeline) CLI to produce a unified chronological timeline
of all file system, registry, event log, and other artifact timestamps.
The super-timeline is the most powerful DFIR correlation tool — it puts
all events from all sources on a single time axis.

Backend: Plaso CLI (subprocess) when available. Plaso is not designed as a
Python library — the CLI is the stable, documented interface.
"""

from __future__ import annotations

import logging
import subprocess
from typing import Any

from mcp.server.fastmcp import Context

from find_evil.server import mcp
from find_evil.tools._base import enforce, complete, fail

logger = logging.getLogger("find_evil.tools.timeline")


def _has_plaso() -> bool:
    try:
        result = subprocess.run(
            ["log2timeline.py", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# Simulated super-timeline entries aligned with the attack scenario.
# Timestamps span the attack window (14:19 - 14:24) and include normal
# background activity for context.
SIMULATED_TIMELINE = [
    # Normal morning activity
    {"timestamp": "2024-01-15T08:00:01Z", "source": "EVT", "source_type": "System", "type": "Content Modification Time", "description": "Event log service started", "filename": "System.evtx", "inode": "-"},
    {"timestamp": "2024-01-15T08:01:15Z", "source": "EVT", "source_type": "Security", "type": "Content Modification Time", "description": "[4624] Logon Type 2: jsmith - Interactive logon", "filename": "Security.evtx", "inode": "-"},
    {"timestamp": "2024-01-15T09:14:33Z", "source": "PE", "source_type": "PE Compilation Time", "type": "Creation Time", "description": "chrome.exe executed", "filename": "C:/Program Files/Google/Chrome/Application/chrome.exe", "inode": "12847"},

    # Attack sequence begins — brute force
    {"timestamp": "2024-01-15T14:19:01Z", "source": "EVT", "source_type": "Security", "type": "Content Modification Time", "description": "[4625] Failed logon: administrator from 192.168.1.200", "filename": "Security.evtx", "inode": "-"},
    {"timestamp": "2024-01-15T14:19:04Z", "source": "EVT", "source_type": "Security", "type": "Content Modification Time", "description": "[4625] Failed logon: admin from 192.168.1.200", "filename": "Security.evtx", "inode": "-"},
    {"timestamp": "2024-01-15T14:19:07Z", "source": "EVT", "source_type": "Security", "type": "Content Modification Time", "description": "[4625] Failed logon: admin from 192.168.1.200", "filename": "Security.evtx", "inode": "-"},

    # Successful logon after brute force
    {"timestamp": "2024-01-15T14:21:33Z", "source": "EVT", "source_type": "Security", "type": "Content Modification Time", "description": "[4624] Logon Type 3: admin from 192.168.1.200 - Network logon", "filename": "Security.evtx", "inode": "-"},

    # Lateral movement and payload delivery
    {"timestamp": "2024-01-15T14:22:47Z", "source": "EVT", "source_type": "Security", "type": "Content Modification Time", "description": "[4688] Process created: cmd.exe by svchost.exe (admin)", "filename": "Security.evtx", "inode": "-"},
    {"timestamp": "2024-01-15T14:22:47Z", "source": "PREFETCH", "source_type": "Prefetch", "type": "Last Run Time", "description": "CMD.EXE-087B4001.pf [Run count: 18]", "filename": "C:/Windows/Prefetch/CMD.EXE-087B4001.pf", "inode": "94521"},
    {"timestamp": "2024-01-15T14:22:49Z", "source": "EVT", "source_type": "Security", "type": "Content Modification Time", "description": "[4688] Process created: powershell.exe (encoded command, hidden)", "filename": "Security.evtx", "inode": "-"},
    {"timestamp": "2024-01-15T14:22:49Z", "source": "PREFETCH", "source_type": "Prefetch", "type": "Last Run Time", "description": "POWERSHELL.EXE-022A1004.pf [Run count: 12]", "filename": "C:/Windows/Prefetch/POWERSHELL.EXE-022A1004.pf", "inode": "94588"},

    # Payload dropped to disk
    {"timestamp": "2024-01-15T14:23:00Z", "source": "FILE", "source_type": "NTFS $MFT", "type": "Creation Time", "description": "File created: update.dll", "filename": "C:/Users/victim/AppData/Local/Temp/update.dll", "inode": "112847"},
    {"timestamp": "2024-01-15T14:23:00Z", "source": "FILE", "source_type": "NTFS $MFT", "type": "Content Modification Time", "description": "File written: update.dll (245760 bytes)", "filename": "C:/Users/victim/AppData/Local/Temp/update.dll", "inode": "112847"},

    # DLL loaded via rundll32
    {"timestamp": "2024-01-15T14:23:15Z", "source": "EVT", "source_type": "Security", "type": "Content Modification Time", "description": "[4688] Process created: rundll32.exe loading update.dll", "filename": "Security.evtx", "inode": "-"},
    {"timestamp": "2024-01-15T14:23:15Z", "source": "PREFETCH", "source_type": "Prefetch", "type": "Last Run Time", "description": "RUNDLL32.EXE-0451A804.pf [Run count: 1]", "filename": "C:/Windows/Prefetch/RUNDLL32.EXE-0451A804.pf", "inode": "94601"},

    # C2 connection established
    {"timestamp": "2024-01-15T14:23:18Z", "source": "NET", "source_type": "Network Connection", "type": "Connection Time", "description": "TCP 192.168.1.105:52344 -> 185.220.101.34:8443 ESTABLISHED (rundll32.exe)", "filename": "-", "inode": "-"},

    # Persistence installed
    {"timestamp": "2024-01-15T14:24:02Z", "source": "EVT", "source_type": "System", "type": "Content Modification Time", "description": "[7045] Service installed: Windows Update Helper (update.dll, AUTO_START)", "filename": "System.evtx", "inode": "-"},
    {"timestamp": "2024-01-15T14:24:10Z", "source": "REG", "source_type": "Registry", "type": "Key Last Written Time", "description": "Run key added: WindowsUpdateHelper -> rundll32.exe update.dll", "filename": "NTUSER.DAT", "inode": "-"},

    # C2 beacon pattern (4-minute intervals)
    {"timestamp": "2024-01-15T14:27:18Z", "source": "NET", "source_type": "Network Connection", "type": "Connection Time", "description": "TCP 192.168.1.105:52400 -> 185.220.101.34:8443 CLOSE_WAIT (rundll32.exe)", "filename": "-", "inode": "-"},
    {"timestamp": "2024-01-15T14:31:18Z", "source": "NET", "source_type": "Network Connection", "type": "Connection Time", "description": "TCP 192.168.1.105:52456 -> 185.220.101.34:8443 ESTABLISHED (rundll32.exe)", "filename": "-", "inode": "-"},
]


@mcp.tool()
async def build_timeline(
    evidence_path: str,
    ctx: Context,
    time_after: str | None = None,
    time_before: str | None = None,
    source_filter: str | None = None,
    max_entries: int = 1000,
) -> dict:
    """Build a super-timeline from evidence using Plaso/log2timeline.

    Generates a chronological timeline combining events from all artifact
    sources: file system ($MFT), event logs, registry, prefetch, network,
    and more. This is the most powerful DFIR correlation tool.

    The timeline enables temporal correlation — seeing what happened before,
    during, and after a suspicious event across all evidence sources.

    Args:
        evidence_path: Path to disk image or evidence directory.
        time_after: ISO timestamp — only events after this time.
        time_before: ISO timestamp — only events before this time.
        source_filter: Filter by source type (e.g., "EVT", "FILE", "REG", "NET", "PREFETCH").
        max_entries: Maximum entries to return (default 1000).
    """
    tc = enforce(ctx, "build_timeline", {
        "evidence_path": evidence_path,
        "time_after": time_after,
        "time_before": time_before,
        "source_filter": source_filter,
    })
    if isinstance(tc, dict):
        return tc

    try:
        if _has_plaso():
            entries = _run_plaso(evidence_path)
            mode = "live"
        else:
            entries = list(SIMULATED_TIMELINE)
            mode = "simulated"

        # Apply filters
        if time_after:
            entries = [e for e in entries if e["timestamp"] >= time_after]
        if time_before:
            entries = [e for e in entries if e["timestamp"] <= time_before]
        if source_filter:
            entries = [e for e in entries if e["source"].upper() == source_filter.upper()]

        entries = sorted(entries, key=lambda e: e["timestamp"])[:max_entries]

        # Count sources
        sources = {}
        for e in entries:
            s = e["source"]
            sources[s] = sources.get(s, 0) + 1

        result = {
            "tool": "build_timeline",
            "mode": mode,
            "data": entries,
            "total_entries": len(entries),
            "source_breakdown": sources,
            "time_range": {
                "earliest": entries[0]["timestamp"] if entries else "",
                "latest": entries[-1]["timestamp"] if entries else "",
            },
            "summary": (
                f"{len(entries)} timeline entries across {len(sources)} sources"
                + (f" ({', '.join(f'{k}:{v}' for k, v in sorted(sources.items()))})" if sources else "")
            ),
        }

        return complete(tc, result)

    except Exception as e:
        fail(tc, str(e))
        raise


def _run_plaso(evidence_path: str) -> list[dict]:
    """Run Plaso log2timeline and parse output."""
    import tempfile
    import csv
    import os

    with tempfile.TemporaryDirectory() as tmpdir:
        plaso_db = os.path.join(tmpdir, "timeline.plaso")
        csv_path = os.path.join(tmpdir, "timeline.csv")

        # Step 1: Generate Plaso storage
        subprocess.run(
            ["log2timeline.py", "--status_view", "none", plaso_db, evidence_path],
            capture_output=True, text=True, timeout=600,
            check=True,
        )

        # Step 2: Export to CSV
        subprocess.run(
            ["psort.py", "-o", "l2tcsv", "-w", csv_path, plaso_db],
            capture_output=True, text=True, timeout=300,
            check=True,
        )

        # Step 3: Parse CSV
        entries = []
        with open(csv_path, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                entries.append({
                    "timestamp": row.get("datetime", ""),
                    "source": row.get("source", ""),
                    "source_type": row.get("sourcetype", ""),
                    "type": row.get("type", ""),
                    "description": row.get("desc", ""),
                    "filename": row.get("filename", ""),
                    "inode": row.get("inode", ""),
                })

        return entries
