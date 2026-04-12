"""Windows Event Log (EVTX) analysis tool.

Parses .evtx files and returns structured event records filtered by
Event ID, time range, and source. Key Event IDs for DFIR:

Security.evtx:
  4624/4625 — Successful/Failed logon
  4688     — Process creation (with command line if audit policy enabled)
  4720     — User account created
  7045     — Service installed

System.evtx:
  7034/7036 — Service crashed/state change
  1074     — Shutdown initiated
  6005/6006 — Event Log service started/stopped

Backend: python-evtx library when available, simulated data for dev/testing.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp.server.fastmcp import Context

from find_evil.server import mcp
from find_evil.tools._base import enforce, complete, fail

logger = logging.getLogger("find_evil.tools.evtx")


def _has_evtx_lib() -> bool:
    try:
        import Evtx  # noqa: F401
        return True
    except ImportError:
        return False


SIMULATED_EVENTS = [
    # Normal logon
    {"EventID": 4624, "TimeCreated": "2024-01-15T08:01:15Z", "Source": "Security", "Computer": "WORKSTATION1", "LogonType": 2, "TargetUserName": "jsmith", "TargetDomainName": "CORP", "IpAddress": "-", "IpPort": "-", "LogonProcessName": "User32"},
    {"EventID": 4624, "TimeCreated": "2024-01-15T08:30:00Z", "Source": "Security", "Computer": "WORKSTATION1", "LogonType": 3, "TargetUserName": "jsmith", "TargetDomainName": "CORP", "IpAddress": "192.168.1.10", "IpPort": "49152", "LogonProcessName": "NtLmSsp"},
    # Suspicious: Network logon from unusual source
    {"EventID": 4624, "TimeCreated": "2024-01-15T14:21:33Z", "Source": "Security", "Computer": "WORKSTATION1", "LogonType": 3, "TargetUserName": "admin", "TargetDomainName": "CORP", "IpAddress": "192.168.1.200", "IpPort": "52100", "LogonProcessName": "NtLmSsp"},
    # Failed logon attempts (brute force indicator)
    {"EventID": 4625, "TimeCreated": "2024-01-15T14:19:01Z", "Source": "Security", "Computer": "WORKSTATION1", "LogonType": 3, "TargetUserName": "administrator", "TargetDomainName": "CORP", "IpAddress": "192.168.1.200", "IpPort": "52001", "Status": "0xC000006D", "SubStatus": "0xC0000064"},
    {"EventID": 4625, "TimeCreated": "2024-01-15T14:19:04Z", "Source": "Security", "Computer": "WORKSTATION1", "LogonType": 3, "TargetUserName": "admin", "TargetDomainName": "CORP", "IpAddress": "192.168.1.200", "IpPort": "52010", "Status": "0xC000006D", "SubStatus": "0xC000006A"},
    {"EventID": 4625, "TimeCreated": "2024-01-15T14:19:07Z", "Source": "Security", "Computer": "WORKSTATION1", "LogonType": 3, "TargetUserName": "admin", "TargetDomainName": "CORP", "IpAddress": "192.168.1.200", "IpPort": "52015", "Status": "0xC000006D", "SubStatus": "0xC000006A"},
    # Process creation — the attack chain
    {"EventID": 4688, "TimeCreated": "2024-01-15T14:22:47Z", "Source": "Security", "Computer": "WORKSTATION1", "NewProcessName": "C:\\Windows\\System32\\cmd.exe", "ParentProcessName": "C:\\Windows\\System32\\svchost.exe", "CommandLine": "cmd.exe /c powershell -ep bypass -nop -w hidden -enc ...", "SubjectUserName": "admin", "TokenElevationType": "%%1937"},
    {"EventID": 4688, "TimeCreated": "2024-01-15T14:22:49Z", "Source": "Security", "Computer": "WORKSTATION1", "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentProcessName": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "powershell -ep bypass -nop -w hidden -enc ...", "SubjectUserName": "admin", "TokenElevationType": "%%1937"},
    {"EventID": 4688, "TimeCreated": "2024-01-15T14:23:15Z", "Source": "Security", "Computer": "WORKSTATION1", "NewProcessName": "C:\\Windows\\System32\\rundll32.exe", "ParentProcessName": "C:\\Windows\\System32\\svchost.exe", "CommandLine": "rundll32.exe C:\\Users\\victim\\AppData\\Local\\Temp\\update.dll,DllRegisterServer", "SubjectUserName": "admin", "TokenElevationType": "%%1937"},
    # Service installation (persistence)
    {"EventID": 7045, "TimeCreated": "2024-01-15T14:24:02Z", "Source": "System", "Computer": "WORKSTATION1", "ServiceName": "Windows Update Helper", "ImagePath": "C:\\Users\\victim\\AppData\\Local\\Temp\\update.dll", "ServiceType": "user mode service", "StartType": "auto start", "AccountName": "LocalSystem"},
    # Normal system events
    {"EventID": 7036, "TimeCreated": "2024-01-15T08:00:30Z", "Source": "System", "Computer": "WORKSTATION1", "ServiceName": "Windows Update", "State": "running"},
    {"EventID": 6005, "TimeCreated": "2024-01-15T08:00:01Z", "Source": "System", "Computer": "WORKSTATION1", "Description": "The Event log service was started."},
]


@mcp.tool()
async def parse_evtx(
    evtx_path: str,
    ctx: Context,
    event_ids: str | None = None,
    time_after: str | None = None,
    time_before: str | None = None,
    source: str | None = None,
    max_events: int = 500,
) -> dict:
    """Parse a Windows Event Log (.evtx) file and return structured events.

    Filters events by Event ID, time range, and source. Returns structured
    records with all relevant fields for DFIR analysis.

    Key Event IDs:
    - 4624: Successful logon (check LogonType 3=network, 10=RDP)
    - 4625: Failed logon (brute force indicator)
    - 4688: Process creation (with command line)
    - 7045: Service installed (persistence indicator)

    Args:
        evtx_path: Path to .evtx file (must be a sealed evidence file).
        event_ids: Comma-separated Event IDs to filter (e.g., "4624,4625,4688").
        time_after: ISO timestamp — only events after this time.
        time_before: ISO timestamp — only events before this time.
        source: Filter by event source (e.g., "Security", "System").
        max_events: Maximum number of events to return (default 500).
    """
    tc = enforce(ctx, "parse_evtx", {
        "evtx_path": evtx_path,
        "event_ids": event_ids,
        "time_after": time_after,
        "time_before": time_before,
        "source": source,
    }, evidence_paths=[evtx_path])
    if isinstance(tc, dict):
        return tc

    try:
        if _has_evtx_lib():
            events = _parse_real_evtx(evtx_path)
            mode = "live"
        else:
            events = list(SIMULATED_EVENTS)
            mode = "simulated"

        # Apply filters
        if event_ids:
            target_ids = {int(x.strip()) for x in event_ids.split(",")}
            events = [e for e in events if e.get("EventID") in target_ids]

        if source:
            events = [e for e in events if e.get("Source", "").lower() == source.lower()]

        if time_after:
            events = [e for e in events if e.get("TimeCreated", "") >= time_after]

        if time_before:
            events = [e for e in events if e.get("TimeCreated", "") <= time_before]

        events = events[:max_events]

        # Flag suspicious events
        for event in events:
            event["suspicious"] = _is_suspicious_event(event)

        suspicious_count = sum(1 for e in events if e.get("suspicious"))
        result = {
            "tool": "parse_evtx",
            "mode": mode,
            "data": events,
            "total_events": len(events),
            "suspicious_count": suspicious_count,
            "summary": (
                f"{len(events)} events returned, "
                f"{suspicious_count} flagged as suspicious"
            ),
        }

        return complete(tc, result)

    except Exception as e:
        fail(tc, str(e))
        raise


def _is_suspicious_event(event: dict) -> bool:
    """Flag events that warrant investigation."""
    eid = event.get("EventID", 0)

    # Failed logons from same source (brute force)
    if eid == 4625:
        return True

    # Network logon (type 3) from unusual times or sources
    if eid == 4624 and event.get("LogonType") == 3:
        hour = event.get("TimeCreated", "T12:")[11:13]
        if hour.isdigit() and (int(hour) < 6 or int(hour) > 22):
            return True

    # Process creation with suspicious command lines
    if eid == 4688:
        cmdline = event.get("CommandLine", "").lower()
        if any(x in cmdline for x in ["-enc", "bypass", "hidden", "temp\\"]):
            return True

    # Service installation from temp/user paths
    if eid == 7045:
        path = event.get("ImagePath", "").lower()
        if any(x in path for x in ["\\temp\\", "\\appdata\\", "\\users\\"]):
            return True

    return False


def _parse_real_evtx(evtx_path: str) -> list[dict]:
    """Parse a real .evtx file using python-evtx library."""
    import Evtx.Evtx as evtx
    import xml.etree.ElementTree as ET

    events = []
    with evtx.Evtx(evtx_path) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
                ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

                system = root.find("ns:System", ns)
                if system is None:
                    continue

                event_id_elem = system.find("ns:EventID", ns)
                time_elem = system.find("ns:TimeCreated", ns)
                computer_elem = system.find("ns:Computer", ns)

                event = {
                    "EventID": int(event_id_elem.text) if event_id_elem is not None and event_id_elem.text else 0,
                    "TimeCreated": time_elem.get("SystemTime", "") if time_elem is not None else "",
                    "Computer": computer_elem.text if computer_elem is not None else "",
                }

                # Extract EventData fields
                event_data = root.find("ns:EventData", ns)
                if event_data is not None:
                    for data_elem in event_data.findall("ns:Data", ns):
                        name = data_elem.get("Name", "")
                        if name and data_elem.text:
                            event[name] = data_elem.text

                events.append(event)
            except ET.ParseError:
                continue

    return events
