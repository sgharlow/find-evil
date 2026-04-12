"""Windows Registry analysis tool.

Queries registry hives for persistence indicators and configuration data.
Key hives and areas for DFIR:

SYSTEM:
  - ControlSet001/Services — installed services (persistence)
  - ControlSet001/Control/Session Manager — boot execution
  - ControlSet001/Control/ComputerName — hostname

SOFTWARE:
  - Microsoft/Windows/CurrentVersion/Run — auto-start programs
  - Microsoft/Windows/CurrentVersion/RunOnce — one-time auto-start
  - Microsoft/Windows NT/CurrentVersion — OS version info
  - Microsoft/Windows/CurrentVersion/Uninstall — installed software

NTUSER.DAT (per-user):
  - Software/Microsoft/Windows/CurrentVersion/Run — user auto-start
  - Software/Microsoft/Windows/CurrentVersion/Explorer/RunMRU — run dialog history
  - Software/Microsoft/Windows/CurrentVersion/Explorer/UserAssist — program execution

SAM:
  - SAM/Domains/Account/Users — local user accounts

Backend: regrippy/python-registry when available, simulated data for dev/testing.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp.server.fastmcp import Context

from find_evil.server import mcp
from find_evil.tools._base import enforce, complete, fail

logger = logging.getLogger("find_evil.tools.registry")


def _has_registry_lib() -> bool:
    try:
        import Registry  # noqa: F401
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Simulated registry data — consistent with the attack scenario
# ---------------------------------------------------------------------------

SIMULATED_RUN_KEYS = [
    {
        "hive": "SOFTWARE",
        "key_path": "Microsoft\\Windows\\CurrentVersion\\Run",
        "value_name": "SecurityHealth",
        "value_data": "C:\\Windows\\System32\\SecurityHealthSystray.exe",
        "value_type": "REG_SZ",
        "last_modified": "2024-01-10T12:00:00Z",
        "suspicious": False,
    },
    {
        "hive": "SOFTWARE",
        "key_path": "Microsoft\\Windows\\CurrentVersion\\Run",
        "value_name": "WindowsDefender",
        "value_data": "\"C:\\Program Files\\Windows Defender\\MSASCuiL.exe\"",
        "value_type": "REG_SZ",
        "last_modified": "2024-01-10T12:00:00Z",
        "suspicious": False,
    },
    # Suspicious: persistence via Run key planted by attacker
    {
        "hive": "NTUSER.DAT",
        "key_path": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "value_name": "WindowsUpdateHelper",
        "value_data": "rundll32.exe C:\\Users\\victim\\AppData\\Local\\Temp\\update.dll,DllRegisterServer",
        "value_type": "REG_SZ",
        "last_modified": "2024-01-15T14:24:10Z",
        "suspicious": True,
    },
]

SIMULATED_SERVICES = [
    {
        "hive": "SYSTEM",
        "key_path": "ControlSet001\\Services\\Dhcp",
        "service_name": "Dhcp",
        "display_name": "DHCP Client",
        "image_path": "C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
        "start_type": 2,
        "start_type_name": "AUTO_START",
        "service_type": 32,
        "last_modified": "2024-01-10T08:00:00Z",
        "suspicious": False,
    },
    {
        "hive": "SYSTEM",
        "key_path": "ControlSet001\\Services\\WinDefend",
        "service_name": "WinDefend",
        "display_name": "Windows Defender Antivirus Service",
        "image_path": "\"C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\4.18.23110.3-0\\MsMpEng.exe\"",
        "start_type": 2,
        "start_type_name": "AUTO_START",
        "service_type": 16,
        "last_modified": "2024-01-12T10:30:00Z",
        "suspicious": False,
    },
    # Suspicious: service installed by attacker
    {
        "hive": "SYSTEM",
        "key_path": "ControlSet001\\Services\\WinUpdateHelper",
        "service_name": "WinUpdateHelper",
        "display_name": "Windows Update Helper",
        "image_path": "C:\\Users\\victim\\AppData\\Local\\Temp\\update.dll",
        "start_type": 2,
        "start_type_name": "AUTO_START",
        "service_type": 16,
        "last_modified": "2024-01-15T14:24:02Z",
        "suspicious": True,
    },
]

SIMULATED_USERASSIST = [
    {
        "hive": "NTUSER.DAT",
        "key_path": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
        "program": "C:\\Windows\\System32\\cmd.exe",
        "run_count": 18,
        "last_run": "2024-01-15T14:22:47Z",
        "focus_time_seconds": 45,
        "suspicious": True,
    },
    {
        "hive": "NTUSER.DAT",
        "key_path": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
        "program": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "run_count": 12,
        "last_run": "2024-01-15T14:22:49Z",
        "focus_time_seconds": 120,
        "suspicious": True,
    },
    {
        "hive": "NTUSER.DAT",
        "key_path": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
        "program": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "run_count": 244,
        "last_run": "2024-01-15T13:00:00Z",
        "focus_time_seconds": 28800,
        "suspicious": False,
    },
]


@mcp.tool()
async def registry_query(
    hive_path: str,
    ctx: Context,
    query_type: str = "all",
    key_filter: str | None = None,
) -> dict:
    """Query a Windows registry hive for persistence indicators and configuration.

    Extracts auto-start entries (Run/RunOnce keys), installed services,
    user execution history (UserAssist), and other forensically relevant
    registry artifacts.

    Args:
        hive_path: Path to registry hive file (SYSTEM, SOFTWARE, NTUSER.DAT, SAM).
        query_type: What to extract: "run_keys", "services", "userassist", or "all".
        key_filter: Optional key path substring filter (e.g., "CurrentVersion\\Run").
    """
    tc = enforce(ctx, "registry_query", {
        "hive_path": hive_path,
        "query_type": query_type,
        "key_filter": key_filter,
    })
    if isinstance(tc, dict):
        return tc

    try:
        if _has_registry_lib():
            entries = _parse_real_registry(hive_path, query_type)
            mode = "live"
        else:
            entries = _get_simulated_registry(query_type)
            mode = "simulated"

        # Apply key filter
        if key_filter:
            entries = [
                e for e in entries
                if key_filter.lower() in e.get("key_path", "").lower()
            ]

        # Flag suspicious entries
        for entry in entries:
            if "suspicious" not in entry:
                entry["suspicious"] = _is_suspicious_registry(entry)

        suspicious_count = sum(1 for e in entries if e.get("suspicious"))
        result = {
            "tool": "registry_query",
            "mode": mode,
            "query_type": query_type,
            "data": entries,
            "total_entries": len(entries),
            "suspicious_count": suspicious_count,
            "summary": (
                f"{len(entries)} registry entries found, "
                f"{suspicious_count} flagged as suspicious"
            ),
        }

        return complete(tc, result)

    except Exception as e:
        fail(tc, str(e))
        raise


def _get_simulated_registry(query_type: str) -> list[dict]:
    """Return simulated registry data based on query type."""
    if query_type == "run_keys":
        return list(SIMULATED_RUN_KEYS)
    elif query_type == "services":
        return list(SIMULATED_SERVICES)
    elif query_type == "userassist":
        return list(SIMULATED_USERASSIST)
    else:  # "all"
        return list(SIMULATED_RUN_KEYS) + list(SIMULATED_SERVICES) + list(SIMULATED_USERASSIST)


def _is_suspicious_registry(entry: dict) -> bool:
    """Flag registry entries that warrant investigation."""
    # Services or Run keys pointing to Temp/AppData paths
    for field in ("value_data", "image_path"):
        val = entry.get(field, "").lower()
        if any(sus in val for sus in ["\\temp\\", "\\appdata\\", "\\users\\"] ):
            if any(ext in val for ext in [".dll", ".exe", ".bat", ".ps1", ".vbs"]):
                return True

    # rundll32 in Run keys
    if "rundll32" in entry.get("value_data", "").lower():
        return True

    # Unusually high cmd.exe or powershell execution from UserAssist
    program = entry.get("program", "").lower()
    run_count = entry.get("run_count", 0)
    if program.endswith("cmd.exe") and run_count > 10:
        return True
    if "powershell" in program and run_count > 5:
        return True

    return False


def _parse_real_registry(hive_path: str, query_type: str) -> list[dict]:
    """Parse a real registry hive file using python-registry."""
    from Registry import Registry

    reg = Registry.Registry(hive_path)
    entries = []

    if query_type in ("run_keys", "all"):
        for path in [
            "Microsoft\\Windows\\CurrentVersion\\Run",
            "Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        ]:
            try:
                key = reg.open(path)
                for value in key.values():
                    entries.append({
                        "key_path": path,
                        "value_name": value.name(),
                        "value_data": str(value.value()),
                        "value_type": str(value.value_type()),
                        "last_modified": str(key.timestamp()),
                    })
            except Registry.RegistryKeyNotFoundException:
                continue

    if query_type in ("services", "all"):
        try:
            services_key = reg.open("ControlSet001\\Services")
            for subkey in services_key.subkeys():
                entry = {
                    "key_path": f"ControlSet001\\Services\\{subkey.name()}",
                    "service_name": subkey.name(),
                    "last_modified": str(subkey.timestamp()),
                }
                for value in subkey.values():
                    if value.name() == "ImagePath":
                        entry["image_path"] = str(value.value())
                    elif value.name() == "Start":
                        entry["start_type"] = value.value()
                    elif value.name() == "DisplayName":
                        entry["display_name"] = str(value.value())
                entries.append(entry)
        except Registry.RegistryKeyNotFoundException:
            pass

    return entries
