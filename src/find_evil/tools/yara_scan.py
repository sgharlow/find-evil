"""YARA rule scanning tool.

Scans files or directories for IOC patterns using YARA rules.
YARA is the standard for pattern matching in malware analysis and
threat hunting. This tool applies YARA rules to evidence files and
returns structured match results.

Backend: yara-python library when available, simulated matches for dev/testing.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp.server.fastmcp import Context

from find_evil.server import mcp
from find_evil.tools._base import enforce, complete, fail

logger = logging.getLogger("find_evil.tools.yara_scan")


def _has_yara() -> bool:
    try:
        import yara  # noqa: F401
        return True
    except ImportError:
        return False


# Built-in detection rules (compiled at runtime if yara-python available).
# These cover common IOC patterns found in the simulated attack scenario.
BUILTIN_RULES_SOURCE = """
rule Suspicious_PowerShell_Encoded {
    meta:
        description = "Detects base64-encoded PowerShell commands"
        severity = "high"
        mitre = "T1059.001"
    strings:
        $enc1 = "powershell" ascii nocase
        $enc2 = "-enc" ascii nocase
        $enc3 = "-encodedcommand" ascii nocase
        $bypass = "-ep bypass" ascii nocase
        $hidden = "-w hidden" ascii nocase
    condition:
        $enc1 and ($enc2 or $enc3) and ($bypass or $hidden)
}

rule Suspicious_DLL_Temp_Path {
    meta:
        description = "DLL loaded from user temp directory"
        severity = "high"
        mitre = "T1204.002"
    strings:
        $temp1 = "\\\\AppData\\\\Local\\\\Temp\\\\" ascii nocase
        $dll = ".dll" ascii nocase
        $rundll = "rundll32" ascii nocase
    condition:
        $temp1 and $dll and $rundll
}

rule Cobalt_Strike_Shellcode_Pattern {
    meta:
        description = "Potential Cobalt Strike or Metasploit shellcode"
        severity = "critical"
        mitre = "T1055.001"
    strings:
        $mz_header = { 4D 5A 90 00 }
        $shellcode_cld = { FC 48 83 E4 F0 }
    condition:
        $mz_header or $shellcode_cld
}

rule C2_IP_Indicator {
    meta:
        description = "Known C2 infrastructure IP address"
        severity = "critical"
        mitre = "T1071.001"
    strings:
        $ip1 = "185.220.101.34" ascii
        $ip2 = "185.220.101" ascii
    condition:
        any of them
}
"""

# Simulated YARA matches consistent with the attack scenario
SIMULATED_MATCHES = [
    {
        "rule": "Suspicious_PowerShell_Encoded",
        "severity": "high",
        "mitre": "T1059.001",
        "description": "Detects base64-encoded PowerShell commands",
        "file": "memory.raw",
        "offset": 8847360,
        "matched_strings": [
            {"identifier": "$enc1", "offset": 8847360, "data": "powershell"},
            {"identifier": "$enc2", "offset": 8847372, "data": "-enc"},
            {"identifier": "$bypass", "offset": 8847382, "data": "-ep bypass"},
        ],
    },
    {
        "rule": "Suspicious_DLL_Temp_Path",
        "severity": "high",
        "mitre": "T1204.002",
        "description": "DLL loaded from user temp directory",
        "file": "memory.raw",
        "offset": 12582912,
        "matched_strings": [
            {"identifier": "$temp1", "offset": 12582912, "data": "\\AppData\\Local\\Temp\\"},
            {"identifier": "$dll", "offset": 12582944, "data": ".dll"},
            {"identifier": "$rundll", "offset": 12582900, "data": "rundll32"},
        ],
    },
    {
        "rule": "Cobalt_Strike_Shellcode_Pattern",
        "severity": "critical",
        "mitre": "T1055.001",
        "description": "Potential Cobalt Strike or Metasploit shellcode",
        "file": "memory.raw",
        "offset": 41943040,
        "matched_strings": [
            {"identifier": "$shellcode_cld", "offset": 41943040, "data": "FC 48 83 E4 F0"},
        ],
    },
    {
        "rule": "C2_IP_Indicator",
        "severity": "critical",
        "mitre": "T1071.001",
        "description": "Known C2 infrastructure IP address",
        "file": "memory.raw",
        "offset": 15728640,
        "matched_strings": [
            {"identifier": "$ip1", "offset": 15728640, "data": "185.220.101.34"},
        ],
    },
]


@mcp.tool()
async def yara_scan(
    target_path: str,
    ctx: Context,
    rules_path: str | None = None,
    severity_filter: str | None = None,
) -> dict:
    """Scan files for IOC patterns using YARA rules.

    Applies YARA rules to evidence files and returns structured match results.
    Includes built-in rules for common attack patterns (encoded PowerShell,
    DLLs in temp paths, shellcode, and known C2 indicators). Custom rules
    can be provided via rules_path.

    Args:
        target_path: Path to file or directory to scan.
        rules_path: Optional path to custom YARA rules file. If omitted, uses built-in rules.
        severity_filter: Filter results by severity: "critical", "high", "medium", "low".
    """
    tc = enforce(ctx, "yara_scan", {
        "target_path": target_path,
        "rules_path": rules_path,
        "severity_filter": severity_filter,
    })
    if isinstance(tc, dict):
        return tc

    try:
        if _has_yara():
            matches = _run_real_yara(target_path, rules_path)
            mode = "live"
        else:
            matches = list(SIMULATED_MATCHES)
            mode = "simulated"

        if severity_filter:
            matches = [m for m in matches if m.get("severity") == severity_filter.lower()]

        # Severity summary
        severity_counts = {}
        for m in matches:
            sev = m.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Extract unique MITRE techniques
        mitre_techniques = sorted({m.get("mitre", "") for m in matches if m.get("mitre")})

        result = {
            "tool": "yara_scan",
            "mode": mode,
            "data": matches,
            "total_matches": len(matches),
            "severity_breakdown": severity_counts,
            "mitre_techniques": mitre_techniques,
            "rules_used": "built-in" if not rules_path else rules_path,
            "summary": (
                f"{len(matches)} YARA matches found"
                + (f" ({', '.join(f'{k}:{v}' for k, v in sorted(severity_counts.items()))})" if severity_counts else "")
                + (f" — MITRE: {', '.join(mitre_techniques)}" if mitre_techniques else "")
            ),
        }

        return complete(tc, result)

    except Exception as e:
        fail(tc, str(e))
        raise


def _run_real_yara(target_path: str, rules_path: str | None) -> list[dict]:
    """Run YARA scan using yara-python library."""
    import yara

    if rules_path:
        rules = yara.compile(filepath=rules_path)
    else:
        rules = yara.compile(source=BUILTIN_RULES_SOURCE)

    raw_matches = rules.match(target_path)

    matches = []
    for match in raw_matches:
        matched_strings = []
        for offset, identifier, data in match.strings:
            matched_strings.append({
                "identifier": identifier,
                "offset": offset,
                "data": data.decode("utf-8", errors="replace")[:100],
            })

        matches.append({
            "rule": match.rule,
            "severity": match.meta.get("severity", "unknown"),
            "mitre": match.meta.get("mitre", ""),
            "description": match.meta.get("description", ""),
            "file": target_path,
            "matched_strings": matched_strings,
        })

    return matches
