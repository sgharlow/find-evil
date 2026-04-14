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

rule Mimikatz_Credential_Theft {
    meta:
        description = "Mimikatz credential dumping tool signatures"
        severity = "critical"
        mitre = "T1003.001"
        author = "find-evil"
    strings:
        $s1 = "sekurlsa::logonpasswords" ascii nocase
        $s2 = "sekurlsa::wdigest" ascii nocase
        $s3 = "lsadump::sam" ascii nocase
        $s4 = "lsadump::dcsync" ascii nocase
        $s5 = "kerberos::golden" ascii nocase
        $s6 = "privilege::debug" ascii nocase
        $s7 = "mimikatz" ascii nocase
        $s8 = "gentilkiwi" ascii nocase
    condition:
        2 of them
}

rule Ransomware_Note_Indicators {
    meta:
        description = "Common ransomware ransom note patterns"
        severity = "critical"
        mitre = "T1486"
        author = "find-evil"
    strings:
        $r1 = "Your files have been encrypted" ascii nocase
        $r2 = "bitcoin" ascii nocase
        $r3 = "decrypt" ascii nocase
        $r4 = "ransom" ascii nocase
        $r5 = ".onion" ascii nocase
        $r6 = "private key" ascii nocase
        $r7 = "payment" ascii nocase
        $r8 = "restore your files" ascii nocase
    condition:
        3 of them
}

rule Webshell_PHP_Indicators {
    meta:
        description = "PHP webshell patterns used for persistence"
        severity = "high"
        mitre = "T1505.003"
        author = "find-evil"
    strings:
        $f1 = "eval(" ascii nocase
        $f2 = "base64_decode(" ascii nocase
        $f3 = "system(" ascii nocase
        $f4 = "exec(" ascii nocase
        $f5 = "passthru(" ascii nocase
        $f6 = "shell_exec(" ascii nocase
        $f7 = "$_REQUEST" ascii
        $f8 = "$_POST" ascii
        $f9 = "cmd" ascii
    condition:
        ($f7 or $f8) and 2 of ($f1, $f2, $f3, $f4, $f5, $f6) and $f9
}

rule Lateral_Movement_PsExec {
    meta:
        description = "PsExec and remote execution tool artifacts"
        severity = "high"
        mitre = "T1570"
        author = "find-evil"
    strings:
        $p1 = "psexec" ascii nocase
        $p2 = "PSEXESVC" ascii nocase
        $p3 = "\\\\ADMIN$\\\\" ascii nocase
        $p4 = "\\\\C$\\\\" ascii nocase
        $p5 = "\\\\IPC$" ascii nocase
        $wmi1 = "wmic" ascii nocase
        $wmi2 = "process call create" ascii nocase
        $wmi3 = "Win32_Process" ascii nocase
    condition:
        2 of ($p1, $p2, $p3, $p4, $p5) or ($wmi1 and ($wmi2 or $wmi3))
}

rule Data_Staging_Archive {
    meta:
        description = "Data staging via archive tools before exfiltration"
        severity = "medium"
        mitre = "T1560.001"
        author = "find-evil"
    strings:
        $z1 = "7z.exe" ascii nocase
        $z2 = "rar.exe" ascii nocase
        $z3 = "Compress-Archive" ascii nocase
        $z4 = "-p" ascii
        $flag1 = "-r" ascii
        $flag2 = "a " ascii
        $target1 = "\\\\Desktop\\\\" ascii nocase
        $target2 = "\\\\Documents\\\\" ascii nocase
        $target3 = "\\\\Downloads\\\\" ascii nocase
    condition:
        ($z1 or $z2 or $z3) and ($flag1 or $flag2 or $z4) and any of ($target*)
}

rule LOLBin_Abuse_Pattern {
    meta:
        description = "Living-off-the-land binary abuse for defense evasion"
        severity = "high"
        mitre = "T1218"
        author = "find-evil"
    strings:
        $l1 = "mshta" ascii nocase
        $l2 = "certutil" ascii nocase
        $l3 = "bitsadmin" ascii nocase
        $l4 = "regsvr32" ascii nocase
        $l5 = "msiexec" ascii nocase
        $d1 = "http://" ascii nocase
        $d2 = "https://" ascii nocase
        $d3 = "-urlcache" ascii nocase
        $d4 = "/transfer" ascii nocase
        $d5 = "scrobj.dll" ascii nocase
    condition:
        any of ($l*) and any of ($d*)
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
    {
        "rule": "Mimikatz_Credential_Theft",
        "severity": "critical",
        "mitre": "T1003.001",
        "description": "Mimikatz credential dumping tool signatures",
        "file": "memory.raw",
        "offset": 50331648,
        "matched_strings": [
            {"identifier": "$s1", "offset": 50331648, "data": "sekurlsa::logonpasswords"},
            {"identifier": "$s6", "offset": 50331580, "data": "privilege::debug"},
        ],
    },
    {
        "rule": "Lateral_Movement_PsExec",
        "severity": "high",
        "mitre": "T1570",
        "description": "PsExec and remote execution tool artifacts",
        "file": "memory.raw",
        "offset": 58720256,
        "matched_strings": [
            {"identifier": "$p2", "offset": 58720256, "data": "PSEXESVC"},
            {"identifier": "$p3", "offset": 58720300, "data": "\\\\ADMIN$\\"},
        ],
    },
    {
        "rule": "Data_Staging_Archive",
        "severity": "medium",
        "mitre": "T1560.001",
        "description": "Data staging via archive tools before exfiltration",
        "file": "memory.raw",
        "offset": 62914560,
        "matched_strings": [
            {"identifier": "$z1", "offset": 62914560, "data": "7z.exe"},
            {"identifier": "$flag1", "offset": 62914572, "data": "-r"},
            {"identifier": "$target2", "offset": 62914580, "data": "\\Documents\\"},
        ],
    },
    {
        "rule": "LOLBin_Abuse_Pattern",
        "severity": "high",
        "mitre": "T1218",
        "description": "Living-off-the-land binary abuse for defense evasion",
        "file": "memory.raw",
        "offset": 67108864,
        "matched_strings": [
            {"identifier": "$l2", "offset": 67108864, "data": "certutil"},
            {"identifier": "$d3", "offset": 67108880, "data": "-urlcache"},
            {"identifier": "$d2", "offset": 67108900, "data": "https://185.220.101.34:8444/payload"},
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
    }, evidence_paths=[target_path])
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
    """Run YARA scan using yara-python library.

    Supports both yara-python 4.x (StringMatch/StringMatchInstance objects)
    and legacy 3.x (offset, identifier, data tuples) APIs.
    """
    import yara

    if rules_path:
        rules = yara.compile(filepath=rules_path)
    else:
        rules = yara.compile(source=BUILTIN_RULES_SOURCE)

    raw_matches = rules.match(target_path)

    matches = []
    for match in raw_matches:
        matched_strings = []
        for string_match in match.strings:
            # yara-python 4.x: StringMatch objects with .identifier and .instances
            if hasattr(string_match, "instances"):
                for instance in string_match.instances:
                    matched_strings.append({
                        "identifier": string_match.identifier,
                        "offset": instance.offset,
                        "data": instance.matched_data.decode(
                            "utf-8", errors="replace"
                        )[:100],
                    })
            else:
                # Legacy 3.x: (offset, identifier, data) tuples
                offset, identifier, data = string_match
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
