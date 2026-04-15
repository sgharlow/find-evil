/*
 * find-evil Custom YARA Rules
 *
 * These rules are designed for the SANS hackathon demo, targeting
 * common indicators of compromise (IOCs) found in forensic evidence.
 * They can be loaded via the yara_scan tool's rules_path parameter:
 *
 *   yara_scan(target_path="/evidence/evidence_iocs.bin",
 *             rules_path="/evidence/find_evil_rules.yar")
 *
 * Rules are organized by MITRE ATT&CK tactic.
 */

// =====================================================================
// Initial Access / Execution (TA0001 / TA0002)
// =====================================================================

rule Encoded_PowerShell_Execution {
    meta:
        description = "Base64-encoded PowerShell with bypass flags — common in initial access payloads"
        severity = "high"
        mitre = "T1059.001"
        author = "find-evil"
    strings:
        $ps = "powershell" ascii nocase
        $enc1 = "-enc" ascii nocase
        $enc2 = "-encodedcommand" ascii nocase
        $bypass = "-ep bypass" ascii nocase
        $hidden = "-w hidden" ascii nocase
        $noprofile = "-nop" ascii nocase
    condition:
        $ps and ($enc1 or $enc2) and ($bypass or $hidden or $noprofile)
}

// =====================================================================
// Persistence (TA0003)
// =====================================================================

rule Suspicious_DLL_In_Temp {
    meta:
        description = "DLL execution from user temp directory via rundll32"
        severity = "high"
        mitre = "T1204.002"
        author = "find-evil"
    strings:
        $temp = "\\AppData\\Local\\Temp\\" ascii nocase
        $dll = ".dll" ascii nocase
        $rundll = "rundll32" ascii nocase
    condition:
        $temp and $dll and $rundll
}

rule Suspicious_Service_Path {
    meta:
        description = "Service binary in non-standard location (user profile, temp)"
        severity = "high"
        mitre = "T1543.003"
        author = "find-evil"
    strings:
        $user_path1 = "\\Users\\" ascii nocase
        $user_path2 = "\\AppData\\" ascii nocase
        $temp_path = "\\Temp\\" ascii nocase
        $svc1 = "ImagePath" ascii nocase
        $svc2 = "ServiceDll" ascii nocase
    condition:
        ($svc1 or $svc2) and ($user_path1 or $user_path2) and $temp_path
}

// =====================================================================
// Privilege Escalation (TA0004)
// =====================================================================

rule Mimikatz_Indicators {
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

// =====================================================================
// Defense Evasion (TA0005)
// =====================================================================

rule LOLBin_Download {
    meta:
        description = "Living-off-the-land binary used for file download"
        severity = "high"
        mitre = "T1218"
        author = "find-evil"
    strings:
        $certutil = "certutil" ascii nocase
        $bitsadmin = "bitsadmin" ascii nocase
        $mshta = "mshta" ascii nocase
        $url1 = "http://" ascii nocase
        $url2 = "https://" ascii nocase
        $urlcache = "-urlcache" ascii nocase
        $transfer = "/transfer" ascii nocase
    condition:
        ($certutil or $bitsadmin or $mshta) and ($url1 or $url2 or $urlcache or $transfer)
}

// =====================================================================
// Lateral Movement (TA0008)
// =====================================================================

rule PsExec_Artifacts {
    meta:
        description = "PsExec remote execution tool artifacts"
        severity = "high"
        mitre = "T1570"
        author = "find-evil"
    strings:
        $psexec = "psexec" ascii nocase
        $psexesvc = "PSEXESVC" ascii
        $admin_share = "\\ADMIN$\\" ascii nocase
        $c_share = "\\C$\\" ascii nocase
        $ipc_share = "\\IPC$" ascii nocase
    condition:
        2 of them
}

// =====================================================================
// Command and Control (TA0011)
// =====================================================================

rule Known_C2_Infrastructure {
    meta:
        description = "IP addresses associated with known C2 infrastructure"
        severity = "critical"
        mitre = "T1071.001"
        author = "find-evil"
    strings:
        $ip1 = "185.220.101.34" ascii
        $ip2 = "185.220.101" ascii
    condition:
        any of them
}

rule Cobalt_Strike_Beacon {
    meta:
        description = "Cobalt Strike shellcode or beacon signature"
        severity = "critical"
        mitre = "T1055.001"
        author = "find-evil"
    strings:
        $shellcode = { FC 48 83 E4 F0 }
        $mz = { 4D 5A 90 00 }
    condition:
        any of them
}

// =====================================================================
// Collection / Exfiltration (TA0009 / TA0010)
// =====================================================================

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
        $flag1 = "-r" ascii
        $flag2 = "a " ascii
        $target1 = "\\Desktop\\" ascii nocase
        $target2 = "\\Documents\\" ascii nocase
        $target3 = "\\Downloads\\" ascii nocase
    condition:
        ($z1 or $z2 or $z3) and ($flag1 or $flag2) and any of ($target*)
}

// =====================================================================
// Impact (TA0040)
// =====================================================================

rule Ransomware_Note {
    meta:
        description = "Ransomware ransom note indicators"
        severity = "critical"
        mitre = "T1486"
        author = "find-evil"
    strings:
        $r1 = "Your files have been encrypted" ascii nocase
        $r2 = "bitcoin" ascii nocase
        $r3 = "decrypt" ascii nocase
        $r4 = ".onion" ascii nocase
        $r5 = "private key" ascii nocase
        $r6 = "payment" ascii nocase
    condition:
        3 of them
}

// =====================================================================
// Web Persistence
// =====================================================================

rule PHP_Webshell {
    meta:
        description = "PHP webshell used for persistent remote access"
        severity = "high"
        mitre = "T1505.003"
        author = "find-evil"
    strings:
        $eval = "eval(" ascii nocase
        $b64 = "base64_decode(" ascii nocase
        $system = "system(" ascii nocase
        $exec = "exec(" ascii nocase
        $passthru = "passthru(" ascii nocase
        $shell = "shell_exec(" ascii nocase
        $request = "$_REQUEST" ascii
        $post = "$_POST" ascii
        $cmd = "cmd" ascii
    condition:
        ($request or $post) and 2 of ($eval, $b64, $system, $exec, $passthru, $shell) and $cmd
}
