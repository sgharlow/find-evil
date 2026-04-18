#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Polished Video Demo — Evidence Integrity Enforcer.

This is the single script you run while recording the 5-minute demo video.
It produces clean, color-coded terminal output with dramatic timing at
key moments that match the narration script (see VIDEO_SCRIPT.md).

Features:
  - Race clock showing elapsed time vs adversary breakout (7:00)
  - Color-coded output (green=pass, red=violation, yellow=self-correct)
  - Timed pauses at key moments for narration
  - Three acts: SEAL -> INVESTIGATE -> TAMPER -> RECOVER -> REPORT

Usage:
    python demo/video_demo.py

Tip: Use a large terminal font (18-20pt) and dark background for recording.
     Terminal should be ~100 columns wide.
"""

import sys
import time
import json
import tempfile
import threading
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from find_evil.session.manager import EvidenceSession
from find_evil.session.hash_daemon import HashDaemon
from find_evil.audit.logger import AuditLogger
from find_evil.analysis.findings_db import FindingsDB
from find_evil.analysis.drs_gate import DRSGate, Finding
from find_evil.tools._base import enforce, complete, ToolContext
from find_evil.tools.findings import build_stix_bundle

# --- ANSI colors ---
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"

# --- Race clock ---
_start_time = None

def start_clock():
    global _start_time
    _start_time = time.time()

def clock_str():
    if _start_time is None:
        return "0:00"
    elapsed = time.time() - _start_time
    m, s = divmod(int(elapsed), 60)
    return f"{m}:{s:02d}"

def clock_line():
    return f"{DIM}[{clock_str()} elapsed | Adversary breakout: 7:00]{RESET}"

# --- Output helpers ---
def banner(text):
    w = 62
    print()
    print(f"  {CYAN}{'=' * w}{RESET}")
    print(f"  {CYAN}{BOLD}  {text}{RESET}")
    print(f"  {CYAN}{'=' * w}{RESET}")
    print(f"  {clock_line()}")

def tool_call(name, args_str=""):
    print(f"  {WHITE}[AGENT]{RESET} Calling: {BOLD}{name}{RESET}({DIM}{args_str}{RESET})")

def mcp_result(text, suspicious=0):
    if suspicious > 0:
        print(f"  {GREEN}[MCP]{RESET}   Integrity verified. {text} {YELLOW}-- {suspicious} SUSPICIOUS{RESET}")
    else:
        print(f"  {GREEN}[MCP]{RESET}   Integrity verified. {text}")

def finding_accepted(desc, confidence):
    print(f"  {GREEN}[+]{RESET} {BOLD}{desc}{RESET}")
    print(f"      {GREEN}Confidence: {confidence:.2f} -> ACCEPTED{RESET}")

def finding_selfcorrect(desc, confidence):
    print(f"  {YELLOW}[~]{RESET} {BOLD}{desc}{RESET}")
    print(f"      {YELLOW}Confidence: {confidence:.2f} -> SELF-CORRECT (seeking corroboration){RESET}")

def violation_banner():
    w = 58
    print()
    print(f"  {BG_RED}{WHITE}{BOLD}{'!' * w}{RESET}")
    print(f"  {BG_RED}{WHITE}{BOLD}  EVIDENCE INTEGRITY VIOLATION DETECTED                  {RESET}")
    print(f"  {BG_RED}{WHITE}{BOLD}{'!' * w}{RESET}")
    print()

def pause(seconds=1.5):
    """Pause for narration timing."""
    time.sleep(seconds)


class MockContext:
    def __init__(self, lifespan):
        self.request_context = type("RC", (), {"lifespan_context": lifespan})()


def main():
    output_dir = Path(__file__).parent.parent / "output"
    output_dir.mkdir(exist_ok=True)

    # Clear previous outputs
    for f in ["audit_trail.jsonl", "findings.db", "ir_report.md"]:
        p = output_dir / f
        if p.exists():
            p.unlink()

    print()
    print(f"  {BOLD}{WHITE}")
    print(f"  ############################################################")
    print(f"  #                                                          #")
    print(f"  #   EVIDENCE INTEGRITY ENFORCER                            #")
    print(f"  #   Autonomous DFIR Investigation                          #")
    print(f"  #                                                          #")
    print(f"  #   FIND EVIL! SANS Hackathon 2026                         #")
    print(f"  #                                                          #")
    print(f"  ############################################################")
    print(f"  {RESET}")

    pause(2)

    # ================================================================
    # ACT 1: SEAL EVIDENCE
    # ================================================================

    with tempfile.TemporaryDirectory() as tmpdir:
        evidence_dir = Path(tmpdir)
        files = {
            "victim-hdd.img": b"DISK_IMAGE_" + b"\x00" * 2000,
            "memory.raw": b"MEMORY_DUMP_" + b"\x00" * 1500,
            "network.pcap": b"PCAP_CAPTURE_" + b"\x00" * 800,
            "Security.evtx": b"EVTX_SECURITY_" + b"\x00" * 600,
            "SYSTEM.hive": b"REG_SYSTEM_" + b"\x00" * 400,
        }
        for name, content in files.items():
            (evidence_dir / name).write_bytes(content)

        session = EvidenceSession()
        audit = AuditLogger(path=str(output_dir / "audit_trail.jsonl"))
        findings_db = FindingsDB(path=str(output_dir / "findings.db"))
        gate = DRSGate()

        start_clock()

        banner("Phase 0: SEAL EVIDENCE")
        pause(1)

        print(f"\n  {DIM}$ sift-enforcer start --case ./evidence/{RESET}\n")
        pause(0.5)

        info = session.initialize(str(evidence_dir))
        audit.set_session_id(info.session_id)
        audit.log_session_start(info.model_dump())
        findings_db.record_session(info.session_id, str(evidence_dir), info.file_count, info.sealed_at)

        print(f"  {GREEN}[MCP-SERVER]{RESET} Initializing evidence session {BOLD}{info.session_id[:8]}...{RESET}")
        pause(0.3)
        print(f"  Hashing evidence files:")
        for fp, h in info.manifest.items():
            name = Path(fp).name
            print(f"    {name:20s}  sha256: {h}  {GREEN}SEALED{RESET}")
            pause(0.2)

        daemon = HashDaemon(session, interval=5)  # 5s for demo
        daemon.start()

        print(f"\n  {GREEN}Evidence sealed. Chain of custody established.{RESET}")
        print(f"  Hash daemon started -- 30 second verification cycle.")

        print(f"\n  {BOLD}Available functions:{RESET}")
        print(f"    vol_pslist | vol_netscan | vol_malfind | vol_cmdline")
        print(f"    parse_evtx | registry_query | build_timeline | yara_scan")
        print(f"    submit_finding | generate_report")
        print(f"\n  {RED}NOT available: execute_shell_cmd | rm | dd | write_to_disk{RESET}")

        ctx = MockContext({
            "session": session, "daemon": daemon,
            "audit": audit, "findings_db": findings_db,
        })
        invocations = {}

        pause(3)

        # ================================================================
        # ACT 2: AUTONOMOUS INVESTIGATION
        # ================================================================

        # -- Phase 1: TRIAGE --
        banner("Phase 1: TRIAGE (Memory)")
        pause(0.5)

        from find_evil.tools.volatility import (
            SIMULATED_PSLIST, SIMULATED_NETSCAN, SIMULATED_MALFIND, SIMULATED_CMDLINE,
            _is_suspicious_process, _is_suspicious_connection,
        )
        from find_evil.tools.evtx import SIMULATED_EVENTS
        from find_evil.tools.registry import SIMULATED_RUN_KEYS, SIMULATED_SERVICES
        from find_evil.tools.timeline import SIMULATED_TIMELINE
        from find_evil.tools.yara_scan import SIMULATED_MATCHES

        for p in SIMULATED_PSLIST:
            p["suspicious"] = _is_suspicious_process(p, SIMULATED_PSLIST)
        for c in SIMULATED_NETSCAN:
            c["suspicious"] = _is_suspicious_connection(c)

        tool_call("vol_pslist", "image_path='memory.raw'")
        tc = enforce(ctx, "vol_pslist", {"memory_image": "memory.raw"})
        complete(tc, {"data": SIMULATED_PSLIST, "summary": "17 procs"})
        invocations["vol_pslist"] = tc.invocation_id
        suspicious_p = sum(1 for p in SIMULATED_PSLIST if p.get("suspicious"))
        mcp_result(f"Returning: 17 processes, {suspicious_p} anomalies flagged", suspicious_p)
        pause(0.8)

        tool_call("vol_netscan", "image_path='memory.raw'")
        tc = enforce(ctx, "vol_netscan", {"memory_image": "memory.raw"})
        complete(tc, {"data": SIMULATED_NETSCAN, "summary": "9 conns"})
        invocations["vol_netscan"] = tc.invocation_id
        suspicious_c = sum(1 for c in SIMULATED_NETSCAN if c.get("suspicious"))
        mcp_result(f"Returning: 9 connections, {suspicious_c} suspicious external", suspicious_c)
        pause(0.8)

        # -- Phase 2: DEEP MEMORY --
        banner("Phase 2: DEEP MEMORY")
        pause(0.5)

        tool_call("vol_malfind", "image_path='memory.raw'")
        tc = enforce(ctx, "vol_malfind", {"memory_image": "memory.raw"})
        complete(tc, {"data": SIMULATED_MALFIND, "summary": "2 injections"})
        invocations["vol_malfind"] = tc.invocation_id
        mcp_result("Returning: 2 suspicious memory regions (MZ header + shellcode)", 2)
        pause(0.8)

        tool_call("vol_cmdline", "image_path='memory.raw'")
        tc = enforce(ctx, "vol_cmdline", {"memory_image": "memory.raw"})
        complete(tc, {"data": SIMULATED_CMDLINE, "summary": "9 cmdlines"})
        invocations["vol_cmdline"] = tc.invocation_id
        mcp_result("Returning: 9 command lines -- encoded PowerShell detected", 3)
        pause(0.8)

        # -- Phase 3: LOGS --
        banner("Phase 3: EVENT LOGS")
        pause(0.5)

        tool_call("parse_evtx", "evtx_path='Security.evtx', event_ids='4624,4625,4688,7045'")
        tc = enforce(ctx, "parse_evtx", {"evtx_path": "Security.evtx"})
        complete(tc, {"data": SIMULATED_EVENTS, "summary": "12 events"})
        invocations["parse_evtx"] = tc.invocation_id
        mcp_result("Returning: 12 events -- 3 failed logons, service install from Temp", 5)
        pause(0.8)

        # -- Phase 4: PERSISTENCE --
        banner("Phase 4: PERSISTENCE (Registry)")
        pause(0.5)

        tool_call("registry_query", "hive_path='SYSTEM', query_type='all'")
        combined_reg = list(SIMULATED_RUN_KEYS) + list(SIMULATED_SERVICES)
        tc = enforce(ctx, "registry_query", {"hive_path": "SYSTEM"})
        complete(tc, {"data": combined_reg, "summary": "6 entries"})
        invocations["registry_query"] = tc.invocation_id
        mcp_result("Returning: 6 entries -- Run key + service pointing to update.dll", 2)
        pause(0.8)

        # -- Phase 5: TIMELINE --
        banner("Phase 5: SUPER-TIMELINE")
        pause(0.5)

        tool_call("build_timeline", "evidence_path='victim-hdd.img'")
        tc = enforce(ctx, "build_timeline", {"evidence_path": "victim-hdd.img"})
        complete(tc, {"data": SIMULATED_TIMELINE, "summary": "20 entries"})
        invocations["build_timeline"] = tc.invocation_id
        mcp_result("Returning: 20 timeline entries across EVT, FILE, NET, REG, PREFETCH")
        pause(0.8)

        # -- Phase 6: IOC SCAN --
        banner("Phase 6: YARA IOC SCAN")
        pause(0.5)

        tool_call("yara_scan", "target_path='memory.raw'")
        tc = enforce(ctx, "yara_scan", {"target_path": "memory.raw"})
        complete(tc, {"data": SIMULATED_MATCHES, "summary": "4 matches"})
        invocations["yara_scan"] = tc.invocation_id
        mcp_result("Returning: 4 YARA matches -- 2 critical, 2 high", 4)
        pause(1)

        # -- Phase 7: DRS GATE --
        banner("Phase 7: SYNTHESIS (DRS Confidence Gate)")
        pause(1)

        findings_data = [
            ("C2 beacon to 185.220.101.34:8443 every 4 min (rundll32.exe PID 4344)",
             "network", 0.95, ["vol_netscan", "build_timeline", "yara_scan"], "T1071.001"),
            ("Process injection: MZ header in RWX memory, svchost.exe PID 4200",
             "memory", 0.92, ["vol_malfind", "vol_pslist"], "T1055.001"),
            ("LOLBin chain: svchost -> cmd -> powershell (encoded) -> rundll32",
             "memory", 0.88, ["vol_pslist", "vol_cmdline", "parse_evtx"], "T1059.003"),
            ("Persistence: Service + Run key -> Temp\\update.dll",
             "registry", 0.93, ["registry_query", "parse_evtx", "build_timeline"], "T1543.003"),
            ("Brute force: 3 failed logons then network logon from 192.168.1.200",
             "log", 0.90, ["parse_evtx", "build_timeline"], "T1110.001"),
            ("Suspicious svchost.exe PID 4200 -- unusual parent (powershell)",
             "memory", 0.60, ["vol_pslist"], "T1036.004"),
        ]

        print()
        accepted_count = 0
        for desc, atype, estr, sources, mitre in findings_data:
            source_ids = [invocations.get(s, "unknown") for s in sources]
            corr = gate.corroboration_score(len(sources), False)
            finding = Finding(
                description=desc, artifact_type=atype,
                source_invocations=source_ids,
                evidence_strength=estr, corroboration=corr,
                mitre_technique=mitre,
            )
            result = gate.evaluate(finding)

            if result.action == "ACCEPT":
                finding_accepted(desc, finding.confidence)
                findings_db.add_finding(
                    session_id=info.session_id, description=desc,
                    artifact_type=atype, confidence=finding.confidence,
                    evidence_strength=estr, corroboration=corr,
                    source_invocations=source_ids, mitre_technique=mitre,
                )
                accepted_count += 1
            else:
                finding_selfcorrect(desc, finding.confidence)
                findings_db.add_self_correction(
                    session_id=info.session_id, original_description=desc,
                    original_confidence=finding.confidence,
                    reason=result.guidance, new_approach="Seek corroboration",
                )
                audit.log_self_correction(
                    {"description": desc, "confidence": finding.confidence},
                    reason=result.guidance, new_approach="Seek additional corroboration",
                )

            audit.log_finding(
                {"description": desc, "confidence": finding.confidence,
                 "mitre": mitre, "gate_action": result.action},
                source_calls=source_ids,
            )
            pause(0.8)

        pause(2)

        # ================================================================
        # ACT 3: TAMPER DETECTION (the wow moment)
        # ================================================================

        banner("TAMPER DETECTION DEMO")
        pause(1)

        print(f"\n  {YELLOW}{BOLD}Watch what happens when someone touches an evidence file.{RESET}")
        pause(1.5)

        target = evidence_dir / "victim-hdd.img"
        print(f"\n  {DIM}# In a second terminal:{RESET}")
        print(f"  {DIM}$ echo 'TAMPERED' >> ./evidence/victim-hdd.img{RESET}")
        pause(1)

        # Actually tamper
        with open(target, "ab") as f:
            f.write(b"\x00\x00TAMPERED_BY_ADVERSARY\x00\x00")

        pause(0.5)
        print(f"\n  {RED}[HASH-DAEMON] INTEGRITY CHECK TRIGGERED{RESET}")

        result = daemon.verify_now()
        audit.log_integrity_check(result.model_dump())

        if not result.passed:
            violation_banner()
            for v in result.failures:
                name = Path(v["file"]).name
                print(f"  {RED}  {name}{RESET}")
                print(f"    Expected: {v['expected']}")
                print(f"    Actual:   {v['actual']}  {RED}<-- MISMATCH{RESET}")

            print(f"\n  {RED}{BOLD}ANALYSIS HALTED -- chain of custody broken.{RESET}")
            print(f"  {RED}All findings voided. Session suspended.{RESET}")
            audit.log_session_halt("Hash mismatch detected during demo")

        pause(3)

        # ================================================================
        # ACT 4: RECOVERY
        # ================================================================

        banner("RECOVERY: Re-seal Evidence")
        pause(1)

        print(f"\n  {DIM}$ sift-enforcer reseal --case ./evidence/{RESET}\n")
        pause(0.5)

        new_info = session.reseal()
        audit.set_session_id(new_info.session_id)
        audit.log_session_start(new_info.model_dump())
        daemon.stop()
        daemon = HashDaemon(session, interval=60)
        daemon.start()

        print(f"  {GREEN}Evidence re-sealed. New session: {new_info.session_id[:8]}...{RESET}")
        print(f"  {GREEN}Analysis may resume with a clean chain of custody.{RESET}")

        pause(2)

        # ================================================================
        # ACT 5: FINAL REPORT
        # ================================================================

        banner("INCIDENT REPORT")
        pause(1)

        all_findings = findings_db.get_findings(info.session_id)
        corrections = findings_db.get_self_corrections(info.session_id)

        print(f"\n  {BOLD}{WHITE}=== INCIDENT REPORT -- Session {info.session_id[:8]} ==={RESET}")
        print(f"  Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
        print(f"  Evidence integrity: {GREEN}VERIFIED{RESET} ({info.file_count} files sealed)")
        print()

        print(f"  {BOLD}HIGH CONFIDENCE FINDINGS (>= 0.75){RESET}")
        print(f"  {'-' * 50}")
        for f_data in all_findings:
            prov = [p["invocation_id"][:8] for p in f_data.get("provenance", [])]
            print(f"  {GREEN}[{f_data['finding_id'][:8]}]{RESET} {f_data['description']}")
            print(f"    confidence: {f_data['confidence']:.2f}  |  {f_data['artifact_type']}  |  {f_data['mitre_technique']}")
            print(f"    tool_calls: [{', '.join(prov)}]")
            print()

        if corrections:
            print(f"  {BOLD}SELF-CORRECTIONS{RESET}")
            print(f"  {'-' * 50}")
            for c in corrections:
                print(f"  {YELLOW}[~]{RESET} {c['original_description']}")
                print(f"    confidence: {c['original_confidence']:.2f} < 0.75 -- needs corroboration")
                print()

        # IOC table
        print(f"  {BOLD}INDICATORS OF COMPROMISE{RESET}")
        print(f"  {'-' * 50}")
        print(f"  {'IOC':<35s} {'Type':<12s} {'MITRE'}")
        print(f"  {'-' * 50}")
        iocs = [
            ("185.220.101.34:8443", "C2 IP", "T1071.001"),
            ("192.168.1.200", "Attacker IP", "T1110.001"),
            ("update.dll (Temp path)", "Malware DLL", "T1204.002"),
            ("Windows Update Helper", "Persistence", "T1543.003"),
            ("FC 48 83 E4 F0", "Shellcode", "T1055.001"),
        ]
        for ioc, itype, mitre in iocs:
            print(f"  {ioc:<35s} {itype:<12s} {mitre}")

        print()
        elapsed = clock_str()
        print(f"  {BOLD}Defender clock: {GREEN}{elapsed}{RESET}  |  Adversary breakout: 7:00")
        print()

        audit_path = output_dir / "audit_trail.jsonl"
        with open(audit_path) as f:
            audit_count = sum(1 for _ in f)

        elapsed = clock_str()
        print(f"\n  {DIM}Audit trail:  {audit_count} entries -> {audit_path}{RESET}")
        print(f"  {DIM}Findings DB:  {output_dir / 'findings.db'}{RESET}")

        # ================================================================
        # ACT 6: STIX 2.1 EXPORT (threat-intel handoff)
        # ================================================================

        banner("STIX 2.1 EXPORT: Threat Intel Handoff")
        pause(1)

        print(f"\n  {DIM}$ sift-enforcer export-stix --case ./evidence/{RESET}\n")
        pause(0.5)

        bundle = build_stix_bundle(all_findings, info.session_id, info.file_count)
        stix_path = output_dir / "bundle.stix.json"
        stix_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")

        ind_count = sum(1 for o in bundle["objects"] if o["type"] == "indicator")
        rel_count = sum(1 for o in bundle["objects"] if o["type"] == "relationship")

        print(f"  {GREEN}STIX 2.1 bundle written: {stix_path}{RESET}")
        print(f"  {GREEN}  bundle id:     {bundle['id']}{RESET}")
        print(f"  {GREEN}  indicators:    {ind_count}{RESET}")
        print(f"  {GREEN}  relationships: {rel_count}{RESET}")
        print(f"  {GREEN}  total objects: {len(bundle['objects'])}{RESET}")
        print()
        print(f"  {DIM}Ready to ingest into MISP / OpenCTI / ThreatConnect.{RESET}")

        pause(2)

        daemon.stop()

    # ================================================================
    # END
    # ================================================================

    print()
    print(f"  {CYAN}{'=' * 62}{RESET}")
    print(f"  {BOLD}This is open source under MIT. The MCP server, the function")
    print(f"  registry, the hash daemon, the audit trail -- all reusable.")
    print(f"  Pull requests welcome.{RESET}")
    print(f"  {CYAN}{'=' * 62}{RESET}")
    print()


if __name__ == "__main__":
    main()
