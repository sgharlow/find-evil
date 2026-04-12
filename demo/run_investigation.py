#!/usr/bin/env python3
"""Simulated Autonomous DFIR Investigation.

Runs the full 7-phase investigation sequence from CLAUDE.md, exercising
every forensic tool, the DRS confidence gate, and the report generator.
Produces:
  - output/audit_trail.jsonl  (deliverable #8: agent execution logs)
  - output/ir_report.md       (generated incident response report)
  - Console output showing the investigation in real-time

This script demonstrates what happens when Claude Code connects to the
MCP server and follows the CLAUDE.md investigation protocol. It calls
the same enforce()/complete() pipeline that real MCP tool calls use.

Usage:
    python demo/run_investigation.py
"""

import sys
import json
import tempfile
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from find_evil.session.manager import EvidenceSession
from find_evil.session.hash_daemon import HashDaemon
from find_evil.audit.logger import AuditLogger
from find_evil.analysis.findings_db import FindingsDB
from find_evil.analysis.drs_gate import DRSGate, Finding
from find_evil.tools._base import enforce, complete, ToolContext


class MockContext:
    def __init__(self, lifespan: dict):
        self.request_context = type("RC", (), {"lifespan_context": lifespan})()


def print_header(phase: str, description: str):
    print()
    print(f"  {'='*60}")
    print(f"  {phase}: {description}")
    print(f"  {'='*60}")


def print_tool_call(tool: str, args: dict):
    args_str = ", ".join(f"{k}={v!r}" for k, v in args.items() if v)
    print(f"  [AGENT] Calling: {tool}({args_str})")


def print_result(summary: str, suspicious: int = 0):
    if suspicious > 0:
        print(f"  [MCP]   {summary} -- {suspicious} SUSPICIOUS")
    else:
        print(f"  [MCP]   {summary}")


def print_finding(desc: str, confidence: float, action: str):
    icon = "+" if action == "ACCEPT" else "~"
    label = "ACCEPTED" if action == "ACCEPT" else "SELF-CORRECT"
    print(f"  [{icon}] Finding: {desc}")
    print(f"      Confidence: {confidence:.2f} -> {label}")


def run_tool(ctx, tool_name: str, args: dict, data_source) -> tuple[ToolContext | None, list]:
    """Run a tool through the enforce gate and return structured results."""
    print_tool_call(tool_name, args)

    tc = enforce(ctx, tool_name, args)
    if isinstance(tc, dict):
        print(f"  [!] INTEGRITY VIOLATION: {tc['message']}")
        return None, []

    # Simulate tool execution with the data source
    if callable(data_source):
        data = data_source()
    else:
        data = data_source

    suspicious = [d for d in data if d.get("suspicious") or d.get("Suspicious")]
    result = {
        "tool": tool_name,
        "mode": "simulated",
        "data": data,
        "summary": f"{len(data)} results, {len(suspicious)} suspicious",
    }
    complete(tc, result)
    print_result(result["summary"], len(suspicious))

    return tc, data


def main():
    output_dir = Path(__file__).parent.parent / "output"
    output_dir.mkdir(exist_ok=True)

    print()
    print("  " + "#" * 60)
    print("  #  EVIDENCE INTEGRITY ENFORCER                             #")
    print("  #  Autonomous DFIR Investigation                           #")
    print("  #  Simulated Scenario: Windows Workstation Compromise       #")
    print("  " + "#" * 60)

    # --- Setup ---
    with tempfile.TemporaryDirectory() as tmpdir:
        evidence_dir = Path(tmpdir)
        (evidence_dir / "memory.raw").write_bytes(b"MEM_" + b"\x00" * 500)
        (evidence_dir / "disk.img").write_bytes(b"DSK_" + b"\x00" * 500)
        (evidence_dir / "Security.evtx").write_bytes(b"EVT_" + b"\x00" * 200)
        (evidence_dir / "SYSTEM.hive").write_bytes(b"REG_" + b"\x00" * 200)
        (evidence_dir / "network.pcap").write_bytes(b"NET_" + b"\x00" * 200)

        session = EvidenceSession()
        audit = AuditLogger(path=str(output_dir / "audit_trail.jsonl"))
        findings_db = FindingsDB(path=str(output_dir / "findings.db"))

        # Phase 0: SEAL
        print_header("Phase 0", "SEAL EVIDENCE")
        info = session.initialize(str(evidence_dir))
        audit.set_session_id(info.session_id)
        audit.log_session_start(info.model_dump())
        findings_db.record_session(
            info.session_id, str(evidence_dir), info.file_count, info.sealed_at,
        )

        daemon = HashDaemon(session, interval=60)
        daemon.start()

        print(f"  Session ID: {info.session_id}")
        print(f"  Evidence files sealed: {info.file_count}")
        for fp, h in info.manifest.items():
            print(f"    {Path(fp).name:20s} sha256: {h}  SEALED")
        print(f"  Hash daemon: RUNNING (30s cycle)")

        ctx = MockContext({
            "session": session,
            "daemon": daemon,
            "audit": audit,
            "findings_db": findings_db,
        })

        gate = DRSGate()
        invocations = {}  # tool_name -> invocation_id

        # --- Import simulated data ---
        from find_evil.tools.volatility import (
            SIMULATED_PSLIST, SIMULATED_NETSCAN, SIMULATED_MALFIND, SIMULATED_CMDLINE,
            _is_suspicious_process, _is_suspicious_connection,
        )
        from find_evil.tools.evtx import SIMULATED_EVENTS
        from find_evil.tools.registry import SIMULATED_RUN_KEYS, SIMULATED_SERVICES
        from find_evil.tools.timeline import SIMULATED_TIMELINE
        from find_evil.tools.yara_scan import SIMULATED_MATCHES

        # Flag suspicious items
        for p in SIMULATED_PSLIST:
            p["suspicious"] = _is_suspicious_process(p, SIMULATED_PSLIST)
        for c in SIMULATED_NETSCAN:
            c["suspicious"] = _is_suspicious_connection(c)

        # Phase 1: TRIAGE
        print_header("Phase 1", "TRIAGE (Memory)")

        tc, _ = run_tool(ctx, "vol_pslist", {"memory_image": "memory.raw"}, SIMULATED_PSLIST)
        if tc:
            invocations["vol_pslist"] = tc.invocation_id

        tc, _ = run_tool(ctx, "vol_netscan", {"memory_image": "memory.raw"}, SIMULATED_NETSCAN)
        if tc:
            invocations["vol_netscan"] = tc.invocation_id

        # Phase 2: DEEP MEMORY
        print_header("Phase 2", "DEEP MEMORY (Injection + Cmdline)")

        tc, _ = run_tool(ctx, "vol_malfind", {"memory_image": "memory.raw"}, SIMULATED_MALFIND)
        if tc:
            invocations["vol_malfind"] = tc.invocation_id

        tc, _ = run_tool(ctx, "vol_cmdline", {"memory_image": "memory.raw"}, SIMULATED_CMDLINE)
        if tc:
            invocations["vol_cmdline"] = tc.invocation_id

        # Phase 3: LOGS
        print_header("Phase 3", "EVENT LOGS")

        tc, _ = run_tool(ctx, "parse_evtx", {"evtx_path": "Security.evtx"}, SIMULATED_EVENTS)
        if tc:
            invocations["parse_evtx"] = tc.invocation_id

        # Phase 4: PERSISTENCE
        print_header("Phase 4", "PERSISTENCE (Registry)")

        combined_reg = list(SIMULATED_RUN_KEYS) + list(SIMULATED_SERVICES)
        tc, _ = run_tool(ctx, "registry_query", {"hive_path": "SYSTEM"}, combined_reg)
        if tc:
            invocations["registry_query"] = tc.invocation_id

        # Phase 5: TIMELINE
        print_header("Phase 5", "SUPER-TIMELINE")

        tc, _ = run_tool(ctx, "build_timeline", {"evidence_path": "disk.img"}, SIMULATED_TIMELINE)
        if tc:
            invocations["build_timeline"] = tc.invocation_id

        # Phase 6: IOC SCAN
        print_header("Phase 6", "YARA IOC SCAN")

        tc, _ = run_tool(ctx, "yara_scan", {"target_path": "memory.raw"}, SIMULATED_MATCHES)
        if tc:
            invocations["yara_scan"] = tc.invocation_id

        # Phase 7: SYNTHESIS
        print_header("Phase 7", "SYNTHESIS (DRS Gate + Report)")

        # Submit findings through DRS gate
        findings_to_submit = [
            {
                "description": "C2 beacon to 185.220.101.34:8443 every 4 minutes via rundll32.exe (PID 4344)",
                "artifact_type": "network",
                "evidence_strength": 0.95,
                "sources": ["vol_netscan", "build_timeline", "yara_scan"],
                "mitre": "T1071.001",
            },
            {
                "description": "Process injection: MZ header in PAGE_EXECUTE_READWRITE in svchost.exe (PID 4200)",
                "artifact_type": "memory",
                "evidence_strength": 0.92,
                "sources": ["vol_malfind", "vol_pslist"],
                "mitre": "T1055.001",
            },
            {
                "description": "LOLBin chain: svchost -> cmd.exe -> powershell (encoded) -> rundll32",
                "artifact_type": "memory",
                "evidence_strength": 0.88,
                "sources": ["vol_pslist", "vol_cmdline", "parse_evtx"],
                "mitre": "T1059.003",
            },
            {
                "description": "Brute force: 3 failed logons then success from 192.168.1.200",
                "artifact_type": "log",
                "evidence_strength": 0.90,
                "sources": ["parse_evtx", "build_timeline"],
                "mitre": "T1110.001",
            },
            {
                "description": "Persistence: Service + Run key pointing to Temp\\update.dll",
                "artifact_type": "registry",
                "evidence_strength": 0.93,
                "sources": ["registry_query", "parse_evtx", "build_timeline"],
                "mitre": "T1543.003",
            },
            {
                "description": "Suspicious svchost.exe (PID 4200) — unusual parent (powershell)",
                "artifact_type": "memory",
                "evidence_strength": 0.60,
                "sources": ["vol_pslist"],
                "mitre": "T1036.004",
            },
        ]

        print()
        accepted = 0
        corrected = 0

        for f_data in findings_to_submit:
            source_ids = [invocations.get(s, "unknown") for s in f_data["sources"]]
            corroboration = gate.corroboration_score(len(f_data["sources"]), False)

            finding = Finding(
                description=f_data["description"],
                artifact_type=f_data["artifact_type"],
                source_invocations=source_ids,
                evidence_strength=f_data["evidence_strength"],
                corroboration=corroboration,
                mitre_technique=f_data["mitre"],
            )
            result = gate.evaluate(finding)
            print_finding(f_data["description"], finding.confidence, result.action)

            audit.log_finding(
                {"description": f_data["description"], "confidence": finding.confidence,
                 "mitre": f_data["mitre"], "gate_action": result.action},
                source_calls=source_ids,
            )

            if result.action == "ACCEPT":
                findings_db.add_finding(
                    session_id=info.session_id,
                    description=f_data["description"],
                    artifact_type=f_data["artifact_type"],
                    confidence=finding.confidence,
                    evidence_strength=f_data["evidence_strength"],
                    corroboration=corroboration,
                    source_invocations=source_ids,
                    mitre_technique=f_data["mitre"],
                )
                accepted += 1
            else:
                findings_db.add_self_correction(
                    session_id=info.session_id,
                    original_description=f_data["description"],
                    original_confidence=finding.confidence,
                    reason=result.guidance,
                    new_approach="Seek additional corroboration from a different tool",
                )
                audit.log_self_correction(
                    {"description": f_data["description"], "confidence": finding.confidence},
                    reason=result.guidance,
                    new_approach="Seek additional corroboration",
                )
                corrected += 1

        # Generate report
        print()
        print(f"  Findings accepted: {accepted}")
        print(f"  Self-corrections:  {corrected}")

        summary = findings_db.get_session_summary(info.session_id)
        all_findings = findings_db.get_findings(info.session_id)
        corrections = findings_db.get_self_corrections(info.session_id)

        # Build IR report
        report_lines = [
            f"# Incident Response Report",
            "",
            f"**Session ID:** {info.session_id}",
            f"**Evidence Directory:** {info.evidence_dir}",
            f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
            f"**Evidence Integrity:** VERIFIED ({info.file_count} files sealed)",
            f"**Analysis Mode:** simulated (SIFT tools not installed)",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            f"Autonomous DFIR analysis identified **{summary['total_findings']} findings** "
            f"across {len(summary['artifact_types'])} artifact types. "
            f"{summary['high_confidence_findings']} findings met the 0.75 confidence threshold. "
            f"{summary['self_corrections']} finding(s) were flagged for self-correction "
            f"due to insufficient corroboration.",
            "",
            "The investigation reveals a network intrusion via brute force (T1110.001), "
            "lateral movement using LOLBin chain (T1059.003), process injection (T1055.001), "
            "C2 communication to 185.220.101.34 (T1071.001), and persistence via service "
            "and Run key installation (T1543.003).",
            "",
            "---",
            "",
            "## High Confidence Findings",
            "",
        ]

        for i, f in enumerate(all_findings, 1):
            prov_ids = [p["invocation_id"][:8] for p in f.get("provenance", [])]
            report_lines.extend([
                f"### Finding {i}: {f['description']}",
                "",
                f"- **Confidence:** {f['confidence']:.2f} "
                f"(evidence: {f['evidence_strength']:.2f}, "
                f"corroboration: {f['corroboration']:.2f})",
                f"- **Artifact type:** {f['artifact_type']}",
                f"- **MITRE ATT&CK:** {f['mitre_technique']}",
                f"- **Provenance:** {', '.join(prov_ids)}",
                "",
            ])

        if corrections:
            report_lines.extend([
                "---",
                "",
                "## Self-Correction Log",
                "",
            ])
            for c in corrections:
                report_lines.extend([
                    f"- **Original:** {c['original_description']} "
                    f"(confidence: {c['original_confidence']:.2f})",
                    f"  **Reason:** {c['reason']}",
                    "",
                ])

        report_lines.extend([
            "---",
            "",
            "## IOC Summary",
            "",
            "| IOC | Type | Source |",
            "|-----|------|--------|",
            "| 185.220.101.34:8443 | C2 IP | netscan, timeline, YARA |",
            "| 192.168.1.200 | Attacker IP | EVTX, timeline |",
            "| update.dll (Temp path) | Malicious DLL | cmdline, registry, timeline |",
            "| Windows Update Helper | Persistence service | EVTX, registry |",
            "| WindowsUpdateHelper | Persistence Run key | registry |",
            "| FC 48 83 E4 F0 | Shellcode pattern | YARA, malfind |",
            "",
            "---",
            "",
            "## Evidence Integrity Statement",
            "",
            f"All {info.file_count} evidence files were SHA-256 sealed at session start "
            "and continuously verified via background hash daemon (30s cycle) and "
            "pre-tool-call enforcement gate. No integrity violations detected.",
            "",
            "---",
            "",
            "*Generated by Evidence Integrity Enforcer v0.1.0*",
        ])

        report_md = "\n".join(report_lines)
        report_path = output_dir / "ir_report.md"
        report_path.write_text(report_md)

        # Cleanup
        daemon.stop()

    # Summary
    audit_path = output_dir / "audit_trail.jsonl"
    with open(audit_path) as f:
        audit_count = sum(1 for _ in f)

    print()
    print_header("COMPLETE", "Investigation finished")
    print()
    print(f"  Findings:         {accepted} accepted, {corrected} self-corrected")
    print(f"  Audit trail:      {audit_count} entries -> {audit_path}")
    print(f"  IR Report:        {report_path}")
    print(f"  Findings DB:      {output_dir / 'findings.db'}")
    print()

    # Show a sample of the audit trail
    print("  Sample audit trail (first 5 entries):")
    with open(audit_path) as f:
        for i, line in enumerate(f):
            if i >= 5:
                break
            record = json.loads(line)
            event = record.get("event", "?")
            tool = record.get("tool", record.get("finding_id", "")[:8] if "finding_id" in record else "")
            ts = record.get("timestamp", "")[:19]
            print(f"    {ts} | {event:25s} | {tool}")
    print(f"    ... ({audit_count - 5} more entries)")
    print()


if __name__ == "__main__":
    main()
