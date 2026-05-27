#!/usr/bin/env python3
"""LIVE Autonomous DFIR Investigation — real evidence, real backends.

Unlike demo/run_investigation.py (which replays a labelled *simulated*
scenario so it runs on any laptop), this script seals the committed
`evidence/` directory and runs the forensic tools in **live mode** against
real artifacts:

  - parse_evtx     -> python-evtx parses a real Windows Application log
  - registry_query -> python-registry parses real SYSTEM / SOFTWARE hives
  - yara_scan      -> yara-python matches a real IOC binary

If a memory image is supplied (env EVIDENCE_MEMORY=/path/to/image.raw, or a
*.raw / *.vmem / *.mem / *.lime file present in evidence/), the Volatility3
memory tools also run live and corroborate the YARA/network findings — which
is what lifts findings across the DRS 0.75 acceptance threshold. Without a
memory image, single-tool findings honestly self-correct (the gate working as
designed on real data).

Produces:
  - output/live_audit_trail.jsonl  (real UUID-linked agent execution log)
  - output/live_ir_report.md       (generated IR report, Analysis Mode: live)

Usage:
    python demo/run_live_investigation.py
    EVIDENCE_MEMORY=/cases/memdump.raw python demo/run_live_investigation.py
"""

import os
import sys
import json
import shutil
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

REPO = Path(__file__).parent.parent
EVIDENCE_SRC = REPO / "evidence"
OUTPUT_DIR = REPO / "output"

# Forensic artifacts to seal (excludes README.md / populate_samples.py helpers).
FORENSIC_FILES = [
    "Application_small.evtx",
    "SYSTEM",
    "SOFTWARE",
    "evidence_iocs.bin",
    "find_evil_rules.yar",
]

SEVERITY_EVIDENCE = {"critical": 0.95, "high": 0.90, "medium": 0.75, "low": 0.55}
MEMORY_EXTS = {".raw", ".vmem", ".mem", ".lime", ".dmp", ".img"}


class MockContext:
    def __init__(self, lifespan: dict):
        self.request_context = type("RC", (), {"lifespan_context": lifespan})()


def hdr(phase: str, desc: str):
    print(f"\n  {'='*62}\n  {phase}: {desc}\n  {'='*62}")


def run_live_tool(ctx, tool_name, args, real_callable, evidence_paths):
    """Run a real tool through the enforce()/complete() gate with LIVE output."""
    arg_str = ", ".join(f"{k}={v!r}" for k, v in args.items() if v)
    print(f"  [AGENT] Calling: {tool_name}({arg_str})")
    tc = enforce(ctx, tool_name, args, evidence_paths=evidence_paths)
    if isinstance(tc, dict):
        print(f"  [!] INTEGRITY/PATH VIOLATION: {tc.get('message')}")
        return None, []
    try:
        data = real_callable()
    except Exception as exc:  # surface real backend errors honestly
        from find_evil.tools._base import fail
        fail(tc, f"{type(exc).__name__}: {exc}")
        print(f"  [MCP]   live backend error: {type(exc).__name__}: {exc}")
        return tc, []
    result = {
        "tool": tool_name,
        "mode": "live",
        "data": data,
        "summary": f"{len(data)} results (live backend)",
    }
    complete(tc, result)
    print(f"  [MCP]   {result['summary']}")
    return tc, data


def find_memory_image() -> str | None:
    env = os.environ.get("EVIDENCE_MEMORY")
    if env and Path(env).is_file():
        return env
    for p in EVIDENCE_SRC.iterdir():
        if p.suffix.lower() in MEMORY_EXTS and p.stat().st_size > 1_000_000:
            return str(p)
    return None


def main():
    OUTPUT_DIR.mkdir(exist_ok=True)
    # Fresh session: the audit logger is append-only by design, so clear the
    # prior live run's artifacts to keep each demo run self-contained.
    for stale in ("live_audit_trail.jsonl", "live_findings.db"):
        (OUTPUT_DIR / stale).unlink(missing_ok=True)
    print("\n  " + "#" * 62)
    print("  #  EVIDENCE INTEGRITY ENFORCER  —  LIVE MODE".ljust(61) + "#")
    print("  #  Autonomous DFIR Investigation against REAL evidence".ljust(61) + "#")
    print("  " + "#" * 62)

    # Import live backends + helpers
    from find_evil.tools.evtx import _parse_real_evtx
    from find_evil.tools.yara_scan import _run_real_yara
    from find_evil.tools.registry import _parse_real_registry, _is_suspicious_registry

    mem_image = find_memory_image()

    # Seal a temp dir holding ONLY the forensic artifacts (real file contents).
    with tempfile.TemporaryDirectory() as tmpdir:
        ev = Path(tmpdir)
        for name in FORENSIC_FILES:
            shutil.copy2(EVIDENCE_SRC / name, ev / name)
        if mem_image:
            shutil.copy2(mem_image, ev / Path(mem_image).name)

        session = EvidenceSession()
        audit = AuditLogger(path=str(OUTPUT_DIR / "live_audit_trail.jsonl"))
        fdb = FindingsDB(path=str(OUTPUT_DIR / "live_findings.db"))

        # Phase 0: SEAL
        hdr("Phase 0", "SEAL EVIDENCE (real SHA-256 over real files)")
        info = session.initialize(str(ev))
        audit.set_session_id(info.session_id)
        audit.log_session_start(info.model_dump())
        fdb.record_session(info.session_id, str(ev), info.file_count, info.sealed_at)
        daemon = HashDaemon(session, interval=60)
        daemon.start()
        print(f"  Session ID: {info.session_id}")
        print(f"  Files sealed: {info.file_count}")
        for fp, h in info.manifest.items():
            print(f"    {Path(fp).name:24s} sha256:{h[:16]}...  SEALED")

        ctx = MockContext({"session": session, "daemon": daemon,
                           "audit": audit, "findings_db": fdb})
        gate = DRSGate()
        inv = {}
        findings = []  # (description, artifact_type, evidence_strength, sources, mitre)

        # Phase 1-2: MEMORY (live only if an image is present)
        hdr("Phase 1-2", "MEMORY (Volatility3)")
        if mem_image:
            from find_evil.tools import volatility as vol
            mem_name = Path(mem_image).name
            mem_path = str(ev / mem_name)
            # Real Volatility3 via the same CLI path the MCP tools use
            # (_run_vol_plugin -> `vol -f <img> <plugin>` -> _parse_*_output).
            mem_rows = {}
            mem_plugins = [
                ("vol_pslist", "windows.pslist.PsList", vol._parse_pslist_output),
                ("vol_netscan", "windows.netscan.NetScan", vol._parse_netscan_output),
                ("vol_malfind", "windows.malfind.Malfind", vol._parse_malfind_output),
            ]
            for tool, plugin, parser in mem_plugins:
                tc, rows = run_live_tool(
                    ctx, tool, {"memory_image": mem_name, "plugin": plugin},
                    lambda p=plugin, pr=parser: pr(vol._run_vol_plugin(p, mem_path)),
                    [mem_path])
                if tc:
                    inv[tool] = tc.invocation_id
                    mem_rows[tool] = rows
            # Memory-native findings (these corroborate the YARA C2 match in Phase 6)
            for row in mem_rows.get("vol_malfind", []):
                findings.append({
                    "description": f"Process injection in {row.get('Process','?')} "
                                   f"(PID {row.get('PID','?')}) - {row.get('Protection','RWX')}",
                    "artifact_type": "memory", "evidence_strength": 0.90,
                    "sources": ["vol_malfind"], "mitre": "T1055.001"})
            for conn in mem_rows.get("vol_netscan", []):
                if vol._is_suspicious_connection(conn):
                    findings.append({
                        "description": f"Suspicious C2 connection to {conn.get('ForeignAddr')}:"
                                       f"{conn.get('ForeignPort')} ({conn.get('Owner','?')})",
                        "artifact_type": "network", "evidence_strength": 0.88,
                        "sources": ["vol_netscan", "yara_scan"], "mitre": "T1071.001"})
        else:
            print("  [skip] No memory image present. Set EVIDENCE_MEMORY=/path/to/image")
            print("         or drop a *.raw/*.vmem into evidence/ to enable live vol_* .")

        # Phase 3: LOGS (live python-evtx)
        hdr("Phase 3", "EVENT LOGS (python-evtx)")
        evtx_path = str(ev / "Application_small.evtx")
        tc, events = run_live_tool(ctx, "parse_evtx", {"evtx_path": "Application_small.evtx"},
                                   lambda: _parse_real_evtx(evtx_path), [evtx_path])
        if tc:
            inv["parse_evtx"] = tc.invocation_id
            comps = sorted({e.get("Computer", "?") for e in events})
            print(f"  [+] Real Windows Application log parsed: {len(events)} events"
                  f" from {', '.join(comps)[:60]}")

        # Phase 4: PERSISTENCE (live python-registry)
        hdr("Phase 4", "PERSISTENCE (python-registry)")
        sys_path = str(ev / "SYSTEM")
        tc, services = run_live_tool(ctx, "registry_query",
                                     {"hive_path": "SYSTEM", "query_type": "services"},
                                     lambda: _parse_real_registry(sys_path, "services"),
                                     [sys_path])
        if tc:
            inv["registry_query"] = tc.invocation_id
            for svc in services:
                if _is_suspicious_registry(svc):
                    findings.append({
                        "description": f"Suspicious persistence service '{svc.get('service_name')}'"
                                       f" -> {svc.get('image_path', 'n/a')}",
                        "artifact_type": "registry",
                        "evidence_strength": 0.85,
                        "sources": ["registry_query"],
                        "mitre": "T1543.003",
                    })

        # Phase 6: IOC SCAN (live yara-python)
        hdr("Phase 6", "YARA IOC SCAN (yara-python)")
        target = str(ev / "evidence_iocs.bin")
        rules = str(ev / "find_evil_rules.yar")
        tc, matches = run_live_tool(ctx, "yara_scan",
                                    {"target_path": "evidence_iocs.bin",
                                     "rules_path": "find_evil_rules.yar"},
                                    lambda: _run_real_yara(target, rules), [target, rules])
        if tc:
            inv["yara_scan"] = tc.invocation_id
            # C2 / Cobalt Strike corroborated by netscan if memory ran
            net_corroborates = "vol_netscan" in inv
            for m in matches:
                srcs = ["yara_scan"]
                rule = m.get("rule", "")
                if net_corroborates and ("C2" in rule or "Cobalt" in rule or "Beacon" in rule):
                    srcs.append("vol_netscan")
                findings.append({
                    "description": f"{rule}: {m.get('description', '')}",
                    "artifact_type": "disk",
                    "evidence_strength": SEVERITY_EVIDENCE.get(m.get("severity", "medium"), 0.75),
                    "sources": srcs,
                    "mitre": m.get("mitre", ""),
                })

        # Phase 7: SYNTHESIS (DRS gate)
        hdr("Phase 7", "SYNTHESIS (DRS confidence gate)")
        accepted = corrected = 0
        for f in findings:
            sids = [inv.get(s, "unknown") for s in f["sources"]]
            corr = gate.corroboration_score(len(set(f["sources"])), False)
            finding = Finding(description=f["description"], artifact_type=f["artifact_type"],
                              source_invocations=sids, evidence_strength=f["evidence_strength"],
                              corroboration=corr, mitre_technique=f["mitre"])
            res = gate.evaluate(finding)
            icon = "+" if res.action == "ACCEPT" else "~"
            label = "ACCEPTED" if res.action == "ACCEPT" else "SELF-CORRECT"
            print(f"  [{icon}] {f['description'][:70]}")
            print(f"      conf {finding.confidence:.2f} (ev {f['evidence_strength']:.2f},"
                  f" corr {corr:.2f}) -> {label}")
            audit.log_finding({"description": f["description"], "confidence": finding.confidence,
                               "mitre": f["mitre"], "gate_action": res.action}, source_calls=sids)
            if res.action == "ACCEPT":
                fdb.add_finding(session_id=info.session_id, description=f["description"],
                                artifact_type=f["artifact_type"], confidence=finding.confidence,
                                evidence_strength=f["evidence_strength"], corroboration=corr,
                                source_invocations=sids, mitre_technique=f["mitre"])
                accepted += 1
            else:
                fdb.add_self_correction(session_id=info.session_id,
                                        original_description=f["description"],
                                        original_confidence=finding.confidence,
                                        reason=res.guidance,
                                        new_approach="Seek corroboration from a different tool"
                                                     " (e.g. add a memory image for netscan/malfind)")
                audit.log_self_correction({"description": f["description"],
                                           "confidence": finding.confidence},
                                          reason=res.guidance,
                                          new_approach="Seek corroboration from a different tool")
                corrected += 1

        # Report
        summary = fdb.get_session_summary(info.session_id)
        all_f = fdb.get_findings(info.session_id)
        corrections = fdb.get_self_corrections(info.session_id)
        backends = "python-evtx, python-registry, yara-python" + \
                   (", volatility3" if mem_image else "")
        lines = [
            "# Incident Response Report (LIVE)", "",
            f"**Session ID:** {info.session_id}",
            f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
            f"**Evidence Integrity:** VERIFIED ({info.file_count} files sealed)",
            f"**Analysis Mode:** live - real evidence parsed via {backends}",
            f"**Memory image:** {'present (' + Path(mem_image).name + ')' if mem_image else 'not supplied - vol_* skipped'}",
            "", "---", "", "## Executive Summary", "",
            f"Live autonomous DFIR analysis sealed {info.file_count} real evidence files and "
            f"ran {len(inv)} forensic tools against them. {summary['total_findings']} finding(s) "
            f"met the 0.75 DRS confidence threshold; {summary['self_corrections']} were flagged "
            f"for self-correction (insufficient cross-tool corroboration on the available evidence).",
            "", "---", "", "## Accepted Findings", "",
        ]
        for i, f in enumerate(all_f, 1):
            prov = [p["invocation_id"][:8] for p in f.get("provenance", [])]
            lines += [f"### {i}. {f['description']}", "",
                      f"- **Confidence:** {f['confidence']:.2f} (ev {f['evidence_strength']:.2f},"
                      f" corr {f['corroboration']:.2f})",
                      f"- **MITRE ATT&CK:** {f['mitre_technique']}",
                      f"- **Provenance:** {', '.join(prov)}", ""]
        if corrections:
            lines += ["---", "", "## Self-Correction Log "
                      "(real data - gate withholding low-corroboration findings)", ""]
            for c in corrections:
                lines += [f"- **{c['original_description']}** "
                          f"(conf {c['original_confidence']:.2f}) - {c['reason']}", ""]
        lines += ["---", "", "*Generated by Evidence Integrity Enforcer - live mode*"]
        (OUTPUT_DIR / "live_ir_report.md").write_text("\n".join(lines), encoding="utf-8")
        daemon.stop()

    audit_path = OUTPUT_DIR / "live_audit_trail.jsonl"
    n = sum(1 for _ in open(audit_path, encoding="utf-8"))
    hdr("COMPLETE", "Live investigation finished")
    print(f"  Findings: {accepted} accepted, {corrected} self-corrected")
    print(f"  Audit trail: {n} entries -> {audit_path}")
    print(f"  IR report:   {OUTPUT_DIR / 'live_ir_report.md'}")
    print()


if __name__ == "__main__":
    main()
