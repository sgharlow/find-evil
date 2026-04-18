"""Finding submission and report generation tools.

These tools close the analysis loop:
- submit_finding: Agent records a scored finding with provenance
- generate_report: Agent produces a structured IR report from all findings

Both tools go through the integrity gate — if evidence is tampered
mid-reporting, the report is halted.
"""

from __future__ import annotations

import json
import logging
import re
import uuid as uuid_mod
from datetime import datetime, timezone

from mcp.server.fastmcp import Context

from find_evil.server import mcp
from find_evil.tools._base import ToolContext, enforce, complete, fail, get_lifespan
from find_evil.analysis.drs_gate import DRSGate, Finding
from find_evil.analysis.findings_db import FindingsDB

logger = logging.getLogger("find_evil.tools.findings")

_gate = DRSGate()

# IOC extraction patterns
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_HASH_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:\\[\w\\. -]+\.\w{2,4}")
_REGISTRY_KEY_RE = re.compile(r"(?:HKLM|HKCU|HKU|HKCR|HKCC)\\[\w\\. -]+")

# Common private/internal IPs to exclude from IOC list
_PRIVATE_IP_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                        "172.30.", "172.31.", "192.168.", "127.", "0.")


def _extract_iocs(findings: list[dict]) -> dict[str, set[str]]:
    """Extract IOCs from finding descriptions."""
    iocs: dict[str, set[str]] = {
        "ipv4": set(),
        "md5": set(),
        "sha256": set(),
        "file_path": set(),
        "registry_key": set(),
    }
    for f in findings:
        text = f["description"]
        for ip in _IPV4_RE.findall(text):
            if not ip.startswith(_PRIVATE_IP_PREFIXES):
                iocs["ipv4"].add(ip)
        iocs["md5"].update(_HASH_MD5_RE.findall(text))
        iocs["sha256"].update(_HASH_SHA256_RE.findall(text))
        iocs["file_path"].update(_WINDOWS_PATH_RE.findall(text))
        iocs["registry_key"].update(_REGISTRY_KEY_RE.findall(text))
    # Filter out SHA-256 hashes that were misclassified as MD5 (first 32 chars)
    iocs["md5"] -= {h[:32] for h in iocs["sha256"]}
    return iocs


def _get_findings_db(ctx: Context) -> FindingsDB:
    """Get or create FindingsDB from lifespan context."""
    lifespan = get_lifespan(ctx)
    if "findings_db" not in lifespan:
        lifespan["findings_db"] = FindingsDB()
    return lifespan["findings_db"]


@mcp.tool()
async def submit_finding(
    description: str,
    artifact_type: str,
    evidence_strength: float,
    source_invocations: str,
    ctx: Context,
    corroboration: float | None = None,
    corroboration_sources: int = 1,
    mitre_technique: str = "",
    action_required: bool = False,
) -> dict:
    """Submit a DFIR finding with confidence scoring through the DRS gate.

    Every finding is scored on evidence strength and corroboration.
    Findings below the 0.75 confidence threshold are flagged for
    self-correction — seek additional corroborating evidence.

    Args:
        description: Specific observable fact (not interpretation).
        artifact_type: One of: memory, disk, registry, network, log.
        evidence_strength: 0.0-1.0. Is the finding directly observed in tool output?
        source_invocations: Comma-separated invocation UUIDs that produced this finding.
        corroboration: 0.0-1.0 override. If omitted, auto-calculated from source count.
        corroboration_sources: Number of independent tool sources (used if corroboration is omitted).
        mitre_technique: MITRE ATT&CK technique ID (e.g., T1059.003).
        action_required: Does the analyst need to investigate further?
    """
    tc = enforce(ctx, "submit_finding", {
        "description": description,
        "artifact_type": artifact_type,
        "evidence_strength": evidence_strength,
    })
    if isinstance(tc, dict):
        return tc

    try:
        invocation_ids = [s.strip() for s in source_invocations.split(",") if s.strip()]

        # Calculate corroboration if not provided
        if corroboration is None:
            corroboration = DRSGate.corroboration_score(
                corroboration_sources, has_contradiction=False,
            )

        finding = Finding(
            description=description,
            artifact_type=artifact_type,
            source_invocations=invocation_ids,
            evidence_strength=evidence_strength,
            corroboration=corroboration,
            mitre_technique=mitre_technique,
            action_required=action_required,
        )

        gate_result = _gate.evaluate(finding)

        # Log to audit trail
        tc.audit.log_finding(
            {
                "description": description,
                "artifact_type": artifact_type,
                "confidence": finding.confidence,
                "evidence_strength": evidence_strength,
                "corroboration": corroboration,
                "mitre_technique": mitre_technique,
                "gate_action": gate_result.action,
            },
            source_calls=invocation_ids,
        )

        # Persist to findings DB
        db = _get_findings_db(ctx)
        session = get_lifespan(ctx)["session"]

        if session.session_id:
            if gate_result.action == "SELF_CORRECT":
                db.add_self_correction(
                    session_id=session.session_id,
                    original_description=description,
                    original_confidence=finding.confidence,
                    reason=gate_result.guidance,
                    new_approach="Agent should seek additional corroboration",
                )
                tc.audit.log_self_correction(
                    {"description": description, "confidence": finding.confidence},
                    reason=gate_result.guidance,
                    new_approach="Seek additional corroboration from a different tool",
                )
            else:
                db.add_finding(
                    session_id=session.session_id,
                    description=description,
                    artifact_type=artifact_type,
                    confidence=finding.confidence,
                    evidence_strength=evidence_strength,
                    corroboration=corroboration,
                    source_invocations=invocation_ids,
                    mitre_technique=mitre_technique,
                    action_required=action_required,
                )

        result = {
            "tool": "submit_finding",
            "gate_action": gate_result.action,
            "confidence": round(finding.confidence, 3),
            "evidence_strength": evidence_strength,
            "corroboration": corroboration,
            "threshold": _gate.threshold,
            "guidance": gate_result.guidance,
            "finding_accepted": gate_result.action == "ACCEPT",
            "summary": (
                f"Finding {'ACCEPTED' if gate_result.action == 'ACCEPT' else 'NEEDS CORROBORATION'} "
                f"(confidence: {finding.confidence:.2f})"
            ),
        }

        return complete(tc, result)

    except Exception as e:
        fail(tc, str(e))
        raise


@mcp.tool()
async def generate_report(ctx: Context, title: str = "Incident Response Report") -> dict:
    """Generate a structured incident response report from all accepted findings.

    Produces a Markdown report containing:
    - Executive summary with finding counts and confidence levels
    - Timeline of events correlated from all findings
    - Detailed findings with provenance (linked to tool invocation UUIDs)
    - IOC table (IPs, hashes, file paths, registry keys)
    - Self-correction log (demonstrates autonomous quality)
    - Recommendations

    Args:
        title: Report title (default: "Incident Response Report").
    """
    tc = enforce(ctx, "generate_report", {"title": title})
    if isinstance(tc, dict):
        return tc

    try:
        session = get_lifespan(ctx)["session"]
        db = _get_findings_db(ctx)

        if not session.session_id:
            return complete(tc, {
                "tool": "generate_report",
                "error": "No active session",
                "summary": "Cannot generate report — no evidence session active.",
            })

        findings = db.get_findings(session.session_id)
        corrections = db.get_self_corrections(session.session_id)
        summary_data = db.get_session_summary(session.session_id)

        # Build Markdown report
        report_lines = [
            f"# {title}",
            "",
            f"**Session ID:** {session.session_id}",
            f"**Evidence Directory:** {session.evidence_dir}",
            f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
            f"**Evidence Integrity:** VERIFIED ({session.file_count} files sealed)",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            f"- **Total findings:** {summary_data['total_findings']}",
            f"- **High confidence (>=0.75):** {summary_data['high_confidence_findings']}",
            f"- **Low confidence (<0.75):** {summary_data['low_confidence_findings']}",
            f"- **Self-corrections:** {summary_data['self_corrections']}",
            f"- **Action required:** {summary_data['action_required_count']}",
            f"- **Artifact types covered:** {', '.join(summary_data['artifact_types'])}",
            "",
            "---",
            "",
            "## Findings",
            "",
        ]

        # High confidence findings first
        high_conf = [f for f in findings if f["confidence"] >= 0.75]
        low_conf = [f for f in findings if f["confidence"] < 0.75]

        if high_conf:
            report_lines.append("### High Confidence Findings")
            report_lines.append("")
            for i, f in enumerate(high_conf, 1):
                provenance_ids = [p["invocation_id"][:8] for p in f.get("provenance", [])]
                report_lines.extend([
                    f"**[{f['finding_id'][:8]}] Finding {i}:** {f['description']}",
                    f"- Confidence: {f['confidence']:.2f} "
                    f"(evidence: {f['evidence_strength']:.2f}, "
                    f"corroboration: {f['corroboration']:.2f})",
                    f"- Artifact type: {f['artifact_type']}",
                    f"- MITRE ATT&CK: {f['mitre_technique'] or 'N/A'}",
                    f"- Provenance: {', '.join(provenance_ids) or 'N/A'}",
                    f"- Action required: {'Yes' if f['action_required'] else 'No'}",
                    "",
                ])

        if low_conf:
            report_lines.append("### Low Confidence Findings (Needs Review)")
            report_lines.append("")
            for i, f in enumerate(low_conf, 1):
                report_lines.extend([
                    f"**[{f['finding_id'][:8]}] Finding {i}:** {f['description']}",
                    f"- Confidence: {f['confidence']:.2f} (BELOW THRESHOLD)",
                    "",
                ])

        # Self-correction log
        if corrections:
            report_lines.extend([
                "---",
                "",
                "## Self-Correction Log",
                "",
                "The following findings were revised during analysis:",
                "",
            ])
            for c in corrections:
                report_lines.extend([
                    f"- **Original:** {c['original_description']} "
                    f"(confidence: {c['original_confidence']:.2f})",
                    f"  **Reason:** {c['reason']}",
                    "",
                ])

        # IOC table
        iocs = _extract_iocs(findings)
        has_iocs = any(v for v in iocs.values())
        if has_iocs:
            report_lines.extend([
                "---",
                "",
                "## Indicators of Compromise (IOCs)",
                "",
                "| Type | Value |",
                "|------|-------|",
            ])
            for ip in sorted(iocs["ipv4"]):
                report_lines.append(f"| IPv4 | `{ip}` |")
            for h in sorted(iocs["sha256"]):
                report_lines.append(f"| SHA-256 | `{h}` |")
            for h in sorted(iocs["md5"]):
                report_lines.append(f"| MD5 | `{h}` |")
            for fp in sorted(iocs["file_path"]):
                report_lines.append(f"| File Path | `{fp}` |")
            for rk in sorted(iocs["registry_key"]):
                report_lines.append(f"| Registry Key | `{rk}` |")
            report_lines.append("")

        report_lines.extend([
            "---",
            "",
            "## Evidence Integrity Statement",
            "",
            f"All {session.file_count} evidence files were SHA-256 sealed at session start "
            "and continuously verified throughout the analysis. The hash daemon ran on a "
            "30-second cycle with additional pre-tool-call verification. No integrity "
            "violations were detected during this session.",
            "",
            "---",
            "",
            f"*Report generated by Evidence Integrity Enforcer v0.1.0*",
        ])

        report_markdown = "\n".join(report_lines)

        result = {
            "tool": "generate_report",
            "report": report_markdown,
            "findings_count": len(findings),
            "corrections_count": len(corrections),
            "summary": (
                f"IR report generated: {len(findings)} findings, "
                f"{len(corrections)} self-corrections"
            ),
        }

        return complete(tc, result)

    except Exception as exc_report:
        fail(tc, str(exc_report))
        raise


def _stix_indicator(ioc_type: str, value: str, finding_ids: list[str]) -> dict:
    """Build a STIX 2.1 Indicator object."""
    pattern_map = {
        "ipv4": f"[ipv4-addr:value = '{value}']",
        "md5": f"[file:hashes.MD5 = '{value}']",
        "sha256": f"[file:hashes.'SHA-256' = '{value}']",
        "file_path": f"[file:name = '{value.split(chr(92))[-1]}']",
        "registry_key": f"[windows-registry-key:key = '{value}']",
    }
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid_mod.uuid5(uuid_mod.NAMESPACE_URL, f'{ioc_type}:{value}')}",
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "modified": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "name": f"{ioc_type.upper()}: {value}",
        "pattern": pattern_map.get(ioc_type, f"[artifact:payload_bin = '{value}']"),
        "pattern_type": "stix",
        "valid_from": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "labels": ["malicious-activity"],
        "external_references": [
            {"source_name": "find-evil", "description": f"Linked to finding(s): {', '.join(f[:8] for f in finding_ids)}"}
        ],
    }


def build_stix_bundle(findings: list[dict], session_id: str, file_count: int) -> dict:
    """Build a STIX 2.1 bundle from a list of findings.

    Pure function with no MCP dependency — callable from demo scripts and tests.
    The MCP tool wrapper export_stix() composes this with session context.
    """
    iocs = _extract_iocs(findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    bundle_id = f"bundle--{uuid_mod.uuid4()}"
    report_id = f"report--{uuid_mod.uuid4()}"

    objects: list[dict] = []
    indicator_ids: list[str] = []

    finding_ids = [f["finding_id"] for f in findings]
    for ioc_type, values in iocs.items():
        for value in sorted(values):
            indicator = _stix_indicator(ioc_type, value, finding_ids)
            objects.append(indicator)
            indicator_ids.append(indicator["id"])

    objects.append({
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created": now,
        "modified": now,
        "name": f"Evidence Integrity Enforcer — Session {session_id[:8]}",
        "published": now,
        "report_types": ["threat-report"],
        "object_refs": indicator_ids,
        "description": (
            f"Automated DFIR analysis: {len(findings)} findings, "
            f"{len(indicator_ids)} IOC indicators extracted. "
            f"Evidence integrity verified ({file_count} files sealed)."
        ),
    })

    for ind_id in indicator_ids:
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid_mod.uuid4()}",
            "created": now,
            "modified": now,
            "relationship_type": "indicates",
            "source_ref": ind_id,
            "target_ref": report_id,
        })

    return {"type": "bundle", "id": bundle_id, "objects": objects}


@mcp.tool()
async def export_stix(ctx: Context) -> dict:
    """Export all findings and IOCs as a STIX 2.1 bundle.

    Produces a standards-compliant STIX 2.1 JSON bundle containing:
    - One Indicator per extracted IOC (IPs, hashes, file paths, registry keys)
    - One Report object linking all indicators
    - Relationship objects connecting indicators to the report

    This enables interoperability with threat intel platforms (MISP, OpenCTI,
    ThreatConnect) and SIEMs that consume STIX feeds.
    """
    tc = enforce(ctx, "export_stix", {})
    if isinstance(tc, dict):
        return tc

    try:
        session = get_lifespan(ctx)["session"]
        db = _get_findings_db(ctx)

        if not session.session_id:
            return complete(tc, {
                "tool": "export_stix",
                "error": "No active session",
                "summary": "Cannot export — no evidence session active.",
            })

        findings = db.get_findings(session.session_id)
        bundle = build_stix_bundle(findings, session.session_id, session.file_count)
        indicator_count = sum(1 for o in bundle["objects"] if o["type"] == "indicator")

        result = {
            "tool": "export_stix",
            "stix_bundle": json.dumps(bundle, indent=2),
            "indicator_count": indicator_count,
            "object_count": len(bundle["objects"]),
            "summary": (
                f"STIX 2.1 bundle exported: {indicator_count} indicators, "
                f"{len(bundle['objects'])} total objects"
            ),
        }

        return complete(tc, result)

    except Exception as e:
        fail(tc, str(e))
        raise
