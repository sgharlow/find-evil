"""Evidence Integrity Enforcer — MCP Server entry point.

FastMCP server exposing ONLY read-only forensic analysis tools.
Destructive commands (shell, write, delete) do not exist in this server.
This is architectural enforcement, not a prompt restriction.

Usage:
    # Direct
    python -m find_evil.server

    # Via Claude Code
    claude mcp add find-evil -- python -m find_evil.server

    # With evidence directory
    EVIDENCE_DIR=/path/to/case-data python -m find_evil.server
"""

from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from mcp.server.fastmcp import FastMCP, Context

from find_evil.session.manager import EvidenceSession, EvidenceIntegrityError
from find_evil.session.hash_daemon import HashDaemon
from find_evil.audit.logger import AuditLogger

logging.basicConfig(
    level=logging.INFO,
    format="[%(name)s] %(levelname)s: %(message)s",
    stream=sys.stderr,  # MCP uses stdout for protocol; logs go to stderr
)
logger = logging.getLogger("find_evil.server")


@asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncIterator[dict]:
    """Initialize shared resources available to all tools via Context.

    The lifespan context manager creates the evidence session, hash daemon,
    and audit logger exactly once. Every tool function receives these via
    the Context parameter — no global mutable state.
    """
    session = EvidenceSession()
    audit = AuditLogger(
        path=os.environ.get("AUDIT_LOG_PATH", "audit_trail.jsonl")
    )
    daemon = HashDaemon(
        session,
        interval=int(os.environ.get("HASH_CHECK_INTERVAL", "30")),
    )

    logger.info("Evidence Integrity Enforcer MCP server starting")

    # If EVIDENCE_DIR is set, auto-seal evidence at startup
    evidence_dir = os.environ.get("EVIDENCE_DIR")
    if evidence_dir:
        try:
            info = session.initialize(evidence_dir)
            audit.set_session_id(info.session_id)
            audit.log_session_start(info.model_dump())
            daemon.start()
            logger.info(
                "Evidence sealed: %d files in %s (session %s)",
                info.file_count,
                evidence_dir,
                info.session_id,
            )
        except Exception as e:
            logger.error("Failed to seal evidence: %s", e)

    try:
        yield {
            "session": session,
            "daemon": daemon,
            "audit": audit,
        }
    finally:
        daemon.stop()
        logger.info("MCP server shutting down")


mcp = FastMCP(
    "find-evil",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Core session management tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def session_init(evidence_dir: str, ctx: Context) -> dict:
    """Initialize an evidence session by sealing all evidence files with SHA-256 hashes.

    This MUST be called before any analysis tools. It:
    1. Discovers all evidence files in the directory (by extension)
    2. Computes SHA-256 hash of each file's contents
    3. Stores the hash manifest for continuous verification
    4. Starts the background hash daemon (30-second check cycle)

    After this call, any modification to evidence files will be detected
    and will halt the analysis session.

    Args:
        evidence_dir: Path to the directory containing evidence files.
    """
    lifespan_ctx = ctx.request_context.lifespan_context
    session: EvidenceSession = lifespan_ctx["session"]
    daemon: HashDaemon = lifespan_ctx["daemon"]
    audit: AuditLogger = lifespan_ctx["audit"]

    info = session.initialize(evidence_dir)
    audit.set_session_id(info.session_id)
    audit.log_session_start(info.model_dump())
    daemon.start()

    return {
        "status": "sealed",
        "session_id": info.session_id,
        "evidence_dir": info.evidence_dir,
        "file_count": info.file_count,
        "sealed_at": info.sealed_at,
        "manifest": info.manifest,
        "hash_daemon": "running (30s cycle)",
        "message": (
            f"Evidence sealed: {info.file_count} files. "
            "Chain of custody established. Analysis may proceed."
        ),
    }


@mcp.tool()
async def verify_integrity(ctx: Context) -> dict:
    """Verify the integrity of all sealed evidence files.

    Re-computes SHA-256 hashes of every evidence file and compares against
    the sealed manifest. If ANY file has been modified, the session is
    immediately halted and all findings are voided.

    This check also runs automatically every 30 seconds via the hash daemon,
    and before every tool call. Use this tool for an explicit on-demand check.
    """
    lifespan_ctx = ctx.request_context.lifespan_context
    daemon: HashDaemon = lifespan_ctx["daemon"]
    audit: AuditLogger = lifespan_ctx["audit"]

    result = daemon.verify_now()
    audit.log_integrity_check(result.model_dump())

    if result.passed:
        return {
            "status": "VERIFIED",
            "files_checked": result.files_checked,
            "message": f"All {result.files_checked} evidence files intact.",
        }

    return {
        "status": "VIOLATION",
        "session_halted": True,
        "files_checked": result.files_checked,
        "violations": result.failures,
        "message": (
            "EVIDENCE INTEGRITY VIOLATION — chain of custody broken. "
            "All findings voided. Session halted. "
            "Re-seal evidence to start a new session."
        ),
    }


@mcp.tool()
async def list_sealed_evidence(ctx: Context) -> dict:
    """List all sealed evidence files and their hash fingerprints.

    Returns the manifest of all evidence files that were sealed at
    session start. Each file is identified by path and truncated SHA-256 hash.
    """
    lifespan_ctx = ctx.request_context.lifespan_context
    session: EvidenceSession = lifespan_ctx["session"]

    if not session.is_active:
        return {
            "status": "no_session",
            "message": "No active session. Call session_init first.",
        }

    return {
        "status": "active",
        "session_id": session.session_id,
        "file_count": session.file_count,
        "manifest": session.get_manifest(),
    }


@mcp.tool()
async def reseal_evidence(ctx: Context) -> dict:
    """Re-seal evidence files after a tamper event or manual intervention.

    Creates a new session with fresh hashes. The old session is abandoned.
    Use this after evidence integrity has been restored (e.g., after replacing
    a corrupted file with a known-good copy).
    """
    lifespan_ctx = ctx.request_context.lifespan_context
    session: EvidenceSession = lifespan_ctx["session"]
    daemon: HashDaemon = lifespan_ctx["daemon"]
    audit: AuditLogger = lifespan_ctx["audit"]

    info = session.reseal()
    audit.set_session_id(info.session_id)
    audit.log_session_start(info.model_dump())

    # Restart the daemon for the new session
    daemon.stop()
    daemon.start()

    return {
        "status": "resealed",
        "session_id": info.session_id,
        "file_count": info.file_count,
        "sealed_at": info.sealed_at,
        "message": (
            f"Evidence re-sealed: {info.file_count} files. "
            "New session started. Previous findings voided."
        ),
    }


# ---------------------------------------------------------------------------
# Forensic analysis tools — imported AFTER mcp is defined to avoid circular
# imports. Each module does `from find_evil.server import mcp` and registers
# tools via @mcp.tool(). The import triggers registration.
#
# NOT AVAILABLE (by design — these functions do not exist):
#   - execute_shell_cmd()
#   - write_file() / rm() / dd()
#   - modify_evidence()
#   - Any function that writes to disk
# ---------------------------------------------------------------------------

import find_evil.tools.volatility  # noqa: E402, F401 — registers vol_pslist, vol_netscan, vol_malfind, vol_cmdline
import find_evil.tools.evtx  # noqa: E402, F401 — registers parse_evtx
import find_evil.tools.registry  # noqa: E402, F401 — registers registry_query
import find_evil.tools.timeline  # noqa: E402, F401 — registers build_timeline
import find_evil.tools.yara_scan  # noqa: E402, F401 — registers yara_scan
import find_evil.tools.findings  # noqa: E402, F401 — registers submit_finding, generate_report


# ---------------------------------------------------------------------------
# MCP Resources — expose read-only data through the MCP protocol.
# This goes beyond Tools to show full MCP mastery.
# ---------------------------------------------------------------------------

@mcp.resource("evidence://session")
def get_session_resource() -> str:
    """Current evidence session metadata — session ID, sealed files, integrity status.

    Read this resource to check what evidence is currently sealed
    and whether the session is active.
    """
    import json
    # Access session via the module-level lifespan (available after startup)
    # This is a best-effort resource — returns empty if no session yet
    try:
        session = mcp._lifespan_context["session"]  # type: ignore[attr-defined]
    except (AttributeError, KeyError, TypeError):
        return json.dumps({"status": "no_session", "message": "Server not yet initialized"})

    if not session.session_id:
        return json.dumps({"status": "no_session"})

    return json.dumps({
        "session_id": session.session_id,
        "evidence_dir": session.evidence_dir,
        "file_count": session.file_count,
        "is_active": session.is_active,
        "sealed_at": session.sealed_at.isoformat() if session.sealed_at else None,
        "manifest": session.get_manifest(),
    }, indent=2)


@mcp.resource("evidence://audit-trail")
def get_audit_trail_resource() -> str:
    """Complete JSONL audit trail of all tool invocations and findings.

    Every tool call, finding, self-correction, and integrity check is
    recorded here with UUID provenance. Read this to trace any finding
    back to its source tool call.
    """
    audit_path = os.environ.get("AUDIT_LOG_PATH", "audit_trail.jsonl")
    try:
        with open(audit_path) as f:
            return f.read()
    except FileNotFoundError:
        return "[]  # No audit trail yet — run session_init and analysis tools first"


@mcp.resource("evidence://tool-registry")
def get_tool_registry_resource() -> str:
    """List of all registered MCP tools and their descriptions.

    Shows exactly which functions are available (read-only forensic tools)
    and which are NOT available (destructive operations that don't exist).
    """
    import json
    tools = mcp._tool_manager.list_tools()
    registered = [
        {"name": t.name, "description": t.description.split("\n")[0]}
        for t in tools
    ]
    not_available = [
        "execute_shell_cmd", "write_file", "rm", "dd", "mkfs",
        "modify_evidence", "delete_file", "bash", "shell",
    ]
    return json.dumps({
        "registered_tools": registered,
        "not_available": not_available,
        "total_registered": len(registered),
        "total_blocked": len(not_available),
        "security_model": "allowlist — destructive functions were never implemented",
    }, indent=2)


# ---------------------------------------------------------------------------
# MCP Prompts — pre-built investigation templates.
# ---------------------------------------------------------------------------

@mcp.prompt()
def triage(evidence_dir: str = "./evidence") -> str:
    """Quick triage of a new evidence set — memory + network only.

    Runs Phase 1 (TRIAGE) from the investigation protocol:
    vol_pslist and vol_netscan to identify suspicious processes
    and network connections. Use this for rapid initial assessment.
    """
    return (
        f"I need you to triage the evidence in {evidence_dir}. "
        f"Start by calling session_init to seal the evidence. "
        f"Then run vol_pslist and vol_netscan on the memory image. "
        f"Report any suspicious processes (unusual parent-child chains) "
        f"and network connections (external IPs, non-standard ports). "
        f"Do NOT proceed to deeper analysis — just triage."
    )


@mcp.prompt()
def full_investigation(evidence_dir: str = "./evidence") -> str:
    """Complete 7-phase DFIR investigation following the CLAUDE.md protocol.

    Executes all phases: SEAL, TRIAGE, DEEP MEMORY, LOGS, PERSISTENCE,
    TIMELINE, IOC SCAN, SYNTHESIS. Produces a full incident response
    report with confidence-scored findings and provenance chain.
    """
    return (
        f"Conduct a full DFIR investigation of the evidence in {evidence_dir}. "
        f"Follow the investigation protocol in CLAUDE.md exactly:\n"
        f"1. session_init to seal evidence\n"
        f"2. vol_pslist + vol_netscan (triage)\n"
        f"3. vol_malfind + vol_cmdline on suspicious PIDs (deep memory)\n"
        f"4. parse_evtx on Security.evtx and System.evtx (logs)\n"
        f"5. registry_query for Run keys and Services (persistence)\n"
        f"6. build_timeline for temporal correlation (timeline)\n"
        f"7. yara_scan for IOC patterns (IOC scan)\n"
        f"8. submit_finding for each discovery through the DRS gate\n"
        f"9. generate_report with all findings\n\n"
        f"Score every finding through the DRS confidence gate. "
        f"Self-correct any finding below 0.75 confidence."
    )


@mcp.prompt()
def persistence_hunt(evidence_dir: str = "./evidence") -> str:
    """Focused persistence mechanism hunt — registry + services + scheduled tasks.

    Targets Phase 4 (PERSISTENCE) artifacts: Run keys, RunOnce, Services,
    UserAssist execution history. Use after triage identifies compromise.
    """
    return (
        f"Hunt for persistence mechanisms in the evidence at {evidence_dir}. "
        f"Focus on:\n"
        f"- registry_query with query_type='run_keys' — auto-start entries\n"
        f"- registry_query with query_type='services' — installed services\n"
        f"- registry_query with query_type='userassist' — execution history\n"
        f"Flag any entries pointing to Temp directories, AppData, or "
        f"user-writable paths. Cross-reference with parse_evtx Event ID 7045 "
        f"(service install) for corroboration."
    )


def main() -> None:
    """Entry point for the find-evil MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
