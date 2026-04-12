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
# Forensic analysis tools will be registered here via imports.
# Each tool module calls @mcp.tool() to register its functions.
#
# NOT AVAILABLE (by design — these functions do not exist):
#   - execute_shell_cmd()
#   - write_file() / rm() / dd()
#   - modify_evidence()
#   - Any function that writes to disk
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry point for the find-evil MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
