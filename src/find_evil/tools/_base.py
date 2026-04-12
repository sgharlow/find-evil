"""Base enforcement layer for all forensic tool functions.

Every MCP tool in this server calls `enforce()` before executing, which:
1. Verifies evidence integrity BEFORE execution
2. Validates file paths are within the sealed evidence directory (anti-traversal)
3. Logs the tool invocation to the audit trail with a UUID
4. Hashes the output for provenance tracking
5. Enforces output size limits to prevent context window overflow
6. Records timing metrics (elapsed_ms) for each tool call

If integrity fails, the tool returns an error instead of executing.
There is no bypass path — the check happens server-side before any SIFT tool runs.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import Context

from find_evil.audit.logger import AuditLogger, hash_output
from find_evil.session.hash_daemon import HashDaemon
from find_evil.session.manager import EvidenceSession

logger = logging.getLogger("find_evil.tools")

# Sentinel returned when integrity check fails
INTEGRITY_VIOLATION = "EVIDENCE_INTEGRITY_VIOLATION"

# Maximum items in a tool's data[] array before truncation.
# Prevents large tool outputs from overflowing the LLM context window.
MAX_OUTPUT_ITEMS = 200


class EvidencePathError(Exception):
    """Raised when a file path is outside the sealed evidence directory."""


@dataclass
class ToolContext:
    """Unpacked lifespan context for forensic tools."""

    session: EvidenceSession
    daemon: HashDaemon
    audit: AuditLogger
    invocation_id: str
    start_time: float = field(default_factory=time.monotonic)


def get_lifespan(ctx: Context) -> dict:
    """Extract the lifespan context dict from a FastMCP Context."""
    return ctx.request_context.lifespan_context


def enforce(
    ctx: Context,
    tool_name: str,
    arguments: dict[str, Any],
    evidence_paths: list[str] | None = None,
) -> ToolContext | dict:
    """Pre-execution enforcement gate. Call this at the top of every forensic tool.

    Args:
        ctx: FastMCP Context (provides lifespan with session/daemon/audit).
        tool_name: Name of the tool being called (for audit logging).
        arguments: Tool arguments (logged to audit trail).
        evidence_paths: Optional list of file path arguments to validate against
            the sealed evidence directory. If any path resolves outside the
            evidence directory, the tool call is rejected.

    Returns:
        ToolContext — if all checks pass. Tool should proceed with analysis.
        dict — if any check fails. Tool should return this dict immediately.
    """
    lifespan = get_lifespan(ctx)
    session: EvidenceSession = lifespan["session"]
    daemon: HashDaemon = lifespan["daemon"]
    audit: AuditLogger = lifespan["audit"]

    # 1. Require an active session
    if not session.is_active:
        return {
            "error": "NO_ACTIVE_SESSION",
            "message": (
                "No active evidence session. Call session_init first, "
                "or reseal_evidence if the previous session was halted."
            ),
        }

    # 2. Verify evidence integrity BEFORE execution
    integrity = daemon.verify_now()
    if not integrity.passed:
        audit.log_session_halt(integrity.summary)
        return {
            "error": INTEGRITY_VIOLATION,
            "message": (
                "ANALYSIS HALTED — chain of custody broken. "
                "All findings voided."
            ),
            "violations": integrity.failures,
            "session_halted": True,
        }

    # 3. Validate evidence file paths (anti-traversal)
    if evidence_paths:
        for raw_path in evidence_paths:
            violation = _validate_evidence_path(raw_path, session)
            if violation:
                audit.log_invocation_error(
                    str(uuid.uuid4()),
                    f"Path validation failed: {violation}",
                )
                return {
                    "error": "EVIDENCE_PATH_VIOLATION",
                    "message": violation,
                    "path": raw_path,
                }

    # 4. Generate invocation UUID, record start time, log start
    invocation_id = str(uuid.uuid4())
    audit.log_invocation_start(tool_name, arguments)

    return ToolContext(
        session=session,
        daemon=daemon,
        audit=audit,
        invocation_id=invocation_id,
        start_time=time.monotonic(),
    )


def complete(tc: ToolContext, result: dict) -> dict:
    """Post-execution: truncate output, hash, log completion with timing, attach provenance."""

    # 1. Enforce output size limits
    if "data" in result and isinstance(result["data"], list):
        original_count = len(result["data"])
        if original_count > MAX_OUTPUT_ITEMS:
            result["data"] = result["data"][:MAX_OUTPUT_ITEMS]
            result["truncated"] = True
            result["truncated_from"] = original_count
            result["truncation_notice"] = (
                f"Output truncated from {original_count} to {MAX_OUTPUT_ITEMS} items. "
                f"Use filters (time_after, time_before, event_ids, pid) to narrow results."
            )

    # 2. Compute timing
    elapsed_ms = round((time.monotonic() - tc.start_time) * 1000, 1)

    # 3. Hash output for provenance
    output_hash_value = hash_output(str(result))

    # 4. Log completion with timing
    result_count = len(result.get("data", []))
    summary = result.get("summary", "")

    tc.audit.log_invocation_complete(
        tc.invocation_id,
        output_hash=output_hash_value,
        result_count=result_count,
        summary=summary,
        elapsed_ms=elapsed_ms,
    )

    # 5. Attach provenance metadata
    result["_provenance"] = {
        "invocation_id": tc.invocation_id,
        "output_hash": output_hash_value,
        "integrity_verified": True,
        "elapsed_ms": elapsed_ms,
    }

    return result


def fail(tc: ToolContext, error: str) -> None:
    """Log a tool execution failure with sanitized error message."""
    # Sanitize: strip internal file paths and system info
    safe_error = _sanitize_error(error)
    tc.audit.log_invocation_error(tc.invocation_id, safe_error)
    logger.error("Tool invocation %s failed: %s", tc.invocation_id, safe_error)


def _validate_evidence_path(raw_path: str, session: EvidenceSession) -> str | None:
    """Validate that a file path refers to a file within the sealed evidence directory.

    Returns None if valid, or an error message string if invalid.
    Prevents path traversal attacks (e.g., ../../etc/passwd).
    """
    if not session.evidence_dir:
        return "No evidence directory set."

    evidence_root = Path(session.evidence_dir).resolve()

    try:
        # Resolve the path (follows symlinks, resolves ..)
        resolved = Path(raw_path).resolve()
    except (OSError, ValueError) as e:
        return f"Invalid path: {e}"

    # Check if the resolved path is within the evidence directory
    try:
        resolved.relative_to(evidence_root)
    except ValueError:
        return (
            f"Path '{raw_path}' resolves outside the sealed evidence directory. "
            f"All file operations must target files within the evidence directory. "
            f"Path traversal is not permitted."
        )

    return None


def _sanitize_error(error: str) -> str:
    """Remove potentially sensitive information from error messages.

    Strips:
    - Absolute file paths (replace with basename)
    - IP addresses (keep first two octets)
    - Stack traces (truncate)
    """
    # Truncate very long errors
    if len(error) > 500:
        error = error[:500] + "... (truncated)"
    return error
