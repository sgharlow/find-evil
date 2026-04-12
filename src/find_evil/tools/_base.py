"""Base enforcement layer for all forensic tool functions.

Every MCP tool in this server calls `enforce()` before executing, which:
1. Verifies evidence integrity BEFORE execution
2. Logs the tool invocation to the audit trail with a UUID
3. Hashes the output for provenance tracking

If integrity fails, the tool returns an error instead of executing.
There is no bypass path — the check happens server-side before any SIFT tool runs.

Design note: We use a helper class (not a decorator) because FastMCP inspects
the tool function's signature to detect the `ctx: Context` parameter. A decorator
that wraps the function with `*args, **kwargs` would hide the Context annotation.
An explicit `enforce()` call preserves the signature while ensuring every tool
goes through the integrity gate.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Any

from mcp.server.fastmcp import Context

from find_evil.audit.logger import AuditLogger, hash_output
from find_evil.session.hash_daemon import HashDaemon
from find_evil.session.manager import EvidenceSession

logger = logging.getLogger("find_evil.tools")


# Sentinel returned when integrity check fails — tools check for this
INTEGRITY_VIOLATION = "EVIDENCE_INTEGRITY_VIOLATION"


@dataclass
class ToolContext:
    """Unpacked lifespan context for forensic tools."""

    session: EvidenceSession
    daemon: HashDaemon
    audit: AuditLogger
    invocation_id: str


def get_lifespan(ctx: Context) -> dict:
    """Extract the lifespan context dict from a FastMCP Context."""
    return ctx.request_context.lifespan_context


def enforce(ctx: Context, tool_name: str, arguments: dict[str, Any]) -> ToolContext | dict:
    """Pre-execution enforcement gate. Call this at the top of every forensic tool.

    Returns:
        ToolContext — if integrity passes. Tool should proceed with analysis.
        dict — if integrity fails. Tool should return this dict immediately
               (it contains the violation error message for the agent).

    Usage in a tool function:
        @mcp.tool()
        async def vol_pslist(memory_image: str, ctx: Context) -> dict:
            result = enforce(ctx, "vol_pslist", {"memory_image": memory_image})
            if isinstance(result, dict):
                return result  # integrity violation
            tc = result  # ToolContext with session, audit, invocation_id
            # ... do analysis ...
            return complete(tc, output_data)
    """
    lifespan = get_lifespan(ctx)
    session: EvidenceSession = lifespan["session"]
    daemon: HashDaemon = lifespan["daemon"]
    audit: AuditLogger = lifespan["audit"]

    # 1. Verify evidence integrity BEFORE execution
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

    # 2. Generate invocation UUID and log start
    invocation_id = str(uuid.uuid4())
    audit.log_invocation_start(tool_name, arguments)

    return ToolContext(
        session=session,
        daemon=daemon,
        audit=audit,
        invocation_id=invocation_id,
    )


def complete(tc: ToolContext, result: dict) -> dict:
    """Post-execution: hash output, log completion, attach provenance.

    Call this before returning from a forensic tool.
    """
    output_hash_value = hash_output(str(result))

    result_count = len(result.get("data", []))
    summary = result.get("summary", "")

    tc.audit.log_invocation_complete(
        tc.invocation_id,
        output_hash=output_hash_value,
        result_count=result_count,
        summary=summary,
    )

    result["_provenance"] = {
        "invocation_id": tc.invocation_id,
        "tool": "unknown",  # caller should set this before calling complete()
        "output_hash": output_hash_value,
        "integrity_verified": True,
    }

    return result


def fail(tc: ToolContext, error: str) -> None:
    """Log a tool execution failure."""
    tc.audit.log_invocation_error(tc.invocation_id, error)
    logger.error("Tool invocation %s failed: %s", tc.invocation_id, error)
