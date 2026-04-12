"""Base decorator for all forensic tool functions.

Every MCP tool in this server is wrapped with @forensic_tool, which enforces:
1. Evidence integrity verification BEFORE execution
2. Audit trail logging (start, complete, error) with UUID provenance
3. Output hashing for provenance tracking

This is the enforcement layer. If integrity fails, the tool returns an error
instead of executing. There is no bypass path — the check happens server-side
before any SIFT tool runs.
"""

from __future__ import annotations

import functools
import logging
import uuid
from typing import Any, Callable

from find_evil.audit.logger import hash_output

logger = logging.getLogger("find_evil.tools")


def forensic_tool(func: Callable) -> Callable:
    """Decorator enforcing audit + integrity on every forensic tool call.

    The decorated function receives `_ctx` as a dict with:
        - session: EvidenceSession
        - daemon: HashDaemon
        - audit: AuditLogger
        - findings: FindingsDB (when available)

    The decorator:
        1. Verifies evidence integrity via the hash daemon
        2. Generates a UUID invocation ID
        3. Logs tool_call_start to audit trail
        4. Executes the tool function
        5. Hashes the output for provenance
        6. Logs tool_call_complete (or tool_call_error)
        7. Attaches provenance metadata to the result
    """

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> dict:
        # Extract the lifespan context (injected by server.py via tool functions)
        ctx = kwargs.get("_ctx")
        if ctx is None:
            raise RuntimeError(
                f"Tool {func.__name__} called without _ctx. "
                "All tools must be called through the MCP server."
            )

        session = ctx["session"]
        daemon = ctx["daemon"]
        audit = ctx["audit"]

        # 1. Verify evidence integrity BEFORE execution
        integrity = daemon.verify_now()
        if not integrity.passed:
            audit.log_session_halt(integrity.summary)
            return {
                "error": "EVIDENCE_INTEGRITY_VIOLATION",
                "message": (
                    "ANALYSIS HALTED — chain of custody broken. "
                    "All findings voided."
                ),
                "violations": integrity.failures,
                "session_halted": True,
            }

        # 2. Generate invocation UUID
        invocation_id = str(uuid.uuid4())

        # 3. Log tool call start
        # Strip internal kwargs before logging
        log_args = {
            k: v for k, v in kwargs.items()
            if not k.startswith("_")
        }
        audit.log_invocation_start(func.__name__, log_args)

        # 4. Execute the actual tool
        try:
            result = await func(*args, **kwargs)
        except Exception as e:
            audit.log_invocation_error(invocation_id, str(e))
            logger.error("Tool %s failed: %s", func.__name__, e)
            raise

        # 5. Hash output for provenance
        output_hash_value = hash_output(str(result))

        # 6. Log completion
        result_count = 0
        summary = ""
        if isinstance(result, dict):
            result_count = len(result.get("data", []))
            summary = result.get("summary", "")

        audit.log_invocation_complete(
            invocation_id,
            output_hash=output_hash_value,
            result_count=result_count,
            summary=summary,
        )

        # 7. Attach provenance metadata
        if isinstance(result, dict):
            result["_provenance"] = {
                "invocation_id": invocation_id,
                "tool": func.__name__,
                "output_hash": output_hash_value,
                "integrity_verified": True,
            }

        return result

    return wrapper
