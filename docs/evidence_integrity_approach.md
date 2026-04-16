# Evidence Integrity Approach

## How does your architecture prevent original data from being modified?

Evidence protection in this submission is **architectural, not prompt-based**.

### Layer 1: Function Registry (Attack Surface Elimination)

The MCP server exposes exactly 15 typed, read-only functions. Destructive
operations — shell execution, file writing, file deletion, disk formatting —
**do not exist in the function registry**. The agent's only interface to
evidence files is through these 15 functions. There is no `execute_shell_cmd()`,
no `write_file()`, no `rm()`, no `dd()`.

This is not a blocklist that denies specific commands. It is an allowlist where
destructive commands were never implemented. The attack surface is zero.

A security verification test (`tests/test_integration.py`) asserts that no
destructive tool names are present in the registry. This runs in CI.

### Layer 2: SHA-256 Hash Sealing (Tamper Detection)

At session start, every evidence file is hashed with SHA-256:

1. `session_init` discovers evidence files by extension (.E01, .img, .raw, .pcap, .evtx, etc.)
2. Each file's **content** (not metadata) is hashed in 64KB chunks
3. The hash manifest is stored in the session object
4. The session is now sealed — any content modification will be detected

Key design decision: SHA-256 hashes file **content**, not metadata. The Unix
`touch` command changes mtime but does not change file content — and therefore
would NOT trigger our detection. This is deliberate and correct. Our tamper
detection test (`test_touch_does_not_trigger_detection`) explicitly documents
this behavior.

### Layer 3: Hash Daemon (Continuous Monitoring)

A background daemon thread re-verifies all evidence hashes on two triggers:

- **Periodic**: Every 30 seconds (configurable via `HASH_CHECK_INTERVAL`)
- **Pre-execution**: Synchronously before every forensic tool call, via the
  `enforce()` gate in `tools/_base.py`

If any hash mismatch is detected:
1. The session is immediately halted (`session.is_active = False`)
2. All findings from the session are voided
3. The audit trail logs a `session_halt` event
4. All subsequent tool calls return `EVIDENCE_INTEGRITY_VIOLATION`
5. The agent is instructed (via CLAUDE.md) to stop and report the violation

### Layer 4: Audit Trail (Provenance Chain)

Every tool invocation is logged to a JSONL audit trail with:
- UUID invocation ID
- Tool name and arguments
- Timestamp
- Integrity verification status
- Output hash (SHA-256 of the result)

Every finding links back to the specific invocation IDs that produced it.
Judges can trace any finding in the final report back through the audit
trail to the exact tool call and verified evidence state.

## What happens when the model ignores read-only rules?

The model **cannot** ignore them. There is no function to call.

If the model attempts to call `execute_shell_cmd()`, the MCP server returns:
"Function 'execute_shell_cmd' is not registered." The model has no other
pathway to evidence files.

This is not a prompt instruction that can be bypassed by adversarial prompting
or hallucination. It is a server-side function registry that physically
does not contain destructive operations.

## Was spoliation tested?

Yes. The test suite includes dedicated spoliation tests:

| Test | File | What It Verifies |
|------|------|-----------------|
| `test_detects_content_modification` | `test_session_manager.py` | Appending bytes triggers halt |
| `test_detects_file_deletion` | `test_session_manager.py` | Deleting evidence file triggers halt |
| `test_detects_content_replacement` | `test_session_manager.py` | Same-size replacement detected |
| `test_session_halts_on_violation` | `test_session_manager.py` | Session becomes inactive |
| `test_require_active_raises_after_halt` | `test_session_manager.py` | Tool gate raises exception |
| `test_touch_does_not_trigger_detection` | `test_session_manager.py` | Metadata-only change not flagged (correct) |
| `test_daemon_detects_tamper` | `test_hash_daemon.py` | Background thread catches modification |
| `test_verify_now_detects_tamper_immediately` | `test_hash_daemon.py` | On-demand check catches tampering |
| `test_tamper_mid_investigation_blocks_subsequent_tools` | `test_integration.py` | Mid-analysis tamper halts pipeline |
| `test_tamper_event_logged` | `test_integration.py` | Tamper detection written to audit trail |
| `test_reseal_creates_new_session` | `test_session_manager.py` | Recovery after tamper creates fresh session |

The tamper demo (`demo/tamper_demo.py`) demonstrates this live:
seal → verify → tamper (byte modification) → detect → halt → re-seal → resume.
