#!/usr/bin/env python3
"""Demo orchestrator - the 4-beat arc for the Evidence Integrity Enforcer.

Runs the demo in the right sequence with paced banners for recording, so you
run ONE command on camera and narrate.

    python demo/record_demo.py                 # HOOK -> live agent -> live tamper -> proof
    python demo/record_demo.py --no-agent      # beat 2 = scripted run_investigation.py (no Claude)
    python demo/record_demo.py --agent-batch   # beat 2 = claude -p (batch, no live stream)
    python demo/record_demo.py --manual-tamper # beat 3 = you tamper a sealed file in another terminal
    python demo/record_demo.py --pause 4       # longer narration gaps (default 2.5; 0 = none)

Beats:
    1. HOOK         the problem (narration cue - no command)
    2. REAL AGENT   interactive `claude` driving the MCP server (the centerpiece)
                    [--no-agent -> scripted run_investigation.py; --agent-batch -> claude -p]
    3. LIVE TAMPER  live_tamper.py: real SHA-256 tamper detection on real evidence -> HALT
    4. PROOF        validate_submission.py (49/49) + a provenance trace from the audit trail

Agent prereq: the find-evil MCP server connected (see docs/try_it_out.md).
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).parent.parent
PY = sys.executable
CYAN, GREEN, DIM, AMBER, RESET = "\033[96m", "\033[92m", "\033[2m", "\033[93m", "\033[0m"

AGENT_PROMPT = (
    "Investigate the sealed evidence at /evidence following your CLAUDE.md protocol. "
    "Seal and verify integrity, then run the phases for the available artifacts: parse the "
    "Application event log; query the SYSTEM and SOFTWARE registry hives for persistence "
    "(services and Run keys); and YARA-scan /evidence/evidence_iocs.bin for malware indicators. "
    "Score every finding through the DRS gate and report findings with tool-call provenance UUIDs."
)


def banner(tag, title, desc):
    line = "=" * 66
    print(f"\n{CYAN}{line}\n  {tag}: {title}\n  {DIM}{desc}{RESET}{CYAN}\n{line}{RESET}\n", flush=True)


def pause(sec):
    if sec > 0:
        print(f"\n{DIM}  (pausing {sec:g}s - narrate, then it continues){RESET}", flush=True)
        time.sleep(sec)


def run_py(*args):
    return subprocess.run([PY, *args], cwd=str(REPO)).returncode


def hook():
    banner("BEAT 1", "THE PROBLEM (narrate)", "why architectural integrity, not prompt rules")
    print(f"  {DIM}Narrate:{RESET} AI-assisted DFIR leans on prompt guardrails - \"please don't")
    print("  modify evidence.\" One silent write voids chain of custody. This submission makes")
    print("  tampering architecturally impossible: 15 read-only tools, SHA-256 sealing, a DRS")
    print("  confidence gate, and a UUID audit trail. Controls, not signs.\n", flush=True)


def run_agent(batch=False):
    banner("BEAT 2", "REAL CLAUDE AGENT (autonomous)", "Claude drives the MCP server itself - THE centerpiece")
    # --allowedTools pre-authorizes the read-only find-evil tools (no approval prompts).
    # Interactive `claude` STREAMS tool calls live (watchable); `claude -p` runs silently.
    if batch:
        cmd = ["claude", "-p", AGENT_PROMPT, "--allowedTools", "mcp__find-evil"]
        print(f"  {DIM}$ claude -p \"...\" --allowedTools mcp__find-evil   (batch - no live stream){RESET}\n", flush=True)
    else:
        cmd = ["claude", AGENT_PROMPT, "--allowedTools", "mcp__find-evil"]
        print(f"  {DIM}$ claude \"{AGENT_PROMPT[:50]}...\" --allowedTools mcp__find-evil{RESET}")
        print(f"  {DIM}  interactive - watch the tool calls stream; type /exit (or Ctrl-C) when done to continue{RESET}\n", flush=True)
    try:
        rc = subprocess.run(cmd, cwd=str(REPO)).returncode
        if rc != 0:
            print(f"{AMBER}  (claude exited {rc} - is the find-evil MCP server connected? see docs/try_it_out.md){RESET}")
    except FileNotFoundError:
        print(f"{AMBER}  (claude CLI not on PATH - skipping the agent act; use --no-agent for the scripted path){RESET}")


def provenance_trace():
    """Show that a real finding links back to its tool-call UUIDs (from beat 2's run)."""
    p = REPO / "output" / "audit_trail.jsonl"
    if not p.exists():
        print(f"  {DIM}(no audit trail at output/audit_trail.jsonl yet){RESET}")
        return
    try:
        events = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    except Exception:
        return
    from collections import Counter
    tally = Counter(e.get("event", "?") for e in events)
    print(f"  Audit trail: {len(events)} events {dict(tally)}")
    finding = next((e for e in reversed(events) if e.get("event") == "finding_committed"), None)
    if finding:
        uuids = finding.get("source_calls") or finding.get("provenance") or finding.get("invocation_ids") or []
        desc = str(finding.get("finding") or finding.get("description") or "")[:72]
        print(f"  Latest finding: {desc}")
        print(f"  -> cites tool-call UUID(s): {', '.join(str(u)[:8] for u in uuids[:3]) or '(see record)'}")
        print(f"  {DIM}Each UUID matches a tool_call_* record -> the verified evidence state at that moment.{RESET}")


def main():
    ap = argparse.ArgumentParser(description="Evidence Integrity Enforcer demo orchestrator (4-beat arc)")
    ap.add_argument("--pause", type=float, default=2.5, help="seconds between beats (default 2.5; 0 = none)")
    ap.add_argument("--no-agent", action="store_true", help="beat 2 = scripted run_investigation.py instead of live Claude")
    ap.add_argument("--agent-batch", action="store_true", help="beat 2 agent via `claude -p` (batch, no live stream)")
    ap.add_argument("--manual-tamper", action="store_true", help="beat 3 pauses so you tamper a sealed file in another terminal")
    args = ap.parse_args()

    # Fresh output for a clean recording
    out = REPO / "output"
    out.mkdir(exist_ok=True)
    for f in ("audit_trail.jsonl", "findings.db", "live_audit_trail.jsonl", "live_findings.db"):
        (out / f).unlink(missing_ok=True)

    # BEAT 1 - HOOK
    hook()
    pause(args.pause)

    # BEAT 2 - REAL AGENT (or scripted fallback)
    if args.no_agent:
        banner("BEAT 2", "INVESTIGATION (scripted fallback)", "run_investigation.py: 7-phase pipeline, accepted + self-corrected findings")
        run_py("demo/run_investigation.py")
    else:
        run_agent(batch=args.agent_batch)
    pause(args.pause)

    # BEAT 3 - LIVE TAMPER (real)
    banner("BEAT 3", "LIVE TAMPER DETECTION (real evidence)", "live_tamper.py: seal real evidence -> modify a byte -> cryptographic HALT")
    run_py("demo/live_tamper.py", *(["--manual"] if args.manual_tamper else []))
    pause(args.pause)

    # BEAT 4 - PROOF + PROVENANCE
    banner("BEAT 4", "PROOF + PROVENANCE", "validate_submission.py (49/49) + trace a finding to its tool-call UUIDs")
    run_py("demo/validate_submission.py")
    print()
    provenance_trace()

    print(f"\n{GREEN}  Demo complete. Outputs in output/: audit_trail.jsonl, ir_report.md, bundle.stix.json{RESET}\n", flush=True)


if __name__ == "__main__":
    main()
