#!/usr/bin/env python3
"""Demo orchestrator for the Evidence Integrity Enforcer.

Runs the demo acts in the right SEQUENCE with on-screen banners and timed
pauses for narration, so you run ONE command on camera.

    python demo/record_demo.py                 # scripted sequence (deterministic)
    python demo/record_demo.py --with-agent    # prepend the REAL Claude agent act (claude -p)
    python demo/record_demo.py --agent-only     # only the real Claude agent act
    python demo/record_demo.py --pause 4        # longer pauses for narration (default 2.5s)
    python demo/record_demo.py --pause 0        # no pauses (fast dry-run / CI smoke)

Acts:
    1. COLD OPEN      validate_submission.py       49 checks + 550 tests pass
    [2. REAL AGENT]   claude -p "<investigate>"    autonomous Claude driving the MCP server (--with-agent)
    3. REAL EVIDENCE  run_live_investigation.py    live python-evtx / registry / yara on real files
    4. TAMPER+REPORT  video_demo.py                seal -> investigate -> TAMPER halt -> re-seal -> IR report

Prereq for the agent act: the find-evil MCP server connected
(`claude mcp add find-evil -- ...`; see docs/try_it_out.md). If `claude` is not
on PATH the agent act is skipped with a notice; the scripted acts still run.
"""
import argparse
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


def run_py(script):
    return subprocess.run([PY, script], cwd=str(REPO)).returncode


def run_agent(batch=False):
    banner("ACT 2", "REAL CLAUDE AGENT (autonomous)", "Claude drives the MCP server itself")
    # --allowedTools pre-authorizes the (read-only) find-evil tools so the agent
    # isn't blocked on approval prompts. Interactive `claude` STREAMS every tool
    # call + result live in the TUI (what you want on camera); `claude -p`
    # (--agent-batch) runs silently and prints only the final report at the end.
    if batch:
        cmd = ["claude", "-p", AGENT_PROMPT, "--allowedTools", "mcp__find-evil"]
        print(f"  {DIM}$ claude -p \"...\" --allowedTools mcp__find-evil   (batch - no live stream){RESET}\n", flush=True)
    else:
        cmd = ["claude", AGENT_PROMPT, "--allowedTools", "mcp__find-evil"]
        print(f"  {DIM}$ claude \"{AGENT_PROMPT[:50]}...\" --allowedTools mcp__find-evil{RESET}")
        print(f"  {DIM}  interactive - watch the tool calls stream; type /exit (or Ctrl-C) when it finishes to continue{RESET}\n", flush=True)
    try:
        rc = subprocess.run(cmd, cwd=str(REPO)).returncode
        if rc != 0:
            print(f"{AMBER}  (claude exited {rc} - is the find-evil MCP server connected? see docs/try_it_out.md){RESET}")
    except FileNotFoundError:
        print(f"{AMBER}  (claude CLI not on PATH - skipping the agent act; scripted acts still run){RESET}")


def main():
    ap = argparse.ArgumentParser(description="Evidence Integrity Enforcer demo orchestrator")
    ap.add_argument("--pause", type=float, default=2.5, help="seconds between acts (default 2.5; 0 = none)")
    ap.add_argument("--with-agent", action="store_true", help="prepend the real Claude agent act (interactive - watchable)")
    ap.add_argument("--agent-only", action="store_true", help="run only the real Claude agent act")
    ap.add_argument("--agent-batch", action="store_true", help="run the agent via `claude -p` (batch, no live stream; for automation)")
    args = ap.parse_args()

    # Fresh output for a clean recording
    out = REPO / "output"
    out.mkdir(exist_ok=True)
    for f in ("audit_trail.jsonl", "findings.db", "live_audit_trail.jsonl", "live_findings.db"):
        (out / f).unlink(missing_ok=True)

    if args.agent_only:
        run_agent(batch=args.agent_batch)
        return

    banner("ACT 1", "COLD OPEN - automated proof", "validate_submission.py: 49 checks + 550 tests")
    run_py("demo/validate_submission.py")
    pause(args.pause)

    if args.with_agent:
        run_agent(batch=args.agent_batch)
        pause(args.pause)

    banner("ACT 3", "REAL EVIDENCE - live backends", "run_live_investigation.py: python-evtx + registry + yara on real files")
    run_py("demo/run_live_investigation.py")
    pause(args.pause)

    banner("ACT 4", "TAMPER + RECOVERY + REPORT", "video_demo.py: seal -> investigate -> TAMPER halt -> re-seal -> IR report")
    run_py("demo/video_demo.py")

    print(f"\n{GREEN}  Demo complete. Outputs in output/: audit_trail.jsonl, ir_report.md, "
          f"live_audit_trail.jsonl, bundle.stix.json{RESET}\n", flush=True)


if __name__ == "__main__":
    main()
