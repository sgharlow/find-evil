"""Foreground visualizer for the live find-evil investigation.

Watches output/audit_trail.jsonl as it grows, pretty-prints each tool call,
and shows ir_report.md / bundle.stix.json when they appear. This is the
screen the recording focuses on — claude itself runs silently in the
background.

Run: python scripts/live-demo-display.py
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
AUDIT = REPO / "output" / "audit_trail.jsonl"
REPORT = REPO / "output" / "ir_report.md"
BUNDLE = REPO / "output" / "bundle.stix.json"
DB = REPO / "output" / "findings.db"

# ANSI colors — most terminals on Windows 10+ support these
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def banner():
    print(f"{CYAN}{BOLD}" + "=" * 78 + f"{RESET}")
    print(f"{CYAN}{BOLD}  EVIDENCE INTEGRITY ENFORCER — LIVE INVESTIGATION{RESET}")
    print(f"{CYAN}{BOLD}" + "=" * 78 + f"{RESET}")
    print(f"{DIM}  Watching: {AUDIT.name}  |  claude is analyzing in the background…{RESET}")
    print()


def pretty_event(entry: dict) -> str:
    """Format one audit-trail JSONL line for display."""
    ts = entry.get("timestamp", "")[:19].replace("T", " ")
    kind = entry.get("event", "?")
    tool = entry.get("tool", "")
    session = entry.get("session_id", "")[:8]

    if kind == "session_start":
        return f"{MAGENTA}[{ts}]{RESET} {BOLD}{MAGENTA}SESSION START{RESET}  session={session}  files sealed"
    if kind == "tool_call_start":
        return f"{YELLOW}[{ts}]{RESET} {BOLD}>> {tool}{RESET}"
    if kind == "tool_call_complete":
        uuid = entry.get("invocation_id", "")[:8]
        dur = entry.get("elapsed_ms")
        dur_s = f" {int(dur)}ms" if dur else ""
        return f"{GREEN}[{ts}]{RESET}    {GREEN}✓ complete{RESET}  uuid={uuid}{DIM}{dur_s}{RESET}"
    if kind == "finding_submitted":
        desc = entry.get("description", "")[:60]
        conf = entry.get("confidence", 0)
        accepted = entry.get("accepted", False)
        marker = f"{GREEN}ACCEPTED{RESET}" if accepted else f"{YELLOW}SELF-CORRECT{RESET}"
        return f"{CYAN}[{ts}]{RESET}    {BOLD}finding{RESET} conf={conf:.2f} {marker}  {DIM}{desc}{RESET}"
    if kind == "integrity_violation":
        return f"{RED}[{ts}]{RESET} {BOLD}{RED}!! INTEGRITY VIOLATION — ANALYSIS HALTED{RESET}"
    if kind == "session_halt":
        return f"{RED}[{ts}]{RESET} {BOLD}{RED}SESSION HALTED{RESET}"

    return f"{DIM}[{ts}] {kind} {tool}{RESET}"


def show_report():
    if not REPORT.exists():
        return False
    print()
    print(f"{CYAN}{BOLD}" + "=" * 78 + f"{RESET}")
    print(f"{CYAN}{BOLD}  INCIDENT RESPONSE REPORT{RESET}")
    print(f"{CYAN}{BOLD}" + "=" * 78 + f"{RESET}")
    try:
        text = REPORT.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    # Show first ~60 lines to fit typical terminal
    lines = text.splitlines()
    for line in lines[:80]:
        if line.startswith("# "):
            print(f"{BOLD}{CYAN}{line}{RESET}")
        elif line.startswith("## "):
            print(f"{BOLD}{MAGENTA}{line}{RESET}")
        elif line.startswith("- "):
            print(f"  {line}")
        else:
            print(line)
    if len(lines) > 80:
        print(f"{DIM}  … (+{len(lines) - 80} more lines in output/ir_report.md){RESET}")
    return True


def show_stix():
    if not BUNDLE.exists():
        return False
    try:
        data = json.loads(BUNDLE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    print()
    print(f"{CYAN}{BOLD}" + "=" * 78 + f"{RESET}")
    print(f"{CYAN}{BOLD}  STIX 2.1 THREAT-INTEL BUNDLE{RESET}")
    print(f"{CYAN}{BOLD}" + "=" * 78 + f"{RESET}")
    print(f"  bundle id:     {GREEN}{data.get('id', '?')}{RESET}")
    objects = data.get("objects", [])
    types = sorted({o.get("type", "?") for o in objects})
    print(f"  total objects: {GREEN}{len(objects)}{RESET}")
    print(f"  types:         {GREEN}{', '.join(types)}{RESET}")
    print(f"  spec_version:  {GREEN}{objects[0].get('spec_version', '?') if objects else '?'}{RESET}")
    print(f"  {DIM}Ready to ingest into MISP / OpenCTI / ThreatConnect{RESET}")
    return True


def main():
    clear()
    banner()

    seen_pos = 0
    finished_grace = 0
    last_event_time = time.time()

    # Wait up to 60s for claude to actually start calling tools
    startup_deadline = time.time() + 60
    while not AUDIT.exists():
        if time.time() > startup_deadline:
            print(f"{YELLOW}  (waiting for audit trail to appear…){RESET}")
            startup_deadline = time.time() + 60
        time.sleep(0.5)

    # Stream new lines
    while True:
        if AUDIT.exists():
            size = AUDIT.stat().st_size
            if size > seen_pos:
                with AUDIT.open("r", encoding="utf-8", errors="replace") as f:
                    f.seek(seen_pos)
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except ValueError:
                            continue
                        print(pretty_event(entry))
                    seen_pos = f.tell()
                last_event_time = time.time()

        # Once we've seen events but no new ones for 15 s and a report exists,
        # assume claude is done and show the final artifacts
        idle = time.time() - last_event_time
        if seen_pos > 0 and idle > 15 and REPORT.exists():
            finished_grace += 1
            if finished_grace >= 3:
                break

        time.sleep(0.5)

    show_report()
    show_stix()

    print()
    print(f"{CYAN}{BOLD}" + "=" * 78 + f"{RESET}")
    print(f"{CYAN}{BOLD}  INVESTIGATION COMPLETE{RESET}")
    print(f"{CYAN}{BOLD}" + "=" * 78 + f"{RESET}")
    print()
    print(f"  {DIM}All outputs in:{RESET} {REPO / 'output'}")
    print(f"  {DIM}Audit trail:{RESET}    output/audit_trail.jsonl")
    print(f"  {DIM}Findings DB:{RESET}    output/findings.db")
    print(f"  {DIM}IR report:{RESET}      output/ir_report.md")
    print(f"  {DIM}STIX bundle:{RESET}    output/bundle.stix.json")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted.{RESET}")
        sys.exit(0)
