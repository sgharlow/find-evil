#!/usr/bin/env python3
"""Populate the evidence/ directory with sample evidence files for live-mode demos.

Copies test fixtures and generates additional sample evidence so the Docker
SIFT container can demonstrate live-mode parsing (not simulated mode).

Usage:
    python evidence/populate_samples.py

This script is idempotent — safe to run multiple times.
"""

import shutil
import sys
from pathlib import Path

EVIDENCE_DIR = Path(__file__).parent
PROJECT_ROOT = EVIDENCE_DIR.parent
FIXTURES_DIR = PROJECT_ROOT / "tests" / "fixtures"


def copy_fixture(name: str, dest_name: str | None = None) -> bool:
    """Copy a test fixture into the evidence directory."""
    src = FIXTURES_DIR / name
    dst = EVIDENCE_DIR / (dest_name or name)
    if not src.exists():
        print(f"  SKIP  {name} (fixture not found — run create scripts first)")
        return False
    shutil.copy2(src, dst)
    print(f"  COPY  {src.name} -> evidence/{dst.name} ({dst.stat().st_size:,} bytes)")
    return True


def generate_iocs_bin() -> bool:
    """Generate evidence_iocs.bin using the fixture generator script."""
    script = FIXTURES_DIR / "create_yara_evidence.py"
    if not script.exists():
        print("  SKIP  evidence_iocs.bin (generator script not found)")
        return False

    # Import and run the generator, targeting evidence/ instead of fixtures/
    sys.path.insert(0, str(FIXTURES_DIR))
    try:
        from create_yara_evidence import create_evidence_file as _create
    except ImportError:
        print("  SKIP  evidence_iocs.bin (import failed)")
        return False
    finally:
        sys.path.pop(0)

    # The generator writes to fixtures dir — copy result to evidence/
    copy_fixture("evidence_iocs.bin")
    return True


def generate_registry_hives() -> bool:
    """Generate registry hive files using the fixture generator script."""
    script = FIXTURES_DIR / "create_test_hives.py"
    if not script.exists():
        print("  SKIP  Registry hives (generator script not found)")
        return False

    sys.path.insert(0, str(FIXTURES_DIR))
    try:
        from create_test_hives import create_forensic_test_hive
    except ImportError:
        print("  SKIP  Registry hives (import failed)")
        return False
    finally:
        sys.path.pop(0)

    system_path = str(EVIDENCE_DIR / "SYSTEM")
    software_path = str(EVIDENCE_DIR / "SOFTWARE")
    s1 = create_forensic_test_hive(system_path, "SYSTEM")
    s2 = create_forensic_test_hive(software_path, "SOFTWARE")
    print(f"  GEN   SYSTEM hive ({s1:,} bytes)")
    print(f"  GEN   SOFTWARE hive ({s2:,} bytes)")
    return True


def main():
    print("=" * 60)
    print("Populating evidence/ with sample files for live-mode demo")
    print("=" * 60)
    print()

    results = []

    # 1. EVTX file (real Windows Event Log)
    print("[1/4] Windows Event Log (.evtx)")
    results.append(copy_fixture("Application_small.evtx"))
    print()

    # 2. Registry hives (binary regf format)
    print("[2/4] Registry hives (SYSTEM, SOFTWARE)")
    results.append(generate_registry_hives())
    print()

    # 3. YARA evidence binary (IOC patterns)
    print("[3/4] YARA evidence binary (evidence_iocs.bin)")
    results.append(copy_fixture("evidence_iocs.bin"))
    print()

    # 4. Verify YARA rules file exists
    print("[4/4] YARA rules file (find_evil_rules.yar)")
    yar = EVIDENCE_DIR / "find_evil_rules.yar"
    if yar.exists():
        print(f"  OK    find_evil_rules.yar ({yar.stat().st_size:,} bytes)")
        results.append(True)
    else:
        print("  MISS  find_evil_rules.yar not found")
        results.append(False)
    print()

    # Summary
    print("=" * 60)
    passed = sum(1 for r in results if r)
    print(f"Done: {passed}/{len(results)} evidence types populated")
    print()
    print("Evidence files ready for Docker SIFT container:")
    for f in sorted(EVIDENCE_DIR.iterdir()):
        if f.name in ("README.md", "populate_samples.py"):
            continue
        if f.is_file():
            print(f"  /evidence/{f.name} ({f.stat().st_size:,} bytes)")
    print()
    print("To run in the Docker container:")
    print("  docker-compose -f docker-compose.sift.yml run --rm mcp-server \\")
    print("    python -c \"from find_evil.tools.yara_scan import _run_real_yara; \\")
    print("      print(_run_real_yara('/evidence/evidence_iocs.bin', '/evidence/find_evil_rules.yar'))\"")
    print("=" * 60)


if __name__ == "__main__":
    main()
