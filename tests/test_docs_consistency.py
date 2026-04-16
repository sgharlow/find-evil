"""Documentation consistency tests.

Validates that README.md, CLAUDE.md, and submission answers all accurately
reflect the actual codebase state. Catches drift between docs and code --
a common issue that undermines credibility with hackathon judges.

These tests are the documentation equivalent of integration tests: they
verify that claims made in user-facing docs match the reality of the
registered MCP tools, test files, and codebase structure.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).parent.parent
README_PATH = PROJECT_ROOT / "README.md"
CLAUDE_MD_PATH = PROJECT_ROOT / "CLAUDE.md"
SUBMISSION_PATH = PROJECT_ROOT / "docs" / "sans-submission-answers.md"
TESTS_DIR = PROJECT_ROOT / "tests"
TOOLS_DIR = PROJECT_ROOT / "src" / "find_evil" / "tools"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_registered_tools() -> set[str]:
    """Return the set of tool names registered in the live MCP server."""
    from find_evil.server import mcp
    return {t.name for t in mcp._tool_manager.list_tools()}


def _get_registered_tool_count() -> int:
    """Return the number of tools registered in the live MCP server."""
    return len(_get_registered_tools())


def _read_text(path: Path) -> str:
    """Read a text file, returning empty string if missing."""
    if path.exists():
        return path.read_text(encoding="utf-8", errors="replace")
    return ""


# ---------------------------------------------------------------------------
# 1. README tool list vs actual registered tools
# ---------------------------------------------------------------------------

class TestREADMEToolConsistency:
    """Verify README.md accurately describes the registered MCP tools."""

    def test_readme_exists(self):
        assert README_PATH.exists(), "README.md must exist"

    def test_all_registered_tools_mentioned_in_readme(self):
        """Every tool registered in the MCP server should be named in README.

        Allows partial matches (e.g., 'list_sealed' for 'list_sealed_evidence')
        since the ASCII architecture diagram uses abbreviated names.
        """
        readme = _read_text(README_PATH)
        tools = _get_registered_tools()
        missing = []
        for tool in sorted(tools):
            # Check full name or a recognizable prefix (>= 10 chars)
            if tool not in readme:
                # Allow partial match for truncated names in ASCII diagrams
                prefix = tool[:min(len(tool), 11)]
                if prefix not in readme:
                    missing.append(tool)
        assert not missing, (
            f"Tools registered in MCP but not mentioned in README: {missing}"
        )

    def test_readme_does_not_list_nonexistent_tools(self):
        """README should not claim tools that do not actually exist."""
        readme = _read_text(README_PATH)
        tools = _get_registered_tools()
        # Extract tool-like names from the README architecture diagram
        # Look for names in the tool listing section
        # Match patterns like "session_init", "vol_pslist", etc.
        tool_pattern = re.compile(r"\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\b")
        readme_tool_candidates = set(tool_pattern.findall(readme))
        # Filter to only those that look like tool names (snake_case, known prefixes)
        tool_prefixes = {"session_", "verify_", "list_", "reseal_", "vol_",
                         "parse_", "registry_", "build_", "yara_",
                         "submit_", "generate_", "export_"}
        readme_tool_names = {
            name for name in readme_tool_candidates
            if any(name.startswith(p) for p in tool_prefixes)
        }
        # Exclude known non-tool references:
        # - list_sealed: abbreviated form of list_sealed_evidence in ASCII diagram
        # - verify_all: internal EvidenceSession method, not an MCP tool
        known_non_tools = {"list_sealed", "verify_all", "require_active"}
        phantom = readme_tool_names - tools - known_non_tools
        assert not phantom, (
            f"README references tools that are not registered: {phantom}"
        )

    def test_readme_tool_count_matches_actual(self):
        """The tool count stated in README should match the actual count.

        The README currently says '15 tools' in the judging criteria table.
        This test ensures that number stays accurate.
        """
        readme = _read_text(README_PATH)
        actual_count = _get_registered_tool_count()
        # Check if the correct tool count appears in the README
        assert str(actual_count) in readme, (
            f"README should mention the actual tool count ({actual_count}). "
            f"Search the README for references to tool count."
        )

    def test_readme_mitre_technique_ids_are_valid(self):
        """MITRE ATT&CK technique IDs in README should follow the TXxxx.xxx pattern."""
        readme = _read_text(README_PATH)
        technique_pattern = re.compile(r"T\d{4}(?:\.\d{3})?")
        techniques = technique_pattern.findall(readme)
        assert len(techniques) >= 10, (
            f"Expected at least 10 MITRE technique references in README, found {len(techniques)}"
        )
        # Verify each one looks valid (T followed by 4 digits, optional .3 digits)
        for t in techniques:
            assert re.match(r"^T\d{4}(\.\d{3})?$", t), (
                f"Invalid MITRE technique format: {t}"
            )


# ---------------------------------------------------------------------------
# 2. CLAUDE.md tool list consistency
# ---------------------------------------------------------------------------

class TestCLAUDEMDConsistency:
    """Verify CLAUDE.md investigation protocol references valid tools."""

    def test_claude_md_exists(self):
        assert CLAUDE_MD_PATH.exists(), "CLAUDE.md must exist"

    def test_claude_md_tools_are_registered(self):
        """Every tool name referenced in CLAUDE.md must exist in the MCP registry."""
        claude_md = _read_text(CLAUDE_MD_PATH)
        tools = _get_registered_tools()
        # Extract tool references from CLAUDE.md (backtick-wrapped tool names)
        backtick_pattern = re.compile(r"`([a-z][a-z0-9_]+)`")
        referenced = set(backtick_pattern.findall(claude_md))
        # Filter to only those that look like tool function names
        tool_like = {r for r in referenced if "_" in r and not r.startswith("pip")}
        # Known non-tool references to exclude
        non_tools = {
            "verify_all", "session_id", "file_count", "require_active",
            "max_iter", "evidence_strength", "tool_call_start",
            "tool_call_complete", "finding_committed", "self_correction",
            "session_halt", "integrity_check", "hash_check_interval",
        }
        tool_like -= non_tools
        unregistered = tool_like - tools
        assert not unregistered, (
            f"CLAUDE.md references tools that are not registered: {unregistered}"
        )

    def test_claude_md_mentions_all_phases(self):
        """CLAUDE.md should describe all 7 investigation phases."""
        claude_md = _read_text(CLAUDE_MD_PATH)
        phases = ["Phase 0", "Phase 1", "Phase 2", "Phase 3",
                  "Phase 4", "Phase 5", "Phase 6", "Phase 7"]
        for phase in phases:
            assert phase in claude_md, f"Missing investigation phase: {phase}"

    def test_claude_md_mentions_drs_gate(self):
        """CLAUDE.md should document the DRS confidence gate."""
        claude_md = _read_text(CLAUDE_MD_PATH)
        assert "DRS" in claude_md
        assert "0.75" in claude_md
        assert "SELF_CORRECT" in claude_md or "SELF-CORRECT" in claude_md

    def test_claude_md_mentions_integrity_violation(self):
        """CLAUDE.md should document the evidence integrity violation protocol."""
        claude_md = _read_text(CLAUDE_MD_PATH)
        assert "EVIDENCE_INTEGRITY_VIOLATION" in claude_md


# ---------------------------------------------------------------------------
# 3. Test coverage: every tool has a corresponding test file
# ---------------------------------------------------------------------------

class TestToolTestCoverage:
    """Verify every MCP tool has corresponding tests."""

    def test_every_tool_module_has_test_file(self):
        """Each tool module in src/find_evil/tools/ should have a test file."""
        tool_modules = [
            f.stem for f in TOOLS_DIR.iterdir()
            if f.is_file() and f.suffix == ".py" and f.stem not in ("__init__", "_base")
        ]
        test_tools_dir = TESTS_DIR / "test_tools"
        test_files = {
            f.stem.replace("test_", "") for f in test_tools_dir.iterdir()
            if f.is_file() and f.suffix == ".py" and f.stem.startswith("test_")
        }
        missing = []
        for module in tool_modules:
            # Handle name variations (yara_scan -> yara)
            if module not in test_files and module.replace("_scan", "") not in test_files:
                missing.append(module)
        assert not missing, (
            f"Tool modules without test files: {missing}. "
            f"Available test files: {sorted(test_files)}"
        )

    def test_session_manager_has_tests(self):
        """Session manager (core component) must have dedicated tests."""
        assert (TESTS_DIR / "test_session_manager.py").exists()

    def test_hash_daemon_has_tests(self):
        """Hash daemon must have dedicated tests."""
        assert (TESTS_DIR / "test_hash_daemon.py").exists()

    def test_audit_logger_has_tests(self):
        """Audit logger must have dedicated tests."""
        assert (TESTS_DIR / "test_audit.py").exists()

    def test_drs_gate_has_tests(self):
        """DRS confidence gate must have dedicated tests."""
        assert (TESTS_DIR / "test_drs_gate.py").exists()

    def test_security_bypass_has_tests(self):
        """Security bypass testing must exist."""
        assert (TESTS_DIR / "test_security_bypass.py").exists()

    def test_integration_tests_exist(self):
        """Integration tests must exist."""
        assert (TESTS_DIR / "test_integration.py").exists()

    def test_scenario_tests_exist(self):
        """Full scenario (7-phase) tests must exist."""
        assert (TESTS_DIR / "test_scenario.py").exists()


# ---------------------------------------------------------------------------
# 4. Submission answers consistency
# ---------------------------------------------------------------------------

class TestSubmissionAnswersConsistency:
    """Verify sans-submission-answers.md references correct stats."""

    def test_submission_file_exists(self):
        assert SUBMISSION_PATH.exists(), "docs/sans-submission-answers.md must exist"

    def test_submission_mentions_correct_tool_count(self):
        """Submission answers should reference the actual tool count."""
        submission = _read_text(SUBMISSION_PATH)
        actual = _get_registered_tool_count()
        assert str(actual) in submission, (
            f"Submission should mention actual tool count ({actual})"
        )

    def test_submission_tool_names_match_registry(self):
        """Tool names listed in submission must match the MCP registry.

        Allows descriptive references (e.g., 'STIX export' for 'export_stix')
        in addition to exact tool name matches.
        """
        submission = _read_text(SUBMISSION_PATH)
        tools = _get_registered_tools()
        # Check that all registered tools appear in the submission (exact or descriptive)
        missing = []
        for t in sorted(tools):
            if t not in submission:
                # Allow descriptive references (both word orderings)
                words = t.split("_")
                descriptive_fwd = " ".join(words)
                descriptive_rev = " ".join(reversed(words))
                sub_lower = submission.lower()
                if descriptive_fwd not in sub_lower and descriptive_rev not in sub_lower:
                    missing.append(t)
        assert not missing, (
            f"Registered tools not mentioned in submission answers: {missing}"
        )

    def test_submission_mentions_stix(self):
        """Submission should mention STIX 2.1 export capability."""
        submission = _read_text(SUBMISSION_PATH)
        assert "STIX" in submission
        assert "2.1" in submission

    def test_submission_mentions_sha256(self):
        """Submission should mention SHA-256 evidence sealing."""
        submission = _read_text(SUBMISSION_PATH)
        assert "SHA-256" in submission

    def test_submission_mentions_drs_threshold(self):
        """Submission should reference the 0.75 DRS threshold."""
        submission = _read_text(SUBMISSION_PATH)
        assert "0.75" in submission

    def test_submission_mitre_techniques_are_valid(self):
        """MITRE technique IDs in submission should be valid format."""
        submission = _read_text(SUBMISSION_PATH)
        technique_pattern = re.compile(r"T\d{4}(?:\.\d{3})?")
        techniques = technique_pattern.findall(submission)
        assert len(techniques) >= 3, "Submission should reference multiple MITRE techniques"
        for t in techniques:
            assert re.match(r"^T\d{4}(\.\d{3})?$", t), f"Invalid format: {t}"

    def test_submission_references_evidence_extensions(self):
        """Submission should mention at least some evidence file extensions."""
        submission = _read_text(SUBMISSION_PATH)
        from find_evil.session.manager import EVIDENCE_EXTENSIONS
        mentioned = sum(1 for ext in EVIDENCE_EXTENSIONS if ext in submission)
        assert mentioned >= 3, (
            f"Submission should mention at least 3 evidence extensions, found {mentioned}"
        )


# ---------------------------------------------------------------------------
# 5. Cross-document consistency
# ---------------------------------------------------------------------------

class TestCrossDocumentConsistency:
    """Verify key facts are consistent across README, CLAUDE.md, and submission."""

    def test_drs_formula_consistent(self):
        """The DRS confidence formula should appear in both CLAUDE.md and submission."""
        claude_md = _read_text(CLAUDE_MD_PATH)
        submission = _read_text(SUBMISSION_PATH)
        # Both should reference the 0.6/0.4 weighting
        assert "0.6" in claude_md and "0.4" in claude_md, (
            "CLAUDE.md missing DRS formula weights"
        )
        assert "0.6" in submission and "0.4" in submission, (
            "Submission missing DRS formula weights"
        )

    def test_hash_daemon_interval_documented(self):
        """Hash daemon interval should be documented in README."""
        readme = _read_text(README_PATH)
        # README should mention the 30-second interval
        assert "30" in readme, "README should mention 30-second hash check interval"
        # CLAUDE.md focuses on investigation protocol, not implementation details,
        # so it may not mention the specific interval -- that is acceptable.

    def test_project_name_consistent(self):
        """Project name should be consistent across docs."""
        readme = _read_text(README_PATH)
        submission = _read_text(SUBMISSION_PATH)
        # Both should use "Evidence Integrity Enforcer"
        assert "Evidence Integrity Enforcer" in readme
        assert "Evidence Integrity Enforcer" in submission

    def test_c2_ip_consistent(self):
        """The C2 IP address used in the attack scenario should be consistent."""
        readme = _read_text(README_PATH)
        submission = _read_text(SUBMISSION_PATH)
        c2_ip = "185.220.101.34"
        assert c2_ip in readme, f"README should reference C2 IP {c2_ip}"
        assert c2_ip in submission, f"Submission should reference C2 IP {c2_ip}"

    def test_confidence_threshold_consistent(self):
        """The confidence threshold should be the same everywhere."""
        readme = _read_text(README_PATH)
        claude_md = _read_text(CLAUDE_MD_PATH)
        submission = _read_text(SUBMISSION_PATH)
        from find_evil.analysis.drs_gate import DRSGate
        gate = DRSGate()
        threshold_str = str(gate.threshold)
        assert threshold_str in claude_md, (
            f"CLAUDE.md threshold ({threshold_str}) mismatch"
        )
        assert threshold_str in submission, (
            f"Submission threshold ({threshold_str}) mismatch"
        )


# ---------------------------------------------------------------------------
# 6. Structural docs checks
# ---------------------------------------------------------------------------

class TestDocumentationStructure:
    """Verify required documentation files exist and have content."""

    @pytest.mark.parametrize("doc_file", [
        "docs/accuracy_report.md",
        "docs/dataset_documentation.md",
        "docs/evidence_integrity_approach.md",
        "docs/sans-submission-answers.md",
        "docs/try_it_out.md",
    ])
    def test_required_doc_exists(self, doc_file):
        """Each submission-required doc file must exist."""
        path = PROJECT_ROOT / doc_file
        assert path.exists(), f"Required doc file missing: {doc_file}"

    @pytest.mark.parametrize("doc_file", [
        "docs/accuracy_report.md",
        "docs/dataset_documentation.md",
        "docs/evidence_integrity_approach.md",
        "docs/sans-submission-answers.md",
        "docs/try_it_out.md",
    ])
    def test_required_doc_has_content(self, doc_file):
        """Each doc file must have meaningful content (not just a header)."""
        path = PROJECT_ROOT / doc_file
        content = path.read_text(encoding="utf-8", errors="replace")
        assert len(content) > 100, (
            f"{doc_file} has too little content ({len(content)} chars)"
        )

    def test_readme_has_quick_start(self):
        """README must have a Quick Start section."""
        readme = _read_text(README_PATH)
        assert "Quick Start" in readme or "quick start" in readme.lower()

    def test_readme_has_architecture_diagram(self):
        """README must have an architecture diagram (ASCII art block)."""
        readme = _read_text(README_PATH)
        assert "SIFT Workstation" in readme
        assert "Evidence Integrity MCP Server" in readme

    def test_readme_has_test_suite_section(self):
        """README must document the test suite."""
        readme = _read_text(README_PATH)
        assert "Test Suite" in readme or "test suite" in readme.lower()

    def test_readme_has_license(self):
        """README must mention the license."""
        readme = _read_text(README_PATH)
        assert "MIT" in readme or "License" in readme


# ---------------------------------------------------------------------------
# 7. Package metadata consistency
# ---------------------------------------------------------------------------

class TestPackageMetadataConsistency:
    """Verify pyproject.toml metadata is correct and entry point exists."""

    PYPROJECT_PATH = PROJECT_ROOT / "pyproject.toml"

    def test_pyproject_exists(self):
        """pyproject.toml must exist."""
        assert self.PYPROJECT_PATH.exists(), "pyproject.toml must exist"

    def test_pyproject_version_is_set(self):
        """pyproject.toml must have a non-empty version string."""
        content = _read_text(self.PYPROJECT_PATH)
        match = re.search(r'version\s*=\s*"([^"]+)"', content)
        assert match, "pyproject.toml must define a version"
        version = match.group(1)
        assert len(version) >= 5, (
            f"Version '{version}' looks too short — expected semver like '0.1.0'"
        )

    def test_pyproject_description_mentions_mcp_or_dfir(self):
        """pyproject.toml description should mention MCP or DFIR."""
        content = _read_text(self.PYPROJECT_PATH)
        match = re.search(r'description\s*=\s*"([^"]+)"', content)
        assert match, "pyproject.toml must define a description"
        desc = match.group(1).lower()
        assert "mcp" in desc or "dfir" in desc, (
            f"pyproject.toml description should mention MCP or DFIR, "
            f"got: '{match.group(1)}'"
        )

    def test_package_entry_point_exists(self):
        """The server entry point module must exist on disk."""
        entry_point = PROJECT_ROOT / "src" / "find_evil" / "server.py"
        assert entry_point.exists(), (
            "Entry point src/find_evil/server.py must exist"
        )

    def test_package_is_importable(self):
        """The find_evil package must be importable."""
        import find_evil
        assert hasattr(find_evil, "__path__"), (
            "find_evil must be a proper Python package"
        )
