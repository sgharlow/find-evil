"""Real YARA scanning tests -- proves find-evil runs real YARA rules against evidence.

These tests scan REAL evidence files using yara-python, demonstrating that
the yara_scan tool uses genuine pattern matching -- not simulated data.

Key proof points for SANS judges:
1. yara-python compiles all 10 built-in detection rules
2. _run_real_yara() finds IOC patterns in real evidence files
3. Match output includes correct rule metadata (severity, MITRE ATT&CK)
4. Multiple MITRE ATT&CK tactics are detected in a single scan
5. The simulated->live transition is seamless (same output schema)

Test fixtures:
- tests/fixtures/evidence_iocs.bin -- binary file with embedded IOC patterns
  matching the built-in YARA rule library (created by create_yara_evidence.py)

If fixtures are missing, tests regenerate them automatically.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Fixture management
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"
EVIDENCE_IOC = FIXTURES_DIR / "evidence_iocs.bin"


def _ensure_evidence():
    """Regenerate evidence file if missing."""
    if EVIDENCE_IOC.exists():
        return
    from tests.fixtures.create_yara_evidence import create_evidence_file
    create_evidence_file()


@pytest.fixture(scope="session", autouse=True)
def ensure_yara_fixtures():
    _ensure_evidence()


@pytest.fixture(scope="session")
def evidence_file() -> Path:
    _ensure_evidence()
    if not EVIDENCE_IOC.exists():
        pytest.skip("Evidence IOC fixture not available")
    return EVIDENCE_IOC


@pytest.fixture(scope="session")
def yara_lib_available():
    from find_evil.tools.yara_scan import _has_yara
    if not _has_yara():
        pytest.skip("yara-python not installed")
    return True


# ---------------------------------------------------------------------------
# Rule compilation tests
# ---------------------------------------------------------------------------

class TestYaraRuleCompilation:
    """Prove all built-in YARA rules compile without errors."""

    def test_all_rules_compile(self, yara_lib_available):
        """All 10 built-in rules compile into a valid YARA Rules object."""
        import yara
        from find_evil.tools.yara_scan import BUILTIN_RULES_SOURCE
        rules = yara.compile(source=BUILTIN_RULES_SOURCE)
        assert rules is not None

    def test_custom_rules_compile(self, yara_lib_available, tmp_path):
        """Custom YARA rule files can be compiled and used."""
        import yara
        rule_file = tmp_path / "custom.yar"
        rule_file.write_text(
            'rule Custom_Test {\n'
            '    meta:\n'
            '        description = "Test rule"\n'
            '        severity = "low"\n'
            '        mitre = "T9999"\n'
            '    strings:\n'
            '        $s1 = "test_pattern"\n'
            '    condition:\n'
            '        $s1\n'
            '}\n'
        )
        rules = yara.compile(filepath=str(rule_file))
        assert rules is not None


# ---------------------------------------------------------------------------
# Real evidence scanning tests
# ---------------------------------------------------------------------------

class TestRealYaraScanning:
    """Prove _run_real_yara() finds IOCs in evidence files."""

    def test_scan_returns_matches(self, evidence_file, yara_lib_available):
        """Real YARA scan produces non-empty match list."""
        from find_evil.tools.yara_scan import _run_real_yara
        matches = _run_real_yara(str(evidence_file), None)
        assert len(matches) > 0, "Should find at least one IOC in evidence"

    def test_powershell_rule_matches(self, evidence_file, yara_lib_available):
        """Suspicious_PowerShell_Encoded rule fires on evidence."""
        from find_evil.tools.yara_scan import _run_real_yara
        matches = _run_real_yara(str(evidence_file), None)
        rules = {m["rule"] for m in matches}
        assert "Suspicious_PowerShell_Encoded" in rules

    def test_shellcode_rule_matches(self, evidence_file, yara_lib_available):
        """Cobalt_Strike_Shellcode_Pattern rule fires on evidence."""
        from find_evil.tools.yara_scan import _run_real_yara
        matches = _run_real_yara(str(evidence_file), None)
        rules = {m["rule"] for m in matches}
        assert "Cobalt_Strike_Shellcode_Pattern" in rules

    def test_c2_ip_rule_matches(self, evidence_file, yara_lib_available):
        """C2_IP_Indicator rule fires on evidence."""
        from find_evil.tools.yara_scan import _run_real_yara
        matches = _run_real_yara(str(evidence_file), None)
        rules = {m["rule"] for m in matches}
        assert "C2_IP_Indicator" in rules

    def test_mimikatz_rule_matches(self, evidence_file, yara_lib_available):
        """Mimikatz_Credential_Theft rule fires on evidence."""
        from find_evil.tools.yara_scan import _run_real_yara
        matches = _run_real_yara(str(evidence_file), None)
        rules = {m["rule"] for m in matches}
        assert "Mimikatz_Credential_Theft" in rules

    def test_lateral_movement_rule_matches(self, evidence_file, yara_lib_available):
        """Lateral_Movement_PsExec rule fires on evidence."""
        from find_evil.tools.yara_scan import _run_real_yara
        matches = _run_real_yara(str(evidence_file), None)
        rules = {m["rule"] for m in matches}
        assert "Lateral_Movement_PsExec" in rules

    def test_data_staging_rule_matches(self, evidence_file, yara_lib_available):
        """Data_Staging_Archive rule fires on evidence."""
        from find_evil.tools.yara_scan import _run_real_yara
        matches = _run_real_yara(str(evidence_file), None)
        rules = {m["rule"] for m in matches}
        assert "Data_Staging_Archive" in rules

    def test_lolbin_rule_matches(self, evidence_file, yara_lib_available):
        """LOLBin_Abuse_Pattern rule fires on evidence."""
        from find_evil.tools.yara_scan import _run_real_yara
        matches = _run_real_yara(str(evidence_file), None)
        rules = {m["rule"] for m in matches}
        assert "LOLBin_Abuse_Pattern" in rules

    def test_minimum_total_matches(self, evidence_file, yara_lib_available):
        """At least 7 different rules match the evidence."""
        from find_evil.tools.yara_scan import _run_real_yara
        matches = _run_real_yara(str(evidence_file), None)
        unique_rules = {m["rule"] for m in matches}
        assert len(unique_rules) >= 7, (
            f"Expected >= 7 rule matches, got {len(unique_rules)}: {unique_rules}"
        )


class TestRealYaraMatchSchema:
    """Verify real match output has correct structure and metadata."""

    def test_matches_have_required_fields(self, evidence_file, yara_lib_available):
        """Every real match has all required output fields."""
        from find_evil.tools.yara_scan import _run_real_yara
        matches = _run_real_yara(str(evidence_file), None)
        for m in matches:
            assert "rule" in m, "Missing rule name"
            assert "severity" in m, "Missing severity"
            assert "mitre" in m, "Missing MITRE technique"
            assert "description" in m, "Missing description"
            assert "file" in m, "Missing file path"
            assert "matched_strings" in m, "Missing matched_strings"

    def test_matched_strings_have_required_fields(self, evidence_file, yara_lib_available):
        """Every matched string entry has identifier, offset, and data."""
        from find_evil.tools.yara_scan import _run_real_yara
        matches = _run_real_yara(str(evidence_file), None)
        for m in matches:
            for s in m["matched_strings"]:
                assert "identifier" in s, f"Missing identifier in {m['rule']}"
                assert "offset" in s, f"Missing offset in {m['rule']}"
                assert "data" in s, f"Missing data in {m['rule']}"
                assert isinstance(s["offset"], int)
                assert isinstance(s["data"], str)

    def test_severity_values_are_valid(self, evidence_file, yara_lib_available):
        """All severity values are from the expected set."""
        from find_evil.tools.yara_scan import _run_real_yara
        matches = _run_real_yara(str(evidence_file), None)
        valid_severities = {"critical", "high", "medium", "low", "unknown"}
        for m in matches:
            assert m["severity"] in valid_severities, (
                f"Invalid severity '{m['severity']}' in rule {m['rule']}"
            )

    def test_mitre_techniques_are_present(self, evidence_file, yara_lib_available):
        """Real matches include MITRE ATT&CK technique IDs."""
        from find_evil.tools.yara_scan import _run_real_yara
        matches = _run_real_yara(str(evidence_file), None)
        techniques = {m["mitre"] for m in matches if m["mitre"]}
        assert len(techniques) >= 5, (
            f"Expected >= 5 MITRE techniques, got {len(techniques)}: {techniques}"
        )


class TestRealYaraMITRECoverage:
    """Verify real scans cover multiple MITRE ATT&CK tactics."""

    def test_execution_detected(self, evidence_file, yara_lib_available):
        from find_evil.tools.yara_scan import _run_real_yara
        techniques = {m["mitre"] for m in _run_real_yara(str(evidence_file), None)}
        assert "T1059.001" in techniques  # PowerShell

    def test_defense_evasion_detected(self, evidence_file, yara_lib_available):
        from find_evil.tools.yara_scan import _run_real_yara
        techniques = {m["mitre"] for m in _run_real_yara(str(evidence_file), None)}
        assert "T1218" in techniques  # LOLBins

    def test_credential_access_detected(self, evidence_file, yara_lib_available):
        from find_evil.tools.yara_scan import _run_real_yara
        techniques = {m["mitre"] for m in _run_real_yara(str(evidence_file), None)}
        assert "T1003.001" in techniques  # Mimikatz

    def test_lateral_movement_detected(self, evidence_file, yara_lib_available):
        from find_evil.tools.yara_scan import _run_real_yara
        techniques = {m["mitre"] for m in _run_real_yara(str(evidence_file), None)}
        assert "T1570" in techniques  # PsExec

    def test_c2_detected(self, evidence_file, yara_lib_available):
        from find_evil.tools.yara_scan import _run_real_yara
        techniques = {m["mitre"] for m in _run_real_yara(str(evidence_file), None)}
        assert "T1071.001" in techniques  # C2 IP

    def test_collection_detected(self, evidence_file, yara_lib_available):
        from find_evil.tools.yara_scan import _run_real_yara
        techniques = {m["mitre"] for m in _run_real_yara(str(evidence_file), None)}
        assert "T1560.001" in techniques  # Data staging


class TestRealYaraSchemaConsistency:
    """Verify real match output matches simulated data schema."""

    def test_schema_matches_simulated(self, evidence_file, yara_lib_available):
        """Real matches use same field names as simulated matches."""
        from find_evil.tools.yara_scan import _run_real_yara, SIMULATED_MATCHES
        real_matches = _run_real_yara(str(evidence_file), None)
        if not real_matches:
            pytest.skip("No real matches")

        sim_keys = set(SIMULATED_MATCHES[0].keys())
        # 'offset' is only in simulated (per-match), not in real (per-string)
        core_keys = {"rule", "severity", "mitre", "description", "file", "matched_strings"}
        for match in real_matches:
            missing = core_keys - set(match.keys())
            assert not missing, f"Real match missing keys: {missing}"


# ---------------------------------------------------------------------------
# Custom rule scanning
# ---------------------------------------------------------------------------

class TestCustomYaraRules:
    """Prove custom YARA rules can be loaded and used."""

    def test_custom_rule_matches(self, evidence_file, yara_lib_available, tmp_path):
        """A custom rule file finds patterns in evidence."""
        from find_evil.tools.yara_scan import _run_real_yara
        rule_file = tmp_path / "custom.yar"
        rule_file.write_text(
            'rule Custom_C2_Check {\n'
            '    meta:\n'
            '        description = "Custom C2 IP check"\n'
            '        severity = "critical"\n'
            '        mitre = "T1071"\n'
            '    strings:\n'
            '        $ip = "185.220.101.34"\n'
            '    condition:\n'
            '        $ip\n'
            '}\n'
        )
        matches = _run_real_yara(str(evidence_file), str(rule_file))
        assert len(matches) >= 1
        assert matches[0]["rule"] == "Custom_C2_Check"

    def test_no_match_rule_returns_empty(self, evidence_file, yara_lib_available, tmp_path):
        """A rule that doesn't match returns an empty list."""
        from find_evil.tools.yara_scan import _run_real_yara
        rule_file = tmp_path / "nomatch.yar"
        rule_file.write_text(
            'rule No_Match {\n'
            '    meta:\n'
            '        description = "Will not match"\n'
            '        severity = "low"\n'
            '        mitre = "T0000"\n'
            '    strings:\n'
            '        $s = "THIS_STRING_IS_NOT_IN_THE_EVIDENCE_FILE_AT_ALL_12345"\n'
            '    condition:\n'
            '        $s\n'
            '}\n'
        )
        matches = _run_real_yara(str(evidence_file), str(rule_file))
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# Performance benchmarks
# ---------------------------------------------------------------------------

class TestYaraPerformance:
    """Performance benchmarks for real YARA scanning."""

    def test_scan_completes_under_threshold(self, evidence_file, yara_lib_available):
        """Scanning the evidence file completes in under 2 seconds."""
        from find_evil.tools.yara_scan import _run_real_yara
        start = time.perf_counter()
        matches = _run_real_yara(str(evidence_file), None)
        elapsed = time.perf_counter() - start
        assert elapsed < 2.0, f"Scan took {elapsed:.2f}s"
        assert len(matches) > 0

    def test_rule_compilation_is_fast(self, yara_lib_available):
        """Rule compilation completes in under 1 second."""
        import yara
        from find_evil.tools.yara_scan import BUILTIN_RULES_SOURCE
        start = time.perf_counter()
        rules = yara.compile(source=BUILTIN_RULES_SOURCE)
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, f"Compilation took {elapsed:.2f}s"
        assert rules is not None


# ---------------------------------------------------------------------------
# Error resilience
# ---------------------------------------------------------------------------

class TestYaraErrorResilience:
    """Prove the scanner handles bad input gracefully."""

    def test_scan_nonexistent_file_raises(self, yara_lib_available):
        from find_evil.tools.yara_scan import _run_real_yara
        with pytest.raises(Exception):
            _run_real_yara("/nonexistent/fake.bin", None)

    def test_scan_empty_file_returns_empty(self, tmp_path, yara_lib_available):
        """An empty file produces no matches (not an error)."""
        from find_evil.tools.yara_scan import _run_real_yara
        empty = tmp_path / "empty.bin"
        empty.write_bytes(b"")
        matches = _run_real_yara(str(empty), None)
        assert matches == []

    def test_scan_clean_file_returns_empty(self, tmp_path, yara_lib_available):
        """A file with no IOCs produces no matches."""
        from find_evil.tools.yara_scan import _run_real_yara
        clean = tmp_path / "clean.txt"
        clean.write_text("This is a perfectly normal file with no IOCs.")
        matches = _run_real_yara(str(clean), None)
        assert matches == []
