"""Tests for YARA scanning tool."""

import pytest

from find_evil.tools.yara_scan import SIMULATED_MATCHES, BUILTIN_RULES_SOURCE


class TestSimulatedYaraMatches:

    def test_has_matches(self):
        assert len(SIMULATED_MATCHES) >= 4

    def test_all_matches_have_required_fields(self):
        for m in SIMULATED_MATCHES:
            assert "rule" in m
            assert "severity" in m
            assert "mitre" in m
            assert "file" in m
            assert "matched_strings" in m

    def test_has_critical_severity(self):
        critical = [m for m in SIMULATED_MATCHES if m["severity"] == "critical"]
        assert len(critical) >= 2  # shellcode + C2 IP

    def test_has_high_severity(self):
        high = [m for m in SIMULATED_MATCHES if m["severity"] == "high"]
        assert len(high) >= 2  # encoded powershell + DLL temp path

    def test_mitre_techniques_present(self):
        techniques = {m["mitre"] for m in SIMULATED_MATCHES}
        assert "T1059.001" in techniques  # PowerShell
        assert "T1055.001" in techniques  # Process injection
        assert "T1071.001" in techniques  # Web protocols (C2)

    def test_c2_ip_detected(self):
        c2_matches = [
            m for m in SIMULATED_MATCHES
            if m["rule"] == "C2_IP_Indicator"
        ]
        assert len(c2_matches) >= 1
        strings_data = [
            s["data"] for m in c2_matches for s in m["matched_strings"]
        ]
        assert any("185.220.101.34" in d for d in strings_data)

    def test_shellcode_detected(self):
        shellcode = [
            m for m in SIMULATED_MATCHES
            if m["rule"] == "Cobalt_Strike_Shellcode_Pattern"
        ]
        assert len(shellcode) >= 1


class TestBuiltinRules:

    def test_rules_source_is_valid_string(self):
        assert isinstance(BUILTIN_RULES_SOURCE, str)
        assert len(BUILTIN_RULES_SOURCE) > 100

    def test_rules_contain_expected_rule_names(self):
        assert "Suspicious_PowerShell_Encoded" in BUILTIN_RULES_SOURCE
        assert "Suspicious_DLL_Temp_Path" in BUILTIN_RULES_SOURCE
        assert "Cobalt_Strike_Shellcode_Pattern" in BUILTIN_RULES_SOURCE
        assert "C2_IP_Indicator" in BUILTIN_RULES_SOURCE

    def test_rules_have_mitre_metadata(self):
        assert "T1059.001" in BUILTIN_RULES_SOURCE
        assert "T1055.001" in BUILTIN_RULES_SOURCE
        assert "T1071.001" in BUILTIN_RULES_SOURCE

    def test_rules_compile_with_yara(self):
        """Only runs if yara-python is installed."""
        try:
            import yara
        except ImportError:
            pytest.skip("yara-python not installed")

        rules = yara.compile(source=BUILTIN_RULES_SOURCE)
        assert rules is not None
