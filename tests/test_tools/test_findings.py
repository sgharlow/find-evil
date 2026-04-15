"""Tests for IOC extraction and STIX 2.1 export."""

import json

import pytest

from find_evil.tools.findings import _extract_iocs, _stix_indicator


class TestIOCExtraction:
    """Test IOC pattern extraction from finding descriptions."""

    def test_extracts_public_ipv4(self):
        findings = [{"description": "Connection to C2 at 185.220.101.34 on port 8443"}]
        iocs = _extract_iocs(findings)
        assert "185.220.101.34" in iocs["ipv4"]

    def test_excludes_private_ipv4(self):
        findings = [{"description": "Local connection to 192.168.1.100 and 10.0.0.1"}]
        iocs = _extract_iocs(findings)
        assert len(iocs["ipv4"]) == 0

    def test_excludes_loopback_ipv4(self):
        findings = [{"description": "Listening on 127.0.0.1:4444"}]
        iocs = _extract_iocs(findings)
        assert len(iocs["ipv4"]) == 0

    def test_extracts_sha256_hash(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        findings = [{"description": f"Malicious binary with hash {h}"}]
        iocs = _extract_iocs(findings)
        assert h in iocs["sha256"]

    def test_extracts_md5_hash(self):
        findings = [{"description": "File hash: d41d8cd98f00b204e9800998ecf8427e"}]
        iocs = _extract_iocs(findings)
        assert "d41d8cd98f00b204e9800998ecf8427e" in iocs["md5"]

    def test_sha256_prefix_not_counted_as_md5(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        findings = [{"description": f"Hash: {h}"}]
        iocs = _extract_iocs(findings)
        # The first 32 chars of the SHA-256 should not appear as an MD5
        assert h[:32] not in iocs["md5"]

    def test_extracts_windows_file_path(self):
        findings = [{"description": r"Suspicious binary at C:\Windows\Temp\update.dll"}]
        iocs = _extract_iocs(findings)
        assert any("update.dll" in fp for fp in iocs["file_path"])

    def test_extracts_registry_key(self):
        findings = [{"description": r"Persistence via HKLM\Software\Microsoft\Windows\CurrentVersion\Run"}]
        iocs = _extract_iocs(findings)
        assert any("Run" in rk for rk in iocs["registry_key"])

    def test_empty_findings_returns_empty_iocs(self):
        iocs = _extract_iocs([])
        assert all(len(v) == 0 for v in iocs.values())

    def test_no_iocs_in_clean_description(self):
        findings = [{"description": "Process svchost.exe running with expected parameters"}]
        iocs = _extract_iocs(findings)
        assert len(iocs["ipv4"]) == 0
        assert len(iocs["sha256"]) == 0

    def test_multiple_iocs_from_single_finding(self):
        findings = [{"description": "C2 beacon to 203.0.113.50 and 198.51.100.25 via HTTPS"}]
        iocs = _extract_iocs(findings)
        assert "203.0.113.50" in iocs["ipv4"]
        assert "198.51.100.25" in iocs["ipv4"]

    def test_deduplicates_iocs_across_findings(self):
        findings = [
            {"description": "Connection to 185.220.101.34"},
            {"description": "Second connection to 185.220.101.34"},
        ]
        iocs = _extract_iocs(findings)
        assert len(iocs["ipv4"]) == 1


class TestSTIXIndicator:
    """Test STIX 2.1 indicator generation."""

    def test_ipv4_indicator_pattern(self):
        ind = _stix_indicator("ipv4", "185.220.101.34", ["finding-1"])
        assert ind["pattern"] == "[ipv4-addr:value = '185.220.101.34']"
        assert ind["type"] == "indicator"
        assert ind["spec_version"] == "2.1"

    def test_sha256_indicator_pattern(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ind = _stix_indicator("sha256", h, ["finding-1"])
        assert f"SHA-256" in ind["pattern"]
        assert h in ind["pattern"]

    def test_md5_indicator_pattern(self):
        ind = _stix_indicator("md5", "d41d8cd98f00b204e9800998ecf8427e", ["finding-1"])
        assert "MD5" in ind["pattern"]

    def test_file_path_indicator_extracts_filename(self):
        ind = _stix_indicator("file_path", r"C:\Windows\Temp\update.dll", ["finding-1"])
        assert "update.dll" in ind["pattern"]

    def test_registry_key_indicator_pattern(self):
        ind = _stix_indicator("registry_key", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", ["finding-1"])
        assert "windows-registry-key" in ind["pattern"]

    def test_indicator_has_deterministic_id(self):
        ind1 = _stix_indicator("ipv4", "185.220.101.34", ["f1"])
        ind2 = _stix_indicator("ipv4", "185.220.101.34", ["f2"])
        assert ind1["id"] == ind2["id"]  # uuid5 is deterministic

    def test_indicator_has_required_stix_fields(self):
        ind = _stix_indicator("ipv4", "1.2.3.4", ["f1"])
        for field in ["type", "spec_version", "id", "created", "modified", "name", "pattern", "pattern_type", "valid_from"]:
            assert field in ind, f"Missing required STIX field: {field}"

    def test_indicator_labels(self):
        ind = _stix_indicator("ipv4", "1.2.3.4", ["f1"])
        assert "malicious-activity" in ind["labels"]

    def test_indicator_external_reference(self):
        ind = _stix_indicator("ipv4", "1.2.3.4", ["finding-abc123"])
        refs = ind["external_references"]
        assert len(refs) == 1
        assert refs[0]["source_name"] == "find-evil"
