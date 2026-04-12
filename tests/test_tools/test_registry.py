"""Tests for Registry analysis tool."""

import pytest

from find_evil.tools.registry import (
    _is_suspicious_registry,
    _get_simulated_registry,
    SIMULATED_RUN_KEYS,
    SIMULATED_SERVICES,
    SIMULATED_USERASSIST,
)


class TestSuspiciousRegistryDetection:

    def test_rundll32_in_run_key_is_suspicious(self):
        entry = {"value_data": "rundll32.exe C:\\Users\\x\\AppData\\Local\\Temp\\bad.dll"}
        assert _is_suspicious_registry(entry) is True

    def test_normal_run_key_is_not_suspicious(self):
        entry = {"value_data": "C:\\Windows\\System32\\SecurityHealthSystray.exe"}
        assert _is_suspicious_registry(entry) is False

    def test_service_from_temp_is_suspicious(self):
        entry = {"image_path": "C:\\Users\\victim\\AppData\\Local\\Temp\\update.dll"}
        assert _is_suspicious_registry(entry) is True

    def test_normal_service_is_not_suspicious(self):
        entry = {"image_path": "C:\\Windows\\system32\\svchost.exe -k LocalService"}
        assert _is_suspicious_registry(entry) is False

    def test_high_cmd_run_count_is_suspicious(self):
        entry = {"program": "C:\\Windows\\System32\\cmd.exe", "run_count": 18}
        assert _is_suspicious_registry(entry) is True

    def test_low_cmd_run_count_is_not_suspicious(self):
        entry = {"program": "C:\\Windows\\System32\\cmd.exe", "run_count": 3}
        assert _is_suspicious_registry(entry) is False

    def test_chrome_userassist_is_not_suspicious(self):
        entry = {"program": "C:\\Program Files\\Google\\Chrome\\chrome.exe", "run_count": 244}
        assert _is_suspicious_registry(entry) is False


class TestSimulatedRegistryData:

    def test_run_keys_have_suspicious_entry(self):
        suspicious = [e for e in SIMULATED_RUN_KEYS if e.get("suspicious")]
        assert len(suspicious) >= 1
        # Should reference the attack DLL
        assert any("update.dll" in e.get("value_data", "") for e in suspicious)

    def test_services_have_suspicious_entry(self):
        suspicious = [e for e in SIMULATED_SERVICES if e.get("suspicious")]
        assert len(suspicious) >= 1
        assert any("update.dll" in e.get("image_path", "") for e in suspicious)

    def test_userassist_has_suspicious_execution(self):
        suspicious = [e for e in SIMULATED_USERASSIST if e.get("suspicious")]
        assert len(suspicious) >= 2  # cmd.exe + powershell

    def test_query_type_filters_correctly(self):
        run_only = _get_simulated_registry("run_keys")
        services_only = _get_simulated_registry("services")
        all_entries = _get_simulated_registry("all")

        assert len(run_only) == len(SIMULATED_RUN_KEYS)
        assert len(services_only) == len(SIMULATED_SERVICES)
        assert len(all_entries) == len(SIMULATED_RUN_KEYS) + len(SIMULATED_SERVICES) + len(SIMULATED_USERASSIST)

    def test_persistence_timestamps_match_attack_window(self):
        """Suspicious registry entries should be timestamped during the attack."""
        for entry in SIMULATED_RUN_KEYS + SIMULATED_SERVICES:
            if entry.get("suspicious"):
                ts = entry.get("last_modified", "")
                assert ts >= "2024-01-15T14:00:00Z", f"Suspicious entry at {ts} is before attack window"
