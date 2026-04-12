"""Tests for EVTX parsing tool."""

import pytest

from find_evil.tools.evtx import _is_suspicious_event, SIMULATED_EVENTS


class TestSuspiciousEventDetection:

    def test_failed_logon_is_suspicious(self):
        event = {"EventID": 4625, "TimeCreated": "2024-01-15T14:19:01Z"}
        assert _is_suspicious_event(event) is True

    def test_normal_logon_is_not_suspicious(self):
        event = {"EventID": 4624, "LogonType": 2, "TimeCreated": "2024-01-15T09:00:00Z"}
        assert _is_suspicious_event(event) is False

    def test_process_creation_with_bypass_is_suspicious(self):
        event = {
            "EventID": 4688,
            "CommandLine": "powershell -ep bypass -nop -w hidden -enc ...",
        }
        assert _is_suspicious_event(event) is True

    def test_normal_process_creation_is_not_suspicious(self):
        event = {
            "EventID": 4688,
            "CommandLine": "notepad.exe C:\\Users\\jsmith\\Document.txt",
        }
        assert _is_suspicious_event(event) is False

    def test_service_install_from_temp_is_suspicious(self):
        event = {
            "EventID": 7045,
            "ImagePath": "C:\\Users\\victim\\AppData\\Local\\Temp\\update.dll",
        }
        assert _is_suspicious_event(event) is True

    def test_normal_service_is_not_suspicious(self):
        event = {
            "EventID": 7045,
            "ImagePath": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
        }
        assert _is_suspicious_event(event) is False


class TestSimulatedEventData:

    def test_has_events(self):
        assert len(SIMULATED_EVENTS) > 0

    def test_has_suspicious_events(self):
        suspicious = [e for e in SIMULATED_EVENTS if _is_suspicious_event(e)]
        assert len(suspicious) >= 4  # failed logons + process creation + service install

    def test_attack_timeline_is_coherent(self):
        """Attack events should be after normal events."""
        attack_events = [
            e for e in SIMULATED_EVENTS
            if _is_suspicious_event(e) and e.get("EventID") == 4688
        ]
        normal_logon = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4624 and not _is_suspicious_event(e)
        ]
        if attack_events and normal_logon:
            assert attack_events[0]["TimeCreated"] > normal_logon[0]["TimeCreated"]
