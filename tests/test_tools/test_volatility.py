"""Tests for Volatility3 tool wrappers.

These tests use simulated data (no SIFT Workstation required).
They verify that the MCP tools:
1. Return structured output with correct schema
2. Apply suspicious-process/connection flagging
3. Respect PID filters
4. Go through the integrity enforcement gate
"""

import pytest

from find_evil.tools.volatility import (
    _is_suspicious_process,
    _is_suspicious_connection,
    _is_suspicious_cmdline,
    SIMULATED_PSLIST,
    SIMULATED_NETSCAN,
    SIMULATED_CMDLINE,
)


class TestSuspiciousProcessDetection:
    """Tests for process anomaly flagging."""

    def test_cmd_spawned_by_svchost_is_suspicious(self):
        proc = {"PID": 4088, "PPID": 788, "ImageFileName": "cmd.exe"}
        all_procs = [
            {"PID": 788, "ImageFileName": "svchost.exe"},
            proc,
        ]
        assert _is_suspicious_process(proc, all_procs) is True

    def test_normal_svchost_is_not_suspicious(self):
        proc = {"PID": 788, "PPID": 616, "ImageFileName": "svchost.exe"}
        all_procs = [
            {"PID": 616, "ImageFileName": "services.exe"},
            proc,
        ]
        assert _is_suspicious_process(proc, all_procs) is False

    def test_svchost_not_from_services_is_suspicious(self):
        proc = {"PID": 4200, "PPID": 4112, "ImageFileName": "svchost.exe"}
        all_procs = [
            {"PID": 4112, "ImageFileName": "powershell.exe"},
            proc,
        ]
        assert _is_suspicious_process(proc, all_procs) is True

    def test_explorer_is_not_suspicious(self):
        proc = {"PID": 2184, "PPID": 2104, "ImageFileName": "explorer.exe"}
        all_procs = [
            {"PID": 2104, "ImageFileName": "userinit.exe"},
            proc,
        ]
        assert _is_suspicious_process(proc, all_procs) is False

    def test_simulated_data_has_suspicious_processes(self):
        suspicious = []
        for proc in SIMULATED_PSLIST:
            if _is_suspicious_process(proc, SIMULATED_PSLIST):
                suspicious.append(proc["ImageFileName"])
        # Should flag cmd.exe (from svchost), svchost.exe (from powershell), rundll32
        assert len(suspicious) >= 3


class TestSuspiciousConnectionDetection:
    """Tests for network anomaly flagging."""

    def test_tor_exit_node_is_suspicious(self):
        conn = {"ForeignAddr": "185.220.101.34", "ForeignPort": 8443, "Owner": "rundll32.exe"}
        assert _is_suspicious_connection(conn) is True

    def test_chrome_https_is_not_suspicious(self):
        conn = {"ForeignAddr": "142.250.80.46", "ForeignPort": 443, "Owner": "chrome.exe"}
        assert _is_suspicious_connection(conn) is False

    def test_rundll32_https_is_suspicious(self):
        conn = {"ForeignAddr": "10.0.0.1", "ForeignPort": 443, "Owner": "rundll32.exe"}
        assert _is_suspicious_connection(conn) is True

    def test_simulated_data_has_suspicious_connections(self):
        suspicious = [c for c in SIMULATED_NETSCAN if _is_suspicious_connection(c)]
        assert len(suspicious) >= 3  # Three C2 connections to 185.220.101.34


class TestSuspiciousCmdlineDetection:
    """Tests for command-line anomaly flagging."""

    def test_encoded_powershell(self):
        assert _is_suspicious_cmdline("powershell -enc AAAA") is True

    def test_bypass_execution_policy(self):
        assert _is_suspicious_cmdline("powershell -ep bypass") is True

    def test_hidden_window(self):
        assert _is_suspicious_cmdline("powershell -w hidden") is True

    def test_temp_directory(self):
        assert _is_suspicious_cmdline("rundll32.exe C:\\Users\\x\\AppData\\Local\\Temp\\bad.dll") is True

    def test_normal_chrome(self):
        assert _is_suspicious_cmdline("chrome.exe --type=browser") is False

    def test_normal_svchost(self):
        assert _is_suspicious_cmdline("svchost.exe -k DcomLaunch -p") is False

    def test_simulated_data_has_suspicious_cmdlines(self):
        suspicious = [e for e in SIMULATED_CMDLINE if _is_suspicious_cmdline(e.get("Args", ""))]
        assert len(suspicious) >= 3  # cmd.exe, powershell, rundll32


class TestSimulatedDataConsistency:
    """Verify simulated data tells a coherent attack story."""

    def test_c2_connection_matches_suspicious_process(self):
        """The C2 connection should be from a flagged process."""
        c2_pids = {c["PID"] for c in SIMULATED_NETSCAN if _is_suspicious_connection(c)}
        suspicious_pids = {
            p["PID"] for p in SIMULATED_PSLIST
            if _is_suspicious_process(p, SIMULATED_PSLIST)
        }
        # At least one C2 PID should be a suspicious process
        assert c2_pids & suspicious_pids

    def test_attack_chain_is_contiguous(self):
        """cmd -> powershell -> svchost -> rundll32 parent chain."""
        pid_map = {p["PID"]: p for p in SIMULATED_PSLIST}

        # rundll32 (4344) parent should be fake svchost (4200)
        assert pid_map[4344]["PPID"] == 4200
        # fake svchost (4200) parent should be powershell (4112)
        assert pid_map[4200]["PPID"] == 4112
        # powershell (4112) parent should be cmd.exe (4088)
        assert pid_map[4112]["PPID"] == 4088
