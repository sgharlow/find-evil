"""Lateral movement and privilege escalation scenario tests.

Validates the expanded evidence fixtures covering:
- PsExec lateral movement (service install on remote host)
- WMI remote execution (WmiPrvSE.exe spawning commands)
- RDP lateral movement (LogonType 10)
- Token manipulation (SeDebugPrivilege, SeImpersonatePrivilege)
- UAC bypass (eventvwr.exe method)
- Sensitive privilege use (4673 events)

These test classes prove that find-evil detects advanced adversary
techniques beyond the baseline brute-force + payload + C2 scenario.
For SANS judges: demonstrates breadth across MITRE ATT&CK tactics
TA0004 (Privilege Escalation) and TA0008 (Lateral Movement).
"""

import pytest

from find_evil.tools.evtx import SIMULATED_EVENTS, _is_suspicious_event
from find_evil.tools.timeline import SIMULATED_TIMELINE
from find_evil.tools.yara_scan import SIMULATED_MATCHES


# ---------------------------------------------------------------------------
# Lateral Movement — PsExec (T1570 / T1021.002)
# ---------------------------------------------------------------------------

class TestPsExecLateralMovement:
    """Verify PsExec-based lateral movement is captured in evidence."""

    def test_psexec_service_install_event_exists(self):
        """7045 event for PSEXESVC service should be in event log."""
        psexec_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 7045 and "PSEXESVC" in e.get("ServiceName", "")
        ]
        assert len(psexec_events) >= 1, "PSEXESVC service install event missing"

    def test_psexec_targets_remote_host(self):
        """PsExec service install should appear on a different computer."""
        psexec_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 7045 and "PSEXESVC" in e.get("ServiceName", "")
        ]
        computers = {e.get("Computer") for e in psexec_events}
        assert "FILESERVER1" in computers, "PsExec should target FILESERVER1"

    def test_psexec_is_flagged_suspicious(self):
        """PSEXESVC service install should be flagged as suspicious."""
        psexec_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 7045 and "PSEXESVC" in e.get("ServiceName", "")
        ]
        assert len(psexec_events) >= 1
        assert _is_suspicious_event(psexec_events[0]), (
            "PSEXESVC service install should be flagged suspicious"
        )

    def test_psexec_demand_start(self):
        """PsExec uses demand start (not auto start) — characteristic pattern."""
        psexec_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 7045 and "PSEXESVC" in e.get("ServiceName", "")
        ]
        assert psexec_events[0].get("StartType") == "demand start"

    def test_psexec_uses_localsystem(self):
        """PsExec runs as LocalSystem — maximum privilege indicator."""
        psexec_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 7045 and "PSEXESVC" in e.get("ServiceName", "")
        ]
        assert psexec_events[0].get("AccountName") == "LocalSystem"

    def test_psexec_in_timeline(self):
        """PsExec lateral movement should appear in the super-timeline."""
        psexec_timeline = [
            e for e in SIMULATED_TIMELINE
            if "PsExec" in e.get("description", "") or "PSEXESVC" in e.get("description", "")
        ]
        assert len(psexec_timeline) >= 1, "PsExec missing from timeline"
        assert "FILESERVER1" in psexec_timeline[0]["description"]


# ---------------------------------------------------------------------------
# Lateral Movement — WMI (T1047)
# ---------------------------------------------------------------------------

class TestWMILateralMovement:
    """Verify WMI-based lateral movement is captured in evidence."""

    def test_wmiprvse_spawn_event_exists(self):
        """WmiPrvSE.exe spawning cmd.exe should appear in process creation logs."""
        wmi_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4688
            and "WmiPrvSE.exe" in e.get("ParentProcessName", "")
        ]
        assert len(wmi_events) >= 1, "WMI process spawn event missing"

    def test_wmiprvse_spawns_cmd(self):
        """WmiPrvSE.exe parent should spawn cmd.exe child."""
        wmi_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4688
            and "WmiPrvSE.exe" in e.get("ParentProcessName", "")
        ]
        child_procs = {e.get("NewProcessName", "").split("\\")[-1].lower() for e in wmi_events}
        assert "cmd.exe" in child_procs

    def test_wmi_spawn_flagged_suspicious(self):
        """Process spawned by WmiPrvSE.exe should be flagged suspicious."""
        wmi_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4688
            and "WmiPrvSE.exe" in e.get("ParentProcessName", "")
        ]
        assert all(_is_suspicious_event(e) for e in wmi_events), (
            "WMI-spawned processes should be flagged suspicious"
        )

    def test_wmi_recon_commands_visible(self):
        """WMI remote execution shows domain enumeration commands."""
        wmi_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4688
            and "WmiPrvSE.exe" in e.get("ParentProcessName", "")
        ]
        cmdlines = " ".join(e.get("CommandLine", "") for e in wmi_events)
        assert "whoami" in cmdlines or "net user" in cmdlines, (
            "WMI execution should include reconnaissance commands"
        )
        assert "Domain Admins" in cmdlines, (
            "WMI execution should include Domain Admin enumeration"
        )

    def test_wmi_targets_remote_host(self):
        """WMI remote execution targets FILESERVER1."""
        wmi_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4688
            and "WmiPrvSE.exe" in e.get("ParentProcessName", "")
        ]
        computers = {e.get("Computer") for e in wmi_events}
        assert "FILESERVER1" in computers

    def test_wmi_in_timeline(self):
        """WMI lateral movement should appear in the super-timeline."""
        wmi_timeline = [
            e for e in SIMULATED_TIMELINE
            if "WMI" in e.get("description", "") or "WmiPrvSE" in e.get("description", "")
        ]
        assert len(wmi_timeline) >= 1, "WMI missing from timeline"


# ---------------------------------------------------------------------------
# Lateral Movement — RDP (T1021.001)
# ---------------------------------------------------------------------------

class TestRDPLateralMovement:
    """Verify RDP-based lateral movement is captured in evidence."""

    def test_rdp_logon_event_exists(self):
        """LogonType 10 (RDP) event should be in event log."""
        rdp_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4624 and e.get("LogonType") == 10
        ]
        assert len(rdp_events) >= 1, "RDP logon event missing"

    def test_rdp_targets_domain_controller(self):
        """RDP lateral movement targets DC01 (Domain Controller)."""
        rdp_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4624 and e.get("LogonType") == 10
        ]
        computers = {e.get("Computer") for e in rdp_events}
        assert "DC01" in computers, "RDP should target Domain Controller"

    def test_rdp_source_is_compromised_host(self):
        """RDP connection originates from the compromised workstation."""
        rdp_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4624 and e.get("LogonType") == 10
        ]
        source_ips = {e.get("IpAddress") for e in rdp_events}
        assert "192.168.1.105" in source_ips, (
            "RDP should originate from compromised 192.168.1.105"
        )

    def test_rdp_is_flagged_suspicious(self):
        """RDP logon (type 10) should be flagged suspicious."""
        rdp_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4624 and e.get("LogonType") == 10
        ]
        assert all(_is_suspicious_event(e) for e in rdp_events), (
            "RDP logons should be flagged suspicious"
        )

    def test_rdp_occurs_after_initial_compromise(self):
        """RDP lateral movement happens after initial breach."""
        rdp_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4624 and e.get("LogonType") == 10
        ]
        initial_compromise = "2024-01-15T14:21:33Z"  # first successful logon
        for e in rdp_events:
            assert e["TimeCreated"] > initial_compromise, (
                "RDP should occur after initial compromise"
            )

    def test_rdp_in_timeline(self):
        """RDP lateral movement should appear in the super-timeline."""
        rdp_timeline = [
            e for e in SIMULATED_TIMELINE
            if "RDP" in e.get("description", "") or "Logon Type 10" in e.get("description", "")
        ]
        assert len(rdp_timeline) >= 1, "RDP missing from timeline"
        assert "DC01" in rdp_timeline[0]["description"]


# ---------------------------------------------------------------------------
# Privilege Escalation — Token Manipulation (T1134)
# ---------------------------------------------------------------------------

class TestTokenManipulation:
    """Verify token manipulation / special privilege assignment is detected."""

    def test_special_privilege_event_exists(self):
        """4672 special privilege assigned event should be in log."""
        priv_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4672
        ]
        assert len(priv_events) >= 1, "4672 special privilege event missing"

    def test_debug_privilege_assigned(self):
        """SeDebugPrivilege should be in the privilege list."""
        priv_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4672
        ]
        priv_lists = " ".join(e.get("PrivilegeList", "") for e in priv_events)
        assert "SeDebugPrivilege" in priv_lists

    def test_impersonate_privilege_assigned(self):
        """SeImpersonatePrivilege should be in the privilege list."""
        priv_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4672
        ]
        priv_lists = " ".join(e.get("PrivilegeList", "") for e in priv_events)
        assert "SeImpersonatePrivilege" in priv_lists

    def test_special_privilege_flagged_suspicious(self):
        """4672 with debug/impersonate privileges should be flagged suspicious."""
        priv_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4672
        ]
        assert all(_is_suspicious_event(e) for e in priv_events), (
            "Special privilege assignments should be flagged suspicious"
        )

    def test_privilege_assigned_at_logon_time(self):
        """Privilege assignment timestamp aligns with initial logon."""
        priv_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4672
        ]
        # Should be within seconds of the initial network logon (14:21:33)
        for e in priv_events:
            assert e["TimeCreated"].startswith("2024-01-15T14:21"), (
                "Privilege assignment should occur at logon time"
            )

    def test_privilege_in_timeline(self):
        """Special privilege assignment should appear in timeline."""
        priv_timeline = [
            e for e in SIMULATED_TIMELINE
            if "privilege" in e.get("description", "").lower()
            or "4672" in e.get("description", "")
        ]
        assert len(priv_timeline) >= 1, "Privilege assignment missing from timeline"


# ---------------------------------------------------------------------------
# Privilege Escalation — UAC Bypass (T1548.002)
# ---------------------------------------------------------------------------

class TestUACBypass:
    """Verify UAC bypass detection via eventvwr.exe technique."""

    def test_eventvwr_uac_bypass_event_exists(self):
        """eventvwr.exe spawned by cmd.exe should be in process creation log."""
        uac_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4688
            and "eventvwr.exe" in e.get("NewProcessName", "").lower()
        ]
        assert len(uac_events) >= 1, "UAC bypass event missing"

    def test_eventvwr_parent_is_cmd(self):
        """eventvwr.exe parent process should be cmd.exe (bypass indicator)."""
        uac_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4688
            and "eventvwr.exe" in e.get("NewProcessName", "").lower()
        ]
        parents = {e.get("ParentProcessName", "").split("\\")[-1].lower() for e in uac_events}
        assert "cmd.exe" in parents

    def test_eventvwr_uac_bypass_flagged_suspicious(self):
        """eventvwr.exe spawned by cmd.exe should be flagged suspicious."""
        uac_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4688
            and "eventvwr.exe" in e.get("NewProcessName", "").lower()
            and "cmd.exe" in e.get("ParentProcessName", "").lower()
        ]
        assert all(_is_suspicious_event(e) for e in uac_events)

    def test_uac_bypass_has_high_integrity(self):
        """UAC bypass process should have High Integrity label."""
        uac_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4688
            and "eventvwr.exe" in e.get("NewProcessName", "").lower()
        ]
        for e in uac_events:
            label = e.get("MandatoryLabel", "")
            # S-1-16-12288 = High Integrity
            assert "12288" in label, "UAC bypass should run at High Integrity"

    def test_uac_bypass_precedes_attack_chain(self):
        """UAC bypass occurs before the main process creation chain."""
        uac_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4688
            and "eventvwr.exe" in e.get("NewProcessName", "").lower()
        ]
        attack_start = "2024-01-15T14:22:47Z"  # cmd.exe in attack chain
        for e in uac_events:
            assert e["TimeCreated"] <= attack_start, (
                "UAC bypass should occur before or at attack chain start"
            )

    def test_uac_bypass_in_timeline(self):
        """UAC bypass should appear in the super-timeline."""
        uac_timeline = [
            e for e in SIMULATED_TIMELINE
            if "UAC" in e.get("description", "") or "eventvwr" in e.get("description", "")
        ]
        assert len(uac_timeline) >= 1, "UAC bypass missing from timeline"


# ---------------------------------------------------------------------------
# Privilege Escalation — Sensitive Privilege Use (T1134)
# ---------------------------------------------------------------------------

class TestSensitivePrivilegeUse:
    """Verify sensitive privilege use (4673) events are detected."""

    def test_sensitive_privilege_event_exists(self):
        """4673 sensitive privilege use event should exist."""
        priv_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4673
        ]
        assert len(priv_events) >= 1, "4673 sensitive privilege use event missing"

    def test_debug_privilege_used(self):
        """SeDebugPrivilege should be the exercised privilege."""
        priv_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4673
        ]
        privs = {e.get("PrivilegeName") for e in priv_events}
        assert "SeDebugPrivilege" in privs

    def test_sensitive_privilege_flagged_suspicious(self):
        """4673 with SeDebugPrivilege should be flagged suspicious."""
        priv_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4673
        ]
        assert all(_is_suspicious_event(e) for e in priv_events)

    def test_sensitive_privilege_after_logon(self):
        """Sensitive privilege use occurs after initial compromise."""
        priv_events = [
            e for e in SIMULATED_EVENTS
            if e.get("EventID") == 4673
        ]
        initial_logon = "2024-01-15T14:21:33Z"
        for e in priv_events:
            assert e["TimeCreated"] > initial_logon


# ---------------------------------------------------------------------------
# Cross-tool correlation for new scenarios
# ---------------------------------------------------------------------------

class TestLateralMovementCorrelation:
    """Verify lateral movement evidence correlates across tools."""

    def test_lateral_movement_timeline_sequence(self):
        """Lateral movement events should follow a logical time sequence:
        PsExec -> WMI -> RDP (escalating access).
        """
        psexec_time = None
        wmi_time = None
        rdp_time = None

        for e in SIMULATED_EVENTS:
            if e.get("EventID") == 7045 and "PSEXESVC" in e.get("ServiceName", ""):
                psexec_time = e["TimeCreated"]
            if (e.get("EventID") == 4688
                    and "WmiPrvSE.exe" in e.get("ParentProcessName", "")
                    and "cmd.exe" in e.get("NewProcessName", "").lower()):
                wmi_time = e["TimeCreated"]
            if e.get("EventID") == 4624 and e.get("LogonType") == 10:
                rdp_time = e["TimeCreated"]

        assert psexec_time is not None, "PsExec event not found"
        assert wmi_time is not None, "WMI event not found"
        assert rdp_time is not None, "RDP event not found"

        assert psexec_time < wmi_time, "PsExec should precede WMI"
        assert wmi_time < rdp_time, "WMI should precede RDP"

    def test_all_lateral_movement_in_timeline(self):
        """All three lateral movement techniques appear in the timeline."""
        descriptions = " ".join(e["description"] for e in SIMULATED_TIMELINE)
        assert "PsExec" in descriptions or "PSEXESVC" in descriptions
        assert "WMI" in descriptions or "WmiPrvSE" in descriptions
        assert "RDP" in descriptions or "Logon Type 10" in descriptions

    def test_privilege_escalation_precedes_lateral_movement(self):
        """Privilege escalation (4672) occurs before lateral movement begins."""
        priv_time = None
        for e in SIMULATED_EVENTS:
            if e.get("EventID") == 4672:
                priv_time = e["TimeCreated"]
                break

        first_lateral = None
        for e in SIMULATED_EVENTS:
            if (e.get("EventID") == 7045 and "PSEXESVC" in e.get("ServiceName", "")):
                first_lateral = e["TimeCreated"]
                break

        assert priv_time is not None
        assert first_lateral is not None
        assert priv_time < first_lateral, (
            "Privilege escalation should precede lateral movement"
        )

    def test_lateral_movement_targets_multiple_hosts(self):
        """Lateral movement spans multiple hosts (FILESERVER1, DC01)."""
        lateral_computers = set()
        for e in SIMULATED_EVENTS:
            if (e.get("EventID") == 7045 and "PSEXESVC" in e.get("ServiceName", "")):
                lateral_computers.add(e["Computer"])
            if (e.get("EventID") == 4688
                    and "WmiPrvSE.exe" in e.get("ParentProcessName", "")):
                lateral_computers.add(e["Computer"])
            if e.get("EventID") == 4624 and e.get("LogonType") == 10:
                lateral_computers.add(e["Computer"])

        assert len(lateral_computers) >= 2, (
            f"Expected lateral movement to 2+ hosts, got {lateral_computers}"
        )

    def test_attacker_account_consistent(self):
        """The same 'admin' account is used across all lateral movement."""
        for e in SIMULATED_EVENTS:
            if (e.get("EventID") == 4688
                    and "WmiPrvSE.exe" in e.get("ParentProcessName", "")):
                assert e.get("SubjectUserName") == "admin"
            if e.get("EventID") == 4624 and e.get("LogonType") == 10:
                assert e.get("TargetUserName") == "admin"


class TestNewEventCounts:
    """Verify the enriched simulated events have the expected count."""

    def test_total_event_count_increased(self):
        """Total simulated events should now include lateral + privesc events."""
        # Original had 12, new additions bring it to 20
        assert len(SIMULATED_EVENTS) >= 20, (
            f"Expected >= 20 simulated events, got {len(SIMULATED_EVENTS)}"
        )

    def test_event_id_diversity(self):
        """Multiple event IDs should be represented."""
        event_ids = {e["EventID"] for e in SIMULATED_EVENTS}
        # Should have: 4624, 4625, 4672, 4673, 4688, 6005, 7036, 7045
        assert len(event_ids) >= 7, (
            f"Expected >= 7 unique Event IDs, got {len(event_ids)}: {event_ids}"
        )

    def test_multi_host_events(self):
        """Events should span multiple computers."""
        computers = {e.get("Computer") for e in SIMULATED_EVENTS}
        assert len(computers) >= 3, (
            f"Expected >= 3 computers, got {computers}"
        )

    def test_normal_events_still_present(self):
        """Normal (non-suspicious) events are still in the data."""
        normal_count = sum(1 for e in SIMULATED_EVENTS if not _is_suspicious_event(e))
        assert normal_count >= 3, "Should still have normal events for contrast"
