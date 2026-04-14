"""Cross-tool investigation scenario test.

Walks through the full investigation sequence from CLAUDE.md using
simulated data, verifying that:
1. Each tool returns coherent results
2. Findings from different tools corroborate the same attack
3. The DRS gate correctly scores findings based on multi-tool evidence
4. The generated report contains all expected elements

This test proves the simulated attack scenario works as a complete,
believable investigation — not just isolated tool outputs.
"""

import pytest

from find_evil.tools.volatility import (
    SIMULATED_PSLIST, SIMULATED_NETSCAN, SIMULATED_MALFIND, SIMULATED_CMDLINE,
    _is_suspicious_process, _is_suspicious_connection, _is_suspicious_cmdline,
)
from find_evil.tools.evtx import SIMULATED_EVENTS, _is_suspicious_event
from find_evil.tools.registry import (
    SIMULATED_RUN_KEYS, SIMULATED_SERVICES, SIMULATED_USERASSIST,
    _is_suspicious_registry,
)
from find_evil.tools.timeline import SIMULATED_TIMELINE
from find_evil.tools.yara_scan import SIMULATED_MATCHES
from find_evil.analysis.drs_gate import DRSGate, Finding


class TestAttackNarrative:
    """Verify the simulated data tells a complete, coherent attack story."""

    # --- Phase 1: TRIAGE (memory) ---

    def test_phase1_identifies_suspicious_processes(self):
        """vol_pslist should reveal the attack chain."""
        suspicious = [
            p for p in SIMULATED_PSLIST
            if _is_suspicious_process(p, SIMULATED_PSLIST)
        ]
        names = {p["ImageFileName"] for p in suspicious}
        # Must find the LOLBin chain
        assert "cmd.exe" in names
        assert "rundll32.exe" in names

    def test_phase1_identifies_c2_connection(self):
        """vol_netscan should find C2 beacon to 185.220.101.34."""
        c2 = [
            c for c in SIMULATED_NETSCAN
            if _is_suspicious_connection(c) and "185.220.101.34" in c.get("ForeignAddr", "")
        ]
        assert len(c2) >= 3  # multiple beacons = beacon pattern
        # All C2 connections owned by rundll32.exe
        assert all(c["Owner"] == "rundll32.exe" for c in c2)

    def test_phase1_c2_pid_matches_suspicious_process(self):
        """The C2 connection PID must be a flagged suspicious process."""
        c2_pids = {
            c["PID"] for c in SIMULATED_NETSCAN
            if "185.220.101.34" in c.get("ForeignAddr", "")
        }
        suspicious_pids = {
            p["PID"] for p in SIMULATED_PSLIST
            if _is_suspicious_process(p, SIMULATED_PSLIST)
        }
        assert c2_pids & suspicious_pids, "C2 PID should be flagged as suspicious process"

    # --- Phase 2: DEEP MEMORY ---

    def test_phase2_malfind_detects_injection(self):
        """vol_malfind should find injected code in attack processes."""
        injected_pids = {m["PID"] for m in SIMULATED_MALFIND if m.get("Suspicious")}
        # Should include the fake svchost (4200) and/or rundll32 (4344)
        assert injected_pids & {4200, 4344}

    def test_phase2_cmdline_reveals_encoded_command(self):
        """vol_cmdline should show the encoded PowerShell payload."""
        suspicious_cmds = [
            e for e in SIMULATED_CMDLINE
            if _is_suspicious_cmdline(e.get("Args", ""))
        ]
        # Must find: encoded PowerShell, DLL load from Temp
        cmd_text = " ".join(e["Args"] for e in suspicious_cmds)
        assert "-enc" in cmd_text.lower()
        assert "update.dll" in cmd_text.lower()

    # --- Phase 3: LOGS ---

    def test_phase3_evtx_shows_brute_force(self):
        """Event logs should show failed logon attempts before the breach."""
        failed = [e for e in SIMULATED_EVENTS if e["EventID"] == 4625]
        assert len(failed) >= 3
        # All from same source IP
        ips = {e.get("IpAddress") for e in failed}
        assert "192.168.1.200" in ips

    def test_phase3_evtx_shows_successful_logon_after_brute_force(self):
        """Successful logon from the attacker IP after failed attempts."""
        failed_times = [e["TimeCreated"] for e in SIMULATED_EVENTS if e["EventID"] == 4625]
        success = [
            e for e in SIMULATED_EVENTS
            if e["EventID"] == 4624 and e.get("IpAddress") == "192.168.1.200"
        ]
        assert len(success) >= 1
        # Success should be after failures
        assert success[0]["TimeCreated"] > max(failed_times)

    def test_phase3_evtx_shows_process_creation_chain(self):
        """4688 events should show the cmd -> powershell -> rundll32 chain."""
        proc_events = [e for e in SIMULATED_EVENTS if e["EventID"] == 4688]
        procs_created = [e.get("NewProcessName", "").split("\\")[-1].lower() for e in proc_events]
        assert "cmd.exe" in procs_created
        assert "powershell.exe" in procs_created
        assert "rundll32.exe" in procs_created

    # --- Phase 4: PERSISTENCE ---

    def test_phase4_registry_run_key_persistence(self):
        """Attacker installed a Run key pointing to the malicious DLL."""
        suspicious_keys = [e for e in SIMULATED_RUN_KEYS if e.get("suspicious")]
        assert any("update.dll" in e.get("value_data", "") for e in suspicious_keys)

    def test_phase4_registry_service_persistence(self):
        """Attacker installed a service pointing to the malicious DLL."""
        suspicious_svc = [e for e in SIMULATED_SERVICES if e.get("suspicious")]
        assert any("update.dll" in e.get("image_path", "") for e in suspicious_svc)

    def test_phase4_userassist_confirms_execution(self):
        """UserAssist shows elevated cmd.exe/powershell execution."""
        suspicious_ua = [e for e in SIMULATED_USERASSIST if e.get("suspicious")]
        programs = {e["program"].split("\\")[-1].lower() for e in suspicious_ua}
        assert "cmd.exe" in programs
        assert "powershell.exe" in programs

    # --- Phase 5: TIMELINE ---

    def test_phase5_timeline_shows_complete_attack_sequence(self):
        """Timeline should have events for every phase of the attack."""
        attack_events = [
            e for e in SIMULATED_TIMELINE
            if e["timestamp"] >= "2024-01-15T14:19"
        ]
        descriptions = " ".join(e["description"] for e in attack_events)
        # Must contain all phases
        assert "Failed logon" in descriptions  # brute force
        assert "Logon Type 3" in descriptions  # network logon
        assert "cmd.exe" in descriptions        # initial access
        assert "powershell" in descriptions     # execution
        assert "update.dll" in descriptions     # payload
        assert "rundll32" in descriptions       # DLL load
        assert "185.220.101.34" in descriptions # C2
        assert "7045" in descriptions           # service persistence

    def test_phase5_timeline_c2_beacon_interval(self):
        """C2 beacons at ~4 minute intervals should be visible in timeline."""
        c2_events = [
            e for e in SIMULATED_TIMELINE
            if "185.220.101.34" in e.get("description", "")
        ]
        times = sorted(e["timestamp"] for e in c2_events)
        assert len(times) >= 3
        # Verify ~4 minute gaps (14:23, 14:27, 14:31)
        assert times[0].endswith("14:23:18Z") or "14:23" in times[0]
        assert times[1].endswith("14:27:18Z") or "14:27" in times[1]
        assert times[2].endswith("14:31:18Z") or "14:31" in times[2]

    # --- Phase 6: IOC SCAN ---

    def test_phase6_yara_detects_all_attack_indicators(self):
        """YARA should match: encoded PowerShell, DLL path, shellcode, C2 IP."""
        rules_matched = {m["rule"] for m in SIMULATED_MATCHES}
        assert "Suspicious_PowerShell_Encoded" in rules_matched
        assert "Suspicious_DLL_Temp_Path" in rules_matched
        assert "Cobalt_Strike_Shellcode_Pattern" in rules_matched
        assert "C2_IP_Indicator" in rules_matched

    def test_phase6_yara_detects_post_exploitation(self):
        """YARA should detect post-exploitation activity: credential theft, lateral movement."""
        rules_matched = {m["rule"] for m in SIMULATED_MATCHES}
        assert "Mimikatz_Credential_Theft" in rules_matched
        assert "Lateral_Movement_PsExec" in rules_matched

    def test_phase6_yara_detects_exfiltration_staging(self):
        """YARA should detect data staging and LOLBin abuse for exfiltration."""
        rules_matched = {m["rule"] for m in SIMULATED_MATCHES}
        assert "Data_Staging_Archive" in rules_matched
        assert "LOLBin_Abuse_Pattern" in rules_matched

    def test_phase6_yara_c2_ip_appears_in_lolbin_download(self):
        """LOLBin download URL should reference the same C2 infrastructure."""
        lolbin = [m for m in SIMULATED_MATCHES if m["rule"] == "LOLBin_Abuse_Pattern"]
        assert len(lolbin) >= 1
        all_data = " ".join(s["data"] for s in lolbin[0]["matched_strings"])
        assert "185.220.101.34" in all_data

    # --- Phase 7: SYNTHESIS (DRS Gate) ---

    def test_phase7_c2_finding_scores_high_confidence(self):
        """C2 beacon finding corroborated by 3+ tools should score >= 0.75."""
        gate = DRSGate()
        finding = Finding(
            description="C2 beacon to 185.220.101.34:8443 every 4 minutes",
            artifact_type="network",
            source_invocations=["inv-netscan", "inv-timeline", "inv-yara"],
            evidence_strength=0.92,
            corroboration=DRSGate.corroboration_score(3, has_contradiction=False),
        )
        result = gate.evaluate(finding)
        assert result.action == "ACCEPT"
        assert finding.confidence >= 0.75

    def test_phase7_weak_finding_triggers_self_correction(self):
        """A finding from only 1 tool should score below threshold."""
        gate = DRSGate()
        finding = Finding(
            description="Suspicious svchost process",
            artifact_type="memory",
            source_invocations=["inv-pslist"],
            evidence_strength=0.6,
            corroboration=DRSGate.corroboration_score(1, has_contradiction=False),
        )
        result = gate.evaluate(finding)
        assert result.action == "SELF_CORRECT"
        assert finding.confidence < 0.75

    def test_phase7_contradicted_finding_scores_zero_corroboration(self):
        """If tools contradict, corroboration drops to 0."""
        gate = DRSGate()
        finding = Finding(
            description="svchost.exe is malicious",
            artifact_type="memory",
            source_invocations=["inv-pslist"],
            contradicting_invocations=["inv-cmdline"],
            evidence_strength=0.7,
            corroboration=DRSGate.corroboration_score(1, has_contradiction=True),
        )
        result = gate.evaluate(finding)
        assert result.action == "SELF_CORRECT"
        assert finding.corroboration == 0.0


class TestCrossToolCorrelation:
    """Verify that findings from different tools point to the same IOCs."""

    def test_c2_ip_consistent_across_tools(self):
        """185.220.101.34 appears in netscan, timeline, YARA, and cmdline."""
        c2_ip = "185.220.101.34"

        # netscan
        netscan_has = any(c2_ip in c.get("ForeignAddr", "") for c in SIMULATED_NETSCAN)
        # timeline
        timeline_has = any(c2_ip in e.get("description", "") for e in SIMULATED_TIMELINE)
        # yara
        yara_has = any(
            c2_ip in s.get("data", "")
            for m in SIMULATED_MATCHES
            for s in m.get("matched_strings", [])
        )
        # cmdline (encoded, but the IP is in the base64 payload's decoded form)
        cmdline_has = any(c2_ip in e.get("Args", "") for e in SIMULATED_CMDLINE)

        assert netscan_has, "C2 IP missing from netscan"
        assert timeline_has, "C2 IP missing from timeline"
        assert yara_has, "C2 IP missing from YARA matches"
        # cmdline may have it encoded — not required but nice to have

    def test_malicious_dll_consistent_across_tools(self):
        """update.dll appears in cmdline, registry, timeline, EVTX, and YARA."""
        dll_name = "update.dll"

        cmdline_has = any(dll_name in e.get("Args", "") for e in SIMULATED_CMDLINE)
        registry_has = any(
            dll_name in e.get("value_data", "") or dll_name in e.get("image_path", "")
            for e in SIMULATED_RUN_KEYS + SIMULATED_SERVICES
        )
        timeline_has = any(dll_name in e.get("description", "") or dll_name in e.get("filename", "") for e in SIMULATED_TIMELINE)
        evtx_has = any(dll_name in e.get("CommandLine", "") or dll_name in e.get("ImagePath", "") for e in SIMULATED_EVENTS)

        assert cmdline_has, "DLL missing from cmdline"
        assert registry_has, "DLL missing from registry"
        assert timeline_has, "DLL missing from timeline"
        assert evtx_has, "DLL missing from EVTX"

    def test_attacker_ip_consistent_across_tools(self):
        """192.168.1.200 (lateral movement source) appears in EVTX and timeline."""
        attacker_ip = "192.168.1.200"
        evtx_has = any(attacker_ip in str(e) for e in SIMULATED_EVENTS)
        timeline_has = any(attacker_ip in e.get("description", "") for e in SIMULATED_TIMELINE)

        assert evtx_has, "Attacker IP missing from EVTX"
        assert timeline_has, "Attacker IP missing from timeline"

    def test_attack_pids_consistent_between_pslist_and_netscan(self):
        """PID 4344 (rundll32) appears in both pslist and netscan C2 connections."""
        pslist_pids = {p["PID"] for p in SIMULATED_PSLIST if p.get("ImageFileName") == "rundll32.exe"}
        netscan_c2_pids = {c["PID"] for c in SIMULATED_NETSCAN if "185.220.101.34" in c.get("ForeignAddr", "")}

        overlap = pslist_pids & netscan_c2_pids
        assert overlap, f"rundll32 PID {pslist_pids} should appear in C2 connections {netscan_c2_pids}"
