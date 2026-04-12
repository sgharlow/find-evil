"""Tests for super-timeline generation tool."""

import pytest

from find_evil.tools.timeline import SIMULATED_TIMELINE


class TestSimulatedTimeline:

    def test_has_entries(self):
        assert len(SIMULATED_TIMELINE) > 10

    def test_entries_are_chronologically_sorted(self):
        timestamps = [e["timestamp"] for e in SIMULATED_TIMELINE]
        assert timestamps == sorted(timestamps)

    def test_covers_multiple_sources(self):
        sources = {e["source"] for e in SIMULATED_TIMELINE}
        assert "EVT" in sources
        assert "FILE" in sources
        assert "NET" in sources
        assert "PREFETCH" in sources
        assert "REG" in sources

    def test_attack_window_has_entries(self):
        """Attack happens between 14:19 and 14:31."""
        attack = [
            e for e in SIMULATED_TIMELINE
            if "2024-01-15T14:19" <= e["timestamp"] <= "2024-01-15T14:32"
        ]
        assert len(attack) >= 10  # brute force + lateral movement + persistence

    def test_c2_beacon_pattern_visible(self):
        """C2 connections at 14:23, 14:27, 14:31 — ~4 minute intervals."""
        c2 = [
            e for e in SIMULATED_TIMELINE
            if "185.220.101.34" in e.get("description", "")
        ]
        assert len(c2) >= 3

    def test_attack_chain_represented(self):
        """Should see: brute force -> logon -> cmd -> powershell -> DLL drop -> rundll32 -> C2."""
        descriptions = " ".join(e["description"] for e in SIMULATED_TIMELINE)
        assert "Failed logon" in descriptions
        assert "cmd.exe" in descriptions
        assert "powershell" in descriptions
        assert "update.dll" in descriptions
        assert "rundll32" in descriptions
        assert "185.220.101.34" in descriptions

    def test_persistence_follows_exploitation(self):
        """Service install (7045) should happen after initial compromise."""
        compromise_time = None
        persistence_time = None
        for e in SIMULATED_TIMELINE:
            if "cmd.exe" in e.get("description", "") and "[4688]" in e.get("description", ""):
                compromise_time = e["timestamp"]
            if "[7045]" in e.get("description", ""):
                persistence_time = e["timestamp"]
        assert compromise_time is not None
        assert persistence_time is not None
        assert persistence_time > compromise_time
