"""Tests for the DRS Confidence Gate."""

import pytest

from find_evil.analysis.drs_gate import DRSGate, Finding


class TestConfidenceScoring:
    """Tests for confidence calculation."""

    def test_high_confidence_accepted(self):
        gate = DRSGate()
        finding = Finding(
            description="cmd.exe lateral movement",
            artifact_type="disk",
            evidence_strength=0.9,
            corroboration=0.85,
        )
        result = gate.evaluate(finding)
        assert result.action == "ACCEPT"
        assert result.confidence >= 0.75

    def test_low_confidence_triggers_self_correction(self):
        gate = DRSGate()
        finding = Finding(
            description="suspicious process name",
            artifact_type="memory",
            evidence_strength=0.6,
            corroboration=0.25,
        )
        result = gate.evaluate(finding)
        assert result.action == "SELF_CORRECT"
        assert result.confidence < 0.75

    def test_confidence_formula(self):
        finding = Finding(
            description="test",
            artifact_type="memory",
            evidence_strength=0.8,
            corroboration=0.5,
        )
        # confidence = (0.8 * 0.6) + (0.5 * 0.4) = 0.48 + 0.20 = 0.68
        assert abs(finding.confidence - 0.68) < 0.001

    def test_perfect_score(self):
        finding = Finding(
            description="definitive IOC",
            artifact_type="network",
            evidence_strength=1.0,
            corroboration=1.0,
        )
        assert finding.confidence == 1.0
        assert finding.meets_threshold is True

    def test_zero_score(self):
        finding = Finding(
            description="pure guess",
            artifact_type="memory",
            evidence_strength=0.0,
            corroboration=0.0,
        )
        assert finding.confidence == 0.0
        assert finding.meets_threshold is False


class TestCorroborationScoring:
    """Tests for the corroboration helper."""

    def test_single_source(self):
        assert DRSGate.corroboration_score(1, False) == 0.25

    def test_two_sources(self):
        assert DRSGate.corroboration_score(2, False) == 0.50

    def test_three_plus_sources(self):
        assert DRSGate.corroboration_score(3, False) == 0.85
        assert DRSGate.corroboration_score(5, False) == 0.85

    def test_contradiction_zeroes_score(self):
        assert DRSGate.corroboration_score(3, True) == 0.0

    def test_no_sources(self):
        assert DRSGate.corroboration_score(0, False) == 0.0


class TestSelfCorrectionGuidance:
    """Tests for guidance messages on self-correction."""

    def test_low_evidence_guidance(self):
        gate = DRSGate()
        finding = Finding(
            description="weak signal",
            artifact_type="log",
            evidence_strength=0.3,
            corroboration=0.5,
        )
        result = gate.evaluate(finding)
        assert "evidence strength is low" in result.guidance.lower()

    def test_low_corroboration_guidance(self):
        gate = DRSGate()
        finding = Finding(
            description="single source",
            artifact_type="disk",
            evidence_strength=0.9,
            corroboration=0.25,
        )
        result = gate.evaluate(finding)
        assert "corroboration is low" in result.guidance.lower()

    def test_contradiction_warning(self):
        gate = DRSGate()
        finding = Finding(
            description="conflicting evidence",
            artifact_type="memory",
            evidence_strength=0.5,
            corroboration=0.0,
            contradicting_invocations=["inv-001"],
        )
        result = gate.evaluate(finding)
        assert "contradicting" in result.guidance.lower()
