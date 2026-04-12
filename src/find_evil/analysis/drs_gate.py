"""DRS (Deployability Readiness Score) Confidence Gate.

Adapted from the ai-control-framework DRS pattern for DFIR findings.
Every finding is scored on two dimensions before being accepted:

- Evidence strength (0.0-1.0): Is it directly observed in tool output?
- Corroboration (0.0-1.0): Is it confirmed by multiple independent tools?

Confidence = (evidence_strength * 0.6) + (corroboration * 0.4)

Findings below the threshold (0.75) trigger self-correction — the agent
must seek additional corroborating evidence before the finding is accepted.
"""

from __future__ import annotations

from dataclasses import dataclass, field


CONFIDENCE_THRESHOLD = 0.75
EVIDENCE_WEIGHT = 0.6
CORROBORATION_WEIGHT = 0.4


@dataclass
class Finding:
    """A DFIR finding with confidence scoring and provenance."""

    description: str
    artifact_type: str  # memory | disk | registry | network | log
    source_invocations: list[str] = field(default_factory=list)
    contradicting_invocations: list[str] = field(default_factory=list)
    evidence_strength: float = 0.0
    corroboration: float = 0.0
    mitre_technique: str = ""
    action_required: bool = False

    @property
    def confidence(self) -> float:
        return (
            self.evidence_strength * EVIDENCE_WEIGHT
            + self.corroboration * CORROBORATION_WEIGHT
        )

    @property
    def meets_threshold(self) -> bool:
        return self.confidence >= CONFIDENCE_THRESHOLD


@dataclass
class GateResult:
    """Result of a DRS gate evaluation."""

    action: str  # "ACCEPT" | "SELF_CORRECT"
    confidence: float
    evidence_strength: float
    corroboration: float
    guidance: str = ""


class DRSGate:
    """Confidence gate that evaluates findings before acceptance.

    Findings below the threshold are returned with guidance for the
    agent to self-correct — seeking additional corroboration or
    revising the finding.
    """

    def __init__(self, threshold: float = CONFIDENCE_THRESHOLD) -> None:
        self.threshold = threshold

    def evaluate(self, finding: Finding) -> GateResult:
        """Evaluate a finding against the confidence threshold."""
        score = finding.confidence

        if score >= self.threshold:
            return GateResult(
                action="ACCEPT",
                confidence=score,
                evidence_strength=finding.evidence_strength,
                corroboration=finding.corroboration,
                guidance=(
                    f"Confidence {score:.2f} meets threshold {self.threshold}. "
                    "Finding accepted."
                ),
            )

        # Below threshold — trigger self-correction
        guidance_parts = [
            f"Confidence {score:.2f} below threshold {self.threshold}.",
        ]

        if finding.evidence_strength < 0.7:
            guidance_parts.append(
                "Evidence strength is low — seek more direct tool evidence."
            )
        if finding.corroboration < 0.5:
            guidance_parts.append(
                "Corroboration is low — verify with a DIFFERENT tool or data source."
            )
        if finding.contradicting_invocations:
            guidance_parts.append(
                f"WARNING: {len(finding.contradicting_invocations)} contradicting "
                "source(s). Document both sides."
            )

        return GateResult(
            action="SELF_CORRECT",
            confidence=score,
            evidence_strength=finding.evidence_strength,
            corroboration=finding.corroboration,
            guidance=" ".join(guidance_parts),
        )

    @staticmethod
    def corroboration_score(source_count: int, has_contradiction: bool) -> float:
        """Calculate corroboration score from source count.

        1 source  → 0.25
        2 sources → 0.50
        3+ sources → 0.85
        Any contradiction → 0.00
        """
        if has_contradiction:
            return 0.0
        if source_count >= 3:
            return 0.85
        if source_count == 2:
            return 0.50
        if source_count == 1:
            return 0.25
        return 0.0
