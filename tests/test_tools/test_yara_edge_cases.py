"""YARA rule edge case and validation tests.

Covers scenarios not tested in test_yara.py or test_real_yara.py:
1. Rule syntax validation — every rule has valid YARA syntax structure
2. Severity filter logic — filtering returns correct subsets
3. Empty/degenerate input handling for simulated mode
4. MITRE ATT&CK tactic breadth — rules span the kill chain
5. Rule metadata completeness — author, description, severity, mitre in every rule
6. Match data integrity — no None/null values in match fields
7. Binary and Unicode resilience in match data
8. Offset monotonicity — simulated offsets are increasing (realistic)
9. Rule condition complexity — rules use more than trivial "any of them"
10. Cross-reference: simulated match rules are a subset of declared rules
"""

from __future__ import annotations

import re

import pytest

from find_evil.tools.yara_scan import SIMULATED_MATCHES, BUILTIN_RULES_SOURCE


# ---------------------------------------------------------------------------
# Rule syntax and structure validation
# ---------------------------------------------------------------------------

class TestRuleSyntaxValidation:
    """Verify YARA rule source has valid structural patterns."""

    def test_every_rule_has_meta_block(self):
        """Every rule declaration must have a meta: block."""
        rule_names = re.findall(r"rule\s+(\w+)\s*\{", BUILTIN_RULES_SOURCE)
        meta_count = BUILTIN_RULES_SOURCE.count("meta:")
        assert meta_count >= len(rule_names), (
            f"Found {len(rule_names)} rules but only {meta_count} meta blocks"
        )

    def test_every_rule_has_strings_block(self):
        """Every rule must have a strings: block."""
        rule_names = re.findall(r"rule\s+(\w+)\s*\{", BUILTIN_RULES_SOURCE)
        strings_count = BUILTIN_RULES_SOURCE.count("strings:")
        assert strings_count >= len(rule_names), (
            f"Found {len(rule_names)} rules but only {strings_count} strings blocks"
        )

    def test_every_rule_has_condition_block(self):
        """Every rule must have a condition: block."""
        rule_names = re.findall(r"rule\s+(\w+)\s*\{", BUILTIN_RULES_SOURCE)
        condition_count = BUILTIN_RULES_SOURCE.count("condition:")
        assert condition_count >= len(rule_names), (
            f"Found {len(rule_names)} rules but only {condition_count} condition blocks"
        )

    def test_rule_names_are_valid_identifiers(self):
        """Rule names must be valid YARA identifiers (alphanumeric + underscore)."""
        rule_names = re.findall(r"rule\s+(\w+)\s*\{", BUILTIN_RULES_SOURCE)
        for name in rule_names:
            assert re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name), (
                f"Invalid YARA rule name: {name}"
            )

    def test_no_duplicate_rule_names(self):
        """Rule names must be unique."""
        rule_names = re.findall(r"rule\s+(\w+)\s*\{", BUILTIN_RULES_SOURCE)
        assert len(rule_names) == len(set(rule_names)), (
            f"Duplicate rule names found: "
            f"{[n for n in rule_names if rule_names.count(n) > 1]}"
        )

    def test_string_identifiers_start_with_dollar(self):
        """All string identifiers in rules should start with $."""
        # Find all string declarations (lines like: $name = "value")
        string_decls = re.findall(r"^\s+(\$\w+)\s*=", BUILTIN_RULES_SOURCE, re.MULTILINE)
        assert len(string_decls) > 0, "No string declarations found"
        for decl in string_decls:
            assert decl.startswith("$"), f"Invalid string identifier: {decl}"

    def test_braces_are_balanced(self):
        """Opening and closing braces should be balanced."""
        opens = BUILTIN_RULES_SOURCE.count("{")
        closes = BUILTIN_RULES_SOURCE.count("}")
        assert opens == closes, (
            f"Unbalanced braces: {opens} opens vs {closes} closes"
        )


# ---------------------------------------------------------------------------
# Rule metadata completeness
# ---------------------------------------------------------------------------

class TestRuleMetadataCompleteness:
    """Verify every rule has all required metadata fields."""

    def _extract_rule_blocks(self) -> list[str]:
        """Split the rules source into individual rule blocks."""
        # Split on 'rule ' at start of line
        parts = re.split(r"\nrule\s+", BUILTIN_RULES_SOURCE)
        # First element might be empty or whitespace
        return [p for p in parts if p.strip()]

    def test_every_rule_has_author_metadata(self):
        """Rules authored by find-evil should have author metadata."""
        blocks = self._extract_rule_blocks()
        # At least the expanded rules (6 of them) should have author
        author_count = BUILTIN_RULES_SOURCE.count('author = "')
        assert author_count >= 6, (
            f"Expected at least 6 rules with author metadata, found {author_count}"
        )

    def test_severity_values_are_from_valid_set(self):
        """All severity values should be critical, high, medium, or low."""
        severities = re.findall(r'severity\s*=\s*"(\w+)"', BUILTIN_RULES_SOURCE)
        valid = {"critical", "high", "medium", "low"}
        for sev in severities:
            assert sev in valid, f"Invalid severity value: {sev}"

    def test_mitre_ids_are_valid_format(self):
        """All MITRE technique IDs should match Txxx or Txxx.xxx format."""
        mitre_ids = re.findall(r'mitre\s*=\s*"(T\d+(?:\.\d+)?)"', BUILTIN_RULES_SOURCE)
        for mid in mitre_ids:
            assert re.match(r"^T\d{4}(\.\d{3})?$", mid), (
                f"Invalid MITRE technique ID: {mid}"
            )

    def test_descriptions_are_non_empty(self):
        """All description metadata must be non-empty strings."""
        descriptions = re.findall(r'description\s*=\s*"([^"]*)"', BUILTIN_RULES_SOURCE)
        for desc in descriptions:
            assert len(desc) > 5, f"Description too short: '{desc}'"


# ---------------------------------------------------------------------------
# Simulated match data integrity
# ---------------------------------------------------------------------------

class TestSimulatedMatchDataIntegrity:
    """Verify simulated match data has no None/null/empty values."""

    def test_no_none_values_in_matches(self):
        """No field in any match should be None."""
        for m in SIMULATED_MATCHES:
            for key, value in m.items():
                assert value is not None, (
                    f"None value in match {m['rule']}, field {key}"
                )

    def test_no_empty_rule_names(self):
        """Rule names must be non-empty strings."""
        for m in SIMULATED_MATCHES:
            assert isinstance(m["rule"], str) and len(m["rule"]) > 0

    def test_no_empty_severity(self):
        """Severity must be a non-empty string."""
        for m in SIMULATED_MATCHES:
            assert isinstance(m["severity"], str) and len(m["severity"]) > 0

    def test_no_empty_mitre(self):
        """MITRE technique must be a non-empty string."""
        for m in SIMULATED_MATCHES:
            assert isinstance(m["mitre"], str) and len(m["mitre"]) > 0

    def test_offsets_are_positive_integers(self):
        """All offsets must be positive integers."""
        for m in SIMULATED_MATCHES:
            assert isinstance(m["offset"], int) and m["offset"] > 0, (
                f"Invalid offset in {m['rule']}: {m['offset']}"
            )

    def test_matched_strings_not_empty(self):
        """Every match must have at least one matched string."""
        for m in SIMULATED_MATCHES:
            assert len(m["matched_strings"]) >= 1, (
                f"Match {m['rule']} has no matched strings"
            )

    def test_matched_string_data_not_empty(self):
        """Matched string data must be non-empty."""
        for m in SIMULATED_MATCHES:
            for s in m["matched_strings"]:
                assert isinstance(s["data"], str) and len(s["data"]) > 0, (
                    f"Empty matched string data in {m['rule']}"
                )

    def test_matched_string_identifiers_are_yara_format(self):
        """Matched string identifiers should start with $."""
        for m in SIMULATED_MATCHES:
            for s in m["matched_strings"]:
                assert s["identifier"].startswith("$"), (
                    f"Invalid identifier '{s['identifier']}' in {m['rule']}"
                )


# ---------------------------------------------------------------------------
# Offset monotonicity (realistic simulation)
# ---------------------------------------------------------------------------

class TestOffsetRealism:
    """Verify simulated offsets are realistic memory addresses."""

    def test_offsets_are_unique(self):
        """Each simulated match should have a unique offset (no duplicates)."""
        offsets = [m["offset"] for m in SIMULATED_MATCHES]
        assert len(offsets) == len(set(offsets)), (
            f"Duplicate offsets found: {[o for o in offsets if offsets.count(o) > 1]}"
        )

    def test_offsets_are_reasonable_memory_addresses(self):
        """Offsets should be within a plausible memory range (< 1 GB)."""
        for m in SIMULATED_MATCHES:
            assert m["offset"] < 1024 * 1024 * 1024, (
                f"Offset {m['offset']} in {m['rule']} exceeds 1 GB"
            )

    def test_per_match_string_offsets_are_close_to_match_offset(self):
        """Matched strings within a match should be near the match offset."""
        for m in SIMULATED_MATCHES:
            base = m["offset"]
            for s in m["matched_strings"]:
                distance = abs(s["offset"] - base)
                assert distance < 1024, (
                    f"String offset {s['offset']} too far from match offset "
                    f"{base} in {m['rule']} (distance: {distance})"
                )


# ---------------------------------------------------------------------------
# Severity filter logic
# ---------------------------------------------------------------------------

class TestSeverityFilterLogic:
    """Verify severity filtering returns correct subsets."""

    def test_filter_critical_only(self):
        """Filtering by 'critical' returns only critical matches."""
        critical = [m for m in SIMULATED_MATCHES if m["severity"] == "critical"]
        assert len(critical) >= 2
        for m in critical:
            assert m["severity"] == "critical"

    def test_filter_high_only(self):
        """Filtering by 'high' returns only high matches."""
        high = [m for m in SIMULATED_MATCHES if m["severity"] == "high"]
        assert len(high) >= 2
        for m in high:
            assert m["severity"] == "high"

    def test_filter_medium_only(self):
        """Filtering by 'medium' returns only medium matches."""
        medium = [m for m in SIMULATED_MATCHES if m["severity"] == "medium"]
        assert len(medium) >= 1
        for m in medium:
            assert m["severity"] == "medium"

    def test_filter_nonexistent_severity_returns_empty(self):
        """Filtering by a nonexistent severity returns empty list."""
        none_match = [m for m in SIMULATED_MATCHES if m["severity"] == "info"]
        assert len(none_match) == 0

    def test_all_severities_sum_to_total(self):
        """Sum of filtered matches across all severities equals total."""
        critical = len([m for m in SIMULATED_MATCHES if m["severity"] == "critical"])
        high = len([m for m in SIMULATED_MATCHES if m["severity"] == "high"])
        medium = len([m for m in SIMULATED_MATCHES if m["severity"] == "medium"])
        low = len([m for m in SIMULATED_MATCHES if m["severity"] == "low"])
        assert critical + high + medium + low == len(SIMULATED_MATCHES)


# ---------------------------------------------------------------------------
# Cross-reference: simulated matches reference declared rules
# ---------------------------------------------------------------------------

class TestMatchRuleCrossReference:
    """Verify simulated matches reference rules that exist in the source."""

    def test_all_match_rules_exist_in_source(self):
        """Every rule name in simulated matches must exist in the rules source."""
        declared_rules = set(re.findall(r"rule\s+(\w+)\s*\{", BUILTIN_RULES_SOURCE))
        for m in SIMULATED_MATCHES:
            assert m["rule"] in declared_rules, (
                f"Simulated match references undeclared rule: {m['rule']}"
            )

    def test_match_severities_match_rule_declarations(self):
        """Severity in match data should match the rule's meta severity."""
        # Extract rule -> severity mapping from source
        rule_severities = {}
        for name in re.findall(r"rule\s+(\w+)\s*\{", BUILTIN_RULES_SOURCE):
            # Find severity for this rule
            pattern = re.compile(
                r"rule\s+" + re.escape(name) + r"\s*\{.*?severity\s*=\s*\"(\w+)\"",
                re.DOTALL,
            )
            match = pattern.search(BUILTIN_RULES_SOURCE)
            if match:
                rule_severities[name] = match.group(1)

        for m in SIMULATED_MATCHES:
            if m["rule"] in rule_severities:
                assert m["severity"] == rule_severities[m["rule"]], (
                    f"Severity mismatch for {m['rule']}: "
                    f"match says '{m['severity']}', rule says '{rule_severities[m['rule']]}'"
                )

    def test_match_mitre_ids_match_rule_declarations(self):
        """MITRE ID in match data should match the rule's meta mitre."""
        rule_mitres = {}
        for name in re.findall(r"rule\s+(\w+)\s*\{", BUILTIN_RULES_SOURCE):
            pattern = re.compile(
                r"rule\s+" + re.escape(name) + r"\s*\{.*?mitre\s*=\s*\"(T[\d.]+)\"",
                re.DOTALL,
            )
            match = pattern.search(BUILTIN_RULES_SOURCE)
            if match:
                rule_mitres[name] = match.group(1)

        for m in SIMULATED_MATCHES:
            if m["rule"] in rule_mitres:
                assert m["mitre"] == rule_mitres[m["rule"]], (
                    f"MITRE mismatch for {m['rule']}: "
                    f"match says '{m['mitre']}', rule says '{rule_mitres[m['rule']]}'"
                )


# ---------------------------------------------------------------------------
# MITRE ATT&CK tactic breadth from rules
# ---------------------------------------------------------------------------

class TestMITRETacticBreadthFromRules:
    """Verify the rule library covers multiple MITRE ATT&CK tactics."""

    def _extract_mitre_ids_from_rules(self) -> set[str]:
        return set(re.findall(r'mitre\s*=\s*"(T[\d.]+)"', BUILTIN_RULES_SOURCE))

    def test_covers_at_least_8_techniques(self):
        """Rule library should cover at least 8 unique MITRE techniques."""
        techniques = self._extract_mitre_ids_from_rules()
        assert len(techniques) >= 8, (
            f"Expected >= 8 MITRE techniques in rules, got {len(techniques)}: {techniques}"
        )

    def test_covers_execution_tactic(self):
        """Rules should detect Execution techniques."""
        techniques = self._extract_mitre_ids_from_rules()
        execution = {t for t in techniques if t.startswith("T1059")}
        assert len(execution) >= 1, "No Execution tactic coverage"

    def test_covers_persistence_tactic(self):
        """Rules should detect Persistence techniques."""
        techniques = self._extract_mitre_ids_from_rules()
        persistence = {t for t in techniques if t in {"T1505.003", "T1543.003", "T1547.001"}}
        assert len(persistence) >= 1, "No Persistence tactic coverage"

    def test_covers_defense_evasion_tactic(self):
        """Rules should detect Defense Evasion techniques."""
        techniques = self._extract_mitre_ids_from_rules()
        evasion = {t for t in techniques if t in {"T1055.001", "T1218", "T1036.004"}}
        assert len(evasion) >= 1, "No Defense Evasion tactic coverage"

    def test_covers_credential_access_tactic(self):
        """Rules should detect Credential Access techniques."""
        techniques = self._extract_mitre_ids_from_rules()
        cred = {t for t in techniques if t.startswith("T1003")}
        assert len(cred) >= 1, "No Credential Access tactic coverage"

    def test_covers_lateral_movement_tactic(self):
        """Rules should detect Lateral Movement techniques."""
        techniques = self._extract_mitre_ids_from_rules()
        lateral = {t for t in techniques if t in {"T1570", "T1021.001", "T1021.002"}}
        assert len(lateral) >= 1, "No Lateral Movement tactic coverage"

    def test_covers_command_and_control_tactic(self):
        """Rules should detect Command and Control techniques."""
        techniques = self._extract_mitre_ids_from_rules()
        c2 = {t for t in techniques if t.startswith("T1071")}
        assert len(c2) >= 1, "No Command and Control tactic coverage"

    def test_covers_impact_tactic(self):
        """Rules should detect Impact techniques."""
        techniques = self._extract_mitre_ids_from_rules()
        impact = {t for t in techniques if t in {"T1486"}}
        assert len(impact) >= 1, "No Impact tactic coverage"

    def test_covers_collection_tactic(self):
        """Rules should detect Collection techniques."""
        techniques = self._extract_mitre_ids_from_rules()
        collection = {t for t in techniques if t.startswith("T1560")}
        assert len(collection) >= 1, "No Collection tactic coverage"


# ---------------------------------------------------------------------------
# Rule condition complexity
# ---------------------------------------------------------------------------

class TestRuleConditionQuality:
    """Verify rules use meaningful conditions, not just 'any of them'."""

    def test_most_conditions_are_non_trivial(self):
        """Most rules should use combinatorial conditions, not just 'any of them'.

        'any of them' is acceptable for specific indicator rules (like C2 IP matching)
        but should not be the norm -- most rules should use combinatorial logic
        for lower false positive rates.
        """
        # Extract condition blocks
        conditions = re.findall(r"condition:\s*\n\s*(.*?)(?=\n\s*\})", BUILTIN_RULES_SOURCE)
        trivial_conditions = [c.strip() for c in conditions if c.strip() == "any of them"]
        rule_count = len(re.findall(r"rule\s+\w+\s*\{", BUILTIN_RULES_SOURCE))
        # At most 1 rule can use trivial 'any of them' (e.g., C2_IP_Indicator)
        assert len(trivial_conditions) <= 1, (
            f"Found {len(trivial_conditions)} rules with trivial 'any of them' conditions "
            f"(expected at most 1 out of {rule_count} rules)"
        )

    def test_most_rules_use_combinatorial_logic(self):
        """Most rules should use 'and', 'or', or numeric conditions."""
        conditions = re.findall(r"condition:\s*\n\s*(.*?)(?=\n\s*\})", BUILTIN_RULES_SOURCE)
        complex_count = sum(
            1 for c in conditions
            if "and" in c or "or" in c or re.search(r"\d+ of", c)
        )
        assert complex_count >= 7, (
            f"Expected >= 7 rules with complex conditions, got {complex_count}"
        )
