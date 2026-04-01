"""Tests for attack path analysis."""

from __future__ import annotations

import unittest

from coyote.attack_paths import AttackPathAnalyzer
from coyote.patterns import PatternMatch, Severity


def _finding(
    rule_name: str,
    severity: Severity,
    finding_id: str,
    metadata: dict[str, object] | None = None,
) -> PatternMatch:
    return PatternMatch(
        rule_name=rule_name,
        severity=severity,
        file_path="src/app.py",
        line_number=10,
        line_content="example",
        description=f"{rule_name} detected",
        matched_text="example",
        finding_id=finding_id,
        metadata=metadata or {},
    )


class AttackPathTests(unittest.TestCase):
    def test_supply_chain_and_code_injection_create_path(self) -> None:
        findings = [
            _finding("Dependency Vulnerability", Severity.HIGH, "dep001", {"reachability": "reachable"}),
            _finding("Eval Usage (JS)", Severity.MEDIUM, "inj001"),
        ]

        result = AttackPathAnalyzer().analyze(findings)

        self.assertGreaterEqual(len(result.paths), 1)
        self.assertTrue(
            any(path.title == "Vulnerable Dependency -> Exploit Chain" for path in result.paths)
        )
        self.assertEqual("CRITICAL", result.worst_severity)

    def test_non_reachable_dependency_does_not_create_supply_chain_path(self) -> None:
        findings = [
            _finding("Dependency Vulnerability", Severity.HIGH, "dep002", {"reachability": "direct-unused"}),
            _finding("Eval Usage (JS)", Severity.MEDIUM, "inj001"),
        ]

        result = AttackPathAnalyzer().analyze(findings)

        self.assertFalse(
            any(path.title == "Vulnerable Dependency -> Exploit Chain" for path in result.paths)
        )

    def test_compromised_dependency_release_maps_to_supply_chain_path(self) -> None:
        findings = [
            _finding("Compromised Dependency Release", Severity.HIGH, "dep003"),
            _finding("Eval Usage (JS)", Severity.MEDIUM, "inj001"),
        ]

        result = AttackPathAnalyzer().analyze(findings)

        self.assertTrue(
            any(path.title == "Vulnerable Dependency -> Exploit Chain" for path in result.paths)
        )


if __name__ == "__main__":
    unittest.main()
