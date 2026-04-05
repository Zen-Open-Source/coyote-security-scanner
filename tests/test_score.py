"""Tests for security scorecard."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from coyote.patterns import PatternMatch, Severity
from coyote.score import (
    CategoryScore,
    classify_finding,
    compute_scorecard,
    _category_score,
    _letter_grade,
)


def _make_finding(
    rule_name: str,
    severity: Severity,
    finding_id: str = "test001",
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
    )


class TestCleanRepoScoresAPlus(unittest.TestCase):
    def test_clean_repo_scores_a_plus(self) -> None:
        sc = compute_scorecard(repo_path="/tmp/clean", findings=[])
        self.assertEqual(sc.aggregate_score, 100.0)
        self.assertEqual(sc.letter_grade, "A+")


class TestHighSecretDropsScore(unittest.TestCase):
    def test_high_secret_drops_score(self) -> None:
        findings = [_make_finding("AWS Access Key", Severity.HIGH)]
        sc = compute_scorecard(repo_path="/tmp/repo", findings=findings)

        secrets_cat = next(c for c in sc.categories if c.name == "Secrets")
        self.assertEqual(secrets_cat.score, 75.0)


class TestGradeThresholds(unittest.TestCase):
    def test_97_is_a_plus(self) -> None:
        self.assertEqual(_letter_grade(97), "A+")

    def test_96_is_a(self) -> None:
        self.assertEqual(_letter_grade(96), "A")

    def test_92_is_a_minus(self) -> None:
        self.assertEqual(_letter_grade(92), "A-")

    def test_89_is_b_plus(self) -> None:
        self.assertEqual(_letter_grade(89), "B+")

    def test_59_is_f(self) -> None:
        self.assertEqual(_letter_grade(59), "F")

    def test_0_is_f(self) -> None:
        self.assertEqual(_letter_grade(0), "F")

    def test_100_is_a_plus(self) -> None:
        self.assertEqual(_letter_grade(100), "A+")


class TestDisabledCategoriesRedistributeWeight(unittest.TestCase):
    def test_disabled_categories_redistribute_weight(self) -> None:
        # deps and history off
        sc = compute_scorecard(
            repo_path="/tmp/repo",
            findings=[],
            deps_enabled=False,
            history_enabled=False,
        )
        active_weights = [c.weight for c in sc.categories if c.enabled]
        self.assertAlmostEqual(sum(active_weights), 1.0, places=5)

        disabled = [c for c in sc.categories if not c.enabled]
        for c in disabled:
            self.assertEqual(c.weight, 0.0)


class TestMultipleFindingsCompound(unittest.TestCase):
    def test_multiple_findings_compound(self) -> None:
        # 2 HIGH (50) + 3 MEDIUM (30) = 80 deducted → score 20
        findings = [
            _make_finding("AWS Access Key", Severity.HIGH, "f1"),
            _make_finding("GitHub Token", Severity.HIGH, "f2"),
            _make_finding("Generic Secret", Severity.MEDIUM, "f3"),
            _make_finding("Generic Secret", Severity.MEDIUM, "f4"),
            _make_finding("Generic Secret", Severity.MEDIUM, "f5"),
        ]
        sc = compute_scorecard(repo_path="/tmp/repo", findings=findings)
        secrets_cat = next(c for c in sc.categories if c.name == "Secrets")
        self.assertEqual(secrets_cat.score, 20.0)


class TestScoreFloorAtZero(unittest.TestCase):
    def test_score_floor_at_zero(self) -> None:
        # 5 HIGH = 125 deducted → clamped to 0
        findings = [
            _make_finding("AWS Access Key", Severity.HIGH, f"f{i}")
            for i in range(5)
        ]
        sc = compute_scorecard(repo_path="/tmp/repo", findings=findings)
        secrets_cat = next(c for c in sc.categories if c.name == "Secrets")
        self.assertEqual(secrets_cat.score, 0.0)


class TestAttackPathPenaltyCapsAtFive(unittest.TestCase):
    def test_attack_path_penalty_caps_at_five(self) -> None:
        sc_no_penalty = compute_scorecard(repo_path="/tmp/repo", findings=[])

        sc_with_penalty = compute_scorecard(
            repo_path="/tmp/repo",
            findings=[],
            attack_paths_critical=10,  # should cap at -5
        )
        diff = sc_no_penalty.aggregate_score - sc_with_penalty.aggregate_score
        self.assertEqual(diff, 5.0)


class TestJsonOutputStructure(unittest.TestCase):
    def test_json_output_structure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # Create a minimal .gitignore so scanner doesn't flag missing one
            with open(os.path.join(tmp, ".gitignore"), "w") as f:
                f.write(".env\nnode_modules/\n")

            from coyote.score import main
            from io import StringIO
            import sys

            captured = StringIO()
            old_stdout = sys.stdout
            sys.stdout = captured
            try:
                rc = main(["--repo", tmp, "--json"])
            finally:
                sys.stdout = old_stdout

            output = captured.getvalue()
            data = json.loads(output)

            self.assertIn("aggregate_score", data)
            self.assertIn("letter_grade", data)
            self.assertIn("categories", data)
            self.assertIn("attack_paths_count", data)
            self.assertIn("files_scanned", data)
            self.assertIn("total_findings", data)
            self.assertIn("scan_timestamp", data)
            self.assertIsInstance(data["categories"], list)


class TestCliReturnsZero(unittest.TestCase):
    def test_cli_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            from coyote.score import main
            from io import StringIO
            import sys

            captured = StringIO()
            old_stdout = sys.stdout
            sys.stdout = captured
            try:
                rc = main(["--repo", tmp, "--json"])
            finally:
                sys.stdout = old_stdout

            self.assertEqual(rc, 0)


class TestClassifyFindingRoutesCorrectly(unittest.TestCase):
    def test_aws_access_key_is_secrets(self) -> None:
        f = _make_finding("AWS Access Key", Severity.HIGH)
        self.assertEqual(classify_finding(f), "Secrets")

    def test_debug_mode_is_code_quality(self) -> None:
        f = _make_finding("Debug Mode Enabled", Severity.MEDIUM)
        self.assertEqual(classify_finding(f), "Code Quality")

    def test_missing_gitignore_is_config_hygiene(self) -> None:
        f = _make_finding("Missing .gitignore", Severity.LOW)
        self.assertEqual(classify_finding(f), "Config Hygiene")

    def test_dependency_vuln_is_dependencies(self) -> None:
        f = _make_finding("Dependency Vulnerability", Severity.HIGH)
        self.assertEqual(classify_finding(f), "Dependencies")

    def test_npm_lifecycle_rule_is_dependencies(self) -> None:
        f = _make_finding("Suspicious NPM Lifecycle Script", Severity.HIGH)
        self.assertEqual(classify_finding(f), "Dependencies")

    def test_entropy_finding_is_secrets(self) -> None:
        f = _make_finding("High Entropy (hex)", Severity.MEDIUM)
        self.assertEqual(classify_finding(f), "Secrets")

    def test_unknown_rule_is_config_hygiene(self) -> None:
        f = _make_finding("Some Unknown Rule", Severity.LOW)
        self.assertEqual(classify_finding(f), "Config Hygiene")

    def test_sensitive_file_is_config_hygiene(self) -> None:
        f = _make_finding("Sensitive File", Severity.HIGH)
        self.assertEqual(classify_finding(f), "Config Hygiene")

    def test_eval_usage_is_code_quality(self) -> None:
        f = _make_finding("Eval Usage (JS)", Severity.MEDIUM)
        self.assertEqual(classify_finding(f), "Code Quality")

    def test_private_key_is_secrets(self) -> None:
        f = _make_finding("Private Key", Severity.HIGH)
        self.assertEqual(classify_finding(f), "Secrets")

    def test_hardcoded_ip_is_config_hygiene(self) -> None:
        f = _make_finding("Hardcoded Internal IP", Severity.LOW)
        self.assertEqual(classify_finding(f), "Config Hygiene")


class TestSupplyChainScanFindingsAffectDependencyScore(unittest.TestCase):
    def test_scanner_supply_chain_findings_enable_dependency_bucket(self) -> None:
        findings = [_make_finding("Suspicious NPM Lifecycle Script", Severity.HIGH)]
        sc = compute_scorecard(repo_path="/tmp/repo", findings=findings, deps_enabled=False)

        deps_cat = next(c for c in sc.categories if c.name == "Dependencies")
        self.assertTrue(deps_cat.enabled)
        self.assertEqual(75.0, deps_cat.score)


if __name__ == "__main__":
    unittest.main()
