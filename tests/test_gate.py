"""Tests for CI gate evaluation logic."""

from __future__ import annotations

import unittest

from coyote.baseline import DiffResult
from coyote.gate import evaluate_gate
from coyote.patterns import PatternMatch, Severity
from coyote.scanner import ScanResult


def _finding(rule: str, severity: Severity, finding_id: str) -> PatternMatch:
    return PatternMatch(
        rule_name=rule,
        severity=severity,
        file_path="src/app.py",
        line_number=10,
        line_content="token = 'x'",
        description=f"{rule} detected",
        matched_text="x",
        finding_id=finding_id,
    )


class GateEvaluationTests(unittest.TestCase):
    def test_absolute_mode_fails_when_high_findings_breach_threshold(self) -> None:
        result = ScanResult(repo_path="repo", findings=[_finding("AWS Access Key", Severity.HIGH, "a1")])

        evaluation = evaluate_gate(
            result,
            diff=None,
            baseline_found=False,
            require_baseline=False,
            fail_on="high",
            fail_on_new="high",
            fail_on_errors=False,
        )

        self.assertFalse(evaluation.passed)
        self.assertEqual("absolute", evaluation.mode)
        self.assertTrue(any("breached fail threshold" in reason for reason in evaluation.fail_reasons))

    def test_absolute_mode_passes_when_only_low_and_threshold_is_high(self) -> None:
        result = ScanResult(repo_path="repo", findings=[_finding("Missing .gitignore", Severity.LOW, "l1")])

        evaluation = evaluate_gate(
            result,
            diff=None,
            baseline_found=False,
            require_baseline=False,
            fail_on="high",
            fail_on_new="high",
            fail_on_errors=False,
        )

        self.assertTrue(evaluation.passed)
        self.assertEqual("absolute", evaluation.mode)

    def test_diff_mode_fails_when_new_high_findings_exist(self) -> None:
        result = ScanResult(repo_path="repo", findings=[_finding("AWS Access Key", Severity.HIGH, "h1")])
        diff = DiffResult(new_findings=[_finding("AWS Access Key", Severity.HIGH, "h1")])

        evaluation = evaluate_gate(
            result,
            diff=diff,
            baseline_found=True,
            require_baseline=False,
            fail_on="high",
            fail_on_new="high",
            fail_on_errors=False,
        )

        self.assertFalse(evaluation.passed)
        self.assertEqual("baseline_diff", evaluation.mode)
        self.assertEqual(1, evaluation.new_high)

    def test_diff_mode_passes_when_only_new_medium_and_fail_on_new_high(self) -> None:
        result = ScanResult(repo_path="repo", findings=[_finding("Eval Usage", Severity.MEDIUM, "m1")])
        diff = DiffResult(new_findings=[_finding("Eval Usage", Severity.MEDIUM, "m1")])

        evaluation = evaluate_gate(
            result,
            diff=diff,
            baseline_found=True,
            require_baseline=False,
            fail_on="high",
            fail_on_new="high",
            fail_on_errors=False,
        )

        self.assertTrue(evaluation.passed)
        self.assertEqual("baseline_diff", evaluation.mode)
        self.assertEqual(1, evaluation.new_medium)

    def test_require_baseline_fails_when_baseline_missing(self) -> None:
        result = ScanResult(repo_path="repo", findings=[])

        evaluation = evaluate_gate(
            result,
            diff=None,
            baseline_found=False,
            require_baseline=True,
            fail_on="none",
            fail_on_new="none",
            fail_on_errors=False,
        )

        self.assertFalse(evaluation.passed)
        self.assertIn("baseline is required but was not found", evaluation.fail_reasons)

    def test_fail_on_errors_fails_when_runtime_errors_present(self) -> None:
        result = ScanResult(repo_path="repo", findings=[])
        result.errors.append("failed reading file")

        evaluation = evaluate_gate(
            result,
            diff=None,
            baseline_found=False,
            require_baseline=False,
            fail_on="none",
            fail_on_new="none",
            fail_on_errors=True,
        )

        self.assertFalse(evaluation.passed)
        self.assertTrue(any("runtime error" in reason for reason in evaluation.fail_reasons))


if __name__ == "__main__":
    unittest.main()
