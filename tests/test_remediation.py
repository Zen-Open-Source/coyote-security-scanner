"""Tests for remediation hints across the findings pipeline."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from coyote.patterns import (
    SECRET_PATTERNS,
    SMELL_PATTERNS,
    PatternMatch,
    Severity,
    get_sensitive_file_remediation,
)
from coyote.reporter import generate_json_report, generate_markdown_report
from coyote.html_report import generate_html_report
from coyote.sarif import generate_sarif
from coyote.scanner import ScanResult


def _finding(
    rule_name: str = "AWS Access Key",
    severity: Severity = Severity.HIGH,
    remediation: str = "Rotate this key.",
) -> PatternMatch:
    return PatternMatch(
        rule_name=rule_name,
        severity=severity,
        file_path="src/app.py",
        line_number=10,
        line_content="AKIA...",
        description=f"{rule_name} detected",
        matched_text="AKIA***",
        finding_id="abc12345",
        remediation=remediation,
    )


def _scan_result(findings: list[PatternMatch] | None = None) -> ScanResult:
    result = ScanResult(repo_path="/tmp/test-repo")
    result.findings = findings or [_finding()]
    result.files_scanned = 10
    return result


class TestSecretPatternsAllHaveRemediation(unittest.TestCase):
    def test_all_secret_patterns_have_remediation(self) -> None:
        for sp in SECRET_PATTERNS:
            with self.subTest(pattern=sp.name):
                self.assertTrue(
                    sp.remediation,
                    f"SecretPattern '{sp.name}' is missing remediation text",
                )


class TestSmellPatternsAllHaveRemediation(unittest.TestCase):
    def test_all_smell_patterns_have_remediation(self) -> None:
        for sp in SMELL_PATTERNS:
            with self.subTest(pattern=sp.name):
                self.assertTrue(
                    sp.remediation,
                    f"SmellPattern '{sp.name}' is missing remediation text",
                )


class TestPatternMatchRemediationField(unittest.TestCase):
    def test_defaults_to_empty(self) -> None:
        pm = PatternMatch(
            rule_name="Test",
            severity=Severity.LOW,
            file_path="f.py",
            line_number=1,
            line_content="x",
            description="test",
        )
        self.assertEqual(pm.remediation, "")

    def test_can_be_set(self) -> None:
        pm = _finding(remediation="Do something.")
        self.assertEqual(pm.remediation, "Do something.")


class TestJsonReportIncludesRemediation(unittest.TestCase):
    def test_json_report_has_remediation_key(self) -> None:
        result = _scan_result()
        report_json = generate_json_report(result)
        report = json.loads(report_json)
        finding = report["findings"][0]
        self.assertIn("remediation", finding)
        self.assertEqual(finding["remediation"], "Rotate this key.")

    def test_json_report_remediation_none_when_empty(self) -> None:
        result = _scan_result([_finding(remediation="")])
        report_json = generate_json_report(result)
        report = json.loads(report_json)
        self.assertIsNone(report["findings"][0]["remediation"])


class TestMarkdownReportIncludesRemediation(unittest.TestCase):
    def test_markdown_has_remediation(self) -> None:
        result = _scan_result()
        md = generate_markdown_report(result)
        self.assertIn("**Remediation:**", md)
        self.assertIn("Rotate this key.", md)

    def test_markdown_omits_remediation_when_empty(self) -> None:
        result = _scan_result([_finding(remediation="")])
        md = generate_markdown_report(result)
        self.assertNotIn("**Remediation:**", md)


class TestHtmlReportIncludesRemediation(unittest.TestCase):
    def test_html_has_remediation_column(self) -> None:
        result = _scan_result()
        html_output = generate_html_report(result)
        self.assertIn("<th>Remediation</th>", html_output)
        self.assertIn("Rotate this key.", html_output)


class TestSarifHelpIncludesRemediation(unittest.TestCase):
    def test_sarif_help_has_remediation(self) -> None:
        result = _scan_result()
        sarif = generate_sarif(result)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        self.assertTrue(len(rules) > 0)
        rule = rules[0]
        self.assertIn("Remediation: Rotate this key.", rule["help"]["text"])
        self.assertIn("**Remediation:** Rotate this key.", rule["help"]["markdown"])


class TestSensitiveFileRemediation(unittest.TestCase):
    def test_env_file_has_specific_remediation(self) -> None:
        rem = get_sensitive_file_remediation(".env")
        self.assertIn(".gitignore", rem)

    def test_pem_file_matches_glob(self) -> None:
        rem = get_sensitive_file_remediation("server.pem")
        self.assertIn("certificate", rem.lower())

    def test_unknown_file_gets_default(self) -> None:
        rem = get_sensitive_file_remediation("weird-file.xyz")
        self.assertIn("Remove this file", rem)

    def test_sensitive_file_finding_has_remediation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_path = os.path.join(tmp, ".env")
            with open(env_path, "w") as f:
                f.write("SECRET=hello\n")
            # Also create .gitignore to avoid that finding confusing things
            with open(os.path.join(tmp, ".gitignore"), "w") as f:
                f.write(".env\nnode_modules/\n")

            from coyote.scanner import run_scan
            result = run_scan(tmp)
            sensitive_findings = [
                f for f in result.findings if f.rule_name == "Sensitive File"
            ]
            self.assertTrue(len(sensitive_findings) > 0)
            for sf in sensitive_findings:
                self.assertTrue(sf.remediation, f"Sensitive file finding missing remediation: {sf.file_path}")


class TestDependencyRemediation(unittest.TestCase):
    def test_finding_with_fix_has_upgrade_remediation(self) -> None:
        f = _finding(
            rule_name="Dependency Vulnerability",
            remediation="Upgrade requests to 2.32.0 or later.",
        )
        self.assertIn("Upgrade", f.remediation)

    def test_finding_without_fix_has_monitor_remediation(self) -> None:
        f = _finding(
            rule_name="Dependency Vulnerability",
            remediation="No fix available yet. Monitor CVE-2024-1234 for updates and consider alternative packages.",
        )
        self.assertIn("Monitor", f.remediation)


if __name__ == "__main__":
    unittest.main()
