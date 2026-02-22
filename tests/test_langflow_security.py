"""Tests for Langflow CVE security scanning."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from coyote.agents.langflow import LangflowSecurityAnalyzer


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


def _check_status(report, check_id: str) -> str:
    for check in report.checks:
        if check.check_id == check_id:
            return check.status
    raise AssertionError(f"Missing check: {check_id}")


class LangflowSecurityTests(unittest.TestCase):
    def test_cve_2025_3248_version_threshold(self) -> None:
        analyzer = LangflowSecurityAnalyzer()

        with tempfile.TemporaryDirectory() as temp_dir:
            _write_json(
                Path(temp_dir) / "package.json",
                {"name": "langflow", "version": "1.2.9"},
            )
            report = analyzer.analyze(temp_dir)

            self.assertEqual("VULNERABLE", _check_status(report, "CVE-2025-3248"))
            self.assertEqual("WARNING", _check_status(report, "CVE-2025-34291"))

    def test_cve_2025_34291_risky_chain_on_affected_version(self) -> None:
        analyzer = LangflowSecurityAnalyzer()

        with tempfile.TemporaryDirectory() as temp_dir:
            _write_json(
                Path(temp_dir) / "package.json",
                {"name": "langflow", "version": "1.6.9"},
            )
            Path(temp_dir, ".env").write_text(
                "\n".join(
                    [
                        "LANGFLOW_CORS_ORIGINS=*",
                        "LANGFLOW_CORS_ALLOW_CREDENTIALS=true",
                        "LANGFLOW_REFRESH_TOKEN_COOKIE_SAMESITE=None",
                    ]
                ),
                encoding="utf-8",
            )
            report = analyzer.analyze(temp_dir)

            self.assertEqual("SAFE", _check_status(report, "CVE-2025-3248"))
            self.assertEqual("VULNERABLE", _check_status(report, "CVE-2025-34291"))

    def test_patched_version_with_safe_config_is_safe(self) -> None:
        analyzer = LangflowSecurityAnalyzer()

        with tempfile.TemporaryDirectory() as temp_dir:
            _write_json(
                Path(temp_dir) / "package.json",
                {"name": "langflow", "version": "1.7.1"},
            )
            Path(temp_dir, ".env").write_text(
                "\n".join(
                    [
                        "LANGFLOW_CORS_ORIGINS=https://app.example.com",
                        "LANGFLOW_CORS_ALLOW_CREDENTIALS=true",
                        "LANGFLOW_REFRESH_TOKEN_COOKIE_SAMESITE=Lax",
                    ]
                ),
                encoding="utf-8",
            )
            report = analyzer.analyze(temp_dir)

            self.assertEqual("SAFE", _check_status(report, "CVE-2025-3248"))
            self.assertEqual("SAFE", _check_status(report, "CVE-2025-34291"))

    def test_unknown_version_marks_checks_unknown(self) -> None:
        analyzer = LangflowSecurityAnalyzer()

        with tempfile.TemporaryDirectory() as temp_dir:
            report = analyzer.analyze(temp_dir)
            self.assertEqual("UNKNOWN", _check_status(report, "CVE-2025-3248"))
            self.assertEqual("UNKNOWN", _check_status(report, "CVE-2025-34291"))

    def test_langflow_base_dependency_threshold(self) -> None:
        analyzer = LangflowSecurityAnalyzer()

        with tempfile.TemporaryDirectory() as temp_dir:
            Path(temp_dir, "requirements.txt").write_text(
                "langflow-base==0.2.9\n",
                encoding="utf-8",
            )
            report = analyzer.analyze(temp_dir)
            self.assertEqual("VULNERABLE", _check_status(report, "CVE-2025-3248"))


if __name__ == "__main__":
    unittest.main()
