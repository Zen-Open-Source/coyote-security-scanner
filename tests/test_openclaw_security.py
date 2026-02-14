"""Tests for OpenClaw CVE security scanning."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from coyote.agents.openclaw import OpenClawSecurityAnalyzer


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


def _check_status(report, check_id: str) -> str:
    for check in report.checks:
        if check.check_id == check_id:
            return check.status
    raise AssertionError(f"Missing check: {check_id}")


class OpenClawSecurityTests(unittest.TestCase):
    def test_cve_version_thresholds(self) -> None:
        analyzer = OpenClawSecurityAnalyzer()

        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _write_json(base / "package.json", {"name": "openclaw", "version": "2026.1.29"})
            report = analyzer.analyze(temp_dir)

            self.assertEqual("SAFE", _check_status(report, "CVE-2026-25253"))
            self.assertEqual("SAFE", _check_status(report, "CVE-2026-24763"))
            self.assertEqual("SAFE", _check_status(report, "CVE-2026-25157"))
            self.assertEqual("VULNERABLE", _check_status(report, "CVE-2026-25475"))
            self.assertEqual("SAFE", _check_status(report, "CVE-2026-25593"))

    def test_cve_risky_config_patterns_on_patched_version(self) -> None:
        analyzer = OpenClawSecurityAnalyzer()

        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _write_json(base / "package.json", {"name": "openclaw", "version": "2026.1.30"})
            _write_json(
                base / "openclaw.config.json",
                {
                    "gatewayUrlSource": "query",
                    "dockerPath": "docker;id",
                    "mode": "remote",
                    "ssh": {
                        "command": "ssh {target}; id",
                        "targetSource": "query",
                    },
                    "media": {"path": "../../etc/passwd"},
                    "websocket": {
                        "host": "127.0.0.1",
                        "requireAuth": "off",
                    },
                    "config": {
                        "apply": {
                            "enabled": True,
                            "source": "query",
                        }
                    },
                },
            )
            report = analyzer.analyze(temp_dir)

            self.assertEqual("WARNING", _check_status(report, "CVE-2026-25253"))
            self.assertEqual("WARNING", _check_status(report, "CVE-2026-24763"))
            self.assertEqual("WARNING", _check_status(report, "CVE-2026-25157"))
            self.assertEqual("WARNING", _check_status(report, "CVE-2026-25475"))
            self.assertEqual("WARNING", _check_status(report, "CVE-2026-25593"))

    def test_unknown_version_marks_cve_checks_unknown(self) -> None:
        analyzer = OpenClawSecurityAnalyzer()

        with tempfile.TemporaryDirectory() as temp_dir:
            report = analyzer.analyze(temp_dir)
            self.assertEqual("UNKNOWN", _check_status(report, "CVE-2026-25253"))
            self.assertEqual("UNKNOWN", _check_status(report, "CVE-2026-24763"))
            self.assertEqual("UNKNOWN", _check_status(report, "CVE-2026-25157"))
            self.assertEqual("UNKNOWN", _check_status(report, "CVE-2026-25475"))
            self.assertEqual("UNKNOWN", _check_status(report, "CVE-2026-25593"))


if __name__ == "__main__":
    unittest.main()
