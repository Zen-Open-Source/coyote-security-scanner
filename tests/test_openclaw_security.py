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


ALL_TRACKED_CVES = [
    "CVE-2026-25253",
    "CVE-2026-24763",
    "CVE-2026-25157",
    "CVE-2026-25475",
    "CVE-2026-25593",
    "CVE-2026-26324",
    "CVE-2026-26325",
    "CVE-2026-26316",
    "CVE-2026-26326",
    "CVE-2026-27003",
    "CVE-2026-27009",
    "CVE-2026-26320",
    "CVE-2026-27487",
    "CVE-2026-27486",
    "CVE-2026-27485",
]


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
            # Newly added Feb 2026 CVEs should be present
            self.assertEqual("VULNERABLE", _check_status(report, "CVE-2026-26324"))
            self.assertEqual("VULNERABLE", _check_status(report, "CVE-2026-26325"))
            self.assertEqual("VULNERABLE", _check_status(report, "CVE-2026-26316"))
            self.assertEqual("VULNERABLE", _check_status(report, "CVE-2026-26326"))
            self.assertEqual("VULNERABLE", _check_status(report, "CVE-2026-27003"))
            self.assertEqual("VULNERABLE", _check_status(report, "CVE-2026-27009"))
            self.assertEqual("SAFE", _check_status(report, "CVE-2026-26320"))
            self.assertEqual("VULNERABLE", _check_status(report, "CVE-2026-27487"))
            self.assertEqual("VULNERABLE", _check_status(report, "CVE-2026-27486"))
            self.assertEqual("VULNERABLE", _check_status(report, "CVE-2026-27485"))

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

    def test_new_cve_version_thresholds(self) -> None:
        analyzer = OpenClawSecurityAnalyzer()

        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _write_json(base / "package.json", {"name": "openclaw", "version": "2026.2.15"})
            report = analyzer.analyze(temp_dir)

            self.assertEqual("SAFE", _check_status(report, "CVE-2026-26324"))
            self.assertEqual("SAFE", _check_status(report, "CVE-2026-26325"))
            self.assertEqual("SAFE", _check_status(report, "CVE-2026-26316"))
            self.assertEqual("SAFE", _check_status(report, "CVE-2026-26326"))
            self.assertEqual("SAFE", _check_status(report, "CVE-2026-27003"))
            self.assertEqual("SAFE", _check_status(report, "CVE-2026-27009"))
            self.assertEqual("SAFE", _check_status(report, "CVE-2026-26320"))
            self.assertEqual("SAFE", _check_status(report, "CVE-2026-27487"))
            self.assertEqual("SAFE", _check_status(report, "CVE-2026-27486"))
            self.assertEqual("VULNERABLE", _check_status(report, "CVE-2026-27485"))

    def test_new_cve_risky_config_patterns_on_patched_version(self) -> None:
        analyzer = OpenClawSecurityAnalyzer()

        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _write_json(base / "package.json", {"name": "openclaw", "version": "2026.2.19"})
            _write_json(
                base / "openclaw.config.json",
                {
                    "gatewayUrlSource": "query",
                    "ssrf": {"allowLocalhost": True},
                    "ssrfBypassProbe": "0:0:0:0:0:ffff:7f00:1",
                    "tools": {"exec": {"host": "node"}},
                    "security": {"mode": "allowlist"},
                    "ask": "on-miss",
                    "rawCommand": "echo hi; id",
                    "command": ["echo", "hi"],
                    "bluebubbles": {
                        "enabled": True,
                        "webhookSecret": "short",
                        "requireWebhookAuth": False,
                    },
                    "bind": "127.0.0.1",
                    "operatorScopes": ["operator.read"],
                    "skills": {"status": {"enabled": True}},
                    "discord": {"token": "discord-secret-token-value"},
                    "telegram": {"token": "123456:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
                    "logging": {"redactTokens": False},
                    "assistant": {"name": "<script>alert(1)</script>"},
                    "controlUi": {"csp": "default-src 'self'; script-src 'unsafe-inline'"},
                    "platform": "macos",
                    "deepLink": {"enabled": True},
                    "deepLinkProbe": "openclaw://agent?cmd=unsafe",
                    "auth": {"provider": "claude", "keychain": {"enabled": True}},
                    "keychain": {"command": "sh -c security add-generic-password $TOKEN"},
                    "cleanup": {"enabled": True, "scope": "global", "command": "pkill -f openclaw"},
                    "skillsPackaging": {"followSymlinks": True},
                    "skills": {
                        "packaging": {"followSymlinks": True, "script": "package_skill.py"},
                        "status": {"enabled": True},
                    },
                },
            )
            (base / "skills" / "skill-creator" / "scripts").mkdir(parents=True, exist_ok=True)
            (base / "skills" / "skill-creator" / "scripts" / "package_skill.py").write_text(
                "# stub",
                encoding="utf-8",
            )

            report = analyzer.analyze(temp_dir)

            self.assertEqual("WARNING", _check_status(report, "CVE-2026-26324"))
            self.assertEqual("WARNING", _check_status(report, "CVE-2026-26325"))
            self.assertEqual("WARNING", _check_status(report, "CVE-2026-26316"))
            self.assertEqual("WARNING", _check_status(report, "CVE-2026-26326"))
            self.assertEqual("WARNING", _check_status(report, "CVE-2026-27003"))
            self.assertEqual("WARNING", _check_status(report, "CVE-2026-27009"))
            self.assertEqual("WARNING", _check_status(report, "CVE-2026-26320"))
            self.assertEqual("WARNING", _check_status(report, "CVE-2026-27487"))
            self.assertEqual("WARNING", _check_status(report, "CVE-2026-27486"))
            self.assertEqual("WARNING", _check_status(report, "CVE-2026-27485"))

    def test_unknown_version_marks_cve_checks_unknown(self) -> None:
        analyzer = OpenClawSecurityAnalyzer()

        with tempfile.TemporaryDirectory() as temp_dir:
            report = analyzer.analyze(temp_dir)
            for check_id in ALL_TRACKED_CVES:
                self.assertEqual("UNKNOWN", _check_status(report, check_id))


if __name__ == "__main__":
    unittest.main()
