"""Tests for dependency vulnerability scanning."""

from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from coyote.deps import (
    COMPROMISED_DEPENDENCY_RULE_NAME,
    DEPENDENCY_RULE_NAME,
    SUPPLY_CHAIN_IOC_RULE_NAME,
    run_dependency_scan,
)
from coyote.gate import main as gate_main
from coyote.patterns import Severity


def _write_local_advisory_db(path: Path, advisories: list[dict[str, object]]) -> None:
    payload = {"advisories": advisories}
    path.write_text(json.dumps(payload), encoding="utf-8")


class DependencyScanTests(unittest.TestCase):
    def test_compromised_axios_release_is_flagged_without_advisory_feed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            package_lock = {
                "name": "demo-app",
                "lockfileVersion": 3,
                "packages": {
                    "": {
                        "name": "demo-app",
                        "version": "1.0.0",
                        "dependencies": {"axios": "1.14.1"},
                    },
                    "node_modules/axios": {"version": "1.14.1"},
                },
            }
            (base / "package-lock.json").write_text(json.dumps(package_lock), encoding="utf-8")
            (base / "src").mkdir()
            (base / "src" / "index.js").write_text("import axios from 'axios';\n", encoding="utf-8")
            advisory_db = base / "advisories.json"
            _write_local_advisory_db(advisory_db, advisories=[])

            result = run_dependency_scan(temp_dir, advisory_db_path=str(advisory_db))

            findings = [f for f in result.findings if f.rule_name == COMPROMISED_DEPENDENCY_RULE_NAME]
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual(Severity.HIGH, finding.severity)
            self.assertIn("axios@1.14.1", finding.matched_text)
            self.assertIn("March 31, 2026", finding.description)
            self.assertEqual("install-time", finding.metadata["execution_path"])

    def test_plain_crypto_js_ioc_is_flagged_without_reachability(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            package_lock = {
                "name": "demo-app",
                "lockfileVersion": 3,
                "packages": {
                    "": {
                        "name": "demo-app",
                        "version": "1.0.0",
                        "dependencies": {"axios": "1.14.0"},
                    },
                    "node_modules/axios": {"version": "1.14.0"},
                    "node_modules/plain-crypto-js": {"version": "0.0.1-security.0"},
                },
            }
            (base / "package-lock.json").write_text(json.dumps(package_lock), encoding="utf-8")
            advisory_db = base / "advisories.json"
            _write_local_advisory_db(advisory_db, advisories=[])

            result = run_dependency_scan(temp_dir, advisory_db_path=str(advisory_db))

            findings = [f for f in result.findings if f.rule_name == SUPPLY_CHAIN_IOC_RULE_NAME]
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual(Severity.HIGH, finding.severity)
            self.assertIn("plain-crypto-js", finding.description)
            self.assertIn("sfrclak.com:8000", finding.remediation)

    def test_requirements_scan_finds_pinned_vulnerable_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            (base / "requirements.txt").write_text(
                "requests==2.19.0\nflask>=2.0.0\n",
                encoding="utf-8",
            )
            advisory_db = base / "advisories.json"
            _write_local_advisory_db(
                advisory_db,
                advisories=[
                    {
                        "ecosystem": "pypi",
                        "name": "requests",
                        "version": "2.19.0",
                        "id": "CVE-2026-1111",
                        "summary": "Request smuggling issue in requests 2.19.0",
                        "severity": "HIGH",
                        "fixed_versions": ["2.31.0"],
                    }
                ],
            )

            result = run_dependency_scan(
                temp_dir,
                advisory_db_path=str(advisory_db),
            )

            self.assertEqual(1, result.total_count)
            finding = result.findings[0]
            self.assertEqual(DEPENDENCY_RULE_NAME, finding.rule_name)
            self.assertEqual(Severity.HIGH, finding.severity)
            self.assertEqual("requirements.txt", finding.file_path)
            self.assertEqual(1, finding.line_number)
            self.assertIn("CVE-2026-1111", finding.description)
            self.assertEqual("unknown", finding.metadata["reachability"])

    def test_skip_dev_dependencies_omits_poetry_dev_package(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            (base / "poetry.lock").write_text(
                """
[[package]]
name = "requests"
version = "2.19.0"
category = "main"

[[package]]
name = "pytest"
version = "7.3.0"
category = "dev"
""".strip(),
                encoding="utf-8",
            )
            advisory_db = base / "advisories.json"
            _write_local_advisory_db(
                advisory_db,
                advisories=[
                    {
                        "ecosystem": "pypi",
                        "name": "requests",
                        "version": "2.19.0",
                        "id": "CVE-2026-2222",
                        "summary": "Main package vulnerability",
                        "severity": "HIGH",
                    },
                    {
                        "ecosystem": "pypi",
                        "name": "pytest",
                        "version": "7.3.0",
                        "id": "CVE-2026-3333",
                        "summary": "Dev package vulnerability",
                        "severity": "HIGH",
                    },
                ],
            )

            result = run_dependency_scan(
                temp_dir,
                include_dev_dependencies=False,
                advisory_db_path=str(advisory_db),
            )

            self.assertEqual(1, result.total_count)
            self.assertIn("requests@2.19.0", result.findings[0].matched_text)
            self.assertNotIn("pytest@7.3.0", result.findings[0].matched_text)

    def test_package_lock_scoped_package_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            package_lock = {
                "name": "demo-app",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo-app", "version": "1.0.0"},
                    "node_modules/@scope/pkg": {"version": "1.2.3"},
                    "node_modules/lodash": {"version": "4.17.21"},
                },
            }
            (base / "package-lock.json").write_text(json.dumps(package_lock), encoding="utf-8")
            advisory_db = base / "advisories.json"
            _write_local_advisory_db(
                advisory_db,
                advisories=[
                    {
                        "ecosystem": "npm",
                        "name": "@scope/pkg",
                        "version": "1.2.3",
                        "id": "GHSA-aaaa-bbbb-cccc",
                        "summary": "Scoped package issue",
                        "severity": "MEDIUM",
                    }
                ],
            )

            result = run_dependency_scan(
                temp_dir,
                advisory_db_path=str(advisory_db),
            )

            self.assertEqual(1, result.total_count)
            finding = result.findings[0]
            self.assertEqual(Severity.MEDIUM, finding.severity)
            self.assertIn("@scope/pkg@1.2.3", finding.matched_text)

    def test_python_dependency_reachability_is_marked_reachable_when_imported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            (base / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
            (base / "app.py").write_text("import requests\n", encoding="utf-8")
            advisory_db = base / "advisories.json"
            _write_local_advisory_db(
                advisory_db,
                advisories=[
                    {
                        "ecosystem": "pypi",
                        "name": "requests",
                        "version": "2.19.0",
                        "id": "CVE-2026-6001",
                        "summary": "Reachable requests issue",
                        "severity": "HIGH",
                    }
                ],
            )

            result = run_dependency_scan(temp_dir, advisory_db_path=str(advisory_db))

            self.assertEqual(1, result.total_count)
            finding = result.findings[0]
            self.assertEqual("reachable", finding.metadata["reachability"])
            self.assertEqual("likely", finding.metadata["exploitability"])
            self.assertIn("requests", finding.metadata["reachability_imports"])
            self.assertIn("app.py", finding.metadata["reachability_files"])

    def test_python_dependency_reachability_marks_direct_unused_when_not_imported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            (base / "requirements.txt").write_text("urllib3==1.25.0\n", encoding="utf-8")
            (base / "app.py").write_text("import json\n", encoding="utf-8")
            advisory_db = base / "advisories.json"
            _write_local_advisory_db(
                advisory_db,
                advisories=[
                    {
                        "ecosystem": "pypi",
                        "name": "urllib3",
                        "version": "1.25.0",
                        "id": "CVE-2026-6002",
                        "summary": "Unused direct dependency issue",
                        "severity": "HIGH",
                    }
                ],
            )

            result = run_dependency_scan(temp_dir, advisory_db_path=str(advisory_db))

            self.assertEqual(1, result.total_count)
            finding = result.findings[0]
            self.assertEqual("direct-unused", finding.metadata["reachability"])
            self.assertEqual([], finding.metadata["reachability_imports"])

    def test_transitive_npm_dependency_is_marked_transitive_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            package_lock = {
                "name": "demo-app",
                "lockfileVersion": 3,
                "packages": {
                    "": {
                        "name": "demo-app",
                        "version": "1.0.0",
                        "dependencies": {"express": "4.18.2"},
                    },
                    "node_modules/express": {"version": "4.18.2"},
                    "node_modules/body-parser": {"version": "1.20.2"},
                },
            }
            (base / "package-lock.json").write_text(json.dumps(package_lock), encoding="utf-8")
            (base / "src").mkdir()
            (base / "src" / "index.js").write_text("import express from 'express';\n", encoding="utf-8")
            advisory_db = base / "advisories.json"
            _write_local_advisory_db(
                advisory_db,
                advisories=[
                    {
                        "ecosystem": "npm",
                        "name": "body-parser",
                        "version": "1.20.2",
                        "id": "GHSA-body-parser",
                        "summary": "Transitive package issue",
                        "severity": "MEDIUM",
                    }
                ],
            )

            result = run_dependency_scan(temp_dir, advisory_db_path=str(advisory_db))

            self.assertEqual(1, result.total_count)
            finding = result.findings[0]
            self.assertEqual("transitive-only", finding.metadata["reachability"])
            self.assertEqual("limited", finding.metadata["exploitability"])

    def test_dependency_findings_can_be_suppressed_by_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            (base / "requirements.txt").write_text("urllib3==1.25.0\n", encoding="utf-8")
            advisory_db = base / "advisories.json"
            _write_local_advisory_db(
                advisory_db,
                advisories=[
                    {
                        "ecosystem": "pypi",
                        "name": "urllib3",
                        "version": "1.25.0",
                        "id": "CVE-2026-4444",
                        "summary": "Known issue in urllib3",
                        "severity": "HIGH",
                    }
                ],
            )

            first = run_dependency_scan(temp_dir, advisory_db_path=str(advisory_db))
            self.assertEqual(1, first.total_count)
            finding_id = first.findings[0].finding_id

            (base / ".coyote-ignore").write_text(f"{finding_id}\n", encoding="utf-8")

            second = run_dependency_scan(temp_dir, advisory_db_path=str(advisory_db))
            self.assertEqual(0, second.total_count)
            self.assertEqual(1, second.findings_suppressed)

    def test_gate_can_fail_on_dependency_vulnerabilities(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            (base / "requirements.txt").write_text("urllib3==1.25.0\n", encoding="utf-8")
            advisory_db = base / "advisories.json"
            _write_local_advisory_db(
                advisory_db,
                advisories=[
                    {
                        "ecosystem": "pypi",
                        "name": "urllib3",
                        "version": "1.25.0",
                        "id": "CVE-2026-5555",
                        "summary": "High severity dependency vuln",
                        "severity": "HIGH",
                    }
                ],
            )

            stdout_buffer = StringIO()
            with redirect_stdout(stdout_buffer):
                exit_code = gate_main([
                    "--repo", temp_dir,
                    "--deps",
                    "--deps-advisory-db", str(advisory_db),
                    "--fail-on", "high",
                    "--json",
                ])

            self.assertEqual(1, exit_code)

    def test_gate_deps_reachable_only_ignores_unused_dependency_vulnerability(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            (base / "requirements.txt").write_text("urllib3==1.25.0\n", encoding="utf-8")
            (base / "app.py").write_text("import json\n", encoding="utf-8")
            advisory_db = base / "advisories.json"
            _write_local_advisory_db(
                advisory_db,
                advisories=[
                    {
                        "ecosystem": "pypi",
                        "name": "urllib3",
                        "version": "1.25.0",
                        "id": "CVE-2026-7777",
                        "summary": "Unused direct dependency vuln",
                        "severity": "HIGH",
                    }
                ],
            )

            stdout_buffer = StringIO()
            with redirect_stdout(stdout_buffer):
                exit_code = gate_main([
                    "--repo", temp_dir,
                    "--deps",
                    "--deps-advisory-db", str(advisory_db),
                    "--deps-reachable-only",
                    "--fail-on", "high",
                    "--json",
                ])

            self.assertEqual(0, exit_code)

    def test_gate_deps_reachable_only_fails_when_dependency_is_imported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            (base / "requirements.txt").write_text("urllib3==1.25.0\n", encoding="utf-8")
            (base / "app.py").write_text("import urllib3\n", encoding="utf-8")
            advisory_db = base / "advisories.json"
            _write_local_advisory_db(
                advisory_db,
                advisories=[
                    {
                        "ecosystem": "pypi",
                        "name": "urllib3",
                        "version": "1.25.0",
                        "id": "CVE-2026-7778",
                        "summary": "Reachable dependency vuln",
                        "severity": "HIGH",
                    }
                ],
            )

            stdout_buffer = StringIO()
            with redirect_stdout(stdout_buffer):
                exit_code = gate_main([
                    "--repo", temp_dir,
                    "--deps",
                    "--deps-advisory-db", str(advisory_db),
                    "--deps-reachable-only",
                    "--fail-on", "high",
                    "--json",
                ])

            self.assertEqual(1, exit_code)

    def test_gate_deps_reachable_only_still_fails_on_supply_chain_ioc(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            package_lock = {
                "name": "demo-app",
                "lockfileVersion": 3,
                "packages": {
                    "": {
                        "name": "demo-app",
                        "version": "1.0.0",
                        "dependencies": {"axios": "1.14.0"},
                    },
                    "node_modules/axios": {"version": "1.14.0"},
                    "node_modules/plain-crypto-js": {"version": "0.0.1-security.0"},
                },
            }
            (base / "package-lock.json").write_text(json.dumps(package_lock), encoding="utf-8")
            advisory_db = base / "advisories.json"
            _write_local_advisory_db(advisory_db, advisories=[])

            stdout_buffer = StringIO()
            with redirect_stdout(stdout_buffer):
                exit_code = gate_main([
                    "--repo", temp_dir,
                    "--deps",
                    "--deps-advisory-db", str(advisory_db),
                    "--deps-reachable-only",
                    "--fail-on", "high",
                    "--json",
                ])

            self.assertEqual(1, exit_code)


if __name__ == "__main__":
    unittest.main()
