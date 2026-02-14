"""Tests for VPS audit parsing and rule checks."""

from __future__ import annotations

import os
import tempfile
import unittest

from coyote.patterns import Severity
from coyote.reporter import save_reports
from coyote.vps import (
    VpsAuditResult,
    VpsFinding,
    check_sshd_settings,
    check_unexpected_public_ports,
    parse_ss_listening_output,
    parse_sshd_config_text,
)


class VpsAuditParsingTests(unittest.TestCase):
    def test_parse_sshd_config_ignores_match_blocks(self) -> None:
        content = """
PermitRootLogin no
PasswordAuthentication no

Match User backup
    PasswordAuthentication yes
"""
        settings = parse_sshd_config_text(content)
        self.assertEqual("no", settings.get("permitrootlogin"))
        self.assertEqual("no", settings.get("passwordauthentication"))

    def test_check_sshd_settings_flags_insecure_values(self) -> None:
        settings = {
            "permitrootlogin": "yes",
            "passwordauthentication": "yes",
            "maxauthtries": "6",
            "ciphers": "aes256-cbc,chacha20-poly1305@openssh.com",
        }
        findings = check_sshd_settings(settings, ssh_config_path="/etc/ssh/sshd_config")
        by_id = {finding.check_id: finding for finding in findings}

        self.assertIn("VPS-SSH-002", by_id)
        self.assertIn("VPS-SSH-004", by_id)
        self.assertIn("VPS-SSH-006", by_id)
        self.assertIn("VPS-SSH-008", by_id)
        self.assertEqual(Severity.HIGH, by_id["VPS-SSH-002"].severity)

    def test_parse_ss_output_and_flag_unexpected_public_port(self) -> None:
        output = """Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:22      0.0.0.0:*
tcp   LISTEN 0      128    [::]:3306       [::]:*
tcp   LISTEN 0      128    127.0.0.1:5432  0.0.0.0:*
"""
        ports = parse_ss_listening_output(output)
        findings = check_unexpected_public_ports(ports, allow_public_ports={22, 80, 443})

        self.assertTrue(any(port.port == 3306 and port.is_public for port in ports))
        self.assertFalse(any(port.port == 5432 and port.is_public for port in ports))
        self.assertEqual(1, len(findings))
        self.assertEqual(Severity.HIGH, findings[0].severity)
        self.assertIn("3306", findings[0].evidence)

    def test_vps_result_converts_to_scan_result(self) -> None:
        vps_result = VpsAuditResult(
            target="host-a",
            timestamp="2026-02-11T00:00:00+00:00",
            allow_public_ports=[22, 80, 443],
            findings=[
                VpsFinding(
                    check_id="VPS-SSH-002",
                    severity=Severity.HIGH,
                    title="SSH root login is enabled",
                    description="Root login over SSH increases risk.",
                    evidence="/etc/ssh/sshd_config: PermitRootLogin yes",
                    remediation="Set PermitRootLogin no",
                )
            ],
            errors=["firewall check timed out"],
            checks_run=4,
        )

        scan_result = vps_result.to_scan_result()
        self.assertEqual("vps://host-a", scan_result.repo_path)
        self.assertEqual(1, scan_result.total_count)
        self.assertEqual(4, scan_result.files_scanned)
        self.assertEqual("VPS-SSH-002", scan_result.findings[0].rule_name)
        self.assertIn("Remediation", scan_result.findings[0].description)
        self.assertEqual(["firewall check timed out"], scan_result.errors)

    def test_vps_result_works_with_shared_report_pipeline(self) -> None:
        vps_result = VpsAuditResult(
            target="host-b",
            timestamp="2026-02-11T00:00:00+00:00",
            allow_public_ports=[22, 80, 443],
            findings=[
                VpsFinding(
                    check_id="VPS-NET-001",
                    severity=Severity.MEDIUM,
                    title="Unexpected public port exposed",
                    description="Non-allowlisted public port is open.",
                    evidence="TCP 0.0.0.0:3306",
                )
            ],
            checks_run=4,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            scan_result = vps_result.to_scan_result()
            paths = save_reports(
                scan_result,
                report_dir=temp_dir,
                formats=["json", "markdown", "sarif", "html"],
                commit_hash="",
            )
            self.assertEqual(4, len(paths))
            for path in paths:
                self.assertTrue(os.path.isfile(path), path)


if __name__ == "__main__":
    unittest.main()
