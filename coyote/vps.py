"""VPS hardening and exposure audit checks for Coyote."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .config import load_config
from .html_report import generate_html_report
from .patterns import PatternMatch, Severity
from .reporter import save_reports
from .sarif import generate_sarif, sarif_to_json
from .scanner import ScanResult, generate_finding_id


DEFAULT_ALLOWED_PUBLIC_PORTS = {22, 80, 443}
HIGH_RISK_PUBLIC_PORTS = {21, 23, 2375, 3306, 5432, 6379, 9200, 11211, 27017}
WEAK_SSH_CIPHERS = {
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "arcfour",
    "blowfish-cbc",
    "cast128-cbc",
}


@dataclass
class ListeningPort:
    proto: str
    address: str
    port: int
    is_public: bool


@dataclass
class VpsFinding:
    check_id: str
    severity: Severity
    title: str
    description: str
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "check_id": self.check_id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class VpsAuditResult:
    target: str
    timestamp: str
    allow_public_ports: list[int]
    findings: list[VpsFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    checks_run: int = 0
    checks_failed: int = 0
    checks_warned: int = 0

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def total_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict[str, object]:
        return {
            "scanner": f"Coyote v{__version__}",
            "mode": "vps_audit",
            "target": self.target,
            "timestamp": self.timestamp,
            "allow_public_ports": self.allow_public_ports,
            "summary": {
                "checks_run": self.checks_run,
                "checks_failed": self.checks_failed,
                "checks_warned": self.checks_warned,
                "total_findings": self.total_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": self.errors,
        }

    def to_scan_result(self) -> ScanResult:
        """Convert VPS findings to ScanResult for shared report pipelines."""
        converted_findings: list[PatternMatch] = []

        for finding in self.findings:
            matched = finding.evidence[:120]
            description = finding.description
            if finding.remediation:
                description += f" Remediation: {finding.remediation}"

            finding_id = generate_finding_id(
                finding.check_id,
                f"vps/{self.target}",
                0,
                f"{finding.title}|{finding.evidence}",
            )

            converted_findings.append(
                PatternMatch(
                    rule_name=finding.check_id,
                    severity=finding.severity,
                    file_path=f"vps/{self.target}",
                    line_number=0,
                    line_content=finding.evidence[:200],
                    description=description,
                    matched_text=matched if matched else "",
                    finding_id=finding_id,
                )
            )

        return ScanResult(
            repo_path=f"vps://{self.target}",
            findings=converted_findings,
            files_scanned=self.checks_run,
            files_skipped=0,
            errors=list(self.errors),
        )


def _run_command(cmd: list[str], timeout: int = 8) -> tuple[int, str, str] | None:
    """Run a local command and return (code, stdout, stderr)."""
    if shutil.which(cmd[0]) is None:
        return None

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", "command timed out"
    except OSError as exc:
        return 127, "", str(exc)


def parse_sshd_config_text(content: str) -> dict[str, str]:
    """Parse the global section of sshd_config into a key/value map."""
    settings: dict[str, str] = {}
    in_match_block = False

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line.lower().startswith("match "):
            in_match_block = True
            continue

        if in_match_block:
            continue

        if "#" in line:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue

        parts = line.split(None, 1)
        if len(parts) != 2:
            continue

        key = parts[0].strip().lower()
        value = parts[1].strip()
        settings[key] = value

    return settings


def check_sshd_settings(settings: dict[str, str], ssh_config_path: str = "/etc/ssh/sshd_config") -> list[VpsFinding]:
    """Evaluate SSH hardening settings from parsed sshd_config."""
    findings: list[VpsFinding] = []

    permit_root_login = settings.get("permitrootlogin", "").lower()
    if not permit_root_login:
        findings.append(VpsFinding(
            check_id="VPS-SSH-001",
            severity=Severity.LOW,
            title="PermitRootLogin not explicitly configured",
            description="Set PermitRootLogin explicitly to 'no' to avoid weak defaults across distributions.",
            evidence=f"{ssh_config_path}: PermitRootLogin missing",
            remediation="Add 'PermitRootLogin no' to sshd_config and reload sshd.",
        ))
    elif permit_root_login == "yes":
        findings.append(VpsFinding(
            check_id="VPS-SSH-002",
            severity=Severity.HIGH,
            title="SSH root login is enabled",
            description="Root login over SSH increases brute-force and credential abuse risk.",
            evidence=f"{ssh_config_path}: PermitRootLogin {settings.get('permitrootlogin')}",
            remediation="Set 'PermitRootLogin no' and use sudo from a non-root account.",
        ))

    password_auth = settings.get("passwordauthentication", "").lower()
    if not password_auth:
        findings.append(VpsFinding(
            check_id="VPS-SSH-003",
            severity=Severity.LOW,
            title="PasswordAuthentication not explicitly configured",
            description="Set PasswordAuthentication explicitly to enforce key-only authentication.",
            evidence=f"{ssh_config_path}: PasswordAuthentication missing",
            remediation="Add 'PasswordAuthentication no' to sshd_config and reload sshd.",
        ))
    elif password_auth == "yes":
        findings.append(VpsFinding(
            check_id="VPS-SSH-004",
            severity=Severity.HIGH,
            title="SSH password authentication is enabled",
            description="Password auth materially increases exposure to brute-force and credential stuffing.",
            evidence=f"{ssh_config_path}: PasswordAuthentication {settings.get('passwordauthentication')}",
            remediation="Set 'PasswordAuthentication no' and require public key authentication.",
        ))

    pubkey_auth = settings.get("pubkeyauthentication", "").lower()
    if pubkey_auth == "no":
        findings.append(VpsFinding(
            check_id="VPS-SSH-005",
            severity=Severity.MEDIUM,
            title="SSH public key authentication is disabled",
            description="Disabling public key auth pushes users toward weaker auth methods.",
            evidence=f"{ssh_config_path}: PubkeyAuthentication {settings.get('pubkeyauthentication')}",
            remediation="Set 'PubkeyAuthentication yes' and provision managed SSH keys.",
        ))

    max_auth_tries = settings.get("maxauthtries")
    if max_auth_tries:
        try:
            tries = int(max_auth_tries.split()[0])
            if tries > 4:
                findings.append(VpsFinding(
                    check_id="VPS-SSH-006",
                    severity=Severity.MEDIUM,
                    title="SSH MaxAuthTries is high",
                    description="Allowing many authentication attempts can help brute-force attacks.",
                    evidence=f"{ssh_config_path}: MaxAuthTries {max_auth_tries}",
                    remediation="Set 'MaxAuthTries 4' or lower.",
                ))
        except ValueError:
            findings.append(VpsFinding(
                check_id="VPS-SSH-007",
                severity=Severity.LOW,
                title="SSH MaxAuthTries has an invalid value",
                description="Invalid auth-tries settings may lead to insecure defaults.",
                evidence=f"{ssh_config_path}: MaxAuthTries {max_auth_tries}",
                remediation="Set a numeric value such as 'MaxAuthTries 4'.",
            ))

    ciphers = settings.get("ciphers", "")
    if ciphers:
        cipher_list = [item.strip().lower() for item in ciphers.replace(" ", "").split(",") if item.strip()]
        weak = sorted(set(cipher_list) & WEAK_SSH_CIPHERS)
        if weak:
            findings.append(VpsFinding(
                check_id="VPS-SSH-008",
                severity=Severity.HIGH,
                title="Weak SSH ciphers configured",
                description="CBC and legacy ciphers are deprecated and weaken transport security.",
                evidence=f"{ssh_config_path}: weak ciphers -> {', '.join(weak)}",
                remediation="Use modern ciphers such as chacha20-poly1305 and aes256-gcm.",
            ))

    return findings


def _parse_endpoint(endpoint: str) -> tuple[str, int] | None:
    endpoint = endpoint.strip()
    if not endpoint or endpoint == "*":
        return None

    if endpoint.startswith("["):
        close = endpoint.find("]")
        if close == -1:
            return None
        host = endpoint[1:close]
        remainder = endpoint[close + 1:]
        if not remainder.startswith(":"):
            return None
        port_str = remainder[1:]
    else:
        if ":" not in endpoint:
            return None
        host, port_str = endpoint.rsplit(":", 1)

    host = host.strip().split("%", 1)[0]
    if port_str in {"*", ""}:
        return None

    try:
        port = int(port_str)
    except ValueError:
        return None

    return host, port


def parse_ss_listening_output(output: str) -> list[ListeningPort]:
    """Parse `ss -tuln` output into normalized listening-port entries."""
    listening: list[ListeningPort] = []

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.lower().startswith("netid"):
            continue

        parts = line.split()
        if len(parts) < 5:
            continue

        proto = parts[0].lower()
        state = parts[1].upper()
        if proto.startswith("tcp") and state != "LISTEN":
            continue
        if proto.startswith("udp") and state not in {"UNCONN", "LISTEN"}:
            continue

        local_endpoint = parts[-2]
        parsed = _parse_endpoint(local_endpoint)
        if parsed is None:
            continue

        host, port = parsed
        is_public = host in {"0.0.0.0", "::", "*"}
        listening.append(ListeningPort(proto=proto, address=host, port=port, is_public=is_public))

    return listening


def check_unexpected_public_ports(
    listening_ports: list[ListeningPort],
    allow_public_ports: set[int],
) -> list[VpsFinding]:
    """Generate findings for public ports that are not explicitly allowed."""
    findings: list[VpsFinding] = []
    seen: set[tuple[str, str, int]] = set()

    for entry in listening_ports:
        key = (entry.proto, entry.address, entry.port)
        if key in seen:
            continue
        seen.add(key)

        if not entry.is_public:
            continue
        if entry.port in allow_public_ports:
            continue

        severity = Severity.HIGH if entry.port in HIGH_RISK_PUBLIC_PORTS else Severity.MEDIUM
        findings.append(VpsFinding(
            check_id="VPS-NET-001",
            severity=severity,
            title="Unexpected public port exposed",
            description="A service is listening on a public interface on a non-allowlisted port.",
            evidence=f"{entry.proto.upper()} {entry.address}:{entry.port}",
            remediation="Restrict binding to localhost, firewall the port, or explicitly allow it if intentional.",
        ))

    return findings


def audit_sshd_config(path: str) -> tuple[list[VpsFinding], list[str]]:
    """Audit SSH daemon hardening configuration."""
    findings: list[VpsFinding] = []
    errors: list[str] = []

    if not os.path.isfile(path):
        findings.append(VpsFinding(
            check_id="VPS-SSH-000",
            severity=Severity.LOW,
            title="SSH daemon config not found",
            description="Could not inspect sshd configuration at the expected path.",
            evidence=path,
            remediation="If SSH is used, pass --ssh-config with the correct path.",
        ))
        return findings, errors

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            content = handle.read()
    except OSError as exc:
        errors.append(f"Failed reading SSH config '{path}': {exc}")
        findings.append(VpsFinding(
            check_id="VPS-SSH-ERR",
            severity=Severity.MEDIUM,
            title="Unable to read SSH daemon config",
            description="SSH hardening checks could not run due to a file read failure.",
            evidence=str(exc),
            remediation="Check file permissions and rerun the audit.",
        ))
        return findings, errors

    settings = parse_sshd_config_text(content)
    findings.extend(check_sshd_settings(settings, ssh_config_path=path))
    return findings, errors


def audit_firewall_state() -> tuple[list[VpsFinding], list[str]]:
    """Audit host firewall status using ufw/nftables/iptables signals."""
    findings: list[VpsFinding] = []
    errors: list[str] = []

    ufw = _run_command(["ufw", "status"])
    if ufw is not None:
        code, stdout, stderr = ufw
        if code == 0 and "Status: active" in stdout:
            return findings, errors
        if code == 0:
            findings.append(VpsFinding(
                check_id="VPS-FW-001",
                severity=Severity.HIGH,
                title="UFW is not active",
                description="Host firewall appears disabled.",
                evidence=stdout or "ufw status returned inactive",
                remediation="Enable UFW and define explicit allow/deny rules.",
            ))
            return findings, errors

        errors.append(f"ufw status failed: {stderr or stdout or f'code {code}'}")

    nft = _run_command(["nft", "list", "ruleset"])
    if nft is not None:
        code, stdout, stderr = nft
        if code == 0 and stdout.strip():
            return findings, errors
        if code == 0:
            findings.append(VpsFinding(
                check_id="VPS-FW-002",
                severity=Severity.HIGH,
                title="nftables has no active rules",
                description="nftables is installed but no active filtering rules were detected.",
                evidence="nft list ruleset returned empty output",
                remediation="Add nftables policies to restrict inbound exposure.",
            ))
            return findings, errors
        errors.append(f"nft list ruleset failed: {stderr or stdout or f'code {code}'}")

    iptables = _run_command(["iptables", "-S"])
    if iptables is not None:
        code, stdout, stderr = iptables
        if code == 0:
            has_filter_rules = any(line.startswith("-A ") for line in stdout.splitlines())
            if has_filter_rules:
                return findings, errors
            findings.append(VpsFinding(
                check_id="VPS-FW-003",
                severity=Severity.HIGH,
                title="iptables has no active filter rules",
                description="iptables appears present but no explicit allow/deny chains were found.",
                evidence="iptables -S contained no '-A' rules",
                remediation="Configure iptables policies to restrict inbound traffic.",
            ))
            return findings, errors

        errors.append(f"iptables -S failed: {stderr or stdout or f'code {code}'}")

    findings.append(VpsFinding(
        check_id="VPS-FW-004",
        severity=Severity.MEDIUM,
        title="Firewall status could not be verified",
        description="No supported firewall tool was detected, or all checks failed.",
        evidence="ufw/nft/iptables unavailable or errored",
        remediation="Install and configure a host firewall (ufw, nftables, or iptables).",
    ))
    return findings, errors


def audit_fail2ban_state() -> tuple[list[VpsFinding], list[str]]:
    """Audit whether fail2ban is installed and running."""
    findings: list[VpsFinding] = []
    errors: list[str] = []

    systemctl = _run_command(["systemctl", "is-active", "fail2ban"])
    if systemctl is not None:
        code, stdout, stderr = systemctl
        state = stdout.strip().lower()
        if code == 0 and state == "active":
            return findings, errors

        if "not-found" in state or "could not be found" in stderr.lower():
            findings.append(VpsFinding(
                check_id="VPS-BF-001",
                severity=Severity.LOW,
                title="fail2ban is not installed",
                description="No brute-force protection service was detected.",
                evidence=stdout or stderr or "service not found",
                remediation="Install fail2ban and enable the sshd jail.",
            ))
            return findings, errors

        if state in {"inactive", "failed", "deactivating"}:
            findings.append(VpsFinding(
                check_id="VPS-BF-002",
                severity=Severity.MEDIUM,
                title="fail2ban service is not active",
                description="Brute-force protection is installed but not actively enforcing bans.",
                evidence=stdout or stderr or "service inactive",
                remediation="Enable and start fail2ban; verify sshd jail configuration.",
            ))
            return findings, errors

        errors.append(f"systemctl is-active fail2ban failed: {stderr or stdout or f'code {code}'}")

    fail2ban_client = _run_command(["fail2ban-client", "ping"])
    if fail2ban_client is not None:
        code, stdout, stderr = fail2ban_client
        if code == 0 and "pong" in stdout.lower():
            return findings, errors

        findings.append(VpsFinding(
            check_id="VPS-BF-003",
            severity=Severity.MEDIUM,
            title="fail2ban daemon not responding",
            description="fail2ban-client is available, but the daemon did not respond to ping.",
            evidence=stderr or stdout or f"exit code {code}",
            remediation="Restart fail2ban and inspect logs for startup failures.",
        ))
        return findings, errors

    findings.append(VpsFinding(
        check_id="VPS-BF-004",
        severity=Severity.LOW,
        title="fail2ban tooling not found",
        description="Unable to verify brute-force protections because fail2ban is not installed.",
        evidence="fail2ban-client not found",
        remediation="Install fail2ban and configure a jail for SSH.",
    ))
    return findings, errors


def audit_open_ports(allow_public_ports: set[int]) -> tuple[list[VpsFinding], list[str]]:
    """Audit public listening ports against an allowlist."""
    findings: list[VpsFinding] = []
    errors: list[str] = []

    ss_result = _run_command(["ss", "-tuln"])
    if ss_result is None:
        findings.append(VpsFinding(
            check_id="VPS-NET-000",
            severity=Severity.MEDIUM,
            title="Unable to inspect listening ports",
            description="`ss` command is unavailable; network exposure could not be audited.",
            evidence="ss command not found",
            remediation="Install iproute2 (`ss`) and rerun the audit.",
        ))
        return findings, errors

    code, stdout, stderr = ss_result
    if code != 0:
        findings.append(VpsFinding(
            check_id="VPS-NET-ERR",
            severity=Severity.MEDIUM,
            title="Listening port check failed",
            description="The port exposure check failed before results could be parsed.",
            evidence=stderr or stdout or f"ss exit code {code}",
            remediation="Run `ss -tuln` manually and fix host command/runtime issues.",
        ))
        return findings, errors

    listening_ports = parse_ss_listening_output(stdout)
    findings.extend(check_unexpected_public_ports(listening_ports, allow_public_ports))
    return findings, errors


def _record_check(result: VpsAuditResult, findings: list[VpsFinding], errors: list[str]) -> None:
    result.checks_run += 1
    result.findings.extend(findings)
    result.errors.extend(errors)

    if not findings:
        return

    if any(finding.severity in (Severity.HIGH, Severity.MEDIUM) for finding in findings):
        result.checks_failed += 1
    else:
        result.checks_warned += 1


def run_local_vps_audit(
    allow_public_ports: set[int] | None = None,
    ssh_config_path: str = "/etc/ssh/sshd_config",
) -> VpsAuditResult:
    """Run a local-host VPS audit."""
    allow_set = set(allow_public_ports or DEFAULT_ALLOWED_PUBLIC_PORTS)
    result = VpsAuditResult(
        target=socket.gethostname(),
        timestamp=datetime.now(timezone.utc).isoformat(),
        allow_public_ports=sorted(allow_set),
    )

    findings, errors = audit_sshd_config(ssh_config_path)
    _record_check(result, findings, errors)

    findings, errors = audit_firewall_state()
    _record_check(result, findings, errors)

    findings, errors = audit_open_ports(allow_set)
    _record_check(result, findings, errors)

    findings, errors = audit_fail2ban_state()
    _record_check(result, findings, errors)

    severity_order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
    result.findings.sort(key=lambda finding: severity_order.get(finding.severity, 3))
    return result


def _should_fail(result: VpsAuditResult, fail_on: str) -> bool:
    if fail_on == "none":
        return False
    if fail_on == "high":
        return result.high_count > 0
    if fail_on == "medium":
        return (result.high_count + result.medium_count) > 0
    if fail_on == "low":
        return result.total_count > 0
    return False


def _print_human_report(result: VpsAuditResult, console: Console) -> None:
    summary = Text()
    summary.append(f"Target: {result.target}\n", style="white")
    summary.append(f"Timestamp: {result.timestamp}\n", style="dim")
    summary.append(f"Checks run: {result.checks_run}\n", style="bold")
    summary.append(f"Checks failed: {result.checks_failed}\n", style="bold red" if result.checks_failed else "green")
    summary.append(f"Checks warned: {result.checks_warned}\n", style="bold yellow" if result.checks_warned else "dim")
    summary.append(
        f"Findings: {result.total_count} ({result.high_count} HIGH, {result.medium_count} MEDIUM, {result.low_count} LOW)",
        style="bold",
    )

    console.print(
        Panel(
            summary,
            title=f"[bold cyan]COYOTE v{__version__} VPS Audit[/]",
            border_style="cyan",
        )
    )

    if result.findings:
        table = Table(show_header=True, header_style="bold", expand=True, show_lines=False)
        table.add_column("Sev", width=6, justify="center")
        table.add_column("Check", width=12)
        table.add_column("Title", width=30)
        table.add_column("Evidence", ratio=1)

        for finding in result.findings:
            if finding.severity == Severity.HIGH:
                sev_style, sev_label = "bold red", "HIGH"
            elif finding.severity == Severity.MEDIUM:
                sev_style, sev_label = "bold yellow", "MED"
            else:
                sev_style, sev_label = "bold blue", "LOW"

            table.add_row(
                Text(sev_label, style=sev_style),
                Text(finding.check_id, style="dim"),
                Text(finding.title, style="white"),
                Text(finding.evidence or finding.description, style="dim"),
            )

        console.print(table)
    else:
        console.print("[bold green]No VPS hardening issues detected by current checks.[/]")

    if result.errors:
        console.print("\n[bold yellow]Check Errors[/]")
        for err in result.errors:
            console.print(f"- [dim]{err}[/]")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Coyote VPS Security Audit",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit_parser = subparsers.add_parser(
        "audit",
        help="Audit local VPS hardening posture",
    )
    audit_parser.add_argument(
        "--local",
        action="store_true",
        default=True,
        help="Audit the local host (currently the only supported target).",
    )
    audit_parser.add_argument(
        "--allow-port",
        action="append",
        dest="allow_ports",
        type=int,
        default=[],
        help="Allowlist a public port (repeatable). Defaults: 22, 80, 443.",
    )
    audit_parser.add_argument(
        "--ssh-config",
        default="/etc/ssh/sshd_config",
        help="Path to sshd_config (default: /etc/ssh/sshd_config).",
    )
    audit_parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON report to stdout.",
    )
    audit_parser.add_argument(
        "--output",
        help="Write JSON report to a file.",
    )
    audit_parser.add_argument(
        "--config",
        default="config.yaml",
        help="Config file path for report defaults (default: config.yaml).",
    )
    audit_parser.add_argument(
        "--report",
        "-r",
        action="store_true",
        help="Save reports using configured output formats.",
    )
    audit_parser.add_argument(
        "--report-dir",
        help="Override output directory for saved reports.",
    )
    audit_parser.add_argument(
        "--sarif",
        nargs="?",
        const="-",
        metavar="FILE",
        help="Output results in SARIF format (to stdout or FILE).",
    )
    audit_parser.add_argument(
        "--sarif-output",
        metavar="FILE",
        help="Write SARIF output to FILE.",
    )
    audit_parser.add_argument(
        "--html",
        nargs="?",
        const="-",
        metavar="FILE",
        help="Output results as HTML dashboard (to FILE or stdout).",
    )
    audit_parser.add_argument(
        "--fail-on",
        choices=["none", "high", "medium", "low"],
        default="none",
        help="Exit non-zero when findings reach threshold (default: none).",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "audit":
        parser.error(f"Unknown command: {args.command}")

    sarif_output_path = args.sarif_output or args.sarif
    if sarif_output_path == "-" and args.html == "-":
        parser.error("--sarif - cannot be combined with --html -")
    if args.json and (sarif_output_path == "-" or args.html == "-"):
        parser.error("--json cannot be combined with --sarif - or --html -")

    allow_set = set(DEFAULT_ALLOWED_PUBLIC_PORTS)
    allow_set.update(args.allow_ports)
    result = run_local_vps_audit(allow_public_ports=allow_set, ssh_config_path=args.ssh_config)
    shared_result = result.to_scan_result()
    config = load_config(args.config)
    report_dir = args.report_dir or config.output.report_dir

    stdout_output = args.json or sarif_output_path == "-" or args.html == "-"
    console = Console(stderr=True) if stdout_output else Console()

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_human_report(result, console)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(result.to_dict(), handle, indent=2)

    if args.report:
        saved = save_reports(
            shared_result,
            report_dir=report_dir,
            formats=list(config.output.format),
            commit_hash="",
        )
        for path in saved:
            console.print(f"[dim]Report saved: {path}[/]")

    if sarif_output_path:
        sarif_doc = generate_sarif(shared_result)
        sarif_json = sarif_to_json(sarif_doc)
        if sarif_output_path == "-":
            print(sarif_json)
        else:
            os.makedirs(os.path.dirname(sarif_output_path) or ".", exist_ok=True)
            with open(sarif_output_path, "w", encoding="utf-8") as handle:
                handle.write(sarif_json)
            console.print(f"[dim]SARIF report saved: {sarif_output_path}[/]")

    if args.html:
        html_content = generate_html_report(shared_result, "")
        if args.html == "-":
            print(html_content)
        else:
            os.makedirs(os.path.dirname(args.html) or ".", exist_ok=True)
            with open(args.html, "w", encoding="utf-8") as handle:
                handle.write(html_content)
            console.print(f"[dim]HTML report saved: {args.html}[/]")

    return 1 if _should_fail(result, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
