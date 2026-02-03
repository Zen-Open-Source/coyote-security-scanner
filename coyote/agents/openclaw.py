"""
OpenClaw Security Analyzer

Detects CVE-2026-25253 (WebSocket hijacking / token exfiltration → RCE)
and performs general OpenClaw hardening checks.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class OpenClawSecurityCheck:
    """Result of a single security check."""

    check_id: str
    name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    status: str  # VULNERABLE, WARNING, SAFE, UNKNOWN
    description: str
    detail: str
    remediation: str


@dataclass
class OpenClawSecurityReport:
    """Aggregated security report for an OpenClaw installation."""

    agent_path: str
    openclaw_version: str | None
    checks: list[OpenClawSecurityCheck] = field(default_factory=list)

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for c in self.checks if c.status == "VULNERABLE")

    @property
    def warning_count(self) -> int:
        return sum(1 for c in self.checks if c.status == "WARNING")

    @property
    def safe_count(self) -> int:
        return sum(1 for c in self.checks if c.status == "SAFE")

    @property
    def unknown_count(self) -> int:
        return sum(1 for c in self.checks if c.status == "UNKNOWN")

    @property
    def max_severity(self) -> str:
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        worst = "LOW"
        for c in self.checks:
            if c.status in ("VULNERABLE", "WARNING"):
                if order.get(c.severity, 0) > order.get(worst, 0):
                    worst = c.severity
        return worst

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_path": self.agent_path,
            "openclaw_version": self.openclaw_version,
            "summary": {
                "vulnerable": self.vulnerable_count,
                "warning": self.warning_count,
                "safe": self.safe_count,
                "unknown": self.unknown_count,
                "max_severity": self.max_severity,
            },
            "checks": [
                {
                    "check_id": c.check_id,
                    "name": c.name,
                    "severity": c.severity,
                    "status": c.status,
                    "description": c.description,
                    "detail": c.detail,
                    "remediation": c.remediation,
                }
                for c in self.checks
            ],
        }


# Version where CVE-2026-25253 was fixed
_CVE_FIX_VERSION = (2026, 1, 29)


def _parse_version(version_str: str) -> tuple[int, ...] | None:
    """Parse a dotted version string into a tuple of ints."""
    match = re.search(r"(\d+(?:\.\d+)+)", version_str)
    if not match:
        return None
    try:
        return tuple(int(p) for p in match.group(1).split("."))
    except ValueError:
        return None


def _load_json_file(path: Path) -> dict[str, Any] | None:
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _find_config_files(base: Path) -> list[Path]:
    """Find OpenClaw-related config files in the given path."""
    candidates = []
    if base.is_file():
        candidates.append(base)
        return candidates

    patterns = [
        "package.json",
        "openclaw.json",
        "openclaw.config.json",
        "config.json",
        ".openclaw/config.json",
        "gateway.json",
        "gateway.config.json",
        "settings.json",
    ]
    for pattern in patterns:
        p = base / pattern
        if p.exists():
            candidates.append(p)

    # Also glob for yaml/toml
    for ext in ("*.json", "*.yaml", "*.yml", "*.toml"):
        for p in base.glob(ext):
            if p not in candidates:
                candidates.append(p)

    # Check subdirectories one level deep
    for subdir in (".openclaw", "config", ".config"):
        sub = base / subdir
        if sub.is_dir():
            for p in sub.glob("*.json"):
                if p not in candidates:
                    candidates.append(p)

    return candidates


class OpenClawSecurityAnalyzer:
    """Runs OpenClaw-specific security checks."""

    def analyze(self, path: str) -> OpenClawSecurityReport:
        base = Path(path).resolve()

        if not base.exists():
            raise FileNotFoundError(f"Path not found: {base}")

        config_files = _find_config_files(base)
        merged_config = self._merge_configs(config_files)
        version = self._extract_version(config_files, merged_config)

        report = OpenClawSecurityReport(
            agent_path=str(base),
            openclaw_version=version,
        )

        # Run all checks
        report.checks.append(self._check_cve_2026_25253(version, merged_config))
        report.checks.append(self._check_gateway_token_exposure(merged_config))
        report.checks.append(self._check_container_escape(merged_config))
        report.checks.append(self._check_approval_bypass(merged_config))
        report.checks.append(self._check_operator_scopes(merged_config))
        report.checks.append(self._check_websocket_origin(merged_config))
        report.checks.append(self._check_loopback_binding(merged_config))

        return report

    def _merge_configs(self, config_files: list[Path]) -> dict[str, Any]:
        """Load and merge all config files into a single dict."""
        merged: dict[str, Any] = {}
        for cf in config_files:
            data = _load_json_file(cf)
            if data and isinstance(data, dict):
                merged.update(data)
        return merged

    def _extract_version(
        self, config_files: list[Path], merged_config: dict[str, Any]
    ) -> str | None:
        """Try to extract the OpenClaw version from configs."""
        # Check package.json first
        for cf in config_files:
            if cf.name == "package.json":
                data = _load_json_file(cf)
                if data:
                    # Direct version field
                    if data.get("name", "").lower() in ("openclaw", "@openclaw/core"):
                        v = data.get("version")
                        if v:
                            return str(v)
                    # Dependency version
                    for dep_key in ("dependencies", "devDependencies"):
                        deps = data.get(dep_key, {})
                        for key in ("openclaw", "@openclaw/core"):
                            if key in deps:
                                return str(deps[key]).lstrip("^~>=<")

        # Check merged config
        for key in ("version", "openclaw_version", "openclawVersion"):
            if key in merged_config:
                return str(merged_config[key])

        return None

    def _check_cve_2026_25253(
        self, version: str | None, config: dict[str, Any]
    ) -> OpenClawSecurityCheck:
        """
        CVE-2026-25253: WebSocket Hijacking / Token Exfiltration → RCE.

        Crafted link causes Control UI to send gateway token to attacker-controlled
        WebSocket server. Attacker then connects to victim's gateway, disables
        sandbox, escapes container, and executes arbitrary commands.
        """
        vulnerable_indicators: list[str] = []

        # 1. Version check
        version_vulnerable = False
        if version:
            parsed = _parse_version(version)
            if parsed and parsed < _CVE_FIX_VERSION:
                version_vulnerable = True
                vulnerable_indicators.append(
                    f"OpenClaw version {version} is below fix version 2026.1.29"
                )
        else:
            vulnerable_indicators.append(
                "Could not determine OpenClaw version (unable to verify patch status)"
            )

        # 2. Gateway URL validation
        gateway_url = config.get("gatewayUrl") or config.get("gateway_url") or config.get("gateway", {}).get("url") if isinstance(config.get("gateway"), dict) else config.get("gatewayUrl")
        gateway_url_source = config.get("gatewayUrlSource") or config.get("gateway_url_source")
        gateway_url_allowlist = config.get("gatewayUrlAllowlist") or config.get("gateway_url_allowlist")

        if gateway_url_source in ("query", "querystring", "query_string", "external"):
            vulnerable_indicators.append(
                "Gateway URL is accepted from external input (query string) without validation"
            )
        elif gateway_url and not gateway_url_allowlist:
            # Has a gateway URL configured but no allowlist
            pass  # Not necessarily vulnerable from config alone

        # 3. Sandbox config — already-exploited state
        exec_approvals = config.get("exec.approvals") or config.get("exec", {}).get("approvals") if isinstance(config.get("exec"), dict) else config.get("exec.approvals")
        exec_host = config.get("tools.exec.host") or config.get("tools", {}).get("exec", {}).get("host") if isinstance(config.get("tools"), dict) and isinstance(config.get("tools", {}).get("exec"), dict) else config.get("tools.exec.host")

        if str(exec_approvals).lower() == "off":
            vulnerable_indicators.append(
                "Exec approvals are disabled (exec.approvals: off) — sandbox bypass active"
            )
        if str(exec_host).lower() == "gateway":
            vulnerable_indicators.append(
                "Exec host is set to gateway (tools.exec.host: gateway) — container escape active"
            )

        # 4. Operator scopes
        scopes = config.get("operator_scopes") or config.get("operatorScopes") or config.get("scopes", [])
        if isinstance(scopes, str):
            scopes = [s.strip() for s in scopes.split(",")]
        high_risk_scopes = [s for s in scopes if s in ("operator.admin", "operator.approvals")]
        if high_risk_scopes:
            vulnerable_indicators.append(
                f"High-risk operator scopes enabled: {', '.join(high_risk_scopes)}"
            )

        # Determine overall status
        if version_vulnerable and len(vulnerable_indicators) > 1:
            status = "VULNERABLE"
            detail = "OpenClaw installation is vulnerable to CVE-2026-25253. " + "; ".join(vulnerable_indicators)
        elif version_vulnerable:
            status = "VULNERABLE"
            detail = vulnerable_indicators[0] if vulnerable_indicators else "Version is below fix."
        elif vulnerable_indicators and version is None:
            status = "UNKNOWN"
            detail = "Cannot confirm patch status. " + "; ".join(vulnerable_indicators)
        elif vulnerable_indicators:
            # Version is patched but risky config
            status = "WARNING"
            detail = "Version appears patched, but risky configuration detected. " + "; ".join(vulnerable_indicators)
        else:
            status = "SAFE"
            detail = "OpenClaw version is at or above 2026.1.29 (fix version)."

        return OpenClawSecurityCheck(
            check_id="CVE-2026-25253",
            name="WebSocket Hijacking / Token Exfiltration → RCE",
            severity="HIGH",
            status=status,
            description=(
                "Crafted link causes Control UI to send gateway token to "
                "attacker-controlled WebSocket server. Attacker then connects "
                "to victim's gateway, disables sandbox, and executes arbitrary commands."
            ),
            detail=detail,
            remediation="Update to OpenClaw >= 2026.1.29. Validate gatewayUrl against an allowlist. Enable WebSocket origin checking.",
        )

    def _check_gateway_token_exposure(
        self, config: dict[str, Any]
    ) -> OpenClawSecurityCheck:
        """Check if gateway tokens are stored in plaintext config."""
        token_keys = ("gateway_token", "gatewayToken", "token", "api_token", "apiToken")
        found_tokens: list[str] = []

        for key in token_keys:
            val = config.get(key)
            if val and isinstance(val, str) and len(val) > 8:
                found_tokens.append(key)

        # Check nested gateway config
        gw = config.get("gateway", {})
        if isinstance(gw, dict):
            for key in ("token", "api_token", "secret"):
                if gw.get(key) and isinstance(gw[key], str) and len(gw[key]) > 8:
                    found_tokens.append(f"gateway.{key}")

        if found_tokens:
            return OpenClawSecurityCheck(
                check_id="OPENCLAW-TOKEN-EXPOSURE",
                name="Gateway Token Stored in Plaintext",
                severity="MEDIUM",
                status="WARNING",
                description="Gateway tokens should not be stored in plaintext configuration files.",
                detail=f"Plaintext token found in config keys: {', '.join(found_tokens)}.",
                remediation="Move tokens to environment variables or a secrets manager. Remove from config files.",
            )

        return OpenClawSecurityCheck(
            check_id="OPENCLAW-TOKEN-EXPOSURE",
            name="Gateway Token Stored in Plaintext",
            severity="MEDIUM",
            status="SAFE",
            description="Gateway tokens should not be stored in plaintext configuration files.",
            detail="No plaintext gateway tokens found in configuration.",
            remediation="N/A",
        )

    def _check_container_escape(
        self, config: dict[str, Any]
    ) -> OpenClawSecurityCheck:
        """Check if tools.exec.host is set to gateway instead of container-scoped."""
        exec_host = None
        tools = config.get("tools", {})
        if isinstance(tools, dict):
            exec_conf = tools.get("exec", {})
            if isinstance(exec_conf, dict):
                exec_host = exec_conf.get("host")
        if exec_host is None:
            exec_host = config.get("tools.exec.host")

        if str(exec_host).lower() == "gateway":
            return OpenClawSecurityCheck(
                check_id="OPENCLAW-CONTAINER-ESCAPE",
                name="Container Escape Risk",
                severity="HIGH",
                status="WARNING",
                description="tools.exec.host should be container-scoped, not gateway.",
                detail="tools.exec.host is set to 'gateway', allowing execution outside the container sandbox.",
                remediation="Set tools.exec.host to 'docker' or 'container' to enforce sandbox isolation.",
            )

        return OpenClawSecurityCheck(
            check_id="OPENCLAW-CONTAINER-ESCAPE",
            name="Container Escape Risk",
            severity="HIGH",
            status="SAFE",
            description="tools.exec.host should be container-scoped, not gateway.",
            detail=f"Container sandbox is active (tools.exec.host: {exec_host or 'default'}).",
            remediation="N/A",
        )

    def _check_approval_bypass(
        self, config: dict[str, Any]
    ) -> OpenClawSecurityCheck:
        """Check if exec.approvals is disabled."""
        approvals = None
        exec_conf = config.get("exec", {})
        if isinstance(exec_conf, dict):
            approvals = exec_conf.get("approvals")
        if approvals is None:
            approvals = config.get("exec.approvals")

        if str(approvals).lower() == "off":
            return OpenClawSecurityCheck(
                check_id="OPENCLAW-APPROVAL-BYPASS",
                name="Exec Approvals Disabled",
                severity="HIGH",
                status="WARNING",
                description="Exec approvals gate dangerous operations behind human review.",
                detail="exec.approvals is set to 'off'. Commands execute without human approval.",
                remediation="Set exec.approvals to 'on' to require approval for dangerous operations.",
            )

        return OpenClawSecurityCheck(
            check_id="OPENCLAW-APPROVAL-BYPASS",
            name="Exec Approvals Disabled",
            severity="HIGH",
            status="SAFE",
            description="Exec approvals gate dangerous operations behind human review.",
            detail=f"Exec approvals are enabled (exec.approvals: {approvals or 'default/on'}).",
            remediation="N/A",
        )

    def _check_operator_scopes(
        self, config: dict[str, Any]
    ) -> OpenClawSecurityCheck:
        """Flag high-risk operator scopes."""
        scopes = config.get("operator_scopes") or config.get("operatorScopes") or config.get("scopes", [])
        if isinstance(scopes, str):
            scopes = [s.strip() for s in scopes.split(",")]

        high_risk = [s for s in scopes if s in ("operator.admin", "operator.approvals")]

        if high_risk:
            return OpenClawSecurityCheck(
                check_id="OPENCLAW-OPERATOR-SCOPES",
                name="High-Risk Operator Scopes",
                severity="MEDIUM",
                status="WARNING",
                description="Operator scopes control what the operator identity can modify at runtime.",
                detail=f"High-risk scopes enabled: {', '.join(high_risk)}. These allow runtime config changes including disabling security controls.",
                remediation="Remove operator.admin and operator.approvals scopes unless strictly required. Use least-privilege scopes.",
            )

        return OpenClawSecurityCheck(
            check_id="OPENCLAW-OPERATOR-SCOPES",
            name="High-Risk Operator Scopes",
            severity="MEDIUM",
            status="SAFE",
            description="Operator scopes control what the operator identity can modify at runtime.",
            detail="No high-risk operator scopes detected.",
            remediation="N/A",
        )

    def _check_websocket_origin(
        self, config: dict[str, Any]
    ) -> OpenClawSecurityCheck:
        """Check if WebSocket origin validation is missing or permissive."""
        ws_config = config.get("websocket", {})
        if not isinstance(ws_config, dict):
            ws_config = {}

        origin_check = ws_config.get("origin_check") or ws_config.get("originCheck")
        allowed_origins = ws_config.get("allowed_origins") or ws_config.get("allowedOrigins")

        if origin_check is False or str(origin_check).lower() in ("false", "off", "disabled"):
            return OpenClawSecurityCheck(
                check_id="OPENCLAW-WS-ORIGIN",
                name="WebSocket Origin Validation",
                severity="HIGH",
                status="WARNING",
                description="WebSocket server should validate the Origin header to prevent cross-origin attacks.",
                detail="WebSocket origin checking is explicitly disabled.",
                remediation="Enable origin validation and configure an allowlist of trusted origins.",
            )

        if isinstance(allowed_origins, list) and "*" in allowed_origins:
            return OpenClawSecurityCheck(
                check_id="OPENCLAW-WS-ORIGIN",
                name="WebSocket Origin Validation",
                severity="HIGH",
                status="WARNING",
                description="WebSocket server should validate the Origin header to prevent cross-origin attacks.",
                detail="WebSocket allowed_origins contains wildcard '*', accepting connections from any origin.",
                remediation="Replace wildcard with specific trusted origins.",
            )

        if isinstance(allowed_origins, str) and allowed_origins == "*":
            return OpenClawSecurityCheck(
                check_id="OPENCLAW-WS-ORIGIN",
                name="WebSocket Origin Validation",
                severity="HIGH",
                status="WARNING",
                description="WebSocket server should validate the Origin header to prevent cross-origin attacks.",
                detail="WebSocket allowed_origins is wildcard '*', accepting connections from any origin.",
                remediation="Replace wildcard with specific trusted origins.",
            )

        if ws_config and (origin_check or allowed_origins):
            return OpenClawSecurityCheck(
                check_id="OPENCLAW-WS-ORIGIN",
                name="WebSocket Origin Validation",
                severity="HIGH",
                status="SAFE",
                description="WebSocket server should validate the Origin header to prevent cross-origin attacks.",
                detail="WebSocket origin validation is configured.",
                remediation="N/A",
            )

        return OpenClawSecurityCheck(
            check_id="OPENCLAW-WS-ORIGIN",
            name="WebSocket Origin Validation",
            severity="HIGH",
            status="UNKNOWN",
            description="WebSocket server should validate the Origin header to prevent cross-origin attacks.",
            detail="No WebSocket configuration found — unable to verify origin validation.",
            remediation="Ensure the WebSocket server validates Origin headers. Configure allowed_origins.",
        )

    def _check_loopback_binding(
        self, config: dict[str, Any]
    ) -> OpenClawSecurityCheck:
        """Warn that loopback-only binding does NOT mitigate CVE-2026-25253."""
        bind_addr = config.get("bind") or config.get("host") or config.get("listen")
        gw = config.get("gateway", {})
        if isinstance(gw, dict):
            bind_addr = bind_addr or gw.get("bind") or gw.get("host")

        is_loopback = str(bind_addr) in ("127.0.0.1", "localhost", "::1")

        if is_loopback:
            return OpenClawSecurityCheck(
                check_id="OPENCLAW-LOOPBACK",
                name="Loopback Binding (False Sense of Security)",
                severity="MEDIUM",
                status="WARNING",
                description=(
                    "Binding to loopback (127.0.0.1) does NOT mitigate CVE-2026-25253. "
                    "The browser acts as a bridge — a malicious page can make the browser "
                    "connect to the local WebSocket server on behalf of the attacker."
                ),
                detail=f"Gateway is bound to {bind_addr}. This does not prevent browser-based WebSocket hijacking.",
                remediation="Do not rely on loopback binding as a security measure. Apply the CVE-2026-25253 patch and enable origin validation.",
            )

        return OpenClawSecurityCheck(
            check_id="OPENCLAW-LOOPBACK",
            name="Loopback Binding (False Sense of Security)",
            severity="MEDIUM",
            status="SAFE",
            description="Loopback-only binding does not mitigate CVE-2026-25253 (browser acts as bridge).",
            detail="Gateway is not bound to loopback address, or binding address is not configured.",
            remediation="N/A",
        )
