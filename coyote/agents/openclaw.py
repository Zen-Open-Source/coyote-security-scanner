"""
OpenClaw Security Analyzer

Detects OpenClaw CVEs and performs general hardening checks.
Tracked CVEs:
- CVE-2026-25253
- CVE-2026-24763
- CVE-2026-25157
- CVE-2026-25475
- CVE-2026-25593
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


_CVE_FIX_VERSIONS = {
    "CVE-2026-25253": (2026, 1, 29),
    "CVE-2026-24763": (2026, 1, 29),
    "CVE-2026-25157": (2026, 1, 29),
    "CVE-2026-25475": (2026, 1, 30),
    "CVE-2026-25593": (2026, 1, 20),
}

# Backward-compatible export used by other modules.
_CVE_FIX_VERSION = _CVE_FIX_VERSIONS["CVE-2026-25253"]
_LATEST_TRACKED_FIX_VERSION = max(_CVE_FIX_VERSIONS.values())

_TRUE_VALUES = {"1", "true", "yes", "on", "enabled"}
_FALSE_VALUES = {"0", "false", "no", "off", "disabled"}
_RISKY_INPUT_SOURCES = {"query", "querystring", "query_string", "external", "user", "env"}
_SHELL_META_PATTERN = re.compile(r"[;&|`$()<>]")


def _format_version(version: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in version)


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
        with open(path, encoding="utf-8") as f:
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

    for ext in ("*.json", "*.yaml", "*.yml", "*.toml"):
        for p in base.glob(ext):
            if p not in candidates:
                candidates.append(p)

    for subdir in (".openclaw", "config", ".config"):
        sub = base / subdir
        if sub.is_dir():
            for p in sub.glob("*.json"):
                if p not in candidates:
                    candidates.append(p)

    return candidates


def _coerce_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in _TRUE_VALUES:
            return True
        if lowered in _FALSE_VALUES:
            return False
    return None


def _as_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    if isinstance(value, list):
        items: list[str] = []
        for item in value:
            if isinstance(item, str):
                stripped = item.strip()
                if stripped:
                    items.append(stripped)
            elif item is not None:
                items.append(str(item))
        return items
    return [str(value)]


def _get_config_value(config: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        if not path:
            continue

        if path in config:
            return config[path]

        current: Any = config
        found = True
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                found = False
                break
        if found:
            return current
    return None


def _contains_shell_metacharacters(value: str) -> bool:
    return bool(_SHELL_META_PATTERN.search(value))


def _is_absolute_path(path_value: str) -> bool:
    if Path(path_value).is_absolute():
        return True
    return bool(re.match(r"^[A-Za-z]:[\\/]", path_value))


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

        report.checks.append(self._check_cve_2026_25253(version, merged_config))
        report.checks.append(self._check_cve_2026_24763(version, merged_config))
        report.checks.append(self._check_cve_2026_25157(version, merged_config))
        report.checks.append(self._check_cve_2026_25475(version, merged_config))
        report.checks.append(self._check_cve_2026_25593(version, merged_config))
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
        for config_file in config_files:
            data = _load_json_file(config_file)
            if data and isinstance(data, dict):
                merged.update(data)
        return merged

    def _extract_version(
        self, config_files: list[Path], merged_config: dict[str, Any]
    ) -> str | None:
        """Try to extract the OpenClaw version from configs."""
        for config_file in config_files:
            if config_file.name != "package.json":
                continue
            data = _load_json_file(config_file)
            if not data:
                continue

            if data.get("name", "").lower() in ("openclaw", "@openclaw/core"):
                version = data.get("version")
                if version:
                    return str(version)

            for dep_key in ("dependencies", "devDependencies"):
                deps = data.get(dep_key, {})
                for key in ("openclaw", "@openclaw/core"):
                    if key in deps:
                        return str(deps[key]).lstrip("^~>=<")

        for key in ("version", "openclaw_version", "openclawVersion"):
            if key in merged_config:
                return str(merged_config[key])

        return None

    def _version_vulnerable(
        self, version: str | None, fix_version: tuple[int, ...]
    ) -> bool | None:
        if not version:
            return None
        parsed = _parse_version(version)
        if not parsed:
            return None
        return parsed < fix_version

    def _build_cve_check(
        self,
        *,
        cve_id: str,
        name: str,
        severity: str,
        description: str,
        remediation: str,
        version: str | None,
        fix_version: tuple[int, ...],
        indicators: list[str],
        safe_detail: str,
    ) -> OpenClawSecurityCheck:
        version_state = self._version_vulnerable(version, fix_version)
        fix_version_str = _format_version(fix_version)

        if version_state is True:
            detail_parts = [
                f"OpenClaw version {version} is below fix version {fix_version_str}."
            ]
            detail_parts.extend(indicators)
            detail = "; ".join(detail_parts)
            status = "VULNERABLE"
        elif version_state is None:
            detail = f"Could not determine OpenClaw version; fixed in {fix_version_str}."
            if indicators:
                detail += " " + "; ".join(indicators)
            status = "UNKNOWN"
        elif indicators:
            detail = (
                "Version appears patched, but risky configuration detected. "
                + "; ".join(indicators)
            )
            status = "WARNING"
        else:
            detail = safe_detail
            status = "SAFE"

        return OpenClawSecurityCheck(
            check_id=cve_id,
            name=name,
            severity=severity,
            status=status,
            description=description,
            detail=detail,
            remediation=f"Update to OpenClaw >= {fix_version_str}. {remediation}",
        )

    def _get_scopes(self, config: dict[str, Any]) -> list[str]:
        return _as_string_list(
            _get_config_value(config, "operator_scopes", "operatorScopes", "scopes")
        )

    def _check_cve_2026_25253(
        self, version: str | None, config: dict[str, Any]
    ) -> OpenClawSecurityCheck:
        """
        CVE-2026-25253: one-click token exfiltration via gatewayUrl.
        """
        indicators: list[str] = []

        gateway_url_source = _get_config_value(
            config,
            "gatewayUrlSource",
            "gateway_url_source",
            "gateway.urlSource",
            "gateway.url_source",
        )
        gateway_url_source_value = str(gateway_url_source).lower() if gateway_url_source else ""
        if gateway_url_source_value in _RISKY_INPUT_SOURCES:
            indicators.append(
                "gatewayUrl is accepted from external input (query/env/user source)."
            )

        exec_approvals = _get_config_value(config, "exec.approvals")
        if _coerce_bool(exec_approvals) is False or str(exec_approvals).lower() == "off":
            indicators.append(
                "Exec approvals are disabled (exec.approvals: off), enabling unsafe execution."
            )

        exec_host = _get_config_value(config, "tools.exec.host", "exec.host")
        if str(exec_host).lower() == "gateway":
            indicators.append(
                "tools.exec.host is set to gateway, increasing blast radius after token theft."
            )

        high_risk_scopes = [
            scope
            for scope in self._get_scopes(config)
            if scope in ("operator.admin", "operator.approvals")
        ]
        if high_risk_scopes:
            indicators.append(
                f"High-risk operator scopes enabled: {', '.join(high_risk_scopes)}."
            )

        return self._build_cve_check(
            cve_id="CVE-2026-25253",
            name="gatewayUrl Token Exfiltration",
            severity="HIGH",
            description=(
                "Crafted link can force Control UI to send a gateway token to an "
                "attacker-controlled endpoint through gatewayUrl handling."
            ),
            remediation=(
                "Validate gatewayUrl against a strict allowlist and enforce "
                "WebSocket origin checks."
            ),
            version=version,
            fix_version=_CVE_FIX_VERSIONS["CVE-2026-25253"],
            indicators=indicators,
            safe_detail=(
                "Version is at or above 2026.1.29 and no risky gatewayUrl token "
                "exfiltration configuration was detected."
            ),
        )

    def _check_cve_2026_24763(
        self, version: str | None, config: dict[str, Any]
    ) -> OpenClawSecurityCheck:
        """
        CVE-2026-24763: command injection via Docker PATH handling.
        """
        indicators: list[str] = []

        docker_path = _get_config_value(
            config, "dockerPath", "docker_path", "docker.path", "runtime.docker.path"
        )
        docker_path_source = _get_config_value(
            config,
            "dockerPathSource",
            "docker_path_source",
            "docker.pathSource",
            "docker.path_source",
        )
        docker_command = _get_config_value(
            config, "dockerCommand", "docker.command", "docker_cmd"
        )

        docker_path_source_value = str(docker_path_source).lower() if docker_path_source else ""
        if docker_path_source_value in _RISKY_INPUT_SOURCES:
            indicators.append(
                "Docker path source comes from untrusted input (query/env/user source)."
            )

        if isinstance(docker_path, str) and _contains_shell_metacharacters(docker_path):
            indicators.append("Configured Docker path contains shell metacharacters.")

        if isinstance(docker_command, str):
            if re.search(r"{\s*(dockerPath|docker_path|path)\s*}", docker_command):
                indicators.append("Docker command template interpolates an untrusted path value.")
            if "sh -c" in docker_command or _contains_shell_metacharacters(docker_command):
                indicators.append("Docker command appears shell-evaluated instead of exec-safe.")

        return self._build_cve_check(
            cve_id="CVE-2026-24763",
            name="Docker PATH Command Injection",
            severity="HIGH",
            description=(
                "Unsafe Docker PATH handling can allow shell command injection "
                "when Docker binary paths are sourced or interpolated unsafely."
            ),
            remediation=(
                "Resolve Docker binary path from trusted static configuration and "
                "invoke Docker with argument arrays, not shell interpolation."
            ),
            version=version,
            fix_version=_CVE_FIX_VERSIONS["CVE-2026-24763"],
            indicators=indicators,
            safe_detail=(
                "Version is at or above 2026.1.29 and no risky Docker PATH handling "
                "patterns were detected."
            ),
        )

    def _check_cve_2026_25157(
        self, version: str | None, config: dict[str, Any]
    ) -> OpenClawSecurityCheck:
        """
        CVE-2026-25157: SSH command injection in remote mode path/target handling.
        """
        indicators: list[str] = []

        mode = _get_config_value(config, "mode", "runMode", "run_mode", "remote.mode")
        remote_mode = _coerce_bool(
            _get_config_value(config, "remoteMode", "remote_mode", "remote.enabled")
        )
        remote_mode_enabled = str(mode).lower() == "remote" or remote_mode is True

        ssh_path = _get_config_value(config, "ssh.path", "sshPath", "remote.path", "targetPath")
        ssh_target = _get_config_value(config, "ssh.target", "sshTarget", "remote.target")
        ssh_command = _get_config_value(config, "ssh.command", "sshCommand", "remote.ssh.command")
        ssh_path_source = _get_config_value(
            config, "ssh.pathSource", "sshPathSource", "remote.pathSource"
        )
        ssh_target_source = _get_config_value(
            config, "ssh.targetSource", "sshTargetSource", "remote.targetSource"
        )

        if remote_mode_enabled:
            if str(ssh_path_source).lower() in _RISKY_INPUT_SOURCES:
                indicators.append("Remote SSH path is sourced from untrusted input.")
            if str(ssh_target_source).lower() in _RISKY_INPUT_SOURCES:
                indicators.append("Remote SSH target is sourced from untrusted input.")
            if isinstance(ssh_path, str) and _contains_shell_metacharacters(ssh_path):
                indicators.append("Configured SSH path contains shell metacharacters.")
            if isinstance(ssh_target, str) and _contains_shell_metacharacters(ssh_target):
                indicators.append("Configured SSH target contains shell metacharacters.")
            if isinstance(ssh_command, str):
                if re.search(r"{\s*(path|target|sshPath|sshTarget)\s*}", ssh_command):
                    indicators.append("SSH command template interpolates path/target values.")
                if "sh -c" in ssh_command or _contains_shell_metacharacters(ssh_command):
                    indicators.append("SSH command appears shell-evaluated in remote mode.")

        return self._build_cve_check(
            cve_id="CVE-2026-25157",
            name="Remote SSH Path/Target Injection",
            severity="HIGH",
            description=(
                "Remote mode SSH path/target handling can permit command injection "
                "when untrusted values are composed into shell commands."
            ),
            remediation=(
                "Treat SSH path/target as untrusted input, sanitize strictly, and "
                "avoid shell command composition in remote mode."
            ),
            version=version,
            fix_version=_CVE_FIX_VERSIONS["CVE-2026-25157"],
            indicators=indicators,
            safe_detail=(
                "Version is at or above 2026.1.29 and no risky remote-mode SSH "
                "path/target handling was detected."
            ),
        )

    def _check_cve_2026_25475(
        self, version: str | None, config: dict[str, Any]
    ) -> OpenClawSecurityCheck:
        """
        CVE-2026-25475: MEDIA path handling allows arbitrary file reads.
        """
        indicators: list[str] = []

        media_config = _get_config_value(config, "media")
        media_path = _get_config_value(
            config, "MEDIA", "mediaPath", "media_path", "media.path", "media.dir", "mediaDir"
        )
        if media_path is None and isinstance(media_config, str):
            media_path = media_config
        if media_path is None and isinstance(media_config, dict):
            media_path = media_config.get("path") or media_config.get("dir")

        media_path_source = _get_config_value(
            config,
            "mediaPathSource",
            "media_path_source",
            "media.pathSource",
            "media.path_source",
        )
        media_allow_absolute = _coerce_bool(
            _get_config_value(config, "media.allowAbsolute", "mediaAllowAbsolute")
        )

        if str(media_path_source).lower() in _RISKY_INPUT_SOURCES:
            indicators.append("MEDIA path is sourced from untrusted input.")

        if isinstance(media_path, str):
            if ".." in Path(media_path).parts or ".." in media_path:
                indicators.append("MEDIA path contains directory traversal ('..') segments.")
            if _is_absolute_path(media_path):
                indicators.append("MEDIA path is absolute, allowing out-of-scope file access.")

        if media_allow_absolute is True:
            indicators.append("MEDIA path handling explicitly allows absolute paths.")

        return self._build_cve_check(
            cve_id="CVE-2026-25475",
            name="MEDIA Path Arbitrary File Read",
            severity="HIGH",
            description=(
                "Improper MEDIA path validation can allow agents to read arbitrary "
                "files outside intended media directories."
            ),
            remediation=(
                "Restrict MEDIA paths to a dedicated base directory, reject "
                "traversal/absolute paths, and canonicalize before access checks."
            ),
            version=version,
            fix_version=_CVE_FIX_VERSIONS["CVE-2026-25475"],
            indicators=indicators,
            safe_detail=(
                "Version is at or above 2026.1.30 and no risky MEDIA path handling "
                "patterns were detected."
            ),
        )

    def _check_cve_2026_25593(
        self, version: str | None, config: dict[str, Any]
    ) -> OpenClawSecurityCheck:
        """
        CVE-2026-25593: unauthenticated local WebSocket config.apply command injection.
        """
        indicators: list[str] = []

        ws_host = _get_config_value(
            config,
            "websocket.host",
            "websocket.bind",
            "websocket.listen",
            "websocket.address",
            "bind",
            "host",
            "listen",
        )
        ws_auth = _get_config_value(
            config,
            "websocket.auth",
            "websocket.requireAuth",
            "websocket.require_auth",
            "websocket.authentication",
        )
        config_apply = _get_config_value(
            config,
            "config.apply.enabled",
            "configApplyEnabled",
            "config_apply_enabled",
            "configApply",
            "config_apply",
            "websocket.config.apply",
            "config.apply",
        )
        config_apply_source = _get_config_value(
            config,
            "config.apply.source",
            "configApplySource",
            "config_apply_source",
        )

        ws_host_value = str(ws_host).strip().lower()
        ws_local = ws_host_value in ("127.0.0.1", "localhost", "::1")
        ws_auth_enabled = _coerce_bool(ws_auth)
        if isinstance(config_apply, dict):
            config_apply = config_apply.get("enabled")
        config_apply_enabled = _coerce_bool(config_apply)

        if ws_local and ws_auth_enabled is False:
            indicators.append(
                "Local WebSocket listener appears unauthenticated (auth disabled)."
            )

        if config_apply_enabled is True and ws_auth_enabled is False:
            indicators.append(
                "config.apply is enabled while WebSocket authentication is disabled."
            )

        if (
            config_apply_enabled is True
            and str(config_apply_source).lower() in _RISKY_INPUT_SOURCES
        ):
            indicators.append("config.apply input is sourced from untrusted input.")

        high_risk_scopes = [
            scope
            for scope in self._get_scopes(config)
            if scope in ("operator.admin", "operator.approvals")
        ]
        if config_apply_enabled is True and high_risk_scopes:
            indicators.append(
                "config.apply is enabled with privileged operator scopes: "
                + ", ".join(high_risk_scopes)
                + "."
            )

        return self._build_cve_check(
            cve_id="CVE-2026-25593",
            name="Unauthenticated WebSocket config.apply Injection",
            severity="CRITICAL",
            description=(
                "An unauthenticated local WebSocket path to config.apply can lead "
                "to command injection."
            ),
            remediation=(
                "Require WebSocket authentication, disable unauthenticated "
                "config.apply, and restrict runtime config mutation endpoints."
            ),
            version=version,
            fix_version=_CVE_FIX_VERSIONS["CVE-2026-25593"],
            indicators=indicators,
            safe_detail=(
                "Version is at or above 2026.1.20 and no unauthenticated "
                "WebSocket config.apply risk pattern was detected."
            ),
        )

    def _check_gateway_token_exposure(
        self, config: dict[str, Any]
    ) -> OpenClawSecurityCheck:
        """Check if gateway tokens are stored in plaintext config."""
        token_keys = ("gateway_token", "gatewayToken", "token", "api_token", "apiToken")
        found_tokens: list[str] = []

        for key in token_keys:
            value = config.get(key)
            if value and isinstance(value, str) and len(value) > 8:
                found_tokens.append(key)

        gateway_config = config.get("gateway", {})
        if isinstance(gateway_config, dict):
            for key in ("token", "api_token", "secret"):
                value = gateway_config.get(key)
                if value and isinstance(value, str) and len(value) > 8:
                    found_tokens.append(f"gateway.{key}")

        if found_tokens:
            return OpenClawSecurityCheck(
                check_id="OPENCLAW-TOKEN-EXPOSURE",
                name="Gateway Token Stored in Plaintext",
                severity="MEDIUM",
                status="WARNING",
                description=(
                    "Gateway tokens should not be stored in plaintext configuration files."
                ),
                detail=f"Plaintext token found in config keys: {', '.join(found_tokens)}.",
                remediation=(
                    "Move tokens to environment variables or a secrets manager. "
                    "Remove from config files."
                ),
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
        exec_host = _get_config_value(config, "tools.exec.host")
        if str(exec_host).lower() == "gateway":
            return OpenClawSecurityCheck(
                check_id="OPENCLAW-CONTAINER-ESCAPE",
                name="Container Escape Risk",
                severity="HIGH",
                status="WARNING",
                description="tools.exec.host should be container-scoped, not gateway.",
                detail=(
                    "tools.exec.host is set to 'gateway', allowing execution outside "
                    "the container sandbox."
                ),
                remediation=(
                    "Set tools.exec.host to 'docker' or 'container' to enforce "
                    "sandbox isolation."
                ),
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
        approvals = _get_config_value(config, "exec.approvals")

        if str(approvals).lower() == "off" or _coerce_bool(approvals) is False:
            return OpenClawSecurityCheck(
                check_id="OPENCLAW-APPROVAL-BYPASS",
                name="Exec Approvals Disabled",
                severity="HIGH",
                status="WARNING",
                description=(
                    "Exec approvals gate dangerous operations behind human review."
                ),
                detail="exec.approvals is set to 'off'. Commands execute without approval.",
                remediation=(
                    "Set exec.approvals to 'on' to require approval for dangerous operations."
                ),
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
        high_risk_scopes = [
            scope
            for scope in self._get_scopes(config)
            if scope in ("operator.admin", "operator.approvals")
        ]

        if high_risk_scopes:
            return OpenClawSecurityCheck(
                check_id="OPENCLAW-OPERATOR-SCOPES",
                name="High-Risk Operator Scopes",
                severity="MEDIUM",
                status="WARNING",
                description=(
                    "Operator scopes control what the operator identity can modify "
                    "at runtime."
                ),
                detail=(
                    "High-risk scopes enabled: "
                    + ", ".join(high_risk_scopes)
                    + ". These allow runtime config changes including disabling "
                    "security controls."
                ),
                remediation=(
                    "Remove operator.admin and operator.approvals unless strictly "
                    "required. Use least-privilege scopes."
                ),
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

        origin_check = ws_config.get("origin_check")
        if origin_check is None:
            origin_check = ws_config.get("originCheck")

        allowed_origins = ws_config.get("allowed_origins")
        if allowed_origins is None:
            allowed_origins = ws_config.get("allowedOrigins")

        if origin_check is False or str(origin_check).lower() in ("false", "off", "disabled"):
            return OpenClawSecurityCheck(
                check_id="OPENCLAW-WS-ORIGIN",
                name="WebSocket Origin Validation",
                severity="HIGH",
                status="WARNING",
                description=(
                    "WebSocket server should validate the Origin header to prevent "
                    "cross-origin attacks."
                ),
                detail="WebSocket origin checking is explicitly disabled.",
                remediation="Enable origin validation and configure trusted origins.",
            )

        if isinstance(allowed_origins, list) and "*" in allowed_origins:
            return OpenClawSecurityCheck(
                check_id="OPENCLAW-WS-ORIGIN",
                name="WebSocket Origin Validation",
                severity="HIGH",
                status="WARNING",
                description=(
                    "WebSocket server should validate the Origin header to prevent "
                    "cross-origin attacks."
                ),
                detail=(
                    "WebSocket allowed_origins contains wildcard '*', accepting "
                    "connections from any origin."
                ),
                remediation="Replace wildcard with specific trusted origins.",
            )

        if isinstance(allowed_origins, str) and allowed_origins == "*":
            return OpenClawSecurityCheck(
                check_id="OPENCLAW-WS-ORIGIN",
                name="WebSocket Origin Validation",
                severity="HIGH",
                status="WARNING",
                description=(
                    "WebSocket server should validate the Origin header to prevent "
                    "cross-origin attacks."
                ),
                detail="WebSocket allowed_origins is wildcard '*'.",
                remediation="Replace wildcard with specific trusted origins.",
            )

        if ws_config and (origin_check or allowed_origins):
            return OpenClawSecurityCheck(
                check_id="OPENCLAW-WS-ORIGIN",
                name="WebSocket Origin Validation",
                severity="HIGH",
                status="SAFE",
                description=(
                    "WebSocket server should validate the Origin header to prevent "
                    "cross-origin attacks."
                ),
                detail="WebSocket origin validation is configured.",
                remediation="N/A",
            )

        return OpenClawSecurityCheck(
            check_id="OPENCLAW-WS-ORIGIN",
            name="WebSocket Origin Validation",
            severity="HIGH",
            status="UNKNOWN",
            description=(
                "WebSocket server should validate the Origin header to prevent "
                "cross-origin attacks."
            ),
            detail="No WebSocket configuration found; unable to verify origin validation.",
            remediation=(
                "Ensure the WebSocket server validates Origin headers and configure "
                "allowed_origins."
            ),
        )

    def _check_loopback_binding(
        self, config: dict[str, Any]
    ) -> OpenClawSecurityCheck:
        """Warn that loopback-only binding does not mitigate browser-bridge abuse."""
        bind_addr = _get_config_value(config, "bind", "host", "listen")
        gateway = config.get("gateway", {})
        if isinstance(gateway, dict):
            bind_addr = bind_addr or gateway.get("bind") or gateway.get("host")

        is_loopback = str(bind_addr) in ("127.0.0.1", "localhost", "::1")

        if is_loopback:
            return OpenClawSecurityCheck(
                check_id="OPENCLAW-LOOPBACK",
                name="Loopback Binding (False Sense of Security)",
                severity="MEDIUM",
                status="WARNING",
                description=(
                    "Binding to loopback does not fully mitigate browser-mediated "
                    "WebSocket abuse."
                ),
                detail=(
                    f"Gateway is bound to {bind_addr}. A browser can still bridge local "
                    "WebSocket requests from malicious pages."
                ),
                remediation=(
                    "Do not rely on loopback binding alone. Patch known CVEs and enforce "
                    "origin/authentication checks."
                ),
            )

        return OpenClawSecurityCheck(
            check_id="OPENCLAW-LOOPBACK",
            name="Loopback Binding (False Sense of Security)",
            severity="MEDIUM",
            status="SAFE",
            description="Loopback-only binding does not mitigate browser-bridge attacks.",
            detail="Gateway is not explicitly loopback-bound, or bind address is not configured.",
            remediation="N/A",
        )
