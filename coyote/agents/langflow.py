"""
Langflow Security Analyzer

Detects high-impact Langflow CVEs and common exploit preconditions.
Tracked CVEs:
- CVE-2025-3248
- CVE-2025-34291
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class LangflowSecurityCheck:
    """Result of a single security check."""

    check_id: str
    name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    status: str  # VULNERABLE, WARNING, SAFE, UNKNOWN
    description: str
    detail: str
    remediation: str


@dataclass
class LangflowSecurityReport:
    """Aggregated security report for a Langflow installation."""

    target_path: str
    langflow_version: str | None
    langflow_base_version: str | None
    checks: list[LangflowSecurityCheck] = field(default_factory=list)

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
            "target_path": self.target_path,
            "langflow_version": self.langflow_version,
            "langflow_base_version": self.langflow_base_version,
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


_CVE_2025_3248_LANGFLOW_FIX = (1, 3, 0)
_CVE_2025_3248_LANGFLOW_BASE_FIX = (0, 3, 0)
_CVE_2025_34291_MAX_AFFECTED = (1, 6, 9)

_TRUE_VALUES = {"1", "true", "yes", "on", "enabled"}
_FALSE_VALUES = {"0", "false", "no", "off", "disabled"}

_LANGFLOW_DEP_PATTERN = re.compile(
    r"(?i)\blangflow\b(?:\[[^\]]+\])?\s*(?:==|~=|>=|<=|>|<|\^)?\s*v?([0-9]+(?:\.[0-9]+)+)"
)
_LANGFLOW_BASE_DEP_PATTERN = re.compile(
    r"(?i)\blangflow-base\b\s*(?:==|~=|>=|<=|>|<|\^)?\s*v?([0-9]+(?:\.[0-9]+)+)"
)


def _format_version(version: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in version)


def _parse_version(version_str: str) -> tuple[int, ...] | None:
    match = re.search(r"(\d+(?:\.\d+)+)", version_str)
    if not match:
        return None
    try:
        return tuple(int(p) for p in match.group(1).split("."))
    except ValueError:
        return None


def _extract_version_literal(value: str) -> str | None:
    parsed = _parse_version(value)
    if not parsed:
        return None
    return _format_version(parsed)


def _load_json_file(path: Path) -> dict[str, Any] | None:
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, OSError):
        pass
    return None


def _load_yaml_file(path: Path) -> dict[str, Any] | None:
    try:
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        if isinstance(data, dict):
            return data
    except (yaml.YAMLError, OSError):
        pass
    return None


def _load_text_file(path: Path) -> str:
    try:
        with open(path, encoding="utf-8", errors="ignore") as handle:
            return handle.read()
    except OSError:
        return ""


def _load_env_file(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    text = _load_text_file(path)
    if not text:
        return entries

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if value.startswith(("'", '"')) and value.endswith(("'", '"')) and len(value) >= 2:
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        entries[key] = value
    return entries


def _find_input_files(base: Path) -> list[Path]:
    if base.is_file():
        return [base]

    candidates: list[Path] = []
    names = [
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "requirements-dev.txt",
        "requirements.in",
        "poetry.lock",
        "uv.lock",
        "langflow.json",
        "config.json",
        ".env",
        ".env.local",
        ".env.production",
        "docker-compose.yml",
        "docker-compose.yaml",
    ]
    for name in names:
        p = base / name
        if p.exists():
            candidates.append(p)

    for pattern in ("langflow*.json", "langflow*.yaml", "langflow*.yml", "*.env"):
        for p in base.glob(pattern):
            if p not in candidates:
                candidates.append(p)

    for subdir in ("config", ".config", "deploy"):
        sub = base / subdir
        if not sub.is_dir():
            continue
        for pattern in ("langflow*.json", "langflow*.yaml", "langflow*.yml", "*.env"):
            for p in sub.glob(pattern):
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
        stripped = value.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            try:
                loaded = json.loads(stripped)
                if isinstance(loaded, list):
                    return [str(item).strip() for item in loaded if str(item).strip()]
            except json.JSONDecodeError:
                pass
        return [item.strip() for item in stripped.split(",") if item.strip()]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()]


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


class LangflowSecurityAnalyzer:
    """Runs Langflow-specific security checks."""

    def analyze(self, path: str) -> LangflowSecurityReport:
        base = Path(path).resolve()
        if not base.exists():
            raise FileNotFoundError(f"Path not found: {base}")

        input_files = _find_input_files(base)
        merged_config = self._merge_configs(input_files)
        langflow_version, langflow_base_version = self._extract_versions(
            input_files,
            merged_config,
        )

        report = LangflowSecurityReport(
            target_path=str(base),
            langflow_version=langflow_version,
            langflow_base_version=langflow_base_version,
        )
        report.checks.append(
            self._check_cve_2025_3248(langflow_version, langflow_base_version)
        )
        report.checks.append(
            self._check_cve_2025_34291(langflow_version, merged_config)
        )
        return report

    def _merge_configs(self, input_files: list[Path]) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        for path in input_files:
            lower_name = path.name.lower()
            suffix = path.suffix.lower()

            if suffix == ".json":
                data = _load_json_file(path)
                if data:
                    merged.update(data)
                continue

            if suffix in (".yaml", ".yml"):
                data = _load_yaml_file(path)
                if data:
                    merged.update(data)
                continue

            if lower_name.startswith(".env") or suffix == ".env":
                merged.update(_load_env_file(path))

        return merged

    def _extract_versions(
        self,
        input_files: list[Path],
        merged_config: dict[str, Any],
    ) -> tuple[str | None, str | None]:
        langflow_version: str | None = None
        langflow_base_version: str | None = None

        for path in input_files:
            lower_name = path.name.lower()

            if lower_name == "package.json":
                package = _load_json_file(path) or {}
                package_name = str(package.get("name", "")).lower()
                if package_name == "langflow" and package.get("version"):
                    parsed = _extract_version_literal(str(package.get("version")))
                    if parsed:
                        langflow_version = langflow_version or parsed
                if package_name in ("langflow-base", "@langflow/base") and package.get("version"):
                    parsed = _extract_version_literal(str(package.get("version")))
                    if parsed:
                        langflow_base_version = langflow_base_version or parsed

                for dep_key in ("dependencies", "devDependencies", "optionalDependencies"):
                    deps = package.get(dep_key, {})
                    if not isinstance(deps, dict):
                        continue

                    raw_langflow = deps.get("langflow")
                    if raw_langflow:
                        parsed = _extract_version_literal(str(raw_langflow))
                        if parsed:
                            langflow_version = langflow_version or parsed

                    raw_langflow_base = deps.get("langflow-base") or deps.get("@langflow/base")
                    if raw_langflow_base:
                        parsed = _extract_version_literal(str(raw_langflow_base))
                        if parsed:
                            langflow_base_version = langflow_base_version or parsed

            if lower_name.endswith((".txt", ".toml", ".lock", ".cfg", ".ini", ".yaml", ".yml")):
                text = _load_text_file(path)
                if text:
                    if langflow_version is None:
                        match = _LANGFLOW_DEP_PATTERN.search(text)
                        if match:
                            langflow_version = _extract_version_literal(match.group(1))
                    if langflow_base_version is None:
                        match = _LANGFLOW_BASE_DEP_PATTERN.search(text)
                        if match:
                            langflow_base_version = _extract_version_literal(match.group(1))

            if langflow_version and langflow_base_version:
                break

        if not langflow_version:
            for key in ("LANGFLOW_VERSION", "langflow_version", "langflowVersion"):
                value = merged_config.get(key)
                if value:
                    parsed = _extract_version_literal(str(value))
                    if parsed:
                        langflow_version = parsed
                        break

        if not langflow_base_version:
            for key in ("LANGFLOW_BASE_VERSION", "langflow_base_version", "langflowBaseVersion"):
                value = merged_config.get(key)
                if value:
                    parsed = _extract_version_literal(str(value))
                    if parsed:
                        langflow_base_version = parsed
                        break

        return langflow_version, langflow_base_version

    def _check_cve_2025_3248(
        self,
        langflow_version: str | None,
        langflow_base_version: str | None,
    ) -> LangflowSecurityCheck:
        """
        CVE-2025-3248: Unauthenticated code validation endpoint can enable RCE.
        """
        langflow_parsed = _parse_version(langflow_version) if langflow_version else None
        langflow_base_parsed = (
            _parse_version(langflow_base_version) if langflow_base_version else None
        )

        vulnerable_components: list[str] = []
        safe_components: list[str] = []

        if langflow_parsed:
            if langflow_parsed < _CVE_2025_3248_LANGFLOW_FIX:
                vulnerable_components.append(
                    f"langflow {langflow_version} < {_format_version(_CVE_2025_3248_LANGFLOW_FIX)}"
                )
            else:
                safe_components.append(f"langflow {langflow_version}")

        if langflow_base_parsed:
            if langflow_base_parsed < _CVE_2025_3248_LANGFLOW_BASE_FIX:
                vulnerable_components.append(
                    "langflow-base "
                    f"{langflow_base_version} < {_format_version(_CVE_2025_3248_LANGFLOW_BASE_FIX)}"
                )
            else:
                safe_components.append(f"langflow-base {langflow_base_version}")

        if vulnerable_components:
            detail = "Detected vulnerable component versions: " + "; ".join(vulnerable_components) + "."
            status = "VULNERABLE"
        elif safe_components:
            detail = (
                "Detected Langflow components in patched range: "
                + "; ".join(safe_components)
                + "."
            )
            status = "SAFE"
        else:
            detail = (
                "Could not determine langflow/langflow-base versions from package or dependency files."
            )
            status = "UNKNOWN"

        return LangflowSecurityCheck(
            check_id="CVE-2025-3248",
            name="Unauthenticated Code Validation RCE",
            severity="CRITICAL",
            status=status,
            description=(
                "The /api/v1/validate/code endpoint can be abused without authentication "
                "to execute attacker-controlled code."
            ),
            detail=detail,
            remediation=(
                "Update langflow to >= "
                + _format_version(_CVE_2025_3248_LANGFLOW_FIX)
                + " and langflow-base to >= "
                + _format_version(_CVE_2025_3248_LANGFLOW_BASE_FIX)
                + ". Restrict public access to Langflow API endpoints."
            ),
        )

    def _check_cve_2025_34291(
        self,
        langflow_version: str | None,
        config: dict[str, Any],
    ) -> LangflowSecurityCheck:
        """
        CVE-2025-34291: CORS + credential/cookie chain can enable account takeover/RCE.
        """
        version_parsed = _parse_version(langflow_version) if langflow_version else None

        cors_origins = _as_string_list(
            _get_config_value(
                config,
                "LANGFLOW_CORS_ORIGINS",
                "LANGFLOW_CORS_ALLOWED_ORIGINS",
                "langflow_cors_origins",
                "langflow_cors_allowed_origins",
                "cors.origins",
                "cors.allowed_origins",
                "allow_origins",
                "allowOrigins",
            )
        )
        wildcard_origins = any(origin.strip() == "*" for origin in cors_origins)

        allow_credentials = _coerce_bool(
            _get_config_value(
                config,
                "LANGFLOW_CORS_ALLOW_CREDENTIALS",
                "langflow_cors_allow_credentials",
                "cors.allow_credentials",
                "cors.allowCredentials",
                "allow_credentials",
                "allowCredentials",
            )
        ) is True

        same_site_value = _get_config_value(
            config,
            "LANGFLOW_REFRESH_TOKEN_COOKIE_SAMESITE",
            "LANGFLOW_REFRESH_COOKIE_SAMESITE",
            "LANGFLOW_COOKIE_SAMESITE",
            "langflow_refresh_token_cookie_samesite",
            "refresh_token_cookie_samesite",
            "refresh.cookie.sameSite",
            "refresh.cookie.samesite",
            "cookie.sameSite",
            "cookie.samesite",
        )
        if same_site_value is None:
            for key, value in config.items():
                if not isinstance(key, str):
                    continue
                lowered = key.lower()
                if "samesite" in lowered and ("cookie" in lowered or "refresh" in lowered):
                    same_site_value = value
                    break

        same_site_none = (
            isinstance(same_site_value, str)
            and same_site_value.strip().lower() == "none"
        )

        indicators: list[str] = []
        if wildcard_origins:
            indicators.append("CORS origins include wildcard '*'.")
        if allow_credentials:
            indicators.append("CORS credentials are enabled.")
        if same_site_none:
            indicators.append("Refresh token cookie SameSite is set to 'None'.")

        full_chain = wildcard_origins and allow_credentials and same_site_none
        affected_by_version = (
            version_parsed is not None and version_parsed <= _CVE_2025_34291_MAX_AFFECTED
        )

        if affected_by_version and full_chain:
            status = "VULNERABLE"
            detail = (
                f"Langflow version {langflow_version} is in the affected range "
                f"(<= {_format_version(_CVE_2025_34291_MAX_AFFECTED)}), and exploit "
                "preconditions were detected: "
                + "; ".join(indicators)
            )
        elif affected_by_version:
            status = "WARNING"
            if indicators:
                detail = (
                    f"Langflow version {langflow_version} is in the affected range "
                    f"(<= {_format_version(_CVE_2025_34291_MAX_AFFECTED)}). "
                    "Some exploit preconditions were detected: "
                    + "; ".join(indicators)
                )
            else:
                detail = (
                    f"Langflow version {langflow_version} is in the affected range "
                    f"(<= {_format_version(_CVE_2025_34291_MAX_AFFECTED)}), but CORS/cookie "
                    "preconditions were not clearly detected from available config."
                )
        elif version_parsed is None:
            status = "UNKNOWN"
            if indicators:
                detail = (
                    "Could not determine Langflow version. Risky CORS/cookie indicators were "
                    "detected: " + "; ".join(indicators)
                )
            else:
                detail = (
                    "Could not determine Langflow version and no clear CORS/cookie chain "
                    "indicators were detected."
                )
        elif full_chain:
            status = "WARNING"
            detail = (
                f"Langflow version {langflow_version} appears newer than "
                f"{_format_version(_CVE_2025_34291_MAX_AFFECTED)}, but high-risk "
                "CORS/cookie configuration remains: " + "; ".join(indicators)
            )
        else:
            status = "SAFE"
            detail = (
                f"Langflow version {langflow_version} is newer than "
                f"{_format_version(_CVE_2025_34291_MAX_AFFECTED)} and no full CORS/cookie "
                "exploit chain was detected."
            )

        return LangflowSecurityCheck(
            check_id="CVE-2025-34291",
            name="CORS Token Hijack Chain",
            severity="CRITICAL",
            status=status,
            description=(
                "A permissive CORS policy with credentialed requests and cross-site refresh "
                "cookies can enable account takeover and remote code execution chains."
            ),
            detail=detail,
            remediation=(
                "Upgrade Langflow beyond the affected range and harden CORS/cookie settings: "
                "avoid wildcard origins when credentials are enabled, and prefer "
                "SameSite=Lax/Strict for refresh cookies."
            ),
        )
