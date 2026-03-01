"""Dependency vulnerability scanning for Coyote.

Scans common dependency manifests/lockfiles, queries vulnerability advisories,
and emits findings using the shared ScanResult/PatternMatch model.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol

import yaml

from . import __version__
from .patterns import PatternMatch, Severity
from .reporter import generate_json_report, generate_markdown_report, save_reports
from .scanner import ScanResult, generate_finding_id
from .suppress import SuppressionConfig, load_suppression_config


DEPENDENCY_RULE_NAME = "Dependency Vulnerability"

SUPPORTED_MANIFESTS = {
    "poetry.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "pnpm-lock.yml",
    "go.mod",
    "Cargo.lock",
}

EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "venv",
    ".venv",
    "__pycache__",
    ".tox",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
}

OSV_ECOSYSTEM_MAP = {
    "pypi": "PyPI",
    "npm": "npm",
    "go": "Go",
    "cratesio": "crates.io",
}

FAIL_THRESHOLDS = ("none", "critical", "high", "medium", "low")


@dataclass(frozen=True)
class DependencyCoordinate:
    """Normalized dependency coordinate discovered in a manifest."""

    ecosystem: str
    name: str
    version: str
    manifest_path: str
    line_number: int = 0
    line_content: str = ""
    is_dev_dependency: bool = False


@dataclass
class DependencyAdvisory:
    """Vulnerability advisory matched to a dependency coordinate."""

    dependency: DependencyCoordinate
    advisory_id: str
    summary: str
    details: str = ""
    severity_name: str = ""
    cvss_score: float | None = None
    aliases: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    source: str = "osv"


class AdvisoryProvider(Protocol):
    """Provider protocol for dependency vulnerability advisories."""

    def lookup(self, dependencies: list[DependencyCoordinate]) -> tuple[list[DependencyAdvisory], list[str]]:
        """Return advisory matches and non-fatal errors."""


class LocalAdvisoryProvider:
    """Advisory provider backed by a local JSON file."""

    def __init__(self, advisory_db_path: str):
        self.advisory_db_path = advisory_db_path
        self._index = self._load_db(advisory_db_path)

    def _load_db(self, advisory_db_path: str) -> dict[tuple[str, str, str], list[dict[str, Any]]]:
        with open(advisory_db_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)

        advisories = payload.get("advisories", [])
        if not isinstance(advisories, list):
            raise ValueError("advisory db must contain a top-level 'advisories' list")

        index: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
        for entry in advisories:
            if not isinstance(entry, dict):
                continue
            ecosystem = str(entry.get("ecosystem", "")).strip().lower()
            name = str(entry.get("name", "")).strip().lower()
            version = str(entry.get("version", "")).strip()
            if not ecosystem or not name or not version:
                continue
            key = (ecosystem, name, version)
            index.setdefault(key, []).append(entry)
        return index

    def lookup(self, dependencies: list[DependencyCoordinate]) -> tuple[list[DependencyAdvisory], list[str]]:
        matches: list[DependencyAdvisory] = []
        for dep in dependencies:
            key = (dep.ecosystem.lower(), dep.name.lower(), dep.version)
            for raw in self._index.get(key, []):
                matches.append(
                    DependencyAdvisory(
                        dependency=dep,
                        advisory_id=str(raw.get("id", "LOCAL-UNKNOWN")),
                        summary=str(raw.get("summary", "Known vulnerable dependency version")),
                        details=str(raw.get("details", "")),
                        severity_name=str(raw.get("severity", "")),
                        cvss_score=_to_float(raw.get("cvss_score")),
                        aliases=_normalize_string_list(raw.get("aliases", [])),
                        fixed_versions=_normalize_string_list(raw.get("fixed_versions", [])),
                        source="local",
                    )
                )
        return matches, []


class OsvAdvisoryProvider:
    """Advisory provider that queries the OSV batch API."""

    def __init__(
        self,
        api_url: str = "https://api.osv.dev/v1/querybatch",
        timeout_seconds: int = 20,
        batch_size: int = 100,
    ):
        self.api_url = api_url
        self.timeout_seconds = timeout_seconds
        self.batch_size = max(1, batch_size)

    def lookup(self, dependencies: list[DependencyCoordinate]) -> tuple[list[DependencyAdvisory], list[str]]:
        advisories: list[DependencyAdvisory] = []
        errors: list[str] = []

        queries: list[DependencyCoordinate] = []
        for dep in dependencies:
            if dep.ecosystem not in OSV_ECOSYSTEM_MAP:
                continue
            if not dep.version:
                continue
            queries.append(dep)

        for start in range(0, len(queries), self.batch_size):
            chunk = queries[start:start + self.batch_size]
            chunk_advisories, chunk_errors = self._lookup_chunk(chunk)
            advisories.extend(chunk_advisories)
            errors.extend(chunk_errors)

        return advisories, errors

    def _lookup_chunk(self, dependencies: list[DependencyCoordinate]) -> tuple[list[DependencyAdvisory], list[str]]:
        payload = {
            "queries": [
                {
                    "package": {
                        "name": dep.name,
                        "ecosystem": OSV_ECOSYSTEM_MAP[dep.ecosystem],
                    },
                    "version": dep.version,
                }
                for dep in dependencies
            ]
        }
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.api_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                data = response.read()
        except urllib.error.URLError as exc:
            return [], [f"OSV query failed: {exc}"]
        except TimeoutError:
            return [], [f"OSV query timed out after {self.timeout_seconds}s"]

        try:
            parsed = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError:
            return [], ["OSV query returned invalid JSON"]

        results = parsed.get("results", [])
        if not isinstance(results, list):
            return [], ["OSV response missing 'results' list"]

        advisories: list[DependencyAdvisory] = []
        for dep, result in zip(dependencies, results):
            if not isinstance(result, dict):
                continue
            vulns = result.get("vulns", [])
            if not isinstance(vulns, list):
                continue
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue
                advisories.append(self._to_advisory(dep, vuln))

        return advisories, []

    def _to_advisory(self, dep: DependencyCoordinate, vuln: dict[str, Any]) -> DependencyAdvisory:
        fixed_versions = _extract_fixed_versions(vuln)
        severity_name = _extract_severity_name(vuln)
        cvss_score = _extract_cvss_score(vuln)
        summary = str(vuln.get("summary") or "").strip()
        details = str(vuln.get("details") or "").strip()
        if not summary:
            summary = details.split("\n", 1)[0][:180] if details else "Known vulnerable dependency version"

        return DependencyAdvisory(
            dependency=dep,
            advisory_id=str(vuln.get("id", "OSV-UNKNOWN")),
            summary=summary,
            details=details,
            severity_name=severity_name,
            cvss_score=cvss_score,
            aliases=_normalize_string_list(vuln.get("aliases", [])),
            fixed_versions=fixed_versions,
            source="osv",
        )


def _normalize_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _extract_fixed_versions(vuln: dict[str, Any]) -> list[str]:
    fixed_versions: set[str] = set()
    affected = vuln.get("affected", [])
    if not isinstance(affected, list):
        return []

    for pkg in affected:
        if not isinstance(pkg, dict):
            continue
        ranges = pkg.get("ranges", [])
        if not isinstance(ranges, list):
            continue
        for rng in ranges:
            if not isinstance(rng, dict):
                continue
            events = rng.get("events", [])
            if not isinstance(events, list):
                continue
            for event in events:
                if not isinstance(event, dict):
                    continue
                fixed = event.get("fixed")
                if fixed:
                    fixed_versions.add(str(fixed))

    return sorted(fixed_versions)


def _extract_severity_name(vuln: dict[str, Any]) -> str:
    db_specific = vuln.get("database_specific", {})
    if isinstance(db_specific, dict):
        severity = db_specific.get("severity")
        if severity:
            return str(severity)

    severities = vuln.get("severity", [])
    if isinstance(severities, list):
        for entry in severities:
            if not isinstance(entry, dict):
                continue
            score = str(entry.get("score", "")).upper()
            if not score:
                continue
            if "CRITICAL" in score:
                return "CRITICAL"
            if "HIGH" in score:
                return "HIGH"
            if "MEDIUM" in score:
                return "MEDIUM"
            if "LOW" in score:
                return "LOW"

    return ""


def _extract_cvss_score(vuln: dict[str, Any]) -> float | None:
    db_specific = vuln.get("database_specific", {})
    if isinstance(db_specific, dict):
        cvss_score = _to_float(db_specific.get("cvss_score"))
        if cvss_score is not None:
            return cvss_score

        cvss = db_specific.get("cvss")
        if isinstance(cvss, dict):
            score = _to_float(cvss.get("score"))
            if score is not None:
                return score

    severities = vuln.get("severity", [])
    if not isinstance(severities, list):
        return None
    for entry in severities:
        if not isinstance(entry, dict):
            continue
        score = _to_float(entry.get("score"))
        if score is not None:
            return score
    return None


def _severity_from_advisory(advisory: DependencyAdvisory) -> Severity:
    level = advisory.severity_name.upper()
    if "CRITICAL" in level or "HIGH" in level:
        return Severity.HIGH
    if "MEDIUM" in level or "MODERATE" in level:
        return Severity.MEDIUM
    if "LOW" in level:
        return Severity.LOW

    if advisory.cvss_score is None:
        return Severity.MEDIUM
    if advisory.cvss_score >= 7.0:
        return Severity.HIGH
    if advisory.cvss_score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _threshold_triggered(high: int, medium: int, low: int, threshold: str) -> bool:
    if threshold == "none":
        return False
    if threshold == "critical":
        # Coyote findings map CRITICAL-class dependency advisories into HIGH.
        return high > 0
    if threshold == "high":
        return high > 0
    if threshold == "medium":
        return (high + medium) > 0
    if threshold == "low":
        return (high + medium + low) > 0
    return False


def _normalize_name(name: str) -> str:
    # Keep package matching stable across ecosystems.
    return name.strip()


def discover_dependency_files(repo_path: str) -> list[str]:
    """Discover known dependency manifests relative to repo_path."""
    manifests: list[str] = []

    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        rel_root = os.path.relpath(root, repo_path)

        for fname in filenames:
            rel_path = os.path.normpath(os.path.join(rel_root, fname))
            if rel_path.startswith("./"):
                rel_path = rel_path[2:]

            if fname in SUPPORTED_MANIFESTS:
                manifests.append(rel_path)
                continue

            if fname.startswith("requirements") and fname.endswith(".txt"):
                manifests.append(rel_path)

    return sorted(set(manifests))


def _parse_requirements(content: str, manifest_path: str) -> list[DependencyCoordinate]:
    deps: list[DependencyCoordinate] = []
    pattern = re.compile(r"^\s*([A-Za-z0-9_.\-]+(?:\[[^\]]+\])?)\s*==\s*([^;\s]+)")

    for idx, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("-r ") or line.startswith("--requirement "):
            continue
        match = pattern.match(line)
        if not match:
            continue
        raw_name = match.group(1)
        version = match.group(2).strip()
        name = _normalize_name(raw_name.split("[", 1)[0]).lower()
        deps.append(
            DependencyCoordinate(
                ecosystem="pypi",
                name=name,
                version=version,
                manifest_path=manifest_path,
                line_number=idx,
                line_content=raw_line.strip(),
            )
        )

    return deps


def _parse_poetry_lock(content: str, manifest_path: str) -> list[DependencyCoordinate]:
    deps: list[DependencyCoordinate] = []
    block: dict[str, str] = {}
    block_start_line = 0
    in_nested_table = False

    def flush_block() -> None:
        if not block:
            return
        name = block.get("name", "").strip().strip('"')
        version = block.get("version", "").strip().strip('"')
        if not name or not version:
            return
        category = block.get("category", "").strip().strip('"').lower()
        is_dev = category == "dev"
        deps.append(
            DependencyCoordinate(
                ecosystem="pypi",
                name=_normalize_name(name),
                version=version,
                manifest_path=manifest_path,
                line_number=block_start_line,
                line_content=f'{name} = "{version}"',
                is_dev_dependency=is_dev,
            )
        )

    for idx, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if line == "[[package]]":
            flush_block()
            block = {}
            block_start_line = idx
            in_nested_table = False
            continue
        if line.startswith("[") and line.endswith("]"):
            # Ignore nested package tables like [package.dependencies].
            in_nested_table = True
            continue
        if not block and not line:
            continue
        if in_nested_table:
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        block[key.strip()] = value.strip()

    flush_block()
    return deps


def _parse_package_lock(content: str, manifest_path: str) -> list[DependencyCoordinate]:
    deps: list[DependencyCoordinate] = []
    parsed = json.loads(content)

    # lockfile v2+ format
    packages = parsed.get("packages")
    if isinstance(packages, dict):
        for path_key, metadata in packages.items():
            if not path_key or not isinstance(metadata, dict):
                continue
            version = str(metadata.get("version", "")).strip()
            if not version:
                continue

            name_match = re.search(r"(?:^|/)node_modules/(@[^/]+/[^/]+|[^/]+)$", path_key)
            if not name_match:
                continue
            name = name_match.group(1).strip().lower()

            deps.append(
                DependencyCoordinate(
                    ecosystem="npm",
                    name=name,
                    version=version,
                    manifest_path=manifest_path,
                    line_number=0,
                    line_content="",
                    is_dev_dependency=bool(metadata.get("dev", False)),
                )
            )

    # lockfile v1 fallback
    top_dependencies = parsed.get("dependencies")
    if isinstance(top_dependencies, dict):
        deps.extend(_parse_npm_dependency_tree(top_dependencies, manifest_path))

    return deps


def _parse_npm_dependency_tree(tree: dict[str, Any], manifest_path: str) -> list[DependencyCoordinate]:
    deps: list[DependencyCoordinate] = []

    for name, metadata in tree.items():
        if not isinstance(metadata, dict):
            continue
        version = str(metadata.get("version", "")).strip()
        if version:
            deps.append(
                DependencyCoordinate(
                    ecosystem="npm",
                    name=str(name).strip(),
                    version=version,
                    manifest_path=manifest_path,
                    line_number=0,
                    line_content="",
                    is_dev_dependency=bool(metadata.get("dev", False)),
                )
            )
        nested = metadata.get("dependencies")
        if isinstance(nested, dict):
            deps.extend(_parse_npm_dependency_tree(nested, manifest_path))

    return deps


def _parse_pnpm_lock(content: str, manifest_path: str) -> list[DependencyCoordinate]:
    deps: list[DependencyCoordinate] = []
    parsed = yaml.safe_load(content) or {}

    packages = parsed.get("packages")
    if isinstance(packages, dict):
        for package_key, metadata in packages.items():
            name, version = _split_pnpm_package_key(str(package_key))
            if not name or not version:
                continue
            is_dev = bool(isinstance(metadata, dict) and metadata.get("dev", False))
            deps.append(
                DependencyCoordinate(
                    ecosystem="npm",
                    name=name,
                    version=version,
                    manifest_path=manifest_path,
                    line_number=0,
                    line_content="",
                    is_dev_dependency=is_dev,
                )
            )

    if deps:
        return deps

    # Fallback for lockfiles that only expose importers with pinned dependency versions.
    importers = parsed.get("importers")
    if not isinstance(importers, dict):
        return deps

    for importer_data in importers.values():
        if not isinstance(importer_data, dict):
            continue
        for section in ("dependencies", "optionalDependencies", "devDependencies"):
            section_data = importer_data.get(section)
            if not isinstance(section_data, dict):
                continue
            for dep_name, dep_version in section_data.items():
                if not isinstance(dep_version, str):
                    continue
                clean_version = dep_version.strip()
                if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.\-]+)?", clean_version):
                    continue
                deps.append(
                    DependencyCoordinate(
                        ecosystem="npm",
                        name=str(dep_name),
                        version=clean_version,
                        manifest_path=manifest_path,
                        line_number=0,
                        line_content="",
                        is_dev_dependency=(section == "devDependencies"),
                    )
                )

    return deps


def _split_pnpm_package_key(package_key: str) -> tuple[str, str]:
    key = package_key.strip()
    if not key:
        return "", ""
    if key.startswith("/"):
        key = key[1:]
    if "(" in key:
        key = key.split("(", 1)[0]
    if "@" not in key:
        return "", ""

    # Scoped package names contain @ in the package name itself.
    at_index = key.rfind("@")
    name = key[:at_index].strip()
    version = key[at_index + 1:].strip()
    if not name or not version:
        return "", ""
    return name, version


def _parse_go_mod(content: str, manifest_path: str) -> list[DependencyCoordinate]:
    deps: list[DependencyCoordinate] = []
    in_require_block = False

    for idx, raw_line in enumerate(content.splitlines(), start=1):
        # Preserve original line for display.
        line_no_comment = raw_line.split("//", 1)[0].strip()
        if not line_no_comment:
            continue

        if line_no_comment == "require (":
            in_require_block = True
            continue
        if in_require_block and line_no_comment == ")":
            in_require_block = False
            continue

        if in_require_block:
            parts = line_no_comment.split()
            if len(parts) < 2:
                continue
            module_name = parts[0].strip()
            version = parts[1].strip()
        elif line_no_comment.startswith("require "):
            remainder = line_no_comment[len("require "):].strip()
            parts = remainder.split()
            if len(parts) < 2:
                continue
            module_name = parts[0].strip()
            version = parts[1].strip()
        else:
            continue

        deps.append(
            DependencyCoordinate(
                ecosystem="go",
                name=module_name,
                version=version,
                manifest_path=manifest_path,
                line_number=idx,
                line_content=raw_line.strip(),
            )
        )

    return deps


def _parse_cargo_lock(content: str, manifest_path: str) -> list[DependencyCoordinate]:
    deps: list[DependencyCoordinate] = []
    block: dict[str, str] = {}
    block_start_line = 0

    def flush_block() -> None:
        if not block:
            return
        name = block.get("name", "").strip().strip('"')
        version = block.get("version", "").strip().strip('"')
        if not name or not version:
            return
        deps.append(
            DependencyCoordinate(
                ecosystem="cratesio",
                name=name,
                version=version,
                manifest_path=manifest_path,
                line_number=block_start_line,
                line_content=f'{name} = "{version}"',
            )
        )

    for idx, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if line == "[[package]]":
            flush_block()
            block = {}
            block_start_line = idx
            continue
        if line.startswith("[") and line.endswith("]"):
            flush_block()
            block = {}
            block_start_line = 0
            continue
        if not block and not line:
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        block[key.strip()] = value.strip()

    flush_block()
    return deps


def _parse_manifest_file(repo_path: str, manifest_path: str) -> list[DependencyCoordinate]:
    full_path = os.path.join(repo_path, manifest_path)
    with open(full_path, "r", encoding="utf-8", errors="ignore") as handle:
        content = handle.read()

    name = os.path.basename(manifest_path)
    lowered_name = name.lower()
    if lowered_name.startswith("requirements") and lowered_name.endswith(".txt"):
        return _parse_requirements(content, manifest_path)
    if name == "poetry.lock":
        return _parse_poetry_lock(content, manifest_path)
    if name == "package-lock.json":
        return _parse_package_lock(content, manifest_path)
    if name in {"pnpm-lock.yaml", "pnpm-lock.yml"}:
        return _parse_pnpm_lock(content, manifest_path)
    if name == "go.mod":
        return _parse_go_mod(content, manifest_path)
    if name == "Cargo.lock":
        return _parse_cargo_lock(content, manifest_path)
    return []


def _build_description(advisory: DependencyAdvisory) -> str:
    dep = advisory.dependency
    summary = advisory.summary or "Known vulnerable dependency version"
    source = advisory.source.upper()
    description = (
        f"{advisory.advisory_id} ({source}) affects "
        f"{dep.name}@{dep.version} [{dep.ecosystem}] - {summary}"
    )

    extras: list[str] = []
    if advisory.fixed_versions:
        extras.append(f"fixed in {', '.join(advisory.fixed_versions[:3])}")
    if advisory.aliases:
        extras.append(f"aliases: {', '.join(advisory.aliases[:3])}")
    if extras:
        description += f" ({'; '.join(extras)})"

    return description


def run_dependency_scan(
    repo_path: str,
    *,
    include_dev_dependencies: bool = True,
    advisory_db_path: str | None = None,
    advisory_provider: AdvisoryProvider | None = None,
    osv_timeout_seconds: int = 20,
    osv_batch_size: int = 100,
    ignore_file: str | None = None,
    no_ignore: bool = False,
) -> ScanResult:
    """Run dependency vulnerability scan and return shared ScanResult."""
    abs_repo = os.path.abspath(repo_path)
    result = ScanResult(repo_path=abs_repo)

    if not os.path.isdir(abs_repo):
        result.errors.append(f"Repository path does not exist: {abs_repo}")
        return result

    suppression_config: SuppressionConfig | None = None
    if not no_ignore:
        suppression_config = load_suppression_config(abs_repo, ignore_file)
        result.suppression_config = suppression_config

    manifest_paths = discover_dependency_files(abs_repo)
    result.files_scanned = len(manifest_paths)

    coordinates: list[DependencyCoordinate] = []
    for manifest_path in manifest_paths:
        try:
            coordinates.extend(_parse_manifest_file(abs_repo, manifest_path))
        except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
            result.files_skipped += 1
            result.errors.append(f"Failed to parse {manifest_path}: {exc}")

    # Keep one coordinate per ecosystem+name+version+manifest path.
    deduped: dict[tuple[str, str, str, str], DependencyCoordinate] = {}
    for dep in coordinates:
        if not include_dev_dependencies and dep.is_dev_dependency:
            continue
        key = (dep.ecosystem, dep.name, dep.version, dep.manifest_path)
        if key not in deduped:
            deduped[key] = dep
    dependencies = list(deduped.values())

    if advisory_provider is None:
        try:
            if advisory_db_path:
                advisory_provider = LocalAdvisoryProvider(advisory_db_path)
            else:
                advisory_provider = OsvAdvisoryProvider(
                    timeout_seconds=osv_timeout_seconds,
                    batch_size=osv_batch_size,
                )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            result.errors.append(f"Failed to initialize advisory provider: {exc}")
            return result

    try:
        advisories, advisory_errors = advisory_provider.lookup(dependencies)
    except Exception as exc:  # keep scan resilient in CI paths
        result.errors.append(f"Advisory lookup failed: {exc}")
        advisories, advisory_errors = [], []
    result.errors.extend(advisory_errors)

    for advisory in advisories:
        dep = advisory.dependency
        severity = _severity_from_advisory(advisory)
        line_number = dep.line_number if dep.line_number > 0 else 0
        matched_value = f"{dep.ecosystem}|{dep.name}|{dep.version}|{advisory.advisory_id}"
        finding_id = generate_finding_id(
            DEPENDENCY_RULE_NAME,
            dep.manifest_path,
            line_number,
            matched_value,
        )
        result.findings.append(
            PatternMatch(
                rule_name=DEPENDENCY_RULE_NAME,
                severity=severity,
                file_path=dep.manifest_path,
                line_number=line_number,
                line_content=dep.line_content[:200],
                description=_build_description(advisory),
                matched_text=f"{dep.name}@{dep.version}",
                finding_id=finding_id,
            )
        )

    if suppression_config and suppression_config.total_rules > 0:
        result.findings = suppression_config.filter_findings(result.findings)
        result.findings_suppressed = suppression_config.findings_suppressed

    return result


def _generate_text_report(result: ScanResult) -> str:
    lines: list[str] = []
    lines.append(f"Coyote v{__version__} dependency scan")
    lines.append(f"Repository: {result.repo_path}")
    lines.append(
        "Summary: "
        f"total={result.total_count} high={result.high_count} "
        f"medium={result.medium_count} low={result.low_count} "
        f"manifests={result.files_scanned}"
    )
    if result.findings_suppressed > 0:
        lines.append(f"Suppressed findings: {result.findings_suppressed}")
    if result.errors:
        lines.append(f"Errors: {len(result.errors)}")
        for err in result.errors:
            lines.append(f"  - {err}")

    if not result.findings:
        lines.append("No known vulnerable dependencies detected.")
        return "\n".join(lines)

    severity_order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
    sorted_findings = sorted(result.findings, key=lambda finding: severity_order.get(finding.severity, 3))

    lines.append("")
    lines.append("Findings:")
    for finding in sorted_findings:
        location = finding.file_path
        if finding.line_number > 0:
            location += f":{finding.line_number}"
        lines.append(
            f"  [{finding.severity.value}] {finding.finding_id} {finding.matched_text} - {location}"
        )
        lines.append(f"      {finding.description}")

    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Coyote dependency vulnerability scanner",
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="Repository path to scan (default: current directory).",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--advisory-db",
        help="Path to local advisory JSON file (offline mode).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=20,
        help="OSV API timeout in seconds (default: 20).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="OSV batch query size (default: 100).",
    )
    parser.add_argument(
        "--skip-dev",
        action="store_true",
        help="Skip development-only dependencies when lockfiles mark them.",
    )
    parser.add_argument(
        "--ignore-file",
        help="Path to ignore file (default: .coyote-ignore in repo root).",
    )
    parser.add_argument(
        "--no-ignore",
        action="store_true",
        help="Disable suppression and report all findings.",
    )
    parser.add_argument(
        "--fail-on",
        choices=FAIL_THRESHOLDS,
        default="none",
        help="Exit non-zero when findings breach severity threshold (default: none).",
    )
    parser.add_argument(
        "--fail-on-errors",
        action="store_true",
        help="Exit non-zero when advisory lookup/parsing errors occur.",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Write JSON/Markdown/SARIF reports to report directory.",
    )
    parser.add_argument(
        "--report-dir",
        default="./reports",
        help="Directory for report files (default: ./reports).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    result = run_dependency_scan(
        repo_path=args.repo,
        include_dev_dependencies=(not args.skip_dev),
        advisory_db_path=args.advisory_db,
        advisory_provider=None,
        osv_timeout_seconds=args.timeout,
        osv_batch_size=args.batch_size,
        ignore_file=args.ignore_file,
        no_ignore=args.no_ignore,
    )

    if args.format == "json":
        print(generate_json_report(result))
    elif args.format == "markdown":
        print(generate_markdown_report(result))
    else:
        print(_generate_text_report(result))

    if args.report:
        report_paths = save_reports(
            result,
            report_dir=args.report_dir,
            formats=["json", "markdown", "sarif"],
        )
        for path in report_paths:
            print(f"Report saved: {path}")

    fail_reasons: list[str] = []
    if _threshold_triggered(result.high_count, result.medium_count, result.low_count, args.fail_on):
        fail_reasons.append(
            "findings breached fail threshold "
            f"({args.fail_on}): HIGH={result.high_count}, "
            f"MEDIUM={result.medium_count}, LOW={result.low_count}"
        )
    if args.fail_on_errors and result.errors:
        fail_reasons.append(f"scan produced {len(result.errors)} runtime error(s)")

    if fail_reasons and args.format != "json":
        print("Gate Result: FAIL")
        for reason in fail_reasons:
            print(f"  - {reason}")

    return 1 if fail_reasons else 0


if __name__ == "__main__":
    raise SystemExit(main())
