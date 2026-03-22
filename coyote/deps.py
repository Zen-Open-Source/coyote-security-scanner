"""Dependency vulnerability scanning for Coyote.

Scans common dependency manifests/lockfiles, queries vulnerability advisories,
and emits findings using the shared ScanResult/PatternMatch model.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol

import yaml

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.11+ ships tomllib
    tomllib = None  # type: ignore[assignment]

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

REACHABILITY_SUPPORTED_ECOSYSTEMS = {
    "pypi": "python",
    "npm": "javascript",
}

REACHABILITY_STATUSES = (
    "reachable",
    "direct-unused",
    "transitive-only",
    "unknown",
)

PYTHON_SOURCE_EXTENSIONS = {".py"}
JAVASCRIPT_SOURCE_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

PYPI_IMPORT_ALIASES = {
    "beautifulsoup4": ("bs4",),
    "opencv-python": ("cv2",),
    "pillow": ("pil",),
    "pyyaml": ("yaml",),
    "python-dateutil": ("dateutil",),
    "scikit-learn": ("sklearn",),
}

JS_IMPORT_PATTERNS = [
    re.compile(r"""import\s+(?:type\s+)?(?:[^'"]+?\s+from\s+)?['"]([^'"]+)['"]"""),
    re.compile(r"""export\s+[^'"]+?\s+from\s+['"]([^'"]+)['"]"""),
    re.compile(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)"""),
    re.compile(r"""import\s*\(\s*['"]([^'"]+)['"]\s*\)"""),
]


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
    is_direct_dependency: bool | None = None


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


@dataclass
class ImportUsage:
    language: str
    files_analyzed: int = 0
    import_map: dict[str, set[str]] = field(default_factory=dict)


@dataclass
class DependencyReachability:
    status: str
    language: str
    direct_dependency: bool | None
    imports: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)


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


def _normalized_lower_name(name: str) -> str:
    return _normalize_name(name).strip().lower()


def _load_toml_file(path: str) -> dict[str, Any]:
    if tomllib is None or not os.path.isfile(path):
        return {}
    try:
        with open(path, "rb") as handle:
            parsed = tomllib.load(handle)
    except (OSError, TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _extract_requirement_name(requirement: str) -> str:
    match = re.match(r"\s*([A-Za-z0-9_.\-]+)", requirement)
    if not match:
        return ""
    return _normalized_lower_name(match.group(1))


def _package_names_from_mapping(value: Any) -> set[str]:
    if not isinstance(value, dict):
        return set()
    return {
        _normalized_lower_name(str(name))
        for name in value.keys()
        if _normalized_lower_name(str(name))
    }


def _package_names_from_sequence(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    names: set[str] = set()
    for item in value:
        name = _extract_requirement_name(str(item))
        if name:
            names.add(name)
    return names


def _load_poetry_direct_dependencies(repo_path: str, manifest_path: str) -> tuple[set[str], set[str]]:
    manifest_dir = os.path.dirname(os.path.join(repo_path, manifest_path))
    pyproject_path = os.path.join(manifest_dir, "pyproject.toml")
    parsed = _load_toml_file(pyproject_path)
    if not parsed:
        return set(), set()

    direct_main: set[str] = set()
    direct_dev: set[str] = set()

    tool = parsed.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            direct_main.update(
                name for name in _package_names_from_mapping(poetry.get("dependencies"))
                if name != "python"
            )
            direct_dev.update(_package_names_from_mapping(poetry.get("dev-dependencies")))

            groups = poetry.get("group")
            if isinstance(groups, dict):
                for group_name, group_value in groups.items():
                    if not isinstance(group_value, dict):
                        continue
                    dependencies = _package_names_from_mapping(group_value.get("dependencies"))
                    if str(group_name).lower() == "dev":
                        direct_dev.update(dependencies)
                    else:
                        direct_main.update(dependencies)

    project = parsed.get("project")
    if isinstance(project, dict):
        direct_main.update(_package_names_from_sequence(project.get("dependencies")))
        optional_deps = project.get("optional-dependencies")
        if isinstance(optional_deps, dict):
            for values in optional_deps.values():
                direct_main.update(_package_names_from_sequence(values))

    return direct_main, direct_dev


def _load_package_json_direct_dependencies(repo_path: str, manifest_path: str) -> tuple[set[str], set[str]]:
    manifest_dir = os.path.dirname(os.path.join(repo_path, manifest_path))
    package_json_path = os.path.join(manifest_dir, "package.json")
    if not os.path.isfile(package_json_path):
        return set(), set()
    try:
        with open(package_json_path, "r", encoding="utf-8") as handle:
            parsed = json.load(handle)
    except (OSError, ValueError, json.JSONDecodeError):
        return set(), set()
    if not isinstance(parsed, dict):
        return set(), set()

    direct_main = set()
    direct_main.update(_package_names_from_mapping(parsed.get("dependencies")))
    direct_main.update(_package_names_from_mapping(parsed.get("optionalDependencies")))
    direct_dev = _package_names_from_mapping(parsed.get("devDependencies"))
    return direct_main, direct_dev


def _load_cargo_direct_dependencies(repo_path: str, manifest_path: str) -> tuple[set[str], set[str]]:
    manifest_dir = os.path.dirname(os.path.join(repo_path, manifest_path))
    cargo_toml_path = os.path.join(manifest_dir, "Cargo.toml")
    parsed = _load_toml_file(cargo_toml_path)
    if not parsed:
        return set(), set()

    direct_main: set[str] = set()
    direct_dev: set[str] = set()

    for section_name, target in (("dependencies", direct_main), ("build-dependencies", direct_main), ("dev-dependencies", direct_dev)):
        target.update(_package_names_from_mapping(parsed.get(section_name)))

    targets = parsed.get("target")
    if isinstance(targets, dict):
        for target_cfg in targets.values():
            if not isinstance(target_cfg, dict):
                continue
            direct_main.update(_package_names_from_mapping(target_cfg.get("dependencies")))
            direct_main.update(_package_names_from_mapping(target_cfg.get("build-dependencies")))
            direct_dev.update(_package_names_from_mapping(target_cfg.get("dev-dependencies")))

    return direct_main, direct_dev


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


def collect_dependencies(repo_path: str, *, include_dev: bool = True) -> list[DependencyCoordinate]:
    """Discover and parse all dependency manifests, returning deduplicated coordinates.

    This is a lightweight wrapper around discover + parse that skips advisory
    lookups and reachability analysis — suitable for SBOM generation and other
    inventory-only workflows.
    """
    abs_repo = os.path.abspath(repo_path)
    manifest_paths = discover_dependency_files(abs_repo)

    coordinates: list[DependencyCoordinate] = []
    for manifest_path in manifest_paths:
        try:
            coordinates.extend(_parse_manifest_file(abs_repo, manifest_path))
        except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError):
            continue

    deduped: dict[tuple[str, str, str, str], DependencyCoordinate] = {}
    for dep in coordinates:
        if not include_dev and dep.is_dev_dependency:
            continue
        key = (dep.ecosystem, dep.name, dep.version, dep.manifest_path)
        if key not in deduped:
            deduped[key] = dep
    return list(deduped.values())


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
                is_direct_dependency=True,
            )
        )

    return deps


def _parse_poetry_lock(repo_path: str, content: str, manifest_path: str) -> list[DependencyCoordinate]:
    deps: list[DependencyCoordinate] = []
    block: dict[str, str] = {}
    block_start_line = 0
    in_nested_table = False
    direct_main, direct_dev = _load_poetry_direct_dependencies(repo_path, manifest_path)

    def flush_block() -> None:
        if not block:
            return
        name = block.get("name", "").strip().strip('"')
        version = block.get("version", "").strip().strip('"')
        if not name or not version:
            return
        category = block.get("category", "").strip().strip('"').lower()
        is_dev = category == "dev"
        normalized_name = _normalize_name(name)
        lowered_name = normalized_name.lower()
        is_direct: bool | None = None
        if direct_main or direct_dev:
            is_direct = lowered_name in direct_main or lowered_name in direct_dev
        deps.append(
            DependencyCoordinate(
                ecosystem="pypi",
                name=normalized_name,
                version=version,
                manifest_path=manifest_path,
                line_number=block_start_line,
                line_content=f'{name} = "{version}"',
                is_dev_dependency=is_dev,
                is_direct_dependency=is_direct,
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


def _parse_package_lock(repo_path: str, content: str, manifest_path: str) -> list[DependencyCoordinate]:
    deps: list[DependencyCoordinate] = []
    parsed = json.loads(content)

    # lockfile v2+ format
    packages = parsed.get("packages")
    if isinstance(packages, dict):
        root_metadata = packages.get("")
        direct_main: set[str] = set()
        direct_dev: set[str] = set()
        if isinstance(root_metadata, dict):
            direct_main.update(_package_names_from_mapping(root_metadata.get("dependencies")))
            direct_main.update(_package_names_from_mapping(root_metadata.get("optionalDependencies")))
            direct_dev.update(_package_names_from_mapping(root_metadata.get("devDependencies")))
        if not direct_main and not direct_dev:
            file_main, file_dev = _load_package_json_direct_dependencies(repo_path, manifest_path)
            direct_main.update(file_main)
            direct_dev.update(file_dev)
        for path_key, metadata in packages.items():
            if not path_key or not isinstance(metadata, dict):
                continue
            version = str(metadata.get("version", "")).strip()
            if not version:
                continue

            name_match = re.search(r"(?:^|/)node_modules/(@[^/]+/[^/]+|[^/]+)$", path_key)
            if not name_match:
                continue
            name = _normalized_lower_name(name_match.group(1))
            is_direct: bool | None = None
            if direct_main or direct_dev:
                is_direct = name in direct_main or name in direct_dev

            deps.append(
                DependencyCoordinate(
                    ecosystem="npm",
                    name=name,
                    version=version,
                    manifest_path=manifest_path,
                    line_number=0,
                    line_content="",
                    is_dev_dependency=bool(metadata.get("dev", False)),
                    is_direct_dependency=is_direct,
                )
            )

    # lockfile v1 fallback
    top_dependencies = parsed.get("dependencies")
    if isinstance(top_dependencies, dict):
        deps.extend(_parse_npm_dependency_tree(top_dependencies, manifest_path, is_direct_level=True))

    return deps


def _parse_npm_dependency_tree(
    tree: dict[str, Any],
    manifest_path: str,
    *,
    is_direct_level: bool,
) -> list[DependencyCoordinate]:
    deps: list[DependencyCoordinate] = []

    for name, metadata in tree.items():
        if not isinstance(metadata, dict):
            continue
        version = str(metadata.get("version", "")).strip()
        if version:
            deps.append(
                DependencyCoordinate(
                    ecosystem="npm",
                    name=_normalized_lower_name(str(name)),
                    version=version,
                    manifest_path=manifest_path,
                    line_number=0,
                    line_content="",
                    is_dev_dependency=bool(metadata.get("dev", False)),
                    is_direct_dependency=is_direct_level,
                )
            )
        nested = metadata.get("dependencies")
        if isinstance(nested, dict):
            deps.extend(_parse_npm_dependency_tree(nested, manifest_path, is_direct_level=False))

    return deps


def _parse_pnpm_lock(repo_path: str, content: str, manifest_path: str) -> list[DependencyCoordinate]:
    deps: list[DependencyCoordinate] = []
    parsed = yaml.safe_load(content) or {}
    direct_main: set[str] = set()
    direct_dev: set[str] = set()

    importers = parsed.get("importers")
    if isinstance(importers, dict):
        for importer_data in importers.values():
            if not isinstance(importer_data, dict):
                continue
            direct_main.update(_package_names_from_mapping(importer_data.get("dependencies")))
            direct_main.update(_package_names_from_mapping(importer_data.get("optionalDependencies")))
            direct_dev.update(_package_names_from_mapping(importer_data.get("devDependencies")))

    if not direct_main and not direct_dev:
        file_main, file_dev = _load_package_json_direct_dependencies(repo_path, manifest_path)
        direct_main.update(file_main)
        direct_dev.update(file_dev)

    packages = parsed.get("packages")
    if isinstance(packages, dict):
        for package_key, metadata in packages.items():
            name, version = _split_pnpm_package_key(str(package_key))
            if not name or not version:
                continue
            lowered_name = _normalized_lower_name(name)
            is_direct: bool | None = None
            if direct_main or direct_dev:
                is_direct = lowered_name in direct_main or lowered_name in direct_dev
            is_dev = bool(isinstance(metadata, dict) and metadata.get("dev", False))
            deps.append(
                DependencyCoordinate(
                    ecosystem="npm",
                    name=lowered_name,
                    version=version,
                    manifest_path=manifest_path,
                    line_number=0,
                    line_content="",
                    is_dev_dependency=is_dev,
                    is_direct_dependency=is_direct,
                )
            )

    if deps:
        return deps

    # Fallback for lockfiles that only expose importers with pinned dependency versions.
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
                lowered_name = _normalized_lower_name(str(dep_name))
                deps.append(
                    DependencyCoordinate(
                        ecosystem="npm",
                        name=lowered_name,
                        version=clean_version,
                        manifest_path=manifest_path,
                        line_number=0,
                        line_content="",
                        is_dev_dependency=(section == "devDependencies"),
                        is_direct_dependency=True,
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
                is_direct_dependency="// indirect" not in raw_line,
            )
        )

    return deps


def _parse_cargo_lock(repo_path: str, content: str, manifest_path: str) -> list[DependencyCoordinate]:
    deps: list[DependencyCoordinate] = []
    block: dict[str, str] = {}
    block_start_line = 0
    direct_main, direct_dev = _load_cargo_direct_dependencies(repo_path, manifest_path)

    def flush_block() -> None:
        if not block:
            return
        name = block.get("name", "").strip().strip('"')
        version = block.get("version", "").strip().strip('"')
        if not name or not version:
            return
        lowered_name = _normalized_lower_name(name)
        is_direct: bool | None = None
        if direct_main or direct_dev:
            is_direct = lowered_name in direct_main or lowered_name in direct_dev
        deps.append(
            DependencyCoordinate(
                ecosystem="cratesio",
                name=lowered_name,
                version=version,
                manifest_path=manifest_path,
                line_number=block_start_line,
                line_content=f'{name} = "{version}"',
                is_direct_dependency=is_direct,
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
        return _parse_poetry_lock(repo_path, content, manifest_path)
    if name == "package-lock.json":
        return _parse_package_lock(repo_path, content, manifest_path)
    if name in {"pnpm-lock.yaml", "pnpm-lock.yml"}:
        return _parse_pnpm_lock(repo_path, content, manifest_path)
    if name == "go.mod":
        return _parse_go_mod(content, manifest_path)
    if name == "Cargo.lock":
        return _parse_cargo_lock(repo_path, content, manifest_path)
    return []


def _project_root_from_manifest(manifest_path: str) -> str:
    rel_dir = os.path.dirname(manifest_path)
    return rel_dir if rel_dir else "."


def _iter_source_files(repo_path: str, project_root: str, extensions: set[str]) -> list[str]:
    abs_root = os.path.join(repo_path, project_root)
    if not os.path.isdir(abs_root):
        return []

    source_files: list[str] = []
    for root, dirs, filenames in os.walk(abs_root):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for filename in filenames:
            _, ext = os.path.splitext(filename)
            if ext.lower() not in extensions:
                continue
            abs_path = os.path.join(root, filename)
            rel_path = os.path.relpath(abs_path, repo_path)
            source_files.append(rel_path)
    return sorted(source_files)


def _record_import(import_map: dict[str, set[str]], import_name: str, file_path: str) -> None:
    if not import_name:
        return
    import_map.setdefault(import_name, set()).add(file_path)


def _collect_python_usage(repo_path: str, project_root: str) -> tuple[ImportUsage, list[str]]:
    usage = ImportUsage(language="python")
    errors: list[str] = []
    source_files = _iter_source_files(repo_path, project_root, PYTHON_SOURCE_EXTENSIONS)
    usage.files_analyzed = len(source_files)

    for rel_path in source_files:
        abs_path = os.path.join(repo_path, rel_path)
        try:
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as handle:
                content = handle.read()
            tree = ast.parse(content, filename=rel_path)
        except (OSError, SyntaxError, ValueError) as exc:
            errors.append(f"Reachability parse failed for {rel_path}: {exc}")
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    import_name = alias.name.split(".", 1)[0].strip().lower()
                    _record_import(usage.import_map, import_name, rel_path)
            elif isinstance(node, ast.ImportFrom):
                if node.level != 0 or not node.module:
                    continue
                import_name = node.module.split(".", 1)[0].strip().lower()
                _record_import(usage.import_map, import_name, rel_path)

    return usage, errors


def _extract_js_package_name(specifier: str) -> str:
    value = specifier.strip()
    if not value or value.startswith(".") or value.startswith("/"):
        return ""
    if value.startswith("@"):
        parts = value.split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}".lower()
        return value.lower()
    return value.split("/", 1)[0].lower()


def _collect_javascript_usage(repo_path: str, project_root: str) -> tuple[ImportUsage, list[str]]:
    usage = ImportUsage(language="javascript")
    errors: list[str] = []
    source_files = _iter_source_files(repo_path, project_root, JAVASCRIPT_SOURCE_EXTENSIONS)
    usage.files_analyzed = len(source_files)

    for rel_path in source_files:
        abs_path = os.path.join(repo_path, rel_path)
        try:
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as handle:
                content = handle.read()
        except OSError as exc:
            errors.append(f"Reachability read failed for {rel_path}: {exc}")
            continue

        for pattern in JS_IMPORT_PATTERNS:
            for match in pattern.finditer(content):
                package_name = _extract_js_package_name(match.group(1))
                _record_import(usage.import_map, package_name, rel_path)

    return usage, errors


def _python_import_candidates(dep_name: str) -> list[str]:
    normalized = dep_name.strip().lower()
    candidates: set[str] = set()

    def add_candidate(value: str) -> None:
        cleaned = value.strip().lower()
        if cleaned:
            candidates.add(cleaned)

    add_candidate(normalized)
    add_candidate(normalized.replace("-", "_"))
    add_candidate(normalized.replace(".", "_"))
    if normalized.startswith("python-"):
        add_candidate(normalized[len("python-"):].replace("-", "_"))
    for alias in PYPI_IMPORT_ALIASES.get(normalized, ()):
        add_candidate(alias)

    return sorted(candidates)


def _import_candidates_for_dependency(dep: DependencyCoordinate) -> list[str]:
    if dep.ecosystem == "pypi":
        return _python_import_candidates(dep.name)
    if dep.ecosystem == "npm":
        return [dep.name.lower()]
    return []


def _exploitability_for_reachability(status: str) -> str:
    if status == "reachable":
        return "likely"
    if status == "direct-unused":
        return "potential"
    if status == "transitive-only":
        return "limited"
    return "unknown"


class DependencyReachabilityAnalyzer:
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.errors: list[str] = []
        self._usage_cache: dict[tuple[str, str], ImportUsage] = {}

    def analyze(self, dependencies: list[DependencyCoordinate]) -> dict[tuple[str, str, str, str], DependencyReachability]:
        findings: dict[tuple[str, str, str, str], DependencyReachability] = {}
        for dep in dependencies:
            key = (dep.ecosystem, dep.name, dep.version, dep.manifest_path)
            findings[key] = self._classify(dep)
        return findings

    def _classify(self, dep: DependencyCoordinate) -> DependencyReachability:
        language = REACHABILITY_SUPPORTED_ECOSYSTEMS.get(dep.ecosystem, "")
        if not language:
            return DependencyReachability(
                status="unknown",
                language="",
                direct_dependency=dep.is_direct_dependency,
            )

        project_root = _project_root_from_manifest(dep.manifest_path)
        usage = self._get_usage(language, project_root)
        if usage.files_analyzed == 0:
            return DependencyReachability(
                status="unknown",
                language=language,
                direct_dependency=dep.is_direct_dependency,
            )

        matched_imports: list[str] = []
        matched_files: set[str] = set()
        for candidate in _import_candidates_for_dependency(dep):
            files = usage.import_map.get(candidate, set())
            if not files:
                continue
            matched_imports.append(candidate)
            matched_files.update(files)

        if matched_files:
            return DependencyReachability(
                status="reachable",
                language=language,
                direct_dependency=dep.is_direct_dependency,
                imports=sorted(set(matched_imports)),
                files=sorted(matched_files),
            )

        if dep.is_direct_dependency is False:
            status = "transitive-only"
        elif dep.is_direct_dependency is True:
            status = "direct-unused"
        else:
            status = "unknown"

        return DependencyReachability(
            status=status,
            language=language,
            direct_dependency=dep.is_direct_dependency,
        )

    def _get_usage(self, language: str, project_root: str) -> ImportUsage:
        cache_key = (language, project_root)
        cached = self._usage_cache.get(cache_key)
        if cached is not None:
            return cached

        if language == "python":
            usage, errors = _collect_python_usage(self.repo_path, project_root)
        else:
            usage, errors = _collect_javascript_usage(self.repo_path, project_root)
        self.errors.extend(errors)
        self._usage_cache[cache_key] = usage
        return usage


def _build_description(
    advisory: DependencyAdvisory,
    reachability: DependencyReachability | None = None,
) -> str:
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
    if reachability is not None:
        extras.append(f"reachability: {reachability.status}")
        if reachability.imports:
            extras.append(f"imports: {', '.join(reachability.imports[:3])}")
        if reachability.files:
            extras.append(f"evidence: {', '.join(reachability.files[:2])}")
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
    reachability_analyzer = DependencyReachabilityAnalyzer(abs_repo)
    reachability = reachability_analyzer.analyze(dependencies)
    result.errors.extend(reachability_analyzer.errors)

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
        dep_key = (dep.ecosystem, dep.name, dep.version, dep.manifest_path)
        dep_reachability = reachability.get(
            dep_key,
            DependencyReachability(
                status="unknown",
                language=REACHABILITY_SUPPORTED_ECOSYSTEMS.get(dep.ecosystem, ""),
                direct_dependency=dep.is_direct_dependency,
            ),
        )
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
                description=_build_description(advisory, dep_reachability),
                matched_text=f"{dep.name}@{dep.version}",
                finding_id=finding_id,
                metadata={
                    "dependency_ecosystem": dep.ecosystem,
                    "dependency_name": dep.name,
                    "dependency_version": dep.version,
                    "dependency_manifest": dep.manifest_path,
                    "dependency_direct": dep.is_direct_dependency,
                    "dependency_dev": dep.is_dev_dependency,
                    "advisory_id": advisory.advisory_id,
                    "advisory_source": advisory.source,
                    "reachability": dep_reachability.status,
                    "reachability_language": dep_reachability.language or None,
                    "reachability_imports": dep_reachability.imports,
                    "reachability_files": dep_reachability.files,
                    "exploitability": _exploitability_for_reachability(dep_reachability.status),
                },
            )
        )

    if suppression_config and suppression_config.total_rules > 0:
        result.findings = suppression_config.filter_findings(result.findings)
        result.findings_suppressed = suppression_config.findings_suppressed

    return result


def _dependency_reachability_counts(findings: list[PatternMatch]) -> dict[str, int]:
    counts = {status: 0 for status in REACHABILITY_STATUSES}
    for finding in findings:
        if finding.rule_name != DEPENDENCY_RULE_NAME:
            continue
        status = str(finding.metadata.get("reachability", "unknown")).lower()
        if status not in counts:
            status = "unknown"
        counts[status] += 1
    return counts


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
    reachability_counts = _dependency_reachability_counts(result.findings)
    if result.findings:
        lines.append(
            "Reachability: "
            f"reachable={reachability_counts['reachable']} "
            f"direct-unused={reachability_counts['direct-unused']} "
            f"transitive-only={reachability_counts['transitive-only']} "
            f"unknown={reachability_counts['unknown']}"
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
