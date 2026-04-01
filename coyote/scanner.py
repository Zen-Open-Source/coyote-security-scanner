"""Core scanning engine for Coyote security scanner."""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .entropy import scan_content_for_entropy, generate_entropy_finding_id
from .suppress import SuppressionConfig, load_suppression_config
from .patterns import (
    GITIGNORE_SHOULD_CONTAIN,
    LARGE_FILE_THRESHOLD,
    SECRET_PATTERNS,
    SENSITIVE_FILENAME_EXACT,
    SENSITIVE_FILENAME_GLOBS,
    SMELL_PATTERNS,
    PatternMatch,
    Severity,
    get_sensitive_file_remediation,
)


def generate_finding_id(
    rule_name: str,
    file_path: str,
    line_number: int,
    matched_value: str = "",
) -> str:
    """
    Generate a stable, deterministic ID for a finding.

    The ID is a truncated SHA-256 hash of the finding's key attributes.
    This enables:
    - Diffing findings across scans (detect new vs existing issues)
    - Suppressing specific findings by ID
    - Tracking finding lifecycle over time

    The ID will remain stable as long as the same issue exists at the same
    location. If the file, line, or matched value changes, the ID changes.

    Args:
        rule_name: The pattern/rule that matched (e.g., "AWS Access Key")
        file_path: Relative path to the file
        line_number: Line number where the finding was detected (0 for file-level)
        matched_value: The actual matched text (or empty for file-level findings)

    Returns:
        An 8-character hexadecimal ID (e.g., "a1b2c3d4")
    """
    # Build a deterministic string from the finding's key attributes
    # Using pipe separator to avoid collisions from concatenation
    id_source = f"{rule_name}|{file_path}|{line_number}|{matched_value}"

    # Hash and truncate to 8 chars (32 bits) - enough for uniqueness in a repo
    hash_bytes = hashlib.sha256(id_source.encode("utf-8")).hexdigest()
    return hash_bytes[:8]


@dataclass
class ScanResult:
    repo_path: str
    findings: list[PatternMatch] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    errors: list[str] = field(default_factory=list)

    # Suppression stats
    findings_suppressed: int = 0
    suppression_config: SuppressionConfig | None = None

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

    @property
    def total_before_suppression(self) -> int:
        return self.total_count + self.findings_suppressed


DEFAULT_EXCLUDE_PATHS = [
    "node_modules/",
    "venv/",
    ".venv/",
    ".git/",
    "vendor/",
    "__pycache__/",
    ".tox/",
    ".mypy_cache/",
    ".pytest_cache/",
    "dist/",
    "build/",
    ".eggs/",
]

DEFAULT_EXCLUDE_EXTENSIONS = [
    ".min.js",
    ".map",
    ".lock",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".ico",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".mp3",
    ".mp4",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".jar",
    ".war",
    ".ear",
    ".class",
    ".pyc",
    ".pyo",
    ".so",
    ".dylib",
    ".dll",
    ".exe",
]

DEFAULT_MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


SHIELD_CANONICAL_FILENAME = "shield.md"
SHIELD_ALTERNATE_FILENAMES = ["SHIELD.md", "Shield.md"]
SHIELD_EXPECTED_VERSION = "0.1"
SHIELD_REQUIRED_FRONTMATTER_KEYS = ["name", "description", "version"]
SHIELD_REQUIRED_SECTIONS = [
    "Purpose",
    "Scope",
    "Threat categories",
    "Enforcement states",
    "Decision requirement",
    "Default behavior",
    "Match eligibility",
    "Confidence threshold",
    "Matching logic",
    "recommendation_agent mini syntax v0",
    "Hard stop rule",
    "Required behavior",
    "Context limits",
    "Active threats (compressed)",
]
SHIELD_REQUIRED_ACTIONS = ["log", "require_approval", "block"]
SHIELD_REQUIRED_CATEGORIES = [
    "prompt",
    "tool",
    "mcp",
    "memory",
    "supply_chain",
    "vulnerability",
    "fraud",
    "policy_bypass",
    "anomaly",
    "skill",
    "other",
]
SHIELD_REQUIRED_DECISION_FIELDS = [
    "action",
    "scope",
    "threat_id",
    "fingerprint",
    "matched_on",
    "match_value",
    "reason",
]


class Scanner:
    def __init__(
        self,
        repo_path: str,
        exclude_paths: list[str] | None = None,
        exclude_extensions: list[str] | None = None,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        enable_entropy: bool = False,
        entropy_threshold: float = 4.5,
        ignore_file: str | None = None,
        no_ignore: bool = False,
        enable_shield_scan: bool = False,
        require_shield: bool = False,
    ):
        self.repo_path = os.path.abspath(repo_path)
        self.exclude_paths = exclude_paths or DEFAULT_EXCLUDE_PATHS
        self.exclude_extensions = exclude_extensions or DEFAULT_EXCLUDE_EXTENSIONS
        self.max_file_size = max_file_size
        self.enable_entropy = enable_entropy
        self.entropy_threshold = entropy_threshold
        self.ignore_file = ignore_file
        self.no_ignore = no_ignore
        self.enable_shield_scan = enable_shield_scan
        self.require_shield = require_shield

    def scan(self) -> ScanResult:
        """Run a full security scan on the repository."""
        result = ScanResult(repo_path=self.repo_path)

        if not os.path.isdir(self.repo_path):
            result.errors.append(f"Repository path does not exist: {self.repo_path}")
            return result

        # Load suppression config (unless disabled)
        suppression_config = None
        if not self.no_ignore:
            suppression_config = load_suppression_config(self.repo_path, self.ignore_file)
            result.suppression_config = suppression_config

        # Collect all files to scan
        files = self._collect_files(result)

        # Check for sensitive files
        self._check_sensitive_files(files, result)

        # Scan file contents for secrets and smells
        self._scan_file_contents(files, result)

        # Git-specific checks
        self._check_gitignore(result)
        self._check_large_files(result)
        self._check_shield_policy(result)

        # Apply suppression rules
        if suppression_config and suppression_config.total_rules > 0:
            result.findings = suppression_config.filter_findings(result.findings)
            result.findings_suppressed = suppression_config.findings_suppressed

        return result

    def _collect_files(self, result: ScanResult) -> list[str]:
        """Walk the repo and collect files to scan, respecting exclusions."""
        files = []
        for root, dirs, filenames in os.walk(self.repo_path):
            # Filter out excluded directories in-place
            rel_root = os.path.relpath(root, self.repo_path)
            dirs[:] = [
                d for d in dirs
                if not self._is_excluded_path(os.path.join(rel_root, d) + "/")
            ]

            for fname in filenames:
                full_path = os.path.join(root, fname)
                rel_path = os.path.relpath(full_path, self.repo_path)

                if self._is_excluded_path(rel_path):
                    result.files_skipped += 1
                    continue

                if self._is_excluded_extension(fname):
                    result.files_skipped += 1
                    continue

                try:
                    size = os.path.getsize(full_path)
                    if size > self.max_file_size:
                        result.files_skipped += 1
                        continue
                except OSError:
                    result.files_skipped += 1
                    continue

                files.append(rel_path)
                result.files_scanned += 1

        return files

    def _is_excluded_path(self, rel_path: str) -> bool:
        """Check if a relative path matches any exclusion pattern."""
        normalized = rel_path.replace("\\", "/")
        if normalized.startswith("./"):
            normalized = normalized[2:]
        for exc in self.exclude_paths:
            if normalized.startswith(exc) or ("/" + exc) in ("/" + normalized):
                return True
        return False

    def _is_excluded_extension(self, filename: str) -> bool:
        """Check if a filename has an excluded extension."""
        lower = filename.lower()
        for ext in self.exclude_extensions:
            if lower.endswith(ext):
                return True
        return False

    def _check_sensitive_files(self, files: list[str], result: ScanResult) -> None:
        """Check for sensitive files that shouldn't be in a repo."""
        for rel_path in files:
            filename = os.path.basename(rel_path)

            # Exact match
            if filename in SENSITIVE_FILENAME_EXACT:
                desc, sev = SENSITIVE_FILENAME_EXACT[filename]
                # Skip .pub files for SSH keys
                if filename.endswith(".pub"):
                    continue
                result.findings.append(PatternMatch(
                    rule_name="Sensitive File",
                    severity=sev,
                    file_path=rel_path,
                    line_number=0,
                    line_content="",
                    description=f"{desc}: {filename}",
                    finding_id=generate_finding_id("Sensitive File", rel_path, 0, filename),
                    remediation=get_sensitive_file_remediation(filename),
                ))

            # Glob match
            for glob_pat, desc, sev in SENSITIVE_FILENAME_GLOBS:
                if fnmatch.fnmatch(filename, glob_pat):
                    result.findings.append(PatternMatch(
                        rule_name="Sensitive File",
                        severity=sev,
                        file_path=rel_path,
                        line_number=0,
                        line_content="",
                        description=f"{desc}: {filename}",
                        finding_id=generate_finding_id("Sensitive File", rel_path, 0, filename),
                        remediation=get_sensitive_file_remediation(filename),
                    ))
                    break  # one match per glob set is enough

    def _scan_file_contents(self, files: list[str], result: ScanResult) -> None:
        """Scan file contents for secrets and security smells."""
        for rel_path in files:
            full_path = os.path.join(self.repo_path, rel_path)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    lines = content.split('\n')
            except (OSError, UnicodeDecodeError):
                continue

            ext = Path(rel_path).suffix.lower()

            # Check secret patterns
            for line_num, line in enumerate(lines, start=1):
                stripped = line.rstrip("\n\r")

                for sp in SECRET_PATTERNS:
                    match = sp.pattern.search(stripped)
                    if match:
                        # If pattern requires nearby context, check it
                        if sp.near_context:
                            if not sp.near_context.search(stripped):
                                continue
                        # Mask the matched text for reporting
                        matched = match.group(0)
                        masked = matched[:4] + "..." + matched[-4:] if len(matched) > 12 else "***"
                        # Use the actual matched value for ID generation (ensures stability)
                        result.findings.append(PatternMatch(
                            rule_name=sp.name,
                            severity=sp.severity,
                            file_path=rel_path,
                            line_number=line_num,
                            line_content=stripped[:200],
                            description=sp.description,
                            matched_text=masked,
                            finding_id=generate_finding_id(sp.name, rel_path, line_num, matched),
                            remediation=sp.remediation,
                        ))

                # Check smell patterns
                for smell in SMELL_PATTERNS:
                    if smell.file_extensions and ext not in smell.file_extensions:
                        continue
                    smell_match = smell.pattern.search(stripped)
                    if smell_match:
                        result.findings.append(PatternMatch(
                            rule_name=smell.name,
                            severity=smell.severity,
                            file_path=rel_path,
                            line_number=line_num,
                            line_content=stripped[:200],
                            description=smell.description,
                            finding_id=generate_finding_id(smell.name, rel_path, line_num, smell_match.group(0)),
                            remediation=smell.remediation,
                        ))

            # Entropy-based detection (if enabled)
            if self.enable_entropy:
                entropy_findings = scan_content_for_entropy(
                    content,
                    rel_path,
                    entropy_threshold=self.entropy_threshold,
                )
                for ef in entropy_findings:
                    result.findings.append(PatternMatch(
                        rule_name=f"High Entropy ({ef.char_set})",
                        severity=ef.severity,
                        file_path=ef.file_path,
                        line_number=ef.line_number,
                        line_content=ef.line_content[:200],
                        description=f"High-entropy string detected (entropy: {ef.entropy:.2f}, confidence: {ef.confidence})",
                        matched_text=ef.masked_value,
                        finding_id=generate_entropy_finding_id(ef),
                        remediation="Investigate this high-entropy string. If it is a secret, rotate it and move it to environment variables.",
                    ))

    def _check_gitignore(self, result: ScanResult) -> None:
        """Check if .gitignore exists and covers common secret patterns."""
        gitignore_path = os.path.join(self.repo_path, ".gitignore")
        if not os.path.isfile(gitignore_path):
            result.findings.append(PatternMatch(
                rule_name="Missing .gitignore",
                severity=Severity.LOW,
                file_path=".gitignore",
                line_number=0,
                line_content="",
                description="No .gitignore file found - secrets may be accidentally committed",
                finding_id=generate_finding_id("Missing .gitignore", ".gitignore", 0, ""),
                remediation="Create a .gitignore file. See github.com/github/gitignore for templates.",
            ))
            return

        try:
            with open(gitignore_path, "r", encoding="utf-8") as f:
                gitignore_content = f.read()
        except OSError:
            return

        missing = []
        for pattern in GITIGNORE_SHOULD_CONTAIN:
            if pattern not in gitignore_content:
                missing.append(pattern)

        if missing:
            # Use sorted missing patterns in ID for stability
            result.findings.append(PatternMatch(
                rule_name="Incomplete .gitignore",
                severity=Severity.LOW,
                file_path=".gitignore",
                line_number=0,
                line_content="",
                description=f".gitignore missing patterns: {', '.join(missing[:5])}{'...' if len(missing) > 5 else ''}",
                finding_id=generate_finding_id("Incomplete .gitignore", ".gitignore", 0, ",".join(sorted(missing))),
                remediation="Add the missing patterns to .gitignore to prevent accidental commits of sensitive files.",
            ))

    def _check_large_files(self, result: ScanResult) -> None:
        """Detect large binary files that shouldn't be in the repo."""
        for root, dirs, filenames in os.walk(self.repo_path):
            rel_root = os.path.relpath(root, self.repo_path)
            dirs[:] = [
                d for d in dirs
                if not self._is_excluded_path(os.path.join(rel_root, d) + "/")
            ]
            for fname in filenames:
                full_path = os.path.join(root, fname)
                try:
                    size = os.path.getsize(full_path)
                    if size > LARGE_FILE_THRESHOLD:
                        rel_path = os.path.relpath(full_path, self.repo_path)
                        size_mb = size / (1024 * 1024)
                        result.findings.append(PatternMatch(
                            rule_name="Large File",
                            severity=Severity.LOW,
                            file_path=rel_path,
                            line_number=0,
                            line_content="",
                            description=f"Large file ({size_mb:.1f} MB) shouldn't be in repository",
                            finding_id=generate_finding_id("Large File", rel_path, 0, str(size)),
                            remediation="Remove this large file from the repository. Use Git LFS or external storage for large assets.",
                        ))
                except OSError:
                    continue

    def _check_shield_policy(self, result: ScanResult) -> None:
        """Validate shield.md policy structure against canonical Shield v0."""
        if not self.enable_shield_scan and not self.require_shield:
            return

        shield_rel_path = ""
        canonical_path = os.path.join(self.repo_path, SHIELD_CANONICAL_FILENAME)
        if os.path.isfile(canonical_path):
            shield_rel_path = SHIELD_CANONICAL_FILENAME
        else:
            for alt_name in SHIELD_ALTERNATE_FILENAMES:
                alt_path = os.path.join(self.repo_path, alt_name)
                if os.path.isfile(alt_path):
                    shield_rel_path = alt_name
                    result.findings.append(PatternMatch(
                        rule_name="shield.md Non-Canonical Filename",
                        severity=Severity.LOW,
                        file_path=alt_name,
                        line_number=0,
                        line_content="",
                        description=f"Use canonical filename '{SHIELD_CANONICAL_FILENAME}' instead of '{alt_name}'",
                        finding_id=generate_finding_id("shield.md Non-Canonical Filename", alt_name, 0, alt_name),
                    ))
                    break

        if not shield_rel_path:
            if self.require_shield:
                result.findings.append(PatternMatch(
                    rule_name="Missing shield.md",
                    severity=Severity.MEDIUM,
                    file_path=SHIELD_CANONICAL_FILENAME,
                    line_number=0,
                    line_content="",
                    description=f"Expected '{SHIELD_CANONICAL_FILENAME}' at repository root",
                    finding_id=generate_finding_id("Missing shield.md", SHIELD_CANONICAL_FILENAME, 0, ""),
                ))
            return

        shield_path = os.path.join(self.repo_path, shield_rel_path)
        try:
            with open(shield_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            result.findings.append(PatternMatch(
                rule_name="shield.md Read Error",
                severity=Severity.MEDIUM,
                file_path=shield_rel_path,
                line_number=0,
                line_content="",
                description="Unable to read shield.md file",
                finding_id=generate_finding_id("shield.md Read Error", shield_rel_path, 0, ""),
            ))
            return

        frontmatter_match = re.match(r"(?s)\A---\s*\n(.*?)\n---\s*(?:\n|$)", content)
        body = content
        frontmatter: dict[str, str] = {}

        if not frontmatter_match:
            result.findings.append(PatternMatch(
                rule_name="shield.md Frontmatter Missing",
                severity=Severity.MEDIUM,
                file_path=shield_rel_path,
                line_number=1,
                line_content="",
                description="shield.md should start with YAML frontmatter delimited by '---'",
                finding_id=generate_finding_id("shield.md Frontmatter Missing", shield_rel_path, 1, ""),
            ))
        else:
            body = content[frontmatter_match.end():]
            frontmatter_text = frontmatter_match.group(1)
            try:
                parsed_frontmatter = yaml.safe_load(frontmatter_text) or {}
                if isinstance(parsed_frontmatter, dict):
                    frontmatter = parsed_frontmatter
                else:
                    result.findings.append(PatternMatch(
                        rule_name="shield.md Frontmatter Invalid",
                        severity=Severity.MEDIUM,
                        file_path=shield_rel_path,
                        line_number=1,
                        line_content="",
                        description="shield.md frontmatter must be a YAML mapping",
                        finding_id=generate_finding_id("shield.md Frontmatter Invalid", shield_rel_path, 1, "not-mapping"),
                    ))
            except yaml.YAMLError:
                result.findings.append(PatternMatch(
                    rule_name="shield.md Frontmatter Invalid",
                    severity=Severity.MEDIUM,
                    file_path=shield_rel_path,
                    line_number=1,
                    line_content="",
                    description="shield.md frontmatter YAML is invalid",
                    finding_id=generate_finding_id("shield.md Frontmatter Invalid", shield_rel_path, 1, "yaml-parse-error"),
                ))

        if frontmatter:
            missing_keys = [k for k in SHIELD_REQUIRED_FRONTMATTER_KEYS if k not in frontmatter]
            if missing_keys:
                result.findings.append(PatternMatch(
                    rule_name="shield.md Frontmatter Missing Keys",
                    severity=Severity.MEDIUM,
                    file_path=shield_rel_path,
                    line_number=1,
                    line_content="",
                    description=f"shield.md frontmatter missing keys: {', '.join(missing_keys)}",
                    finding_id=generate_finding_id(
                        "shield.md Frontmatter Missing Keys",
                        shield_rel_path,
                        1,
                        ",".join(sorted(missing_keys)),
                    ),
                ))

            name_value = str(frontmatter.get("name", "")).strip()
            if name_value and name_value != SHIELD_CANONICAL_FILENAME:
                result.findings.append(PatternMatch(
                    rule_name="shield.md Frontmatter Name Mismatch",
                    severity=Severity.LOW,
                    file_path=shield_rel_path,
                    line_number=1,
                    line_content="",
                    description=f"frontmatter name should be '{SHIELD_CANONICAL_FILENAME}', found '{name_value}'",
                    finding_id=generate_finding_id("shield.md Frontmatter Name Mismatch", shield_rel_path, 1, name_value),
                ))

            version_value = str(frontmatter.get("version", "")).strip().lower().lstrip("v")
            if version_value and version_value != SHIELD_EXPECTED_VERSION:
                result.findings.append(PatternMatch(
                    rule_name="shield.md Version Mismatch",
                    severity=Severity.LOW,
                    file_path=shield_rel_path,
                    line_number=1,
                    line_content="",
                    description=f"Expected shield.md version '{SHIELD_EXPECTED_VERSION}', found '{frontmatter.get('version')}'",
                    finding_id=generate_finding_id("shield.md Version Mismatch", shield_rel_path, 1, str(frontmatter.get("version"))),
                ))

        section_matches = list(re.finditer(r"(?m)^\s*##\s+(.+?)\s*$", body))
        normalized_sections = {
            self._normalize_heading_name(match.group(1)): match.group(1).strip()
            for match in section_matches
        }
        missing_sections = [
            section for section in SHIELD_REQUIRED_SECTIONS
            if self._normalize_heading_name(section) not in normalized_sections
        ]
        if missing_sections:
            result.findings.append(PatternMatch(
                rule_name="shield.md Missing Sections",
                severity=Severity.MEDIUM,
                file_path=shield_rel_path,
                line_number=0,
                line_content="",
                description=f"Missing required sections: {', '.join(missing_sections[:6])}{'...' if len(missing_sections) > 6 else ''}",
                finding_id=generate_finding_id(
                    "shield.md Missing Sections",
                    shield_rel_path,
                    0,
                    ",".join(sorted(missing_sections)),
                ),
            ))

        sections = self._extract_sections(body)

        threat_categories_text = sections.get(self._normalize_heading_name("Threat categories"), "")
        missing_categories = [
            category for category in SHIELD_REQUIRED_CATEGORIES
            if not re.search(rf"(?m)^\s*-\s*{re.escape(category)}\s*$", threat_categories_text)
        ]
        if missing_categories:
            result.findings.append(PatternMatch(
                rule_name="shield.md Missing Threat Categories",
                severity=Severity.MEDIUM,
                file_path=shield_rel_path,
                line_number=0,
                line_content="",
                description=f"Threat categories section missing: {', '.join(missing_categories[:6])}{'...' if len(missing_categories) > 6 else ''}",
                finding_id=generate_finding_id(
                    "shield.md Missing Threat Categories",
                    shield_rel_path,
                    0,
                    ",".join(sorted(missing_categories)),
                ),
            ))

        enforcement_states_text = sections.get(self._normalize_heading_name("Enforcement states"), "")
        missing_actions = [
            action for action in SHIELD_REQUIRED_ACTIONS
            if not re.search(rf"(?m)^\s*-\s*{re.escape(action)}\s*$", enforcement_states_text)
        ]
        if missing_actions:
            result.findings.append(PatternMatch(
                rule_name="shield.md Missing Enforcement Actions",
                severity=Severity.MEDIUM,
                file_path=shield_rel_path,
                line_number=0,
                line_content="",
                description=f"Enforcement states section missing actions: {', '.join(missing_actions)}",
                finding_id=generate_finding_id(
                    "shield.md Missing Enforcement Actions",
                    shield_rel_path,
                    0,
                    ",".join(sorted(missing_actions)),
                ),
            ))

        decision_requirement_text = sections.get(self._normalize_heading_name("Decision requirement"), "")
        missing_decision_fields = [
            field for field in SHIELD_REQUIRED_DECISION_FIELDS
            if not re.search(rf"(?im)^\s*{re.escape(field)}\s*:", decision_requirement_text)
        ]
        if missing_decision_fields:
            result.findings.append(PatternMatch(
                rule_name="shield.md Decision Fields Missing",
                severity=Severity.MEDIUM,
                file_path=shield_rel_path,
                line_number=0,
                line_content="",
                description=f"Decision block missing fields: {', '.join(missing_decision_fields)}",
                finding_id=generate_finding_id(
                    "shield.md Decision Fields Missing",
                    shield_rel_path,
                    0,
                    ",".join(sorted(missing_decision_fields)),
                ),
            ))

    @staticmethod
    def _normalize_heading_name(heading: str) -> str:
        return re.sub(r"\s+", " ", heading.strip().lower())

    def _extract_sections(self, markdown: str) -> dict[str, str]:
        """Extract level-2 markdown sections keyed by normalized heading."""
        sections: dict[str, str] = {}
        matches = list(re.finditer(r"(?m)^\s*##\s+(.+?)\s*$", markdown))
        for idx, match in enumerate(matches):
            heading = self._normalize_heading_name(match.group(1))
            start = match.end()
            end = matches[idx + 1].start() if idx + 1 < len(matches) else len(markdown)
            sections[heading] = markdown[start:end].strip()
        return sections


def run_scan(
    repo_path: str,
    exclude_paths: list[str] | None = None,
    exclude_extensions: list[str] | None = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    enable_entropy: bool = False,
    entropy_threshold: float = 4.5,
    ignore_file: str | None = None,
    no_ignore: bool = False,
    enable_shield_scan: bool = False,
    require_shield: bool = False,
) -> ScanResult:
    """Convenience function to run a scan and return results."""
    scanner = Scanner(
        repo_path=repo_path,
        exclude_paths=exclude_paths,
        exclude_extensions=exclude_extensions,
        max_file_size=max_file_size,
        enable_entropy=enable_entropy,
        entropy_threshold=entropy_threshold,
        ignore_file=ignore_file,
        no_ignore=no_ignore,
        enable_shield_scan=enable_shield_scan,
        require_shield=require_shield,
    )
    return scanner.scan()
