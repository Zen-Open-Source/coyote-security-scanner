"""Finding suppression for Coyote.

Allows users to suppress specific findings by:
- Finding ID (e.g., a1b2c3d4)
- Rule name (e.g., rule:Generic Secret)
- File path (e.g., file:tests/fixtures/)

Suppression rules are defined in a .coyote-ignore file.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import TextIO

from .patterns import PatternMatch


# Default ignore file name
DEFAULT_IGNORE_FILE = ".coyote-ignore"


@dataclass
class SuppressionRule:
    """A single suppression rule."""

    rule_type: str  # "id", "rule", "file", "pattern"
    value: str
    comment: str = ""
    line_number: int = 0

    def matches(self, finding: PatternMatch) -> bool:
        """Check if this rule matches a finding."""
        if self.rule_type == "id":
            return finding.finding_id == self.value
        elif self.rule_type == "rule":
            # Case-insensitive rule name match
            return finding.rule_name.lower() == self.value.lower()
        elif self.rule_type == "file":
            # File path prefix match
            return finding.file_path.startswith(self.value)
        elif self.rule_type == "pattern":
            # Regex pattern match on file path
            try:
                return bool(re.search(self.value, finding.file_path))
            except re.error:
                return False
        return False


@dataclass
class SuppressionConfig:
    """Configuration for finding suppression."""

    rules: list[SuppressionRule] = field(default_factory=list)
    source_file: str = ""

    # Stats
    findings_suppressed: int = 0
    suppression_counts: dict[str, int] = field(default_factory=dict)  # rule -> count

    def add_rule(self, rule: SuppressionRule) -> None:
        """Add a suppression rule."""
        self.rules.append(rule)

    def should_suppress(self, finding: PatternMatch) -> tuple[bool, SuppressionRule | None]:
        """
        Check if a finding should be suppressed.

        Returns:
            Tuple of (should_suppress, matching_rule)
        """
        for rule in self.rules:
            if rule.matches(finding):
                return True, rule
        return False, None

    def filter_findings(self, findings: list[PatternMatch]) -> list[PatternMatch]:
        """
        Filter a list of findings, removing suppressed ones.

        Updates internal stats for reporting.

        Returns:
            List of non-suppressed findings
        """
        filtered = []
        self.findings_suppressed = 0
        self.suppression_counts = {}

        for finding in findings:
            should_suppress, rule = self.should_suppress(finding)
            if should_suppress and rule:
                self.findings_suppressed += 1
                # Track which rules are suppressing findings
                rule_key = f"{rule.rule_type}:{rule.value}"
                self.suppression_counts[rule_key] = self.suppression_counts.get(rule_key, 0) + 1
            else:
                filtered.append(finding)

        return filtered

    @property
    def total_rules(self) -> int:
        return len(self.rules)

    @property
    def id_rules(self) -> int:
        return sum(1 for r in self.rules if r.rule_type == "id")

    @property
    def rule_rules(self) -> int:
        return sum(1 for r in self.rules if r.rule_type == "rule")

    @property
    def file_rules(self) -> int:
        return sum(1 for r in self.rules if r.rule_type == "file")


def parse_ignore_file(file_path: str) -> SuppressionConfig:
    """
    Parse a .coyote-ignore file.

    File format:
        # Comment lines start with #
        a1b2c3d4                    # Suppress by finding ID
        rule:Generic Secret         # Suppress by rule name
        file:tests/fixtures/        # Suppress by file path prefix
        pattern:test_.*\\.py$       # Suppress by file path regex

    Args:
        file_path: Path to the ignore file

    Returns:
        SuppressionConfig with parsed rules
    """
    config = SuppressionConfig(source_file=file_path)

    if not os.path.isfile(file_path):
        return config

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            _parse_ignore_stream(f, config)
    except (OSError, UnicodeDecodeError):
        pass

    return config


def _parse_ignore_stream(stream: TextIO, config: SuppressionConfig) -> None:
    """Parse an ignore file stream into a config."""
    for line_num, line in enumerate(stream, start=1):
        # Strip whitespace
        line = line.strip()

        # Skip empty lines
        if not line:
            continue

        # Skip comment-only lines
        if line.startswith("#"):
            continue

        # Extract inline comment
        comment = ""
        if "#" in line:
            parts = line.split("#", 1)
            line = parts[0].strip()
            comment = parts[1].strip()

        # Skip if line is now empty
        if not line:
            continue

        # Parse the rule
        rule = _parse_rule_line(line, comment, line_num)
        if rule:
            config.add_rule(rule)


def _parse_rule_line(line: str, comment: str, line_num: int) -> SuppressionRule | None:
    """Parse a single rule line."""
    # Check for prefixed rules
    if line.startswith("rule:"):
        value = line[5:].strip()
        if value:
            return SuppressionRule("rule", value, comment, line_num)

    elif line.startswith("file:"):
        value = line[5:].strip()
        if value:
            return SuppressionRule("file", value, comment, line_num)

    elif line.startswith("pattern:"):
        value = line[8:].strip()
        if value:
            return SuppressionRule("pattern", value, comment, line_num)

    elif line.startswith("id:"):
        # Explicit ID prefix (optional)
        value = line[3:].strip()
        if value:
            return SuppressionRule("id", value, comment, line_num)

    else:
        # Assume it's a finding ID (8 hex chars)
        # Be lenient - accept any alphanumeric string
        if re.match(r'^[a-fA-F0-9]{6,16}$', line):
            return SuppressionRule("id", line.lower(), comment, line_num)

    return None


def load_suppression_config(
    repo_path: str,
    ignore_file: str | None = None,
) -> SuppressionConfig:
    """
    Load suppression config for a repository.

    Args:
        repo_path: Path to the repository root
        ignore_file: Custom ignore file path (or None for default)

    Returns:
        SuppressionConfig (empty if no ignore file found)
    """
    if ignore_file:
        # Use custom path (absolute or relative to cwd)
        if os.path.isabs(ignore_file):
            path = ignore_file
        else:
            path = os.path.join(os.getcwd(), ignore_file)
    else:
        # Look for .coyote-ignore in repo root
        path = os.path.join(repo_path, DEFAULT_IGNORE_FILE)

    return parse_ignore_file(path)


def generate_ignore_entry(finding: PatternMatch, include_context: bool = True) -> str:
    """
    Generate an ignore file entry for a finding.

    Useful for helping users add findings to their ignore file.

    Args:
        finding: The finding to generate an entry for
        include_context: Whether to include a comment with context

    Returns:
        A line suitable for .coyote-ignore
    """
    if include_context:
        context = f"# {finding.rule_name} in {finding.file_path}"
        if finding.line_number > 0:
            context += f":{finding.line_number}"
        return f"{finding.finding_id}  {context}"
    return finding.finding_id


def create_example_ignore_file() -> str:
    """Generate example .coyote-ignore file content."""
    return """# Coyote Ignore File
# Suppress specific findings from Coyote security scans
#
# Format:
#   <finding-id>              Suppress by finding ID (8 hex chars)
#   rule:<rule-name>          Suppress all findings of a rule type
#   file:<path-prefix>        Suppress findings in files matching prefix
#   pattern:<regex>           Suppress findings in files matching regex
#
# Examples:

# Suppress specific findings by ID
# a1b2c3d4  # False positive - test API key

# Suppress all findings of a specific rule
# rule:Generic Secret  # Too noisy for this codebase

# Suppress findings in test directories
# file:tests/fixtures/
# file:test_data/

# Suppress findings in files matching a pattern
# pattern:.*_test\\.py$
# pattern:mock_.*\\.json$

"""
