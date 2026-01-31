"""Git history scanning for Coyote.

Scans git commit history to find secrets that were ever committed,
even if they were later removed. Secrets in git history are still
exposed and should be rotated.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Generator

from .patterns import SECRET_PATTERNS, PatternMatch, Severity, SecretPattern
from .scanner import generate_finding_id


@dataclass
class HistoryFinding:
    """A secret found in git history."""

    # Finding details
    finding_id: str
    rule_name: str
    severity: Severity
    description: str
    matched_text: str

    # Git context
    commit_hash: str
    commit_short: str
    commit_message: str
    commit_author: str
    commit_date: str

    # File context
    file_path: str
    line_content: str

    @property
    def is_high_severity(self) -> bool:
        return self.severity == Severity.HIGH


@dataclass
class HistoryScanResult:
    """Result of scanning git history."""

    findings: list[HistoryFinding] = field(default_factory=list)
    commits_scanned: int = 0
    repo_path: str = ""
    branch: str = ""
    scan_depth: int = 0  # How many commits back we scanned

    @property
    def total_count(self) -> int:
        return len(self.findings)

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
    def unique_commits(self) -> int:
        """Number of unique commits with findings."""
        return len(set(f.commit_hash for f in self.findings))

    def findings_by_commit(self) -> dict[str, list[HistoryFinding]]:
        """Group findings by commit hash."""
        by_commit: dict[str, list[HistoryFinding]] = {}
        for f in self.findings:
            if f.commit_hash not in by_commit:
                by_commit[f.commit_hash] = []
            by_commit[f.commit_hash].append(f)
        return by_commit


def _parse_git_log_output(output: str) -> Generator[dict, None, None]:
    """
    Parse git log -p output into commit chunks.

    Yields dicts with commit metadata and diff content.
    """
    # Split by commit boundaries
    commit_pattern = re.compile(r'^commit ([a-f0-9]{40})$', re.MULTILINE)

    commits = commit_pattern.split(output)
    # commits[0] is empty, then alternating: hash, content, hash, content...

    i = 1
    while i < len(commits) - 1:
        commit_hash = commits[i]
        content = commits[i + 1]
        i += 2

        # Parse commit metadata
        lines = content.strip().split('\n')
        author = ""
        date = ""
        message = ""
        diff_start = len(lines)  # Default to end if no diff found

        # Find metadata and diff start
        in_headers = True
        for idx, line in enumerate(lines):
            if in_headers:
                if line.startswith('Author:'):
                    author = line[7:].strip()
                elif line.startswith('Date:'):
                    date = line[5:].strip()
                elif line.strip() == '':
                    in_headers = False
            elif line.startswith('diff --git'):
                diff_start = idx
                break
            elif not message and line.strip():
                # First non-empty line after headers is the commit message
                message = line.strip()

        # Extract diff content
        diff_content = '\n'.join(lines[diff_start:]) if diff_start < len(lines) else ""

        yield {
            'hash': commit_hash,
            'short': commit_hash[:7],
            'author': author,
            'date': date,
            'message': message[:100] if message else "(no message)",
            'diff': diff_content,
        }


def _parse_diff_hunks(diff: str) -> Generator[tuple[str, str], None, None]:
    """
    Parse diff content and yield (file_path, added_line) tuples.

    Only yields lines that were added (start with +, but not +++).
    """
    current_file = ""

    for line in diff.split('\n'):
        # Track current file from diff headers
        if line.startswith('diff --git'):
            # Extract file path: diff --git a/path b/path
            match = re.search(r'b/(.+)$', line)
            if match:
                current_file = match.group(1)
        elif line.startswith('+++'):
            # Alternative way to get file path
            if line.startswith('+++ b/'):
                current_file = line[6:]
            elif line.startswith('+++ '):
                current_file = line[4:]
        elif line.startswith('+') and not line.startswith('+++'):
            # This is an added line
            added_content = line[1:]  # Remove the leading +
            if current_file and added_content.strip():
                yield (current_file, added_content)


def _should_skip_file(file_path: str) -> bool:
    """Check if a file should be skipped during history scanning."""
    skip_patterns = [
        r'\.min\.js$',
        r'\.min\.css$',
        r'\.map$',
        r'package-lock\.json$',
        r'yarn\.lock$',
        r'Gemfile\.lock$',
        r'poetry\.lock$',
        r'\.png$', r'\.jpg$', r'\.jpeg$', r'\.gif$', r'\.ico$',
        r'\.woff$', r'\.woff2$', r'\.ttf$', r'\.eot$',
        r'\.pdf$', r'\.zip$', r'\.tar$', r'\.gz$',
    ]

    for pattern in skip_patterns:
        if re.search(pattern, file_path, re.IGNORECASE):
            return True
    return False


def scan_history(
    repo_path: str,
    branch: str = "HEAD",
    max_commits: int = 100,
    patterns: list[SecretPattern] | None = None,
    exclude_paths: list[str] | None = None,
) -> HistoryScanResult:
    """
    Scan git history for secrets.

    Args:
        repo_path: Path to the git repository
        branch: Branch or ref to scan (default: HEAD)
        max_commits: Maximum number of commits to scan
        patterns: Security patterns to use (default: SECRET_PATTERNS)
        exclude_paths: Path prefixes to exclude

    Returns:
        HistoryScanResult with all findings
    """
    patterns = patterns or SECRET_PATTERNS
    exclude_paths = exclude_paths or []

    result = HistoryScanResult(
        repo_path=repo_path,
        branch=branch,
        scan_depth=max_commits,
    )

    # Get git log with patches
    try:
        cmd = [
            "git", "-C", repo_path,
            "log", "-p",
            f"-{max_commits}",
            "--no-merges",  # Skip merge commits (no new code)
            branch,
        ]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout for large repos
        )

        if proc.returncode != 0:
            # Git command failed
            return result

        log_output = proc.stdout

    except subprocess.TimeoutExpired:
        # Timeout - return partial results
        return result
    except Exception:
        return result

    # Track seen finding IDs to avoid duplicates
    seen_findings: set[str] = set()

    # Process each commit
    for commit in _parse_git_log_output(log_output):
        result.commits_scanned += 1

        if not commit['diff']:
            continue

        # Scan added lines in the diff
        for file_path, line_content in _parse_diff_hunks(commit['diff']):
            # Skip excluded paths
            skip = False
            for exclude in exclude_paths:
                if file_path.startswith(exclude.rstrip('/')):
                    skip = True
                    break

            if skip or _should_skip_file(file_path):
                continue

            # Check each pattern
            for pattern in patterns:
                match = pattern.pattern.search(line_content)
                if match:
                    matched_text = match.group(0)

                    # Generate finding ID (includes commit for uniqueness)
                    finding_id = generate_finding_id(
                        pattern.name,
                        f"{commit['short']}:{file_path}",
                        0,  # No line number in diff context
                        matched_text,
                    )

                    # Skip if we've seen this exact finding
                    if finding_id in seen_findings:
                        continue
                    seen_findings.add(finding_id)

                    finding = HistoryFinding(
                        finding_id=finding_id,
                        rule_name=pattern.name,
                        severity=pattern.severity,
                        description=pattern.description,
                        matched_text=matched_text[:50] + "..." if len(matched_text) > 50 else matched_text,
                        commit_hash=commit['hash'],
                        commit_short=commit['short'],
                        commit_message=commit['message'],
                        commit_author=commit['author'],
                        commit_date=commit['date'],
                        file_path=file_path,
                        line_content=line_content[:200] if len(line_content) > 200 else line_content,
                    )
                    result.findings.append(finding)

    return result


def format_history_report(result: HistoryScanResult) -> str:
    """Generate a human-readable report of history scan findings."""
    lines = []

    lines.append("=" * 60)
    lines.append("GIT HISTORY SCAN REPORT")
    lines.append("=" * 60)
    lines.append(f"Repository: {result.repo_path}")
    lines.append(f"Branch: {result.branch}")
    lines.append(f"Commits scanned: {result.commits_scanned}")
    lines.append("")

    if result.total_count == 0:
        lines.append("No secrets found in git history.")
        lines.append("=" * 60)
        return "\n".join(lines)

    lines.append(f"FINDINGS: {result.total_count} secrets in {result.unique_commits} commits")
    lines.append(f"  HIGH:   {result.high_count}")
    lines.append(f"  MEDIUM: {result.medium_count}")
    lines.append(f"  LOW:    {result.low_count}")
    lines.append("")

    # Group by commit
    by_commit = result.findings_by_commit()

    for commit_hash, findings in by_commit.items():
        first = findings[0]
        lines.append("-" * 60)
        lines.append(f"Commit: {first.commit_short} - {first.commit_message}")
        lines.append(f"Author: {first.commit_author}")
        lines.append(f"Date:   {first.commit_date}")
        lines.append("")

        for f in findings:
            lines.append(f"  [{f.severity.value}] {f.rule_name}")
            lines.append(f"    File: {f.file_path}")
            lines.append(f"    ID:   {f.finding_id}")
            # Don't show actual secret content for security
            lines.append("")

    lines.append("=" * 60)
    lines.append("")
    lines.append("WARNING: These secrets were committed to git history.")
    lines.append("Even if removed, they may still be exposed. Consider:")
    lines.append("  1. Rotating/revoking the exposed credentials")
    lines.append("  2. Using git-filter-repo to rewrite history (advanced)")
    lines.append("  3. If the repo is public, assume the secrets are compromised")
    lines.append("")

    return "\n".join(lines)
