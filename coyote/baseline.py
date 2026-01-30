"""Baseline management and scan diffing for Coyote.

This module enables comparing scans over time by:
1. Saving scan results as a baseline
2. Loading previous baselines
3. Diffing current scan against baseline to find new/fixed/existing findings
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .patterns import PatternMatch, Severity
from .scanner import ScanResult


# Default baseline file location
DEFAULT_BASELINE_PATH = ".coyote-baseline.json"


@dataclass
class DiffResult:
    """Result of comparing current scan against a baseline."""

    # Findings that exist in current scan but not in baseline
    new_findings: list[PatternMatch] = field(default_factory=list)

    # Findings that existed in baseline but not in current scan (resolved)
    fixed_findings: list[PatternMatch] = field(default_factory=list)

    # Findings that exist in both baseline and current scan
    existing_findings: list[PatternMatch] = field(default_factory=list)

    # Metadata
    baseline_timestamp: str = ""
    baseline_commit: str = ""
    current_commit: str = ""

    @property
    def new_count(self) -> int:
        return len(self.new_findings)

    @property
    def fixed_count(self) -> int:
        return len(self.fixed_findings)

    @property
    def existing_count(self) -> int:
        return len(self.existing_findings)

    @property
    def has_new_findings(self) -> bool:
        return self.new_count > 0

    @property
    def new_high_count(self) -> int:
        return sum(1 for f in self.new_findings if f.severity == Severity.HIGH)

    @property
    def new_medium_count(self) -> int:
        return sum(1 for f in self.new_findings if f.severity == Severity.MEDIUM)

    @property
    def new_low_count(self) -> int:
        return sum(1 for f in self.new_findings if f.severity == Severity.LOW)


def _finding_to_baseline_dict(f: PatternMatch) -> dict[str, Any]:
    """Convert a PatternMatch to a dict for baseline storage."""
    return {
        "finding_id": f.finding_id,
        "rule_name": f.rule_name,
        "severity": f.severity.value,
        "file_path": f.file_path,
        "line_number": f.line_number,
        "line_content": f.line_content,
        "description": f.description,
        "matched_text": f.matched_text,
    }


def _baseline_dict_to_finding(d: dict[str, Any]) -> PatternMatch:
    """Convert a baseline dict back to a PatternMatch."""
    return PatternMatch(
        finding_id=d.get("finding_id", ""),
        rule_name=d["rule_name"],
        severity=Severity(d["severity"]),
        file_path=d["file_path"],
        line_number=d["line_number"],
        line_content=d.get("line_content", ""),
        description=d["description"],
        matched_text=d.get("matched_text", ""),
    )


def save_baseline(
    result: ScanResult,
    path: str = DEFAULT_BASELINE_PATH,
    commit_hash: str = "",
) -> str:
    """
    Save a scan result as a baseline for future comparisons.

    Args:
        result: The scan result to save as baseline
        path: Path to save the baseline file
        commit_hash: Optional git commit hash to associate with baseline

    Returns:
        The path where the baseline was saved
    """
    baseline = {
        "version": "0.3",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "commit": commit_hash,
        "repo_path": result.repo_path,
        "summary": {
            "total": result.total_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
            "files_scanned": result.files_scanned,
        },
        "findings": [_finding_to_baseline_dict(f) for f in result.findings],
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2)

    return path


def load_baseline(path: str = DEFAULT_BASELINE_PATH) -> tuple[list[PatternMatch], dict[str, Any]]:
    """
    Load a baseline from disk.

    Args:
        path: Path to the baseline file

    Returns:
        Tuple of (list of findings, metadata dict)

    Raises:
        FileNotFoundError: If baseline file doesn't exist
        json.JSONDecodeError: If baseline file is invalid
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = [_baseline_dict_to_finding(d) for d in data.get("findings", [])]

    metadata = {
        "version": data.get("version", "unknown"),
        "timestamp": data.get("timestamp", ""),
        "commit": data.get("commit", ""),
        "repo_path": data.get("repo_path", ""),
        "summary": data.get("summary", {}),
    }

    return findings, metadata


def baseline_exists(path: str = DEFAULT_BASELINE_PATH) -> bool:
    """Check if a baseline file exists."""
    return os.path.isfile(path)


def diff_scans(
    current_result: ScanResult,
    baseline_path: str = DEFAULT_BASELINE_PATH,
    current_commit: str = "",
) -> DiffResult:
    """
    Compare current scan results against a saved baseline.

    Uses finding_id to match findings between scans. This means:
    - Same finding_id = same issue (existing)
    - finding_id in current but not baseline = new issue
    - finding_id in baseline but not current = fixed issue

    Args:
        current_result: The current scan result to compare
        baseline_path: Path to the baseline file
        current_commit: Optional current git commit hash

    Returns:
        DiffResult with categorized findings

    Raises:
        FileNotFoundError: If baseline doesn't exist
    """
    baseline_findings, metadata = load_baseline(baseline_path)

    # Build sets of finding IDs for fast lookup
    baseline_ids = {f.finding_id for f in baseline_findings}
    current_ids = {f.finding_id for f in current_result.findings}

    # Categorize findings
    new_ids = current_ids - baseline_ids
    fixed_ids = baseline_ids - current_ids
    existing_ids = current_ids & baseline_ids

    # Build finding lists
    new_findings = [f for f in current_result.findings if f.finding_id in new_ids]
    fixed_findings = [f for f in baseline_findings if f.finding_id in fixed_ids]
    existing_findings = [f for f in current_result.findings if f.finding_id in existing_ids]

    return DiffResult(
        new_findings=new_findings,
        fixed_findings=fixed_findings,
        existing_findings=existing_findings,
        baseline_timestamp=metadata.get("timestamp", ""),
        baseline_commit=metadata.get("commit", ""),
        current_commit=current_commit,
    )


def generate_diff_summary(diff: DiffResult) -> str:
    """Generate a human-readable summary of the diff."""
    lines = []

    # Header
    lines.append("=" * 50)
    lines.append("SCAN DIFF SUMMARY")
    lines.append("=" * 50)

    if diff.baseline_commit or diff.current_commit:
        if diff.baseline_commit:
            lines.append(f"Baseline: {diff.baseline_commit}")
        if diff.current_commit:
            lines.append(f"Current:  {diff.current_commit}")
        lines.append("")

    # Summary counts
    lines.append(f"New findings:      {diff.new_count:3d}  {'⚠️  ACTION REQUIRED' if diff.new_count > 0 else '✓'}")
    lines.append(f"Fixed findings:    {diff.fixed_count:3d}  {'🎉' if diff.fixed_count > 0 else ''}")
    lines.append(f"Existing findings: {diff.existing_count:3d}")
    lines.append("")

    # New findings breakdown
    if diff.new_count > 0:
        lines.append(f"New findings by severity:")
        lines.append(f"  HIGH:   {diff.new_high_count}")
        lines.append(f"  MEDIUM: {diff.new_medium_count}")
        lines.append(f"  LOW:    {diff.new_low_count}")
        lines.append("")

    # List new findings
    if diff.new_findings:
        lines.append("-" * 50)
        lines.append("NEW FINDINGS:")
        lines.append("-" * 50)
        for f in diff.new_findings:
            loc = f.file_path
            if f.line_number > 0:
                loc += f":{f.line_number}"
            lines.append(f"  [{f.severity.value}] {f.rule_name}")
            lines.append(f"    {loc}")
            lines.append(f"    ID: {f.finding_id}")
            lines.append("")

    # List fixed findings
    if diff.fixed_findings:
        lines.append("-" * 50)
        lines.append("FIXED FINDINGS:")
        lines.append("-" * 50)
        for f in diff.fixed_findings:
            loc = f.file_path
            if f.line_number > 0:
                loc += f":{f.line_number}"
            lines.append(f"  [{f.severity.value}] {f.rule_name}")
            lines.append(f"    {loc}")
            lines.append(f"    ID: {f.finding_id}")
            lines.append("")

    lines.append("=" * 50)

    return "\n".join(lines)
