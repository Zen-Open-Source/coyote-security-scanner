"""Report generation for Coyote scan results (JSON, Markdown, and SARIF)."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from .html_report import generate_html_report
from .patterns import Severity
from .sarif import generate_sarif, sarif_to_json
from .scanner import ScanResult


def _finding_to_dict(f) -> dict:
    return {
        "id": f.finding_id,  # Stable ID for diffing/suppression
        "rule": f.rule_name,
        "severity": f.severity.value,
        "file": f.file_path,
        "line": f.line_number,
        "description": f.description,
        "matched_text": f.matched_text or None,
    }


def generate_json_report(result: ScanResult, commit_hash: str = "") -> str:
    """Generate a JSON-formatted scan report."""
    report = {
        "scanner": "Coyote v1.3.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repo_path": result.repo_path,
        "commit": commit_hash,
        "summary": {
            "total_findings": result.total_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
        },
        "findings": [_finding_to_dict(f) for f in result.findings],
        "errors": result.errors,
    }
    return json.dumps(report, indent=2)


def generate_markdown_report(result: ScanResult, commit_hash: str = "") -> str:
    """Generate a Markdown-formatted scan report."""
    lines = []
    lines.append("# Coyote Security Scan Report")
    lines.append("")
    lines.append(f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"**Repository:** `{result.repo_path}`")
    if commit_hash:
        lines.append(f"**Commit:** `{commit_hash}`")
    lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total Findings | {result.total_count} |")
    lines.append(f"| HIGH | {result.high_count} |")
    lines.append(f"| MEDIUM | {result.medium_count} |")
    lines.append(f"| LOW | {result.low_count} |")
    lines.append(f"| Files Scanned | {result.files_scanned} |")
    lines.append(f"| Files Skipped | {result.files_skipped} |")
    lines.append("")

    if not result.findings:
        lines.append("## Findings")
        lines.append("")
        lines.append("No security issues found. All clear!")
        lines.append("")
        return "\n".join(lines)

    # Group by severity
    for severity in [Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        findings = [f for f in result.findings if f.severity == severity]
        if not findings:
            continue

        icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}[severity.value]
        lines.append(f"## {icon} {severity.value} Findings ({len(findings)})")
        lines.append("")

        for f in findings:
            loc = f"`{f.file_path}"
            if f.line_number > 0:
                loc += f":{f.line_number}"
            loc += "`"
            lines.append(f"- **{f.rule_name}**: {f.description}")
            lines.append(f"  - ID: `{f.finding_id}`")
            lines.append(f"  - Location: {loc}")
            if f.matched_text:
                lines.append(f"  - Match: `{f.matched_text}`")
            lines.append("")

    if result.errors:
        lines.append("## Errors")
        lines.append("")
        for err in result.errors:
            lines.append(f"- {err}")
        lines.append("")

    return "\n".join(lines)


def generate_sarif_report(result: ScanResult) -> str:
    """Generate a SARIF-formatted scan report."""
    sarif = generate_sarif(result)
    return sarif_to_json(sarif)


def save_reports(
    result: ScanResult,
    report_dir: str = "./reports",
    formats: list[str] | None = None,
    commit_hash: str = "",
) -> list[str]:
    """Save scan reports to disk. Returns list of file paths written."""
    if formats is None:
        formats = ["json", "markdown"]

    os.makedirs(report_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    saved = []

    if "json" in formats:
        path = os.path.join(report_dir, f"coyote_report_{timestamp}.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write(generate_json_report(result, commit_hash))
        saved.append(path)

    if "markdown" in formats:
        path = os.path.join(report_dir, f"coyote_report_{timestamp}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(generate_markdown_report(result, commit_hash))
        saved.append(path)

    if "sarif" in formats:
        path = os.path.join(report_dir, f"coyote_report_{timestamp}.sarif")
        with open(path, "w", encoding="utf-8") as f:
            f.write(generate_sarif_report(result))
        saved.append(path)

    if "html" in formats:
        path = os.path.join(report_dir, f"coyote_report_{timestamp}.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(generate_html_report(result, commit_hash))
        saved.append(path)

    return saved
