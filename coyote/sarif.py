"""SARIF (Static Analysis Results Interchange Format) output for Coyote.

SARIF is a standard JSON format for static analysis tools, supported by:
- GitHub Code Scanning
- VS Code SARIF Viewer
- Azure DevOps
- Many other security tools

Specification: https://sarifweb.azurewebsites.net/
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .patterns import Severity, PatternMatch
from .scanner import ScanResult


# SARIF schema version
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def _severity_to_sarif_level(severity: Severity) -> str:
    """Map Coyote severity to SARIF level."""
    mapping = {
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
    }
    return mapping.get(severity, "note")


def _severity_to_sarif_rank(severity: Severity) -> float:
    """Map Coyote severity to SARIF security-severity rank (0-10)."""
    mapping = {
        Severity.HIGH: 9.0,
        Severity.MEDIUM: 6.0,
        Severity.LOW: 3.0,
    }
    return mapping.get(severity, 1.0)


def _get_rule_id(finding: PatternMatch) -> str:
    """Generate a stable rule ID from a finding."""
    # Normalize rule name to a valid ID (alphanumeric + hyphens)
    rule_name = finding.rule_name.lower()
    rule_id = "".join(c if c.isalnum() else "-" for c in rule_name)
    # Remove consecutive hyphens and trim
    while "--" in rule_id:
        rule_id = rule_id.replace("--", "-")
    return f"coyote/{rule_id.strip('-')}"


def _build_rule_definition(finding: PatternMatch) -> dict[str, Any]:
    """Build a SARIF rule definition from a finding."""
    rule_id = _get_rule_id(finding)
    severity = finding.severity

    return {
        "id": rule_id,
        "name": finding.rule_name,
        "shortDescription": {
            "text": finding.rule_name,
        },
        "fullDescription": {
            "text": finding.description,
        },
        "help": {
            "text": f"{finding.description}\n\nThis finding was detected by Coyote security scanner.",
            "markdown": f"**{finding.rule_name}**\n\n{finding.description}\n\n"
                       f"Detected by [Coyote](https://github.com/anthropics/coyote) security scanner.",
        },
        "defaultConfiguration": {
            "level": _severity_to_sarif_level(severity),
        },
        "properties": {
            "security-severity": str(_severity_to_sarif_rank(severity)),
            "tags": ["security", "secrets"] if severity == Severity.HIGH else ["security"],
        },
    }


def _build_result(finding: PatternMatch, repo_path: str) -> dict[str, Any]:
    """Build a SARIF result from a finding."""
    rule_id = _get_rule_id(finding)

    # Build the location
    # SARIF uses 1-based line numbers (same as Coyote)
    artifact_location = {
        "uri": finding.file_path,
        "uriBaseId": "%SRCROOT%",
    }

    physical_location: dict[str, Any] = {
        "artifactLocation": artifact_location,
    }

    # Add region if we have line number
    if finding.line_number > 0:
        physical_location["region"] = {
            "startLine": finding.line_number,
            "startColumn": 1,
        }
        # If we have line content, we can add snippet
        if finding.line_content:
            physical_location["region"]["snippet"] = {
                "text": finding.line_content[:500],  # Limit snippet length
            }

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": 0,  # Will be updated later
        "level": _severity_to_sarif_level(finding.severity),
        "message": {
            "text": finding.description,
        },
        "locations": [
            {
                "physicalLocation": physical_location,
            }
        ],
        "fingerprints": {
            "coyoteFindingId": finding.finding_id,
        },
        "partialFingerprints": {
            "primaryLocationLineHash": finding.finding_id,
        },
    }

    # Add matched text as a property (but masked for security)
    if finding.matched_text:
        result["properties"] = {
            "matchedText": finding.matched_text,
        }

    return result


def generate_sarif(
    result: ScanResult,
    include_suppressed: bool = False,
) -> dict[str, Any]:
    """
    Generate SARIF output from a scan result.

    Args:
        result: The scan result to convert
        include_suppressed: Whether to include suppressed findings

    Returns:
        SARIF document as a dictionary
    """
    # Collect unique rules
    rules_map: dict[str, dict[str, Any]] = {}
    rule_indices: dict[str, int] = {}

    for finding in result.findings:
        rule_id = _get_rule_id(finding)
        if rule_id not in rules_map:
            rules_map[rule_id] = _build_rule_definition(finding)
            rule_indices[rule_id] = len(rules_map) - 1

    # Build results
    sarif_results = []
    for finding in result.findings:
        sarif_result = _build_result(finding, result.repo_path)
        # Update rule index
        rule_id = _get_rule_id(finding)
        sarif_result["ruleIndex"] = rule_indices.get(rule_id, 0)
        sarif_results.append(sarif_result)

    # Build the SARIF document
    sarif: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Coyote",
                        "fullName": "Coyote Security Scanner",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/anthropics/coyote",
                        "rules": list(rules_map.values()),
                        "properties": {
                            "tags": ["security", "secrets", "credentials"],
                        },
                    },
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
                "originalUriBaseIds": {
                    "%SRCROOT%": {
                        "uri": f"file://{os.path.abspath(result.repo_path)}/",
                        "description": {
                            "text": "The root directory of the scanned repository.",
                        },
                    },
                },
                "properties": {
                    "filesScanned": result.files_scanned,
                    "filesSkipped": result.files_skipped,
                    "findingsSuppressed": result.findings_suppressed,
                },
            }
        ],
    }

    return sarif


def sarif_to_json(sarif: dict[str, Any], indent: int = 2) -> str:
    """Convert SARIF dict to JSON string."""
    return json.dumps(sarif, indent=indent, ensure_ascii=False)


def save_sarif(
    result: ScanResult,
    output_path: str,
    include_suppressed: bool = False,
) -> str:
    """
    Save scan results as a SARIF file.

    Args:
        result: The scan result to save
        output_path: Path to save the SARIF file
        include_suppressed: Whether to include suppressed findings

    Returns:
        The path where the file was saved
    """
    sarif = generate_sarif(result, include_suppressed)
    sarif_json = sarif_to_json(sarif)

    # Ensure directory exists
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(sarif_json)

    return output_path


def generate_sarif_summary(sarif: dict[str, Any]) -> str:
    """Generate a human-readable summary of SARIF results."""
    lines = []

    for run in sarif.get("runs", []):
        tool = run.get("tool", {}).get("driver", {})
        results = run.get("results", [])

        lines.append(f"Tool: {tool.get('name', 'Unknown')} v{tool.get('version', '?')}")
        lines.append(f"Results: {len(results)} findings")

        # Count by level
        by_level = {"error": 0, "warning": 0, "note": 0}
        for r in results:
            level = r.get("level", "note")
            by_level[level] = by_level.get(level, 0) + 1

        lines.append(f"  Errors:   {by_level['error']}")
        lines.append(f"  Warnings: {by_level['warning']}")
        lines.append(f"  Notes:    {by_level['note']}")

    return "\n".join(lines)
