"""
Moltbot Agent Security - User-Facing Output

Generates human-readable safety summaries, diff reports, and warnings.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from .models import (
    CapabilityCategory,
    CapabilityDiff,
    CapabilityManifest,
    RiskLevel,
)


# =============================================================================
# Icons and Labels
# =============================================================================

RISK_ICONS = {
    RiskLevel.NONE: "",
    RiskLevel.LOW: "",
    RiskLevel.MEDIUM: "",
    RiskLevel.HIGH: "",
    RiskLevel.CRITICAL: "",
}

RISK_COLORS = {
    RiskLevel.NONE: "green",
    RiskLevel.LOW: "blue",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.HIGH: "red",
    RiskLevel.CRITICAL: "red bold",
}

CATEGORY_LABELS = {
    CapabilityCategory.FILE_READ: "Read Files",
    CapabilityCategory.FILE_WRITE: "Write Files",
    CapabilityCategory.NETWORK_OUTBOUND: "Network (Outbound)",
    CapabilityCategory.NETWORK_INBOUND: "Network (Inbound)",
    CapabilityCategory.PROCESS_SPAWN: "Run Commands",
    CapabilityCategory.SECRET_ACCESS: "Access Secrets",
    CapabilityCategory.TOOL_INVOCATION: "Use Tools",
    CapabilityCategory.SELF_MODIFICATION: "Self-Modify",
    CapabilityCategory.AGENT_SPAWNING: "Spawn Agents",
    CapabilityCategory.CODE_EXECUTION: "Execute Code",
    CapabilityCategory.BROWSER_ACCESS: "Browser Access",
    CapabilityCategory.CLIPBOARD_ACCESS: "Clipboard Access",
    CapabilityCategory.SYSTEM_INFO: "System Info",
}

CATEGORY_ICONS = {
    CapabilityCategory.FILE_READ: "",
    CapabilityCategory.FILE_WRITE: "",
    CapabilityCategory.NETWORK_OUTBOUND: "",
    CapabilityCategory.NETWORK_INBOUND: "",
    CapabilityCategory.PROCESS_SPAWN: "",
    CapabilityCategory.SECRET_ACCESS: "",
    CapabilityCategory.TOOL_INVOCATION: "",
    CapabilityCategory.SELF_MODIFICATION: "",
    CapabilityCategory.AGENT_SPAWNING: "",
    CapabilityCategory.CODE_EXECUTION: "",
    CapabilityCategory.BROWSER_ACCESS: "",
    CapabilityCategory.CLIPBOARD_ACCESS: "",
    CapabilityCategory.SYSTEM_INFO: "",
}


# =============================================================================
# Safety Summary Generator
# =============================================================================

class SafetySummaryGenerator:
    """
    Generates user-friendly safety summaries from capability manifests.
    """

    def generate_text_summary(self, manifest: CapabilityManifest) -> str:
        """Generate a plain text safety summary."""
        lines = []

        # Header
        lines.append("=" * 60)
        lines.append("AGENT SAFETY SUMMARY")
        lines.append("=" * 60)
        lines.append("")

        # Agent info
        lines.append(f"Agent: {manifest.metadata.name}")
        lines.append(f"Version: {manifest.metadata.version}")
        lines.append(f"Author: {manifest.metadata.author}")
        if manifest.metadata.source_url:
            lines.append(f"Source: {manifest.metadata.source_url}")
        lines.append("")

        # Risk summary
        max_risk = manifest.max_risk_level
        risk_icon = RISK_ICONS.get(max_risk, "")
        lines.append(f"Overall Risk: {risk_icon} {max_risk.value.upper()}")
        lines.append("")

        # Capability counts by risk
        by_risk = manifest.capabilities_by_risk()
        lines.append("Capabilities by Risk Level:")
        for risk in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
            count = len(by_risk.get(risk, []))
            if count > 0:
                lines.append(f"  {RISK_ICONS.get(risk, '')} {risk.value.upper()}: {count}")
        lines.append("")

        # High-risk capabilities (detailed)
        high_risk_caps = by_risk.get(RiskLevel.CRITICAL, []) + by_risk.get(RiskLevel.HIGH, [])
        if high_risk_caps:
            lines.append("HIGH-RISK CAPABILITIES:")
            lines.append("-" * 40)
            for cap in high_risk_caps:
                icon = CATEGORY_ICONS.get(cap.category, "")
                label = CATEGORY_LABELS.get(cap.category, cap.category.value)
                lines.append(f"  {icon} {label}")
                lines.append(f"     Scope: {cap.scope}")
                lines.append(f"     Why risky: {cap.risk_reason}")
                lines.append("")

        # Warnings
        if manifest.analysis_warnings:
            lines.append("WARNINGS:")
            lines.append("-" * 40)
            for warning in manifest.analysis_warnings:
                lines.append(f"  {warning}")
            lines.append("")

        # Summary by category
        lines.append("CAPABILITIES BY CATEGORY:")
        lines.append("-" * 40)
        by_category = manifest.capabilities_by_category()
        for category, caps in sorted(by_category.items(), key=lambda x: x[0].value):
            icon = CATEGORY_ICONS.get(category, "")
            label = CATEGORY_LABELS.get(category, category.value)
            risk_order = [RiskLevel.NONE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
            max_cap_risk = max((c.risk_level for c in caps), key=lambda r: risk_order.index(r)) if caps else RiskLevel.NONE
            risk_icon = RISK_ICONS.get(max_cap_risk, "")
            lines.append(f"  {icon} {label} ({len(caps)}) {risk_icon}")
            for cap in caps[:3]:  # Show first 3
                lines.append(f"      - {cap.scope}")
            if len(caps) > 3:
                lines.append(f"      ... and {len(caps) - 3} more")
        lines.append("")

        lines.append("=" * 60)
        lines.append(f"Analyzed: {manifest.analyzed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"Manifest Hash: {manifest.manifest_hash}")
        lines.append("=" * 60)

        return "\n".join(lines)

    def generate_compact_summary(self, manifest: CapabilityManifest) -> str:
        """Generate a compact one-line summary."""
        max_risk = manifest.max_risk_level
        risk_icon = RISK_ICONS.get(max_risk, "")

        critical = len(manifest.capabilities_by_risk().get(RiskLevel.CRITICAL, []))
        high = len(manifest.capabilities_by_risk().get(RiskLevel.HIGH, []))

        summary = f"{risk_icon} {manifest.metadata.name} v{manifest.metadata.version}"

        if critical > 0:
            summary += f" | {critical} CRITICAL"
        if high > 0:
            summary += f" | {high} HIGH"

        summary += f" | {len(manifest.capabilities)} capabilities"

        return summary

    def generate_markdown_summary(self, manifest: CapabilityManifest) -> str:
        """Generate a Markdown safety summary."""
        lines = []

        # Header
        lines.append(f"# Agent Safety Summary: {manifest.metadata.name}")
        lines.append("")

        # Metadata table
        lines.append("| Property | Value |")
        lines.append("|----------|-------|")
        lines.append(f"| Version | {manifest.metadata.version} |")
        lines.append(f"| Author | {manifest.metadata.author} |")
        lines.append(f"| Risk Level | **{manifest.max_risk_level.value.upper()}** |")
        lines.append(f"| Capabilities | {len(manifest.capabilities)} |")
        lines.append("")

        # Risk breakdown
        lines.append("## Risk Breakdown")
        lines.append("")
        by_risk = manifest.capabilities_by_risk()
        for risk in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
            count = len(by_risk.get(risk, []))
            if count > 0:
                lines.append(f"- **{risk.value.upper()}**: {count} capabilities")
        lines.append("")

        # High-risk capabilities
        high_risk_caps = by_risk.get(RiskLevel.CRITICAL, []) + by_risk.get(RiskLevel.HIGH, [])
        if high_risk_caps:
            lines.append("## High-Risk Capabilities")
            lines.append("")
            lines.append("| Category | Scope | Risk Reason |")
            lines.append("|----------|-------|-------------|")
            for cap in high_risk_caps:
                label = CATEGORY_LABELS.get(cap.category, cap.category.value)
                lines.append(f"| {label} | `{cap.scope[:40]}` | {cap.risk_reason} |")
            lines.append("")

        # Warnings
        if manifest.analysis_warnings:
            lines.append("## Warnings")
            lines.append("")
            for warning in manifest.analysis_warnings:
                lines.append(f"- {warning}")
            lines.append("")

        # All capabilities
        lines.append("## All Capabilities")
        lines.append("")
        by_category = manifest.capabilities_by_category()
        for category, caps in sorted(by_category.items(), key=lambda x: x[0].value):
            label = CATEGORY_LABELS.get(category, category.value)
            lines.append(f"### {label}")
            lines.append("")
            for cap in caps:
                risk_badge = f"**{cap.risk_level.value.upper()}**" if cap.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL] else cap.risk_level.value
                lines.append(f"- `{cap.scope}` ({risk_badge})")
            lines.append("")

        # Footer
        lines.append("---")
        lines.append(f"*Analyzed: {manifest.analyzed_at.isoformat()}*")
        lines.append(f"*Manifest Hash: `{manifest.manifest_hash}`*")

        return "\n".join(lines)

    def generate_json_summary(self, manifest: CapabilityManifest) -> str:
        """Generate a JSON summary."""
        return json.dumps(manifest.to_dict(), indent=2)


# =============================================================================
# Diff Report Generator
# =============================================================================

class DiffReportGenerator:
    """
    Generates human-readable diff reports.
    """

    def generate_text_diff(self, diff: CapabilityDiff) -> str:
        """Generate a plain text diff report."""
        lines = []

        # Header
        lines.append("=" * 60)
        lines.append("AGENT PERMISSION CHANGES")
        lines.append("=" * 60)
        lines.append("")

        lines.append(f"Agent: {diff.agent_id}")
        lines.append(f"Version: {diff.old_version} -> {diff.new_version}")
        lines.append("")

        # Summary
        if not diff.has_changes:
            lines.append("No permission changes detected.")
            return "\n".join(lines)

        # Risk escalations (most important)
        if diff.has_risk_escalation:
            lines.append("RISK ESCALATIONS:")
            lines.append("-" * 40)
            for cap, old_risk, new_risk in diff.risk_escalations:
                lines.append(f"  {cap.description}")
                lines.append(f"    {old_risk.value.upper()} -> {new_risk.value.upper()}")
                lines.append(f"    Scope: {cap.scope}")
                lines.append("")

        # Added capabilities
        if diff.added_capabilities:
            lines.append(f"NEW CAPABILITIES ({len(diff.added_capabilities)}):")
            lines.append("-" * 40)
            for cap in diff.added_capabilities:
                risk_icon = RISK_ICONS.get(cap.risk_level, "")
                label = CATEGORY_LABELS.get(cap.category, cap.category.value)
                lines.append(f"  + {risk_icon} {label}: {cap.scope}")
                if cap.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                    lines.append(f"      Reason: {cap.risk_reason}")
            lines.append("")

        # Removed capabilities
        if diff.removed_capabilities:
            lines.append(f"REMOVED CAPABILITIES ({len(diff.removed_capabilities)}):")
            lines.append("-" * 40)
            for cap in diff.removed_capabilities:
                label = CATEGORY_LABELS.get(cap.category, cap.category.value)
                lines.append(f"  - {label}: {cap.scope}")
            lines.append("")

        # Changed capabilities
        if diff.changed_capabilities:
            lines.append(f"CHANGED CAPABILITIES ({len(diff.changed_capabilities)}):")
            lines.append("-" * 40)
            for old_cap, new_cap in diff.changed_capabilities:
                label = CATEGORY_LABELS.get(new_cap.category, new_cap.category.value)
                lines.append(f"  ~ {label}: {new_cap.scope}")
                if old_cap.risk_level != new_cap.risk_level:
                    lines.append(f"      Risk: {old_cap.risk_level.value} -> {new_cap.risk_level.value}")
            lines.append("")

        lines.append("=" * 60)

        return "\n".join(lines)

    def generate_compact_diff(self, diff: CapabilityDiff) -> str:
        """Generate a compact one-line diff summary."""
        parts = []

        if diff.has_risk_escalation:
            parts.append(f"RISK ESCALATION")

        if diff.added_capabilities:
            parts.append(f"+{len(diff.added_capabilities)} new")

        if diff.removed_capabilities:
            parts.append(f"-{len(diff.removed_capabilities)} removed")

        if diff.changed_capabilities:
            parts.append(f"~{len(diff.changed_capabilities)} changed")

        if not parts:
            return "No changes"

        return f"{diff.old_version} -> {diff.new_version}: " + ", ".join(parts)

    def generate_markdown_diff(self, diff: CapabilityDiff) -> str:
        """Generate a Markdown diff report."""
        lines = []

        lines.append(f"# Permission Changes: {diff.agent_id}")
        lines.append("")
        lines.append(f"**Version**: {diff.old_version} → {diff.new_version}")
        lines.append("")

        if not diff.has_changes:
            lines.append("*No permission changes detected.*")
            return "\n".join(lines)

        # Risk escalations
        if diff.has_risk_escalation:
            lines.append("## Risk Escalations")
            lines.append("")
            for cap, old_risk, new_risk in diff.risk_escalations:
                lines.append(f"- **{cap.description}**: {old_risk.value} → {new_risk.value}")
                lines.append(f"  - Scope: `{cap.scope}`")
            lines.append("")

        # Added
        if diff.added_capabilities:
            lines.append("## New Capabilities")
            lines.append("")
            lines.append("| Category | Scope | Risk |")
            lines.append("|----------|-------|------|")
            for cap in diff.added_capabilities:
                label = CATEGORY_LABELS.get(cap.category, cap.category.value)
                lines.append(f"| {label} | `{cap.scope[:30]}` | {cap.risk_level.value} |")
            lines.append("")

        # Removed
        if diff.removed_capabilities:
            lines.append("## Removed Capabilities")
            lines.append("")
            for cap in diff.removed_capabilities:
                label = CATEGORY_LABELS.get(cap.category, cap.category.value)
                lines.append(f"- ~~{label}: `{cap.scope}`~~")
            lines.append("")

        return "\n".join(lines)


# =============================================================================
# Warning Generator
# =============================================================================

def generate_intake_warning(manifest: CapabilityManifest) -> str | None:
    """
    Generate a warning message for agent intake, if warranted.

    Returns None if no warning is needed.
    """
    max_risk = manifest.max_risk_level

    if max_risk == RiskLevel.CRITICAL:
        return (
            f"This agent has CRITICAL risk capabilities.\n"
            f"\n"
            f"It can:\n"
            + "\n".join(
                f"  - {cap.description}: {cap.scope}"
                for cap in manifest.capabilities
                if cap.risk_level == RiskLevel.CRITICAL
            )
            + f"\n\n"
            f"Proceed with extreme caution. Consider reviewing the source code."
        )

    elif max_risk == RiskLevel.HIGH:
        high_caps = [c for c in manifest.capabilities if c.risk_level == RiskLevel.HIGH]
        return (
            f"This agent has {len(high_caps)} high-risk capabilities.\n"
            f"\n"
            f"Review the safety summary before proceeding."
        )

    elif manifest.analysis_warnings:
        return (
            f"Analysis detected {len(manifest.analysis_warnings)} warnings:\n"
            + "\n".join(f"  - {w}" for w in manifest.analysis_warnings)
        )

    return None


# =============================================================================
# OpenClaw Report Generator
# =============================================================================

class OpenClawReportGenerator:
    """Generates reports for OpenClaw security assessments."""

    STATUS_LABELS = {
        "VULNERABLE": "VULNERABLE",
        "WARNING": "WARNING  ",
        "SAFE": "PASS     ",
        "UNKNOWN": "UNKNOWN  ",
    }

    def generate_text_report(self, report: "OpenClawSecurityReport", show_fix: bool = False) -> str:
        from .openclaw import OpenClawSecurityReport  # noqa: F811

        lines = []
        lines.append("=" * 60)
        lines.append("OPENCLAW SECURITY ASSESSMENT")
        lines.append("=" * 60)
        lines.append(f"Target: {report.agent_path}")

        if report.openclaw_version:
            from .openclaw import _parse_version, _CVE_FIX_VERSION
            parsed = _parse_version(report.openclaw_version)
            version_note = ""
            if parsed and parsed < _CVE_FIX_VERSION:
                version_note = " (OUTDATED - update to >= 2026.1.29)"
            elif parsed:
                version_note = " (up to date)"
            lines.append(f"Version: {report.openclaw_version}{version_note}")
        else:
            lines.append("Version: unknown")

        lines.append("")
        lines.append("CHECKS:")

        for check in report.checks:
            label = self.STATUS_LABELS.get(check.status, check.status)
            lines.append(f"  {label}  {check.check_id}: {check.name}")
            lines.append(f"              {check.detail}")
            if show_fix and check.status in ("VULNERABLE", "WARNING", "UNKNOWN"):
                lines.append(f"              Fix: {check.remediation}")

        lines.append("")
        parts = []
        if report.vulnerable_count:
            parts.append(f"{report.vulnerable_count} VULNERABLE")
        if report.warning_count:
            parts.append(f"{report.warning_count} WARNING")
        if report.unknown_count:
            parts.append(f"{report.unknown_count} UNKNOWN")
        if report.safe_count:
            parts.append(f"{report.safe_count} PASS")
        lines.append(f"Summary: {' | '.join(parts)}")
        lines.append("=" * 60)

        return "\n".join(lines)

    def generate_json_report(self, report: "OpenClawSecurityReport") -> str:
        return json.dumps(report.to_dict(), indent=2)

    def generate_markdown_report(self, report: "OpenClawSecurityReport", show_fix: bool = False) -> str:
        lines = []
        lines.append("# OpenClaw Security Assessment")
        lines.append("")
        lines.append(f"**Target**: `{report.agent_path}`")
        lines.append(f"**Version**: {report.openclaw_version or 'unknown'}")
        lines.append("")
        lines.append("## Checks")
        lines.append("")
        if show_fix:
            lines.append("| Status | ID | Name | Detail | Remediation |")
            lines.append("|--------|----|------|--------|-------------|")
        else:
            lines.append("| Status | ID | Name | Detail |")
            lines.append("|--------|----|------|--------|")
        for check in report.checks:
            status_badge = f"**{check.status}**"
            detail = check.detail.replace("|", "\\|")
            if show_fix:
                remediation = check.remediation.replace("|", "\\|")
                lines.append(f"| {status_badge} | {check.check_id} | {check.name} | {detail} | {remediation} |")
            else:
                lines.append(f"| {status_badge} | {check.check_id} | {check.name} | {detail} |")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        parts = []
        if report.vulnerable_count:
            parts.append(f"- **VULNERABLE**: {report.vulnerable_count}")
        if report.warning_count:
            parts.append(f"- **WARNING**: {report.warning_count}")
        if report.unknown_count:
            parts.append(f"- **UNKNOWN**: {report.unknown_count}")
        if report.safe_count:
            parts.append(f"- **PASS**: {report.safe_count}")
        lines.extend(parts)
        lines.append("")

        return "\n".join(lines)


def generate_update_warning(diff: CapabilityDiff) -> str | None:
    """
    Generate a warning message for agent update, if warranted.

    Returns None if no warning is needed.
    """
    if diff.has_risk_escalation:
        return (
            f"This update INCREASES risk level.\n"
            f"\n"
            f"New high-risk capabilities:\n"
            + "\n".join(
                f"  - {cap.description} ({old.value} → {new.value})"
                for cap, old, new in diff.risk_escalations
            )
            + f"\n\n"
            f"Review changes carefully before updating."
        )

    if diff.max_new_risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
        return (
            f"This update adds {len(diff.added_capabilities)} new capabilities.\n"
            f"Highest new risk: {diff.max_new_risk.value.upper()}\n"
            f"\n"
            f"Review changes before updating."
        )

    return None
