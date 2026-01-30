"""Webhook notifications for Coyote.

Supports sending scan alerts to:
- Slack (via Incoming Webhooks)
- Discord (via Webhooks)
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Any

from .scanner import ScanResult
from .baseline import DiffResult


@dataclass
class NotificationConfig:
    """Configuration for webhook notifications."""

    enabled: bool = False
    slack_webhook_url: str = ""
    discord_webhook_url: str = ""

    # When to notify
    notify_on_completion: bool = True  # Always notify when scan completes
    notify_only_on_findings: bool = False  # Only notify if findings exist
    notify_only_on_new: bool = False  # Only notify if NEW findings (diff mode)

    # Severity threshold (only notify if findings at or above this level)
    min_severity: str = "LOW"  # LOW, MEDIUM, HIGH

    # Include details in message
    include_finding_list: bool = True
    max_findings_in_message: int = 10


def _severity_value(severity: str) -> int:
    """Convert severity string to numeric value for comparison."""
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3}.get(severity.upper(), 0)


def _build_scan_summary(result: ScanResult, repo_name: str = "") -> dict[str, Any]:
    """Build a summary dict from scan results."""
    return {
        "repo": repo_name or result.repo_path,
        "total": result.total_count,
        "high": result.high_count,
        "medium": result.medium_count,
        "low": result.low_count,
        "files_scanned": result.files_scanned,
    }


def _build_diff_summary(diff: DiffResult) -> dict[str, Any]:
    """Build a summary dict from diff results."""
    return {
        "new_count": diff.new_count,
        "fixed_count": diff.fixed_count,
        "existing_count": diff.existing_count,
        "new_high": diff.new_high_count,
        "new_medium": diff.new_medium_count,
        "new_low": diff.new_low_count,
    }


def _format_slack_message(
    result: ScanResult,
    diff: DiffResult | None = None,
    repo_name: str = "",
    config: NotificationConfig | None = None,
) -> dict[str, Any]:
    """Format scan results as a Slack message payload."""
    config = config or NotificationConfig()
    repo = repo_name or result.repo_path

    # Determine emoji and color based on results
    if diff:
        if diff.new_count > 0:
            emoji = ":warning:"
            color = "danger"
            title = f"Coyote: {diff.new_count} NEW findings in {repo}"
        elif diff.fixed_count > 0:
            emoji = ":white_check_mark:"
            color = "good"
            title = f"Coyote: {diff.fixed_count} findings FIXED in {repo}"
        else:
            emoji = ":mag:"
            color = "#439FE0"
            title = f"Coyote: No changes in {repo}"
    else:
        if result.high_count > 0:
            emoji = ":rotating_light:"
            color = "danger"
            title = f"Coyote: {result.high_count} HIGH severity findings in {repo}"
        elif result.medium_count > 0:
            emoji = ":warning:"
            color = "warning"
            title = f"Coyote: {result.medium_count} MEDIUM severity findings in {repo}"
        elif result.total_count > 0:
            emoji = ":information_source:"
            color = "#439FE0"
            title = f"Coyote: {result.total_count} findings in {repo}"
        else:
            emoji = ":white_check_mark:"
            color = "good"
            title = f"Coyote: All clear in {repo}"

    # Build fields
    fields = []

    if diff:
        fields.extend([
            {"title": "New", "value": str(diff.new_count), "short": True},
            {"title": "Fixed", "value": str(diff.fixed_count), "short": True},
            {"title": "Existing", "value": str(diff.existing_count), "short": True},
        ])
        if diff.new_count > 0:
            fields.append({
                "title": "New by Severity",
                "value": f"HIGH: {diff.new_high_count} | MEDIUM: {diff.new_medium_count} | LOW: {diff.new_low_count}",
                "short": False,
            })
    else:
        fields.extend([
            {"title": "HIGH", "value": str(result.high_count), "short": True},
            {"title": "MEDIUM", "value": str(result.medium_count), "short": True},
            {"title": "LOW", "value": str(result.low_count), "short": True},
            {"title": "Files Scanned", "value": str(result.files_scanned), "short": True},
        ])

    # Add finding details if enabled
    if config.include_finding_list:
        findings_to_show = diff.new_findings if diff else result.findings
        findings_to_show = findings_to_show[:config.max_findings_in_message]

        if findings_to_show:
            finding_lines = []
            for f in findings_to_show:
                loc = f.file_path
                if f.line_number > 0:
                    loc += f":{f.line_number}"
                finding_lines.append(f"• `[{f.severity.value}]` {f.rule_name} - `{loc}`")

            fields.append({
                "title": "Findings" if not diff else "New Findings",
                "value": "\n".join(finding_lines),
                "short": False,
            })

    return {
        "attachments": [
            {
                "fallback": title,
                "color": color,
                "pretext": f"{emoji} {title}",
                "fields": fields,
                "footer": "Coyote Security Scanner",
                "footer_icon": "https://em-content.zobj.net/source/twitter/376/wolf_1f43a.png",
            }
        ]
    }


def _format_discord_message(
    result: ScanResult,
    diff: DiffResult | None = None,
    repo_name: str = "",
    config: NotificationConfig | None = None,
) -> dict[str, Any]:
    """Format scan results as a Discord webhook payload."""
    config = config or NotificationConfig()
    repo = repo_name or result.repo_path

    # Determine color based on results (Discord uses decimal color values)
    if diff:
        if diff.new_count > 0:
            color = 15158332  # Red
            title = f"🐺 {diff.new_count} NEW findings detected"
        elif diff.fixed_count > 0:
            color = 3066993  # Green
            title = f"✅ {diff.fixed_count} findings FIXED"
        else:
            color = 3447003  # Blue
            title = "🔍 No changes detected"
    else:
        if result.high_count > 0:
            color = 15158332  # Red
            title = f"🚨 {result.high_count} HIGH severity findings"
        elif result.medium_count > 0:
            color = 15105570  # Orange
            title = f"⚠️ {result.medium_count} MEDIUM severity findings"
        elif result.total_count > 0:
            color = 3447003  # Blue
            title = f"ℹ️ {result.total_count} findings detected"
        else:
            color = 3066993  # Green
            title = "✅ All clear - no findings"

    # Build embed fields
    fields = []

    if diff:
        fields.extend([
            {"name": "New", "value": str(diff.new_count), "inline": True},
            {"name": "Fixed", "value": str(diff.fixed_count), "inline": True},
            {"name": "Existing", "value": str(diff.existing_count), "inline": True},
        ])
        if diff.new_count > 0:
            fields.append({
                "name": "New by Severity",
                "value": f"HIGH: {diff.new_high_count} | MEDIUM: {diff.new_medium_count} | LOW: {diff.new_low_count}",
                "inline": False,
            })
    else:
        fields.extend([
            {"name": "HIGH", "value": str(result.high_count), "inline": True},
            {"name": "MEDIUM", "value": str(result.medium_count), "inline": True},
            {"name": "LOW", "value": str(result.low_count), "inline": True},
            {"name": "Files Scanned", "value": str(result.files_scanned), "inline": True},
        ])

    # Add finding details if enabled
    if config.include_finding_list:
        findings_to_show = diff.new_findings if diff else result.findings
        findings_to_show = findings_to_show[:config.max_findings_in_message]

        if findings_to_show:
            finding_lines = []
            for f in findings_to_show:
                loc = f.file_path
                if f.line_number > 0:
                    loc += f":{f.line_number}"
                finding_lines.append(f"• **[{f.severity.value}]** {f.rule_name} - `{loc}`")

            fields.append({
                "name": "Findings" if not diff else "New Findings",
                "value": "\n".join(finding_lines)[:1024],  # Discord field limit
                "inline": False,
            })

    return {
        "embeds": [
            {
                "title": title,
                "description": f"Repository: `{repo}`",
                "color": color,
                "fields": fields,
                "footer": {"text": "Coyote Security Scanner 🐺"},
            }
        ]
    }


def send_slack_notification(
    webhook_url: str,
    result: ScanResult,
    diff: DiffResult | None = None,
    repo_name: str = "",
    config: NotificationConfig | None = None,
) -> tuple[bool, str]:
    """
    Send a scan notification to Slack.

    Returns:
        Tuple of (success, message)
    """
    if not webhook_url:
        return False, "No Slack webhook URL configured"

    payload = _format_slack_message(result, diff, repo_name, config)

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                return True, "Slack notification sent"
            return False, f"Slack returned status {response.status}"

    except urllib.error.HTTPError as e:
        return False, f"Slack webhook error: {e.code} {e.reason}"
    except urllib.error.URLError as e:
        return False, f"Slack connection error: {e.reason}"
    except Exception as e:
        return False, f"Slack notification failed: {str(e)}"


def send_discord_notification(
    webhook_url: str,
    result: ScanResult,
    diff: DiffResult | None = None,
    repo_name: str = "",
    config: NotificationConfig | None = None,
) -> tuple[bool, str]:
    """
    Send a scan notification to Discord.

    Returns:
        Tuple of (success, message)
    """
    if not webhook_url:
        return False, "No Discord webhook URL configured"

    payload = _format_discord_message(result, diff, repo_name, config)

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=10) as response:
            # Discord returns 204 No Content on success
            if response.status in (200, 204):
                return True, "Discord notification sent"
            return False, f"Discord returned status {response.status}"

    except urllib.error.HTTPError as e:
        return False, f"Discord webhook error: {e.code} {e.reason}"
    except urllib.error.URLError as e:
        return False, f"Discord connection error: {e.reason}"
    except Exception as e:
        return False, f"Discord notification failed: {str(e)}"


def send_notifications(
    config: NotificationConfig,
    result: ScanResult,
    diff: DiffResult | None = None,
    repo_name: str = "",
) -> list[tuple[str, bool, str]]:
    """
    Send notifications to all configured webhooks.

    Respects notification config settings (notify_only_on_findings, etc.)

    Returns:
        List of (service_name, success, message) tuples
    """
    results = []

    if not config.enabled:
        return results

    # Check if we should notify based on config
    if config.notify_only_on_new and diff:
        if diff.new_count == 0:
            return results  # No new findings, skip notification

    if config.notify_only_on_findings:
        if diff:
            if diff.new_count == 0:
                return results
        else:
            if result.total_count == 0:
                return results

    # Check severity threshold
    min_sev = _severity_value(config.min_severity)
    if diff:
        max_finding_sev = 0
        if diff.new_high_count > 0:
            max_finding_sev = 3
        elif diff.new_medium_count > 0:
            max_finding_sev = 2
        elif diff.new_low_count > 0:
            max_finding_sev = 1

        if max_finding_sev < min_sev and diff.new_count > 0:
            return results  # Findings don't meet severity threshold
    else:
        max_finding_sev = 0
        if result.high_count > 0:
            max_finding_sev = 3
        elif result.medium_count > 0:
            max_finding_sev = 2
        elif result.low_count > 0:
            max_finding_sev = 1

        if max_finding_sev < min_sev and result.total_count > 0:
            return results  # Findings don't meet severity threshold

    # Send to Slack
    if config.slack_webhook_url:
        success, msg = send_slack_notification(
            config.slack_webhook_url, result, diff, repo_name, config
        )
        results.append(("Slack", success, msg))

    # Send to Discord
    if config.discord_webhook_url:
        success, msg = send_discord_notification(
            config.discord_webhook_url, result, diff, repo_name, config
        )
        results.append(("Discord", success, msg))

    return results


def load_notification_config(config_dict: dict[str, Any]) -> NotificationConfig:
    """Load notification config from a config dictionary."""
    notif = config_dict.get("notifications", {})

    return NotificationConfig(
        enabled=notif.get("enabled", False),
        slack_webhook_url=notif.get("slack_webhook_url", ""),
        discord_webhook_url=notif.get("discord_webhook_url", ""),
        notify_on_completion=notif.get("notify_on_completion", True),
        notify_only_on_findings=notif.get("notify_only_on_findings", False),
        notify_only_on_new=notif.get("notify_only_on_new", False),
        min_severity=notif.get("min_severity", "LOW"),
        include_finding_list=notif.get("include_finding_list", True),
        max_findings_in_message=notif.get("max_findings_in_message", 10),
    )
