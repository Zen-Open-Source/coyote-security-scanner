"""Terminal UI for Coyote security scanner using Rich."""

from __future__ import annotations

import random
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

from rich.align import Align
from rich.columns import Columns
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .baseline import (
    DEFAULT_BASELINE_PATH,
    DiffResult,
    baseline_exists,
    diff_scans,
    generate_diff_summary,
    save_baseline,
)
from .config import CoyoteConfig, load_config
from .coyote_art import CoyotePose, get_art, get_quote
from .history import HistoryScanResult, scan_history, format_history_report
from .notifications import NotificationConfig, load_notification_config, send_notifications
from .patterns import Severity
from .reporter import save_reports
from .scanner import ScanResult, run_scan


class CoyoteTUI:
    def __init__(
        self,
        config: CoyoteConfig | None = None,
        notification_config: NotificationConfig | None = None,
        enable_entropy: bool = False,
        entropy_threshold: float = 4.5,
        ignore_file: str | None = None,
        no_ignore: bool = False,
    ):
        self.config = config or load_config()
        self.notification_config = notification_config or NotificationConfig()
        self.enable_entropy = enable_entropy
        self.entropy_threshold = entropy_threshold
        self.ignore_file = ignore_file
        self.no_ignore = no_ignore
        self.console = Console()
        self.pose = CoyotePose.IDLE
        self.quote_index = 0
        self.status_message = "Initializing..."
        self.last_commit = ""
        self.last_commit_time = ""
        self.scan_result: ScanResult | None = None
        self.last_diff: DiffResult | None = None  # Track last diff for notifications
        self.running = False
        self.scan_in_progress = False
        self._lock = threading.Lock()

    def _get_repo_info(self) -> tuple[str, str, str]:
        """Get current repo info (commit hash, message, time)."""
        local_path = self.config.target.local_path
        try:
            hash_result = subprocess.run(
                ["git", "-C", local_path, "rev-parse", "--short", "HEAD"],
                capture_output=True, text=True, timeout=10,
            )
            commit_hash = hash_result.stdout.strip() if hash_result.returncode == 0 else "unknown"

            time_result = subprocess.run(
                ["git", "-C", local_path, "log", "-1", "--format=%cr"],
                capture_output=True, text=True, timeout=10,
            )
            commit_time = time_result.stdout.strip() if time_result.returncode == 0 else ""

            msg_result = subprocess.run(
                ["git", "-C", local_path, "log", "-1", "--format=%s"],
                capture_output=True, text=True, timeout=10,
            )
            commit_msg = msg_result.stdout.strip()[:50] if msg_result.returncode == 0 else ""

            return commit_hash, commit_time, commit_msg
        except Exception:
            return "unknown", "", ""

    def _build_coyote_panel(self) -> Panel:
        """Build the left panel with coyote art and quote."""
        art = get_art(self.pose, compact=True)
        quote = get_quote(self.pose, self.quote_index)

        art_text = Text(art, style="bold cyan")
        quote_text = Text(f"\nCoyote says:\n\"{quote}\"", style="italic yellow")

        content = Group(art_text, quote_text)
        return Panel(
            content,
            title="[bold cyan]COYOTE[/]",
            border_style="cyan",
            width=22,
            height=20,
        )

    def _build_info_panel(self) -> Panel:
        """Build the right top panel with repo info and status."""
        repo_url = self.config.target.repo_url or "(local scan)"
        branch = self.config.target.branch

        info = Text()
        info.append("Target: ", style="bold")
        info.append(f"{repo_url}\n", style="white")
        info.append("Branch: ", style="bold")
        info.append(f"{branch}\n", style="white")
        info.append("Last Commit: ", style="bold")
        if self.last_commit:
            info.append(f"{self.last_commit}", style="green")
            if self.last_commit_time:
                info.append(f" ({self.last_commit_time})", style="dim")
            info.append("\n")
        else:
            info.append("N/A\n", style="dim")
        info.append("Status: ", style="bold")

        if self.scan_in_progress:
            info.append(self.status_message, style="bold yellow")
        elif self.scan_result and self.scan_result.total_count > 0:
            info.append(self.status_message, style="bold red")
        else:
            info.append(self.status_message, style="bold green")

        return Panel(info, title="[bold white]Status[/]", border_style="white", height=8)

    def _build_results_panel(self) -> Panel:
        """Build the scan results panel."""
        if self.scan_result is None:
            content = Text("No scan results yet. Press [S] to scan.", style="dim")
            return Panel(content, title="[bold white]Scan Results[/]", border_style="white")

        result = self.scan_result

        if result.total_count == 0:
            content = Text("No security issues found. All clear!", style="bold green")
            return Panel(content, title="[bold green]Scan Results[/]", border_style="green")

        table = Table(show_header=True, header_style="bold", expand=True, show_lines=False)
        table.add_column("Sev", width=4, justify="center")
        table.add_column("ID", width=8, justify="left")  # Stable finding ID for reference
        table.add_column("Rule", width=20)
        table.add_column("File", width=26)
        table.add_column("Description", ratio=1)

        # Sort: HIGH first, then MEDIUM, then LOW
        severity_order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
        sorted_findings = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 3))

        # Show at most 20 findings in the TUI
        display_findings = sorted_findings[:20]
        remaining = len(sorted_findings) - len(display_findings)

        for f in display_findings:
            sev_style = {
                Severity.HIGH: ("bold red", "HIGH"),
                Severity.MEDIUM: ("bold yellow", " MED"),
                Severity.LOW: ("bold blue", " LOW"),
            }
            style, label = sev_style.get(f.severity, ("white", " ???"))

            loc = f.file_path
            if f.line_number > 0:
                loc += f":{f.line_number}"

            table.add_row(
                Text(label, style=style),
                Text(f.finding_id, style="dim"),  # Show ID in dim style
                Text(f.rule_name, style="white"),
                Text(loc[:26], style="cyan"),
                Text(f.description[:45], style="dim white"),
            )

        content_parts = [table]
        if remaining > 0:
            content_parts.append(Text(f"\n  ... and {remaining} more findings. See full report.", style="dim"))

        summary = Text(
            f"\n  Summary: {result.high_count} HIGH | {result.medium_count} MEDIUM | "
            f"{result.low_count} LOW | {result.files_scanned} files scanned",
            style="bold",
        )
        content_parts.append(summary)

        # Show suppression stats if any
        if result.findings_suppressed > 0:
            suppressed_text = Text(
                f"  ({result.findings_suppressed} findings suppressed via .coyote-ignore)",
                style="dim",
            )
            content_parts.append(suppressed_text)

        title_style = "red" if result.high_count > 0 else "yellow" if result.medium_count > 0 else "blue"
        return Panel(
            Group(*content_parts),
            title=f"[bold {title_style}]Scan Results ({result.total_count} findings)[/]",
            border_style=title_style,
        )

    def _build_footer(self) -> Panel:
        """Build the footer with keybindings."""
        keys = Text()
        keys.append(" [Q]", style="bold cyan")
        keys.append("uit  ", style="dim")
        keys.append("[S]", style="bold cyan")
        keys.append("can Now  ", style="dim")
        keys.append("[R]", style="bold cyan")
        keys.append("eport  ", style="dim")
        keys.append("[C]", style="bold cyan")
        keys.append("onfigure", style="dim")
        return Panel(keys, style="dim", height=3)

    def build_layout(self) -> Layout:
        """Build the full TUI layout."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )

        # Header
        header = Panel(
            Align.center(Text(f"COYOTE v{__version__} - Repository Security Scanner", style="bold cyan")),
            style="cyan",
        )
        layout["header"].update(header)

        # Body: left coyote + right content
        layout["body"].split_row(
            Layout(name="coyote", size=22),
            Layout(name="content"),
        )
        layout["body"]["coyote"].update(self._build_coyote_panel())

        # Right side: info + results
        layout["body"]["content"].split_column(
            Layout(name="info", size=8),
            Layout(name="results"),
        )
        layout["body"]["content"]["info"].update(self._build_info_panel())
        layout["body"]["content"]["results"].update(self._build_results_panel())

        # Footer
        layout["footer"].update(self._build_footer())

        return layout

    def run_scan(self) -> None:
        """Execute a scan on the configured repository."""
        with self._lock:
            self.scan_in_progress = True
            self.pose = CoyotePose.SCANNING
            self.status_message = "Scanning repository..."

        local_path = self.config.target.local_path
        result = run_scan(
            repo_path=local_path,
            exclude_paths=self.config.scan.exclude_paths,
            exclude_extensions=self.config.scan.exclude_extensions,
            max_file_size=self.config.max_file_size_bytes,
            enable_entropy=self.enable_entropy,
            entropy_threshold=self.entropy_threshold,
            ignore_file=self.ignore_file,
            no_ignore=self.no_ignore,
        )

        with self._lock:
            self.scan_result = result
            self.scan_in_progress = False

            commit_hash, commit_time, _ = self._get_repo_info()
            self.last_commit = commit_hash
            self.last_commit_time = commit_time

            if result.total_count == 0:
                self.pose = CoyotePose.ALL_CLEAR
                self.status_message = "Scan complete - no issues found!"
            else:
                self.pose = CoyotePose.ALERT
                self.quote_index = random.randint(0, 3)
                self.status_message = f"Found {result.total_count} issues!"

    def save_report(self) -> list[str]:
        """Save the current scan results to reports."""
        if self.scan_result is None:
            return []
        return save_reports(
            self.scan_result,
            report_dir=self.config.output.report_dir,
            formats=self.config.output.format,
            commit_hash=self.last_commit,
        )

    def send_notification(self, diff: DiffResult | None = None) -> list[tuple[str, bool, str]]:
        """Send webhook notifications if configured."""
        if self.scan_result is None:
            return []

        repo_name = self.config.target.repo_url or self.config.target.local_path
        results = send_notifications(
            self.notification_config,
            self.scan_result,
            diff=diff,
            repo_name=repo_name,
        )
        return results

    def _build_diff_panel(self, diff: DiffResult) -> Panel:
        """Build a panel showing diff results."""
        parts = []

        # Summary header
        summary = Text()
        summary.append("  NEW:      ", style="bold")
        summary.append(f"{diff.new_count:3d}", style="bold red" if diff.new_count > 0 else "green")
        if diff.new_count > 0:
            summary.append(f"  ({diff.new_high_count} HIGH, {diff.new_medium_count} MED, {diff.new_low_count} LOW)", style="dim")
        summary.append("\n")
        summary.append("  FIXED:    ", style="bold")
        summary.append(f"{diff.fixed_count:3d}", style="bold green" if diff.fixed_count > 0 else "dim")
        summary.append("\n")
        summary.append("  EXISTING: ", style="bold")
        summary.append(f"{diff.existing_count:3d}", style="dim")
        parts.append(summary)

        # New findings table
        if diff.new_findings:
            parts.append(Text("\n  New Findings:", style="bold red"))
            table = Table(show_header=True, header_style="bold", expand=True, show_lines=False)
            table.add_column("Sev", width=4, justify="center")
            table.add_column("ID", width=8)
            table.add_column("Rule", width=18)
            table.add_column("File", width=26)

            for f in diff.new_findings[:10]:
                sev_style = {
                    Severity.HIGH: ("bold red", "HIGH"),
                    Severity.MEDIUM: ("bold yellow", " MED"),
                    Severity.LOW: ("bold blue", " LOW"),
                }.get(f.severity, ("white", " ???"))
                style, label = sev_style
                loc = f.file_path
                if f.line_number > 0:
                    loc += f":{f.line_number}"
                table.add_row(
                    Text(label, style=style),
                    Text(f.finding_id, style="dim"),
                    Text(f.rule_name, style="white"),
                    Text(loc[:26], style="cyan"),
                )
            parts.append(table)
            if len(diff.new_findings) > 10:
                parts.append(Text(f"  ... and {len(diff.new_findings) - 10} more new findings", style="dim"))

        # Fixed findings summary
        if diff.fixed_findings:
            parts.append(Text(f"\n  Fixed Findings: {diff.fixed_count} issues resolved", style="bold green"))

        # Determine border style
        if diff.new_count > 0:
            border_style = "red"
            title = f"[bold red]Scan Diff: {diff.new_count} NEW findings[/]"
        elif diff.fixed_count > 0:
            border_style = "green"
            title = f"[bold green]Scan Diff: {diff.fixed_count} findings FIXED[/]"
        else:
            border_style = "blue"
            title = "[bold blue]Scan Diff: No changes[/]"

        return Panel(Group(*parts), title=title, border_style=border_style)

    def run_diff_scan(self, baseline_path: str = DEFAULT_BASELINE_PATH) -> DiffResult:
        """Run a scan and compare against baseline."""
        self.console.print(Panel(
            Align.center(Text(f"COYOTE v{__version__} - Repository Security Scanner", style="bold cyan")),
            style="cyan",
        ))

        art = get_art(CoyotePose.SCANNING)
        self.console.print(Text(art, style="cyan"))
        self.console.print("[yellow]Scanning and comparing to baseline...[/]\n")

        # Run the scan
        self.run_scan()

        if self.scan_result is None:
            self.console.print("[red]Scan failed![/]")
            return DiffResult()

        # Compare against baseline
        try:
            diff = diff_scans(self.scan_result, baseline_path, self.last_commit)
        except FileNotFoundError:
            self.console.print(f"[red]Baseline not found: {baseline_path}[/]")
            self.console.print("[yellow]Run with --save-baseline first to create a baseline.[/]")
            return DiffResult()

        # Display diff results
        self.console.print(self._build_diff_panel(diff))
        self.console.print()

        # Show appropriate coyote
        if diff.new_count > 0:
            art = get_art(CoyotePose.ALERT)
            self.console.print(Text(art, style="red"))
            self.console.print(f"[bold red]Found {diff.new_count} NEW issues![/]")
        elif diff.fixed_count > 0:
            art = get_art(CoyotePose.ALL_CLEAR)
            self.console.print(Text(art, style="green"))
            self.console.print(f"[bold green]{diff.fixed_count} issues fixed! No new issues.[/]")
        else:
            art = get_art(CoyotePose.IDLE)
            self.console.print(Text(art, style="cyan"))
            self.console.print("[bold cyan]No changes since baseline.[/]")

        return diff

    def _build_history_panel(self, result: HistoryScanResult) -> Panel:
        """Build a panel showing history scan results."""
        parts = []

        # Summary
        summary = Text()
        summary.append("  Commits scanned: ", style="bold")
        summary.append(f"{result.commits_scanned}\n", style="white")
        summary.append("  Secrets found:   ", style="bold")
        if result.total_count > 0:
            summary.append(f"{result.total_count}", style="bold red")
            summary.append(f" in {result.unique_commits} commits\n", style="dim")
        else:
            summary.append("0\n", style="bold green")

        if result.total_count > 0:
            summary.append("  Severity:        ", style="bold")
            summary.append(f"{result.high_count} HIGH", style="red")
            summary.append(" | ", style="dim")
            summary.append(f"{result.medium_count} MED", style="yellow")
            summary.append(" | ", style="dim")
            summary.append(f"{result.low_count} LOW", style="blue")

        parts.append(summary)

        # Findings table grouped by commit
        if result.findings:
            parts.append(Text("\n"))

            table = Table(show_header=True, header_style="bold", expand=True, show_lines=False)
            table.add_column("Sev", width=4, justify="center")
            table.add_column("Commit", width=9)
            table.add_column("Rule", width=18)
            table.add_column("File", width=24)
            table.add_column("Author", width=20)

            # Show at most 15 findings
            for f in result.findings[:15]:
                sev_style = {
                    Severity.HIGH: ("bold red", "HIGH"),
                    Severity.MEDIUM: ("bold yellow", " MED"),
                    Severity.LOW: ("bold blue", " LOW"),
                }.get(f.severity, ("white", " ???"))
                style, label = sev_style

                table.add_row(
                    Text(label, style=style),
                    Text(f.commit_short, style="cyan"),
                    Text(f.rule_name[:18], style="white"),
                    Text(f.file_path[:24], style="dim"),
                    Text(f.commit_author.split('<')[0].strip()[:20], style="dim"),
                )

            parts.append(table)

            if len(result.findings) > 15:
                parts.append(Text(f"\n  ... and {len(result.findings) - 15} more findings", style="dim"))

            # Warning
            parts.append(Text("\n\n  ⚠️  These secrets are in git history and may be exposed!", style="bold yellow"))
            parts.append(Text("\n  Consider rotating credentials and rewriting history.", style="dim"))

        # Determine style
        if result.high_count > 0:
            border_style = "red"
            title = f"[bold red]History Scan: {result.total_count} secrets found[/]"
        elif result.total_count > 0:
            border_style = "yellow"
            title = f"[bold yellow]History Scan: {result.total_count} secrets found[/]"
        else:
            border_style = "green"
            title = "[bold green]History Scan: No secrets in history[/]"

        return Panel(Group(*parts), title=title, border_style=border_style)

    def run_history_scan(self, max_commits: int = 100, branch: str = "HEAD") -> HistoryScanResult:
        """Scan git history for secrets."""
        self.console.print(Panel(
            Align.center(Text(f"COYOTE v{__version__} - Repository Security Scanner", style="bold cyan")),
            style="cyan",
        ))

        art = get_art(CoyotePose.SCANNING)
        self.console.print(Text(art, style="cyan"))
        self.console.print(f"[yellow]Scanning git history ({max_commits} commits)...[/]\n")

        local_path = self.config.target.local_path

        result = scan_history(
            repo_path=local_path,
            branch=branch,
            max_commits=max_commits,
            exclude_paths=self.config.scan.exclude_paths,
        )

        # Display results
        self.console.print(self._build_history_panel(result))
        self.console.print()

        # Show appropriate coyote
        if result.high_count > 0:
            art = get_art(CoyotePose.ALERT)
            self.console.print(Text(art, style="red"))
            self.console.print(f"[bold red]Found {result.total_count} secrets in git history![/]")
        elif result.total_count > 0:
            art = get_art(CoyotePose.ALERT)
            self.console.print(Text(art, style="yellow"))
            self.console.print(f"[bold yellow]Found {result.total_count} secrets in git history.[/]")
        else:
            art = get_art(CoyotePose.ALL_CLEAR)
            self.console.print(Text(art, style="green"))
            self.console.print("[bold green]No secrets found in git history![/]")

        return result

    def run_interactive(self) -> None:
        """Run the interactive TUI with live updates."""
        self.running = True
        self.status_message = "Watching for changes..."
        self.pose = CoyotePose.IDLE

        # Try to get initial repo info
        commit_hash, commit_time, _ = self._get_repo_info()
        self.last_commit = commit_hash
        self.last_commit_time = commit_time

        try:
            import tty
            import termios
            import select

            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            tty.setcbreak(fd)

            with Live(self.build_layout(), console=self.console, refresh_per_second=2, screen=True) as live:
                while self.running:
                    # Check for keypress (non-blocking)
                    if select.select([sys.stdin], [], [], 0.5)[0]:
                        key = sys.stdin.read(1).lower()
                        if key == "q":
                            self.running = False
                            break
                        elif key == "s":
                            scan_thread = threading.Thread(target=self.run_scan, daemon=True)
                            scan_thread.start()
                        elif key == "r":
                            saved = self.save_report()
                            if saved:
                                self.status_message = f"Report saved: {saved[0]}"
                            else:
                                self.status_message = "No scan results to report."

                    live.update(self.build_layout())

            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

        except (ImportError, termios.error, AttributeError):
            # Fallback for environments without terminal control
            self.console.print("[yellow]Interactive mode not available. Running single scan...[/]")
            self.run_scan()
            self.console.print(self.build_layout())

    def run_single_scan(self) -> ScanResult:
        """Run a single scan and display results (non-interactive)."""
        self.console.print(Panel(
            Align.center(Text(f"COYOTE v{__version__} - Repository Security Scanner", style="bold cyan")),
            style="cyan",
        ))

        art = get_art(CoyotePose.SCANNING)
        self.console.print(Text(art, style="cyan"))
        self.console.print("[yellow]Scanning...[/]\n")

        self.run_scan()

        # Display results
        self.console.print(self._build_results_panel())
        self.console.print()

        if self.scan_result and self.scan_result.total_count == 0:
            art = get_art(CoyotePose.ALL_CLEAR)
            self.console.print(Text(art, style="green"))
            self.console.print("[bold green]All clear![/]")
        elif self.scan_result:
            art = get_art(CoyotePose.ALERT)
            self.console.print(Text(art, style="red"))
            self.console.print(f"[bold red]Found {self.scan_result.total_count} issues![/]")

        return self.scan_result


def main():
    """Entry point for the TUI."""
    import argparse
    import yaml

    parser = argparse.ArgumentParser(description="Coyote - Repository Security Scanner")
    parser.add_argument("--config", default="config.yaml", help="Path to config file")
    parser.add_argument("--repo", help="Path to repository to scan (overrides config)")
    parser.add_argument("--interactive", "-i", action="store_true", help="Run interactive TUI")
    parser.add_argument("--report", "-r", action="store_true", help="Save reports after scan")

    # Baseline/diff options
    parser.add_argument(
        "--save-baseline",
        action="store_true",
        help="Save current scan as baseline for future comparisons"
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Compare scan against saved baseline and show new/fixed findings"
    )
    parser.add_argument(
        "--baseline-path",
        default=DEFAULT_BASELINE_PATH,
        help=f"Path to baseline file (default: {DEFAULT_BASELINE_PATH})"
    )
    parser.add_argument(
        "--fail-on-new",
        action="store_true",
        help="Exit with code 1 if new findings are detected (useful for CI)"
    )

    # Notification options
    parser.add_argument(
        "--notify",
        action="store_true",
        help="Send webhook notifications (uses config file settings)"
    )
    parser.add_argument(
        "--slack-webhook",
        help="Slack webhook URL (overrides config)"
    )
    parser.add_argument(
        "--discord-webhook",
        help="Discord webhook URL (overrides config)"
    )

    # History scanning options
    parser.add_argument(
        "--history",
        action="store_true",
        help="Scan git history for secrets (finds secrets in past commits)"
    )
    parser.add_argument(
        "--max-commits",
        type=int,
        default=100,
        help="Maximum commits to scan in history mode (default: 100)"
    )
    parser.add_argument(
        "--branch",
        default="HEAD",
        help="Branch to scan for history mode (default: HEAD)"
    )

    # Entropy detection options
    parser.add_argument(
        "--entropy",
        action="store_true",
        help="Enable entropy-based secret detection (finds high-randomness strings)"
    )
    parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=4.5,
        help="Entropy threshold for detection (default: 4.5, lower = more sensitive)"
    )

    # Suppression options
    parser.add_argument(
        "--ignore-file",
        help="Path to ignore file (default: .coyote-ignore in repo root)"
    )
    parser.add_argument(
        "--no-ignore",
        action="store_true",
        help="Disable suppression (ignore .coyote-ignore file)"
    )
    parser.add_argument(
        "--show-suppressed",
        action="store_true",
        help="Show which findings were suppressed"
    )

    args = parser.parse_args()

    config = load_config(args.config)
    if args.repo:
        config.target.local_path = args.repo

    # Load notification config from config file
    notification_config = NotificationConfig()
    try:
        with open(args.config, "r") as f:
            config_dict = yaml.safe_load(f) or {}
            notification_config = load_notification_config(config_dict)
    except FileNotFoundError:
        pass

    # Override with CLI args
    if args.notify:
        notification_config.enabled = True
    if args.slack_webhook:
        notification_config.enabled = True
        notification_config.slack_webhook_url = args.slack_webhook
    if args.discord_webhook:
        notification_config.enabled = True
        notification_config.discord_webhook_url = args.discord_webhook

    tui = CoyoteTUI(
        config,
        notification_config,
        enable_entropy=args.entropy,
        entropy_threshold=args.entropy_threshold,
        ignore_file=args.ignore_file,
        no_ignore=args.no_ignore,
    )

    # Handle history scan mode
    if args.history:
        result = tui.run_history_scan(max_commits=args.max_commits, branch=args.branch)

        # Save report if requested
        if args.report and result.findings:
            from .history import format_history_report
            report_content = format_history_report(result)
            report_path = f"{config.output.report_dir}/coyote_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            import os
            os.makedirs(config.output.report_dir, exist_ok=True)
            with open(report_path, "w") as f:
                f.write(report_content)
            tui.console.print(f"[dim]History report saved: {report_path}[/]")

        # Exit with error if findings and --fail-on-new (reuse flag for CI)
        if args.fail_on_new and result.total_count > 0:
            tui.console.print(f"[red]Failing due to {result.total_count} secrets in history.[/]")
            sys.exit(1)
        return

    # Handle diff mode
    if args.diff:
        diff = tui.run_diff_scan(args.baseline_path)
        if args.report:
            saved = tui.save_report()
            for path in saved:
                tui.console.print(f"[dim]Report saved: {path}[/]")
        # Send notifications
        if notification_config.enabled:
            notif_results = tui.send_notification(diff=diff)
            for service, success, msg in notif_results:
                if success:
                    tui.console.print(f"[dim green]{service}: {msg}[/]")
                else:
                    tui.console.print(f"[dim red]{service}: {msg}[/]")
        # Exit with error if new findings and --fail-on-new
        if args.fail_on_new and diff.has_new_findings:
            tui.console.print(f"[red]Failing due to {diff.new_count} new findings.[/]")
            sys.exit(1)
        return

    # Handle interactive mode
    if args.interactive:
        tui.run_interactive()
        return

    # Standard scan
    tui.run_single_scan()

    # Save baseline if requested
    if args.save_baseline and tui.scan_result:
        path = save_baseline(tui.scan_result, args.baseline_path, tui.last_commit)
        tui.console.print(f"[bold green]Baseline saved: {path}[/]")
        tui.console.print(f"[dim]Contains {tui.scan_result.total_count} findings. Use --diff to compare future scans.[/]")

    # Save reports if requested
    if args.report:
        saved = tui.save_report()
        for path in saved:
            tui.console.print(f"[dim]Report saved: {path}[/]")

    # Send notifications
    if notification_config.enabled:
        notif_results = tui.send_notification()
        for service, success, msg in notif_results:
            if success:
                tui.console.print(f"[dim green]{service}: {msg}[/]")
            else:
                tui.console.print(f"[dim red]{service}: {msg}[/]")


if __name__ == "__main__":
    main()
