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

from .config import CoyoteConfig, load_config
from .coyote_art import CoyotePose, get_art, get_quote
from .patterns import Severity
from .reporter import save_reports
from .scanner import ScanResult, run_scan


class CoyoteTUI:
    def __init__(self, config: CoyoteConfig | None = None):
        self.config = config or load_config()
        self.console = Console()
        self.pose = CoyotePose.IDLE
        self.quote_index = 0
        self.status_message = "Initializing..."
        self.last_commit = ""
        self.last_commit_time = ""
        self.scan_result: ScanResult | None = None
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
            Align.center(Text("COYOTE v1.0 - Repository Security Scanner", style="bold cyan")),
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
            Align.center(Text("COYOTE v1.0 - Repository Security Scanner", style="bold cyan")),
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

    parser = argparse.ArgumentParser(description="Coyote - Repository Security Scanner")
    parser.add_argument("--config", default="config.yaml", help="Path to config file")
    parser.add_argument("--repo", help="Path to repository to scan (overrides config)")
    parser.add_argument("--interactive", "-i", action="store_true", help="Run interactive TUI")
    parser.add_argument("--report", "-r", action="store_true", help="Save reports after scan")
    args = parser.parse_args()

    config = load_config(args.config)
    if args.repo:
        config.target.local_path = args.repo

    tui = CoyoteTUI(config)

    if args.interactive:
        tui.run_interactive()
    else:
        tui.run_single_scan()
        if args.report:
            saved = tui.save_report()
            for path in saved:
                tui.console.print(f"[dim]Report saved: {path}[/]")


if __name__ == "__main__":
    main()
