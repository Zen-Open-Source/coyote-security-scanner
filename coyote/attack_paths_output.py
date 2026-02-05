"""Output formatters for attack path analysis results."""

from __future__ import annotations

import json

from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.console import Group

from .attack_paths import AttackPath, AttackPathResult


SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold blue",
}


class AttackPathReportGenerator:
    """Generates reports from attack path analysis results."""

    def generate_text_report(self, result: AttackPathResult) -> str:
        """Generate an ASCII-art attack path report."""
        lines: list[str] = []
        sep = "=" * 60

        lines.append(sep)
        lines.append("ATTACK PATH ANALYSIS")
        lines.append(sep)
        lines.append("")

        for i, path in enumerate(result.paths, 1):
            lines.append(f"PATH {i}: {path.title} ({path.escalated_severity})")
            lines.append(f"Blast Radius: {path.blast_radius}")
            lines.append(f"Composite Score: {path.composite_score:.1f}/10")
            lines.append("")

            # Render nodes with connectors
            for j, node in enumerate(path.nodes):
                sev = node.finding.severity.value
                name = node.finding.rule_name
                loc = node.finding.file_path
                if node.finding.line_number > 0:
                    loc += f":{node.finding.line_number}"

                if j == 0:
                    # First node
                    lines.append(f"  [{sev}] {name}")
                    lines.append(f"         {loc}")
                    if len(path.nodes) > 1:
                        lines.append("                                          │")
                        lines.append("                                          ▼")
                elif j < len(path.nodes) - 1:
                    # Middle node
                    lines.append(f"  [{sev}] {name}")
                    lines.append(f"         {loc}")
                    lines.append("                                          │")
                    lines.append("                                          ▼")
                else:
                    # Last node
                    lines.append(f"  [{sev}] {name}")
                    lines.append(f"         {loc}")

            lines.append("")
            # Description
            lines.append(f"  {path.description}")
            lines.append("")
            lines.append("-" * 60)

        lines.append(sep)
        lines.append(
            f"{len(result.paths)} attack paths found | "
            f"Worst: {result.worst_severity} | "
            f"{result.findings_in_paths} findings chained"
        )
        lines.append(sep)

        return "\n".join(lines)

    def generate_json_report(self, result: AttackPathResult) -> str:
        """Generate a structured JSON report."""
        data = {
            "attack_path_analysis": {
                "total_paths": len(result.paths),
                "total_findings_analyzed": result.total_findings_analyzed,
                "findings_in_paths": result.findings_in_paths,
                "worst_severity": result.worst_severity,
                "paths": [],
            }
        }

        for path in result.paths:
            path_data = {
                "path_id": path.path_id,
                "title": path.title,
                "escalated_severity": path.escalated_severity,
                "composite_score": round(path.composite_score, 1),
                "blast_radius": path.blast_radius,
                "description": path.description,
                "nodes": [
                    {
                        "node_id": n.node_id,
                        "rule_name": n.finding.rule_name,
                        "severity": n.finding.severity.value,
                        "category": n.category.value,
                        "file_path": n.finding.file_path,
                        "line_number": n.finding.line_number,
                        "description": n.finding.description,
                    }
                    for n in path.nodes
                ],
                "edges": [
                    {
                        "source_id": e.source_id,
                        "target_id": e.target_id,
                        "chain_rule": e.chain_rule_name,
                        "relationship": e.relationship,
                        "escalated_severity": e.escalated_severity,
                    }
                    for e in path.edges
                ],
            }
            data["attack_path_analysis"]["paths"].append(path_data)

        return json.dumps(data, indent=2)

    def generate_markdown_report(self, result: AttackPathResult) -> str:
        """Generate a markdown report with tables per path."""
        lines: list[str] = []
        lines.append("# Attack Path Analysis")
        lines.append("")
        lines.append(
            f"**{len(result.paths)} paths found** | "
            f"Worst: **{result.worst_severity}** | "
            f"{result.findings_in_paths} findings chained"
        )
        lines.append("")

        for i, path in enumerate(result.paths, 1):
            lines.append(f"## Path {i}: {path.title}")
            lines.append("")
            lines.append(f"- **Severity:** {path.escalated_severity}")
            lines.append(f"- **Score:** {path.composite_score:.1f}/10")
            lines.append(f"- **Blast Radius:** {path.blast_radius}")
            lines.append("")
            lines.append("| Step | Severity | Finding | Location |")
            lines.append("|------|----------|---------|----------|")

            for j, node in enumerate(path.nodes, 1):
                loc = node.finding.file_path
                if node.finding.line_number > 0:
                    loc += f":{node.finding.line_number}"
                lines.append(
                    f"| {j} | {node.finding.severity.value} | "
                    f"{node.finding.rule_name} | `{loc}` |"
                )

            lines.append("")
            lines.append(f"> {path.description}")
            lines.append("")

        return "\n".join(lines)

    def generate_rich_panel(self, result: AttackPathResult) -> Panel:
        """Generate a Rich Panel for TUI integration."""
        parts: list[Text | Table] = []

        if not result.paths:
            parts.append(Text(
                "No attack paths found — findings do not form exploitable chains.",
                style="dim",
            ))
            return Panel(
                Group(*parts),
                title="[bold white]Attack Path Analysis[/]",
                border_style="white",
            )

        for i, path in enumerate(result.paths, 1):
            sev_style = SEVERITY_STYLE.get(path.escalated_severity, "white")

            header = Text()
            header.append(f"\n  PATH {i}: ", style="bold")
            header.append(path.title, style=sev_style)
            header.append(f" ({path.escalated_severity})", style=sev_style)
            header.append(f"\n  Score: {path.composite_score:.1f}/10", style="dim")
            header.append(f"\n  Blast Radius: {path.blast_radius}\n", style="dim")
            parts.append(header)

            table = Table(
                show_header=True, header_style="bold",
                expand=True, show_lines=False,
            )
            table.add_column("Step", width=4, justify="center")
            table.add_column("Sev", width=4, justify="center")
            table.add_column("Finding", width=24)
            table.add_column("Location", width=28)

            for j, node in enumerate(path.nodes, 1):
                sev = node.finding.severity.value
                node_style = SEVERITY_STYLE.get(sev, "white")
                loc = node.finding.file_path
                if node.finding.line_number > 0:
                    loc += f":{node.finding.line_number}"

                step_marker = f"{j}"
                if j < len(path.nodes):
                    step_marker += " ->"

                table.add_row(
                    Text(step_marker, style="bold"),
                    Text(sev[:4], style=node_style),
                    Text(node.finding.rule_name, style="white"),
                    Text(loc[:28], style="cyan"),
                )

            parts.append(table)

            desc = Text(f"\n  {path.description}\n", style="dim")
            parts.append(desc)

        # Summary
        summary = Text(
            f"\n  {len(result.paths)} attack paths | "
            f"Worst: {result.worst_severity} | "
            f"{result.findings_in_paths} findings chained",
            style="bold",
        )
        parts.append(summary)

        worst_sev = result.worst_severity
        border = "red" if worst_sev == "CRITICAL" else "yellow" if worst_sev == "HIGH" else "blue"
        title_style = border

        return Panel(
            Group(*parts),
            title=f"[bold {title_style}]Attack Path Analysis ({len(result.paths)} paths)[/]",
            border_style=border,
        )
