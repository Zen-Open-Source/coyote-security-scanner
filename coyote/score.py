"""Security scorecard for Coyote scanner.

Produces a Rich-based security scorecard with a letter grade (A+ through F),
per-category colored progress bars, and a severity breakdown.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .attack_paths import (
    AttackPathAnalyzer,
    FindingCategory,
    RULE_CATEGORY_MAP,
)
from .patterns import PatternMatch, Severity


# ---------------------------------------------------------------------------
# Finding classification
# ---------------------------------------------------------------------------

SCORECARD_SECRETS = {
    FindingCategory.CREDENTIAL,
    FindingCategory.PRIVATE_KEY,
    FindingCategory.AUTH_TOKEN,
}

SCORECARD_CODE_QUALITY = {
    FindingCategory.CODE_INJECTION,
    FindingCategory.DEBUG_CONFIG,
    FindingCategory.NETWORK_WEAKNESS,
}

SCORECARD_CONFIG_HYGIENE = {
    FindingCategory.SENSITIVE_FILE,
    FindingCategory.INFRASTRUCTURE,
}

# Rule names that map to Config Hygiene at the scanner (file-level) layer
CONFIG_HYGIENE_RULE_NAMES = {
    "Missing .gitignore",
    "Incomplete .gitignore",
    "Large File",
}


def classify_finding(finding: PatternMatch) -> str:
    """Return a scorecard category name for *finding*."""
    # Entropy-based findings are secrets
    if finding.rule_name.startswith("High Entropy"):
        return "Secrets"

    # Config hygiene file-level rules
    if finding.rule_name in CONFIG_HYGIENE_RULE_NAMES:
        return "Config Hygiene"

    cat = RULE_CATEGORY_MAP.get(finding.rule_name)
    if cat is None:
        return "Config Hygiene"  # fallback
    if cat in SCORECARD_SECRETS:
        return "Secrets"
    if cat in SCORECARD_CODE_QUALITY:
        return "Code Quality"
    if cat == FindingCategory.SUPPLY_CHAIN:
        return "Dependencies"
    if cat in SCORECARD_CONFIG_HYGIENE:
        return "Config Hygiene"
    # Gateway / websocket / anything else
    return "Config Hygiene"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CategoryScore:
    name: str
    score: float
    weight: float
    enabled: bool
    high_count: int
    medium_count: int
    low_count: int
    finding_count: int


@dataclass
class Scorecard:
    repo_path: str
    aggregate_score: float
    letter_grade: str
    categories: list[CategoryScore]
    attack_paths_count: int
    worst_attack_severity: str
    files_scanned: int
    total_findings: int
    scan_timestamp: str

    def to_dict(self) -> dict:
        return {
            "repo_path": self.repo_path,
            "aggregate_score": round(self.aggregate_score, 1),
            "letter_grade": self.letter_grade,
            "categories": [
                {
                    "name": c.name,
                    "score": round(c.score, 1),
                    "weight": round(c.weight, 3),
                    "enabled": c.enabled,
                    "high_count": c.high_count,
                    "medium_count": c.medium_count,
                    "low_count": c.low_count,
                    "finding_count": c.finding_count,
                }
                for c in self.categories
            ],
            "attack_paths_count": self.attack_paths_count,
            "worst_attack_severity": self.worst_attack_severity,
            "files_scanned": self.files_scanned,
            "total_findings": self.total_findings,
            "scan_timestamp": self.scan_timestamp,
        }


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

BASE_WEIGHTS: dict[str, float] = {
    "Secrets": 0.35,
    "Dependencies": 0.25,
    "Code Quality": 0.15,
    "Git History": 0.10,
    "Config Hygiene": 0.15,
}

GRADE_TABLE: list[tuple[int, str, str]] = [
    (97, "A+", "bright_green"),
    (93, "A",  "green"),
    (90, "A-", "green"),
    (87, "B+", "yellow"),
    (83, "B",  "yellow"),
    (80, "B-", "yellow"),
    (77, "C+", "dark_orange"),
    (73, "C",  "dark_orange"),
    (70, "C-", "dark_orange"),
    (67, "D+", "red"),
    (63, "D",  "red"),
    (60, "D-", "red"),
    (0,  "F",  "bold red"),
]


def _letter_grade(score: float) -> str:
    for threshold, grade, _ in GRADE_TABLE:
        if score >= threshold:
            return grade
    return "F"


def _grade_color(score: float) -> str:
    for threshold, _, color in GRADE_TABLE:
        if score >= threshold:
            return color
    return "bold red"


def _category_score(high: int, medium: int, low: int) -> float:
    deductions = high * 25 + medium * 10 + low * 3
    return max(0.0, 100.0 - deductions)


def compute_scorecard(
    repo_path: str,
    findings: list[PatternMatch],
    *,
    deps_enabled: bool = False,
    deps_findings: list[PatternMatch] | None = None,
    history_enabled: bool = False,
    history_high: int = 0,
    history_medium: int = 0,
    history_low: int = 0,
    history_total: int = 0,
    attack_paths_count: int = 0,
    attack_paths_critical: int = 0,
    worst_attack_severity: str = "NONE",
    files_scanned: int = 0,
) -> Scorecard:
    """Compute a full scorecard from scan results."""

    # Bucket scan findings by category
    buckets: dict[str, list[PatternMatch]] = {
        "Secrets": [],
        "Code Quality": [],
        "Config Hygiene": [],
        "Dependencies": [],
    }
    for f in findings:
        cat = classify_finding(f)
        if cat == "Dependencies":
            continue  # deps come from the dedicated scan
        buckets.setdefault(cat, []).append(f)

    if deps_findings:
        buckets["Dependencies"].extend(deps_findings)

    # Build category scores
    active_categories: dict[str, bool] = {
        "Secrets": True,
        "Dependencies": deps_enabled,
        "Code Quality": True,
        "Git History": history_enabled,
        "Config Hygiene": True,
    }

    category_scores: list[CategoryScore] = []
    for name in ["Secrets", "Dependencies", "Code Quality", "Git History", "Config Hygiene"]:
        enabled = active_categories[name]
        if name == "Git History":
            h, m, lo, total = history_high, history_medium, history_low, history_total
        else:
            cat_findings = buckets.get(name, [])
            h = sum(1 for f in cat_findings if f.severity == Severity.HIGH)
            m = sum(1 for f in cat_findings if f.severity == Severity.MEDIUM)
            lo = sum(1 for f in cat_findings if f.severity == Severity.LOW)
            total = len(cat_findings)

        score = _category_score(h, m, lo) if enabled else 0.0
        category_scores.append(CategoryScore(
            name=name,
            score=score,
            weight=0.0,  # normalized below
            enabled=enabled,
            high_count=h,
            medium_count=m,
            low_count=lo,
            finding_count=total,
        ))

    # Normalize weights among enabled categories
    total_active_weight = sum(
        BASE_WEIGHTS[c.name] for c in category_scores if c.enabled
    )
    if total_active_weight > 0:
        for c in category_scores:
            if c.enabled:
                c.weight = BASE_WEIGHTS[c.name] / total_active_weight
            else:
                c.weight = 0.0

    # Aggregate score
    aggregate = sum(c.score * c.weight for c in category_scores)

    # Attack path penalty
    penalty = min(attack_paths_critical * 2, 5)
    aggregate = max(0.0, aggregate - penalty)

    total_findings = sum(c.finding_count for c in category_scores)

    return Scorecard(
        repo_path=repo_path,
        aggregate_score=aggregate,
        letter_grade=_letter_grade(aggregate),
        categories=category_scores,
        attack_paths_count=attack_paths_count,
        worst_attack_severity=worst_attack_severity,
        files_scanned=files_scanned,
        total_findings=total_findings,
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
    )


# ---------------------------------------------------------------------------
# Rich rendering
# ---------------------------------------------------------------------------

def render_scorecard(scorecard: Scorecard) -> None:
    """Render the scorecard to the terminal using Rich."""
    from rich.align import Align
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text

    console = Console()
    score_val = scorecard.aggregate_score
    color = _grade_color(score_val)

    # --- Header panel ---
    grade_text = Text(scorecard.letter_grade, style=f"bold {color}")
    score_text = Text(f" {score_val:.0f}/100", style=color)

    header_lines = Text.assemble(
        ("COYOTE SECURITY SCORECARD\n", "bold cyan"),
        "\n",
        "Grade: ",
        grade_text,
        score_text,
        "\n\n",
        (f"Repo:     {scorecard.repo_path}\n", "dim"),
        (f"Files:    {scorecard.files_scanned}   Findings: {scorecard.total_findings}\n", "dim"),
    )
    console.print(Panel(Align.center(header_lines), border_style="cyan"))

    # --- Category table ---
    table = Table(title="Category Breakdown", show_header=True, header_style="bold")
    table.add_column("Category", style="bold", min_width=16)
    table.add_column("Score", justify="right", min_width=6)
    table.add_column("Bar", min_width=22)
    table.add_column("HIGH", justify="right", style="red")
    table.add_column("MED", justify="right", style="yellow")
    table.add_column("LOW", justify="right", style="dim")
    table.add_column("Grade", justify="center")

    for cat in scorecard.categories:
        if not cat.enabled:
            table.add_row(cat.name, "-", "[dim]N/A[/dim]", "-", "-", "-", "Skip")
            continue

        s = cat.score
        bar_filled = int(s / 100 * 20)
        bar_empty = 20 - bar_filled
        if s >= 90:
            bar_color = "green"
        elif s >= 80:
            bar_color = "yellow"
        elif s >= 70:
            bar_color = "dark_orange"
        else:
            bar_color = "red"
        bar_str = f"[{bar_color}]{'█' * bar_filled}[/{bar_color}][dim]{'░' * bar_empty}[/dim]"
        cat_grade = _letter_grade(s)

        table.add_row(
            cat.name,
            f"{s:.0f}",
            bar_str,
            str(cat.high_count),
            str(cat.medium_count),
            str(cat.low_count),
            cat_grade,
        )

    console.print(table)

    # --- Attack paths panel (conditional) ---
    if scorecard.attack_paths_count > 0:
        ap_text = Text.assemble(
            (f"  {scorecard.attack_paths_count} attack path(s) detected", "bold red"),
            ("  |  Worst severity: ", "dim"),
            (scorecard.worst_attack_severity, "bold red"),
            "\n",
            ("  Run ", "dim"),
            ("coyote scan --attack-paths", "bold cyan"),
            (" for details.", "dim"),
        )
        console.print(Panel(ap_text, title="Attack Paths", border_style="red"))

    # --- Footer ---
    console.print(Rule(style="dim"))
    grade_char = scorecard.letter_grade[0]
    advice = {
        "A": "[green]Excellent security posture.[/green]",
        "B": "[yellow]Good baseline — address HIGH findings.[/yellow]",
        "C": "[dark_orange]Moderate risk — review and remediate.[/dark_orange]",
        "D": "[red]Significant exposure — prioritize remediation.[/red]",
        "F": "[bold red]Critical issues — stop and remediate immediately.[/bold red]",
    }
    console.print(advice.get(grade_char, advice["F"]))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="coyote score",
        description="Generate a security scorecard with letter grade.",
    )
    parser.add_argument("--repo", default=".", help="Repository path (default: .)")
    parser.add_argument("--deps", action="store_true", help="Include dependency vulnerability scan")
    parser.add_argument("--deps-advisory-db", metavar="FILE", help="Local advisory DB for offline deps scanning")
    parser.add_argument("--history", action="store_true", help="Include git history scan")
    parser.add_argument("--history-depth", type=int, default=50, metavar="N", help="Max commits for history (default: 50)")
    parser.add_argument("--entropy", action="store_true", help="Enable entropy-based secret detection")
    parser.add_argument("--full", action="store_true", help="Enable all optional scans (--deps --history --entropy)")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output as JSON instead of Rich display")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``coyote score``."""
    parser = _build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    if args.full:
        args.deps = True
        args.history = True
        args.entropy = True

    repo_path = args.repo

    from rich.console import Console
    console = Console(stderr=True)

    # 1. Core scan
    from .scanner import run_scan
    with console.status("[bold cyan]Scanning repository..."):
        scan_result = run_scan(repo_path, enable_entropy=args.entropy)
    all_findings: list[PatternMatch] = list(scan_result.findings)

    # 2. Optional: dependency scan
    deps_findings: list[PatternMatch] = []
    if args.deps:
        from .deps import run_dependency_scan
        with console.status("[bold cyan]Scanning dependencies..."):
            deps_result = run_dependency_scan(
                repo_path,
                advisory_db_path=args.deps_advisory_db,
            )
        deps_findings = list(deps_result.findings)
        all_findings.extend(deps_findings)

    # 3. Optional: git history scan
    history_high = history_medium = history_low = history_total = 0
    if args.history:
        from .history import scan_history
        with console.status("[bold cyan]Scanning git history..."):
            hist_result = scan_history(repo_path, max_commits=args.history_depth)
        history_high = hist_result.high_count
        history_medium = hist_result.medium_count
        history_low = hist_result.low_count
        history_total = hist_result.total_count

    # 4. Attack path analysis
    with console.status("[bold cyan]Analyzing attack paths..."):
        ap_result = AttackPathAnalyzer().analyze(all_findings)

    critical_paths = sum(
        1 for p in ap_result.paths if p.escalated_severity == "CRITICAL"
    )

    # 5. Compute scorecard
    scorecard = compute_scorecard(
        repo_path=repo_path,
        findings=scan_result.findings,
        deps_enabled=args.deps,
        deps_findings=deps_findings,
        history_enabled=args.history,
        history_high=history_high,
        history_medium=history_medium,
        history_low=history_low,
        history_total=history_total,
        attack_paths_count=len(ap_result.paths),
        attack_paths_critical=critical_paths,
        worst_attack_severity=ap_result.worst_severity,
        files_scanned=scan_result.files_scanned,
    )

    # 6. Output
    if args.json_output:
        print(json.dumps(scorecard.to_dict(), indent=2))
    else:
        render_scorecard(scorecard)

    return 0
