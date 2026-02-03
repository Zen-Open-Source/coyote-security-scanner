"""
Moltsec CLI - Agent Security Analysis Tool

Usage:
    python -m moltsec analyze <agent_path>
    python -m moltsec diff <agent_id>
    python -m moltsec policy <agent_id> [--strict|--permissive]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import (
    PermissionTracker,
    analyze_agent,
    analyze_agent_file,
)
from .output import (
    DiffReportGenerator,
    OpenClawReportGenerator,
    SafetySummaryGenerator,
    generate_intake_warning,
    generate_update_warning,
)
from .openclaw import OpenClawSecurityAnalyzer


def cmd_analyze(args: argparse.Namespace) -> int:
    """Analyze an agent and show safety summary."""
    path = Path(args.path)

    if not path.exists():
        print(f"Error: Path not found: {path}", file=sys.stderr)
        return 1

    try:
        manifest = analyze_agent_file(path)
    except Exception as e:
        print(f"Error analyzing agent: {e}", file=sys.stderr)
        return 1

    # Generate output
    generator = SafetySummaryGenerator()

    if args.format == "text":
        print(generator.generate_text_summary(manifest))
    elif args.format == "markdown":
        print(generator.generate_markdown_summary(manifest))
    elif args.format == "json":
        print(generator.generate_json_summary(manifest))
    elif args.format == "compact":
        print(generator.generate_compact_summary(manifest))

    # Show warning if warranted
    warning = generate_intake_warning(manifest)
    if warning and args.format != "json":
        print("\n" + "!" * 60)
        print("WARNING")
        print("!" * 60)
        print(warning)

    # Register with tracker if requested
    if args.register:
        tracker = PermissionTracker()
        saved_path, diff = tracker.register_agent(manifest)
        print(f"\nManifest saved: {saved_path}")

        if diff and diff.has_changes:
            print("\nChanges from previous version:")
            diff_gen = DiffReportGenerator()
            print(diff_gen.generate_compact_diff(diff))

            update_warning = generate_update_warning(diff)
            if update_warning:
                print(f"\n{update_warning}")

    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    """Show permission diff for an agent."""
    tracker = PermissionTracker()

    diff = tracker.get_agent_diff(
        args.agent_id,
        from_version=args.from_version,
        to_version=args.to_version,
    )

    if diff is None:
        print(f"No diff available for agent: {args.agent_id}")
        print("(Need at least 2 versions to compare)")
        return 1

    generator = DiffReportGenerator()

    if args.format == "text":
        print(generator.generate_text_diff(diff))
    elif args.format == "markdown":
        print(generator.generate_markdown_diff(diff))
    elif args.format == "json":
        print(json.dumps(diff.to_dict(), indent=2))
    elif args.format == "compact":
        print(generator.generate_compact_diff(diff))

    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    """Generate security policy for an agent."""
    tracker = PermissionTracker()

    strictness = "strict" if args.strict else "permissive" if args.permissive else "normal"

    if args.output:
        output_path = tracker.save_policy(args.agent_id, args.output, strictness)
        if output_path:
            print(f"Policy saved: {output_path}")
            return 0
        else:
            print(f"Error: Agent not found: {args.agent_id}")
            return 1
    else:
        policy = tracker.generate_policy(args.agent_id, strictness)
        if policy:
            print(json.dumps(policy.to_dict(), indent=2))
            return 0
        else:
            print(f"Error: Agent not found: {args.agent_id}")
            return 1


def cmd_secure_openclaw(args: argparse.Namespace) -> int:
    """Run OpenClaw-specific security checks."""
    path = Path(args.path)

    if not path.exists():
        print(f"Error: Path not found: {path}", file=sys.stderr)
        return 1

    try:
        analyzer = OpenClawSecurityAnalyzer()
        report = analyzer.analyze(str(path))
    except Exception as e:
        print(f"Error analyzing OpenClaw installation: {e}", file=sys.stderr)
        return 1

    generator = OpenClawReportGenerator()

    if args.format == "text":
        print(generator.generate_text_report(report, show_fix=args.fix))
    elif args.format == "json":
        print(generator.generate_json_report(report))
    elif args.format == "markdown":
        print(generator.generate_markdown_report(report, show_fix=args.fix))

    return 0


def cmd_list(args: argparse.Namespace) -> int:
    """List tracked agents."""
    from .tracker import ManifestStore

    store = ManifestStore()

    agents_dir = store.manifests_dir
    if not agents_dir.exists():
        print("No agents tracked yet.")
        return 0

    generator = SafetySummaryGenerator()

    for agent_dir in agents_dir.iterdir():
        if not agent_dir.is_dir():
            continue

        manifest = store.get_latest_manifest(agent_dir.name)
        if manifest:
            print(generator.generate_compact_summary(manifest))

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Moltsec - Agent Security Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Analyze an agent:
    python -m moltsec analyze ./agents/my-agent.json

  Show permission diff:
    python -m moltsec diff my-agent-id

  Generate policy file:
    python -m moltsec policy my-agent-id --output policy.json --strict

  List tracked agents:
    python -m moltsec list
""",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # analyze command
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze an agent and show safety summary",
    )
    analyze_parser.add_argument("path", help="Path to agent config file or directory")
    analyze_parser.add_argument(
        "--format", "-f",
        choices=["text", "markdown", "json", "compact"],
        default="text",
        help="Output format (default: text)",
    )
    analyze_parser.add_argument(
        "--register", "-r",
        action="store_true",
        help="Register the agent with the permission tracker",
    )
    analyze_parser.set_defaults(func=cmd_analyze)

    # diff command
    diff_parser = subparsers.add_parser(
        "diff",
        help="Show permission changes between versions",
    )
    diff_parser.add_argument("agent_id", help="Agent ID to show diff for")
    diff_parser.add_argument(
        "--from", dest="from_version",
        help="Starting version (default: second-to-last)",
    )
    diff_parser.add_argument(
        "--to", dest="to_version",
        help="Ending version (default: latest)",
    )
    diff_parser.add_argument(
        "--format", "-f",
        choices=["text", "markdown", "json", "compact"],
        default="text",
        help="Output format (default: text)",
    )
    diff_parser.set_defaults(func=cmd_diff)

    # policy command
    policy_parser = subparsers.add_parser(
        "policy",
        help="Generate runtime security policy",
    )
    policy_parser.add_argument("agent_id", help="Agent ID")
    policy_parser.add_argument(
        "--output", "-o",
        help="Output file path (default: stdout)",
    )
    policy_parser.add_argument(
        "--strict",
        action="store_true",
        help="Use strict policy (more prompts)",
    )
    policy_parser.add_argument(
        "--permissive",
        action="store_true",
        help="Use permissive policy (fewer prompts)",
    )
    policy_parser.set_defaults(func=cmd_policy)

    # secure-openclaw command
    openclaw_parser = subparsers.add_parser(
        "secure-openclaw",
        help="Run OpenClaw-specific security checks (CVE-2026-25253 and hardening)",
    )
    openclaw_parser.add_argument("path", help="Path to OpenClaw installation, config directory, or config file")
    openclaw_parser.add_argument(
        "--format", "-f",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format (default: text)",
    )
    openclaw_parser.add_argument(
        "--fix",
        action="store_true",
        help="Show detailed remediation steps for each finding",
    )
    openclaw_parser.set_defaults(func=cmd_secure_openclaw)

    # list command
    list_parser = subparsers.add_parser(
        "list",
        help="List tracked agents",
    )
    list_parser.set_defaults(func=cmd_list)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
