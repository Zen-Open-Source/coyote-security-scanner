"""
Coyote - Security Scanner for Repositories and AI Agents

Usage:
    python3 -m coyote scan [OPTIONS]        # Scan a repository
    python3 -m coyote gate [OPTIONS]        # Run CI gate checks
    python3 -m coyote deps [OPTIONS]        # Scan dependencies for known CVEs
    python3 -m coyote sbom [OPTIONS]        # Generate CycloneDX SBOM
    python3 -m coyote score [OPTIONS]       # Security scorecard
    python3 -m coyote agent [SUBCOMMAND]    # Analyze AI agents
    python3 -m coyote vps [SUBCOMMAND]      # Audit VPS security posture
    python3 -m coyote --repo /path          # Legacy: same as 'scan --repo'
"""

from __future__ import annotations

import sys


def main():
    """Main entry point with subcommand routing."""
    # Check if using subcommand style or legacy style
    if len(sys.argv) > 1:
        subcommand = sys.argv[1]

        if subcommand == "scan":
            # Repository scanning mode
            sys.argv = [sys.argv[0]] + sys.argv[2:]  # Remove 'scan' from argv
            from .tui import main as scan_main
            scan_main()

        elif subcommand == "gate":
            # CI gate mode
            sys.argv = [sys.argv[0]] + sys.argv[2:]  # Remove 'gate' from argv
            from .gate import main as gate_main
            sys.exit(gate_main())

        elif subcommand == "deps":
            # Dependency vulnerability scanning mode
            sys.argv = [sys.argv[0]] + sys.argv[2:]  # Remove 'deps' from argv
            from .deps import main as deps_main
            sys.exit(deps_main())

        elif subcommand == "sbom":
            # CycloneDX SBOM generation mode
            sys.argv = [sys.argv[0]] + sys.argv[2:]  # Remove 'sbom' from argv
            from .sbom import main as sbom_main
            sys.exit(sbom_main())

        elif subcommand == "score":
            # Security scorecard mode
            sys.argv = [sys.argv[0]] + sys.argv[2:]  # Remove 'score' from argv
            from .score import main as score_main
            sys.exit(score_main())

        elif subcommand == "agent":
            # Agent security analysis mode
            sys.argv = [sys.argv[0]] + sys.argv[2:]  # Remove 'agent' from argv
            from .agents.__main__ import main as agent_main
            sys.exit(agent_main())

        elif subcommand == "vps":
            # VPS security audit mode
            sys.argv = [sys.argv[0]] + sys.argv[2:]  # Remove 'vps' from argv
            from .vps import main as vps_main
            sys.exit(vps_main())

        elif subcommand in ("--help", "-h"):
            print_help()
            sys.exit(0)

        elif subcommand == "--version":
            from . import __version__
            print(f"Coyote v{__version__}")
            sys.exit(0)

        else:
            # Legacy mode: assume it's repo scanning arguments
            from .tui import main as scan_main
            scan_main()
    else:
        # No arguments - show help
        print_help()
        sys.exit(0)


def print_help():
    """Print main help message."""
    from . import __version__

    help_text = f"""
Coyote v{__version__} - Security Scanner for Repositories and AI Agents

USAGE:
    python3 -m coyote <COMMAND> [OPTIONS]
    python3 -m coyote [LEGACY OPTIONS]

COMMANDS:
    scan        Scan a repository for security issues (secrets, credentials, etc.)
    gate        Run CI gate checks (scan + baseline diff + fail thresholds)
    deps        Scan dependency lockfiles/manifests for known vulnerabilities
    sbom        Generate a CycloneDX v1.5 JSON Software Bill of Materials
    score       Generate a security scorecard with letter grade
    agent       Analyze OpenClaw/Moltbot AI agents for security risks
    vps         Audit VPS hardening and exposure (SSH/firewall/ports/fail2ban)

LEGACY MODE:
    For backward compatibility, you can also run without a subcommand:
    python3 -m coyote --repo /path/to/repo [OPTIONS]

EXAMPLES:
    # Scan a repository
    python3 -m coyote scan --repo /path/to/repo
    python3 -m coyote scan --repo . --entropy --report

    # Run CI gate checks
    python3 -m coyote gate --repo . --fail-on high --sarif results.sarif

    # Scan dependency manifests for known vulnerabilities
    python3 -m coyote deps --repo .
    python3 -m coyote deps --repo . --fail-on high

    # Generate a CycloneDX SBOM
    python3 -m coyote sbom --repo .
    python3 -m coyote sbom --repo . --output bom.cdx.json --include-dev

    # Security scorecard
    python3 -m coyote score --repo .
    python3 -m coyote score --repo . --full

    # Analyze an AI agent
    python3 -m coyote agent analyze ./my-agent.json
    python3 -m coyote agent diff my-agent-id
    python3 -m coyote agent policy my-agent-id --strict

    # Audit local VPS security posture
    python3 -m coyote vps audit --local

    # Legacy (equivalent to 'scan')
    python3 -m coyote --repo /path/to/repo --diff --fail-on-new

Run 'python3 -m coyote <COMMAND> --help' for more information on a command.
"""
    print(help_text)


if __name__ == "__main__":
    main()
