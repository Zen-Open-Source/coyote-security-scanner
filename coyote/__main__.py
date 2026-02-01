"""
Coyote - Security Scanner for Repositories and AI Agents

Usage:
    python3 -m coyote scan [OPTIONS]        # Scan a repository
    python3 -m coyote agent [SUBCOMMAND]    # Analyze AI agents
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

        elif subcommand == "agent":
            # Agent security analysis mode
            sys.argv = [sys.argv[0]] + sys.argv[2:]  # Remove 'agent' from argv
            from .agents.__main__ import main as agent_main
            sys.exit(agent_main())

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
    agent       Analyze OpenClaw/Moltbot AI agents for security risks

LEGACY MODE:
    For backward compatibility, you can also run without a subcommand:
    python3 -m coyote --repo /path/to/repo [OPTIONS]

EXAMPLES:
    # Scan a repository
    python3 -m coyote scan --repo /path/to/repo
    python3 -m coyote scan --repo . --entropy --report

    # Analyze an AI agent
    python3 -m coyote agent analyze ./my-agent.json
    python3 -m coyote agent diff my-agent-id
    python3 -m coyote agent policy my-agent-id --strict

    # Legacy (equivalent to 'scan')
    python3 -m coyote --repo /path/to/repo --diff --fail-on-new

Run 'python3 -m coyote <COMMAND> --help' for more information on a command.
"""
    print(help_text)


if __name__ == "__main__":
    main()
