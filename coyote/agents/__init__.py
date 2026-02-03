"""
Coyote Agent Security - Analysis for OpenClaw/Moltbot Agents

This subpackage provides security analysis for AI agents:
- Static analysis of agent configs, prompts, and tools
- Capability manifest generation
- Permission tracking and diffing
- Runtime guardrails
- User-facing safety reports

Usage:
    from coyote.agents import analyze_agent, PermissionTracker

    # Analyze an agent
    manifest = analyze_agent(
        agent_id="my-agent",
        config={"name": "My Agent", ...},
        prompt="You are a helpful assistant...",
        tools=[{"name": "read_file", ...}]
    )

    # Get safety summary
    from coyote.agents import SafetySummaryGenerator
    summary = SafetySummaryGenerator().generate_text_summary(manifest)
    print(summary)
"""

from __future__ import annotations

__version__ = "0.1.0"

from .analyzer import AgentAnalyzer, analyze_agent_file
from .models import (
    AgentMetadata,
    AgentPolicy,
    Capability,
    CapabilityCategory,
    CapabilityDiff,
    CapabilityManifest,
    PolicyRule,
    RiskLevel,
    RuntimeAction,
)
from .tracker import ManifestStore, PermissionDiffer, PermissionTracker, PolicyGenerator
from .runtime import ActionLogger, BehaviorDriftDetector, RuntimeGuard
from .openclaw import OpenClawSecurityAnalyzer, OpenClawSecurityCheck, OpenClawSecurityReport
from .output import (
    DiffReportGenerator,
    OpenClawReportGenerator,
    SafetySummaryGenerator,
    generate_intake_warning,
    generate_update_warning,
)


def analyze_agent(
    agent_id: str,
    config: dict,
    prompt: str = "",
    tools: list[dict] | None = None,
    use_llm: bool = False,
) -> CapabilityManifest:
    """
    Analyze an agent and produce a capability manifest.

    This is the main entry point for agent analysis.

    Args:
        agent_id: Unique identifier for the agent
        config: Agent configuration dictionary
        prompt: System prompt text
        tools: List of tool definitions
        use_llm: Whether to use LLM for ambiguous analysis

    Returns:
        CapabilityManifest with all detected capabilities
    """
    analyzer = AgentAnalyzer(use_llm=use_llm)
    return analyzer.analyze_agent(agent_id, config, prompt, tools)


__all__ = [
    # Version
    "__version__",
    # Main function
    "analyze_agent",
    "analyze_agent_file",
    # Models
    "AgentMetadata",
    "AgentPolicy",
    "Capability",
    "CapabilityCategory",
    "CapabilityDiff",
    "CapabilityManifest",
    "PolicyRule",
    "RiskLevel",
    "RuntimeAction",
    # Analyzer
    "AgentAnalyzer",
    # Tracker
    "ManifestStore",
    "PermissionDiffer",
    "PermissionTracker",
    "PolicyGenerator",
    # Runtime
    "ActionLogger",
    "BehaviorDriftDetector",
    "RuntimeGuard",
    # OpenClaw
    "OpenClawSecurityAnalyzer",
    "OpenClawSecurityCheck",
    "OpenClawSecurityReport",
    # Output
    "DiffReportGenerator",
    "OpenClawReportGenerator",
    "SafetySummaryGenerator",
    "generate_intake_warning",
    "generate_update_warning",
]
