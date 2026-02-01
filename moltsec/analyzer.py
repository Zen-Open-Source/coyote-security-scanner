"""
Moltbot Agent Security - Static Analyzer

Analyzes agent configs, prompts, and tool definitions to extract
capability manifests. Uses deterministic pattern matching first,
with optional LLM analysis for ambiguous cases.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import (
    AgentMetadata,
    Capability,
    CapabilityCategory,
    CapabilityManifest,
    RiskLevel,
)


# =============================================================================
# Pattern Definitions
# =============================================================================

@dataclass
class CapabilityPattern:
    """A pattern that indicates a capability."""
    pattern: re.Pattern
    category: CapabilityCategory
    risk_level: RiskLevel
    description_template: str
    risk_reason: str
    scope_extractor: str | None = None  # Regex group name for scope


# File access patterns (in configs and prompts)
FILE_ACCESS_PATTERNS = [
    # Explicit file path patterns
    CapabilityPattern(
        pattern=re.compile(r'(?:read|access|open|load).*?["\']?(~/\.ssh/[^"\'\s]*)["\']?', re.I),
        category=CapabilityCategory.FILE_READ,
        risk_level=RiskLevel.CRITICAL,
        description_template="Read SSH keys and config",
        risk_reason="SSH keys provide authentication to remote systems",
    ),
    CapabilityPattern(
        pattern=re.compile(r'(?:read|access|open|load).*?["\']?(~/\.aws/[^"\'\s]*)["\']?', re.I),
        category=CapabilityCategory.FILE_READ,
        risk_level=RiskLevel.CRITICAL,
        description_template="Read AWS credentials",
        risk_reason="AWS credentials can access cloud infrastructure",
    ),
    CapabilityPattern(
        pattern=re.compile(r'(?:read|access|open|load).*?["\']?(~/\.kube/[^"\'\s]*)["\']?', re.I),
        category=CapabilityCategory.FILE_READ,
        risk_level=RiskLevel.CRITICAL,
        description_template="Read Kubernetes config",
        risk_reason="Kube config provides cluster access",
    ),
    CapabilityPattern(
        pattern=re.compile(r'(?:read|access|open|load).*?["\']?(/etc/passwd|/etc/shadow)["\']?', re.I),
        category=CapabilityCategory.FILE_READ,
        risk_level=RiskLevel.HIGH,
        description_template="Read system user database",
        risk_reason="Contains user account information",
    ),
    CapabilityPattern(
        pattern=re.compile(r'(?:read|access|open|load).*?\.env(?:\.local|\.prod|\.dev)?', re.I),
        category=CapabilityCategory.FILE_READ,
        risk_level=RiskLevel.HIGH,
        description_template="Read environment files",
        risk_reason="Environment files often contain secrets",
    ),
    CapabilityPattern(
        pattern=re.compile(r'(?:read|access|open|load).*?(?:password|secret|credential|token|key).*?(?:file|\.txt|\.json|\.yaml)', re.I),
        category=CapabilityCategory.FILE_READ,
        risk_level=RiskLevel.HIGH,
        description_template="Read potential secret files",
        risk_reason="Filename suggests sensitive content",
    ),
    CapabilityPattern(
        pattern=re.compile(r'(?:read|access|open|load).*?browser.*?(?:history|cookie|password|bookmark)', re.I),
        category=CapabilityCategory.BROWSER_ACCESS,
        risk_level=RiskLevel.CRITICAL,
        description_template="Access browser data",
        risk_reason="Browser data contains passwords and browsing history",
    ),
    # File write patterns
    CapabilityPattern(
        pattern=re.compile(r'(?:write|save|create|modify|edit|append).*?(?:file|document)', re.I),
        category=CapabilityCategory.FILE_WRITE,
        risk_level=RiskLevel.MEDIUM,
        description_template="Write to files",
        risk_reason="Can modify or create files on disk",
    ),
    CapabilityPattern(
        pattern=re.compile(r'(?:write|modify).*?(?:~/.bashrc|~/.zshrc|~/.profile|/etc/)', re.I),
        category=CapabilityCategory.FILE_WRITE,
        risk_level=RiskLevel.CRITICAL,
        description_template="Modify system/shell config",
        risk_reason="Can alter shell behavior or system config",
    ),
]

# Network access patterns
NETWORK_PATTERNS = [
    CapabilityPattern(
        pattern=re.compile(r'(?:fetch|request|call|http|curl|wget|post|get).*?(?:https?://[^\s"\']+)', re.I),
        category=CapabilityCategory.NETWORK_OUTBOUND,
        risk_level=RiskLevel.MEDIUM,
        description_template="Make HTTP requests",
        risk_reason="Can send data to external servers",
    ),
    CapabilityPattern(
        pattern=re.compile(r'(?:webhook|callback|notify).*?(?:url|endpoint)', re.I),
        category=CapabilityCategory.NETWORK_OUTBOUND,
        risk_level=RiskLevel.HIGH,
        description_template="Send webhooks to external URLs",
        risk_reason="Can exfiltrate data via webhooks",
    ),
    CapabilityPattern(
        pattern=re.compile(r'websocket|wss?://', re.I),
        category=CapabilityCategory.NETWORK_OUTBOUND,
        risk_level=RiskLevel.HIGH,
        description_template="WebSocket connections",
        risk_reason="Persistent connection for real-time data transfer",
    ),
    CapabilityPattern(
        pattern=re.compile(r'(?:listen|server|bind|accept).*?(?:port|socket|connection)', re.I),
        category=CapabilityCategory.NETWORK_INBOUND,
        risk_level=RiskLevel.HIGH,
        description_template="Accept incoming connections",
        risk_reason="Can receive commands from external sources",
    ),
]

# Process/code execution patterns
EXECUTION_PATTERNS = [
    CapabilityPattern(
        pattern=re.compile(r'(?:exec|spawn|run|shell|subprocess|system|popen)\s*\(', re.I),
        category=CapabilityCategory.PROCESS_SPAWN,
        risk_level=RiskLevel.HIGH,
        description_template="Execute shell commands",
        risk_reason="Can run arbitrary system commands",
    ),
    CapabilityPattern(
        pattern=re.compile(r'(?:bash|sh|zsh|cmd|powershell)\s+', re.I),
        category=CapabilityCategory.PROCESS_SPAWN,
        risk_level=RiskLevel.HIGH,
        description_template="Invoke shell directly",
        risk_reason="Direct shell access enables arbitrary command execution",
    ),
    CapabilityPattern(
        pattern=re.compile(r'(?:eval|exec)\s*\(.*?\)', re.I),
        category=CapabilityCategory.CODE_EXECUTION,
        risk_level=RiskLevel.CRITICAL,
        description_template="Dynamic code execution",
        risk_reason="Can execute arbitrary code at runtime",
    ),
    CapabilityPattern(
        pattern=re.compile(r'(?:import|require|load).*?(?:dynamic|url|remote)', re.I),
        category=CapabilityCategory.CODE_EXECUTION,
        risk_level=RiskLevel.CRITICAL,
        description_template="Load remote code",
        risk_reason="Can download and execute code from internet",
    ),
]

# Self-modification patterns
SELF_MOD_PATTERNS = [
    CapabilityPattern(
        pattern=re.compile(r'(?:update|modify|change|rewrite).*?(?:self|own|this).*?(?:prompt|config|instruction)', re.I),
        category=CapabilityCategory.SELF_MODIFICATION,
        risk_level=RiskLevel.CRITICAL,
        description_template="Self-modify prompts or config",
        risk_reason="Agent can change its own behavior",
    ),
    CapabilityPattern(
        pattern=re.compile(r'(?:download|fetch|pull).*?(?:update|new version|latest)', re.I),
        category=CapabilityCategory.SELF_MODIFICATION,
        risk_level=RiskLevel.HIGH,
        description_template="Download updates",
        risk_reason="Can pull new code that changes behavior",
    ),
]

# Agent spawning patterns
AGENT_PATTERNS = [
    CapabilityPattern(
        pattern=re.compile(r'(?:spawn|create|start|invoke|call).*?(?:agent|assistant|bot)', re.I),
        category=CapabilityCategory.AGENT_SPAWNING,
        risk_level=RiskLevel.HIGH,
        description_template="Spawn other agents",
        risk_reason="Can create agents that may have different permissions",
    ),
    CapabilityPattern(
        pattern=re.compile(r'(?:delegate|hand.?off|transfer).*?(?:task|request|action)', re.I),
        category=CapabilityCategory.AGENT_SPAWNING,
        risk_level=RiskLevel.MEDIUM,
        description_template="Delegate to other agents",
        risk_reason="Tasks may be handled by agents with different trust levels",
    ),
]

# Secret access patterns
SECRET_PATTERNS = [
    CapabilityPattern(
        pattern=re.compile(r'(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)', re.I),
        category=CapabilityCategory.SECRET_ACCESS,
        risk_level=RiskLevel.HIGH,
        description_template="Access API keys/tokens",
        risk_reason="Can use stored credentials",
    ),
    CapabilityPattern(
        pattern=re.compile(r'(?:password|credential|secret).*?(?:get|read|access|use)', re.I),
        category=CapabilityCategory.SECRET_ACCESS,
        risk_level=RiskLevel.HIGH,
        description_template="Access stored secrets",
        risk_reason="Can read stored passwords/credentials",
    ),
    CapabilityPattern(
        pattern=re.compile(r'(?:keychain|credential.?manager|vault|secrets?.?store)', re.I),
        category=CapabilityCategory.SECRET_ACCESS,
        risk_level=RiskLevel.CRITICAL,
        description_template="Access system credential store",
        risk_reason="Can access all stored system credentials",
    ),
]

# Clipboard access
CLIPBOARD_PATTERNS = [
    CapabilityPattern(
        pattern=re.compile(r'(?:clipboard|pasteboard|copy|paste)', re.I),
        category=CapabilityCategory.CLIPBOARD_ACCESS,
        risk_level=RiskLevel.MEDIUM,
        description_template="Access clipboard",
        risk_reason="Can read/write clipboard (may contain sensitive data)",
    ),
]

ALL_PATTERNS = (
    FILE_ACCESS_PATTERNS +
    NETWORK_PATTERNS +
    EXECUTION_PATTERNS +
    SELF_MOD_PATTERNS +
    AGENT_PATTERNS +
    SECRET_PATTERNS +
    CLIPBOARD_PATTERNS
)


# =============================================================================
# Tool Definitions Analysis
# =============================================================================

# Known tool categories and their inherent risks
KNOWN_TOOLS = {
    # File tools
    "read_file": (CapabilityCategory.FILE_READ, RiskLevel.MEDIUM, "Read arbitrary files"),
    "write_file": (CapabilityCategory.FILE_WRITE, RiskLevel.MEDIUM, "Write arbitrary files"),
    "list_directory": (CapabilityCategory.FILE_READ, RiskLevel.LOW, "List directory contents"),
    "delete_file": (CapabilityCategory.FILE_WRITE, RiskLevel.HIGH, "Delete files"),

    # Network tools
    "http_request": (CapabilityCategory.NETWORK_OUTBOUND, RiskLevel.MEDIUM, "Make HTTP requests"),
    "fetch": (CapabilityCategory.NETWORK_OUTBOUND, RiskLevel.MEDIUM, "Fetch remote content"),
    "web_search": (CapabilityCategory.NETWORK_OUTBOUND, RiskLevel.LOW, "Search the web"),
    "send_email": (CapabilityCategory.NETWORK_OUTBOUND, RiskLevel.HIGH, "Send emails"),
    "webhook": (CapabilityCategory.NETWORK_OUTBOUND, RiskLevel.HIGH, "Call webhooks"),

    # Execution tools
    "bash": (CapabilityCategory.PROCESS_SPAWN, RiskLevel.CRITICAL, "Execute shell commands"),
    "shell": (CapabilityCategory.PROCESS_SPAWN, RiskLevel.CRITICAL, "Execute shell commands"),
    "execute": (CapabilityCategory.PROCESS_SPAWN, RiskLevel.CRITICAL, "Execute arbitrary commands"),
    "python": (CapabilityCategory.CODE_EXECUTION, RiskLevel.CRITICAL, "Execute Python code"),
    "javascript": (CapabilityCategory.CODE_EXECUTION, RiskLevel.CRITICAL, "Execute JavaScript code"),
    "eval": (CapabilityCategory.CODE_EXECUTION, RiskLevel.CRITICAL, "Evaluate code dynamically"),

    # Agent tools
    "spawn_agent": (CapabilityCategory.AGENT_SPAWNING, RiskLevel.HIGH, "Create new agents"),
    "delegate": (CapabilityCategory.AGENT_SPAWNING, RiskLevel.MEDIUM, "Delegate to other agents"),

    # Browser tools
    "browser": (CapabilityCategory.BROWSER_ACCESS, RiskLevel.HIGH, "Control web browser"),
    "screenshot": (CapabilityCategory.BROWSER_ACCESS, RiskLevel.MEDIUM, "Take screenshots"),

    # System tools
    "clipboard": (CapabilityCategory.CLIPBOARD_ACCESS, RiskLevel.MEDIUM, "Access clipboard"),
    "system_info": (CapabilityCategory.SYSTEM_INFO, RiskLevel.LOW, "Read system information"),
}


# =============================================================================
# Analyzer Implementation
# =============================================================================

class AgentAnalyzer:
    """
    Static analyzer for Moltbot agent configurations.

    Extracts capabilities from:
    - Agent config files (JSON/YAML)
    - System prompts
    - Tool definitions
    """

    def __init__(self, use_llm: bool = False):
        """
        Initialize the analyzer.

        Args:
            use_llm: Whether to use LLM for ambiguous analysis.
                     When False, only deterministic pattern matching is used.
        """
        self.use_llm = use_llm
        self.warnings: list[str] = []

    def analyze_agent(
        self,
        agent_id: str,
        config: dict[str, Any],
        prompt: str = "",
        tools: list[dict[str, Any]] | None = None,
    ) -> CapabilityManifest:
        """
        Analyze an agent and produce a capability manifest.

        Args:
            agent_id: Unique identifier for the agent
            config: Agent configuration dictionary
            prompt: System prompt text
            tools: List of tool definitions

        Returns:
            CapabilityManifest with all detected capabilities
        """
        self.warnings = []
        capabilities: list[Capability] = []

        # Compute content hashes
        config_hash = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()[:16]
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:16]
        tools_hash = hashlib.sha256(json.dumps(tools or [], sort_keys=True).encode()).hexdigest()[:16]

        # Extract metadata
        metadata = self._extract_metadata(agent_id, config)

        # Analyze each source
        capabilities.extend(self._analyze_config(config))
        capabilities.extend(self._analyze_prompt(prompt))
        capabilities.extend(self._analyze_tools(tools or []))

        # Deduplicate capabilities
        capabilities = self._deduplicate_capabilities(capabilities)

        # Create manifest
        manifest = CapabilityManifest(
            metadata=metadata,
            capabilities=capabilities,
            analysis_warnings=self.warnings,
        )
        manifest.config_hash = config_hash
        manifest.prompt_hash = prompt_hash
        manifest.tools_hash = tools_hash

        return manifest

    def _extract_metadata(self, agent_id: str, config: dict[str, Any]) -> AgentMetadata:
        """Extract agent metadata from config."""
        return AgentMetadata(
            agent_id=agent_id,
            name=config.get("name", "Unknown Agent"),
            version=config.get("version", "0.0.0"),
            author=config.get("author", "Unknown"),
            source_url=config.get("source_url", ""),
            description=config.get("description", ""),
        )

    def _analyze_config(self, config: dict[str, Any]) -> list[Capability]:
        """Analyze agent config for capabilities."""
        capabilities: list[Capability] = []

        # Check for explicit permissions/capabilities section
        if "permissions" in config:
            capabilities.extend(self._parse_permissions(config["permissions"]))

        if "capabilities" in config:
            capabilities.extend(self._parse_declared_capabilities(config["capabilities"]))

        # Check for tool references in config
        if "tools" in config and isinstance(config["tools"], list):
            for tool_ref in config["tools"]:
                if isinstance(tool_ref, str):
                    cap = self._capability_from_tool_name(tool_ref, "config.tools")
                    if cap:
                        capabilities.append(cap)

        # Check for network endpoints
        if "endpoints" in config or "webhooks" in config:
            endpoints = config.get("endpoints", {})
            webhooks = config.get("webhooks", {})
            for name, url in {**endpoints, **webhooks}.items():
                capabilities.append(Capability(
                    category=CapabilityCategory.NETWORK_OUTBOUND,
                    description=f"Connect to {name}",
                    scope=str(url),
                    risk_level=RiskLevel.MEDIUM,
                    risk_reason="Configured external endpoint",
                    source=f"config.endpoints.{name}",
                ))

        # Scan config text for patterns
        config_text = json.dumps(config)
        capabilities.extend(self._scan_text_for_patterns(config_text, "config"))

        return capabilities

    def _analyze_prompt(self, prompt: str) -> list[Capability]:
        """Analyze system prompt for implied capabilities."""
        if not prompt:
            return []

        capabilities: list[Capability] = []

        # Scan for capability patterns
        capabilities.extend(self._scan_text_for_patterns(prompt, "prompt"))

        # Check for concerning prompt patterns
        concerning_patterns = [
            (r"ignore.*(?:previous|prior|above).*(?:instruction|rule|guideline)", "prompt injection resistance bypass"),
            (r"you\s+(?:can|may|should)\s+(?:always|never).*(?:ignore|bypass|override)", "rule override capability"),
            (r"(?:pretend|act|imagine).*(?:no|without).*(?:restriction|limit|rule)", "restriction bypass"),
        ]

        for pattern, description in concerning_patterns:
            if re.search(pattern, prompt, re.I):
                self.warnings.append(f"Prompt contains concerning pattern: {description}")

        return capabilities

    def _analyze_tools(self, tools: list[dict[str, Any]]) -> list[Capability]:
        """Analyze tool definitions for capabilities."""
        capabilities: list[Capability] = []

        for tool in tools:
            tool_name = tool.get("name", tool.get("function", {}).get("name", ""))
            tool_desc = tool.get("description", tool.get("function", {}).get("description", ""))

            # Check known tools
            cap = self._capability_from_tool_name(tool_name, f"tools.{tool_name}")
            if cap:
                capabilities.append(cap)
            else:
                # Unknown tool - infer from description
                inferred = self._infer_tool_capability(tool_name, tool_desc)
                if inferred:
                    capabilities.append(inferred)
                else:
                    self.warnings.append(f"Unknown tool with unclear capability: {tool_name}")

            # Scan tool description for patterns
            if tool_desc:
                capabilities.extend(self._scan_text_for_patterns(tool_desc, f"tools.{tool_name}.description"))

            # Check tool parameters for concerning patterns
            params = tool.get("parameters", tool.get("function", {}).get("parameters", {}))
            if params:
                param_text = json.dumps(params)
                capabilities.extend(self._scan_text_for_patterns(param_text, f"tools.{tool_name}.parameters"))

        return capabilities

    def _scan_text_for_patterns(self, text: str, source: str) -> list[Capability]:
        """Scan text for capability patterns."""
        capabilities: list[Capability] = []

        for cap_pattern in ALL_PATTERNS:
            matches = cap_pattern.pattern.finditer(text)
            for match in matches:
                scope = match.group(1) if match.groups() else match.group(0)
                capabilities.append(Capability(
                    category=cap_pattern.category,
                    description=cap_pattern.description_template,
                    scope=scope[:200],  # Limit scope length
                    risk_level=cap_pattern.risk_level,
                    risk_reason=cap_pattern.risk_reason,
                    source=source,
                ))

        return capabilities

    def _capability_from_tool_name(self, tool_name: str, source: str) -> Capability | None:
        """Create capability from known tool name."""
        # Normalize tool name
        normalized = tool_name.lower().replace("-", "_").replace(" ", "_")

        if normalized in KNOWN_TOOLS:
            category, risk, desc = KNOWN_TOOLS[normalized]
            return Capability(
                category=category,
                description=desc,
                scope=tool_name,
                risk_level=risk,
                risk_reason=f"Tool '{tool_name}' has known risk profile",
                source=source,
            )

        # Check for partial matches
        for known_name, (category, risk, desc) in KNOWN_TOOLS.items():
            if known_name in normalized or normalized in known_name:
                return Capability(
                    category=category,
                    description=desc,
                    scope=tool_name,
                    risk_level=risk,
                    risk_reason=f"Tool '{tool_name}' matches known pattern",
                    source=source,
                    confidence=0.7,
                )

        return None

    def _infer_tool_capability(self, name: str, description: str) -> Capability | None:
        """Infer capability from tool name and description when not in known list."""
        text = f"{name} {description}".lower()

        # Simple keyword matching
        inferences = [
            (["file", "read", "open", "load"], CapabilityCategory.FILE_READ, RiskLevel.MEDIUM),
            (["file", "write", "save", "create"], CapabilityCategory.FILE_WRITE, RiskLevel.MEDIUM),
            (["http", "fetch", "request", "api", "url"], CapabilityCategory.NETWORK_OUTBOUND, RiskLevel.MEDIUM),
            (["exec", "run", "command", "shell", "bash"], CapabilityCategory.PROCESS_SPAWN, RiskLevel.HIGH),
            (["eval", "code", "script"], CapabilityCategory.CODE_EXECUTION, RiskLevel.HIGH),
            (["agent", "spawn", "delegate"], CapabilityCategory.AGENT_SPAWNING, RiskLevel.MEDIUM),
        ]

        for keywords, category, risk in inferences:
            if any(kw in text for kw in keywords):
                return Capability(
                    category=category,
                    description=f"Tool: {name}",
                    scope=name,
                    risk_level=risk,
                    risk_reason="Inferred from tool name/description",
                    source=f"tools.{name}",
                    confidence=0.5,
                )

        return None

    def _parse_permissions(self, permissions: dict[str, Any] | list[str]) -> list[Capability]:
        """Parse explicit permissions section."""
        capabilities: list[Capability] = []

        if isinstance(permissions, list):
            for perm in permissions:
                cap = self._parse_permission_string(perm)
                if cap:
                    capabilities.append(cap)
        elif isinstance(permissions, dict):
            for category, scopes in permissions.items():
                caps = self._parse_permission_dict(category, scopes)
                capabilities.extend(caps)

        return capabilities

    def _parse_permission_string(self, perm: str) -> Capability | None:
        """Parse a permission string like 'file:read:~/.ssh/*'."""
        parts = perm.split(":")
        if len(parts) < 2:
            return None

        category_map = {
            "file": {
                "read": CapabilityCategory.FILE_READ,
                "write": CapabilityCategory.FILE_WRITE,
            },
            "network": {
                "outbound": CapabilityCategory.NETWORK_OUTBOUND,
                "inbound": CapabilityCategory.NETWORK_INBOUND,
            },
            "process": {
                "spawn": CapabilityCategory.PROCESS_SPAWN,
                "exec": CapabilityCategory.PROCESS_SPAWN,
            },
        }

        cat_group = parts[0].lower()
        action = parts[1].lower() if len(parts) > 1 else "any"
        scope = parts[2] if len(parts) > 2 else "*"

        if cat_group in category_map and action in category_map[cat_group]:
            category = category_map[cat_group][action]
            risk = self._assess_scope_risk(category, scope)
            return Capability(
                category=category,
                description=f"{cat_group} {action} permission",
                scope=scope,
                risk_level=risk,
                risk_reason="Explicitly declared permission",
                source="config.permissions",
            )

        return None

    def _parse_permission_dict(self, category: str, scopes: Any) -> list[Capability]:
        """Parse permission dict entry."""
        capabilities: list[Capability] = []
        category_map = {
            "file_read": CapabilityCategory.FILE_READ,
            "file_write": CapabilityCategory.FILE_WRITE,
            "network": CapabilityCategory.NETWORK_OUTBOUND,
            "process": CapabilityCategory.PROCESS_SPAWN,
            "tools": CapabilityCategory.TOOL_INVOCATION,
        }

        if category.lower() not in category_map:
            return capabilities

        cat = category_map[category.lower()]
        scope_list = scopes if isinstance(scopes, list) else [scopes]

        for scope in scope_list:
            risk = self._assess_scope_risk(cat, str(scope))
            capabilities.append(Capability(
                category=cat,
                description=f"Declared {category} capability",
                scope=str(scope),
                risk_level=risk,
                risk_reason="Explicitly declared in config",
                source=f"config.permissions.{category}",
            ))

        return capabilities

    def _parse_declared_capabilities(self, capabilities_section: Any) -> list[Capability]:
        """Parse capabilities section of config."""
        # Similar to permissions but with potentially different format
        return self._parse_permissions(capabilities_section)

    def _assess_scope_risk(self, category: CapabilityCategory, scope: str) -> RiskLevel:
        """Assess risk level based on capability scope."""
        scope_lower = scope.lower()

        # Critical paths
        critical_patterns = [".ssh", ".aws", ".kube", "/etc/shadow", "keychain", "credential"]
        if any(p in scope_lower for p in critical_patterns):
            return RiskLevel.CRITICAL

        # High risk paths
        high_patterns = [".env", "password", "secret", "token", "/etc/", "browser"]
        if any(p in scope_lower for p in high_patterns):
            return RiskLevel.HIGH

        # Wildcards are concerning
        if scope == "*" or scope == "**":
            return RiskLevel.HIGH

        # Code execution is always high
        if category in [CapabilityCategory.CODE_EXECUTION, CapabilityCategory.PROCESS_SPAWN]:
            return RiskLevel.HIGH

        return RiskLevel.MEDIUM

    def _deduplicate_capabilities(self, capabilities: list[Capability]) -> list[Capability]:
        """Remove duplicate capabilities, keeping highest confidence."""
        seen: dict[tuple, Capability] = {}

        for cap in capabilities:
            key = (cap.category, cap.scope)
            if key not in seen or cap.confidence > seen[key].confidence:
                seen[key] = cap

        return list(seen.values())


def analyze_agent_file(agent_path: Path | str, use_llm: bool = False) -> CapabilityManifest:
    """
    Convenience function to analyze an agent from a file path.

    Supports:
    - .json agent config files
    - Directories containing config.json + prompt.txt + tools.json
    """
    agent_path = Path(agent_path)
    analyzer = AgentAnalyzer(use_llm=use_llm)

    if agent_path.is_file():
        with open(agent_path) as f:
            config = json.load(f)
        prompt = config.pop("prompt", config.pop("system_prompt", ""))
        tools = config.pop("tools", [])
        agent_id = config.get("id", agent_path.stem)
    elif agent_path.is_dir():
        config_file = agent_path / "config.json"
        prompt_file = agent_path / "prompt.txt"
        tools_file = agent_path / "tools.json"

        config = json.loads(config_file.read_text()) if config_file.exists() else {}
        prompt = prompt_file.read_text() if prompt_file.exists() else ""
        tools = json.loads(tools_file.read_text()) if tools_file.exists() else []
        agent_id = config.get("id", agent_path.name)
    else:
        raise FileNotFoundError(f"Agent not found: {agent_path}")

    return analyzer.analyze_agent(agent_id, config, prompt, tools)
