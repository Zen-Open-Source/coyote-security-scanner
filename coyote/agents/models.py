"""
Moltbot Agent Security - Core Data Models

This module defines the schema for agent capabilities, risk assessment,
and permission tracking.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class RiskLevel(Enum):
    """Risk levels for agent capabilities."""
    NONE = "none"           # No security concern
    LOW = "low"             # Minor concern, informational
    MEDIUM = "medium"       # Noteworthy, user should be aware
    HIGH = "high"           # Significant risk, requires attention
    CRITICAL = "critical"   # Severe risk, should block or strongly warn


class CapabilityCategory(Enum):
    """Categories of agent capabilities."""
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NETWORK_OUTBOUND = "network_outbound"
    NETWORK_INBOUND = "network_inbound"
    PROCESS_SPAWN = "process_spawn"
    SECRET_ACCESS = "secret_access"
    TOOL_INVOCATION = "tool_invocation"
    SELF_MODIFICATION = "self_modification"
    AGENT_SPAWNING = "agent_spawning"
    CODE_EXECUTION = "code_execution"
    BROWSER_ACCESS = "browser_access"
    CLIPBOARD_ACCESS = "clipboard_access"
    SYSTEM_INFO = "system_info"


@dataclass
class Capability:
    """
    A single capability that an agent may have.

    Examples:
    - Read files in ~/.ssh/
    - Make HTTP requests to api.openai.com
    - Execute shell commands
    """
    category: CapabilityCategory
    description: str
    scope: str                          # What specifically (path pattern, domain, tool name)
    risk_level: RiskLevel
    risk_reason: str                    # Why this is risky
    source: str                         # Where this was detected (config line, prompt section)
    confidence: float = 1.0             # 1.0 = definitely has this, 0.5 = might have this

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "description": self.description,
            "scope": self.scope,
            "risk_level": self.risk_level.value,
            "risk_reason": self.risk_reason,
            "source": self.source,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Capability:
        return cls(
            category=CapabilityCategory(data["category"]),
            description=data["description"],
            scope=data["scope"],
            risk_level=RiskLevel(data["risk_level"]),
            risk_reason=data["risk_reason"],
            source=data["source"],
            confidence=data.get("confidence", 1.0),
        )


@dataclass
class AgentMetadata:
    """Basic metadata about an agent."""
    agent_id: str                       # Unique identifier
    name: str
    version: str
    author: str
    source_url: str                     # Moltbook URL
    description: str
    imported_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "source_url": self.source_url,
            "description": self.description,
            "imported_at": self.imported_at.isoformat(),
        }


@dataclass
class CapabilityManifest:
    """
    Complete capability manifest for an agent.

    This is the core output of the intake analysis - a structured
    representation of everything an agent can do.
    """
    metadata: AgentMetadata
    capabilities: list[Capability]
    manifest_version: str = "1.0"
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    analysis_warnings: list[str] = field(default_factory=list)

    # Content hashes for change detection
    config_hash: str = ""
    prompt_hash: str = ""
    tools_hash: str = ""

    @property
    def manifest_hash(self) -> str:
        """Compute a hash of the entire manifest for comparison."""
        # Hash the core content without including the hash itself
        content = {
            "metadata": self.metadata.to_dict(),
            "capabilities": [c.to_dict() for c in self.capabilities],
            "config_hash": self.config_hash,
            "prompt_hash": self.prompt_hash,
            "tools_hash": self.tools_hash,
        }
        return hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()[:16]

    @property
    def max_risk_level(self) -> RiskLevel:
        """Return the highest risk level among all capabilities."""
        if not self.capabilities:
            return RiskLevel.NONE
        risk_order = [RiskLevel.NONE, RiskLevel.LOW, RiskLevel.MEDIUM,
                      RiskLevel.HIGH, RiskLevel.CRITICAL]
        max_idx = max(risk_order.index(c.risk_level) for c in self.capabilities)
        return risk_order[max_idx]

    def capabilities_by_category(self) -> dict[CapabilityCategory, list[Capability]]:
        """Group capabilities by category."""
        result: dict[CapabilityCategory, list[Capability]] = {}
        for cap in self.capabilities:
            if cap.category not in result:
                result[cap.category] = []
            result[cap.category].append(cap)
        return result

    def capabilities_by_risk(self) -> dict[RiskLevel, list[Capability]]:
        """Group capabilities by risk level."""
        result: dict[RiskLevel, list[Capability]] = {}
        for cap in self.capabilities:
            if cap.risk_level not in result:
                result[cap.risk_level] = []
            result[cap.risk_level].append(cap)
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_version": self.manifest_version,
            "analyzed_at": self.analyzed_at.isoformat(),
            "metadata": self.metadata.to_dict(),
            "capabilities": [c.to_dict() for c in self.capabilities],
            "analysis_warnings": self.analysis_warnings,
            "hashes": {
                "config": self.config_hash,
                "prompt": self.prompt_hash,
                "tools": self.tools_hash,
                "manifest": self.manifest_hash,
            },
            "summary": {
                "total_capabilities": len(self.capabilities),
                "max_risk_level": self.max_risk_level.value,
                "by_risk": {
                    level.value: len(caps)
                    for level, caps in self.capabilities_by_risk().items()
                },
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CapabilityManifest:
        metadata = AgentMetadata(
            agent_id=data["metadata"]["agent_id"],
            name=data["metadata"]["name"],
            version=data["metadata"]["version"],
            author=data["metadata"]["author"],
            source_url=data["metadata"]["source_url"],
            description=data["metadata"]["description"],
            imported_at=datetime.fromisoformat(data["metadata"]["imported_at"]),
        )
        capabilities = [Capability.from_dict(c) for c in data["capabilities"]]
        manifest = cls(
            metadata=metadata,
            capabilities=capabilities,
            manifest_version=data["manifest_version"],
            analyzed_at=datetime.fromisoformat(data["analyzed_at"]),
            analysis_warnings=data.get("analysis_warnings", []),
        )
        manifest.config_hash = data.get("hashes", {}).get("config", "")
        manifest.prompt_hash = data.get("hashes", {}).get("prompt", "")
        manifest.tools_hash = data.get("hashes", {}).get("tools", "")
        return manifest


@dataclass
class CapabilityDiff:
    """
    Represents changes between two capability manifests.
    """
    agent_id: str
    old_version: str
    new_version: str
    old_manifest_hash: str
    new_manifest_hash: str

    added_capabilities: list[Capability] = field(default_factory=list)
    removed_capabilities: list[Capability] = field(default_factory=list)
    changed_capabilities: list[tuple[Capability, Capability]] = field(default_factory=list)

    # Risk escalations are specially flagged
    risk_escalations: list[tuple[Capability, RiskLevel, RiskLevel]] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added_capabilities or self.removed_capabilities or self.changed_capabilities)

    @property
    def has_risk_escalation(self) -> bool:
        return bool(self.risk_escalations)

    @property
    def max_new_risk(self) -> RiskLevel:
        """Highest risk level among newly added capabilities."""
        if not self.added_capabilities:
            return RiskLevel.NONE
        risk_order = [RiskLevel.NONE, RiskLevel.LOW, RiskLevel.MEDIUM,
                      RiskLevel.HIGH, RiskLevel.CRITICAL]
        max_idx = max(risk_order.index(c.risk_level) for c in self.added_capabilities)
        return risk_order[max_idx]

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "old_manifest_hash": self.old_manifest_hash,
            "new_manifest_hash": self.new_manifest_hash,
            "has_changes": self.has_changes,
            "has_risk_escalation": self.has_risk_escalation,
            "added": [c.to_dict() for c in self.added_capabilities],
            "removed": [c.to_dict() for c in self.removed_capabilities],
            "changed": [
                {"old": old.to_dict(), "new": new.to_dict()}
                for old, new in self.changed_capabilities
            ],
            "risk_escalations": [
                {
                    "capability": cap.to_dict(),
                    "old_risk": old.value,
                    "new_risk": new.value,
                }
                for cap, old, new in self.risk_escalations
            ],
        }


@dataclass
class RuntimeAction:
    """
    A logged action taken by an agent at runtime.
    Used for audit trails and behavior drift detection.
    """
    timestamp: datetime
    agent_id: str
    action_type: CapabilityCategory
    action_detail: str              # e.g., "Read file /etc/passwd"
    was_permitted: bool
    was_prompted: bool = False      # Did we ask the user?
    user_allowed: bool | None = None  # If prompted, what did user say?

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "agent_id": self.agent_id,
            "action_type": self.action_type.value,
            "action_detail": self.action_detail,
            "was_permitted": self.was_permitted,
            "was_prompted": self.was_prompted,
            "user_allowed": self.user_allowed,
        }


@dataclass
class PolicyRule:
    """
    A single rule in the agent's security policy.
    """
    category: CapabilityCategory
    scope_pattern: str              # Glob or regex pattern
    action: str                     # "allow", "deny", "prompt", "log"
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "scope_pattern": self.scope_pattern,
            "action": self.action,
            "reason": self.reason,
        }


@dataclass
class AgentPolicy:
    """
    Security policy for an agent, derived from its manifest.
    This is what the runtime enforces.
    """
    agent_id: str
    manifest_hash: str
    rules: list[PolicyRule]
    default_action: str = "prompt"  # What to do for uncovered cases

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_version": "1.0",
            "agent_id": self.agent_id,
            "manifest_hash": self.manifest_hash,
            "default_action": self.default_action,
            "rules": [r.to_dict() for r in self.rules],
        }
