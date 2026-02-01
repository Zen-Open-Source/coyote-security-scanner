"""
Moltbot Agent Security - Permission Tracker

Tracks agent capability manifests over time and computes diffs
when agents are updated.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import (
    AgentPolicy,
    Capability,
    CapabilityCategory,
    CapabilityDiff,
    CapabilityManifest,
    PolicyRule,
    RiskLevel,
)


class ManifestStore:
    """
    Persistent storage for agent capability manifests.

    Stores versioned manifests in a local directory structure:
    .moltsec/
      manifests/
        <agent_id>/
          v1.0.0_20240115_103000.json
          v1.0.1_20240116_142000.json
          latest.json -> symlink to most recent
    """

    def __init__(self, base_dir: Path | str = ".moltsec"):
        self.base_dir = Path(base_dir)
        self.manifests_dir = self.base_dir / "manifests"
        self.manifests_dir.mkdir(parents=True, exist_ok=True)

    def _agent_dir(self, agent_id: str) -> Path:
        """Get the directory for an agent's manifests."""
        safe_id = agent_id.replace("/", "_").replace("\\", "_")
        agent_dir = self.manifests_dir / safe_id
        agent_dir.mkdir(exist_ok=True)
        return agent_dir

    def save_manifest(self, manifest: CapabilityManifest) -> Path:
        """
        Save a manifest to the store.

        Returns the path to the saved manifest.
        """
        agent_dir = self._agent_dir(manifest.metadata.agent_id)

        # Create versioned filename
        timestamp = manifest.analyzed_at.strftime("%Y%m%d_%H%M%S")
        version = manifest.metadata.version.replace(".", "_")
        filename = f"v{version}_{timestamp}.json"
        filepath = agent_dir / filename

        # Save manifest
        with open(filepath, "w") as f:
            json.dump(manifest.to_dict(), f, indent=2)

        # Update latest symlink
        latest_link = agent_dir / "latest.json"
        if latest_link.exists() or latest_link.is_symlink():
            latest_link.unlink()
        latest_link.symlink_to(filename)

        return filepath

    def get_latest_manifest(self, agent_id: str) -> CapabilityManifest | None:
        """Get the most recent manifest for an agent."""
        agent_dir = self._agent_dir(agent_id)
        latest_link = agent_dir / "latest.json"

        if not latest_link.exists():
            return None

        with open(latest_link) as f:
            data = json.load(f)
        return CapabilityManifest.from_dict(data)

    def get_manifest_history(self, agent_id: str) -> list[CapabilityManifest]:
        """Get all stored manifests for an agent, oldest first."""
        agent_dir = self._agent_dir(agent_id)
        manifests = []

        for filepath in sorted(agent_dir.glob("v*.json")):
            if filepath.name == "latest.json":
                continue
            with open(filepath) as f:
                data = json.load(f)
            manifests.append(CapabilityManifest.from_dict(data))

        return manifests

    def get_manifest_by_version(self, agent_id: str, version: str) -> CapabilityManifest | None:
        """Get a specific version's manifest."""
        agent_dir = self._agent_dir(agent_id)
        version_prefix = f"v{version.replace('.', '_')}_"

        for filepath in agent_dir.glob(f"{version_prefix}*.json"):
            with open(filepath) as f:
                data = json.load(f)
            return CapabilityManifest.from_dict(data)

        return None


class PermissionDiffer:
    """
    Computes diffs between capability manifests.
    """

    def diff(
        self,
        old_manifest: CapabilityManifest,
        new_manifest: CapabilityManifest,
    ) -> CapabilityDiff:
        """
        Compute the difference between two manifests.
        """
        diff = CapabilityDiff(
            agent_id=new_manifest.metadata.agent_id,
            old_version=old_manifest.metadata.version,
            new_version=new_manifest.metadata.version,
            old_manifest_hash=old_manifest.manifest_hash,
            new_manifest_hash=new_manifest.manifest_hash,
        )

        # Build lookup for old capabilities
        old_caps = {self._capability_key(c): c for c in old_manifest.capabilities}
        new_caps = {self._capability_key(c): c for c in new_manifest.capabilities}

        # Find added capabilities
        for key, cap in new_caps.items():
            if key not in old_caps:
                diff.added_capabilities.append(cap)

        # Find removed capabilities
        for key, cap in old_caps.items():
            if key not in new_caps:
                diff.removed_capabilities.append(cap)

        # Find changed capabilities (same key, different risk or scope)
        for key, new_cap in new_caps.items():
            if key in old_caps:
                old_cap = old_caps[key]
                if self._capability_changed(old_cap, new_cap):
                    diff.changed_capabilities.append((old_cap, new_cap))

                    # Check for risk escalation
                    if self._risk_increased(old_cap.risk_level, new_cap.risk_level):
                        diff.risk_escalations.append(
                            (new_cap, old_cap.risk_level, new_cap.risk_level)
                        )

        # Also check added capabilities for risk escalations
        # (new HIGH+ capabilities are effectively escalations from NONE)
        for cap in diff.added_capabilities:
            if cap.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                diff.risk_escalations.append(
                    (cap, RiskLevel.NONE, cap.risk_level)
                )

        return diff

    def _capability_key(self, cap: Capability) -> tuple:
        """Generate a unique key for a capability."""
        return (cap.category, cap.scope)

    def _capability_changed(self, old: Capability, new: Capability) -> bool:
        """Check if a capability has meaningfully changed."""
        return (
            old.risk_level != new.risk_level or
            old.description != new.description or
            abs(old.confidence - new.confidence) > 0.1
        )

    def _risk_increased(self, old_risk: RiskLevel, new_risk: RiskLevel) -> bool:
        """Check if risk level increased."""
        risk_order = [RiskLevel.NONE, RiskLevel.LOW, RiskLevel.MEDIUM,
                      RiskLevel.HIGH, RiskLevel.CRITICAL]
        return risk_order.index(new_risk) > risk_order.index(old_risk)


class PolicyGenerator:
    """
    Generates runtime security policies from capability manifests.
    """

    def generate_policy(
        self,
        manifest: CapabilityManifest,
        strictness: str = "normal",
    ) -> AgentPolicy:
        """
        Generate a security policy from a manifest.

        Args:
            manifest: The capability manifest
            strictness: "permissive", "normal", or "strict"

        Returns:
            AgentPolicy ready for runtime enforcement
        """
        rules: list[PolicyRule] = []

        for cap in manifest.capabilities:
            action = self._determine_action(cap, strictness)
            rules.append(PolicyRule(
                category=cap.category,
                scope_pattern=self._scope_to_pattern(cap.scope),
                action=action,
                reason=cap.risk_reason,
            ))

        # Add default deny rules for sensitive categories not explicitly declared
        sensitive_categories = [
            CapabilityCategory.FILE_READ,
            CapabilityCategory.FILE_WRITE,
            CapabilityCategory.NETWORK_OUTBOUND,
            CapabilityCategory.PROCESS_SPAWN,
            CapabilityCategory.CODE_EXECUTION,
            CapabilityCategory.SECRET_ACCESS,
        ]

        declared_categories = {cap.category for cap in manifest.capabilities}
        for cat in sensitive_categories:
            if cat not in declared_categories:
                rules.append(PolicyRule(
                    category=cat,
                    scope_pattern="*",
                    action="prompt" if strictness != "strict" else "deny",
                    reason="Undeclared capability",
                ))

        return AgentPolicy(
            agent_id=manifest.metadata.agent_id,
            manifest_hash=manifest.manifest_hash,
            rules=rules,
            default_action="prompt" if strictness == "permissive" else "deny",
        )

    def _determine_action(self, cap: Capability, strictness: str) -> str:
        """Determine the policy action for a capability."""
        if strictness == "strict":
            if cap.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                return "prompt"
            elif cap.risk_level == RiskLevel.MEDIUM:
                return "log"
            else:
                return "allow"
        elif strictness == "normal":
            if cap.risk_level == RiskLevel.CRITICAL:
                return "prompt"
            elif cap.risk_level == RiskLevel.HIGH:
                return "log"
            else:
                return "allow"
        else:  # permissive
            if cap.risk_level == RiskLevel.CRITICAL:
                return "log"
            else:
                return "allow"

    def _scope_to_pattern(self, scope: str) -> str:
        """Convert scope to a glob pattern."""
        # Already a pattern
        if "*" in scope or "?" in scope:
            return scope

        # Looks like a path
        if scope.startswith("/") or scope.startswith("~"):
            return scope

        # Domain or URL
        if "://" in scope or "." in scope:
            return scope

        # Generic - match exactly
        return scope


class PermissionTracker:
    """
    High-level interface for tracking agent permissions over time.
    """

    def __init__(self, base_dir: Path | str = ".moltsec"):
        self.store = ManifestStore(base_dir)
        self.differ = PermissionDiffer()
        self.policy_gen = PolicyGenerator()

    def register_agent(self, manifest: CapabilityManifest) -> tuple[Path, CapabilityDiff | None]:
        """
        Register a new or updated agent.

        Returns:
            Tuple of (saved manifest path, diff from previous version if any)
        """
        # Check for existing manifest
        old_manifest = self.store.get_latest_manifest(manifest.metadata.agent_id)

        # Compute diff if updating
        diff = None
        if old_manifest:
            diff = self.differ.diff(old_manifest, manifest)

        # Save new manifest
        saved_path = self.store.save_manifest(manifest)

        return saved_path, diff

    def get_agent_diff(
        self,
        agent_id: str,
        from_version: str | None = None,
        to_version: str | None = None,
    ) -> CapabilityDiff | None:
        """
        Get the diff between two versions of an agent.

        If versions not specified, compares the two most recent.
        """
        if from_version and to_version:
            old = self.store.get_manifest_by_version(agent_id, from_version)
            new = self.store.get_manifest_by_version(agent_id, to_version)
        else:
            history = self.store.get_manifest_history(agent_id)
            if len(history) < 2:
                return None
            old = history[-2]
            new = history[-1]

        if not old or not new:
            return None

        return self.differ.diff(old, new)

    def generate_policy(
        self,
        agent_id: str,
        strictness: str = "normal",
    ) -> AgentPolicy | None:
        """Generate a policy for an agent."""
        manifest = self.store.get_latest_manifest(agent_id)
        if not manifest:
            return None
        return self.policy_gen.generate_policy(manifest, strictness)

    def save_policy(
        self,
        agent_id: str,
        output_path: Path | str | None = None,
        strictness: str = "normal",
    ) -> Path | None:
        """Generate and save a policy file."""
        policy = self.generate_policy(agent_id, strictness)
        if not policy:
            return None

        if output_path is None:
            output_path = Path(f".molt-policy-{agent_id.replace('/', '_')}.json")
        else:
            output_path = Path(output_path)

        with open(output_path, "w") as f:
            json.dump(policy.to_dict(), f, indent=2)

        return output_path
