"""
Moltbot Agent Security - Runtime Guardrails

Lightweight runtime monitoring and enforcement for agent actions.
Designed to be hooked into the Moltbot/OpenClaw runtime.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .models import (
    AgentPolicy,
    CapabilityCategory,
    PolicyRule,
    RuntimeAction,
)


class ActionLogger:
    """
    Logs agent actions for audit trails.
    """

    def __init__(self, log_dir: Path | str = ".moltsec/logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._current_log: list[RuntimeAction] = []

    def log_action(self, action: RuntimeAction) -> None:
        """Log an action."""
        self._current_log.append(action)

        # Also append to daily log file
        date_str = action.timestamp.strftime("%Y-%m-%d")
        log_file = self.log_dir / f"actions_{date_str}.jsonl"

        with open(log_file, "a") as f:
            f.write(json.dumps(action.to_dict()) + "\n")

    def get_actions(
        self,
        agent_id: str | None = None,
        since: datetime | None = None,
        action_type: CapabilityCategory | None = None,
    ) -> list[RuntimeAction]:
        """Query logged actions."""
        results = []

        for action in self._current_log:
            if agent_id and action.agent_id != agent_id:
                continue
            if since and action.timestamp < since:
                continue
            if action_type and action.action_type != action_type:
                continue
            results.append(action)

        return results

    def get_recent_files_accessed(self, agent_id: str, limit: int = 10) -> list[str]:
        """Get recently accessed file paths for an agent."""
        file_actions = self.get_actions(
            agent_id=agent_id,
            action_type=CapabilityCategory.FILE_READ,
        )
        file_actions.extend(self.get_actions(
            agent_id=agent_id,
            action_type=CapabilityCategory.FILE_WRITE,
        ))

        # Extract paths and dedupe
        paths = []
        seen = set()
        for action in reversed(file_actions):
            path = action.action_detail.split(" ", 1)[-1]  # "Read file /path" -> "/path"
            if path not in seen:
                paths.append(path)
                seen.add(path)
            if len(paths) >= limit:
                break

        return paths

    def get_external_connections(self, agent_id: str) -> list[str]:
        """Get all external URLs/hosts an agent has connected to."""
        net_actions = self.get_actions(
            agent_id=agent_id,
            action_type=CapabilityCategory.NETWORK_OUTBOUND,
        )

        hosts = set()
        for action in net_actions:
            # Extract host from action detail
            detail = action.action_detail
            # Try to find URL pattern
            match = re.search(r'https?://([^/\s]+)', detail)
            if match:
                hosts.add(match.group(1))

        return list(hosts)


class RuntimeGuard:
    """
    Runtime guard that checks actions against policy.

    This is designed to be integrated into the Moltbot runtime
    as a hook on agent actions.
    """

    def __init__(
        self,
        policy: AgentPolicy,
        logger: ActionLogger | None = None,
        prompt_callback: Callable[[str, str], bool] | None = None,
    ):
        """
        Initialize the runtime guard.

        Args:
            policy: The security policy to enforce
            logger: Optional action logger
            prompt_callback: Function to prompt user for permission.
                             Takes (action_description, risk_reason) and returns bool.
        """
        self.policy = policy
        self.logger = logger or ActionLogger()
        self.prompt_callback = prompt_callback

        # Track first-time actions for prompting
        self._prompted_actions: set[tuple] = set()

        # Track behavior patterns
        self._action_counts: dict[CapabilityCategory, int] = {}

    def check_action(
        self,
        category: CapabilityCategory,
        scope: str,
        detail: str = "",
    ) -> tuple[bool, str]:
        """
        Check if an action should be allowed.

        Args:
            category: The capability category
            scope: The specific scope (path, URL, etc.)
            detail: Human-readable action detail

        Returns:
            Tuple of (allowed, reason)
        """
        # Find matching rule
        rule = self._find_matching_rule(category, scope)

        if rule is None:
            # No specific rule - use default
            action = self.policy.default_action
            reason = "No specific rule, using default policy"
        else:
            action = rule.action
            reason = rule.reason

        # Execute action
        allowed, final_reason = self._execute_action(
            action, category, scope, detail, reason
        )

        # Log the action
        self.logger.log_action(RuntimeAction(
            timestamp=datetime.now(timezone.utc),
            agent_id=self.policy.agent_id,
            action_type=category,
            action_detail=detail or f"{category.value}: {scope}",
            was_permitted=allowed,
            was_prompted=(action == "prompt"),
            user_allowed=allowed if action == "prompt" else None,
        ))

        # Track action counts for drift detection
        self._action_counts[category] = self._action_counts.get(category, 0) + 1

        return allowed, final_reason

    def _find_matching_rule(
        self,
        category: CapabilityCategory,
        scope: str,
    ) -> PolicyRule | None:
        """Find the first matching rule for an action."""
        for rule in self.policy.rules:
            if rule.category != category:
                continue

            # Check if scope matches pattern
            if self._scope_matches(scope, rule.scope_pattern):
                return rule

        return None

    def _scope_matches(self, scope: str, pattern: str) -> bool:
        """Check if a scope matches a pattern."""
        # Exact match
        if scope == pattern:
            return True

        # Wildcard match
        if pattern == "*":
            return True

        # Glob pattern match
        if fnmatch.fnmatch(scope, pattern):
            return True

        # Path prefix match
        if pattern.endswith("/") or pattern.endswith("/*"):
            base = pattern.rstrip("/*")
            if scope.startswith(base):
                return True

        # Regex match (patterns starting with ^)
        if pattern.startswith("^"):
            try:
                if re.match(pattern, scope):
                    return True
            except re.error:
                pass

        return False

    def _execute_action(
        self,
        action: str,
        category: CapabilityCategory,
        scope: str,
        detail: str,
        reason: str,
    ) -> tuple[bool, str]:
        """Execute a policy action."""
        if action == "allow":
            return True, "Allowed by policy"

        elif action == "deny":
            return False, f"Denied: {reason}"

        elif action == "log":
            # Allow but log
            return True, "Allowed (logged)"

        elif action == "prompt":
            # Check if we've already prompted for this
            action_key = (category, scope)
            if action_key in self._prompted_actions:
                return True, "Previously approved"

            # Prompt user
            if self.prompt_callback:
                description = detail or f"{category.value}: {scope}"
                allowed = self.prompt_callback(description, reason)
                if allowed:
                    self._prompted_actions.add(action_key)
                return allowed, "User decision" if allowed else f"User denied: {reason}"
            else:
                # No callback - log warning and allow with caution
                return True, "Prompt required but no callback (allowed with warning)"

        else:
            # Unknown action - deny
            return False, f"Unknown policy action: {action}"

    def get_behavior_summary(self) -> dict[str, Any]:
        """Get a summary of the agent's runtime behavior."""
        return {
            "agent_id": self.policy.agent_id,
            "action_counts": {
                cat.value: count
                for cat, count in self._action_counts.items()
            },
            "prompted_actions": len(self._prompted_actions),
            "files_accessed": self.logger.get_recent_files_accessed(
                self.policy.agent_id
            ),
            "external_connections": self.logger.get_external_connections(
                self.policy.agent_id
            ),
        }


class BehaviorDriftDetector:
    """
    Detects when an agent's runtime behavior deviates from its declared capabilities.
    """

    def __init__(self, logger: ActionLogger):
        self.logger = logger
        self._baseline_patterns: dict[str, dict[CapabilityCategory, int]] = {}

    def establish_baseline(
        self,
        agent_id: str,
        window_hours: int = 24,
    ) -> dict[CapabilityCategory, int]:
        """
        Establish a baseline of normal behavior for an agent.
        """
        since = datetime.now(timezone.utc)

        actions = self.logger.get_actions(agent_id=agent_id, since=since)

        baseline: dict[CapabilityCategory, int] = {}
        for action in actions:
            baseline[action.action_type] = baseline.get(action.action_type, 0) + 1

        self._baseline_patterns[agent_id] = baseline
        return baseline

    def check_drift(
        self,
        agent_id: str,
        current_behavior: dict[CapabilityCategory, int],
        threshold: float = 2.0,
    ) -> list[tuple[CapabilityCategory, str, float]]:
        """
        Check if current behavior deviates significantly from baseline.

        Returns list of (category, description, deviation_factor) for concerning deviations.
        """
        baseline = self._baseline_patterns.get(agent_id, {})
        if not baseline:
            return []

        deviations = []

        for category, count in current_behavior.items():
            baseline_count = baseline.get(category, 0)

            if baseline_count == 0:
                if count > 0:
                    # New behavior not in baseline
                    deviations.append((
                        category,
                        f"New behavior: {category.value} (not in baseline)",
                        float("inf"),
                    ))
            else:
                ratio = count / baseline_count
                if ratio > threshold:
                    deviations.append((
                        category,
                        f"Increased {category.value}: {ratio:.1f}x baseline",
                        ratio,
                    ))

        return deviations


def create_terminal_prompt_callback() -> Callable[[str, str], bool]:
    """
    Create a simple terminal-based prompt callback.
    """
    def prompt(description: str, reason: str) -> bool:
        print("\n" + "=" * 60)
        print("AGENT PERMISSION REQUEST")
        print("=" * 60)
        print(f"\nAction: {description}")
        print(f"Reason: {reason}")
        print("\nAllow this action? [y/N] ", end="")

        try:
            response = input().strip().lower()
            return response in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False

    return prompt
