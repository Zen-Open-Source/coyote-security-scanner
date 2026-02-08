"""Tests for shield.md validation scan."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from coyote.scanner import run_scan


VALID_SHIELD = """---
name: shield.md
description: Reference Shield policy
version: "0.1"
---

## Purpose
Reference policy for tests.

## Scope
Applies to all agent runs.

## Threat categories
- prompt
- tool
- mcp
- memory
- supply_chain
- vulnerability
- fraud
- policy_bypass
- anomaly
- skill
- other

## Enforcement states
- log
- require_approval
- block

## Decision requirement
action: block
scope: prompt|tool|mcp|memory|supply_chain|vulnerability|fraud|policy_bypass|anomaly|skill|other
threat_id: T001
fingerprint: fp_001
matched_on: prompt
match_value: suspicious prompt
reason: test decision

## Default behavior
Use log when uncertain.

## Match eligibility
Only grounded threats are eligible.

## Confidence threshold
Block only for high confidence.

## Matching logic
Rules are deterministic.

## recommendation_agent mini syntax v0
Fields are line based.

## Hard stop rule
Only block when evidence supports it.

## Required behavior
Never skip decision output.

## Context limits
Do not overfit stale context.

## Active threats (compressed)
No active threats.
"""


def _shield_rule_names(result) -> list[str]:
    return [
        finding.rule_name
        for finding in result.findings
        if finding.rule_name == "Missing shield.md" or finding.rule_name.startswith("shield.md")
    ]


class ShieldScanTests(unittest.TestCase):
    def test_require_shield_reports_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = run_scan(
                temp_dir,
                enable_shield_scan=True,
                require_shield=True,
            )
            self.assertIn("Missing shield.md", _shield_rule_names(result))

    def test_valid_shield_has_no_shield_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            Path(temp_dir, "shield.md").write_text(VALID_SHIELD, encoding="utf-8")
            result = run_scan(
                temp_dir,
                enable_shield_scan=True,
                require_shield=True,
            )
            self.assertEqual([], _shield_rule_names(result))

    def test_invalid_shield_reports_structure_issues(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            Path(temp_dir, "shield.md").write_text(
                """---
name: shield.md
description: Broken policy
version: "0.1"
---

## Purpose
Only one section exists.
""",
                encoding="utf-8",
            )
            result = run_scan(
                temp_dir,
                enable_shield_scan=True,
            )
            rules = _shield_rule_names(result)
            self.assertIn("shield.md Missing Sections", rules)
            self.assertIn("shield.md Missing Enforcement Actions", rules)


if __name__ == "__main__":
    unittest.main()
