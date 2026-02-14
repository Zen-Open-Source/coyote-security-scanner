"""Tests for agent runtime guard and behavior baseline logic."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from coyote.agents.models import CapabilityCategory, RuntimeAction
from coyote.agents.runtime import ActionLogger, BehaviorDriftDetector


class BehaviorDriftDetectorTests(unittest.TestCase):
    def test_establish_baseline_respects_window_hours(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = ActionLogger(log_dir=temp_dir)
            detector = BehaviorDriftDetector(logger)

            now = datetime.now(timezone.utc)
            agent_id = "agent-1"

            logger.log_action(RuntimeAction(
                timestamp=now - timedelta(minutes=20),
                agent_id=agent_id,
                action_type=CapabilityCategory.FILE_READ,
                action_detail="Read file /tmp/recent.txt",
                was_permitted=True,
            ))
            logger.log_action(RuntimeAction(
                timestamp=now - timedelta(hours=2),
                agent_id=agent_id,
                action_type=CapabilityCategory.FILE_READ,
                action_detail="Read file /tmp/old.txt",
                was_permitted=True,
            ))

            baseline = detector.establish_baseline(agent_id, window_hours=1)

            self.assertEqual(1, baseline.get(CapabilityCategory.FILE_READ, 0))


if __name__ == "__main__":
    unittest.main()
