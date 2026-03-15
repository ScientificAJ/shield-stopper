import logging
import unittest

from aeon_stopper import (
    HIGH_PRIORITY_CLASS,
    REALTIME_PRIORITY_CLASS,
    ShieldConfig,
    ShieldStopper,
    TargetInfo,
)


class FakeAdapter:
    def __init__(self) -> None:
        self.system_cpu = 10.0
        self.targets = [TargetInfo(pid=101, name="game.exe", hwnds=[1])]
        self.hung = False
        self.priority_calls = []
        self.suspend_calls = []
        self.capture_calls = []
        self.terminate_calls = []

    def set_self_priority(self, priority_class: int) -> None:
        self.priority_calls.append(priority_class)

    def get_system_cpu_percent(self) -> float:
        return self.system_cpu

    def list_targets(self):
        return list(self.targets)

    def is_target_hung(self, target: TargetInfo, timeout_ms: int) -> bool:
        return self.hung

    def suspend_process_tree(self, pid: int) -> None:
        self.suspend_calls.append(pid)

    def capture_forensics(self, target: TargetInfo, system_cpu: float, reason: str):
        payload = {"pid": target.pid, "cpu": system_cpu, "reason": reason}
        self.capture_calls.append(payload)
        return payload

    def terminate_process_tree(self, pid: int, timeout_seconds: float) -> None:
        self.terminate_calls.append(pid)


class ShieldStopperTests(unittest.TestCase):
    def setUp(self) -> None:
        logger = logging.getLogger(f"test.{self.id()}")
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())
        self.adapter = FakeAdapter()
        self.config = ShieldConfig(
            poll_interval_seconds=1,
            grace_period_seconds=120,
            high_cpu_threshold=95,
            critical_cpu_threshold=98,
        )
        self.stopper = ShieldStopper(config=self.config, adapter=self.adapter, logger=logger)

    def test_defaults_to_high_priority(self) -> None:
        self.adapter.system_cpu = 50.0
        self.stopper.step(now=0.0)
        self.assertEqual(self.adapter.priority_calls, [HIGH_PRIORITY_CLASS])

    def test_escalates_to_realtime_above_threshold(self) -> None:
        self.adapter.system_cpu = 96.0
        self.stopper.step(now=0.0)
        self.assertEqual(self.adapter.priority_calls[-1], REALTIME_PRIORITY_CLASS)

    def test_critical_cpu_triggers_immediate_intervention(self) -> None:
        self.adapter.system_cpu = 99.0
        self.adapter.hung = True
        self.stopper.step(now=0.0)
        self.assertEqual(self.adapter.suspend_calls, [101])
        self.assertEqual(self.adapter.terminate_calls, [101])
        self.assertEqual(self.adapter.capture_calls[0]["reason"], "critical_cpu:99.0>=98.0")

    def test_grace_period_expiry_triggers_intervention(self) -> None:
        self.adapter.system_cpu = 60.0
        self.adapter.hung = True
        self.stopper.step(now=0.0)
        self.assertEqual(self.adapter.terminate_calls, [])
        self.stopper.step(now=121.0)
        self.assertEqual(self.adapter.terminate_calls, [101])
        self.assertEqual(self.adapter.capture_calls[0]["reason"], "grace_expired:121.0s")

    def test_recovery_resets_grace_period(self) -> None:
        self.adapter.system_cpu = 60.0
        self.adapter.hung = True
        self.stopper.step(now=0.0)
        self.adapter.hung = False
        self.stopper.step(now=60.0)
        self.adapter.hung = True
        self.stopper.step(now=61.0)
        self.stopper.step(now=170.0)
        self.assertEqual(self.adapter.terminate_calls, [])
        self.stopper.step(now=182.0)
        self.assertEqual(self.adapter.terminate_calls, [101])


if __name__ == "__main__":
    unittest.main()
