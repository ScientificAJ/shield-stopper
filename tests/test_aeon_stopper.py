import logging
import subprocess
import unittest
from types import SimpleNamespace
from unittest import mock

from aeon_stopper import (
    LinuxPlatformAdapter,
    MacOSPlatformAdapter,
    PRIORITY_HIGH,
    PRIORITY_REALTIME,
    ShieldConfig,
    ShieldStopper,
    SystemLoad,
    TargetInfo,
    lookup_english_perf_index,
    select_windows_dump_type,
)


class FakeAdapter:
    def __init__(self) -> None:
        self.system_cpu = 10.0
        self.system_gpu = None
        self.targets = [TargetInfo(pid=101, name="game.exe", handles=["1"])]
        self.hung = False
        self.priority_calls = []
        self.suspend_calls = []
        self.capture_calls = []
        self.terminate_calls = []

    def set_self_priority(self, priority_mode: str) -> None:
        self.priority_calls.append(priority_mode)

    def get_system_load(self) -> SystemLoad:
        return SystemLoad(cpu_percent=self.system_cpu, gpu_percent=self.system_gpu)

    def list_targets(self):
        return list(self.targets)

    def is_target_hung(self, target: TargetInfo, timeout_ms: int) -> bool:
        return self.hung

    def suspend_process_tree(self, pid: int) -> None:
        self.suspend_calls.append(pid)

    def capture_forensics(self, target: TargetInfo, system_load: SystemLoad, reason: str):
        payload = {
            "pid": target.pid,
            "cpu": system_load.cpu_percent,
            "gpu": system_load.gpu_percent,
            "reason": reason,
        }
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
            high_gpu_threshold=95,
            critical_gpu_threshold=98,
        )
        self.stopper = ShieldStopper(config=self.config, adapter=self.adapter, logger=logger)

    def test_defaults_to_high_priority_mode(self) -> None:
        self.adapter.system_cpu = 50.0
        self.stopper.step(now=0.0)
        self.assertEqual(self.adapter.priority_calls, [PRIORITY_HIGH])

    def test_escalates_to_realtime_above_cpu_threshold(self) -> None:
        self.adapter.system_cpu = 96.0
        self.stopper.step(now=0.0)
        self.assertEqual(self.adapter.priority_calls[-1], PRIORITY_REALTIME)

    def test_escalates_to_realtime_above_gpu_threshold(self) -> None:
        self.adapter.system_cpu = 40.0
        self.adapter.system_gpu = 97.0
        self.stopper.step(now=0.0)
        self.assertEqual(self.adapter.priority_calls[-1], PRIORITY_REALTIME)

    def test_critical_cpu_triggers_immediate_intervention(self) -> None:
        self.adapter.system_cpu = 99.0
        self.adapter.hung = True
        self.stopper.step(now=0.0)
        self.assertEqual(self.adapter.suspend_calls, [101])
        self.assertEqual(self.adapter.terminate_calls, [101])
        self.assertEqual(self.adapter.capture_calls[0]["reason"], "critical_cpu:99.0>=98.0")

    def test_critical_gpu_triggers_immediate_intervention(self) -> None:
        self.adapter.system_cpu = 40.0
        self.adapter.system_gpu = 99.0
        self.adapter.hung = True
        self.stopper.step(now=0.0)
        self.assertEqual(self.adapter.capture_calls[0]["reason"], "critical_gpu:99.0>=98.0")

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


class AdapterHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        logger = logging.getLogger(f"test.{self.id()}")
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())
        self.logger = logger
        self.config = ShieldConfig()

    def test_windows_dump_type_defaults_to_normal(self) -> None:
        self.assertEqual(select_windows_dump_type(False), 0x00000000)

    def test_windows_dump_type_supports_full_memory_opt_in(self) -> None:
        self.assertEqual(select_windows_dump_type(True), 0x00000002)

    def test_linux_hung_check_uses_disk_sleep_state(self) -> None:
        adapter = LinuxPlatformAdapter(self.config, self.logger)
        target = TargetInfo(pid=200, name="renderd", handles=[])
        with mock.patch.object(adapter, "_linux_process_state", return_value="D"):
            self.assertTrue(adapter.is_target_hung(target, 1000))

    def test_linux_terminate_process_tree_uses_sigkill(self) -> None:
        adapter = LinuxPlatformAdapter(self.config, self.logger)
        fake_processes = [SimpleNamespace(pid=11), SimpleNamespace(pid=22)]
        with mock.patch.object(adapter, "_process_tree", return_value=fake_processes), \
            mock.patch("aeon_stopper.os.kill") as kill_mock, \
            mock.patch("aeon_stopper.psutil.wait_procs", return_value=([], [])):
            adapter.terminate_process_tree(11, 5.0)
        self.assertEqual(kill_mock.call_args_list[0].args[1].name, "SIGKILL")

    def test_macos_hung_check_treats_applescript_timeout_as_hang(self) -> None:
        adapter = MacOSPlatformAdapter(self.config, self.logger)
        target = TargetInfo(pid=300, name="Final Cut Pro")
        fake_process = SimpleNamespace(status=lambda: "running")
        with mock.patch("aeon_stopper.psutil.Process", return_value=fake_process), \
            mock.patch("aeon_stopper.shutil.which", return_value="/usr/bin/osascript"), \
            mock.patch("aeon_stopper.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["osascript"], timeout=2)):
            self.assertTrue(adapter.is_target_hung(target, 1000))

    def test_perf_index_lookup_reads_english_counter_map(self) -> None:
        fake_registry = SimpleNamespace(
            HKEY_LOCAL_MACHINE="HKLM",
            OpenKey=mock.MagicMock(),
            QueryValueEx=mock.Mock(return_value=(["230", "GPU Engine", "231", "Utilization Percentage"], 0)),
        )
        fake_registry.OpenKey.return_value.__enter__.return_value = mock.MagicMock()
        with mock.patch("aeon_stopper.winreg", fake_registry):
            self.assertEqual(lookup_english_perf_index("GPU Engine"), 230)


if __name__ == "__main__":
    unittest.main()
