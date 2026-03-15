import sys
import unittest
from pathlib import Path

from shield_launcher import ROOT_DIR, build_watchdog_command, resolve_config_path


class ShieldLauncherTests(unittest.TestCase):
    def test_resolve_config_path_defaults_to_repo_root(self) -> None:
        resolved = resolve_config_path("config.json")
        self.assertEqual(resolved, (ROOT_DIR / "config.json").resolve())

    def test_build_watchdog_command_points_at_script_and_config(self) -> None:
        config_path = Path("/tmp/test-config.json")
        command = build_watchdog_command(config_path)
        self.assertEqual(command[0], sys.executable)
        self.assertEqual(command[1], str((ROOT_DIR / "aeon_stopper.py").resolve()))
        self.assertEqual(command[2:], ["--config", str(config_path)])


if __name__ == "__main__":
    unittest.main()
