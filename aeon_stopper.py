#!/usr/bin/env python3
"""Shield Stopper: adaptive Windows process watchdog.

This script monitors visible GUI processes for hung windows, applies a grace
period before intervention, captures forensics, and force-terminates the
offending process tree when the system becomes unstable.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import msvcrt
except ImportError:  # pragma: no cover - handled in Windows-only code paths
    msvcrt = None

try:
    import psutil
except ImportError:  # pragma: no cover - handled in main()
    psutil = None

try:
    import pywintypes
    import win32api
    import win32con
    import win32gui
    import win32process
    import win32ui
except ImportError:  # pragma: no cover - handled in main()
    pywintypes = None
    win32api = None
    win32con = None
    win32gui = None
    win32process = None
    win32ui = None


HIGH_PRIORITY_CLASS = 0x00000080
REALTIME_PRIORITY_CLASS = 0x00000100

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
PROCESS_SUSPEND_RESUME = 0x0800

WM_NULL = 0x0000
SMTO_ABORTIFHUNG = 0x0002

DEFAULT_CONFIG_PATH = "config.json"
DEFAULT_LOG_FILE = "shield_stopper.log"


@dataclass
class ShieldConfig:
    poll_interval_seconds: float = 2.0
    grace_period_seconds: float = 120.0
    high_cpu_threshold: float = 95.0
    critical_cpu_threshold: float = 98.0
    unresponsive_timeout_ms: int = 1000
    terminate_timeout_seconds: float = 5.0
    snapshot_dir: str = "artifacts"
    target_process_names: list[str] = field(default_factory=list)
    excluded_process_names: list[str] = field(default_factory=list)
    minidump_enabled: bool = True
    screenshot_enabled: bool = True

    @classmethod
    def from_file(cls, path: Path) -> "ShieldConfig":
        payload = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            poll_interval_seconds=float(payload.get("poll_interval_seconds", 2.0)),
            grace_period_seconds=float(payload.get("grace_period_seconds", 120.0)),
            high_cpu_threshold=float(payload.get("high_cpu_threshold", 95.0)),
            critical_cpu_threshold=float(payload.get("critical_cpu_threshold", 98.0)),
            unresponsive_timeout_ms=int(payload.get("unresponsive_timeout_ms", 1000)),
            terminate_timeout_seconds=float(payload.get("terminate_timeout_seconds", 5.0)),
            snapshot_dir=str(payload.get("snapshot_dir", "artifacts")),
            target_process_names=[str(name).lower() for name in payload.get("target_process_names", [])],
            excluded_process_names=[str(name).lower() for name in payload.get("excluded_process_names", [])],
            minidump_enabled=bool(payload.get("minidump_enabled", True)),
            screenshot_enabled=bool(payload.get("screenshot_enabled", True)),
        )


@dataclass
class TargetInfo:
    pid: int
    name: str
    hwnds: list[int]


@dataclass
class WatchState:
    hung_since: float | None = None
    last_action_at: float | None = None


class PlatformAdapter:
    """Platform abstraction so the policy can be tested off Windows."""

    def set_self_priority(self, priority_class: int) -> None:
        raise NotImplementedError

    def get_system_cpu_percent(self) -> float:
        raise NotImplementedError

    def list_targets(self) -> list[TargetInfo]:
        raise NotImplementedError

    def is_target_hung(self, target: TargetInfo, timeout_ms: int) -> bool:
        raise NotImplementedError

    def suspend_process_tree(self, pid: int) -> None:
        raise NotImplementedError

    def capture_forensics(self, target: TargetInfo, system_cpu: float, reason: str) -> dict[str, Any]:
        raise NotImplementedError

    def terminate_process_tree(self, pid: int, timeout_seconds: float) -> None:
        raise NotImplementedError


class ShieldStopper:
    """Adaptive policy engine for process monitoring and intervention."""

    def __init__(self, config: ShieldConfig, adapter: PlatformAdapter, logger: logging.Logger) -> None:
        self.config = config
        self.adapter = adapter
        self.logger = logger
        self.states: dict[int, WatchState] = {}
        self.current_priority: int | None = None

    def run_forever(self) -> None:
        self.logger.info("Shield Stopper started.")
        while True:
            self.step()
            time.sleep(self.config.poll_interval_seconds)

    def step(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        system_cpu = self.adapter.get_system_cpu_percent()
        desired_priority = self._desired_priority(system_cpu)
        if desired_priority != self.current_priority:
            self.adapter.set_self_priority(desired_priority)
            self.current_priority = desired_priority
            self.logger.info(
                "Adjusted watchdog priority to %s at %.1f%% system CPU.",
                self._priority_name(desired_priority),
                system_cpu,
            )

        visible_pids: set[int] = set()
        for target in self.adapter.list_targets():
            if not self._should_monitor(target):
                continue

            visible_pids.add(target.pid)
            state = self.states.setdefault(target.pid, WatchState())
            hung = self.adapter.is_target_hung(target, self.config.unresponsive_timeout_ms)
            if hung:
                if state.hung_since is None:
                    state.hung_since = now
                    self.logger.warning(
                        "Detected unresponsive UI for %s (PID %s); starting %.0fs grace period.",
                        target.name,
                        target.pid,
                        self.config.grace_period_seconds,
                    )

                elapsed = now - state.hung_since
                if system_cpu >= self.config.critical_cpu_threshold:
                    reason = (
                        f"critical_cpu:{system_cpu:.1f}>="
                        f"{self.config.critical_cpu_threshold:.1f}"
                    )
                    self._respond(target, system_cpu, elapsed, reason)
                    self.states.pop(target.pid, None)
                elif elapsed >= self.config.grace_period_seconds:
                    reason = f"grace_expired:{elapsed:.1f}s"
                    self._respond(target, system_cpu, elapsed, reason)
                    self.states.pop(target.pid, None)
            else:
                if state.hung_since is not None:
                    self.logger.info(
                        "Process %s (PID %s) recovered after %.1fs; resetting timer.",
                        target.name,
                        target.pid,
                        now - state.hung_since,
                    )
                    state.hung_since = None

        self.states = {pid: state for pid, state in self.states.items() if pid in visible_pids}

    def _respond(self, target: TargetInfo, system_cpu: float, elapsed: float, reason: str) -> None:
        self.logger.error(
            "Intervening on %s (PID %s) after %.1fs hung state; reason=%s.",
            target.name,
            target.pid,
            elapsed,
            reason,
        )
        try:
            self.adapter.suspend_process_tree(target.pid)
        except Exception as exc:
            self.logger.exception("Suspension failed for PID %s: %s", target.pid, exc)

        artifact_summary: dict[str, Any] = {"error": "forensics_not_collected"}
        try:
            artifact_summary = self.adapter.capture_forensics(target, system_cpu, reason)
        except Exception as exc:
            artifact_summary = {"error": str(exc)}
            self.logger.exception("Forensics failed for PID %s: %s", target.pid, exc)

        self.logger.error("Forensic snapshot for PID %s: %s", target.pid, artifact_summary)
        try:
            self.adapter.terminate_process_tree(target.pid, self.config.terminate_timeout_seconds)
        except Exception as exc:
            self.logger.exception("Termination failed for PID %s: %s", target.pid, exc)
            return
        self.logger.error("Forced termination complete for PID %s.", target.pid)

    def _desired_priority(self, system_cpu: float) -> int:
        if system_cpu >= self.config.high_cpu_threshold:
            return REALTIME_PRIORITY_CLASS
        return HIGH_PRIORITY_CLASS

    def _priority_name(self, priority_class: int) -> str:
        if priority_class == REALTIME_PRIORITY_CLASS:
            return "REALTIME_PRIORITY_CLASS"
        return "HIGH_PRIORITY_CLASS"

    def _should_monitor(self, target: TargetInfo) -> bool:
        lowered_name = target.name.lower()
        if target.pid == os.getpid():
            return False
        if lowered_name in self.config.excluded_process_names:
            return False
        if self.config.target_process_names and lowered_name not in self.config.target_process_names:
            return False
        return bool(target.hwnds)


class WindowsPlatformAdapter(PlatformAdapter):
    """Windows implementation for process inspection, forensics, and control."""

    def __init__(self, config: ShieldConfig, logger: logging.Logger) -> None:
        self.config = config
        self.logger = logger
        self.snapshot_dir = Path(config.snapshot_dir)
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        self.dbghelp = ctypes.WinDLL("DbgHelp", use_last_error=True)
        self._configure_win32_calls()

    def _configure_win32_calls(self) -> None:
        self.kernel32.SetPriorityClass.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD]
        self.kernel32.SetPriorityClass.restype = ctypes.wintypes.BOOL

        self.kernel32.OpenProcess.argtypes = [
            ctypes.wintypes.DWORD,
            ctypes.wintypes.BOOL,
            ctypes.wintypes.DWORD,
        ]
        self.kernel32.OpenProcess.restype = ctypes.wintypes.HANDLE

        self.kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = ctypes.wintypes.BOOL

        self.user32.SendMessageTimeoutW.argtypes = [
            ctypes.wintypes.HWND,
            ctypes.wintypes.UINT,
            ctypes.wintypes.WPARAM,
            ctypes.wintypes.LPARAM,
            ctypes.wintypes.UINT,
            ctypes.wintypes.UINT,
            ctypes.POINTER(ctypes.wintypes.ULONG_PTR),
        ]
        self.user32.SendMessageTimeoutW.restype = ctypes.wintypes.LPARAM

        self.ntdll.NtSuspendProcess.argtypes = [ctypes.wintypes.HANDLE]
        self.ntdll.NtSuspendProcess.restype = ctypes.wintypes.LONG

        self.dbghelp.MiniDumpWriteDump.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.wintypes.DWORD,
            ctypes.wintypes.HANDLE,
            ctypes.wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        self.dbghelp.MiniDumpWriteDump.restype = ctypes.wintypes.BOOL

    def set_self_priority(self, priority_class: int) -> None:
        handle = self.kernel32.GetCurrentProcess()
        if not self.kernel32.SetPriorityClass(handle, priority_class):
            raise ctypes.WinError(ctypes.get_last_error())

    def get_system_cpu_percent(self) -> float:
        return float(psutil.cpu_percent(interval=None))

    def list_targets(self) -> list[TargetInfo]:
        window_map: dict[int, list[int]] = {}

        def callback(hwnd: int, _: Any) -> bool:
            try:
                if not win32gui.IsWindowVisible(hwnd):
                    return True
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                if pid == 0 or pid == os.getpid():
                    return True
                window_map.setdefault(pid, []).append(hwnd)
            except pywintypes.error:
                return True
            return True

        win32gui.EnumWindows(callback, None)
        targets: list[TargetInfo] = []
        for pid, hwnds in window_map.items():
            try:
                process = psutil.Process(pid)
                targets.append(TargetInfo(pid=pid, name=process.name(), hwnds=hwnds))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return targets

    def is_target_hung(self, target: TargetInfo, timeout_ms: int) -> bool:
        for hwnd in target.hwnds:
            if self._is_window_unresponsive(hwnd, timeout_ms):
                return True
        return False

    def suspend_process_tree(self, pid: int) -> None:
        try:
            process = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return

        descendants = process.children(recursive=True)
        ordered_pids = [process.pid] + [child.pid for child in descendants]
        for target_pid in ordered_pids:
            try:
                self._suspend_pid(target_pid)
            except Exception as exc:  # pragma: no cover - Windows only
                self.logger.warning("Unable to suspend PID %s: %s", target_pid, exc)

    def capture_forensics(self, target: TargetInfo, system_cpu: float, reason: str) -> dict[str, Any]:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        stem = f"{target.name}_{target.pid}_{timestamp}".replace(" ", "_")
        metadata_path = self.snapshot_dir / f"{stem}.json"
        dump_path = self.snapshot_dir / f"{stem}.dmp"
        screenshot_path = self.snapshot_dir / f"{stem}.bmp"

        snapshot = self._snapshot_metadata(target, system_cpu, reason)
        if self.config.minidump_enabled:
            try:
                self._write_minidump(target.pid, dump_path)
                snapshot["minidump_path"] = str(dump_path)
            except Exception as exc:  # pragma: no cover - Windows only
                snapshot["minidump_error"] = str(exc)

        if self.config.screenshot_enabled:
            try:
                self._capture_desktop_screenshot(screenshot_path)
                snapshot["screenshot_path"] = str(screenshot_path)
            except Exception as exc:  # pragma: no cover - Windows only
                snapshot["screenshot_error"] = str(exc)

        snapshot["metadata_path"] = str(metadata_path)
        metadata_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        return snapshot

    def terminate_process_tree(self, pid: int, timeout_seconds: float) -> None:
        try:
            parent = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return

        processes = parent.children(recursive=True) + [parent]
        for process in reversed(processes):
            try:
                process.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        _, alive = psutil.wait_procs(processes, timeout=timeout_seconds)
        for process in alive:
            try:
                process.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _is_window_unresponsive(self, hwnd: int, timeout_ms: int) -> bool:
        if not win32gui.IsWindow(hwnd):
            return False

        if hasattr(win32gui, "IsHungAppWindow"):
            try:
                if win32gui.IsHungAppWindow(hwnd):
                    return True
            except pywintypes.error:
                pass

        result = ctypes.wintypes.ULONG_PTR()
        ctypes.set_last_error(0)
        response = self.user32.SendMessageTimeoutW(
            hwnd,
            WM_NULL,
            0,
            0,
            SMTO_ABORTIFHUNG,
            timeout_ms,
            ctypes.byref(result),
        )
        if response == 0:
            error = ctypes.get_last_error()
            return error in (0, 1460)
        return False

    def _suspend_pid(self, pid: int) -> None:
        handle = self.kernel32.OpenProcess(
            PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION,
            False,
            pid,
        )
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())

        try:
            status = self.ntdll.NtSuspendProcess(handle)
            if status != 0:
                raise OSError(f"NtSuspendProcess failed with status 0x{status:08x}")
        finally:
            self.kernel32.CloseHandle(handle)

    def _snapshot_metadata(self, target: TargetInfo, system_cpu: float, reason: str) -> dict[str, Any]:
        process = psutil.Process(target.pid)
        with process.oneshot():
            memory_info = process.memory_info()
            try:
                cpu_percent = process.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                cpu_percent = None
            try:
                cmdline = process.cmdline()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                cmdline = []
            try:
                exe = process.exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                exe = ""

        return {
            "captured_at_utc": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "pid": target.pid,
            "name": target.name,
            "system_cpu_percent": system_cpu,
            "process_cpu_percent": cpu_percent,
            "rss_bytes": memory_info.rss,
            "vms_bytes": memory_info.vms,
            "exe": exe,
            "cmdline": cmdline,
            "window_titles": self._window_titles(target.hwnds),
        }

    def _window_titles(self, hwnds: list[int]) -> list[str]:
        titles: list[str] = []
        for hwnd in hwnds:
            try:
                title = win32gui.GetWindowText(hwnd).strip()
            except pywintypes.error:
                title = ""
            if title:
                titles.append(title)
        return titles

    def _write_minidump(self, pid: int, output_path: Path) -> None:
        if msvcrt is None:  # pragma: no cover - non-Windows import guard
            raise RuntimeError("msvcrt is unavailable outside Windows.")
        dump_type = 0x00000002  # MiniDumpWithFullMemory
        process_handle = self.kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            False,
            pid,
        )
        if not process_handle:
            raise ctypes.WinError(ctypes.get_last_error())

        try:
            with output_path.open("wb") as handle:
                file_handle = msvcrt.get_osfhandle(handle.fileno())
                success = self.dbghelp.MiniDumpWriteDump(
                    process_handle,
                    pid,
                    file_handle,
                    dump_type,
                    None,
                    None,
                    None,
                )
                if not success:
                    raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self.kernel32.CloseHandle(process_handle)

    def _capture_desktop_screenshot(self, output_path: Path) -> None:
        left = win32api.GetSystemMetrics(win32con.SM_XVIRTUALSCREEN)
        top = win32api.GetSystemMetrics(win32con.SM_YVIRTUALSCREEN)
        width = win32api.GetSystemMetrics(win32con.SM_CXVIRTUALSCREEN)
        height = win32api.GetSystemMetrics(win32con.SM_CYVIRTUALSCREEN)

        desktop_hwnd = win32gui.GetDesktopWindow()
        desktop_dc = win32gui.GetWindowDC(desktop_hwnd)
        img_dc = win32ui.CreateDCFromHandle(desktop_dc)
        mem_dc = img_dc.CreateCompatibleDC()
        bitmap = win32ui.CreateBitmap()
        bitmap.CreateCompatibleBitmap(img_dc, width, height)
        mem_dc.SelectObject(bitmap)
        mem_dc.BitBlt((0, 0), (width, height), img_dc, (left, top), win32con.SRCCOPY)
        bitmap.SaveBitmapFile(mem_dc, str(output_path))

        win32gui.DeleteObject(bitmap.GetHandle())
        mem_dc.DeleteDC()
        img_dc.DeleteDC()
        win32gui.ReleaseDC(desktop_hwnd, desktop_dc)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Shield Stopper process watchdog")
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help="Path to config.json (default: config.json)",
    )
    return parser.parse_args()


def setup_logger(log_path: Path) -> logging.Logger:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("shield_stopper")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    return logger


def ensure_windows_runtime() -> None:
    if os.name != "nt":
        raise RuntimeError("Shield Stopper only runs on Windows.")
    if psutil is None:
        raise RuntimeError("Missing dependency: psutil.")
    if not all([pywintypes, win32api, win32con, win32gui, win32process, win32ui]):
        raise RuntimeError("Missing dependency: pywin32.")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise RuntimeError("Shield Stopper must be started with Administrator privileges.")


def main() -> int:
    args = parse_args()
    config_path = Path(args.config).resolve()
    if not config_path.exists():
        print(f"Config file not found: {config_path}", file=sys.stderr)
        return 1

    try:
        ensure_windows_runtime()
        config = ShieldConfig.from_file(config_path)
        log_path = Path(config.snapshot_dir) / DEFAULT_LOG_FILE
        logger = setup_logger(log_path)
        adapter = WindowsPlatformAdapter(config=config, logger=logger)

        # Prime psutil's CPU sampling so the first values are meaningful.
        psutil.cpu_percent(interval=None)

        stopper = ShieldStopper(config=config, adapter=adapter, logger=logger)
        stopper.run_forever()
    except KeyboardInterrupt:
        print("Shield Stopper interrupted by user.")
        return 0
    except Exception as exc:
        print(f"Shield Stopper failed: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
