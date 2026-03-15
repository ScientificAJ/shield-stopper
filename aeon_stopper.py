#!/usr/bin/env python3
"""Shield Stopper: cross-platform adaptive process watchdog."""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import msvcrt
except ImportError:  # pragma: no cover - Windows only
    msvcrt = None

try:
    import pwd
except ImportError:  # pragma: no cover - Windows only
    pwd = None

try:
    import winreg
except ImportError:  # pragma: no cover - Windows only
    winreg = None

try:
    import psutil
except ImportError:  # pragma: no cover - handled in runtime checks
    psutil = None

try:
    import pywintypes
    import win32api
    import win32con
    import win32gui
    import win32pdh
    import win32process
    import win32ui
except ImportError:  # pragma: no cover - handled in runtime checks
    pywintypes = None
    win32api = None
    win32con = None
    win32gui = None
    win32pdh = None
    win32process = None
    win32ui = None


HIGH_PRIORITY_CLASS = 0x00000080
REALTIME_PRIORITY_CLASS = 0x00000100

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
PROCESS_SUSPEND_RESUME = 0x0800

MINIDUMP_NORMAL = 0x00000000
MINIDUMP_WITH_FULL_MEMORY = 0x00000002

WM_NULL = 0x0000
SMTO_ABORTIFHUNG = 0x0002

DEFAULT_CONFIG_PATH = "config.json"
DEFAULT_LOG_FILE = "shield_stopper.log"

PRIORITY_HIGH = "high"
PRIORITY_REALTIME = "realtime"


@dataclass
class ShieldConfig:
    poll_interval_seconds: float = 2.0
    grace_period_seconds: float = 120.0
    high_cpu_threshold: float = 95.0
    critical_cpu_threshold: float = 98.0
    high_gpu_threshold: float = 95.0
    critical_gpu_threshold: float = 98.0
    unresponsive_timeout_ms: int = 1000
    terminate_timeout_seconds: float = 5.0
    snapshot_dir: str = "artifacts"
    target_process_names: list[str] = field(default_factory=list)
    excluded_process_names: list[str] = field(default_factory=list)
    minidump_enabled: bool = True
    screenshot_enabled: bool = True
    full_memory_dumps: bool = False

    @classmethod
    def from_file(cls, path: Path) -> "ShieldConfig":
        payload = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            poll_interval_seconds=float(payload.get("poll_interval_seconds", 2.0)),
            grace_period_seconds=float(payload.get("grace_period_seconds", 120.0)),
            high_cpu_threshold=float(payload.get("high_cpu_threshold", 95.0)),
            critical_cpu_threshold=float(payload.get("critical_cpu_threshold", 98.0)),
            high_gpu_threshold=float(payload.get("high_gpu_threshold", 95.0)),
            critical_gpu_threshold=float(payload.get("critical_gpu_threshold", 98.0)),
            unresponsive_timeout_ms=int(payload.get("unresponsive_timeout_ms", 1000)),
            terminate_timeout_seconds=float(payload.get("terminate_timeout_seconds", 5.0)),
            snapshot_dir=str(payload.get("snapshot_dir", "artifacts")),
            target_process_names=[str(name).lower() for name in payload.get("target_process_names", [])],
            excluded_process_names=[str(name).lower() for name in payload.get("excluded_process_names", [])],
            minidump_enabled=bool(payload.get("minidump_enabled", True)),
            screenshot_enabled=bool(payload.get("screenshot_enabled", True)),
            full_memory_dumps=bool(payload.get("full_memory_dumps", False)),
        )


@dataclass
class TargetInfo:
    pid: int
    name: str
    handles: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class WatchState:
    hung_since: float | None = None


@dataclass
class SystemLoad:
    cpu_percent: float
    gpu_percent: float | None = None

    def summary(self) -> str:
        if self.gpu_percent is None:
            return f"CPU {self.cpu_percent:.1f}% / GPU unavailable"
        return f"CPU {self.cpu_percent:.1f}% / GPU {self.gpu_percent:.1f}%"


def select_windows_dump_type(full_memory_dumps: bool) -> int:
    if full_memory_dumps:
        return MINIDUMP_WITH_FULL_MEMORY
    return MINIDUMP_NORMAL


class PlatformAdapter:
    """OS-specific hooks for the watchdog core."""

    platform_name = "unknown"

    def __init__(self, config: ShieldConfig, logger: logging.Logger) -> None:
        self.config = config
        self.logger = logger

    def set_self_priority(self, priority_mode: str) -> None:
        raise NotImplementedError

    def get_system_load(self) -> SystemLoad:
        raise NotImplementedError

    def list_targets(self) -> list[TargetInfo]:
        raise NotImplementedError

    def is_target_hung(self, target: TargetInfo, timeout_ms: int) -> bool:
        raise NotImplementedError

    def suspend_process_tree(self, pid: int) -> None:
        raise NotImplementedError

    def capture_forensics(self, target: TargetInfo, system_load: SystemLoad, reason: str) -> dict[str, Any]:
        raise NotImplementedError

    def terminate_process_tree(self, pid: int, timeout_seconds: float) -> None:
        raise NotImplementedError


class ShieldStopper:
    """OS-agnostic policy engine."""

    def __init__(self, config: ShieldConfig, adapter: PlatformAdapter, logger: logging.Logger) -> None:
        self.config = config
        self.adapter = adapter
        self.logger = logger
        self.states: dict[int, WatchState] = {}
        self.current_priority_mode: str | None = None

    def run_forever(self) -> None:
        self.logger.info("Shield Stopper started on %s.", self.adapter.platform_name)
        while True:
            self.step()
            time.sleep(self.config.poll_interval_seconds)

    def step(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        system_load = self.adapter.get_system_load()
        desired_priority_mode = self._desired_priority_mode(system_load)
        if desired_priority_mode != self.current_priority_mode:
            self.adapter.set_self_priority(desired_priority_mode)
            self.current_priority_mode = desired_priority_mode
            self.logger.info(
                "Adjusted watchdog priority to %s at %s.",
                desired_priority_mode,
                system_load.summary(),
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
                        "Detected unresponsive target for %s (PID %s); starting %.0fs grace period.",
                        target.name,
                        target.pid,
                        self.config.grace_period_seconds,
                    )

                elapsed = now - state.hung_since
                critical_reason = self._critical_reason(system_load)
                if critical_reason is not None:
                    self._respond(target, system_load, elapsed, critical_reason)
                    self.states.pop(target.pid, None)
                elif elapsed >= self.config.grace_period_seconds:
                    self._respond(target, system_load, elapsed, f"grace_expired:{elapsed:.1f}s")
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

    def _respond(self, target: TargetInfo, system_load: SystemLoad, elapsed: float, reason: str) -> None:
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
            artifact_summary = self.adapter.capture_forensics(target, system_load, reason)
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

    def _desired_priority_mode(self, system_load: SystemLoad) -> str:
        if system_load.cpu_percent >= self.config.high_cpu_threshold:
            return PRIORITY_REALTIME
        if system_load.gpu_percent is not None and system_load.gpu_percent >= self.config.high_gpu_threshold:
            return PRIORITY_REALTIME
        return PRIORITY_HIGH

    def _critical_reason(self, system_load: SystemLoad) -> str | None:
        reasons: list[str] = []
        if system_load.cpu_percent >= self.config.critical_cpu_threshold:
            reasons.append(
                f"critical_cpu:{system_load.cpu_percent:.1f}>={self.config.critical_cpu_threshold:.1f}"
            )
        if system_load.gpu_percent is not None and system_load.gpu_percent >= self.config.critical_gpu_threshold:
            reasons.append(
                f"critical_gpu:{system_load.gpu_percent:.1f}>={self.config.critical_gpu_threshold:.1f}"
            )
        if not reasons:
            return None
        return ",".join(reasons)

    def _should_monitor(self, target: TargetInfo) -> bool:
        name = target.name.lower()
        if target.pid == os.getpid():
            return False
        if name in self.config.excluded_process_names:
            return False
        if self.config.target_process_names and name not in self.config.target_process_names:
            return False
        return True


class UnixPlatformAdapter(PlatformAdapter):
    """Shared Unix process and artifact helpers for Linux and macOS."""

    screenshot_commands: list[list[str]] = []

    def __init__(self, config: ShieldConfig, logger: logging.Logger) -> None:
        super().__init__(config, logger)
        self.snapshot_dir = Path(config.snapshot_dir)
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)

    def set_self_priority(self, priority_mode: str) -> None:
        try:
            if sys.platform.startswith("linux") and hasattr(os, "sched_setscheduler"):
                if priority_mode == PRIORITY_REALTIME:
                    os.sched_setscheduler(0, os.SCHED_RR, os.sched_param(10))
                else:
                    os.sched_setscheduler(0, os.SCHED_OTHER, os.sched_param(0))
                    os.setpriority(os.PRIO_PROCESS, 0, -10)
            else:
                nice_value = -20 if priority_mode == PRIORITY_REALTIME else -10
                os.setpriority(os.PRIO_PROCESS, 0, nice_value)
        except Exception as exc:
            self.logger.warning("Unable to change %s priority mode: %s", self.platform_name, exc)

    def suspend_process_tree(self, pid: int) -> None:
        for process in self._process_tree(pid):
            try:
                os.kill(process.pid, signal.SIGSTOP)
            except ProcessLookupError:
                continue
            except PermissionError as exc:
                self.logger.warning("SIGSTOP failed for PID %s: %s", process.pid, exc)

    def terminate_process_tree(self, pid: int, timeout_seconds: float) -> None:
        processes = self._process_tree(pid)
        for process in reversed(processes):
            try:
                os.kill(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                continue
            except PermissionError as exc:
                self.logger.warning("SIGKILL failed for PID %s: %s", process.pid, exc)

        try:
            psutil.wait_procs(processes, timeout=timeout_seconds)
        except Exception:
            pass

    def capture_forensics(self, target: TargetInfo, system_load: SystemLoad, reason: str) -> dict[str, Any]:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        stem = f"{target.name}_{target.pid}_{timestamp}".replace(" ", "_")
        metadata_path = self.snapshot_dir / f"{stem}.json"
        screenshot_path = self.snapshot_dir / f"{stem}.png"
        snapshot = self._snapshot_metadata(target, system_load, reason)

        dump_path = self._write_native_dump(target.pid, stem)
        if dump_path is not None:
            snapshot["native_dump_path"] = str(dump_path)

        if self.config.screenshot_enabled:
            screenshot_result = self._capture_screenshot(screenshot_path)
            if screenshot_result is not None:
                snapshot["screenshot_path"] = str(screenshot_result)

        snapshot["metadata_path"] = str(metadata_path)
        metadata_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        return snapshot

    def _process_tree(self, pid: int) -> list[psutil.Process]:
        try:
            parent = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return []
        return parent.children(recursive=True) + [parent]

    def _snapshot_metadata(self, target: TargetInfo, system_load: SystemLoad, reason: str) -> dict[str, Any]:
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
            try:
                status = process.status()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                status = "unknown"

        return {
            "captured_at_utc": datetime.now(timezone.utc).isoformat(),
            "platform": self.platform_name,
            "reason": reason,
            "pid": target.pid,
            "name": target.name,
            "system_cpu_percent": system_load.cpu_percent,
            "system_gpu_percent": system_load.gpu_percent,
            "process_cpu_percent": cpu_percent,
            "process_status": status,
            "rss_bytes": memory_info.rss,
            "vms_bytes": memory_info.vms,
            "exe": exe,
            "cmdline": cmdline,
            "handles": target.handles,
            "metadata": target.metadata,
        }

    def _capture_screenshot(self, output_path: Path) -> Path | None:
        for command in self.screenshot_commands:
            if shutil.which(command[0]) is None:
                continue
            try:
                subprocess.run(command + [str(output_path)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
                return output_path
            except Exception as exc:
                self.logger.warning("Screenshot command failed for %s: %s", command[0], exc)
        return None

    def _write_native_dump(self, pid: int, stem: str) -> Path | None:
        raise NotImplementedError


class LinuxPlatformAdapter(UnixPlatformAdapter):
    platform_name = "linux"
    screenshot_commands = [
        ["scrot", "-z"],
        ["gnome-screenshot", "-f"],
        ["import", "-window", "root"],
        ["grim"],
    ]

    def get_system_load(self) -> SystemLoad:
        return SystemLoad(cpu_percent=float(psutil.cpu_percent(interval=None)), gpu_percent=self._sample_gpu_percent())

    def list_targets(self) -> list[TargetInfo]:
        window_targets = self._list_x11_targets()
        if window_targets:
            return window_targets
        return self._fallback_process_targets()

    def is_target_hung(self, target: TargetInfo, timeout_ms: int) -> bool:
        if self._linux_process_state(target.pid) == "D":
            return True
        if target.handles and shutil.which("xprop") is not None:
            for window_id in target.handles:
                if self._xprop_ping(window_id, timeout_ms):
                    return False
            return True
        return False

    def _write_native_dump(self, pid: int, stem: str) -> Path | None:
        if shutil.which("gcore") is None:
            return None
        output_prefix = self.snapshot_dir / stem
        try:
            subprocess.run(
                ["gcore", "-o", str(output_prefix), str(pid)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
            )
        except Exception as exc:
            self.logger.warning("gcore failed for PID %s: %s", pid, exc)
            return None

        dump_path = Path(f"{output_prefix}.{pid}")
        if dump_path.exists():
            return dump_path
        return None

    def _list_x11_targets(self) -> list[TargetInfo]:
        if shutil.which("wmctrl") is None:
            return []
        try:
            result = subprocess.run(
                ["wmctrl", "-lp"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
        except Exception:
            return []

        grouped: dict[int, TargetInfo] = {}
        for line in result.stdout.splitlines():
            parts = line.split(None, 4)
            if len(parts) < 4:
                continue
            window_id, _, pid_text, _host = parts[:4]
            title = parts[4] if len(parts) == 5 else ""
            if not pid_text.isdigit():
                continue
            pid = int(pid_text)
            try:
                name = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            target = grouped.setdefault(pid, TargetInfo(pid=pid, name=name))
            target.handles.append(window_id)
            if title:
                target.metadata.setdefault("window_titles", []).append(title)
        return list(grouped.values())

    def _fallback_process_targets(self) -> list[TargetInfo]:
        current_uid = os.getuid()
        targets: list[TargetInfo] = []
        for process in psutil.process_iter(["pid", "name", "uids", "terminal"]):
            try:
                if process.info["pid"] == os.getpid():
                    continue
                uids = process.info.get("uids")
                if uids is not None and uids.real != current_uid:
                    continue
                if process.info.get("terminal"):
                    continue
                targets.append(TargetInfo(pid=process.info["pid"], name=process.info.get("name") or f"pid-{process.pid}"))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return targets

    def _linux_process_state(self, pid: int) -> str | None:
        stat_path = Path("/proc") / str(pid) / "stat"
        try:
            payload = stat_path.read_text(encoding="utf-8")
        except OSError:
            return None
        parts = payload.split()
        if len(parts) < 3:
            return None
        return parts[2]

    def _xprop_ping(self, window_id: str, timeout_ms: int) -> bool:
        if shutil.which("xprop") is None:
            return False
        try:
            subprocess.run(
                ["xprop", "-id", window_id, "WM_NAME"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=max(timeout_ms / 1000.0, 0.2),
            )
            return True
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False

    def _sample_gpu_percent(self) -> float | None:
        if shutil.which("nvidia-smi") is None:
            return None
        try:
            result = subprocess.run(
                ["nvidia-smi", "--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
        except Exception:
            return None

        values: list[float] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                values.append(float(line))
            except ValueError:
                continue
        if not values:
            return None
        return max(values)


class MacOSPlatformAdapter(UnixPlatformAdapter):
    platform_name = "macos"
    screenshot_commands = [["screencapture", "-x"]]

    def get_system_load(self) -> SystemLoad:
        return SystemLoad(cpu_percent=float(psutil.cpu_percent(interval=None)), gpu_percent=None)

    def list_targets(self) -> list[TargetInfo]:
        if shutil.which("osascript") is None:
            return self._fallback_process_targets()
        script = """
        tell application "System Events"
          set rows to {}
          repeat with p in (every application process whose background only is false)
            set end of rows to ((unix id of p as text) & "|" & (name of p as text))
          end repeat
          return rows as string
        end tell
        """
        try:
            result = subprocess.run(
                ["osascript", "-e", script],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
        except Exception:
            return self._fallback_process_targets()

        targets: list[TargetInfo] = []
        for row in result.stdout.split(", "):
            if "|" not in row:
                continue
            pid_text, name = row.split("|", 1)
            if not pid_text.isdigit():
                continue
            targets.append(TargetInfo(pid=int(pid_text), name=name.strip()))
        return targets

    def is_target_hung(self, target: TargetInfo, timeout_ms: int) -> bool:
        try:
            status = psutil.Process(target.pid).status()
            if status == psutil.STATUS_DISK_SLEEP:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

        if shutil.which("osascript") is None:
            return False

        script = f'''
        with timeout of {max(int(timeout_ms / 1000), 1)} seconds
          tell application "System Events"
            set theName to name of first application process whose unix id is {target.pid}
          end tell
        end timeout
        '''
        try:
            subprocess.run(
                ["osascript", "-e", script],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=max(timeout_ms / 1000.0, 1.0) + 1.0,
            )
            return False
        except subprocess.TimeoutExpired:
            return True
        except Exception:
            return False

    def _write_native_dump(self, pid: int, stem: str) -> Path | None:
        if shutil.which("lldb") is None:
            return None
        output_path = self.snapshot_dir / f"{stem}.core"
        command = [
            "lldb",
            "--batch",
            "-o",
            f"process attach --pid {pid}",
            "-o",
            f"process save-core {output_path}",
            "-o",
            "detach",
            "-o",
            "quit",
        ]
        try:
            subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
            if output_path.exists():
                return output_path
        except Exception as exc:
            self.logger.warning("lldb core dump failed for PID %s: %s", pid, exc)
        return None

    def _fallback_process_targets(self) -> list[TargetInfo]:
        current_uid = os.getuid()
        username = pwd.getpwuid(current_uid).pw_name if pwd is not None else None
        targets: list[TargetInfo] = []
        for process in psutil.process_iter(["pid", "name", "username"]):
            try:
                if process.info["pid"] == os.getpid():
                    continue
                if username and process.info.get("username") != username:
                    continue
                targets.append(TargetInfo(pid=process.info["pid"], name=process.info.get("name") or f"pid-{process.pid}"))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return targets


class WindowsPlatformAdapter(PlatformAdapter):
    platform_name = "windows"

    def __init__(self, config: ShieldConfig, logger: logging.Logger) -> None:
        super().__init__(config, logger)
        self.snapshot_dir = Path(config.snapshot_dir)
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        self.dbghelp = ctypes.WinDLL("DbgHelp", use_last_error=True)
        self.pdh = ctypes.WinDLL("pdh", use_last_error=True)
        self.gpu_sampler = WindowsGpuCounterSampler(self.logger, self.pdh)
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

        self.pdh.PdhLookupPerfNameByIndexW.argtypes = [
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.DWORD,
            ctypes.wintypes.LPWSTR,
            ctypes.POINTER(ctypes.wintypes.DWORD),
        ]
        self.pdh.PdhLookupPerfNameByIndexW.restype = ctypes.wintypes.LONG

    def set_self_priority(self, priority_mode: str) -> None:
        desired = REALTIME_PRIORITY_CLASS if priority_mode == PRIORITY_REALTIME else HIGH_PRIORITY_CLASS
        handle = self.kernel32.GetCurrentProcess()
        if not self.kernel32.SetPriorityClass(handle, desired):
            raise ctypes.WinError(ctypes.get_last_error())

    def get_system_load(self) -> SystemLoad:
        return SystemLoad(
            cpu_percent=float(psutil.cpu_percent(interval=None)),
            gpu_percent=self.gpu_sampler.sample(),
        )

    def list_targets(self) -> list[TargetInfo]:
        grouped: dict[int, TargetInfo] = {}

        def callback(hwnd: int, _: Any) -> bool:
            try:
                if not win32gui.IsWindowVisible(hwnd):
                    return True
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                if pid == 0 or pid == os.getpid():
                    return True
                process = psutil.Process(pid)
                target = grouped.setdefault(pid, TargetInfo(pid=pid, name=process.name()))
                target.handles.append(str(hwnd))
                title = win32gui.GetWindowText(hwnd).strip()
                if title:
                    target.metadata.setdefault("window_titles", []).append(title)
            except (pywintypes.error, psutil.NoSuchProcess, psutil.AccessDenied):
                return True
            return True

        win32gui.EnumWindows(callback, None)
        return list(grouped.values())

    def is_target_hung(self, target: TargetInfo, timeout_ms: int) -> bool:
        for hwnd_text in target.handles:
            if self._is_window_unresponsive(int(hwnd_text), timeout_ms):
                return True
        return False

    def suspend_process_tree(self, pid: int) -> None:
        for process in self._process_tree(pid):
            try:
                self._suspend_pid(process.pid)
            except Exception as exc:
                self.logger.warning("Unable to suspend PID %s: %s", process.pid, exc)

    def capture_forensics(self, target: TargetInfo, system_load: SystemLoad, reason: str) -> dict[str, Any]:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        stem = f"{target.name}_{target.pid}_{timestamp}".replace(" ", "_")
        metadata_path = self.snapshot_dir / f"{stem}.json"
        dump_path = self.snapshot_dir / f"{stem}.dmp"
        screenshot_path = self.snapshot_dir / f"{stem}.bmp"

        snapshot = self._snapshot_metadata(target, system_load, reason)
        if self.config.minidump_enabled:
            try:
                self._write_minidump(target.pid, dump_path)
                snapshot["minidump_path"] = str(dump_path)
                snapshot["minidump_type"] = "full_memory" if self.config.full_memory_dumps else "normal"
            except Exception as exc:
                snapshot["minidump_error"] = str(exc)

        if self.config.screenshot_enabled:
            try:
                self._capture_desktop_screenshot(screenshot_path)
                snapshot["screenshot_path"] = str(screenshot_path)
            except Exception as exc:
                snapshot["screenshot_error"] = str(exc)

        snapshot["metadata_path"] = str(metadata_path)
        metadata_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        return snapshot

    def terminate_process_tree(self, pid: int, timeout_seconds: float) -> None:
        processes = self._process_tree(pid)
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

    def _process_tree(self, pid: int) -> list[psutil.Process]:
        try:
            parent = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return []
        return parent.children(recursive=True) + [parent]

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
            return ctypes.get_last_error() in (0, 1460)
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

    def _snapshot_metadata(self, target: TargetInfo, system_load: SystemLoad, reason: str) -> dict[str, Any]:
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
            "platform": self.platform_name,
            "reason": reason,
            "pid": target.pid,
            "name": target.name,
            "system_cpu_percent": system_load.cpu_percent,
            "system_gpu_percent": system_load.gpu_percent,
            "process_cpu_percent": cpu_percent,
            "rss_bytes": memory_info.rss,
            "vms_bytes": memory_info.vms,
            "exe": exe,
            "cmdline": cmdline,
            "handles": target.handles,
            "metadata": target.metadata,
        }

    def _write_minidump(self, pid: int, output_path: Path) -> None:
        if msvcrt is None:
            raise RuntimeError("msvcrt is unavailable outside Windows.")
        dump_type = select_windows_dump_type(self.config.full_memory_dumps)
        process_handle = self.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
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


class WindowsGpuCounterSampler:
    """Locale-aware GPU usage sampling for Windows performance counters."""

    def __init__(self, logger: logging.Logger, pdh: ctypes.WinDLL) -> None:
        self.logger = logger
        self.pdh = pdh
        self.query: Any | None = None
        self.counters: list[tuple[str, Any]] = []
        self.warning_emitted = False
        self.object_name = self._lookup_localized_perf_name("GPU Engine")
        self.counter_name = self._lookup_localized_perf_name("Utilization Percentage")
        self._initialize_query()

    def sample(self) -> float | None:
        if win32pdh is None or self.query is None or not self.counters:
            return None
        sample = self._sample_once()
        if sample is not None:
            return sample
        self._initialize_query()
        return self._sample_once()

    def _initialize_query(self) -> None:
        self._close_query()
        if win32pdh is None or not self.object_name or not self.counter_name:
            self._warn_once("Localized GPU performance counters are unavailable; GPU monitoring disabled.")
            return
        try:
            self.query = win32pdh.OpenQuery()
            _, instances = win32pdh.EnumObjectItems(None, None, self.object_name, win32pdh.PERF_DETAIL_WIZARD)
            for instance in instances:
                if instance == "_Total":
                    continue
                path = win32pdh.MakeCounterPath((None, self.object_name, instance, None, -1, self.counter_name))
                counter = win32pdh.AddCounter(self.query, path)
                self.counters.append((instance, counter))
            if self.counters:
                win32pdh.CollectQueryData(self.query)
            else:
                self._warn_once("GPU counters were found but no GPU engine instances were available.")
        except Exception as exc:
            self._warn_once(f"GPU counter initialization failed: {exc}")
            self._close_query()

    def _sample_once(self) -> float | None:
        try:
            win32pdh.CollectQueryData(self.query)
            totals_by_engine: dict[str, float] = {}
            for instance, counter in self.counters:
                _, value = win32pdh.GetFormattedCounterValue(counter, win32pdh.PDH_FMT_DOUBLE)
                if value < 0:
                    continue
                engine_type = self._engine_type(instance)
                totals_by_engine[engine_type] = totals_by_engine.get(engine_type, 0.0) + float(value)
            if not totals_by_engine:
                return 0.0
            return min(100.0, max(totals_by_engine.values()))
        except Exception as exc:
            self._warn_once(f"GPU utilization sample failed: {exc}")
            return None

    def _lookup_localized_perf_name(self, english_name: str) -> str | None:
        index = lookup_english_perf_index(english_name)
        if index is None:
            return None
        size = ctypes.wintypes.DWORD(0)
        self.pdh.PdhLookupPerfNameByIndexW(None, index, None, ctypes.byref(size))
        if size.value == 0:
            return None
        buffer = ctypes.create_unicode_buffer(size.value + 1)
        status = self.pdh.PdhLookupPerfNameByIndexW(None, index, buffer, ctypes.byref(size))
        if status != 0:
            return None
        return buffer.value

    def _engine_type(self, instance: str) -> str:
        marker = "engtype_"
        if marker not in instance:
            return "unknown"
        return instance.split(marker, 1)[1]

    def _close_query(self) -> None:
        if self.query is None or win32pdh is None:
            self.query = None
            self.counters = []
            return
        try:
            win32pdh.CloseQuery(self.query)
        except Exception:
            pass
        finally:
            self.query = None
            self.counters = []

    def _warn_once(self, message: str) -> None:
        if self.warning_emitted:
            return
        self.warning_emitted = True
        self.logger.warning(message)


def lookup_english_perf_index(english_name: str) -> int | None:
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\009") as key:
            values, _ = winreg.QueryValueEx(key, "Counter")
    except OSError:
        return None

    for idx in range(0, len(values), 2):
        if idx + 1 >= len(values):
            break
        if values[idx + 1].lower() == english_name.lower():
            try:
                return int(values[idx])
            except ValueError:
                return None
    return None


def create_platform_adapter(config: ShieldConfig, logger: logging.Logger) -> PlatformAdapter:
    if sys.platform == "win32":
        ensure_windows_runtime()
        return WindowsPlatformAdapter(config, logger)
    if sys.platform.startswith("linux"):
        ensure_unix_runtime("linux")
        return LinuxPlatformAdapter(config, logger)
    if sys.platform == "darwin":
        ensure_unix_runtime("macos")
        return MacOSPlatformAdapter(config, logger)
    raise RuntimeError(f"Unsupported platform: {sys.platform}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Shield Stopper process watchdog")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="Path to config.json (default: config.json)")
    return parser.parse_args(argv)


def setup_logger(log_path: Path) -> logging.Logger:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("shield_stopper")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.propagate = False

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    return logger


def ensure_windows_runtime() -> None:
    if psutil is None:
        raise RuntimeError("Missing dependency: psutil.")
    if not all([pywintypes, win32api, win32con, win32gui, win32process, win32ui]):
        raise RuntimeError("Missing dependency: pywin32.")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise RuntimeError("Shield Stopper must be started with Administrator privileges.")


def ensure_unix_runtime(platform_name: str) -> None:
    if psutil is None:
        raise RuntimeError("Missing dependency: psutil.")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise RuntimeError(f"Shield Stopper on {platform_name} must be started with sudo/root privileges.")


def run_watchdog(config_path: Path) -> int:
    if not config_path.exists():
        print(f"Config file not found: {config_path}", file=sys.stderr)
        return 1

    try:
        config = ShieldConfig.from_file(config_path)
        log_path = Path(config.snapshot_dir) / DEFAULT_LOG_FILE
        logger = setup_logger(log_path)
        adapter = create_platform_adapter(config, logger)
        psutil.cpu_percent(interval=None)
        ShieldStopper(config=config, adapter=adapter, logger=logger).run_forever()
    except KeyboardInterrupt:
        print("Shield Stopper interrupted by user.")
        return 0
    except Exception as exc:
        print(f"Shield Stopper failed: {exc}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    return run_watchdog(Path(args.config).resolve())


if __name__ == "__main__":
    raise SystemExit(main())
