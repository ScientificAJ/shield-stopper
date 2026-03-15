#!/usr/bin/env python3
"""Friendly GUI and CLI launcher for Shield Stopper."""

from __future__ import annotations

import argparse
import ctypes
import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

from aeon_stopper import DEFAULT_CONFIG_PATH, ShieldConfig, run_watchdog


ROOT_DIR = Path(__file__).resolve().parent
WATCHDOG_SCRIPT = ROOT_DIR / "aeon_stopper.py"


def resolve_config_path(config_value: str) -> Path:
    candidate = Path(config_value)
    if not candidate.is_absolute():
        candidate = ROOT_DIR / candidate
    return candidate.resolve()


def build_watchdog_command(config_path: Path) -> list[str]:
    return [sys.executable, str(WATCHDOG_SCRIPT), "--config", str(config_path)]


def has_required_privileges() -> bool:
    if os.name != "nt":
        return not hasattr(os, "geteuid") or os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def dependency_available(module_name: str) -> bool:
    return importlib.util.find_spec(module_name) is not None


def print_doctor_report(config_path: Path) -> int:
    print("Shield Stopper Doctor")
    print(f"Root: {ROOT_DIR}")
    print(f"Python: {sys.executable}")
    print(f"Config: {config_path}")
    print(f"Config exists: {'yes' if config_path.exists() else 'no'}")
    print(f"Platform: {os.name}")
    print(f"Privileges ready: {'yes' if has_required_privileges() else 'no'}")
    print(f"psutil installed: {'yes' if dependency_available('psutil') else 'no'}")
    print(f"pywin32 installed: {'yes' if dependency_available('win32gui') else 'no'}")

    if config_path.exists():
        try:
            config = ShieldConfig.from_file(config_path)
            artifact_dir = (ROOT_DIR / config.snapshot_dir).resolve()
            print(f"Artifacts: {artifact_dir}")
            print(f"Grace period: {config.grace_period_seconds}s")
            print(f"Realtime thresholds: CPU {config.high_cpu_threshold}% / GPU {config.high_gpu_threshold}%")
            print(f"Critical thresholds: CPU {config.critical_cpu_threshold}% / GPU {config.critical_gpu_threshold}%")
            print(f"Full memory dumps: {'yes' if config.full_memory_dumps else 'no'}")
        except Exception as exc:
            print(f"Config load: failed ({exc})")
            return 1

    return 0


def open_in_shell(path: Path) -> int:
    if os.name == "nt":
        os.startfile(str(path))
        return 0
    opener = "open" if sys.platform == "darwin" else "xdg-open"
    if shutil.which(opener):
        subprocess.Popen([opener, str(path)], cwd=str(ROOT_DIR))
        return 0
    print(path)
    return 0


def launch_detached(config_path: Path) -> int:
    command = build_watchdog_command(config_path)
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
        subprocess.Popen(command, cwd=str(ROOT_DIR), creationflags=creationflags)
        return 0

    subprocess.Popen(command, cwd=str(ROOT_DIR), start_new_session=True)
    return 0


def run_gui(config_path: Path) -> int:
    import tkinter as tk
    from tkinter import messagebox

    def start_watchdog() -> None:
        if not config_path.exists():
            messagebox.showerror("Shield Stopper", f"Config file not found:\n{config_path}")
            return
        if not has_required_privileges():
            messagebox.showerror(
                "Shield Stopper",
                "Elevated privileges are required.\nUse run_shield.bat on Windows or run_shield.sh on Linux/macOS.",
            )
            return
        try:
            launch_detached(config_path)
            status_var.set("Watchdog started in a new console window.")
        except Exception as exc:
            messagebox.showerror("Shield Stopper", f"Unable to start watchdog:\n{exc}")

    def open_config() -> None:
        open_in_shell(config_path)

    def open_artifacts() -> None:
        try:
            config = ShieldConfig.from_file(config_path)
            artifact_dir = (ROOT_DIR / config.snapshot_dir).resolve()
            artifact_dir.mkdir(parents=True, exist_ok=True)
            open_in_shell(artifact_dir)
        except Exception as exc:
            messagebox.showerror("Shield Stopper", f"Unable to open artifacts:\n{exc}")

    def run_doctor() -> None:
        try:
            report_lines = capture_doctor_report(config_path)
        except Exception as exc:
            messagebox.showerror("Shield Stopper", f"Doctor failed:\n{exc}")
            return
        messagebox.showinfo("Shield Stopper Doctor", "\n".join(report_lines))

    root = tk.Tk()
    root.title("Shield Stopper")
    root.geometry("520x320")
    root.resizable(False, False)

    container = tk.Frame(root, padx=18, pady=18)
    container.pack(fill="both", expand=True)

    title = tk.Label(container, text="Shield Stopper", font=("Segoe UI", 18, "bold"))
    title.pack(anchor="w")

    subtitle = tk.Label(
        container,
        text="Launch the watchdog, inspect config, and verify the install after a git update.",
        justify="left",
        wraplength=470,
    )
    subtitle.pack(anchor="w", pady=(6, 14))

    details = tk.Label(
        container,
        text=(
            f"Config: {config_path}\n"
            f"CLI: python shield_launcher.py start --config \"{config_path}\"\n"
            f"Doctor: python shield_launcher.py doctor"
        ),
        justify="left",
        wraplength=470,
    )
    details.pack(anchor="w", pady=(0, 14))

    buttons = tk.Frame(container)
    buttons.pack(anchor="w", pady=(0, 12))

    tk.Button(buttons, text="Start Watchdog", width=18, command=start_watchdog).grid(row=0, column=0, padx=(0, 8), pady=4)
    tk.Button(buttons, text="Open Config", width=18, command=open_config).grid(row=0, column=1, padx=(0, 8), pady=4)
    tk.Button(buttons, text="Open Artifacts", width=18, command=open_artifacts).grid(row=1, column=0, padx=(0, 8), pady=4)
    tk.Button(buttons, text="Run Doctor", width=18, command=run_doctor).grid(row=1, column=1, padx=(0, 8), pady=4)

    status_var = tk.StringVar(value="Ready.")
    status = tk.Label(container, textvariable=status_var, anchor="w", justify="left", wraplength=470)
    status.pack(anchor="w", pady=(12, 0))

    root.mainloop()
    return 0


def capture_doctor_report(config_path: Path) -> list[str]:
    lines = [
        "Shield Stopper Doctor",
        f"Root: {ROOT_DIR}",
        f"Python: {sys.executable}",
        f"Config: {config_path}",
        f"Config exists: {'yes' if config_path.exists() else 'no'}",
        f"Platform: {os.name}",
        f"Privileges ready: {'yes' if has_required_privileges() else 'no'}",
        f"psutil installed: {'yes' if dependency_available('psutil') else 'no'}",
        f"pywin32 installed: {'yes' if dependency_available('win32gui') else 'no'}",
    ]
    if config_path.exists():
        config = ShieldConfig.from_file(config_path)
        lines.extend(
            [
                f"Artifacts: {(ROOT_DIR / config.snapshot_dir).resolve()}",
                f"Grace period: {config.grace_period_seconds}s",
                f"Realtime thresholds: CPU {config.high_cpu_threshold}% / GPU {config.high_gpu_threshold}%",
                f"Critical thresholds: CPU {config.critical_cpu_threshold}% / GPU {config.critical_gpu_threshold}%",
                f"Full memory dumps: {'yes' if config.full_memory_dumps else 'no'}",
            ]
        )
    return lines


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Shield Stopper GUI and CLI launcher")
    parser.add_argument(
        "mode",
        nargs="?",
        default="gui",
        choices=["gui", "start", "launch", "doctor", "open-config", "open-artifacts"],
        help="gui opens the desktop launcher; start runs in the current console; launch starts in a new console",
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help="Path to config.json (default: config.json)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config_path = resolve_config_path(args.config)

    if args.mode == "gui":
        return run_gui(config_path)
    if args.mode == "start":
        return run_watchdog(config_path)
    if args.mode == "launch":
        return launch_detached(config_path)
    if args.mode == "doctor":
        return print_doctor_report(config_path)
    if args.mode == "open-config":
        return open_in_shell(config_path)
    if args.mode == "open-artifacts":
        if config_path.exists():
            config = ShieldConfig.from_file(config_path)
            artifact_dir = (ROOT_DIR / config.snapshot_dir).resolve()
        else:
            artifact_dir = ROOT_DIR / "artifacts"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        return open_in_shell(artifact_dir)

    parser.error(f"Unsupported mode: {args.mode}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
