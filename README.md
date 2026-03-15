# Shield Stopper V2

Shield Stopper is a cross-platform watchdog for catastrophic application hangs. It watches user-facing processes, gives them a short recovery window, captures forensic artifacts, and force-terminates the process tree when the machine is sliding toward a lockup.

V2 keeps the native Windows implementation, fixes the dump-size and GPU-localization edge cases, and adds Linux and macOS adapters through the same `PlatformAdapter` architecture.

## Highlights

- OS-agnostic watchdog policy in `aeon_stopper.py`
- Native platform adapters for Windows, Linux, and macOS
- Adaptive priority escalation on overload
- Grace-period reset if the target recovers
- Immediate intervention on critical CPU or GPU load
- Process-tree suspension before forensics
- Forced process-tree termination after artifact capture

## V2 Fixes

### Adaptive Windows Minidumps

The default dump mode is now `MiniDumpNormal` instead of `MiniDumpWithFullMemory`.

- Default: small stack-oriented dumps
- Opt-in: set `"full_memory_dumps": true` in `config.json` if you explicitly want full memory dumps

This prevents a hung 12 GB game from immediately writing a 12 GB `.dmp` file by default.

### Locale-Aware Windows GPU Counters

Windows GPU monitoring now resolves localized performance counter names instead of assuming the literal English string `GPU Engine`.

- The adapter reads the English counter index from `Perflib\\009`
- It then uses `PdhLookupPerfNameByIndexW` to resolve the localized object and counter names

That keeps GPU-triggered escalation working on non-English Windows installs.

## Platform Behavior

### Windows

- Hang checks: `IsHungAppWindow` and `SendMessageTimeout`
- Priority: `HIGH_PRIORITY_CLASS` by default, `REALTIME_PRIORITY_CLASS` on overload
- Forensics: Win32 minidump plus desktop screenshot
- Suspension: `NtSuspendProcess`
- Termination: forced process-tree kill via `psutil`

### Linux

- Hang checks: X11 probing through `wmctrl` and `xprop` when available, plus `/proc/<pid>/stat` detection for `D` state
- Priority: aggressive `nice` / `sched_setscheduler` where allowed
- Forensics: `gcore` for native dumps when available, screenshot via `scrot` / `gnome-screenshot` / `import` / `grim`
- Suspension: `SIGSTOP`
- Termination: `SIGKILL`

### macOS

- Hang checks: AppleScript / `System Events` timeout probing, plus process-state fallback
- Priority: elevated `nice` values where permitted
- Forensics: `lldb` core-save attempt, screenshot via `screencapture`
- Suspension: `SIGSTOP`
- Termination: `SIGKILL`

## Repository Layout

- `aeon_stopper.py`: watchdog core plus platform adapters
- `shield_launcher.py`: GUI and CLI launcher
- `run_shield.bat`: elevated Windows launcher
- `run_shield.sh`: elevated Linux/macOS launcher
- `config.json`: thresholds and runtime behavior
- `requirements.txt`: environment-marked Python dependencies
- `USAGE_GUIDE.md`: step-by-step install and run guide
- `tests/`: simulation and adapter tests

## Quick Start

### Windows

1. Install Python 3.11+
2. Install dependencies:

   ```powershell
   py -3 -m pip install -r requirements.txt
   ```

3. Double-click `run_shield.bat`

### Linux / macOS

1. Install Python 3.11+
2. Install dependencies:

   ```bash
   python3 -m pip install -r requirements.txt
   ```

3. Launch:

   ```bash
   ./run_shield.sh
   ```

The shell launcher auto-reexecs with `sudo` when required.

## Optional Native Tools

Shield Stopper works best when these native tools are available:

- Linux: `wmctrl`, `xprop`, `gcore`, `scrot`, `gnome-screenshot`, `import`, or `grim`
- macOS: `osascript`, `lldb`, `screencapture`

The watchdog degrades gracefully when a platform-specific forensic tool is missing.

## Configuration

`config.json` controls:

- `poll_interval_seconds`
- `grace_period_seconds`
- `high_cpu_threshold`
- `critical_cpu_threshold`
- `high_gpu_threshold`
- `critical_gpu_threshold`
- `target_process_names`
- `excluded_process_names`
- `minidump_enabled`
- `screenshot_enabled`
- `full_memory_dumps`

## Run Modes

The launcher supports both GUI and CLI usage:

- Current console: `python shield_launcher.py start --config config.json`
- Detached launch: `python shield_launcher.py launch --config config.json`
- GUI launcher: `python shield_launcher.py gui --config config.json`
- Environment check: `python shield_launcher.py doctor`

On Windows, `run_shield.bat` defaults to `start`.
On Linux and macOS, `run_shield.sh` defaults to `start`.

## Verification

The included tests verify:

- CPU and GPU threshold escalation
- emergency intervention behavior
- grace-period reset behavior
- adaptive Windows dump-type selection
- Linux `SIGKILL` behavior
- Linux `D`-state hang detection
- macOS timeout-based hang detection
- launcher path resolution and command building

Run them with:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

## Current Validation Scope

This repository now contains working cross-platform adapters and simulation coverage, but this environment can only execute Linux-hosted tests. The Windows and macOS adapter paths were validated by unit tests and static checks here, not by live end-to-end execution on native Windows and macOS hosts.

## License

MIT
