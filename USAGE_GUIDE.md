# Shield Stopper V2 Usage Guide

## 1. Supported Platforms

- Windows 10 / 11
- Linux with Python 3.11+
- macOS with Python 3.11+

Shield Stopper expects elevated privileges on every platform because suspension, dumping, and forced termination often fail without them.

## 2. Install Python Dependencies

### Windows

```powershell
py -3 -m pip install -r requirements.txt
```

### Linux / macOS

```bash
python3 -m pip install -r requirements.txt
```

`requirements.txt` now uses environment markers, so `pywin32` is only installed on Windows.

## 3. Optional Native Tools

For the best forensic coverage, install the native tools your platform supports.

### Linux

- `wmctrl`
- `xprop`
- `gcore`
- `scrot` or `gnome-screenshot` or `import` or `grim`

### macOS

- `osascript`
- `lldb`
- `screencapture`

### Windows

- No extra native package install is required beyond Python + `pywin32`

## 4. Configure the Watchdog

Open `config.json` and adjust:

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

Important:

- `full_memory_dumps` defaults to `false`
- Leave it `false` unless you intentionally want very large Windows dump files

Example allowlist:

```json
"target_process_names": ["blender.exe", "cyberpunk2077.exe", "ue4editor.exe"]
```

## 5. Start Shield Stopper

### Windows

Use the bundled batch launcher:

```powershell
run_shield.bat
```

It automatically re-launches itself with UAC elevation and starts:

```powershell
py -3 shield_launcher.py start --config config.json
```

If you want the optional GUI launcher instead:

```powershell
run_shield.bat gui
```

### Linux / macOS

Use the bundled shell launcher:

```bash
./run_shield.sh
```

It automatically re-launches itself with `sudo` when needed and starts:

```bash
python3 shield_launcher.py start --config config.json
```

If you want the optional GUI launcher instead:

```bash
./run_shield.sh gui
```

## 6. CLI Modes

You can also invoke the launcher directly:

```bash
python3 shield_launcher.py start --config config.json
python3 shield_launcher.py launch --config config.json
python3 shield_launcher.py gui --config config.json
python3 shield_launcher.py doctor
python3 shield_launcher.py open-config
python3 shield_launcher.py open-artifacts
```

## 7. What Happens During a Hang

1. Shield Stopper finds a target process it is allowed to monitor.
2. It checks whether the process appears unresponsive using the current platform adapter.
3. If the process recovers, the timer resets.
4. If the grace period expires, or CPU / GPU crosses the critical threshold:
   - the target process tree is suspended
   - forensic metadata is written
   - native dump capture is attempted
   - screenshot capture is attempted
   - the target process tree is force-killed

## 8. Artifact Output

Artifacts are written under `artifacts/` by default:

- `shield_stopper.log`
- `*.json` metadata snapshots
- Windows: `*.dmp`
- Linux: `gcore` output such as `*.PID`
- macOS: `*.core` when `lldb` succeeds
- screenshots when platform tools are available

## 9. Verify the Install

Run:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

This validates the cross-platform policy and adapter behavior through simulation.

## 10. Operational Advice

- Start with an allowlist of known heavy apps instead of watching every process on day one.
- Keep `full_memory_dumps` disabled unless you explicitly need full-memory crash forensics.
- Validate the platform-specific tooling on each OS before trusting it in production.
- Do not point Shield Stopper at critical operating-system services.
