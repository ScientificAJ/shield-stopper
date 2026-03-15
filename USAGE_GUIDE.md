# Shield Stopper Usage Guide

## 1. Prerequisites

- Windows 10 or Windows 11
- Administrator rights on the machine
- Python 3.11 or newer

## 2. Install Python

1. Download Python from https://www.python.org/downloads/windows/
2. During installation, enable `Add python.exe to PATH`.
3. Open `Command Prompt` and verify:

   ```powershell
   py -3 --version
   ```

## 3. Get the Project

1. Download the repository ZIP from GitHub and extract it, or clone it:

   ```powershell
   git clone <your-repo-url>
   cd shielder
   ```

## 4. Install Dependencies

Run:

```powershell
py -3 -m pip install -r requirements.txt
```

## 5. Configure What Shield Stopper Watches

Open `config.json` and adjust:

- `grace_period_seconds` if you want a shorter or longer wait.
- `target_process_names` if you want to only monitor specific heavy apps.
- `excluded_process_names` if you never want certain processes touched.
- `snapshot_dir` if you want forensic output in a different folder.

Example allowlist:

```json
"target_process_names": ["blender.exe", "eldenring.exe", "ue4editor.exe"]
```

If `target_process_names` is left empty, Shield Stopper watches all visible GUI processes except itself.

## 6. Start the Watchdog

The recommended entrypoint is `run_shield.bat`. It now opens a simple GUI by default and still supports CLI modes.

1. Double-click `run_shield.bat`.
2. Accept the Windows UAC prompt.
3. In the GUI, click `Start Watchdog`.
4. Leave the watchdog console window open while Shield Stopper is active.

The batch file re-launches itself with elevation automatically, then starts the launcher:

```powershell
py -3 shield_launcher.py gui --config config.json
```

### CLI options

If you prefer the terminal, use:

```powershell
run_shield.bat start --config config.json
```

Other useful modes:

```powershell
run_shield.bat launch --config config.json
run_shield.bat doctor
run_shield.bat open-config
run_shield.bat open-artifacts
```

You can also run the launcher directly after a `git pull`:

```powershell
py -3 shield_launcher.py start --config config.json
```

## 7. What Happens During a Hang

1. Shield Stopper detects an unresponsive GUI window.
2. A grace timer starts.
3. If the app recovers, the timer resets.
4. If the timer expires or total CPU hits the critical threshold:
   - the process tree is suspended
   - forensic data is written
   - a minidump and screenshot are attempted
   - the process tree is force-killed

## 8. Where Forensics Are Stored

By default, artifacts are written under `artifacts/`:

- `shield_stopper.log`
- `*.json` metadata snapshots
- `*.dmp` minidumps
- `*.bmp` desktop screenshots

## 9. Validate the Realtime Escalation Path

Run the included simulation tests:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

On a real Windows machine, you should also test with a sacrificial GUI application before trusting the tool in production.

## 10. Operational Advice

- Start with a short allowlist of known heavy applications.
- Do not point the tool at system-critical Windows processes.
- Review artifacts after each intervention to confirm the target and timing were correct.
- If minidump generation fails for protected processes, the JSON metadata and screenshot still provide a forensic trail.
