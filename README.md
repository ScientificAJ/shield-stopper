# Shield Stopper

Shield Stopper is a Windows "first responder" for catastrophic application hangs. Instead of leaving you to fight Task Manager while the machine is stuttering, it watches GUI processes, waits through a configurable grace period, captures forensics, and escalates its own scheduling priority so it can still shut down the offending process tree when the system is close to locking up.

## What It Does

- Starts as a high-priority watchdog process.
- Escalates itself to `REALTIME_PRIORITY_CLASS` whenever total CPU or GPU usage crosses the configured overload threshold.
- Detects GUI hangs through `IsHungAppWindow` and `SendMessageTimeout`.
- Gives a hung app a configurable grace period to recover.
- Responds immediately if the grace period expires or the machine enters a critical CPU or GPU state.
- Suspends the target process tree before collecting forensic artifacts.
- Writes a JSON forensic record plus a minidump and desktop screenshot when available.
- Force-kills the target process tree to break the lockup cycle.

## Repository Layout

- `aeon_stopper.py`: main watchdog implementation and Windows adapter.
- `shield_launcher.py`: friendly GUI and CLI launcher.
- `run_shield.bat`: UAC-aware launcher for end users.
- `config.json`: runtime thresholds and target selection.
- `requirements.txt`: Python dependencies.
- `USAGE_GUIDE.md`: install and launch instructions.
- `tests/test_aeon_stopper.py`: simulation-based verification for escalation and grace-period behavior.

## Safety Notes

- `REALTIME_PRIORITY_CLASS` is intentionally aggressive. Shield Stopper only switches to it while the machine is already in an overload state, then drops back to `HIGH_PRIORITY_CLASS` when CPU pressure subsides.
- Administrator privileges are required because suspension, dumping, and process-tree termination on third-party processes can otherwise fail.
- The default configuration monitors visible GUI processes. If you want to limit intervention to known heavy applications, populate `target_process_names` in `config.json`.

## Quick Start

1. Install Python 3.11+ on Windows.
2. Install dependencies:

   ```powershell
   py -3 -m pip install -r requirements.txt
   ```

3. Double-click `run_shield.bat` to start the watchdog immediately with elevation.
4. If you want the optional desktop launcher instead, use `run_shield.bat gui`.
5. Review `artifacts/shield_stopper.log` and generated forensic files after an intervention.

## Easy Run Modes

After a `git pull`, you do not need to remember the raw Python entrypoint. Use one of these:

- One-click default: `run_shield.bat`
- GUI: `run_shield.bat gui`
- CLI in current console: `run_shield.bat start --config config.json`
- CLI in a new console: `run_shield.bat launch --config config.json`
- Install check: `run_shield.bat doctor`
- Direct Python CLI: `python shield_launcher.py start --config config.json`

## Configuration

`config.json` controls:

- `poll_interval_seconds`: watchdog scan interval.
- `grace_period_seconds`: how long an app may remain hung before intervention.
- `high_cpu_threshold`: CPU threshold for escalating Shield Stopper to realtime scheduling.
- `high_gpu_threshold`: GPU threshold for escalating Shield Stopper to realtime scheduling.
- `critical_cpu_threshold`: CPU threshold that bypasses the grace period and triggers immediate action.
- `critical_gpu_threshold`: GPU threshold that bypasses the grace period and triggers immediate action.
- `target_process_names`: optional allowlist of process image names such as `["blender.exe", "ue4editor.exe"]`.
- `excluded_process_names`: optional denylist.

## Verification

The included tests simulate:

- escalation from high priority to realtime when the host CPU crosses the overload threshold
- escalation from high priority to realtime when the host GPU crosses the overload threshold
- immediate intervention when CPU or GPU reaches the critical threshold
- grace-period expiry handling
- timer reset when a process recovers before the deadline

Run them with:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

## GitHub Launch Checklist

1. Initialize the repository and commit the files.
2. Create a GitHub repository.
3. Push the default branch.
4. Tag a release after you validate on a Windows machine with administrative rights.

Shield Stopper is released under the MIT License.
