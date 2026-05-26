# PC Check — Python parity port

Read-only Windows forensic kit. A gamer runs it, hands the resulting `.txt` (and matching `_visual.html`) to a third party, and the third party reads it to decide whether the machine shows signs of cheat software, HWID spoofers, DMA-cheat build artifacts, or commercial input adapters (XIM, Cronus, ReaSnow, KMBox, Titan, reWASD).

This is a Python parity port of the PowerShell kit. **The PowerShell kit in `../kit/` remains the canonical implementation.** This Python version is provided as an alternative for reviewers who would rather read Python source, and for cross-platform development.

## What it does

- 22 scanners across Prefetch, BAM, MUICache, USB history, ShimCache, services, drivers, downloads, recent files, AppData, user-folder script content, lua scripts, obscured filenames, process modules, DLL injection event timeline, network attack tools, AI-vision aimbot constellation, known hashes, DMA build artifacts, application data dirs.
- BYOVD detection by cross-referencing loaded drivers against the public [loldrivers.io](https://www.loldrivers.io) database (opt-in network call, the only network call the kit ever makes).
- Recency decay: artifacts older than 180 days are logged in a separate Historical section and do not bump the verdict — a clean current machine should not be condemned for old, abandoned software.
- Verdict tiers:
  - PC mode: `CHEATS DETECTED` / `INPUT DEVICES DETECTED` / `UNSURE` / `CLEAN`
  - Console-rig mode: `MITM CHEAT STACK DETECTED` / `CAPTURE STACK PRESENT` / `UNSURE` / `CLEAN`
- HTML companion auto-generated alongside the text report.

## Requirements

- Windows 10 / 11
- Python 3.10 or newer (Windows installer from python.org or the Microsoft Store both work)
- Run as Administrator for full coverage (BAM, USB property keys, ShimCache, driver enumeration). The scan still runs without admin but will emit `WARN` for inaccessible sources.

No `pip install` is required to inspect the source — every file is plain `.py` and the kit uses only the Python standard library.

## Usage

PC mode (default — for a gamer auditing their own gaming PC):

```powershell
python -m pc_check
# or, if installed:
pc-check
```

Console-rig mode (for a console gamer auditing a PC connected to their console rig):

```powershell
python -m pc_check.console_rig_audit
# or, if installed:
pc-check-console-rig
```

Unified launcher (runs both back-to-back, like the PowerShell `Run scan.bat`):

```powershell
scripts\run-scan.bat
```

Options:

- `--output PATH` — override the auto-resolved Desktop output path.
- `--skip-loldrivers` — disable the optional LOLDrivers BYOVD cross-reference (the only outbound network call).
- `--no-html` — skip the HTML companion.

## Output

Two files on the user's Desktop, both timestamped:

- `PCForensicCheck_YYYYMMDD_HHMMSS.txt` (or `ConsoleRigAudit_*.txt`)
- `PCForensicCheck_YYYYMMDD_HHMMSS_visual.html`

The `.txt` opens with a `QUICK READ` block stating the verdict and the named items that drove it. The HTML is a colour-coded version of the same data plus a finding timeline.

## Architecture

- `src/pc_check/keywords.py` — all keyword arrays, allowlists, hash database. Add a new cheat-brand token here and every scanner picks it up.
- `src/pc_check/utils.py` — `match_keyword`, `classify_path_risk`, `score_item`, `score_and_add`, admin check, FileTime conversion.
- `src/pc_check/scanners.py` — the 21 scan functions and `invoke_all_scans`.
- `src/pc_check/snapshots.py` — process + service snapshots.
- `src/pc_check/recency.py` — `apply_recency_decay` and the 180-day rule.
- `src/pc_check/loldrivers.py` — `resolve_loldrivers_db` (opt-in CSV fetch + 1h cache).
- `src/pc_check/reports.py` — text report builder, shared by both drivers.
- `src/pc_check/visual_companion.py` — HTML companion, shared by both drivers (unified from day one).
- `src/pc_check/forensic_scan.py` — PC driver.
- `src/pc_check/console_rig_audit.py` — console-rig driver.

## Authorship

Author: Bread. Contributor: Drownmw.

See `../docs/handoff.md` for the full PowerShell-kit history and the project's design rationale.
