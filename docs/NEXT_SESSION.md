# NEXT SESSION — open items after v4.2.0 visual companion ship

Fresh-session pickup doc. The previous session (committed in `e8ec1f3`)
landed the v4.2.0 PowerShell visual-companion port to the dark-tactical
design, added the new **Activity by pattern** lifecycle section, fixed
several rendering bugs, and tightened scanner keyword matching to drop a
class of false positives. Two carryover issues from the v4.1.5 field
test remain — one of which (Issue 1) was deliberately deferred when Brad
chose to pursue Issue 2 first.

**Read this first**, then `docs/handoff.md` for project context, then
`git show e8ec1f3 --stat` to see exactly what shipped.

Repo: https://github.com/Sutaigne/alibi · current tip: `e8ec1f3` (untagged)

---

## Issue 1 — "It ran multiple scans" (CARRYOVER from v4.1.5)

**Status:** Untouched. Same diagnosis the previous handoff carried.

**Symptom:** Double-clicking `Run scan.bat` (the unified launcher at repo
root) produced more than the expected pair of scans (PC mode +
console-rig mode). Exact count unclear.

**Possible causes (ranked by likelihood):**

1. **UAC self-elevation loop.** `Run scan.bat` checks `NET SESSION`, and
   if non-admin, calls `powershell.exe ... Start-Process -FilePath
   '%~f0' -Verb RunAs` to spawn an elevated copy of itself, then
   `exit /b`. If the elevated copy somehow re-enters the elevation
   branch (e.g. `NET SESSION` failing intermittently inside the elevated
   process), it re-spawns. Infinite loop possible.
2. **Accidental double-click.** Each click spawns its own independent
   UAC + scan flow. The kit doesn't prevent concurrent launches.
3. **v4.1.5 self-elevation messaging change broke parsing.** v4.1.5
   added an explanatory text block before the elevation. Possibly a
   character in the new echo block breaks cmd parsing and causes weird
   control flow. Diff v4.1.4 vs v4.1.5 of `Run scan.bat` and look for
   unescaped `&`, `(`, `)`, `|`, `^`, `>` inside the new echo block.

**Diagnosis to run first in the next session:**

```powershell
# Count actual report files on Brad's Desktop with timestamps
Get-ChildItem $env:USERPROFILE\Desktop -Filter 'AlibiReport_*.txt' |
    Sort-Object LastWriteTime |
    Select-Object Name, LastWriteTime
Get-ChildItem $env:USERPROFILE\Desktop -Filter 'AlibiRigReport_*.txt' |
    Sort-Object LastWriteTime |
    Select-Object Name, LastWriteTime
# Plus look for the older PCForensicCheck_* names if any pre-rename runs remain.
```

If more than 2 files (1 PC + 1 console-rig) per scan attempt, that
confirms multiple-scan execution. Timestamps tell back-to-back
(= elevation loop) from spaced (= user clicked twice).

**Suggested fix path:**

- **Best:** Remove self-elevation entirely. Replace with a check at the
  top: if not admin, print a clear "RIGHT-CLICK `Run scan.bat` AND PICK
  'Run as administrator'" message, pause, exit. No `Start-Process -Verb
  RunAs`. No second window. No re-entry possible.
- **Acceptable:** Keep self-elevation but add a `--already-elevated`
  sentinel argument the elevated copy passes to itself, and refuse to
  re-elevate if that flag is present.

---

## Issue 3 — Field test v4.2.0 on Brad's real machine (NEW)

The v4.2.0 work is verified by unit tests + a synthetic .txt smoke test
+ a re-render of Brad's last saved `PCForensicCheck_20260525_185106.txt`
(which is from a scan run BEFORE the keyword-tightening fix landed, so
its false-positive findings are baked in). **A fresh end-to-end scan has
not been run with v4.2.0 yet.**

**What to confirm on the fresh scan:**

- Scanner keyword tightening actually drops the `hoic`→`CHOICE.EXE` and
  `hping`→`PATHPING.EXE` `[HIGH]/[NetAttack]` findings.
- With those false positives gone, `totalCheatHigh` should drop to 0 on
  Brad's machine, and the verdict tier should fall through from `CHEATS
  DETECTED` (the false-positive-driven verdict in the old .txt) to
  `INPUT DEVICES DETECTED` (the accurate tier for his XIM / reWASD /
  HidHide stack).
- Lifecycle section should render 6 tracks (`XIM MATRIX`, `XIM (other)`,
  `Cronus Zen Studio`, `reWASD`, `HidHide`, plus whatever else is
  current).
- Named-items block should show ALL HIGH input-device patterns in
  `main` (not `also`) because the verdict is no longer cheat-driven.
- Today-beam on the lifecycle SVG should render on the right edge
  (SVG-coord fix verified in synthetic data).

**Run:**

```powershell
# As admin
& "D:\Claude\Projects\PC Check\Run scan.bat"
# Or just the PC-mode driver if Run scan.bat is still under suspicion (Issue 1):
& "D:\Claude\Projects\PC Check\scanner\forensic-scan.ps1"
```

The HTML auto-opens in the default browser. Compare against the
pre-v4.2.0 `PCForensicCheck_20260525_185106_visual_NEW.html` on the
Desktop for a before/after visual.

---

## Issue 4 — HASHES.txt regeneration (NEW, mechanical)

Several `scanner/*` hashes in `HASHES.txt` are stale after the v4.2.0
commit (the two driver shims + the new common module + the moved
CSS/JS, plus `forensic-common.ps1` for the bounded-matching change).
Before the next release tag, regenerate:

```powershell
Get-ChildItem 'D:\Claude\Projects\PC Check\scanner' -Filter '*.ps1' |
    Get-FileHash -Algorithm SHA256 |
    ForEach-Object {
        '{0} *scanner/{1}' -f $_.Hash.ToLower(), ($_.Path | Split-Path -Leaf)
    }
# Plus visual_styles.css, visual_scripts.js, one-page-guide.html, run-check.bat, etc.
# Compare against HASHES.txt; rewrite the changed lines.
```

Not blocking — only matters when cutting a release tag for distribution.

---

## What v4.2.0 shipped — keep / build on

These are stable and don't need rework unless field-test surfaces issues:

| Component | Status |
|---|---|
| `scanner/visual-companion-common.ps1` (~1100 lines, parser + dark-tactical renderer mirroring `python/src/alibi/visual_companion.py`) | Stable, unit-tested |
| `scanner/generate-visual-companion.ps1` + `-console.ps1` (60-line shims; old 800+/900+ line v3.x renderers replaced) | Stable |
| Activity-by-pattern lifecycle section in both Python and PS renderers | Stable |
| Track-key fallback (`Pattern → Label → DisplayName → DeviceName`) so AppData/USB findings get their own tracks | Stable |
| Named-items verdict-aware routing (`CHEATS DETECTED` splits input to "also"; other verdicts route all HIGH to main) | Stable |
| Named-items dedup by Pattern with "+N" corroborating-source chip | Stable |
| SVG coord InvariantCulture F1 formatting (replaced `{0:N1}` that broke at X≥1000 in en-US locale) | Stable |
| `match_keyword(..., bounded=True)` / `Match-Keyword -Bounded` for short generic keywords; applied to `scan_network_attack_tools` and `scan_lua_scripts` (Python + PS) | Stable, 21 tests pass (hoic↛CHOICE, hping↛PATHPING, esp↛FDResPub, loader↛RTSSHooksLoader64, anticheat↛EasyAntiCheat) |
| Shared `scanner/visual_styles.css` and `scanner/visual_scripts.js` (moved up from `python/src/alibi/`, Python loader updated) | Stable |
| `visual-companion-common.ps1` + matching python entry in scanner self-exclusion lists | Stable |

---

## Low-priority items still open

- **Track-label truncation.** Lifecycle SVG track labels are capped at
  14 characters with `...` (so "Cronus Zen Studio" displays as
  "CRONUS ZEN ST..."). Bumping to ~18 chars or sliding `left_pad`
  from 180 to 220 fits common names without truncation. Minor.
- **Named-items chip cleanup.** The "InstalledSoftware +3" chip format
  is informative but visually dense. Could simplify to "+3" or
  "(4 sources)" as a separate sub-element. Subjective polish.
- **Reference HTMLs aren't updated.**
  `docs/design-handoff-2026-05/reports/report-pc-*.html` predate v4.0's
  log-scale timeline AND the new v4.2 lifecycle section. They're frozen
  design specs. Regenerating from the current Python renderer would
  update the spec to match what ships. Useful for parity checks, not
  blocking.
- **Self-detection meta-quirk.** Scanner running on Brad's dev machine
  finds its OWN keyword strings (`engineowning`, `rut.gg`, etc.)
  embedded in `scanner/forensic-common.ps1` and
  `python/src/alibi/keywords.py`. Triggers HIGH cheat findings pointing
  at the repo source. Reviewers running on a stranger's machine won't
  hit this. Worth a scope-skip in `Scan-UserScriptContents` and
  `Scan-KnownHashes` for any directory tree containing
  `scanner/forensic-common.ps1` (or any directory matching `alibi*` or
  `pc-check*`).
- **Auto-zip of reports** — deliberately parked. Don't ship without
  re-discussion.
- **Browser-history scanner.** `$CheatMarketplaceDomains` (40 reseller
  domains) sits inert in `forensic-common.ps1` waiting for a future
  `Scan-BrowserHistory` with hit-threshold logic.
- **`$KnownCheatHashes` backfill.** Still 1 entry (RUT v4 launcher
  SHA256). More candidates worth hashing if samples are obtainable:
  Two2nd / Tomware / Cynical CoD launchers (Activision-C&D'd Feb 2025),
  DMA vendor firmware images, Aimmy / Sunone release binaries.

---

## Files to read first in the next session

1. **This file** (`docs/NEXT_SESSION.md`)
2. `docs/handoff.md` — full project history, design rationale
3. `git show e8ec1f3 --stat` — what just shipped in v4.2.0
4. `scanner/visual-companion-common.ps1` — the new shared module
   (parser + renderer + scoring + bounded keyword matching)
5. `python/src/alibi/visual_companion.py` — canonical Python renderer
   (the PS module mirrors this 1:1)
6. `Run scan.bat` — needs Issue 1 attention; diff against v4.1.4
7. `scanner/forensic-common.ps1` — `Match-Keyword` now has a `-Bounded`
   switch; `Score-NetworkBlob` and the Lua-script loop use it

---

**Author:** Bread ([@Sutaigne](https://github.com/Sutaigne)) — Activision ID `Bread#3266221`. Contributor: Drownmw.
