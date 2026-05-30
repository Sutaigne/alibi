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

## Issue 1 — "It ran multiple scans" (CLOSED 2026-05-26 — not a code bug)

**Status:** Closed. Diagnosis below.

**Diagnostic run on Brad's Desktop on 2026-05-26** produced two recent
launches:

- **Run 1 (5/25 23:41 → 23:56):** PC #1 (23:41:54 → 23:47:42, 572 KB)
  → Rig #1 (23:47:43 → 23:53:35, 577 KB) → PC #2 (23:51:34 → 23:56:27,
  567 KB). PC #2 started 9 min 40 s after Run 1 began, **during** Rig #1.
- **Run 2 (5/26 00:18 → 00:19):** 1 PC + 1 Rig, perfectly sequential.
  Clean.

**Why the three v4.1.5-bug hypotheses are all ruled out:**

1. *Inline fall-through (parens / echo-block parser regression).* If the
   non-admin parent had run inline alongside the elevated child, PC #2
   would start at ~23:41:54, not 23:51:34.
2. *Non-admin partial scan in the parent window.* PC #2 weighs 567 KB —
   essentially identical to PC #1's 572 KB. That's a full elevated scan,
   not a permission-denied stub.
3. *UAC self-elevation loop.* A loop wouldn't space launches 10 minutes
   apart, and each iteration would need a UAC prompt the user couldn't
   miss.

**Actual cause:** A second `Run scan.bat` launch around 23:51:30. UAC
prompted again, was approved, and a fresh elevated copy started PC #2 in
parallel with the still-running Rig #1. Whether that second launch was
an accidental re-click *or* a deliberate impatient re-launch isn't
resolvable from the data alone, and the distinction matters less than
it sounds: both point at the same latent UX defect.

The v4.1.5 echo regression hypothesis from the earlier handoff is
falsified by this data. `Run scan.bat` is structurally sound; the cmd
parser correctly balances `(takes ~1-3 minutes)` inside the if-block,
and the byte dump showed no hidden chars.

**Latent UX defect to consider for a future iteration.** Phase 2
(`console-rig-audit.ps1`) emits no progress output for ~5 minutes
during the LOLDrivers fetch + filesystem walks. To a user watching the
launcher window after Phase 1's flurry of activity, the window looks
dead. That's the condition under which a reasonable person re-launches
"just in case it stalled" — exactly the failure shape this issue
reports. Two cheap mitigations, either is sufficient:

- Periodic dot/heartbeat output from the long-running scans
  (`Write-Host -NoNewline '.'` every 5–10 s during slow sections), so
  the window visibly isn't dead.
- A `Run scan.bat` lockfile guard: if another scan is already running,
  show "a scan is already in progress in window <PID>" and exit instead
  of starting a parallel scan.

Neither is blocking; both would prevent the only failure mode the field
test surfaced. Reopen if symptom recurs *and* matches a different
pattern (near-simultaneous launches, repeated UAC prompts, or PC #2
weighing much less than PC #1).

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

## Issue 4 — HASHES.txt regeneration (DONE 2026-05-26)

Regenerated against the current working tree. `sha256sum -c HASHES.txt`
verifies all 37 shipped files OK.

Net changes vs the pre-v4.2.0 file:

- **Modified hashes:** `scanner/forensic-common.ps1` (bounded matching),
  `scanner/generate-visual-companion.ps1` and
  `scanner/generate-visual-companion-console.ps1` (60-line shims
  replacing the old 800+/900+ line renderers),
  `python/src/alibi/scanners.py`, `python/src/alibi/utils.py`,
  `python/src/alibi/visual_companion.py`.
- **Added:** `scanner/visual-companion-common.ps1`,
  `scanner/visual_styles.css`, `scanner/visual_scripts.js`.
- **Removed:** `python/src/alibi/visual_styles.css`,
  `python/src/alibi/visual_scripts.js` (moved to `scanner/`).

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
6. `scanner/forensic-common.ps1` — `Match-Keyword` now has a `-Bounded`
   switch; `Score-NetworkBlob` and the Lua-script loop use it

---

**Author:** Bread ([@Sutaigne](https://github.com/Sutaigne)) — Activision ID `Bread#3266221`. Contributor: Drownmw.
