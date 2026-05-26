# NEXT SESSION — open issues from 2026-05-26

This is a fresh-session pickup doc. Two real bugs surfaced at the very end of the previous session, while Brad was field-testing `v4.1.5`. **Read this first**, then `docs/handoff.md` for full project context, then the relevant source files.

Repo: https://github.com/Sutaigne/alibi · current tag: `v4.1.5`

---

## Issue 1 — "It ran multiple scans"

**Symptom:** Brad double-clicked `Run scan.bat` (the unified launcher at repo root) and saw the kit run **more than the expected pair** of scans (PC mode + console-rig mode). Exact count unclear.

**Possible causes (ranked by likelihood):**

1. **UAC self-elevation loop.** `Run scan.bat` checks `NET SESSION`, if non-admin it calls `powershell.exe ... Start-Process -FilePath '%~f0' -Verb RunAs` to spawn an elevated copy of itself, then `exit /b`. If the elevated copy somehow re-enters the elevation branch (e.g. `NET SESSION` failing intermittently inside the elevated process for some reason), it would re-spawn another elevated copy of itself — infinite loop possible. Worth verifying that the elevated instance reliably passes the admin check on Brad's machine.
2. **`Run scan.bat` was accidentally double-clicked.** Each click spawns its own independent UAC + scan flow. The kit doesn't prevent concurrent launches.
3. **The v4.1.5 self-elevation messaging change broke something.** v4.1.5 added a long explanatory text block before the elevation. Possible the new block contains a character that breaks cmd parsing and causes weird control flow. Worth diffing v4.1.4 vs v4.1.5 of `Run scan.bat` and looking for `&`, `(`, `)`, `|`, `^`, `>` inside the new echo block.

**Diagnosis to run first in next session:**

```powershell
# 1. Count actual report files on Brad's Desktop with timestamps
Get-ChildItem $env:USERPROFILE\Desktop -Filter 'AlibiReport_*.txt' |
    Sort-Object LastWriteTime |
    Select-Object Name, LastWriteTime

Get-ChildItem $env:USERPROFILE\Desktop -Filter 'AlibiRigReport_*.txt' |
    Sort-Object LastWriteTime |
    Select-Object Name, LastWriteTime
```

If there are more than 2 files (1 PC + 1 console-rig) per scan attempt, that confirms multiple-scan execution. The timestamps will show whether they're back-to-back (=self-elevation loop) or spaced (=user clicked twice).

**Suggested fix path:**

- **Best:** Remove self-elevation entirely. Replace with a check at the top: if not admin, print clear "RIGHT-CLICK `Run scan.bat` AND PICK 'Run as administrator'" message, pause, exit. No `Start-Process -Verb RunAs`. No second window. No possible loop. The trade-off: one extra user action (right-click), but zero risk of re-entry and the user never sees the two-window pattern that confused them in v4.1.5.
- **Acceptable:** Keep self-elevation but add a `--already-elevated` sentinel flag that the elevated copy passes to itself, and refuse to re-elevate if that flag is set. Belt-and-suspenders.

---

## Issue 2 — "It also ran the old UI"

**Symptom:** The HTML companion that opened in Brad's browser at the end of the scan was rendered in the **old v3.x cream/serif design**, NOT the new dark-tactical readout (the one shipped in v4.0 from the design handoff bundle).

**Root cause — confirmed by code inspection:**

The new dark-tactical design was **only** ported to the Python parity port. Look at the file tree:

```
python/src/alibi/
├── visual_companion.py        ← NEW dark-tactical renderer (v4.0)
├── visual_styles.css          ← 1300 lines of design tokens
└── visual_scripts.js          ← 350 lines of vanilla-JS interactivity

scanner/                       ← PowerShell side (canonical)
├── generate-visual-companion.ps1         ← STILL the v3.x design
└── generate-visual-companion-console.ps1 ← STILL the v3.x design
```

When `Run scan.bat` runs (the canonical PowerShell path), it calls `scanner/forensic-scan.ps1` which calls `scanner/generate-visual-companion.ps1` — that .ps1 has its own embedded HTML template using the OLD cream/serif design (the v3.x "Neon Forensics" / safety-card look). It also carries its own duplicate keyword arrays — explicitly flagged as tech debt in `docs/handoff.md`:

> | Visual-companion .ps1 duplication | `generate-visual-companion.ps1` and `generate-visual-companion-console.ps1` each carry their own embedded keyword arrays. The v3.8 expansion added 7 more arrays that had to be hand-mirrored into the visual companion. Drift risk is growing. Next time these need updating: extract parser + SVG renderer + HTML template into `visual-companion-common.ps1` and have both visual-companion drivers dot-source it.

That tech-debt note was written before we even started the v4.0 design work. It anticipated exactly this problem.

**Suggested fix path:**

1. Move `python/src/alibi/visual_styles.css` and `visual_scripts.js` up to `scanner/` (or a new `assets/` folder) so both PS and Python can read them as shared resources. Update the Python `_load_resource` to point at the new location.
2. Create `scanner/visual-companion-common.ps1` that:
   - Reads the shared CSS + JS files at runtime
   - Defines a `Render-AlibiHtml` function that mirrors `python/src/alibi/visual_companion.py :: render_html()` exactly — same section order, same finding-card markup, same timeline math, same donut math, same named-items grid
   - Lives next to `forensic-common.ps1` and is dot-sourced by both `generate-visual-companion.ps1` and `generate-visual-companion-console.ps1`
3. Rewrite `generate-visual-companion.ps1` and `generate-visual-companion-console.ps1` as thin shims that parse the .txt report into the finding / process / service objects, then call `Render-AlibiHtml` and write the file. The OLD inline HTML templates get deleted.
4. Verify byte-for-byte (or near-byte-for-byte) parity between the HTML the PS side emits and what the Python side emits. The existing three reference HTMLs in `docs/design-handoff-2026-05/reports/` are the spec.

Reference files to mirror against:
- **Design spec:** `docs/design-handoff-2026-05/README.md` (the high-fidelity handoff doc, ~28 KB)
- **Python implementation:** `python/src/alibi/visual_companion.py` (~750 lines)
- **Live preview of expected output:** https://sutaigne.github.io/alibi/

The Python port is the source of truth for the visual now. The PS port has been lagging.

---

## Status of this session's other shipped work — keep / build on

These are stable and don't need rework:

| Version | What landed | Status |
|---|---|---|
| v4.0.0 | Repo rename `pc-check` → `alibi`. Python package rename `pc_check` → `alibi`. Console scripts `alibi` / `alibi-rig`. Output filenames `AlibiReport_*.txt`. | Stable |
| v4.0.0 | `HASHES.txt`, `SECURITY.md`, `docs/for-reviewers.md`, private vulnerability reporting, GitHub Pages preview at https://sutaigne.github.io/alibi/ | Stable |
| v4.0.0 | Fix falsified "no Invoke-Web" copy in `scanner/alibi-safety-card.html` + `one-page-guide.html` + `START HERE.txt` + root `README.md` | Stable |
| v4.0.0 | README CoD-primary framing, Activision ID `Bread#3266221` labeled, timeline correction (project predates May 22 by 10+ days, original name "CheatChecks") | Stable |
| v4.1.0 | Repo restructure: `kit/` → `scanner/`, `ready-to-flash/` collapsed into repo root. Whole-tree speed pass (event log MaxEvents caps, depth limits). Per-scanner timing in `Invoke-AllScans` / `invoke_all_scans`. | Stable |
| v4.1.1 | First AIVision dep-cache exclude attempt — turned out to be incomplete, see v4.1.4 | Superseded |
| v4.1.2 | Auto-open HTML in browser at scan completion. `-SkipBrowserOpen` / `--no-open-browser` flags on individual drivers; unified launcher passes them and opens just one tab. | Mostly stable; see Issue 2 |
| v4.1.3 | Sharper FINAL SCAN SUMMARY block in both launchers. Clipboard copy of all four paths via `clip.exe`. | Stable |
| v4.1.4 | **Real** AIVision fix: new `Get-PrunedFiles` helper in `scanner/forensic-common.ps1`. .NET `DirectoryInfo.EnumerateDirectories` with name-pruning BEFORE recursing. Applied to AIVision + Lua + UserScripts + ObscuredNames + KnownHashes. Verified end-to-end: AIVision 33.87s, total 92.92s on Brad's machine. | Stable |
| v4.1.5 | Self-elevation messaging clarified. `explorer.exe` relay for browser open (avoids admin-token leak to Chrome/Edge). | **See Issue 1** — messaging may have introduced multi-scan bug; verify the .bat parses cleanly. |

---

## Other low-priority items still open

These were noted in earlier session work but not addressed:

- **Self-detection meta-quirk.** The scanner finds its OWN keyword strings (`engineowning`, `rut.gg`, etc.) embedded in `scanner/forensic-common.ps1` and `python/src/alibi/keywords.py`. When Brad runs the scan on his own dev machine, this triggers a HIGH cheat finding pointing at his repo source. Real reviewers running it on a stranger's machine won't hit this. Worth a follow-up tweak: in `Scan-UserScriptContents` and `Scan-KnownHashes`, scope-skip any directory tree containing a `scanner/forensic-common.ps1` (or any directory matching `alibi*` or `pc-check*`).
- **Auto-zip of reports** — deliberately parked. Brad's stance: the .txt should stay individually shareable. Don't ship without re-discussion.
- **Browser-history scanner.** `$CheatMarketplaceDomains` (40 reseller domains) sits inert in `forensic-common.ps1` waiting for a future `Scan-BrowserHistory` with hit-threshold logic. Design notes are in `docs/handoff.md` under "Recommended next moves."
- **`$KnownCheatHashes` backfill.** Currently 1 entry (RUT v4 launcher SHA256). More candidates worth hashing if samples are obtainable: Two2nd / Tomware / Cynical CoD launchers (Activision-C&D'd Feb 2025), DMA vendor firmware images, Aimmy / Sunone release binaries.

---

## Files to read first in the next session

1. **This file** (`docs/NEXT_SESSION.md`)
2. `docs/handoff.md` — full project history, design rationale
3. `docs/for-reviewers.md` — reviewer-side workflow (what reports mean, how to verify)
4. `scanner/forensic-common.ps1` — the engine (the `Get-PrunedFiles` helper at the top is recent; understand it before touching)
5. `python/src/alibi/visual_companion.py` — the canonical new visual implementation (the PS side should be brought into parity with this)
6. `Run scan.bat` — the unified launcher; needs the most-recent attention for Issue 1
7. `scanner/generate-visual-companion.ps1` — the PS-side HTML generator that needs to be rewritten or replaced for Issue 2

---

**Author:** Bread ([@Sutaigne](https://github.com/Sutaigne)) — Activision ID `Bread#3266221`. Contributor: Drownmw.
