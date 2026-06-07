# Suggested memory entry — PC Check project

This file is a draft for inclusion in Brad's personal memory. It's not yet filed.

---

## What to add to the MEMORY.md index

Append this bullet to whichever `MEMORY.md` Brad uses for top-level `D:\Claude\Projects\` items (the existing `BO7-AVT` entry lives at `C:\Users\BradS\.claude\projects\D--Claude-Projects-Fun\memory\MEMORY.md` — top-level projects may map to a different path):

```
- [PC Check project state](pc_check_project_state.md) — Forensic kit for proving a Windows gaming PC isn't running cheats. Dual-driver pattern (PC + console-rig) over a shared `forensic-common.ps1` engine. Lives at `D:\Claude\Projects\PC Check\`. Read `docs\handoff.md` first on any return. Author: Bread (contributor: Drownmw).
```

## What to put in the per-project memory file (`pc_check_project_state.md`)

```markdown
# PC Check — Project State

**Path:** `D:\Claude\Projects\PC Check\`
**Purpose:** Read-only forensic kit that lets a Windows gamer prove to a third party that their machine isn't running cheats. Two scan modes (PC + console-rig) over a shared engine.

## Read order on return

1. `docs\handoff.md` — dev handoff with architecture + common edits + known issues
2. `kit\README.txt` — user-facing kit documentation
3. `kit\forensic-common.ps1` synopsis block — architectural intent

## Architecture in one line

`forensic-common.ps1` holds all keyword arrays + Scan-* functions + utilities. The two drivers (`forensic-scan.ps1` and `console-rig-audit.ps1`) dot-source it, set their own composite keyword arrays, compute their own verdicts. Add a new keyword in ONE place, both modes pick it up.

## Distribution

- `kit\` — live flat edit copy (where you make changes)
- `ready-to-flash\` — snapshot for USB-stick distribution. Top-level has 4 plain-named entry points + a `kit\` subfolder. Updated by manual copy (no `sync-bundle.bat` yet).

## Known cheat-product coverage

- COD cheat brands (EngineOwning, PhantomOverlay, rut.gg, etc.)
- HWID spoofers (Sync, TraceX, HidHide)
- DMA artifacts (pcileech variants, `_top.bin`)
- Input adapters (XIM, Cronus, ReaSnow, KMBox, reWASD)
- Console-MITM vision aimbots (AimMMO, AimSync, Aimflux, NoRecoilZ, etc.)
- Anti-cheat-killer batch scripts, Defender-disabler patterns
- LUA/AutoHotkey mouse-macro scripts (G HUB + Razer Synapse + AHK recoil control)
- Obscured executable filenames (hex, numeric, ultra-short)
- DLL injection via process-module scan
- Known-bad SHA256 hashes (currently 1: RUT v4 launcher)

## Field-tested

Yes. A self-confessed cheater ran v3.2 successfully against their own machine; their feedback drove v3.3-v3.5 additions.
```
