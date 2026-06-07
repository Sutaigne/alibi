# Project handoff — alibi (formerly "PC Check", originally "CheatChecks")

> **Naming history:** **CheatChecks** (original name; folder of that name preserved in `C:\Users\BradS\Downloads\CheatChecks\` containing the May-12 source) → **pc-forensic-check** (zip-distribution name through May 19–22) → **PC Check** (when it got its own project directory, May 25) → **alibi** (v4.0.0, 2026-05-25, GitHub publication).
>
> **Timeline correction:** The version-history list below starts at v3.2 because that is the **earliest file artifact recoverable from disk** — the May-12 `forensic-scan.ps1` already stamps itself `PC Forensic Check v3.2` in its synopsis. Earlier iterations (v1.x, v2.x, v3.0, v3.1) existed in Claude chat sessions that weren't preserved as standalone files. The kit was producing real, mature scan reports by May 12 (`PCForensicCheck_20260512_224115.txt` records HIGH=10, MEDIUM=1 against a real machine, full QUICK READ block, all sections). The "first field test" entry below (2026-05-22, CoD cheater friend) was the trigger that drove the v3.3+ feature push, **not** the project's birth.
>
> The v4.0.0 rename to "alibi" only changed the brand and added verification scaffolding (HASHES.txt, SECURITY.md, docs/for-reviewers.md, Pages preview). Scanner engine and detection logic are unchanged from v3.8.

---

**Last touched:** 2026-05-25 (multi-game expansion + recency decay, then renamed)
**Project root:** `D:\Claude\Projects\PC Check\` (kept on disk — repo is `Sutaigne/alibi` on GitHub)
**Author:** Bread
**Contributor:** Drownmw
**Original scanner version at the time of these notes:** v3.8 / console-rig v1.2 (now both consolidated to v4.0)

## What this project is

A read-only forensic kit for Windows that lets a gamer demonstrate to a third party that their machine isn't running cheats. The deliverable is two timestamped `.txt` reports on the user's Desktop, with matching `_visual.html` companions. A reviewer reads those files. No network calls, no system modifications, no installed software.

Two scan modes share one engine:
- **PC mode** (`forensic-scan.ps1`) — PC gamers
- **Console-rig mode** (`console-rig-audit.ps1`) — console gamers with a PC connected to their rig

Both run automatically from a single launcher (`Run scan.bat`).

## Read these first if you're returning

1. **This file** — dev-side handoff (you are here)
2. `kit\one-page-guide.html` — user-facing visual guide; also serves as a quick refresher on architecture
3. `kit\README.txt` — kit reference documentation
4. `kit\forensic-common.ps1` synopsis block — architectural intent

## Project directory layout

```
D:\Claude\Projects\PC Check\
│
├── kit\                                  ← LIVE EDIT COPY. Make changes here.
│   ├── forensic-common.ps1               (shared engine, ~900 lines, all keywords + scan functions)
│   ├── forensic-scan.ps1                 (PC driver, ~400 lines, dot-sources common)
│   ├── console-rig-audit.ps1             (console driver, ~460 lines, dot-sources common)
│   ├── generate-visual-companion.ps1     (PC report → HTML, has own keyword arrays - tech debt)
│   ├── generate-visual-companion-console.ps1
│   ├── run-check.bat                     (dev launcher for PC scan, separate from ready-to-flash bat)
│   ├── console-run-check.bat             (dev launcher for console scan)
│   ├── README.txt                        (kit-level reference)
│   ├── one-page-guide.html               (comprehensive user/reviewer visual guide)
│   ├── pc-check-safety-card.html         (safety attestation)
│   ├── console-setup-checklist.html      (photo guide for no-PC users)
│   ├── console-lockdown-explained.html   (why USB scanners don't work on consoles)
│   ├── top-bin-explainer.html            (DMA-cheat _top.bin explainer, online)
│   └── top-bin-explainer-offline.html    (same, no internet needed)
│
├── ready-to-flash\                       ← USB-stick distribution snapshot
│   ├── START HERE.txt                    (user-facing intro)
│   ├── Run scan.bat                      (UNIFIED launcher, no menu, runs both scans)
│   └── kit\                              (mirrors the live kit\ - keep in sync manually)
│
└── docs\
    ├── handoff.md                        (this file)
    └── memory-suggested.md               (draft memory entry, not yet filed)
```

> **Note (2026-05-29):** the `archive\` folder of historical zips (`pc-forensic-check*.zip`)
> was removed to cut antivirus/SmartScreen false-positive triggers — nested ZIPs of
> forensic PowerShell are a heuristic red flag, and the old versions live in git history
> anyway. See `SECURITY.md` → "Antivirus / SmartScreen false positives".

## Architecture — current shape after the 2026-05-25 refactor

```
kit\
├── forensic-common.ps1                ← shared engine. ~900 lines.
│                                        ALL keyword databases + ALL Scan-* functions
│                                        + utility helpers + hash database + allowlists.
│                                        Driver scripts dot-source this file.
│
├── forensic-scan.ps1                  ← PC driver. ~400 lines.
│                                        - Param + output path resolution
│                                        - Dot-sources common
│                                        - Sets PC composite keyword arrays
│                                        - Runs Invoke-AllScans + snapshots
│                                        - Computes PC verdict
│                                        - Writes PC QUICK READ block + report
│                                        - Writes %TEMP%\pc-check-pc.summary
│                                        - Auto-generates HTML (no prompt)
│                                        - Output: PCForensicCheck_<ts>.txt
│
├── console-rig-audit.ps1              ← console driver. ~460 lines.
│                                        Same shape, plus:
│                                        - Defines $VisionAimbots, $HidEmulators,
│                                          $CaptureCardSoftware (console-only)
│                                        - Extends composite keyword arrays
│                                        - Custom verdict tier logic
│                                          (MITM CHEAT STACK / CAPTURE STACK / etc.)
│                                        - Writes %TEMP%\pc-check-console.summary
│                                        - Output: ConsoleRigAudit_<ts>.txt
│
└── (visual companion .ps1 files still have their own keyword arrays — tech debt)
```

**Critical refactor rule**: keyword and scan logic lives ONLY in `forensic-common.ps1`. Drivers contain only what's mode-specific (verdict tiers, output filename, QUICK READ block content). Adding a new keyword goes in **one place** and both modes pick it up automatically.

## What's in `forensic-common.ps1`

1. **Keyword arrays** (base level):
   - `$CheatBrands_COD` — EngineOwning, PhantomOverlay, Lavi/Sky/iWant, X22, Golden Gun, Tateware, GcAimX, HdCheat, SecureCheats OVERLORD, ZHEX, **rut.gg + RUAVT family (added 2026-05-25)**
   - `$Spoofer_Brands` — Sync, TraceX, SlothyTech, PokeSpoof, **HidHide family (added 2026-05-25)**
   - `$CheatFeature_Names` — generic terms (aimbot, wallhack, triggerbot, norecoil, hwidspoofer, etc.)
   - `$DMA_Indicators` — pcileech variants, `_top.bin`
   - `$InputDevices` — XIM, Cronus, ReaSnow, KMBox, Titan, ConsoleTuner, **reWASD (added 2026-05-25)**
   - `$DMA_DualUse` — Vivado, Arbor
   - `$DualUse_Tools` — Cheat Engine, x64dbg, IDA, BleachBit, ProcessHacker, etc.
   - `$ScriptContent_HighRisk` — patterns to match INSIDE .bat/.cmd/.ps1 content (bcdedit testsigning, taskkill anti-cheat, Defender disablers, HWID queries, encoded PowerShell, anti-forensic commands)
   - `$ScriptContent_MouseMacro` — Logitech G HUB API names (MoveMouseRelative, OnEvent), Razer Synapse, anti-recoil signatures, AutoHotkey patterns
   - `$LuaCheat_Keywords` **(v3.6)** — cheat-specific Lua tokens for name-based .lua matching (aimbot, esp, bhop, spinbot, radarhack, skinchanger, undetected, etc.)
   - `$DLLInjector_Names` **(v3.6)** — named DLL injectors filtered against event-log image-loaded names (Xenos, Extreme Injector, GH Injector, manual_map, Syringe, Chimera, Winject, etc.)
   - `$NetworkAttack_High` **(v3.6)** — named consumer DDoS clients (LOIC, HOIC, slowloris, GoldenEye, torshammer, hulk, rudy, ufonet, xerxes, andosid, booter/stresser)
   - `$NetworkAttack_Medium` **(v3.6)** — dual-use network tools (hping/hping3, masscan, zmap, ostinato, iperf3, tshark)
   - `$CheatBrands_CS2` **(v3.8)** — Neverlose, Memesense, Fatality.win, Primordial, Skeet/Gamesense, Onetap, Aimware, Axion CS2
   - `$CheatBrands_Apex` **(v3.8)** — Kernaim, CosmoCheats Apex, Apex HackSuite
   - `$CheatBrands_Tarkov` **(v3.8)** — Phantom EFT, CheatVault EFT, Ownage Software
   - `$CheatBrands_Rust` **(v3.8)** — Cobra Rust, CobraSN, Atomic Rust, Cheater.Ninja
   - `$CheatBrands_R6` **(v3.8)** — HyperForce, CheatVault R6
   - `$CheatBrands_MarvelRivals` **(v3.8)** — Marvel Maxim, EloCarry Rivals
   - `$CheatBrands_LowConfidence` **(v3.8)** — single-source / thin-sourcing cheat names. Composited into `$Keywords_Medium` only (never `$Keywords_High_Cheats`) so they show up but never trigger HIGH on their own.
   - `$VisionAimbot_AI_PC` **(v3.8)** — PC-side AI-vision aimbots (Aimmy, sunone_aimbot, RootKit AI-Aimbot, Zelesis NEO, Unibot, Embedded-AI Pi aimbot, etc.). Composited into `$Keywords_High_Cheats`.
   - `$CheatMarketplaceDomains` **(v3.8, deferred)** — 40 reseller/forum domains held for a future `Scan-BrowserHistory` that will require a hit threshold (e.g., ≥3 visits across ≥2 distinct domains in last 6 months) so a single curious click doesn't bump verdict.

2. **Hash database** (`$KnownCheatHashes`): structured array, 1 entry currently (RUT v4 launcher SHA256). Append more with source URLs.

3. **Allowlists**:
   - `$KnownGood` — vendor-name fragments for user-writable path classification (Microsoft, Logitech, Razer, Steam, Discord, etc.)
   - `$DriverPublisher_Allowlist` — **EXPANDED 2026-05-25**: was 10 entries (Microsoft/Intel/AMD/NVIDIA/Realtek/Qualcomm), now 60+ including all major gaming peripherals (Logitech, Razer, Corsair, SteelSeries, HyperX, etc.), PC/laptop OEMs (Dell/HP/Lenovo/Acer/ASUS/MSI/Gigabyte/ASRock/EVGA), components (Cooler Master, NZXT, Noctua, G.SKILL, Crucial, Samsung, Seagate, WD), and monitors (LG Electronics, BenQ, ViewSonic). See section in forensic-common.ps1 for full list with substring-safety notes.
   - `$AppDataPatterns` — directories to recognize as XIM/Cronus/ReaSnow app data

4. **Utility functions**: `Add-Finding`, `Test-IsAdmin`, `Match-Keyword`, `Match-Allowlist`, `Classify-PathRisk`, `Score-Item`, `Convert-FileTimeBytes`, `Score-And-Add`

5. **Scan functions (21 total)**: `Scan-Prefetch`, `Scan-BAM`, `Scan-InstalledSoftware`, `Scan-RecentFiles`, `Scan-MUICache`, `Scan-USBHistory`, `Scan-DriverSigning`, `Scan-Drivers` (enhanced v3.7 with LOLDrivers cross-ref), `Scan-Downloads`, `Scan-Services-Trace`, `Scan-DMABuildArtifacts`, `Scan-ApplicationData`, `Scan-ShimCache`, `Scan-UserScriptContents`, `Scan-ObscuredFileNames`, `Scan-ProcessModules`, `Scan-KnownHashes`, `Scan-LuaScripts` (v3.6), `Scan-DLLInjectionTimestamps` (v3.6), `Scan-NetworkAttackTools` (v3.6), `Scan-AIVisionArtifacts` (v3.8). The standard run is wrapped in `Invoke-AllScans` (at bottom of file). v3.7 added two utility functions: `Get-LOLDriversDB` and `Resolve-LOLDriversDB`. **v3.8 also adds recency-decay infrastructure**: `Apply-RecencyDecay` (called by drivers AFTER `Invoke-AllScans` and BEFORE verdict computation), `Get-FindingTimestamp` (extracts most-recent timestamp from any of 12 known metadata keys), `$RecencyThresholdDays` (default 180), `$AlwaysRecentCategories` (state-based categories exempt from decay), `$RecencyMetadataKeys` (ordered list of timestamp metadata key names to consult).

6. **Snapshot functions**: `Get-ProcessSnapshot`, `Get-ServiceSnapshot`, `Get-Named-Items`

## Distribution flow (ready-to-flash)

- Top-level has only 3 visible items: `START HERE.txt`, `Run scan.bat`, `kit\`
- `Run scan.bat` self-elevates via UAC; if declined, shows clear error with "right-click → Run as administrator" instructions
- Runs both scans sequentially (no menu, no choices)
- Each scan auto-generates its HTML companion (no press-any-key prompt — removed late session)
- After both scans, the .bat reads `%TEMP%\pc-check-pc.summary` and `%TEMP%\pc-check-console.summary` (each scan writes a pipe-delimited summary line) and displays a consolidated "FINAL SCAN SUMMARY" block with both verdicts + counts + report paths
- Window stays open until user presses any key

## Common dev edits

### Add a new cheat-brand keyword
1. Open `kit\forensic-common.ps1`
2. Find the relevant array (`$CheatBrands_COD`, `$ScriptContent_HighRisk`, etc.)
3. Append new token(s). Prefer multi-token phrases over single ambiguous words.
4. Parse-check: `[System.Management.Automation.Language.Parser]::ParseFile(...)`
5. Sync to bundle: `cp kit\forensic-common.ps1 ready-to-flash\kit\`

Both drivers pick it up automatically.

### Add a confirmed cheat-sample hash
1. Open `kit\forensic-common.ps1`
2. Find `$KnownCheatHashes`
3. Append a hashtable with `SHA256`, `Name`, `Source`. **Source must be a verifiable URL.**

### Add a new Scan-* function
1. Define `function Scan-NewThing { ... }` in `kit\forensic-common.ps1`
2. Add `Scan-NewThing` to `Invoke-AllScans` at the bottom of the file
3. Both drivers will call it automatically

### Change verdict tiers
Verdict logic is **driver-specific** — lives in each driver's main flow + QUICK READ switch block, NOT in common.

## Tech debt / known issues

| Item | Notes |
|---|---|
| **Visual-companion .ps1 duplication** | `generate-visual-companion.ps1` (now also has v3.8 keyword additions mirrored in) and `generate-visual-companion-console.ps1` each carry their own embedded keyword arrays. The v3.8 expansion added 7 more arrays that had to be hand-mirrored into the visual companion. Drift risk is growing. Next time these need updating: extract parser + SVG renderer + HTML template into `visual-companion-common.ps1` and have both visual-companion drivers dot-source it (mirroring how the main scanners were refactored). |
| **Hash database is 1 entry** | Only RUT v4 launcher in `$KnownCheatHashes`. Every additional sample needs a verifiable source URL. |
| **`ready-to-flash` is a snapshot** | Manually copied from `kit\`. Re-sync needed after every kit change. No `sync-bundle.bat` exists yet. |
| **No automated tests** | Scripts are parse-checked but not unit-tested. Smoke testing requires running with admin against a known machine. |
| **No memory file in `.claude`** | `docs\memory-suggested.md` has the content; not yet filed into the auto-memory system. Top-level projects don't have a known `D--Claude-Projects` mapping yet. |
| **MUICache lacks per-value timestamps** (v3.8 surface) | Recency decay can't age out MUICache findings individually — the registry only exposes a write timestamp on the parent key, not per value name. MUICache hits currently get `RecencyClass='unknown'` (treated as recent for safety). Future fix would be a more invasive registry-key snapshot approach or just accepting the limitation. |
| **`Scan-BrowserHistory` not built** (v3.8 deferred) | `$CheatMarketplaceDomains` (40 reseller/forum domains) is inert in the engine — nothing reads it yet. When implemented, the scanner MUST enforce a hit threshold (suggested: ≥3 visits across ≥2 distinct cheat-marketplace domains within last 6 months) so a single curious click doesn't bump verdict. Browser-history sources to consider: Chrome `History` SQLite, Edge `History`, Firefox `places.sqlite`, browser bookmarks (HTML/JSON exports). |
| **AI-vision constellation logic is loose** | `Scan-AIVisionArtifacts` co-location check uses simple `StartsWith` on `DirectoryName` — works for typical setups but can miss artifacts spread across deeper subtrees or sibling dirs. Future tightening: walk the parent dir and look for any descendant matches. |

## Version history

- **v3.8** (current) — Multi-game cheat brand expansion + recency decay + AI-vision aimbot scanner. Research-driven (2026 cheat-community pulse): added seven new keyword arrays — `$CheatBrands_CS2`, `$CheatBrands_Apex`, `$CheatBrands_Tarkov`, `$CheatBrands_Rust`, `$CheatBrands_R6`, `$CheatBrands_MarvelRivals`, and `$VisionAimbot_AI_PC` (HIGH-emitting) — plus `$CheatBrands_LowConfidence` (MEDIUM-only for single-source items) and `$CheatMarketplaceDomains` (deferred, for a future browser-history scanner with hit-threshold logic). Extended `$CheatBrands_COD` with C&D'd Feb 2025 brands (Two2nd, Tomware, Cynical Software). Extended `$DMA_Indicators` with branded DMA hardware vendors (Atomic, Captain, Leet, Lurker, Suspect, Phoenix Labs, Squirrel, Enigma X-1, MVP, HackDMA, ZDMA, Captain Fuser). Net keyword additions: ~120 tokens across 9 new/extended arrays. New scanner `Scan-AIVisionArtifacts` detects the PC-side AI aimbot constellation (ONNX models + Python ML deps + Arduino HID sketches + named brand executables). **Architectural addition: recency decay** — `Apply-RecencyDecay` walks `$Findings` after `Invoke-AllScans` and demotes anything older than `$RecencyThresholdDays` (default 180): HIGH→MEDIUM, MEDIUM→INFO. Original severity preserved in `Metadata.OriginalSeverity`. State-based categories (Processes/Services/ProcessModules/Drivers/LOLDrivers/ShimCache/BCD) are always treated as recent. Both drivers updated to call `Apply-RecencyDecay`, filter verdict counts on `Metadata.RecencyClass`, and render a separate HISTORICAL findings section in both the QUICK READ block and the report body. Visual companion adds Section 06 "Historical findings". Scanner count now 22; console-rig version bumped to v1.2 (engine refactor alignment, not console-specific changes).
- **v3.7** — LOLDrivers (loldrivers.io) BYOVD detection integration. Adds `Get-LOLDriversDB` (fetches public CSV, builds filename + SHA256 indexes), `Resolve-LOLDriversDB` (opt-in Y/N prompt with 1-hour `$env:TEMP` cache so back-to-back PC + console-rig runs only prompt once), and enhances `Scan-Drivers` to enrich rows via `Win32_SystemDriver`, SHA256-hash drivers in non-standard paths, and cross-reference against the LOLDrivers DB. Verdict tiering: malicious-category = HIGH; vulnerable + SHA256 confirmed = HIGH (BYOVD confirmed); vulnerable + filename-only = MEDIUM (could be different version). Drivers expose `-SkipLOLDrivers` switch for unattended runs. This is the kit's first and only outbound network call; "No network calls" copy in README, one-page-guide, and the report's metadata line is now dynamic ("One outbound network call (loldrivers.io, opt-in)" vs. "No network calls") based on whether the DB was actually fetched.
- **v3.6** — Merged friend's v3.3 additions into the v3.5 refactored architecture (2026-05-25 post-refactor session). Three new scanners ported to `forensic-common.ps1` and registered in `Invoke-AllScans`: **Scan-LuaScripts** (name+path matching of `.lua` files across Documents/Desktop/Downloads/AppData/source/Projects/Games; HIGH on `$LuaCheat_Keywords` hits, INFO on unrecognized .lua so game mods / G HUB / Neovim don't bump verdict to UNSURE — decision-B downgrade from friend's original MEDIUM), **Scan-DLLInjectionTimestamps** (historical injector timeline from Sysmon EID 7 + Security EID 4688 + Application log + Prefetch, filtered against `$DLLInjector_Names`), **Scan-NetworkAttackTools** (DDoS-tool hunt across 6 sources — Prefetch/BAM/Installed/Downloads/MUICache/Recent — against `$NetworkAttack_High` and `$NetworkAttack_Medium`). Four new keyword arrays added with mirroring into `generate-visual-companion.ps1` embedded duplicates. README+capability list bumped to 20 scanners.
- **v3.5** — Curated rut.gg tokens, known-hash scanner. Shared `forensic-common.ps1` engine via dot-source. Console-rig at v1.1 with same engine. Distribution restructured to 3 visible top-level items. Unified launcher (no menu, runs both scans, auto-HTML, no press-any-key). Driver publisher allowlist expanded from 10 to 60+ entries (gaming peripherals + OEMs + components). %TEMP% summary files for end-of-run consolidated display.
- **v3.4** — LUA/AHK mouse-macro detection, obscured-filename scanner, process-module scanner (DLL injection)
- **v3.3** — User-folder script-content scanner (.bat/.cmd/.ps1/.vbs/.lua/.ahk with content-pattern matching)
- **v3.2** — Earliest preserved baseline (May 12, 2026; original project name "CheatChecks"). HidHide + reWASD keyword additions. Visual companion timeline. OneDrive Desktop fix. Press-any-key visual flow (removed in v3.5). Pre-v3.2 iterations existed only in Claude chat sessions; not preserved as standalone files.

## Field-test log

| Date | Tester | Result | Feedback that landed |
|---|---|---|---|
| pre-2026-05-12 | Brad (self) | Kit already at v3.2 by May 12 — produced its first preserved scan report on a real machine at 22:41 local time that night. Earlier iterations (v1.x, v2.x, v3.0, v3.1) developed in Claude chat sessions; not preserved as files. | Established the engine, the scoring tiers, the QUICK READ block, the report shape. |
| 2026-05-22 | A self-confessed CoD cheater (friend) | First *external* field test. Scan correctly flagged their setup. | Drove the v3.3+ feature push: binary compilation (declined — destroys auditability), DOS-script content scanning (→ v3.3), rut.gg coverage (→ v3.5 after independent research), obscured filename detection (→ v3.4), LUA mouse-macro detection (→ v3.4), DLL-injection via process modules (→ v3.4). |
| 2026-05-25 | Drownmw (contributor) | Submitted v3.3 monolithic with Lua/DLL-injection/Network-attack scanners + v3.4 LOLDrivers monolithic for BYOVD detection | All merged into v3.6 / v3.7 refactored architecture |
| 2026-05-25 | Brad (session-level direction) | Multi-game expansion + recency-decay architecture | Drove the v3.8 design — 7 new keyword arrays, Scan-AIVisionArtifacts, 180-day recency-decay rule with Historical findings section, single-source items routed into MEDIUM-only LowConfidence bucket, marketplace-domains list deferred for a future hit-threshold browser-history scanner |

---

# 🔀 NEXT SESSION — handoff at end of v3.8

## Current state

**Scanner version:** v3.8 / console-rig v1.2. **Scanner count:** 21. **Base keyword tokens:** 503. **Outstanding work surfaces below.**

Everything in `kit\` and `ready-to-flash\kit\` is md5-identical (last verified end of v3.8 session). Both drivers parse-check clean. The unified `Run scan.bat` self-elevates, runs PC + console-rig back-to-back, prompts once for LOLDrivers opt-in (cached for 1h so the second run reuses), and writes summaries to `%TEMP%` for the final consolidated screen.

## Recommended next moves (priority order)

### 1. Browser-history scanner (deferred from v3.8) — primary path

`$CheatMarketplaceDomains` is sitting inert in `forensic-common.ps1` with 40 entries. The user wants browser-history detection that **requires** a sustained hit pattern — a single curious click two years ago must not bump the verdict.

Suggested design:
- `Scan-BrowserHistory` reads (read-only) Chrome's `History` SQLite (`%LOCALAPPDATA%\Google\Chrome\User Data\Default\History`), Edge's equivalent, and Firefox's `places.sqlite`. Use System.Data.SQLite or just file-copy the DB to `%TEMP%` and read via `sqlite-tools` if installed; otherwise skip with a WARN.
- Also read browser bookmarks JSON/HTML.
- Threshold logic: a finding fires only when **≥3 visits across ≥2 distinct cheat-marketplace domains within the last 180 days**. Single-domain or low-visit-count hits go into the report at INFO, not MEDIUM/HIGH.
- Should respect the same recency-decay rule (most-recent-visit ≤180d).
- Skip the user's primary work-search history (no general web log dump in the report — match against the marketplace list only).

### 2. `visual-companion-common.ps1` refactor (tech debt #1)

Mirrors the v3.5 main-engine refactor. Both visual-companion .ps1 files now carry duplicated keyword arrays (v3.8 added 7 more that had to be hand-mirrored). Extract the parser, SVG/timeline renderer, score-color logic, and HTML template into a shared file; both visual drivers dot-source it.

### 3. Backfill `$KnownCheatHashes`

Currently 1 entry (RUT v4 launcher). Every additional sample needs a verifiable source URL (Hybrid Analysis, VirusTotal community submissions, vendor sandbox reports). Drownmw's research surfaced candidates worth hashing if samples are obtainable: any of the C&D'd CoD launchers (Two2nd, Tomware, Cynical), DMA vendor firmware images, Aimmy/Sunone release binaries.

### 4. `sync-bundle.bat` (tech debt #3)

A 5-line BAT that copies `kit\*` → `ready-to-flash\kit\` would eliminate the manual sync step and the risk of forgetting one file (already happened on README sync earlier in v3.7).

### 5. Smoke-test harness (tech debt #4)

Build a fixtures directory under `tests\` with synthetic Prefetch files, fake registry exports, planted `.lua` files, and a dummy ONNX next to a fake `aimmy.exe`. A test driver runs each `Scan-*` against the fixtures and asserts expected finding counts. Recency-decay needs special attention here — manipulate file timestamps to create both recent and historical fixtures.

## What NOT to lose

All v3.6/v3.7/v3.8 additions are critical. The recency-decay piece especially — without it, the kit gives unfair verdicts to anyone with old artifacts on a currently-clean machine.

- ✅ Shared-engine refactor (both drivers dot-source `forensic-common.ps1`)
- ✅ rut.gg curated token list (multi-token phrases only, never bare `rut`)
- ✅ All v3.6 scanners: `Scan-LuaScripts`, `Scan-DLLInjectionTimestamps`, `Scan-NetworkAttackTools`
- ✅ v3.7 LOLDrivers integration (`Get-LOLDriversDB`, `Resolve-LOLDriversDB`, enhanced `Scan-Drivers` with BYOVD cross-ref + 1-hour cache, `-SkipLOLDrivers` switch on both drivers, dynamic "no network call" wording)
- ✅ v3.8 nine new/extended keyword arrays (503 total tokens)
- ✅ v3.8 `Scan-AIVisionArtifacts` (constellation logic, not just brand-name match)
- ✅ **v3.8 recency-decay infrastructure** — `Apply-RecencyDecay`, `Get-FindingTimestamp`, `$RecencyThresholdDays`, `$AlwaysRecentCategories`, `$RecencyMetadataKeys`. Drivers MUST call `Apply-RecencyDecay` between `Invoke-AllScans` and verdict computation, and verdict counts MUST filter on `Metadata.RecencyClass -ne 'historical'`. Historical findings must render in their own section in both report body and visual companion.
- ✅ Expanded `$DriverPublisher_Allowlist` (60+ entries)
- ✅ Unified `Run scan.bat` in `ready-to-flash\` (no menu, auto-HTML, %TEMP% summary read)
- ✅ OneDrive Desktop redirection fix
- ✅ Author/contributor attribution: `Bread` and `Drownmw` in 29 places — never collapse, never drop

## Useful commands during the next session

```powershell
# Parse-check after any .ps1 edit
foreach($f in @('forensic-common.ps1','forensic-scan.ps1','console-rig-audit.ps1','generate-visual-companion.ps1')){
    $t=$null;$e=$null
    [System.Management.Automation.Language.Parser]::ParseFile("D:\Claude\Projects\PC Check\kit\$f",[ref]$t,[ref]$e)|Out-Null
    if($e.Count -eq 0){"$f`: OK"}else{$e|ForEach-Object{"$f`: line $($_.Extent.StartLineNumber): $($_.Message)"}}
}
```

```bash
# Sync kit/ -> ready-to-flash/kit/ after edits
cd "D:/Claude/Projects/PC Check"
cp kit/forensic-common.ps1 kit/forensic-scan.ps1 kit/console-rig-audit.ps1 kit/generate-visual-companion.ps1 kit/README.txt kit/one-page-guide.html ready-to-flash/kit/
# Verify
for f in forensic-common.ps1 forensic-scan.ps1 console-rig-audit.ps1 generate-visual-companion.ps1 README.txt one-page-guide.html; do
  a=$(md5sum "kit/$f" | cut -d' ' -f1); b=$(md5sum "ready-to-flash/kit/$f" | cut -d' ' -f1)
  if [ "$a" = "$b" ]; then echo "$f: MATCH"; else echo "$f: MISMATCH"; fi
done
```

```powershell
# Recount keyword arrays after edits
$f='D:\Claude\Projects\PC Check\kit\forensic-common.ps1';$c=Get-Content $f -Raw
foreach($n in @('CheatBrands_COD','Spoofer_Brands','InputDevices','DMA_Indicators','LuaCheat_Keywords','DLLInjector_Names','NetworkAttack_High','NetworkAttack_Medium','ScriptContent_HighRisk','ScriptContent_MouseMacro','CheatBrands_CS2','CheatBrands_Apex','CheatBrands_Tarkov','CheatBrands_Rust','CheatBrands_R6','CheatBrands_MarvelRivals','CheatBrands_LowConfidence','VisionAimbot_AI_PC','CheatMarketplaceDomains')){
    if($c -match "(?ms)^\`$$n = @\((.*?)^\)"){
        $count=([regex]::Matches($matches[1],"'[^']+'")).Count
        "{0,-30} {1,4}" -f $n,$count
    }
}
```
