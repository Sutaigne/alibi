# alibi v4.3 — handoff for Claude Code

*Written 2026-07-11. Read this first, then `PROPOSAL-v5.md`.*

## TL;DR
A trust-first credibility release (v4.3) is **drafted and applied** to the engine
in this working tree. It fixes the false positives that broke both example scan
reports — most importantly the one where alibi returned **CHEATS DETECTED against
its own source code**. Changes are parse-verified and unit-tested; the only thing
left before tagging is a **live admin run on real Windows** + eyeballing the HTML.

## Why this work happened — the two reports
- **`4070PC` / lj031 → CHEATS DETECTED (false).** User downloaded the GitHub zip
  to `\Downloads`; the content scanner read `dev/intel/extract-known-tokens.ps1`
  (a dev file that *lists* cheat brands by design), matched `aimbot`, and drove a
  HIGH/cheat verdict. alibi flagged itself. Also 16 Opera GX MEDIUM FPs +
  `afd.sys`/`KslD.sys` LOLDrivers FPs + ASUS driver FPs.
- **`DESKTOP-F3SN84F` / dalto → INPUT DEVICES DETECTED (correct, but noisy).**
  Real Cronus rig, but ~30 of 34 MEDIUMs were noise: 10 WER crashes mis-tagged as
  DLL injection, the same `afd.sys`/`KslD.sys` collisions, ~11 duplicate
  "UNSIGNED: LIGHTSPEED Receiver".

Full analysis + the v5 roadmap live in `alibi-engine/docs/PROPOSAL-v5.md`.

## What changed in this tree

### Modified
- **`alibi-engine/scanner/forensic-common.ps1`** — the 5 P0 fixes (grep `v4.3 P0`
  for every edit site).
- **`alibi-engine/scanner/visual-companion-common.ps1`** — `$script:ALIBI_VERSION`
  bumped `4.2.1` → `4.3.0`.

### Added
- **`alibi-engine/docs/PROPOSAL-v5.md`** — phased plan (v4.3 fixes + v5 redesign).
- **`alibi-engine/tests/p0-regression.Tests.ps1`** — pure-logic regression suite.
- **`alibi-engine/docs/HANDOFF-v4.3.md`** — this file.

## The 5 P0 fixes (all in forensic-common.ps1)

| ID | What | Mechanism | Anchor |
|----|------|-----------|--------|
| P0-1 | **Self-immunity** — never scan alibi's own files | `Test-IsAlibiOwnPath` + `$Script:AlibiSelfPathPatterns`/`AlibiSelfFileNames`; wired into `Get-PrunedFiles` (dir + file prune) and guards in `Scan-UserScriptContents` / `Scan-Downloads` | grep `P0-1` |
| P0-2 | **Authenticode trust** for user-writable binaries (kills Opera-type FPs) | `Test-TrustedSignature` (path-cached); used in `Score-Item` (covers process/service snapshots) and `Scan-ProcessModules`; `$KnownGood` expanded with common AppData apps | grep `P0-2` |
| P0-3 | **LOLDrivers hash-first** (kills `afd.sys`/`KslD.sys`) | Hash every readable driver; SHA256 wins over filename; filename-only matches on **Microsoft-signed** drivers demoted to INFO | grep `P0-3` |
| P0-4 | **Injector free-text fix** (kills 10 WER FPs) | Drop generic `inject`/`injector` tokens, require word-bounded match, skip WER/crash providers, record matched token | grep `P0-4` |
| P0-5 | **Dedup** unsigned-driver findings | `$seenUnsigned` keyed by DeviceName+FileName in `Scan-Drivers` rule 2 | grep `P0-5` |

## Verification status
- **Parse:** clean. `[System.Management.Automation.Language.Parser]::ParseFile`
  over the full engine → 0 errors (validated on PowerShell 7.4.6).
- **Behavior:** 14/14 in `tests/p0-regression.Tests.ps1`, including the headline
  case — `dev/intel/extract-known-tokens.ps1` is now recognized as alibi's own
  and skipped, while a real `…\aimbot-loader\loader.ps1` still fires.
- **Live run on real Windows:** **PENDING.** The scanner uses Windows-only
  cmdlets (Get-CimInstance, Get-WinEvent, driverquery, registry) so it can't run
  end-to-end off-Windows. Run `Run scan.bat` as admin and confirm the HTML.

### Run the tests
```powershell
pwsh -File alibi-engine/tests/p0-regression.Tests.ps1
# or Windows PowerShell:
powershell -ExecutionPolicy Bypass -File alibi-engine\tests\p0-regression.Tests.ps1
```

## ⚠️ Gotcha that cost us time
If you work through a Linux sandbox mount, its copy of large files can go
**stale/truncated** relative to the real file. It made `forensic-common.ps1`
look truncated at line ~2127 and threw phantom parse errors. The host-side
tooling (and the real file) were correct the whole time. **Trust host-side
Read/Edit + `Get-AuthenticodeSignature`/`ParseFile` against the real path; don't
diagnose from a possibly-stale mount.** In Code (running natively on Windows)
this won't bite you.

## Next steps, in order
1. **Live-verify v4.3.** Run `Run scan.bat` as admin on a real box.
   Acceptance:
   - A copy of the alibi repo sitting under a scanned root (Desktop/Downloads)
     produces **no** HIGH/cheat findings sourced from it (self-immunity).
   - Opera GX (or any signed AppData app) → **0** user-writable MEDIUMs from it.
   - `afd.sys` / `KslD.sys` → **0** LOLDrivers MEDIUMs (INFO at most).
   - WER-heavy Application log → **0** phantom DLLInject findings.
   - Multi-endpoint unsigned receiver → **1** finding, not ~11.
   - Regression guard: a genuine Cronus/HidHide box still reports the real hits.
2. **Set up version control.** This tree is a plain zip (no `.git`). `git init`,
   commit as the 4.3.0 baseline so the P0 diff is reviewable, then tag.
3. **Ship v4.3**, re-shoot the two example reports as before/after proof.
4. **Start v5** per `PROPOSAL-v5.md`: (a) collectors/rules/verdict refactor with
   fixture tests + external keyword/allowlist/hash data files; (b) intent
   scanners — Cronus `.gpc`/`.gpj` names, G HUB Lua **body** matching, HidHide
   hide-list; (c) removed-hardware ghosts + `setupapi.dev.log`; (d) anti-forensics
   scoring (OS install date, 1102/104/3079, wiper residue).

## Open risks to watch when live-testing
- **Authenticode latency/CRL.** `Get-AuthenticodeSignature` may attempt a
  revocation network call — for a "no network calls" tool, confirm behavior and
  consider pinning to chain-status-without-revocation. Path-caching already bounds
  the call count.
- **Self-immunity heuristic.** v4.3 matches on path shape (`alibi-engine`,
  `alibi-main`, `dev/intel`, `dev/scripts` + known dev filenames). v5 should move
  to a content sentinel stamped into alibi's own files so a renamed folder can't
  defeat it (and a cheat can't hide under an `alibi-engine\` folder name).
