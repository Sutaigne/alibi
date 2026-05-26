# Alibi

A read-only forensic kit for Windows that lets a gamer demonstrate to a third party that their machine isn't running cheats. The deliverable is two timestamped files on the user's Desktop — a plain-text report and a matching `_visual.html` companion. A reviewer reads those files. **No system modifications, no installed software, no telemetry.** Exactly one outbound network call — the opt-in LOLDrivers BYOVD cross-reference — is prompted before running and explicitly disclosed in every report; everything else stays on the machine.

**Primarily built for Call of Duty.** The kit was born out of the CoD cheating scene — the first field test (2026-05-22) was a self-confessed CoD cheater, and the deepest keyword coverage is for CoD-side brands: EngineOwning, PhantomOverlay, Lavi/Sky/iWantCheats, X22, the rut.gg / RUAVT family, Two2nd / Tomware / Cynical (the Activision-C&D'd Feb-2025 brands), plus Ricochet- and HWID-spoofer-focused detection logic. CS2, Apex, Tarkov, Rust, R6, and Marvel Rivals brand arrays were added later because the same engine handled them for free — but if you're auditing a CoD rig, this is the kit that's been most actively shaped for that.

Two scan modes share one engine:

- **PC mode** — for PC gamers auditing their own gaming PC
- **Console-rig mode** — for console gamers auditing a PC connected to their console rig (capture-card host, streaming PC, MITM-aimbot setup)

Author: **Bread** — Activision ID `Bread#3266221`, GitHub [@Sutaigne](https://github.com/Sutaigne). Contributor: **Drownmw**.

> The Activision ID is intentional: this kit was built by an active CoD player, and reviewers can verify that in-game. If you're auditing a CoD rig, you should be able to look up the kit's author the same way you'd look up the person whose machine you're scanning.

> **Reviewer?** Someone handed you a report and is asking you to believe it? Read [**`docs/for-reviewers.md`**](./docs/for-reviewers.md) first. It walks you through verifying the kit, reading the verdict, and what `CLEAN` does and does not rule out. The verification chain starts with [`HASHES.txt`](./HASHES.txt).

## Quick start

**The repo itself is the runnable distribution.** Download the ZIP from GitHub (or `git clone`), unzip / copy to a USB stick if you want portability, then **double-click `Run scan.bat` at the root.** That's it.

```
.
├── Run scan.bat              ← double-click this
├── START HERE.txt            ← read this first if confused
├── scanner/                  ← the .ps1 scanner files (the engine)
├── python/                   ← Python parity port (alternative implementation)
├── docs/                     ← reviewer guide, dev history, design source
├── archive/                  ← old builds, kept for provenance
├── README.md / SECURITY.md / HASHES.txt / LICENSE
```

Two scans run back-to-back (PC mode + console-rig mode); two pairs of timestamped files land on the Desktop. Approve the UAC prompt when it appears — admin is required for full coverage. Total time: about 1–2 minutes on a typical machine; the first run pulls the LOLDrivers driver database (opt-in, ~50 KB).

### Python parity (alternative implementation for reviewers who prefer Python)

```powershell
cd python
python -m alibi                          # PC mode
python -m alibi.console_rig_audit        # console-rig mode
```

Or install and use the console scripts:

```powershell
cd python
pip install -e .
alibi
alibi-rig
```

Python 3.10+ required. Pure stdlib (except an opt-in `urllib` call to [loldrivers.io](https://www.loldrivers.io) for BYOVD detection).

## What it detects

- **22 scanners** across Prefetch, BAM, MUICache, USB history, ShimCache, services, drivers, downloads, recent files, AppData, user-folder script content, lua scripts, obscured filenames, process modules, DLL injection event timeline, network attack tools, AI-vision aimbot constellation, known hashes, DMA build artifacts, application data dirs.
- **520+ research-confirmed keyword tokens** across cheat brands (CoD, CS2, Apex, Tarkov, Rust, R6, Marvel Rivals), HWID spoofers, DMA hardware vendors, AI-vision aimbots, mouse-macro / anti-recoil patterns, input devices (XIM, Cronus, ReaSnow, KMBox, Titan, reWASD), and dual-use tools.
- **LOLDrivers BYOVD detection** — cross-references loaded drivers against the public [loldrivers.io](https://www.loldrivers.io) database. The only network call the kit ever makes, and it's opt-in.
- **Recency decay** — artifacts older than 180 days are logged in a separate Historical section but do not bump the verdict. A clean current machine should not be condemned for old, abandoned software.

## Verdict tiers

| Mode | Verdicts |
|---|---|
| PC | `CHEATS DETECTED` / `INPUT DEVICES DETECTED` / `UNSURE` / `CLEAN` |
| Console-rig | `MITM CHEAT STACK DETECTED` / `CAPTURE STACK PRESENT` / `UNSURE` / `CLEAN` |

## Example outputs

**Live preview:** [**sutaigne.github.io/alibi**](https://sutaigne.github.io/alibi/) — three rendered states served from GitHub Pages, full interactivity, no download required.

The Python port ships three synthetic examples in [`python/examples/`](./python/examples) — one per visual state (red / amber / green). They are generated by piping fake data through the production formatters, so what you see is bit-identical to what a real scan would produce.

| Verdict state | Live preview | `.txt` source | `.html` source |
|---|---|---|---|
| **CHEATS DETECTED** (red) | [open ↗](https://sutaigne.github.io/alibi/pc-mode-cheats-detected_visual.html) | [.txt](./python/examples/pc-mode-cheats-detected.txt) | [.html](./python/examples/pc-mode-cheats-detected_visual.html) |
| **CAPTURE STACK PRESENT** (amber, console-rig mode) | [open ↗](https://sutaigne.github.io/alibi/console-rig-capture-stack_visual.html) | [.txt](./python/examples/console-rig-capture-stack.txt) | [.html](./python/examples/console-rig-capture-stack_visual.html) |
| **CLEAN** (green, with a Historical demo) | [open ↗](https://sutaigne.github.io/alibi/pc-mode-clean_visual.html) | [.txt](./python/examples/pc-mode-clean.txt) | [.html](./python/examples/pc-mode-clean_visual.html) |

The `_visual.html` files are fully self-contained (inline CSS + JS, no external assets) and work offline once downloaded.

## Auditability

This kit's whole value is being readable by a reviewer who has no reason to trust the author. Therefore:

- All source is plain `.ps1` / `.py` / `.css` / `.js` / `.html`. Nothing is minified, compiled, or obfuscated.
- No binaries are shipped (the historical zips in `archive/` are PowerShell source).
- No external dependencies at runtime beyond Python 3.10+ stdlib (Python port) or the PowerShell that ships with Windows.
- No telemetry, no analytics, no tracking.
- Exactly one outbound network call (LOLDrivers BYOVD cross-reference) exists, prompts the user with Y/N before running, skipped by default with `-SkipLOLDrivers` / `--skip-loldrivers`, and is explicitly disclosed in every report.
- Every shipped file has its SHA256 published in [`HASHES.txt`](./HASHES.txt) so a reviewer can confirm the kit they received matches this repo.
- The reviewer-side workflow is documented in [`docs/for-reviewers.md`](./docs/for-reviewers.md).
- Security disclosure policy: [`SECURITY.md`](./SECURITY.md). Private vulnerability reporting is enabled — use it for bypass reports or false-positive contributions.

## Project history

See [`docs/handoff.md`](./docs/handoff.md) for the full PowerShell-side history (v3.2 through v3.8, 2026-05-25), the design rationale for each scanner, the recency-decay architecture, and the dev workflow.

See [`docs/design-handoff-2026-05/`](./docs/design-handoff-2026-05/) for the visual design's source-of-truth bundle (reference HTMLs, design canvas, design tokens spec).

## License

MIT — see [`LICENSE`](./LICENSE). Free to read, run, fork, redistribute.
