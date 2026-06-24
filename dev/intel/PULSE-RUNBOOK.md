# Cheat-Intel Pulse — Runbook

**Goal:** keep alibi's brand/keyword coverage current by periodically scanning the
wild for new cheating repos, software, and the forums/social channels promoting
them — then proposing new tokens for review. **CoD-first**, other games second.

This is a **discovery** process. It does NOT touch a user's machine — that's the
scanner's job. This feeds the scanner's keyword arrays.

> **Human-in-the-loop is mandatory.** This runbook produces a *candidate report*
> only. Nothing lands in `alibi-engine/scanner/forensic-common.ps1` until Brad
> reviews it. Every accepted token needs a **verifiable source URL** (the same
> rule as `handoff.md`'s "Add a new cheat-brand keyword").

---

## Step 0 — Build the dedupe corpus

```
powershell -File dev\intel\extract-known-tokens.ps1 > dev\intel\known-tokens.txt
```

~460 tokens. Every candidate is checked against this; already-covered brands are
dropped (or noted as "alias of <existing>"). This file is regenerated each run —
never trust a stale copy.

## Step 1 — Discover (fan out across sources, CoD-first)

Run all three source classes. CoD brands are the priority signal; surface
other-game and cross-game tooling too, but tag the game.

### A. GitHub (most automatable — highest ROI)
Search repos + code, sort by recently created/updated. Starting queries:
- `aimbot`, `triggerbot`, `no recoil`, `wallhack`, `esp` + `call of duty` / `warzone` / `cod`
- `hwid spoofer`, `serial spoofer`, `tpm spoofer`, `disk spoofer`
- `dma cheat`, `pcileech`, `fuser`, `kmbox`, `gamehook` (DMA / external)
- `yolov8 aimbot`, `onnx aimbot`, `ai aim assist`, `arduino mouse` (AI-vision constellation)
- topics: `game-cheat`, `game-hacking`, `aimbot`, `external-cheat`
- `gh search repos --sort updated --created '>=<last-run-date>'` to bound to new activity.
Capture: repo URL, name, stars, last push, what it targets.

### B. Forums & marketplaces (search/research, not scraping)
Anti-bot + login walls make direct scraping brittle — use web search scoped to:
- UnknownCheats, MPGH, elitepvpers (thread titles, "release" / "undetected" posts)
- rut.gg / RUAVT family, and reseller storefronts
- New brand names, C&D / ban-wave news (Activision legal actions name brands).
Capture: brand name, the page URL, what game, whether it's sold or free.

### C. Social promo (best-effort, mostly manual)
- YouTube / TikTok ("cod cheat 2026", "warzone aimbot undetected"), Telegram/Discord invite mentions.
- These rarely yield clean tokens but surface *names* to chase back to A/B for a verifiable URL.

## Step 2 — Triage & route

For each surviving candidate decide **tier** and **array**. Routing table:

| Signal | Array | Verdict effect |
|---|---|---|
| Named CoD cheat brand, well-sourced | `$CheatBrands_COD` | HIGH → `CHEATS DETECTED` |
| Named brand, other game | `$CheatBrands_<Game>` | HIGH |
| **True** HWID/TPM/disk/serial spoofer | `$Spoofer_Brands` | HIGH |
| DMA cheat firmware / vendor | `$DMA_Indicators` | HIGH |
| AI-vision aimbot (model/repo/brand) | `$VisionAimbot_AI_PC` | HIGH |
| Generic feature word (new variant) | `$CheatFeature_Names` | HIGH |
| Controller adapter / remap / HID tool | `$InputDevices` | INPUT DEVICES (not cheat) |
| Dual-use / background dependency (cf. HidHide) | `$DualUse_Tools` | MEDIUM only |
| **Single-source / thin / unconfirmed** | `$CheatBrands_LowConfidence` | MEDIUM only |
| DDoS / network attack tool | `$NetworkAttack_High` / `_Medium` | HIGH / MEDIUM |
| Forum/reseller **domain** | `$CheatMarketplaceDomains` (deferred) | inert until browser-history scanner exists |

**Tier discipline (learned from the HidHide false positive):** a tool is only
HIGH-cheat if its *primary purpose is cheating*. Dual-use components, controller
adapters, and anything thinly sourced go MEDIUM/INPUT — never HIGH. When unsure,
default DOWN a tier; an accusation false-positive is worse than a missed dot.

## Step 3 — Emit the candidate report

Write `dev/intel/pulses/pulse-YYYY-MM.md` from `pulse-template.md`. One row per
candidate: token(s), brand, game, source URL, suggested array, tier, dedupe note,
confidence. Summarize counts and flag anything legally notable (new C&D, ban wave).

## Step 4 — Review (Brad) → patch

Brad approves/edits the report. Accepted tokens are appended to the right array in
`forensic-common.ps1` (one place — both modes inherit). Then the standard release
chain: regenerate `HASHES.txt` → rebuild `dist\alibi.zip` → cut a new GitHub release
(see [[alibi-launcher]] / `dev/scripts/build-release.ps1`). Mirror any HIGH/MEDIUM
PC-side additions into the visual companion arrays (`visual-companion-common.ps1`)
— that duplication is known tech debt.

## Honesty about limits
- GitHub is clean and reliable. Forums/social are best-effort: login walls,
  anti-bot, and ToS mean coverage there is search-surfaced, not exhaustive.
- A run that finds nothing new is a valid result — log it; don't pad the report.
- Never auto-commit tokens. The HIL gate is the whole point.
