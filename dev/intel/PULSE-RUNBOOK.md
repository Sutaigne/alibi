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
powershell -File dev\intel\extract-known-tokens.ps1 -OutFile dev\intel\known-tokens.txt
```

~460 tokens. Use `-OutFile` (UTF-8) — **not** a `>` redirect, which writes UTF-16
in PowerShell 5.1 and crashes `grep`. Every candidate is checked against this;
already-covered brands are dropped (or noted as "alias of <existing>"). Note that
several reseller domains live in `$CheatMarketplaceDomains`, so a brand may match
as a `.com` domain without being a HIGH brand token. Regenerated each run — never
trust a stale copy. For the dedup checks use **ripgrep or PowerShell `-contains`** —
the Git-Bash `grep` binary on this machine SIGABRTs on this file.

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

### A2. Durable feeds (RSS/Atom) — the bot-friendly layer
The most reliable monitor is a published feed: no API key, no 403, no anti-bot
(routes AROUND the walls that block Reddit JSON / the Chrome filter / WebFetch).
- **GitHub** exposes per-repo Atom with no rate limit: `github.com/<o>/<r>/releases.atom`
  (new release filenames + dates — proven on Aimmy), `.../commits.atom`, `.../tags.atom`.
  Keep a watchlist of known cheat repos and poll these.
- **Forums** that still expose RSS (UnknownCheats / vBulletin `external.php?type=RSS2`)
  are bot-tolerant — prefer the feed over scraping the hostile HTML.
- The pulse supplies the **diff** (entries since the last report) + the human-review gate.
- **Don't** buy all-in-one social-scraper MCPs (SocialCrawl/Apify/etc.) — they cover
  X/IG/TikTok/LinkedIn, which are the *wrong* surfaces; cheat intel lives on
  Discord/Telegram/forums/GitHub. Breadth you'll never query.

### B. Forums & marketplaces (search/research, not scraping)
Anti-bot + login walls make direct scraping brittle — use web search scoped to:
- UnknownCheats, MPGH, elitepvpers (thread titles, "release" / "undetected" posts)
- rut.gg / RUAVT family, and reseller storefronts
- New brand names, C&D / ban-wave news (Activision legal actions name brands).
Capture: brand name, the page URL, what game, whether it's sold or free.

### C. Social promo (best-effort, mostly manual)
- YouTube / TikTok ("cod cheat 2026", "warzone aimbot undetected"), Telegram/Discord invite mentions.
- These rarely yield clean tokens but surface *names* to chase back to A/B for a verifiable URL.

### C2. Discord co-browse (ATTENDED ONLY — never in the unattended cron)
Cheat sites link to Discord invites with rich `#updates`/`#changelog` content. Reading
them is valuable but constrained:
- **Brad must be present.** Joining/navigating a server is automating his `breadlyAI`
  account (Discord ToS) — he authorizes it per-run; the scheduled job does NOT do this.
- **Hard stops:** the agent does NOT solve **CAPTCHAs** or accept **rules/verification
  gates** — hand back to Brad, who clears them, then the agent resumes read-only.
- **Join → read target channels → LEAVE.** No messages, reactions, or DMs.
- **Known limitation (2026-06 BurgerCheats co-browse):** the Layer-2 gold (loader
  filenames, DLLs, install paths) lives in **customer-role-gated** channels. A free
  join yields product codenames + changelog prose, not on-disk artifacts. Don't expect
  filenames from a free account.
- **Invite *metadata*** (server name, member/online counts, operator handle) IS
  automatable and ToS-clean via the invites API — that part can run in the cron.

### C3. Reddit (ATTENDED/MANUAL — blocked from automation here)
Reddit is **un-pullable from this environment**: WebFetch refuses reddit.com, the
public JSON API 403s anti-bot, and the Chrome MCP safety filter blocks `reddit.com`.
So Reddit is a **manual source** — Brad (a real logged-in user) browses and drops
notable threads, same posture as the Discord co-browse.
- **Best signal = persistent discussion/review communities, not overt selling subs.**
  Same adaptation as the Discords (verification gates / "use code words"): the subs
  that LAST survive by not making selling the overt purpose — they frame as discussion,
  **provider reviews**, and "is X legit," and lean on **coded vocabulary**. Don't write
  them off as low-signal; the brand intel lives there.
- **Search the coded vocabulary, NOT "aimbot/cheat"** (obvious terms under-surface these
  communities). High-yield terms: *provider, private, menu, loader, config, spoofer,
  unlock-all, "legit check," "vouch"/"rep," "is it undetected," "best provider for <game>,"
  "got banned using <X>."* **Provider-review / vouch / legit-check threads name brands
  constantly** — that is the gold.
- Lower-value but real: ban-wave reports + anti-cheat patch reactions = scene pulse.
  Reddit gives names, rarely filenames.
- **Subs to watch:** general — `r/gamehacks`, `r/gamecheats` (casual/mixed signal).
  Per-game discussion (highest intel) — `r/CODWarzone`, `r/Warzone`, `r/blackops6`,
  `r/BlackOps7` (verify), `r/CompetitiveCoD`; and for the other engine-covered games
  `r/EscapeFromTarkov`, `r/playrust`, `r/apexlegends`, `r/cs2`, `r/MarvelRivals`.
- Treat any brand name seen here as a **lead** → confirm with a verifiable URL (site/
  GitHub) before it becomes a candidate token.

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

## Step 2b — Artifact deep-dive (Layer 2: the *files*, not just the name)

A brand name only catches a cheater if their on-disk files contain it. The
higher-fidelity signal is the **concrete artifact** the cheat drops. For each
confirmed candidate (and worthwhile watch-list repos), dig for artifacts and
route them to the artifact arrays.

**Where to look (GitHub & forums are gold; seller pages rarely expose files):**
- **GitHub file trees** — list the repo contents directly, no clone, no download:
  `gh api repos/<owner>/<repo>/contents` and drill into subdirs
  (`/contents/models`, `/configs`, `/src`). Read the README/SetUp/"how to use"
  for the loader name and install path.
- **GitHub release assets** — `gh api repos/<owner>/<repo>/releases` lists the
  **actual download filenames** (the loader/archive) + download counts, without
  fetching the file. This is the proven clean source for real artifact names from
  the open/free target class — e.g. `AimmyV2.5.0.zip` (Babyhamsta/Aimmy, 100k+ dl),
  `Release.rar` (TheRyoSaeba/BLOPS7). **NEVER download the asset** (it's malware /
  dual-use); the *name* is the intel. Distinctive names → brand-as-filename token.
- **Forum setup guides** — UnknownCheats/MPGH "how to run" posts list the loader
  exe, the DLL, and where to drop it.
- **Website API/asset intercept** — `python dev/intel/api-intercept.py <urls...>`
  (headless Playwright, Swiss Army Tool core from `Fun/bridge-server.py`). Captures
  the JSON endpoints + asset/file paths a candidate site loads on a normal visit.
  Yields **platform fingerprint** (IPB vs WooCommerce — clusters vendors) and
  **affiliations** (e.g. epvp logo). **Boundary:** it only observes the page's own
  traffic — NO fuzzing, dir-busting, or auth bypass. The actual loader binary is
  purchase-gated, so don't expect it here. ToS-clean and batchable, so this part CAN
  run in the unattended cron (unlike the Discord co-browse).
  - **Triage asset hits by type — don't dismiss them wholesale.** The asset bucket
    mixes two kinds:
    - *(a) media / framework* (`.webp`, `.jpg`, `.css`, `.js`) = marketing, **not**
      software. A banner `COD-Phantom.webp` never lands on a cheater's disk — don't
      tokenize it. The embedded product **name-string** is only **corroborating
      LowConfidence** signal *if independently found as a process/file/folder on a
      scanned machine*; never a trigger.
    - *(b) executable / archive / download paths* (`.exe`, `.zip`, `.dll`, `.bin`,
      `.msi`, `/download`, `/loader`, `/release`) = **real candidate artifacts —
      evaluate per the tier table.**
    The 2026-06 sample (3 polished IPB/WooCommerce storefronts) returned only (a)
    because they gate downloads — a free/open cheat, a direct-download host, a
    GitHub-release link, or a sloppily-modded site will surface (b). A few sanitized
    targets is NOT a verdict on the method; judge every run by what that target leaks.
  - **Wrong tool for static pages.** Blog/forum/SEO-spam posts (itch.io blogs, MPGH
    threads) fire no relevant on-load network calls — the interceptor returns nothing.
    Their download link is *body text*; use text extraction (WebFetch / get_page_text)
    to pull it. The interceptor shines on AJAX stores + file-host landing pages.
  - **Boundary:** do NOT follow free-cheat download chains to malware file hosts just
    to exercise the executable bucket. Loading throwaway distribution domains is real
    risk for marginal proof. GitHub release names (`gh api releases`, names only) cover
    the open/free class cleanly.

**Artifact → array routing:**

| Artifact | → Array | Token form |
|---|---|---|
| Distinctive loader/exe (`Aimmy2.exe`) | the brand array, as a filename | `aimmy2.exe` / `aimmy2` |
| Injected DLL name | `$DLLInjector_Names` | the dll basename |
| `.lua` cheat script name | `$LuaCheat_Keywords` | the script token |
| AppData/Documents folder | `$AppDataPatterns` | the distinctive dir name |
| `.onnx` model + `models\` + `.cfg` together | `$VisionAimbot_AI_PC` | the **constellation**, not a lone `.onnx` |
| Service / driver name | `$Spoofer_Brands` / brand array | the service basename |

**FP discipline (critical):** only **distinctive** artifacts. NEVER tokenize
generic names a legit app could ship — `loader.exe`, `config.cfg`, `cheat.dll`,
a bare `.onnx`, `models\`. Those only count as part of a constellation that
`Scan-AIVisionArtifacts` already requires. **This version handles filenames &
paths only — no downloading binaries, no hashes** (that's a deliberate
scope line; `$KnownCheatHashes` stays manual).

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
