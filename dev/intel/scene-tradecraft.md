# Cheat-Scene Tradecraft — surfaces, evasion, and our counter-methods

A field map for the cheat-intel pulse, distilled from the 2026-06 runs. One idea
runs through all of it:

> **The scene sanitizes the *surface* identically on every platform; the real
> intel lives one layer down. The clean surface is the tell — read underneath it.**
> A polished storefront, a verification-gated Discord, a "discussion-only" subreddit:
> all are the same move — make the public face ToS-clean while the substance persists
> behind a wall or in code. Our methodology has to mirror that, surface by surface.

This doc is the index; the **`PULSE-RUNBOOK.md`** has the step-by-step. Both are
dev-side (never shipped in the kit).

> **Lineage:** this methodology was generalized into **Ventris** — a domain-agnostic
> forensic-intel engine (engine + per-topic domain packs + a bootstrapper). Alibi's
> cheat-intel pulse is its origin/reference domain. *(Ventris = its own project; the
> cheat pack stays here.)*

## Surface map

| Surface | How they sanitize it | Where the intel actually is | Our counter-method | Tool |
|---|---|---|---|---|
| **Storefronts** (websites) | loader paywalled; marketing copy only; product images named for products | platform fingerprint, vendor clustering, affiliations, product *names* | read page traffic the site fires on load | `api-intercept.py` |
| **Discord** | verification gates: CAPTCHA, customer-role walls, RestoreCord OAuth, "use code words" | lazily-modded / unsanitized servers; user complaint & query channels | **attended** co-browse — Brad operates the account, agent reads | Claude-in-Chrome (attended) |
| **Reddit** | discussion-framing + coded vocabulary (dodges selling-bans) | persistent provider-review / "is X legit" / vouch threads | **manual** — Brad skims with the coded-vocab lens | (env-blocked; manual) |
| **Forums** (UC/MPGH/epvp) | anti-bot, hostile HTML, login walls | release/undetected threads, setup guides | RSS where exposed; else scoped web search | `poll-feeds.py` / WebSearch |
| **GitHub** | repos DMCA'd; decay is the signal | repo file trees, **release-asset filenames**, commits | API (no scraping) + Atom feeds | `gh api` / `poll-feeds.py` |
| **Feeds** (RSS/Atom) | — (the bot-friendly layer that routes *around* the walls) | new releases/commits/threads since last pass | poll → diff vs state → flag new | `poll-feeds.py` |

## What each surface yields — and its ceiling

- **Storefronts:** fingerprint + product taxonomy + affiliations. **Ceiling:** the actual
  loader is purchase-gated; marketing-image filenames (`.webp`/`.jpg`) are **NOT** software
  artifacts — don't tokenize them. The product *name-string* is corroboration only.
- **Discord (sanitized vendor servers):** brand + product taxonomy + operator handle +
  popularity. **Ceiling:** Layer-2 files behind customer-role / OAuth. Free join = taxonomy.
- **Discord (lazily-modded community servers):** the real nuggets — users pasting versions,
  filenames, error logs in complaint/query channels. *(Higher value; not yet sampled.)*
- **Reddit:** brand sightings + scene pulse (ban waves, anti-cheat reactions). Names, not files.
- **GitHub:** the cleanest source of **real filenames** — release assets
  (`AimmyV2.5.0.zip`, `Release.rar`) and file trees (`models\*.onnx`). Open/free class.
- **Feeds:** durable change-detection across all of the above that publish one.

## The boundary — observe, never acquire

This is anti-cheat *detection* research. The line is explicit and non-negotiable:

- **Names, filenames, paths, public URLs ONLY.** Never download, build, run, or link a
  cheat binary / DMA firmware / loader. `$KnownCheatHashes` stays manual (no sample-pulling).
- **No fuzzing / dir-busting / enumeration** of third-party infrastructure — observe only
  what a normal visit serves.
- **No CAPTCHA solving, no rules/verification gates, no OAuth grants.** Account actions
  (joining a server) are **attended-only**, operated by Brad, never the unattended cron.
- If the pipeline ever starts pulling working exploits, it has drifted — stop.

## Triage discipline (hard-won)

- **HidHide lesson:** HIGH-cheat only if the tool's *primary purpose* is cheating. Dual-use
  components / controller adapters / thin-sourced → MEDIUM / INPUT. Default DOWN when unsure.
- **Dictionary-word brands** (`zenith` ↔ ROG Zenith; `phantom`, `ancient`, `arcane`) → never
  the bare word; qualified token or LowConfidence only.
- **Marketing-image filenames** ≠ artifacts → corroboration only, if independently found.
- **Same-software ≠ same-operator** (Burger ≈ Vindy were both Invision Community but on
  different hosts) → confirm shared-operator claims via host / NS / mail / registrant.
- Every accepted token needs a **verifiable source URL**, and a **human review gate** before
  it touches `forensic-common.ps1`.

## Tooling index (`dev/intel/`)

| Tool | Purpose |
|---|---|
| `extract-known-tokens.ps1` | dump the ~460-token dedupe corpus from the live engine |
| `api-intercept.py` | headless website API/asset interceptor (fingerprint + paths) |
| `poll-feeds.py` + `feeds.txt` | RSS/Atom monitor → diff → flag-new loop |
| `PULSE-RUNBOOK.md` | the step-by-step procedure (this doc is its index) |
| `pulse-template.md` → `pulses/` | candidate-report shape + monthly outputs |

Scheduled monthly as `cheat-intel-pulse` (9am, 1st) → opens a draft PR. HIL throughout.
