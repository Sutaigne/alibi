# Cheat-Intel Pulse — YYYY-MM

- **Run date:** YYYY-MM-DD
- **Window covered:** since <last pulse date>
- **Dedupe corpus:** <N> known tokens (`extract-known-tokens.ps1`)
- **Sources run:** GitHub ☐  Forums/marketplaces ☐  Social ☐

## Summary
- New candidates: **<n>**  (HIGH: <n> · MEDIUM/INPUT: <n> · deferred domains: <n>)
- Legal/scene notes: <new C&D, ban wave, major brand shutdown, or "none">
- Nothing-new sources: <list, if any — a dry source is a valid result>

## Candidates

| Token(s) | Brand / project | Game | Source URL | → Array | Tier | Dedupe | Conf. |
|---|---|---|---|---|---|---|---|
| `example_brand` | Example | CoD | https://… | `$CheatBrands_COD` | HIGH | new | high |
| `examp2` | Example2 | CS2 | https://… | `$CheatBrands_LowConfidence` | MEDIUM | single-source | low |

*Conf. = confidence the token is a real, current cheat AND won't false-positive
on legit software. Low-confidence items go MEDIUM regardless of tier guess.*

## Artifact deep-dive (Layer 2 — files, not just names)
For confirmed candidates / watch-list repos with public file trees or setup guides.
Distinctive artifacts only — no generic names, no hashes this version.

| Brand | Artifact | Type | Source (repo/thread) | → Array | Conf. |
|---|---|---|---|---|---|
| Example | `exampleloader.exe` | exe | https://github.com/…/contents | `$CheatBrands_COD` (filename) | high |
| Example | `models\*.onnx` + `configs\*.cfg` | constellation | https://github.com/…/ | `$VisionAimbot_AI_PC` | med |

## Aliases / already-covered (dropped)
- `xyz` — alias of existing `<token>`, no action.

## Recommended for Brad's review
1. <the high-confidence, well-sourced ones worth accepting this cycle>

## Deferred / watch
- <names seen but not yet a verifiable URL — chase next pulse>
