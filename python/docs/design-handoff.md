# Alibi — design handoff

You're being handed two synthetic example reports (`.txt` and matching `_visual.html`) and this doc. Goal: a new visual design for the HTML report. The text `.txt` doesn't change — the reviewer reads the text version when they want a plain log; the HTML is the readable, scannable, "I'm going to spend two minutes on this and make a call" surface.

## What this product is

A Windows gamer runs a read-only forensic scan against their own PC. Two files land on their Desktop: a timestamped `.txt` report and a matching `_visual.html`. They send both to a third party. The third party reads the HTML, decides whether the machine shows signs of cheat software, and replies with a yes / no / unsure.

The kit is invoked by a non-technical user. The HTML is read by a more-engaged but still non-forensic reviewer (e.g. tournament admin, coach, friend who knows what XIM is, a parent). The reviewer is **not** a security analyst — they need the verdict in the first second, the named items in the next ten, and the full detail available if they want to dig.

The PowerShell version of the kit has been in field use since May 2026. This is the Python port. It produces the **same** data shape and the same text report; the HTML companion is the surface we're redesigning.

## Who reads the HTML — and what they're deciding

| Reader | Time they'll spend | What they want |
|---|---|---|
| Tournament admin | 30 seconds | Verdict + named items |
| Friend / opponent | 1 minute | Verdict + reason + a sense of how clean the rest looks |
| The gamer themselves | 5+ minutes | The full detail, in case they want to dispute |
| Security-curious reviewer | 10+ minutes | Everything — timeline, all metadata, the historical section |

The design has to serve all four. The verdict + named items must be unmissable; the deep detail must be there but not in the way.

## Verdict tiers

The verdict is a four-state enum, but it differs between PC mode and console-rig mode.

**PC mode** (gamer auditing their own PC, run via `alibi`):

| Verdict | Colour | Means |
|---|---|---|
| `CHEATS DETECTED` | Red | HIGH-confidence cheat-brand / spoofer / DMA artifact present |
| `INPUT DEVICES DETECTED` | Red | No cheats, but adapter software (XIM / Cronus / etc.) found |
| `UNSURE` | Amber | No HIGH matches, but MEDIUM dual-use tools or odd locations |
| `CLEAN` | Green | No recent HIGH or MEDIUM matches |

**Console-rig mode** (console gamer auditing a PC connected to their console rig, run via `alibi-rig`):

| Verdict | Colour | Means |
|---|---|---|
| `MITM CHEAT STACK DETECTED` | Red | Vision-aimbot or adapter configurator present |
| `CAPTURE STACK PRESENT` | Amber | Only capture-card / HID-emulator software found — legit-streamer signal |
| `UNSURE` | Amber | Other MEDIUM dual-use matches |
| `CLEAN` | Green | Nothing flagged |

Both example HTMLs you have show real verdict shapes: the PC example is `CHEATS DETECTED` (red, packed with named items); the console example is `CAPTURE STACK PRESENT` (amber, streamer-disclosure shape).

## What the data looks like

The scan produces three lists:

1. **Findings** — one per detected artifact. Each has:
   - `severity` — `HIGH` / `MEDIUM` / `WARN` (access denied) / `INFO`
   - `kind` — `cheat` / `input` / `dual-use` / `other`
   - `category` — which scanner produced it (`Prefetch`, `BAM`, `MUICache`, `USB`, `DMA`, `LOLDrivers`, `AIVision`, `UserScripts`, `Drivers`, etc.)
   - `detail` — a one-line human-readable string, often with a `[matched-pattern]` prefix
   - `source` — where on the system the artifact was found (a file path, a registry key, a process)
   - `metadata` — arbitrary key/value pairs (`Pattern`, `LastWrite`, `SHA256`, `LOLDrivers_URL`, etc.)

2. **Processes** — every currently-running process, scored `HIGH` / `MEDIUM` / `LOW` / `CLEAN` with a kind, pattern, and reason. `HIGH` and `MEDIUM` rows matter; `LOW` and `CLEAN` are background.

3. **Services** — same shape as Processes.

Findings carry one extra dimension: **recency**. The kit has a 180-day rule. Findings with a most-recent-timestamp older than 180 days are demoted (HIGH→MEDIUM, MEDIUM→INFO) and tagged `RecencyClass='historical'`. They appear in their own section — visible to the reviewer, but not counted toward the verdict. The PC example HTML has a Historical section showing this: an old EngineOwning Prefetch entry from 420 days ago, originally HIGH, now MEDIUM.

## Current HTML structure (what's there now)

The example `_visual.html` files render six sections:

| # | Section | What it shows |
|---|---|---|
| Header | Verdict banner, hostname, user, timestamp | First-second comprehension |
| 01 | Cheat trace findings | HIGH/MEDIUM/WARN/INFO counts + a card per finding with all metadata |
| 02 | Running processes | Score-coloured table |
| 03 | Services | Score-coloured table |
| 04 | Timeline | Findings sorted by most-recent-timestamp, newest first |
| 05 | Coverage limitations | One paragraph; what the scan cannot detect |
| 06 | Historical findings | The >180d demoted block, if any (the PC example has one) |

This is a starting point, not a constraint — feel free to rethink the section order, the relative weighting, or the existence of any of them. The data model is fixed; the rendering is yours.

## Constraints

- **One self-contained HTML file.** Inline CSS, inline JS. No external assets, no CDN links, no fonts loaded over HTTPS. The file must render correctly when opened from a USB stick on an air-gapped machine. (Reviewers sometimes review reports without internet.)
- **No JS framework.** Vanilla JS only. The file is generated by Python on the gamer's machine — pulling in React or Vue would mean shipping a bundler. Plain `<script>` + `addEventListener` is fine and welcome.
- **Reviewer-readable source.** The HTML's source view must look auditable. No minified blobs, no obfuscation, no compiled-from-something. A curious reviewer should be able to open the `.html` in a text editor and confirm it's "just" presentation.
- **Works in stock Edge, Chrome, Firefox.** No experimental CSS, no flexbox features added after 2022.
- **Modest size.** The current HTML is ~20 KB. Anything under ~150 KB is fine — that includes any base64-encoded SVG icons you want to inline.
- **No tracking.** Obviously. No telemetry, no analytics, no third-party requests. (See "reviewer-readable" above.)
- **No emoji.** This is a security tool. The aesthetic is `engineering-document` not `consumer-app`.

## What we'd love from the design pass

A unified design language plus mockups for these states:

1. **The verdict banner.** Four states (red / amber / amber-variant / green). It's the single most important pixel in the report.
2. **A finding card.** The atomic unit. Severity badge, category tag, one-line detail, source path (often long), and a key/value metadata block. The metadata can have anywhere from 2 to 12 fields. The PC example has cards with all the realistic shapes — RUT hash match, LOLDrivers BYOVD with URL, AI-vision ONNX co-located finding, script content with pattern.
3. **The counts strip at the top of Section 01.** Currently four count-cards (HIGH / MEDIUM / WARN / INFO). Could be a sparkline, a stacked bar, a circular indicator — pick what reads fastest.
4. **The process / service tables.** Currently dense rows with score-coloured cells. Could stay tabular, could become collapsed-by-default groups, could be a different shape entirely.
5. **The Historical section.** The hardest part of the existing design — it has to be visible enough that a reviewer can find it, but visibly secondary so it doesn't get conflated with current evidence. The current "yellow tag" pattern is weak.
6. **The timeline.** Currently a flat reverse-chronological list. Could be a horizontal timeline ruler, a calendar heatmap, a sparkline-per-category. Or it could be removed entirely if the per-finding cards already carry timestamps clearly enough.

You're also welcome to propose:
- A persistent legend / key for severities and kinds
- Filtering controls (toggle WARN/INFO off, filter by category)
- A "copy this finding" affordance for the reviewer who wants to ask about a specific item

## What's out of scope

- **No new features.** Don't add an "explain this finding" button that calls an LLM, a "report to admin" link, or anything that requires runtime data the kit doesn't already collect.
- **No interactivity that requires network.** A filter toggle is fine; a "look up this binary on VirusTotal" link is not (unless it's a plain anchor the reviewer opens themselves).
- **Don't redesign the `.txt` report.** That's plain-text by intention and reviewer expectation.
- **Don't redesign the QUICK READ block of the `.txt` either.** It's a copy-paste payload for the AI-handoff flow in `UNSURE` mode.

## Inputs in this package

| File | Use |
|---|---|
| `examples/pc-mode-cheats-detected.txt` | Plain-text report. Read this first to see what data we're rendering. |
| `examples/pc-mode-cheats-detected_visual.html` | Current HTML rendering — your "before" baseline. |
| `examples/console-rig-capture-stack.txt` | Console-rig variant, amber-verdict shape. |
| `examples/console-rig-capture-stack_visual.html` | Current HTML, amber-verdict baseline. |
| `examples/generate_example.py` | The script that produced the above. If you want to test a different verdict state, edit this and re-run. |
| `src/alibi/visual_companion.py` | The current Python that renders the HTML. Your final design will replace the body of `render_html()`. |
| `src/alibi/findings.py` | The data model (`Finding`, `ScoredItem`). Authoritative. |
| `src/alibi/keywords.py` | All the keyword arrays, severities, allowlists, and the recency-decay config. Useful for understanding what categories exist and what `Pattern` values look like. |

## Deliverable shape

Mockups (Figma, HTML, screenshots — whatever's natural) covering at minimum:

1. PC-mode `CHEATS DETECTED` (red) — the rich case
2. Console-rig `CAPTURE STACK PRESENT` (amber) — the streamer case
3. PC-mode `CLEAN` (green) — the empty case (we don't have an example file for this; data is just the snapshot tables + a green banner + "no findings")
4. The Historical section in isolation

When the design lands, we'll port it back into `visual_companion.py` as a unified `render_html()` rewrite. Self-contained HTML/JS mockups would pipe in cleanest — but any format that conveys the intent works.

---

**Author note:** the PowerShell version of this kit and the data semantics are stable; what's loose is the visual layer. Don't be precious about the existing six-section structure. The reviewer's first second is the brief.
