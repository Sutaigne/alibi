# Handoff · pc-check visual companion redesign

## Overview

This bundle is the visual layer of the **pc-check** forensic-scan tool. It replaces the body of `src/pc_check/visual_companion.py :: render_html()` so the timestamped `_visual.html` the kit drops on the gamer's desktop matches the new "dark tactical readout" look.

Three verdict states are designed and shipped here:

| File | State | Color | Purpose |
|---|---|---|---|
| `reports/report-pc-cheats-detected.html` | **CHEATS DETECTED** | red | The rich case — full evidence load |
| `reports/report-console-capture-stack.html` | **CAPTURE STACK PRESENT** | amber | Console-rig streamer disclosure |
| `reports/report-pc-clean.html` | **CLEAN** | green | Empty case + an example archived block |

Plus a design canvas (`reports/Design Overview.html` + `reports/design-canvas.jsx`) that previews all three side-by-side. Not for shipping — design reference only.

## About the design files

The files in `reports/` are **HTML design references** — fully self-contained prototypes showing the intended look, interaction model, and data-to-pixel mapping. They are NOT the implementation. The job is to **port them into `visual_companion.py`'s `render_html()` so the Python kit emits the same HTML** for any `Finding` / `ScoredItem` input.

The HTML is generated; do not hand-author it. Treat the prototypes as a spec.

The Python data model is fixed (`src/pc_check/findings.py`): `Finding(severity, kind, category, detail, source, metadata)` and `ScoredItem` for processes/services. The shape doesn't change — only how it's rendered.

## Fidelity

**High-fidelity.** Every color, spacing token, radius, font, animation easing, and CSS variable in the HTML is final. Lift values literally — they're not approximations.

## Constraints (carry over from the original brief)

These constraints are non-negotiable and the design respects them:

- **One self-contained HTML file per scan.** Inline CSS, inline JS. No CDN links, no external fonts, no network calls. File must render correctly from a USB stick on an air-gapped machine.
- **No JS framework.** Vanilla JS, plain `<script>` + `addEventListener`. The kit ships from Python; pulling in React would mean shipping a bundler.
- **Reviewer-readable source.** No minification, no obfuscation. A curious reviewer should be able to open the HTML in a text editor and confirm it's "just" presentation.
- **Works in stock Edge, Chrome, Firefox.** No experimental CSS. Tested against modern stable.
- **Modest size.** Each report renders in ~80–125 KB. Donut + timeline + dots scales with finding count but stays under 200 KB.
- **No tracking.** Zero telemetry. Zero analytics.
- **No emoji.** The aesthetic is `engineering-document`. Use ASCII glyphs (`·`, `→`, `≤`, `↗`, `▾`) only.

## File map

```
design_handoff_pc_check_visual/
├── README.md                                  ← you are here
├── source-handoff.md                          ← original PM brief (kept for context)
└── reports/
    ├── report-pc-cheats-detected.html         ← red verdict · rich case (PORT THIS FIRST)
    ├── report-console-capture-stack.html      ← amber verdict · console rig
    ├── report-pc-clean.html                   ← green verdict · with archived demo
    ├── Design Overview.html                   ← design canvas (not for shipping)
    └── design-canvas.jsx                      ← dependency of the canvas only
```

The three report files share a CSS shell (~1300 lines, identical across files) and a JS interactivity layer (~250 lines, identical). Only the verdict block, named-items, timeline data, category map, findings list, runtime tables, donut, and historical section change between files.

Build `render_html()` so the shell is a constant template and only the variable parts are interpolated.

---

## Document structure (top → bottom)

Every report has the same section order:

1. **Doc bar** — `pc-check` tool name + scan id, top of page
2. **Verdict block** — the most important pixel
3. **Timeline ribbon** — cone-shaped, recency-biased
4. **Category signal map** — tile grid of categories that fired (rich case only — skip if no findings)
5. **Indicator distribution donut** — score-tier breakdown (rich case only — skip if total <10 indicators)
6. **01 · Findings** — filter bar + severity-grouped finding cards
7. **02·03 · Runtime** — processes & services side-by-side
8. **Historical** — archived (>180d) findings, dashed border, hatched rail (only when archived data exists)
9. **Coverage limitations** — bottom disclosure
10. **Doc foot** — tool tagline + outbound-call disclosure

The brief explicitly DROPPED the original "Section 04 · Timeline" (the flat reverse-chrono list) — per-finding cards carry timestamps clearly enough, and the cone timeline at the top does the time work.

---

## Design tokens

All declared in `:root` at the top of every report. **Lift these exactly — they're tuned together.**

### Color

```css
/* surfaces */
--bg:        #08080a;
--bg-2:      #0c0c10;
--panel:     #0f0f13;
--panel-2:   #14141a;
--panel-hi:  #1a1a22;
--rule:      #1f1f27;
--rule-2:    #2a2a34;
--rule-3:    #3a3a46;

/* ink (foreground) */
--ink:       #f5f5f4;
--ink-2:     #d6d3d1;
--ink-3:     #a8a29e;
--ink-4:     #78716c;
--ink-5:     #4a4845;

/* severity */
--hi:        #ff5757;      /* HIGH */
--hi-2:      #ff8a8a;
--hi-bg:     rgba(255, 87, 87, 0.10);
--hi-bg-2:   rgba(255, 87, 87, 0.18);
--hi-edge:   rgba(255, 87, 87, 0.42);

--md:        #f5b53a;      /* MEDIUM */
--md-2:      #ffcb6a;
--md-bg:     rgba(245, 181, 58, 0.10);
--md-edge:   rgba(245, 181, 58, 0.40);

--wn:        #9a958d;      /* WARN (access denied) */
--wn-bg:     rgba(154, 149, 141, 0.08);
--info:      #6b6660;      /* INFO */

--ok:        #4ade80;      /* CLEAN / verdict green */
--ok-bg:     rgba(74, 222, 128, 0.10);
--ok-edge:   rgba(74, 222, 128, 0.40);

--accent:    #7dd3fc;      /* affordances, hover indicators, links */
--accent-2:  #38bdf8;
--accent-bg: rgba(125, 211, 252, 0.10);

--hist-tone: #5b5752;      /* archived findings rail */
```

### Type

- **Body / sans:** `ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif`. No web fonts (offline constraint).
- **Mono / numeric / paths / labels:** `ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace`.

All "labels" (section headers, KV keys, tooltip labels, axis labels, eyebrows) are uppercase + letter-spaced monospace. All paths / hashes / source identifiers are monospace at body size.

| Element | Size | Weight | Letter-spacing | Color |
|---|---|---|---|---|
| Verdict text (`.v-text`) | 38px | 700 | -0.01em | severity color |
| Section H2 (`.sec-head h2`) | 13.5px | 700 | 0.14em UPPER | `--ink` |
| Sub-eyebrow (`.named-head h3`, `.tbl-head h3`) | 12.5px | 700 | 0.14em UPPER | `--ink` |
| Finding title | 14.5px | 600 | normal | `--ink` |
| KV key | 10px | 400 | 0.10em UPPER | `--ink-5` |
| KV value | 12px | 400 | normal mono | `--ink-2` |
| Doc bar | 11px | 400 mono | 0.04em | `--ink-4` |

### Spacing & layout

- Doc max-width: **1280px**, padding `22px 28px 80px`.
- Section gap: `22px` between sections.
- All `border-radius`: `4px` on small chrome, `6px` on cards / panels.
- Block shadows: avoid. Use `box-shadow: 0 0 8px var(--hi-edge)` only as glow on severity dots / verdict text.

### Background texture

Subtle 48px grid behind everything via `body::before`:

```css
body::before {
  content: "";
  position: fixed; inset: 0;
  background-image:
    linear-gradient(rgba(255,255,255,0.018) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,0.018) 1px, transparent 1px);
  background-size: 48px 48px;
  pointer-events: none;
}
```

---

## Components

### 1. Doc bar (`.docbar`)

Top of every page. Two lines, mono, ink-4.

```
●  pc-check 3.8 · python · consolidated report           scan BREAD-PC · 2026-05-25T20:37:06 · read-only · no system state was modified
```

The leading `●` is a pulsing dot, colored by verdict state:

```css
.docbar .tool::before {
  background: var(--hi);     /* or --md, or --ok */
  box-shadow: 0 0 8px var(--hi);
  animation: pulse 1.8s ease-in-out infinite;
}
@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.35; } }
```

### 2. Verdict block (`.verdict`)

A bordered panel with a radial gradient wash in the top-left in the severity color (`rgba(255,87,87,0.18)` for red, etc.). Two-column grid:

- **Left col (1.4fr):** Eyebrow ("VERDICT") + huge verdict text + one-sentence sub + monospace `host / user / os / admin / scan` metadata grid.
- **Right col (1fr) — readout panel (`.readout`):** Eyebrow ("RECENT FINDINGS · LAST 180D"), a stacked count bar (HIGH/MEDIUM/WARN/INFO segments sized by count), a 4-row grid of `dot · severity · count · note`, and a kind-breakdown footer (`cheat-kind 9 · input-kind 2 · dual-use 4 · archived 2`).
- **Below the grid — named items (`.named`):** "Why this verdict · N named items" eyebrow, then a 2-column grid of `dot · category · text` rows, each clickable to jump-and-pin its finding card. An "Also detected · input devices" section under a dashed divider.

The **named-items** block is THE 10-second comprehension surface. Every row links to a finding by id. Clicking a row scrolls to + pins the matching `.finding` (or `tr.has-link`) below.

#### Readout fade in CLEAN

In the green verdict, the readout panel is muted so the verdict carries the weight:

```css
.readout.is-empty {
  opacity: 0.55;
  filter: saturate(0.4);
  transition: opacity 200ms, filter 200ms;
}
.readout.is-empty:hover { opacity: 1; filter: saturate(1); }
```

### 3. Timeline ribbon (`.tl-wrap`)

The most distinctive piece. **Log-scale live zone + collapsed archive strip with an explicit hatched fold.**

#### Coordinate system

ViewBox `0 0 1200 200`. The x-axis has two independent log scales separated by a hatched fold band:

| Zone | SVG x-range | Width | Domain |
|---|---|---|---|
| Archive strip (>180d) | `44..196` | 152 px (13%) | log-compressed, daysAgo 180..3000 |
| Fold (hatched, non-clickable) | `200..214` | 14 px | visual seam |
| Live zone (≤180d) | `220..1196` | 976 px (81%) | log of daysAgo 0..180 |

Live-zone projection:

```python
import math
X_LEFT, X_RIGHT = 220, 1196

def x_live(d):
    if d <= 0:    return X_RIGHT
    if d >= 180:  return X_LEFT
    return X_RIGHT - (X_RIGHT - X_LEFT) * math.log(d + 1) / math.log(181)
```

This is **honest log scale** — the recent end naturally gets more room because of math, not psychology. Last 7 days take ~31% of the live zone; last 30 days take ~57%; last 90 days take ~78%.

#### Lanes

4 horizontal lanes at fixed y: HIGH=50, MEDIUM=86, WARN=118, INFO=148. Uniform spacing across both zones. Lane labels live at the **right edge** of the live zone (x=1200, anchored-end).

#### Collision stacking

Live dots within the same lane that fall within `STACK_DX = 9` SVG units stack **upward** with a shrinking radius:

```python
STACK_DX = 9      # collision threshold (px)
STACK_DY = 9      # vertical offset per stack level
R_MIN = 2.8       # smallest dot radius

def place_dots(findings, lanes):
    placed = {lane: [] for lane in lanes}
    for f in sorted(findings, key=lambda f: f.days_ago):
        x = x_live(f.days_ago)
        stack = placed[f.lane]
        k = sum(1 for p in stack if abs(p['x'] - x) < STACK_DX)
        y = lanes[f.lane] - k * STACK_DY
        r = max(R_MIN, 5.0 - k * 0.55)
        stack.append({'x': x, 'y': y, 'r': r})
        yield f, x, y, r
```

A dense day like `-5d` (two HIGH findings at the same x) reads as a tight 2-dot column rather than overlapping discs. The eye picks up density as height.

#### Archive strip (`x = 44..196`)

Archived findings (>180d) collapse into the strip. They stack horizontally from right (newest) to left (oldest), aligned to their severity lane, at uniform 18px spacing:

```python
ARCH_RIGHT_EDGE = 192   # FOLD_LEFT - 8

for i, finding in enumerate(sorted(archived, key=lambda f: f.days_ago)):
    x = ARCH_RIGHT_EDGE - i * 18
    y = lanes[finding.lane]
    # render dot with .archived.stroked class
    # below: small age label (e.g. "1y", "7y", "420d") at y=lane+14
```

Each archived dot uses class `.dot.archived.stroked` — desaturated, dashed stroke, 55% opacity. Lane rules within the strip render at 60% opacity. A small `archive · N` header sits at the top; if N=0 it shows `— none —`.

#### Fold band (`x = 200..214`)

```html
<defs>
  <pattern id="foldhatch" patternUnits="userSpaceOnUse" width="6" height="6" patternTransform="rotate(45)">
    <line x1="0" y1="0" x2="0" y2="6" stroke="var(--ink-5)" stroke-width="1.5" opacity="0.6"></line>
  </pattern>
</defs>
<rect x="200" y="20" width="14" height="152" fill="url(#foldhatch)"></rect>
```

Bracketed by 1px vertical lines at x=200 and x=214 (color `--ink-4`). Makes it unmistakable that two coordinate systems meet here.

#### Axis ticks (live)

Vertical dashed lines + bottom labels at log-meaningful intervals: `today`, `-1d`, `-3d`, `-1w`, `-2w`, `-1mo`, `-3mo`, `-6mo`. Each computed via `x_live(d)`. Labels at y=184.

Archive zone gets two labels: `> 180d` (start-anchored) and `log compressed →` centered between archive-left and fold-left.

#### Density wash

A faint colored rect from `x_live(7)` to `1196` indicates the "hot" recent activity area:

```html
<rect x="..." y="20" width="..." height="156" fill="var(--hi)" opacity="0.06"></rect>
```

Color matches verdict: `--hi` red for CHEATS, `--md` amber for CAPTURE STACK, skip entirely for CLEAN.

#### Today beam

At x=1196. 1.5px cyan vertical line with an animated `pulse-ring` on the top dot:

```css
@keyframes ringpulse {
  0%   { r: 4;  opacity: 0.9; stroke-width: 1.5; }
  100% { r: 22; opacity: 0;   stroke-width: 0.5; }
}
```

For amber/green variants, override the `--accent` CSS var on `.tl-wrap` (e.g. `style="--accent: #4ade80;"`).

#### Hover scrub

A vertical dashed line follows the mouse across the SVG, with a date readout above it. JS inverts the piecewise mapping:

```js
function svgXToDate(svgX) {
  var daysAgo, archived = false;
  if (svgX >= 220) {                          // live zone
    var frac = (1196 - svgX) / 976;
    daysAgo = Math.exp(frac * Math.log(181)) - 1;
  } else if (svgX >= 200) {                   // fold
    daysAgo = 180;
  } else {                                    // archive
    archived = true;
    var fracA = (196 - svgX) / 152;
    daysAgo = 180 * Math.pow(3000 / 180, fracA);
  }
  // ...iso date string, return { daysAgo, iso, archived }
}
```

In the archived zone, the readout prefixes with `archived · ` (e.g. `archived · 2024-08-15 · −283d`).

#### Stats strip

Above the SVG: 3 stats — `7 in last 7 days · 14 in last 30 days · 21 in last 180 days`. First stat gets `.hot` class (red glow) when non-zero. In green/amber variants, zero counts render in `--ok` color.

### 4. Category signal map (`.catmap`)

A `repeat(auto-fit, minmax(122px, 1fr))` grid of tiles. Each tile is one category that fired: name + dominant-severity count + tiny severity-color bar at the bottom. Tile gets a subtle gradient wash matching its top severity (red, amber, or default).

Clicking a tile sets `catFilter = <name>` and scrolls to the findings section. The active filter shows as a removable pill in the filter bar.

Skip this section entirely if no scanners fired (clean case).

### 5. Indicator distribution donut (`.indi`)

The cheats case shows this. Score-tier donut with 5 slices: HIGH / MEDIUM / WARN / INFO / LOW+CLEAN.

ViewBox 240×240, center (120,120), r=88, stroke-width=24. Slices drawn as overlapping `<circle pathLength=100>` elements with `stroke-dasharray` + rotated to cumulative start angles. Gaps of 0.5% between slices.

Legend on the right: each row is `swatch | label · breakdown | count`. Hovering a row highlights its slice (and vice versa) via `.is-active` class — `currentColor` lights up the drop-shadow.

Skip when total indicators < ~10 (the clean case skips it; donut would show a solid LOW/CLEAN ring with no useful information).

### 6. Filter bar (`.filters`)

Severity chips (HIGH/MEDIUM/WARN/INFO) on the left — colored by their severity (red, amber, gray, dim). When pressed, fill solid with severity color. INFO is unpressed by default to declutter the findings list.

Kind chips on the right (cheat/input/dual-use/other). All pressed by default.

Plus a `reset` button and a cyan "active category" pill that appears when category-map filter is active.

### 7. Finding cards (`.finding`)

The atomic unit. Each card:

```html
<li id="f-aimmy" class="finding" data-severity="HIGH" data-kind="cheat" data-category="AIVision"
    data-pattern="aimmy" data-keys="aimmy.exe yolov8n.onnx">
  <div class="finding-head">
    <span class="sev-tag" data-sev="HIGH">HIGH</span>
    <span class="kind-tag">cheat</span>
    <span class="cat-tag" data-cat="AIVision">AIVision</span>
    <time class="finding-when">last write 2026-05-23 · 2 d ago</time>
  </div>
  <div class="finding-title"><span class="pat">aimmy</span>AI-vision aimbot executable: <code>aimmy.exe</code></div>
  <div class="finding-source">
    <span class="src-label">source</span>
    <code class="src-path">C:\Users\Bob\source\aimmy\aimmy.exe</code>
    <button class="copy-btn" data-copy="…">copy</button>
  </div>
  <dl class="finding-meta" data-collapsed="4">
    <div class="kv"><dt>Pattern</dt><dd>aimmy</dd></div>
    …4 visible kvs…
    <div class="kv hidden"><dt>FullPath</dt><dd>…</dd></div>
  </dl>
  <button class="meta-expand"><span class="car"></span>expand · 2 more</button>
</li>
```

Severity rail (3px) glows on the left edge via `::before`. Hovering reveals the `copy` button, brightens the source-path border, and highlights related findings via the cross-linking JS (see below).

Metadata is a 2-column KV grid by default. Items beyond the 4th are `.kv.hidden` until the user clicks `.meta-expand`, which adds `.is-expanded` to the card.

`code.src-path` is monospace, wraps at `anywhere`, sits in a subtle inset box (`bg-2` + 1px `rule` border).

`.pat` is the matched pattern (e.g. `aimmy`, `rut.gg`, `bcdedit /set testsigning`) shown as a chip-styled inline-code prefix to the title. Color matches severity (red bg for HIGH, amber for MEDIUM).

Special metadata renderers:
- `IsSigned`: render with class `true` (green) or `false` (amber) on the `<dd>`.
- `SHA256`, `LOLDrivers_Id`, other hash-like values: class `hash` (lower contrast).
- `LOLDrivers_URL` / `Reference`: wrap as `<a>` with `--accent` color.

Sparkline support (`.spark`): when metadata represents a time-span (USB lifecycle, AppData activity), include a small horizontal track with positioned `<span class="ev" data-kind="…">` markers. See the Cronus Zen finding in the cheats report for the markup.

### 8. Runtime tables (`.tbl-shell`)

Two side-by-side tables — processes and services. Each row:
- score column (HIGH/MEDIUM in semantic color + glow dot, LOW/CLEAN in muted gray)
- pid or state
- name (bold ink) + path (muted) + reason line ("matches `engineowning` · cheat keyword · cmd …")

CLEAN/LOW rows have class `.clean-row` and are `hidden` by default (button `show CLEAN` in the footer toggles).

Cross-linking: rows with `class="has-link"` and `data-pattern` / `data-keys` participate in the same hover-related highlighting as finding cards (see below).

### 9. Historical (`.hist`)

When archived (>180d) findings exist, render this section AT THE BOTTOM with a hatched divider:

```
████ archived · > 180 days · did NOT affect verdict ████████████████████████
```

(Implemented as a flex with a `.label` and a `.hatch` rule using `repeating-linear-gradient`.)

Cards in this section use:
- `.finding` with `border-style: dashed`
- The severity rail (`::before`) replaced with a diagonal hatch fill
- Severity tags get `opacity: 0.7`
- An `.hist-orig` pill shows the original severity + age: `orig HIGH · 420 d old`

The clean case includes this section as a demo (XIM Manager 2018 + an old EngineOwning prefetch) — proves the layout still reads when the verdict is green but there's history.

### 10. Coverage & doc foot

Plain text disclosures. The coverage section's `<h2>` is the same eyebrow style as other section headers. `<em>` tags inside use `font-style: normal; color: var(--ink-2)` — they're emphasis, not italics.

---

## Interactions & behaviors

All vanilla JS, ~250 lines, identical across the three files (apart from a couple of null-guards for elements that don't exist in the empty case).

### Filter chips
Toggling a chip flips `[aria-pressed]`. JS reads all currently-pressed chips per filter group (`sev`, `kind`) and shows/hides findings whose `[data-severity]` / `[data-kind]` are in the active set. Empty severity-group headers (e.g. WARN when WARN chip is off) are hidden too. Reset button restores defaults (everything except INFO is on; INFO is off by default to declutter).

### Category-map → findings filter
Clicking a `.cat-tile` (or any `.cat-tag[data-cat]` inside a finding card) sets a single-category filter and scrolls to the findings section. A removable cyan pill appears in the filter bar to clear it. Pressing `Escape` clears too.

### Cross-linking hovers
Findings and process/service rows declare `data-pattern` (single match string, e.g. `engineowning`) and `data-keys` (space-separated additional tokens, e.g. `engineowning ENGINEOWNING.exe EO.exe`). Hovering any one of them tokenizes its keys and adds `.is-related` to every other element with an overlapping token. The host body gets `.has-focus` which dims unrelated finding cards to 30%. Mouse-leave clears.

Hovering a timeline dot does the same — it looks up `[data-target]` and bridges to the finding card, then triggers the related-highlight. Plus the dot gets `.is-active` (brightness boost + drop-shadow).

### Click to pin
Clicking a named-items row or a timeline dot scrolls smoothly to the matching finding (or `tr.has-link`), expands its metadata, and adds `.is-pinned` (cyan border) for 2.2 seconds. Escape clears all pins.

### Donut ↔ legend
Rows in `.indi-legend` and slices in `.indi-donut` both have `[data-tier]`. Hovering either highlights the other (`.is-active`).

### Copy button
`navigator.clipboard.writeText` with a textarea-select fallback for `file://` contexts. Visual feedback: button label changes to `copied` and turns cyan for 1.2s.

### Show / hide CLEAN rows in runtime tables
`.toggle-clean` button toggles `.hidden` on `tr.clean-row` and updates the footer count.

### Expand finding metadata
`.meta-expand` button toggles `.is-expanded` on the parent `.finding`. CSS rule `.finding.is-expanded .finding-meta .kv.hidden { display: grid; }` reveals the hidden KVs.

### Keyboard
`Escape` clears: hover-related highlights, all pins, the timeline tooltip, the category filter.

---

## Data → DOM mapping

A reviewer-friendly mental model for the port:

| Python object | Where it lands |
|---|---|
| `Finding` (severity, kind, category, detail, source, metadata) | One `.finding` `<li>` with `[data-severity] [data-kind] [data-category] [data-pattern] [data-keys]` and an `id` like `f-{slug}`. Metadata becomes KV rows. |
| `Finding` w/ `RecencyClass='historical'` | One `.finding` inside the `.hist` section (NOT in the main findings list) with the `OriginalSeverity` pill, AND one `<circle class="archived">` dot in the timeline's compressed log zone. |
| `Finding` w/ no timestamp | Card in the findings list. Timeline dot anchors near x=234 with a small dashed indicator. |
| `ScoredItem` (process) | One `<tr>` in `#proc-tbl`. HIGH/MEDIUM also get a "named-items" row in the verdict block. |
| `ScoredItem` (service) | Same, in `#svc-tbl`. |
| Verdict | Drives the `.verdict[data-state]` attribute (`red` / `amber` / `green`), the `.v-text`, the docbar pulse color, the "today beam" color in the timeline, the radial gradient wash, and the readout `.is-empty` class on green. |
| Counts (HIGH/MED/WARN/INFO) | Flex weights on `.readout-bar > span`, numbers in `.readout-rows .n`, chip counts. |
| Recency stats (7d / 30d / 180d) | The `.tl-stats` strip above the timeline. The 7d stat gets `.hot` when > 0. |

### Slug rules for IDs

`Finding` ids should be stable so the named-items grid and timeline can target them. Suggested:

```
f-<lowercased category>-<short pattern slug>
e.g.  f-prefetch-eo, f-mui-rut, f-usb-cronus
```

`ScoredItem` ids: `proc-<name-slug>`, `svc-<name-slug>`.

### Cross-link key tokens

Build `data-keys` from: filename (without path), exe name from process cmd, any "Pattern" metadata, service Display name. Tokens are space-separated; the JS lowercases everything before comparison. Two elements link if they share ANY token.

This is intentionally fuzzy — you want a `Prefetch: ENGINEOWNING` finding and a process row `ENGINEOWNING.exe` to light each other up.

---

## Empty / edge cases

- **No findings (CLEAN):** Drop sections 4 (catmap), 5 (donut). Findings section becomes a single green-dotted "No findings to display" callout + the 4 INFO scan-summary cards. Show the historical section if archived data exists (see `report-pc-clean.html` for the demo).
- **No archived findings:** Drop the entire `.hist` section.
- **No HIGH findings:** The HIGH `sev-group` header still renders if INFO is on (and the user wants to filter), but the HIGH chip in the filter shows `HIGH 0` and the timeline HIGH lane shows a centered `— no HIGH findings in any zone —` text.
- **No timestamp on a Finding:** Anchor its timeline dot at x=234 (recent edge of live zone) with a small dashed indicator line above it; the tooltip says `(no ts)`.
- **Single recency tier dominates the donut:** Skip the donut entirely.

---

## Layout grid summary (for the CSS skim-reader)

| Element | Display | Notes |
|---|---|---|
| `.doc` | block, max-width 1280px | center, padding 22/28 |
| `.verdict-grid` | grid `1.4fr 1fr` | collapses to 1col under 880px |
| `.named-grid` | grid `1fr 1fr` | each row `12px 92px 1fr auto` |
| `.tl-stats` | flex, row | gap 18px, dividers via `border-left` |
| `.catmap-grid` | grid `repeat(auto-fit, minmax(122px, 1fr))` | gap 6px |
| `.indi-body` | grid `280px 1fr` | donut left, legend right |
| `.filters` | flex, wrap | severity chips colored by tier |
| `.findings` | grid, gap 8px | column of cards |
| `.finding-meta` | grid `repeat(2, minmax(0, 1fr))` | each KV is `160px 1fr` inside |
| `.runtime-grid` | grid `1fr 1fr` | processes + services side-by-side |

---

## Assets

**No image assets ship.** Every visual element is CSS, SVG, or a Unicode glyph (`·`, `→`, `≤`, `▾`, `↗`). The fold-band is an SVG pattern (`<pattern id="foldhatch">`). The grid texture is a CSS `linear-gradient`. The pulsing dot, ring-pulse, fresh-dot glow are CSS animations.

The historical section's diagonal hatch on the rail is `repeating-linear-gradient` (45°). The `.hist-divider .hatch` is the same trick.

No fonts are loaded over the network. System UI sans + system monospace only.

---

## What to do first

1. Read `reports/report-pc-cheats-detected.html` end-to-end as a spec. It contains every component.
2. Inspect `reports/report-pc-clean.html` for the empty/historical-only edge case.
3. Pull the `<style>` block as a Python triple-quoted constant. Don't paraphrase the CSS.
4. Write a `Section` enum-ish helper that knows the section order from §1 above, and a per-section render function.
5. Implement the timeline math as plain functions: `x_live(d)`, `place_dots(findings, lanes)` (collision-stack), and the inverse `svgXToDate(svgX)` for the hover scrub. Constants are in this README. Archive strip layout is independent (uniform 18px spacing).
6. Match the JS exactly (or as closely as feasible — it's already vanilla, can paste). Inline it as a triple-quoted constant too.
7. Wire up the `Finding` / `ScoredItem` → DOM mapping per §"Data → DOM mapping". Generate stable ids.
8. Compare your output to the three reference files. They should be visually indistinguishable.

If anything's ambiguous, defer to the HTML — the HTML is source of truth.
