"""Visual HTML companion — dark-tactical readout.

This is a faithful port of the high-fidelity design (Claude Design, May 2026)
into the production renderer. The CSS (~1300 lines) and JS (~350 lines) are
shipped as raw resource files under ``scanner/`` at the repo root so both
this Python module AND the PowerShell visual-companion drivers can read the
same source of truth:

    scanner/visual_styles.css   — design tokens, layout, component styles
    scanner/visual_scripts.js   — vanilla-JS interactivity (filters, hover-linking,
                                  timeline scrub, donut↔legend, copy-to-clipboard)

Keep those resources verbatim — a reviewer should be able to open them in a
text editor and confirm they're "just" presentation + interactivity.

Document structure (top → bottom):

    1. doc bar
    2. verdict block (with readout + named items)
    3. timeline ribbon (log-scale live + collapsed archive strip)
    4. category signal map           (skipped if no scanners fired)
    5. indicator distribution donut  (skipped if total indicators < 10)
    6. 01 · findings                 (filter bar + severity-grouped cards)
    7. 02·03 · runtime               (processes + services side-by-side)
    8. historical                    (only when >180d findings exist)
    9. coverage limitations
   10. doc foot

Verdict → state mapping (drives colours, density wash, today-beam accent):

    CHEATS DETECTED / INPUT DEVICES DETECTED / MITM CHEAT STACK DETECTED  → red
    CAPTURE STACK PRESENT / UNSURE                                        → amber
    CLEAN                                                                 → green
"""
from __future__ import annotations

import html
import math
import os
import platform
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

from alibi.findings import Finding, ScoredItem
from alibi.recency import get_finding_timestamp
from alibi.utils import Engine, is_admin


# ---------------------------------------------------------------------------
# Resource loading — CSS and JS live under scanner/ at the repo root so the
# PowerShell drivers and this Python module read the same source of truth.
# Layout: <repo>/python/src/alibi/visual_companion.py  →  parents[3] == <repo>
# ---------------------------------------------------------------------------
_SCANNER_DIR = Path(__file__).resolve().parents[3] / "scanner"


def _load_resource(name: str) -> str:
    return (_SCANNER_DIR / name).read_text(encoding="utf-8")


_CSS = _load_resource("visual_styles.css")
_JS = _load_resource("visual_scripts.js")


# ---------------------------------------------------------------------------
# Constants — verdict mapping, lanes, log-scale math, recency thresholds
# ---------------------------------------------------------------------------
VERDICT_STATE: dict[str, str] = {
    "CHEATS DETECTED": "red",
    "INPUT DEVICES DETECTED": "red",
    "MITM CHEAT STACK DETECTED": "red",
    "CAPTURE STACK PRESENT": "amber",
    "UNSURE": "amber",
    "CLEAN": "green",
}

STATE_COLOUR_VAR = {"red": "--hi", "amber": "--md", "green": "--ok"}

LANE_Y = {"HIGH": 50, "MEDIUM": 86, "WARN": 118, "INFO": 148}

X_LIVE_LEFT = 220
X_LIVE_RIGHT = 1196
LIVE_LOG_BASE = math.log(181)

ARCH_RIGHT_EDGE = 192  # FOLD_LEFT (200) minus 8

STACK_DX = 9
STACK_DY = 9
R_MIN = 2.8
R_MAX = 5.0
R_STEP = 0.55

FRESH_MAX_DAYS = 7

# Metadata keys that carry timestamp dimensions for a finding. Order matters
# — when generating dot labels we prefer the more specific key. (Same list
# the recency module consults, but expanded with NewestWrite/OldestWrite for
# AppData-lifecycle dots.)
TIMESTAMP_KEYS: list[str] = [
    "LastRun", "LastExecution", "LastArrival", "Timestamp",
    "LastWrite", "LastModified", "NewestWrite",
    "Created", "FirstSeen", "FirstInstall", "InstallDate", "LastRemoval",
    "OldestWrite", "MostRecentTimestamp",
]

# Metadata keys to display as paths (no quoting / wrapping) vs values
HASH_KEYS = {"SHA256", "Sha256", "sha256", "LOLDrivers_Id"}
URL_KEYS = {"LOLDrivers_URL", "Reference"}
BYTES_KEYS = {"SizeBytes", "BlobSizeBytes"}

# Severities (display order in groups + filter chip order)
SEVERITY_ORDER = ["HIGH", "MEDIUM", "WARN", "INFO"]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _esc(s: Any) -> str:
    return html.escape("" if s is None else str(s), quote=True)


def _slug(s: str, maxlen: int = 32) -> str:
    """Produce a safe-for-HTML-id slug. Lowercase, [a-z0-9-] only."""
    if not s:
        return "x"
    out = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    if not out:
        out = "x"
    return out[:maxlen]


def _format_bytes(n: Any) -> str:
    try:
        i = int(n)
    except (TypeError, ValueError):
        return _esc(n)
    return f"{i:,}"


def _state_for(verdict: str) -> str:
    return VERDICT_STATE.get(verdict, "amber")


def _x_live(days_ago: float) -> float:
    if days_ago <= 0:
        return float(X_LIVE_RIGHT)
    if days_ago >= 180:
        return float(X_LIVE_LEFT)
    return X_LIVE_RIGHT - (X_LIVE_RIGHT - X_LIVE_LEFT) * math.log(days_ago + 1) / LIVE_LOG_BASE


def _human_age(days: float) -> str:
    d = int(round(days))
    if d <= 0:
        return "today"
    if d == 1:
        return "1 d ago"
    if d < 30:
        return f"{d} d ago"
    if d < 365:
        return f"{d // 30} mo ago"
    years = d / 365.0
    if years < 2:
        return f"{years:.1f} y ago"
    return f"{int(years)} y ago"


def _short_age(days: float) -> str:
    """Compact age label for archive strip ('1y', '7y', '420d')."""
    d = int(round(days))
    if d < 365:
        return f"{d}d"
    return f"{d // 365}y"


def _iso_date(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d")


def _iso_datetime(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


def _finding_timestamps(f: Finding) -> list[tuple[str, datetime]]:
    """Walk a finding's metadata and return [(label, dt), ...] for every
    timestamp-shaped value present. Order follows TIMESTAMP_KEYS so the
    "most decisive recent" key surfaces first.
    """
    out: list[tuple[str, datetime]] = []
    if not f.metadata:
        return out
    seen: set[str] = set()
    for key in TIMESTAMP_KEYS:
        if key not in f.metadata:
            continue
        val = f.metadata[key]
        if val in (None, "", "unknown"):
            continue
        dt: datetime | None = None
        if isinstance(val, datetime):
            dt = val
        else:
            dt = _try_parse_dt(str(val))
        if dt is None:
            continue
        sig = f"{dt.isoformat()}"
        if sig in seen:
            continue
        seen.add(sig)
        out.append((key, dt))
    return out


def _try_parse_dt(s: str) -> datetime | None:
    s = s.strip()
    if not s:
        return None
    fmts = (
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%Y/%m/%d %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y",
    )
    for fmt in fmts:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s.replace("Z", ""))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# ID + cross-link key generation
# ---------------------------------------------------------------------------
def _finding_id(f: Finding, used: set[str]) -> str:
    """Build a stable HTML id for a finding. Format: f-<category>-<short>.
    Disambiguates within a category by appending a counter.
    """
    cat = _slug(f.category, 16)
    short = ""
    pat = (f.metadata.get("Pattern") if f.metadata else None) or ""
    if pat:
        short = _slug(str(pat), 16)
    else:
        # Fall back to a slug of the source basename.
        base = os.path.basename(f.source) if f.source else ""
        short = _slug(base, 16) or "x"
    base_id = f"f-{cat}-{short}"
    candidate = base_id
    i = 2
    while candidate in used:
        candidate = f"{base_id}-{i}"
        i += 1
    used.add(candidate)
    return candidate


def _process_id(p: ScoredItem, used: set[str]) -> str:
    base = f"proc-{_slug(p.name, 24)}"
    candidate = base
    i = 2
    while candidate in used:
        candidate = f"{base}-{i}"
        i += 1
    used.add(candidate)
    return candidate


def _service_id(s: ScoredItem, used: set[str]) -> str:
    base = f"svc-{_slug(s.name, 24)}"
    candidate = base
    i = 2
    while candidate in used:
        candidate = f"{base}-{i}"
        i += 1
    used.add(candidate)
    return candidate


def _data_keys_for_finding(f: Finding) -> str:
    """Build the cross-link token set. Tokens include the matched pattern,
    the source basename, FileName, ModuleName, DeviceName, ProcessName.
    JS lowercases both sides, so case doesn't matter.
    """
    keys: list[str] = []
    if f.metadata:
        for k in ("Pattern", "FileName", "ModuleName", "DeviceName",
                  "ProcessName", "ServiceName", "Value"):
            v = f.metadata.get(k)
            if v:
                keys.append(str(v))
    if f.source:
        keys.append(os.path.basename(f.source))
    return " ".join(sorted(set(t for t in keys if t)))


def _data_keys_for_proc(p: ScoredItem) -> str:
    keys = [p.name]
    if p.pattern:
        keys.append(p.pattern)
    exec_path = p.extra.get("ExecutablePath", "")
    if exec_path:
        keys.append(os.path.basename(exec_path))
    return " ".join(sorted(set(t for t in keys if t)))


def _data_keys_for_svc(s: ScoredItem) -> str:
    keys = [s.name]
    if s.pattern:
        keys.append(s.pattern)
    display = s.extra.get("DisplayName", "")
    if display:
        keys.append(display)
    return " ".join(sorted(set(t for t in keys if t)))


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------
def _render_docbar(*, scan_host: str, scan_iso: str, lol_db_used: bool) -> str:
    net = "1 outbound call to loldrivers.io (opt-in)" if lol_db_used else "no network calls"
    return (
        '<div class="docbar">'
        '<span class="tool"><b>alibi</b> 3.8 · python · consolidated report</span>'
        f'<span>scan <b>{_esc(scan_host)}</b> · {_esc(scan_iso)} · read-only · {_esc(net)}</span>'
        '</div>'
    )


def _render_verdict(
    *,
    verdict: str,
    state: str,
    sub_text: str,
    mode_label: str,
    scan_iso: str,
    recent_findings: list[Finding],
    archived_findings: list[Finding],
    processes: list[ScoredItem],
    services: list[ScoredItem],
    named_items_struct: dict[str, list[dict[str, str]]],
) -> str:
    host = os.environ.get("COMPUTERNAME", "")
    user = os.environ.get("USERNAME", "")
    os_str = f"{platform.system()} {platform.release()} · {platform.version()}"
    admin = "true" if is_admin() else "false"

    # Severity counts among recent (verdict-relevant) findings only.
    sev_count = {s: 0 for s in SEVERITY_ORDER}
    for f in recent_findings:
        if f.severity in sev_count:
            sev_count[f.severity] += 1

    # Kind breakdown across all recent items (findings + scored proc/svc).
    kind_count = {"cheat": 0, "input": 0, "dual-use": 0, "other": 0}
    for f in recent_findings:
        if f.kind in kind_count:
            kind_count[f.kind] += 1
    for p in processes:
        if p.score in ("HIGH", "MEDIUM") and p.kind in kind_count:
            kind_count[p.kind] += 1
    for s in services:
        if s.score in ("HIGH", "MEDIUM") and s.kind in kind_count:
            kind_count[s.kind] += 1

    # Readout bar widths — minimum 1 so empty segments still render thinly.
    def w(s: str) -> int:
        return max(1, sev_count[s]) if sev_count[s] else 0
    bar_segments = "".join(
        f'<span class="{cls}" style="flex:{sev_count[sev]}"></span>'
        for sev, cls in (("HIGH", "b-hi"), ("MEDIUM", "b-md"),
                         ("WARN", "b-wn"), ("INFO", "b-info"))
        if sev_count[sev] > 0
    )
    if not bar_segments:  # CLEAN case — emit a single thin empty bar
        bar_segments = '<span class="b-info" style="flex:1; opacity:0.3"></span>'

    readout_rows = (
        f'<span class="dot hi"></span><span class="l">HIGH</span>'
        f'<span class="n">{sev_count["HIGH"]}</span>'
        '<span class="note">verdict-driving</span>'
        f'<span class="dot md"></span><span class="l">MEDIUM</span>'
        f'<span class="n">{sev_count["MEDIUM"]}</span>'
        '<span class="note">dual-use signals</span>'
        f'<span class="dot wn"></span><span class="l">WARN</span>'
        f'<span class="n">{sev_count["WARN"]}</span>'
        '<span class="note">access denied</span>'
        f'<span class="dot info"></span><span class="l">INFO</span>'
        f'<span class="n">{sev_count["INFO"]}</span>'
        '<span class="note">scan summary</span>'
    )

    archived_count = len(archived_findings)
    readout_foot = (
        f'<span>cheat-kind&nbsp;<b>{kind_count["cheat"]}</b></span>'
        f'<span>input-kind&nbsp;<b>{kind_count["input"]}</b></span>'
        f'<span>dual-use&nbsp;<b>{kind_count["dual-use"]}</b></span>'
        f'<span>archived&nbsp;<b>{archived_count}</b> '
        f'<span style="color:var(--ink-5)">(off-verdict)</span></span>'
    )

    readout_class = "readout"
    if state == "green" and sum(sev_count.values()) == 0:
        readout_class += " is-empty"

    # Verdict subtitle text picks per verdict.
    sub_html = f'<p class="v-sub">{_esc(sub_text)}</p>' if sub_text else ""

    # Named items — Why this verdict
    named_main = named_items_struct.get("main", [])
    named_also = named_items_struct.get("also", [])
    named_block = ""
    if named_main or named_also:
        named_rows = "".join(
            f'<li data-sev="{_esc(item["sev"])}" data-target="{_esc(item["target"])}">'
            '<span class="dot"></span>'
            f'<span class="cat">{_esc(item["category"])}</span>'
            f'<span class="text">{item["html"]}</span>'
            '<span class="arrow">↗</span></li>'
            for item in named_main
        )
        also_block = ""
        if named_also:
            also_rows = "".join(
                f'<li><span class="dot"></span>'
                f'<span class="cat">{_esc(item["category"])}</span>'
                f'<span class="text">{item["html"]}</span></li>'
                for item in named_also
            )
            also_block = (
                '<div class="named-also">'
                '<h4>Also detected · input devices (separate category)</h4>'
                f'<ul>{also_rows}</ul></div>'
            )
        named_block = (
            '<div class="named">'
            '<div class="named-head">'
            f'<h3>Why this verdict · {len(named_main)} named items</h3>'
            '<span class="rule"></span>'
            '<span class="hint">click an item to jump &amp; pin its finding card ↓</span>'
            '</div>'
            f'<ul class="named-grid" id="named-list">{named_rows}</ul>'
            f'{also_block}'
            '</div>'
        )

    return (
        f'<div class="verdict" data-state="{state}">'
        '<div class="verdict-grid">'
        '<div>'
        '<div class="v-label">Verdict</div>'
        f'<h1 class="v-text">{_esc(verdict)}</h1>'
        f'{sub_html}'
        '<dl class="v-meta">'
        f'<dt>host</dt><dd>{_esc(host)}</dd>'
        f'<dt>user</dt><dd>{_esc(user)}</dd>'
        f'<dt>os</dt><dd>{_esc(os_str)}</dd>'
        f'<dt>admin</dt><dd>{_esc(admin)}</dd>'
        f'<dt>scan</dt><dd>{_esc(scan_iso)} · {_esc(mode_label)}</dd>'
        '</dl></div>'
        f'<div class="{readout_class}">'
        '<div class="v-label">Recent findings · last 180d</div>'
        f'<div class="readout-bar">{bar_segments}</div>'
        f'<div class="readout-rows">{readout_rows}</div>'
        f'<div class="readout-foot">{readout_foot}</div>'
        '</div></div>'
        f'{named_block}'
        '</div>'
    )


def _render_timeline(
    *,
    state: str,
    recent_findings: list[Finding],
    archived_findings: list[Finding],
    finding_ids: dict[int, str],
) -> str:
    """Render the log-scale timeline ribbon. Dots are emitted per timestamp
    on each finding (so lifecycle metadata gets multiple dots) and stacked
    using the README's collision algorithm.
    """
    now = datetime.now()

    # ---- (a) Build live-zone dot records --------------------------------
    @dataclass_lite
    class DotRec:
        x: float
        y: float
        r: float
        target: str
        sev: str
        cat: str
        when_label: str
        detail: str
        is_fresh: bool

    live_dots: list[DotRec] = []
    archived_dot_recs: list[tuple[Finding, datetime]] = []

    for f in recent_findings:
        target_id = finding_ids.get(id(f), "")
        for key, ts in _finding_timestamps(f):
            if key == "MostRecentTimestamp":
                continue  # synthesized aggregate; ignore for dot emission
            age_days = (now - ts).days
            if age_days < 0:
                age_days = 0
            if age_days >= 180:
                continue  # belongs in archive strip
            x = _x_live(age_days)
            lane = LANE_Y.get(f.severity, LANE_Y["INFO"])
            label_age = "today" if age_days == 0 else f"−{age_days}d"
            when_label = f"{_iso_date(ts)} ({label_age})"
            detail = f"{f.detail} · {key}"
            live_dots.append(DotRec(
                x=x, y=float(lane), r=R_MAX,
                target=target_id, sev=f.severity, cat=f.category,
                when_label=when_label, detail=detail,
                is_fresh=(age_days <= FRESH_MAX_DAYS),
            ))

    for f in archived_findings:
        for key, ts in _finding_timestamps(f):
            if key == "MostRecentTimestamp":
                continue
            archived_dot_recs.append((f, ts))
            break  # one dot per archived finding (don't dilute the strip)

    # ---- (b) Apply collision stacking by lane ---------------------------
    by_lane: dict[float, list[DotRec]] = {}
    live_dots.sort(key=lambda d: d.x, reverse=True)  # newest first
    for d in live_dots:
        stack = by_lane.setdefault(d.y, [])
        k = sum(1 for p in stack if abs(p.x - d.x) < STACK_DX)
        d.y = d.y - k * STACK_DY
        d.r = max(R_MIN, R_MAX - k * R_STEP)
        stack.append(d)

    # ---- (c) Stats strip ------------------------------------------------
    def _count_within(days: int) -> int:
        cutoff = now.timestamp() - days * 86400
        total = 0
        for f in recent_findings:
            ts = get_finding_timestamp(f)
            if ts and ts.timestamp() >= cutoff:
                total += 1
        return total
    s7 = _count_within(7)
    s30 = _count_within(30)
    s180 = _count_within(180)

    # ---- (d) Density wash + accent override -----------------------------
    density_colour_var = STATE_COLOUR_VAR[state]
    density_x = _x_live(7)
    density_w = X_LIVE_RIGHT - density_x
    accent_override = ""
    if state == "amber":
        accent_override = ' style="--accent: #f5b53a;"'
    elif state == "green":
        accent_override = ' style="--accent: #4ade80;"'

    # ---- (e) Axis tick coordinates --------------------------------------
    ticks = [
        ("today", float(X_LIVE_RIGHT)),
        ("−1d", _x_live(1)),
        ("−3d", _x_live(3)),
        ("−1w", _x_live(7)),
        ("−2w", _x_live(14)),
        ("−1mo", _x_live(30)),
        ("−3mo", _x_live(90)),
        ("−6mo", float(X_LIVE_LEFT)),
    ]
    tick_lines = "".join(
        f'<line x1="{x:.1f}" x2="{x:.1f}" y1="20" y2="170" '
        'style="stroke: var(--rule-2); stroke-dasharray: 1 5;"></line>'
        for _label, x in ticks
    )
    tick_labels_html: list[str] = []
    for label, x in ticks:
        if label == "today":
            tick_labels_html.append(
                f'<text x="{x:.1f}" y="184" text-anchor="end" class="abs">today</text>'
            )
        else:
            tick_labels_html.append(
                f'<text x="{x:.1f}" y="184" text-anchor="middle">{label}</text>'
            )
    tick_labels = "".join(tick_labels_html)

    # ---- (f) Build dot SVG ----------------------------------------------
    dot_svg: list[str] = []
    for d in live_dots:
        classes = ["dot", d.sev]
        if d.is_fresh:
            classes.append("is-fresh")
        dot_svg.append(
            f'<circle class="{" ".join(classes)}" r="{d.r:.1f}" '
            f'cx="{d.x:.1f}" cy="{d.y:.1f}" '
            f'data-target="{_esc(d.target)}" data-sev="{_esc(d.sev)}" '
            f'data-cat="{_esc(d.cat)}" data-when="{_esc(d.when_label)}" '
            f'data-detail="{_esc(d.detail)}"></circle>'
        )

    # If a severity lane has no live dots, emit a soft "no findings" placeholder.
    # (Only for HIGH because that's the most visible silence.)
    if not any(d.sev == "HIGH" for d in live_dots):
        dot_svg.append(
            '<text x="708" y="54" text-anchor="middle" '
            'style="fill: var(--ink-5); font-family: ui-monospace, monospace; '
            'font-size: 10px; font-style: italic;">— no HIGH findings in any zone —</text>'
        )

    # ---- (g) Archive strip ---------------------------------------------
    archived_dot_recs.sort(key=lambda pair: (now - pair[1]).days)  # newest first
    archive_svg: list[str] = []
    for i, (f, ts) in enumerate(archived_dot_recs):
        x = ARCH_RIGHT_EDGE - i * 18
        if x < 48:
            break  # ran out of room
        lane = LANE_Y.get(f.severity, LANE_Y["INFO"])
        age_days = (now - ts).days
        archive_svg.append(
            '<g>'
            f'<circle class="dot {f.severity} archived stroked" r="3.5" '
            f'cx="{x}" cy="{lane}" data-target="" data-sev="{_esc(f.severity)}" '
            f'data-cat="{_esc(f.category)} (archived)" '
            f'data-when="{_iso_date(ts)} (−{age_days}d · was {_esc(f.metadata.get("OriginalSeverity", f.severity))}, demoted)" '
            f'data-detail="{_esc(f.detail)}"></circle>'
            f'<text x="{x}" y="{lane + 14}" text-anchor="middle" '
            'style="fill: var(--ink-5); font-family: ui-monospace, monospace; '
            f'font-size: 9px;">{_short_age(age_days)}</text>'
            '</g>'
        )

    archive_count = len(archived_dot_recs)
    archive_label = f"archive · {archive_count}" if archive_count else "archive · — none —"

    # ---- (h) Heading + stats --------------------------------------------
    hot_class = "tl-stat hot" if s7 > 0 else "tl-stat"
    tl_h_html = (
        f'<h3 class="tl-h">Log-scale recency · '
        f'<span class="accent">{len(recent_findings)} recent</span>'
        f' + <span style="color: var(--ink-4)">{len(archived_findings)} archived</span> findings</h3>'
    )

    return (
        f'<div class="tl-wrap" id="timeline"{accent_override}>'
        '<div class="tl-head">'
        '<div class="tl-head-left">'
        '<span class="tl-eyebrow">Forensic timeline</span>'
        f'{tl_h_html}</div>'
        '<div class="tl-stats">'
        f'<div class="{hot_class}"><span class="n">{s7}</span><span class="l">in last 7 days</span></div>'
        f'<div class="tl-stat"><span class="n">{s30}</span><span class="l">in last 30 days</span></div>'
        f'<div class="tl-stat"><span class="n">{s180}</span><span class="l">in last 180 days</span></div>'
        '</div></div>'
        '<svg class="tl-svg" viewBox="0 0 1200 200" preserveAspectRatio="none" aria-label="log-scale timeline">'
        f'<rect x="{density_x:.1f}" y="20" width="{density_w:.1f}" height="156" fill="var({density_colour_var})" opacity="0.06"></rect>'
        '<g>'
        '<line class="lane-rule" x1="220" x2="1196" y1="50" y2="50"></line>'
        '<line class="lane-rule" x1="220" x2="1196" y1="86" y2="86"></line>'
        '<line class="lane-rule" x1="220" x2="1196" y1="118" y2="118"></line>'
        '<line class="lane-rule" x1="220" x2="1196" y1="148" y2="148"></line>'
        '</g><g>'
        '<text class="band-label" x="1200" y="54">HIGH</text>'
        '<text class="band-label" x="1200" y="90">MED</text>'
        '<text class="band-label muted" x="1200" y="122">WARN</text>'
        '<text class="band-label muted" x="1200" y="152">INFO</text>'
        '</g>'
        f'<g class="axis-tick">{tick_lines}{tick_labels}</g>'
        '<g class="today">'
        '<line class="beam-glow" x1="1196" x2="1196" y1="20" y2="172"></line>'
        '<line x1="1196" x2="1196" y1="20" y2="172"></line>'
        '<circle class="now-dot" cx="1196" cy="20" r="3"></circle>'
        '<circle class="pulse-ring" cx="1196" cy="20"></circle>'
        '</g><g>'
        '<line class="hover-line" id="tl-hover-line" x1="0" x2="0" y1="20" y2="172"></line>'
        '<text class="hover-readout" id="tl-hover-text" x="0" y="14" text-anchor="middle"></text>'
        '</g>'
        '<defs>'
        '<pattern id="foldhatch" patternUnits="userSpaceOnUse" width="6" height="6" patternTransform="rotate(45)">'
        '<line x1="0" y1="0" x2="0" y2="6" stroke="var(--ink-5)" stroke-width="1.5" opacity="0.6"></line>'
        '</pattern></defs>'
        '<rect x="200" y="20" width="14" height="152" fill="url(#foldhatch)"></rect>'
        '<line x1="200" y1="20" x2="200" y2="172" stroke="var(--ink-4)" stroke-width="1"></line>'
        '<line x1="214" y1="20" x2="214" y2="172" stroke="var(--ink-4)" stroke-width="1"></line>'
        f'<text x="120" y="14" text-anchor="middle" style="fill: var(--ink-3); '
        'font-family: ui-monospace, monospace; font-size: 10px; letter-spacing: 0.16em; '
        f'text-transform: uppercase; font-weight: 700;">{_esc(archive_label)}</text>'
        '<g style="opacity: 0.6;">'
        '<line class="lane-rule" x1="44" x2="196" y1="50" y2="50"></line>'
        '<line class="lane-rule" x1="44" x2="196" y1="86" y2="86"></line>'
        '<line class="lane-rule" x1="44" x2="196" y1="118" y2="118"></line>'
        '<line class="lane-rule" x1="44" x2="196" y1="148" y2="148"></line>'
        '</g>'
        '<text x="44" y="184" text-anchor="start" class="abs">&gt; 180d</text>'
        '<text x="122" y="184" text-anchor="middle" class="abs">log compressed →</text>'
        f'{"".join(dot_svg)}'
        f'{"".join(archive_svg)}'
        '</svg>'
        '<div class="tl-tooltip" id="tl-tooltip"></div>'
        '</div>'
    )


def _render_lifecycle(
    *,
    recent_findings: list[Finding],
    processes: list[ScoredItem],
    finding_ids: dict[int, str],
) -> str:
    """Per-keyword lifecycle ribbon. One horizontal track per Pattern, with
    every recoverable timestamp plotted on a linear time axis. InstallDate
    / FirstInstall (pulled from the Windows uninstall registry) renders as
    an open diamond; every other timestamp is a filled circle coloured by
    severity. Hovering a marker reveals the source field + ISO date.

    Complements the log-scale severity-banded timeline above by collapsing
    "which tool, over what span" instead of "what severity, when". Skipped
    when no recent HIGH/MEDIUM finding (or scored proc) carries a Pattern,
    since per-keyword aggregation adds no signal on bare severity data.
    """
    install_keys = {"InstallDate", "FirstInstall"}

    # 1. Collect events per pattern (lowercased for grouping; original case
    # preserved for the track label).
    tracks: dict[str, dict[str, Any]] = {}

    def _add(pat_lc: str, display: str, dt: datetime, kind: str,
             sev: str, target: str, is_install: bool) -> None:
        t = tracks.setdefault(pat_lc, {
            "display": display, "events": [], "sev_rank": 99, "sev": sev,
        })
        rank = {"HIGH": 0, "MEDIUM": 1, "WARN": 2, "INFO": 3}.get(sev, 9)
        if rank < t["sev_rank"]:
            t["sev_rank"] = rank
            t["sev"] = sev
        t["events"].append({
            "dt": dt, "kind": kind, "sev": sev,
            "target": target, "is_install": is_install,
        })

    # Track-key fallback chain. Pattern is the primary key, but several
    # finding shapes don't carry it: AppData findings expose a Label
    # ("Cronus Zen Studio", "XIM (other)"), Installed-software findings
    # expose DisplayName, USB findings expose DeviceName. Walking this
    # chain recovers the per-tool tracks the old v3.x renderer plotted.
    track_key_fallbacks = ("Label", "DisplayName", "DeviceName")

    for f in recent_findings:
        if f.severity not in ("HIGH", "MEDIUM"):
            continue
        pat = str(f.metadata.get("Pattern") or "").strip()
        if not pat:
            for k in track_key_fallbacks:
                v = str(f.metadata.get(k) or "").strip()
                if v:
                    pat = v
                    break
        if not pat:
            continue
        pat_lc = pat.lower()
        target = finding_ids.get(id(f), "")
        for key, ts in _finding_timestamps(f):
            if key == "MostRecentTimestamp":
                continue
            _add(pat_lc, pat, ts, key, f.severity, target,
                 is_install=(key in install_keys))

    for p in processes:
        if p.score not in ("HIGH", "MEDIUM"):
            continue
        pat = (p.pattern or "").strip()
        if not pat:
            continue
        started = p.extra.get("Started", "")
        dt = _try_parse_dt(str(started))
        if dt:
            _add(pat.lower(), pat, dt, "process start", p.score, "", False)

    if not tracks:
        return ""

    # 2. Sort tracks: most severe first, then by earliest activity.
    def _sort_key(item: tuple[str, dict[str, Any]]) -> tuple[int, datetime]:
        _key, t = item
        earliest = min(e["dt"] for e in t["events"])
        return (t["sev_rank"], earliest)
    sorted_tracks = sorted(tracks.items(), key=_sort_key)

    MAX_TRACKS = 8
    if len(sorted_tracks) > MAX_TRACKS:
        keep = sorted_tracks[: MAX_TRACKS - 1]
        merged_events: list[dict[str, Any]] = []
        merged_rank = 99
        merged_sev = "MEDIUM"
        for _k, t in sorted_tracks[MAX_TRACKS - 1:]:
            merged_events.extend(t["events"])
            if t["sev_rank"] < merged_rank:
                merged_rank = t["sev_rank"]
                merged_sev = t["sev"]
        sorted_tracks = keep + [("__other__", {
            "display": "other", "events": merged_events,
            "sev_rank": merged_rank, "sev": merged_sev,
        })]

    # 3. X-axis range: earliest event → today, padded a little on both sides.
    now = datetime.now()
    all_dates = [e["dt"] for _k, t in sorted_tracks for e in t["events"]]
    earliest = min(all_dates)
    span_days = max(1, (now - earliest).days)
    pad_days = max(7, span_days * 0.04)
    x_min = earliest - timedelta(days=pad_days)
    x_max = now + timedelta(days=pad_days * 0.5)
    range_secs = (x_max - x_min).total_seconds()
    if range_secs <= 0:
        return ""  # degenerate

    # 4. SVG geometry.
    width = 1200
    left_pad = 180
    right_pad = 28
    top_pad = 44
    row_h = 36
    bottom_pad = 38
    plot_w = width - left_pad - right_pad
    plot_h = len(sorted_tracks) * row_h
    total_h = top_pad + plot_h + bottom_pad

    def _x_for(dt: datetime) -> float:
        return left_pad + ((dt - x_min).total_seconds() / range_secs) * plot_w

    # 5. Month gridlines + labels.
    grid_svg: list[str] = []
    cur = datetime(x_min.year, x_min.month, 1)
    if cur < x_min:
        cur = (datetime(cur.year + 1, 1, 1) if cur.month == 12
               else datetime(cur.year, cur.month + 1, 1))
    while cur <= x_max:
        x = _x_for(cur)
        grid_svg.append(
            f'<line class="lc-axis-tick" x1="{x:.1f}" x2="{x:.1f}" '
            f'y1="{top_pad}" y2="{top_pad + plot_h}"></line>'
        )
        lbl = cur.strftime("%b '%y").upper()
        grid_svg.append(
            f'<text class="lc-axis-label" x="{x:.1f}" y="{top_pad - 14}" '
            f'text-anchor="middle">{_esc(lbl)}</text>'
        )
        cur = (datetime(cur.year + 1, 1, 1) if cur.month == 12
               else datetime(cur.year, cur.month + 1, 1))

    # 6. Today beam on the right.
    now_x = _x_for(now)
    today_svg = (
        '<g class="lc-today">'
        f'<line x1="{now_x:.1f}" x2="{now_x:.1f}" y1="{top_pad}" y2="{top_pad + plot_h}"></line>'
        f'<text x="{now_x:.1f}" y="{top_pad - 4}" text-anchor="end">today</text>'
        '</g>'
    )

    # 7. Per-track rendering.
    track_svg: list[str] = []
    sev_class = {"HIGH": "hi", "MEDIUM": "md"}
    for i, (_k, t) in enumerate(sorted_tracks):
        row_y = top_pad + i * row_h
        cy = row_y + row_h / 2
        track_svg.append(
            f'<line class="lc-lane-rule" x1="{left_pad}" x2="{left_pad + plot_w}" '
            f'y1="{cy:.1f}" y2="{cy:.1f}"></line>'
        )
        label = t["display"]
        if len(label) > 14:
            label = label[:13] + "…"
        track_svg.append(
            f'<text class="lc-track-label" x="{left_pad - 12}" y="{cy + 4:.1f}" '
            f'text-anchor="end">{_esc(label.upper())}</text>'
        )
        for e in t["events"]:
            x = _x_for(e["dt"])
            cls = sev_class.get(e["sev"], "md")
            iso = _iso_date(e["dt"])
            title = _esc(f"{t['display']} · {e['kind']} · {iso}")
            target_attr = (f' data-target="{_esc(e["target"])}"'
                           if e["target"] else '')
            if e["is_install"]:
                r = 6
                pts = (f"{x:.1f},{cy - r:.1f} {x + r:.1f},{cy:.1f} "
                       f"{x:.1f},{cy + r:.1f} {x - r:.1f},{cy:.1f}")
                track_svg.append(
                    f'<polygon class="lc-install {cls}" points="{pts}"{target_attr}>'
                    f'<title>{title}</title></polygon>'
                )
            else:
                track_svg.append(
                    f'<circle class="lc-event {cls}" cx="{x:.1f}" cy="{cy:.1f}" '
                    f'r="4"{target_attr}><title>{title}</title></circle>'
                )

    n_tracks = len(sorted_tracks)
    n_events = sum(len(t["events"]) for _k, t in sorted_tracks)
    cap = (
        '<p class="lc-cap">'
        f'{n_events} dated event{"s" if n_events != 1 else ""} across '
        f'{n_tracks} pattern{"s" if n_tracks != 1 else ""}. '
        'Diamonds are install dates from the Windows uninstall registry; '
        'circles are execution, write, USB-arrival, or run events. '
        'Hover any marker for the source field and date.'
        '</p>'
    )

    return (
        '<section class="lifecycle">'
        '<div class="sec-head">'
        '<h2><span class="num">01·a</span>Activity by pattern</h2>'
        '<span class="sec-aside">linear timeline · install diamond · activity circle</span>'
        '</div>'
        f'<svg class="lc-svg" viewBox="0 0 {width} {total_h:.0f}" '
        'preserveAspectRatio="none" aria-label="per-keyword lifecycle timeline">'
        f'{"".join(grid_svg)}'
        f'{"".join(track_svg)}'
        f'{today_svg}'
        '</svg>'
        f'{cap}'
        '</section>'
    )


def _render_catmap(recent_findings: list[Finding]) -> str:
    """Tile grid of categories that fired, with dominant-severity colouring.
    Skip entirely if no findings present.
    """
    if not recent_findings:
        return ""
    # Group by category, skipping internal summary categories and the
    # generic "(scan)" / "(summary)" rows that scanners emit for stats.
    cats: dict[str, dict[str, int]] = {}
    for f in recent_findings:
        if f.category in ("RecencyDecay",):
            continue
        if (f.source or "").strip() in ("(scan)", "(summary)"):
            continue
        sev_counts = cats.setdefault(f.category, {s: 0 for s in SEVERITY_ORDER})
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    if not cats:
        return ""

    # Sort: HIGH-first, then MEDIUM-first, then alphabetical by category.
    def sort_key(item: tuple[str, dict[str, int]]) -> tuple[int, int, str]:
        cat, counts = item
        top = 3
        if counts.get("HIGH"):
            top = 0
        elif counts.get("MEDIUM"):
            top = 1
        elif counts.get("WARN"):
            top = 2
        return (top, -sum(counts.values()), cat.lower())

    tiles: list[str] = []
    for cat, counts in sorted(cats.items(), key=sort_key):
        top_sev = ""
        for s in SEVERITY_ORDER:
            if counts.get(s):
                top_sev = s
                break
        top_class = {"HIGH": "b-hi", "MEDIUM": "b-md", "WARN": "b-wn", "INFO": "b-info"}.get(top_sev, "b-info")
        top_n = counts.get(top_sev, 0)
        # Meta line: "HIGH" or "HIGH<br>+ N INFO"
        other_bits = []
        for s in SEVERITY_ORDER:
            if s == top_sev:
                continue
            if counts.get(s):
                other_bits.append(f"+ {counts[s]} {s}")
        meta_html = _esc(top_sev) + ("<br>" + _esc(", ".join(other_bits)) if other_bits else "")
        # Bars: top severity primary, smaller for others
        bar_html = f'<span class="{top_class}" style="flex:{max(1, top_n)}"></span>'
        for s in SEVERITY_ORDER:
            if s == top_sev or not counts.get(s):
                continue
            cls = {"HIGH": "b-hi", "MEDIUM": "b-md", "WARN": "b-wn", "INFO": "b-info"}[s]
            bar_html += f'<span class="{cls}" style="flex:{counts[s]}"></span>'

        data_top = f' data-top-sev="{top_sev}"' if top_sev in ("HIGH", "MEDIUM") else ""
        tiles.append(
            f'<button class="cat-tile" data-cat="{_esc(cat)}"{data_top}>'
            f'<div class="tile-name">{_esc(cat)}</div>'
            f'<div class="tile-counts"><span class="nbig">{top_n}</span>'
            f'<span class="meta">{meta_html}</span></div>'
            f'<div class="tile-bars">{bar_html}</div>'
            '</button>'
        )

    return (
        '<div class="catmap" style="margin-top: 16px;">'
        '<div class="catmap-head">'
        '<span class="l">Category signal · which scanners fired</span>'
        '<span class="r">click to filter findings ↓</span>'
        '</div>'
        f'<div class="catmap-grid">{"".join(tiles)}</div>'
        '</div>'
    )


def _render_donut(
    *,
    recent_findings: list[Finding],
    processes: list[ScoredItem],
    services: list[ScoredItem],
) -> str:
    """Score-tier donut. Skip when total indicators < 10 (clean / near-clean
    case — a solid LOW/CLEAN ring carries no useful information).
    """
    counts = {"HIGH": 0, "MEDIUM": 0, "WARN": 0, "INFO": 0, "LOW": 0}
    # findings (recent only) — WARN/INFO have no LOW/CLEAN counterpart
    for f in recent_findings:
        if f.severity in counts:
            counts[f.severity] += 1
    # processes + services by score
    f_proc_hi = sum(1 for p in processes if p.score == "HIGH")
    f_proc_md = sum(1 for p in processes if p.score == "MEDIUM")
    f_proc_low = sum(1 for p in processes if p.score in ("LOW", "CLEAN"))
    f_svc_hi = sum(1 for s in services if s.score == "HIGH")
    f_svc_md = sum(1 for s in services if s.score == "MEDIUM")
    f_svc_low = sum(1 for s in services if s.score in ("LOW", "CLEAN"))
    counts["HIGH"] += f_proc_hi + f_svc_hi
    counts["MEDIUM"] += f_proc_md + f_svc_md
    counts["LOW"] += f_proc_low + f_svc_low

    total = sum(counts.values())
    if total < 10:
        return ""

    # Compute slice percentages with a 0.5% gap between slices.
    gap = 0.5
    slices_order = ["HIGH", "MEDIUM", "WARN", "INFO", "LOW"]
    raw = {k: (counts[k] / total) * 100.0 for k in slices_order}
    # Subtract a half-gap from each side of each slice (effectively gap between slices).
    # Render each slice as a circle with pathLength=100 and dasharray "len rest".
    # The transform rotates the slice to its start angle (slices go clockwise from top).

    slice_svg: list[str] = []
    label_svg: list[str] = []
    angle_cursor = 0.0
    for tier in slices_order:
        pct = raw[tier]
        if pct <= 0:
            continue
        len_ = max(0.01, pct - gap)
        rest = max(0.01, 100.0 - len_)
        # rotate(-90 + angle_cursor*3.6) ; start at angle measured from top (12 o'clock)
        rotation = -90 + (angle_cursor * 3.6)
        cls = {"HIGH": "hi", "MEDIUM": "md", "WARN": "wn", "INFO": "info", "LOW": "empty"}[tier]
        style = ' style="stroke: var(--ink-5);"' if tier == "LOW" else ""
        slice_svg.append(
            f'<circle class="slice {cls}" cx="120" cy="120" r="88" '
            f'pathLength="100" stroke-dasharray="{len_:.2f} {rest:.2f}" '
            f'transform="rotate({rotation:.1f} 120 120)" '
            f'data-tier="{tier}"{style}></circle>'
        )
        angle_cursor += pct

    # Legend rows
    legend_descriptions = {
        "HIGH": (f'{counts["HIGH"] - f_proc_hi - f_svc_hi} findings · '
                 f'{f_proc_hi} process · {f_svc_hi} service'),
        "MEDIUM": (f'{counts["MEDIUM"] - f_proc_md - f_svc_md} findings · '
                   f'{f_proc_md} process · {f_svc_md} service'),
        "WARN": f'{counts["WARN"]} findings · access denied',
        "INFO": f'{counts["INFO"]} scan-summary findings · informational only',
        "LOW": f'{f_proc_low} LOW/CLEAN processes · {f_svc_low} LOW/CLEAN services',
    }
    legend_rows = "".join(
        f'<div class="row" data-tier="{tier}">'
        f'<span class="swatch {tcls}"></span>'
        f'<span class="lbl">{tlabel}<span class="breakdown">{_esc(legend_descriptions[tier])}</span></span>'
        f'<span class="n">{counts[tier]}</span>'
        '</div>'
        for tier, tcls, tlabel in (
            ("HIGH", "hi", "HIGH"),
            ("MEDIUM", "md", "MEDIUM"),
            ("WARN", "wn", "WARN"),
            ("INFO", "info", "INFO"),
            ("LOW", "empty", "LOW / CLEAN"),
        )
        if counts[tier] > 0
    )

    pct_hi = (counts["HIGH"] / total) * 100.0
    caption = (
        '<p class="indi-cap">'
        f'Each slice is one score tier across all artifact classes. '
        f'<b>{counts["HIGH"]} HIGH indicators ({pct_hi:.1f}%)</b> drive the verdict. '
        'A clean machine would show a single solid LOW/CLEAN ring — the more '
        'red and amber present, the worse the picture.</p>'
    )

    return (
        '<section class="indi">'
        '<div class="sec-head" style="border-bottom-color: var(--rule); margin-bottom: 14px;">'
        '<h2><span class="num">00</span>All indicators · score distribution</h2>'
        f'<span class="sec-aside">findings + processes + services · {total} indicators</span>'
        '</div>'
        '<div class="indi-body">'
        '<svg class="indi-donut" viewBox="0 0 240 240" aria-label="indicator distribution by score tier">'
        '<circle class="ring-bg" cx="120" cy="120" r="88"></circle>'
        f'{"".join(slice_svg)}'
        '<text class="total-label" x="120" y="106" text-anchor="middle">total</text>'
        f'<text class="total-n" x="120" y="142" text-anchor="middle">{total}</text>'
        '<text class="total-sub" x="120" y="156" text-anchor="middle">indicators</text>'
        '</svg>'
        f'<div class="indi-legend" id="indi-legend">{legend_rows}</div>'
        '</div>'
        f'{caption}'
        '</section>'
    )


def _render_filters(sev_counts: dict[str, int]) -> str:
    chips: list[str] = []
    for sev in SEVERITY_ORDER:
        pressed = "true" if sev != "INFO" else "false"  # INFO off by default
        chips.append(
            f'<button class="chip" data-filter="sev" data-val="{sev}" '
            f'aria-pressed="{pressed}">{sev}'
            f'<span class="count">{sev_counts.get(sev, 0)}</span></button>'
        )
    kind_chips = "".join(
        f'<button class="chip" data-filter="kind" data-val="{k}" '
        f'aria-pressed="true">{_esc(k)}</button>'
        for k in ("cheat", "input", "dual-use", "other")
    )
    return (
        '<div class="filters" role="toolbar" aria-label="filter findings">'
        '<span class="flabel">severity</span>'
        f'{"".join(chips)}'
        '<span class="filters-divider"></span>'
        '<span class="flabel">kind</span>'
        f'{kind_chips}'
        '<button class="clear" id="clear-filters">reset</button>'
        '<div class="cat-filter" id="cat-filter" hidden>'
        '<span class="pill"><span id="cat-filter-name">—</span>'
        '<button id="cat-filter-clear">×</button></span>'
        '</div>'
        '</div>'
    )


def _render_finding_card(f: Finding, *, fid: str) -> str:
    """Render one <li class="finding"> card."""
    # Head: severity + kind + category + best-available timestamp
    primary_ts: tuple[str, datetime] | None = None
    ts_list = _finding_timestamps(f)
    for key, ts in ts_list:
        if key in ("LastWrite", "LastModified", "LastRemoval", "NewestWrite",
                   "LastRun", "LastExecution", "LastArrival", "Timestamp", "Created"):
            primary_ts = (key, ts)
            break
    if primary_ts is None and ts_list:
        primary_ts = ts_list[0]

    when_html = ""
    if primary_ts:
        key, ts = primary_ts
        label_word = {
            "LastWrite": "last write", "LastModified": "last modified",
            "LastRemoval": "last removal", "NewestWrite": "newest write",
            "LastRun": "last run", "LastExecution": "last run",
            "LastArrival": "last arrival", "Created": "created",
            "FirstSeen": "first seen", "FirstInstall": "first install",
            "InstallDate": "installed", "Timestamp": "",
        }.get(key, "")
        age_days = (datetime.now() - ts).days
        ago = _human_age(age_days)
        prefix = f"{label_word} " if label_word else ""
        when_html = (
            f'<time class="finding-when" datetime="{_iso_date(ts)}">'
            f'{_esc(prefix)}{_iso_date(ts)} '
            f'<span class="ago">· {_esc(ago)}</span></time>'
        )

    head = (
        '<div class="finding-head">'
        f'<span class="sev-tag" data-sev="{_esc(f.severity)}">{_esc(f.severity)}</span>'
        f'<span class="kind-tag">{_esc(f.kind or "other")}</span>'
        f'<span class="cat-tag" data-cat="{_esc(f.category)}">{_esc(f.category)}</span>'
        f'{when_html}</div>'
    )

    # Title — pattern chip + detail text
    pattern = ""
    if f.metadata:
        pattern = str(f.metadata.get("Pattern") or "")
    pat_html = ""
    if pattern:
        pat_html = f'<span class="pat">{_esc(pattern)}</span>'
    title = f'<div class="finding-title">{pat_html}{_esc(f.detail)}</div>'

    # Source
    src_path = f.source or ""
    copy_btn = ""
    if src_path and ("\\" in src_path or "/" in src_path or src_path.startswith("HK")):
        copy_btn = f'<button class="copy-btn" data-copy="{_esc(src_path)}">copy</button>'
    src_block = (
        '<div class="finding-source">'
        '<span class="src-label">source</span>'
        f'<code class="src-path">{_esc(src_path)}</code>'
        f'{copy_btn}</div>'
    )

    # Metadata — collapse beyond 4 visible
    meta_items = []
    if f.metadata:
        # Filter out internal recency-tracking keys (carried separately).
        hidden_keys = {"RecencyClass", "OriginalSeverity", "AgeDays",
                       "MostRecentTimestamp"}
        for k, v in f.metadata.items():
            if k in hidden_keys:
                continue
            if v in (None, ""):
                continue
            meta_items.append((k, v))

    meta_html_parts: list[str] = []
    extra_count = 0
    for i, (k, v) in enumerate(meta_items):
        cls_attr = ""
        dd_cls = ""
        if k in HASH_KEYS:
            dd_cls = ' class="hash"'
        elif k == "IsSigned":
            sv = str(v).lower()
            if sv in ("true", "1", "yes"):
                dd_cls = ' class="true"'
            elif sv in ("false", "0", "no"):
                dd_cls = ' class="false"'
        if i >= 4:
            cls_attr = "kv hidden"
            extra_count += 1
        else:
            cls_attr = "kv"
        # Special render for URL keys
        if k in URL_KEYS and isinstance(v, str) and v.startswith("http"):
            dd_inner = (f'<a href="{_esc(v)}" rel="noopener noreferrer">'
                        f'{_esc(v[:60])}{"…" if len(v) > 60 else ""}</a>')
            dd_cls = ' class="url"'
        elif k in BYTES_KEYS:
            dd_inner = _format_bytes(v)
        else:
            dd_inner = _esc(v)
        meta_html_parts.append(
            f'<div class="{cls_attr}"><dt>{_esc(k)}</dt><dd{dd_cls}>{dd_inner}</dd></div>'
        )

    meta_block = ""
    if meta_html_parts:
        collapsed = ' data-collapsed="4"' if extra_count > 0 else ""
        single = ' single' if not extra_count and len(meta_items) <= 2 else ""
        expand_btn = (f'<button class="meta-expand">'
                      f'<span class="car"></span>expand · {extra_count} more</button>'
                      if extra_count > 0 else "")
        meta_block = (
            f'<dl class="finding-meta{single}"{collapsed}>'
            f'{"".join(meta_html_parts)}'
            '</dl>'
            f'{expand_btn}'
        )

    return (
        f'<li id="{_esc(fid)}" class="finding" '
        f'data-severity="{_esc(f.severity)}" data-kind="{_esc(f.kind or "other")}" '
        f'data-category="{_esc(f.category)}" '
        f'data-pattern="{_esc(pattern)}" '
        f'data-keys="{_esc(_data_keys_for_finding(f))}">'
        f'{head}{title}{src_block}{meta_block}'
        '</li>'
    )


def _render_findings_section(
    *,
    recent_findings: list[Finding],
    finding_ids: dict[int, str],
) -> str:
    # Group recent findings by severity, in SEVERITY_ORDER
    grouped: dict[str, list[Finding]] = {s: [] for s in SEVERITY_ORDER}
    for f in recent_findings:
        if f.severity in grouped:
            grouped[f.severity].append(f)
    sev_counts = {s: len(grouped[s]) for s in SEVERITY_ORDER}

    filter_bar = _render_filters(sev_counts)

    group_blocks: list[str] = []
    for sev in SEVERITY_ORDER:
        if not grouped[sev]:
            continue
        # Sort within group: HIGH/MEDIUM by category alphabetical; WARN/INFO ditto.
        items = sorted(grouped[sev], key=lambda f: (f.category.lower(), f.detail.lower()))
        suffix = " · hidden by default" if sev == "INFO" else ""
        hdr_extra = " · access denied" if sev == "WARN" else ""
        head = (
            f'<div class="sev-group" data-sev="{sev}">'
            f'<h3><span class="dot"></span>{sev}{_esc(hdr_extra)}</h3>'
            f'<span class="count">{len(items)} findings{_esc(suffix)}</span>'
            '<span class="group-rule"></span></div>'
        )
        # Apply display:none style on INFO cards (matches reference)
        cards = []
        for f in items:
            card_html = _render_finding_card(f, fid=finding_ids[id(f)])
            if sev == "INFO":
                card_html = card_html.replace(
                    '<li id=', '<li style="display:none" id=', 1
                )
            cards.append(card_html)
        group_blocks.append(head + '<ul class="findings">' + "".join(cards) + "</ul>")

    empty_callout = ""
    if not any(grouped.values()):
        empty_callout = (
            '<div class="empty-callout">'
            '<span class="dot ok"></span>'
            '<p>No findings to display. The scanners ran but matched nothing against the keyword database within the last 180 days. '
            'See the runtime tables below and the historical section (if present) for the full picture.</p>'
            '</div>'
        )

    return (
        '<section id="findings">'
        '<div class="sec-head">'
        '<h2><span class="num">01</span>Findings · cheat trace scan</h2>'
        '<span class="sec-aside">recent (≤180d) · verdict-relevant</span>'
        '</div>'
        f'{filter_bar}'
        f'{empty_callout}'
        f'{"".join(group_blocks)}'
        '</section>'
    )


def _render_runtime(
    *,
    processes: list[ScoredItem],
    services: list[ScoredItem],
    process_ids: dict[int, str],
    service_ids: dict[int, str],
) -> str:
    def proc_rows(items: list[ScoredItem], ids: dict[int, str], kind: str) -> str:
        rows: list[str] = []
        # Order: HIGH, MEDIUM, then LOW/CLEAN (CLEAN hidden until toggle)
        sortkey = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "CLEAN": 3}
        items_sorted = sorted(items, key=lambda x: (sortkey.get(x.score, 9), x.name.lower()))
        for item in items_sorted:
            iid = ids.get(id(item), "")
            score = item.score
            if kind == "proc":
                pid = _esc(item.extra.get("ProcessId", ""))
                name = _esc(item.name)
                exe = _esc(item.extra.get("ExecutablePath", ""))
                cmd = _esc(item.extra.get("CommandLine", ""))
                reason_bits = [item.reason or ""]
                if cmd:
                    reason_bits.append(f"cmd <code>{cmd}</code>")
                reason_html = (f'<div class="reason">{_esc(item.reason or "")}'
                               + (f' · cmd <code>{cmd}</code>' if cmd else '') + '</div>')
                row_classes = "has-link" if score in ("HIGH", "MEDIUM") else "clean-row"
                if score == "CLEAN":
                    row_classes += " hidden"
                row = (
                    f'<tr id="{_esc(iid)}" class="{row_classes}" '
                    f'data-pattern="{_esc(item.pattern)}" data-keys="{_esc(_data_keys_for_proc(item))}">'
                    f'<td><span class="score" data-s="{_esc(score)}"><i></i>{_esc(score)}</span></td>'
                    f'<td>{pid}</td>'
                    f'<td><span class="name">{name}</span><br>'
                    f'<span style="color:var(--ink-4)">{exe}</span>'
                    f'{reason_html if score in ("HIGH", "MEDIUM") else ""}'
                    '</td></tr>'
                )
            else:  # svc
                display = _esc(item.extra.get("DisplayName", ""))
                state = _esc(item.extra.get("State", ""))
                start_mode = _esc(item.extra.get("StartMode", ""))
                path = _esc(item.extra.get("PathName", ""))
                name = _esc(item.name)
                state_cell = state
                if start_mode and score in ("HIGH", "MEDIUM"):
                    state_cell += f'<br><span style="color:var(--ink-5); font-size:10.5px">{start_mode}</span>'
                reason_html = ""
                if score in ("HIGH", "MEDIUM"):
                    reason_html = f'<div class="reason">{_esc(item.reason or "")}</div>'
                row_classes = "has-link" if score in ("HIGH", "MEDIUM") else "clean-row"
                if score == "CLEAN":
                    row_classes += " hidden"
                row = (
                    f'<tr id="{_esc(iid)}" class="{row_classes}" '
                    f'data-pattern="{_esc(item.pattern)}" data-keys="{_esc(_data_keys_for_svc(item))}">'
                    f'<td><span class="score" data-s="{_esc(score)}"><i></i>{_esc(score)}</span></td>'
                    f'<td>{state_cell}</td>'
                    f'<td><span class="name">{name}</span> · '
                    f'<span style="color:var(--ink-4)">{display}</span><br>'
                    f'<span style="color:var(--ink-4)">{path}</span>'
                    f'{reason_html}'
                    '</td></tr>'
                )
            rows.append(row)
        return "".join(rows)

    def breakdown(items: list[ScoredItem]) -> str:
        n_hi = sum(1 for x in items if x.score == "HIGH")
        n_md = sum(1 for x in items if x.score == "MEDIUM")
        n_low = sum(1 for x in items if x.score in ("LOW", "CLEAN"))
        return (
            f'<div class="breakdown">'
            f'<span class="hi"><b>{n_hi}</b>HIGH</span>'
            f'<span class="md"><b>{n_md}</b>MED</span>'
            f'<span><b>{n_low}</b>LOW/CLEAN</span></div>'
        )

    def foot(items: list[ScoredItem], target_id: str) -> str:
        n_hidden = sum(1 for x in items if x.score == "CLEAN")
        n_shown = len(items) - n_hidden
        return (
            '<div class="runtime-foot">'
            f'<span><b>{n_shown}</b> of {len(items)} shown · {n_hidden} CLEAN hidden</span>'
            f'<button class="toggle-clean" data-target="{_esc(target_id)}">show CLEAN</button>'
            '</div>'
        )

    return (
        '<section>'
        '<div class="sec-head">'
        '<h2><span class="num">02·03</span>Runtime · processes &amp; services</h2>'
        '<span class="sec-aside">hover a row to highlight linked findings ↑</span>'
        '</div>'
        '<div class="runtime-grid">'
        # ---- Processes ----
        '<div class="tbl-shell">'
        '<div class="tbl-head"><h3>Processes</h3>'
        f'{breakdown(processes)}</div>'
        '<table class="runtime" id="proc-tbl"><thead><tr>'
        '<th style="width:90px">score</th><th style="width:60px">pid</th>'
        '<th>name · path</th></tr></thead><tbody>'
        f'{proc_rows(processes, process_ids, "proc")}'
        '</tbody></table>'
        f'{foot(processes, "proc-tbl")}'
        '</div>'
        # ---- Services ----
        '<div class="tbl-shell">'
        '<div class="tbl-head"><h3>Services</h3>'
        f'{breakdown(services)}</div>'
        '<table class="runtime" id="svc-tbl"><thead><tr>'
        '<th style="width:90px">score</th><th style="width:80px">state</th>'
        '<th>name · path</th></tr></thead><tbody>'
        f'{proc_rows(services, service_ids, "svc")}'
        '</tbody></table>'
        f'{foot(services, "svc-tbl")}'
        '</div>'
        '</div></section>'
    )


def _render_historical(archived: list[Finding], threshold_days: int) -> str:
    if not archived:
        return ""

    archived_high = [f for f in archived if f.metadata.get("OriginalSeverity") == "HIGH"]
    intro_extra = ""
    if archived_high:
        intro_extra = (f' <b style="color: var(--ink-2)">'
                       f'{len(archived_high)} originally HIGH-severity</b>.')

    cards: list[str] = []
    for f in sorted(archived, key=lambda x: -int(x.metadata.get("AgeDays") or 0)):
        ts_list = _finding_timestamps(f)
        primary_ts = ts_list[0] if ts_list else None
        when_html = ""
        if primary_ts:
            _key, ts = primary_ts
            when_html = (f'<time class="finding-when" datetime="{_iso_date(ts)}">'
                         f'most recent {_iso_date(ts)}</time>')
        orig = _esc(f.metadata.get("OriginalSeverity") or "")
        age = f.metadata.get("AgeDays") or "?"
        try:
            age_fmt = f"{int(age):,}"
        except (TypeError, ValueError):
            age_fmt = str(age)
        orig_pill = (f'<span class="hist-orig">orig&nbsp;<b>{orig}</b>'
                     f'&nbsp;·&nbsp;{age_fmt} d old</span>') if orig else ""

        pattern = ""
        if f.metadata:
            pattern = str(f.metadata.get("Pattern") or "")
        pat_html = ""
        if pattern:
            pat_html = (f'<span class="pat" style="background:var(--panel-2); '
                        f'color:var(--ink-3); border-color:var(--rule-2);">'
                        f'{_esc(pattern)}</span>')

        # Meta — show all keys, no collapse on archived cards
        meta_items = []
        if f.metadata:
            hidden_keys = {"RecencyClass"}
            for k, v in f.metadata.items():
                if k in hidden_keys or v in (None, ""):
                    continue
                meta_items.append((k, v))
        meta_html = ""
        if meta_items:
            kv_html = []
            for k, v in meta_items:
                dd_cls = ""
                if k in HASH_KEYS:
                    dd_cls = ' class="hash"'
                if k in BYTES_KEYS:
                    inner = _format_bytes(v)
                else:
                    inner = _esc(v)
                kv_html.append(f'<div class="kv"><dt>{_esc(k)}</dt><dd{dd_cls}>{inner}</dd></div>')
            meta_html = f'<dl class="finding-meta">{"".join(kv_html)}</dl>'

        card = (
            '<li class="finding" '
            f'data-severity="{_esc(f.severity)}" data-kind="{_esc(f.kind or "other")}" '
            f'data-category="{_esc(f.category)}">'
            '<div class="finding-head">'
            f'<span class="sev-tag" data-sev="{_esc(f.severity)}">{_esc(f.severity)}</span>'
            f'<span class="kind-tag">{_esc(f.kind or "other")}</span>'
            f'<span class="cat-tag">{_esc(f.category)}</span>'
            f'{orig_pill}{when_html}</div>'
            f'<div class="finding-title">{pat_html}{_esc(f.detail)}</div>'
            '<div class="finding-source"><span class="src-label">source</span>'
            f'<code class="src-path">{_esc(f.source)}</code></div>'
            f'{meta_html}'
            '</li>'
        )
        cards.append(card)

    return (
        '<section class="hist">'
        '<div class="hist-divider">'
        f'<span class="label">archived · &gt; {threshold_days} days · did NOT affect verdict</span>'
        '<span class="hatch"></span>'
        '</div>'
        f'<p class="hist-intro">{len(archived)} finding(s) with a most-recent timestamp '
        f'older than {threshold_days} days were demoted by the recency-decay rule.{intro_extra} '
        'They are logged here for transparency — old artifacts from games or tools the user '
        'has long since stopped using do not, on their own, make a currently-clean machine look dirty.</p>'
        f'<ul class="findings">{"".join(cards)}</ul>'
        '</section>'
    )


def _render_coverage(limitations: list[str]) -> str:
    items = "".join(f"<li>{_esc(line)}</li>" for line in limitations)
    return (
        '<section class="coverage">'
        '<h2>Coverage limitations</h2>'
        f'<ul>{items}</ul></section>'
    )


def _render_docfoot(lol_db_used: bool) -> str:
    net = ("1 outbound call to loldrivers.io (opt-in) · file self-contained"
           if lol_db_used else
           "no network calls · file self-contained")
    return (
        '<div class="docfoot">'
        '<span>alibi 4.0 · python · read-only scan · no system state was modified</span>'
        f'<span>{_esc(net)}</span>'
        '</div>'
    )


# ---------------------------------------------------------------------------
# dataclass shim — avoid importing dataclasses inside hot helpers
# ---------------------------------------------------------------------------
def dataclass_lite(cls):  # noqa: D401 - simple decorator
    """Tiny @dataclass replacement for the inner DotRec — keeps the module
    free of a hard `from dataclasses import dataclass` repeat (we already
    import that elsewhere). Stores positional kwargs as attributes.
    """
    orig_init = cls.__init__ if "__init__" in vars(cls) else None
    def __init__(self, **kw):  # noqa: N807
        for k, v in kw.items():
            setattr(self, k, v)
    cls.__init__ = __init__
    return cls


# ---------------------------------------------------------------------------
# Verdict sub-text
# ---------------------------------------------------------------------------
_VERDICT_SUBS: dict[str, str] = {
    "CHEATS DETECTED":
        "High-confidence indicators of cheat software, HWID spoofers, or "
        "DMA-cheat development artifacts were present on this machine within "
        "the last 180 days.",
    "INPUT DEVICES DETECTED":
        "No cheat brands or HWID spoofers were detected. The scan did find "
        "high-confidence input-device adapter software (XIM / Cronus / ReaSnow "
        "/ KMBox / Titan). Some games treat these as bannable; some do not.",
    "MITM CHEAT STACK DETECTED":
        "High-confidence indicators that this PC is part of a console-MITM "
        "cheat stack — vision aimbot, input-adapter configurator, or "
        "traditional PC cheats.",
    "CAPTURE STACK PRESENT":
        "No cheats or adapter software detected. Capture-card and/or HID-"
        "emulation drivers were found — legitimate for streaming and "
        "controller remapping, but also a component of console-MITM stacks.",
    "UNSURE":
        "No HIGH-confidence cheat or input-device matches. MEDIUM findings "
        "require human review — usually dual-use tools or binaries in "
        "user-writable locations not on the allowlist.",
    "CLEAN":
        "No recent HIGH or MEDIUM matches against the cheat / input-device / "
        "dual-use keyword database (within the last 180 days). This is "
        "necessary but not sufficient evidence — see limitations below.",
}


# ---------------------------------------------------------------------------
# Named-items: produce the structured records for the verdict block
# ---------------------------------------------------------------------------
def _build_named_items(
    *,
    engine: Engine,
    processes: list[ScoredItem],
    services: list[ScoredItem],
    finding_ids: dict[int, str],
    process_ids: dict[int, str],
    service_ids: dict[int, str],
    verdict: str,
) -> dict[str, list[dict[str, str]]]:
    """Return {"main": [...], "also": [...]} for the "Why this verdict" block.

    Dedupe rule
    -----------
    Every HIGH-confidence indicator is grouped by Pattern (lowercased). A
    pattern corroborated by N different scanners (e.g. xim matrix found in
    InstalledSoftware + Prefetch + USBHistory) produces ONE row, not N. The
    chip shows the representative source plus a "+(N-1)" suffix when more
    than one scanner agreed.

    Routing rule (verdict-aware)
    ----------------------------
    The "also" bucket exists to keep input-device findings visually
    separate when the verdict is cheat-driven. When the verdict IS about
    input devices or a console-MITM stack, everything goes to "main" — a
    header reading "0 named items" while 8 items render below is exactly
    the misleading shape this routing prevents.

        CHEATS DETECTED                → cheat/dual-use to main, input to also
        INPUT DEVICES DETECTED         → all HIGH to main
        MITM CHEAT STACK DETECTED      → all HIGH to main
        CAPTURE STACK PRESENT          → all HIGH to main
        UNSURE / CLEAN                 → (no HIGH findings anyway)
    """
    sep_input = (verdict == "CHEATS DETECTED")

    # Stage 1: gather every HIGH indicator into a flat list of candidates,
    # one entry per finding/process/service.
    @dataclass_lite
    class Cand:
        pattern_key: str   # lower-cased dedup key
        pattern: str       # original case for display
        category: str      # source scanner / "Process" / "Service"
        kind: str
        target: str        # html-id to jump to
        detail: str        # one-line summary
        sort_key: tuple    # for picking representative within a group

    cands: list[Cand] = []

    for f in engine.findings:
        if f.metadata.get("RecencyClass") == "historical":
            continue
        if f.severity != "HIGH":
            continue
        target = finding_ids.get(id(f), "")
        if not target:
            continue
        pat = str(f.metadata.get("Pattern") or "").strip()
        key = pat.lower() if pat else f"_d:{f.detail.lower()}"  # fall back to detail
        detail_short = f.detail
        if pat:
            prefix = f"[{pat}] "
            if detail_short.startswith(prefix):
                detail_short = detail_short[len(prefix):]
        if len(detail_short) > 80:
            detail_short = detail_short[:77] + "…"
        cands.append(Cand(
            pattern_key=key, pattern=pat, category=f.category,
            kind=(f.kind or "other"), target=target, detail=detail_short,
            # Prefer richer categories (Installed > Prefetch > USB > others)
            # within a group by giving a category-priority then alpha.
            sort_key=(_NAMED_CAT_PRIORITY.get(f.category, 9), f.category.lower()),
        ))

    for p in processes:
        if p.score != "HIGH":
            continue
        target = process_ids.get(id(p), "")
        pat = (p.pattern or "").strip()
        key = pat.lower() if pat else f"_p:{p.name.lower()}"
        cands.append(Cand(
            pattern_key=key, pattern=(pat or p.name), category="Process",
            kind=(p.kind or "other"), target=target,
            detail=f'(PID {p.extra.get("ProcessId","?")}) running',
            sort_key=(5, "process"),
        ))

    for s in services:
        if s.score != "HIGH":
            continue
        target = service_ids.get(id(s), "")
        pat = (s.pattern or "").strip()
        key = pat.lower() if pat else f"_s:{s.name.lower()}"
        cands.append(Cand(
            pattern_key=key, pattern=(pat or s.name), category="Service",
            kind=(s.kind or "other"), target=target,
            detail=f'service ({s.extra.get("State","?")})',
            sort_key=(6, "service"),
        ))

    # Stage 2: group by pattern_key. For each group, pick the representative
    # (lowest sort_key wins) and count corroborating sources.
    groups: dict[str, list[Cand]] = {}
    for c in cands:
        groups.setdefault(c.pattern_key, []).append(c)

    def _build_rec(group: list[Cand]) -> dict[str, str]:
        rep = sorted(group, key=lambda c: c.sort_key)[0]
        sources_n = len(group)
        cat_label = rep.category
        if sources_n > 1:
            cat_label = f"{rep.category} +{sources_n - 1}"
        text_html = (f'<b>{_esc(rep.pattern)}</b> — {_esc(rep.detail)}'
                     if rep.pattern else _esc(rep.detail))
        return {
            "sev": "HIGH", "target": rep.target, "category": cat_label,
            "html": text_html, "kind": rep.kind, "sources_n": str(sources_n),
        }

    # Stage 3: route to main / also based on verdict.
    main: list[dict[str, str]] = []
    also: list[dict[str, str]] = []
    # Preserve insertion order (first-seen wins for ordering inside main/also).
    for key in groups:  # dict preserves insertion order
        rec = _build_rec(groups[key])
        if sep_input and rec["kind"] == "input":
            also.append(rec)
        else:
            main.append(rec)
    return {"main": main, "also": also}


# Category priority used when picking the representative finding for a pattern
# group: registry/install evidence beats execution evidence beats device-enum.
# Lower number = higher priority.
_NAMED_CAT_PRIORITY = {
    "InstalledSoftware": 0,
    "Uninstall": 0,
    "LoLDriver": 0,
    "Driver": 1,
    "Prefetch": 2,
    "BAM": 2,
    "MUICache": 2,
    "UserAssist": 2,
    "ShimCache": 3,
    "Amcache": 3,
    "USBHistory": 4,
    "RecentFiles": 4,
    "ApplicationData": 4,
    "ProcessModule": 4,
    "DLLInjection": 4,
    "LuaScript": 4,
    "ObscuredName": 4,
    "KnownHash": 0,
    "Process": 5,
    "Service": 6,
}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def render_html(
    *,
    engine: Engine,
    processes: list[ScoredItem],
    services: list[ScoredItem],
    verdict: str,
    threshold_days: int,
    report_title: str,
    mode_label: str = "pc-mode",
    lol_db_used: bool = False,
    coverage_limitations: list[str] | None = None,
) -> str:
    """Build the full HTML document for a scan. The CSS and JS are embedded
    verbatim from the .css and .js resource files; only the body markup is
    interpolated here from the Finding / ScoredItem data.
    """
    state = _state_for(verdict)
    sub_text = _VERDICT_SUBS.get(verdict, "")
    if coverage_limitations is None:
        coverage_limitations = [
            "DMA cheats cannot be detected at runtime by design — no PC-side "
            "footprint. This scan flags DMA development artifacts only.",
            "Input devices configured on a separate machine leave no trace on this PC.",
            "Session duration is recorded in SRUM and requires an ESE database "
            "parser. Not extracted here.",
            "Keyword matching only. Sophisticated cleaners can wipe most of these artifacts.",
            "A clean result is necessary but not sufficient.",
        ]

    # Partition findings.
    recent = [f for f in engine.findings
              if f.metadata.get("RecencyClass") != "historical"
              and f.category != "RecencyDecay"]
    archived = [f for f in engine.findings
                if f.metadata.get("RecencyClass") == "historical"]
    # RecencyDecay summary belongs in INFO of recent
    decay_summary = [f for f in engine.findings if f.category == "RecencyDecay"]
    recent.extend(decay_summary)

    # Assign stable ids.
    used_ids: set[str] = set()
    finding_ids: dict[int, str] = {id(f): _finding_id(f, used_ids) for f in recent}
    used_proc_ids: set[str] = set()
    process_ids: dict[int, str] = {id(p): _process_id(p, used_proc_ids) for p in processes}
    used_svc_ids: set[str] = set()
    service_ids: dict[int, str] = {id(s): _service_id(s, used_svc_ids) for s in services}

    named_items = _build_named_items(
        engine=engine, processes=processes, services=services,
        finding_ids=finding_ids, process_ids=process_ids, service_ids=service_ids,
        verdict=verdict,
    )

    scan_host = os.environ.get("COMPUTERNAME", "")
    scan_iso = _now_iso()

    # Assemble.
    parts: list[str] = []
    parts.append("<!doctype html>")
    parts.append('<html lang="en"><head>')
    parts.append('<meta charset="utf-8">')
    parts.append(f"<title>alibi · {_esc(scan_host)} · {_esc(_iso_date(datetime.now()))} · {_esc(verdict)}</title>")
    parts.append(f'<meta name="generator" content="alibi 4.0 (python)">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append("<!--\n  alibi · visual companion (dark)\n"
                 "  Self-contained. No network, no external assets, no analytics.\n"
                 "  All interactivity is plain vanilla JS in the <script> block at\n"
                 "  the bottom of this file. View source freely.\n-->")
    parts.append(f"<style>\n{_CSS}\n</style>")
    parts.append("</head><body>")
    parts.append('<div class="doc">')

    parts.append(_render_docbar(scan_host=scan_host, scan_iso=scan_iso,
                                lol_db_used=lol_db_used))
    parts.append(_render_verdict(
        verdict=verdict, state=state, sub_text=sub_text,
        mode_label=mode_label, scan_iso=_iso_datetime(datetime.now()),
        recent_findings=recent, archived_findings=archived,
        processes=processes, services=services,
        named_items_struct=named_items,
    ))
    parts.append(_render_timeline(
        state=state, recent_findings=recent, archived_findings=archived,
        finding_ids=finding_ids,
    ))
    parts.append(_render_lifecycle(
        recent_findings=recent, processes=processes, finding_ids=finding_ids,
    ))
    parts.append(_render_catmap(recent))
    parts.append(_render_donut(
        recent_findings=recent, processes=processes, services=services,
    ))
    parts.append(_render_findings_section(
        recent_findings=recent, finding_ids=finding_ids,
    ))
    parts.append(_render_runtime(
        processes=processes, services=services,
        process_ids=process_ids, service_ids=service_ids,
    ))
    parts.append(_render_historical(archived, threshold_days))
    parts.append(_render_coverage(coverage_limitations))
    parts.append(_render_docfoot(lol_db_used))

    parts.append("</div>")
    parts.append(f"<script>\n{_JS}\n</script>")
    parts.append("</body></html>")
    return "\n".join(parts)


def write_html(path: str, content: str) -> None:
    """Write the HTML to disk as UTF-8."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
