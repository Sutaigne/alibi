"""Alibi (console-rig mode) — Python parity of console-rig-audit.ps1.

Drives a console-rig-mode scan: PC-mode base + three console-specific
keyword arrays (vision aimbots, HID emulators, capture-card software). The
verdict logic gains the "CAPTURE STACK PRESENT" tier — capture-card +
HID-emulator software alone is recorded as a legitimate-streamer signal,
not as "unsure".
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime

from alibi import CONSOLE_RIG_VERSION
from alibi.keywords import (
    CAPTURE_CARD_SOFTWARE, CHEAT_BRANDS_APEX, CHEAT_BRANDS_COD,
    CHEAT_BRANDS_CS2, CHEAT_BRANDS_LOW_CONFIDENCE, CHEAT_BRANDS_MARVEL_RIVALS,
    CHEAT_BRANDS_R6, CHEAT_BRANDS_RUST, CHEAT_BRANDS_TARKOV,
    CHEAT_FEATURE_NAMES, DMA_DUAL_USE, DMA_INDICATORS, DUAL_USE_TOOLS,
    HID_EMULATORS, INPUT_DEVICES, RECENCY_THRESHOLD_DAYS,
    SCRIPT_CONTENT_HIGH_RISK, SCRIPT_CONTENT_MOUSE_MACRO, SPOOFER_BRANDS,
    VISION_AIMBOTS_CONSOLE, VISION_AIMBOT_AI_PC,
)
from alibi.loldrivers import resolve_loldrivers_db
from alibi.recency import apply_recency_decay
from alibi.reports import ReportContext, ReportSpec, build_text_report, collect_named_items
from alibi.scanners import invoke_all_scans
from alibi.snapshots import get_process_snapshot, get_service_snapshot
from alibi.utils import Engine, is_admin, resolve_desktop, match_keyword
from alibi.visual_companion import render_html, write_html

from alibi.forensic_scan import _resolve_output_path, _write_summary


def _is_capture_or_hid_pattern(pattern: str | None) -> bool:
    if not pattern:
        return False
    return match_keyword(pattern, CAPTURE_CARD_SOFTWARE + HID_EMULATORS) is not None


def _console_quick_read(ctx: ReportContext) -> list[str]:
    lines: list[str] = []
    if ctx.verdict == "MITM CHEAT STACK DETECTED":
        lines.append("  This scan found HIGH-confidence indicators that this PC is part")
        lines.append("  of a console-MITM cheat stack. One or more of these is present:")
        lines.append("    - Vision-aimbot software (watches capture-card feed, auto-aims)")
        lines.append("    - Input-adapter configurator (XIM, Cronus, ReaSnow, KMBox,")
        lines.append("      Titan, reWASD - the PC-side software for the hardware")
        lines.append("      adapters that translate mouse+keyboard into console input)")
        lines.append("    - Traditional PC cheat brands or DMA-cheat artifacts")
        lines.append("")
        lines.append("  On a PC connected to a console rig, none of these has a")
        lines.append("  legitimate purpose. The report below names exactly what was")
        lines.append("  found and where.")
        lines.append("")
        if ctx.named_cheats:
            lines.append("  Named items (aimbot / cheat-confidence):")
            for n in ctx.named_cheats:
                lines.append(f"    - {n}")
            lines.append("")
        if ctx.named_input:
            lines.append("  Named items (input-adapter configurator software):")
            for n in ctx.named_input:
                lines.append(f"    - {n}")
    elif ctx.verdict == "CAPTURE STACK PRESENT":
        lines.append("  No vision-aimbot software, input-adapter configurator, or")
        lines.append("  traditional PC cheats were detected. However, this scan found")
        lines.append("  capture-card software and/or HID-emulation drivers.")
        lines.append("")
        lines.append("  These have legitimate uses (streaming, recording, controller")
        lines.append("  remapping via Steam or DS4Windows). They are disclosed here")
        lines.append("  because they are also components of console-MITM cheat stacks.")
        lines.append("  Their presence alone is not evidence of cheating.")
        lines.append("")
        lines.append("  Reviewer note: if you are auditing for cheat behavior, the")
        lines.append("  absence of any aimbot or adapter software alongside the")
        lines.append("  capture-card stack is the relevant finding.")
        lines.append("")
        lines.append("  Named items:")
        for f in ctx.medium_findings:
            pat = f.metadata.get("Pattern")
            if pat:
                lines.append(f"    - [{f.category}] {pat} - {f.detail}")
        for p in ctx.proc_medium:
            lines.append(f"    - [Process] {p.pattern} - {p.name} (PID {p.extra.get('ProcessId','?')})")
        for s in ctx.svc_medium:
            lines.append(f"    - [Service] {s.pattern} - {s.name} ({s.extra.get('State','?')})")
    elif ctx.verdict == "UNSURE":
        lines.append("  No HIGH-confidence cheat or input-device matches were detected.")
        lines.append(f"  However, {ctx.total_medium} MEDIUM finding(s) require human review.")
        lines.append("  These are typically dual-use tools or binaries running from")
        lines.append("  user-writable locations that the allowlist does not recognize.")
        lines.append("")
        lines.append("  AI HANDOFF: paste the full contents of this .txt file into")
        lines.append("  any AI chat (ChatGPT, Claude, Gemini) and ask it to classify")
        lines.append("  each MEDIUM finding as benign / worth-reviewing / suspicious")
        lines.append("  with cited sources.")
    else:  # CLEAN
        lines.append(f"  No RECENT HIGH or MEDIUM matches against the cheat / input-device /")
        lines.append(f"  dual-use keyword database (within the last {RECENCY_THRESHOLD_DAYS} days).")
        lines.append("")
        lines.append("  Scope of this scan:")
        lines.append(f"    Cheat-trace findings checked : {len(ctx.engine.findings)} total artifacts")
        lines.append(f"    Running processes scored     : {len(ctx.processes)}")
        lines.append(f"    Services scored              : {len(ctx.services)}")
        lines.append("")
        lines.append("  This is necessary but not sufficient evidence. See limitations")
        lines.append("  section at the bottom of this report.")
    return lines


_CONSOLE_LIMITATIONS = [
    "The CONSOLE itself cannot be scanned. This script can only see the Windows PC "
    "connected to the rig. A pure console + TV setup with no PC in the loop cannot "
    "be audited this way - use the visual setup checklist (console-setup-checklist.html) instead.",
    "DMA cheats cannot be detected at runtime by design (no PC-side footprint). "
    "This scan flags DMA development artifacts only.",
    "Input devices configured on a separate machine and used purely as pass-through "
    "leave no trace on this PC.",
    "Keyword matching only. Sophisticated cleaners can wipe most of these artifacts.",
    "A clean result is necessary but not sufficient.",
]


def _compute_verdict_console(
    *, cheat_high: int, input_high: int, capture_or_hid_medium: int,
    other_medium: int,
) -> str:
    if cheat_high > 0 or input_high > 0:
        return "MITM CHEAT STACK DETECTED"
    if capture_or_hid_medium > 0 and other_medium == 0:
        return "CAPTURE STACK PRESENT"
    if (capture_or_hid_medium + other_medium) > 0:
        return "UNSURE"
    return "CLEAN"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="alibi-rig",
        description="Alibi (console-rig mode) — Python parity of console-rig-audit.ps1.",
    )
    parser.add_argument("--output", default=None, help="Explicit output .txt path.")
    parser.add_argument("--skip-loldrivers", action="store_true")
    parser.add_argument("--no-html", action="store_true")
    parser.add_argument("--no-open-browser", action="store_true",
                        help="Do not auto-open the HTML companion in the default browser at end.")
    parser.add_argument("--non-interactive", action="store_true")
    args = parser.parse_args(argv)

    output_path = _resolve_output_path(args.output, stem="AlibiRigReport")

    keywords_high_cheats = (
        CHEAT_BRANDS_COD + SPOOFER_BRANDS + CHEAT_FEATURE_NAMES + DMA_INDICATORS
        + VISION_AIMBOTS_CONSOLE
        + CHEAT_BRANDS_CS2 + CHEAT_BRANDS_APEX + CHEAT_BRANDS_TARKOV + CHEAT_BRANDS_RUST
        + CHEAT_BRANDS_R6 + CHEAT_BRANDS_MARVEL_RIVALS + VISION_AIMBOT_AI_PC
    )
    keywords_high_input = INPUT_DEVICES
    keywords_medium = (
        DMA_DUAL_USE + DUAL_USE_TOOLS + HID_EMULATORS + CAPTURE_CARD_SOFTWARE
        + CHEAT_BRANDS_LOW_CONFIDENCE
    )

    engine = Engine(
        keywords_high_cheats=keywords_high_cheats,
        keywords_high_input=keywords_high_input,
        keywords_medium=keywords_medium,
        keywords_script_high=SCRIPT_CONTENT_HIGH_RISK,
        keywords_mouse_macro=SCRIPT_CONTENT_MOUSE_MACRO,
    )

    print()
    print(f"  Alibi (console-rig mode) {CONSOLE_RIG_VERSION}")
    print("  =======================")
    print()
    print(f"  Host:   {os.environ.get('COMPUTERNAME','')}")
    print(f"  User:   {os.environ.get('USERNAME','')}")
    print(f"  Admin:  {'Yes' if is_admin() else 'No (run as admin for full coverage)'}")
    print()
    print("  Scanning this PC for console-cheat MITM software.")
    print("  This will take 30-90 seconds.")
    print()

    engine.lol_db = resolve_loldrivers_db(
        engine, skip=args.skip_loldrivers, interactive=not args.non_interactive
    )

    print("  [Phase 1/3] Cheat trace scan")
    invoke_all_scans(engine)
    print()
    print("  [Phase 2/3] Process snapshot")
    processes = get_process_snapshot(engine)
    print()
    print("  [Phase 3/3] Service snapshot")
    services = get_service_snapshot(engine)

    apply_recency_decay(engine)

    high_cheats = [f for f in engine.findings
                   if f.severity == "HIGH" and f.kind == "cheat"
                   and f.metadata.get("RecencyClass") != "historical"]
    high_input = [f for f in engine.findings
                  if f.severity == "HIGH" and f.kind == "input"
                  and f.metadata.get("RecencyClass") != "historical"]
    medium_any = [f for f in engine.findings
                  if f.severity == "MEDIUM"
                  and f.metadata.get("RecencyClass") != "historical"]

    historical = [f for f in engine.findings if f.metadata.get("RecencyClass") == "historical"]
    historical_high = [f for f in historical if f.metadata.get("OriginalSeverity") == "HIGH"]

    proc_high_cheat = [p for p in processes if p.score == "HIGH" and p.kind == "cheat"]
    proc_high_input = [p for p in processes if p.score == "HIGH" and p.kind == "input"]
    proc_medium = [p for p in processes if p.score == "MEDIUM"]

    svc_high_cheat = [s for s in services if s.score == "HIGH" and s.kind == "cheat"]
    svc_high_input = [s for s in services if s.score == "HIGH" and s.kind == "input"]
    svc_medium = [s for s in services if s.score == "MEDIUM"]

    total_cheat_high = len(high_cheats) + len(proc_high_cheat) + len(svc_high_cheat)
    total_input_high = len(high_input) + len(proc_high_input) + len(svc_high_input)
    total_medium = len(medium_any) + len(proc_medium) + len(svc_medium)

    capture_or_hid = 0
    other_medium = 0
    for f in medium_any:
        if _is_capture_or_hid_pattern(f.metadata.get("Pattern")):
            capture_or_hid += 1
        else:
            other_medium += 1
    for p in proc_medium:
        if _is_capture_or_hid_pattern(p.pattern):
            capture_or_hid += 1
        else:
            other_medium += 1
    for s in svc_medium:
        if _is_capture_or_hid_pattern(s.pattern):
            capture_or_hid += 1
        else:
            other_medium += 1

    verdict = _compute_verdict_console(
        cheat_high=total_cheat_high,
        input_high=total_input_high,
        capture_or_hid_medium=capture_or_hid,
        other_medium=other_medium,
    )

    named_cheats = collect_named_items(engine, processes, services, "cheat", "HIGH")
    named_input = collect_named_items(engine, processes, services, "input", "HIGH")

    ctx = ReportContext(
        engine=engine,
        processes=processes,
        services=services,
        verdict=verdict,
        total_cheat_high=total_cheat_high,
        total_input_high=total_input_high,
        total_medium=total_medium,
        named_cheats=named_cheats,
        named_input=named_input,
        historical_findings=historical,
        historical_high=historical_high,
        medium_findings=medium_any,
        proc_medium=proc_medium,
        svc_medium=svc_medium,
        lol_db_used=engine.lol_db is not None,
        capture_or_hid_medium_count=capture_or_hid,
        other_medium_count=other_medium,
    )

    spec = ReportSpec(
        title=f"ALIBI (CONSOLE-RIG MODE) {CONSOLE_RIG_VERSION} - CONSOLIDATED REPORT",
        quick_read_block=_console_quick_read,
        limitations=_CONSOLE_LIMITATIONS,
        threshold_days=RECENCY_THRESHOLD_DAYS,
    )

    text = build_text_report(spec, ctx)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(text)

    if not args.no_html:
        html_path = os.path.splitext(output_path)[0] + "_visual.html"
        html_content = render_html(
            engine=engine, processes=processes, services=services,
            verdict=verdict, threshold_days=RECENCY_THRESHOLD_DAYS,
            report_title=f"Alibi (console-rig mode) {CONSOLE_RIG_VERSION}",
            mode_label="console-rig",
            lol_db_used=engine.lol_db is not None,
        )
        write_html(html_path, html_content)
        if not args.no_open_browser:
            import webbrowser
            try:
                webbrowser.open(f"file:///{html_path.replace(os.sep, '/')}")
            except Exception:  # noqa: BLE001 - browser open is best-effort
                pass
    else:
        html_path = None

    print()
    print("  ============================================================")
    print("  Scan complete.")
    print()
    print(f"  VERDICT: {verdict}")
    print()
    print(f"  Cheat HIGH:    {total_cheat_high}")
    print(f"  Input HIGH:    {total_input_high}")
    print(f"  MEDIUM total:  {total_medium}  (capture/HID: {capture_or_hid}, other: {other_medium})")
    print(f"  Procs scored:  {len(processes)}")
    print(f"  Svcs scored:   {len(services)}")
    print()
    print(f"  Saved to: {output_path}")
    if html_path:
        print(f"  HTML visual saved: {html_path}")
    print("  ============================================================")
    print()

    _write_summary("alibi-console.summary", verdict, output_path,
                   total_cheat_high, total_input_high, total_medium)
    return 0


if __name__ == "__main__":
    sys.exit(main())
