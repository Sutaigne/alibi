"""Alibi — Python parity of forensic-scan.ps1.

Drives a PC-mode scan: all 21 scanners + process / service snapshots, then
applies recency decay, computes a 4-tier verdict, writes the .txt report and
the matching _visual.html, and drops a summary file the unified launcher can
read back.
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime

from alibi import SCANNER_VERSION
from alibi.keywords import (
    CHEAT_BRANDS_APEX, CHEAT_BRANDS_COD, CHEAT_BRANDS_CS2, CHEAT_BRANDS_LOW_CONFIDENCE,
    CHEAT_BRANDS_MARVEL_RIVALS, CHEAT_BRANDS_R6, CHEAT_BRANDS_RUST, CHEAT_BRANDS_TARKOV,
    CHEAT_FEATURE_NAMES, DMA_DUAL_USE, DMA_INDICATORS, DUAL_USE_TOOLS,
    INPUT_DEVICES, RECENCY_THRESHOLD_DAYS, SCRIPT_CONTENT_HIGH_RISK,
    SCRIPT_CONTENT_MOUSE_MACRO, SPOOFER_BRANDS, VISION_AIMBOT_AI_PC,
)
from alibi.loldrivers import resolve_loldrivers_db
from alibi.recency import apply_recency_decay
from alibi.reports import ReportContext, ReportSpec, build_text_report, collect_named_items
from alibi.scanners import invoke_all_scans
from alibi.snapshots import get_process_snapshot, get_service_snapshot
from alibi.utils import Engine, is_admin, resolve_desktop
from alibi.visual_companion import render_html, write_html


def _pc_quick_read(ctx: ReportContext) -> list[str]:
    lines: list[str] = []
    if ctx.verdict == "CHEATS DETECTED":
        lines.append("  This scan found HIGH-confidence indicators of cheat software,")
        lines.append("  HWID spoofers, or DMA-cheat development artifacts on this machine.")
        lines.append("")
        lines.append("  Named items (cheat-confidence):")
        for n in ctx.named_cheats:
            lines.append(f"    - {n}")
        if ctx.named_input:
            lines.append("")
            lines.append("  Also detected (input devices - separate category):")
            for n in ctx.named_input:
                lines.append(f"    - {n}")
    elif ctx.verdict == "INPUT DEVICES DETECTED":
        lines.append("  No cheat brands or HWID spoofers were detected, but this scan")
        lines.append("  found HIGH-confidence indicators of input-device software.")
        lines.append("  (XIM, Cronus, ReaSnow, KMBox, Titan, etc.)")
        lines.append("")
        lines.append("  These are commercial mouse/keyboard adapters. Some games treat")
        lines.append("  them as bannable; some do not. Context is required.")
        lines.append("")
        lines.append("  Named items:")
        for n in ctx.named_input:
            lines.append(f"    - {n}")
    elif ctx.verdict == "UNSURE":
        lines.append("  No HIGH-confidence cheat or input-device matches were detected.")
        lines.append(f"  However, {ctx.total_medium} MEDIUM finding(s) require human review.")
        lines.append("  These are typically dual-use tools or binaries running from")
        lines.append("  user-writable locations that the allowlist does not recognize.")
        lines.append("")
        lines.append("  ----------------------------------------------------------------")
        lines.append("  AI HANDOFF - copy the block below into any AI chat with web")
        lines.append("  access (ChatGPT, Claude, Gemini, etc.), then attach this .txt")
        lines.append("  file or paste its full contents where indicated.")
        lines.append("  ----------------------------------------------------------------")
        lines.append("")
        lines.append(">>> PROMPT START >>>")
        lines.append("")
        lines.append("You are reviewing a forensic scan report from a Windows PC. The")
        lines.append("report flagged some items at MEDIUM confidence but no HIGH-confidence")
        lines.append("cheat or input-device matches. I need your help determining whether")
        lines.append("the MEDIUM items are benign software or warrant further investigation.")
        lines.append("")
        lines.append("Your task:")
        lines.append("1. Read the attached/pasted log between the LOG START and LOG END markers below.")
        lines.append("2. For each MEDIUM finding, MEDIUM-scored process, and MEDIUM-scored service,")
        lines.append("   look up the binary name, service name, or product name using web search.")
        lines.append("3. Classify each as one of:")
        lines.append("     - LIKELY BENIGN (well-known legitimate software, publisher verifiable)")
        lines.append("     - WORTH REVIEWING (legitimate but capable of misuse, dual-use, or")
        lines.append("       installed in an unusual location for its category)")
        lines.append("     - SUSPICIOUS (associated with cheating, malware, hacking tools, or")
        lines.append("       has no clear legitimate use case)")
        lines.append("4. Cite the source URL for any classification you make.")
        lines.append("5. Produce a final summary plus a one-sentence recommendation.")
        lines.append("")
        lines.append("Constraints:")
        lines.append("  - Do NOT speculate beyond what the log content and web searches support.")
        lines.append("  - Do NOT make claims about the user. Only classify the software.")
        lines.append("  - Do NOT recommend deletion, modification, or further scans.")
        lines.append("  - The scan report is the only data source.")
        lines.append("")
        lines.append("Context for interpretation:")
        lines.append(f"  - This log was produced by Alibi {SCANNER_VERSION}, a read-only")
        lines.append("    forensic scan that matches Windows artifact data against a")
        lines.append("    research-confirmed keyword database of cheat software, HWID spoofers,")
        lines.append("    DMA-cheat artifacts, and commercial input devices (XIM, Cronus,")
        lines.append("    ReaSnow, etc.).")
        lines.append("  - HIGH = unambiguous keyword match. MEDIUM = dual-use tool or binary")
        lines.append("    running from a user-writable location not on the allowlist.")
        lines.append("")
        lines.append("<<< LOG START >>>")
        lines.append("")
        lines.append("[Paste the full contents of the AlibiReport_*.txt file here,")
        lines.append(" OR upload the file as an attachment.]")
        lines.append("")
        lines.append("<<< LOG END >>>")
        lines.append("")
        lines.append("<<< PROMPT END <<<")
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
        lines.append("  section at the bottom of this report for what this scan cannot")
        lines.append("  detect (DMA cheats at runtime, separately-paired input devices,")
        lines.append("  professionally cleaned machines, etc).")
    return lines


_PC_LIMITATIONS = [
    "DMA cheats cannot be detected at runtime by design (no PC-side footprint). "
    "This scan flags DMA development artifacts only.",
    "Input devices configured on a separate machine leave no trace on this PC.",
    "Session duration is recorded in SRUM and requires an ESE database parser. Not extracted here.",
    "Keyword matching only. Sophisticated cleaners can wipe most of these artifacts.",
    "A clean result is necessary but not sufficient.",
]


def _resolve_output_path(explicit: str | None, *, stem: str = "AlibiReport") -> str:
    if explicit:
        parent = os.path.dirname(explicit)
        if parent and not os.path.isdir(parent):
            try:
                os.makedirs(parent, exist_ok=True)
            except OSError:
                explicit = os.path.join(
                    os.environ.get("USERPROFILE", os.path.expanduser("~")),
                    os.path.basename(explicit),
                )
        return explicit
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(resolve_desktop(), f"{stem}_{stamp}.txt")


def _write_summary(temp_name: str, verdict: str, output_path: str,
                   cheat_high: int, input_high: int, medium: int) -> None:
    temp_dir = os.environ.get("TEMP", os.environ.get("TMP", "."))
    try:
        with open(os.path.join(temp_dir, temp_name), "w", encoding="utf-8") as fh:
            fh.write(f"{verdict}|{output_path}|{cheat_high}|{input_high}|{medium}")
    except OSError:
        pass


def _compute_verdict_pc(
    *, cheat_high: int, input_high: int, medium: int,
) -> str:
    if cheat_high > 0:
        return "CHEATS DETECTED"
    if input_high > 0:
        return "INPUT DEVICES DETECTED"
    if medium > 0:
        return "UNSURE"
    return "CLEAN"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="alibi",
        description="Alibi — Python parity of forensic-scan.ps1.",
    )
    parser.add_argument("--output", default=None, help="Explicit output .txt path.")
    parser.add_argument("--skip-loldrivers", action="store_true",
                        help="Skip the LOLDrivers BYOVD cross-reference (no network call).")
    parser.add_argument("--no-html", action="store_true",
                        help="Skip the HTML visual companion.")
    parser.add_argument("--non-interactive", action="store_true",
                        help="Never prompt; combined with --skip-loldrivers for unattended runs.")
    args = parser.parse_args(argv)

    output_path = _resolve_output_path(args.output)

    # Composite keyword arrays — PC mode.
    keywords_high_cheats = (
        CHEAT_BRANDS_COD + SPOOFER_BRANDS + CHEAT_FEATURE_NAMES + DMA_INDICATORS
        + CHEAT_BRANDS_CS2 + CHEAT_BRANDS_APEX + CHEAT_BRANDS_TARKOV + CHEAT_BRANDS_RUST
        + CHEAT_BRANDS_R6 + CHEAT_BRANDS_MARVEL_RIVALS + VISION_AIMBOT_AI_PC
    )
    keywords_high_input = INPUT_DEVICES
    keywords_medium = DMA_DUAL_USE + DUAL_USE_TOOLS + CHEAT_BRANDS_LOW_CONFIDENCE

    engine = Engine(
        keywords_high_cheats=keywords_high_cheats,
        keywords_high_input=keywords_high_input,
        keywords_medium=keywords_medium,
        keywords_script_high=SCRIPT_CONTENT_HIGH_RISK,
        keywords_mouse_macro=SCRIPT_CONTENT_MOUSE_MACRO,
    )

    print()
    print(f"  Alibi {SCANNER_VERSION}")
    print("  =======================")
    print()
    print(f"  Host:   {os.environ.get('COMPUTERNAME','')}")
    print(f"  User:   {os.environ.get('USERNAME','')}")
    print(f"  Admin:  {'Yes' if is_admin() else 'No (run as admin for full coverage)'}")
    print()
    print("  This will take 30-90 seconds. Please wait...")
    print()

    engine.lol_db = resolve_loldrivers_db(
        engine,
        skip=args.skip_loldrivers,
        interactive=not args.non_interactive,
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

    # Verdict counts — exclude historical findings.
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

    verdict = _compute_verdict_pc(
        cheat_high=total_cheat_high,
        input_high=total_input_high,
        medium=total_medium,
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
    )

    spec = ReportSpec(
        title=f"ALIBI {SCANNER_VERSION} - CONSOLIDATED REPORT",
        quick_read_block=_pc_quick_read,
        limitations=_PC_LIMITATIONS,
        threshold_days=RECENCY_THRESHOLD_DAYS,
    )

    text = build_text_report(spec, ctx)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(text)

    # HTML companion.
    if not args.no_html:
        html_path = os.path.splitext(output_path)[0] + "_visual.html"
        html_content = render_html(
            engine=engine,
            processes=processes,
            services=services,
            verdict=verdict,
            threshold_days=RECENCY_THRESHOLD_DAYS,
            report_title=f"Alibi {SCANNER_VERSION}",
            mode_label="pc-mode",
            lol_db_used=engine.lol_db is not None,
        )
        write_html(html_path, html_content)
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
    print(f"  MEDIUM total:  {total_medium}")
    print(f"  Procs scored:  {len(processes)}")
    print(f"  Svcs scored:   {len(services)}")
    print()
    print(f"  Saved to: {output_path}")
    if html_path:
        print(f"  HTML visual saved: {html_path}")
    print("  ============================================================")
    print()

    _write_summary("alibi-pc.summary", verdict, output_path,
                   total_cheat_high, total_input_high, total_medium)
    return 0


if __name__ == "__main__":
    sys.exit(main())
