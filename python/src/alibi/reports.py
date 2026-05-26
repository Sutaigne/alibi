"""Text report builder. One module shared by both drivers; the per-mode
differences (QUICK READ verdict copy, banner title, limitations block) are
passed in via the ReportSpec.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Iterable

from alibi.findings import Finding, SCORE_RANK, SEVERITY_RANK, ScoredItem
from alibi.utils import Engine, is_admin


@dataclass
class ReportSpec:
    title: str                      # e.g. "ALIBI v4.0 - CONSOLIDATED REPORT"
    quick_read_block: Callable[["ReportContext"], list[str]]
    limitations: list[str]          # bullet lines, '  - ' prefix added automatically
    threshold_days: int


@dataclass
class ReportContext:
    engine: Engine
    processes: list[ScoredItem]
    services: list[ScoredItem]
    verdict: str
    total_cheat_high: int
    total_input_high: int
    total_medium: int
    named_cheats: list[str]
    named_input: list[str]
    historical_findings: list[Finding]
    historical_high: list[Finding]
    medium_findings: list[Finding] = field(default_factory=list)
    proc_medium: list[ScoredItem] = field(default_factory=list)
    svc_medium: list[ScoredItem] = field(default_factory=list)
    lol_db_used: bool = False
    capture_or_hid_medium_count: int = 0  # console-mode only
    other_medium_count: int = 0           # console-mode only


def _hostname() -> str:
    import os
    return os.environ.get("COMPUTERNAME", "")


def _username() -> str:
    import os
    return os.environ.get("USERNAME", "")


def _os_string() -> str:
    import platform
    return f"{platform.system()} {platform.release()} ({platform.version()})"


def build_text_report(spec: ReportSpec, ctx: ReportContext) -> str:
    lines: list[str] = []

    # ---- QUICK READ -------------------------------------------------------
    lines.append("================================================================")
    lines.append("  QUICK READ - START HERE")
    lines.append("================================================================")
    lines.append("")
    lines.append(f"  VERDICT: {ctx.verdict}")
    lines.append("")
    lines.extend(spec.quick_read_block(ctx))

    if ctx.historical_findings:
        lines.append("")
        lines.append("  ----------------------------------------------------------------")
        lines.append("  HISTORICAL findings (logged, did NOT affect verdict)")
        lines.append("  ----------------------------------------------------------------")
        lines.append(f"  {len(ctx.historical_findings)} finding(s) older than "
                     f"{spec.threshold_days} days were demoted by the")
        lines.append("  recency-decay rule. These are visible below in the full report but")
        lines.append("  did not count toward the verdict above. Old artifacts from games or")
        lines.append("  tools the user has long since stopped using should not make a")
        lines.append("  currently-clean machine look dirty.")
        if ctx.historical_high:
            lines.append("")
            lines.append(f"  Of these, {len(ctx.historical_high)} were originally HIGH-severity cheat or input matches.")
            lines.append("  The most-recent timestamps and AgeDays are recorded per finding.")

    lines.append("")
    lines.append("================================================================")
    lines.append("")

    # ---- Standard report header ------------------------------------------
    lines.append("================================================================")
    lines.append(f"  {spec.title}")
    lines.append("================================================================")
    lines.append("")
    lines.append(f"  Generated:  {datetime.now().isoformat(sep=' ', timespec='seconds')}")
    lines.append(f"  Hostname:   {_hostname()}")
    lines.append(f"  Username:   {_username()}")
    lines.append(f"  OS:         {_os_string()}")
    lines.append(f"  Admin mode: {is_admin()}")
    lines.append(f"  Verdict:    {ctx.verdict}")
    lines.append("")
    if ctx.lol_db_used:
        lines.append("  Read-only scan. No system state was modified. One outbound network call (loldrivers.io, opt-in).")
    else:
        lines.append("  Read-only scan. No system state was modified. No network calls.")
    lines.append("================================================================")
    lines.append("")

    # ---- Section 1: cheat-trace scan -------------------------------------
    recent = [f for f in ctx.engine.findings if f.metadata.get("RecencyClass") != "historical"]
    historical = [f for f in ctx.engine.findings if f.metadata.get("RecencyClass") == "historical"]

    high = [f for f in recent if f.severity == "HIGH"]
    medium = [f for f in recent if f.severity == "MEDIUM"]
    warn = [f for f in recent if f.severity == "WARN"]
    info = [f for f in recent if f.severity == "INFO"]

    lines.append("================================================================")
    lines.append("  SECTION 1 OF 3 - CHEAT TRACE SCAN")
    lines.append("================================================================")
    lines.append("")
    lines.append(f"  Summary (recent, within last {spec.threshold_days} days - verdict-relevant):")
    lines.append(f"    HIGH    findings : {len(high)}")
    lines.append(f"    MEDIUM  findings : {len(medium)}")
    lines.append(f"    INFO    items    : {len(info)}")
    lines.append(f"    WARN    (access) : {len(warn)}")
    if historical:
        orig_high = [f for f in historical if f.metadata.get("OriginalSeverity") == "HIGH"]
        lines.append("")
        lines.append(f"  Summary (historical, >{spec.threshold_days} days old - logged but did NOT affect verdict):")
        lines.append(f"    Demoted historical findings : {len(historical)}")
        lines.append(f"    (Originally HIGH-severity   : {len(orig_high)})")
    lines.append("")

    if not ctx.engine.findings:
        lines.append("  No findings.")
        lines.append("")
    else:
        for f in sorted(recent, key=lambda x: (SEVERITY_RANK.get(x.severity, 9), x.category)):
            _emit_finding(lines, f)
        if historical:
            lines.append("  ------------------------------------------------------------")
            lines.append(f"  HISTORICAL FINDINGS (>{spec.threshold_days} days old, did NOT affect verdict)")
            lines.append("  ------------------------------------------------------------")
            lines.append("")
            for f in sorted(historical, key=lambda x: -int(x.metadata.get("AgeDays", 0))):
                _emit_finding(lines, f, historical=True)

    # ---- Section 2: processes --------------------------------------------
    lines.extend(_emit_snapshot_section(ctx.processes, title="SECTION 2 OF 3 - RUNNING PROCESSES (scored)",
                                        path_label="Path", display_label=None, mode_label=None))
    # ---- Section 3: services ---------------------------------------------
    lines.extend(_emit_snapshot_section(ctx.services, title="SECTION 3 OF 3 - SERVICES (scored)",
                                        path_label="Path", display_label="Display", mode_label="Mode"))

    # ---- Limitations -----------------------------------------------------
    lines.append("================================================================")
    lines.append("  COVERAGE LIMITATIONS")
    lines.append("================================================================")
    lines.append("")
    for bullet in spec.limitations:
        lines.append(f"  - {bullet}")
    lines.append("")
    lines.append(f"  Report generated: {datetime.now().isoformat(sep=' ', timespec='seconds')}")
    lines.append("")

    return "\n".join(lines)


def _emit_finding(lines: list[str], f: Finding, *, historical: bool = False) -> None:
    if historical:
        orig = f.metadata.get("OriginalSeverity")
        orig_str = f"was {orig}" if orig else "demoted"
        age = f.metadata.get("AgeDays")
        age_str = f"{age}d old" if age else "age unknown"
        lines.append(f"  [{f.severity}/{f.kind}] [{f.category}] [HISTORICAL {orig_str}, {age_str}] {f.detail}")
    else:
        lines.append(f"  [{f.severity}/{f.kind}] [{f.category}] {f.detail}")
    lines.append(f"        Source: {f.source}")
    for k, v in f.metadata.items():
        if v not in (None, ""):
            lines.append(f"        {k}: {v}")
    lines.append("")


def _emit_snapshot_section(
    items: list[ScoredItem],
    *,
    title: str,
    path_label: str,
    display_label: str | None,
    mode_label: str | None,
) -> list[str]:
    lines: list[str] = []
    high = [i for i in items if i.score == "HIGH"]
    med = [i for i in items if i.score == "MEDIUM"]
    low = [i for i in items if i.score == "LOW"]
    clean = [i for i in items if i.score == "CLEAN"]

    lines.append("================================================================")
    lines.append(f"  {title}")
    lines.append("================================================================")
    lines.append("")
    label = "processes" if "PROCESSES" in title else "services"
    lines.append(f"  Total {label} captured: {len(items)}")
    lines.append(f"    HIGH:   {len(high)}")
    lines.append(f"    MEDIUM: {len(med)}")
    lines.append(f"    LOW:    {len(low)}")
    lines.append(f"    CLEAN:  {len(clean)}")
    lines.append("")

    if high or med:
        lines.append(f"  HIGH and MEDIUM {label} (full detail):")
        lines.append("")
        for item in list(high) + list(med):
            if "PROCESSES" in title:
                lines.append(f"    [{item.score}/{item.kind}] {item.name} (PID {item.extra.get('ProcessId','?')})")
                lines.append(f"        {path_label}:    {item.extra.get('ExecutablePath','')}")
                lines.append(f"        Cmd:     {item.extra.get('CommandLine','')}")
            else:
                lines.append(f"    [{item.score}/{item.kind}] {item.name} ({item.extra.get('State','?')})")
                if display_label:
                    lines.append(f"        {display_label}: {item.extra.get('DisplayName','')}")
                lines.append(f"        {path_label}:    {item.extra.get('PathName','')}")
                if mode_label:
                    lines.append(f"        {mode_label}:    {item.extra.get('StartMode','')}")
            lines.append(f"        Reason:  {item.reason}")
            if item.pattern:
                lines.append(f"        Pattern: {item.pattern}")
            lines.append("")

    if items:
        lines.append(f"  Full {label} table (sorted by suspicion score):")
        lines.append("")
        for item in items:
            if "PROCESSES" in title:
                lines.append(
                    f"    {item.score:6}  PID {item.extra.get('ProcessId',''):>6}  "
                    f"{item.name:<32}  {item.extra.get('ExecutablePath','')}"
                )
            else:
                lines.append(
                    f"    {item.score:6}  {item.extra.get('State',''):<7}  "
                    f"{item.name:<32}  {item.extra.get('PathName','')}"
                )
        lines.append("")
    return lines


# ---------------------------------------------------------------------------
# Convenience: compute the named-items lists for the QUICK READ block.
# ---------------------------------------------------------------------------
def collect_named_items(
    engine: Engine,
    processes: list[ScoredItem],
    services: list[ScoredItem],
    kind: str,
    severity: str,
) -> list[str]:
    from alibi.snapshots import named_items
    return named_items(engine, processes, services, kind, severity)
