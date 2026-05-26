"""Process + service snapshots — Python parity for Get-ProcessSnapshot and
Get-ServiceSnapshot.

Both shell out to PowerShell's Get-CimInstance (Win32_Process and
Win32_Service) and parse the CSV output. Shelling out keeps us stdlib-only
on the Python side (no pywin32 / no WMI ctypes) while still pulling the
exact same fields the PS engine pulls. The subprocess command is plainly
visible in source, which preserves the kit's "reviewer reads what runs"
property.
"""
from __future__ import annotations

import csv
import io
import re
import subprocess
from datetime import datetime
from typing import Any

from pc_check.findings import SCORE_RANK, ScoredItem
from pc_check.utils import Engine, score_item


_PS_PROCESS_CMD = [
    "powershell.exe",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy", "Bypass",
    "-Command",
    "Get-CimInstance Win32_Process | "
    "Select-Object ProcessId,ParentProcessId,Name,CreationDate,ExecutablePath,CommandLine | "
    "ConvertTo-Csv -NoTypeInformation",
]

_PS_SERVICE_CMD = [
    "powershell.exe",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy", "Bypass",
    "-Command",
    "Get-CimInstance Win32_Service | "
    "Select-Object Name,DisplayName,State,StartMode,PathName,StartName,ProcessId | "
    "ConvertTo-Csv -NoTypeInformation",
]


def _run_csv(cmd: list[str]) -> list[dict[str, str]]:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120, check=False,
        )
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        return []
    out = result.stdout or ""
    if not out.strip():
        return []
    reader = csv.DictReader(io.StringIO(out))
    return list(reader)


# CIM CreationDate looks like '20250524123456.000000-300' — keep the date,
# trim the fractional + offset for a sortable ISO-ish string.
_CIM_DATE_RE = re.compile(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})")


def _format_cim_date(raw: str) -> str:
    if not raw:
        return ""
    m = _CIM_DATE_RE.match(raw)
    if not m:
        return raw
    y, mo, d, h, mi, s = m.groups()
    return f"{y}-{mo}-{d}T{h}:{mi}:{s}"


def get_process_snapshot(engine: Engine) -> list[ScoredItem]:
    print("  [*] Collecting running processes (scored)...")
    rows = _run_csv(_PS_PROCESS_CMD)
    scored: list[ScoredItem] = []
    for row in rows:
        name = row.get("Name", "") or ""
        path = row.get("ExecutablePath", "") or ""
        cmdline = row.get("CommandLine", "") or ""
        s = score_item(engine, name, path, cmdline)
        scored.append(ScoredItem(
            name=name,
            score=s["score"],
            kind=s["kind"],
            pattern=s["pattern"],
            reason=s["reason"],
            extra={
                "ProcessId": row.get("ProcessId", ""),
                "ParentProcessId": row.get("ParentProcessId", ""),
                "Started": _format_cim_date(row.get("CreationDate", "")),
                "ExecutablePath": path,
                "CommandLine": cmdline,
            },
        ))
    scored.sort(key=lambda x: (SCORE_RANK.get(x.score, 99), x.name.lower()))
    return scored


def get_service_snapshot(engine: Engine) -> list[ScoredItem]:
    print("  [*] Collecting services (scored)...")
    rows = _run_csv(_PS_SERVICE_CMD)
    scored: list[ScoredItem] = []
    for row in rows:
        name = row.get("Name", "") or ""
        path = row.get("PathName", "") or ""
        display = row.get("DisplayName", "") or ""
        s = score_item(engine, name, path, display)
        scored.append(ScoredItem(
            name=name,
            score=s["score"],
            kind=s["kind"],
            pattern=s["pattern"],
            reason=s["reason"],
            extra={
                "DisplayName": display,
                "State": row.get("State", ""),
                "StartMode": row.get("StartMode", ""),
                "PathName": path,
                "StartName": row.get("StartName", ""),
                "ProcessId": row.get("ProcessId", ""),
            },
        ))
    scored.sort(key=lambda x: (SCORE_RANK.get(x.score, 99), x.name.lower()))
    return scored


def named_items(
    engine: Engine,
    processes: list[ScoredItem],
    services: list[ScoredItem],
    kind: str,
    severity: str,
) -> list[str]:
    """Get-Named-Items equivalent — concatenates HIGH-kind findings, processes,
    and services into one human-readable list for the QUICK READ block.
    """
    out: list[str] = []
    for f in engine.findings:
        if f.severity == severity and f.kind == kind:
            pat = f.metadata.get("Pattern", "?")
            out.append(f"[{f.category}] {pat} - {f.detail}")
    for p in processes:
        if p.score == severity and p.kind == kind:
            out.append(f"[Process] {p.pattern} - {p.name} (PID {p.extra.get('ProcessId','?')})")
    for s in services:
        if s.score == severity and s.kind == kind:
            out.append(f"[Service] {s.pattern} - {s.name} ({s.extra.get('State','?')})")
    return out
