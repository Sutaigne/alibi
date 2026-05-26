"""Generate synthetic example reports that exercise every visual state.

Two reports are produced:
  - pc-mode-cheats-detected.txt + _visual.html
      PC mode, CHEATS DETECTED verdict, packed with HIGH cheat + input matches,
      LOLDrivers BYOVD hits (malicious + vulnerable tiers), AI-vision
      constellation findings, mouse-macro script content, DMA artifact, and
      a Historical section showing recency decay.
  - console-rig-capture-stack.txt + _visual.html
      Console-rig mode, CAPTURE STACK PRESENT verdict — no cheats, just
      capture-card + HID emulator dual-use findings. Shows the amber
      verdict state and the streamer-disclosure quick-read shape.

The data is piped through the production formatters (reports.build_text_report
and visual_companion.render_html), so the output is guaranteed to match
exactly what a real scan would produce.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_SRC = _HERE.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from alibi import CONSOLE_RIG_VERSION, SCANNER_VERSION
from alibi.findings import Finding, ScoredItem
from alibi.keywords import RECENCY_THRESHOLD_DAYS
from alibi.reports import ReportContext, ReportSpec, build_text_report, collect_named_items
from alibi.utils import Engine
from alibi.visual_companion import render_html, write_html
from alibi.forensic_scan import _pc_quick_read, _PC_LIMITATIONS
from alibi.console_rig_audit import _console_quick_read, _CONSOLE_LIMITATIONS


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def _ago(days: int = 0, hours: int = 0) -> str:
    return _iso(datetime.now() - timedelta(days=days, hours=hours))


# ---------------------------------------------------------------------------
# PC MODE — CHEATS DETECTED
# ---------------------------------------------------------------------------
def build_pc_engine() -> Engine:
    e = Engine(
        keywords_high_cheats=["engineowning", "rut.gg"],
        keywords_high_input=["cronus", "xim"],
        keywords_medium=["cheatengine", "vivado"],
        keywords_script_high=["bcdedit /set testsigning"],
        keywords_mouse_macro=["MoveMouseRelative"],
    )

    # --- HIGH cheat findings, multiple categories -------------------------
    e.add("Prefetch", r"C:\Windows\Prefetch\ENGINEOWNING.EXE-1A2B3C4D.pf",
          "[engineowning] ENGINEOWNING", "HIGH", "cheat",
          {"Pattern": "engineowning", "FirstSeen": _ago(days=14),
           "LastModified": _ago(days=2)})
    e.add("MUICache", r"HKCU\...\MuiCache",
          "[rut.gg] C:\\Users\\Bob\\Downloads\\RUT V4 Launcher.exe",
          "HIGH", "cheat",
          {"Pattern": "rut.gg",
           "Value": "C:\\Users\\Bob\\Downloads\\RUT V4 Launcher.exe",
           "Data": "RUT and RUAVT", "LastWrite": _ago(days=5)})
    e.add("DMA", r"C:\Users\Bob\source\pcileech-fpga-build\pcileech_top.bin",
          "pcileech firmware build output: pcileech_top.bin", "HIGH", "cheat",
          {"FileName": "pcileech_top.bin",
           "FullPath": r"C:\Users\Bob\source\pcileech-fpga-build\pcileech_top.bin",
           "Created": _ago(days=21)})
    e.add("KnownHashes", r"C:\Users\Bob\Downloads\RUT AND RUAVT LAUNCHER UPDATED.exe",
          "[RUT AND RUAVT LAUNCHER UPDATED.exe (rut.gg)] hash match - confirmed cheat sample",
          "HIGH", "cheat",
          {"Pattern": "RUT AND RUAVT LAUNCHER UPDATED.exe (rut.gg)",
           "SHA256": "b1b89dedcff0c502d605a707e550b1565224b5949e778168ac45f01b8171160f",
           "FileName": "RUT AND RUAVT LAUNCHER UPDATED.exe",
           "FullPath": r"C:\Users\Bob\Downloads\RUT AND RUAVT LAUNCHER UPDATED.exe",
           "SizeBytes": 8_421_376, "LastWrite": _ago(days=5),
           "KnownSampleOf": "RUT AND RUAVT LAUNCHER UPDATED.exe (rut.gg)",
           "HashSource": "Hybrid Analysis sandbox report"})

    # LOLDrivers BYOVD — both tiers
    e.add("LOLDrivers", r"C:\Users\Bob\AppData\Local\Temp\rtcore64.sys",
          "VULNERABLE DRIVER - hash confirmed (BYOVD risk): rtcore64.sys",
          "HIGH", "cheat",
          {"DeviceName": "RTCore64", "Manufacturer": "MSI",
           "IsSigned": "True", "FileName": "rtcore64.sys",
           "FilePath": r"C:\Users\Bob\AppData\Local\Temp\rtcore64.sys",
           "LOLDrivers_Id": "0c9b1b21-5e26-4e0e-8baa-2bbb4ce4f0bd",
           "LOLDrivers_Category": "vulnerable",
           "LOLDrivers_Tags": "rtcore64.sys,rtcore32.sys",
           "LOLDrivers_MatchBy": "SHA256",
           "SHA256": "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd",
           "LOLDrivers_URL": "https://www.loldrivers.io/drivers/0c9b1b21-5e26-4e0e-8baa-2bbb4ce4f0bd/"})

    # USB history hit
    e.add("USB", "VID_2E24&PID_1000",
          "[cronus] Cronus Zen", "HIGH", "input",
          {"Pattern": "cronus", "FriendlyName": "Cronus Zen",
           "VID_PID": "VID_2E24&PID_1000",
           "FirstInstall": _ago(days=120),
           "LastArrival": _ago(days=1),
           "LastRemoval": _ago(hours=4)})

    # HIGH input — AppData
    e.add("AppData", r"C:\Users\Bob\AppData\Local\ConsoleTuner",
          "Cronus / Titan - 247 files, 38 distinct days",
          "HIGH", "input",
          {"Label": "Cronus / Titan",
           "Directory": r"C:\Users\Bob\AppData\Local\ConsoleTuner",
           "FileCount": 247, "DistinctActivityDays": 38,
           "ActivitySpanDays": 95,
           "OldestWrite": _ago(days=95),
           "NewestWrite": _ago(days=1)})

    # HIGH script content
    e.add("UserScripts", r"C:\Users\Bob\Desktop\setup.bat",
          "[bcdedit /set testsigning] ~\\Desktop\\setup.bat - high-risk command pattern inside script",
          "HIGH", "cheat",
          {"Pattern": "bcdedit /set testsigning",
           "MatchKind": "high-risk command in script",
           "FileName": "setup.bat",
           "FullPath": r"C:\Users\Bob\Desktop\setup.bat",
           "SizeBytes": 412, "LastWrite": _ago(days=8)})

    e.add("UserScripts", r"C:\Users\Bob\Documents\macros\norecoil.lua",
          "[MoveMouseRelative] ~\\Documents\\macros\\norecoil.lua - mouse-macro / anti-recoil script pattern",
          "HIGH", "cheat",
          {"Pattern": "MoveMouseRelative",
           "MatchKind": "mouse-macro / anti-recoil script",
           "FileName": "norecoil.lua",
           "FullPath": r"C:\Users\Bob\Documents\macros\norecoil.lua",
           "SizeBytes": 1_847, "LastWrite": _ago(days=3)})

    # AI-vision constellation
    e.add("AIVision", r"C:\Users\Bob\source\aimmy\aimmy.exe",
          "[aimmy] AI-vision aimbot executable: aimmy.exe", "HIGH", "cheat",
          {"Pattern": "aimmy", "FileName": "aimmy.exe",
           "FullPath": r"C:\Users\Bob\source\aimmy\aimmy.exe",
           "SizeBytes": 18_223_104,
           "Created": _ago(days=18),
           "LastWrite": _ago(days=2)})
    e.add("AIVision", r"C:\Users\Bob\source\aimmy\yolov8n.onnx",
          "ONNX model co-located with AI-aimbot executable: yolov8n.onnx",
          "HIGH", "cheat",
          {"FileName": "yolov8n.onnx",
           "FullPath": r"C:\Users\Bob\source\aimmy\yolov8n.onnx",
           "SizeBytes": 12_405_633,
           "CoLocated": r"C:\Users\Bob\source\aimmy\aimmy.exe",
           "Created": _ago(days=18),
           "LastWrite": _ago(days=18)})

    # BCD flag
    e.add("BCD", "testsigning",
          "TEST SIGNING ENABLED - unsigned drivers can load",
          "HIGH", "cheat", {})

    # --- MEDIUM dual-use --------------------------------------------------
    e.add("Installed", "Cheat Engine 7.5",
          "[cheatengine] Cheat Engine 7.5", "MEDIUM", "dual-use",
          {"Pattern": "cheatengine", "Name": "Cheat Engine 7.5",
           "Publisher": "Dark Byte", "InstallDate": "2026-03-12",
           "Version": "7.5"})

    e.add("ObscuredNames", r"C:\Users\Bob\Downloads\deadbeef12345678.exe",
          "Obscured filename: raw hex name (deadbeef12345678.exe)",
          "MEDIUM", "dual-use",
          {"FileName": "deadbeef12345678.exe",
           "FullPath": r"C:\Users\Bob\Downloads\deadbeef12345678.exe",
           "Pattern": "raw hex name (deadbeef12345678.exe)",
           "SizeBytes": 1_204_800,
           "LastWrite": _ago(days=4)})

    e.add("Drivers", "obscure_helper",
          "UNSIGNED: obscure_helper", "MEDIUM", "dual-use",
          {"DeviceName": "obscure_helper",
           "Manufacturer": "Unknown", "IsSigned": "False",
           "FileName": "obscure_helper.sys",
           "FilePath": r"C:\Windows\System32\drivers\obscure_helper.sys"})

    e.add("DLLInject", "Sysmon EID 7",
          "Injector activity: xenos64.dll @ " + _ago(days=11),
          "MEDIUM", "dual-use",
          {"Source": "Sysmon EID 7",
           "Timestamp": _ago(days=11),
           "ImageLoaded": r"C:\Users\Bob\source\xenos\xenos64.dll",
           "TargetProcess": "explorer.exe", "ProcessId": "4288"})

    # --- INFO -------------------------------------------------------------
    e.add("ProcessModules", "(scan)",
          "Scanned 8412 DLL modules across all running processes",
          "INFO", "other", {"ModulesScanned": 8412})
    e.add("KnownHashes", "(scan)",
          "Hashed 312 executables, checked against 1 known-bad SHA256 sample(s)",
          "INFO", "other", {"Hashed": 312, "DatabaseSize": 1})
    e.add("AIVision", r"C:\Users\Bob\Documents\ml-class\resnet50.onnx",
          "ONNX model present (no aimbot constellation): resnet50.onnx",
          "INFO", "other",
          {"FileName": "resnet50.onnx",
           "FullPath": r"C:\Users\Bob\Documents\ml-class\resnet50.onnx",
           "SizeBytes": 102_400_000,
           "Created": _ago(days=42),
           "LastWrite": _ago(days=40)})
    e.add("RecencyDecay", "(summary)",
          "Recency analysis: 19 recent, 4 historical (>180d demoted), 2 unknown-timestamp",
          "INFO", "other",
          {"ThresholdDays": 180,
           "RecentFindings": 19,
           "HistoricalFindings": 4,
           "UnknownTimestampFindings": 2})

    # --- WARN -------------------------------------------------------------
    e.add("BAM", r"HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
          "Access denied", "WARN", "other", {})
    e.add("ShimCache",
          r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache",
          "Access denied", "WARN", "other", {})

    # --- HISTORICAL (recency-decay demoted) -------------------------------
    # These were originally HIGH cheat — kept in report at lower severity.
    e.add("Prefetch", r"C:\Windows\Prefetch\OLDCHEAT.EXE-9F8E7D6C.pf",
          "[engineowning] OLDCHEAT (CoD MW 2019)", "MEDIUM", "cheat",
          {"Pattern": "engineowning",
           "FirstSeen": _ago(days=720),
           "LastModified": _ago(days=420),
           "MostRecentTimestamp": _ago(days=420),
           "AgeDays": 420,
           "RecencyClass": "historical",
           "OriginalSeverity": "HIGH"})
    e.add("Installed", "Old XIM Manager",
          "[xim] XIM Manager 2018", "INFO", "input",
          {"Pattern": "xim", "Name": "XIM Manager 2018",
           "InstallDate": "2018-11-04",
           "MostRecentTimestamp": "2018-11-04T00:00:00",
           "AgeDays": 2_750,
           "RecencyClass": "historical",
           "OriginalSeverity": "MEDIUM"})

    return e


def build_pc_processes() -> list[ScoredItem]:
    return [
        ScoredItem(
            name="ENGINEOWNING.exe", score="HIGH", kind="cheat",
            pattern="engineowning",
            reason="matches 'engineowning' (cheat keyword)",
            extra={"ProcessId": "9128", "ParentProcessId": "4288",
                   "Started": _ago(hours=2),
                   "ExecutablePath": r"C:\Users\Bob\AppData\Local\engineowning\EO.exe",
                   "CommandLine": r'"C:\Users\Bob\AppData\Local\engineowning\EO.exe" --loader'},
        ),
        ScoredItem(
            name="cheatengine-x86_64.exe", score="MEDIUM", kind="dual-use",
            pattern="cheatengine",
            reason="matches 'cheatengine' (dual-use tool)",
            extra={"ProcessId": "7416", "ParentProcessId": "4288",
                   "Started": _ago(hours=1),
                   "ExecutablePath": r"C:\Program Files\Cheat Engine 7.5\cheatengine-x86_64.exe",
                   "CommandLine": r'"C:\Program Files\Cheat Engine 7.5\cheatengine-x86_64.exe"'},
        ),
        ScoredItem(
            name="explorer.exe", score="CLEAN", kind="other",
            extra={"ProcessId": "4288", "ParentProcessId": "4128",
                   "Started": _ago(days=1),
                   "ExecutablePath": r"C:\Windows\explorer.exe",
                   "CommandLine": r"C:\Windows\Explorer.EXE"},
            reason="standard system location",
        ),
        ScoredItem(
            name="svchost.exe", score="CLEAN", kind="other",
            extra={"ProcessId": "1248", "ParentProcessId": "984",
                   "Started": _ago(days=1),
                   "ExecutablePath": r"C:\Windows\System32\svchost.exe",
                   "CommandLine": r"C:\Windows\System32\svchost.exe -k NetworkService"},
            reason="standard system location",
        ),
        ScoredItem(
            name="chrome.exe", score="LOW", kind="other",
            extra={"ProcessId": "12384", "ParentProcessId": "4288",
                   "Started": _ago(hours=3),
                   "ExecutablePath": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                   "CommandLine": r'"C:\Program Files\Google\Chrome\Application\chrome.exe"'},
            reason="runs from Program Files",
        ),
    ]


def build_pc_services() -> list[ScoredItem]:
    return [
        ScoredItem(
            name="HidHide", score="HIGH", kind="cheat",
            pattern="hidhide",
            reason="matches 'hidhide' (cheat keyword)",
            extra={"DisplayName": "HidHide Service", "State": "Running",
                   "StartMode": "Auto", "PathName": r"C:\Program Files\Nefarius Software Solutions\HidHide\x64\HidHideClient.exe",
                   "StartName": "LocalSystem", "ProcessId": "3120"},
        ),
        ScoredItem(
            name="vgc", score="CLEAN", kind="other",
            extra={"DisplayName": "vgc", "State": "Stopped", "StartMode": "Manual",
                   "PathName": r'"C:\Program Files\Riot Vanguard\vgc.exe"',
                   "StartName": "LocalSystem", "ProcessId": "0"},
            reason="standard system location",
        ),
        ScoredItem(
            name="ViGEmBus", score="MEDIUM", kind="dual-use",
            pattern="vigembus",
            reason="matches 'vigembus' (dual-use tool)",
            extra={"DisplayName": "Virtual Gamepad Emulation Bus",
                   "State": "Running", "StartMode": "Manual",
                   "PathName": r"C:\Windows\System32\drivers\ViGEmBus.sys",
                   "StartName": "LocalSystem", "ProcessId": "4"},
        ),
    ]


# ---------------------------------------------------------------------------
# CONSOLE RIG MODE — CAPTURE STACK PRESENT
# ---------------------------------------------------------------------------
def build_console_engine() -> Engine:
    e = Engine(
        keywords_high_cheats=[], keywords_high_input=[],
        keywords_medium=["obs studio", "elgato", "vigembus", "ds4windows"],
        keywords_script_high=[], keywords_mouse_macro=[],
    )

    # All MEDIUM and all from capture/HID lists — that's what triggers
    # CAPTURE STACK PRESENT (vs. UNSURE).
    e.add("Installed", "OBS Studio",
          "[obs studio] OBS Studio", "MEDIUM", "dual-use",
          {"Pattern": "obs studio", "Name": "OBS Studio",
           "Publisher": "OBS Project",
           "InstallDate": "2026-02-08", "Version": "30.1.2"})
    e.add("Installed", "Elgato 4K Capture Utility",
          "[elgato] Elgato 4K Capture Utility", "MEDIUM", "dual-use",
          {"Pattern": "elgato", "Name": "Elgato 4K Capture Utility",
           "Publisher": "Corsair Memory, Inc.",
           "InstallDate": "2026-04-19", "Version": "1.6.0"})
    e.add("Installed", "DS4Windows",
          "[ds4windows] DS4Windows", "MEDIUM", "dual-use",
          {"Pattern": "ds4windows", "Name": "DS4Windows",
           "Publisher": "Ryochan7",
           "InstallDate": "2026-01-15", "Version": "3.3.3"})
    e.add("Services", "ViGEmBus",
          "[vigembus] ViGEmBus | Virtual Gamepad Emulation Bus | C:\\Windows\\System32\\drivers\\ViGEmBus.sys",
          "MEDIUM", "dual-use",
          {"Pattern": "vigembus", "ServiceName": "ViGEmBus",
           "DisplayName": "Virtual Gamepad Emulation Bus",
           "ImagePath": r"C:\Windows\System32\drivers\ViGEmBus.sys"})

    # INFO + RecencyDecay summary
    e.add("RecencyDecay", "(summary)",
          "Recency analysis: 4 recent, 0 historical (>180d demoted), 1 unknown-timestamp",
          "INFO", "other",
          {"ThresholdDays": 180, "RecentFindings": 4,
           "HistoricalFindings": 0, "UnknownTimestampFindings": 1})
    e.add("ProcessModules", "(scan)",
          "Scanned 6122 DLL modules across all running processes",
          "INFO", "other", {"ModulesScanned": 6122})

    return e


def build_console_processes() -> list[ScoredItem]:
    return [
        ScoredItem(name="obs64.exe", score="MEDIUM", kind="dual-use",
                   pattern="obs", reason="matches 'obs' (dual-use tool)",
                   extra={"ProcessId": "8120", "ParentProcessId": "4288",
                          "Started": _ago(hours=2),
                          "ExecutablePath": r"C:\Program Files\obs-studio\bin\64bit\obs64.exe",
                          "CommandLine": r'"C:\Program Files\obs-studio\bin\64bit\obs64.exe"'}),
        ScoredItem(name="DS4Windows.exe", score="MEDIUM", kind="dual-use",
                   pattern="ds4windows", reason="matches 'ds4windows' (dual-use tool)",
                   extra={"ProcessId": "10428", "ParentProcessId": "4288",
                          "Started": _ago(hours=2),
                          "ExecutablePath": r"C:\Program Files\DS4Windows\DS4Windows.exe",
                          "CommandLine": r'"C:\Program Files\DS4Windows\DS4Windows.exe"'}),
        ScoredItem(name="explorer.exe", score="CLEAN", kind="other",
                   extra={"ProcessId": "4288", "ParentProcessId": "4128",
                          "Started": _ago(days=1),
                          "ExecutablePath": r"C:\Windows\explorer.exe",
                          "CommandLine": r"C:\Windows\Explorer.EXE"},
                   reason="standard system location"),
    ]


def build_console_services() -> list[ScoredItem]:
    return [
        ScoredItem(name="ViGEmBus", score="MEDIUM", kind="dual-use",
                   pattern="vigembus", reason="matches 'vigembus' (dual-use tool)",
                   extra={"DisplayName": "Virtual Gamepad Emulation Bus",
                          "State": "Running", "StartMode": "Manual",
                          "PathName": r"C:\Windows\System32\drivers\ViGEmBus.sys",
                          "StartName": "LocalSystem", "ProcessId": "4"}),
    ]


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def emit_pc(out_dir: Path) -> None:
    engine = build_pc_engine()
    processes = build_pc_processes()
    services = build_pc_services()

    # Verdict counts (exclude historical).
    high_cheats = [f for f in engine.findings
                   if f.severity == "HIGH" and f.kind == "cheat"
                   and f.metadata.get("RecencyClass") != "historical"]
    high_input = [f for f in engine.findings
                  if f.severity == "HIGH" and f.kind == "input"
                  and f.metadata.get("RecencyClass") != "historical"]
    medium_any = [f for f in engine.findings
                  if f.severity == "MEDIUM"
                  and f.metadata.get("RecencyClass") != "historical"]
    historical = [f for f in engine.findings
                  if f.metadata.get("RecencyClass") == "historical"]
    historical_high = [f for f in historical
                       if f.metadata.get("OriginalSeverity") == "HIGH"]

    proc_high_cheat = [p for p in processes if p.score == "HIGH" and p.kind == "cheat"]
    proc_high_input = [p for p in processes if p.score == "HIGH" and p.kind == "input"]
    proc_medium = [p for p in processes if p.score == "MEDIUM"]
    svc_high_cheat = [s for s in services if s.score == "HIGH" and s.kind == "cheat"]
    svc_high_input = [s for s in services if s.score == "HIGH" and s.kind == "input"]
    svc_medium = [s for s in services if s.score == "MEDIUM"]

    total_cheat_high = len(high_cheats) + len(proc_high_cheat) + len(svc_high_cheat)
    total_input_high = len(high_input) + len(proc_high_input) + len(svc_high_input)
    total_medium = len(medium_any) + len(proc_medium) + len(svc_medium)

    ctx = ReportContext(
        engine=engine, processes=processes, services=services,
        verdict="CHEATS DETECTED",
        total_cheat_high=total_cheat_high,
        total_input_high=total_input_high,
        total_medium=total_medium,
        named_cheats=collect_named_items(engine, processes, services, "cheat", "HIGH"),
        named_input=collect_named_items(engine, processes, services, "input", "HIGH"),
        historical_findings=historical,
        historical_high=historical_high,
        medium_findings=medium_any,
        proc_medium=proc_medium,
        svc_medium=svc_medium,
        lol_db_used=True,
    )

    spec = ReportSpec(
        title=f"ALIBI {SCANNER_VERSION} - CONSOLIDATED REPORT",
        quick_read_block=_pc_quick_read,
        limitations=_PC_LIMITATIONS,
        threshold_days=RECENCY_THRESHOLD_DAYS,
    )

    text_path = out_dir / "pc-mode-cheats-detected.txt"
    html_path = out_dir / "pc-mode-cheats-detected_visual.html"
    text_path.write_text(build_text_report(spec, ctx), encoding="utf-8")
    write_html(str(html_path), render_html(
        engine=engine, processes=processes, services=services,
        verdict="CHEATS DETECTED",
        threshold_days=RECENCY_THRESHOLD_DAYS,
        report_title=f"Alibi {SCANNER_VERSION}",
        mode_label="pc-mode",
        lol_db_used=True,
    ))
    print(f"  wrote: {text_path.name}")
    print(f"  wrote: {html_path.name}")


def emit_console(out_dir: Path) -> None:
    engine = build_console_engine()
    processes = build_console_processes()
    services = build_console_services()

    medium_any = [f for f in engine.findings if f.severity == "MEDIUM"]
    proc_medium = [p for p in processes if p.score == "MEDIUM"]
    svc_medium = [s for s in services if s.score == "MEDIUM"]
    total_medium = len(medium_any) + len(proc_medium) + len(svc_medium)

    ctx = ReportContext(
        engine=engine, processes=processes, services=services,
        verdict="CAPTURE STACK PRESENT",
        total_cheat_high=0, total_input_high=0, total_medium=total_medium,
        named_cheats=[], named_input=[],
        historical_findings=[], historical_high=[],
        medium_findings=medium_any, proc_medium=proc_medium, svc_medium=svc_medium,
        lol_db_used=False,
        capture_or_hid_medium_count=total_medium, other_medium_count=0,
    )

    spec = ReportSpec(
        title=f"ALIBI (CONSOLE-RIG MODE) {CONSOLE_RIG_VERSION} - CONSOLIDATED REPORT",
        quick_read_block=_console_quick_read,
        limitations=_CONSOLE_LIMITATIONS,
        threshold_days=RECENCY_THRESHOLD_DAYS,
    )

    text_path = out_dir / "console-rig-capture-stack.txt"
    html_path = out_dir / "console-rig-capture-stack_visual.html"
    text_path.write_text(build_text_report(spec, ctx), encoding="utf-8")
    write_html(str(html_path), render_html(
        engine=engine, processes=processes, services=services,
        verdict="CAPTURE STACK PRESENT",
        threshold_days=RECENCY_THRESHOLD_DAYS,
        report_title=f"Alibi (console-rig mode) {CONSOLE_RIG_VERSION}",
        mode_label="console-rig",
        lol_db_used=False,
    ))
    print(f"  wrote: {text_path.name}")
    print(f"  wrote: {html_path.name}")


# ---------------------------------------------------------------------------
# PC MODE — CLEAN (with a Historical demo)
# ---------------------------------------------------------------------------
def build_clean_engine() -> Engine:
    e = Engine(
        keywords_high_cheats=[], keywords_high_input=[], keywords_medium=[],
        keywords_script_high=[], keywords_mouse_macro=[],
    )
    # Recent: zero MEDIUM/HIGH. Just INFO scan summaries.
    e.add("ProcessModules", "(scan)",
          "Scanned 6021 DLL modules across all running processes",
          "INFO", "other", {"ModulesScanned": 6021})
    e.add("KnownHashes", "(scan)",
          "Hashed 284 executables, checked against 1 known-bad SHA256 sample(s)",
          "INFO", "other", {"Hashed": 284, "DatabaseSize": 1})
    e.add("RecencyDecay", "(summary)",
          "Recency analysis: 0 recent, 2 historical (>180d demoted), 1 unknown-timestamp",
          "INFO", "other",
          {"ThresholdDays": 180, "RecentFindings": 0,
           "HistoricalFindings": 2, "UnknownTimestampFindings": 1})

    # Historical demo — proves the layout still reads when verdict is green
    # but there's history.
    e.add("Installed", "Old XIM Manager",
          "[xim] XIM Manager 2018", "INFO", "input",
          {"Pattern": "xim", "Name": "XIM Manager 2018",
           "InstallDate": "2018-11-04",
           "MostRecentTimestamp": "2018-11-04T00:00:00",
           "AgeDays": 2_750, "RecencyClass": "historical",
           "OriginalSeverity": "MEDIUM"})
    e.add("Prefetch", r"C:\Windows\Prefetch\OLDCHEAT.EXE-9F8E7D6C.pf",
          "[engineowning] OLDCHEAT (CoD MW 2019)",
          "MEDIUM", "cheat",
          {"Pattern": "engineowning",
           "FirstSeen": _ago(days=720),
           "LastModified": _ago(days=420),
           "MostRecentTimestamp": _ago(days=420),
           "AgeDays": 420, "RecencyClass": "historical",
           "OriginalSeverity": "HIGH"})
    return e


def build_clean_processes() -> list[ScoredItem]:
    return [
        ScoredItem(name="explorer.exe", score="CLEAN", kind="other",
                   reason="standard system location",
                   extra={"ProcessId": "4288", "ParentProcessId": "4128",
                          "Started": _ago(days=1),
                          "ExecutablePath": r"C:\Windows\explorer.exe",
                          "CommandLine": r"C:\Windows\Explorer.EXE"}),
        ScoredItem(name="svchost.exe", score="CLEAN", kind="other",
                   reason="standard system location",
                   extra={"ProcessId": "1248", "ParentProcessId": "984",
                          "Started": _ago(days=1),
                          "ExecutablePath": r"C:\Windows\System32\svchost.exe",
                          "CommandLine": r"C:\Windows\System32\svchost.exe -k NetworkService"}),
        ScoredItem(name="chrome.exe", score="LOW", kind="other",
                   reason="runs from Program Files",
                   extra={"ProcessId": "12384", "ParentProcessId": "4288",
                          "Started": _ago(hours=3),
                          "ExecutablePath": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                          "CommandLine": r'"C:\Program Files\Google\Chrome\Application\chrome.exe"'}),
    ]


def build_clean_services() -> list[ScoredItem]:
    return [
        ScoredItem(name="vgc", score="CLEAN", kind="other",
                   reason="standard system location",
                   extra={"DisplayName": "vgc", "State": "Stopped",
                          "StartMode": "Manual",
                          "PathName": r'"C:\Program Files\Riot Vanguard\vgc.exe"'}),
    ]


def emit_clean(out_dir: Path) -> None:
    engine = build_clean_engine()
    processes = build_clean_processes()
    services = build_clean_services()

    ctx = ReportContext(
        engine=engine, processes=processes, services=services,
        verdict="CLEAN",
        total_cheat_high=0, total_input_high=0, total_medium=0,
        named_cheats=[], named_input=[],
        historical_findings=[f for f in engine.findings
                             if f.metadata.get("RecencyClass") == "historical"],
        historical_high=[f for f in engine.findings
                         if f.metadata.get("OriginalSeverity") == "HIGH"
                         and f.metadata.get("RecencyClass") == "historical"],
        medium_findings=[], proc_medium=[], svc_medium=[],
        lol_db_used=False,
    )

    spec = ReportSpec(
        title=f"ALIBI {SCANNER_VERSION} - CONSOLIDATED REPORT",
        quick_read_block=_pc_quick_read,
        limitations=_PC_LIMITATIONS,
        threshold_days=RECENCY_THRESHOLD_DAYS,
    )

    text_path = out_dir / "pc-mode-clean.txt"
    html_path = out_dir / "pc-mode-clean_visual.html"
    text_path.write_text(build_text_report(spec, ctx), encoding="utf-8")
    write_html(str(html_path), render_html(
        engine=engine, processes=processes, services=services,
        verdict="CLEAN", threshold_days=RECENCY_THRESHOLD_DAYS,
        report_title=f"Alibi {SCANNER_VERSION}",
        mode_label="pc-mode", lol_db_used=False,
    ))
    print(f"  wrote: {text_path.name}")
    print(f"  wrote: {html_path.name}")


if __name__ == "__main__":
    out_dir = _HERE
    print(f"Generating synthetic examples into {out_dir}")
    emit_pc(out_dir)
    emit_console(out_dir)
    emit_clean(out_dir)
    print("Done.")
